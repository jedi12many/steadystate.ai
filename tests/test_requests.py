"""Request recipes -- a vetted ask becomes a review-gated PR in another repo. These pin the recipe
schema (author/repo/file/value/title required; only declared+compilable params; placeholders must
be declared; unknown edit kinds rejected), the parameter discipline (regex-validated, no newlines,
unknown/missing rejected -- the model never composes a diff), the full API choreography (read file
-> branch -> commit -> PR, no clone), the dedup (open PR found -> its link; value already present
-> nothing to request; orphan branch -> honest decline), the effect tiering (`requests` read-only,
`request` external-send: NL echo, MCP write grant), and the audit."""

from __future__ import annotations

import base64
import json
import urllib.error

import pytest

import steadystate.act.requests as req_mod
from steadystate.act.requests import (
    fulfill_request,
    load_requests,
    parse_request,
)
from steadystate.inbound.base import REQUEST, REQUESTS_LIST, Command, command_from_text, tool_schema
from steadystate.inbound.mcp import mcp_tools
from steadystate.state import StateStore
from steadystate.verbs import run_command

RECIPE = {
    "name": "proxy-domain",
    "problem": "a server needs outbound access to a new domain",
    "repo": "acme/proxy-outbound",
    "file": "allowlist.txt",
    "edit": "append-line",
    "value": "{domain}",
    "params": {"domain": r"^[a-z0-9.-]+\.[a-z]{2,}$"},
    "title": "request: allow outbound to {domain}",
    "author": "ops",
}


@pytest.fixture
def _catalog(tmp_path, monkeypatch):
    path = tmp_path / "requests.json"
    path.write_text(json.dumps([RECIPE]))
    monkeypatch.setenv("STEADYSTATE_REQUESTS", str(path))
    monkeypatch.setenv("STEADYSTATE_GITHUB_TOKEN", "tok")
    monkeypatch.delenv("GITHUB_API_URL", raising=False)


class _Resp:
    def __init__(self, body) -> None:
        self._body = json.dumps(body).encode()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        return self._body


def _github(monkeypatch, *, file_lines: str, open_prs: list | None = None):
    """A fake GitHub: records every (method, url, body) and answers the fulfillment choreography."""
    calls: list[tuple[str, str, dict | None]] = []

    def fake_urlopen(request, timeout=0):
        method = request.get_method()
        url = request.full_url
        body = json.loads(request.data) if request.data else None
        calls.append((method, url, body))
        if "/pulls?state=open" in url:
            return _Resp(open_prs or [])
        if url.endswith("/repos/acme/proxy-outbound"):
            return _Resp({"default_branch": "main"})
        if "/contents/allowlist.txt?ref=" in url:
            return _Resp(
                {"content": base64.b64encode(file_lines.encode()).decode(), "sha": "file-sha"}
            )
        if "/git/ref/heads/main" in url:
            return _Resp({"object": {"sha": "base-sha"}})
        if url.endswith("/git/refs"):
            return _Resp({"ref": body["ref"]})
        if "/contents/allowlist.txt" in url and method == "PUT":
            return _Resp({"commit": {"sha": "new-sha"}})
        if url.endswith("/pulls") and method == "POST":
            return _Resp({"html_url": "https://github.com/acme/proxy-outbound/pull/7"})
        raise AssertionError(f"unexpected call: {method} {url}")

    monkeypatch.setattr(req_mod, "safe_urlopen", fake_urlopen)
    return calls


# -- the recipe schema -------------------------------------------------------------------------


def test_parse_requires_the_audit_anchor_and_a_real_repo():
    assert parse_request(RECIPE) is not None
    assert parse_request({**RECIPE, "author": ""}) is None  # unsigned isn't auditable
    assert parse_request({**RECIPE, "repo": "not-a-repo"}) is None
    assert parse_request({**RECIPE, "edit": "rewrite-everything"}) is None  # deterministic only


def test_parse_rejects_undeclared_placeholders_and_broken_param_regexes():
    undeclared = {**RECIPE, "value": "{domain} {port}"}  # {port} never declared -> unvalidatable
    assert parse_request(undeclared) is None
    broken = {**RECIPE, "params": {"domain": "([unclosed"}}
    assert parse_request(broken) is None


def test_load_skips_invalid_entries(tmp_path, monkeypatch):
    path = tmp_path / "requests.json"
    path.write_text(json.dumps([RECIPE, {"name": "no-author"}]))
    monkeypatch.setenv("STEADYSTATE_REQUESTS", str(path))
    assert [r.name for r in load_requests()] == ["proxy-domain"]


# -- the parameter discipline ------------------------------------------------------------------


def test_params_are_regex_validated_and_typos_rejected(_catalog):
    ok, detail = fulfill_request("proxy-domain", ["domain=not a domain"], "amy")
    assert not ok and "doesn't match" in detail
    ok, detail = fulfill_request("proxy-domain", ["domian=example.com"], "amy")
    assert not ok and "unknown parameter" in detail and "domain" in detail
    ok, detail = fulfill_request("proxy-domain", [], "amy")
    assert not ok and "missing parameter" in detail
    ok, detail = fulfill_request("unknown-recipe", [], "amy")
    assert not ok and "no request named" in detail


# -- the fulfillment choreography --------------------------------------------------------------


def test_a_request_becomes_a_pr_with_the_deterministic_edit(_catalog, monkeypatch):
    calls = _github(monkeypatch, file_lines="existing.example\n")
    ok, detail = fulfill_request("proxy-domain", ["domain=example.com"], "amy")
    assert ok and "https://github.com/acme/proxy-outbound/pull/7" in detail
    assert "review" in detail  # the channel reply sets the expectation
    put = next(b for m, _, b in calls if m == "PUT")
    decoded = base64.b64decode(put["content"]).decode()
    assert decoded == "existing.example\nexample.com\n"  # append-line, nothing else touched
    assert put["branch"].startswith("steadystate/request/proxy-domain/")
    pr = next(b for m, u, b in calls if m == "POST" and u.endswith("/pulls"))
    assert pr["title"] == "request: allow outbound to example.com"
    assert "Requested by **amy**" in pr["body"] and "vouched by ops" in pr["body"]
    assert ("POST", "/git/refs") in [(m, u[-9:]) for m, u, _ in calls]  # a fresh branch was cut


def test_asking_twice_points_at_the_open_pr(_catalog, monkeypatch):
    calls = _github(
        monkeypatch,
        file_lines="x\n",
        open_prs=[{"html_url": "https://github.com/acme/proxy-outbound/pull/3"}],
    )
    ok, detail = fulfill_request("proxy-domain", ["domain=example.com"], "amy")
    assert ok and "already requested" in detail and "/pull/3" in detail
    assert not any(m in ("PUT", "POST") and "/pulls" not in u for m, u, _ in calls[1:])  # read-only


def test_a_value_already_in_the_file_is_nothing_to_request(_catalog, monkeypatch):
    _github(monkeypatch, file_lines="example.com\nother.example\n")
    ok, detail = fulfill_request("proxy-domain", ["domain=example.com"], "amy")
    assert ok and "nothing to request" in detail and "already in allowlist.txt" in detail


def test_an_orphan_branch_declines_honestly(_catalog, monkeypatch):
    def fake_urlopen(request, timeout=0):
        url, method = request.full_url, request.get_method()
        if "/pulls?state=open" in url:
            return _Resp([])
        if url.endswith("/repos/acme/proxy-outbound"):
            return _Resp({"default_branch": "main"})
        if "/contents/" in url and method == "GET":
            return _Resp({"content": base64.b64encode(b"x\n").decode(), "sha": "s"})
        if "/git/ref/heads/main" in url:
            return _Resp({"object": {"sha": "base-sha"}})
        if url.endswith("/git/refs"):
            raise urllib.error.HTTPError(url, 422, "Unprocessable", {}, None)
        raise AssertionError(f"unexpected: {method} {url}")

    monkeypatch.setattr(req_mod, "safe_urlopen", fake_urlopen)
    ok, detail = fulfill_request("proxy-domain", ["domain=example.com"], "amy")
    assert not ok and "already exists" in detail and "declined" in detail


def test_no_token_fails_closed(_catalog, monkeypatch):
    monkeypatch.delenv("STEADYSTATE_GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    ok, detail = fulfill_request("proxy-domain", ["domain=example.com"], "amy")
    assert not ok and "STEADYSTATE_GITHUB_TOKEN" in detail


# -- grammar, tiering, audit -------------------------------------------------------------------


def test_request_params_ride_verbatim_and_bare_request_is_not_actionable():
    command = command_from_text("request proxy-domain domain=example.com", "amy")
    assert command == Command(REQUEST, "amy", "proxy-domain", argument2="domain=example.com")
    assert command_from_text("request", "amy") is None


def test_requests_is_read_only_and_request_needs_the_mcp_write_grant():
    effects = {t["name"]: t["effect"] for t in tool_schema()["tools"]}
    assert effects[REQUESTS_LIST] == "read-only"
    assert effects[REQUEST] == "external-send"
    read_only_tools = {t["name"] for t in mcp_tools(write=False)}
    assert REQUESTS_LIST in read_only_tools and REQUEST not in read_only_tools


def test_the_requests_view_names_the_params_and_the_target_repo(_catalog):
    view = run_command(Command(REQUESTS_LIST, "amy"), "")
    assert "request proxy-domain domain=<domain>" in view
    assert "[PR on acme/proxy-outbound]" in view


def test_a_request_is_audited_with_who_asked(_catalog, monkeypatch, tmp_path):
    monkeypatch.setattr(
        "steadystate.act.requests.fulfill_request", lambda *a, **k: (True, "opened: url")
    )
    state = str(tmp_path / "state.db")
    reply = run_command(
        Command(REQUEST, "amy", "proxy-domain", argument2="domain=example.com"), state
    )
    assert reply == "opened: url"
    with StateStore(state) as store:
        entries = store.audit_log()
    assert len(entries) == 1
    assert entries[0].actor == "amy" and entries[0].source == "request"
    assert "proxy-domain" in entries[0].drift_identity
    assert "domain=example.com" in entries[0].drift_identity
