"""`runs` + `dispatch` -- the agent repo's workflows as the agent's own instruments. These pin the
repo resolution (env > config > the GitHub surface's), the read view (`runs` renders status/branch/
when/link; honest one-liners for no repo / no token / an API miss), the dispatch scoping (the repo
is ALWAYS the agent repo -- the caller only picks the workflow file), the grammar (inputs ride
verbatim, never flag-eaten; bare `dispatch` isn't actionable), the effect tiering (`runs` is
read-only everywhere; `dispatch` is effectful -- NL echoes it, MCP needs the write grant), and the
audit (who dispatched what lands in history, success or failure)."""

from __future__ import annotations

import json

import pytest

import steadystate.act.workflow as workflow_mod
from steadystate.act.workflow import agent_repo, dispatch_named, list_runs
from steadystate.inbound.base import DISPATCH, RUNS, Command, command_from_text, tool_schema
from steadystate.inbound.mcp import mcp_tools
from steadystate.state import StateStore
from steadystate.verbs import run_command


@pytest.fixture
def _agent_repo(monkeypatch):
    monkeypatch.setenv("STEADYSTATE_WORKFLOWS_REPO", "acme/agent-repo")
    monkeypatch.setenv("STEADYSTATE_GITHUB_TOKEN", "tok")


class _Resp:
    def __init__(self, body: bytes = b"{}") -> None:
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        return self._body


# -- repo resolution ---------------------------------------------------------------------------


def test_agent_repo_env_beats_config_beats_github_fallback(tmp_path, monkeypatch):
    monkeypatch.delenv("STEADYSTATE_WORKFLOWS_REPO", raising=False)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("steadystate.notify.github._resolve_repo", lambda: "acme/from-origin")
    assert agent_repo() == "acme/from-origin"  # the fallback: the repo the listener runs from
    (tmp_path / "steadystate").mkdir()
    (tmp_path / "steadystate" / "config.toml").write_text('[workflows]\nrepo = "acme/agent"\n')
    assert agent_repo() == "acme/agent"  # committed config beats the fallback
    monkeypatch.setenv("STEADYSTATE_WORKFLOWS_REPO", "acme/override")
    assert agent_repo() == "acme/override"  # env beats config (12-factor)


# -- runs: the read view -----------------------------------------------------------------------


def test_runs_renders_recent_run_history(_agent_repo, monkeypatch):
    payload = {
        "workflow_runs": [
            {
                "path": ".github/workflows/nightly-scan.yml",
                "status": "completed",
                "conclusion": "success",
                "head_branch": "main",
                "updated_at": "2026-06-10T05:00:12Z",
                "html_url": "https://github.com/acme/agent-repo/actions/runs/1",
            },
            {
                "path": ".github/workflows/redeploy.yml",
                "status": "in_progress",
                "conclusion": None,
                "head_branch": "main",
                "updated_at": "2026-06-10T06:00:00Z",
                "html_url": "https://github.com/acme/agent-repo/actions/runs/2",
            },
        ]
    }
    seen: dict = {}

    def fake_urlopen(request, timeout=0):
        seen["url"] = request.full_url
        return _Resp(json.dumps(payload).encode())

    monkeypatch.setattr(workflow_mod, "safe_urlopen", fake_urlopen)
    out = list_runs()
    assert "acme/agent-repo" in seen["url"] and "/actions/runs?" in seen["url"]
    assert "nightly-scan.yml" in out and "success" in out  # completed -> its conclusion
    assert "redeploy.yml" in out and "in_progress" in out  # not finished -> its status
    assert "https://github.com/acme/agent-repo/actions/runs/1" in out  # clickable


def test_runs_scopes_to_one_workflow(_agent_repo, monkeypatch):
    seen: dict = {}

    def fake_urlopen(request, timeout=0):
        seen["url"] = request.full_url
        return _Resp(json.dumps({"workflow_runs": []}).encode())

    monkeypatch.setattr(workflow_mod, "safe_urlopen", fake_urlopen)
    out = list_runs("nightly-scan.yml")
    assert "/actions/workflows/nightly-scan.yml/runs?" in seen["url"]
    assert "no runs for nightly-scan.yml" in out  # an empty history says so, plainly


def test_runs_misses_are_honest_one_liners(monkeypatch, tmp_path):
    monkeypatch.delenv("STEADYSTATE_WORKFLOWS_REPO", raising=False)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("steadystate.notify.github._resolve_repo", lambda: None)
    assert "no workflows repo configured" in list_runs()
    monkeypatch.setenv("STEADYSTATE_WORKFLOWS_REPO", "acme/agent-repo")
    monkeypatch.delenv("STEADYSTATE_GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    assert "needs a token" in list_runs()


# -- dispatch: scoped to the agent repo --------------------------------------------------------


def test_dispatch_named_always_targets_the_agent_repo(_agent_repo, monkeypatch):
    seen: dict = {}
    monkeypatch.setattr(
        workflow_mod, "dispatch_workflow", lambda spec: seen.update(spec=spec) or (True, "ok")
    )
    ok, _ = dispatch_named("redeploy.yml@staging", ["cluster=prod"])
    assert ok
    assert (seen["spec"].owner, seen["spec"].repo) == ("acme", "agent-repo")
    assert seen["spec"].workflow == "redeploy.yml" and seen["spec"].ref == "staging"
    assert seen["spec"].inputs == {"cluster": "prod"}
    # A caller passing a path can't escape the repo -- the path only names the FILE within it.
    dispatch_named("other/repo/x.yml", [])
    assert (seen["spec"].owner, seen["spec"].repo) == ("acme", "agent-repo")
    assert seen["spec"].workflow == "x.yml"


# -- the grammar + effect tiering --------------------------------------------------------------


def test_dispatch_inputs_ride_verbatim_and_bare_dispatch_is_not_actionable():
    command = command_from_text("dispatch redeploy.yml cluster=prod note=json", "amy")
    assert command == Command(
        DISPATCH, "amy", "redeploy.yml", argument2="cluster=prod note=json"
    )  # 'json' stays an input value, never eaten as a flag
    assert command_from_text("dispatch", "amy") is None
    bare_runs = command_from_text("runs", "amy")
    assert bare_runs is not None and bare_runs.verb == RUNS and bare_runs.argument == ""


def test_runs_is_read_only_and_dispatch_needs_the_mcp_write_grant():
    effects = {t["name"]: t["effect"] for t in tool_schema()["tools"]}
    assert effects[RUNS] == "read-only"
    assert effects[DISPATCH] == "external-send"  # effectful -> NL echoes it to confirm
    read_only_tools = {t["name"] for t in mcp_tools(write=False)}
    assert RUNS in read_only_tools and DISPATCH not in read_only_tools
    assert DISPATCH in {t["name"] for t in mcp_tools(write=True)}


# -- the audit ---------------------------------------------------------------------------------


def test_a_dispatch_is_audited_with_who_asked(_agent_repo, monkeypatch, tmp_path):
    monkeypatch.setattr(
        "steadystate.act.workflow.dispatch_workflow", lambda spec: (True, "dispatched x")
    )
    state = str(tmp_path / "state.db")
    reply = run_command(Command(DISPATCH, "jeff", "redeploy.yml", argument2="cluster=prod"), state)
    assert reply == "dispatched x"
    with StateStore(state) as store:
        entries = store.audit_log()
    assert len(entries) == 1
    entry = entries[0]
    assert entry.actor == "jeff" and entry.source == "workflow"
    assert "redeploy.yml" in entry.drift_identity and "cluster=prod" in entry.drift_identity


def test_a_failed_dispatch_is_audited_too(_agent_repo, monkeypatch, tmp_path):
    monkeypatch.setattr(
        "steadystate.act.workflow.dispatch_workflow", lambda spec: (False, "failed (404)")
    )
    state = str(tmp_path / "state.db")
    reply = run_command(Command(DISPATCH, "jeff", "gone.yml"), state)
    assert "404" in reply
    with StateStore(state) as store:
        entries = store.audit_log()
    assert len(entries) == 1 and "failed" in entries[0].detail
