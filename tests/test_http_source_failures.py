"""HTTP-fetching drift sources (ArgoCD, Rancher) must not crash or hang the scan (M2).

`safe_urlopen` was called with no timeout (block forever) and the JSON/HTTP errors weren't caught,
so a 401/500 or a hung server took the scan down with a raw traceback. The fetch now routes through
`fetch_json`: a hard timeout + every failure converted to a clean `SourceError` (the urllib
parallel to M1's `run_tool`).
"""

from __future__ import annotations

import urllib.error
import urllib.request

import pytest

from steadystate.sources import base
from steadystate.sources.base import SourceError, fetch_json


class _FakeResp:
    def __init__(self, body: bytes) -> None:
        self._body = body

    def __enter__(self) -> _FakeResp:
        return self

    def __exit__(self, *exc: object) -> bool:
        return False

    def read(self) -> bytes:
        return self._body


def _raise(exc):
    def boom(*args, **kwargs):
        raise exc

    return boom


# -- fetch_json: every failure mode becomes a SourceError ----------------------


def test_fetch_json_http_error_surfaces_the_code(monkeypatch):
    monkeypatch.setattr(
        base,
        "safe_urlopen",
        _raise(urllib.error.HTTPError("http://x", 401, "Unauthorized", {}, None)),
    )
    with pytest.raises(SourceError, match="HTTP 401"):
        fetch_json(urllib.request.Request("http://x"), timeout=5, tool="argocd")


def test_fetch_json_unreachable_server(monkeypatch):
    monkeypatch.setattr(base, "safe_urlopen", _raise(urllib.error.URLError("connection refused")))
    with pytest.raises(SourceError, match="unreachable"):
        fetch_json("http://x", timeout=5, tool="rancher")


def test_fetch_json_timeout_is_unreachable_not_a_crash(monkeypatch):
    monkeypatch.setattr(base, "safe_urlopen", _raise(TimeoutError("timed out")))
    with pytest.raises(SourceError, match="unreachable"):
        fetch_json("http://x", timeout=5, tool="argocd")


def test_fetch_json_rejects_a_non_json_body(monkeypatch):
    monkeypatch.setattr(base, "safe_urlopen", lambda *a, **k: _FakeResp(b"<html>503</html>"))
    with pytest.raises(SourceError, match="no parseable JSON"):
        fetch_json("http://x", timeout=5, tool="argocd")


def test_fetch_json_passes_the_timeout_through(monkeypatch):
    seen = {}

    def fake(request, *, timeout):
        seen["timeout"] = timeout
        return _FakeResp(b"{}")

    monkeypatch.setattr(base, "safe_urlopen", fake)
    fetch_json("http://x", timeout=9.5, tool="argocd")
    assert seen["timeout"] == 9.5  # the hang guard is actually wired


# -- each live source raises SourceError, not a raw traceback ------------------


def test_argocd_source_raises_sourceerror_on_http_error(monkeypatch):
    from steadystate.sources.argocd import ArgoCDSource

    monkeypatch.setattr(
        base, "safe_urlopen", _raise(urllib.error.HTTPError("http://x", 500, "err", {}, None))
    )
    with pytest.raises(SourceError):
        ArgoCDSource(app_name="web", base_url="http://argo").collect_drift()


def test_rancher_source_raises_sourceerror_when_unreachable(monkeypatch):
    from steadystate.sources.rancher import RancherSource

    monkeypatch.setattr(base, "safe_urlopen", _raise(urllib.error.URLError("refused")))
    with pytest.raises(SourceError):
        RancherSource(gitrepo_name="repo", base_url="http://rancher").collect_drift()
