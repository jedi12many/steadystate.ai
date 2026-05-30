"""The audited HTTP gate (_http.safe_urlopen): every outbound urlopen is restricted to http(s)."""

from __future__ import annotations

import urllib.request

import pytest

from steadystate._http import safe_urlopen


def test_rejects_non_http_schemes_before_opening(monkeypatch):
    opened: list = []
    monkeypatch.setattr("urllib.request.urlopen", lambda *a, **k: opened.append(a) or "resp")
    for bad in ("file:///etc/passwd", "ftp://h/x", "gopher://h", "/etc/passwd", "data:text/x,hi"):
        with pytest.raises(ValueError, match="non-http"):
            safe_urlopen(bad)
    assert opened == []  # the socket layer is never reached for a disallowed scheme


def test_allows_http_and_https_and_passes_target_and_timeout(monkeypatch):
    seen: dict = {}

    def fake(target, timeout=None):
        seen["target"], seen["timeout"] = target, timeout
        return "resp"

    monkeypatch.setattr("urllib.request.urlopen", fake)
    assert safe_urlopen("https://example.com/hook", timeout=5) == "resp"
    assert seen == {"target": "https://example.com/hook", "timeout": 5}
    assert safe_urlopen("http://localhost:9090/api") == "resp"  # plain http allowed too


def test_a_request_object_is_scheme_checked_the_same_way(monkeypatch):
    monkeypatch.setattr("urllib.request.urlopen", lambda target, timeout=None: ("ok", target))
    ok = urllib.request.Request("https://api.example.com", data=b"{}", method="POST")
    assert safe_urlopen(ok)[0] == "ok"
    bad = urllib.request.Request("file:///etc/shadow")  # a Request can't smuggle a file:// URL
    with pytest.raises(ValueError, match="non-http"):
        safe_urlopen(bad)
