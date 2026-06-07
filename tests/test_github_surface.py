"""The GitHub Issues surface: open an issue only when SURE (severity gate), one issue per finding
(dedup by the fingerprint marker), and close it when the finding clears (the other half of the
loop). The GitHub API is faked with a local server -- no real GitHub, no token."""

from __future__ import annotations

import contextlib
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from steadystate.notify.github import GithubIssuesSurface, format_issue
from steadystate.reason.alert import Alert, Severity
from steadystate.reconcile_state import ResolvedFinding


def _alert(title: str, severity: Severity, fp: str) -> Alert:
    # the alert's correlation_fingerprint is the dedup key the surface keys issues on
    return Alert(
        title=title,
        severity=severity,
        drifts=[],
        why_it_matters="because",
        correlation_fingerprint=fp,
    )


class _FakeGitHub:
    """Records calls + holds the open-issue list, so we can assert gate/dedup/close behaviour."""

    def __init__(self) -> None:
        self.calls: list[tuple] = []
        self.open: list[dict] = []
        self._next = 100

    def handler(self):
        gh = self

        class _H(BaseHTTPRequestHandler):
            def _send(self, obj, code=200):
                body = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(body)

            def _body(self):
                n = int(self.headers.get("Content-Length", 0))
                return json.loads(self.rfile.read(n) or "{}")

            def do_GET(self):  # noqa: N802
                gh.calls.append(("GET", self.path))
                self._send(gh.open)  # list open issues

            def do_POST(self):  # noqa: N802
                body = self._body()
                gh.calls.append(("POST", self.path, body))
                if self.path.endswith("/issues"):
                    gh._next += 1
                    issue = {"number": gh._next, "body": body["body"], "labels": body["labels"]}
                    gh.open.append(issue)
                    self._send(issue, 201)
                else:  # a comment
                    self._send({}, 201)

            def do_PATCH(self):  # noqa: N802
                gh.calls.append(("PATCH", self.path, self._body()))
                self._send({})

            def log_message(self, *_a):
                return

        return _H


@contextlib.contextmanager
def _github(monkeypatch):
    fake = _FakeGitHub()
    httpd = HTTPServer(("127.0.0.1", 0), fake.handler())
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    monkeypatch.setenv("GITHUB_API_URL", f"http://127.0.0.1:{httpd.server_address[1]}")
    monkeypatch.setenv("STEADYSTATE_GITHUB_TOKEN", "t")
    monkeypatch.setenv("STEADYSTATE_GITHUB_REPO", "acme/infra")
    try:
        yield fake
    finally:
        httpd.shutdown()


def _posts_to_issues(fake: _FakeGitHub) -> list[dict]:
    return [c[2] for c in fake.calls if c[0] == "POST" and c[1].endswith("/issues")]


# -- the pure payload -----------------------------------------------------------


def test_format_issue_embeds_the_fingerprint_marker_and_labels():
    alert = _alert("gateway down", Severity.HIGH, "f" * 64)
    issue = format_issue(alert)
    assert issue["title"].startswith("[steadystate] ") and "steadystate" in issue["labels"]
    assert "high" in issue["labels"]
    assert f"<!-- steadystate-fp: {'f' * 64} -->" in issue["body"]  # the dedup key


# -- the lifecycle --------------------------------------------------------------


class _Rep:
    def __init__(self, alerts):
        self.alerts = alerts


def test_only_a_sure_alert_files_an_issue(monkeypatch):
    with _github(monkeypatch) as fake:
        hi = _alert("gateway is CrashLoopBackOff", Severity.HIGH, "a" * 64)
        lo = _alert("a label drifted", Severity.LOW, "b" * 64)
        GithubIssuesSurface().emit(_Rep([hi, lo]))
    issues = _posts_to_issues(fake)
    assert len(issues) == 1  # the LOW alert is below the bar -- not filed (sure-of-a-problem gate)
    assert "CrashLoopBackOff" in issues[0]["title"]


def test_a_rescan_does_not_open_a_duplicate(monkeypatch):
    with _github(monkeypatch) as fake:
        hi = _alert("gateway down", Severity.HIGH, "a" * 64)
        surface = GithubIssuesSurface()
        surface.emit(_Rep([hi]))  # opens #101
        before = len(_posts_to_issues(fake))
        surface.emit(_Rep([hi]))  # the open issue exists -> no new one
    assert before == 1 and len(_posts_to_issues(fake)) == 1  # deduped by the fingerprint marker


def test_a_cleared_finding_closes_its_issue(monkeypatch):
    with _github(monkeypatch) as fake:
        fp = "a" * 64
        surface = GithubIssuesSurface()
        surface.emit(_Rep([_alert("gateway down", Severity.HIGH, fp)]))  # opens an issue
        opened = fake.open[0]["number"]
        # next scan: nothing wrong, but the finding resolved -> close its issue
        surface.emit(_Rep([]), resolved=[ResolvedFinding(fingerprint=fp, title="gateway down")])
    patches = [c for c in fake.calls if c[0] == "PATCH"]
    assert patches and patches[-1][2] == {"state": "closed"}  # closed the issue it opened
    assert f"/issues/{opened}" in patches[-1][1]


def test_unconfigured_is_a_quiet_no_op(monkeypatch):
    monkeypatch.delenv("STEADYSTATE_GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.setenv("STEADYSTATE_GITHUB_REPO", "acme/infra")
    # no token -> not configured -> emits nothing, never raises
    GithubIssuesSurface().emit(_Rep([_alert("x", Severity.HIGH, "a" * 64)]))
