"""GitHub Issues surface -- open (and later close) an issue per Alert, when steadystate is SURE.

The close-the-loop tracker for teams that triage in GitHub: a finding that crosses the bar lands as
an issue your process already runs on -- not just a chat ping. Each Alert maps to ONE issue, keyed
by the Alert's fingerprint embedded as a hidden marker in the body, so a re-scan never files a
duplicate (it leaves the open issue). And the other half of the loop: when a finding **clears**, the
surface **closes** the issue it opened (with a note) -- a scheduled scan closes its own tickets, no
manual cleanup. **"Sure of a problem" is a severity gate**: only high/critical alerts become issues
by default (a dial), so an issue is a real signal, never noise.

Config:
  STEADYSTATE_GITHUB_TOKEN / GITHUB_TOKEN  a token with issues:write (priority that order)
  STEADYSTATE_GITHUB_REPO     owner/name (else parsed from `git remote get-url origin`)
  STEADYSTATE_GITHUB_SEVERITY min severity to file (default high): low|medium|high|critical
  STEADYSTATE_GITHUB_AUTOCLOSE  false/0/no keeps cleared issues open (default: auto-close)
  GITHUB_API_URL              API base (default https://api.github.com)

Outbound only; stdlib urllib, http(s)-gated by ``safe_urlopen``. Honest degrade when unconfigured --
says so once and opens nothing, never pretends it filed.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import subprocess  # noqa: S404 -- argv only, no shell; reads `git remote` for the repo default
import urllib.error
import urllib.request
from collections.abc import Sequence
from typing import TYPE_CHECKING, Any

from .._http import safe_urlopen
from ..probe.solutions import solutions_for_alert
from ..reason.alert import Alert
from ..reason.report import Report

if TYPE_CHECKING:
    from ..reconcile_state import ResolvedFinding

logger = logging.getLogger(__name__)

_LABEL = "steadystate"  # every issue carries this -- so the dedup/close lookup is a cheap list
_SEVERITY_RANK = {"critical": 3, "high": 2, "medium": 1, "low": 0}
# The fingerprint, hidden in the issue body -- the dedup key (GitHub has no correlation_id field).
_MARKER = re.compile(r"<!--\s*steadystate-fp:\s*(\S+)\s*-->")
_DEFAULT_API = "https://api.github.com"


def _falsey(value: str | None) -> bool:
    return (value or "").strip().lower() in {"false", "0", "no", "off"}


def _resolve_repo() -> str | None:
    """``owner/name`` from ``STEADYSTATE_GITHUB_REPO``, else parsed from ``git remote get-url
    origin`` (https or ssh GitHub URL). None when neither resolves."""
    explicit = os.environ.get("STEADYSTATE_GITHUB_REPO")
    if explicit:
        return explicit.strip()
    try:
        url = subprocess.run(  # noqa: S603,S607 -- argv list, no shell; reads the remote URL only
            ["git", "remote", "get-url", "origin"], capture_output=True, text=True, timeout=5
        ).stdout.strip()
    except (subprocess.SubprocessError, OSError):
        return None
    match = re.search(r"github\.com[:/]([^/]+/[^/]+?)(?:\.git)?$", url)
    return match.group(1) if match else None


def _alert_fingerprint(alert: Alert) -> str:
    """A stable per-alert key for dedup: a correlated group's single fingerprint (one issue for the
    whole group), else the first member's (drift / policy / symptom), else a content hash."""
    if alert.correlation_fingerprint:
        return alert.correlation_fingerprint
    for items in (alert.drifts, alert.findings, alert.symptoms):
        if items:
            return items[0].fingerprint
    return hashlib.sha256(f"{alert.environment or ''}|{alert.title}".encode()).hexdigest()


def format_issue(alert: Alert) -> dict:
    """One Alert as a GitHub issue payload (pure + testable). The fingerprint marker in the body is
    the dedup key; the ``steadystate`` + severity labels make the issue easy to find + filter."""
    fp = _alert_fingerprint(alert)
    lines = [alert.why_it_matters]
    if alert.recommended_action:
        lines.append(f"\n**Recommended action:** {alert.recommended_action}")
    if alert.resources:
        lines.append("\n**Resources:** " + ", ".join(alert.resources))
    if alert.environment:
        lines.append(f"\n**Environment:** {alert.environment}")
    if alert.references:
        refs = ", ".join(f"{r.framework} {r.id}" for r in alert.references)
        lines.append(f"\n**References:** {refs}")
    # The runbook, surfaced where the problem lands: if the team authored a fix for this, name it +
    # who vouched, so the issue carries the problem AND your known solution. Read-only -- the issue
    # documents the fix; running it still goes through `approve` + the bound + the audit.
    matched = solutions_for_alert(alert)
    if matched:
        lines.append("\n**Known fix (from your runbook):**")
        for sol in matched:
            action = sol.run or f"{sol.kind} {sol.target}".strip()
            lines.append(f"- `{action}` -- *{sol.name}*, by {sol.author}")
    lines.append(f"\n<!-- steadystate-fp: {fp} -->")
    lines.append("_Opened by steadystate; closed automatically when the finding clears._")
    return {
        "title": f"[steadystate] {alert.title}"[:256],
        "body": "\n".join(line for line in lines if line),
        "labels": [_LABEL, alert.severity.value],
    }


class GithubIssuesSurface:
    """A Surface that opens (and auto-closes) a GitHub issue per Alert over the severity bar. Dedup
    + close are keyed on the fingerprint marker; it only files when sure (the severity gate)."""

    name = "github"

    def __init__(
        self,
        token: str | None = None,
        repo: str | None = None,
        min_severity: str | None = None,
        timeout: float = 15.0,
    ) -> None:
        self.token = (
            token or os.environ.get("STEADYSTATE_GITHUB_TOKEN") or os.environ.get("GITHUB_TOKEN")
        )
        self.repo = repo or _resolve_repo()
        self.min_severity = (
            min_severity or os.environ.get("STEADYSTATE_GITHUB_SEVERITY") or "high"
        ).lower()
        self.autoclose = not _falsey(os.environ.get("STEADYSTATE_GITHUB_AUTOCLOSE"))
        self.api_url = (os.environ.get("GITHUB_API_URL") or _DEFAULT_API).rstrip("/")
        self.timeout = timeout

    def _configured(self) -> bool:
        return bool(self.token and self.repo)

    def _sure(self, alert: Alert) -> bool:
        """The 'sure of a problem' gate: only file an issue for an alert at/above the threshold
        severity (default high). Keeps GitHub for real signals, not every drift."""
        bar = _SEVERITY_RANK.get(self.min_severity, _SEVERITY_RANK["high"])
        return _SEVERITY_RANK.get(alert.severity.value, 0) >= bar

    def emit(self, report: Report, resolved: Sequence[ResolvedFinding] | None = None) -> None:
        if not self._configured():
            logger.warning(
                "GitHub surface enabled but not configured (set STEADYSTATE_GITHUB_TOKEN + "
                "STEADYSTATE_GITHUB_REPO); skipping %d alert(s).",
                len(report.alerts),
            )
            return
        try:  # one cheap list keys both the dedup (don't re-open) and the auto-close
            open_issues = self._open_issues()
        except (urllib.error.URLError, OSError, ValueError) as exc:
            logger.warning("GitHub issue lookup failed: %s; skipping to avoid duplicates.", exc)
            return
        for alert in report.alerts:
            if self._sure(alert) and _alert_fingerprint(alert) not in open_issues:
                self._open(alert)
        # The other half of the loop: a finding that cleared this scan -> close its open issue. A
        # stateful scan passes `resolved`; a stateless one passes none (nothing to close).
        if self.autoclose:
            for finding in resolved or ():
                number = open_issues.get(finding.fingerprint)
                if number is not None:
                    self._close(number, finding)

    def _open(self, alert: Alert) -> None:
        try:
            self._request("POST", f"/repos/{self.repo}/issues", format_issue(alert))
        except (urllib.error.URLError, OSError) as exc:
            logger.warning("GitHub issue create failed: %s", exc)

    def _close(self, number: int, finding: ResolvedFinding) -> None:
        """Comment + close the open issue for a cleared finding -- it closes what it opened."""
        try:
            self._request(
                "POST",
                f"/repos/{self.repo}/issues/{number}/comments",
                {"body": f"steadystate: finding cleared -- {finding.title}. Closing."},
            )
            self._request("PATCH", f"/repos/{self.repo}/issues/{number}", {"state": "closed"})
        except (urllib.error.URLError, OSError) as exc:
            logger.warning("GitHub issue close failed for #%s: %s", number, exc)

    def _open_issues(self) -> dict[str, int]:
        """``{fingerprint: issue_number}`` for OPEN ``steadystate``-labelled issues. PRs (which the
        issues API also returns) are filtered out; an issue without our marker is ignored."""
        raw = self._request(
            "GET", f"/repos/{self.repo}/issues?labels={_LABEL}&state=open&per_page=100"
        )
        out: dict[str, int] = {}
        for item in raw or []:
            if not isinstance(item, dict) or "pull_request" in item:
                continue
            match = _MARKER.search(item.get("body") or "")
            if match:
                out[match.group(1)] = item["number"]
        return out

    def _request(self, method: str, path: str, body: dict | None = None) -> Any:
        data = json.dumps(body).encode("utf-8") if body is not None else None
        request = urllib.request.Request(
            f"{self.api_url}{path}",
            data=data,
            method=method,
            headers={
                "Authorization": f"Bearer {self.token}",  # the only place the token is used
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "steadystate",
                "Content-Type": "application/json",
            },
        )
        with safe_urlopen(request, timeout=self.timeout) as response:
            return json.loads(response.read() or "null")
