"""ServiceNow surface -- open (or update) an Incident per Alert via the Table API.

The ITSM half of "page louder": a drift or malfunction that crosses the bar should land as a
ServiceNow incident your existing triage process already runs on -- not just a chat ping. Each
Alert maps to one incident, keyed by the Alert's fingerprint in ``correlation_id``, so a re-scan
**updates the one open incident** (adds a work note) instead of filing a duplicate every run --
the ITSM analog of PagerDuty's ``dedup_key``. A correlated group rides on its single
``correlation_fingerprint``, so the same workload failing in N places is **one** incident, not N.
A finding whose incident was resolved/closed and then recurs opens a fresh one (the lookup is
scoped to ``active`` records). And the other half of the loop: when a finding **clears**, the
surface **auto-resolves** its open incident (state -> Resolved, with close notes) -- so a
scheduled scan closes tickets it opened, no manual cleanup. Matches on ``correlation_id``, so a
grouped finding's incident resolves when the whole group clears.

Config (HTTP Basic auth against the Table API):
  STEADYSTATE_SERVICENOW_INSTANCE     instance ("dev12345") or a full base URL
  STEADYSTATE_SERVICENOW_USER         the integration user
  STEADYSTATE_SERVICENOW_PASSWORD     that user's password (or token)
  STEADYSTATE_SERVICENOW_TABLE        target table (default "incident")
  STEADYSTATE_SERVICENOW_CLOSE_CODE   close_code for auto-resolve (default "Solved (Permanently)")
  STEADYSTATE_SERVICENOW_AUTOCLOSE    set false/0/no to disable auto-resolve (default on)

Outbound only; stdlib urllib, http(s)-gated by ``safe_urlopen``. Honest degrade when
unconfigured -- says so once and sends nothing, never pretends it delivered.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Sequence
from typing import TYPE_CHECKING

from .._http import safe_urlopen
from ..reason.alert import Alert
from ..reason.report import Report

if TYPE_CHECKING:
    from ..reconcile_state import ResolvedFinding

logger = logging.getLogger(__name__)

# steadystate Severity -> ServiceNow urgency/impact (1 = High, 2 = Medium, 3 = Low). ServiceNow
# derives an incident's Priority from urgency x impact, so setting both is enough.
_SN_URGENCY = {"critical": "1", "high": "1", "medium": "2", "low": "3"}

# ServiceNow incident state for an auto-resolve (6 = Resolved). We resolve rather than Close (7),
# the conventional, reversible step a tool should take -- a human still owns the final close.
_RESOLVED_STATE = "6"


def _falsey(value: str | None) -> bool:
    return (value or "").strip().lower() in {"false", "0", "no", "off"}


def _correlation_id(alert: Alert) -> str:
    """A stable per-alert key for ServiceNow's ``correlation_id`` so a re-scan updates the one
    incident instead of filing a duplicate. A correlated group uses its single group fingerprint
    (one incident for the whole group); otherwise the first member fingerprint (drift / policy /
    symptom); a content hash only if the alert somehow has none."""
    if alert.correlation_fingerprint:
        return alert.correlation_fingerprint
    for items in (alert.drifts, alert.findings, alert.symptoms):
        if items:
            return items[0].fingerprint
    return hashlib.sha256(f"{alert.environment or ''}|{alert.title}".encode()).hexdigest()


def _description(alert: Alert) -> str:
    """The incident body: the reasoning, the fix, what it concerns, and the fingerprint -- so an
    operator working the ticket has the same context the chat/console surfaces show. Pure."""
    lines = [alert.why_it_matters]
    if alert.recommended_action:
        lines.append(f"Recommended action: {alert.recommended_action}")
    if alert.resources:
        lines.append("Resources: " + ", ".join(alert.resources))
    if alert.environment:
        lines.append(f"Environment: {alert.environment}")
    if alert.references:
        lines.append("References: " + ", ".join(f"{r.framework} {r.id}" for r in alert.references))
    lines.append(f"steadystate fingerprint: {_correlation_id(alert)}")
    return "\n".join(line for line in lines if line)


def format_servicenow_incident(alert: Alert) -> dict:
    """One Alert as a ServiceNow Table API incident record. Pure + testable. ``short_description``
    is capped at ServiceNow's 160-char limit; ``correlation_id`` is the dedup key."""
    return {
        "short_description": alert.title[:160],
        "description": _description(alert),
        "urgency": _SN_URGENCY.get(alert.severity.value, "2"),
        "impact": _SN_URGENCY.get(alert.severity.value, "2"),
        "correlation_id": _correlation_id(alert),
    }


class ServiceNowSurface:
    """A Surface that opens (or updates) a ServiceNow incident per Alert via the Table API."""

    name = "servicenow"

    def __init__(
        self,
        instance: str | None = None,
        user: str | None = None,
        password: str | None = None,
        table: str | None = None,
        timeout: float = 10.0,
    ) -> None:
        self.instance = instance or os.environ.get("STEADYSTATE_SERVICENOW_INSTANCE")
        self.user = user or os.environ.get("STEADYSTATE_SERVICENOW_USER")
        self.password = password or os.environ.get("STEADYSTATE_SERVICENOW_PASSWORD")
        self.table = table or os.environ.get("STEADYSTATE_SERVICENOW_TABLE") or "incident"
        self.timeout = timeout
        # Auto-resolve an incident when its finding clears (default on). close_code is instance-
        # configurable; the OOB default works on a stock instance.
        self.autoclose = not _falsey(os.environ.get("STEADYSTATE_SERVICENOW_AUTOCLOSE"))
        self.close_code = (
            os.environ.get("STEADYSTATE_SERVICENOW_CLOSE_CODE") or "Solved (Permanently)"
        )

    def _configured(self) -> bool:
        return bool(self.instance and self.user and self.password)

    def _table_url(self) -> str:
        """The Table API endpoint for this table. ``instance`` may be a bare name (``dev12345``)
        or a full base URL."""
        inst = self.instance or ""
        base = (
            inst if inst.startswith(("http://", "https://")) else f"https://{inst}.service-now.com"
        )
        return f"{base.rstrip('/')}/api/now/table/{self.table}"

    def _auth_header(self) -> str:
        token = base64.b64encode(f"{self.user}:{self.password}".encode()).decode("ascii")
        return f"Basic {token}"

    def emit(self, report: Report, resolved: Sequence[ResolvedFinding] | None = None) -> None:
        if not self._configured():
            logger.warning(
                "ServiceNow surface enabled but not configured (set STEADYSTATE_SERVICENOW_INSTANCE"
                ", _USER, _PASSWORD); skipping %d alert(s).",
                len(report.alerts),
            )
            return
        for alert in report.alerts:
            self._upsert(format_servicenow_incident(alert))
        # The other half of the loop: a finding that cleared this scan -> resolve its open incident,
        # so the surface closes tickets it opened. Stateful scans pass `resolved`; a stateless one
        # passes none, and there's nothing to close.
        if self.autoclose:
            for finding in resolved or ():
                self._resolve_incident(finding)

    def _upsert(self, fields: dict) -> None:
        """Create the incident, or -- if one is already open for this correlation_id -- add a work
        note to that one. Conservative on a failed lookup: skip rather than risk a duplicate."""
        correlation_id = fields["correlation_id"]
        try:
            sys_id = self._find_open(correlation_id)
        except (urllib.error.URLError, OSError, ValueError) as exc:
            logger.warning(
                "ServiceNow lookup failed for %s: %s; skipping to avoid a duplicate.",
                correlation_id,
                exc,
            )
            return
        try:
            if sys_id is not None:
                note = (
                    f"steadystate: still present as of this scan -- {fields['short_description']}"
                )
                self._request("PATCH", f"{self._table_url()}/{sys_id}", {"work_notes": note})
            else:
                self._request("POST", self._table_url(), fields)
        except (urllib.error.URLError, OSError) as exc:
            logger.warning("ServiceNow delivery failed: %s", exc)

    def _resolve_incident(self, finding: ResolvedFinding) -> None:
        """Auto-resolve the open incident for a cleared finding (state -> Resolved, with close
        notes). Matches on ``correlation_id`` -- the same key the incident was opened with -- so a
        grouped finding's incident resolves when the group clears. No open incident -> nothing to
        do. Best-effort: a failed lookup/resolve is logged, never raised."""
        try:
            sys_id = self._find_open(finding.fingerprint)
        except (urllib.error.URLError, OSError, ValueError) as exc:
            logger.warning("ServiceNow resolve lookup failed for %s: %s", finding.fingerprint, exc)
            return
        if sys_id is None:  # no open incident for this finding (never filed, or already closed)
            return
        body = {
            "state": _RESOLVED_STATE,
            "close_code": self.close_code,
            "close_notes": f"steadystate: finding cleared -- {finding.title}",
        }
        try:
            self._request("PATCH", f"{self._table_url()}/{sys_id}", body)
        except (urllib.error.URLError, OSError) as exc:
            logger.warning("ServiceNow resolve failed: %s", exc)

    def _find_open(self, correlation_id: str) -> str | None:
        """The sys_id of an existing *active* incident for this correlation_id, or None. Scoped to
        active records so a resolved-then-recurring finding opens a fresh incident."""
        query = urllib.parse.urlencode(
            {
                "sysparm_query": f"correlation_id={correlation_id}^active=true",
                "sysparm_limit": "1",
                "sysparm_fields": "sys_id",
            }
        )
        raw = self._request("GET", f"{self._table_url()}?{query}")
        results = (json.loads(raw or "{}") or {}).get("result") or []
        return results[0]["sys_id"] if results else None

    def _request(self, method: str, url: str, body: dict | None = None) -> str:
        data = json.dumps(body).encode("utf-8") if body is not None else None
        request = urllib.request.Request(
            url,
            data=data,
            method=method,
            headers={
                "Authorization": self._auth_header(),
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )
        with safe_urlopen(request, timeout=self.timeout) as response:
            return response.read().decode("utf-8")
