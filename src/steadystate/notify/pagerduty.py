"""PagerDuty surface -- open an incident per Alert via the Events API v2.

Fits the "page louder" story: a drift that breaches a PromQL bar *right now* (`--enrich
prometheus`) should open an incident, not just post to a channel. Each Alert becomes a `trigger`
event keyed by the Alert's fingerprint as PagerDuty's ``dedup_key`` -- so re-scanning the same
drift updates the one open incident instead of spamming new ones (and a resolved finding could
later auto-resolve it, a follow-up).

Needs ``STEADYSTATE_PAGERDUTY_ROUTING_KEY`` (an Events API v2 integration key). Outbound only;
stdlib urllib, http(s)-gated. Honest degrade when unconfigured.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import urllib.error
import urllib.request
from collections.abc import Sequence
from typing import TYPE_CHECKING

from .._http import safe_urlopen
from ..reason.alert import Alert
from ..reason.report import Report

if TYPE_CHECKING:
    from ..reconcile_state import ResolvedFinding

logger = logging.getLogger(__name__)

_ENDPOINT = "https://events.pagerduty.com/v2/enqueue"
# steadystate Severity -> PagerDuty Events API v2 severity vocabulary.
_PD_SEVERITY = {"low": "info", "medium": "warning", "high": "error", "critical": "critical"}


def _dedup_key(alert: Alert) -> str:
    """A stable per-alert key so PagerDuty folds repeated triggers into one incident. The first
    finding fingerprint (drift / policy / symptom); a content hash only if the alert has none."""
    for items in (alert.drifts, alert.findings, alert.symptoms):
        if items:
            return items[0].fingerprint
    return hashlib.sha256(f"{alert.environment or ''}|{alert.title}".encode()).hexdigest()


def format_pagerduty_event(alert: Alert, routing_key: str) -> dict:
    """A PagerDuty Events API v2 ``trigger`` payload for one Alert. Pure + testable."""
    return {
        "routing_key": routing_key,
        "event_action": "trigger",
        "dedup_key": _dedup_key(alert),
        "payload": {
            "summary": alert.title[:1024],  # PD caps the summary at 1024 chars
            "source": alert.resource_label() or "steadystate",
            "severity": _PD_SEVERITY.get(alert.severity.value, "error"),
            "custom_details": {
                "why_it_matters": alert.why_it_matters,
                "recommended_action": alert.recommended_action,
                "resources": alert.resources,
                "environment": alert.environment,
                "references": [f"{r.framework} {r.id}" for r in alert.references],
                "remediable": alert.remediable,
            },
        },
    }


class PagerDutySurface:
    """A Surface that opens a PagerDuty incident per Alert via the Events API v2."""

    name = "pagerduty"

    def __init__(self, routing_key: str | None = None, timeout: float = 10.0) -> None:
        self.routing_key = routing_key or os.environ.get("STEADYSTATE_PAGERDUTY_ROUTING_KEY")
        self.timeout = timeout

    def emit(self, report: Report, resolved: Sequence[ResolvedFinding] | None = None) -> None:
        if not self.routing_key:
            logger.warning(
                "PagerDuty surface enabled but no routing key "
                "(set STEADYSTATE_PAGERDUTY_ROUTING_KEY); skipping %d alert(s).",
                len(report.alerts),
            )
            return
        for alert in report.alerts:
            self._post(format_pagerduty_event(alert, self.routing_key))

    def _post(self, payload: dict) -> None:
        data = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            _ENDPOINT, data=data, headers={"Content-Type": "application/json"}, method="POST"
        )
        try:
            with safe_urlopen(request, timeout=self.timeout) as response:
                response.read()
        except (urllib.error.URLError, OSError) as exc:
            logger.warning("PagerDuty delivery failed: %s", exc)
