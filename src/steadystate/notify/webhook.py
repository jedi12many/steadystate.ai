"""Generic webhook surface -- POST each Alert as provider-agnostic JSON to any HTTP endpoint.

The escape hatch for everything steadystate has no native surface for: Opsgenie, Jira, an internal
event bus (ServiceNow has its own native ``--to servicenow``). Point ``STEADYSTATE_WEBHOOK_URL`` at
a receiver (or a small middleware that maps the event onto your tool's API) and every surfaced
Alert arrives as one structured JSON event.
Outbound only; stdlib urllib, http(s)-gated by `safe_urlopen`.

Honest degrade: no URL configured -> says so once and sends nothing, never pretends it delivered.
"""

from __future__ import annotations

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


def _fingerprints(alert: Alert) -> list[str]:
    """Every durable finding key in this alert (drift / policy / symptom) -- so a downstream
    consumer can dedupe an incident across scans the same way the state store does."""
    return [
        item.fingerprint
        for items in (alert.drifts, alert.findings, alert.symptoms)
        for item in items
    ]


def _source(alert: Alert) -> str | None:
    for items in (alert.drifts, alert.findings, alert.symptoms):
        if items:
            return items[0].provenance.source
    return None


def alert_event(alert: Alert) -> dict:
    """One Alert as a provider-agnostic JSON event. Pure + testable -- the contract a webhook
    consumer codes against, stable across surfaces (it's the same shape the others render)."""
    return {
        "title": alert.title,
        "severity": alert.severity.value,
        "tier": alert.layer.value,
        "why_it_matters": alert.why_it_matters,
        "recommended_action": alert.recommended_action,
        "remediable": alert.remediable,
        "source": _source(alert),
        "environment": alert.environment,
        "resources": alert.resources,
        "references": [{"framework": r.framework, "id": r.id} for r in alert.references],
        "fingerprints": _fingerprints(alert),
        "llm_backed": alert.llm_backed,
    }


class WebhookSurface:
    """A Surface that POSTs each Alert as JSON to a configured endpoint."""

    name = "webhook"

    def __init__(self, url: str | None = None, timeout: float = 10.0) -> None:
        self.url = url or os.environ.get("STEADYSTATE_WEBHOOK_URL")
        self.timeout = timeout

    def emit(self, report: Report, resolved: Sequence[ResolvedFinding] | None = None) -> None:
        if not self.url:
            logger.warning(
                "webhook surface enabled but no endpoint configured "
                "(set STEADYSTATE_WEBHOOK_URL or pass url); skipping %d alert(s).",
                len(report.alerts),
            )
            return
        for alert in report.alerts:
            # `producer` is who sent it (steadystate); the event's own `source` is which backend
            # drifted (terraform/k8s/...) -- distinct keys so neither clobbers the other.
            self._post({"producer": "steadystate", "event": "alert", **alert_event(alert)})

    def _post(self, payload: dict) -> None:
        assert self.url is not None  # emit() guards a configured URL
        data = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            self.url, data=data, headers={"Content-Type": "application/json"}, method="POST"
        )
        try:
            with safe_urlopen(request, timeout=self.timeout) as response:
                response.read()
        except (urllib.error.URLError, OSError) as exc:
            logger.warning("webhook delivery failed: %s", exc)
