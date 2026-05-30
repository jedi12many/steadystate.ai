"""Grafana surface -- outbound v1.

Posts one annotation per Alert to Grafana's HTTP API so alerts show up as markers
on dashboards. The base URL comes from the constructor or the GRAFANA_URL env var,
and the API token from the constructor or GRAFANA_TOKEN. Uses stdlib urllib so we
take on no new dependency.

Honest degrade: if the URL or token isn't configured we say so once and do nothing,
rather than pretending we delivered anything.
"""

from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request
from collections.abc import Sequence
from datetime import datetime
from typing import TYPE_CHECKING

from ..reason.alert import Alert
from ..reason.report import Report

if TYPE_CHECKING:
    from ..reconcile_state import ResolvedFinding

logger = logging.getLogger(__name__)


def format_grafana_annotation(alert: Alert, now: datetime | None = None) -> dict:
    """Build the annotation payload for one Alert. Pure + testable (no network).

    Grafana annotation times are epoch milliseconds. ``now`` overrides the time
    for tests; otherwise we use the Alert's own created_at.
    """
    when = now if now is not None else alert.created_at
    time_ms = int(when.timestamp() * 1000)

    tags = ["steadystate", f"severity:{alert.severity.value}"]
    if alert.flagged_by is not None:  # only when a domain pack flagged it
        tags.append(f"flagged_by:{alert.flagged_by}")
    if alert.drifts:  # source lives on the first drift's provenance, if we have one
        tags.append(f"source:{alert.drifts[0].provenance.source}")
    elif alert.findings:  # a standing-policy Alert has no drift; source is on the finding
        tags.append(f"source:{alert.findings[0].provenance.source}")

    return {
        "time": time_ms,
        "tags": tags,
        "text": f"{alert.title} — {alert.why_it_matters}",
    }


class GrafanaSurface:
    """A Surface that POSTs each Alert as an annotation to Grafana's API."""

    name = "grafana"

    def __init__(
        self,
        base_url: str | None = None,
        token: str | None = None,
        timeout: float = 10.0,
    ) -> None:
        self.base_url = base_url or os.environ.get("GRAFANA_URL")
        self.token = token or os.environ.get("GRAFANA_TOKEN")
        self.timeout = timeout

    def emit(self, report: Report, resolved: Sequence[ResolvedFinding] | None = None) -> None:
        # Page only on Alerts -- the top tier. Events/signals stay on the console.
        # ``resolved`` is console-first in Phase 0; Grafana ignores it for now.
        if not self.base_url or not self.token:
            logger.warning(
                "Grafana surface enabled but not configured "
                "(set GRAFANA_URL and GRAFANA_TOKEN or pass base_url/token); "
                "skipping %d alert(s).",
                len(report.alerts),
            )
            return
        for alert in report.alerts:
            self._post(format_grafana_annotation(alert))

    def _post(self, payload: dict) -> None:
        assert self.base_url is not None and self.token is not None  # emit() guards config
        url = f"{self.base_url.rstrip('/')}/api/annotations"
        data = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=data,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.token}",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                response.read()
        except (urllib.error.URLError, OSError) as exc:
            logger.warning("Grafana delivery failed: %s", exc)
