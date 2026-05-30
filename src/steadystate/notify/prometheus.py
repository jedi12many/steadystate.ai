"""Prometheus surface -- outbound v1.

A one-shot scan is a batch job, so we push a snapshot to a Prometheus Pushgateway
rather than expose a scrape endpoint. The gateway URL comes from the constructor
or the PROMETHEUS_PUSHGATEWAY_URL env var. Uses stdlib urllib so we take on no new
dependency.

We PUT to ``{pushgateway_url}/metrics/job/{job}``: PUT replaces the job's whole
group, which is exactly the right semantics for a fresh scan snapshot (the previous
scan's series for this job are dropped, not merged).

Honest degrade: if no gateway is configured we say so once and do nothing, rather
than pretending we delivered anything.
"""

from __future__ import annotations

import logging
import os
import time
import urllib.error
import urllib.request
from collections.abc import Sequence
from typing import TYPE_CHECKING

from ..reason.cost import cost_usd, roll_up
from ..reason.report import Report

if TYPE_CHECKING:
    from ..reconcile_state import ResolvedFinding

logger = logging.getLogger(__name__)

# Every severity, always emitted (0 when none) so a series never vanishes between
# scrapes -- a disappearing gauge reads as "no data", not "zero alerts".
_SEVERITIES = ("low", "medium", "high", "critical")


def _escape_label_value(value: str) -> str:
    """Escape a label value per the Prometheus text exposition rules."""
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def format_prometheus_metrics(
    report: Report,
    resolved: Sequence[ResolvedFinding] | None = None,
    now: float | None = None,
) -> str:
    """Render a scan as Prometheus text exposition format. Pure + testable (no network).

    ``now`` defaults to the current unix time; tests pin it for a stable timestamp.
    """
    if now is None:
        now = time.time()

    by_severity = {sev: 0 for sev in _SEVERITIES}
    for alert in report.alerts:
        sev = alert.severity.value
        if sev in by_severity:  # defensive: only the known low/medium/high/critical
            by_severity[sev] += 1

    lines: list[str] = []

    lines.append("# HELP steadystate_alerts Correlated alerts in the last scan, by severity.")
    lines.append("# TYPE steadystate_alerts gauge")
    for sev in _SEVERITIES:  # every severity, including zeros, low cardinality
        label = _escape_label_value(sev)
        lines.append(f'steadystate_alerts{{severity="{label}"}} {by_severity[sev]}')

    lines.append("# HELP steadystate_alerts_total Total correlated alerts in the last scan.")
    lines.append("# TYPE steadystate_alerts_total gauge")
    lines.append(f"steadystate_alerts_total {len(report.alerts)}")

    lines.append("# HELP steadystate_signals_total Counted signals below the event bar.")
    lines.append("# TYPE steadystate_signals_total gauge")
    lines.append(f"steadystate_signals_total {report.signal_count}")

    lines.append("# HELP steadystate_resolved_total Findings that cleared since the last scan.")
    lines.append("# TYPE steadystate_resolved_total gauge")
    lines.append(f"steadystate_resolved_total {len(resolved or [])}")

    lines.append("# HELP steadystate_last_scan_timestamp_seconds Unix time of this scan.")
    lines.append("# TYPE steadystate_last_scan_timestamp_seconds gauge")
    lines.append(f"steadystate_last_scan_timestamp_seconds {now}")

    # LLM spend for this scan: a top-line total (always emitted, 0 when no model was used)
    # plus a per-caller breakdown. Priced from the scan's recorded token counts.
    total_cost = sum(cost_usd(c) for c in report.llm_calls)
    lines.append(
        "# HELP steadystate_llm_cost_usd_total Estimated USD spent on LLM calls this scan."
    )
    lines.append("# TYPE steadystate_llm_cost_usd_total gauge")
    lines.append(f"steadystate_llm_cost_usd_total {total_cost}")

    lines.append("# HELP steadystate_llm_calls_total LLM calls made this scan (incl. failures).")
    lines.append("# TYPE steadystate_llm_calls_total gauge")
    lines.append(f"steadystate_llm_calls_total {len(report.llm_calls)}")

    lines.append("# HELP steadystate_llm_cost_usd Estimated USD spent this scan, by caller.")
    lines.append("# TYPE steadystate_llm_cost_usd gauge")
    for row in roll_up(report.llm_calls):  # only callers that actually spent this scan
        label = _escape_label_value(row.caller)
        lines.append(f'steadystate_llm_cost_usd{{caller="{label}"}} {row.cost_usd}')

    return "\n".join(lines) + "\n"  # exposition format ends with a trailing newline


class PrometheusSurface:
    """A Surface that PUTs a scan-snapshot metric group to a Prometheus Pushgateway."""

    name = "prometheus"

    def __init__(
        self,
        pushgateway_url: str | None = None,
        job: str = "steadystate",
        timeout: float = 10.0,
    ) -> None:
        self.pushgateway_url = pushgateway_url or os.environ.get("PROMETHEUS_PUSHGATEWAY_URL")
        self.job = job
        self.timeout = timeout

    def emit(self, report: Report, resolved: Sequence[ResolvedFinding] | None = None) -> None:
        # A whole-scan snapshot, not per-alert: counts + a freshness timestamp.
        if not self.pushgateway_url:
            logger.warning(
                "Prometheus surface enabled but no pushgateway configured "
                "(set PROMETHEUS_PUSHGATEWAY_URL or pass pushgateway_url); "
                "skipping %d alert(s).",
                len(report.alerts),
            )
            return
        self._push(format_prometheus_metrics(report, resolved))

    def _push(self, body: str) -> None:
        assert self.pushgateway_url is not None  # emit() guards a configured gateway
        url = f"{self.pushgateway_url.rstrip('/')}/metrics/job/{self.job}"
        data = body.encode("utf-8")
        request = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "text/plain; version=0.0.4"},
            method="PUT",  # PUT replaces the job group -- a clean snapshot per scan
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                response.read()
        except (urllib.error.URLError, OSError) as exc:
            logger.warning("Prometheus delivery failed: %s", exc)
