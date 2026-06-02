"""Canonical JSON serialization of a reasoned Report -- the machine-readable form of what the
console/chat render.

`scan --json` / `probe --json` emit this so a pipeline (or an LLM/agent -- e.g. a Teams Copilot)
can consume a scan as a structured object instead of scraping a human digest. The shape is a
superset of the webhook surface's per-alert event: it keeps the reasoning (`why`), the action +
guardrail (`recommended_action`/`remediable`), the durable keys (`fingerprints`,
`correlation_fingerprint`), the memory annotations (`status`/`first_seen`), the structured
`evidence` a `--deep`/health probe captured, and the declared->observed `changes` for drift.
Pure -- no I/O, no clock; the caller passes anything time/cost-related.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

from .reason.alert import Alert
from .reason.report import Report

if TYPE_CHECKING:
    from .reconcile_state import ResolvedFinding
    from .state import Finding


def finding_to_dict(finding: Finding) -> dict:
    """One *stored* finding as a JSON-ready dict -- for `show <fp> json` / `findings json`, the
    agent's read-back of remembered findings. The durable record: fingerprint, title, lifecycle
    status, last severity, first/last-seen timestamps, and the captured `evidence` (namespace,
    cluster, last log, ...). Pure."""
    return {
        "fingerprint": finding.fingerprint,
        "title": finding.last_title,
        "status": finding.status,
        "severity": finding.last_severity,
        "first_seen": finding.first_seen,
        "last_seen": finding.last_seen,
        "evidence": finding.details,
    }


def _member_fingerprints(alert: Alert) -> list[str]:
    """Every durable finding key in this alert (drift / policy / symptom) -- so a consumer can
    dedupe across scans the way the state store does."""
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


def _evidence(alert: Alert) -> dict[str, str]:
    """The structured key/value evidence the probe captured (namespace, cluster, last log, ...),
    merged across the alert's symptoms -- the same fields the `show <fp>` view lists."""
    evidence: dict[str, str] = {}
    for symptom in alert.symptoms:
        evidence.update(symptom.evidence)
    return evidence


def alert_to_dict(alert: Alert) -> dict:
    """One Alert as a JSON-ready dict. Stable contract; superset of the webhook event."""
    return {
        "title": alert.title,
        "severity": alert.severity.value,
        "tier": alert.layer.value,
        "why": alert.why_it_matters,
        "recommended_action": alert.recommended_action,
        "remediable": alert.remediable,
        "remediation_label": alert.remediation_label,
        "source": _source(alert),
        "environment": alert.environment,
        "resources": alert.resources,
        "references": [{"framework": r.framework, "id": r.id} for r in alert.references],
        "fingerprints": _member_fingerprints(alert),
        "correlation_fingerprint": alert.correlation_fingerprint,
        "status": alert.status,
        "first_seen": alert.first_seen.isoformat() if alert.first_seen else None,
        "llm_backed": alert.llm_backed,
        "evidence": _evidence(alert),
        "changes": [
            {
                "identity": d.identity,
                "change_type": d.change_type.value,
                "declared": d.declared,
                "observed": d.observed,
            }
            for d in alert.drifts
        ],
    }


def report_to_dict(
    report: Report,
    *,
    resolved: Sequence[ResolvedFinding] = (),
    spend: dict | None = None,
) -> dict:
    """A whole scan as a JSON-ready dict: a summary tally, the alerts (worst-first, as the report
    orders them), what resolved since the last scan, and the scan's LLM spend (when any)."""
    return {
        "summary": {
            "alerts": len(report.alerts),
            "signals": report.signal_count,
            "resolved": len(resolved),
        },
        "alerts": [alert_to_dict(a) for a in report.alerts],
        "resolved": [{"fingerprint": r.fingerprint, "title": r.title} for r in resolved],
        "spend": spend,
    }
