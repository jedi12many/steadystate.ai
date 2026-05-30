"""The reasoning output model and the three tiers: Signal -> Event -> Alert.

A drift starts as a Signal (raw, counted). Filtering promotes the ones worth
recording to Events. Analysis + correlation promote those to Alerts -- the
surfaced artifact, with or without a recommended action (sometimes we can't act).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import TYPE_CHECKING

from ..model import Drift

if TYPE_CHECKING:
    # Imported under TYPE_CHECKING only: domains.base and observe.base import Severity from this
    # module, so a runtime import here would be circular. All are plain value types.
    from ..domains.base import PolicyFinding, Reference
    from ..observe.base import Symptom


class Layer(str, Enum):
    SIGNAL = "signal"  # raw drift -- the firehose, counted
    EVENT = "event"  # cleared the filter -- recorded
    ALERT = "alert"  # analyzed + correlated -- surfaced, with or without an action


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Alert:
    """A reasoned finding at some tier. Alerts (the top tier) carry the narrative
    plus an optional recommended action; lower tiers are recorded/counted."""

    title: str
    severity: Severity
    drifts: list[Drift]
    why_it_matters: str  # the reasoning; honest about it when no LLM was available
    layer: Layer = Layer.ALERT
    recommended_action: str | None = None
    llm_backed: bool = False  # did an LLM actually reason about this? (honesty)
    flagged_by: str | None = None  # domain pack that raised the severity, if any
    # Framework references the flagging domain mapped this drift to (MITRE ATT&CK today;
    # CIS/STIG/CWE later, same field). Config-exposure -> technique mapping, NOT behavioral
    # detection. Populated alongside flagged_by in the pipeline; empty when nothing mapped.
    references: list[Reference] = field(default_factory=list)
    # The policy origin of a *baseline* Alert (CIS/STIG), where drifts is empty: the
    # PolicyFinding(s) a Domain.evaluate generated. Carries the data the surfaces render
    # and the fingerprint reconciliation keys memory on. Empty for ordinary drift Alerts.
    findings: list[PolicyFinding] = field(default_factory=list)
    # The operational origin of a malfunction Alert: the Symptom(s) a prober produced (the
    # resource is failing now). On a *diagnosis* Alert these ride alongside `drifts` -- a Symptom
    # correlated with the Drift that is its likely root cause. Empty for ordinary drift Alerts.
    symptoms: list[Symptom] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    # Memory annotations, populated by the state store during a stateful scan and
    # left None when scanning statelessly (so Pipeline stays pure and the stateless
    # path is unchanged). first_seen = when this finding was first recorded; status =
    # its lifecycle state (open / muted / snoozed / resolved).
    first_seen: datetime | None = None
    status: str | None = None
    # Live-health note attached by an enricher (reason/enrich.py) during a scan: a short
    # summary of the drifted resource's current unhealthy state in an external system
    # (Prometheus today). Populated only when enrichment runs and the resource is failing
    # right now; None otherwise, so the stateless / un-enriched path is unchanged.
    runtime_context: str | None = None
    # Operator-set scan label identifying *which environment* this came from (e.g. "prod-aws"),
    # stamped from `scan --label` after the pipeline. None when unset (the pipeline stays pure),
    # so surfaces show an environment line only when the operator asked for one.
    environment: str | None = None

    @property
    def resources(self) -> list[str]:
        """The identities of the resources this alert concerns -- its drifts' identities, else
        its policy findings', else its symptoms'. What a surface shows so an operator knows
        *which* resource is affected, not merely that something is."""
        if self.drifts:
            return [drift.identity for drift in self.drifts]
        if self.findings:
            return [finding.identity for finding in self.findings]
        return [symptom.identity for symptom in self.symptoms]

    def resource_label(self, limit: int = 5) -> str:
        """A compact 'which resources' string for surfaces: the identities, capped with a +N."""
        names = self.resources
        shown = ", ".join(names[:limit])
        extra = len(names) - limit
        return f"{shown} (+{extra} more)" if extra > 0 else shown
