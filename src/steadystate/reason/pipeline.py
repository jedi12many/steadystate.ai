"""The reasoning pipeline: drift -> Signal/Event -> (LLM correlation) -> Alerts.

Every drift is scored deterministically and filtered by a Brain-Tuning bar into a
Signal (counted firehose) or an Event. The Events are handed to the LLM correlator
in one batch; it groups them by root cause, and each group becomes an Alert -- which
is why several signals from different sources (a node out of storage) can fold into
one Alert. Without a model the correlator degrades honestly: each Event becomes its
own uncorrelated Alert.
"""

from __future__ import annotations

from ..act.plan import RemediationPlan, assess
from ..domains import default_domains
from ..domains.base import Domain
from ..model import ChangeType, Drift
from .alert import Alert, Layer, Severity
from .llm import Cluster, LLMAnalyst
from .report import Report, Tuning, classify

_SEVERITY_RANK = {Severity.LOW: 0, Severity.MEDIUM: 1, Severity.HIGH: 2, Severity.CRITICAL: 3}

# An Event awaiting correlation: the drift plus its deterministic score.
_Event = tuple[Drift, Severity, "str | None"]


def baseline_severity(drift: Drift) -> Severity:
    """Deterministic floor, before any domain pack weighs in."""
    if drift.change_type is ChangeType.REMOVED:
        return Severity.HIGH  # something we declared is gone from reality
    if drift.change_type is ChangeType.MODIFIED:
        return Severity.MEDIUM
    return Severity.LOW


def _action_from_plan(plan: RemediationPlan) -> str:
    if plan.eligible:
        return f"Reconcile to declared state: {' '.join(plan.command)} ({plan.blast_radius})"
    return f"Manual review required: {plan.reason}"


class Pipeline:
    def __init__(
        self,
        analyst: LLMAnalyst | None = None,
        domains: list[Domain] | None = None,
        tuning: Tuning = Tuning.DEFAULT,
    ) -> None:
        self.analyst = analyst or LLMAnalyst()
        self.domains = domains if domains is not None else default_domains()
        self.tuning = tuning

    def _score(self, drift: Drift) -> tuple[Severity, str | None]:
        """Deterministic severity + which domain pack (if any) raised it."""
        severity = baseline_severity(drift)
        flagged_by: str | None = None
        for domain in self.domains:
            scored = domain.score(drift)
            if scored is not None and _SEVERITY_RANK[scored] > _SEVERITY_RANK[severity]:
                severity = scored
                flagged_by = domain.name
        return severity, flagged_by

    def _signal(self, drift: Drift, severity: Severity, flagged_by: str | None) -> Alert:
        # Below the Event bar: the counted firehose, never analyzed.
        return Alert(
            title=drift.summary(),
            severity=severity,
            drifts=[drift],
            why_it_matters=f"{drift.summary()}: declared and observed state diverge.",
            layer=Layer.SIGNAL,
            recommended_action=None,
            llm_backed=False,
            flagged_by=flagged_by,
        )

    def _alert_from_cluster(self, cluster: Cluster, events: list[_Event]) -> Alert:
        members = [events[i] for i in cluster.drift_indexes]
        drifts = [m[0] for m in members]
        severity = max((m[1] for m in members), key=lambda s: _SEVERITY_RANK[s])
        flagged_by = next((m[2] for m in members if m[2] is not None), None)
        action = cluster.recommended_action
        # A single Terraform Event with no model-suggested action -> the executor's plan.
        if action is None and len(drifts) == 1 and drifts[0].provenance.source == "terraform":
            action = _action_from_plan(assess(drifts[0]))
        return Alert(
            title=cluster.title,
            severity=severity,
            drifts=drifts,
            why_it_matters=cluster.why_it_matters,
            layer=Layer.ALERT,
            recommended_action=action,
            llm_backed=cluster.llm_backed,
            flagged_by=flagged_by,
        )

    def run(self, drifts: list[Drift]) -> Report:
        signals: list[Alert] = []
        events: list[_Event] = []
        for drift in drifts:
            severity, flagged_by = self._score(drift)
            if classify(severity, self.tuning) is Layer.SIGNAL:
                signals.append(self._signal(drift, severity, flagged_by))
            else:
                events.append((drift, severity, flagged_by))
        clusters = self.analyst.correlate([event[0] for event in events])
        alerts = [self._alert_from_cluster(cluster, events) for cluster in clusters]
        return Report(items=signals + alerts, tuning=self.tuning)
