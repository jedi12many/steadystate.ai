"""The reasoning pipeline: drift -> three-layer classification -> Report.

Every drift is an Event (the firehose). Deterministic scoring plus a Brain-Tuning
bar promote the ones that matter into Alerts (recorded) and Cases (page-worthy,
full narrative). The LLM analyst and the executor's recommended action run only for
what clears the bar -- Events are counted, not analyzed. The bar moves with the
tuning knob (lenient raises it, strict lowers it), so one setting adjusts all layers.
"""

from __future__ import annotations

from ..act.plan import RemediationPlan, assess
from ..domains import default_domains
from ..domains.base import Domain
from ..model import ChangeType, Drift
from .case import Case, Layer, Severity
from .llm import LLMAnalyst
from .report import Report, Tuning, classify

_SEVERITY_RANK = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}


def baseline_severity(drift: Drift) -> Severity:
    """Deterministic floor, before any domain pack or LLM weighs in."""
    if drift.change_type is ChangeType.REMOVED:
        return Severity.HIGH  # something we declared is gone from reality
    if drift.change_type is ChangeType.MODIFIED:
        return Severity.MEDIUM
    return Severity.LOW


def _action_from_plan(plan: RemediationPlan) -> str:
    """Render the executor's remediation plan as a concrete recommended action."""
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

    def _event(self, drift: Drift, severity: Severity, flagged_by: str | None) -> Case:
        # firehose: counted, not analyzed -- no LLM call, no executor plan
        return Case(
            title=drift.summary(),
            severity=severity,
            drifts=[drift],
            why_it_matters=f"{drift.summary()}: declared and observed state diverge.",
            layer=Layer.EVENT,
            recommended_action=None,
            llm_backed=False,
            flagged_by=flagged_by,
        )

    def _surfaced_case(
        self, drift: Drift, severity: Severity, layer: Layer, flagged_by: str | None
    ) -> Case:
        analysis = self.analyst.analyze(drift)
        recommended_action = analysis.recommended_action
        # The executor's plan is Terraform-specific today, so only derive a reconcile
        # action for Terraform drift; other sources await their own executors.
        if recommended_action is None and drift.provenance.source == "terraform":
            recommended_action = _action_from_plan(assess(drift))
        return Case(
            title=drift.summary(),
            severity=severity,
            drifts=[drift],
            why_it_matters=analysis.why_it_matters,
            layer=layer,
            recommended_action=recommended_action,
            llm_backed=analysis.llm_backed,
            flagged_by=flagged_by,
        )

    def run(self, drifts: list[Drift]) -> Report:
        cases: list[Case] = []
        for drift in drifts:
            severity, flagged_by = self._score(drift)
            layer = classify(severity, self.tuning)
            if layer is Layer.EVENT:
                cases.append(self._event(drift, severity, flagged_by))
            else:
                cases.append(self._surfaced_case(drift, severity, layer, flagged_by))
        return Report(all_cases=cases, tuning=self.tuning)
