"""The reasoning pipeline: drift -> three-layer scoring -> Cases.

v0 keeps the bar low (every non-trivial drift becomes a Case) and the scoring
deterministic. Domain packs and cross-drift correlation will raise/lower the bar
later -- that's the whole point of keeping the core domain-agnostic.
"""

from __future__ import annotations

from ..model import ChangeType, Drift
from .case import Case, Layer, Severity
from .llm import LLMAnalyst


def baseline_severity(drift: Drift) -> Severity:
    """Deterministic floor, before any domain pack or LLM weighs in."""
    if drift.change_type is ChangeType.REMOVED:
        return Severity.HIGH  # something we declared is gone from reality
    if drift.change_type is ChangeType.MODIFIED:
        return Severity.MEDIUM
    return Severity.LOW


class Pipeline:
    def __init__(self, analyst: LLMAnalyst | None = None) -> None:
        self.analyst = analyst or LLMAnalyst()

    def run(self, drifts: list[Drift]) -> list[Case]:
        cases: list[Case] = []
        for drift in drifts:
            analysis = self.analyst.analyze(drift)
            cases.append(
                Case(
                    title=drift.summary(),
                    severity=baseline_severity(drift),
                    drifts=[drift],
                    why_it_matters=analysis.why_it_matters,
                    layer=Layer.CASE,
                    recommended_action=analysis.recommended_action,
                    llm_backed=analysis.llm_backed,
                )
            )
        return cases
