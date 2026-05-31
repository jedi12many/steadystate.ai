"""The Executor plugin seam + its result type.

Every remediation must be apply-eligibility-checked, snapshotted, verified, and
reversible. Chat is a convenient trigger, never a bypass of these guardrails.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from ..model import Drift
from .artifact import RemediationArtifact
from .plan import RemediationPlan


@dataclass
class RemediationResult:
    plan: RemediationPlan
    applied: bool
    verified: bool  # post-apply re-check: did the drift actually clear?
    detail: str = ""
    snapshot: dict | None = field(default=None)  # pre-change state, for the record / revert


@runtime_checkable
class Executor(Protocol):
    name: str

    def plan_for(self, drift: Drift) -> RemediationPlan: ...

    def remediate(self, drift: Drift, *, confirm: bool = False) -> RemediationResult: ...


@runtime_checkable
class Proposer(Protocol):
    """An *optional* executor capability: render a drift as a reviewable code change instead of a
    live apply. Probed by ``isinstance(executor, Proposer)`` -- like the inbound adapters' optional
    ``defer``/``complete`` -- so an executor that can express a fix as a patch implements it and one
    that can only apply live simply doesn't, and the propose path degrades honestly for it.

    ``propose`` returns ``None`` for a drift it has no code-change for (e.g. the apply direction is
    the right fix), so a caller can offer artifacts only where one genuinely exists."""

    def propose(self, drift: Drift) -> RemediationArtifact | None: ...
