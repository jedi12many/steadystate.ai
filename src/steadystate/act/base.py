"""The Executor plugin seam + its result type.

Every remediation must be apply-eligibility-checked, snapshotted, verified, and
reversible. Chat is a convenient trigger, never a bypass of these guardrails.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from ..model import Drift
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
