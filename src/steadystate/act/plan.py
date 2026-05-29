"""Remediation planning + the apply-eligibility guardrail.

This is the differentiated part: before anything runs, decide whether a drift is
*safe* to auto-reconcile, classify its blast radius, and record an honest revert
path. Pure and deterministic, so it is fully testable without touching real infra.

The rule that matters: bringing reality back to declared state is safe when it
*creates* or *updates* something you already declared, but reconciling a REMOVED
drift means destroying a live resource that isn't in your config -- that is never
automatically eligible.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from ..model import ChangeType, Drift


class Risk(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class RemediationPlan:
    drift_identity: str
    eligible: bool  # safe to auto-reconcile without explicit operator override?
    risk: Risk
    reason: str  # why eligible / why not
    command: list[str] = field(default_factory=list)  # the executable remediation
    blast_radius: str = ""  # plain-language description of what running this touches
    revert: str = ""  # honest revert guidance


def assess(drift: Drift) -> RemediationPlan:
    """The apply-eligibility guardrail for a single drift."""
    addr = drift.identity
    target = ["terraform", "apply", "-target", addr, "-auto-approve"]

    if drift.change_type is ChangeType.REMOVED:
        return RemediationPlan(
            drift_identity=addr,
            eligible=False,
            risk=Risk.HIGH,
            reason=(
                "Reconciling would destroy a live resource that is not in declared config. "
                "Requires explicit operator approval -- never automatic."
            ),
            command=target,
            blast_radius=f"Destroys {drift.kind} {addr} in the real environment.",
            revert=(
                "Re-add the resource to config and re-apply; a destroyed resource may not be "
                "perfectly recreatable (new IDs, lost data)."
            ),
        )

    if drift.change_type is ChangeType.ADDED:
        return RemediationPlan(
            drift_identity=addr,
            eligible=True,
            risk=Risk.LOW,
            reason="Declared resource is missing from the environment; reconciling creates it.",
            command=target,
            blast_radius=f"Creates {drift.kind} {addr} as declared.",
            revert=f"terraform destroy -target {addr}",
        )

    # MODIFIED
    return RemediationPlan(
        drift_identity=addr,
        eligible=True,
        risk=Risk.MEDIUM,
        reason="Resource configuration drifted; reconciling re-applies the declared values.",
        command=target,
        blast_radius=f"Updates {drift.kind} {addr} in place to match declared config.",
        revert="Restore the prior values in config and re-apply (a snapshot is captured first).",
    )
