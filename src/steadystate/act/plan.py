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
from .bounds import BoundPolicy, Envelope, Impact, Reversibility, bound_from_env, within_bounds


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
    # The structured (impact, reversibility) form of blast_radius/revert above -- what the bound
    # gate (act/bounds.py) reads, so the SAME autonomy calculus governs this remediation as governs
    # a kubectl cleanup or an ansible play. None on a plan that predates the envelope (the human
    # approve path still works; only the autonomous gate needs it).
    envelope: Envelope | None = None


def can_run_unattended(plan: RemediationPlan, policy: BoundPolicy | None = None) -> bool:
    """May this remediation run WITHOUT a human -- the gate the autonomous (`--autonomy auto`) path
    adds on top of ``eligible``. The two questions are different: ``eligible`` answers *"may a human
    approve this?"* (never a destroy); this answers the stricter *"may it run unattended?"* -- it
    must ALSO sit within the operator's bound (act/bounds.py). So a recoverable change a human can
    approve still escalates under ``auto`` until the operator widens the bound.

    A plan with no declared ``envelope`` falls back to ``eligible`` alone -- its executor has not
    been migrated to the bound (terraform declares an envelope; ansible does not yet), so this never
    *loosens* the prior behavior, only tightens it where an envelope exists. ``policy`` defaults to
    the active env bound (``bound_from_env``); inject one in tests to stay pure."""
    if not plan.eligible:
        return False
    if plan.envelope is None:
        return True  # eligible already True; un-migrated executor keeps its prior auto behavior
    return within_bounds(plan.envelope, policy if policy is not None else bound_from_env())


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
            # Destroying a live resource is the irreversible case -- the bound escalates it no
            # matter the size, mirroring `eligible=False`.
            envelope=Envelope(Reversibility.IRREVERSIBLE, Impact.SERVICE),
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
            # Creating a declared resource has a known inverse (destroy it) -> recoverable.
            envelope=Envelope(Reversibility.RECOVERABLE, Impact.SERVICE),
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
        # An in-place update is reversible by restoring prior values (a snapshot is captured) ->
        # recoverable, one resource.
        envelope=Envelope(Reversibility.RECOVERABLE, Impact.SERVICE),
    )
