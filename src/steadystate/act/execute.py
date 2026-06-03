"""Run a vetted catalog action -- the generic executor behind chat `fix`/`run`.

This is the evicted-cleanup runner (act/cleanup.run_cleanup), generalized to ANY catalog action.
A PendingAction whose ``source`` is ``CATALOG_SOURCE`` carries a command that some catalog entry's
allow-pattern must accept; we look the action up *by its command* (the patterns are disjoint), read
its TRUSTED envelope, and run it only if that envelope is within the human's bound -- then execute
it as an argv list (no shell), bounded by a timeout. Two layers of defense before anything runs:

  * the command must match a catalog action's allow-pattern (re-checked HERE, at run time, so a
    stored/tampered command that isn't a vetted shape is refused -- never an arbitrary command);
  * the matched action's envelope must be within the bound (so even a vetted action can't run if
    policy says its blast radius is too big -- it escalates instead).

Identical discipline to run_cleanup; the only difference is it serves the whole catalog, so `fix`
and `run` route here through the same approve guardrail (claim-once + audit) `approve` uses.
"""

from __future__ import annotations

import shlex
import subprocess

from ..state import PendingAction
from .base import RemediationResult
from .bounds import within_bounds
from .catalog import action_for_command
from .plan import RemediationPlan, Risk

# The sentinel ``source`` that marks a PendingAction as a direct catalog-action command (vs a drift
# remediation). ``apply_pending`` routes it here.
CATALOG_SOURCE = "kubectl-catalog"


def run_catalog_action(action: PendingAction, *, timeout: float = 30.0) -> RemediationResult:
    """Execute the catalog-action command on ``action``. Re-validates it against the catalog's
    allow-patterns (refuses anything no vetted action recognizes), checks the matched action's
    envelope is within the bound (else escalates -- never runs out of bounds), then runs it as an
    argv list (no shell), with a timeout. Best-effort: a failed command is reported, not raised."""
    command = action.command
    matched = action_for_command(command)
    plan = RemediationPlan(
        drift_identity=action.drift_identity,
        eligible=matched is not None,
        risk=Risk.MEDIUM,
        reason=f"catalog action {matched.name}" if matched else "unrecognized command",
        command=shlex.split(command) if matched else [],
        blast_radius=matched.envelope.label if matched else "",
        revert="",
        envelope=matched.envelope if matched else None,
    )
    if matched is None:  # defense in depth: only a vetted catalog command shape ever runs
        return RemediationResult(
            plan=plan,
            applied=False,
            verified=False,
            detail=f"refused: not a recognized catalog command ({command!r}).",
        )
    if not within_bounds(matched.envelope):  # the bound is supreme, even at run time
        return RemediationResult(
            plan=plan,
            applied=False,
            verified=False,
            detail=f"refused: '{matched.name}' ({matched.envelope.label}) is outside the bound.",
        )
    try:
        proc = subprocess.run(  # noqa: S603 -- argv list (no shell), command allow-pattern-validated
            plan.command, capture_output=True, text=True, timeout=timeout, check=False
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return RemediationResult(
            plan=plan, applied=False, verified=False, detail=f"action failed: {exc}"
        )
    if proc.returncode != 0:
        why = (proc.stderr or proc.stdout or "").strip()[:200]
        return RemediationResult(
            plan=plan,
            applied=False,
            verified=False,
            detail=f"action failed (exit {proc.returncode}): {why}",
        )
    out = (proc.stdout or "").strip()[:200]
    return RemediationResult(
        plan=plan, applied=True, verified=True, detail=f"ran {matched.name}. {out}".strip()
    )
