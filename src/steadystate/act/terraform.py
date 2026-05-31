"""Terraform executor: reconcile a drift back to declared state, with guardrails.

For an eligible drift: snapshot (`terraform show -json`) -> targeted apply ->
verify (re-plan; is the drift gone?). Live apply is gated behind BOTH
apply-eligibility AND an explicit `confirm=True`; nothing runs by default.
"""

from __future__ import annotations

import json
import subprocess
import time
from collections.abc import Callable
from pathlib import Path

from ..model import Drift
from .artifact import RemediationArtifact
from .base import RemediationResult
from .codify import terraform_restore
from .plan import RemediationPlan, assess

# Verifying a reconcile against real cloud infra has two traps a naive "is the resource still in
# the drift list?" check falls into:
#   1. Refresh-only noise. Right after a clean apply, a full `terraform plan` refresh often lists
#      the resource under `resource_drift` (server-set fields, IAM/storage eventual consistency)
#      while it is a no-op in `resource_changes` -- terraform has *nothing left to apply*. Those
#      drifts are marked actionable=False, so the verify only counts ACTIONABLE residual drift.
#   2. Propagation lag. A setting can briefly still read its pre-apply value, so even an actionable
#      re-check can false-negative for a few seconds; we re-check a few times before concluding.
# A genuinely-unreconciled drift (e.g. a provider that merged a set) stays actionable through every
# attempt and is still honestly reported as "applied, not verified".
_VERIFY_ATTEMPTS = 3
_VERIFY_DELAY_SECONDS = 4.0


class TerraformExecutor:
    name = "terraform"

    def __init__(self, working_dir: str | Path | None = None) -> None:
        self.working_dir = Path(working_dir) if working_dir else None

    def plan_for(self, drift: Drift) -> RemediationPlan:
        return assess(drift)

    def propose(self, drift: Drift) -> RemediationArtifact | None:
        """Render the drift as a reviewable *accept-reality* code change (the Proposer
        capability), or None when there's no safe code-change for it. Today: a REMOVED drift
        (config deleted while the resource is still in state) becomes a patch that re-adds the
        declaration, averting the destroy ``assess`` refuses to auto-apply. Pure: no infra
        touched, no model in the loop."""
        return terraform_restore(drift)

    def remediate(self, drift: Drift, *, confirm: bool = False) -> RemediationResult:
        plan = self.plan_for(drift)
        if not plan.eligible:
            return RemediationResult(
                plan=plan,
                applied=False,
                verified=False,
                detail="Refused: not apply-eligible (see reason).",
            )
        if not confirm:
            return RemediationResult(
                plan=plan,
                applied=False,
                verified=False,
                detail="Dry run: pass confirm=True (or --apply) to reconcile.",
            )
        if self.working_dir is None:
            return RemediationResult(
                plan=plan,
                applied=False,
                verified=False,
                detail="No terraform working dir configured; cannot apply.",
            )
        snapshot = self._snapshot()
        self._run(plan.command)
        cleared = not self._still_drifting(drift)
        return RemediationResult(
            plan=plan,
            applied=True,
            verified=cleared,
            snapshot=snapshot,
            detail="Applied and verified clear."
            if cleared
            else "Applied, but drift still present on re-check.",
        )

    # --- live terraform (guarded; not exercised by unit tests) ---

    def _snapshot(self) -> dict:
        assert self.working_dir is not None  # remediate() guards this before calling
        planfile = self.working_dir / ".steadystate.snapshot.tfplan"
        subprocess.run(
            ["terraform", "plan", "-refresh=true", "-out", str(planfile)],
            cwd=self.working_dir,
            check=True,
            capture_output=True,
        )
        res = subprocess.run(
            ["terraform", "show", "-json", str(planfile)],
            cwd=self.working_dir,
            check=True,
            capture_output=True,
            text=True,
        )
        return json.loads(res.stdout)

    def _run(self, command: list[str]) -> None:
        subprocess.run(command, cwd=self.working_dir, check=True, capture_output=True, text=True)

    def _still_drifting(self, drift: Drift) -> bool:
        from ..sources.terraform import TerraformSource

        source = TerraformSource(working_dir=self.working_dir)
        return self._persists(source.collect_drift, drift)

    @staticmethod
    def _persists(collect: Callable[[], list[Drift]], drift: Drift) -> bool:
        """True iff ``drift`` is still present after a few re-checks. Returns False as soon as it
        clears (the apply took, allowing for cloud propagation lag); True only if it survives every
        attempt. No subprocess here, so the retry policy is unit-testable with a fake collect."""
        for attempt in range(_VERIFY_ATTEMPTS):
            # Only an *actionable* residual counts: terraform would still change it. A refresh-only
            # entry (actionable=False) means the reconcile took -- nothing left to apply.
            if not any(d.identity == drift.identity and d.actionable for d in collect()):
                return False
            if attempt < _VERIFY_ATTEMPTS - 1:
                time.sleep(_VERIFY_DELAY_SECONDS)
        return True
