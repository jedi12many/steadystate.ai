"""Terraform executor: reconcile a drift back to declared state, with guardrails.

For an eligible drift: snapshot (`terraform show -json`) -> targeted apply ->
verify (re-plan; is the drift gone?). Live apply is gated behind BOTH
apply-eligibility AND an explicit `confirm=True`; nothing runs by default.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from ..model import Drift
from .base import RemediationResult
from .plan import RemediationPlan, assess


class TerraformExecutor:
    name = "terraform"

    def __init__(self, working_dir: str | Path | None = None) -> None:
        self.working_dir = Path(working_dir) if working_dir else None

    def plan_for(self, drift: Drift) -> RemediationPlan:
        return assess(drift)

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

        residual = TerraformSource(working_dir=self.working_dir).collect_drift()
        return any(d.identity == drift.identity for d in residual)
