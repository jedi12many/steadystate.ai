"""Ansible executor: reconcile a drifted host back to its playbook, with guardrails.

A drift from the ansible source is `host:task` -- a task `ansible-playbook --check` said
would change on a host. Remediation is the natural inverse: run the playbook for real,
scoped to that host (`ansible-playbook --limit <host>`), which is reconcile-toward-declared
(the safe self-heal direction -- Ansible doesn't destroy undeclared resources). Live apply is
gated behind apply-eligibility AND `confirm=True`; nothing runs by default.

Ansible is not transactional, so there is no clean snapshot/auto-revert (unlike terraform's
plan). We're honest about that in the plan's revert guidance. Verify re-runs `--check` for the
host and reports whether the drift cleared.

The playbook + inventory are configured out of band (constructor or the env vars
STEADYSTATE_ANSIBLE_PLAYBOOK / STEADYSTATE_ANSIBLE_INVENTORY), since the drift input the CLI
passes is the captured check output, not the playbook itself.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from ..model import Drift
from .base import RemediationResult
from .plan import RemediationPlan, Risk


class AnsibleExecutor:
    name = "ansible"

    def __init__(
        self,
        playbook: str | None = None,
        inventory: str | None = None,
        working_dir: str | Path | None = None,
    ) -> None:
        self.playbook = playbook or os.environ.get("STEADYSTATE_ANSIBLE_PLAYBOOK")
        self.inventory = inventory or os.environ.get("STEADYSTATE_ANSIBLE_INVENTORY")
        self.working_dir = Path(working_dir) if working_dir else None

    def _host(self, drift: Drift) -> str:
        return drift.identity.split(":", 1)[0]

    def plan_for(self, drift: Drift) -> RemediationPlan:
        host = self._host(drift)
        command = ["ansible-playbook", "--limit", host]
        if self.inventory:
            command += ["-i", self.inventory]
        if self.playbook:
            command.append(self.playbook)
        return RemediationPlan(
            drift_identity=drift.identity,
            # Re-running the playbook reconciles the host to declared -- the safe self-heal
            # direction. Always eligible: Ansible converges toward the playbook, it doesn't
            # destroy resources the playbook doesn't mention.
            eligible=True,
            risk=Risk.MEDIUM,
            reason="Re-running the playbook on the host reconciles it to the declared config.",
            command=command,
            blast_radius=f"Runs the playbook against host {host}.",
            revert=(
                "Ansible is not transactional -- there is no automatic revert; restore from a "
                "known-good playbook state and re-run if needed."
            ),
        )

    def remediate(self, drift: Drift, *, confirm: bool = False) -> RemediationResult:
        plan = self.plan_for(drift)
        if not confirm:
            return RemediationResult(
                plan=plan,
                applied=False,
                verified=False,
                detail="Dry run: pass confirm=True (or --apply) to reconcile.",
            )
        if not self.playbook:
            return RemediationResult(
                plan=plan,
                applied=False,
                verified=False,
                detail="No playbook configured; set STEADYSTATE_ANSIBLE_PLAYBOOK to apply.",
            )
        self._run(plan.command)
        cleared = not self._still_drifting(drift)
        return RemediationResult(
            plan=plan,
            applied=True,
            verified=cleared,
            detail="Applied and verified clear."
            if cleared
            else "Applied, but the host still drifts on re-check.",
        )

    # --- live ansible (guarded; not exercised by unit tests) ---

    def _run(self, command: list[str]) -> None:
        subprocess.run(command, cwd=self.working_dir, check=True, capture_output=True, text=True)

    def _still_drifting(self, drift: Drift) -> bool:
        from ..sources.ansible import AnsibleSource

        residual = AnsibleSource(
            playbook=self.playbook, inventory=self.inventory, working_dir=self.working_dir
        ).collect_drift()
        return any(d.identity == drift.identity for d in residual)
