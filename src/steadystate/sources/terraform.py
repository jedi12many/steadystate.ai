"""Terraform source -- v0.

Terraform already reconciles declared config against real cloud state, so we ride
its own diff instead of re-deriving it: parse a `terraform show -json <plan>`
document into Drift records.

- `resource_drift`   = real-world changes detected since the last apply.
- `resource_changes` = config diverged from recorded state (non-no-op actions).
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from ..model import ChangeType, Drift, Provenance

# terraform plan action lists -> our ChangeType
_ACTION_MAP = {
    ("create",): ChangeType.ADDED,
    ("delete",): ChangeType.REMOVED,
    ("update",): ChangeType.MODIFIED,
    ("create", "delete"): ChangeType.MODIFIED,  # replace
    ("delete", "create"): ChangeType.MODIFIED,  # replace
}


def _drift_from_change(rc: dict) -> Drift | None:
    change = rc.get("change") or {}
    actions = tuple(a for a in change.get("actions", []) if a not in ("no-op", "read"))
    if not actions:
        return None
    return Drift(
        identity=rc.get("address") or rc.get("name") or "?",
        kind=rc.get("type", "unknown"),
        change_type=_ACTION_MAP.get(actions, ChangeType.MODIFIED),
        provenance=Provenance(source="terraform", address=rc.get("address")),
        declared=change.get("after"),
        observed=change.get("before"),
    )


def drifts_from_plan_json(plan: dict) -> list[Drift]:
    """Parse a `terraform show -json <plan>` document into Drift records. Pure + testable."""
    out: list[Drift] = []
    for rc in plan.get("resource_drift") or []:
        d = _drift_from_change(rc)
        if d is not None:
            out.append(d)
    for rc in plan.get("resource_changes") or []:
        d = _drift_from_change(rc)
        if d is not None:
            out.append(d)
    return out


class TerraformSource:
    """A DriftSource. Construct with a captured plan JSON (testing / CI) or a
    working dir to run terraform live."""

    name = "terraform"

    def __init__(
        self,
        working_dir: str | Path | None = None,
        plan_json: dict | None = None,
    ) -> None:
        self.working_dir = Path(working_dir) if working_dir else None
        self._plan_json = plan_json

    def collect_drift(self) -> list[Drift]:
        plan = self._plan_json if self._plan_json is not None else self._run_terraform()
        return drifts_from_plan_json(plan)

    def _run_terraform(self) -> dict:
        if self.working_dir is None:
            raise ValueError("TerraformSource needs working_dir or plan_json")
        planfile = self.working_dir / ".steadystate.tfplan"
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
