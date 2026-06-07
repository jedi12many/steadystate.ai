"""Terraform source -- v0.

Terraform already reconciles declared config against real cloud state, so we ride
its own diff instead of re-deriving it: parse a `terraform show -json <plan>`
document into Drift records.

- `resource_drift`   = real-world changes detected since the last apply.
- `resource_changes` = config diverged from recorded state (non-no-op actions).
"""

from __future__ import annotations

from pathlib import Path

from ..model import ChangeType, Drift, Provenance
from .base import Capabilities, loads_json, run_tool

# terraform plan action lists -> our ChangeType
_ACTION_MAP = {
    ("create",): ChangeType.ADDED,
    ("delete",): ChangeType.REMOVED,
    ("update",): ChangeType.MODIFIED,
    ("create", "delete"): ChangeType.MODIFIED,  # replace
    ("delete", "create"): ChangeType.MODIFIED,  # replace
}


def _drift_from_change(rc: dict, *, actionable: bool) -> Drift | None:
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
        actionable=actionable,
    )


def drifts_from_plan_json(plan: dict) -> list[Drift]:
    """Parse a `terraform show -json <plan>` document into Drift records. Pure + testable.

    A resource that drifted in reality AND has a planned reconciliation appears in BOTH
    sections at once -- `resource_changes` and `resource_drift` -- but it's one finding, so
    we dedupe by address. `resource_changes` wins: its before/after is exactly declared-config
    (after) vs current reality (before), which is steadystate's declared-vs-observed framing;
    `resource_drift` carries them in the opposite sense (current reality vs last-applied state),
    so using it would invert declared/observed. resource_drift is the fallback only for
    resources the plan won't change.
    """
    by_address: dict[str, Drift] = {}
    order: list[str] = []
    # resource_changes first: it's the plan's reconciliation, so those drifts are actionable
    # (terraform apply will fix them) and win the dedup. resource_drift-only entries are NOT
    # actionable -- reality moved but the plan is a no-op for them, so there's nothing to
    # apply; they're floored to LOW downstream (see baseline_severity).
    for section, actionable in (("resource_changes", True), ("resource_drift", False)):
        for rc in plan.get(section) or []:
            d = _drift_from_change(rc, actionable=actionable)
            if d is None or d.identity in by_address:
                continue
            by_address[d.identity] = d
            order.append(d.identity)
    return [by_address[a] for a in order]


class TerraformSource:
    """A DriftSource. Construct with a captured plan JSON (testing / CI) or a
    working dir to run terraform live."""

    name = "terraform"
    commands = Capabilities(
        observe=("terraform plan", "terraform show -json", "terraform output"),
        destructive=("terraform apply", "terraform destroy"),
    )

    def __init__(
        self,
        working_dir: str | Path | None = None,
        plan_json: dict | None = None,
        timeout: float = 300.0,  # a live `terraform plan` against real cloud can take minutes
        refresh: bool = True,
    ) -> None:
        self.working_dir = Path(working_dir) if working_dir else None
        self._plan_json = plan_json
        self.timeout = timeout
        # refresh=False -> `terraform plan -refresh=false`: diff config against the RECORDED state
        # only, no per-resource cloud refresh. Cheap, fast, and needs no broad cloud read creds --
        # just access to the backend state. Answers "is the code in sync with what's deployed?"
        # (config-vs-state), not live drift (state-vs-reality, which needs the refresh).
        self.refresh = refresh

    def collect_drift(self) -> list[Drift]:
        plan = self._plan_json if self._plan_json is not None else self._run_terraform()
        return drifts_from_plan_json(plan)

    def _run_terraform(self) -> dict:
        if self.working_dir is None:
            raise ValueError("TerraformSource needs working_dir or plan_json")
        planfile = self.working_dir / ".steadystate.tfplan"
        refresh_flag = f"-refresh={'true' if self.refresh else 'false'}"
        run_tool(
            ["terraform", "plan", refresh_flag, "-out", str(planfile)],
            cwd=self.working_dir,
            timeout=self.timeout,
            tool="terraform plan",
        )
        stdout = run_tool(
            ["terraform", "show", "-json", str(planfile)],
            cwd=self.working_dir,
            timeout=self.timeout,
            tool="terraform show",
        )
        parsed = loads_json(stdout, tool="terraform show")
        return parsed if isinstance(parsed, dict) else {}
