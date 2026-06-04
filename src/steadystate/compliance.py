"""The CIS compliance report -- a benchmark view over the standing-policy findings.

The domain packs already emit a ``PolicyFinding`` for every CIS rule a resource violates (CIS
Docker, CIS Kubernetes Pod Security), each carrying its CIS section as a ``Reference`` with a
``level``. This rolls those findings up into a benchmark report: per control, which resources fail
it and how badly. Filtered to a CIS level (1 by default), so ``compliance`` answers "what CIS Level
1 controls is this failing, on what?".

Honest framing (the same line the packs draw): this reports the controls steadystate actually
*checks* and that something *violated* -- it is **not** a full pass/fail over every control in the
published benchmark. The control-plane sections (CIS Kubernetes §1-4) need node/file access
(kube-bench territory) and are N/A on managed clusters; a complete control catalog with explicit
PASS rows is a deliberate follow-up. What this gives is the live, agentless failures, grouped the
way the benchmark numbers them. Pure -- it takes findings in and renders text/JSON out.
"""

from __future__ import annotations

from dataclasses import dataclass

from .domains.base import PolicyFinding
from .reason.alert import Severity

# Severity is a str Enum (not ordinal), so rank explicitly: worst first in the report.
_SEVERITY_RANK = {Severity.CRITICAL: 3, Severity.HIGH: 2, Severity.MEDIUM: 1, Severity.LOW: 0}


@dataclass(frozen=True)
class ControlResult:
    """One CIS control that something failed: its id + name, the worst severity across the
    resources failing it, and those resources (deduped, in first-seen order)."""

    framework: str  # "CIS"
    control_id: str  # e.g. "Kubernetes-5.2.1"
    name: str  # the control's name, from the Reference
    severity: Severity  # the worst severity among the failing resources
    resources: tuple[str, ...]  # the resource identities failing this control


def cis_report(findings: list[PolicyFinding], level: int | None = 1) -> list[ControlResult]:
    """Group CIS ``findings`` by control, filtered to ``level`` (None = every CIS level). Worst
    severity first, then control id. Pure -- the caller collects the findings (one scan's policy
    pass) and decides how to render."""
    by_control: dict[str, dict] = {}
    for finding in findings:
        for ref in finding.references:
            if ref.framework != "CIS":
                continue
            if level is not None and ref.level != level:
                continue
            entry = by_control.setdefault(
                ref.id,
                {"name": ref.name, "severity": finding.severity, "resources": []},
            )
            entry["resources"].append(finding.identity)
            if _SEVERITY_RANK[finding.severity] > _SEVERITY_RANK[entry["severity"]]:
                entry["severity"] = finding.severity
    results = [
        ControlResult(
            framework="CIS",
            control_id=control_id,
            name=entry["name"],
            severity=entry["severity"],
            resources=tuple(dict.fromkeys(entry["resources"])),  # dedupe, keep order
        )
        for control_id, entry in by_control.items()
    ]
    return sorted(results, key=lambda r: (-_SEVERITY_RANK[r.severity], r.control_id))


def render_cis_report(results: list[ControlResult], level: int | None = 1) -> list[str]:
    """Render the grouped CIS report as console lines. A clean header (level, controls failing,
    resources affected) then, per control worst-first, its id/name/severity and the failing
    resources. An all-clear when nothing failed. Pure."""
    scope = f"CIS Level {level}" if level is not None else "CIS"
    if not results:
        return [f"{scope}: no failures -- every checked control passed on the scanned resources."]
    affected = len({r for result in results for r in result.resources})
    lines = [
        f"{scope}: {len(results)} control(s) failing across {affected} resource(s)",
        "(the controls steadystate checks live, agentless -- not a full benchmark catalog)",
    ]
    for result in results:
        lines.append(
            f"  [{result.severity.value.upper():<8}] {result.framework} {result.control_id}  "
            f"{result.name}"
        )
        for identity in result.resources:
            lines.append(f"      - {identity}")
    return lines


def cis_report_as_dict(results: list[ControlResult], level: int | None = 1) -> dict:
    """The report as a JSON-ready dict, for `compliance --json` (other tooling / an agent)."""
    return {
        "framework": "CIS",
        "level": level,
        "controls_failing": len(results),
        "resources_affected": len({r for result in results for r in result.resources}),
        "controls": [
            {
                "id": result.control_id,
                "name": result.name,
                "severity": result.severity.value,
                "resources": list(result.resources),
            }
            for result in results
        ],
    }
