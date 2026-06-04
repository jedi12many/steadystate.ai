"""The compliance report -- one stacked benchmark view over the standing-policy findings.

The domain packs emit a ``PolicyFinding`` for every benchmark rule a resource violates (CIS Docker,
CIS Kubernetes Pod Security at Level 1, the stricter Level 2 posture gaps via the compliance-only
posture pass). Each finding carries the benchmark control(s) it maps to as ``Reference``s. This
rolls them into a single report: grouped by the *check* steadystate actually performs, citing every
benchmark control + level that check satisfies, worst-first. CIS and STIG (when mapped) stack into
one scan -- the same underlying check cited under each framework, not separate runs.

Honest framing (the disclaimer the report prints): steadystate validates these **live + agentless**,
from the cluster API and declared config, so it covers the *workload-policy* controls it can
observe. It does NOT cover the control-plane / node controls (API-server, etcd, kubelet flags --
node access / kube-bench, and N/A on managed clusters), nor the procedural controls a human must
attest. The report says so, on every run. Pure -- findings in, text/JSON out.
"""

from __future__ import annotations

from dataclasses import dataclass

from .domains.base import PolicyFinding, Reference
from .reason.alert import Severity

# Severity is a str Enum (not ordinal), so rank explicitly: worst first in the report.
_SEVERITY_RANK = {Severity.CRITICAL: 3, Severity.HIGH: 2, Severity.MEDIUM: 1, Severity.LOW: 0}

# The frameworks this report treats as compliance benchmarks (vs MITRE, an attack-technique rail).
_BENCHMARKS = ("CIS", "STIG")

# Printed on every report: what "validated live" actually covers, and what it deliberately doesn't.
DISCLAIMER = (
    "Scope: validated live + agentless, from the cluster API / declared config -- the "
    "workload-policy controls steadystate can observe (Pod Security, capabilities, host "
    "namespaces, seccomp, ...). NOT covered here (needs another tool or a human): control-plane & "
    "node controls (API-server, etcd, kubelet flags -- node access / kube-bench; N/A on managed "
    "clusters), and procedural controls (policy/process attestation)."
)


@dataclass(frozen=True)
class CheckResult:
    """One check steadystate performs that something failed: the worst severity across the failing
    resources, the benchmark controls it maps to (CIS/STIG, with levels), and those resources."""

    rule_id: str  # the check steadystate owns, e.g. "k8s-privileged"
    title: str  # a generic, per-control description (from the mapped control's name)
    severity: Severity
    controls: tuple[Reference, ...]  # the benchmark controls this check satisfies (CIS/STIG)
    resources: tuple[str, ...]  # the resource identities failing this check


def _benchmark_refs(finding: PolicyFinding, level: int | None, framework: str | None) -> list:
    """The benchmark (CIS/STIG) references on ``finding`` that pass the optional level/framework
    filters. A level filter applies only to refs that *have* a level (CIS); a non-levelled framework
    (STIG) passes the level filter so it still stacks in."""
    refs = [r for r in finding.references if r.framework in _BENCHMARKS]
    if framework is not None:
        refs = [r for r in refs if r.framework.upper() == framework.upper()]
    if level is not None:
        refs = [r for r in refs if r.level is None or r.level == level]
    return refs


def compliance_report(
    findings: list[PolicyFinding], *, level: int | None = None, framework: str | None = None
) -> list[CheckResult]:
    """Group ``findings`` by the check they failed, citing every benchmark control that check maps
    to. ``level`` (CIS level) and ``framework`` ("CIS"/"STIG") are optional filters; the default
    (both None) stacks every framework and level into one report. Worst severity first, then rule.
    Pure -- the caller collects the findings (the policy + posture passes) and renders."""
    by_check: dict[str, dict] = {}
    for finding in findings:
        refs = _benchmark_refs(finding, level, framework)
        if not refs:
            continue  # no benchmark control matched the filters -> not in this report
        entry = by_check.setdefault(
            finding.rule_id,
            {"severity": finding.severity, "controls": {}, "resources": []},
        )
        entry["resources"].append(finding.identity)
        if _SEVERITY_RANK[finding.severity] > _SEVERITY_RANK[entry["severity"]]:
            entry["severity"] = finding.severity
        for ref in refs:
            entry["controls"].setdefault((ref.framework, ref.id), ref)
    results = [
        CheckResult(
            rule_id=rule_id,
            title=next(iter(entry["controls"].values())).name or rule_id,
            severity=entry["severity"],
            controls=tuple(entry["controls"].values()),
            resources=tuple(dict.fromkeys(entry["resources"])),  # dedupe, keep order
        )
        for rule_id, entry in by_check.items()
    ]
    return sorted(results, key=lambda r: (-_SEVERITY_RANK[r.severity], r.rule_id))


def _control_chips(controls: tuple[Reference, ...]) -> str:
    """The benchmark controls a check maps to, as inline chips: `CIS Kubernetes-5.2.1 (L1)`."""
    parts = []
    for ref in controls:
        suffix = f" (L{ref.level})" if ref.level is not None else ""
        parts.append(f"{ref.framework} {ref.id}{suffix}")
    return "  ".join(parts)


def _scope_label(level: int | None, framework: str | None) -> str:
    fw = framework.upper() if framework else "/".join(_BENCHMARKS)
    return f"{fw} Level {level}" if level is not None else fw


def render_compliance_report(
    results: list[CheckResult],
    *,
    level: int | None = None,
    framework: str | None = None,
    max_resources: int = 10,
) -> list[str]:
    """Render the stacked report as console lines: a header (scope + counts), the scope disclaimer,
    then each failing check worst-first -- its severity, description, the benchmark control chips,
    and the failing resources (capped at ``max_resources``, with a '+N more'). An all-clear when
    nothing failed. Pure."""
    scope = _scope_label(level, framework)
    if not results:
        return [
            f"{scope}: no failures -- every checked control passed on the scanned resources.",
            "",
            DISCLAIMER,
        ]
    affected = len({r for result in results for r in result.resources})
    lines = [
        f"{scope}: {len(results)} check(s) failing across {affected} resource(s)",
        DISCLAIMER,
        "",
    ]
    for result in results:
        chips = _control_chips(result.controls)
        lines.append(f"  [{result.severity.value.upper():<8}] {result.title}   {chips}")
        for identity in result.resources[:max_resources]:
            lines.append(f"      - {identity}")
        if len(result.resources) > max_resources:
            lines.append(f"      ... and {len(result.resources) - max_resources} more")
    return lines


def compliance_report_as_dict(
    results: list[CheckResult], *, level: int | None = None, framework: str | None = None
) -> dict:
    """The stacked report as a JSON-ready dict, for `compliance --json`."""
    return {
        "frameworks": list(_BENCHMARKS) if framework is None else [framework.upper()],
        "level": level,
        "checks_failing": len(results),
        "resources_affected": len({r for result in results for r in result.resources}),
        "disclaimer": DISCLAIMER,
        "checks": [
            {
                "rule_id": result.rule_id,
                "title": result.title,
                "severity": result.severity.value,
                "controls": [
                    {"framework": ref.framework, "id": ref.id, "level": ref.level}
                    for ref in result.controls
                ],
                "resources": list(result.resources),
            }
            for result in results
        ],
    }
