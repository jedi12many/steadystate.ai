"""Fleet sweep: probe every target (cluster) in one pass and roll up what's on fire.

The single-target ``probe`` is the instant, stateless look at one cluster; this is the **batch**:
``probe all`` (chat) and ``steadystate sweep`` (CLI) run every target through the same engine and
report a fleet digest -- which clusters are on fire, which are clear, what changed since the last
sweep.

It is **stateful** by design (unlike the single ``probe``): each sweep reconciles against the
state store, so a cluster that catches fire reads as *new* and one that recovers reads as
*resolved*. The catch a fleet must get right: a per-target reconcile would call ``resolve_absent``
with only one cluster's fingerprints and so mark every *other* cluster's findings resolved. So we
reconcile **once over the union** of all targets' reports -- correct presence/absence across the
whole fleet. (Findings stay distinct per cluster because the live source qualifies each identity
with its context.)
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .engine import build_report
from .reason.report import Report
from .reconcile_state import reconcile
from .state import StateStore
from .targets import Target


@dataclass(frozen=True)
class TargetResult:
    """One target's outcome in a sweep: whether the probe ran, how many alerts (fires) it surfaced,
    how many are new this sweep, and -- when it failed -- why."""

    name: str
    ok: bool
    alerts: int = 0
    new: int = 0
    detail: str = ""  # the failure message when ``ok`` is False
    titles: tuple[str, ...] = ()  # the alert titles, worst-first (for the digest)


@dataclass(frozen=True)
class SweepResult:
    """A whole fleet sweep: a result per target, plus the findings resolved across the fleet."""

    results: tuple[TargetResult, ...] = ()
    resolved: tuple[str, ...] = ()  # titles of findings gone from the whole fleet this sweep

    @property
    def on_fire(self) -> int:
        return sum(1 for r in self.results if r.ok and r.alerts)

    @property
    def clear(self) -> int:
        return sum(1 for r in self.results if r.ok and not r.alerts)

    @property
    def unreachable(self) -> int:
        return sum(1 for r in self.results if not r.ok)


def sweep_targets(
    targets: dict[str, Target],
    state_path: str | Path,
    now: datetime | None = None,
    *,
    stateless: bool = False,
) -> SweepResult:
    """Probe every target and roll up the fleet. Stateful unless ``stateless``: one reconcile over
    the **union** of all reports (so absence is judged fleet-wide, never per-target), which records
    new/recurring and returns what resolved across the fleet. A target whose probe raises (an
    unreachable cluster, a missing kubectl) is reported as not-``ok`` and never sinks the sweep."""
    now = now or datetime.now(UTC)

    built: list[tuple[str, Report | None, str]] = []
    for name, target in sorted(targets.items()):
        try:
            report = build_report(
                target.source,
                Path(target.path),
                probe="auto",
                label=target.label,
                context=target.context,
            )
            built.append((name, report, ""))
        except Exception as exc:  # an unreachable/misconfigured cluster must not sink the sweep
            built.append((name, None, str(exc)))

    resolved_titles: tuple[str, ...] = ()
    live: list[Report] = [rep for _, rep, _ in built if rep is not None]
    if not stateless and live:
        # ONE reconcile over the union -- so resolve_absent judges presence across the whole fleet,
        # not per-target (which would resolve every other cluster's findings).
        combined = Report(items=[item for rep in live for item in rep.items])
        Path(state_path).parent.mkdir(parents=True, exist_ok=True)
        with StateStore(state_path) as store:
            resolved = reconcile(combined, store, now)
            for rep in live:  # best-effort spend telemetry, like a normal scan
                for call in rep.llm_calls:
                    store.record_llm_call(call, now)
        resolved_titles = tuple(r.title for r in resolved)

    results: list[TargetResult] = []
    for name, report_opt, detail in built:
        if report_opt is None:
            results.append(TargetResult(name=name, ok=False, detail=detail))
            continue
        alerts = report_opt.alerts
        new = sum(1 for a in alerts if a.first_seen == now)  # first_seen == this sweep -> new
        results.append(
            TargetResult(
                name=name,
                ok=True,
                alerts=len(alerts),
                new=new,
                titles=tuple(a.title for a in alerts),
            )
        )
    return SweepResult(results=tuple(results), resolved=resolved_titles)


def render_sweep(result: SweepResult, *, verbose: bool = False) -> list[str]:
    """The fleet digest as lines: a headline tally, then a line per target (on fire / clear /
    unreachable), and what resolved fleet-wide. ``verbose`` lists each fire's title. Pure."""
    n = len(result.results)
    head = (
        f"Fleet sweep: {n} cluster(s) -- {result.on_fire} on fire, "
        f"{result.clear} clear, {result.unreachable} unreachable."
    )
    lines = [head]
    for r in result.results:
        if not r.ok:
            lines.append(f"  {r.name:<24} unreachable -- {r.detail}")
        elif r.alerts:
            new = f" ({r.new} new)" if r.new else ""
            lines.append(f"  {r.name:<24} {r.alerts} alert(s){new}")
            if verbose:
                lines.extend(f"      - {title}" for title in r.titles)
        else:
            lines.append(f"  {r.name:<24} clear")
    if result.resolved:
        lines.append(f"  resolved since last sweep ({len(result.resolved)}):")
        lines.extend(f"      - {title}" for title in result.resolved)
    return lines
