"""Console surface -- the v0 default. Shows correlated Alerts + a Signal count.

When a state store backs the scan (the default), each Alert is annotated with its
memory: a NEW marker the first time a finding is seen, an age ("seen Nd") on
recurrence, and a muted/snoozed tag when an operator has silenced it. Findings that
cleared since the last scan are listed once under "Resolved since last scan".
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import TYPE_CHECKING

from rich.console import Console
from rich.panel import Panel

from ..reason.alert import Alert
from ..reason.report import Report

if TYPE_CHECKING:
    from ..reconcile_state import ResolvedFinding

_SEVERITY_STYLE = {"low": "dim", "medium": "yellow", "high": "red", "critical": "bold red"}


def _reference_chips(alert: Alert) -> str:
    """Compact framework chips like ``[MITRE T1530] [MITRE T1190]``, or "" if none.

    Config-exposure -> technique mapping, not behavioral detection -- the chip names the
    technique the recognized config change *enables*. Empty string when the Alert carries
    no references, so the stateless/no-reference path renders exactly as before.
    """
    return " ".join(f"[{ref.framework} {ref.id}]" for ref in alert.references)


def _memory_marker(alert: Alert, now: datetime | None) -> str | None:
    """The state badge for an Alert's title (NEW / seen Nd / muted / snoozed), or None.

    None when the scan is stateless (``status`` unset) -- the title then renders exactly
    as it did before this feature, so the stateless path is visually unchanged.

    The NEW-vs-age decision needs a reference for "this scan's time". Tests pin it via
    ``now``; in production we use the Alert's own ``created_at`` (stamped in the pure
    pipeline a hair *before* reconcile stamps ``first_seen``), so a first-seen finding has
    ``first_seen >= created_at`` (NEW) and a recurrence has ``first_seen < created_at``
    (an age). This keeps the marker correct without threading a clock through every
    Surface -- Slack/Teams stay untouched.
    """
    if alert.status is None:
        return None
    if alert.status in ("muted", "snoozed"):
        return alert.status.upper()
    if alert.first_seen is None:
        return None
    reference = now if now is not None else alert.created_at
    if alert.first_seen >= reference:
        return "NEW"
    days = max((reference - alert.first_seen).days, 0)
    return f"seen {days}d"


class ConsoleSurface:
    name = "console"

    def __init__(self) -> None:
        self._console = Console()

    def emit(
        self,
        report: Report,
        resolved: Sequence[ResolvedFinding] | None = None,
        now: datetime | None = None,
    ) -> None:
        # ``now`` is the optional scan-time reference for NEW-vs-age (tests pin it); when
        # None, each Alert's own created_at is used (see _memory_marker). We deliberately
        # do NOT coerce it to wall-clock here, so the per-Alert fallback stays available.
        if not report.items and not resolved:
            self._console.print("[green]Steady state: no drift detected.[/green]")
            return

        for alert in report.alerts:
            style = _SEVERITY_STYLE.get(alert.severity.value, "white")
            backed = "LLM" if alert.llm_backed else "deterministic"
            title = f"{alert.title}  |  {backed}"
            marker = _memory_marker(alert, now)
            if marker:
                title = f"{marker}  |  {title}"
            if len(alert.drifts) > 1:
                title += f"  |  {len(alert.drifts)} correlated"
            body = f"[{style}]{alert.severity.value.upper()}[/{style}]  {alert.why_it_matters}"
            where = []
            if alert.environment:  # which environment this scan came from (scan --label)
                where.append(f"[bold]env:[/bold] {alert.environment}")
            if alert.resources:  # *which* resource(s) drifted -- the identity to triage on
                where.append(f"[bold]resource:[/bold] {alert.resource_label()}")
            if alert.symptoms:  # operational malfunction (the second departure type)
                where.append(
                    "[bold]symptom:[/bold] "
                    + ", ".join(sorted({s.category for s in alert.symptoms}))
                )
            if where:
                body += "\n\n" + "   ".join(where)
            if alert.recommended_action:
                body += f"\n\n[bold]Next:[/bold] {alert.recommended_action}"
            chips = _reference_chips(alert)
            if chips:  # only when references exist; absent references render nothing
                body += f"\n\n[dim]{chips}[/dim]"
            if alert.runtime_context:  # live-health note from enrichment; absent -> nothing
                body += f"\n[dim]{alert.runtime_context}[/dim]"
            self._console.print(Panel(body, title=title, title_align="left"))

        if resolved:
            titles = ", ".join(r.title for r in resolved)
            self._console.print(
                f"[green]Resolved since last scan: {len(resolved)}[/green] [dim]({titles})[/dim]"
            )

        if report.signal_count:
            self._console.print(
                f"[dim]+ {report.signal_count} signal(s) below the bar (counted, not shown).[/dim]"
            )

        self._console.print(
            f"[dim]tuning: {report.tuning.value}  |  {len(report.alerts)} alert(s) "
            f"from {report.event_count} event(s), {report.signal_count} signal(s)[/dim]"
        )

    def emit_remediations(self, items: list) -> None:
        """Render remediation plans (and results, if applied).

        Each item is a (RemediationPlan, RemediationResult | None) tuple.
        """
        if not items:
            self._console.print("[green]No drift to remediate.[/green]")
            return
        risk_style = {"low": "dim", "medium": "yellow", "high": "bold red"}
        for plan, result in items:
            style = risk_style.get(plan.risk.value, "white")
            verdict = "[green]eligible[/green]" if plan.eligible else "[red]needs approval[/red]"
            body = (
                f"[{style}]{plan.risk.value.upper()}[/{style}]  {verdict}\n{plan.reason}\n\n"
                f"[bold]Would run:[/bold] {' '.join(plan.command)}\n"
                f"[bold]Blast radius:[/bold] {plan.blast_radius}\n"
                f"[bold]Revert:[/bold] {plan.revert}"
            )
            if result is not None:
                if result.applied and result.verified:
                    status = "[green]applied + verified[/green]"
                elif result.applied:
                    status = "[yellow]applied, not verified[/yellow]"
                else:
                    status = "[dim]not applied[/dim]"
                body += f"\n[bold]Result:[/bold] {status} - {result.detail}"
            self._console.print(Panel(body, title=plan.drift_identity, title_align="left"))
