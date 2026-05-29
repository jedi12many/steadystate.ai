"""Console surface -- the v0 default. Shows the full three-tier breakdown."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel

from ..reason.report import Report

_SEVERITY_STYLE = {"low": "dim", "medium": "yellow", "high": "red", "critical": "bold red"}


class ConsoleSurface:
    name = "console"

    def __init__(self) -> None:
        self._console = Console()

    def emit(self, report: Report) -> None:
        if not report.items:
            self._console.print("[green]Steady state: no drift detected.[/green]")
            return

        for alert in report.alerts:  # surfaced: full panel
            style = _SEVERITY_STYLE.get(alert.severity.value, "white")
            backed = "LLM" if alert.llm_backed else "deterministic"
            body = f"[{style}]{alert.severity.value.upper()}[/{style}]  {alert.why_it_matters}"
            if alert.recommended_action:
                body += f"\n\n[bold]Next:[/bold] {alert.recommended_action}"
            self._console.print(
                Panel(body, title=f"{alert.title}  |  {backed}", title_align="left")
            )

        for event in report.events:  # recorded: one line each
            style = _SEVERITY_STYLE.get(event.severity.value, "white")
            self._console.print(
                f"[{style}]EVENT {event.severity.value.upper()}[/{style}]  {event.title}"
            )

        if report.signal_count:  # firehose: counted, not listed
            self._console.print(
                f"[dim]+ {report.signal_count} signal(s) below the bar (counted, not shown).[/dim]"
            )

        self._console.print(
            f"[dim]tuning: {report.tuning.value}  |  "
            f"{len(report.alerts)} alert(s), {len(report.events)} event(s), "
            f"{report.signal_count} signal(s)[/dim]"
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
