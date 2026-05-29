"""Console surface -- the v0 default. Shows correlated Alerts + a Signal count."""

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

        for alert in report.alerts:
            style = _SEVERITY_STYLE.get(alert.severity.value, "white")
            backed = "LLM" if alert.llm_backed else "deterministic"
            title = f"{alert.title}  |  {backed}"
            if len(alert.drifts) > 1:
                title += f"  |  {len(alert.drifts)} correlated"
            body = f"[{style}]{alert.severity.value.upper()}[/{style}]  {alert.why_it_matters}"
            if alert.recommended_action:
                body += f"\n\n[bold]Next:[/bold] {alert.recommended_action}"
            self._console.print(Panel(body, title=title, title_align="left"))

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
