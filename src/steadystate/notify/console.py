"""Console surface -- the v0 default. Slack/Teams (bidirectional ChatOps) come next."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel

from ..reason.case import Case

_SEVERITY_STYLE = {"low": "dim", "medium": "yellow", "high": "red", "critical": "bold red"}


class ConsoleSurface:
    name = "console"

    def __init__(self) -> None:
        self._console = Console()

    def emit(self, cases: list[Case]) -> None:
        if not cases:
            self._console.print("[green]Steady state: no drift worth surfacing.[/green]")
            return
        for case in cases:
            style = _SEVERITY_STYLE.get(case.severity.value, "white")
            backed = "LLM" if case.llm_backed else "deterministic"
            body = f"[{style}]{case.severity.value.upper()}[/{style}]  {case.why_it_matters}"
            if case.recommended_action:
                body += f"\n\n[bold]Next:[/bold] {case.recommended_action}"
            self._console.print(Panel(body, title=f"{case.title}  |  {backed}", title_align="left"))

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
