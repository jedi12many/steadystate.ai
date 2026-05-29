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
