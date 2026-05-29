"""steadystate command-line interface."""

from __future__ import annotations

import json
from pathlib import Path

import typer

from .act.terraform import TerraformExecutor
from .notify.console import ConsoleSurface
from .reason.pipeline import Pipeline
from .sources.terraform import TerraformSource

app = typer.Typer(
    help="Stateful monitoring: reconcile declared state vs reality, reason about the drift.",
    no_args_is_help=True,
)


@app.callback()
def _root() -> None:
    """Stateful monitoring: reconcile declared state vs reality, reason about drift."""


@app.command()
def scan(
    path: Path = typer.Argument(
        ...,
        help="A Terraform working dir, or a `terraform show -json` plan file.",
    ),
) -> None:
    """Scan declared state for drift and surface the Cases."""
    if path.is_file():
        source = TerraformSource(plan_json=json.loads(path.read_text()))
    else:
        source = TerraformSource(working_dir=path)
    drifts = source.collect_drift()
    cases = Pipeline().run(drifts)
    ConsoleSurface().emit(cases)


@app.command()
def fix(
    path: Path = typer.Argument(
        ...,
        help="A Terraform working dir, or a `terraform show -json` plan file.",
    ),
    apply: bool = typer.Option(
        False, "--apply", help="Run the eligible remediations (default: dry run)."
    ),
) -> None:
    """Show guardrailed remediations for detected drift (use --apply to run the eligible ones)."""
    if path.is_file():
        source = TerraformSource(plan_json=json.loads(path.read_text()))
        executor = TerraformExecutor()
    else:
        source = TerraformSource(working_dir=path)
        executor = TerraformExecutor(working_dir=path)
    items = []
    for drift in source.collect_drift():
        plan = executor.plan_for(drift)
        result = executor.remediate(drift, confirm=True) if (apply and plan.eligible) else None
        items.append((plan, result))
    ConsoleSurface().emit_remediations(items)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
