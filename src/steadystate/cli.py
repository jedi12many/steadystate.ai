"""steadystate command-line interface."""

from __future__ import annotations

import json
from pathlib import Path

import typer

from .act.terraform import TerraformExecutor
from .notify.console import ConsoleSurface
from .notify.slack import SlackSurface
from .reason.pipeline import Pipeline
from .sources.argocd import ArgoCDSource
from .sources.terraform import TerraformSource

app = typer.Typer(
    help="Stateful monitoring: reconcile declared state vs reality, reason about the drift.",
    no_args_is_help=True,
)


@app.callback()
def _root() -> None:
    """Stateful monitoring: reconcile declared state vs reality, reason about drift."""


def _drift_source(source: str, path: Path):
    """Build a drift source from the --source choice. Terraform and ArgoCD both
    reconcile natively (DriftSource). docker-compose is declared-only and needs a
    reconcile flow, so it is not a scan source yet."""
    if source == "terraform":
        if path.is_file():
            return TerraformSource(plan_json=json.loads(path.read_text()))
        return TerraformSource(working_dir=path)
    if source == "argocd":
        return ArgoCDSource(app=json.loads(path.read_text()))
    raise typer.BadParameter(f"unknown source '{source}' (expected: terraform | argocd)")


@app.command()
def scan(
    path: Path = typer.Argument(
        ...,
        help="Source input: a Terraform dir / `terraform show -json` plan file, "
        "or an ArgoCD Application JSON file (with --source argocd).",
    ),
    source: str = typer.Option(
        "terraform", "--source", help="Declared-state source: terraform | argocd."
    ),
    slack: bool = typer.Option(
        False, "--slack", help="Also emit Cases to Slack (needs SLACK_WEBHOOK_URL)."
    ),
) -> None:
    """Scan declared state for drift and surface the Cases."""
    drifts = _drift_source(source, path).collect_drift()
    cases = Pipeline().run(drifts)
    ConsoleSurface().emit(cases)
    if slack:
        SlackSurface().emit(cases)


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
