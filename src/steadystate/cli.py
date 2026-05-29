"""steadystate command-line interface."""

from __future__ import annotations

import json
from pathlib import Path

import typer

from .act.terraform import TerraformExecutor
from .notify import SURFACES, build_surfaces
from .notify.base import Surface
from .notify.console import ConsoleSurface
from .reason.pipeline import Pipeline
from .sources import DRIFT_SOURCES, build_drift_source
from .sources.terraform import TerraformSource

app = typer.Typer(
    help="Stateful monitoring: reconcile declared state vs reality, reason about the drift.",
    no_args_is_help=True,
)


@app.callback()
def _root() -> None:
    """Stateful monitoring: reconcile declared state vs reality, reason about drift."""


def _drift_source(source: str, path: Path):
    """Resolve --source to a DriftSource via the registry in sources/__init__.py.
    Adding a source is a one-line registry entry -- this dispatcher never changes."""
    try:
        return build_drift_source(source, path)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from None


def _surfaces(names: list[str]) -> list[Surface]:
    """Resolve --to to Surfaces via the registry in notify/__init__.py.
    Adding a surface is a one-line registry entry -- this dispatcher never changes."""
    try:
        return build_surfaces(names)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from None


@app.command()
def scan(
    path: Path = typer.Argument(
        ...,
        help="Source input: a Terraform dir / `terraform show -json` plan file, "
        "or an ArgoCD Application JSON file (with --source argocd).",
    ),
    source: str = typer.Option(
        "terraform",
        "--source",
        help=f"Declared-state source: {' | '.join(sorted(DRIFT_SOURCES))}.",
    ),
    to: str = typer.Option(
        "console",
        "--to",
        help=f"Comma-separated surfaces to emit Cases to: {', '.join(sorted(SURFACES))}.",
    ),
) -> None:
    """Scan declared state for drift and surface the Cases."""
    names = [name.strip() for name in to.split(",") if name.strip()]
    surfaces = _surfaces(names)
    drifts = _drift_source(source, path).collect_drift()
    cases = Pipeline().run(drifts)
    for surface in surfaces:
        surface.emit(cases)


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
