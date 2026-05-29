"""steadystate command-line interface."""

from __future__ import annotations

import json
from pathlib import Path

import typer

from .act.terraform import TerraformExecutor
from .notify import SURFACES, build_surfaces
from .notify.base import Surface
from .notify.console import ConsoleSurface
from .reason.correlate import Correlator
from .reason.llm import LLMAnalyst
from .reason.pipeline import CORRELATORS, Pipeline, build_correlator
from .reason.report import Tuning
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


def _tuning(value: str) -> Tuning:
    try:
        return Tuning(value)
    except ValueError:
        raise typer.BadParameter("tuning must be: lenient | default | strict") from None


def _correlator(value: str, analyst: LLMAnalyst) -> Correlator:
    """Resolve --correlator to a Correlator via the registry in reason/pipeline.py.
    Adding a correlator is a one-line registry entry -- this dispatcher never changes."""
    try:
        return build_correlator(value, analyst)
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
        help=f"Comma-separated surfaces to emit Alerts to: {', '.join(sorted(SURFACES))}.",
    ),
    tuning: str = typer.Option(
        "default",
        "--tuning",
        help="Surfacing bar (moves the Signal/Event/Alert tiers together): "
        "lenient | default | strict.",
    ),
    correlator: str = typer.Option(
        "auto",
        "--correlator",
        help="How to group Events into Alerts: auto (LLM if a provider is configured, "
        f"else deterministic) | {' | '.join(sorted(CORRELATORS))} (force one; the LLM "
        "correlator degrades on failure, deterministic never calls a model).",
    ),
) -> None:
    """Scan declared state for drift and surface the Alerts."""
    surfaces = _surfaces([name.strip() for name in to.split(",") if name.strip()])
    level = _tuning(tuning)
    analyst = LLMAnalyst()
    grouping = _correlator(correlator, analyst)
    drifts = _drift_source(source, path).collect_drift()
    report = Pipeline(analyst=analyst, tuning=level, correlator=grouping).run(drifts)
    for surface in surfaces:
        surface.emit(report)


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
