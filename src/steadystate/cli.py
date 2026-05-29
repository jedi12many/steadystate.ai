"""steadystate command-line interface."""

from __future__ import annotations

import json
from pathlib import Path

import typer

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


def main() -> None:
    app()


if __name__ == "__main__":
    main()
