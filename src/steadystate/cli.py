"""steadystate command-line interface."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
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
from .reconcile_state import reconcile
from .sources import DRIFT_SOURCES, build_drift_source
from .sources.base import StateSource
from .sources.terraform import TerraformSource
from .state import StateStore

DEFAULT_STATE_PATH = ".steadystate/state.db"

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


def _open_store(state: Path) -> StateStore:
    """Open (auto-creating its parent dir) the SQLite state store at ``state``.

    The schema is created idempotently by StateStore, so this is safe on a fresh box
    or an existing db. The default lives under .steadystate/ (gitignored)."""
    state.parent.mkdir(parents=True, exist_ok=True)
    return StateStore(state)


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
    state: Path = typer.Option(
        Path(DEFAULT_STATE_PATH),
        "--state",
        help="SQLite state db that makes scans memoryful (new/recurring/resolved and "
        "mute/snooze suppression). Auto-created; default under .steadystate/.",
    ),
    stateless: bool = typer.Option(
        False,
        "--stateless",
        help="Skip the state store entirely: a pure, amnesiac scan (no memory, no "
        "suppression, no new/resolved markers).",
    ),
) -> None:
    """Scan declared state for drift and surface the Alerts."""
    surfaces = _surfaces([name.strip() for name in to.split(",") if name.strip()])
    level = _tuning(tuning)
    analyst = LLMAnalyst()
    grouping = _correlator(correlator, analyst)
    src = _drift_source(source, path)
    drifts = src.collect_drift()
    # The declared inventory feeds the standing-policy pass (CIS/STIG). Only sources that
    # enumerate declared state implement StateSource; native drift sources (Terraform,
    # ArgoCD) don't, so they contribute no baseline findings -- guard rather than assume.
    resources = src.collect_declared() if isinstance(src, StateSource) else []
    report = Pipeline(analyst=analyst, tuning=level, correlator=grouping).run(drifts, resources)
    # The Pipeline is pure; memory is applied here, between run() and emit(). Stateless
    # scans skip the store entirely and surface exactly as before (Alerts un-annotated).
    # One `now` for the whole scan so the store's timestamps and the console's NEW-vs-age
    # rendering agree on "this scan's time"; reconcile stamps first_seen == now for a new
    # finding, which the console reads back against each Alert's own created_at.
    now = datetime.now(UTC)
    resolved = []
    if not stateless:
        with _open_store(state) as store:
            resolved = reconcile(report, store, now)
    for surface in surfaces:
        surface.emit(report, resolved=resolved)


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


_STATE_OPTION = typer.Option(
    Path(DEFAULT_STATE_PATH),
    "--state",
    help="SQLite state db (same default as `scan`; auto-created under .steadystate/).",
)


@app.command()
def mute(
    fingerprint: str = typer.Argument(..., help="The Event fingerprint (from `findings`)."),
    note: str = typer.Option("", "--note", help="Why it's muted (recorded with the finding)."),
    actor: str = typer.Option("cli", "--actor", help="Who muted it (recorded for audit)."),
    state: Path = _STATE_OPTION,
) -> None:
    """Mute a finding by fingerprint: future scans suppress it until you `unmute`."""
    with _open_store(state) as store:
        store.mute(fingerprint, note or None, actor, datetime.now(UTC))
    typer.echo(f"muted {fingerprint}")


@app.command()
def unmute(
    fingerprint: str = typer.Argument(..., help="The Event fingerprint to un-mute/un-snooze."),
    state: Path = _STATE_OPTION,
) -> None:
    """Clear a mute or snooze on a finding: it surfaces again on the next scan."""
    with _open_store(state) as store:
        store.unmute(fingerprint, datetime.now(UTC))
    typer.echo(f"unmuted {fingerprint}")


@app.command()
def snooze(
    fingerprint: str = typer.Argument(..., help="The Event fingerprint to snooze."),
    days: int = typer.Option(..., "--days", help="Suppress it for this many days from now."),
    actor: str = typer.Option("cli", "--actor", help="Who snoozed it (recorded for audit)."),
    state: Path = _STATE_OPTION,
) -> None:
    """Snooze a finding for N days: suppressed until the snooze lapses, then it returns."""
    now = datetime.now(UTC)
    with _open_store(state) as store:
        store.snooze(fingerprint, now + timedelta(days=days), actor, now)
    typer.echo(f"snoozed {fingerprint} for {days}d")


@app.command()
def findings(state: Path = _STATE_OPTION) -> None:
    """List stored findings: fingerprint, status, first_seen, last_severity, title."""
    with _open_store(state) as store:
        rows = store.all_findings()
    if not rows:
        typer.echo("no findings recorded yet.")
        return
    # Print the FULL fingerprint, not a prefix: it's the exact value an operator copies
    # into `mute`/`snooze`/`unmute`, and those match on the whole hex (a prefix would
    # silently create a junk finding via their upsert).
    for f in rows:
        typer.echo(
            f"{f.fingerprint}  {f.status:<8}  {f.first_seen}  {f.last_severity:<8}  {f.last_title}"
        )


def main() -> None:
    app()


if __name__ == "__main__":
    main()
