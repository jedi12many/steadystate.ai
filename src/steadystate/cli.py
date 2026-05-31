"""steadystate command-line interface."""

from __future__ import annotations

import contextlib
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from .act import EXECUTORS, build_executor
from .act.approve import apply_pending, decline_pending
from .catalog import gather_catalog, render_console, render_html
from .engine import build_report
from .inbound import INBOUND, build_inbound
from .inbound.base import PROBE, Command, command_from_text
from .inbound.server import run_command, serve
from .notify import SURFACES, build_surfaces
from .notify.base import Surface
from .notify.console import ConsoleSurface
from .probe import PROBES
from .reason.cost import roll_up, roll_up_by_period, scan_cost_line
from .reason.enrich import ENRICHERS
from .reason.pipeline import CORRELATORS
from .reconcile_state import reconcile
from .sources import CAPABILITIES, DRIFT_SOURCES, build_drift_source
from .state import PendingAction, StateStore

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


def _open_store(state: Path) -> StateStore:
    """Open (auto-creating its parent dir) the SQLite state store at ``state``.

    The schema is created idempotently by StateStore, so this is safe on a fresh box
    or an existing db. The default lives under .steadystate/ (gitignored)."""
    state.parent.mkdir(parents=True, exist_ok=True)
    return StateStore(state)


def _record_suggestions(
    store: StateStore, source: str, path: Path, report, now: datetime, environment: str | None
) -> list[str]:
    """Under `--autonomy suggest`/`auto`, offer an eligible remediation per drift. Returns the
    fingerprints recorded (what `auto` then applies). An observe-only source (no executor) has
    nothing to suggest. Only `plan.eligible` drifts are recorded -- a REMOVED drift, which would
    destroy a live resource, is never eligible, so it can never reach the auto-apply path."""
    executor = build_executor(source, path)
    if executor is None:
        return []
    recorded: list[str] = []
    for alert in report.alerts:
        for drift in alert.drifts:
            plan = executor.plan_for(drift)
            if plan.eligible:
                store.record_pending(
                    PendingAction(
                        fingerprint=drift.fingerprint,
                        source=source,
                        path=str(path),
                        drift_identity=drift.identity,
                        command=" ".join(plan.command),
                        environment=environment,
                    ),
                    now,
                )
                recorded.append(drift.fingerprint)
    return recorded


def _auto_apply(store: StateStore, fingerprints: list[str]) -> None:
    """Under `--autonomy auto`, run each eligible pending remediation through the SAME guardrailed
    approval core a human `approve` uses. The LLM is never in this decision: eligibility is
    deterministic (act/plan.py), so a hallucinated analysis can't trigger an apply, and a REMOVED
    drift is never eligible, so auto never destroys. Each apply is recorded as actor "auto"."""
    if not fingerprints:
        typer.echo("autonomy=auto: nothing eligible to apply.")
        return
    typer.echo(f"autonomy=auto: applying {len(fingerprints)} eligible remediation(s).")
    results = []
    for fingerprint in fingerprints:
        message, result = apply_pending(store, fingerprint, "auto")
        if result is not None:
            results.append((result.plan, result))
        else:  # drift already cleared, or an observe-only source slipped through
            typer.echo(f"  {fingerprint}: {message}")
    if results:
        ConsoleSurface().emit_remediations(results)


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
    enrich: str = typer.Option(
        "none",
        "--enrich",
        help="Cross-reference each Alert against a live metric and escalate a drift on a "
        f"currently-breaching resource: none (default) | {' | '.join(sorted(ENRICHERS))} "
        "(prometheus needs PROMETHEUS_URL + STEADYSTATE_ENRICH_QUERY; honestly no-ops when "
        "unconfigured/unreachable). For pod/container health use --probe instead.",
    ),
    probe: str = typer.Option(
        "none",
        "--probe",
        help=f"Go deeper than drift: probe the live *health* of declared resources, surfacing "
        f"operational malfunction (Symptoms) even with no drift -- and diagnosing one against a "
        f"co-located drift: none (default) | auto (the probe matching --source) | "
        f"{' | '.join(sorted(PROBES))}. Degrades to no symptoms when the backend is unreachable.",
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
    no_llm: bool = typer.Option(
        False,
        "--no-llm",
        help="Kill switch: make no LLM calls this scan (correlation degrades to "
        "deterministic, analysis to drift facts). Same as STEADYSTATE_LLM_ENABLED=false.",
    ),
    autonomy: str = typer.Option(
        "observe",
        "--autonomy",
        help="observe (alert only, default) | suggest (record an eligible remediation per "
        "drift to approve/decline later) | auto (apply every eligible remediation now -- "
        "guardrailed, never destroys, LLM not in the decision). Acting is always behind the "
        "executor guardrails.",
    ),
    label: str = typer.Option(
        "",
        "--label",
        help="Environment label for this scan (e.g. prod-aws, staging) -- shown on every alert "
        "so an operator knows which environment it came from. Omit for none.",
    ),
    cost: bool = typer.Option(
        False,
        "--cost",
        help="Break this scan's LLM spend down by caller (a one-line total always prints when "
        "any calls were made).",
    ),
) -> None:
    """Scan declared state for drift and surface the Alerts."""
    if autonomy not in ("observe", "suggest", "auto"):
        raise typer.BadParameter("autonomy must be: observe | suggest | auto")
    if autonomy == "auto" and stateless:
        raise typer.BadParameter(
            "--autonomy auto needs the state store for its audit trail; remove --stateless."
        )
    surfaces = _surfaces([name.strip() for name in to.split(",") if name.strip()])
    # The reasoned report -- drift + probe symptoms, scored/correlated/enriched -- comes from
    # the shared engine, the SAME path the chat-summoned probe runs (inbound/server.py). An
    # unknown source/probe/correlator/enricher/tuning surfaces as a clean BadParameter.
    try:
        report = build_report(
            source,
            path,
            probe=probe,
            tuning=tuning,
            correlator=correlator,
            enrich=enrich,
            no_llm=no_llm,
            label=label,
        )
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from None
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
            # Best-effort spend telemetry: persist this scan's LLM calls. Never a
            # correctness path -- a wedged db must not break a scan, so we swallow failures.
            with contextlib.suppress(Exception):
                for call in report.llm_calls:
                    store.record_llm_call(call, now)
            if autonomy in ("suggest", "auto"):  # offer an eligible remediation per drift
                recorded = _record_suggestions(store, source, path, report, now, label or None)
                if autonomy == "auto":  # ...and, on auto, apply them through the same guardrails
                    _auto_apply(store, recorded)
    for surface in surfaces:
        surface.emit(report, resolved=resolved)
    # A paid call should never go unseen: print this scan's spend (silent on a --no-llm run).
    # --cost adds the per-caller breakdown of this scan. Cumulative spend lives in `cost`.
    spend = scan_cost_line(report.llm_calls)
    if spend:
        typer.echo(spend)
        if cost:
            for r in roll_up(report.llm_calls):
                typer.echo(f"  {r.caller:<12} ~${r.cost_usd:.4f}  {r.calls} call(s)")


@app.command()
def fix(
    path: Path = typer.Argument(
        ...,
        help="Source input (same as `scan`): a Terraform dir/plan, or a captured source file.",
    ),
    source: str = typer.Option(
        "terraform",
        "--source",
        help=f"Backend to remediate: {' | '.join(sorted(EXECUTORS))} "
        "(other sources are observe-only -- run `commands` to see).",
    ),
    apply: bool = typer.Option(
        False, "--apply", help="Run the eligible remediations (default: dry run)."
    ),
) -> None:
    """Show guardrailed remediations for detected drift (use --apply to run the eligible ones)."""
    executor = build_executor(source, path)
    if executor is None:
        raise typer.BadParameter(
            f"source '{source}' is observe-only -- no executor to remediate with. "
            "Run `steadystate commands` to see each plugin's act commands."
        )
    items = []
    for drift in _drift_source(source, path).collect_drift():
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


@app.command()
def cost(
    state: Path = _STATE_OPTION,
    window: str = typer.Option(
        "all",
        "--window",
        help="Spend window: all | 24h | 60m (60m is the fastest signal a caller has "
        "gone wild on retries).",
    ),
    by: str = typer.Option(
        "",
        "--by",
        help="Bucket spend over time into a trend: day | week (vs the default per-caller "
        "rollup). Composes with --window. For a richer time series, surface to Prometheus.",
    ),
) -> None:
    """Estimated LLM spend, by caller (default) or over time (--by day|week). Raw tokens are
    recorded per call (incl. failures); dollars are priced at read time, so history re-prices
    when rates change."""
    cutoff: datetime | None = None
    if window == "24h":
        cutoff = datetime.now(UTC) - timedelta(hours=24)
    elif window == "60m":
        cutoff = datetime.now(UTC) - timedelta(hours=1)
    elif window != "all":
        raise typer.BadParameter("window must be: all | 24h | 60m")
    if by and by not in ("day", "week"):
        raise typer.BadParameter("--by must be: day | week")

    with _open_store(state) as store:
        if by:
            periods = roll_up_by_period(store.timed_llm_calls_since(cutoff), by)
            if not periods:
                typer.echo("no LLM calls recorded yet.")
                return
            total = sum(p.cost_usd for p in periods)
            typer.echo(f"LLM spend ({window}, by {by}): ~${total:.4f} total")
            for p in periods:
                fail = f"  {p.failures} failed" if p.failures else ""
                typer.echo(
                    f"  {p.period:<11} ~${p.cost_usd:.4f}  {p.calls} call(s){fail}  "
                    f"{p.total_tokens / 1000:.1f}k tokens"
                )
            return
        rows = roll_up(store.llm_calls_since(cutoff))
    if not rows:
        typer.echo("no LLM calls recorded yet.")
        return
    total = sum(r.cost_usd for r in rows)
    calls = sum(r.calls for r in rows)
    typer.echo(f"LLM spend ({window}): ~${total:.4f} over {calls} call(s)")
    for r in rows:
        fail = f"  {r.failures} failed" if r.failures else ""
        typer.echo(
            f"  {r.caller:<12} ~${r.cost_usd:.4f}  {r.calls} call(s){fail}  "
            f"in={r.input_tokens} out={r.output_tokens} cache_read={r.cache_read_tokens}"
        )


@app.command()
def commands(
    source: str = typer.Option("", "--source", help="Show one source; default shows all."),
) -> None:
    """Document each plugin's commands by permission category: observe (pre-approved,
    read-only) vs potentially destructive (require approval before they run)."""
    if source and source not in CAPABILITIES:
        known = ", ".join(sorted(CAPABILITIES))
        raise typer.BadParameter(f"unknown source '{source}' (known: {known})")
    for name in [source] if source else sorted(CAPABILITIES):
        caps = CAPABILITIES[name]
        typer.echo(name)
        typer.echo("  observe (pre-approved):")
        for cmd in caps.observe:
            typer.echo(f"    {cmd}")
        typer.echo("  potentially destructive (needs approval):")
        if caps.destructive:
            for cmd in caps.destructive:
                typer.echo(f"    {cmd}")
        else:
            typer.echo("    (none -- observe-only plugin)")


@app.command()
def catalog(
    html: bool = typer.Option(
        False,
        "--html",
        help="Emit a self-contained HTML page instead (redirect to a file and open it).",
    ),
) -> None:
    """Show everything this build offers: every plugin (all seams) and every command + option.

    Read live from the registries, so it always matches what's installed. `--html` writes a
    standalone page: `steadystate catalog --html > catalog.html`."""
    cat = gather_catalog(typer.main.get_command(app))
    if html:
        typer.echo(render_html(cat))
    else:
        render_console(cat, Console())


@app.command()
def pending(state: Path = _STATE_OPTION) -> None:
    """List remediations awaiting approval (recorded by `scan --autonomy suggest`)."""
    with _open_store(state) as store:
        rows = store.all_pending()
    if not rows:
        typer.echo("no pending remediations.")
        return
    for p in rows:
        typer.echo(f"{p.fingerprint}  {p.source}  {p.drift_identity}")
        typer.echo(f"    would run: {p.command}")


@app.command()
def history(
    label: str = typer.Option(
        "", "--label", help="Filter to one environment label (from scan --label)."
    ),
    limit: int = typer.Option(20, "--limit", help="Show the most recent N entries."),
    state: Path = _STATE_OPTION,
) -> None:
    """Show the remediation audit log: every approve/decline, newest first (append-only)."""
    with _open_store(state) as store:
        rows = store.audit_log(limit=limit, environment=label or None)
    if not rows:
        typer.echo("no remediation history.")
        return
    table = Table(box=None, pad_edge=False)
    for column in ("when", "actor", "decision", "outcome", "environment", "resource"):
        table.add_column(column)
    for entry in rows:
        table.add_row(
            entry.at.replace("T", " ")[:19],  # ISO -> "YYYY-MM-DD HH:MM:SS"
            entry.actor,
            entry.decision,
            entry.outcome,
            entry.environment or "-",
            entry.drift_identity,
        )
    Console().print(table)


@app.command()
def approve(
    fingerprint: str = typer.Argument(
        ..., help="The drift fingerprint to remediate (from `pending`)."
    ),
    actor: str = typer.Option("cli", "--actor", help="Who approved it (recorded for audit)."),
    state: Path = _STATE_OPTION,
) -> None:
    """Approve a pending remediation: rebuild its source + executor and run it, guardrailed."""
    with _open_store(state) as store:
        message, result = apply_pending(store, fingerprint, actor)
    if result is not None:
        ConsoleSurface().emit_remediations([(result.plan, result)])
    else:
        typer.echo(message)


@app.command()
def decline(
    fingerprint: str = typer.Argument(..., help="The drift fingerprint to decline."),
    actor: str = typer.Option("cli", "--actor", help="Who declined it (recorded for audit)."),
    state: Path = _STATE_OPTION,
) -> None:
    """Decline a pending remediation: it won't be re-offered until you approve it later."""
    with _open_store(state) as store:
        typer.echo(decline_pending(store, fingerprint, actor))


@app.command()
def listen(
    channel: str = typer.Option(
        "slack",
        "--from",
        help=f"Chat channel to accept commands from: {' | '.join(sorted(INBOUND))}.",
    ),
    port: int = typer.Option(8723, "--port", help="Port for the interactivity endpoint."),
    state: Path = _STATE_OPTION,
) -> None:
    """Run the chat command listener: the persistent, two-way counterpart to a scheduled scan.
    It accepts `approve`/`decline` (the gated remediation), the read-only `help`/`pending`, and
    `probe <target>` (Summon -- an on-demand scan of a named target from STEADYSTATE_TARGETS).
    Each channel needs its signing secret / public key in the environment; point your chat app's
    Request URL at http://<host>:<port>/. Set STEADYSTATE_TARGETS to enable `probe`."""
    try:
        adapter = build_inbound(channel)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from None
    problem = adapter.ready()
    if problem:
        raise typer.BadParameter(problem)
    state.parent.mkdir(parents=True, exist_ok=True)
    typer.echo(f"steadystate: listening for {adapter.name} commands on :{port}")
    serve(adapter, port, str(state))


def _local_actor() -> str:
    """Who's at the terminal -- recorded on a chat command's audit trail, like a chat username."""
    return os.environ.get("USER") or os.environ.get("USERNAME") or "cli"


@app.command()
def chat(state: Path = _STATE_OPTION) -> None:
    """A local chat client: drive the listener's command grammar from your terminal -- no Slack /
    Teams / Discord, no signing (a local shell is already trusted). It runs the SAME parser
    (command_from_text) and dispatch (run_command) the chat adapters use, so it's a faithful way to
    exercise the chat mechanism. Commands: `help`, `pending`, `probe <target>` (needs
    STEADYSTATE_TARGETS), `approve <fp>`, `decline <fp>`. Ctrl-D or `exit` to quit."""
    state.parent.mkdir(parents=True, exist_ok=True)
    actor = _local_actor()
    typer.echo("steadystate chat -- type `help`, or a command. Ctrl-D (or `exit`) to quit.")
    while True:
        try:
            line = input("steadystate> ").strip()
        except EOFError:
            typer.echo("")
            break
        if not line:
            continue
        if line in ("exit", "quit"):
            break
        command = command_from_text(line, actor)
        if command is None:
            typer.echo("unrecognized -- type `help` for the commands this accepts.")
            continue
        typer.echo(run_command(command, str(state)))


@app.command()
def probe(
    target: str = typer.Argument(..., help="A named target from STEADYSTATE_TARGETS to scan now."),
    state: Path = _STATE_OPTION,
) -> None:
    """Summon a scan of a named target now -- the one-shot, scriptable form of the chat
    `probe <target>` verb. Resolves the target from STEADYSTATE_TARGETS, runs the read-only engine
    (drift + health), and prints what's wrong. The SAME path the listener runs, so it's a faithful
    local test of Summon -- and easy to drop into cron/CI."""
    state.parent.mkdir(parents=True, exist_ok=True)
    typer.echo(run_command(Command(PROBE, _local_actor(), target), str(state)))


def main() -> None:
    app()


if __name__ == "__main__":
    main()
