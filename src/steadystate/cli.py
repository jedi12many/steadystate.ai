"""steadystate command-line interface."""

from __future__ import annotations

import contextlib
import json
import os
import re
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from .act import EXECUTORS, build_executor
from .act.approve import apply_pending, decline_pending
from .act.base import Proposer
from .act.cleanup import record_cleanups
from .act.decide import (
    AUTHORIZED,
    ESCALATE,
    REJECTED,
    CatalogDecider,
    Decider,
    LLMDecider,
    act_on_proposals,
    decider_auto_enabled,
    environment_context,
    propose_for,
    record_proposals,
)
from .act.deliver import build_deliveries
from .act.plan import can_run_unattended
from .act.reflex import reflexes, run_hold
from .act.solution_remedy import record_solution_remediations
from .catalog import gather_catalog, render_console, render_html
from .compliance import (
    compliance_report,
    compliance_report_as_dict,
    render_compliance_report,
)
from .config import config_table
from .discover import (
    ansible_live_target,
    context_reachable,
    context_targets,
    deep_inspect,
    deep_targets,
    emit_github_actions,
    emittable_sources,
    kube_contexts,
    kubeconfig_targets,
    probe_environment,
    proposed_targets,
    render_inspections,
    scannable_now,
)
from .discover import (
    as_dict as discovery_as_dict,
)
from .discover import render as render_discovery
from .domains import default_domains, evaluate_posture_with, evaluate_with
from .engine import build_report, collect_resources
from .inbound import INBOUND, build_inbound
from .inbound.base import PROBE, Command, command_from_text, tool_schema
from .inbound.server import serve
from .inbound.translate import (
    confident_command,
    nl_to_command,
    persist_llm_calls,
    state_snapshot,
)
from .notify import SURFACES, build_surfaces
from .notify.base import Surface
from .notify.console import ConsoleSurface
from .onboarding import SECTIONS, Status, audit, read_env_file, summary, write_env_file
from .probe import PROBE_CAPABILITIES, PROBES
from .reason.cost import roll_up, roll_up_by_period, scan_cost_line
from .reason.enrich import ENRICHERS
from .reason.explain import explain_finding, explain_state, finding_facts
from .reason.llm import LLMAnalyst
from .reason.pipeline import CORRELATORS
from .reconcile_state import reconcile
from .serialize import report_to_dict
from .sources import CAPABILITIES, DRIFT_SOURCES, PATHLESS_SOURCES, build_drift_source
from .sources.base import DriftSource, SourceError
from .sources.k8s import HelmLiveSource, KustomizeLiveSource, capture_baseline
from .state import OPEN, Finding, PendingAction, StateStore, filter_findings
from .sweep import render_sweep, sweep_targets
from .targets import (
    DEFAULT_TARGETS_FILE,
    TARGETS_ENV,
    Target,
    load_targets,
    save_targets,
    target_issues,
)
from .verbs import run_command

DEFAULT_STATE_PATH = ".steadystate/state.db"

app = typer.Typer(
    help="Stateful monitoring: reconcile declared state vs reality, reason about the drift.",
    no_args_is_help=True,
)


def _version_callback(value: bool) -> None:
    if value:
        from . import __version__

        typer.echo(f"steadystate {__version__}")
        raise typer.Exit()


_ACTIVE_SILO = ""  # the named silo this invocation is operating in (set by --silo), for the label


@app.callback()
def _root(
    version: bool = typer.Option(
        False,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Show the steadystate version and exit.",
    ),
    silo: str = typer.Option(
        "",
        "--silo",
        help="Operate in a named silo (a registered deployment): chdir into its folder so its "
        "state.db / targets / checks / kubeconfig all resolve there -- keeping deployments apart. "
        "Register with `steadystate silo add <name> <dir>`. Like `git -C`, but by name.",
    ),
) -> None:
    """Stateful monitoring: reconcile declared state vs reality, reason about drift."""
    global _ACTIVE_SILO
    _ACTIVE_SILO = silo  # reset each invocation (CliRunner reuses the process)
    if not silo:
        return
    from .silos import resolve_silo

    directory = resolve_silo(silo)
    if directory is None:
        raise typer.BadParameter(f"unknown silo: {silo!r}. See `steadystate silo list`.")
    if not Path(directory).is_dir():
        raise typer.BadParameter(f"silo {silo!r} points at a missing folder: {directory}")
    os.chdir(directory)  # every relative default now resolves inside this silo


silo_app = typer.Typer(
    help="Manage named silos -- your deployments, kept separate (each its own folder/state).",
    no_args_is_help=True,
)
app.add_typer(silo_app, name="silo")


@silo_app.command("add")
def silo_add(
    name: str = typer.Argument(..., help="A short name for this deployment, e.g. gateway-use1."),
    directory: str = typer.Argument(..., help="Its folder (holds .steadystate/ + the kubeconfig)."),
) -> None:
    """Register a deployment as a named silo, so you can `--silo <name>` instead of a long path.
    Stores only the folder path (never secrets). Re-adding a name re-points it."""
    from .silos import add_silo

    target = Path(directory).expanduser()
    if not target.is_dir():
        typer.echo(f"not a directory: {directory}", err=True)
        raise typer.Exit(1)
    stored = add_silo(name, directory)
    typer.echo(f"silo '{name}' -> {stored}")


@silo_app.command("discover")
def silo_discover(
    directory: str = typer.Argument("", help="Parent folder to scan (default: current dir)."),
) -> None:
    """Auto-register every immediate subfolder that has a `.steadystate/` as a named silo (named by
    the subfolder). From a `prod/` holding `web1/ web2/ runners1/` -- each with its own
    `.steadystate/` -- names them all in one go. Re-running re-points to where they are now."""
    from .silos import add_silo, discover_silos

    found = discover_silos(directory)
    if not found:
        where = directory or "the current directory"
        typer.echo(f"no silos found under {where} (no immediate subfolder has a .steadystate/).")
        raise typer.Exit(1)
    for name in sorted(found):
        typer.echo(f"silo '{name}' -> {add_silo(name, found[name])}")
    typer.echo(f"registered {len(found)} silo(s).")


@silo_app.command("list")
def silo_list() -> None:
    """List the registered silos (name -> folder). Flags any whose folder has gone missing."""
    from .silos import load_silos, silos_path

    silos = load_silos()
    if not silos:
        typer.echo(f"no silos registered (registry: {silos_path()}).")
        typer.echo("add one with:  steadystate silo add <name> <dir>")
        return
    typer.echo(f"{len(silos)} silo(s):")
    for name in sorted(silos):
        directory = silos[name]
        mark = "" if Path(directory).is_dir() else "   (MISSING)"
        typer.echo(f"  {name}  ->  {directory}{mark}")


@silo_app.command("rm")
def silo_remove(
    name: str = typer.Argument(..., help="The silo name to drop from the registry."),
) -> None:
    """Forget a silo (removes only the registry entry -- never touches the folder or its data)."""
    from .silos import remove_silo

    if remove_silo(name):
        typer.echo(f"removed silo '{name}'.")
    else:
        typer.echo(f"no silo named '{name}'.", err=True)
        raise typer.Exit(1)


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


def _confirm_llm_egress(provider: str, model: str, system: str, user: str) -> bool:
    """The `--confirm-llm` egress gate: show exactly what would be sent + where, then ask. Returns
    True to allow the send. The analyst degrades to deterministic on a decline -- nothing leaves."""
    console = Console()
    console.print(f"\n[bold yellow]About to send a prompt to {provider} ({model}).[/bold yellow]")
    console.print("[dim]--- instruction ---[/dim]")
    console.print(system)
    console.print("[dim]--- content (your declared/observed state) ---[/dim]")
    console.print(user)
    return typer.confirm("Send this to the model?", default=False)


def _open_store(state: Path) -> StateStore:
    """Open (auto-creating its parent dir) the SQLite state store at ``state``.

    The schema is created idempotently by StateStore, so this is safe on a fresh box
    or an existing db. The default lives under .steadystate/ (gitignored)."""
    state.parent.mkdir(parents=True, exist_ok=True)
    return StateStore(state)


def _record_suggestions(
    store: StateStore, source: str, path: Path, report, now: datetime, environment: str | None
) -> tuple[list[str], list[str]]:
    """Under `--autonomy suggest`/`auto`, record a suggestion per drift. A suggestion carries
    whichever directions exist: the *enforce* command (when apply-eligible) and/or an
    *accept-reality* patch (a code change for the same drift, when the executor can render one).

    Returns ``(auto, held)``: the eligible fingerprints **within the autonomous bound** that `auto`
    applies, and the eligible-but-out-of-bound ones it records as pending and leaves for a human.
    Eligibility (human-approvable) and the bound (auto-runnable) are different gates: a recoverable
    terraform change is recorded for approval but, under the default bound, *held* from auto -- so
    `auto` never runs a change the operator hasn't allowed unattended (widen `STEADYSTATE_BOUND` to
    opt in). A patch-only suggestion (a REMOVED drift, where enforcing would destroy) is recorded
    for review but is in neither list, so it never auto-applies. Observe-only source -> nothing."""
    executor = build_executor(source, path)
    if executor is None:
        return [], []
    auto: list[str] = []
    held: list[str] = []
    for alert in report.alerts:
        for drift in alert.drifts:
            plan = executor.plan_for(drift)
            # isinstance inline (not a saved bool) so the type checker narrows `executor` to
            # Proposer for the call -- an executor without the optional capability yields no patch.
            artifact = executor.propose(drift) if isinstance(executor, Proposer) else None
            if not plan.eligible and artifact is None:
                continue  # nothing to enforce and nothing to accept -- not a suggestion
            store.record_pending(
                PendingAction(
                    fingerprint=drift.fingerprint,
                    source=source,
                    path=str(path),
                    drift_identity=drift.identity,
                    command=" ".join(plan.command) if plan.eligible else "",
                    environment=environment,
                    patch=artifact.patch if artifact is not None else None,
                ),
                now,
            )
            if plan.eligible:
                (auto if can_run_unattended(plan) else held).append(drift.fingerprint)
    return auto, held


def _deliver(source: str, path: Path, report, deliver_names: list[str]) -> None:
    """`--deliver`: ship each drift's accept-reality code change through the chosen adapter(s).
    Orthogonal to --autonomy -- it works even under `observe` (just open the PRs; enforce nothing).
    The patch is deterministic (no model); auth lives in the adapter, and the default needs none.
    A source with no code-change artifacts, or an unconfigured adapter, is skipped honestly."""
    executor = build_executor(source, path)
    if not isinstance(executor, Proposer):
        typer.echo(f"--deliver: source '{source}' has no code-change artifacts to deliver.")
        return
    try:
        adapters = build_deliveries(deliver_names)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from None
    ready = []
    for adapter in adapters:
        if adapter.ready():
            ready.append(adapter)
        else:
            typer.echo(f"  delivery '{adapter.name}' is not configured; skipping.")
    artifacts = [
        artifact
        for alert in report.alerts
        for drift in alert.drifts
        if (artifact := executor.propose(drift)) is not None
    ]
    if not artifacts or not ready:
        return
    typer.echo(f"--deliver: {len(artifacts)} code-change artifact(s).")
    for artifact in artifacts:
        typer.echo(f"  {artifact.title}")
        for adapter in ready:
            receipt = adapter.deliver(artifact)
            verb = "delivered" if receipt.delivered else "skipped"
            typer.echo(f"    {verb} via {adapter.name}: {receipt.ref or receipt.detail}")


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


def _targets_file() -> Path:
    """Targets registry path: STEADYSTATE_TARGETS if set, else .steadystate/targets.json."""
    return Path(os.environ.get(TARGETS_ENV) or DEFAULT_TARGETS_FILE)


def _resolve_target(name: str) -> Target:
    """Look up a named target in the registry, or raise a clean BadParameter (missing file,
    malformed file, or unknown name -- listing what's known)."""
    target_file = _targets_file()
    if not target_file.exists():
        raise typer.BadParameter(
            f"--target needs a targets file; none at {target_file}. "
            "Create one with `discover --create`."
        )
    try:
        registry = load_targets(target_file)
    except (OSError, ValueError) as exc:
        raise typer.BadParameter(f"targets file {target_file} is malformed: {exc}") from exc
    resolved = registry.get(name)
    if resolved is None:
        known = ", ".join(sorted(registry)) or "(none)"
        raise typer.BadParameter(f"unknown target '{name}'. Known: {known}.")
    return resolved


def _spend_dict(calls: list) -> dict | None:
    """This scan's LLM spend as a JSON-ready dict (total + per-caller), or None when nothing was
    spent -- the structured form of the human spend line, for `--json`."""
    if not calls:
        return None
    rows = roll_up(calls)
    return {
        "usd": round(sum(r.cost_usd for r in rows), 6),
        "calls": sum(r.calls for r in rows),
        "by_caller": [
            {"caller": r.caller, "usd": round(r.cost_usd, 6), "calls": r.calls} for r in rows
        ],
    }


@app.command()
def scan(
    path: Path | None = typer.Argument(
        None,
        help="Source input: a Terraform dir / `terraform show -json` plan file, "
        "or an ArgoCD Application JSON file (with --source argocd). Omit when using --target.",
    ),
    source: str = typer.Option(
        "terraform",
        "--source",
        help=f"Declared-state source: {' | '.join(sorted(DRIFT_SOURCES))}.",
    ),
    target: str = typer.Option(
        "",
        "--target",
        help="Run a named target from the registry (STEADYSTATE_TARGETS, else "
        ".steadystate/targets.json) -- "
        "the one `discover --create` writes and chat resolves. Supplies source/path/label/probe; "
        "an explicit --label/--probe still wins. Mutually exclusive with the positional path.",
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
    confirm_llm: bool = typer.Option(
        False,
        "--confirm-llm",
        help="Before any prompt is sent to the model, show it (the instruction + your infra "
        "state) and the destination, and ask. Decline -> nothing leaves the box, the scan "
        "degrades to deterministic. A per-call egress review and a hard spend gate. Interactive "
        "only: with no terminal to ask on it runs without the LLM (fail-closed).",
    ),
    autonomy: str = typer.Option(
        "observe",
        "--autonomy",
        help="observe (alert only, default) | suggest (record a suggestion per drift to "
        "approve/decline later -- the eligible apply command and/or an accept-reality code-change "
        "patch, shown by `pending`) | auto (apply every eligible remediation now -- guardrailed, "
        "never destroys, LLM not in the decision). Acting is always behind the executor "
        "guardrails.",
    ),
    deliver: str = typer.Option(
        "none",
        "--deliver",
        help="Ship each drift's accept-reality code change somewhere reviewable -- an axis "
        "orthogonal to --autonomy (which is about *enforcing*). none (default) | patch-file "
        "(write a .patch under STEADYSTATE_PATCH_DIR, no auth) | github-pr (open a PR via the "
        "GitHub API; needs STEADYSTATE_GITHUB_TOKEN/GITHUB_TOKEN). Comma-separated for several; "
        "an unconfigured adapter is skipped.",
    ),
    label: str = typer.Option(
        "",
        "--label",
        help="Environment label for this scan (e.g. prod-aws, staging) -- shown on every alert "
        "so an operator knows which environment it came from. Omit for none.",
    ),
    context: str = typer.Option(
        "",
        "--context",
        help="Aim a live source at a named backend context -- today a kube context, so "
        "`--source k8s-live --context <ctx>` probes that one cluster for fires (a target = a "
        "cluster). Ignored by sources that read a file/dir. Omit for the ambient context.",
    ),
    kubeconfig: str = typer.Option(
        "",
        "--kubeconfig",
        help="Read the context from this kubeconfig file (for a context not on kubectl's default "
        "path, e.g. one sitting in the project dir). Adds `--kubeconfig` to every kubectl call.",
    ),
    inventory: str = typer.Option(
        "",
        "--inventory",
        help="Ansible inventory for `--source ansible-live` (live host/service health). Passed to "
        "the probe as `-i`. Omit to use ansible.cfg's default.",
    ),
    cost: bool = typer.Option(
        False,
        "--cost",
        help="Break this scan's LLM spend down by caller (a one-line total always prints when "
        "any calls were made).",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Show the evidence per alert on the console: the declared->observed before/after "
        "(and policy/symptom detail), so a scan can be audited, not just trusted.",
    ),
    json_out: bool = typer.Option(
        False,
        "--json",
        help="Emit the report as JSON to stdout instead of the console digest -- scriptable, an "
        "agent-readable object (alerts with reasoning, fingerprints, evidence, before/after). "
        "Memory still applies (status/first_seen/resolved included); suppresses the surfaces.",
    ),
) -> None:
    """Scan declared state for drift and surface the Alerts."""
    # --target resolves source/path/label/probe from the registry (the same one chat uses), so a
    # `discover --create`'d target runs from the CLI by name. Explicit --label/--probe still win;
    # --source is the target's (the path it points at must match it).
    if target:
        if path is not None:
            raise typer.BadParameter("pass a path or --target, not both.")
        tgt = _resolve_target(target)
        source = tgt.source
        # A live target (k8s-live) has no path -- give the factory the placeholder it ignores.
        path = Path(tgt.path) if tgt.path else Path(".")
        label = label or tgt.label
        if probe == "none":
            probe = tgt.probe
        context = context or tgt.context  # explicit --context still wins
    elif path is None:
        # No path + no target: fall back to the committed config's [defaults], so a configured repo
        # runs a bare `scan` (the repo IS the wall). Config source only applies when source is still
        # the built-in default (an explicit --source argocd still wins); config path fills the path.
        defaults = config_table("defaults")
        if source == "terraform" and defaults.get("source"):
            source = str(defaults["source"])
        if defaults.get("path"):
            path = Path(str(defaults["path"]))
        # A pathless source (k8s-live) reads live state itself -- no file/dir to point at. Give the
        # factory a harmless placeholder it ignores; everything else still needs a path or --target.
        elif source in PATHLESS_SOURCES:
            path = Path(".")
        else:
            raise typer.BadParameter("give a path, --target <name>, or set [defaults] in config.")
    if autonomy not in ("observe", "suggest", "auto"):
        raise typer.BadParameter("autonomy must be: observe | suggest | auto")
    if autonomy == "auto" and stateless:
        raise typer.BadParameter(
            "--autonomy auto needs the state store for its audit trail; remove --stateless."
        )
    surfaces = _surfaces([name.strip() for name in to.split(",") if name.strip()])
    if verbose:  # --verbose is a console-rendering choice; flip it on any console surface
        for surface in surfaces:
            if isinstance(surface, ConsoleSurface):
                surface.verbose = True
    # --confirm-llm: review egress before it happens. Needs a terminal to ask on; with none we
    # fail closed (run without the LLM, sending nothing) rather than block a headless scan forever.
    gate = None
    if confirm_llm and not no_llm:
        if sys.stdin.isatty():
            gate = _confirm_llm_egress
        else:
            typer.echo("--confirm-llm: no terminal to confirm on; running without the LLM.")
            no_llm = True
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
            context=context,
            kubeconfig=kubeconfig,
            inventory=inventory,
            llm_gate=gate,
        )
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from None
    except SourceError as exc:
        # A live tool failed (missing binary, non-zero exit, timeout, garbage output). Report it
        # cleanly and exit non-zero -- never a raw traceback, and never a false "no drift" (the
        # source raises rather than returning empty), so a scheduled scan/CI sees a real failure.
        typer.secho(f"scan failed: {exc}", fg="red", err=True)
        raise typer.Exit(1) from None
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
                recorded, held = _record_suggestions(
                    store, source, path, report, now, label or None
                )
                if autonomy == "auto":  # ...and, on auto, apply them through the same guardrails
                    _auto_apply(store, recorded)
                    if held:  # eligible but outside the autonomous bound -> left for a human
                        typer.echo(
                            f"autonomy=auto: held {len(held)} eligible change(s) for approval -- "
                            "they exceed the autonomous bound (recoverable/irreversible). "
                            "Run `approve`, or widen STEADYSTATE_BOUND to opt in."
                        )
            # Offer approvable evicted-pod cleanups (approve-gated, never auto-run) -- independent
            # of --autonomy, since the cleanup is a safe delete of dead tombstones a human OKs.
            record_cleanups(store, report, now)
            # Offer the wall's authored runbook fixes for any matching malfunction (approve-gated).
            record_solution_remediations(store, report, now)
    if json_out:  # the machine-readable form: stdout is pure JSON, no surfaces, no spend footer
        payload = report_to_dict(report, resolved=resolved, spend=_spend_dict(report.llm_calls))
        typer.echo(json.dumps(payload, indent=2))
        return
    for surface in surfaces:
        surface.emit(report, resolved=resolved)
    deliver_names = [d.strip() for d in deliver.split(",") if d.strip() and d.strip() != "none"]
    if deliver_names:  # ship the accept-reality code change(s) -- orthogonal to --autonomy
        _deliver(source, path, report, deliver_names)
    # A paid call should never go unseen: print this scan's spend (silent on a --no-llm run).
    # --cost adds the per-caller breakdown of this scan. Cumulative spend lives in `cost`.
    spend = scan_cost_line(report.llm_calls)
    if spend:
        typer.echo(spend)
        if cost:
            for r in roll_up(report.llm_calls):
                typer.echo(f"  {r.caller:<12} ~${r.cost_usd:.4f}  {r.calls} call(s)")


# The CI-gate severity calculus: an alert fails the gate when its severity is at/above the
# `fail_on` threshold. "any" trips on anything; "none" never trips (report/deliver only).
_CI_SEVERITY = {"critical": 4, "high": 3, "medium": 2, "low": 1}
_CI_THRESHOLD = {"any": 0, "low": 1, "medium": 2, "high": 3, "critical": 4, "none": 99}
_CI_CONFIG_DEFAULT = "steadystate/config.toml"  # the committed convention (see repo-native-posture)


def _load_ci_config(path: Path) -> dict:
    """The optional ``[ci]`` table from the config (source / path / fail_on / to / deliver) -- all
    keys optional. Missing/malformed -> {} (CLI flags + defaults still apply)."""
    return config_table("ci", path)


@app.command()
def ci(
    path: Path | None = typer.Argument(None, help="The IaC to scan (else config, else '.')."),
    source: str = typer.Option("", "--source", help="Override the config/default source."),
    fail_on: str = typer.Option(
        "", "--fail-on", help="Gate threshold: any | low | medium | high | critical | none."
    ),
    to: str = typer.Option("", "--to", help="Surfaces, e.g. `github` to open an issue."),
    deliver: str = typer.Option(
        "", "--deliver", help="e.g. `github-pr` to open an accept-reality reconcile PR."
    ),
    config: Path = typer.Option(
        Path(_CI_CONFIG_DEFAULT), "--config", help="The steadystate config file (TOML)."
    ),
) -> None:
    """The GitOps gate: a **stateless, deterministic** scan of the repo's IaC -- no db, no LLM, no
    standing creds -- that **exits non-zero on a problem** (a CI gate) and optionally **opens a PR**
    (`--deliver github-pr`, for code-reconcilable drift) or an **issue** (`--to github`). Reads an
    optional `steadystate/config.toml` `[ci]` table (source / path / fail_on / to / deliver); CLI
    flags override it. The lowest-friction posture: `git clone` + a token + this one line."""
    cfg = _load_ci_config(config)
    base = config_table("defaults", config)  # [ci] overrides [defaults] overrides the built-in
    source = source or str(cfg.get("source") or base.get("source") or "terraform")
    scan_path = path or Path(str(cfg.get("path") or base.get("path") or "."))
    fail_on = (fail_on or str(cfg.get("fail_on") or "any")).lower()
    to = to or str(cfg.get("to") or "console")
    deliver = deliver or str(cfg.get("deliver") or "none")
    if fail_on not in _CI_THRESHOLD:
        raise typer.BadParameter(f"--fail-on must be one of: {', '.join(_CI_THRESHOLD)}")
    try:  # stateless + deterministic by design: reproducible, no spend, no egress, no creds
        report = build_report(source, scan_path, no_llm=True)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from None
    except SourceError as exc:
        typer.secho(f"ci scan failed: {exc}", fg="red", err=True)
        raise typer.Exit(1) from None  # a tooling failure is a gate failure, never a false "clean"
    for surface in _surfaces([s.strip() for s in to.split(",") if s.strip()]):
        surface.emit(report)
    deliver_names = [d.strip() for d in deliver.split(",") if d.strip() and d.strip() != "none"]
    if deliver_names:
        _deliver(source, scan_path, report, deliver_names)
    # The gate: count alerts at/above the threshold, print a one-line verdict, exit accordingly.
    threshold = _CI_THRESHOLD[fail_on]
    failing = [a for a in report.alerts if _CI_SEVERITY.get(a.severity.value, 0) >= threshold]
    total = len(report.alerts)
    if not failing:
        clean = "clean -- no drift/malfunction" if not total else f"{total} finding(s) below gate"
        typer.secho(f"steadystate ci: PASS -- {clean}", fg="green")
        return
    typer.secho(
        f"steadystate ci: FAIL -- {len(failing)} of {total} finding(s) at/above '{fail_on}'",
        fg="red",
    )
    raise typer.Exit(1)


@app.command()
def verify(
    declared: Path = typer.Argument(
        ...,
        help="Your declared 'left': a Kustomize overlay dir (kustomization.yaml) or a Helm chart "
        "dir (Chart.yaml) -- auto-detected.",
    ),
    context: str = typer.Option(
        "",
        "--context",
        help="The kube context of the cluster to verify against (a target = a cluster).",
    ),
    kubeconfig: str = typer.Option(
        "",
        "--kubeconfig",
        help="Read the context from this kubeconfig file (off the default path).",
    ),
    release: str = typer.Option(
        "",
        "--release",
        help="Helm only: the release name (must match the installed release so `.Release.Name`-"
        "derived resource names align). Defaults to the chart dir's name.",
    ),
    values: list[str] = typer.Option(
        [], "--values", "-f", help="Helm only: a values file (repeatable), as `helm install -f`."
    ),
    namespace: str = typer.Option(
        "", "--namespace", "-n", help="Helm only: the release namespace, as `helm install -n`."
    ),
    label: str = typer.Option("", "--label", help="Environment label stamped on each finding."),
    state: Path = typer.Option(
        Path(DEFAULT_STATE_PATH), "--state", help="State db (memoryful; auto-created)."
    ),
    stateless: bool = typer.Option(
        False, "--stateless", help="Skip the store: a pure, amnesiac check."
    ),
    json_out: bool = typer.Option(False, "--json", help="Emit the report as JSON."),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Show the full evidence per finding."
    ),
) -> None:
    """Verify the running cluster against your declared Git state -- **verify the left**.

    Renders your declared source -- a **Kustomize overlay** (`kustomization.yaml`) or a **Helm
    chart** (`Chart.yaml`), auto-detected -- with the platform's own tooling (no YAML wrangling),
    and reconciles it against the live cluster, scoped to the namespaces the render touches. Answers
    "is prod still what Git says?": a workload **in Git but not running** (ADDED), **running but
    drifted** from Git -- e.g. an out-of-band image change (MODIFIED), or **running but not in Git**
    (REMOVED). Coarse on purpose (presence + image + replicas), so it flags real divergence, not the
    hundred fields the cluster mutates server-side. Findings land in the store like any other --
    muteable, tracked new/recurring/resolved, and (within the bound) actionable -- so you run it
    continuously, not once.

    Helm: `--release`/`--values`/`--namespace` mirror `helm install`. The same engine backs
    `scan --source kustomize-live|helm-live <dir>`; this is the friendly entrypoint."""
    if (declared / "Chart.yaml").exists():
        source_name = "helm-live"
        src: DriftSource = HelmLiveSource(
            declared, release=release, values=[Path(v) for v in values], namespace=namespace
        )
    elif any((declared / n).exists() for n in ("kustomization.yaml", "kustomization.yml")):
        source_name = "kustomize-live"
        src = KustomizeLiveSource(declared)
    else:
        raise typer.BadParameter(
            f"{declared} is neither a Helm chart (Chart.yaml) nor a Kustomize overlay "
            "(kustomization.yaml)."
        )
    try:
        report = build_report(
            source_name, declared, context=context, kubeconfig=kubeconfig, label=label, src=src
        )
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from None
    except SourceError as exc:
        typer.secho(f"verify failed: {exc}", fg="red", err=True)
        raise typer.Exit(1) from None
    now = datetime.now(UTC)
    resolved: list = []
    if not stateless:
        with _open_store(state) as store:
            resolved = reconcile(report, store, now)
    if json_out:
        typer.echo(json.dumps(report_to_dict(report, resolved=resolved, spend=None), indent=2))
        return
    surface = ConsoleSurface()
    surface.verbose = verbose
    surface.emit(report, resolved=resolved)


@app.command()
def compliance(
    path: Path | None = typer.Argument(
        None, help="Source input (a manifest/snapshot dir or file). Omit when using --target."
    ),
    source: str = typer.Option(
        "k8s-live",
        "--source",
        help=f"What to audit: {' | '.join(sorted(DRIFT_SOURCES))}. Defaults to k8s-live -- the "
        "differentiated case (the running cluster's posture, not just your manifests).",
    ),
    target: str = typer.Option(
        "",
        "--target",
        help="Audit a named target from the registry (supplies source/path/context).",
    ),
    context: str = typer.Option(
        "", "--context", help="Aim a live source at a kube context (a target = a cluster)."
    ),
    kubeconfig: str = typer.Option(
        "",
        "--kubeconfig",
        help="Read the context from this kubeconfig file (off the default path).",
    ),
    framework: str = typer.Option(
        "", "--framework", help="Limit to one benchmark: cis | stig. Default: all stacked together."
    ),
    level: int = typer.Option(
        0, "--level", help="CIS benchmark level to report: 0 = all (default), or 1 / 2 to narrow."
    ),
    json_out: bool = typer.Option(
        False, "--json", help="Emit the report as JSON (for other tooling) instead of text."
    ),
) -> None:
    """Audit a target against the **benchmark** controls steadystate checks, grouped by check.

    The differentiated case is **live**: `compliance --source k8s-live --context <ctx>` audits the
    *running cluster's* pod-security posture (privileged, hostNetwork/PID/IPC, capabilities,
    hostPath, runAsRoot, seccomp, dropped capabilities, ...), agentless via kubectl -- the failures
    in what's actually deployed. Declared-side scanning is a commodity (Checkov/Trivy/kube-bench in
    CI); this owns the live posture. Also audits a captured snapshot or a compose project.

    Every framework + level **stacks into one scan** by default -- CIS Level 1 + Level 2 (and STIG,
    where a check maps to it) cited together on the check they share. `--level` (1/2) or
    `--framework` (cis/stig) narrows; `--json` for tooling. The report prints a scope disclaimer: it
    validates the workload-policy controls it can observe live, NOT the control-plane/node controls
    (node access / kube-bench, N/A on managed clusters) or procedural controls (a human attests)."""
    if target:
        if path is not None:
            raise typer.BadParameter("pass a path or --target, not both.")
        tgt = _resolve_target(target)
        source, context, kubeconfig = (
            tgt.source,
            context or tgt.context,
            kubeconfig or tgt.kubeconfig,
        )
        path = Path(tgt.path) if tgt.path else Path(".")
    elif path is None:
        if source in PATHLESS_SOURCES:
            path = Path(".")
        else:
            raise typer.BadParameter("give a path to audit, or --target <name>.")
    want_level = level if level != 0 else None
    want_framework = framework or None
    try:
        resources = collect_resources(source, path, context=context, kubeconfig=kubeconfig)
    except (ValueError, SourceError) as exc:
        typer.secho(f"compliance scan failed: {exc}", fg="red", err=True)
        raise typer.Exit(1) from None
    # Both passes: the affirmative controls (also surfaced by a normal scan) AND the compliance-only
    # posture gaps (CIS Level 2 -- absence-based, so a normal scan skips them to stay quiet).
    findings = [
        f
        for domain in default_domains()
        for f in (*evaluate_with(domain, resources), *evaluate_posture_with(domain, resources))
    ]
    results = compliance_report(findings, level=want_level, framework=want_framework)
    if json_out:
        doc = compliance_report_as_dict(results, level=want_level, framework=want_framework)
        typer.echo(json.dumps(doc, indent=2))
        return
    for line in render_compliance_report(results, level=want_level, framework=want_framework):
        typer.echo(line)


def _apply_remediations(drifts: list, executor, apply: bool) -> tuple[list, int]:
    """Plan (and, with ``apply``, run) the remediation for each drift. Returns the (plan, result)
    pairs + a failure count. **A remediation that throws (a terraform apply non-zero, a provider
    constraint) is reported and skipped, never propagated** -- one bad apply must not abort the rest
    or dump a raw traceback, so the operator learns what reconciled and what didn't (especially when
    a finding was a security exposure). Found by a real-GCP run."""
    items: list = []
    failures = 0
    for drift in drifts:
        plan = executor.plan_for(drift)
        result = None
        if apply and plan.eligible:
            try:
                result = executor.remediate(drift, confirm=True)
            except Exception as exc:  # noqa: BLE001 -- any remediation-tool failure, reported not raised
                failures += 1
                typer.secho(f"  remediation FAILED for {drift.identity}: {exc}", fg="red", err=True)
        items.append((plan, result))
    return items, failures


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
    try:
        drifts = _drift_source(source, path).collect_drift()
    except SourceError as exc:
        # Same live-tool failure path as `scan` (missing binary, non-zero exit, timeout, garbage
        # output): report it cleanly and exit non-zero -- never a raw traceback. The source raises
        # rather than returning empty, so a fix run never silently treats a tooling failure as "no
        # drift to remediate".
        typer.secho(f"fix failed: {exc}", fg="red", err=True)
        raise typer.Exit(1) from None
    items, failures = _apply_remediations(drifts, executor, apply)
    ConsoleSurface().emit_remediations(items)
    if failures:
        raise typer.Exit(1)  # non-zero so a script/CI knows a remediation didn't take


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
def resolve(
    fingerprint: str = typer.Argument(..., help="The Event fingerprint (from `findings`)."),
    solution: str = typer.Argument(
        "",
        help="Optional: how you fixed it. Recorded with the finding and fed to `learn` + the "
        "decider's grounding, so next time this category recurs steadystate knows what worked.",
    ),
    actor: str = typer.Option("cli", "--actor", help="Who resolved it (recorded for audit)."),
    state: Path = _STATE_OPTION,
) -> None:
    """Mark a finding resolved by hand -- and, optionally, record *how* you fixed it.

    Unlike the automatic resolve-on-absence, this captures the human's fix as a **learnable
    demonstration**: `learn` surfaces it, and it grounds the decider ("last time this fleet hit X,
    it was fixed by Y"). The next scan reopens it if the finding is in fact still present."""
    with _open_store(state) as store:
        store.resolve(fingerprint, solution or None, actor, datetime.now(UTC))
    tail = f' -- recorded fix: "{solution}"' if solution else ""
    typer.echo(f"resolved {fingerprint}{tail}")


@app.command()
def findings(
    state: Path = _STATE_OPTION,
    open_: bool = typer.Option(False, "--open", help="Only open findings."),
    resolved: bool = typer.Option(
        False, "--resolved", help="Only resolved findings (hidden by default)."
    ),
    muted: bool = typer.Option(False, "--muted", help="Only muted findings."),
    all_: bool = typer.Option(False, "--all", help="Every finding, resolved included."),
) -> None:
    """List stored findings: fingerprint, status, first_seen, last_severity, title.

    Resolved findings are **hidden by default** (a cleared finding is usually noise after the
    fact); pass --resolved or --all to see them, or --open/--muted to filter."""
    status = (
        "all" if all_ else "resolved" if resolved else "open" if open_ else "muted" if muted else ""
    )
    with _open_store(state) as store:
        every = store.all_findings()
    rows = filter_findings(every, status)
    if not rows:
        hidden = len(every) - len(rows)
        hint = f" ({hidden} resolved hidden -- --resolved/--all to show)" if hidden else ""
        typer.echo(f"no findings to show{hint}." if every else "no findings recorded yet.")
        return
    # Print the FULL fingerprint, not a prefix: it's the exact value an operator copies
    # into `mute`/`snooze`/`unmute`, and those match on the whole hex (a prefix would
    # silently create a junk finding via their upsert).
    for f in rows:
        typer.echo(
            f"{f.fingerprint}  {f.status:<8}  {f.first_seen}  {f.last_severity:<8}  {f.last_title}"
        )


@app.command()
def show(
    fingerprint: str = typer.Argument(..., help="A finding's fingerprint (or a unique prefix)."),
    state: Path = _STATE_OPTION,
    json_out: bool = typer.Option(False, "--json", help="Emit the finding as JSON instead."),
) -> None:
    """Show one finding's captured evidence -- the structured fields a probe/scan recorded
    (namespace, cluster, pod count, the failing pod's last log line, ...) plus first/last seen. The
    deterministic single-finding drill-down (no LLM -- that's `explain`); mirrors the chat/MCP
    `show` verb. Accepts a unique fingerprint prefix."""
    from .verbs import _render_show

    flags = frozenset({"json"}) if json_out else frozenset()
    typer.echo(_render_show(fingerprint, str(state), flags))


@app.command()
def analyze(
    fingerprint: str = typer.Argument(..., help="A finding's fingerprint (or a unique prefix)."),
    state: Path = _STATE_OPTION,
    to: str = typer.Option(
        "", "--to", help="After analyzing, send the RCA to a surface (`github` -> an issue)."
    ),
) -> None:
    """Grounded **root-cause analysis** of a captured crash/panic finding -- the RCA a senior
    on-call writes (root cause, call chain, the smoking gun, the trigger, the operational facts),
    but **anchored to the evidence the probe captured** (the stack trace) and told to cite it and
    never invent. Needs an LLM (it *is* the analysis; `show` is the raw evidence). The RCA is saved
    (so `show` shows it); `--to github` opens/updates an issue carrying it -- the close-the-loop."""
    from .verbs import _render_analyze, _send_analysis

    typer.echo(_render_analyze(fingerprint, str(state)))
    if to.strip():
        typer.echo(_send_analysis(fingerprint, str(state), to.strip().lower()))


class _WatchDone(Exception):  # noqa: N818 -- a control-flow signal, not an error
    """Raised to break the watch loop on the first match (`--once`)."""


def _new_matches(
    findings: list[Finding], pattern: re.Pattern[str] | None, seen: set[str]
) -> list[Finding]:
    """The open findings not yet seen this watch session, matching ``pattern`` (or all). Marks EVERY
    fresh one seen (so a non-matching one doesn't re-report either), returns the matching ones. Pure
    given ``seen`` (which it mutates) -- the watch's 'what's new since last poll' decision."""
    fresh: list[Finding] = []
    for finding in findings:
        if finding.status != OPEN or finding.fingerprint in seen:
            continue
        seen.add(finding.fingerprint)
        if pattern is None or pattern.search(finding.last_title):
            fresh.append(finding)
    return fresh


@app.command()
def watch(
    target: str = typer.Argument(..., help="A target name (STEADYSTATE_TARGETS) to watch live."),
    for_pattern: str = typer.Option(
        "", "--for", help="Only report findings whose title matches this (regex, case-insensitive)."
    ),
    timeout: str = typer.Option(
        "5m", "--timeout", help="How long to watch: 5m | 30s | 1h | 0 (until Ctrl-C)."
    ),
    interval: str = typer.Option("20s", "--interval", help="How often to re-probe the target."),
    once: bool = typer.Option(False, "--once", help="Stop at the first matching finding."),
    deep: bool = typer.Option(
        True, "--deep/--no-deep", help="Scan pod logs too -- catches a panic in the logs."
    ),
    state: Path = _STATE_OPTION,
) -> None:
    """Watch a target **live** for a bounded window (default **5m**) -- re-probe every `--interval`
    and report the moment a finding appears that's NEW since the watch began (optionally only those
    matching `--for`). The repro tool: trigger a transient failure, watch it land, then
    `analyze <fp>` it. Bounded by design (`--timeout` / `--once` / Ctrl-C) -- a focused repro
    helper, not a monitoring daemon. Records to state, so a catch is tracked + ready for
    `show`/`analyze`. Exits non-zero if it caught something (a gate-friendly signal)."""
    import time

    from .verbs import _parse_duration, probe_report

    every = _parse_duration(interval)
    if every is None:
        raise typer.BadParameter("--interval must be like 20s, 1m, 2m, ...")
    unbounded = timeout.strip() in ("0", "")
    limit = None if unbounded else _parse_duration(timeout)
    if not unbounded and limit is None:
        raise typer.BadParameter("--timeout must be like 5m, 30s, 1h, or 0 for no limit.")
    deadline = None if limit is None else time.monotonic() + limit.total_seconds()
    pattern = re.compile(for_pattern, re.IGNORECASE) if for_pattern else None
    window = "until Ctrl-C" if unbounded else timeout
    match_note = f", matching /{for_pattern}/" if pattern else ""
    typer.echo(f"watching {target} every {interval} for {window}{match_note} -- Ctrl-C to stop")
    seen: set[str] = set()
    matched = 0
    first = True
    try:
        while True:
            try:
                probe_report(target, str(state), scan_logs=deep)  # records findings to state
            except LookupError as exc:  # unresolvable target -> a clean message, not a crash
                typer.secho(str(exc), fg="red", err=True)
                raise typer.Exit(2) from None
            except Exception as exc:  # noqa: BLE001 -- a probe blip mustn't kill the watch
                typer.secho(f"  (probe failed this poll: {exc})", fg="yellow", err=True)
            else:
                with _open_store(state) as store:
                    findings = store.all_findings()
                fresh = _new_matches(findings, pattern, seen)
                if first:  # baseline the pre-existing findings -- we report only NEW ones
                    first = False
                else:
                    for finding in fresh:
                        matched += 1
                        stamp = datetime.now(UTC).strftime("%H:%M:%S")
                        typer.secho(
                            f"[{stamp}] CAUGHT  {finding.last_title}  [{finding.last_severity}]",
                            fg="yellow",
                        )
                        hint = f"          -> steadystate analyze {finding.fingerprint[:12]}"
                        typer.secho(hint, fg="cyan")
                        if once:
                            raise _WatchDone
            if deadline is not None and time.monotonic() >= deadline:
                break
            time.sleep(every.total_seconds())
    except (KeyboardInterrupt, _WatchDone):
        pass
    tail = "" if matched else " -- all quiet"
    typer.echo(f"\nwatched {target}: caught {matched} new finding(s){tail}")
    if matched:
        raise typer.Exit(1)


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
    read-only) vs potentially destructive (require approval before they run).

    Covers sources and probes -- a probe (`--probe`) shells out too (e.g. `kubectl logs`), so its
    read-only commands are declared here for the same transparency + least-privilege RBAC."""
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
    if not source:  # probes are observe-only health readers; list them after the sources
        for name in sorted(PROBE_CAPABILITIES):
            typer.echo(f"{name} (probe)")
            typer.echo("  observe (pre-approved):")
            for cmd in PROBE_CAPABILITIES[name].observe or ("(reads a captured snapshot)",):
                typer.echo(f"    {cmd}")


@app.command()
def targets(
    check: bool = typer.Option(
        False,
        "--check",
        help="Validate each target: its source is registered, its probe is real, and its path "
        "still resolves. Exits non-zero if any target has a problem.",
    ),
) -> None:
    """List the named scan/probe targets (STEADYSTATE_TARGETS, else .steadystate/targets.json).

    This is the registry `discover --create` writes, `scan --target` runs, and the chat listener
    resolves -- so `targets` lets you see and validate it from the CLI without opening the JSON."""
    target_file = _targets_file()
    if not target_file.exists():
        typer.echo(f"no targets file ({target_file}). Create one with `discover --create`.")
        return
    try:
        registry = load_targets(target_file)
    except (OSError, ValueError) as exc:
        typer.echo(f"targets file {target_file} is malformed: {exc}", err=True)
        raise typer.Exit(1) from exc
    if not registry:
        typer.echo(f"{target_file} has no targets.")
        return
    known_sources = set(DRIFT_SOURCES)
    known_probes = {"auto", "none", *PROBES}
    typer.echo(f"{len(registry)} target(s) in {target_file}:")
    problems = 0
    for name, entry in sorted(registry.items()):
        # A live target shows its context (the cluster it reaches); a file target shows its path.
        locator = f"context={entry.context}" if entry.context else entry.path
        line = f"  {name:<26} {entry.source:<14} {locator}"
        if check:
            issues = target_issues(
                entry, known_sources, known_probes, lambda p: Path(p).exists(), PATHLESS_SOURCES
            )
            if issues:
                problems += 1
                line += "  [" + "; ".join(issues) + "]"
            else:
                line += "  [ok]"
        typer.echo(line)
    if check and problems:
        typer.echo(f"{problems} target(s) with problems.", err=True)
        raise typer.Exit(1)


@app.command()
def sweep(
    state: Path = typer.Option(
        Path(DEFAULT_STATE_PATH),
        "--state",
        help="SQLite state db that makes the sweep memoryful (new/recurring/resolved across the "
        "fleet). Auto-created; default under .steadystate/.",
    ),
    stateless: bool = typer.Option(
        False,
        "--stateless",
        help="Skip the state store -- a pure snapshot of what's on fire now, no new/resolved.",
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="List each fire's title under its cluster."
    ),
    deep: bool = typer.Option(
        False,
        "--deep",
        help="Also scan every cluster's Running pods' logs for errors (a `kubectl logs` per pod).",
    ),
    to: str = typer.Option(
        "",
        "--to",
        help=f"Also push the fleet's fires (every cluster's alerts, each labeled with its cluster) "
        f"to these surfaces: {', '.join(sorted(SURFACES))}. The digest always prints to stdout; "
        "this adds outward alerting, so a scheduled sweep can page without an inbound endpoint.",
    ),
) -> None:
    """Probe every target (cluster) and roll up what's on fire -- a stateful fleet sweep.

    The batch counterpart to `scan --target <one>`: it runs every target in the registry
    (STEADYSTATE_TARGETS, else .steadystate/targets.json) through the same engine and prints a
    digest --
    which clusters are on fire, which are clear, and what recovered since the last sweep. One
    cluster being unreachable is reported inline, never sinks the rest. `--to` additionally pushes
    the fires to alert surfaces, so a cron sweep pages out (no inbound endpoint needed)."""
    target_file = _targets_file()
    if not target_file.exists():
        typer.echo(f"no targets file ({target_file}). Create one with `discover --create`.")
        return
    try:
        registry = load_targets(target_file)
    except (OSError, ValueError) as exc:
        typer.echo(f"targets file {target_file} is malformed: {exc}", err=True)
        raise typer.Exit(1) from exc
    if not registry:
        typer.echo(f"{target_file} has no targets.")
        return
    # Resolve surfaces before the (slow) sweep, so a bad --to fails fast with a clean BadParameter.
    surfaces = _surfaces([n.strip() for n in to.split(",") if n.strip()])
    result = sweep_targets(registry, state, datetime.now(UTC), stateless=stateless, scan_logs=deep)
    for line in render_sweep(result, verbose=verbose):
        typer.echo(line)
    for surface in surfaces:  # push the union of the fleet's alerts outward (each cluster-labeled)
        surface.emit(result.report)


@app.command()
def hold(
    state: Path = typer.Option(
        Path(DEFAULT_STATE_PATH),
        "--state",
        help="SQLite state db -- the hold tick records findings + offers cleanups through it, and "
        "audits anything it applies. Auto-created; default under .steadystate/.",
    ),
    apply: bool = typer.Option(
        False,
        "--apply",
        help="Actually execute the reflexes at `auto` (within blast-radius). Without it, hold is a "
        "DRY RUN: it prints what it would hold and touches nothing -- the mode you watch first.",
    ),
    deep: bool = typer.Option(
        False, "--deep", help="Probe deep (pod logs + node disk %) before holding."
    ),
) -> None:
    """Hold the fleet at steady state: probe, and for each *known* malfunction apply its reflex.

    The control loop, not a monitor. It sweeps every target, then for each finding consults the
    reflex registry: a known stimulus whose reflex is at `auto` and within blast-radius is held
    autonomously (the prober's own safe cleanup, run through the approve guardrail and audited);
    anything novel, or out of envelope (an abnormal pod count, or a fleet-wide storm of the same
    finding), is ESCALATED -- left pending for a human. Knowing when *not* to act is the point.

    Self-correcting: a reflex whose own past fixes keep RECURRING (you cleaned it, it came back)
    loses trust and escalates instead of churning -- a fix that won't hold is a root-cause problem
    a cleanup can't reach (evicted pods that keep re-evicting are a capacity problem).

    Reflexes ship at `propose` (dry-run): out of the box this holds nothing. Promote one you've
    watched be right with `STEADYSTATE_REFLEX_AUTO=reclaim-evicted`, then `hold --apply`."""
    target_file = _targets_file()
    if not target_file.exists():
        typer.echo(f"no targets file ({target_file}). Create one with `discover --create`.")
        return
    try:
        registry = load_targets(target_file)
    except (OSError, ValueError) as exc:
        typer.echo(f"targets file {target_file} is malformed: {exc}", err=True)
        raise typer.Exit(1) from exc
    if not registry:
        typer.echo(f"{target_file} has no targets.")
        return
    now = datetime.now(UTC)
    result = sweep_targets(registry, str(state), now, scan_logs=deep)
    with _open_store(state) as store:
        record_cleanups(store, result.report, now)  # offer cleanups so hold can approve them
        record_solution_remediations(store, result.report, now)  # + authored runbook fixes
        outcome = run_hold(store, result.report, apply=apply, now=now)
    for line in _render_hold(outcome, apply=apply):
        typer.echo(line)


def _render_hold(outcome, *, apply: bool) -> list[str]:
    """Render a hold tick: the reflexes in play, then act / watch / escalate, then what ran."""
    active = reflexes()
    lines = [
        f"hold: {len(active)} reflex(es) -- " + ", ".join(f"{r.name}[{r.autonomy}]" for r in active)
    ]
    plan = outcome.plan
    if not plan.decisions:
        lines.append("  fleet is at steady state -- nothing for a reflex to hold.")
        return lines
    if apply and outcome.applied:
        lines.append(f"  HELD {outcome.held}/{len(outcome.applied)} autonomously:")
        for decision, res in outcome.applied:
            ok = "ok" if res is not None and res.applied else "FAILED"
            detail = (res.detail if res is not None else "").strip()
            lines.append(f"    [{ok}] {decision.identity}  ({decision.reflex})  {detail}")
    elif plan.to_act:
        verb = "would hold" if not apply else "to hold"
        lines.append(f"  {len(plan.to_act)} {verb} (auto, within blast-radius):")
        for d in plan.to_act:
            lines.append(f"    + {d.identity}  ({d.reflex})  {d.command}")
    for d in plan.watched:
        lines.append(f"  ~ watch: {d.identity}  {d.reason}")
    for d in plan.escalated:
        lines.append(f"  ! escalate: {d.identity}  ({d.reason})")
    if not apply and plan.to_act:
        lines.append("  dry run -- re-run with --apply to execute the auto reflexes.")
    return lines


@app.command()
def propose(
    state: Path = typer.Option(
        Path(DEFAULT_STATE_PATH), "--state", help="State db for the sweep (auto-created)."
    ),
    llm: bool = typer.Option(
        False,
        "--llm",
        help="Ask the configured model to decide (egress-gated; honest degrade to the catalog "
        "decider when no model is set). Without it, the deterministic catalog decider is used.",
    ),
    record: bool = typer.Option(
        False,
        "--record",
        help="Record the AUTHORIZED (within-bound) proposals as approvable pendings -- the LLM "
        "drives, you confirm with `approve`/`fix`. Out-of-bound ones stay advisory. Without it, "
        "this is read-only.",
    ),
    apply: bool = typer.Option(
        False,
        "--apply",
        help="Auto-RUN the AUTHORIZED (within-bound) proposals through the approve guardrail, no "
        "trigger needed -- the decider as a bounded operator. Requires the access grant "
        "STEADYSTATE_DECIDER_AUTO; out-of-bound ones still escalate to a human.",
    ),
    deep: bool = typer.Option(False, "--deep", help="Probe deep (pod logs + node disk %) first."),
) -> None:
    """What an autonomous **decider** would do for findings `hold` can't answer -- read-only,
    `--record` to queue the safe ones for approval, or `--apply` to let it act within the bound.

    A decider *proposes* a remediation for a novel finding; the deterministic **gate** then
    authorizes it -- blind to who proposed. A proposal is REJECTED unless it names a vetted
    **catalog** action whose command passes the allow-pattern; ESCALATES if the action's envelope is
    outside your bound; otherwise AUTHORIZED. So `--llm` can never widen its own blast radius or run
    an un-vetted command. With `--llm`, the model is **grounded** in how *this* fleet handled the
    category before (learned lessons + recurrence), so its proposals reflect your history.

    `--record` queues the AUTHORIZED proposals as **pendings** an operator confirms with
    `approve`/`fix` (the model drives *what*, the human stays the trigger). `--apply` goes one step:
    with the access grant `STEADYSTATE_DECIDER_AUTO` set, it RUNS them through the exact same
    guardrail (audited as `decider`) -- autonomy is granted like a new admin's access, not earned by
    a track record; the bound + catalog allow-list is the guardrail, your DR plan the backstop.
    Either way, out-of-bound proposals stay advisory -- a human runs those via break-glass."""
    target_file = _targets_file()
    if not target_file.exists():
        typer.echo(f"no targets file ({target_file}). Create one with `discover --create`.")
        return
    try:
        registry = load_targets(target_file)
    except (OSError, ValueError) as exc:
        typer.echo(f"targets file {target_file} is malformed: {exc}", err=True)
        raise typer.Exit(1) from exc
    if not registry:
        typer.echo(f"{target_file} has no targets.")
        return
    result = sweep_targets(registry, str(state), datetime.now(UTC), scan_logs=deep)
    with _open_store(state) as store:
        if llm:
            analyst = LLMAnalyst(gate=_confirm_llm_egress)
            # ground the model in THIS fleet's history of the category (lessons + recurrence)
            findings, acted = store.all_findings(), store.acted_fingerprints()
            decider: Decider = LLMDecider(
                analyst._complete,
                context_for=lambda s: environment_context(findings, acted, s.category),
            )
        else:
            decider = CatalogDecider()
        gated = propose_for(result.report, decider)  # propose_for honors the operator's bound dial
        if apply:
            if not decider_auto_enabled():
                typer.echo(
                    "propose --apply needs the decider's access grant -- set "
                    "STEADYSTATE_DECIDER_AUTO=1 to let it act within the bound. (Use --record to "
                    "queue the proposals for your approval instead.)"
                )
                return
            executed, advised, _dropped = act_on_proposals(store, gated, datetime.now(UTC))
            typer.echo(
                f"propose --apply ({decider.name}): {len(executed)} acted (within bound), "
                f"{len(advised)} advisory (break-glass)."
            )
            for g, res in executed:
                mark = "ran" if res is not None and res.applied else "failed"
                typer.echo(f"  [{mark}] {g.proposal.identity}  ->  {g.proposal.action}")
                typer.echo(f"      {res.detail if res is not None else g.proposal.command}")
            for adv in advised:
                p = adv.proposal
                typer.echo(f"  [advisory] {p.identity}  ->  {p.action}  ({adv.reason})")
                typer.echo(f"      a human runs this via break-glass: run {p.action} <fp>")
            if not executed and not advised:
                typer.echo(
                    "  nothing to act on -- no within-bound proposal for an unhandled finding."
                )
            return
        if record:
            recorded, advised, _dropped = record_proposals(store, gated, datetime.now(UTC))
            typer.echo(
                f"propose --record ({decider.name}): {len(recorded)} recorded to pending, "
                f"{len(advised)} advisory (break-glass)."
            )
            for g in recorded:
                typer.echo(f"  [pending] {g.proposal.identity}  ->  {g.proposal.action}")
                typer.echo(f"      approve {g.proposal.fingerprint}   ({g.proposal.command})")
            for g in advised:
                typer.echo(
                    f"  [advisory] {g.proposal.identity}  ->  {g.proposal.action}  ({g.reason})"
                )
                typer.echo(f"      a human runs this via break-glass: run {g.proposal.action} <fp>")
            if not recorded and not advised:
                typer.echo(
                    "  nothing to record -- no within-bound proposal for an unhandled finding."
                )
            return
    typer.echo(
        f"propose ({decider.name} decider): {len(gated)} proposal(s) for findings hold can't."
    )
    for g in gated:
        mark = {AUTHORIZED: "+", ESCALATE: "!", REJECTED: "x"}.get(g.verdict, "?")
        typer.echo(f"  [{mark} {g.verdict}] {g.proposal.identity}  ->  {g.proposal.action}")
        typer.echo(f"      {g.proposal.command}")
        typer.echo(f"      why: {g.proposal.rationale}  ({g.reason})")
    if not gated:
        typer.echo(
            "  nothing to propose -- every malfunction either has a reflex or no vetted fix."
        )


@app.command()
def learn(state: Path = _STATE_OPTION) -> None:
    """Show what steadystate has *learned* from findings that resolved without it -- and what to do.

    The homeostat learns the response it was never shown. A finding that cleared and is NOT in the
    audit log (steadystate didn't act) cleared **out-of-band** -- a human fixed it in their own
    terminal, or it self-healed. This reads those resolutions, generalizes them by category (the
    namespace/cluster that varies becomes a free variable), and proposes:

      * ADOPT -- a category you keep fixing by hand that steadystate already has a reflex for:
        promote it (`STEADYSTATE_REFLEX_AUTO=<name>`) so `hold` reclaims it next time.
      * SELF-HEALS -- a category that keeps clearing on its own: a candidate to mute (stop paging).
      * CAPTURE -- a category you keep fixing with ONE consistent command: the exact `add-solution`
        to put it in your runbook (so next time it's offered as a one-approve remediation).

    Read-only and a proposal: it never promotes a reflex, mutes, or authors anything -- you do, once
    you agree. The strength of a lesson is how often it would have been the right call. Shares the
    one renderer with chat/MCP, so every surface shows the same lessons + the runbook drafts."""
    from .verbs import _render_learn

    typer.echo(_render_learn(str(state)))


@app.command()
def baseline(
    target: str = typer.Argument(
        ..., help="A named target whose cluster (context) to snapshot as the known-good baseline."
    ),
) -> None:
    """Capture a cluster's current workloads as a known-good **baseline** (under .steadystate/).

    For a cluster you have no manifests for, the baseline is the *declared* side: once captured, a
    `k8s-baseline` target reports config drift against it -- a workload added/removed, or an image
    changed, since the snapshot. Resolves the cluster from the target's `context`; refresh anytime
    by re-running. Compared on presence + images (replicas are ignored, so HPA isn't noise)."""
    tgt = _resolve_target(target)
    if not tgt.context:
        raise typer.BadParameter(
            f"target '{target}' has no context -- baseline needs a live cluster target (k8s-live "
            "/ k8s-baseline)."
        )
    try:
        # Pass the target's kubeconfig (a cwd kubeconfig the context lives in, from discovery) so a
        # context not on kubectl's default path still baselines -- mirrors the probe/scan path.
        path, count = capture_baseline(tgt.context, kubeconfig=tgt.kubeconfig)
    except SourceError as exc:
        typer.secho(f"baseline failed: {exc}", fg="red", err=True)
        raise typer.Exit(1) from None
    typer.echo(f"baseline captured: {count} workload(s) for context '{tgt.context}' -> {path}")


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
        if p.command:
            typer.echo(f"    enforce (approve to run): {p.command}")
        if p.patch:
            typer.echo("    accept reality (review + `git apply`, the tool won't apply it):")
            for line in p.patch.splitlines():
                typer.echo(f"      {line}")
        if not p.command and not p.patch:  # defensive: a recorded suggestion always has one
            typer.echo("    (no remediation recorded)")


@app.command("summary")
def summary_status(state: Path = _STATE_OPTION) -> None:
    """A one-glance status: open findings by severity, what's pending your approval, the homeostat's
    posture, and the single worst thing right now -- the 'what do I look at first' rollup. Reads the
    last probe/sweep from the store (no fresh scan); mirrors the chat `summary` command."""
    from .verbs import _render_summary

    typer.echo(_render_summary(str(state)))


_CHECKS_OPTION = typer.Option(
    "",
    "--checks",
    help="Path to the checks file (else STEADYSTATE_CHECKS, else .steadystate/checks.json). Point "
    "it at a VERSION-CONTROLLED file so checks are reviewed/shared, not lost like local state.",
)

_SOLUTIONS_OPTION = typer.Option(
    "",
    "--solutions",
    help="Path to the runbook (else STEADYSTATE_SOLUTIONS, else .steadystate/solutions.json). "
    "Version-control it so authored fixes are reviewed/shared and keep their audit.",
)


@app.command()
def metrics() -> None:
    """The live metric readings from your monitoring (Prometheus / ...) for the queries you
    configured (`{name: query}` at STEADYSTATE_METRIC_QUERIES) -- the agent's metric context next to
    steadystate's findings. steadystate *rents* your monitoring; it doesn't reimplement it."""
    from .verbs import _render_metrics

    typer.echo(_render_metrics())


@app.command()
def posture() -> None:
    """The honest answer to 'am I bounded by steadystate's gates?' -- what it enforces on its own
    path (catalog + bound + audit), where that ends (it can't constrain an agent's *other* tools,
    e.g. a shell), and the sole-actuator setup that makes it a real fence -- no overclaim."""
    from .verbs import _render_posture

    typer.echo(_render_posture())


@app.command()
def checks(checks: str = _CHECKS_OPTION) -> None:
    """List the custom health checks (--checks / STEADYSTATE_CHECKS / .steadystate/checks.json)."""
    from .verbs import _render_checks

    typer.echo(_render_checks(checks))


@app.command()
def solutions(solutions: str = _SOLUTIONS_OPTION) -> None:
    """List this wall's authored runbook -- the documented problem->fix entries (a command, a
    playbook, a reboot), each signed by an author. They surface against a matching finding in
    `show`. Read-only (--solutions / STEADYSTATE_SOLUTIONS / .steadystate/solutions.json)."""
    from .verbs import _render_solutions

    typer.echo(_render_solutions(solutions))


@app.command()
def health(
    workload: str = typer.Argument(
        "", help="Scope to one workload + correlate (smoke / symptom / drift)."
    ),
    state: Path = _STATE_OPTION,
    checks: str = _CHECKS_OPTION,
) -> None:
    """The one-glance 'is it actually working?' verdict (WORKING | DEGRADED | DOWN) -- runs this
    wall's `http` smoke tests live and folds in the live malfunctions. Add a workload name to scope
    to it and correlate the smoke result + live symptoms + the config drift that likely caused them.
    Active but read-only. Exits non-zero when the verdict isn't WORKING (for CI / a gate)."""
    from .health import WORKING
    from .verbs import health_report

    text, verdict = health_report(str(state), checks, workload)
    typer.echo(text)
    if verdict != WORKING:  # gate on the verdict as data, not by string-matching the rendered text
        raise typer.Exit(1)


@app.command()
def smoke(checks: str = _CHECKS_OPTION) -> None:
    """Run this wall's `http` smoke tests live and report PASS/FAIL each -- the affirmative
    'is it actually working?' answer (it exercises the endpoint), and an agent's close-the-loop
    verify after a fix. Active but read-only (GET/HEAD). Exits non-zero if any smoke test fails."""
    from .probe.custom import run_smoke_checks
    from .verbs import _format_smoke

    results = run_smoke_checks(
        checks
    )  # run ONCE -- render and gate the exit code from the same run
    typer.echo(_format_smoke(results, checks))
    if any(not r.passed for r in results):
        raise typer.Exit(1)  # a failed smoke test -> non-zero, so CI / a script can gate on it


@app.command("add-check")
def add_check_cmd(
    check: str = typer.Argument(..., help="The check as a JSON object."),
    checks: str = _CHECKS_OPTION,
) -> None:
    """Store a custom health check from a JSON object -- validated against the vetted schema, then
    written to the checks file (re-defining a name updates it). Keep that file in version control
    (--checks / STEADYSTATE_CHECKS) so checks are intent, not local state. To author one in plain
    English instead, use `define-check`."""
    from .verbs import _add_check

    typer.echo(_add_check(check, checks))


@app.command("define-check")
def define_check_cmd(
    request: str = typer.Argument(..., help="What to watch, in plain English."),
    checks: str = _CHECKS_OPTION,
) -> None:
    """Author a custom health check by describing it -- the LLM fills the vetted schema, steadystate
    validates it (only a schema-valid, observe-only check is stored), and writes it to the checks
    file. Needs an LLM configured (see `doctor`). e.g. "alert if a service stops on a host"."""
    from .probe.custom import add_check, define_check

    analyst = LLMAnalyst()
    if analyst._provider() == "none":
        typer.echo(
            "define-check needs an LLM (ANTHROPIC_API_KEY or a custom endpoint). Use `add-check` "
            "with JSON, or see `doctor`.",
            err=True,
        )
        raise typer.Exit(1)
    raw = define_check(request, analyst._complete)
    if raw is None:
        typer.echo(
            "the model didn't return a check -- try rephrasing, or `add-check` with JSON.", err=True
        )
        raise typer.Exit(1)
    check, message = add_check(raw, checks)
    typer.echo(message)
    if check is None:
        typer.echo(f"\n(the model proposed: {raw})", err=True)
        raise typer.Exit(1)


_AUTHOR_OPTION = typer.Option(
    "cli", "--author", help="Who authored this fix -- recorded on the entry (the audit anchor)."
)


@app.command("add-solution")
def add_solution_cmd(
    solution: str = typer.Argument(..., help="The solution as a JSON object."),
    author: str = _AUTHOR_OPTION,
    solutions: str = _SOLUTIONS_OPTION,
) -> None:
    """Add an authored fix to this wall's runbook from a JSON object -- a problem->fix entry
    (for/match + a command/playbook/reboot), stamped with --author and validated (an unsigned fix is
    rejected). Re-using a name updates it. Version-control the file (--solutions / STEADYSTATE_
    SOLUTIONS). To author one in plain English instead, use `define-solution`."""
    from .verbs import _add_solution

    typer.echo(_add_solution(solution, author=author, solutions_path=solutions))


@app.command("define-solution")
def define_solution_cmd(
    request: str = typer.Argument(..., help="The problem and its fix, in plain English."),
    author: str = _AUTHOR_OPTION,
    solutions: str = _SOLUTIONS_OPTION,
) -> None:
    """Author a runbook solution by describing it -- the LLM drafts the entry, steadystate validates
    it and stamps --author, then writes it to the runbook. Needs an LLM (see `doctor`). e.g.
    "for evicted pods, delete the Failed ones in that namespace"."""
    from .probe.solutions import add_solution, define_solution

    analyst = LLMAnalyst()
    if analyst._provider() == "none":
        typer.echo(
            "define-solution needs an LLM (ANTHROPIC_API_KEY or a custom endpoint). Use "
            "`add-solution` with JSON, or see `doctor`.",
            err=True,
        )
        raise typer.Exit(1)
    raw = define_solution(request, analyst._complete)
    if raw is None:
        typer.echo(
            "the model didn't return a solution -- try rephrasing, or `add-solution` with JSON.",
            err=True,
        )
        raise typer.Exit(1)
    sol, message = add_solution(raw, author=author, path=solutions)
    typer.echo(message)
    if sol is None:
        typer.echo(f"\n(the model proposed: {raw})", err=True)
        raise typer.Exit(1)


@app.command()
def mcp(
    state: Path = _STATE_OPTION,
    directory: str = typer.Option(
        "",
        "--dir",
        help="Run as if from this directory -- resolve the default .steadystate/state.db, "
        "STEADYSTATE_TARGETS, and any relative kubeconfig paths against it. Use it when an MCP "
        "client (Claude Code, Copilot CLI) launches the server from a different working directory "
        "than your wall folder -- one absolute --dir per server instead of pinning every path.",
    ),
    label: str = typer.Option(
        "",
        "--label",
        help="A name for this wall, stamped into the server's identity + the connect summary so a "
        "client (and you) can tell one wall's server from another's. Defaults to the --dir folder "
        "name.",
    ),
    refresh: str = typer.Option(
        "",
        "--refresh",
        help="Probe this target once at startup, so a connecting agent gets CURRENT state instead "
        "of the last stored scan. Trades a few seconds of connect latency for freshness; off by "
        "default (a slow cluster could trip a client's handshake timeout).",
    ),
    author: bool = typer.Option(
        False,
        "--author",
        help="Expose the AUTHORING verbs (`add-check`, `add-solution`) WITHOUT full --write -- an "
        "agent can write custom checks + runbook solutions (schema-gated, signed) but NOT "
        "approve/fix/run infra. The middle tier between read-only and --write. Also "
        "STEADYSTATE_MCP_AUTHOR=1.",
    ),
    write: bool = typer.Option(
        False,
        "--write",
        help="Also expose the EFFECTFUL verbs (approve/decline/fix/run/mute/snooze/send). They "
        "still run through the bound + catalog guardrails and are audited as `mcp`. Off by default "
        "(an agent can observe + diagnose, not act). Also enabled by STEADYSTATE_MCP_WRITE=1.",
    ),
) -> None:
    """Run steadystate as an MCP (Model Context Protocol) server over stdio, so Claude Code/Desktop
    or any agent can drive the vetted command grammar. Three grant tiers: **read-only** (default --
    `summary`/`findings`/`show`/`probe`); **--author** adds `add-check`/`add-solution` so an agent
    writes custom checks + runbook fixes (schema-gated, signed) without touching infra; **--write**
    adds the effectful verbs
    (`approve`/`fix`/`run`/...) within the SAME guardrails a human hits. The agent picks WHAT;
    the gate decides WHETHER. Speaks JSON-RPC over stdio; point your client at `steadystate mcp`.

    A client launches this server from *its* working directory, not your wall folder -- so the
    cwd-relative defaults (.steadystate/state.db, targets, kubeconfigs) miss. Pass `--dir <folder>`
    so they resolve against that folder, exactly as if you'd run it from there. On connect the
    server hands the agent a live status summary (this wall, what's open/pending, how fresh) so it
    resumes without a round-trip; `--refresh <target>` makes that summary current first."""
    from .inbound.mcp import serve_stdio

    if directory:
        target = Path(directory)
        if not target.is_dir():
            typer.echo(f"--dir: not a directory: {directory}", err=True)
            raise typer.Exit(1)
        os.chdir(
            target
        )  # resolve every relative default against the wall folder, like a `cd` there
    if refresh:  # freshen the store before serving, so a connecting agent sees current state
        run_command(Command(PROBE, _local_actor(), refresh), str(state))
    # the label self-identifies the silo: an explicit --label wins, else the --silo name (from the
    # root callback), else the --dir basename. So `--silo gateway-use1 mcp` labels itself.
    wall = label or _ACTIVE_SILO or (Path(directory).name if directory else "")
    truthy = ("1", "true", "yes", "on")
    granted = write or os.environ.get("STEADYSTATE_MCP_WRITE", "").strip().lower() in truthy
    can_author = author or os.environ.get("STEADYSTATE_MCP_AUTHOR", "").strip().lower() in truthy
    serve_stdio(str(state), write=granted, author=can_author, label=wall)


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


def _load_history(history_path: Path) -> None:
    """Give the chat prompt arrow-key recall + editing, seeded from a prior session's history.

    Importing ``readline`` is enough to upgrade ``input()`` to a full line editor -- up/down through
    prior commands, Ctrl-A/E, reverse-search -- so we just load the saved history. stdlib-only and
    best-effort: ``readline`` ships with CPython on Linux/macOS but not on Windows, whose console
    already provides its own up-arrow recall, so a missing module is a clean no-op, not an error."""
    if sys.platform == "win32":  # no stdlib readline; the console gives its own recall
        return
    with contextlib.suppress(ImportError, OSError):  # readline not built; or no history yet
        import readline

        readline.read_history_file(history_path)
        readline.set_history_length(1000)


def _save_history(history_path: Path) -> None:
    """Persist the session's commands so up-arrow recall survives a restart. Best-effort: a no-op
    where readline is absent (Windows) or the file can't be written."""
    if sys.platform == "win32":
        return
    with contextlib.suppress(ImportError, OSError):
        import readline

        readline.write_history_file(history_path)


@app.command()
def chat(state: Path = _STATE_OPTION) -> None:
    """A local chat client: drive the listener's command grammar from your terminal -- no Slack /
    Teams / Discord, no signing (a local shell is already trusted). It runs the SAME parser
    (command_from_text) and dispatch (run_command) the chat adapters use, so it's a faithful way to
    exercise the chat mechanism. Targets resolve from STEADYSTATE_TARGETS, else
    .steadystate/targets.json (what `discover --create` writes), so no env var is needed locally.
    Commands: `help`, `pending`, `probe <target>` (or `probe all` to sweep the fleet),
    `approve <fp>`, `decline <fp>`. Ctrl-D or `exit` to quit."""
    state.parent.mkdir(parents=True, exist_ok=True)
    history_path = state.parent / "chat_history"
    _load_history(history_path)  # up-arrow recall + editing, seeded from prior sessions
    actor = _local_actor()
    # Natural-language fallback: when an LLM is configured, a line the typed grammar can't parse is
    # handed to the model to map onto ONE vetted verb (the model parses, never executes; an
    # effectful verb is echoed for you to confirm). No LLM -> chat is exactly the typed grammar.
    analyst = LLMAnalyst()  # no egress gate: an interactive shell is already trusted
    # Gate on a real provider, not just the kill switch: `enabled` defaults True even with no key,
    # so `_provider()` ("none" when nothing's configured) is what tells us the model can answer.
    complete = analyst._complete if analyst._provider() != "none" else None
    nl = " -- LLM on: ask a question or give a command in plain English." if complete else ""
    typer.echo(f"steadystate chat -- type `help`, or a command. Ctrl-D (or `exit`) to quit.{nl}")
    # With a model as fallback, guard the deterministic-first shortcut so a verb-leading *sentence*
    # ("show me the findings") isn't mis-grabbed as `show me` -- it falls through to the model. With
    # no model, keep the tolerant parser (it's the only chance to act on the line).
    parse = confident_command if complete is not None else command_from_text
    persisted = 0  # how many of the analyst's calls are already in the cost ledger
    try:
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
            command = parse(line, actor)
            if command is not None:
                typer.echo(run_command(command, str(state)))
                continue
            if complete is None:
                typer.echo("unrecognized -- type `help` for the commands this accepts.")
                continue
            result = nl_to_command(line, actor, complete, state_path=str(state))
            # Count this line's model spend in the ledger (the analyst is long-lived across the
            # loop, so persist only the calls added since last time).
            persist_llm_calls(str(state), analyst.calls[persisted:])
            persisted = len(analyst.calls)
            if result.command is not None:
                note = f"(read as `{result.interpreted}`)\n" if result.interpreted else ""
                typer.echo(note + run_command(result.command, str(state)))
            else:
                typer.echo(result.message)
    finally:
        _save_history(history_path)  # persist so up-arrow survives a restart


@app.command()
def explain(
    fingerprint: str = typer.Argument(
        "",
        help="A finding's fingerprint (prefix ok) to explain in plain language; omit to summarize "
        "the whole current state.",
    ),
    state: Path = _STATE_OPTION,
) -> None:
    """Explain a finding -- or the current state -- in plain language: the LLM's grounded read.

    `explain <fingerprint>` narrates ONE finding from its captured evidence (what it is, why it
    matters, the next step); bare `explain` synthesizes what's open + pending. It reasons over only
    the stored facts, so it never invents risk the data doesn't support. With no LLM configured it
    degrades honestly to the raw facts. The model spend is recorded in the cost ledger under the
    `explain` caller."""
    analyst = LLMAnalyst()  # no egress gate: a local CLI is already trusted
    complete = analyst._complete if analyst._provider() != "none" else None
    _RAW = "(no LLM configured -- showing the raw facts.)\n\n"
    _DEGRADED = "(the model was unavailable -- showing the raw facts.)\n\n"
    with _open_store(state) as store:
        if fingerprint:
            finding = store.get(fingerprint)
            if finding is None:
                matches = store.find_by_prefix(fingerprint)
                if len(matches) == 1:
                    finding = matches[0]
                elif not matches:
                    typer.echo(f"No finding matches '{fingerprint}'. Run `findings` to list them.")
                    raise typer.Exit(1)
                else:
                    typer.echo(
                        f"'{fingerprint}' matches {len(matches)} findings -- "
                        "use more of the fingerprint."
                    )
                    raise typer.Exit(1)
            facts = finding_facts(finding)
            if complete is None:
                typer.echo(_RAW + facts)
                return
            narrative = explain_finding(finding, complete)
            persist_llm_calls(str(state), analyst.calls)  # count the spend in the ledger
            typer.echo(narrative or (_DEGRADED + facts))
        else:
            snapshot = state_snapshot(str(state), with_evidence=True)
            if not snapshot.strip():  # nothing open -> no need to spend a model call
                typer.echo("Nothing open right now -- the cluster looks clear.")
                return
            if complete is None:
                typer.echo(_RAW + snapshot)
                return
            summary = explain_state(snapshot, complete)
            persist_llm_calls(str(state), analyst.calls)
            typer.echo(summary or (_DEGRADED + snapshot))


@app.command()
def probe(
    target: str = typer.Argument(..., help="A named target from STEADYSTATE_TARGETS to scan now."),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Show the full evidence per finding (why + declared/observed).",
    ),
    cost: bool = typer.Option(False, "--cost", help="Add the per-caller LLM spend breakdown."),
    unmute: bool = typer.Option(
        False, "--unmute", help="Show muted/snoozed findings too (bypass suppression this run)."
    ),
    deep: bool = typer.Option(
        False,
        "--deep",
        help="Also scan Running pods' logs for errors (a `kubectl logs` per pod) AND each node's "
        "disk usage % (a `stats/summary` per node) -- a pod up-but-erroring, and a node filling up "
        "before it evicts. Off by default.",
    ),
    json_out: bool = typer.Option(
        False,
        "--json",
        help="Emit the report as JSON to stdout, not the digest -- scriptable, agent-readable "
        "(alerts with reasoning, fingerprints, evidence). Records findings as usual.",
    ),
    state: Path = _STATE_OPTION,
) -> None:
    """Summon a health check of a named target now -- the one-shot, scriptable form of the chat
    `probe <target>` verb. Resolves the target from STEADYSTATE_TARGETS, runs the engine
    (drift + health), and prints what's wrong. **Records** the findings to --state (record-only --
    so they show in `findings` and can be muted -- never resolving another target's; that's
    `sweep`). Honors the mutes/snoozes in --state by default (--unmute shows everything); --verbose
    adds the evidence; --deep also scans pod logs; --json emits a structured object. The SAME path
    the listener runs."""
    state.parent.mkdir(parents=True, exist_ok=True)
    if json_out:  # the machine-readable form: build the report directly and dump it
        from .verbs import probe_report

        try:
            report = probe_report(target, str(state), scan_logs=deep)
        except LookupError as exc:
            typer.echo(str(exc))
            raise typer.Exit(1) from None
        except Exception as exc:  # a real probe failure (unreachable backend, ...)
            typer.secho(f"probe failed: {exc}", fg="red", err=True)
            raise typer.Exit(1) from None
        typer.echo(
            json.dumps(report_to_dict(report, spend=_spend_dict(report.llm_calls)), indent=2)
        )
        return
    flags = frozenset(
        name
        for name, on in (("verbose", verbose), ("cost", cost), ("unmute", unmute), ("deep", deep))
        if on
    )
    typer.echo(run_command(Command(PROBE, _local_actor(), target, flags=flags), str(state)))


@app.command()
def tools() -> None:
    """Emit steadystate's chat verbs as a JSON tool/function-call schema (to stdout).

    For wiring an LLM agent -- e.g. a Microsoft Teams Copilot -- to *drive* steadystate: each tool
    carries its args, its `effect` (read-only / state-write / guardrailed-write / external-send --
    the guardrail the agent must respect), and (for `probe`) its flags. Built from the same command
    table `help`/`chat` use, so it never drifts from what the listener actually dispatches."""
    typer.echo(json.dumps(tool_schema(), indent=2))


_STATUS_STYLE = {
    Status.READY: ("ready", "green"),
    Status.PARTIAL: ("partial", "yellow"),
    Status.OFF: ("off", "dim"),
}


def _detail(cap, status: Status, detail: str) -> str:
    """What to show in the right-hand column: the assessor's note, or -- for an unconfigured
    capability -- the env vars it would need (the 'what do I set?' answer)."""
    if detail:
        return detail
    if status is Status.OFF:
        return "needs " + ", ".join(s.env for s in cap.settings if s.required)
    return "configured"


def _render_audit(console: Console, env: dict[str, str], *, title: str) -> None:
    rows = {row.capability: row for row in audit(env)}
    console.print(f"\n[bold]{title}[/bold]")
    for section, caps in SECTIONS:
        table = Table(show_header=True, header_style="bold", title_justify="left")
        table.add_column(section)
        table.add_column("status")
        table.add_column("needs / detail", overflow="fold")
        for cap in caps:
            row = rows[cap]
            label, style = _STATUS_STYLE[row.status]
            table.add_row(
                cap.title, f"[{style}]{label}[/{style}]", _detail(cap, row.status, row.detail)
            )
        console.print(table)
    counts = summary(list(rows.values()))
    console.print(
        f"[green]{counts[Status.READY]} ready[/green]  "
        f"[yellow]{counts[Status.PARTIAL]} partial[/yellow]  "
        f"[dim]{counts[Status.OFF]} off[/dim]"
    )


# The runtime *dials* -- behavior tuners that the capability audit doesn't cover (they're not
# ready/partial/off, they're a value with a default). (env var, default shown when unset, effect).
# None are secrets, so doctor prints their live values. The full table lives in CONFIG.md.
_DIALS: tuple[tuple[str, str, str], ...] = (
    ("STEADYSTATE_TARGETS", ".steadystate/targets.json", "named-targets registry (your wall)"),
    ("STEADYSTATE_DECIDER_AUTO", "off", "let the LLM decider act autonomously (within the bound)"),
    ("STEADYSTATE_REFLEX_AUTO", "off", "let reflexes act autonomously"),
    ("STEADYSTATE_MCP_WRITE", "off", "expose effectful verbs over MCP (= mcp --write)"),
    (
        "STEADYSTATE_MCP_AUTHOR",
        "off",
        "expose check-authoring over MCP, not infra (= mcp --author)",
    ),
    ("STEADYSTATE_BOUND", "built-in", "override the impact x reversibility bound"),
    ("STEADYSTATE_BREAKGLASS_USERS", "(nobody)", "who may confirm an out-of-bound action"),
    ("STEADYSTATE_LLM_ENABLED", "on", "LLM kill switch (false/0/no/off disables all calls)"),
    ("STEADYSTATE_LLM_PROVIDER", "auto", "force anthropic | openai"),
    ("STEADYSTATE_LLM_TIMEOUT", "30", "per-call timeout (seconds)"),
    ("STEADYSTATE_MODEL", "claude-sonnet-4-6", "default model"),
    ("STEADYSTATE_MODEL_CHEAP", "claude-haiku-4-5", "cheap tier (routing callers, e.g. chat-nl)"),
    ("STEADYSTATE_REACHABLE_TIMEOUT", "8s", "cluster reachability probe timeout (0 = no cap)"),
    ("STEADYSTATE_RESOLVE_AFTER", "30m", "grace before a gone finding resolves (0 = immediate)"),
    ("STEADYSTATE_PATCH_DIR", ".steadystate/patches", "where remediation patch files are written"),
    ("STEADYSTATE_SILOS", "~/.steadystate/silos.json", "named-silo registry (`silo add` / --silo)"),
    ("STEADYSTATE_CHECKS", ".steadystate/checks.json", "custom-checks file (version-control this)"),
    ("STEADYSTATE_SOLUTIONS", ".steadystate/solutions.json", "authored runbook (version-control)"),
    ("STEADYSTATE_SOLUTION_AUTO", "off", "auto-apply matched solutions in-bound (else offer)"),
    ("STEADYSTATE_ENRICH_QUERY", "(none)", "PromQL bar for --enrich prometheus"),
    ("STEADYSTATE_METRICS_SOURCE", "prometheus", "monitoring backend `metrics` reads"),
    ("STEADYSTATE_METRIC_QUERIES", ".steadystate/metrics.json", "{name: query} map for `metrics`"),
)


def _render_dials(console: Console, env: dict[str, str]) -> None:
    """The runtime dials with their live values -- the behavior tuners the capability audit omits.
    Each shows the set value, or its default when unset. None are secrets. See CONFIG.md for all."""
    table = Table(show_header=True, header_style="bold", title_justify="left")
    table.add_column("runtime dial")
    table.add_column("value")
    table.add_column("effect", overflow="fold")
    for name, default, effect in _DIALS:
        value = env.get(name, "").strip()
        shown = value if value else f"[dim](default: {default})[/dim]"
        table.add_row(name, shown, effect)
    console.print(
        "\n[bold]Runtime dials[/bold] [dim](behavior tuners -- full table in CONFIG.md)[/dim]"
    )
    console.print(table)


@app.command()
def doctor(
    env_file: Path | None = typer.Option(
        None, "--env-file", help="Also read this .env (the live environment still wins)."
    ),
) -> None:
    """Show what's configured and what each capability still needs -- a read-only preflight.

    Inspects the live environment (plus an optional --env-file) and reports every capability as
    ready / partial / off, then the runtime dials with their live values. Never prints a secret
    value -- safe to run and paste. The answer to 'if I didn't set this up, what do I need?'"""
    env = dict(os.environ)
    if env_file:
        env = {**read_env_file(env_file), **env}  # live env overrides the file
    console = Console()
    _render_audit(console, env, title="Configuration")
    _render_dials(console, env)
    _render_intent(console)


def _render_intent(console: Console) -> None:
    """The authored-intent preflight: diagnose `checks.json` + `solutions.json` so an authored rule
    that 'doesn't show up' has a clear cause -- they load SILENTLY (bad path / bad JSON / a bad
    entry all vanish without a word), and this is where that becomes visible."""
    from .probe.custom import diagnose_checks
    from .probe.solutions import diagnose_solutions

    console.print("\n[bold]Authored intent[/bold] (checks + runbook)")
    for line in diagnose_checks() + diagnose_solutions():
        console.print(f"  {line}")


def _create_targets(
    findings: list, extra: list | None = None, *, check_reachable: bool = False
) -> None:
    """`--create`: (re)write the targets registry (the name -> target map the chat listener
    resolves) to exactly what's discovered *now* -- overwriting the old file. A re-run reflects
    current reality: a re-discovered target is refreshed, and a stale entry (a cluster/kubeconfig/
    source no longer here) is dropped rather than lingering. ``extra`` carries the live-discovered
    targets from a paired ``--deep`` (compose projects rooted outside the cwd).

    ``check_reachable`` skips a discovered live cluster context whose API server isn't answering (a
    stopped minikube, a deleted context still lingering in the kubeconfig) -- one fast `kubectl
    cluster-info` per live target, so a dead cluster never lands in the registry. Only ``k8s-live``
    targets are pinged; file/host sources are never contacted."""
    target_file = Path(os.environ.get(TARGETS_ENV) or DEFAULT_TARGETS_FILE)
    proposed = proposed_targets(findings, Path.cwd())
    # Fold in the live-discovered targets, but drop any the cwd-local pass already covers -- so a
    # compose project *in* the cwd isn't registered twice under two names. Key on (source, path,
    # context, kubeconfig): live cluster targets share an empty path, so context (+ which kubeconfig
    # it lives in) is what distinguishes them.
    seen = {(t.source, t.path, t.context, t.kubeconfig, t.inventory) for t in proposed}
    for target in extra or []:
        key = (target.source, target.path, target.context, target.kubeconfig, target.inventory)
        if key not in seen:
            proposed.append(target)
            seen.add(key)
    # Reachability filter: a discovered live context whose cluster isn't up (a stopped minikube, a
    # deleted context still in the kubeconfig) shouldn't be registered as a probe target.
    unreachable: list = []
    if check_reachable:
        kept = []
        for target in proposed:
            if target.source == "k8s-live" and not context_reachable(
                target.context, target.kubeconfig
            ):
                unreachable.append(target)
            else:
                kept.append(target)
        proposed = kept
    if not proposed and not unreachable:
        typer.echo("\nno scannable source found here -- nothing to create.")
        return
    try:
        existing = load_targets(target_file) if target_file.exists() else {}
    except (OSError, ValueError) as exc:
        typer.echo(f"\nexisting targets file {target_file} is malformed: {exc}", err=True)
        raise typer.Exit(1) from exc
    # Overwrite: the file becomes exactly this discovery. Names in the old file that weren't
    # rediscovered are dropped (reported as stale), so the registry never accretes dead entries.
    fresh = {target.name: target for target in proposed}
    removed = [name for name in existing if name not in fresh]
    save_targets(target_file, fresh)
    typer.echo(f"\nTARGETS -> {target_file}  (overwritten)")
    for target in proposed:
        mark = "refreshed" if target.name in existing else "added"
        locator = f"context={target.context}" if target.context else target.path
        typer.echo(f"  {target.name:<26} {target.source} @ {locator}  [{mark}]")
    for target in unreachable:
        typer.echo(
            f"  {target.name:<26} {target.source} @ context={target.context}  "
            f"[skipped (unreachable)]"
        )
    for name in removed:
        typer.echo(f"  {name:<26} [removed (stale)]")
    typer.echo(f"point the listener at it:  export {TARGETS_ENV}={target_file}")


@app.command()
def discover(
    deep: bool = typer.Option(
        False,
        "--deep",
        help="Also run read-only live reads (kubectl get nodes, helm list, ...) against reachable "
        "backends and report concrete facts + commands carrying your real release/namespace names.",
    ),
    create: bool = typer.Option(
        False,
        "--create",
        help="Write the discovered sources into the targets registry (STEADYSTATE_TARGETS, else "
        ".steadystate/targets.json) as named scan/probe targets -- named after the cwd, suffixed "
        "per source "
        "when several are found. With --deep, also registers live compose projects rooted outside "
        "the cwd. OVERWRITES the registry with what's discovered now -- stale entries (no longer "
        "present) are dropped, a re-discovered target is refreshed.",
    ),
    reachable: bool = typer.Option(
        True,
        "--reachable/--no-reachable",
        help="With --create, skip a live cluster context whose cluster isn't reachable (a stopped "
        "minikube, a deleted context left in the kubeconfig) -- a fast `kubectl cluster-info` per "
        "context. Use --no-reachable to register every context even if unreachable (e.g. a CI or "
        "setup box that can't reach the clusters at discover time).",
    ),
    emit_ci: bool = typer.Option(
        False,
        "--emit-ci",
        help="Instead of the report, print a GitHub Actions workflow that scans the sources found "
        "here -- tailored capture + scan per source, auth left as TODO. Pipe it: "
        "`discover --emit-ci > .github/workflows/steadystate-drift.yml`.",
    ),
    json_out: bool = typer.Option(
        False,
        "--json",
        help="Emit the report as JSON (sources/probes, the --deep facts, and a top-level "
        "`scannable` flag) instead of text -- for other tooling to consume.",
    ),
    check: bool = typer.Option(
        False,
        "--check",
        help="Exit non-zero if nothing is scannable here (no READY source, no snapshot) -- a "
        "branchable signal for a CI/preflight gate. Composes with the normal or --json output.",
    ),
) -> None:
    """Show what `scan`/`probe` can do *here* -- in the current directory and on this machine.

    Where `doctor` checks credentials and `catalog` lists what the build offers, this is the
    environment preflight: per `--source` and `--probe`, whether the CLI it needs is installed and
    its backend reachable, whether a usable input is in the cwd, and the exact command to run.
    `--deep` goes further -- it interrogates the live backends (read-only) and tailors the advice
    to what's actually there. `--create` turns the hits into named targets. `--emit-ci` prints a
    tailored GitHub Actions workflow instead of the report. `--json` emits the report for tooling;
    `--check` exits non-zero when nothing is scannable. Run it from the directory you intend to
    scan."""
    # --emit-ci and --json are mutually-exclusive *output formats*; --create mutates the targets
    # registry and prints a human summary, so it can't ride a clean machine-output stream.
    if emit_ci and json_out:
        raise typer.BadParameter("--emit-ci and --json are different output formats; pick one.")
    if create and (emit_ci or json_out):
        raise typer.BadParameter("--create can't combine with --emit-ci/--json (a pure output).")

    findings = probe_environment()
    # --emit-ci is a scripting mode: stdout is *only* the workflow YAML (for `> drift.yml`), so the
    # human report is suppressed and progress notes go to stderr.
    if emit_ci:
        cwd = Path.cwd()
        if not emittable_sources(findings):
            typer.echo("no scannable source discovered here -- nothing to emit.", err=True)
            return
        for line in emit_github_actions(findings, cwd):
            typer.echo(line)
        return

    inspections = deep_inspect() if deep else []
    if json_out:
        typer.echo(json.dumps(discovery_as_dict(findings, inspections if deep else None), indent=2))
    else:
        lines = render_discovery(findings)
        if deep:
            lines += render_inspections(inspections)
        for line in lines:
            typer.echo(line)
        if create:
            # Live targets to fold in: deep-discovered compose projects (with --deep), one k8s-live
            # target per kube context, plus one per context in any kubeconfig sitting in the cwd
            # (each carrying its kubeconfig so `probe` can reach it) -- so `discover --create`
            # registers your clusters, including the ones not on kubectl's default path.
            extra = (
                deep_targets(inspections)
                + context_targets(kube_contexts())
                + kubeconfig_targets(Path.cwd())
            )
            ansible_live = ansible_live_target(Path.cwd())  # a live host-health target if inventory
            if ansible_live is not None:
                extra.append(ansible_live)
            _create_targets(findings, extra=extra, check_reachable=reachable)

    # --check turns "nothing to scan here" into a non-zero exit, AFTER the report/create so the
    # output (and any target writes) still happen -- it only gates the exit code.
    if check and not scannable_now(findings):
        raise typer.Exit(1)


@app.command()
def init(
    env_file: Path = typer.Option(
        Path(".env"), "--env-file", help="The .env to write (merged, gitignored)."
    ),
) -> None:
    """Interactive setup wizard: walk the capabilities, prompt for what you want, write a .env.

    Skips anything you decline, hides secret input, and merges into an existing .env without
    wiping the keys you're not touching. The file is gitignored and chmod 600 -- secrets stay out
    of the repo and off the terminal. Ends by printing the `doctor` view of the result."""
    console = Console()
    console.print("[bold]steadystate setup[/bold] - configure a capability, or skip it.")
    existing = read_env_file(env_file)
    if existing:
        console.print(f"[dim]Merging into existing {env_file} ({len(existing)} key(s)).[/dim]")

    updates: dict[str, str] = {}
    for section, caps in SECTIONS:
        console.print(f"\n[bold cyan]{section}[/bold cyan]")
        for cap in caps:
            if not typer.confirm(f"  Configure {cap.title}? - {cap.blurb}", default=False):
                continue
            for s in cap.settings:
                current = existing.get(s.env, "")
                value = typer.prompt(
                    f"    {s.prompt}",
                    default=current,
                    hide_input=s.secret,
                    show_default=not s.secret,
                )
                if value:
                    updates[s.env] = value

    if not updates:
        console.print("\n[dim]Nothing configured — no file written.[/dim]")
        raise typer.Exit()

    merged = write_env_file(env_file, updates)
    console.print(
        f"\n[green]Wrote {len(updates)} setting(s)[/green] to {env_file} [dim](gitignored)[/dim]."
    )
    _render_audit(console, merged, title="Result")
    console.print(
        "\nLoad it:  [bold]set -a; . ./.env; set +a[/bold]  or  "
        "[bold]docker run --env-file .env …[/bold]"
    )
    console.print("[dim]Secrets live only in this file. Never commit it.[/dim]")


def _ensure_utf8_streams() -> None:
    """Make stdout/stderr UTF-8 with a replace fallback. LLM output (and resource names) can carry
    any Unicode -- an arrow, an em-dash, an emoji -- but a Windows console stdout defaults to a
    non-UTF-8 codec (cp1252), which **crashes** rich/typer on such a character. So a model writing
    ``->`` could take down a whole scan. This makes output encodable everywhere; a no-op where a
    stream can't be reconfigured (a redirected pipe without the method)."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            with contextlib.suppress(Exception):
                reconfigure(encoding="utf-8", errors="replace")


def main() -> None:
    _ensure_utf8_streams()
    app()


if __name__ == "__main__":
    main()
