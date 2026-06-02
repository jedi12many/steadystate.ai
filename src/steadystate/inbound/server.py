"""The generic inbound listener: one stdlib HTTP shell over any InboundAdapter.

steadystate is a one-shot CLI and Python ships no websocket client, so approvals arrive
over a chat provider's *interactive HTTP* webhook. This module owns the transport and the
routing; the provider-specific signing and payload shapes live in the adapter. The routing
is factored into `dispatch` (pure: request in, status + reply bytes out) so the security and
control flow are testable without standing up a socket.
"""

from __future__ import annotations

import contextlib
import json
import logging
import threading
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from ..act.approve import apply_pending, decline_pending
from ..engine import build_report
from ..reason.alert import Alert
from ..reason.cost import roll_up, roll_up_by_period, scan_cost_line
from ..reason.report import Report
from ..reconcile_state import _fingerprints, finding_evidence, seen_findings
from ..state import StateStore
from ..sweep import render_sweep, sweep_targets
from ..targets import load_targets_from_env
from .base import (
    APPROVE,
    COST,
    DECLINE,
    FINDINGS,
    HELP,
    HISTORY,
    MUTE,
    PENDING,
    PROBE,
    RAW,
    TARGETS,
    Command,
    InboundAdapter,
    render_help,
)

logger = logging.getLogger(__name__)


def _render_pending(state_path: str) -> str:
    """The chat view of `steadystate pending`: the open remediations and their fingerprints, so
    an operator can discover what's awaiting them (and what to approve) without leaving chat."""
    with StateStore(state_path) as store:
        rows = store.all_pending()
    if not rows:
        return "No remediations awaiting approval."
    lines = [f"{len(rows)} remediation(s) awaiting approval:"]
    lines += [f"  {p.fingerprint}  {p.source}  {p.drift_identity}" for p in rows]
    lines.append("Approve with:  approve <fingerprint>")
    return "\n".join(lines)


def _compact(value: object) -> str:
    """A one-line, length-capped view of a drift's declared/observed side for `verbose`."""
    return json.dumps(value, default=str)[:240] if value is not None else "(none)"


def _evidence(alert: Alert) -> list[str]:
    """The full reasoning + before/after for one alert -- what `probe ... verbose` adds so an
    operator can *audit* a finding (is it accurate?) instead of trusting the title alone."""
    out = [f"           why: {alert.why_it_matters}"]
    if alert.recommended_action:
        out.append(f"           fix: {alert.recommended_action}")
    if alert.remediation_label:  # whether steadystate can carry out the fix, or it's manual
        out.append(f"           can: {alert.remediation_label}")
    for d in alert.drifts:
        out.append(f"           drift: {d.summary()}")
        if d.declared is not None or d.observed is not None:
            out.append(f"             declared: {_compact(d.declared)}")
            out.append(f"             observed: {_compact(d.observed)}")
    for f in alert.findings:
        out.append(f"           finding: {f.title} -- {f.detail}")
    for s in alert.symptoms:
        out.append(f"           symptom: {s.title} -- {s.detail}")
    return out


def _summarize(name: str, alerts: list[Alert], suppressed: int = 0, verbose: bool = False) -> str:
    """A chat summary of a summoned scan: the kept alerts (worst first, as the report orders them)
    or a clean all-clear, plus how many were withheld by mute/snooze. Each alert shows its title,
    a one-line description (``why_it_matters``), and its fingerprint(s); ``verbose`` swaps the
    one-liner for the full evidence (the declared->observed before/after, fix, per-symptom detail).
    Read-only -- it reports, never records or applies. (Spend footer is appended by the caller.)"""
    if not alerts:
        if suppressed:
            return f"{name}: clean except {suppressed} muted/snoozed -- add `unmute` to show."
        return f"{name}: clean -- no drift or symptoms above the bar."
    lines = [f"{name}: {len(alerts)} alert(s)"]
    for a in alerts:
        chips = " ".join(f"[{r.framework} {r.id}]" for r in a.references)
        head = f"  {a.severity.value.upper():<8} {a.title}"
        lines.append(f"{head}  {chips}" if chips else head)
        # The description -- so a probe says WHAT is wrong, not just a title + fingerprints.
        # `verbose` replaces it with the full evidence (which already leads with why_it_matters).
        if verbose:
            lines += _evidence(a)
        elif a.why_it_matters:
            lines.append(f"           {a.why_it_matters}")
        if a.recommended_action and not verbose:  # the one-line fix, when there is one
            lines.append(f"           fix: {a.recommended_action}")
        # The fingerprint(s) so the finding is actionable -- `mute <fp>` a benign one, and a
        # diagnosis Alert (drift + symptom) lists both, since suppressing it needs both muted.
        for fp in _fingerprints(a):
            lines.append(f"           fp {fp}")
    if suppressed:
        lines.append(f"  (+{suppressed} suppressed by mute/snooze -- add `unmute` to show)")
    return "\n".join(lines)


def _render_cost(state_path: str, period: str) -> str:
    """The chat view of `steadystate cost`: cumulative LLM spend from the listener's store (which
    the scheduled scans + approvals share). ``period`` "day"/"week" gives the trend, else the
    per-caller rollup. Read-only."""
    if not state_path or not Path(state_path).exists():
        return "No spend recorded yet."
    with StateStore(state_path) as store:
        if period in ("day", "week"):
            buckets = roll_up_by_period(store.timed_llm_calls_since(None), period)
            if not buckets:
                return "No LLM calls recorded yet."
            total = sum(p.cost_usd for p in buckets)
            lines = [f"LLM spend (by {period}): ~${total:.4f} total"]
            lines += [f"  {p.period:<11} ~${p.cost_usd:.4f}  {p.calls} call(s)" for p in buckets]
            return "\n".join(lines)
        rows = roll_up(store.llm_calls_since(None))
        if not rows:
            return "No LLM calls recorded yet."
        total = sum(r.cost_usd for r in rows)
        calls = sum(r.calls for r in rows)
        lines = [f"LLM spend (all): ~${total:.4f} over {calls} call(s)"]
        lines += [f"  {r.caller:<12} ~${r.cost_usd:.4f}  {r.calls} call(s)" for r in rows]
        return "\n".join(lines)


def _honor_mutes(alerts: list[Alert], state_path: str) -> tuple[list[Alert], int]:
    """Drop alerts whose fingerprints are ALL muted or actively snoozed -- the exact rule the
    stateful reconcile uses (reconcile_state), but READ-ONLY: it reads the suppression state and
    writes nothing. Returns (kept, suppressed_count)."""
    kept: list[Alert] = []
    suppressed = 0
    now = datetime.now(UTC)
    with StateStore(state_path) as store:
        for alert in alerts:
            fps = _fingerprints(alert)
            if fps and all(store.is_suppressed(fp, now) for fp in fps):
                suppressed += 1
            else:
                kept.append(alert)
    return kept, suppressed


def _render_targets() -> str:
    """The chat view of the probe-target registry (STEADYSTATE_TARGETS) -- so an operator can see
    what `probe <target>` can reach without recalling the targets file."""
    targets = load_targets_from_env()
    if not targets:
        return "No targets configured -- run `discover --create` or set STEADYSTATE_TARGETS."
    lines = [f"{len(targets)} target(s):"]
    lines += [
        f"  {name:<14} {t.source:<14} {('context=' + t.context) if t.context else t.label}"
        for name, t in sorted(targets.items())
    ]
    return "\n".join(lines)


def _render_findings(state_path: str) -> str:
    """The chat view of `steadystate findings`: every remembered finding, its fingerprint, status
    (open/muted/snoozed/resolved) and last severity -- the keys for mute/approve. Read-only."""
    if not state_path or not Path(state_path).exists():
        return "No findings recorded yet."
    with StateStore(state_path) as store:
        rows = store.all_findings()
    if not rows:
        return "No findings recorded yet."
    lines = [f"{len(rows)} finding(s):"]
    lines += [f"  {f.fingerprint}  {f.status:<8} {f.last_severity:<6} {f.last_title}" for f in rows]
    return "\n".join(lines)


def _render_raw(fingerprint: str, state_path: str) -> str:
    """The chat view of `raw <fingerprint>`: a finding's captured evidence -- the structured fields
    a probe recorded (namespace, cluster, pod count, the failing pod's last log line, ...) plus when
    it was first and last seen, so an operator can answer "what exactly broke, and was it during the
    window I care about?". Accepts a unique fingerprint prefix (they're long). Read-only.

    Each error keeps its own fingerprint, so on a grouped finding you ask `raw` of any one member's
    fingerprint and get that instance's detail -- one example is enough."""
    if not state_path or not Path(state_path).exists():
        return "No findings recorded yet -- run a `probe`/`scan` first."
    with StateStore(state_path) as store:
        finding = store.get(fingerprint)
        if finding is None:  # not an exact id -> try a unique prefix (a copy-pasted short fp)
            matches = store.find_by_prefix(fingerprint)
            if len(matches) > 1:
                return f"'{fingerprint}' matches {len(matches)} findings -- use more of the fp."
            finding = matches[0] if matches else None
    if finding is None:
        return f"Unknown fingerprint '{fingerprint}'. Run `findings` to list them."
    lines = [
        finding.last_title,
        f"  fingerprint   {finding.fingerprint}",
        f"  status        {finding.status}   severity {finding.last_severity}",
        f"  first seen    {finding.first_seen}",
        f"  last seen     {finding.last_seen}",
    ]
    if finding.details:
        lines.append("  -- evidence --")
        lines += [f"  {key:<14} {value}" for key, value in finding.details.items()]
    else:  # a finding recorded before evidence capture, or a type that carries none
        lines.append("  (no raw evidence captured -- re-run a `probe`/`scan` to capture it)")
    return "\n".join(lines)


def _render_history(state_path: str) -> str:
    """The chat view of `steadystate history`: the remediation audit log, newest first -- what ran
    against real infra, who decided, and the outcome. Read-only."""
    if not state_path or not Path(state_path).exists():
        return "No remediation history."
    with StateStore(state_path) as store:
        rows = store.audit_log(limit=10)
    if not rows:
        return "No remediation history."
    lines = ["recent remediations (newest first):"]
    lines += [f"  {r.outcome.upper():<9} {r.drift_identity}  {r.actor}  {r.at[:10]}" for r in rows]
    return "\n".join(lines)


def _record_probe_findings(report: Report, state_path: str) -> None:
    """Persist a summoned probe's findings to the store (new/recurring memory, and the db file
    itself) so they show in `findings` and can be muted. **Record-only**: no `resolve_absent` -- a
    single probe isn't a full-fleet view, so it must never mark another target's findings resolved
    (that's `sweep`'s job, over the union). Best-effort: a wedged store never sinks the probe."""
    with contextlib.suppress(Exception):
        Path(state_path).parent.mkdir(parents=True, exist_ok=True)
        with StateStore(state_path) as store:
            store.record(seen_findings(report), datetime.now(UTC), finding_evidence(report))


def _run_probe(target_name: str, state_path: str, flags: frozenset[str]) -> str:
    """Summon: scan a named target now and report what's wrong. Resolves the name against the
    targets registry (STEADYSTATE_TARGETS), runs the SAME engine a scheduled scan runs -- and,
    unless ``unmute`` is set, honors the mutes/snoozes the operator already set.
    ``verbose`` adds the full evidence per alert; ``cost`` adds the per-caller spend breakdown.
    The reply carries a one-line spend footer. It **records** its findings (record-only -- so they
    show in `findings` and can be muted -- never resolving another target's), but never applies:
    chat stays a trigger, not a bypass."""
    if target_name == "all":  # `probe all` -> the stateful fleet sweep, not a single summon
        return _run_sweep(state_path, flags)
    targets = load_targets_from_env()
    if not targets:
        return "No targets configured -- run `discover --create` or set STEADYSTATE_TARGETS."
    target = targets.get(target_name)
    if target is None:
        return f"Unknown target '{target_name}'. Known: {', '.join(sorted(targets))}."
    try:
        # A live target (k8s-live) has no path -- Path("") is "." which its source ignores; the
        # context aims the source + probe at that one cluster.
        report = build_report(
            target.source,
            Path(target.path),
            probe="auto",
            label=target.label,
            context=target.context,
        )
    except Exception as exc:  # a summon must report the failure, never crash the listener
        return f"Probe of '{target_name}' failed: {exc}"
    if state_path:  # persist the findings (record-only) -- this also creates the db
        _record_probe_findings(report, state_path)
    alerts = list(report.alerts)
    suppressed = 0
    # Honor mutes by default, read-only -- but only when there's an existing store to read (opening
    # a missing path would create one, a write). `unmute` skips suppression for this run.
    if "unmute" not in flags and state_path and Path(state_path).exists():
        alerts, suppressed = _honor_mutes(alerts, state_path)
    out = _summarize(target_name, alerts, suppressed, verbose="verbose" in flags)
    spend = scan_cost_line(report.llm_calls)  # None on a --no-llm run -> no footer
    if spend:
        out += f"\n  {spend}"
        if "cost" in flags:  # the per-caller breakdown of this probe's spend
            out += "".join(
                f"\n    {r.caller:<12} ~${r.cost_usd:.4f}  {r.calls} call(s)"
                for r in roll_up(report.llm_calls)
            )
    return out


def _run_sweep(state_path: str, flags: frozenset[str]) -> str:
    """`probe all`: the **stateful** fleet sweep -- every target probed, rolled up into one digest
    of what's on fire across the fleet. Unlike the single `probe` (stateless), this records to the
    store so each sweep compares to the last (new/resolved) -- the operator asked for the batch to
    build history. Degrades to a stateless snapshot when the listener has no store path.

    The reply is the cluster tally (which clusters are on fire / clear / unreachable, and what
    recovered) followed by the fleet's findings in the SAME detail a single `probe` gives --
    description and fingerprint(s) -- so `probe all` says WHAT is wrong and stays muteable, not just
    a count. ``verbose`` swaps each finding's one-liner for its full evidence."""
    targets = load_targets_from_env()
    if not targets:
        return "No targets configured -- run `discover --create` or set STEADYSTATE_TARGETS."
    result = sweep_targets(targets, state_path, datetime.now(UTC), stateless=not state_path)
    # The tally; the CLI's terse "correlated" roll-up is replaced below by the full-detail findings.
    lines = render_sweep(result, correlated=False)
    if result.report.alerts:  # the deduped fleet findings, rendered like a single probe
        lines.append(_summarize("the fleet", result.report.alerts, verbose="verbose" in flags))
    return "\n".join(lines)


def run_command(command: Command, state_path: str) -> str:
    """Drive a parsed Command to an outcome string the provider echoes back. The read-only verbs
    (help, targets, pending, probe, cost, findings, history) answer directly; mute and
    approve/decline write through the SAME cores the CLI uses. probe is read-only -- it scans +
    reports, so chat stays a trigger, never a bypass; mute only silences a finding."""
    if command.verb == HELP:
        return render_help()
    if command.verb == TARGETS:
        return _render_targets()
    if command.verb == PENDING:
        return _render_pending(state_path)
    if command.verb == PROBE:
        return _run_probe(command.argument, state_path, command.flags)
    if command.verb == COST:
        return _render_cost(state_path, command.argument)
    if command.verb == FINDINGS:
        return _render_findings(state_path)
    if command.verb == RAW:
        return _render_raw(command.argument, state_path)
    if command.verb == HISTORY:
        return _render_history(state_path)
    with StateStore(state_path) as store:
        if command.verb == APPROVE:
            message, _result = apply_pending(store, command.argument, command.actor)
            return message
        if command.verb == DECLINE:
            return decline_pending(store, command.argument, command.actor)
        if command.verb == MUTE:
            # Silence a finding (e.g. a benign probe result) on future scans/probes. Upserts, so
            # it works on a fingerprint the store hasn't recorded yet -- exactly the probe case.
            store.mute(command.argument, None, command.actor, datetime.now(UTC))
            fp = command.argument
            return f"Muted {fp} -- silenced on future scans until `steadystate unmute {fp}`."
    return "Nothing to do."


# Verbs whose work can exceed a chat provider's ~3s interaction window (a probe runs a full
# scan). For these, if the provider supports deferral, we ACK immediately and post the result
# back when it's ready; everything else answers synchronously.
_DEFERRABLE = frozenset({PROBE})


def _try_defer(adapter: InboundAdapter, body: str) -> bytes | None:
    """The provider's immediate ACK bytes if it supports deferral (Discord/Slack), else None
    (Teams -> synchronous). An optional capability, probed by attribute like the rest of the
    seam -- so a provider without it conforms unchanged."""
    defer = getattr(adapter, "defer", None)
    return defer(body) if defer is not None else None


def _complete(adapter: InboundAdapter, body: str, message: str) -> None:
    """Post the finished result back through the provider's deferral channel (PATCH the deferred
    Discord message / POST a Slack response_url). Best-effort -- a failed post must never crash
    the background worker."""
    complete = getattr(adapter, "complete", None)
    if complete is None:
        return
    try:
        complete(body, message)
    except Exception as exc:  # the worker must never crash the listener on a flaky post
        logger.warning("failed to post deferred result: %s", exc)


def dispatch(
    adapter: InboundAdapter, headers: Mapping[str, str], body: str, state_path: str
) -> tuple[int, bytes, Callable[[], None] | None]:
    """One inbound POST -> (HTTP status, immediate reply bytes, optional deferred work). The order
    is the security order: verify FIRST (a forged request is 401 before anything else looks at it),
    then answer a protocol handshake, then parse + run the command.

    When the command is slow (a probe) and the adapter supports deferral, the reply is an immediate
    ACK and the third element is a callable the handler runs in the background -- it does the scan
    and posts the result back via the provider. Otherwise the reply IS the result and it's None."""
    if not adapter.verify(headers, body):
        return 401, b"", None
    reply = adapter.handshake(body)
    if reply is not None:
        return 200, reply, None
    command = adapter.parse(body)
    if command is None:
        return 200, adapter.respond("Nothing to do."), None
    if command.verb in _DEFERRABLE:
        ack = _try_defer(adapter, body)
        if ack is not None:  # ACK now; do the slow scan + post the result in the background

            def _work() -> None:
                _complete(adapter, body, run_command(command, state_path))

            return 200, ack, _work
    return 200, adapter.respond(run_command(command, state_path)), None


def make_handler(adapter: InboundAdapter, state_path: str) -> type[BaseHTTPRequestHandler]:
    """A BaseHTTPRequestHandler bound to one adapter + state db -- a thin shell over dispatch."""

    class _Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length).decode("utf-8", "replace")
            # self.headers is an email.message.Message; flatten to a plain mapping for the
            # adapter (provider header names arrive with stable casing, e.g. X-Slack-Signature).
            headers = dict(self.headers.items())
            status, reply, deferred = dispatch(adapter, headers, body, state_path)
            self.send_response(status)
            if reply:
                self.send_header("Content-Type", adapter.content_type)
            self.end_headers()
            self.wfile.write(reply)
            # Run any deferred work AFTER the ACK is flushed, off the request path, so the handler
            # returns immediately (within the provider's window) and the scan posts back when done.
            if deferred is not None:
                threading.Thread(target=deferred, daemon=True).start()

        def log_message(self, *args: object) -> None:  # keep the listener quiet
            pass

    return _Handler


def serve(adapter: InboundAdapter, port: int, state_path: str) -> None:  # pragma: no cover
    """Run the approval listener for ``adapter`` until interrupted (blocking)."""
    HTTPServer(("", port), make_handler(adapter, state_path)).serve_forever()
