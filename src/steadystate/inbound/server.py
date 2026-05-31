"""The generic inbound listener: one stdlib HTTP shell over any InboundAdapter.

steadystate is a one-shot CLI and Python ships no websocket client, so approvals arrive
over a chat provider's *interactive HTTP* webhook. This module owns the transport and the
routing; the provider-specific signing and payload shapes live in the adapter. The routing
is factored into `dispatch` (pure: request in, status + reply bytes out) so the security and
control flow are testable without standing up a socket.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from ..act.approve import apply_pending, decline_pending
from ..engine import build_report
from ..reason.alert import Alert
from ..reason.cost import roll_up, roll_up_by_period, scan_cost_line
from ..reconcile_state import _fingerprints
from ..state import StateStore
from ..targets import load_targets_from_env
from .base import (
    APPROVE,
    COST,
    DECLINE,
    HELP,
    PENDING,
    PROBE,
    Command,
    InboundAdapter,
    render_help,
)


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


def _summarize(name: str, alerts: list[Alert], suppressed: int = 0) -> str:
    """A chat summary of a summoned scan: the kept alerts (worst first, as the report orders them)
    or a clean all-clear, plus how many were withheld by mute/snooze. Read-only -- it reports,
    it never records or applies. (The spend footer is appended by the caller.)"""
    if not alerts:
        if suppressed:
            return f"{name}: clean except {suppressed} muted/snoozed -- add `unmute` to show."
        return f"{name}: clean -- no drift or symptoms above the bar."
    lines = [f"{name}: {len(alerts)} alert(s)"]
    for a in alerts:
        lines.append(f"  {a.severity.value.upper():<8} {a.title}")
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


def _run_probe(target_name: str, state_path: str, bypass: bool) -> str:
    """Summon: scan a named target now and report what's wrong. Resolves the name against the
    targets registry (STEADYSTATE_TARGETS), runs the SAME engine a scheduled scan runs -- and,
    unless ``bypass`` (the `unmute` flag), honors the mutes/snoozes the operator already set
    (read-only). The reply carries a one-line spend footer. It never records or applies -- chat
    stays a trigger, not a bypass."""
    targets = load_targets_from_env()
    if not targets:
        return "No targets configured (set STEADYSTATE_TARGETS to a targets file on the listener)."
    target = targets.get(target_name)
    if target is None:
        return f"Unknown target '{target_name}'. Known: {', '.join(sorted(targets))}."
    try:
        report = build_report(target.source, Path(target.path), probe="auto", label=target.label)
    except Exception as exc:  # a summon must report the failure, never crash the listener
        return f"Probe of '{target_name}' failed: {exc}"
    alerts = list(report.alerts)
    suppressed = 0
    # Honor mutes by default, read-only -- but only when there's an existing store to read (opening
    # a missing path would create one, a write). `unmute` skips suppression for this run.
    if not bypass and state_path and Path(state_path).exists():
        alerts, suppressed = _honor_mutes(alerts, state_path)
    summary = _summarize(target_name, alerts, suppressed)
    spend = scan_cost_line(report.llm_calls)  # None on a --no-llm run -> no footer
    return f"{summary}\n  {spend}" if spend else summary


def run_command(command: Command, state_path: str) -> str:
    """Drive a parsed Command to an outcome string the provider echoes back. The read-only verbs
    (help, pending, probe, cost) answer directly; approve/decline run the SAME guardrailed core the
    CLI uses. probe is read-only -- it scans + reports, so chat stays a trigger, never a bypass."""
    if command.verb == HELP:
        return render_help()
    if command.verb == PENDING:
        return _render_pending(state_path)
    if command.verb == PROBE:
        return _run_probe(command.argument, state_path, command.bypass)
    if command.verb == COST:
        return _render_cost(state_path, command.argument)
    with StateStore(state_path) as store:
        if command.verb == APPROVE:
            message, _result = apply_pending(store, command.argument, command.actor)
            return message
        if command.verb == DECLINE:
            return decline_pending(store, command.argument, command.actor)
    return "Nothing to do."


def dispatch(
    adapter: InboundAdapter, headers: Mapping[str, str], body: str, state_path: str
) -> tuple[int, bytes]:
    """One inbound POST -> (HTTP status, reply body). The order is the security order:
    verify FIRST (a forged request is 401 before anything else looks at it), then answer a
    protocol handshake, then parse + run the operator's command."""
    if not adapter.verify(headers, body):
        return 401, b""
    reply = adapter.handshake(body)
    if reply is not None:
        return 200, reply
    command = adapter.parse(body)
    message = "Nothing to do." if command is None else run_command(command, state_path)
    return 200, adapter.respond(message)


def make_handler(adapter: InboundAdapter, state_path: str) -> type[BaseHTTPRequestHandler]:
    """A BaseHTTPRequestHandler bound to one adapter + state db -- a thin shell over dispatch."""

    class _Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length).decode("utf-8", "replace")
            # self.headers is an email.message.Message; flatten to a plain mapping for the
            # adapter (provider header names arrive with stable casing, e.g. X-Slack-Signature).
            headers = dict(self.headers.items())
            status, reply = dispatch(adapter, headers, body, state_path)
            self.send_response(status)
            if reply:
                self.send_header("Content-Type", adapter.content_type)
            self.end_headers()
            self.wfile.write(reply)

        def log_message(self, *args: object) -> None:  # keep the listener quiet
            pass

    return _Handler


def serve(adapter: InboundAdapter, port: int, state_path: str) -> None:  # pragma: no cover
    """Run the approval listener for ``adapter`` until interrupted (blocking)."""
    HTTPServer(("", port), make_handler(adapter, state_path)).serve_forever()
