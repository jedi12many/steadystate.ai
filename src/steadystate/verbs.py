"""The shared verb/view layer: every steadystate command, as a pure function.

This is the application core the three surfaces all drive -- the CLI (`cli.py`), the chat listener
(`inbound/server.py`), and the MCP server (`inbound/mcp.py`). Each verb takes a state path / data
and returns a string (or, for `probe_report`, a `Report`); none of it touches a socket, a thread,
or a provider adapter. It lived inside `inbound/server.py` and the CLI reached in for ~14 private
helpers -- a transport module owning the domain views, an inverted dependency. Pulled out here so
the verbs are surface-agnostic and `server.py` is just the HTTP shell that calls `run_command`.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .act.approve import apply_pending, decline_pending
from .act.bounds import confirmation_tier
from .act.breakglass import BREAKGLASS_SOURCE, breakglass_allowed
from .act.catalog import ACTIONS as CATALOG_ACTIONS
from .act.catalog import CatalogAction, FindingFields, catalog_action, offered_action
from .act.cleanup import record_cleanups
from .act.decide import decider_auto_enabled
from .act.execute import CATALOG_SOURCE
from .act.learn import ADOPT, promotable_solutions
from .act.learn import learn as derive_lessons
from .act.reflex import reflex_recurrence, reflexes
from .act.solution_remedy import no_safety_net, record_solution_remediations
from .classify import APPLICATION, finding_layer
from .engine import build_report
from .evidence import EvidenceKeys
from .health import IMPAIRED, NOTED, WORKING, finding_disposition, wall_verdict
from .inbound.base import (
    ACTIONS_LIST,
    ADD_CHECK,
    ADD_SOLUTION,
    ANALYZE,
    APPROVE,
    ASK,
    CHECKS,
    COST,
    DECLINE,
    FINDINGS,
    FIX,
    HEALTH,
    HELP,
    HISTORY,
    HOLD,
    LEARN,
    METRICS,
    MUTE,
    PENDING,
    POSTURE,
    PROBE,
    RUN,
    SEND,
    SHOW,
    SMOKE,
    SNOOZE,
    SOLUTIONS,
    SUMMARY,
    SURFACES_LIST,
    TARGETS,
    UNMUTE,
    VOUCH,
    Command,
    render_help,
)
from .metrics import fetch_metrics
from .notify import SURFACES
from .onboarding import Status, capabilities
from .probe.custom import CheckResult, add_check, describe_check, load_checks, run_smoke_checks
from .probe.solutions import (
    add_solution,
    describe_solution,
    load_solutions,
    solutions_for,
    vouch_solution,
)
from .reason.alert import Alert, Layer, Severity
from .reason.analyze import analyze_finding, prior_incidents
from .reason.cost import roll_up, roll_up_by_period, scan_cost_line
from .reason.llm import LLMAnalyst
from .reason.report import Report
from .reconcile_state import _fingerprints, alert_suppressed, finding_evidence, seen_findings
from .serialize import finding_to_dict, report_to_dict
from .state import FINDING_FILTERS, Finding, PendingAction, StateStore, filter_findings
from .sweep import render_sweep, sweep_targets
from .targets import load_targets_from_env

logger = logging.getLogger(__name__)


def _nl_analyst() -> LLMAnalyst | None:
    """The analyst backing the natural-language fallback, or None when no provider is configured
    (then the listener is exactly the typed grammar it has always been). A signed webhook is already
    an authenticated operator, so -- like a headless scan -- there's no interactive egress gate; the
    STEADYSTATE_LLM_ENABLED kill switch applies, and its model calls are persisted to the cost
    ledger so chat spend is counted, not invisible."""
    analyst = LLMAnalyst()
    return analyst if analyst._provider() != "none" else None


def _render_pending(state_path: str) -> str:
    """The chat view of `steadystate pending`: the open remediations and their fingerprints, so
    an operator can discover what's awaiting them (and what to approve) without leaving chat."""
    with StateStore(state_path) as store:
        rows = store.all_pending()
    if not rows:
        return "No remediations awaiting approval."
    lines = [f"{len(rows)} remediation(s) awaiting approval:"]
    # Number the rows so an operator can `approve <n>` instead of copying a 64-char fingerprint.
    lines += [
        f"  {i}. {p.fingerprint}  {p.source}  {p.drift_identity}" for i, p in enumerate(rows, 1)
    ]
    lines.append("Approve with:  approve <n>  (or a fingerprint, or bare if there's just one)")
    return "\n".join(lines)


def _resolve_pending(store: StateStore, token: str) -> tuple[str, str]:
    """Resolve an approve/decline reference to a pending fingerprint. Accepts an ordinal (1-based,
    as `pending` lists), a fingerprint or unique prefix, or -- when ``token`` is empty -- the sole
    pending. Returns (fingerprint, "") or ("", message). This is the heart of "not argument-heavy":
    the common case (one pending) needs no argument at all, and the rest take a short number."""
    rows = store.all_pending()
    if not rows:
        return "", "No remediations awaiting approval."
    if not token:  # bare `approve` -> the only pending, else ask which
        if len(rows) == 1:
            return rows[0].fingerprint, ""
        return "", (
            f"{len(rows)} remediations pending -- say `approve <n>` or `approve <fingerprint>` "
            "(see `pending`)."
        )
    if token.isdigit():  # an ordinal from the numbered `pending` list
        n = int(token)
        if 1 <= n <= len(rows):
            return rows[n - 1].fingerprint, ""
        return "", f"No pending #{n} -- there are {len(rows)} (see `pending`)."
    exact = next((r for r in rows if r.fingerprint == token), None)
    if exact is not None:
        return exact.fingerprint, ""
    prefixed = [r for r in rows if r.fingerprint.startswith(token)]
    if len(prefixed) == 1:
        return prefixed[0].fingerprint, ""
    if not prefixed:
        return "", f"No pending matches '{token}'. Run `pending` to list them."
    return "", f"'{token}' matches {len(prefixed)} pending -- use more of the fingerprint."


def _resolve_mute_target(store: StateStore, token: str) -> tuple[str, str]:
    """Resolve a fingerprint to mute: an exact fp, a unique prefix of a *known* finding, or -- when
    nothing matches -- the token itself, so an operator can still pre-mute a fingerprint the store
    hasn't recorded yet (a `mute-all` correlation key, or known noise). Ambiguous prefix -> ask for
    more. Returns (fingerprint, "") or ("", message)."""
    if store.get(token) is not None:
        return token, ""
    matches = store.find_by_prefix(token)
    if len(matches) == 1:
        return matches[0].fingerprint, ""
    if len(matches) > 1:
        return "", f"'{token}' matches {len(matches)} findings -- use more of the fingerprint."
    return token, ""  # no stored match -> pre-mute the literal token (upsert), as before


def _parse_duration(text: str) -> timedelta | None:
    """Parse a chat snooze duration: ``2d`` / ``3h`` / ``45m`` / ``90s`` / ``1w``, or a bare integer
    read as days (the CLI snooze's unit). None when it isn't a recognized, positive duration, so the
    caller asks for one rather than guessing. Pure."""
    text = text.strip().lower()
    if not text:
        return None
    units = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days", "w": "weeks"}
    if text[-1] in units:
        head = text[:-1]
        if head.isdigit() and int(head) > 0:
            return timedelta(**{units[text[-1]]: int(head)})
        return None
    if (
        text.isdigit() and int(text) > 0
    ):  # bare number -> days, matching `steadystate snooze --days`
        return timedelta(days=int(text))
    return None


def _unmute_finding(store: StateStore, token: str) -> str:
    """`unmute <fp>`: lift a mute or snooze so the finding surfaces again. Resolves a prefix to a
    *known* finding (you only un-silence what the store remembers); reports when it can't."""
    finding, error = _lookup_finding(store, token)
    if finding is None:
        return error
    store.unmute(finding.fingerprint, datetime.now(UTC))
    return f"Unmuted {finding.fingerprint} -- it surfaces again on the next scan."


def _snooze_finding(store: StateStore, token: str, duration_text: str, actor: str) -> str:
    """`snooze <fp> <duration>`: silence a finding until the duration lapses, then it returns.
    Resolves the fingerprint like `mute` (prefix, or pre-snooze an unseen one), and parses the
    duration; an unrecognized duration is reported, never defaulted."""
    duration = _parse_duration(duration_text)
    if duration is None:
        return (
            f"'{duration_text}' isn't a duration -- try `2d`, `3h`, `45m` (units h/m/d/w; bare = "
            "days)."
        )
    fp, error = _resolve_mute_target(store, token)
    if error:
        return error
    now = datetime.now(UTC)
    store.snooze(fp, now + duration, actor, now)
    return f"Snoozed {fp} for {duration_text} -- silent until it lapses, then it returns."


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
        # On a correlated group, lead with the one 'mute-all' key -- mute it to silence the whole
        # group at once (each member still keeps its own fp below, so detail isn't lost).
        if a.correlation_fingerprint:
            lines.append(f"           mute-all {a.correlation_fingerprint}  (silences this group)")
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
    """Drop alerts the operator has silenced -- the group's correlation fp muted, or every member
    muted/snoozed -- the exact rule the stateful reconcile uses (alert_suppressed), but READ-ONLY:
    it reads the suppression state and writes nothing. Returns (kept, suppressed_count)."""
    kept: list[Alert] = []
    suppressed = 0
    now = datetime.now(UTC)
    with StateStore(state_path) as store:
        for alert in alerts:
            if alert_suppressed(alert, store, now):
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


def _json(payload: object) -> str:
    """A chat reply as JSON (for the `json` flag -- an agent-readable response)."""
    return json.dumps(payload, indent=2)


def _json_error(message: str) -> str:
    """An error as JSON, so an agent in `json` mode always gets parseable output -- never a prose
    error it has to special-case."""
    return _json({"error": message})


_STATUS_WORDS = frozenset(FINDING_FILTERS) - {""}  # open / resolved / muted / snoozed / all


def _split_findings_query(query: str) -> tuple[str, str]:
    """Split a chat `findings` query into (status_filter, keyword). The first token is the status
    filter when it's a status word (open/resolved/muted/snoozed/all); everything else is the
    free-text keyword. Lowercased. So `findings web` -> ("", "web"), `findings resolved timeout` ->
    ("resolved", "timeout"), `findings open` -> ("open", "")."""
    parts = query.split()
    status = ""
    if parts and parts[0].lower() in _STATUS_WORDS:
        status, parts = parts[0].lower(), parts[1:]
    return status, " ".join(parts).lower()


def _finding_matches(finding: Finding, keyword: str) -> bool:
    """True if ``keyword`` (already lowercased) is a substring of the finding's searchable text --
    its title, fingerprint, severity, status, and captured evidence values. The chat equivalent of
    grepping the `findings` list, since you can't pipe a chat reply."""
    haystack = " ".join(
        [
            finding.last_title,
            finding.fingerprint,
            finding.last_severity,
            finding.status,
            *finding.details.values(),
        ]
    ).lower()
    return keyword in haystack


def _render_findings(state_path: str, query: str = "", flags: frozenset[str] = frozenset()) -> str:
    """The chat view of `steadystate findings`: every remembered finding, its fingerprint, status
    (open/muted/snoozed/resolved) and last severity -- the keys for mute/approve. ``query`` is an
    optional status word and/or a free-text keyword: a status (`findings resolved`/`open`/`muted`/
    `all`; resolved hidden by default) filters by lifecycle, and a keyword greps the list in chat --
    `findings web` keeps only findings whose title/fingerprint/severity/evidence mention 'web', and
    `findings resolved timeout` does both. `json` returns the filtered list as JSON. Read-only."""
    want_json = "json" in flags
    status, keyword = _split_findings_query(query)
    if not state_path or not Path(state_path).exists():
        return _json([]) if want_json else "No findings recorded yet."
    with StateStore(state_path) as store:
        every = store.all_findings()
    rows = filter_findings(every, status)
    if keyword:
        rows = [f for f in rows if _finding_matches(f, keyword)]
    if want_json:
        return _json([finding_to_dict(f) for f in rows])
    if not rows:
        if keyword:
            scope = f" {status}" if status else ""
            return f"No{scope} findings match '{keyword}'."
        hidden = len(every) - len(rows)
        if hidden:
            return f"No findings to show ({hidden} resolved hidden -- `findings all` to include)."
        return "No findings recorded yet."
    suffix = f" matching '{keyword}'" if keyword else ""
    lines = [f"{len(rows)} finding(s){suffix}:"]
    lines += [f"  {f.fingerprint}  {f.status:<8} {f.last_severity:<6} {f.last_title}" for f in rows]
    return "\n".join(lines)


def _render_show(fingerprint: str, state_path: str, flags: frozenset[str] = frozenset()) -> str:
    """The chat view of `show <fingerprint>`: a finding's captured evidence -- the structured fields
    a probe recorded (namespace, cluster, pod count, the failing pod's last log line, ...) plus when
    it was first and last seen, so an operator can answer "what exactly broke, and was it during the
    window I care about?". Accepts a unique fingerprint prefix (they're long); `json` returns the
    finding as JSON. Read-only.

    Each error keeps its own fingerprint, so on a grouped finding you `show` any one member's
    fingerprint and get that instance's detail -- one example is enough."""
    want_json = "json" in flags
    if not state_path or not Path(state_path).exists():
        msg = "No findings recorded yet -- run a `probe`/`scan` first."
        return _json_error(msg) if want_json else msg
    with StateStore(state_path) as store:
        finding, error = _lookup_finding(store, fingerprint)
        analysis = store.get_analysis(finding.fingerprint) if finding is not None else None
    if finding is None:
        return _json_error(error) if want_json else error
    if want_json:
        return _json(finding_to_dict(finding))
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
        lines.append("  (no evidence captured -- re-run a `probe`/`scan` to capture it)")
    # The wall's runbook: if the operator authored a solution for this problem (by category or a
    # title regex), surface it -- "here's the documented fix, and who vouched for it". Read-only.
    category = (finding.details or {}).get(EvidenceKeys.CATEGORY, "")
    matches = solutions_for(category, finding.last_title, load_solutions())
    if matches:
        lines.append("  -- known solution(s) (authored runbook) --")
        lines += [f"  {describe_solution(s)}" for s in matches]
    if analysis is not None:  # a saved root-cause analysis (`analyze`) rides along
        rca, when = analysis
        lines.append(f"  -- root-cause analysis ({when[:19]}) --")
        lines += [f"  {line}" for line in rca.splitlines()]
    return "\n".join(lines)


def _refetch_logs(finding: Finding) -> str:
    """Best-effort: re-fetch the finding's pod logs FRESH at analyze time (current + previous
    container) so the model investigates the live picture, not just the scan-time snapshot. '' for a
    non-k8s finding, a pod we can't name from the evidence, or any failure -- `analyze` then falls
    back to the captured window. Read-only (`kubectl logs`), aimed at the finding's cluster."""
    from .probe.kubectl import KubectlProbe

    fields = _finding_fields(finding)
    pod = (finding.details or {}).get("pods", "").split(",")[0].strip()  # the probe's pod list
    if not fields.namespace or not pod:
        return ""  # not a k8s workload finding (or no pod named) -> nothing to re-fetch
    probe = KubectlProbe()
    if fields.context:
        probe.use_context(fields.context)
    if fields.kubeconfig:
        probe.use_kubeconfig(fields.kubeconfig)
    return probe.logs_for_analysis(fields.namespace, pod)


def _render_analyze(fingerprint: str, state_path: str) -> str:
    """`analyze <fingerprint>`: the root-cause analysis of a captured finding (a crash / panic). The
    RCA a senior on-call would write -- root cause, the call chain, the smoking gun, the trigger,
    operational facts. steadystate re-fetches the pod's logs LIVE (current + previous container) and
    feeds the model the lead-up; the model investigates, quoting what it cites. Read-only; needs an
    LLM (it *is* the analysis)."""
    if not state_path or not Path(state_path).exists():
        return "No findings yet -- run a `probe`/`scan` first, then `analyze <fingerprint>`."
    with StateStore(state_path) as store:
        finding, error = _lookup_finding(store, fingerprint)
        prior = prior_incidents(store, finding) if finding is not None else ""
    if finding is None:
        return error
    analyst = _nl_analyst()
    if analyst is None:
        return (
            "analyze needs an LLM (ANTHROPIC_API_KEY or a custom endpoint) -- it's a grounded RCA "
            "over the captured evidence, not a guess. `show` gives the raw evidence; see `doctor`."
        )
    live = _refetch_logs(finding)  # fresh current + previous logs, best-effort -> investigate live
    rca = analyze_finding(finding, analyst._complete, live_logs=live, prior=prior)
    if not rca:
        return "the model returned no analysis -- try again, or `show` the captured evidence."
    with StateStore(state_path) as store:  # persist it -- don't lose the RCA, or re-pay the model
        store.save_analysis(finding.fingerprint, rca, datetime.now(UTC))
    saved = f"\n\n(saved -- `show {finding.fingerprint[:12]}` shows it; `--to github` sends it)"
    return f"root-cause analysis -- {finding.last_title}\n{'=' * 60}\n{rca}{saved}"


def _render_ask(question: str, state_path: str) -> str:
    """`ask <question>`: answer from the committed knowledge base (steadystate/kb/*.md) -- the
    Tier-1 half of chat. Retrieval is deterministic (keyword scoring over the docs' sections); the
    model only synthesizes an answer FROM the retrieved sections and cites the file -- with no
    model, the sections themselves are the (honest) answer. Read-only; an LLM egress like analyze,
    and its spend lands in the same cost ledger."""
    from .inbound.translate import persist_llm_calls
    from .reason.knowledge import ask_kb

    analyst = _nl_analyst()
    reply = ask_kb(question, analyst._complete if analyst is not None else None)
    if analyst is not None:
        persist_llm_calls(state_path, analyst.calls)
    return reply


def _send_analysis(fingerprint: str, state_path: str, surface: str) -> str:
    """Send a finding's **saved** RCA to a surface -- the close-the-loop step (`analyze --to github`
    opens/updates a GitHub issue carrying it, so notifying the vendor is one command). The RCA must
    exist first (`analyze` saves it). Only `github` carries an RCA today."""
    if surface != "github":
        return f"--to {surface}: only `github` carries an RCA today."
    if not state_path or not Path(state_path).exists():
        return "no findings yet -- `analyze <fingerprint>` first."
    with StateStore(state_path) as store:
        finding, error = _lookup_finding(store, fingerprint)
        analysis = store.get_analysis(finding.fingerprint) if finding is not None else None
    if finding is None:
        return error
    if analysis is None:
        return "no saved analysis for that finding -- run `analyze <fingerprint>` first."
    from .notify.github import GithubIssuesSurface

    return GithubIssuesSurface().post_rca(finding.fingerprint, finding.last_title, analysis[0])


def _lookup_finding(store: StateStore, token: str) -> tuple[Finding | None, str]:
    """Resolve a fingerprint token to a stored Finding -- exact, else a *unique* prefix (they're
    long, so a copy-pasted short form should work). Returns (finding, "") or (None, message)."""
    finding = store.get(token)
    if finding is not None:
        return finding, ""
    matches = store.find_by_prefix(token)
    if len(matches) > 1:
        return None, f"'{token}' matches {len(matches)} findings -- use more of the fp."
    if not matches:
        return None, f"Unknown fingerprint '{token}'. Run `findings` to list them."
    return matches[0], ""


def _surface_status(name: str) -> tuple[Status, str]:
    """How ready an alert surface is to send, from the onboarding catalog (env-var readiness). A
    surface with no capability entry (``console``) is always ready."""
    cap = {c.key: c for c in capabilities()}.get(name)
    return cap.assess(os.environ) if cap is not None else (Status.READY, "")


def _render_surfaces() -> str:
    """The chat view of `surfaces`: the alert surfaces you can `send <fp>` to, and whether each is
    configured (so you know what'll actually deliver). Read-only."""
    lines = ["alert surfaces (use `send <fp> <surface>`):"]
    marks = {Status.READY: "configured", Status.PARTIAL: "partial", Status.OFF: "not configured"}
    for name in sorted(SURFACES):
        status, detail = _surface_status(name)
        note = f" -- {detail}" if detail and status is not Status.READY else ""
        lines.append(f"  {name:<12} {marks[status]}{note}")
    return "\n".join(lines)


def _alert_from_finding(finding: Finding) -> Alert:
    """Reconstruct a summary Alert from a stored Finding, so a `send` can escalate a remembered
    finding to a surface without a fresh scan. The store keeps the title, severity, captured
    evidence and timestamps -- enough for a notification/incident -- but not the original
    drift/symptom objects, so this is a summary (no before/after). The finding's fingerprint rides
    as the Alert's ``correlation_fingerprint`` so a surface that dedups (ServiceNow's
    correlation_id) ties it to the same incident a scheduled scan would open."""
    severity = Severity(finding.last_severity) if finding.last_severity else Severity.MEDIUM
    detail = "; ".join(f"{k}: {v}" for k, v in finding.details.items())
    why = detail or f"Escalated from steadystate findings (first seen {finding.first_seen})."
    return Alert(
        title=finding.last_title,
        severity=severity,
        drifts=[],
        why_it_matters=why,
        layer=Layer.ALERT,
        correlation_fingerprint=finding.fingerprint,
    )


def _send_finding(fingerprint: str, surface_name: str, state_path: str) -> str:
    """`send <fp> <surface>`: dispatch one remembered finding to an alert surface now -- an ad-hoc
    escalation ("file this in ServiceNow"), not a full scan. Resolves the fingerprint against the
    store, checks the surface is configured (so we don't silently send nothing), reconstructs a
    summary Alert, and emits it. A trigger, not a bypass -- it forwards a finding, never acts."""
    if surface_name not in SURFACES:
        return f"Unknown surface '{surface_name}'. Known: {', '.join(sorted(SURFACES))}."
    status, detail = _surface_status(surface_name)
    if status is not Status.READY:
        gap = f" ({detail})" if detail else ""
        return f"Surface '{surface_name}' isn't configured{gap}; nothing sent. See `surfaces`."
    if not state_path or not Path(state_path).exists():
        return "No findings recorded yet -- run a `probe`/`scan` first."
    with StateStore(state_path) as store:
        finding, error = _lookup_finding(store, fingerprint)
    if finding is None:
        return error
    try:
        SURFACES[surface_name]().emit(Report(items=[_alert_from_finding(finding)]))
    except Exception as exc:  # a surface must never crash the listener
        return f"Send to '{surface_name}' failed: {exc}"
    short = finding.fingerprint[:12]
    return f"Sent {short} ({finding.last_title}) to {surface_name}."


def _render_actions() -> str:
    """The chat view of `actions`: the vetted actions you can `fix`/`run`, each with its blast
    radius (the envelope). Read-only -- so you know what's on the menu before issuing one."""
    lines = ["vetted actions (use `fix <fp>` for the offered one, or `run <action> <fp>`):"]
    for action in CATALOG_ACTIONS.values():
        first_line = action.description.split(" -- ")[0]
        lines.append(f"  {action.name:<24} [{action.envelope.label}]  {first_line}")
    return "\n".join(lines)


def _finding_fields(finding: Finding) -> FindingFields:
    """The keys for composing a command, pulled from a stored finding's evidence -- plus the
    kubeconfig resolved from the matching target (the finding stores its cluster *context*, the
    target carries that context's kubeconfig). Empty for anything the finding doesn't carry."""
    details = finding.details
    context = details.get(EvidenceKeys.CLUSTER, "")
    kubeconfig = ""
    if context:
        target = next((t for t in load_targets_from_env().values() if t.context == context), None)
        kubeconfig = target.kubeconfig if target is not None else ""
    return FindingFields(
        kind=details.get(EvidenceKeys.KIND, ""),
        # a workload finding stores `workload`; a node finding stores `node` (the node name).
        name=details.get(EvidenceKeys.WORKLOAD) or details.get(EvidenceKeys.NODE, ""),
        namespace=details.get(EvidenceKeys.NAMESPACE, ""),
        context=context,
        kubeconfig=kubeconfig,
    )


def _apply_catalog_action(
    store: StateStore, finding: Finding, action: CatalogAction, actor: str
) -> str:
    """Compose ``action``'s command from the finding's keys, gate it (allow-pattern + bound), and
    run it through the SAME approve guardrail (claim-once + audit) -- the core of `fix`/`run`.
    Honest at each gate: a finding it can't compose for, or an action out of bound, is reported,
    never forced."""
    if action.compose is None:
        return f"'{action.name}' has no composer -- can't issue it for a finding."
    fields = _finding_fields(finding)
    command = action.compose(fields)
    if command is None:
        return f"can't compose '{action.name}' for this finding (missing namespace/kind/name)."
    if not action.validate(command):  # belt-and-suspenders -- the composed shape must still pass
        return f"composed command for '{action.name}' didn't pass its allow-pattern; not run."
    tier = confirmation_tier(action.envelope)
    if tier > 0:  # out of the autonomous bound -> break-glass: record + challenge, don't run now
        return _breakglass_challenge(store, finding, action, command, fields, actor, tier)
    # within the bound: record the command as a pending catalog action, then run it through the
    # approve guardrail (claim-once, re-validate, run as argv, audit under the chat actor).
    store.record_pending(
        PendingAction(
            fingerprint=finding.fingerprint,
            source=CATALOG_SOURCE,
            path="",
            drift_identity=finding.last_title,
            command=command,
        ),
        datetime.now(UTC),
    )
    message, _result = apply_pending(store, finding.fingerprint, actor)
    return f"{action.name}: {message}\n  $ {command}"


def _breakglass_challenge(
    store: StateStore,
    finding: Finding,
    action: CatalogAction,
    command: str,
    fields: FindingFields,
    actor: str,
    tier: int,
) -> str:
    """Out-of-bound action: record it as a pending break-glass command and return the confirmation
    challenge (the command, its blast radius, and how to confirm). It does NOT run -- only an
    authorized `approve` does. Default-closed: refused unless the operator is allowlisted."""
    if not breakglass_allowed(actor):
        return (
            f"'{action.name}' ({action.envelope.label}) is BREAK-GLASS (outside the bound), and "
            f"you ({actor}) aren't authorized. Set STEADYSTATE_BREAKGLASS_USERS to enable it."
        )
    # The strong tier's confirm token is the target's name (the node/workload) -- stored as the
    # pending's drift_identity so `approve <fp> <name>` can check it.
    target = fields.name or finding.last_title
    store.record_pending(
        PendingAction(
            fingerprint=finding.fingerprint,
            source=BREAKGLASS_SOURCE,
            path="",
            drift_identity=target,
            command=command,
        ),
        datetime.now(UTC),
    )
    fp = finding.fingerprint
    confirm = f"approve {fp} {target}" if tier >= 2 else f"approve {fp}"
    return (
        f"⚠ BREAK-GLASS — {action.envelope.label}\n"
        f"  $ {command}\n"
        f"  outside the autonomous bound. to run, confirm:\n    {confirm}"
        + (f"  (type the target name '{target}')" if tier >= 2 else "")
    )


def _fix_finding(fingerprint: str, state_path: str, actor: str) -> str:
    """`fix <fp>`: apply the OFFERED vetted action for a finding (the one mapped to its category --
    e.g. roll-restart a wedged workload). 'No automated fix' when nothing in the catalog recovers
    that category, rather than guessing."""
    if not state_path or not Path(state_path).exists():
        return "No findings recorded yet -- run a `probe`/`scan` first."
    with StateStore(state_path) as store:
        finding, error = _lookup_finding(store, fingerprint)
        if finding is None:
            return error
        category = finding.details.get(EvidenceKeys.CATEGORY, "")
        action = offered_action(category)
        if action is None:
            return (
                f"No automated fix offered for '{category or finding.last_title}' -- escalate "
                "(or `run <action> <fp>` if you know one applies)."
            )
        return _apply_catalog_action(store, finding, action, actor)


def _run_action(action_name: str, fingerprint: str, state_path: str, actor: str) -> str:
    """`run <action> <fp>`: run a SPECIFIC vetted action against a finding (you pick the action, the
    finding supplies the parameters). Refuses an action not in the catalog."""
    action = catalog_action(action_name)
    if action is None:
        return f"Unknown action '{action_name}'. See `actions` for the vetted ones."
    if not state_path or not Path(state_path).exists():
        return "No findings recorded yet -- run a `probe`/`scan` first."
    with StateStore(state_path) as store:
        finding, error = _lookup_finding(store, fingerprint)
        if finding is None:
            return error
        return _apply_catalog_action(store, finding, action, actor)


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


def _render_hold(state_path: str) -> str:
    """The chat view of the homeostat's posture: each reflex's earned autonomy (observe/propose/
    auto) and blast-radius envelope, which of its fixes are NOT holding (recurrence -- the
    self-correction signal), and whether the decider has been granted autonomy. A cheap read from
    the store -- no fresh scan (that's `probe`); it answers 'what is steadystate maintaining on its
    own, and is anything not holding?'. Read-only."""
    active = reflexes()
    recurrence: dict[str, int] = {}
    if state_path and Path(state_path).exists():
        with StateStore(state_path) as store:
            recurrence = reflex_recurrence(store.all_findings(), store.acted_fingerprints(), active)
    lines = ["homeostat posture (reflexes):"]
    for r in active:
        churn = recurrence.get(r.name, 0)
        note = f"  -- {churn} fix(es) recurring (not holding)" if churn else ""
        lines.append(f"  {r.name:<18} {r.autonomy:<8} [{r.envelope.label}]  {r.category}{note}")
    grant = "ON" if decider_auto_enabled() else "off"
    lines.append(f"  decider autonomy: {grant}  (grant via STEADYSTATE_DECIDER_AUTO)")
    return "\n".join(lines)


_SEVERITY_RANK = {"critical": 3, "high": 2, "medium": 1, "low": 0}


def _freshness(findings: list[Finding]) -> str:
    """'12m ago' / '3h ago' / '2d ago' from the most recent finding timestamp -- how stale the
    stored state is (when the last scan/probe touched it). '' when there's nothing recorded. So a
    glance (and an MCP-connected agent) knows whether to trust the snapshot or refresh it."""
    stamps = [f.last_seen for f in findings if f.last_seen]
    if not stamps:
        return ""
    try:
        latest = datetime.fromisoformat(max(stamps))
    except ValueError:
        return ""
    if latest.tzinfo is None:
        latest = latest.replace(tzinfo=UTC)
    secs = max(0, int((datetime.now(UTC) - latest).total_seconds()))
    if secs < 90:
        return "just now"
    if secs < 5400:
        return f"{secs // 60}m ago"
    if secs < 172800:
        return f"{secs // 3600}h ago"
    return f"{secs // 86400}d ago"


def _render_summary(state_path: str) -> str:
    """A glanceable, deterministic rollup of the current state -- open findings by severity, what's
    pending your approval, the homeostat's posture, the single worst thing right now, and how fresh
    the data is. The 'morning glance': what to look at first, without piecing it together from
    `findings` / `pending` / `hold`. Reads stored state (the last probe/sweep) -- no fresh scan."""
    findings: list[Finding] = []
    pendings: list = []
    as_of = ""
    promotable = 0
    if state_path and Path(state_path).exists():
        with StateStore(state_path) as store:
            every = store.all_findings()
            findings = filter_findings(every, "")  # the open view (hides resolved)
            pendings = store.all_pending()
            as_of = _freshness(every)
            # Learning: responses you keep applying by hand that have earned an autonomy review.
            lessons = derive_lessons(every, store.acted_fingerprints())
            promotable = sum(1 for le in lessons if le.ready_to_promote)
    # Split YOUR apps from the platform plumbing (coredns / cattle-* / svclb / ...), so the glance
    # leads with what you own. The count, breakdown, and worst are over APP findings; platform is an
    # aside (never hidden -- a coredns crashloop is real, just not your app's problem).
    app: list[Finding] = []
    platform: list[Finding] = []
    for f in findings:
        (app if finding_layer(f.details, f.last_title) == APPLICATION else platform).append(f)
    # Function first: among YOUR apps, separate a live malfunction (IMPAIRED -- worth attention)
    # from mere config drift / posture (NOTED -- diverged but working). The glance leads with what's
    # actually failing, so neither you nor an agent chases a red herring. Platform stays an aside.
    impaired = [f for f in app if finding_disposition(f.details) == IMPAIRED]
    noted = [f for f in app if finding_disposition(f.details) == NOTED]
    # A high-severity NOTED finding (a drift exposure -- an opened firewall, a public bucket) is
    # still not a *malfunction*, so it never drives the verdict or counts as impaired. But it must
    # not be flattened into the count either: serious risk earns a REVIEW flag, not silence.
    review = [f for f in noted if _SEVERITY_RANK.get(f.last_severity, 0) >= _SEVERITY_RANK["high"]]
    counts: dict[str, int] = {}
    for f in impaired:
        counts[f.last_severity] = counts.get(f.last_severity, 0) + 1
    breakdown = ", ".join(
        f"{counts[s]} {s}" for s in sorted(counts, key=lambda s: -_SEVERITY_RANK.get(s, 0))
    )
    parts: list[str] = []
    if impaired:
        parts.append(f"{len(impaired)} impaired" + (f" ({breakdown})" if breakdown else ""))
    else:
        parts.append("working -- nothing impaired")
    if pendings:
        parts.append(f"{len(pendings)} pending your approval")
    if noted:
        flag = f"; {len(review)} to review" if review else ""
        parts.append(f"{len(noted)} noted (drift/posture{flag})")
    if platform:
        parts.append(f"{len(platform)} platform")
    if not impaired and not pendings and not noted and not platform:
        parts = ["all clear -- 0 open findings, nothing pending"]
    head = "  |  ".join(parts)
    if as_of:
        head += f"  (as of {as_of})"
    lines = [head]
    # Homeostat line: reflexes (how many auto), whether any fix isn't holding, the decider grant.
    active = reflexes()
    if active:
        auto = sum(1 for r in active if r.autonomy == "auto")
        churn = 0
        if findings and state_path and Path(state_path).exists():
            with StateStore(state_path) as store:
                churn = sum(
                    reflex_recurrence(
                        store.all_findings(), store.acted_fingerprints(), active
                    ).values()
                )
        not_holding = f", {churn} not holding" if churn else ""
        grant = "auto" if decider_auto_enabled() else "manual"
        lines.append(
            f"homeostat: {len(active)} reflex(es), {auto} auto{not_holding} | decider: {grant}"
        )
    # Worst line: the highest-severity IMPAIRED finding (a live failure), oldest-first on a tie --
    # what to look at first. We never surface a NOTED drift as "worst" -- that'd be a red herring.
    if impaired:
        worst = min(impaired, key=lambda f: (-_SEVERITY_RANK.get(f.last_severity, 0), f.first_seen))
        lines.append(f"worst: {worst.last_title}  [{worst.last_severity}]")
    # Review line: a serious NOTED finding (a high/critical drift -- a security exposure) is named,
    # not buried in the count. A flag to look, never a 'worst'/'impaired' -- function-first holds
    # (it doesn't make the wall not-working), but a real exposure is never silent.
    if review:
        top = min(review, key=lambda f: (-_SEVERITY_RANK.get(f.last_severity, 0), f.first_seen))
        lines.append(f"review: {top.last_title}  [{top.last_severity}]")
    # Learning line: a response you keep applying by hand has earned an autonomy review (`learn`).
    if promotable:
        s = "s" if promotable != 1 else ""
        lines.append(f"learning: {promotable} response{s} earned a promotion review (`learn`)")
    return "\n".join(lines)


def _render_learn(state_path: str) -> str:
    """The chat view of `steadystate learn`: what steadystate has learned from findings that
    resolved on their own (out-of-band -- a human fixed it, or it self-healed). Surfaces the
    categories to ADOPT a reflex for, or that SELF-HEAL (mute candidates). Read-only and a
    suggestion -- it promotes/mutes nothing; the strength is how often it would've been right."""
    if not state_path or not Path(state_path).exists():
        return "Nothing learned yet -- steadystate learns from findings that resolve on their own."
    with StateStore(state_path) as store:
        findings = store.all_findings()
        acted = store.acted_fingerprints()
    lessons = derive_lessons(findings, acted)
    # The on-ramp to the runbook: a category you keep fixing by hand with ONE consistent command is
    # ready to capture as an authored solution (so next time it's offered + one-approve). Skip ones
    # already in the runbook; surface the exact `add-solution`. Learning proposes; authoring gates.
    have = frozenset(s.for_category for s in load_solutions() if s.for_category)
    drafts = promotable_solutions(findings, acted, skip_categories=have)
    if not lessons and not drafts:
        return "Nothing learned yet -- run scans/probes over time so resolutions accumulate."
    lines: list[str] = []
    if lessons:
        backing = sum(lesson.occurrences for lesson in lessons)
        lines.append(f"learned from {backing} out-of-band fix(es) -- {len(lessons)} lesson(s):")
        for lesson in lessons:
            tag = "ADOPT" if lesson.kind == ADOPT else "SELF-HEAL"
            lines.append(f"  [{tag}] {lesson.category} x{lesson.occurrences} {lesson.scope}")
            lines.append(f"      {lesson.recommendation}")
    if drafts:
        lines.append("")
        lines.append("ready to capture as runbook solutions (a fix you keep applying by hand):")
        for draft in drafts:
            run = draft["solution"]["run"]
            lines.append(f"  {draft['for']}: you keep running `{run}`")
            lines.append(f"      capture: add-solution '{json.dumps(draft)}' --author you")
    return "\n".join(lines)


def _render_checks(checks_path: str = "") -> str:
    """The chat/CLI/MCP view of the custom health checks (STEADYSTATE_CHECKS / the default)."""
    checks = load_checks(checks_path)
    if not checks:
        return "no custom checks here -- add one with `add-check` (or `define-check`)."
    return f"{len(checks)} custom check(s):\n" + "\n".join(f"  {describe_check(c)}" for c in checks)


def _render_solutions(solutions_path: str = "") -> str:
    """The chat/CLI/MCP view of the wall's authored runbook (STEADYSTATE_SOLUTIONS / the default) --
    the documented problem->fix entries that surface against a matching finding. Read-only."""
    sols = load_solutions(solutions_path)
    if not sols:
        return (
            "no solutions authored here -- document a fix in .steadystate/solutions.json "
            "(problem -> command/playbook/reboot, signed by an author). It surfaces on a match."
        )
    body = "\n".join(f"  {describe_solution(s)}" for s in sols)
    out = f"{len(sols)} solution(s) -- the wall's runbook:\n{body}"
    if any(s.proposed for s in sols):
        out += "\n  (DRAFT = authored live, not yet runnable -- `vouch <name>` to offer it.)"
    return out


def _render_smoke(checks_path: str = "") -> str:
    """Run the wall's `http` smoke tests live and report PASS/FAIL each -- the affirmative
    'is it actually working?' view. Active (GET/HEAD), read-only. No http results -> a DIAGNOSING
    note (smoke runs only `http` checks; a loaded non-http check would otherwise look invisible)."""
    return _format_smoke(run_smoke_checks(checks_path), checks_path)


def _format_smoke(results: list[CheckResult], checks_path: str = "") -> str:
    """Render smoke results as PASS/FAIL lines -- split from the run so a caller (the CLI) can
    render AND gate the exit code from ONE run, instead of executing every http endpoint twice."""
    if not results:
        return _smoke_empty_reason(checks_path)
    passed = sum(1 for r in results if r.passed)
    failed = len(results) - passed
    head = f"{len(results)} smoke test(s): {passed} pass" + (f", {failed} FAIL" if failed else "")
    lines = [head]
    for r in sorted(results, key=lambda r: r.passed):  # failures first
        mark = "PASS" if r.passed else "FAIL"
        line = f"  [{mark}] {r.name}  {r.target}"
        if not r.passed and r.detail:
            line += f" -- {r.detail}"
        lines.append(line)
    return "\n".join(lines)


def _smoke_empty_reason(checks_path: str = "") -> str:
    """Why `smoke` found nothing to run -- because it runs ONLY `http` checks, so a checks.json full
    of `kubectl-log`/`ansible-service`/... loads fine yet `smoke` shows nothing, which reads as
    'steadystate can't see my file'. This names the resolved path + what it DID load: no checks at
    all vs N loaded but none `http` (those run during `probe`/`scan`, not `smoke`)."""
    from .probe.custom import load_checks, resolve_checks_path

    path = resolve_checks_path(checks_path)
    loaded = load_checks(checks_path)
    if not loaded:
        return (
            f"no checks loaded from {path} -- author one (`define-check` / `add-check`), or run "
            "`doctor` to see if a wrong path / bad JSON is hiding it."
        )
    kinds = ", ".join(sorted({c.kind for c in loaded}))
    return (
        f"no `http` smoke tests to run -- but {len(loaded)} check(s) ARE loaded from {path} "
        f"(kinds: {kinds}). `smoke` runs ONLY `http` checks; the others run during `probe`/`scan`. "
        "Add an `http` check to actively smoke-test a service."
    )


def _names_workload(finding: Finding, workload: str) -> bool:
    """Whether a finding belongs to ``workload`` -- by its structured ``workload`` field (a Symptom
    carries it) or, failing that, by the name appearing in its title. A forgiving substring match,
    so `health gateway` catches `payments-gateway`."""
    w = workload.lower()
    wl = (finding.details or {}).get("workload", "").lower()
    if wl:
        return w in wl
    return w in (finding.last_title or "").lower()


def _render_metrics() -> str:
    """The agent's metric context: the live readings from your monitoring (Prometheus / ...) for the
    queries you configured. steadystate *consumes* monitoring, it doesn't reimplement it. Read-only;
    an unavailable reading is shown as such (never a guessed number)."""
    from .metrics import fetch_metrics, load_metric_queries

    if not load_metric_queries():
        return (
            "no metrics configured -- set STEADYSTATE_METRIC_QUERIES (a JSON {name: query} file) + "
            "a source (e.g. PROMETHEUS_URL). steadystate rents monitoring, doesn't replace it."
        )
    readings = fetch_metrics()
    lines = ["metrics (from your monitoring):"]
    for m in readings:
        if m.available:
            extra = f"  ({m.note})" if m.note else ""
            lines.append(f"  {m.name}: {m.value:g}{extra}")
        else:
            lines.append(f"  {m.name}: unavailable -- {m.note}")
    return "\n".join(lines)


def _render_posture() -> str:
    """The honest answer to 'are you bounding me?' -- so a worried operator (or an agent they asked)
    gets the real boundary, never an overclaim. States what steadystate enforces on its OWN path,
    where that ends (it can't see your other tools), and the sole-actuator setup that makes it a
    real fence. Deliberately candid: the point is to be trusted, which means not pretending."""
    grant = (
        "auto -- acts within the bound without asking"
        if decider_auto_enabled()
        else "manual -- a human approves each effectful action"
    )
    net_line = (
        "  - !! SAFETY NET OFF (STEADYSTATE_NO_SAFETY_NET): a DRAFT is offerable and an open "
        "command is auto-eligible -- YOU own the risk; permitted actions audited [no-safety-net]."
        if no_safety_net()
        else "  - solution safety net ON: a DRAFT fix isn't runnable until a human vouches it."
    )
    return "\n".join(
        [
            "steadystate -- what I bound, and what I don't (the honest answer):",
            "",
            "THROUGH steadystate (this CLI / chat / MCP), every change runs the gate:",
            "  - a vetted action CATALOG -- you can only name a fixed menu item, never invent;",
            "  - an impact x reversibility BOUND -- out-of-envelope actions are refused/escalated;",
            "  - APPROVAL + an immutable AUDIT -- nothing effectful runs unseen;",
            "  - grant tiers: read-only (observe) -> --author (checks) -> --write (remediate);",
            f"  - decider right now: {grant}.",
            net_line,
            "  On this path, I am a real boundary.",
            "",
            "But I am NOT a sandbox around you:",
            "  - I govern only what flows THROUGH me; I can't see or constrain your OTHER tools.",
            "  - If you also have a shell + cluster credentials, you can run kubectl directly or",
            "    hit any API -- none of which passes my gate, because none of it goes through me.",
            "  - Guardrails on a road, not a fence around the car. The real hard limit on a",
            "    shell-enabled agent is the credentials it was given (RBAC / IAM), not me.",
            "",
            "To make me your REAL boundary (the sole-actuator setup):",
            "  1. Give the agent ONLY the steadystate MCP -- no shell, no filesystem, no kubectl.",
            "  2. Let steadystate hold the kubeconfig (`steadystate --silo <name> mcp`); you never",
            "     see it.",
            "  3. Grant: default read-only; add --author to write checks; --write to remediate.",
            "  4. Scope steadystate's own credentials with least-privilege RBAC / IAM.",
            "  Then your whole authority is my vetted, bounded, audited catalog -- no off-road.",
            "",
            "Full control model: LLM_SAFETY.md.",
        ]
    )


def health_report(state_path: str, checks_path: str = "", workload: str = "") -> tuple[str, str]:
    """The one-call "is it working?" view AND its verdict (WORKING | DEGRADED | DOWN), from a single
    computation -- so a caller (the CLI) gates on the verdict as data, not by string-matching the
    rendered text. Leads with the active signal: run the `http` smoke tests (proof), fold in live
    malfunctions (impaired). With ``workload`` it scopes to one workload and **correlates** -- the
    smoke result, the live symptoms, AND a config drift on that same workload (a likely cause).
    Read-only; no grant."""
    smoke = run_smoke_checks(checks_path, match=workload)
    smoke_fail = [r for r in smoke if not r.passed]
    impaired: list[Finding] = []
    drifted: list[Finding] = []
    review: list[Finding] = []
    if state_path and Path(state_path).exists():
        with StateStore(state_path) as store:
            findings = filter_findings(store.all_findings(), "")  # open view
        app = [f for f in findings if finding_layer(f.details, f.last_title) == APPLICATION]
        if workload:
            app = [f for f in app if _names_workload(f, workload)]
        impaired = [f for f in app if finding_disposition(f.details) == IMPAIRED]
        drifted = [f for f in app if "change" in (f.details or {})]  # config diverged here
        # a high/critical NOTED finding (a security drift) -- flag for review, never the verdict
        review = [
            f
            for f in app
            if finding_disposition(f.details) == NOTED
            and _SEVERITY_RANK.get(f.last_severity, 0) >= _SEVERITY_RANK["high"]
        ]
    verdict = wall_verdict(len(impaired), len(smoke_fail))
    smoke_part = f"smoke {len(smoke) - len(smoke_fail)}/{len(smoke)} pass" if smoke else "no smoke"
    scope = f"{workload}  --  " if workload else ""
    head = f"{verdict}  --  {scope}{smoke_part}  |  {len(impaired)} impaired"
    lines = [head]
    for r in smoke_fail:  # name what's actively failing
        why = f" -- {r.detail}" if r.detail else ""
        lines.append(f"  [smoke FAIL] {r.name}  {r.target}{why}")
    if impaired:
        worst = min(impaired, key=lambda f: (-_SEVERITY_RANK.get(f.last_severity, 0), f.first_seen))
        lines.append(f"  worst impaired: {worst.last_title}  [{worst.last_severity}]")
    # Correlation -- the fresh edge: if something's wrong AND a config drift sits on the same
    # workload, surface it as a likely cause (steadystate knows declared-vs-observed; monitoring
    # doesn't). A NOTED drift on a working app stays out of it (don't chase red herrings).
    if (smoke_fail or impaired) and drifted:
        lines.append(f"  likely cause: {drifted[0].last_title}  (config drift on this workload)")
    # Review -- a serious drift (high/critical) named even when the wall is WORKING. It doesn't move
    # the verdict (a drift isn't a malfunction), but a security exposure is never left silent.
    if review:
        top = min(review, key=lambda f: (-_SEVERITY_RANK.get(f.last_severity, 0), f.first_seen))
        lines.append(f"  review: {top.last_title}  [{top.last_severity}]  (drift, not impaired)")
    # Enrichment -- the live metrics from your monitoring, as CONTEXT (not part of the verdict: a
    # high latency is for the agent to weigh, not an automatic DOWN). steadystate rents monitoring.
    shown = [m for m in fetch_metrics(workload=workload) if m.available]
    if shown:
        lines.append("  metrics: " + "  |  ".join(f"{m.name} {m.value:g}" for m in shown))
    if verdict == WORKING and not smoke:
        lines.append("  (no smoke test here -- add an `http` check to actively verify)")
    return "\n".join(lines), verdict


def _render_health(state_path: str, checks_path: str = "", workload: str = "") -> str:
    """The health view as text (chat/MCP); the CLI uses ``health_report`` for the verdict."""
    return health_report(state_path, checks_path, workload)[0]


def _add_check(payload: str, checks_path: str = "") -> str:
    """Validate a check (a JSON object, or a JSON string) against the vetted schema and store it.
    The schema is the gate -- only a valid, observe-only check is written. Used by the `add-check`
    verb an agent calls after filling the schema from a conversation."""
    if not payload.strip():
        return "add-check needs a check (a JSON object). See `checks` / the schema."
    try:
        raw = json.loads(payload)
    except ValueError:
        return "couldn't parse the check -- it must be a JSON object matching the schema."
    if not isinstance(raw, dict):
        return "a check must be a single JSON object."
    _check, message = add_check(raw, checks_path)
    return message


def _add_solution(
    payload: str, author: str = "", solutions_path: str = "", *, proposed: bool = True
) -> str:
    """Validate a solution (a JSON object/string) and store it in the wall's runbook, stamping the
    ``author`` (an unsigned fix is rejected). Used by the `add-solution` verb an agent calls after
    filling the schema. ``proposed`` defaults True: a live/agent-authored fix lands as a DRAFT
    (surfaced, not runnable) until a human ``vouch``es it -- the CLI authoring path passes False."""
    if not payload.strip():
        return "add-solution needs a solution (a JSON object). See `solutions` / the schema."
    try:
        raw = json.loads(payload)
    except ValueError:
        return "couldn't parse the solution -- it must be a JSON object matching the schema."
    if not isinstance(raw, dict):
        return "a solution must be a single JSON object."
    _sol, message = add_solution(
        raw, author=author or "agent", path=solutions_path, proposed=proposed
    )
    return message


def _vouch(name: str, actor: str = "", solutions_path: str = "") -> str:
    """Promote a drafted solution to vouched (the human gate). Effectful runbook write -- exposed at
    the write grant, so an `--author` agent can't vouch its own draft."""
    if not name.strip():
        return "vouch needs a solution name. See `solutions` for the drafts."
    _ok, message = vouch_solution(name.strip(), actor=actor, path=solutions_path)
    return message


def _record_probe_findings(report: Report, state_path: str) -> None:
    """Persist a summoned probe's findings to the store (new/recurring memory, and the db file
    itself) so they show in `findings` and can be muted. **Record-only**: no `resolve_absent` -- a
    single probe isn't a full-fleet view, so it must never mark another target's findings resolved
    (that's `sweep`'s job, over the union). Best-effort: a wedged store never sinks the probe."""
    with contextlib.suppress(Exception):
        Path(state_path).parent.mkdir(parents=True, exist_ok=True)
        now = datetime.now(UTC)
        with StateStore(state_path) as store:
            store.record(seen_findings(report), now, finding_evidence(report))
            # Offer an approvable cleanup for any evicted pods -- so `pending` lists it and
            # `approve <fp>` runs the kubectl delete. Never auto-runs; approve is the gate.
            record_cleanups(store, report, now)
            # Same gate for the wall's authored runbook: a malfunction matching a solution with a
            # runnable command is offered as a pending remediation (approve runs it, audited).
            record_solution_remediations(store, report, now)


def probe_report(target_name: str, state_path: str, *, scan_logs: bool = False) -> Report:
    """Build (and record) the health report for one named target -- the report behind BOTH the chat
    `probe` summary and CLI `probe --json`. Resolves the name against the targets registry, runs the
    same engine a scheduled scan runs, and records the findings (record-only -- never resolves
    another target's). Raises ``LookupError`` (with a human-readable message) for an unresolvable
    target; lets a real probe failure (unreachable backend, ...) propagate."""
    targets = load_targets_from_env()
    if not targets:
        raise LookupError(
            "No targets configured -- run `discover --create` or set STEADYSTATE_TARGETS."
        )
    target = targets.get(target_name)
    if target is None:
        raise LookupError(f"Unknown target '{target_name}'. Known: {', '.join(sorted(targets))}.")
    # A live target (k8s-live) has no path -- Path("") is "." which its source ignores; the
    # context aims the source + probe at that one cluster.
    report = build_report(
        target.source,
        Path(target.path),
        probe="auto",
        label=target.label,
        context=target.context,
        kubeconfig=target.kubeconfig,  # a cwd kubeconfig the context lives in (else "")
        inventory=target.inventory,  # an ansible-live target's inventory (else "")
        scan_logs=scan_logs,  # `--deep` -> also scan pod logs for errors
    )
    if state_path:  # persist the findings (record-only) -- this also creates the db
        _record_probe_findings(report, state_path)
    return report


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
    want_json = "json" in flags
    try:
        report = probe_report(target_name, state_path, scan_logs="deep" in flags)
    except LookupError as exc:  # unresolvable target -> the human-readable reason it carries
        return _json_error(str(exc)) if want_json else str(exc)
    except Exception as exc:  # a summon must report the failure, never crash the listener
        msg = f"Probe of '{target_name}' failed: {exc}"
        return _json_error(msg) if want_json else msg
    if want_json:  # the agent-readable report -- the SAME shape as `scan --json`
        return _json(report_to_dict(report, spend=None))
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
        msg = "No targets configured -- run `discover --create` or set STEADYSTATE_TARGETS."
        return _json_error(msg) if "json" in flags else msg
    result = sweep_targets(
        targets, state_path, datetime.now(UTC), stateless=not state_path, scan_logs="deep" in flags
    )
    if "json" in flags:  # `probe all json` -> the fleet's (deduped) findings as the report shape
        return _json(report_to_dict(result.report))
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
    if command.verb == SUMMARY:
        return _render_summary(state_path)
    if command.verb == ASK:
        return _render_ask(command.argument, state_path)
    if command.verb == TARGETS:
        return _render_targets()
    if command.verb == PENDING:
        return _render_pending(state_path)
    if command.verb == PROBE:
        return _run_probe(command.argument, state_path, command.flags)
    if command.verb == COST:
        return _render_cost(state_path, command.argument)
    if command.verb == FINDINGS:
        return _render_findings(state_path, command.argument, command.flags)
    if command.verb == SHOW:
        return _render_show(command.argument, state_path, command.flags)
    if command.verb == ANALYZE:
        return _render_analyze(command.argument, state_path)
    if command.verb == SURFACES_LIST:
        return _render_surfaces()
    if command.verb == SEND:
        return _send_finding(command.argument, command.argument2, state_path)
    if command.verb == ACTIONS_LIST:
        return _render_actions()
    if command.verb == FIX:
        return _fix_finding(command.argument, state_path, command.actor)
    if command.verb == RUN:  # run <action> <fp>: argument=action, argument2=fingerprint
        return _run_action(command.argument, command.argument2, state_path, command.actor)
    if command.verb == HISTORY:
        return _render_history(state_path)
    if command.verb == HOLD:
        return _render_hold(state_path)
    if command.verb == LEARN:
        return _render_learn(state_path)
    if command.verb == HEALTH:
        return _render_health(state_path, workload=command.argument)
    if command.verb == POSTURE:
        return _render_posture()
    if command.verb == METRICS:
        return _render_metrics()
    if command.verb == CHECKS:
        return _render_checks()
    if command.verb == SOLUTIONS:
        return _render_solutions()
    if command.verb == SMOKE:
        return _render_smoke()
    if command.verb == ADD_CHECK:
        return _add_check(command.argument)
    if command.verb == ADD_SOLUTION:
        return _add_solution(command.argument, author=command.actor)
    if command.verb == VOUCH:
        return _vouch(command.argument, actor=command.actor)
    with StateStore(state_path) as store:
        if command.verb == APPROVE:
            fp, error = _resolve_pending(store, command.argument)
            if error:
                return error
            # argument2 carries the break-glass confirm token (the target name) when present.
            message, _result = apply_pending(store, fp, command.actor, token=command.argument2)
            return message
        if command.verb == DECLINE:
            fp, error = _resolve_pending(store, command.argument)
            if error:
                return error
            return decline_pending(store, fp, command.actor)
        if command.verb == MUTE:
            # Silence a finding (e.g. a benign probe result) on future scans/probes. Resolves a
            # prefix to a known finding, but still upserts an unseen fingerprint (pre-mute).
            fp, error = _resolve_mute_target(store, command.argument)
            if error:
                return error
            store.mute(fp, None, command.actor, datetime.now(UTC))
            return f"Muted {fp} -- silenced on future scans until `unmute {fp}`."
        if command.verb == UNMUTE:
            return _unmute_finding(store, command.argument)
        if command.verb == SNOOZE:
            return _snooze_finding(store, command.argument, command.argument2, command.actor)
    return "Nothing to do."
