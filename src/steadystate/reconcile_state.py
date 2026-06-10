"""Bridge the pure Pipeline to the state store -- the *memoryful scan* logic.

The Pipeline (reason/pipeline.py) stays pure: drift in, a Report of Alerts out, no
idea a database exists. All the memory lives here and runs *between* ``pipeline.run()``
and ``surface.emit()`` (the CLI calls :func:`reconcile`). Keeping it out of the
Pipeline means the stateless path is byte-for-byte unchanged and every reasoning test
runs without a store.

What reconciliation does, in order:

1. Collect each surfaced Alert's member-drift fingerprints, with the (severity, title)
   the store should display.
2. :meth:`StateStore.record` them -> per-fingerprint state (new vs recurring, age,
   status). Annotate each Alert (``first_seen`` / ``status``) from its drifts.
3. Drop Alerts whose fingerprints are *all* suppressed (muted, or an active snooze) --
   a partially-suppressed Alert still surfaces, annotated with whatever's left.
4. :meth:`StateStore.resolve_absent` over the scan's *full* fingerprint set (signals
   included) -> findings that have cleared since last scan, returned for a one-time
   "Resolved since last scan" note.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from .evidence import EvidenceKeys
from .model import Drift
from .mutes import apply_committed_mutes
from .reason.alert import Alert
from .reason.report import Report
from .state import StateStore

# How long a finding must stay ABSENT before a scan marks it resolved -- the "give it plenty of
# room" window. An intermittent log error is *sampled*: it can skip a scan or two while the problem
# is still happening, and without this buffer it would flap resolved->reopened every other scan. So
# we wait for sustained absence -- lack of signal over time -- before deciding it went away. The
# window only matters when scans are more frequent than it (log probing every few minutes); a daily
# sweep or a CI drift scan is already spaced wider, so absence always exceeds it and resolution is
# immediate as before. Tunable via STEADYSTATE_RESOLVE_AFTER; default 30 minutes.
DEFAULT_RESOLVE_GRACE = timedelta(minutes=30)


def _parse_window(text: str) -> timedelta | None:
    """Parse a resolve-grace window: ``30m`` / ``2h`` / ``1d`` / ``90s`` / ``1w``, or a bare integer
    read as minutes (the natural unit for a quiet window). None when it isn't a recognized,
    non-negative duration, so the caller falls back to the default rather than guessing. Pure."""
    text = text.strip().lower()
    if not text:
        return None
    units = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days", "w": "weeks"}
    if text[-1] in units:
        head = text[:-1]
        return timedelta(**{units[text[-1]]: int(head)}) if head.isdigit() else None
    return timedelta(minutes=int(text)) if text.isdigit() else None


def resolve_grace(raw: str | None = None) -> timedelta:
    """The active resolve-grace window: ``STEADYSTATE_RESOLVE_AFTER`` if set and parseable, else
    ``DEFAULT_RESOLVE_GRACE`` (30m). ``STEADYSTATE_RESOLVE_AFTER=0`` restores the original
    resolve-on-first-absence behavior. An unparseable value falls back to the default -- a typo can
    never silently change the window to something surprising. Pure given ``raw``."""
    raw = os.environ.get("STEADYSTATE_RESOLVE_AFTER") if raw is None else raw
    if raw is None:
        return DEFAULT_RESOLVE_GRACE
    parsed = _parse_window(raw)
    return parsed if parsed is not None else DEFAULT_RESOLVE_GRACE


@dataclass(frozen=True)
class ResolvedFinding:
    """A finding that cleared since the last scan -- surfaced once, then forgotten."""

    fingerprint: str
    title: str


def _fingerprints(alert: Alert) -> list[str]:
    # Drift Alerts key memory on their member drifts; standing-policy Alerts on their
    # PolicyFindings; malfunction Alerts on their Symptoms. Every fingerprint is
    # source|identity|<discriminator>, so the store treats them identically -- this is the one
    # seam that makes new/recurring/resolved + mute/snooze work for all three departure types,
    # with no change to StateStore. A diagnosis Alert (drift + symptom) keys on both.
    return (
        [d.fingerprint for d in alert.drifts]
        + [f.fingerprint for f in alert.findings]
        + [s.fingerprint for s in alert.symptoms]
    )


def alert_suppressed(alert: Alert, store: StateStore, now: datetime) -> bool:
    """Whether an Alert should be withheld from a surface right now. Two ways to silence it: mute
    its **correlation fingerprint** (the 'mute-all' key on a grouped finding -- the whole group
    goes quiet at once), or mute **every** individual member. So: corr muted, OR (it has members
    and all of them are muted/snoozed). The shared rule for the stateful reconcile and the chat
    `_honor_mutes` read, so both honor a group mute identically."""
    corr = alert.correlation_fingerprint
    if corr and store.is_suppressed(corr, now):
        return True
    fps = _fingerprints(alert)
    return bool(fps) and all(store.is_suppressed(fp, now) for fp in fps)


def _display(drift: Drift, alert: Alert) -> tuple[str, str]:
    """The (severity, title) the store should remember for this drift's fingerprint.

    Title is the drift's own one-line summary (stable per fingerprint) rather than the
    Alert title, which can be a correlated group heading shared by several findings.
    """
    return (alert.severity.value, drift.summary())


def seen_findings(report: Report) -> dict[str, tuple[str, str]]:
    """Every fingerprint in ``report`` -> the ``(severity, title)`` the store should remember for
    it. Drifts, standing-policy findings, and symptoms all record identically (the store never
    knows the difference). Pure -- shared by the full ``reconcile`` and the record-only path a
    summoned ``probe`` uses to persist findings without resolving absent ones."""
    seen: dict[str, tuple[str, str]] = {}
    for item in report.items:
        for drift in item.drifts:
            seen[drift.fingerprint] = _display(drift, item)
        for pf in item.findings:
            seen[pf.fingerprint] = (item.severity.value, pf.title)
        for symptom in item.symptoms:
            seen[symptom.fingerprint] = (item.severity.value, symptom.title)
        # A correlated group's own "mute-all" fingerprint is remembered too -- so it shows in
        # `findings` (discoverable after the probe scrolls away), gets the new/resolved lifecycle,
        # and can be muted or `show`n. Its title is the group heading ("... in N place(s)").
        if item.correlation_fingerprint:
            seen[item.correlation_fingerprint] = (item.severity.value, item.title)
    return seen


def finding_evidence(report: Report) -> dict[str, dict[str, str]]:
    """Every fingerprint -> a small dict of structured fields to remember for the `show <fp>` view.
    A Symptom contributes the probe's structured evidence (namespace, cluster, pod count, the
    failing pod's last log line, ...); a Drift contributes its change type + kind. Pure; a finding
    with no fields is omitted (the store then keeps whatever it last had)."""
    out: dict[str, dict[str, str]] = {}
    for item in report.items:
        for drift in item.drifts:
            out[drift.fingerprint] = {
                EvidenceKeys.CHANGE: drift.change_type.value,
                EvidenceKeys.KIND: drift.kind,
            }
        for symptom in item.symptoms:
            if symptom.evidence:
                out[symptom.fingerprint] = dict(symptom.evidence)
        # The group fingerprint's evidence: how many places, and a couple shared fields -- so
        # `show <correlation-fp>` shows the scope of the group, not "no evidence".
        if item.correlation_fingerprint and item.symptoms:
            first = item.symptoms[0]
            out[item.correlation_fingerprint] = {
                EvidenceKeys.CORRELATED: f"{len(item.symptoms)} place(s)",
                EvidenceKeys.WORKLOAD: first.identity.rsplit("/", 1)[-1].rsplit(".", 1)[-1],
                EvidenceKeys.KIND: first.kind,
                EvidenceKeys.CATEGORY: first.category,
            }
    return out


def reconcile(
    report: Report, store: StateStore, now: datetime | None = None
) -> list[ResolvedFinding]:
    """Make ``report`` memoryful against ``store``; return findings resolved this scan.

    Mutates ``report.items`` in place: annotates surviving Alerts with their stored
    ``first_seen`` / ``status`` and drops fully-suppressed ones. Signals are recorded
    (so they count toward presence/absence) but never annotated or dropped here -- the
    surface treats them as a count, as before.
    """
    now = now or datetime.now(UTC)

    # 0. Import the COMMITTED mutes (steadystate/mutes.json) the db doesn't already suppress --
    #    so a fresh state.db self-heals on its first scan and an operator's "this is benign"
    #    survives any db loss. Idempotent; a missing/malformed file is simply no committed mutes.
    apply_committed_mutes(store, now)

    # 1. Every fingerprint seen this scan -> (severity, title) to remember (alerts + signals both
    #    count as "present", so a finding that drops below the Event bar isn't read as resolved).
    seen = seen_findings(report)

    # 2. Record + read back per-fingerprint state (plus structured evidence for the `show` view).
    state = store.record(seen, now, finding_evidence(report))

    # 3. Annotate + suppress Alerts (signals are left as a count).
    surviving: list[Alert] = []
    for item in report.alerts:
        fps = _fingerprints(item)
        # Drop the Alert when silenced -- the operator muted the group's correlation fp, or every
        # individual member.
        if alert_suppressed(item, store, now):
            continue
        _annotate(item, fps, state)
        surviving.append(item)

    # Rebuild items as the kept signals + surviving alerts (drop suppressed alerts).
    report.items = report.signals + surviving

    # 4. Resolve findings absent from this scan's *full* fingerprint set -- but only once they've
    #    been absent for the grace window (so a sampled log error doesn't flap resolved/reopened).
    resolved_fps = store.resolve_absent(set(seen), now, resolve_grace())
    resolved: list[ResolvedFinding] = []
    for fp in resolved_fps:
        finding = store.get(fp)
        title = finding.last_title if finding is not None else fp
        resolved.append(ResolvedFinding(fingerprint=fp, title=title))
    return resolved


def _annotate(alert: Alert, fingerprints: list[str], state: dict[str, dict]) -> None:
    """Set ``alert.first_seen`` / ``alert.status`` from its members' stored state.

    An Alert can bundle several fingerprints (a correlated group). We surface the
    *earliest* ``first_seen`` across members (the finding has been around at least that
    long); the console derives NEW-vs-age from that against the scan time. ``status`` is
    the strongest operator state present (muted/snoozed win over open) so a partially
    muted/snoozed group still shows an operator has touched it; otherwise it's the real
    lifecycle status (``open``).
    """
    members = [state[fp] for fp in fingerprints if fp in state]
    if not members:
        return
    alert.first_seen = min(_parse(m["first_seen"]) for m in members)
    alert.status = _summary_status(members)


def _summary_status(members: list[dict]) -> str:
    """Collapse member lifecycle statuses into the one to show for the Alert."""
    statuses = {m["status"] for m in members}
    # Operator states win over plain open, so a partial mute/snooze stays visible.
    for s in ("muted", "snoozed"):
        if s in statuses:
            return s
    return "open"


def _parse(iso: str) -> datetime:
    return datetime.fromisoformat(iso)
