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

from dataclasses import dataclass
from datetime import UTC, datetime

from .model import Drift
from .reason.alert import Alert
from .reason.report import Report
from .state import StateStore


@dataclass(frozen=True)
class ResolvedFinding:
    """A finding that cleared since the last scan -- surfaced once, then forgotten."""

    fingerprint: str
    title: str


def _fingerprints(alert: Alert) -> list[str]:
    return [d.fingerprint for d in alert.drifts]


def _display(drift: Drift, alert: Alert) -> tuple[str, str]:
    """The (severity, title) the store should remember for this drift's fingerprint.

    Title is the drift's own one-line summary (stable per fingerprint) rather than the
    Alert title, which can be a correlated group heading shared by several findings.
    """
    return (alert.severity.value, drift.summary())


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

    # 1. Every fingerprint seen this scan -> (severity, title) to remember. Alerts and
    #    signals both count toward "present", so a finding that drops below the Event
    #    bar isn't mistaken for resolved.
    seen: dict[str, tuple[str, str]] = {}
    for item in report.items:
        for drift in item.drifts:
            seen[drift.fingerprint] = _display(drift, item)

    # 2. Record + read back per-fingerprint state.
    state = store.record(seen, now)

    # 3. Annotate + suppress Alerts (signals are left as a count).
    surviving: list[Alert] = []
    for item in report.alerts:
        fps = _fingerprints(item)
        # All suppressed -> drop the Alert entirely (operator silenced every member).
        if fps and all(store.is_suppressed(fp, now) for fp in fps):
            continue
        _annotate(item, fps, state)
        surviving.append(item)

    # Rebuild items as the kept signals + surviving alerts (drop suppressed alerts).
    report.items = report.signals + surviving

    # 4. Resolve findings absent from this scan's *full* fingerprint set.
    resolved_fps = store.resolve_absent(set(seen), now)
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
