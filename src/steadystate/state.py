"""The state store -- a tiny SQLite memory that makes ``scan`` memoryful.

Phase 0 of ChatOps: before this, every scan was amnesiac -- it could not tell a
finding it had surfaced ten times from one it was seeing for the first time, could
not notice a finding had *cleared*, and had nowhere to record an operator muting
or snoozing one. This store is that memory, and nothing more: one table keyed by a
Drift's stable :pyattr:`~steadystate.model.Drift.fingerprint`, recording when we
first/last saw each finding and its operator status (open / muted / snoozed /
resolved). It is deliberately stdlib ``sqlite3`` -- no new dependency, a single file
on disk, migration-safe via ``CREATE TABLE IF NOT EXISTS``.

It is intentionally dumb about reasoning: it never sees a Drift or an Alert, only
fingerprints + a (severity, title) pair to display. The scan-side reconciliation
(cli helpers) owns the policy; this owns the durable facts. Clocks are injected
(every mutating call takes ``now``) so the store is fully deterministic under test.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

# The finding lifecycle. A finding is born ``open``; an operator may ``mute`` or
# ``snooze`` it; the reconciler flips it to ``resolved`` when it stops appearing,
# and back to ``open`` if it recurs.
OPEN = "open"
MUTED = "muted"
SNOOZED = "snoozed"
RESOLVED = "resolved"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    fingerprint   TEXT PRIMARY KEY,
    first_seen    TEXT,
    last_seen     TEXT,
    last_severity TEXT,
    last_title    TEXT,
    status        TEXT,
    snooze_until  TEXT,
    note          TEXT,
    actor         TEXT
)
"""


def _iso(now: datetime) -> str:
    """ISO-8601 string for a tz-aware UTC datetime (the store's only time format)."""
    return now.isoformat()


@dataclass(frozen=True)
class Finding:
    """One stored row -- the durable record of a single fingerprinted finding."""

    fingerprint: str
    first_seen: str
    last_seen: str
    last_severity: str
    last_title: str
    status: str
    snooze_until: str | None = None
    note: str | None = None
    actor: str | None = None


class StateStore:
    """A SQLite-backed memory of findings, keyed by Drift fingerprint.

    Open it on a path (``:memory:`` for tests, a file for real runs); the schema is
    created idempotently so opening an existing db is a no-op migration. Every method
    that records time takes ``now`` rather than reading the clock, so tests pin it.
    """

    def __init__(self, path: str | Path = ":memory:") -> None:
        # isolation_level=None -> autocommit; each statement is its own transaction,
        # which is all this single-writer, one-shot-per-scan store needs.
        self._conn = sqlite3.connect(str(path), isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute(_SCHEMA)

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> StateStore:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- reads ------------------------------------------------------------------

    def get(self, fingerprint: str) -> Finding | None:
        row = self._conn.execute(
            "SELECT * FROM findings WHERE fingerprint = ?", (fingerprint,)
        ).fetchone()
        return _row_to_finding(row) if row is not None else None

    def status(self, fingerprint: str) -> str | None:
        """The stored status for ``fingerprint``, or None if we've never seen it."""
        row = self._conn.execute(
            "SELECT status FROM findings WHERE fingerprint = ?", (fingerprint,)
        ).fetchone()
        return row["status"] if row is not None else None

    def all_findings(self) -> list[Finding]:
        """Every stored finding, newest-first-seen last (stable for listing)."""
        rows = self._conn.execute(
            "SELECT * FROM findings ORDER BY first_seen, fingerprint"
        ).fetchall()
        return [_row_to_finding(r) for r in rows]

    def is_suppressed(self, fingerprint: str, now: datetime) -> bool:
        """True if this finding should be withheld from the surface right now.

        Muted -> always suppressed. Snoozed -> suppressed only while ``snooze_until``
        is still in the future; a lapsed snooze no longer suppresses (the reconciler
        will fold it back to ``open`` on its next pass). Anything else -> shown.
        """
        row = self._conn.execute(
            "SELECT status, snooze_until FROM findings WHERE fingerprint = ?",
            (fingerprint,),
        ).fetchone()
        if row is None:
            return False
        if row["status"] == MUTED:
            return True
        if row["status"] == SNOOZED and row["snooze_until"] is not None:
            return _iso(now) < row["snooze_until"]
        return False

    # -- the scan reconciliation ------------------------------------------------

    def record(self, seen: dict[str, tuple[str, str]], now: datetime) -> dict[str, dict]:
        """Upsert every fingerprint surfaced this scan; return per-fingerprint state.

        ``seen`` maps fingerprint -> (severity, title). For each one:

        * new fingerprint -> insert with ``first_seen == last_seen == now``, ``open``;
        * known fingerprint -> refresh ``last_seen`` + severity/title, preserve the
          original ``first_seen`` and any operator status (mute/snooze survive a
          re-sighting -- only the reconciler/operator changes status);
        * a previously ``resolved`` fingerprint that recurs -> reactivated to ``open``
          (it's drifting again), keeping its original ``first_seen`` so age is honest.

        Returns ``{fingerprint: {"is_new": bool, "first_seen": str, "status": str}}``
        for exactly the fingerprints in ``seen`` -- what the surface needs to render
        a NEW marker vs an age, and to know the current status.
        """
        now_s = _iso(now)
        out: dict[str, dict] = {}
        for fingerprint, (severity, title) in seen.items():
            existing = self.get(fingerprint)
            if existing is None:
                self._conn.execute(
                    "INSERT INTO findings (fingerprint, first_seen, last_seen, "
                    "last_severity, last_title, status) VALUES (?, ?, ?, ?, ?, ?)",
                    (fingerprint, now_s, now_s, severity, title, OPEN),
                )
                out[fingerprint] = {
                    "is_new": True,
                    "first_seen": now_s,
                    "status": OPEN,
                }
                continue
            # A resolved finding that reappears is drifting again -> reopen it; any
            # other status (open/muted/snoozed) is the operator's, leave it be.
            status = OPEN if existing.status == RESOLVED else existing.status
            self._conn.execute(
                "UPDATE findings SET last_seen = ?, last_severity = ?, "
                "last_title = ?, status = ? WHERE fingerprint = ?",
                (now_s, severity, title, status, fingerprint),
            )
            out[fingerprint] = {
                "is_new": False,
                "first_seen": existing.first_seen,
                "status": status,
            }
        return out

    def resolve_absent(self, current_fingerprints: set[str], now: datetime) -> list[str]:
        """Resolve ``open`` findings that did NOT appear in this scan; return them.

        These are findings that have *cleared* since we last looked. We flip them to
        ``resolved`` (stamping ``last_seen``) and hand their fingerprints back so the
        surface can note "Resolved since last scan" exactly once -- next scan they're
        already ``resolved`` and won't appear again. Only ``open`` findings resolve:
        a muted/snoozed finding that's absent stays as the operator set it.
        """
        now_s = _iso(now)
        rows = self._conn.execute(
            "SELECT fingerprint FROM findings WHERE status = ?", (OPEN,)
        ).fetchall()
        absent = [r["fingerprint"] for r in rows if r["fingerprint"] not in current_fingerprints]
        for fingerprint in absent:
            self._conn.execute(
                "UPDATE findings SET status = ?, last_seen = ? WHERE fingerprint = ?",
                (RESOLVED, now_s, fingerprint),
            )
        return absent

    # -- operator actions -------------------------------------------------------

    def mute(self, fingerprint: str, note: str | None, actor: str | None, now: datetime) -> None:
        """Mute a finding: suppress it from surfaces until explicitly unmuted.

        Upserts -- an operator may mute a fingerprint the store hasn't seen surfaced
        yet (e.g. pre-empting known noise); it's created ``muted`` with this instant
        as both first/last seen.
        """
        self._upsert_status(fingerprint, MUTED, snooze_until=None, note=note, actor=actor, now=now)

    def unmute(self, fingerprint: str, now: datetime) -> None:
        """Clear a mute (or a snooze) -- back to ``open``, dropping note/actor/snooze.

        A no-op if the fingerprint is unknown (nothing to unmute).
        """
        if self.get(fingerprint) is None:
            return
        self._conn.execute(
            "UPDATE findings SET status = ?, snooze_until = NULL, note = NULL, "
            "actor = NULL, last_seen = ? WHERE fingerprint = ?",
            (OPEN, _iso(now), fingerprint),
        )

    def snooze(self, fingerprint: str, until: datetime, actor: str | None, now: datetime) -> None:
        """Snooze a finding until ``until``: suppressed only while that's in the future.

        Upserts like :meth:`mute`. ``until`` is stored as an ISO string; ``is_suppressed``
        compares it against the scan's ``now``, so a lapsed snooze stops suppressing on
        its own.
        """
        self._upsert_status(
            fingerprint, SNOOZED, snooze_until=_iso(until), note=None, actor=actor, now=now
        )

    def _upsert_status(
        self,
        fingerprint: str,
        status: str,
        *,
        snooze_until: str | None,
        note: str | None,
        actor: str | None,
        now: datetime,
    ) -> None:
        now_s = _iso(now)
        existing = self.get(fingerprint)
        if existing is None:
            self._conn.execute(
                "INSERT INTO findings (fingerprint, first_seen, last_seen, "
                "last_severity, last_title, status, snooze_until, note, actor) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    fingerprint,
                    now_s,
                    now_s,
                    "unknown",
                    fingerprint,
                    status,
                    snooze_until,
                    note,
                    actor,
                ),
            )
            return
        self._conn.execute(
            "UPDATE findings SET status = ?, snooze_until = ?, note = ?, actor = ?, "
            "last_seen = ? WHERE fingerprint = ?",
            (status, snooze_until, note, actor, now_s, fingerprint),
        )


def _row_to_finding(row: sqlite3.Row) -> Finding:
    return Finding(
        fingerprint=row["fingerprint"],
        first_seen=row["first_seen"],
        last_seen=row["last_seen"],
        last_severity=row["last_severity"],
        last_title=row["last_title"],
        status=row["status"],
        snooze_until=row["snooze_until"],
        note=row["note"],
        actor=row["actor"],
    )
