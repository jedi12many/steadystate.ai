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

import contextlib
import json
import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from .reason.cost import LlmCall

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
    actor         TEXT,
    details       TEXT
)
"""

# LLM spend telemetry: one row per model call (including failures + retries), raw token
# counts only. Dollars are computed at read time from reason/cost.py, so history re-prices
# for free. Append-only; never on the critical path -- a wedged db must not break a scan.
_LLM_SCHEMA = """
CREATE TABLE IF NOT EXISTS llm_calls (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    at                    TEXT NOT NULL,
    caller                TEXT NOT NULL,
    provider              TEXT NOT NULL,
    model                 TEXT NOT NULL,
    input_tokens          INTEGER NOT NULL,
    output_tokens         INTEGER NOT NULL,
    cache_creation_tokens INTEGER NOT NULL,
    cache_read_tokens     INTEGER NOT NULL,
    succeeded             INTEGER NOT NULL
)
"""

# Remediations offered for approval under `--autonomy suggest`, keyed by drift fingerprint.
# An operator drives them with the approve/decline verbs. status: pending | approved | declined.
# `environment` is the scan's --label, carried so the audit log can record which env it was.
_PENDING_SCHEMA = """
CREATE TABLE IF NOT EXISTS pending_actions (
    fingerprint    TEXT PRIMARY KEY,
    source         TEXT NOT NULL,
    path           TEXT NOT NULL,
    drift_identity TEXT NOT NULL,
    command        TEXT NOT NULL,
    status         TEXT NOT NULL,
    created_at     TEXT NOT NULL,
    actor          TEXT,
    environment    TEXT,
    patch          TEXT
)
"""

# The remediation audit log: one APPEND-ONLY row per approve/decline, never mutated. This is
# the accountability trail for the act loop -- what ran, when, who decided, and the outcome.
_AUDIT_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_log (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    at             TEXT NOT NULL,
    fingerprint    TEXT NOT NULL,
    source         TEXT NOT NULL,
    drift_identity TEXT NOT NULL,
    environment    TEXT,
    actor          TEXT NOT NULL,
    decision       TEXT NOT NULL,
    outcome        TEXT NOT NULL,
    detail         TEXT
)
"""

# Pending-action lifecycle.
PENDING = "pending"
APPROVED = "approved"
DECLINED = "declined"

# Audit outcomes (the result of an approved remediation; a decline records DECLINED).
VERIFIED = "verified"  # applied and the drift confirmed cleared
APPLIED = "applied"  # ran, but post-apply verification didn't confirm it cleared
FAILED = "failed"  # the executor could not apply
NOOP = "noop"  # the drift was already gone by approval time


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
    # Structured evidence captured when the finding was last recorded -- the key/value fields the
    # `show <fp>` view shows (namespace, cluster, pod count, last log line, ...). Empty until a
    # probe records any, and for finding types that carry none.
    details: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class PendingAction:
    """A remediation offered for approval. A suggestion can carry either or both directions: the
    *enforce* command an ``approve`` would run (when apply-eligible), and an *accept-reality*
    ``patch`` -- a reviewable code change for the same drift (e.g. a REMOVED drift, where enforcing
    would destroy the resource, so the only safe fix is to restore its declaration in code)."""

    fingerprint: str  # the drift's fingerprint -- the same key the findings table uses
    source: str  # so approve can rebuild the source + executor
    path: str  # the scan input (terraform dir, captured file, ...) approve re-reads
    drift_identity: str
    command: str  # display: the eligible remediation command ("" when there's no eligible apply)
    status: str = PENDING  # overwritten by the store on read; default eases construction
    created_at: str = ""  # the store stamps this on record
    actor: str | None = None
    environment: str | None = None  # the scan's --label, so the audit log can record the env
    # The accept-reality code change for this drift (a unified diff a human reviews + applies), or
    # None when there's no code-change form. Surfaced by `pending`; the tool never auto-applies it.
    patch: str | None = None


@dataclass(frozen=True)
class AuditEntry:
    """One append-only record of a remediation decision -- the act loop's accountability trail."""

    fingerprint: str
    source: str
    drift_identity: str
    actor: str  # who decided: cli / auto / a chat username
    decision: str  # APPROVED | DECLINED
    outcome: str  # VERIFIED | APPLIED | FAILED | NOOP (approved), or DECLINED
    environment: str | None = None
    detail: str | None = None  # the executor's result detail / message
    at: str = ""  # the store stamps this on record


class StateStore:
    """A SQLite-backed memory of findings, keyed by Drift fingerprint.

    Open it on a path (``:memory:`` for tests, a file for real runs); the schema is
    created idempotently so opening an existing db is a no-op migration. Every method
    that records time takes ``now`` rather than reading the clock, so tests pin it.
    """

    def __init__(self, path: str | Path = ":memory:") -> None:
        # isolation_level=None -> autocommit; each statement is its own transaction.
        self._conn = sqlite3.connect(str(path), isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        # This store is shared by design: a scheduled scan and the chat listener (which writes
        # from per-command daemon threads) hit one file on a shared volume. WAL lets readers and
        # the single writer proceed without blocking each other; busy_timeout makes a contended
        # write wait-and-retry instead of raising "database is locked"; synchronous=NORMAL is the
        # durability/throughput point WAL is designed for. busy_timeout + synchronous are
        # per-connection, so they're set on every open (WAL is a persistent db property, but
        # re-stating it is a harmless no-op). On :memory: (tests) WAL is silently not applied.
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute(_SCHEMA)
        self._conn.execute(_LLM_SCHEMA)
        self._conn.execute(_PENDING_SCHEMA)
        self._conn.execute(_AUDIT_SCHEMA)
        self._migrate()

    def _migrate(self) -> None:
        """Idempotent column adds for dbs created before a column existed (CREATE IF NOT EXISTS
        leaves an old table untouched). Cheap and safe to run on every open."""
        cols = {row["name"] for row in self._conn.execute("PRAGMA table_info(pending_actions)")}
        if "environment" not in cols:
            self._conn.execute("ALTER TABLE pending_actions ADD COLUMN environment TEXT")
        if "patch" not in cols:
            self._conn.execute("ALTER TABLE pending_actions ADD COLUMN patch TEXT")
        finding_cols = {row["name"] for row in self._conn.execute("PRAGMA table_info(findings)")}
        if "details" not in finding_cols:  # structured per-fingerprint evidence (the `show` view)
            self._conn.execute("ALTER TABLE findings ADD COLUMN details TEXT")

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

    def find_by_prefix(self, prefix: str) -> list[Finding]:
        """Findings whose fingerprint starts with ``prefix`` -- so a chat user can pass a short,
        copy-pasted fingerprint (`raw 4f72305e`) instead of all 64 hex chars. ``%``/``_`` are
        escaped so they can't act as LIKE wildcards. Ordered for a stable 'ambiguous' message."""
        escaped = prefix.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        rows = self._conn.execute(
            "SELECT * FROM findings WHERE fingerprint LIKE ? ESCAPE '\\' ORDER BY fingerprint",
            (escaped + "%",),
        ).fetchall()
        return [_row_to_finding(r) for r in rows]

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

    def record(
        self,
        seen: dict[str, tuple[str, str]],
        now: datetime,
        evidence: Mapping[str, Mapping[str, str]] | None = None,
    ) -> dict[str, dict]:
        """Upsert every fingerprint surfaced this scan; return per-fingerprint state.

        ``seen`` maps fingerprint -> (severity, title). ``evidence`` optionally maps a fingerprint
        to a small dict of structured fields (namespace, cluster, last log, ...) the `show <fp>`
        view shows; a re-sighting that carries none preserves what was last captured (COALESCE), so
        a cheap stateless probe never erases a richer record. For each fingerprint:

        * new fingerprint -> insert with ``first_seen == last_seen == now``, ``open``;
        * known fingerprint -> refresh ``last_seen`` + severity/title, preserve the
          original ``first_seen``; a *mute* or an *active* snooze survives a re-sighting
          (operator state isn't cleared by merely seeing the finding again);
        * a previously ``resolved`` fingerprint that recurs -> reactivated to ``open``
          (it's drifting again), keeping its original ``first_seen`` so age is honest;
        * a finding whose snooze has *lapsed* (snooze_until in the past) -> folded back
          to ``open`` and snooze_until cleared, so a re-surfaced finding never lingers
          labelled ``snoozed`` once the snooze no longer suppresses it.

        Returns ``{fingerprint: {"is_new": bool, "first_seen": str, "status": str}}``
        for exactly the fingerprints in ``seen`` -- what the surface needs to render
        a NEW marker vs an age, and to know the current status.
        """
        now_s = _iso(now)
        evidence = evidence or {}
        out: dict[str, dict] = {}
        for fingerprint, (severity, title) in seen.items():
            fields = evidence.get(fingerprint)
            details_json = json.dumps(dict(fields)) if fields else None
            existing = self.get(fingerprint)
            if existing is None:
                self._conn.execute(
                    "INSERT INTO findings (fingerprint, first_seen, last_seen, "
                    "last_severity, last_title, status, details) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (fingerprint, now_s, now_s, severity, title, OPEN, details_json),
                )
                out[fingerprint] = {
                    "is_new": True,
                    "first_seen": now_s,
                    "status": OPEN,
                }
                continue
            status, snooze_until = self._refreshed_status(existing, now_s)
            self._conn.execute(
                "UPDATE findings SET last_seen = ?, last_severity = ?, last_title = ?, status = ?, "
                "snooze_until = ?, details = COALESCE(?, details) WHERE fingerprint = ?",
                (now_s, severity, title, status, snooze_until, details_json, fingerprint),
            )
            out[fingerprint] = {
                "is_new": False,
                "first_seen": existing.first_seen,
                "status": status,
            }
        return out

    @staticmethod
    def _refreshed_status(existing: Finding, now_s: str) -> tuple[str, str | None]:
        """The (status, snooze_until) a re-seen finding should carry.

        Reopens a resolved finding (it's drifting again) and folds a lapsed snooze back
        to open; a mute or an active snooze is the operator's state and is preserved.
        """
        if existing.status == RESOLVED:
            return OPEN, existing.snooze_until
        if (
            existing.status == SNOOZED
            and existing.snooze_until is not None
            and now_s >= existing.snooze_until
        ):
            return OPEN, None
        return existing.status, existing.snooze_until

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

    # -- LLM spend telemetry ----------------------------------------------------

    def record_llm_call(self, call: LlmCall, now: datetime) -> None:
        """Append one model call. Best-effort -- callers wrap this so telemetry never
        breaks a scan; failures and retries each get their own row."""
        self._conn.execute(
            "INSERT INTO llm_calls (at, caller, provider, model, input_tokens, "
            "output_tokens, cache_creation_tokens, cache_read_tokens, succeeded) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                _iso(now),
                call.caller,
                call.provider,
                call.model,
                call.input_tokens,
                call.output_tokens,
                call.cache_creation_tokens,
                call.cache_read_tokens,
                int(call.succeeded),
            ),
        )

    def llm_calls_since(self, cutoff: datetime | None = None) -> list[LlmCall]:
        """Every recorded call (oldest first), or only those at/after ``cutoff``. The
        caller rolls these up and prices them at read time (reason/cost.py)."""
        if cutoff is None:
            rows = self._conn.execute("SELECT * FROM llm_calls ORDER BY at, id").fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM llm_calls WHERE at >= ? ORDER BY at, id", (_iso(cutoff),)
            ).fetchall()
        return [_row_to_llm_call(r) for r in rows]

    def timed_llm_calls_since(self, cutoff: datetime | None = None) -> list[tuple[str, LlmCall]]:
        """Like ``llm_calls_since``, but each call paired with its recorded ``at`` timestamp --
        for bucketing spend over time (reason/cost.roll_up_by_period)."""
        if cutoff is None:
            rows = self._conn.execute("SELECT * FROM llm_calls ORDER BY at, id").fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM llm_calls WHERE at >= ? ORDER BY at, id", (_iso(cutoff),)
            ).fetchall()
        return [(r["at"], _row_to_llm_call(r)) for r in rows]

    # -- pending remediations (autonomy: suggest) -------------------------------

    def record_pending(self, action: PendingAction, now: datetime) -> None:
        """Offer a remediation for approval, keyed by drift fingerprint. A drift the operator
        already declined is not re-offered; otherwise upsert it as pending (a recurred drift is
        offered again), preserving the original created_at."""
        existing = self.get_pending(action.fingerprint)
        if existing is not None and existing.status == DECLINED:
            return
        created = existing.created_at if existing is not None else _iso(now)
        self._conn.execute(
            "INSERT OR REPLACE INTO pending_actions (fingerprint, source, path, drift_identity, "
            "command, status, created_at, actor, environment, patch) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                action.fingerprint,
                action.source,
                action.path,
                action.drift_identity,
                action.command,
                PENDING,
                created,
                None,
                action.environment,
                action.patch,
            ),
        )

    def get_pending(self, fingerprint: str) -> PendingAction | None:
        row = self._conn.execute(
            "SELECT * FROM pending_actions WHERE fingerprint = ?", (fingerprint,)
        ).fetchone()
        return _row_to_pending(row) if row is not None else None

    def all_pending(self) -> list[PendingAction]:
        """Every action still awaiting a decision, oldest first."""
        rows = self._conn.execute(
            "SELECT * FROM pending_actions WHERE status = ? ORDER BY created_at, fingerprint",
            (PENDING,),
        ).fetchall()
        return [_row_to_pending(r) for r in rows]

    def set_pending_status(self, fingerprint: str, status: str, actor: str | None = None) -> None:
        self._conn.execute(
            "UPDATE pending_actions SET status = ?, actor = ? WHERE fingerprint = ?",
            (status, actor, fingerprint),
        )

    def claim_pending(
        self, fingerprint: str, from_status: str, to_status: str, actor: str | None = None
    ) -> bool:
        """Atomically move a pending action from ``from_status`` to ``to_status``, returning True
        iff THIS call made the transition. The conditional ``WHERE status = from_status`` is the
        concurrency guard against double-approval: with two approvers racing the same fingerprint
        (two chat users), exactly one sees ``rowcount == 1`` and proceeds to remediate, while the
        other sees 0 and bails -- so an irreversible remediation runs at most once. Autocommit (+
        WAL) makes the check-and-set one atomic statement, closing the read-then-act TOCTOU."""
        cur = self._conn.execute(
            "UPDATE pending_actions SET status = ?, actor = ? WHERE fingerprint = ? AND status = ?",
            (to_status, actor, fingerprint, from_status),
        )
        return cur.rowcount == 1

    # -- audit log (append-only history of every remediation decision) ----------

    def record_audit(self, entry: AuditEntry, now: datetime) -> None:
        """Append one immutable record of an approve/decline. Never updates an existing row."""
        self._conn.execute(
            "INSERT INTO audit_log (at, fingerprint, source, drift_identity, environment, "
            "actor, decision, outcome, detail) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                _iso(now),
                entry.fingerprint,
                entry.source,
                entry.drift_identity,
                entry.environment,
                entry.actor,
                entry.decision,
                entry.outcome,
                entry.detail,
            ),
        )

    def audit_log(self, limit: int = 50, environment: str | None = None) -> list[AuditEntry]:
        """The most recent audit records, newest first, optionally filtered to one environment."""
        if environment is not None:
            rows = self._conn.execute(
                "SELECT * FROM audit_log WHERE environment = ? ORDER BY id DESC LIMIT ?",
                (environment, limit),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [_row_to_audit(row) for row in rows]


def _row_to_finding(row: sqlite3.Row) -> Finding:
    details: dict[str, str] = {}
    raw = row["details"]  # always present: _migrate adds the column on every open
    if raw:
        with contextlib.suppress(ValueError, TypeError):  # a hand-corrupted row degrades to {}
            details = json.loads(raw)
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
        details=details,
    )


def _row_to_llm_call(row: sqlite3.Row) -> LlmCall:
    return LlmCall(
        caller=row["caller"],
        provider=row["provider"],
        model=row["model"],
        input_tokens=row["input_tokens"],
        output_tokens=row["output_tokens"],
        cache_creation_tokens=row["cache_creation_tokens"],
        cache_read_tokens=row["cache_read_tokens"],
        succeeded=bool(row["succeeded"]),
    )


def _row_to_pending(row: sqlite3.Row) -> PendingAction:
    return PendingAction(
        fingerprint=row["fingerprint"],
        source=row["source"],
        path=row["path"],
        drift_identity=row["drift_identity"],
        command=row["command"],
        status=row["status"],
        created_at=row["created_at"],
        actor=row["actor"],
        environment=row["environment"],
        patch=row["patch"],
    )


def _row_to_audit(row: sqlite3.Row) -> AuditEntry:
    return AuditEntry(
        fingerprint=row["fingerprint"],
        source=row["source"],
        drift_identity=row["drift_identity"],
        actor=row["actor"],
        decision=row["decision"],
        outcome=row["outcome"],
        environment=row["environment"],
        detail=row["detail"],
        at=row["at"],
    )
