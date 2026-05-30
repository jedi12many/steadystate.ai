"""The remediation audit log: append-only history of every approve/decline."""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime

from steadystate.state import (
    APPROVED,
    DECLINED,
    NOOP,
    VERIFIED,
    AuditEntry,
    PendingAction,
    StateStore,
)


def _t(day: int) -> datetime:
    return datetime(2026, 1, day, 12, 0, 0, tzinfo=UTC)


def _entry(
    outcome: str = VERIFIED, decision: str = APPROVED, env: str | None = "prod"
) -> AuditEntry:
    return AuditEntry(
        fingerprint="fp1",
        source="terraform",
        drift_identity="aws_s3_bucket.logs",
        actor="jeff",
        decision=decision,
        outcome=outcome,
        environment=env,
        detail="ok",
    )


def test_record_and_read_audit_newest_first():
    store = StateStore()
    store.record_audit(_entry(outcome=VERIFIED), _t(1))
    store.record_audit(_entry(outcome=NOOP, decision=DECLINED), _t(2))
    rows = store.audit_log()
    assert [r.outcome for r in rows] == [NOOP, VERIFIED]  # newest first
    assert rows[0].at == _t(2).isoformat()
    assert rows[0].actor == "jeff" and rows[0].drift_identity == "aws_s3_bucket.logs"


def test_audit_is_append_only():
    store = StateStore()
    store.record_audit(_entry(), _t(1))
    store.record_audit(_entry(), _t(2))  # same fingerprint -> a SECOND row, never an update
    assert len(store.audit_log()) == 2


def test_audit_respects_limit():
    store = StateStore()
    for day in range(1, 6):
        store.record_audit(_entry(), _t(day))
    assert len(store.audit_log(limit=3)) == 3


def test_audit_filters_by_environment():
    store = StateStore()
    store.record_audit(_entry(env="prod"), _t(1))
    store.record_audit(_entry(env="staging"), _t(2))
    store.record_audit(_entry(env="prod"), _t(3))
    prod = store.audit_log(environment="prod")
    assert len(prod) == 2 and all(r.environment == "prod" for r in prod)


def test_pending_round_trips_its_environment():
    store = StateStore()
    store.record_pending(
        PendingAction(
            fingerprint="fp",
            source="terraform",
            path="/repo",
            drift_identity="x",
            command="c",
            environment="prod-aws",
        ),
        _t(1),
    )
    assert store.get_pending("fp").environment == "prod-aws"


def test_migration_adds_environment_to_an_old_pending_db(tmp_path):
    # A db created before the `environment` column existed: opening it must migrate, not crash.
    db = tmp_path / "old.db"
    conn = sqlite3.connect(db)
    conn.execute(
        "CREATE TABLE pending_actions (fingerprint TEXT PRIMARY KEY, source TEXT, path TEXT, "
        "drift_identity TEXT, command TEXT, status TEXT, created_at TEXT, actor TEXT)"
    )
    conn.close()
    with StateStore(db) as store:  # opening runs _migrate
        store.record_pending(
            PendingAction(
                fingerprint="fp",
                source="s",
                path="p",
                drift_identity="d",
                command="c",
                environment="prod",
            ),
            _t(1),
        )
        assert store.get_pending("fp").environment == "prod"
