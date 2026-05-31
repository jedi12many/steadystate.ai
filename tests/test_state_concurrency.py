"""Concurrency hardening for the shared SQLite store (C2).

The store is shared by design -- a scheduled scan and the chat listener (writing from per-command
daemon threads) hit one file. These pin the two fixes:

- the connection opens in WAL with a busy_timeout, so concurrent writers wait-and-retry instead of
  raising "database is locked";
- `claim_pending` is an atomic check-and-set, so two approvers racing the same fingerprint can't
  both run the (irreversible) remediation -- closing the TOCTOU in `apply_pending`.
"""

from __future__ import annotations

import threading
from datetime import UTC, datetime

from steadystate.state import APPROVED, DECLINED, PENDING, PendingAction, StateStore


def _pending(fp: str = "fp1") -> PendingAction:
    return PendingAction(
        fingerprint=fp,
        source="terraform",
        path="x",
        drift_identity="aws_s3_bucket.logs",
        command="terraform apply",
    )


# -- WAL + busy_timeout on the connection --------------------------------------


def test_store_opens_in_wal_with_a_busy_timeout(tmp_path):
    with StateStore(tmp_path / "state.db") as store:
        mode = store._conn.execute("PRAGMA journal_mode").fetchone()[0]
        timeout = store._conn.execute("PRAGMA busy_timeout").fetchone()[0]
    assert mode.lower() == "wal"  # readers + the single writer don't block each other
    assert timeout == 5000  # a contended write waits, instead of erroring immediately


# -- claim_pending: the atomic guard against double-approval -------------------


def test_claim_pending_transitions_only_from_the_expected_status(tmp_path):
    now = datetime.now(UTC)
    with StateStore(tmp_path / "state.db") as store:
        store.record_pending(_pending("fp1"), now)
        assert store.claim_pending("fp1", PENDING, APPROVED, "alice") is True  # first wins
        assert store.claim_pending("fp1", PENDING, APPROVED, "bob") is False  # already approved
        # and it really moved out of pending (the loser would not re-run a remediation)
        assert store.get_pending("fp1").status == APPROVED


def test_claim_pending_is_false_for_an_unknown_fingerprint(tmp_path):
    with StateStore(tmp_path / "state.db") as store:
        assert store.claim_pending("nope", PENDING, APPROVED, "x") is False


def test_concurrent_claims_have_exactly_one_winner(tmp_path):
    # The real race: N threads, each its OWN connection (like a listener's per-command threads),
    # all claim the same fingerprint at once. WAL + busy_timeout must let the writes serialize
    # without "database is locked", and the conditional UPDATE must pick a single winner.
    db = tmp_path / "state.db"
    with StateStore(db) as store:
        store.record_pending(_pending("fp1"), datetime.now(UTC))

    n = 8
    results: list[bool] = []
    lock = threading.Lock()
    barrier = threading.Barrier(n)

    def worker() -> None:
        barrier.wait()  # line everyone up to maximize contention
        with StateStore(db) as s:  # a fresh connection per thread, as the listener does
            won = s.claim_pending("fp1", PENDING, APPROVED, "racer")
        with lock:
            results.append(won)

    threads = [threading.Thread(target=worker) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(results) == n  # nobody crashed on a lock
    assert results.count(True) == 1  # exactly one approver ran the remediation


def test_decline_still_uses_set_pending_status(tmp_path):
    # decline has no irreversible action, so it stays a plain set (regression guard that the
    # claim refactor didn't break the non-racing path).
    now = datetime.now(UTC)
    with StateStore(tmp_path / "state.db") as store:
        store.record_pending(_pending("fp1"), now)
        store.set_pending_status("fp1", DECLINED, "alice")
        assert store.get_pending("fp1").status == DECLINED
