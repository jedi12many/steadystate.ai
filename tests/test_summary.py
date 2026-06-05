"""The `summary` rollup: a glanceable, deterministic status read from stored state (no fresh scan).
The load-bearing bits: it counts open findings by severity worst-first, names the single worst
finding, surfaces what's pending approval + the homeostat posture, and says 'all clear' when there's
nothing -- and it never probes (pure read), so it's cheap to run constantly."""

from __future__ import annotations

from datetime import UTC, datetime

from steadystate.inbound.base import SUMMARY, Command
from steadystate.inbound.server import _render_summary, run_command
from steadystate.state import PendingAction, StateStore

_NOW = datetime(2026, 6, 5, tzinfo=UTC)


def test_summary_is_all_clear_on_an_empty_or_missing_store(tmp_path):
    assert "all clear" in _render_summary(str(tmp_path / "absent.db"))  # no file yet -> no crash
    db = str(tmp_path / "s.db")
    with StateStore(db):
        pass  # an empty store
    out = _render_summary(db)
    assert "all clear -- 0 open findings, nothing pending" in out
    assert "decider:" in out  # the homeostat line is always shown


def test_summary_counts_by_severity_worst_first_and_names_the_worst(tmp_path):
    db = str(tmp_path / "s.db")
    with StateStore(db) as store:
        store.record(
            {
                "a" * 64: ("high", "web is CrashLoopBackOff"),
                "b" * 64: ("medium", "coredns adds capabilities"),
                "c" * 64: ("medium", "svclb adds capabilities"),
            },
            _NOW,
        )
        store.record_pending(
            PendingAction("d" * 64, "kubectl-cleanup", "", "web", "kubectl x"), _NOW
        )
    out = _render_summary(db)
    assert "3 open findings (1 high, 2 medium)" in out  # worst severity first
    assert "1 pending your approval" in out
    assert "worst: web is CrashLoopBackOff  [high]" in out  # the highest severity is surfaced


def test_summary_orders_critical_before_low(tmp_path):
    db = str(tmp_path / "s.db")
    with StateStore(db) as store:
        store.record({"a" * 64: ("low", "minor"), "b" * 64: ("critical", "boom")}, _NOW)
    out = _render_summary(db)
    assert "(1 critical, 1 low)" in out and "worst: boom  [critical]" in out


def test_summary_dispatches_as_a_read_only_chat_command(tmp_path):
    db = str(tmp_path / "s.db")
    with StateStore(db) as store:
        store.record({"a" * 64: ("high", "web down")}, _NOW)
    out = run_command(Command(SUMMARY, "amy"), db)  # same path the listener/REPL use
    assert "1 open finding" in out and "worst: web down  [high]" in out
