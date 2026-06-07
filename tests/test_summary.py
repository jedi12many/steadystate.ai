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


def test_summary_counts_impaired_by_severity_worst_first_and_names_the_worst(tmp_path):
    # impaired = a LIVE malfunction (a symptom carries evidence). The count/breakdown/worst are over
    # the impaired, worst severity first -- what's actually failing, not the drift pile.
    db = str(tmp_path / "s.db")
    with StateStore(db) as store:
        store.record(
            {
                "a" * 64: ("high", "web is CrashLoopBackOff"),
                "b" * 64: ("medium", "api OOMKilled"),
                "c" * 64: ("medium", "worker Evicted"),
            },
            _NOW,
            {  # evidence -> these are live symptoms (impaired), not drift/posture
                "a" * 64: {"category": "CrashLoopBackOff", "namespace": "default"},
                "b" * 64: {"category": "OOMKilled"},
                "c" * 64: {"category": "Evicted"},
            },
        )
        store.record_pending(
            PendingAction("d" * 64, "kubectl-cleanup", "", "web", "kubectl x"), _NOW
        )
    out = _render_summary(db)
    assert "3 impaired (1 high, 2 medium)" in out  # worst severity first
    assert "1 pending your approval" in out
    assert "worst: web is CrashLoopBackOff  [high]" in out  # the highest severity is surfaced


def test_summary_orders_critical_before_low(tmp_path):
    db = str(tmp_path / "s.db")
    with StateStore(db) as store:
        store.record(
            {"a" * 64: ("low", "minor"), "b" * 64: ("critical", "boom")},
            _NOW,
            {"a" * 64: {"category": "x"}, "b" * 64: {"category": "y"}},  # live symptoms
        )
    out = _render_summary(db)
    assert "2 impaired (1 critical, 1 low)" in out and "worst: boom  [critical]" in out


def test_summary_leads_with_your_apps_and_sets_platform_aside(tmp_path):
    # 'is my app healthy' means YOUR workloads: the count + worst are app-only, the Rancher/k8s
    # plumbing (coredns/svclb -- here title-only, the real CIS shape) is an aside, never hidden.
    db = str(tmp_path / "s.db")
    with StateStore(db) as store:
        store.record(
            {
                "a" * 64: ("high", "postfix not routing mail"),
                "b" * 64: ("medium", "workload 'coredns' adds Linux capabilities"),
                "c" * 64: ("high", "workload 'svclb-traefik-3f72' adds NET_ADMIN"),
            },
            _NOW,
            {"a" * 64: {"namespace": "mail", "workload": "postfix"}},  # the app one carries details
        )
    out = _render_summary(db)
    assert "1 impaired (1 high)" in out  # your apps: just postfix is actually failing
    assert "2 platform" in out  # coredns + svclb set aside, not hidden
    assert "worst: postfix not routing mail  [high]" in out  # worst APP finding, not the plumbing


def test_summary_leads_with_function_drift_is_noted_not_impaired(tmp_path):
    # the red-herring filter: a config drift (carries a `change`) is NOTED, not impaired -- so it
    # never shows as 'worst' and never invites a fix. Only the live symptom is impaired.
    db = str(tmp_path / "s.db")
    with StateStore(db) as store:
        store.record(
            {"a" * 64: ("high", "gateway image drifted"), "b" * 64: ("high", "gateway 5xx spike")},
            _NOW,
            {
                "a" * 64: {"change": "MODIFIED", "kind": "deployment"},  # drift -> noted
                "b" * 64: {"category": "Unhealthy", "namespace": "akeyless"},  # symptom -> impaired
            },
        )
    out = _render_summary(db)
    assert "1 impaired (1 high)" in out and "1 noted (drift/posture)" in out
    assert "worst: gateway 5xx spike  [high]" in out  # the live failure, NOT the drift
    assert "image drifted" not in out.split("worst:")[1]  # the drift is never the headline problem


def test_summary_shows_data_freshness(tmp_path):
    db = str(tmp_path / "s.db")
    with StateStore(db) as store:
        store.record({"a" * 64: ("high", "web down")}, datetime.now(UTC))
    assert "as of" in _render_summary(db)  # how stale the stored state is, for a glance/an agent
    empty = str(tmp_path / "e.db")
    with StateStore(empty):
        pass
    assert "as of" not in _render_summary(empty)  # nothing recorded -> no staleness line


def test_summary_surfaces_a_promotion_ready_response(tmp_path, monkeypatch):
    monkeypatch.delenv("STEADYSTATE_REFLEX_AUTO", raising=False)
    db = str(tmp_path / "s.db")
    with StateStore(db) as store:
        store.record(
            {"a" * 64: ("medium", "hog Evicted"), "b" * 64: ("medium", "hog2 Evicted")},
            _NOW,
            evidence={"a" * 64: {"category": "Evicted"}, "b" * 64: {"category": "Evicted"}},
        )
        # resolved by hand, same fix both times -> a response that's earned a promotion review
        store.resolve("a" * 64, "raise the ephemeral-storage limit", "jeff", _NOW)
        store.resolve("b" * 64, "raise the ephemeral-storage limit", "jeff", _NOW)
    assert "earned a promotion review" in _render_summary(db)  # glanceable, not buried in `learn`


def test_summary_dispatches_as_a_read_only_chat_command(tmp_path):
    db = str(tmp_path / "s.db")
    with StateStore(db) as store:
        store.record(
            {"a" * 64: ("high", "web down")}, _NOW, {"a" * 64: {"category": "Unavailable"}}
        )
    out = run_command(Command(SUMMARY, "amy"), db)  # same path the listener/REPL use
    assert "1 impaired" in out and "worst: web down  [high]" in out
