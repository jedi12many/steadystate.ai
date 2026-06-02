"""Evicted-pod cleanup: the guardrailed, command-based remediation -- validation, recording, run,
and the approve routing. The one place steadystate runs a `kubectl delete`, so the security gate
(only the exact allow-listed command, never arbitrary input) is pinned hard."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest import mock

from steadystate.act.approve import apply_pending
from steadystate.act.cleanup import CLEANUP_SOURCE, is_safe_cleanup, record_cleanups, run_cleanup
from steadystate.model import Provenance
from steadystate.probe.base import Symptom
from steadystate.reason.alert import Alert, Layer, Severity
from steadystate.reason.report import Report
from steadystate.state import PendingAction, StateStore

_NOW = datetime(2026, 6, 2, 12, 0, 0, tzinfo=UTC)
_FIX = "kubectl delete pods -n prod --field-selector=status.phase=Failed"


def _evicted_report(fix: str = _FIX) -> tuple[Report, Symptom]:
    sym = Symptom(
        identity="apps/Deployment/prod/web",
        kind="Deployment",
        category="Evicted",
        severity=Severity.MEDIUM,
        title="web is Evicted in prod",
        detail="1 pod",
        provenance=Provenance(source="kubernetes", address="x"),
        recommended_action=fix,
    )
    alert = Alert(
        title=sym.title,
        severity=sym.severity,
        drifts=[],
        why_it_matters="x",
        layer=Layer.ALERT,
        symptoms=[sym],
        recommended_action=fix,
    )
    return Report(items=[alert]), sym


# -- the security gate ----------------------------------------------------------


def test_is_safe_cleanup_accepts_only_the_generated_shape():
    assert is_safe_cleanup("kubectl delete pods --field-selector=status.phase=Failed")
    assert is_safe_cleanup(_FIX)
    assert is_safe_cleanup(_FIX + " --context prod-cluster")


def test_is_safe_cleanup_rejects_injection_and_other_commands():
    bad = [
        "kubectl delete pods -n prod; rm -rf /",
        "kubectl delete pods -n prod --field-selector=status.phase=Failed && curl evil",
        "kubectl delete pods -n prod --field-selector=status.phase=Failed | sh",
        "kubectl delete deploy web -n prod --field-selector=status.phase=Failed",  # not pods
        "kubectl delete pods -n prod",  # no field selector -> could match Running pods
        "kubectl get pods -A",
        "rm -rf /",
        "",
    ]
    assert not any(is_safe_cleanup(c) for c in bad)


# -- recording ------------------------------------------------------------------


def test_record_cleanups_offers_an_approvable_pending_per_evicted_symptom():
    store = StateStore()
    report, sym = _evicted_report()
    assert record_cleanups(store, report, _NOW) == 1
    [pending] = store.all_pending()
    assert pending.fingerprint == sym.fingerprint and pending.source == CLEANUP_SOURCE
    assert pending.command == _FIX
    # idempotent: re-recording the same finding upserts, doesn't duplicate.
    record_cleanups(store, report, _NOW)
    assert len(store.all_pending()) == 1


def test_record_cleanups_skips_symptoms_without_a_safe_fix():
    store = StateStore()
    report, _ = _evicted_report(fix="kubectl delete pods -n prod; rm -rf /")  # unsafe -> skipped
    assert record_cleanups(store, report, _NOW) == 0
    assert store.all_pending() == []


# -- running --------------------------------------------------------------------


def _action(command: str = _FIX) -> PendingAction:
    return PendingAction(
        fingerprint="f" * 64,
        source=CLEANUP_SOURCE,
        path="",
        drift_identity="prod/web",
        command=command,
    )


def _proc(returncode: int = 0, stdout: str = "", stderr: str = ""):
    return mock.Mock(returncode=returncode, stdout=stdout, stderr=stderr)


def test_run_cleanup_runs_the_delete_as_an_argv_list_and_verifies_on_success():
    with mock.patch(
        "steadystate.act.cleanup.subprocess.run", return_value=_proc(0, 'pod "web-abc" deleted')
    ) as run:
        result = run_cleanup(_action())
    argv, _kwargs = run.call_args
    assert argv[0] == [
        "kubectl",
        "delete",
        "pods",
        "-n",
        "prod",
        "--field-selector=status.phase=Failed",
    ]
    assert run.call_args.kwargs.get("timeout")  # bounded; no shell
    assert result.applied and result.verified and "deleted" in result.detail


def test_run_cleanup_reports_a_nonzero_exit_as_failed():
    with mock.patch(
        "steadystate.act.cleanup.subprocess.run", return_value=_proc(1, stderr="forbidden")
    ):
        result = run_cleanup(_action())
    assert not result.applied and "forbidden" in result.detail


def test_run_cleanup_refuses_an_unsafe_command_without_executing():
    with mock.patch("steadystate.act.cleanup.subprocess.run") as run:
        result = run_cleanup(_action("kubectl delete pods -n prod; rm -rf /"))
    run.assert_not_called()  # the gate stops it BEFORE any execution
    assert not result.applied and "refused" in result.detail


# -- approve routing ------------------------------------------------------------


def test_approve_routes_a_cleanup_to_the_command_runner_and_audits_it():
    store = StateStore()
    report, sym = _evicted_report()
    record_cleanups(store, report, _NOW)
    with mock.patch(
        "steadystate.act.cleanup.subprocess.run", return_value=_proc(0, "deleted")
    ) as run:
        message, result = apply_pending(store, sym.fingerprint, "amy", _NOW)
    run.assert_called_once()
    assert result is not None and result.applied
    assert "cleaned up" in message
    assert [(a.outcome, a.actor) for a in store.audit_log(limit=5)] == [("verified", "amy")]


def test_approve_runs_a_cleanup_at_most_once():
    store = StateStore()
    report, sym = _evicted_report()
    record_cleanups(store, report, _NOW)
    with mock.patch("steadystate.act.cleanup.subprocess.run", return_value=_proc(0, "deleted")):
        first, _ = apply_pending(store, sym.fingerprint, "amy", _NOW)
        second, result2 = apply_pending(store, sym.fingerprint, "amy", _NOW)
    assert "cleaned up" in first
    assert result2 is None and "no pending remediation" in second  # claimed -> not re-runnable
