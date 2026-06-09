"""`fix <fp>` / `run <action> <fp>` / `actions` from chat: issue a vetted, bounded remediation
against a finding, composed from its stored keys, run through the SAME approve guardrail + audit.
Covers the generic runner and the three chat verbs end to end (subprocess mocked, no kubectl)."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest import mock

from steadystate.act.execute import CATALOG_SOURCE, run_catalog_action
from steadystate.inbound.base import Command
from steadystate.state import PendingAction, StateStore
from steadystate.verbs import run_command

_NOW = datetime(2026, 6, 3, 12, 0, 0, tzinfo=UTC)
_RESTART = "kubectl rollout restart deployment/web -n prod --context east"


def _proc(returncode=0, stdout="deployment.apps/web restarted", stderr=""):
    return mock.Mock(returncode=returncode, stdout=stdout, stderr=stderr)


# -- the generic runner ---------------------------------------------------------


def _pending(command: str) -> PendingAction:
    return PendingAction(
        fingerprint="f" * 64, source=CATALOG_SOURCE, path="", drift_identity="x", command=command
    )


def test_run_catalog_action_runs_a_vetted_command_as_argv():
    with mock.patch("steadystate.act.execute.subprocess.run", return_value=_proc()) as run:
        result = run_catalog_action(_pending(_RESTART))
    argv, _ = run.call_args
    assert argv[0][:4] == ["kubectl", "rollout", "restart", "deployment/web"]  # argv, no shell
    assert result.applied and result.verified and "rollout-restart-workload" in result.detail


def test_run_catalog_action_refuses_an_unrecognized_command():
    with mock.patch("steadystate.act.execute.subprocess.run") as run:
        result = run_catalog_action(_pending("kubectl drain worker-1"))  # not a vetted shape
    run.assert_not_called()  # never executed
    assert not result.applied and "not a recognized catalog command" in result.detail


# -- the chat verbs, end to end -------------------------------------------------


def _record(path, fp: str, *, category: str, kind="Deployment", workload="web", namespace="prod"):
    with StateStore(str(path)) as store:
        store.record(
            {fp: ("high", f"{workload} is {category}")},
            _NOW,
            {
                fp: {
                    "category": category,
                    "kind": kind,
                    "workload": workload,
                    "namespace": namespace,
                }
            },
        )


def _fix(path, fp, actor="amy"):
    return run_command(Command(verb="fix", actor=actor, argument=fp), str(path))


def test_fix_applies_the_offered_action_and_audits_it(tmp_path):
    db = tmp_path / "state.db"
    fp = "a" * 64
    _record(db, fp, category="CrashLoopBackOff")  # offered fix -> rollout-restart-workload
    with mock.patch("steadystate.act.execute.subprocess.run", return_value=_proc()) as run:
        msg = _fix(db, fp)
    run.assert_called_once()
    assert "rollout-restart-workload" in msg and "restarted" in msg
    with StateStore(str(db)) as store:
        [entry] = store.audit_log(limit=5)
    assert entry.actor == "amy" and entry.outcome == "verified"


def test_fix_honestly_declines_when_no_action_is_offered(tmp_path):
    db = tmp_path / "state.db"
    fp = "b" * 64
    _record(db, fp, category="DiskFilling")  # no catalog action recovers a full disk
    with mock.patch("steadystate.act.execute.subprocess.run") as run:
        msg = _fix(db, fp)
    run.assert_not_called()
    assert "No automated fix" in msg and "escalate" in msg


def test_run_action_lets_you_pick_a_specific_vetted_action(tmp_path):
    db = tmp_path / "state.db"
    fp = "c" * 64
    _record(db, fp, category="Erroring", workload="api")
    cmd = Command(verb="run", actor="amy", argument="rollout-restart-workload", argument2=fp)
    with mock.patch("steadystate.act.execute.subprocess.run", return_value=_proc()) as run:
        msg = run_command(cmd, str(db))
    run.assert_called_once()
    assert "kubectl rollout restart deployment/api -n prod" in msg


def test_run_action_rejects_an_unknown_action(tmp_path):
    db = tmp_path / "state.db"
    fp = "d" * 64
    _record(db, fp, category="CrashLoopBackOff")
    cmd = Command(verb="run", actor="amy", argument="nuke-everything", argument2=fp)
    with mock.patch("steadystate.act.execute.subprocess.run") as run:
        msg = run_command(cmd, str(db))
    run.assert_not_called()
    assert "Unknown action 'nuke-everything'" in msg


def test_actions_lists_the_vetted_menu_with_blast_radius(tmp_path):
    msg = run_command(Command(verb="actions", actor="amy"), str(tmp_path / "state.db"))
    assert "rollout-restart-workload" in msg and "self_healing/service" in msg
    assert "reclaim-evicted-pods" in msg and "lossless/tenant" in msg
