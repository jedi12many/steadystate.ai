"""AnsibleExecutor: reconcile a drifted host by re-running its playbook (--limit host).

Mocks subprocess + the verify re-check, so no real ansible runs."""

from pathlib import Path
from unittest.mock import patch

from steadystate.act import EXECUTORS, build_executor
from steadystate.act.ansible import AnsibleExecutor
from steadystate.act.base import Executor
from steadystate.act.plan import Risk
from steadystate.model import ChangeType, Drift, Provenance


def _drift(identity: str = "web01:Deploy haproxy.cfg") -> Drift:
    return Drift(
        identity=identity,
        kind="template",
        change_type=ChangeType.MODIFIED,
        provenance=Provenance(source="ansible", address=identity),
    )


def test_plan_targets_the_host_and_is_eligible():
    plan = AnsibleExecutor(playbook="site.yml", inventory="hosts.ini").plan_for(_drift())
    assert plan.eligible and plan.risk is Risk.MEDIUM
    assert plan.command == ["ansible-playbook", "--limit", "web01", "-i", "hosts.ini", "site.yml"]
    assert "web01" in plan.blast_radius
    assert "not transactional" in plan.revert.lower()  # honest: no auto-revert


def test_dry_run_does_not_apply():
    result = AnsibleExecutor(playbook="site.yml").remediate(_drift(), confirm=False)
    assert result.applied is False and "dry run" in result.detail.lower()


def test_no_playbook_refuses_to_apply(monkeypatch):
    monkeypatch.delenv("STEADYSTATE_ANSIBLE_PLAYBOOK", raising=False)
    result = AnsibleExecutor(playbook=None).remediate(_drift(), confirm=True)
    assert result.applied is False and "playbook" in result.detail.lower()


def test_apply_runs_the_playbook_and_verifies_clear():
    ex = AnsibleExecutor(playbook="site.yml", working_dir="/tmp")
    with (
        patch("steadystate.act.ansible.subprocess.run") as run,
        patch.object(AnsibleExecutor, "_still_drifting", return_value=False),
    ):
        result = ex.remediate(_drift(), confirm=True)
    run.assert_called_once()
    assert result.applied and result.verified


def test_apply_reports_unverified_when_host_still_drifts():
    ex = AnsibleExecutor(playbook="site.yml", working_dir="/tmp")
    with (
        patch("steadystate.act.ansible.subprocess.run"),
        patch.object(AnsibleExecutor, "_still_drifting", return_value=True),
    ):
        result = ex.remediate(_drift(), confirm=True)
    assert result.applied and not result.verified


def test_registered_in_executor_registry():
    assert "ansible" in EXECUTORS
    assert isinstance(build_executor("ansible", Path("x")), Executor)
