"""TerraformExecutor: the one path that mutates real infra (snapshot -> targeted
apply -> re-plan verify). Pure mocks -- no real terraform, no network.

We patch subprocess AS IMPORTED in act/terraform.py and the drift re-collection
the verify step uses (sources.terraform.TerraformSource), so nothing live runs.
"""

from steadystate.act.plan import Risk, assess
from steadystate.act.terraform import TerraformExecutor
from steadystate.model import ChangeType, Drift, Provenance


def _drift(change_type: ChangeType, identity: str = "aws_s3_bucket.logs") -> Drift:
    return Drift(
        identity=identity,
        kind="aws_s3_bucket",
        change_type=change_type,
        provenance=Provenance(source="terraform", address=identity),
        declared={"acl": "private"},
        observed={"acl": "public-read"},
    )


class _FakeCompleted:
    """Stand-in for subprocess.CompletedProcess: only .stdout is read."""

    def __init__(self, stdout: str = "") -> None:
        self.stdout = stdout


def _patch_subprocess(monkeypatch, calls, snapshot_json='{"format_version": "1.0"}'):
    """Record every terraform argv in order; feed `show -json` valid JSON on stdout.

    Order matters: _snapshot() runs `plan` then `show` BEFORE _run() invokes the
    apply, so the recorded sequence proves snapshot-before-apply.
    """

    def fake_run(argv, *args, **kwargs):
        calls.append(list(argv))
        # only `terraform show -json` has its stdout parsed (json.loads)
        if "show" in argv:
            return _FakeCompleted(stdout=snapshot_json)
        return _FakeCompleted(stdout="")

    # patch the exact attribute the module uses
    monkeypatch.setattr("steadystate.act.terraform.subprocess.run", fake_run)


def _patch_residual(monkeypatch, residual_drifts):
    """Patch the TerraformSource that _still_drifting re-collects with."""

    class _FakeSource:
        def __init__(self, *args, **kwargs):
            pass

        def collect_drift(self):
            return list(residual_drifts)

    # _still_drifting does `from ..sources.terraform import TerraformSource`
    # at call time, so patching the attribute on that module is what binds.
    monkeypatch.setattr("steadystate.sources.terraform.TerraformSource", _FakeSource)


def test_ineligible_drift_never_applies(monkeypatch):
    # A REMOVED drift would destroy a live resource -> never auto-eligible.
    calls: list[list[str]] = []
    _patch_subprocess(monkeypatch, calls)

    ex = TerraformExecutor(working_dir="/tmp/tf")
    result = ex.remediate(_drift(ChangeType.REMOVED), confirm=True)

    assert result.plan.eligible is False
    assert result.applied is False
    assert "Refused" in result.detail
    assert result.verified is False
    assert result.snapshot is None
    assert calls == []  # nothing live ran


def test_eligible_but_no_confirm_is_dry_run(monkeypatch):
    # Eligible drift, but confirm defaults False -> dry run, nothing executes.
    calls: list[list[str]] = []
    _patch_subprocess(monkeypatch, calls)

    ex = TerraformExecutor(working_dir="/tmp/tf")
    result = ex.remediate(_drift(ChangeType.MODIFIED))  # confirm=False default

    assert result.plan.eligible is True
    assert result.applied is False
    assert "Dry run" in result.detail
    assert result.snapshot is None
    assert calls == []


def test_apply_runs_expected_argv_after_snapshot(monkeypatch):
    # Eligible + confirm=True + working_dir set: snapshot first, then targeted apply.
    calls: list[list[str]] = []
    _patch_subprocess(monkeypatch, calls)
    _patch_residual(monkeypatch, [])  # drift cleared on re-check

    drift = _drift(ChangeType.MODIFIED)
    ex = TerraformExecutor(working_dir="/tmp/tf")
    result = ex.remediate(drift, confirm=True)

    assert result.applied is True

    # The snapshot (plan + show) is captured BEFORE the apply runs.
    apply_calls = [c for c in calls if "apply" in c]
    assert len(apply_calls) == 1
    apply_argv = apply_calls[0]
    apply_index = calls.index(apply_argv)
    assert any("plan" in c for c in calls[:apply_index])  # snapshot plan precedes apply
    assert any("show" in c for c in calls[:apply_index])  # snapshot show precedes apply

    # The apply is the exact targeted, auto-approved remediation argv.
    assert apply_argv == [
        "terraform",
        "apply",
        "-target",
        drift.identity,
        "-auto-approve",
    ]


def test_snapshot_captured_before_apply(monkeypatch):
    # The pre-change snapshot is the parsed `terraform show -json` document,
    # recorded on the result for the revert path.
    calls: list[list[str]] = []
    _patch_subprocess(monkeypatch, calls, snapshot_json='{"format_version": "1.0", "k": 1}')
    _patch_residual(monkeypatch, [])

    ex = TerraformExecutor(working_dir="/tmp/tf")
    result = ex.remediate(_drift(ChangeType.MODIFIED), confirm=True)

    assert result.snapshot == {"format_version": "1.0", "k": 1}


def test_verified_true_when_residual_drift_clears(monkeypatch):
    # Post-apply re-collection no longer contains the identity -> verified True.
    calls: list[list[str]] = []
    _patch_subprocess(monkeypatch, calls)
    _patch_residual(monkeypatch, [])  # nothing left

    ex = TerraformExecutor(working_dir="/tmp/tf")
    result = ex.remediate(_drift(ChangeType.MODIFIED), confirm=True)

    assert result.applied is True
    assert result.verified is True


def test_verified_false_when_drift_still_present(monkeypatch):
    # Post-apply re-collection STILL contains the identity -> applied but not verified.
    calls: list[list[str]] = []
    _patch_subprocess(monkeypatch, calls)
    drift = _drift(ChangeType.MODIFIED)
    # residual still has a drift with the SAME identity (different object instance)
    _patch_residual(monkeypatch, [_drift(ChangeType.MODIFIED, identity=drift.identity)])

    ex = TerraformExecutor(working_dir="/tmp/tf")
    result = ex.remediate(drift, confirm=True)

    assert result.applied is True
    assert result.verified is False


def test_no_working_dir_refuses_to_apply(monkeypatch):
    # Eligible + confirm=True but no working dir -> cannot apply; nothing runs.
    calls: list[list[str]] = []
    _patch_subprocess(monkeypatch, calls)

    ex = TerraformExecutor()  # working_dir=None
    result = ex.remediate(_drift(ChangeType.MODIFIED), confirm=True)

    assert result.applied is False
    assert result.snapshot is None
    assert calls == []


# --- plan-layer (assess) guarantees, preserved from the original test_executor.py ---


def test_assess_removed_not_eligible_high_risk():
    plan = assess(_drift(ChangeType.REMOVED))
    assert plan.eligible is False
    assert plan.risk is Risk.HIGH


def test_assess_added_eligible_low_risk():
    plan = assess(_drift(ChangeType.ADDED))
    assert plan.eligible is True
    assert plan.risk is Risk.LOW


def test_assess_modified_eligible_medium_and_targets_address():
    plan = assess(_drift(ChangeType.MODIFIED))
    assert plan.eligible is True
    assert plan.risk is Risk.MEDIUM
    assert "aws_s3_bucket.logs" in plan.command
