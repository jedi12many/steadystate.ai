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
    monkeypatch.setattr("steadystate.act.terraform.time.sleep", lambda *_: None)  # no real waits
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


# --- can_run_unattended: eligible (human-approvable) vs. the bound (auto-runnable) ---


def test_can_run_unattended_separates_approvable_from_auto():
    from steadystate.act.bounds import DEFAULT_BOUND, bound_from_env
    from steadystate.act.plan import can_run_unattended

    removed = assess(_drift(ChangeType.REMOVED))
    modified = assess(_drift(ChangeType.MODIFIED))
    # REMOVED isn't even approvable -> never unattended.
    assert can_run_unattended(removed, DEFAULT_BOUND) is False
    # MODIFIED is approvable (eligible) but recoverable -> held from auto under the default bound...
    assert modified.eligible is True
    assert can_run_unattended(modified, DEFAULT_BOUND) is False
    # ...and runs unattended once the operator widens the bound to allow it.
    assert can_run_unattended(modified, bound_from_env("recoverable=service")) is True


def test_can_run_unattended_falls_back_to_eligible_without_an_envelope():
    from steadystate.act.plan import RemediationPlan, Risk, can_run_unattended

    # An un-migrated executor (no envelope) keeps its prior behavior: eligible -> may auto-run.
    no_envelope = RemediationPlan("h", eligible=True, risk=Risk.MEDIUM, reason="", envelope=None)
    assert can_run_unattended(no_envelope) is True
    ineligible = RemediationPlan("h", eligible=False, risk=Risk.HIGH, reason="", envelope=None)
    assert can_run_unattended(ineligible) is False


# -- verify retry: cloud settings are eventually consistent ---------------------


def test_verify_retries_through_propagation_lag(monkeypatch):
    # The apply took, but the first re-checks still read the pre-apply value (cloud lag);
    # the drift clears on a later attempt -> not still drifting.
    monkeypatch.setattr("steadystate.act.terraform.time.sleep", lambda *_: None)
    target = _drift(ChangeType.MODIFIED, "google_storage_bucket.sandbox")
    other = _drift(ChangeType.MODIFIED, "x.other")
    results = iter([[target], [target], [other]])  # drifts twice, then clears
    assert TerraformExecutor._persists(lambda: next(results), target) is False


def test_verify_reports_genuinely_persistent_drift(monkeypatch):
    # A drift that survives every re-check (e.g. a provider that merged a set) stays not-verified.
    monkeypatch.setattr("steadystate.act.terraform.time.sleep", lambda *_: None)
    target = _drift(ChangeType.MODIFIED, "google_compute_firewall.ssh")
    assert TerraformExecutor._persists(lambda: [target], target) is True


def test_verify_clears_immediately_without_sleeping(monkeypatch):
    slept: list[float] = []
    monkeypatch.setattr("steadystate.act.terraform.time.sleep", lambda s: slept.append(s))
    target = _drift(ChangeType.MODIFIED)
    assert TerraformExecutor._persists(lambda: [], target) is False
    assert slept == []  # cleared on the first check -> never waits


def test_verify_ignores_non_actionable_refresh_drift(monkeypatch):
    # After a clean apply a full plan can still list the resource as refresh-only drift
    # (actionable=False -- terraform has nothing to apply). That must NOT count as still-drifting.
    monkeypatch.setattr("steadystate.act.terraform.time.sleep", lambda *_: None)
    target = _drift(ChangeType.MODIFIED, "google_storage_bucket.sandbox")
    noise = Drift(
        identity=target.identity,
        kind="google_storage_bucket",
        change_type=ChangeType.MODIFIED,
        provenance=Provenance(source="terraform", address=target.identity),
        actionable=False,
    )
    assert TerraformExecutor._persists(lambda: [noise], target) is False
