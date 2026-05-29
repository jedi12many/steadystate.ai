from steadystate.act.plan import Risk, assess
from steadystate.act.terraform import TerraformExecutor
from steadystate.model import ChangeType, Drift, Provenance


def _drift(change_type: ChangeType) -> Drift:
    return Drift(
        identity="aws_s3_bucket.logs",
        kind="aws_s3_bucket",
        change_type=change_type,
        provenance=Provenance(source="terraform", address="aws_s3_bucket.logs"),
    )


def test_removed_is_not_auto_eligible_and_high_risk():
    plan = assess(_drift(ChangeType.REMOVED))
    assert plan.eligible is False
    assert plan.risk is Risk.HIGH


def test_added_is_eligible_low_risk():
    plan = assess(_drift(ChangeType.ADDED))
    assert plan.eligible is True
    assert plan.risk is Risk.LOW


def test_modified_is_eligible_medium_and_targets_the_address():
    plan = assess(_drift(ChangeType.MODIFIED))
    assert plan.eligible is True
    assert plan.risk is Risk.MEDIUM
    assert "aws_s3_bucket.logs" in plan.command


def test_executor_refuses_ineligible_even_with_confirm():
    result = TerraformExecutor().remediate(_drift(ChangeType.REMOVED), confirm=True)
    assert result.applied is False
    assert "Refused" in result.detail


def test_executor_dry_run_does_not_apply():
    result = TerraformExecutor().remediate(_drift(ChangeType.MODIFIED), confirm=False)
    assert result.applied is False
    assert "Dry run" in result.detail
