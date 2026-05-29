from steadystate.model import ChangeType
from steadystate.sources.terraform import drifts_from_plan_json


def test_parses_drift_and_changes_skipping_noop():
    plan = {
        "resource_drift": [
            {
                "address": "aws_s3_bucket.logs",
                "type": "aws_s3_bucket",
                "name": "logs",
                "change": {
                    "actions": ["update"],
                    "before": {"acl": "private"},
                    "after": {"acl": "public-read"},
                },
            },
        ],
        "resource_changes": [
            {
                "address": "aws_security_group.web",
                "type": "aws_security_group",
                "name": "web",
                "change": {"actions": ["delete"], "before": {"id": "sg-1"}, "after": None},
            },
            {
                "address": "aws_instance.noop",
                "type": "aws_instance",
                "name": "noop",
                "change": {"actions": ["no-op"]},
            },
        ],
    }
    drifts = drifts_from_plan_json(plan)
    assert len(drifts) == 2  # no-op excluded

    by_id = {d.identity: d for d in drifts}
    assert by_id["aws_s3_bucket.logs"].change_type is ChangeType.MODIFIED
    assert by_id["aws_security_group.web"].change_type is ChangeType.REMOVED
