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


def test_resource_in_both_drift_and_changes_is_deduped_to_one():
    # A real `terraform plan` (with refresh) lists a drifted-then-reconciled resource in
    # BOTH sections. It's one finding -- dedupe by address, and keep the resource_changes
    # view (declared = config, observed = reality), not the inverted resource_drift view.
    plan = {
        "resource_drift": [
            {
                "address": "google_compute_firewall.ssh",
                "type": "google_compute_firewall",
                "name": "ssh",
                "change": {
                    "actions": ["update"],
                    "before": {"source_ranges": ["35.235.240.0/20"]},  # last-applied state
                    "after": {"source_ranges": ["0.0.0.0/0"]},  # current reality
                },
            },
        ],
        "resource_changes": [
            {
                "address": "google_compute_firewall.ssh",
                "type": "google_compute_firewall",
                "name": "ssh",
                "change": {
                    "actions": ["update"],
                    "before": {"source_ranges": ["0.0.0.0/0"]},  # current reality
                    "after": {"source_ranges": ["35.235.240.0/20"]},  # declared config
                },
            },
        ],
    }
    drifts = drifts_from_plan_json(plan)
    assert len(drifts) == 1  # one finding, not a double-count
    drift = drifts[0]
    assert drift.identity == "google_compute_firewall.ssh"
    # resource_changes wins: declared = config, observed = the opened-to-world reality.
    assert drift.declared == {"source_ranges": ["35.235.240.0/20"]}
    assert drift.observed == {"source_ranges": ["0.0.0.0/0"]}
    assert drift.actionable is True  # from resource_changes: the plan can reconcile it


def test_resource_changes_drift_is_actionable():
    plan = {
        "resource_changes": [
            {
                "address": "aws_s3_bucket.logs",
                "type": "aws_s3_bucket",
                "name": "logs",
                "change": {"actions": ["update"], "before": {"x": 1}, "after": {"x": 2}},
            },
        ],
    }
    assert drifts_from_plan_json(plan)[0].actionable is True


def test_resource_drift_only_is_not_actionable():
    # Reality moved (refresh detected it) but there's no plan to reconcile -> informational.
    plan = {
        "resource_drift": [
            {
                "address": "google_compute_instance.vm",
                "type": "google_compute_instance",
                "name": "vm",
                "change": {"actions": ["update"], "before": {"x": 1}, "after": {"x": 2}},
            },
        ],
    }
    assert drifts_from_plan_json(plan)[0].actionable is False
