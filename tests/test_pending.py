"""Autonomy `suggest`: pending remediations recorded by scan, driven by approve/decline."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime

import pytest

from steadystate.cli import app
from steadystate.state import APPROVED, DECLINED, PENDING, PendingAction, StateStore


def _action(fp: str = "fp1", source: str = "terraform") -> PendingAction:
    return PendingAction(
        fingerprint=fp,
        source=source,
        path="/repo",
        drift_identity="aws_s3_bucket.logs",
        command="terraform apply -target aws_s3_bucket.logs -auto-approve",
    )


def _t(day: int) -> datetime:
    return datetime(2026, 1, day, 12, 0, 0, tzinfo=UTC)


# -- the store ------------------------------------------------------------------


def test_record_and_read_back_pending():
    store = StateStore()
    store.record_pending(_action(), _t(1))
    got = store.get_pending("fp1")
    assert got is not None
    assert got.status == PENDING and got.command.startswith("terraform apply")
    assert [p.fingerprint for p in store.all_pending()] == ["fp1"]


def test_decline_is_not_re_offered_on_re_scan():
    store = StateStore()
    store.record_pending(_action(), _t(1))
    store.set_pending_status("fp1", DECLINED, actor="alice")
    store.record_pending(_action(), _t(2))  # a re-scan would re-offer -- but it's declined
    assert store.get_pending("fp1").status == DECLINED
    assert store.all_pending() == []  # declined ones aren't pending


def test_re_record_preserves_original_created_at():
    store = StateStore()
    store.record_pending(_action(), _t(1))
    store.record_pending(_action(), _t(5))  # recurred
    assert store.get_pending("fp1").created_at == _t(1).isoformat()


# -- the scan -> pending -> approve/decline flow --------------------------------

# A terraform plan with one in-place update -> one eligible (MODIFIED) drift.
_PLAN = {
    "resource_changes": [
        {
            "address": "aws_s3_bucket.logs",
            "type": "aws_s3_bucket",
            "change": {"actions": ["update"], "before": {"x": 1}, "after": {"x": 2}},
        }
    ]
}


def _runner():
    return pytest.importorskip("typer.testing").CliRunner()


def _suggest_scan(tmp_path):
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps(_PLAN))
    db = tmp_path / "state.db"
    result = _runner().invoke(
        app,
        [
            "scan",
            str(plan),
            "--source",
            "terraform",
            "--autonomy",
            "suggest",
            "--state",
            str(db),
            "--to",
            "console",
        ],
    )
    assert result.exit_code == 0
    return db


def test_scan_suggest_records_an_eligible_pending_remediation(tmp_path):
    db = _suggest_scan(tmp_path)
    with StateStore(db) as store:
        pend = store.all_pending()
    assert len(pend) == 1
    assert pend[0].source == "terraform"
    assert "aws_s3_bucket.logs" in pend[0].command


def test_decline_clears_a_pending_remediation(tmp_path):
    db = _suggest_scan(tmp_path)
    with StateStore(db) as store:
        fp = store.all_pending()[0].fingerprint
    result = _runner().invoke(app, ["decline", fp, "--state", str(db)])
    assert result.exit_code == 0
    with StateStore(db) as store:
        assert store.all_pending() == []
        assert store.get_pending(fp).status == DECLINED


def test_approve_runs_the_executor_and_marks_approved(tmp_path):
    # The terraform executor has no working dir (plan file), so it honestly can't apply --
    # but the approve flow completes and the action is marked approved.
    db = _suggest_scan(tmp_path)
    with StateStore(db) as store:
        fp = store.all_pending()[0].fingerprint
    result = _runner().invoke(app, ["approve", fp, "--state", str(db)])
    assert result.exit_code == 0
    with StateStore(db) as store:
        assert store.get_pending(fp).status == APPROVED


# -- the scan -> auto-apply flow ------------------------------------------------


def _auto_scan(tmp_path, plan_obj=_PLAN, source="terraform", extra=None):
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps(plan_obj))
    db = tmp_path / "state.db"
    args = ["scan", str(plan), "--source", source, "--autonomy", "auto",
            "--state", str(db), "--to", "console"]  # fmt: skip
    return _runner().invoke(app, args + (extra or [])), db


# The _PLAN drift's fingerprint: sha256(source|identity|change_type) -- see model.Drift.
_FP = hashlib.sha256(b"terraform|aws_s3_bucket.logs|modified").hexdigest()


def test_auto_applies_an_eligible_drift_without_a_human(tmp_path):
    # auto records the eligible MODIFIED drift AND drives it through the same guardrailed
    # approval core -- so it lands APPROVED, actored "auto", with nothing left pending.
    result, db = _auto_scan(tmp_path)
    assert result.exit_code == 0
    assert "autonomy=auto" in result.stdout
    with StateStore(db) as store:
        assert store.all_pending() == []  # applied, not left pending
        action = store.get_pending(_FP)
    assert action is not None
    assert action.status == APPROVED and action.actor == "auto"


def test_auto_never_applies_a_removed_drift(tmp_path):
    # A delete is never eligible (it would destroy a live resource), so auto records nothing
    # and applies nothing -- the deterministic guardrail, not the LLM, is the floor.
    removed = {
        "resource_changes": [
            {
                "address": "aws_s3_bucket.logs",
                "type": "aws_s3_bucket",
                "change": {"actions": ["delete"], "before": {"x": 1}, "after": None},
            }
        ]
    }
    result, db = _auto_scan(tmp_path, plan_obj=removed)
    assert result.exit_code == 0
    assert "nothing eligible to apply" in result.stdout
    with StateStore(db) as store:
        assert store.all_pending() == []


def test_auto_rejects_stateless(tmp_path):
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps(_PLAN))
    result = _runner().invoke(
        app, ["scan", str(plan), "--autonomy", "auto", "--stateless", "--to", "console"]
    )
    assert result.exit_code != 0
    assert "stateless" in result.stdout.lower() or "stateless" in str(result.output).lower()
