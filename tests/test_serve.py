"""Slack approval listener: signature verification, payload parsing, dispatch, + buttons."""

from __future__ import annotations

import hashlib
import hmac
from datetime import UTC, datetime

from steadystate.model import ChangeType, Drift, Provenance
from steadystate.notify.slack import format_slack_message
from steadystate.reason.alert import Alert, Severity
from steadystate.serve import handle_interaction, parse_interaction, verify_slack_signature
from steadystate.state import PendingAction, StateStore

_SECRET = "shhh"
_NOW = 1_700_000_000.0


def _sign(ts: str, body: str) -> str:
    base = f"v0:{ts}:{body}".encode()
    return "v0=" + hmac.new(_SECRET.encode(), base, hashlib.sha256).hexdigest()


# -- signature verification (the security boundary) -----------------------------


def test_valid_signature_passes():
    ts, body = "1700000000", "payload=%7B%7D"
    assert verify_slack_signature(_SECRET, ts, body, _sign(ts, body), now=_NOW)


def test_bad_signature_fails():
    assert not verify_slack_signature(_SECRET, "1700000000", "x=1", "v0=deadbeef", now=_NOW)


def test_stale_timestamp_fails():
    ts, body = "1700000000", "x=1"
    assert not verify_slack_signature(_SECRET, ts, body, _sign(ts, body), now=_NOW + 9999)


def test_non_numeric_timestamp_fails():
    assert not verify_slack_signature(_SECRET, "nope", "x", "v0=x", now=_NOW)


# -- payload parsing ------------------------------------------------------------


def test_parse_approve_and_decline():
    assert parse_interaction(
        {"actions": [{"action_id": "steadystate_approve", "value": "fp1"}]}
    ) == (
        "approve",
        "fp1",
    )
    assert parse_interaction(
        {"actions": [{"action_id": "steadystate_decline", "value": "fp1"}]}
    ) == (
        "decline",
        "fp1",
    )


def test_parse_rejects_unknown_action_missing_fp_and_empty():
    assert parse_interaction({"actions": [{"action_id": "other", "value": "fp"}]}) is None
    assert parse_interaction({"actions": [{"action_id": "steadystate_approve"}]}) is None
    assert parse_interaction({}) is None


# -- dispatch -------------------------------------------------------------------


def _pending(fp: str = "fp1") -> PendingAction:
    return PendingAction(
        fingerprint=fp, source="terraform", path="/repo", drift_identity="x", command="cmd"
    )


def test_handle_decline_marks_declined(tmp_path):
    db = str(tmp_path / "s.db")
    with StateStore(db) as store:
        store.record_pending(_pending(), datetime(2026, 1, 1, tzinfo=UTC))
    msg = handle_interaction(
        {
            "actions": [{"action_id": "steadystate_decline", "value": "fp1"}],
            "user": {"username": "bob"},
        },
        db,
    )
    assert "declined" in msg
    with StateStore(db) as store:
        assert store.get_pending("fp1").status == "declined"


def test_handle_approve_routes_to_core(monkeypatch, tmp_path):
    seen: dict = {}

    def fake_apply(store, fingerprint, actor):
        seen["fp"], seen["actor"] = fingerprint, actor
        return "applied!", None

    monkeypatch.setattr("steadystate.serve.apply_pending", fake_apply)
    msg = handle_interaction(
        {
            "actions": [{"action_id": "steadystate_approve", "value": "fp9"}],
            "user": {"username": "amy"},
        },
        str(tmp_path / "s.db"),
    )
    assert msg == "applied!" and seen == {"fp": "fp9", "actor": "amy"}


def test_handle_non_steadystate_payload_is_a_noop():
    assert handle_interaction({"actions": []}, ":memory:") == "Nothing to do."


# -- the Slack surface carries the buttons --------------------------------------


def _drift_alert() -> Alert:
    drift = Drift(
        identity="aws_s3_bucket.logs",
        kind="aws_s3_bucket",
        change_type=ChangeType.MODIFIED,
        provenance=Provenance(source="terraform"),
    )
    return Alert(title="t", severity=Severity.HIGH, drifts=[drift], why_it_matters="w")


def test_slack_message_carries_approve_decline_buttons():
    msg = format_slack_message(_drift_alert())
    actions = next(b for b in msg["blocks"] if b["type"] == "actions")
    assert {e["action_id"] for e in actions["elements"]} == {
        "steadystate_approve",
        "steadystate_decline",
    }
    fingerprint = _drift_alert().drifts[0].fingerprint
    assert all(e["value"] == fingerprint for e in actions["elements"])


def test_slack_message_has_no_buttons_without_a_fingerprint():
    bare = Alert(title="t", severity=Severity.LOW, drifts=[], why_it_matters="w")
    assert "blocks" not in format_slack_message(bare)
