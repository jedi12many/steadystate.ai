"""The inbound seam: signature verification, payload->Interaction, dispatch, and the registry."""

from __future__ import annotations

import hashlib
import hmac
import json
import urllib.parse
from datetime import UTC, datetime

import pytest

from steadystate.inbound import INBOUND, build_inbound
from steadystate.inbound.base import APPROVE, DECLINE, Interaction
from steadystate.inbound.server import dispatch, run_interaction
from steadystate.inbound.slack import (
    SlackInbound,
    interaction_from_payload,
    verify_slack_signature,
)
from steadystate.model import ChangeType, Drift, Provenance
from steadystate.notify.slack import format_slack_message
from steadystate.reason.alert import Alert, Severity
from steadystate.state import PendingAction, StateStore

_SECRET = "shhh"
_NOW = 1_700_000_000.0


def _sign(ts: str, body: str) -> str:
    base = f"v0:{ts}:{body}".encode()
    return "v0=" + hmac.new(_SECRET.encode(), base, hashlib.sha256).hexdigest()


def _slack_body(action_id: str, fp: str, actor: str = "bob") -> str:
    payload = {"actions": [{"action_id": action_id, "value": fp}], "user": {"username": actor}}
    return urllib.parse.urlencode({"payload": json.dumps(payload)})


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


def test_adapter_verify_reads_the_slack_headers():
    ts, body = "1700000000", "payload=%7B%7D"
    headers = {"X-Slack-Request-Timestamp": ts, "X-Slack-Signature": _sign(ts, body)}
    assert SlackInbound(_SECRET).verify(headers, body, now=_NOW)
    assert not SlackInbound(_SECRET).verify({"X-Slack-Signature": "v0=bad"}, body, now=_NOW)


# -- payload parsing ------------------------------------------------------------


def test_parse_approve_and_decline():
    assert interaction_from_payload(
        {
            "actions": [{"action_id": "steadystate_approve", "value": "fp1"}],
            "user": {"username": "amy"},
        }
    ) == Interaction(APPROVE, "fp1", "amy")
    assert interaction_from_payload(
        {"actions": [{"action_id": "steadystate_decline", "value": "fp1"}]}
    ) == Interaction(DECLINE, "fp1", "slack")  # actor defaults when absent


def test_parse_rejects_unknown_action_missing_fp_and_empty():
    assert interaction_from_payload({"actions": [{"action_id": "other", "value": "fp"}]}) is None
    assert interaction_from_payload({"actions": [{"action_id": "steadystate_approve"}]}) is None
    assert interaction_from_payload({}) is None


def test_slack_adapter_parse_decodes_the_form_body():
    got = SlackInbound(_SECRET).parse(_slack_body("steadystate_approve", "fp7", "carol"))
    assert got == Interaction(APPROVE, "fp7", "carol")
    assert SlackInbound(_SECRET).parse("not-form-data") is None


# -- the approval core dispatch -------------------------------------------------


def _pending(fp: str = "fp1") -> PendingAction:
    return PendingAction(
        fingerprint=fp, source="terraform", path="/repo", drift_identity="x", command="cmd"
    )


def test_run_interaction_decline_marks_declined(tmp_path):
    db = str(tmp_path / "s.db")
    with StateStore(db) as store:
        store.record_pending(_pending(), datetime(2026, 1, 1, tzinfo=UTC))
    msg = run_interaction(Interaction(DECLINE, "fp1", "bob"), db)
    assert "declined" in msg
    with StateStore(db) as store:
        assert store.get_pending("fp1").status == "declined"


def test_run_interaction_approve_routes_to_core(monkeypatch, tmp_path):
    seen: dict = {}

    def fake_apply(store, fingerprint, actor):
        seen["fp"], seen["actor"] = fingerprint, actor
        return "applied!", None

    monkeypatch.setattr("steadystate.inbound.server.apply_pending", fake_apply)
    msg = run_interaction(Interaction(APPROVE, "fp9", "amy"), str(tmp_path / "s.db"))
    assert msg == "applied!" and seen == {"fp": "fp9", "actor": "amy"}


# -- the generic dispatch shell (verify -> handshake -> parse -> run) ------------


class _FakeAdapter:
    """A minimal adapter to exercise dispatch's control flow without a real provider."""

    name = "fake"
    content_type = "application/json"

    def __init__(self, ok=True, handshake_reply=None, interaction=None):
        self._ok, self._handshake, self._interaction = ok, handshake_reply, interaction

    def ready(self):
        return None

    def verify(self, headers, body):
        return self._ok

    def handshake(self, body):
        return self._handshake

    def parse(self, body):
        return self._interaction

    def respond(self, message):
        return message.encode()


def test_dispatch_401s_a_forged_request_before_parsing():
    status, body = dispatch(_FakeAdapter(ok=False), {}, "anything", ":memory:")
    assert status == 401 and body == b""


def test_dispatch_answers_a_handshake_without_touching_the_core():
    # Discord's PING -> PONG: a verified non-interaction reply, returned as-is.
    status, body = dispatch(_FakeAdapter(handshake_reply=b'{"type":1}'), {}, "ping", ":memory:")
    assert status == 200 and body == b'{"type":1}'


def test_dispatch_runs_a_parsed_interaction(monkeypatch):
    monkeypatch.setattr(
        "steadystate.inbound.server.run_interaction", lambda interaction, path: "done"
    )
    adapter = _FakeAdapter(interaction=Interaction(APPROVE, "fp1", "x"))
    status, body = dispatch(adapter, {}, "body", ":memory:")
    assert status == 200 and body == b"done"


def test_dispatch_noops_an_unrecognized_payload():
    status, body = dispatch(_FakeAdapter(interaction=None), {}, "body", ":memory:")
    assert status == 200 and body == b"Nothing to do."


# -- the registry ---------------------------------------------------------------


def test_registry_builds_slack_and_rejects_unknown():
    assert isinstance(build_inbound("slack"), SlackInbound)
    assert "slack" in INBOUND
    with pytest.raises(ValueError, match="unknown inbound channel"):
        build_inbound("nope")


def test_slack_adapter_not_ready_without_a_secret(monkeypatch):
    monkeypatch.delenv("STEADYSTATE_SLACK_SIGNING_SECRET", raising=False)
    assert SlackInbound().ready() is not None
    assert SlackInbound("a-secret").ready() is None


# -- the Slack surface carries the buttons (outbound side) ----------------------


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
