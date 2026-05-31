"""The inbound seam: signature verification, payload->Command, dispatch, and the registry."""

from __future__ import annotations

import hashlib
import hmac
import json
import urllib.parse
from datetime import UTC, datetime

import pytest

from steadystate.inbound import INBOUND, build_inbound
from steadystate.inbound.base import (
    APPROVE,
    COST,
    DECLINE,
    HELP,
    PENDING,
    PROBE,
    Command,
    command_from_text,
    render_help,
)
from steadystate.inbound.server import dispatch, run_command
from steadystate.inbound.slack import (
    SlackInbound,
    command_from_payload,
    verify_slack_signature,
)
from steadystate.model import ChangeType, Drift, Provenance
from steadystate.notify.slack import format_slack_message
from steadystate.reason.alert import Alert, Layer, Severity
from steadystate.state import PendingAction, StateStore

_SECRET = "shhh"
_NOW = 1_700_000_000.0


def _sign(ts: str, body: str) -> str:
    base = f"v0:{ts}:{body}".encode()
    return "v0=" + hmac.new(_SECRET.encode(), base, hashlib.sha256).hexdigest()


def _slack_button(action_id: str, fp: str, actor: str = "bob") -> str:
    payload = {"actions": [{"action_id": action_id, "value": fp}], "user": {"username": actor}}
    return urllib.parse.urlencode({"payload": json.dumps(payload)})


def _slack_slash(text: str, actor: str = "carol") -> str:
    return urllib.parse.urlencode({"command": "/steadystate", "text": text, "user_name": actor})


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


# -- the shared text grammar (Teams @mention, Slack slash) ----------------------


def test_text_grammar_parses_act_and_readonly_verbs():
    assert command_from_text("approve fp7", "amy") == Command(APPROVE, "amy", "fp7")
    assert command_from_text("decline fp7", "amy") == Command(DECLINE, "amy", "fp7")
    assert command_from_text("help", "amy") == Command(HELP, "amy")
    assert command_from_text("pending", "amy") == Command(PENDING, "amy")
    assert command_from_text("probe prod-k8s", "amy") == Command(PROBE, "amy", "prod-k8s")
    assert command_from_text("cost", "amy") == Command(COST, "amy")  # optional arg absent
    assert command_from_text("cost week", "amy") == Command(COST, "amy", "week")  # optional period


def test_text_grammar_parses_the_probe_unmute_flag():
    assert command_from_text("probe prod unmute", "amy") == Command(
        PROBE, "amy", "prod", bypass=True
    )
    assert command_from_text("probe prod --unmute", "amy") == Command(
        PROBE, "amy", "prod", bypass=True
    )
    assert command_from_text("probe prod", "amy") == Command(PROBE, "amy", "prod", bypass=False)


def test_text_grammar_is_case_insensitive_and_skips_leading_noise():
    assert command_from_text("hey  PENDING please", "amy") == Command(PENDING, "amy")


def test_text_grammar_needs_a_fingerprint_for_act_verbs_and_ignores_unknowns():
    assert command_from_text("approve", "amy") is None  # no fingerprint -> not actionable
    assert command_from_text("", "amy") is None
    assert command_from_text("status now", "amy") is None  # unknown verb


def test_render_help_lists_every_command():
    text = render_help()
    for verb in (HELP, PENDING, PROBE, COST, APPROVE, DECLINE):
        assert verb in text


# -- Slack payload parsing (buttons + slash) ------------------------------------


def test_parse_approve_and_decline_buttons():
    assert command_from_payload(
        {
            "actions": [{"action_id": "steadystate_approve", "value": "fp1"}],
            "user": {"username": "amy"},
        }
    ) == Command(APPROVE, "amy", "fp1")
    assert command_from_payload(
        {"actions": [{"action_id": "steadystate_decline", "value": "fp1"}]}
    ) == Command(DECLINE, "slack", "fp1")  # actor defaults when absent


def test_parse_rejects_unknown_action_missing_fp_and_empty():
    assert command_from_payload({"actions": [{"action_id": "other", "value": "fp"}]}) is None
    assert command_from_payload({"actions": [{"action_id": "steadystate_approve"}]}) is None
    assert command_from_payload({}) is None


def test_slack_adapter_parse_decodes_a_button_body():
    got = SlackInbound(_SECRET).parse(_slack_button("steadystate_approve", "fp7", "carol"))
    assert got == Command(APPROVE, "carol", "fp7")
    assert SlackInbound(_SECRET).parse("not-form-data") is None


def test_slack_adapter_parse_handles_a_slash_command():
    assert SlackInbound(_SECRET).parse(_slack_slash("help")) == Command(HELP, "carol")
    assert SlackInbound(_SECRET).parse(_slack_slash("pending", "dora")) == Command(PENDING, "dora")
    assert SlackInbound(_SECRET).parse(_slack_slash("approve fp3")) == Command(
        APPROVE, "carol", "fp3"
    )


# -- the command core dispatch --------------------------------------------------


def _pending(fp: str = "fp1") -> PendingAction:
    return PendingAction(
        fingerprint=fp, source="terraform", path="/repo", drift_identity="x", command="cmd"
    )


def test_run_command_decline_marks_declined(tmp_path):
    db = str(tmp_path / "s.db")
    with StateStore(db) as store:
        store.record_pending(_pending(), datetime(2026, 1, 1, tzinfo=UTC))
    msg = run_command(Command(DECLINE, "bob", "fp1"), db)
    assert "declined" in msg
    with StateStore(db) as store:
        assert store.get_pending("fp1").status == "declined"


def test_run_command_approve_routes_to_core(monkeypatch, tmp_path):
    seen: dict = {}

    def fake_apply(store, fingerprint, actor):
        seen["fp"], seen["actor"] = fingerprint, actor
        return "applied!", None

    monkeypatch.setattr("steadystate.inbound.server.apply_pending", fake_apply)
    msg = run_command(Command(APPROVE, "amy", "fp9"), str(tmp_path / "s.db"))
    assert msg == "applied!" and seen == {"fp": "fp9", "actor": "amy"}


def test_run_command_help_lists_commands_without_touching_state():
    # No state path is read: help is pure self-documentation.
    msg = run_command(Command(HELP, "amy"), "/nonexistent/never-opened.db")
    assert HELP in msg and PENDING in msg and APPROVE in msg


def test_run_command_pending_lists_open_remediations(tmp_path):
    db = str(tmp_path / "s.db")
    with StateStore(db) as store:
        store.record_pending(_pending("fpA"), datetime(2026, 1, 1, tzinfo=UTC))
        store.record_pending(_pending("fpB"), datetime(2026, 1, 1, tzinfo=UTC))
    msg = run_command(Command(PENDING, "amy"), db)
    assert "fpA" in msg and "fpB" in msg and "2 remediation" in msg


def test_run_command_pending_says_so_when_empty(tmp_path):
    msg = run_command(Command(PENDING, "amy"), str(tmp_path / "s.db"))
    assert "No remediations" in msg


# -- probe (Summon): resolve a named target -> run the engine -> summarize ------


def _targets_file(tmp_path, data: dict) -> str:
    path = tmp_path / "targets.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return str(path)


def _report_with_one_alert() -> object:
    from steadystate.reason.report import Report

    alert = Alert(
        title="web is Degraded",
        severity=Severity.HIGH,
        drifts=[],
        why_it_matters="0/3 pods available",
        layer=Layer.ALERT,
    )
    return Report(items=[alert])


def test_run_command_probe_resolves_and_summarizes(monkeypatch, tmp_path):
    monkeypatch.setenv(
        "STEADYSTATE_TARGETS",
        _targets_file(tmp_path, {"prod": {"source": "argocd", "path": "/x", "label": "prod"}}),
    )
    # Stub the engine: this test is about the wiring (resolve -> run -> summarize), not a real scan.
    monkeypatch.setattr(
        "steadystate.inbound.server.build_report", lambda *a, **k: _report_with_one_alert()
    )
    msg = run_command(Command(PROBE, "amy", "prod"), ":memory:")
    assert "prod: 1 alert" in msg and "web is Degraded" in msg and "HIGH" in msg


def test_run_command_probe_unknown_target_lists_the_known_ones(monkeypatch, tmp_path):
    monkeypatch.setenv(
        "STEADYSTATE_TARGETS",
        _targets_file(tmp_path, {"prod": {"source": "argocd", "path": "/x"}}),
    )
    msg = run_command(Command(PROBE, "amy", "nope"), ":memory:")
    assert "Unknown target 'nope'" in msg and "prod" in msg


def test_run_command_probe_with_no_targets_configured(monkeypatch):
    monkeypatch.delenv("STEADYSTATE_TARGETS", raising=False)
    assert "No targets configured" in run_command(Command(PROBE, "amy", "prod"), ":memory:")


def test_run_command_probe_honors_mutes_and_unmute_bypasses(tmp_path, monkeypatch):
    # A terraform target with one (security-relevant) drift -- read from a plan.json, no subprocess.
    from datetime import UTC, datetime

    from steadystate.engine import build_report
    from steadystate.reconcile_state import _fingerprints
    from steadystate.state import StateStore

    plan = tmp_path / "plan.json"
    plan.write_text(
        json.dumps(
            {
                "resource_changes": [
                    {
                        "address": "aws_s3_bucket.logs",
                        "type": "aws_s3_bucket",
                        "name": "logs",
                        "change": {
                            "actions": ["update"],
                            "before": {"acl": "private"},
                            "after": {"acl": "public-read"},
                        },
                    }
                ]
            }
        )
    )
    monkeypatch.setenv(
        "STEADYSTATE_TARGETS",
        _targets_file(
            tmp_path, {"demo": {"source": "terraform", "path": str(plan), "label": "demo"}}
        ),
    )
    db = str(tmp_path / "s.db")

    # before mute: the drift surfaces
    assert "1 alert" in run_command(Command(PROBE, "me", "demo"), db)

    # mute its fingerprint in the same store the listener uses
    fp = _fingerprints(build_report("terraform", plan, label="demo").alerts[0])[0]
    with StateStore(db) as store:
        store.mute(fp, None, "me", datetime.now(UTC))

    # after mute: honored by default, but transparently (count shown, never silent)
    muted = run_command(Command(PROBE, "me", "demo"), db)
    assert "clean except 1 muted" in muted and "unmute" in muted

    # unmute bypasses suppression for this run
    assert "1 alert" in run_command(Command(PROBE, "me", "demo", bypass=True), db)


def test_run_command_probe_reports_an_engine_failure_without_crashing(monkeypatch, tmp_path):
    monkeypatch.setenv(
        "STEADYSTATE_TARGETS",
        _targets_file(tmp_path, {"prod": {"source": "argocd", "path": "/missing.json"}}),
    )

    def boom(*a, **k):
        raise ValueError("source blew up")

    monkeypatch.setattr("steadystate.inbound.server.build_report", boom)
    assert "Probe of 'prod' failed: source blew up" in run_command(
        Command(PROBE, "amy", "prod"), ":memory:"
    )


def test_run_command_probe_appends_a_spend_footer(monkeypatch, tmp_path):
    from steadystate.reason.cost import LlmCall

    report = _report_with_one_alert()
    report.llm_calls = [
        LlmCall("correlate", "anthropic", "claude-sonnet-4-5", input_tokens=1000, output_tokens=100)
    ]
    monkeypatch.setenv(
        "STEADYSTATE_TARGETS",
        _targets_file(tmp_path, {"prod": {"source": "argocd", "path": "/x", "label": "prod"}}),
    )
    monkeypatch.setattr("steadystate.inbound.server.build_report", lambda *a, **k: report)
    msg = run_command(Command(PROBE, "amy", "prod"), ":memory:")
    assert "prod: 1 alert" in msg and "LLM: 1 call(s)" in msg  # the summon shows what it cost


def test_run_command_probe_shows_the_fingerprint_to_act_on(monkeypatch, tmp_path):
    from steadystate.reason.report import Report

    drift = Drift(
        identity="aws_s3_bucket.logs",
        kind="aws_s3_bucket",
        change_type=ChangeType.MODIFIED,
        provenance=Provenance(source="terraform"),
    )
    alert = Alert(
        title="bucket drifted",
        severity=Severity.HIGH,
        drifts=[drift],
        why_it_matters="x",
        layer=Layer.ALERT,
    )
    monkeypatch.setenv(
        "STEADYSTATE_TARGETS",
        _targets_file(tmp_path, {"prod": {"source": "terraform", "path": "/x", "label": "prod"}}),
    )
    monkeypatch.setattr(
        "steadystate.inbound.server.build_report", lambda *a, **k: Report(items=[alert])
    )
    msg = run_command(Command(PROBE, "amy", "prod"), ":memory:")
    # the fingerprint is shown so a benign finding can be `mute`d
    assert f"fp {drift.fingerprint}" in msg


# -- cost (chat view of `steadystate cost`) -------------------------------------


def _record_calls(db: str) -> None:
    from datetime import UTC, datetime, timedelta

    from steadystate.reason.cost import LlmCall

    now = datetime.now(UTC)
    with StateStore(db) as store:
        store.record_llm_call(
            LlmCall("correlate", "anthropic", "claude-sonnet-4-5", input_tokens=12000), now
        )
        store.record_llm_call(
            LlmCall("analyze", "anthropic", "claude-opus-4-8", input_tokens=5000),
            now - timedelta(days=1),
        )


def test_run_command_cost_rolls_up_by_caller(tmp_path):
    db = str(tmp_path / "s.db")
    _record_calls(db)
    msg = run_command(Command(COST, "amy"), db)
    assert "LLM spend (all)" in msg and "correlate" in msg and "analyze" in msg


def test_run_command_cost_day_shows_the_trend(tmp_path):
    db = str(tmp_path / "s.db")
    _record_calls(db)
    msg = run_command(Command(COST, "amy", "day"), db)
    assert "by day" in msg and msg.count("~$") >= 2  # a total + at least one day row


def test_run_command_cost_says_so_when_nothing_recorded(tmp_path):
    assert "No spend recorded" in run_command(Command(COST, "amy"), str(tmp_path / "empty.db"))


# -- the generic dispatch shell (verify -> handshake -> parse -> run) ------------


class _FakeAdapter:
    """A minimal adapter to exercise dispatch's control flow without a real provider."""

    name = "fake"
    content_type = "application/json"

    def __init__(self, ok=True, handshake_reply=None, command=None):
        self._ok, self._handshake, self._command = ok, handshake_reply, command

    def ready(self):
        return None

    def verify(self, headers, body):
        return self._ok

    def handshake(self, body):
        return self._handshake

    def parse(self, body):
        return self._command

    def respond(self, message):
        return message.encode()


def test_dispatch_401s_a_forged_request_before_parsing():
    status, body = dispatch(_FakeAdapter(ok=False), {}, "anything", ":memory:")
    assert status == 401 and body == b""


def test_dispatch_answers_a_handshake_without_touching_the_core():
    # Discord's PING -> PONG: a verified non-command reply, returned as-is.
    status, body = dispatch(_FakeAdapter(handshake_reply=b'{"type":1}'), {}, "ping", ":memory:")
    assert status == 200 and body == b'{"type":1}'


def test_dispatch_runs_a_parsed_command(monkeypatch):
    monkeypatch.setattr("steadystate.inbound.server.run_command", lambda command, path: "done")
    adapter = _FakeAdapter(command=Command(APPROVE, "x", "fp1"))
    status, body = dispatch(adapter, {}, "body", ":memory:")
    assert status == 200 and body == b"done"


def test_dispatch_noops_an_unrecognized_payload():
    status, body = dispatch(_FakeAdapter(command=None), {}, "body", ":memory:")
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
