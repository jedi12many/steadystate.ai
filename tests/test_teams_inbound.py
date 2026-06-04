"""Teams inbound adapter: HMAC verification + @mention-command parsing. Stdlib only, so every
test runs unconditionally (no optional crypto dep, unlike Discord's Ed25519)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json

from steadystate.inbound import build_inbound
from steadystate.inbound.base import APPROVE, DECLINE, HELP, PENDING, Command
from steadystate.inbound.server import dispatch
from steadystate.inbound.teams import (
    TeamsInbound,
    command_from_activity,
    verify_teams_signature,
)

_TOKEN = base64.b64encode(b"super-secret-key").decode()  # a base64 security token, as Teams gives


def _sign(token: str, body: str) -> str:
    digest = hmac.new(base64.b64decode(token), body.encode("utf-8"), hashlib.sha256).digest()
    return "HMAC " + base64.b64encode(digest).decode()


def _activity(text: str, name: str = "Jeff") -> dict:
    return {"type": "message", "text": text, "from": {"name": name}}


# -- HMAC verification (the security boundary) ----------------------------------


def test_valid_signature_passes():
    body = json.dumps(_activity("<at>steadystate</at> approve fp1"))
    assert verify_teams_signature(_TOKEN, body, _sign(_TOKEN, body))


def test_bad_signature_fails():
    assert not verify_teams_signature(_TOKEN, "the body", "HMAC d29uZw==")


def test_non_hmac_authorization_fails():
    body = "x"
    assert not verify_teams_signature(_TOKEN, body, "Bearer " + _sign(_TOKEN, body))


def test_malformed_token_is_false_not_an_error():
    assert verify_teams_signature("not base64 !!", "x", "HMAC abc") is False


# -- @mention-command parsing (pure) -------------------------------------------


def test_parse_approve_decline_and_strips_the_mention():
    assert command_from_activity(_activity("<at>steadystate</at> approve fp1")) == Command(
        APPROVE, "Jeff", "fp1"
    )
    assert command_from_activity(_activity("decline fp2", name="Amy")) == Command(
        DECLINE, "Amy", "fp2"
    )


def test_parse_readonly_help_and_pending():
    assert command_from_activity(_activity("<at>steadystate</at> help")) == Command(HELP, "Jeff")
    assert command_from_activity(_activity("pending", name="Amy")) == Command(PENDING, "Amy")


def test_parse_actor_defaults_when_absent():
    assert command_from_activity({"type": "message", "text": "approve fp1"}).actor == "teams"


def test_parse_rejects_no_command_keyword_without_fp_and_no_text():
    assert command_from_activity(_activity("<at>steadystate</at> hello there")) is None
    assert command_from_activity(_activity("probe")) is None  # needs a target, none given
    assert command_from_activity({"type": "message"}) is None  # no text


# -- the adapter ----------------------------------------------------------------


def test_adapter_verify_reads_the_authorization_header():
    body = json.dumps(_activity("approve fp1"))
    assert TeamsInbound(_TOKEN).verify({"Authorization": _sign(_TOKEN, body)}, body)
    assert not TeamsInbound(_TOKEN).verify({"Authorization": "HMAC nope"}, body)


def test_handshake_is_none():
    assert TeamsInbound(_TOKEN).handshake('{"type":"message"}') is None


def test_parse_decodes_the_json_body():
    assert TeamsInbound(_TOKEN).parse(json.dumps(_activity("approve fp9"))) == Command(
        APPROVE, "Jeff", "fp9"
    )
    assert TeamsInbound(_TOKEN).parse("not json") is None


def test_respond_is_a_message_activity():
    assert json.loads(TeamsInbound(_TOKEN).respond("done")) == {"type": "message", "text": "done"}


def test_not_ready_without_a_token(monkeypatch):
    monkeypatch.delenv("STEADYSTATE_TEAMS_SECURITY_TOKEN", raising=False)
    assert TeamsInbound().ready() is not None
    assert TeamsInbound(_TOKEN).ready() is None


def test_registered_in_the_inbound_registry():
    assert isinstance(build_inbound("teams"), TeamsInbound)


# -- end-to-end through the generic dispatch ------------------------------------


def test_dispatch_runs_a_verified_command_and_rejects_a_forged_one(monkeypatch):
    adapter = TeamsInbound(_TOKEN)
    body = json.dumps(_activity("approve fp1"))
    monkeypatch.setattr("steadystate.inbound.server.run_command", lambda c, p: "approved!")
    status, reply, _ = dispatch(adapter, {"Authorization": _sign(_TOKEN, body)}, body, ":memory:")
    assert status == 200 and json.loads(reply) == {"type": "message", "text": "approved!"}
    status, _, _ = dispatch(adapter, {"Authorization": "HMAC forged"}, body, ":memory:")
    assert status == 401  # the forged request never reaches the approval core
