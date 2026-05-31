"""Discord inbound adapter: Ed25519 verification, PING/PONG, slash-command parsing.

The crypto tests need the optional [discord] extra (PyNaCl); they importorskip when it's
absent (e.g. a core CI run). The pure parsing/handshake/respond tests always run.
"""

from __future__ import annotations

import json

import pytest

from steadystate.inbound import build_inbound
from steadystate.inbound.base import APPROVE, DECLINE, HELP, PENDING, PROBE, Command
from steadystate.inbound.discord import (
    DiscordInbound,
    command_from_payload,
    verify_ed25519,
)
from steadystate.inbound.server import dispatch


def _command(decision: str, fingerprint: str, actor: str = "jeff") -> dict:
    return {
        "type": 2,  # APPLICATION_COMMAND
        "data": {
            "name": "steadystate",
            "options": [
                {
                    "name": decision,
                    "type": 1,  # SUB_COMMAND
                    "options": [{"name": "fingerprint", "type": 3, "value": fingerprint}],
                }
            ],
        },
        "member": {"user": {"username": actor}},
    }


def _readonly_command(verb: str, actor: str = "jeff") -> dict:
    # help / pending are arg-less subcommands -- no options under the subcommand.
    return {
        "type": 2,
        "data": {"name": "steadystate", "options": [{"name": verb, "type": 1}]},
        "member": {"user": {"username": actor}},
    }


# -- slash-command parsing (pure) -----------------------------------------------


def test_parse_approve_and_decline():
    assert command_from_payload(_command("approve", "fp1")) == Command(APPROVE, "jeff", "fp1")
    assert command_from_payload(_command("decline", "fp2", actor="amy")) == Command(
        DECLINE, "amy", "fp2"
    )


def test_parse_readonly_help_and_pending_take_no_argument():
    assert command_from_payload(_readonly_command("help")) == Command(HELP, "jeff")
    assert command_from_payload(_readonly_command("pending", "amy")) == Command(PENDING, "amy")


def test_parse_probe_takes_its_target_option():
    # probe carries a `target` option (not `fingerprint`); the parser takes the first string opt.
    payload = {
        "type": 2,
        "data": {
            "name": "steadystate",
            "options": [
                {
                    "name": "probe",
                    "type": 1,
                    "options": [{"name": "target", "type": 3, "value": "prod-k8s"}],
                }
            ],
        },
        "member": {"user": {"username": "jeff"}},
    }
    assert command_from_payload(payload) == Command(PROBE, "jeff", "prod-k8s")


def test_parse_probe_unmute_boolean_option_sets_bypass():
    payload = {
        "type": 2,
        "data": {
            "name": "steadystate",
            "options": [
                {
                    "name": "probe",
                    "type": 1,
                    "options": [
                        {"name": "target", "type": 3, "value": "prod-k8s"},
                        {"name": "unmute", "type": 5, "value": True},
                    ],
                }
            ],
        },
        "member": {"user": {"username": "jeff"}},
    }
    assert command_from_payload(payload) == Command(PROBE, "jeff", "prod-k8s", bypass=True)


def test_parse_actor_falls_back_to_top_level_user_then_default():
    payload = _command("approve", "fp1")
    del payload["member"]
    payload["user"] = {"username": "dm-user"}  # a DM interaction
    assert command_from_payload(payload).actor == "dm-user"
    del payload["user"]
    assert command_from_payload(payload).actor == "discord"


def test_parse_rejects_non_command_unknown_sub_and_missing_fingerprint():
    assert command_from_payload({"type": 1}) is None  # a PING is not a command
    assert command_from_payload(_command("nuke", "fp1")) is None  # unknown subcommand
    bad = _command("approve", "fp1")
    bad["data"]["options"][0]["options"] = []  # no fingerprint option
    assert command_from_payload(bad) is None


# -- handshake + respond (pure) -------------------------------------------------


def test_handshake_answers_ping_with_pong():
    reply = DiscordInbound("deadbeef").handshake(json.dumps({"type": 1}))
    assert reply is not None and json.loads(reply) == {"type": 1}


def test_handshake_returns_none_for_a_command_or_garbage():
    adapter = DiscordInbound("deadbeef")
    assert adapter.handshake(json.dumps(_command("approve", "fp1"))) is None
    assert adapter.handshake("not json") is None


def test_respond_is_a_type4_channel_message():
    body = json.loads(DiscordInbound("deadbeef").respond("applied!"))
    assert body == {"type": 4, "data": {"content": "applied!"}}


def test_parse_decodes_the_json_body():
    got = DiscordInbound("deadbeef").parse(json.dumps(_command("approve", "fp9")))
    assert got == Command(APPROVE, "jeff", "fp9")
    assert DiscordInbound("deadbeef").parse("not json") is None


# -- readiness ------------------------------------------------------------------


def test_not_ready_without_a_public_key(monkeypatch):
    monkeypatch.delenv("STEADYSTATE_DISCORD_PUBLIC_KEY", raising=False)
    assert DiscordInbound().ready() is not None


def test_not_ready_without_the_crypto_dep(monkeypatch):
    # Simulate the [discord] extra being absent even though a key is set.
    monkeypatch.setattr("steadystate.inbound.discord.VerifyKey", None)
    assert "pip install" in DiscordInbound("deadbeef").ready()


def test_registered_in_the_inbound_registry():
    assert isinstance(build_inbound("discord"), DiscordInbound)


# -- Ed25519 verification (the security boundary; needs the [discord] extra) -----


def _keys():
    nacl_signing = pytest.importorskip("nacl.signing")
    signing = nacl_signing.SigningKey.generate()
    public_hex = signing.verify_key.encode().hex()
    return signing, public_hex


def _sign(signing, message: str) -> str:
    return signing.sign(message.encode()).signature.hex()


def test_valid_ed25519_signature_passes():
    signing, public_hex = _keys()
    ts, body = "1700000000", '{"type":1}'
    assert verify_ed25519(public_hex, ts + body, _sign(signing, ts + body))


def test_tampered_body_fails():
    signing, public_hex = _keys()
    ts, body = "1700000000", '{"type":1}'
    sig = _sign(signing, ts + body)
    assert not verify_ed25519(public_hex, ts + '{"type":2}', sig)  # body changed after signing


def test_wrong_key_fails():
    signing, _ = _keys()
    _, other_public = _keys()
    ts, body = "1700000000", "x"
    assert not verify_ed25519(other_public, ts + body, _sign(signing, ts + body))


def test_malformed_hex_is_false_not_an_error():
    assert verify_ed25519("nothex", "msg", "alsonothex") is False


def test_adapter_verify_reads_the_discord_headers():
    signing, public_hex = _keys()
    ts, body = "1700000000", json.dumps(_command("approve", "fp1"))
    headers = {"X-Signature-Ed25519": _sign(signing, ts + body), "X-Signature-Timestamp": ts}
    assert DiscordInbound(public_hex).verify(headers, body)
    assert not DiscordInbound(public_hex).verify({}, body)  # missing headers


def test_dispatch_end_to_end_pong_and_forged(monkeypatch):
    signing, public_hex = _keys()
    adapter = DiscordInbound(public_hex)
    # A correctly-signed PING -> 200 PONG, without touching the approval core.
    ping = json.dumps({"type": 1})
    ts = "1700000000"
    headers = {"X-Signature-Ed25519": _sign(signing, ts + ping), "X-Signature-Timestamp": ts}
    status, reply = dispatch(adapter, headers, ping, ":memory:")
    assert status == 200 and json.loads(reply) == {"type": 1}
    # A forged signature -> 401 before anything parses it.
    status, _ = dispatch(
        adapter, {"X-Signature-Ed25519": "00", "X-Signature-Timestamp": ts}, ping, ":memory:"
    )
    assert status == 401
