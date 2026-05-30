"""Discord inbound adapter -- approvals via a slash command, over the inbound seam.

Discord doesn't sign with an HMAC like Slack; it signs each interaction with **Ed25519** over
``timestamp + body`` and verifies against the application's public key. Ed25519 isn't in the
Python stdlib, so this adapter needs an optional crypto dependency -- ``pip install
steadystate[discord]`` (PyNaCl). The core stays stdlib-only: the import is guarded and a
missing dependency is reported by ``ready()``, never an import crash.

The flow Discord requires:
  * a PING (type 1) -- answered with a PONG (type 1) via ``handshake`` (this is how Discord
    verifies the endpoint when you save the Interactions URL, and a periodic health check);
  * an APPLICATION_COMMAND (type 2) -- the operator's ``/steadystate approve|decline
    fingerprint:<fp>`` slash command, parsed into an Interaction and run through the shared
    approval core; we reply with a type-4 message the operator sees in-channel.

The channel webhook surface (notify/discord.py) posts the alerts (with the fingerprint); this
adapter takes the reply back. Register the slash command once against your application -- see
the deploy notes -- and point its Interactions Endpoint URL at ``listen --from discord``.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping

from .base import APPROVE, DECLINE, Interaction

try:  # the optional [discord] extra; absence is handled by ready(), never an import crash
    from nacl.exceptions import BadSignatureError
    from nacl.signing import VerifyKey
except ImportError:  # pragma: no cover - exercised only where the extra isn't installed
    VerifyKey = None  # type: ignore[assignment,misc]
    BadSignatureError = Exception  # type: ignore[assignment,misc]

_PING = 1  # Discord interaction types
_APPLICATION_COMMAND = 2
_PONG = {"type": _PING}
_CHANNEL_MESSAGE = 4  # CHANNEL_MESSAGE_WITH_SOURCE -- the operator sees our reply in-channel


def verify_ed25519(public_key_hex: str, message: str, signature_hex: str) -> bool:
    """True iff ``signature_hex`` is a valid Ed25519 signature of ``message`` for the app's
    public key. Returns False (never raises) on a bad signature, malformed hex, or -- so a
    missing optional dep fails safe -- when PyNaCl isn't installed."""
    if VerifyKey is None:
        return False
    try:
        VerifyKey(bytes.fromhex(public_key_hex)).verify(
            message.encode(), bytes.fromhex(signature_hex)
        )
        return True
    except (BadSignatureError, ValueError):
        return False


def _actor(payload: dict) -> str:
    """The clicking operator: guild interactions carry the user under ``member.user``, DMs
    under ``user``."""
    user = (payload.get("member") or {}).get("user") or payload.get("user") or {}
    return user.get("username") or "discord"


def interaction_from_payload(payload: dict) -> Interaction | None:
    """An Interaction from a Discord APPLICATION_COMMAND payload, or None if it isn't one of
    ours. The command is ``/steadystate <approve|decline> fingerprint:<fp>`` -- a subcommand
    whose name is the decision, carrying a ``fingerprint`` string option."""
    if payload.get("type") != _APPLICATION_COMMAND:
        return None
    subcommands = (payload.get("data") or {}).get("options") or []
    if not subcommands or not isinstance(subcommands[0], dict):
        return None
    decision = subcommands[0].get("name")
    if decision not in (APPROVE, DECLINE):
        return None
    options = subcommands[0].get("options") or []
    fingerprint = next(
        (o.get("value") for o in options if isinstance(o, dict) and o.get("name") == "fingerprint"),
        None,
    )
    if not isinstance(fingerprint, str) or not fingerprint:
        return None
    return Interaction(decision, fingerprint, _actor(payload))


class DiscordInbound:
    """The Discord inbound adapter: Ed25519 verification + slash-command parsing."""

    name = "discord"
    content_type = "application/json"

    def __init__(self, public_key: str | None = None) -> None:
        self.public_key = public_key or os.environ.get("STEADYSTATE_DISCORD_PUBLIC_KEY") or ""

    def ready(self) -> str | None:
        if not self.public_key:
            return "set STEADYSTATE_DISCORD_PUBLIC_KEY to run the Discord listener."
        if VerifyKey is None:
            return "Discord approvals need PyNaCl: pip install steadystate[discord]."
        return None

    def verify(self, headers: Mapping[str, str], body: str) -> bool:
        signature = headers.get("X-Signature-Ed25519", "")
        timestamp = headers.get("X-Signature-Timestamp", "")
        if not signature or not timestamp:
            return False
        return verify_ed25519(self.public_key, timestamp + body, signature)

    def handshake(self, body: str) -> bytes | None:
        try:
            payload = json.loads(body)
        except ValueError:
            return None
        if isinstance(payload, dict) and payload.get("type") == _PING:
            return json.dumps(_PONG).encode()
        return None

    def parse(self, body: str) -> Interaction | None:
        try:
            payload = json.loads(body)
        except ValueError:
            return None
        return interaction_from_payload(payload) if isinstance(payload, dict) else None

    def respond(self, message: str) -> bytes:
        return json.dumps({"type": _CHANNEL_MESSAGE, "data": {"content": message}}).encode()
