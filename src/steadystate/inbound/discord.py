"""Discord inbound adapter -- approvals via a slash command, over the inbound seam.

Discord doesn't sign with an HMAC like Slack; it signs each interaction with **Ed25519** over
``timestamp + body`` and verifies against the application's public key. Ed25519 isn't in the
Python stdlib, so this adapter needs an optional crypto dependency -- ``pip install
steadystate[discord]`` (PyNaCl). The core stays stdlib-only: the import is guarded and a
missing dependency is reported by ``ready()``, never an import crash.

The flow Discord requires:
  * a PING (type 1) -- answered with a PONG (type 1) via ``handshake`` (this is how Discord
    verifies the endpoint when you save the Interactions URL, and a periodic health check);
  * an APPLICATION_COMMAND (type 2) -- the operator's ``/steadystate <verb>`` slash command
    (``approve``/``decline fingerprint:<fp>`` to act, or ``help``/``pending`` to discover what's
    available), parsed into a Command and run through the shared command core; we reply with a
    type-4 message the operator sees in-channel.

The channel webhook surface (notify/discord.py) posts the alerts (with the fingerprint); this
adapter takes the reply back. Register the slash command once against your application -- see
the deploy notes -- and point its Interactions Endpoint URL at ``listen --from discord``.
"""

from __future__ import annotations

import json
import os
import urllib.request
from collections.abc import Mapping

from .._http import safe_urlopen
from .base import (
    APPROVE,
    COST,
    DECLINE,
    FINDINGS,
    HELP,
    HISTORY,
    MUTE,
    PENDING,
    PROBE,
    TARGETS,
    Command,
)

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
_DEFERRED_MESSAGE = 5  # DEFERRED_CHANNEL_MESSAGE_WITH_SOURCE -- "thinking..."; edit in the result
_API = "https://discord.com/api/v10"
# Discord's Cloudflare edge bans the default Python-urllib UA (error 1010); send a real one.
_USER_AGENT = "steadystate (+https://github.com/jedi12many/steadystate.ai)"


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


_ARGLESS = frozenset({HELP, TARGETS, PENDING, FINDINGS, HISTORY})
_BOOL_FLAGS = frozenset({"unmute", "cost", "verbose"})  # probe's boolean options -> canonical flags


def command_from_payload(payload: dict) -> Command | None:
    """A Command from a Discord APPLICATION_COMMAND payload, or None if it isn't one of ours.
    The command is ``/steadystate <verb> [...]`` -- a subcommand whose name is the verb; the
    arg-taking verbs carry a string option (a `fingerprint` or a `target`), probe also carries
    boolean flag options (`verbose`/`cost`/`unmute`), help/targets/etc carry none."""
    if payload.get("type") != _APPLICATION_COMMAND:
        return None
    subcommands = (payload.get("data") or {}).get("options") or []
    if not subcommands or not isinstance(subcommands[0], dict):
        return None
    verb = subcommands[0].get("name")
    actor = _actor(payload)
    options = subcommands[0].get("options") or []
    if verb in _ARGLESS:
        return Command(verb, actor)
    if verb == COST:  # an optional `period` (day|week) string option
        period = next(
            (
                o["value"]
                for o in options
                if isinstance(o, dict) and isinstance(o.get("value"), str)
            ),
            "",
        )
        return Command(verb, actor, period)
    if verb in (APPROVE, DECLINE, PROBE, MUTE):
        # take the first non-empty STRING option (the fingerprint / target), and any boolean flag
        # options that are set (so probe's `verbose`/`cost`/`unmute` ride through).
        argument = next(
            (
                o["value"]
                for o in options
                if isinstance(o, dict) and isinstance(o.get("value"), str)
            ),
            None,
        )
        flags = frozenset(
            o["name"]
            for o in options
            if isinstance(o, dict) and o.get("name") in _BOOL_FLAGS and o.get("value") is True
        )
        if isinstance(argument, str) and argument:
            return Command(verb, actor, argument, flags=flags)
    return None


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

    def parse(self, body: str) -> Command | None:
        try:
            payload = json.loads(body)
        except ValueError:
            return None
        return command_from_payload(payload) if isinstance(payload, dict) else None

    def respond(self, message: str) -> bytes:
        return json.dumps({"type": _CHANNEL_MESSAGE, "data": {"content": message}}).encode()

    def defer(self, body: str) -> bytes | None:
        """Ack a slow command with a *deferred* response (type 5) so Discord shows "thinking..."
        and we get ~15 min to edit in the real result via ``complete``. None for a non-command
        payload (a PING is handled by ``handshake``), so the synchronous path takes over."""
        try:
            payload = json.loads(body)
        except ValueError:
            return None
        if not isinstance(payload, dict) or payload.get("type") != _APPLICATION_COMMAND:
            return None
        return json.dumps({"type": _DEFERRED_MESSAGE}).encode()

    def complete(self, body: str, message: str) -> None:
        """Edit the deferred response in place with the finished result (PATCH @original). The
        interaction token in the URL authenticates the edit -- no bot token needed."""
        payload = json.loads(body)
        app_id, token = payload.get("application_id"), payload.get("token")
        if not app_id or not token:
            return
        request = urllib.request.Request(
            f"{_API}/webhooks/{app_id}/{token}/messages/@original",
            data=json.dumps({"content": message}).encode(),
            headers={"Content-Type": "application/json", "User-Agent": _USER_AGENT},
            method="PATCH",
        )
        with safe_urlopen(request, timeout=15):
            pass
