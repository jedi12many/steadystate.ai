"""Teams inbound adapter -- approvals via an Outgoing Webhook, over the inbound seam.

Microsoft Teams signs each Outgoing Webhook call with HMAC-SHA256 over the raw request body,
keyed by the webhook's base64 security token, and sends it as ``Authorization: HMAC <sig>``.
That's the same shared-secret model as Slack, so this adapter is stdlib-only -- no extra
dependency (unlike Discord's Ed25519) and a much lighter setup (no app, public key, or command
registration).

The flow: an operator @mentions the webhook with a command -- ``@steadystate approve <fp>``
(or ``decline``) -- which Teams delivers as a message Activity. We verify the HMAC, pull the
decision + fingerprint out of the text, run the shared approval core, and reply with a message
the operator sees in the channel.

Setup: in the team, Manage team -> Apps -> Create an Outgoing Webhook, point its callback URL
at ``listen --from teams``, and put the security token in STEADYSTATE_TEAMS_SECURITY_TOKEN.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import re
from collections.abc import Mapping

from .base import APPROVE, DECLINE, Interaction

# Teams wraps an @mention as <at>name</at> in the activity text; strip it before scanning.
_MENTION = re.compile(r"<at>.*?</at>", re.IGNORECASE | re.DOTALL)


def verify_teams_signature(token: str, body: str, authorization: str) -> bool:
    """True iff ``authorization`` is Teams' valid HMAC for ``body`` under the base64 ``token``.

    Teams computes HMAC-SHA256 over the raw body, keyed by the base64-decoded security token,
    and base64-encodes the digest into ``Authorization: HMAC <sig>``. Returns False (never
    raises) on a malformed token or header, so a bad request fails closed."""
    if not authorization.startswith("HMAC "):
        return False
    provided = authorization[len("HMAC ") :]
    try:
        key = base64.b64decode(token, validate=True)
    except (binascii.Error, ValueError):
        return False
    digest = hmac.new(key, body.encode("utf-8"), hashlib.sha256).digest()
    expected = base64.b64encode(digest).decode()
    return hmac.compare_digest(expected, provided)


def interaction_from_activity(activity: dict) -> Interaction | None:
    """An Interaction from a Teams message Activity, or None if the text isn't an approve/
    decline of ours. The operator types ``@steadystate approve <fingerprint>``; we strip the
    ``<at>..</at>`` mention and scan for the decision keyword followed by a fingerprint token."""
    text = activity.get("text")
    if not isinstance(text, str):
        return None
    tokens = _MENTION.sub(" ", text).split()
    for index, token in enumerate(tokens[:-1]):  # [:-1] -> a keyword needs a token after it
        decision = token.lower()
        if decision in (APPROVE, DECLINE):
            actor = (activity.get("from") or {}).get("name") or "teams"
            return Interaction(decision, tokens[index + 1], actor)
    return None


class TeamsInbound:
    """The Teams inbound adapter: HMAC verification + @mention-command parsing."""

    name = "teams"
    content_type = "application/json"

    def __init__(self, token: str | None = None) -> None:
        self.token = token or os.environ.get("STEADYSTATE_TEAMS_SECURITY_TOKEN") or ""

    def ready(self) -> str | None:
        if not self.token:
            return "set STEADYSTATE_TEAMS_SECURITY_TOKEN to run the Teams listener."
        return None

    def verify(self, headers: Mapping[str, str], body: str) -> bool:
        return verify_teams_signature(self.token, body, headers.get("Authorization", ""))

    def handshake(self, body: str) -> bytes | None:
        return None  # Teams outgoing webhooks have no PING handshake

    def parse(self, body: str) -> Interaction | None:
        try:
            activity = json.loads(body)
        except ValueError:
            return None
        return interaction_from_activity(activity) if isinstance(activity, dict) else None

    def respond(self, message: str) -> bytes:
        return json.dumps({"type": "message", "text": message}).encode()
