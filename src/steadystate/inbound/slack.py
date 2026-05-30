"""Slack inbound adapter -- the first implementation of the inbound seam.

Slack POSTs an application/x-www-form-urlencoded body (``payload=<json>``) when an operator
clicks an Approve/Decline button, signed with an HMAC-SHA256 over the signing secret. We
verify the signature (with replay protection), parse the action + drift fingerprint, and hand
back an Interaction. Stdlib only -- hmac + hashlib + json + urllib.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
import urllib.parse
from collections.abc import Mapping

from .base import APPROVE, DECLINE, Interaction

_APPROVE_ACTION = "steadystate_approve"
_DECLINE_ACTION = "steadystate_decline"
_MAX_SKEW_SECONDS = 300  # reject payloads older than 5 minutes (replay protection)


def verify_slack_signature(
    secret: str, timestamp: str, body: str, signature: str, now: float | None = None
) -> bool:
    """True iff ``signature`` is Slack's valid v0 HMAC for ``body`` and the timestamp is fresh."""
    now = time.time() if now is None else now
    try:
        if abs(now - int(timestamp)) > _MAX_SKEW_SECONDS:
            return False
    except (TypeError, ValueError):
        return False
    basestring = f"v0:{timestamp}:{body}".encode()
    expected = "v0=" + hmac.new(secret.encode(), basestring, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature or "")


def interaction_from_payload(payload: dict) -> Interaction | None:
    """An Interaction from a Slack button payload, or None if it's not one of ours.

    Slack sends ``{"actions": [{"action_id": "steadystate_approve", "value": "<fp>"}], ...}``;
    the fingerprint rides in the button's ``value`` and the clicker in ``user.username``."""
    actions = payload.get("actions") or []
    if not actions or not isinstance(actions[0], dict):
        return None
    action_id = actions[0].get("action_id")
    fingerprint = actions[0].get("value")
    if not isinstance(fingerprint, str) or not fingerprint:
        return None
    actor = (payload.get("user") or {}).get("username") or "slack"
    if action_id == _APPROVE_ACTION:
        return Interaction(APPROVE, fingerprint, actor)
    if action_id == _DECLINE_ACTION:
        return Interaction(DECLINE, fingerprint, actor)
    return None


class SlackInbound:
    """The Slack inbound adapter: HMAC verification + interactive-payload parsing."""

    name = "slack"
    content_type = "application/json"

    def __init__(self, secret: str | None = None) -> None:
        self.secret = secret or os.environ.get("STEADYSTATE_SLACK_SIGNING_SECRET") or ""

    def ready(self) -> str | None:
        if not self.secret:
            return "set STEADYSTATE_SLACK_SIGNING_SECRET to run the Slack listener."
        return None

    def verify(self, headers: Mapping[str, str], body: str, now: float | None = None) -> bool:
        timestamp = headers.get("X-Slack-Request-Timestamp", "")
        signature = headers.get("X-Slack-Signature", "")
        return verify_slack_signature(self.secret, timestamp, body, signature, now)

    def handshake(self, body: str) -> bytes | None:
        return None  # Slack interactivity has no PING/PONG handshake

    def parse(self, body: str) -> Interaction | None:
        # Slack posts application/x-www-form-urlencoded with payload=<json>.
        form = urllib.parse.parse_qs(body)
        try:
            payload = json.loads(form.get("payload", ["{}"])[0])
        except ValueError:
            return None
        return interaction_from_payload(payload)

    def respond(self, message: str) -> bytes:
        # replace_original=False -> post the outcome as a follow-up, keep the alert visible.
        return json.dumps({"text": message, "replace_original": False}).encode()
