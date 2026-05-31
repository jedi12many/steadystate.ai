"""Slack inbound adapter -- the first implementation of the inbound seam.

Slack reaches the listener two ways, both an application/x-www-form-urlencoded POST signed with
the same HMAC-SHA256 over the signing secret:

  * an Approve/Decline **button** click on an alert -> ``payload=<json>`` (block_actions); the
    fingerprint rides in the button's ``value``. This is how you act on a specific alert.
  * a ``/steadystate <verb>`` **slash command** -> ``command=/steadystate&text=<verb ...>``; this
    is how an operator discovers + drives the listener by text (``help``, ``pending``, or
    ``approve <fp>``) without a button to click.

We verify the signature (with replay protection) once, then route on the body shape to a
provider-agnostic Command. Stdlib only -- hmac + hashlib + json + urllib.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
import urllib.parse
import urllib.request
from collections.abc import Mapping

from .._http import safe_urlopen
from .base import APPROVE, DECLINE, Command, command_from_text

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


def command_from_payload(payload: dict) -> Command | None:
    """A Command from a Slack button payload, or None if it's not one of ours.

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
        return Command(APPROVE, actor, fingerprint)
    if action_id == _DECLINE_ACTION:
        return Command(DECLINE, actor, fingerprint)
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

    def parse(self, body: str) -> Command | None:
        # Slack posts application/x-www-form-urlencoded; route on which shape it is.
        form = urllib.parse.parse_qs(body)
        if "payload" in form:  # a button click (block_actions): payload=<json>
            try:
                payload = json.loads(form["payload"][0])
            except ValueError:
                return None
            return command_from_payload(payload)
        if form.get("command"):  # a slash command: command=/steadystate&text=<verb ...>
            actor = form.get("user_name", ["slack"])[0]
            return command_from_text(form.get("text", [""])[0], actor)
        return None

    def respond(self, message: str) -> bytes:
        # replace_original=False -> post the outcome as a follow-up, keep the alert visible.
        return json.dumps({"text": message, "replace_original": False}).encode()

    def defer(self, body: str) -> bytes | None:
        """Ack a slow slash command immediately (an ephemeral "running...") so Slack doesn't time
        out; the result is posted to its ``response_url`` by ``complete``. Returns None for a
        button click (block_actions has no slow work here) -> the synchronous path takes over."""
        form = urllib.parse.parse_qs(body)
        if not form.get("response_url"):
            return None
        return json.dumps({"response_type": "ephemeral", "text": "running..."}).encode()

    def complete(self, body: str, message: str) -> None:
        """Post the finished result to the slash command's ``response_url`` (valid ~30 min)."""
        response_url = urllib.parse.parse_qs(body).get("response_url", [""])[0]
        if not response_url:
            return
        request = urllib.request.Request(
            response_url,
            data=json.dumps({"response_type": "in_channel", "text": message}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with safe_urlopen(request, timeout=15):
            pass
