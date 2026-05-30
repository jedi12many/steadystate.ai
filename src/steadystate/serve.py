"""Slack approval listener -- the inbound half of the surface seam, over stdlib HTTP.

steadystate is a one-shot CLI, and Python ships no websocket client, so we use Slack's
*interactive HTTP* model rather than Socket Mode: Slack POSTs a signed payload when an
operator clicks Approve/Decline on an alert. We verify the signature (HMAC-SHA256 over the
Slack signing secret, with replay protection), parse the action + drift fingerprint, and run
it through the same approval core as the CLI. No new dependency -- http.server + hmac + json.

Point your Slack app's Interactivity "Request URL" at http://<host>:<port>/ and run
`steadystate listen`.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

from .act.approve import apply_pending, decline_pending
from .state import StateStore

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


def parse_interaction(payload: dict) -> tuple[str, str] | None:
    """(decision, fingerprint) from a Slack button payload, or None if it's not ours.

    Slack sends ``{"actions": [{"action_id": "steadystate_approve", "value": "<fp>"}], ...}``
    when a button is clicked; the fingerprint rides in the button's ``value``."""
    actions = payload.get("actions") or []
    if not actions or not isinstance(actions[0], dict):
        return None
    action_id = actions[0].get("action_id")
    fingerprint = actions[0].get("value")
    if not isinstance(fingerprint, str) or not fingerprint:
        return None
    if action_id == _APPROVE_ACTION:
        return "approve", fingerprint
    if action_id == _DECLINE_ACTION:
        return "decline", fingerprint
    return None


def handle_interaction(payload: dict, state_path: str) -> str:
    """Run a parsed Slack interaction through the approval core; return a reply message."""
    parsed = parse_interaction(payload)
    if parsed is None:
        return "Nothing to do."
    decision, fingerprint = parsed
    actor = (payload.get("user") or {}).get("username") or "slack"
    with StateStore(state_path) as store:
        if decision == "approve":
            message, _result = apply_pending(store, fingerprint, actor)
            return message
        return decline_pending(store, fingerprint, actor)


class _Handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("utf-8", "replace")
        timestamp = self.headers.get("X-Slack-Request-Timestamp", "")
        signature = self.headers.get("X-Slack-Signature", "")
        if not verify_slack_signature(self.server.secret, timestamp, body, signature):  # type: ignore[attr-defined]
            self.send_response(401)
            self.end_headers()
            return
        # Slack posts application/x-www-form-urlencoded with payload=<json>.
        form = urllib.parse.parse_qs(body)
        try:
            payload = json.loads(form.get("payload", ["{}"])[0])
        except ValueError:
            payload = {}
        message = handle_interaction(payload, self.server.state_path)  # type: ignore[attr-defined]
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        # replace_original=False -> post the outcome as a follow-up, keep the alert visible.
        self.wfile.write(json.dumps({"text": message, "replace_original": False}).encode())

    def log_message(self, *args: object) -> None:  # keep the listener quiet
        pass


def serve_slack(port: int, secret: str, state_path: str) -> None:  # pragma: no cover - blocking
    """Run the Slack approval listener until interrupted (blocking)."""
    httpd = HTTPServer(("", port), _Handler)
    httpd.secret = secret  # type: ignore[attr-defined]
    httpd.state_path = state_path  # type: ignore[attr-defined]
    httpd.serve_forever()
