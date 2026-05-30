"""The generic inbound listener: one stdlib HTTP shell over any InboundAdapter.

steadystate is a one-shot CLI and Python ships no websocket client, so approvals arrive
over a chat provider's *interactive HTTP* webhook. This module owns the transport and the
routing; the provider-specific signing and payload shapes live in the adapter. The routing
is factored into `dispatch` (pure: request in, status + reply bytes out) so the security and
control flow are testable without standing up a socket.
"""

from __future__ import annotations

from collections.abc import Mapping
from http.server import BaseHTTPRequestHandler, HTTPServer

from ..act.approve import apply_pending, decline_pending
from ..state import StateStore
from .base import APPROVE, DECLINE, InboundAdapter, Interaction


def run_interaction(interaction: Interaction, state_path: str) -> str:
    """Drive a parsed decision through the SAME approval core the CLI verbs use; return a
    human-readable outcome for the provider to echo back to the operator."""
    with StateStore(state_path) as store:
        if interaction.decision == APPROVE:
            message, _result = apply_pending(store, interaction.fingerprint, interaction.actor)
            return message
        if interaction.decision == DECLINE:
            return decline_pending(store, interaction.fingerprint, interaction.actor)
    return "Nothing to do."


def dispatch(
    adapter: InboundAdapter, headers: Mapping[str, str], body: str, state_path: str
) -> tuple[int, bytes]:
    """One inbound POST -> (HTTP status, reply body). The order is the security order:
    verify FIRST (a forged request is 401 before anything else looks at it), then answer a
    protocol handshake, then parse + run the operator's decision."""
    if not adapter.verify(headers, body):
        return 401, b""
    reply = adapter.handshake(body)
    if reply is not None:
        return 200, reply
    interaction = adapter.parse(body)
    message = "Nothing to do." if interaction is None else run_interaction(interaction, state_path)
    return 200, adapter.respond(message)


def make_handler(adapter: InboundAdapter, state_path: str) -> type[BaseHTTPRequestHandler]:
    """A BaseHTTPRequestHandler bound to one adapter + state db -- a thin shell over dispatch."""

    class _Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length).decode("utf-8", "replace")
            # self.headers is an email.message.Message; flatten to a plain mapping for the
            # adapter (provider header names arrive with stable casing, e.g. X-Slack-Signature).
            headers = dict(self.headers.items())
            status, reply = dispatch(adapter, headers, body, state_path)
            self.send_response(status)
            if reply:
                self.send_header("Content-Type", adapter.content_type)
            self.end_headers()
            self.wfile.write(reply)

        def log_message(self, *args: object) -> None:  # keep the listener quiet
            pass

    return _Handler


def serve(adapter: InboundAdapter, port: int, state_path: str) -> None:  # pragma: no cover
    """Run the approval listener for ``adapter`` until interrupted (blocking)."""
    HTTPServer(("", port), make_handler(adapter, state_path)).serve_forever()
