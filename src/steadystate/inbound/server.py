"""The generic inbound listener: one stdlib HTTP shell over any InboundAdapter.

steadystate is a one-shot CLI and Python ships no websocket client, so approvals arrive
over a chat provider's *interactive HTTP* webhook. This module owns the transport and the
routing; the provider-specific signing and payload shapes live in the adapter. The routing
is factored into `dispatch` (pure: request in, status + reply bytes out) so the security and
control flow are testable without standing up a socket.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable, Mapping
from http.server import BaseHTTPRequestHandler, HTTPServer

from ..verbs import _nl_analyst, run_command
from .base import (
    PROBE,
    Command,
    InboundAdapter,
)
from .translate import confident_command, nl_to_command, persist_llm_calls

logger = logging.getLogger(__name__)


def _resolve_text(
    adapter: InboundAdapter, body: str, state_path: str
) -> tuple[Command | None, str | None]:
    """Resolve a free-text message to either a command to run or an immediate reply. Returns
    ``(command, None)`` to run a (read-only) command, or ``(None, reply)`` to answer directly (an
    NL answer, an effectful command echoed for confirmation, a clarifying question). When no model
    is configured or there's no free text, returns ``(None, None)`` so the caller falls back to the
    deterministic ``parse``. Prefers a *confident* typed command before consulting the model, so a
    real command ('probe all') never burns an LLM call and a sentence isn't mis-grabbed."""
    getter = getattr(adapter, "message", None)
    msg = getter(body) if getter is not None else None
    if msg is None:
        return None, None
    analyst = _nl_analyst()
    if analyst is None:
        return None, None
    text, actor = msg
    command = confident_command(text, actor)
    if command is not None:
        return command, None  # a real typed command -> no model call, no spend
    result = nl_to_command(text, actor, analyst._complete, state_path=state_path)
    persist_llm_calls(state_path, analyst.calls)  # count this request's spend in the ledger
    if result.command is not None:
        return result.command, None  # a read-only verb -> run it through the normal path
    return None, result.message  # an answer / confirm-echo / clarify -> reply as-is


# Verbs whose work can exceed a chat provider's ~3s interaction window (a probe runs a full
# scan). For these, if the provider supports deferral, we ACK immediately and post the result
# back when it's ready; everything else answers synchronously.
_DEFERRABLE = frozenset({PROBE})


def _try_defer(adapter: InboundAdapter, body: str) -> bytes | None:
    """The provider's immediate ACK bytes if it supports deferral (Discord/Slack), else None
    (Teams -> synchronous). An optional capability, probed by attribute like the rest of the
    seam -- so a provider without it conforms unchanged."""
    defer = getattr(adapter, "defer", None)
    return defer(body) if defer is not None else None


def _complete(adapter: InboundAdapter, body: str, message: str) -> None:
    """Post the finished result back through the provider's deferral channel (PATCH the deferred
    Discord message / POST a Slack response_url). Best-effort -- a failed post must never crash
    the background worker."""
    complete = getattr(adapter, "complete", None)
    if complete is None:
        return
    try:
        complete(body, message)
    except Exception as exc:  # the worker must never crash the listener on a flaky post
        logger.warning("failed to post deferred result: %s", exc)


def dispatch(
    adapter: InboundAdapter, headers: Mapping[str, str], body: str, state_path: str
) -> tuple[int, bytes, Callable[[], None] | None]:
    """One inbound POST -> (HTTP status, immediate reply bytes, optional deferred work). The order
    is the security order: verify FIRST (a forged request is 401 before anything else looks at it),
    then answer a protocol handshake, then parse + run the command.

    When the command is slow (a probe) and the adapter supports deferral, the reply is an immediate
    ACK and the third element is a callable the handler runs in the background -- it does the scan
    and posts the result back via the provider. Otherwise the reply IS the result and it's None."""
    if not adapter.verify(headers, body):
        return 401, b"", None
    reply = adapter.handshake(body)
    if reply is not None:
        return 200, reply, None
    # Natural-language layer: with a model configured, a free-text message (a slash command /
    # @mention) is resolved by the confident parser then the model -- so a verb-leading sentence
    # isn't mis-grabbed, and a question gets a grounded answer. An answer / confirmation / clarify
    # replies immediately; a resolved read command runs the normal path. With no model, or for a
    # button/structured payload, this is a no-op and the deterministic parse stands.
    nl_command, nl_reply = _resolve_text(adapter, body, state_path)
    if nl_reply is not None:
        return 200, adapter.respond(nl_reply), None
    command = nl_command or adapter.parse(body)
    if command is None:
        return 200, adapter.respond("Nothing to do."), None
    if command.verb in _DEFERRABLE:
        ack = _try_defer(adapter, body)
        if ack is not None:  # ACK now; do the slow scan + post the result in the background

            def _work() -> None:
                _complete(adapter, body, run_command(command, state_path))

            return 200, ack, _work
    return 200, adapter.respond(run_command(command, state_path)), None


def make_handler(adapter: InboundAdapter, state_path: str) -> type[BaseHTTPRequestHandler]:
    """A BaseHTTPRequestHandler bound to one adapter + state db -- a thin shell over dispatch."""

    class _Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length).decode("utf-8", "replace")
            # self.headers is an email.message.Message; flatten to a plain mapping for the
            # adapter (provider header names arrive with stable casing, e.g. X-Slack-Signature).
            headers = dict(self.headers.items())
            status, reply, deferred = dispatch(adapter, headers, body, state_path)
            self.send_response(status)
            if reply:
                self.send_header("Content-Type", adapter.content_type)
            self.end_headers()
            self.wfile.write(reply)
            # Run any deferred work AFTER the ACK is flushed, off the request path, so the handler
            # returns immediately (within the provider's window) and the scan posts back when done.
            if deferred is not None:
                threading.Thread(target=deferred, daemon=True).start()

        def log_message(self, *args: object) -> None:  # keep the listener quiet
            pass

    return _Handler


def serve(adapter: InboundAdapter, port: int, state_path: str) -> None:  # pragma: no cover
    """Run the approval listener for ``adapter`` until interrupted (blocking)."""
    HTTPServer(("", port), make_handler(adapter, state_path)).serve_forever()
