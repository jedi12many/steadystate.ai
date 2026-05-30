"""The inbound seam: turn a signed chat-provider webhook into an approval decision.

This is the bidirectional half of the surface seam. Outbound Surfaces (notify/) push
Alerts out; an InboundAdapter takes an operator's reply back -- a click on an Approve /
Decline button -- and runs it through the shared approval core (act/approve.py). A new
chat provider (Slack, Discord, Teams, an email gateway) is a plugin here, NOT a fork of
the listener: implement the four provider-specific steps below and register one line.

The steps are deliberately small and provider-shaped so very different protocols fit the
same shell: Slack signs with HMAC and has no handshake; Discord signs with Ed25519 and
must answer a PING with a PONG before it will deliver any interaction.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

# An operator's decision. Kept tiny and provider-agnostic on purpose: every adapter parses
# its own payload shape down to exactly this, so the approval core never sees a vendor field.
APPROVE = "approve"
DECLINE = "decline"


@dataclass(frozen=True)
class Interaction:
    """A parsed operator decision: approve or decline one pending remediation."""

    decision: str  # APPROVE | DECLINE
    fingerprint: str  # the pending remediation's key (the button carried it)
    actor: str  # who clicked -- recorded for the audit trail


@runtime_checkable
class InboundAdapter(Protocol):
    """A chat provider's inbound half. Mirrors the outbound Surface seam (notify/__init__.py):
    register a factory in INBOUND and `listen --from <name>` dispatches to it."""

    name: str
    content_type: str  # the Content-Type the provider expects on the reply

    def ready(self) -> str | None:
        """None when configured (signing secret / public key present), else a human-readable
        reason the CLI turns into a clean error -- so a misconfigured listener fails loudly at
        startup, not silently on the first click."""
        ...

    def verify(self, headers: Mapping[str, str], body: str) -> bool:
        """True iff the request is an authentic, fresh call from the provider. THE security
        boundary -- a forged or replayed click must never reach the approval core."""
        ...

    def handshake(self, body: str) -> bytes | None:
        """A protocol reply that isn't an Interaction (e.g. Discord PING -> PONG), or None to
        proceed to parse(). Providers without a handshake (Slack interactivity) return None."""
        ...

    def parse(self, body: str) -> Interaction | None:
        """The operator's decision, or None when the payload isn't an approve/decline of ours."""
        ...

    def respond(self, message: str) -> bytes:
        """Wrap an outcome message as the provider's reply body."""
        ...
