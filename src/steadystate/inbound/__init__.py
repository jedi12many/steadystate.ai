"""Inbound adapters: take operator approvals back from a chat provider.

Register an adapter here so `listen --from <name>` dispatches without hand-editing the CLI.
Add one: write its module in this package, then add a single line to INBOUND. (Mirrors the
outbound Surface registry in notify/__init__.py.)
"""

from __future__ import annotations

from collections.abc import Callable

from .base import InboundAdapter
from .slack import SlackInbound

# name -> zero-arg factory -> InboundAdapter. Each reads its signing secret / public key from
# the environment (like the outbound surfaces read their webhooks), so all are zero-arg.
INBOUND: dict[str, Callable[[], InboundAdapter]] = {
    "slack": SlackInbound,
}

__all__ = ["INBOUND", "build_inbound"]


def build_inbound(name: str) -> InboundAdapter:
    """Construct the registered InboundAdapter for ``name``, or raise ValueError."""
    try:
        factory = INBOUND[name]
    except KeyError:
        known = ", ".join(sorted(INBOUND))
        raise ValueError(f"unknown inbound channel '{name}' (known: {known})") from None
    return factory()
