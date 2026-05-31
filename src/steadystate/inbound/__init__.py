"""Inbound adapters: take operator approvals back from a chat provider.

Register an in-tree adapter here so `listen --from <name>` dispatches without hand-editing the
CLI. Add one: write its module in this package, then add a single line to _BUILTIN_INBOUND.
(Mirrors the outbound Surface registry in notify/__init__.py.)

Out-of-tree adapters register the same way without editing this file: a separately installed
package declares a `steadystate.inbound` entry point (a zero-arg factory) and `merged()` overlays
it on the built-ins (built-ins win a name clash). See plugins.py.
"""

from __future__ import annotations

from collections.abc import Callable

from ..plugins import merged
from .base import InboundAdapter
from .discord import DiscordInbound
from .slack import SlackInbound
from .teams import TeamsInbound

# name -> zero-arg factory -> InboundAdapter. Each reads its signing secret / public key from
# the environment (like the outbound surfaces read their webhooks), so all are zero-arg.
_BUILTIN_INBOUND: dict[str, Callable[[], InboundAdapter]] = {
    "slack": SlackInbound,
    "discord": DiscordInbound,
    "teams": TeamsInbound,
}

# Built-ins overlaid with discovered `steadystate.inbound` entry points.
INBOUND: dict[str, Callable[[], InboundAdapter]] = merged("inbound", _BUILTIN_INBOUND)

__all__ = ["INBOUND", "build_inbound"]


def build_inbound(name: str) -> InboundAdapter:
    """Construct the registered InboundAdapter for ``name``, or raise ValueError."""
    try:
        factory = INBOUND[name]
    except KeyError:
        known = ", ".join(sorted(INBOUND))
        raise ValueError(f"unknown inbound channel '{name}' (known: {known})") from None
    return factory()
