"""Surface plugins: push Alerts out (and, later, take operator input back).

Surfaces register here so `--to <name>` dispatches without hand-editing the CLI
for each one. Add an in-tree surface: write its module in this package, then add a
single line to _BUILTIN_SURFACES -- the CLI and its tests pick it up automatically.
(Mirrors the DriftSource registry in sources/__init__.py.)

Out-of-tree surfaces register the same way without editing this file: a separately
installed package declares a `steadystate.surfaces` entry point (a zero-arg factory)
and `merged()` overlays it on the built-ins (built-ins win a name clash). See plugins.py.
"""

from __future__ import annotations

from collections.abc import Callable

from ..plugins import merged
from .base import Surface
from .console import ConsoleSurface
from .discord import DiscordSurface
from .grafana import GrafanaSurface
from .pagerduty import PagerDutySurface
from .prometheus import PrometheusSurface
from .servicenow import ServiceNowSurface
from .slack import SlackSurface
from .teams import TeamsSurface
from .webhook import WebhookSurface

# name -> zero-arg factory -> Surface. Indexed by the CLI's --to choice.
# slack/teams read their webhook, prometheus/grafana their URL+token, webhook/pagerduty
# their URL+key, from the environment, so all are zero-arg.
_BUILTIN_SURFACES: dict[str, Callable[[], Surface]] = {
    "console": ConsoleSurface,
    "slack": SlackSurface,
    "teams": TeamsSurface,
    "discord": DiscordSurface,
    "prometheus": PrometheusSurface,
    "grafana": GrafanaSurface,
    "webhook": WebhookSurface,
    "pagerduty": PagerDutySurface,
    "servicenow": ServiceNowSurface,
}

# Built-ins overlaid with discovered `steadystate.surfaces` entry points.
SURFACES: dict[str, Callable[[], Surface]] = merged("surfaces", _BUILTIN_SURFACES)

__all__ = ["SURFACES", "build_surfaces"]


def build_surfaces(names: list[str]) -> list[Surface]:
    """Construct the registered Surfaces for `names`, or raise ValueError."""
    surfaces: list[Surface] = []
    for name in names:
        try:
            factory = SURFACES[name]
        except KeyError:
            known = ", ".join(sorted(SURFACES))
            raise ValueError(f"unknown surface '{name}' (known: {known})") from None
        surfaces.append(factory())
    return surfaces
