"""Surface plugins: push Alerts out (and, later, take operator input back).

Surfaces register here so `--to <name>` dispatches without hand-editing the CLI
for each one. Add a surface: write its module in this package, then add a single
line to SURFACES -- the CLI and its tests pick it up automatically. (Mirrors the
DriftSource registry in sources/__init__.py.)
"""

from __future__ import annotations

from collections.abc import Callable

from .base import Surface
from .console import ConsoleSurface
from .slack import SlackSurface
from .teams import TeamsSurface

# name -> zero-arg factory -> Surface. Indexed by the CLI's --to choice.
# slack/teams read their webhook from the environment, so all are zero-arg.
SURFACES: dict[str, Callable[[], Surface]] = {
    "console": ConsoleSurface,
    "slack": SlackSurface,
    "teams": TeamsSurface,
}

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
