"""StateSource plugins: declared state in.

Drift sources register here so `--source <name>` dispatches without hand-editing
the CLI for each one. Add a source: write its module in this package, then add a
single line to DRIFT_SOURCES -- the CLI and its tests pick it up automatically.

(This is the in-tree registry; the eventual endpoint is importlib entry points so
out-of-tree packs register without editing this file -- see ARCHITECTURE.md.)
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

from .argocd import ArgoCDSource
from .base import DriftSource
from .terraform import TerraformSource


def _terraform(path: Path) -> DriftSource:
    if path.is_file():
        return TerraformSource(plan_json=json.loads(path.read_text()))
    return TerraformSource(working_dir=path)


def _argocd(path: Path) -> DriftSource:
    return ArgoCDSource(app=json.loads(path.read_text()))


# name -> factory(path) -> DriftSource. Indexed by the CLI's --source choice.
DRIFT_SOURCES: dict[str, Callable[[Path], DriftSource]] = {
    "terraform": _terraform,
    "argocd": _argocd,
}

# docker-compose is a declared-only StateSource (no native reconcile), so it is
# deliberately NOT a drift source yet -- it needs the observed-state/reconcile path
# before `scan` can use it. Tracked as the deferred StateSource work.

__all__ = ["DRIFT_SOURCES", "build_drift_source"]


def build_drift_source(source: str, path: Path) -> DriftSource:
    """Construct the registered DriftSource for `source`, or raise ValueError."""
    try:
        factory = DRIFT_SOURCES[source]
    except KeyError:
        known = ", ".join(sorted(DRIFT_SOURCES))
        raise ValueError(f"unknown source '{source}' (known: {known})") from None
    return factory(path)
