"""Named targets: a friendly name -> what to scan/probe on demand.

A scheduled scan knows its source/path/label from the cron command line. A chat-summoned probe
(``@steadystate probe prod-k8s``) only has a *name*, so the listener needs a registry that maps
that name to the same inputs a scan takes. It's a small JSON document the operator provides
(pointed at by ``STEADYSTATE_TARGETS``); each entry is one target. Keeping it a plain file --
not code -- means the listener never needs redeploying to add a target.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

TARGETS_ENV = "STEADYSTATE_TARGETS"  # path to the targets JSON document


@dataclass(frozen=True)
class Target:
    """One named target: the inputs a summoned scan/probe runs with -- the same shape as the
    arguments to ``scan`` (source + path + label), plus the probe to read live health with."""

    name: str
    source: str
    path: str
    label: str  # the environment stamped on the alerts; defaults to the name
    probe: str = "auto"  # the health probe to run; "auto" matches the source


def load_targets(path: str | Path) -> dict[str, Target]:
    """Load the targets JSON document at ``path`` into a name -> Target map.

    Format: ``{"<name>": {"source": ..., "path": ..., "label"?: ..., "probe"?: ...}, ...}``.
    Raises ``ValueError`` (or ``OSError`` if the file is missing) on a malformed document, so a
    typo fails loudly at load time -- never silently mid-probe.
    """
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("targets file must be a JSON object of name -> target")
    out: dict[str, Target] = {}
    for name, spec in raw.items():
        if not isinstance(spec, dict) or "source" not in spec or "path" not in spec:
            raise ValueError(f"target '{name}' needs at least 'source' and 'path'")
        out[name] = Target(
            name=name,
            source=str(spec["source"]),
            path=str(spec["path"]),
            label=str(spec.get("label") or name),
            probe=str(spec.get("probe") or "auto"),
        )
    return out


def load_targets_from_env() -> dict[str, Target]:
    """The targets registry from ``STEADYSTATE_TARGETS``, or ``{}`` when it isn't set -- so a
    listener with no targets configured answers a probe request cleanly instead of erroring."""
    path = os.environ.get(TARGETS_ENV)
    return load_targets(path) if path else {}
