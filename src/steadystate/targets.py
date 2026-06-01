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
from collections.abc import Callable
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


def target_to_spec(target: Target) -> dict[str, str]:
    """A Target as the minimal JSON spec ``load_targets`` reads back: ``label`` and ``probe`` are
    omitted when they hold their defaults (the name, and ``auto``), so a generated file stays terse.
    Pure -- inverse of the per-entry parse in ``load_targets``."""
    spec = {"source": target.source, "path": target.path}
    if target.label != target.name:
        spec["label"] = target.label
    if target.probe != "auto":
        spec["probe"] = target.probe
    return spec


def merge_targets(
    existing: dict[str, Target], proposed: list[Target]
) -> tuple[dict[str, Target], list[str], list[str]]:
    """Overlay ``proposed`` onto ``existing`` WITHOUT clobbering: a proposed target whose name is
    already taken is skipped (the operator's hand-edits win). Returns (merged map, names added,
    names skipped). Pure -- the caller decides whether to persist the result."""
    added: dict[str, Target] = {}
    skipped: list[str] = []
    for target in proposed:
        if target.name in existing or target.name in added:
            skipped.append(target.name)
        else:
            added[target.name] = target
    return {**existing, **added}, list(added), skipped


def save_targets(path: str | Path, targets: dict[str, Target]) -> None:
    """Write the targets map to ``path`` as the JSON document ``load_targets`` reads. Overwrites the
    file wholesale, so callers preserving existing entries merge first (``merge_targets``)."""
    doc = {name: target_to_spec(target) for name, target in targets.items()}
    Path(path).write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")


def target_issues(
    target: Target,
    known_sources: set[str],
    known_probes: set[str],
    path_exists: Callable[[str], bool],
) -> list[str]:
    """Validate one target against the running build: its source is registered, its probe is a real
    one (or ``auto``/``none``), and its path resolves. Returns a list of human-readable problems --
    empty means healthy. Pure: ``path_exists`` is injected, so it's testable without a disk."""
    issues: list[str] = []
    if target.source not in known_sources:
        issues.append(f"unknown source '{target.source}'")
    if target.probe not in known_probes:
        issues.append(f"unknown probe '{target.probe}'")
    if not path_exists(target.path):
        issues.append("path not found")
    return issues
