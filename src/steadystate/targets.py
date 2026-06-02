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
# The default registry path when STEADYSTATE_TARGETS isn't set. Deliberately steadystate-specific
# (not a bare ``targets.json``) so `discover --create` and the chat fallback never read or clobber
# an unrelated `targets.json` that happens to be in the cwd.
DEFAULT_TARGETS_FILE = "steadystate.targets.json"


@dataclass(frozen=True)
class Target:
    """One named target: the inputs a summoned scan/probe runs with -- the same shape as the
    arguments to ``scan`` (source + path + label), plus the probe to read live health with.

    A **live** target (a pathless source like ``k8s-live``) carries no ``path`` -- it reads live
    state itself -- and instead names a ``context`` (a kube context), so a target *is* a cluster:
    ``probe prod-cluster`` aims the source + probe at that one cluster."""

    name: str
    source: str
    path: str = ""  # empty for a live source that reads live state (no file/dir to point at)
    label: str = ""  # the environment stamped on the alerts; defaults to the name
    probe: str = "auto"  # the health probe to run; "auto" matches the source
    context: str = ""  # a live backend context (a kube context) -- aims source + probe at it


def load_targets(path: str | Path) -> dict[str, Target]:
    """Load the targets JSON document at ``path`` into a name -> Target map.

    Format: ``{"<name>": {"source": ..., "path"?: ..., "label"?: ..., "probe"?: ...,
    "context"?: ...}, ...}``. ``path`` is optional -- a live target (k8s-live) omits it and names a
    ``context`` instead. Raises ``ValueError`` (or ``OSError`` if the file is missing) on a
    malformed document, so a typo fails loudly at load time -- never silently mid-probe.
    """
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("targets file must be a JSON object of name -> target")
    out: dict[str, Target] = {}
    for name, spec in raw.items():
        if not isinstance(spec, dict) or "source" not in spec:
            raise ValueError(f"target '{name}' needs at least a 'source'")
        out[name] = Target(
            name=name,
            source=str(spec["source"]),
            path=str(spec.get("path") or ""),
            label=str(spec.get("label") or name),
            probe=str(spec.get("probe") or "auto"),
            context=str(spec.get("context") or ""),
        )
    return out


def load_targets_from_env() -> dict[str, Target]:
    """The targets registry: ``STEADYSTATE_TARGETS`` if set, else ``./steadystate.targets.json``
    when it exists -- the same resolution `scan --target` / `targets` use, so a `discover --create`
    registry is picked up by the local `chat` REPL without exporting an env var. ``{}`` when neither
    resolves, so a listener with no targets answers a probe cleanly instead of erroring."""
    path = os.environ.get(TARGETS_ENV)
    if path:
        return load_targets(path)
    default = Path(DEFAULT_TARGETS_FILE)
    return load_targets(default) if default.exists() else {}


def target_to_spec(target: Target) -> dict[str, str]:
    """A Target as the minimal JSON spec ``load_targets`` reads back: ``path``/``label``/``probe``/
    ``context`` are omitted when empty or at their default (so a live target writes just
    ``source`` + ``context``, a file target stays terse). Pure -- inverse of ``load_targets``."""
    spec = {"source": target.source}
    if target.path:
        spec["path"] = target.path
    if target.label != target.name:
        spec["label"] = target.label
    if target.probe != "auto":
        spec["probe"] = target.probe
    if target.context:
        spec["context"] = target.context
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
    pathless: frozenset[str] = frozenset(),
) -> list[str]:
    """Validate one target against the running build: its source is registered, its probe is a real
    one (or ``auto``/``none``), and its path resolves. Returns a list of human-readable problems --
    empty means healthy. Pure: ``path_exists`` is injected, so it's testable without a disk.

    A target whose source is in ``pathless`` (a live source like ``k8s-live``) reads live state, so
    it has no path to resolve -- its reachability is the probe's job at run time, not a static
    check here -- so the path check is skipped for it."""
    issues: list[str] = []
    if target.source not in known_sources:
        issues.append(f"unknown source '{target.source}'")
    if target.probe not in known_probes:
        issues.append(f"unknown probe '{target.probe}'")
    if target.source not in pathless and not path_exists(target.path):
        issues.append("path not found")
    return issues
