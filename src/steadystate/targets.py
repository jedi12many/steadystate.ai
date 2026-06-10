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
# The legacy/gitignored registry path -- still read when it's what a repo has. Targets earned a
# committed home when `kubeconfig_from` made them pointers (a broker command), never keys: see
# COMMITTED_TARGETS_FILE below, the preferred location.
DEFAULT_TARGETS_FILE = ".steadystate/targets.json"
COMMITTED_TARGETS_FILE = "steadystate/targets.json"  # version-controlled INTENT (preferred)


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
    # The kubeconfig file this target's context lives in, when it isn't on the default path (e.g. a
    # kubeconfig sitting in the project dir, not merged into ~/.kube/config). Empty = the ambient
    # kubeconfig. When set, every kubectl read for this target adds ``--kubeconfig <file>``.
    kubeconfig: str = ""
    # The **broker command** that mints this target's kubeconfig fresh at probe time (e.g.
    # ``akeyless get-secret-value --name /k8s/prod/kubeconfig``, a ``vault``/``rancher`` one-liner,
    # or your own script): its stdout IS the kubeconfig. Run as an argv (no shell), fail-closed,
    # the output held in a temp file for exactly one probe -- the long-running-server answer to
    # short-lived credentials (see broker.py / examples/brokered-creds). Mutually exclusive with
    # ``kubeconfig`` (one says where the file IS, the other says how to MINT it).
    kubeconfig_from: str = ""
    # The Ansible inventory file an ``ansible-live`` target reads host/service health from (empty
    # for other sources). Discovered from ansible.cfg/cwd; passed to the ansible probe as ``-i``.
    inventory: str = ""


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
        if spec.get("kubeconfig") and spec.get("kubeconfig_from"):
            # Ambiguous intent must fail at load, not silently pick one mid-probe: `kubeconfig`
            # names a standing file, `kubeconfig_from` mints a fresh one -- they can't both win.
            raise ValueError(
                f"target '{name}' sets both 'kubeconfig' and 'kubeconfig_from' -- choose one "
                "(a standing file, or a broker command that mints it at probe time)"
            )
        out[name] = Target(
            name=name,
            source=str(spec["source"]),
            path=str(spec.get("path") or ""),
            label=str(spec.get("label") or name),
            probe=str(spec.get("probe") or "auto"),
            context=str(spec.get("context") or ""),
            kubeconfig=str(spec.get("kubeconfig") or ""),
            kubeconfig_from=str(spec.get("kubeconfig_from") or ""),
            inventory=str(spec.get("inventory") or ""),
        )
    return out


def resolve_targets_path(explicit: str = "") -> str:
    """Where the targets registry lives. Targets are *intent* once their credentials are brokered
    (``kubeconfig_from`` -- pointers, never keys), so the **committed** ``steadystate/`` is the
    preferred home: it travels with the repo, and every entry point -- the CLI, the listener, an
    MCP server a client spawns with no env -- finds it with nothing exported. Order: ``explicit``,
    else ``STEADYSTATE_TARGETS``, else committed ``steadystate/targets.json`` if it exists, else
    the legacy ``.steadystate/targets.json`` if THAT exists -- and for a fresh write (neither
    yet), the committed location, so a new registry lands somewhere reviewed."""
    from .config import in_steadystate_tree

    if explicit:
        return explicit
    env = os.environ.get(TARGETS_ENV, "").strip()
    if env:
        return env
    if Path(COMMITTED_TARGETS_FILE).exists():
        return COMMITTED_TARGETS_FILE
    # Inside a steadystate/ tree (a silo at steadystate/silos/<name>/) the committed prefix would
    # stutter -- the bare file IS the committed location there, and fresh writes land bare too.
    in_tree = in_steadystate_tree()
    if in_tree and Path("targets.json").exists():
        return "targets.json"
    if Path(DEFAULT_TARGETS_FILE).exists():
        return DEFAULT_TARGETS_FILE
    return "targets.json" if in_tree else COMMITTED_TARGETS_FILE


def load_targets_from_env() -> dict[str, Target]:
    """The targets registry every surface resolves (scan --target / chat / MCP / `up`'s sweep):
    ``STEADYSTATE_TARGETS`` if set (a set-but-unreadable path fails LOUDLY -- a typo must never
    read as 'no targets'), else the committed ``steadystate/targets.json``, else the legacy
    ``.steadystate/targets.json``. ``{}`` when none resolves, so a listener with no targets
    answers a probe cleanly instead of erroring."""
    env = os.environ.get(TARGETS_ENV, "").strip()
    if env:
        return load_targets(env)
    path = resolve_targets_path()
    return load_targets(path) if Path(path).exists() else {}


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
    if target.kubeconfig:
        spec["kubeconfig"] = target.kubeconfig
    if target.kubeconfig_from:
        spec["kubeconfig_from"] = target.kubeconfig_from
    if target.inventory:
        spec["inventory"] = target.inventory
    return spec


def save_targets(path: str | Path, targets: dict[str, Target]) -> None:
    """Write the targets map to ``path`` as the JSON document ``load_targets`` reads. Creates the
    parent dir (the default lives under ``.steadystate/``) and overwrites the file wholesale -- the
    map passed in is the file's new, complete contents."""
    doc = {name: target_to_spec(target) for name, target in targets.items()}
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")


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
