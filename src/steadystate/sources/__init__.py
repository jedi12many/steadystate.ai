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

from .ansible import AnsibleSource
from .argocd import ArgoCDSource
from .base import Capabilities, DriftSource
from .docker_compose import DockerComposeSource
from .k8s import KubernetesSource
from .rancher import RancherSource
from .terraform import TerraformSource


def _terraform(path: Path) -> DriftSource:
    if path.is_file():
        return TerraformSource(plan_json=json.loads(path.read_text()))
    return TerraformSource(working_dir=path)


def _argocd(path: Path) -> DriftSource:
    return ArgoCDSource(app=json.loads(path.read_text()))


def _ansible(path: Path) -> DriftSource:
    # A FILE = captured `ANSIBLE_STDOUT_CALLBACK=json ansible-playbook --check --diff` output.
    return AnsibleSource(result=json.loads(path.read_text()))


def _rancher(path: Path) -> DriftSource:
    # A FILE = a captured Fleet GitRepo JSON.
    return RancherSource(gitrepo=json.loads(path.read_text()))


def _docker_compose(path: Path) -> DriftSource:
    # A directory = a live Compose project (run `docker compose config` + `ps`).
    # A file = a captured {"config": {...}, "ps": [...]} snapshot (testing / offline).
    if path.is_file():
        snap = json.loads(path.read_text())
        return DockerComposeSource(config=snap.get("config"), ps=snap.get("ps"))
    return DockerComposeSource(working_dir=path)


def _k8s(path: Path) -> DriftSource:
    # A file = a captured {"declared": <doc>, "observed": <doc>} snapshot. Both docs
    # are JSON (a K8s List, a bare array, or a single object) -- the project is
    # stdlib-only, so manifests are rendered to JSON first (e.g. `kubectl ... -o json`).
    snap = json.loads(path.read_text())
    return KubernetesSource(declared=snap.get("declared"), observed=snap.get("observed"))


# name -> factory(path) -> DriftSource. Indexed by the CLI's --source choice.
# docker-compose has no native plan diff, so it reconciles declared services
# (`docker compose config`) against running containers (`docker compose ps`).
DRIFT_SOURCES: dict[str, Callable[[Path], DriftSource]] = {
    "terraform": _terraform,
    "argocd": _argocd,
    "ansible": _ansible,
    "docker-compose": _docker_compose,
    "k8s": _k8s,
    "rancher": _rancher,
}

# Per-plugin command manifests: observe (pre-approved, read-only) vs destructive (needs
# approval). Keyed like DRIFT_SOURCES -- adding a source means declaring its commands too.
CAPABILITIES: dict[str, Capabilities] = {
    "terraform": TerraformSource.commands,
    "argocd": ArgoCDSource.commands,
    "ansible": AnsibleSource.commands,
    "docker-compose": DockerComposeSource.commands,
    "k8s": KubernetesSource.commands,
    "rancher": RancherSource.commands,
}

__all__ = ["CAPABILITIES", "DRIFT_SOURCES", "Capabilities", "build_drift_source"]


def build_drift_source(source: str, path: Path) -> DriftSource:
    """Construct the registered DriftSource for `source`, or raise ValueError."""
    try:
        factory = DRIFT_SOURCES[source]
    except KeyError:
        known = ", ".join(sorted(DRIFT_SOURCES))
        raise ValueError(f"unknown source '{source}' (known: {known})") from None
    return factory(path)
