"""StateSource plugins: declared state in.

Drift sources register here so `--source <name>` dispatches without hand-editing
the CLI for each one. Add an in-tree source: write its module in this package, then
add a single line to _BUILTIN_SOURCES -- the CLI and its tests pick it up automatically.

Out-of-tree sources register the same way without editing this file: a separately
installed package declares a `steadystate.sources` entry point and `merged()` overlays
it on the built-ins (built-ins win a name clash). See plugins.py / ARCHITECTURE.md.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

from ..plugins import merged
from .ansible import AnsibleSource
from .argocd import ArgoCDSource
from .base import Capabilities, DriftSource
from .docker_compose import DockerComposeSource
from .helm import HelmSource
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


def _helm(path: Path) -> DriftSource:
    # A FILE = captured `helm list --output json` (a JSON array of releases).
    return HelmSource(releases=json.loads(path.read_text()))


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
_BUILTIN_SOURCES: dict[str, Callable[[Path], DriftSource]] = {
    "terraform": _terraform,
    "argocd": _argocd,
    "ansible": _ansible,
    "docker-compose": _docker_compose,
    "k8s": _k8s,
    "rancher": _rancher,
    "helm": _helm,
}

# Per-plugin command manifests: observe (pre-approved, read-only) vs destructive (needs
# approval). Keyed like the source registry -- adding a source means declaring its commands too.
_BUILTIN_CAPABILITIES: dict[str, Capabilities] = {
    "terraform": TerraformSource.commands,
    "argocd": ArgoCDSource.commands,
    "ansible": AnsibleSource.commands,
    "docker-compose": DockerComposeSource.commands,
    "k8s": KubernetesSource.commands,
    "rancher": RancherSource.commands,
    "helm": HelmSource.commands,
}


def _build_sources() -> dict[str, Callable[[Path], DriftSource]]:
    return merged("sources", _BUILTIN_SOURCES)


def _build_capabilities(
    sources: dict[str, Callable[[Path], DriftSource]],
) -> dict[str, Capabilities]:
    """Built-in command manifests, plus any a discovered source factory advertises.

    An out-of-tree source factory may carry a ``commands`` attribute (a ``Capabilities``) so it
    shows up in ``steadystate commands`` and the catalog; if it doesn't, the source still scans,
    it just isn't listed there. Built-in manifests are authoritative and never overridden.
    """
    caps = dict(_BUILTIN_CAPABILITIES)
    for name, factory in sources.items():
        if name in caps:
            continue
        advertised = getattr(factory, "commands", None)
        if isinstance(advertised, Capabilities):
            caps[name] = advertised
    return caps


# The live registries: built-ins overlaid with discovered `steadystate.sources` entry points.
DRIFT_SOURCES: dict[str, Callable[[Path], DriftSource]] = _build_sources()
CAPABILITIES: dict[str, Capabilities] = _build_capabilities(DRIFT_SOURCES)

__all__ = ["CAPABILITIES", "DRIFT_SOURCES", "Capabilities", "build_drift_source"]


def build_drift_source(source: str, path: Path) -> DriftSource:
    """Construct the registered DriftSource for `source`, or raise ValueError."""
    try:
        factory = DRIFT_SOURCES[source]
    except KeyError:
        known = ", ".join(sorted(DRIFT_SOURCES))
        raise ValueError(f"unknown source '{source}' (known: {known})") from None
    return factory(path)
