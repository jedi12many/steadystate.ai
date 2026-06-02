"""Probe plugins: read the live health of declared resources into Symptoms (§4 of the
architecture). A new health probe registers here so `--probe <name>` dispatches without
editing the CLI. Mirrors the source / surface / enricher registries.

A probe is selected by name, or by `--probe auto` (the probe that matches `--source`). Live
probes (kubectl, docker) shell out for health and ignore the path; snapshot probes (argocd)
read the same captured document the source does, so they take the scan ``path``.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

from ..sources.base import Capabilities
from .argocd import ArgoCDProbe
from .base import Prober, Symptom
from .docker import DockerProbe
from .kubectl import KubectlProbe


def _load_json(path: Path) -> dict:
    """The captured document a snapshot probe reads (the source's input). {} on any failure, so a
    mismatched --source/--probe degrades to no symptoms rather than crashing."""
    try:
        parsed = json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


# name -> factory(path) -> Prober, indexed by the CLI's --probe choice. "none" (the default)
# means no probe -- resolved to None in build_prober, not registered here.
PROBES: dict[str, Callable[[Path], Prober]] = {
    "kubectl": lambda path: KubectlProbe(),
    "docker": lambda path: DockerProbe(),
    "argocd": lambda path: ArgoCDProbe(_load_json(path)),
}

# Per-probe command manifest, mirroring the sources' CAPABILITIES: the read-only `observe`
# commands each probe shells out to (a probe never acts, so there are no destructive ones). Keyed
# like PROBES, so `steadystate commands` and the catalog show exactly what a probe will run -- and
# an operator can derive least-privilege access (e.g. kubectl `pods` + `pods/log`) from it.
PROBE_CAPABILITIES: dict[str, Capabilities] = {
    "kubectl": KubectlProbe.commands,
    "docker": DockerProbe.commands,
    "argocd": ArgoCDProbe.commands,
}

# Which probe `--probe auto` picks per source -- only the sources with a real health signal
# distinct from their drift (k8s pods, compose containers, ArgoCD's own health field).
# Keys are the registered --source names (DRIFT_SOURCES), NOT a resource's provenance.source --
# the Kubernetes source registers as "k8s" (it stamps provenance "kubernetes" internally, which
# is what the kubectl probe filters on, a separate namespace). test_auto_keys_are_registered_sources
# guards this so a key can never silently miss its source again.
_AUTO: dict[str, str] = {
    "k8s": "kubectl",
    "k8s-live": "kubectl",  # the live cluster-health source relies on the kubectl probe for fires
    "docker-compose": "docker",
    "argocd": "argocd",
}

__all__ = [
    "PROBE_CAPABILITIES",
    "PROBES",
    "Prober",
    "Symptom",
    "auto_prober_for",
    "build_prober",
]


def auto_prober_for(source: str) -> str | None:
    """The probe name `--probe auto` selects for ``source``, or None if none makes sense."""
    return _AUTO.get(source)


def build_prober(mode: str, path: Path) -> Prober | None:
    """Construct the Prober for ``mode`` (a registry name or ``none``), or raise ValueError.

    - ``none``: None -- no probe step runs, the un-probed path is unchanged.
    - any registered name (``kubectl`` | ``docker`` | ``argocd`` | an out-of-tree probe).
    - anything else: ValueError, which the CLI turns into a clean typer.BadParameter.
    """
    if mode == "none":
        return None
    try:
        factory = PROBES[mode]
    except KeyError:
        known = ", ".join(sorted(PROBES))
        raise ValueError(f"unknown prober '{mode}' (known: none, auto, {known})") from None
    return factory(path)
