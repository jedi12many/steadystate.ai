"""Registry-driven guard: EVERY live drift source fails clean, not with a raw traceback (M1/M2).

The per-bug tests (test_source_failures, test_http_source_failures) each pin one source. This is
the guard that closes the *class*: it drives every registered `DRIFT_SOURCES` entry's live path
with the underlying tool/HTTP failing and requires a `SourceError`. A new source with no wiring
here fails the wiring check below, so it can't ship without a failure-path test -- the same
"registry and its tests can't silently drift apart" property as the auto-probe-key and
per-source command-manifest guards. (Why this matters: M1/M2 went unnoticed because every
*other* source test injected clean captured JSON and never exercised the live branch.)
"""

from __future__ import annotations

import subprocess
import urllib.error
from collections.abc import Callable

import pytest

from steadystate.sources import DRIFT_SOURCES
from steadystate.sources import base as sources_base
from steadystate.sources.ansible import AnsibleSource
from steadystate.sources.argocd import ArgoCDSource
from steadystate.sources.base import SourceError
from steadystate.sources.docker_compose import DockerComposeSource
from steadystate.sources.helm import HelmSource
from steadystate.sources.k8s import (
    KubernetesBaselineSource,
    KubernetesLiveSource,
    KubernetesSource,
    KustomizeLiveSource,
)
from steadystate.sources.rancher import RancherSource
from steadystate.sources.terraform import TerraformSource


def _raise(exc):
    def boom(*args, **kwargs):
        raise exc

    return boom


# Each registered source -> a constructor that puts it in LIVE mode (no captured input), returning
# the live method whose call shells out / fetches. Usually `collect_drift`; for the zero-drift
# k8s-live source that's `collect_declared` (its live kubectl read lives there -- collect_drift is
# a constant []). Add an entry when you add a source.
_LIVE: dict[str, Callable[[object], Callable[[], object]]] = {
    "terraform": lambda d: TerraformSource(working_dir=d).collect_drift,
    "k8s": lambda d: KubernetesSource(declared=[], get_args=["pods"]).collect_drift,
    "k8s-live": lambda d: KubernetesLiveSource().collect_declared,
    # baseline injected so collect_drift gets past the baseline load to the live read (the kubectl).
    "k8s-baseline": lambda d: KubernetesBaselineSource(baseline={"items": []}).collect_drift,
    # the overlay dir (tmp_path) has no kustomization.yaml -> `kubectl kustomize` fails (or kubectl
    # is absent) -> render raises SourceError before any reconcile.
    "kustomize-live": lambda d: KustomizeLiveSource(d).collect_drift,
    "docker-compose": lambda d: DockerComposeSource(working_dir=d).collect_drift,
    "ansible": lambda d: AnsibleSource(playbook="site.yml").collect_drift,
    "helm": lambda d: HelmSource().collect_drift,
    "argocd": lambda d: ArgoCDSource(app_name="web", base_url="http://argo.test").collect_drift,
    "rancher": lambda d: (
        RancherSource(gitrepo_name="repo", base_url="http://rancher.test").collect_drift
    ),
}


# Probe-only sources: pathless sources whose drift path is a deliberate constant [] (no backend
# I/O) -- the live read is the health *probe's* job, and a probe degrades to [] (never raises) by
# design. They have no raising drift read to guard here, so they're exempt; a new one must be added
# here on purpose. (ansible-live hosts the ansible health probe, like k8s-live hosts kubectl -- but
# k8s-live's collect_declared still does a live kubectl read, so it stays in _LIVE.)
_PROBE_ONLY: frozenset[str] = frozenset({"ansible-live"})


def test_live_failure_wiring_covers_every_registered_source():
    # The guard's guard: if a source is registered but absent here, the parametrized test below
    # would skip its live branch -- so require the two sets to match exactly (minus probe-only).
    assert set(_LIVE) == set(DRIFT_SOURCES) - _PROBE_ONLY, (
        f"sources without live-failure wiring: {set(DRIFT_SOURCES) - _PROBE_ONLY - set(_LIVE)}"
    )


@pytest.mark.parametrize("name", sorted(set(DRIFT_SOURCES) - _PROBE_ONLY))
def test_every_live_source_raises_sourceerror_not_a_traceback(name, tmp_path, monkeypatch):
    # Make BOTH backends fail: subprocess sources hit a missing binary, HTTP sources an unreachable
    # server. Each source uses whichever it depends on; either way the scan must get a clean
    # SourceError -- never a raw FileNotFoundError/URLError/JSONDecodeError, never a silent empty.
    monkeypatch.setattr(subprocess, "run", _raise(FileNotFoundError()))
    monkeypatch.setattr(sources_base, "safe_urlopen", _raise(urllib.error.URLError("down")))
    trigger = _LIVE[name](tmp_path)
    with pytest.raises(SourceError):
        trigger()
