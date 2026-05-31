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
from steadystate.sources.k8s import KubernetesSource
from steadystate.sources.rancher import RancherSource
from steadystate.sources.terraform import TerraformSource


def _raise(exc):
    def boom(*args, **kwargs):
        raise exc

    return boom


# Each registered source -> a constructor that puts it in LIVE mode (no captured input), returning
# the `collect_drift` whose call shells out / fetches. Add an entry when you add a source.
_LIVE: dict[str, Callable[[object], Callable[[], object]]] = {
    "terraform": lambda d: TerraformSource(working_dir=d).collect_drift,
    "k8s": lambda d: KubernetesSource(declared=[], get_args=["pods"]).collect_drift,
    "docker-compose": lambda d: DockerComposeSource(working_dir=d).collect_drift,
    "ansible": lambda d: AnsibleSource(playbook="site.yml").collect_drift,
    "helm": lambda d: HelmSource().collect_drift,
    "argocd": lambda d: ArgoCDSource(app_name="web", base_url="http://argo.test").collect_drift,
    "rancher": lambda d: (
        RancherSource(gitrepo_name="repo", base_url="http://rancher.test").collect_drift
    ),
}


def test_live_failure_wiring_covers_every_registered_source():
    # The guard's guard: if a source is registered but absent here, the parametrized test below
    # would skip its live branch -- so require the two sets to match exactly.
    assert set(_LIVE) == set(DRIFT_SOURCES), (
        f"sources without live-failure wiring: {set(DRIFT_SOURCES) - set(_LIVE)}"
    )


@pytest.mark.parametrize("name", sorted(DRIFT_SOURCES))
def test_every_live_source_raises_sourceerror_not_a_traceback(name, tmp_path, monkeypatch):
    # Make BOTH backends fail: subprocess sources hit a missing binary, HTTP sources an unreachable
    # server. Each source uses whichever it depends on; either way the scan must get a clean
    # SourceError -- never a raw FileNotFoundError/URLError/JSONDecodeError, never a silent empty.
    monkeypatch.setattr(subprocess, "run", _raise(FileNotFoundError()))
    monkeypatch.setattr(sources_base, "safe_urlopen", _raise(urllib.error.URLError("down")))
    trigger = _LIVE[name](tmp_path)
    with pytest.raises(SourceError):
        trigger()
