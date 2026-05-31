"""Helm source -- v0.

Helm tracks deployments as *releases* (a chart + values, rendered and installed). A release in
steady state has status ``deployed``; one that's ``failed``, stuck in ``pending-upgrade`` /
``pending-rollback`` / ``pending-install``, or mid-``uninstalling`` is a departure -- usually an
interrupted or broken ``helm upgrade``, one of the most common Helm problems. We ride Helm's own
machine-readable status (``helm list -o json``) rather than re-derive it, and turn every
not-``deployed`` release into a Drift.

Capture the status with core Helm (no plugin needed)::

    helm list --all-namespaces --output json > releases.json   # then --source helm

Per-resource config drift (deployed manifests vs the chart, via the helm-diff plugin) is a
follow-up; this catches release-level malfunction, which the k8s source -- resource-level --
does not.
"""

from __future__ import annotations

import json
import subprocess

from ..model import ChangeType, Drift, Provenance
from .base import Capabilities

_HEALTHY = "deployed"  # the only steady-state Helm release status
# status -> ChangeType: a release that never landed reads as ADDED, one being torn down as
# REMOVED, and everything else (failed / pending-upgrade / pending-rollback / ...) as MODIFIED.
_ADDED_STATES = {"pending-install"}
_REMOVED_STATES = {"uninstalling"}


def _change_type(status: str) -> ChangeType:
    if status in _ADDED_STATES:
        return ChangeType.ADDED
    if status in _REMOVED_STATES:
        return ChangeType.REMOVED
    return ChangeType.MODIFIED


def drifts_from_helm_releases(releases: list[dict]) -> list[Drift]:
    """Parse ``helm list -o json`` output into Drift records -- one per release whose status isn't
    ``deployed``. The release's chart + revision ride along as observed context. Pure + testable."""
    out: list[Drift] = []
    for release in releases:
        status = str(release.get("status") or "").lower()
        if not status or status == _HEALTHY:
            continue
        name = release.get("name") or "?"
        namespace = release.get("namespace") or ""
        identity = "/".join(part for part in (namespace, name) if part)
        out.append(
            Drift(
                identity=identity,
                kind="HelmRelease",
                change_type=_change_type(status),
                provenance=Provenance(source="helm", address=identity),
                observed={
                    "status": status,
                    "chart": release.get("chart"),
                    "revision": release.get("revision"),
                },
            )
        )
    return out


class HelmSource:
    """A DriftSource. Construct with captured ``helm list -o json`` releases (testing / CI) or let
    it run ``helm list`` live -- all namespaces, or one via ``namespace``."""

    name = "helm"
    # Observe-only by declaration: steadystate reads release status; Helm owns the deploying.
    commands = Capabilities(
        observe=("helm list -o json", "helm status", "helm get manifest"),
        destructive=("helm upgrade", "helm rollback", "helm uninstall"),
    )

    def __init__(
        self,
        releases: list[dict] | None = None,
        namespace: str | None = None,
        timeout: float = 15.0,
    ) -> None:
        self._releases = releases
        self.namespace = namespace
        self.timeout = timeout

    def collect_drift(self) -> list[Drift]:
        releases = self._releases if self._releases is not None else self._run_list()
        return drifts_from_helm_releases(releases)

    def _run_list(self) -> list[dict]:
        cmd = ["helm", "list", "--output", "json"]
        cmd += ["--namespace", self.namespace] if self.namespace else ["--all-namespaces"]
        result = subprocess.run(
            cmd, check=True, capture_output=True, text=True, timeout=self.timeout
        )
        data = json.loads(result.stdout or "[]")
        return data if isinstance(data, list) else []
