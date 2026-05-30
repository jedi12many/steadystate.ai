"""Rancher (Fleet) source -- v0.

Rancher's GitOps engine, Fleet, already reconciles declared (Git) manifests
against downstream clusters, so we ride its own status instead of re-deriving
it: read a Fleet `GitRepo`'s `status.resources[]` and turn every non-Ready
resource into a Drift.

Each resource carries apiVersion/kind/namespace/name plus a per-resource `state`
(e.g. "Ready" / "Modified" / "Missing" / "Orphaned"); anything that isn't Ready
is divergence.
"""

from __future__ import annotations

import json
import os
import urllib.request

from ..model import ChangeType, Drift, Provenance

# state -> ChangeType. Anything absent from these sets is treated as MODIFIED.
_ADDED_STATES = {"Missing", "NotFound"}  # declared, not in reality yet
_REMOVED_STATES = {"Orphaned", "ExtraResource"}  # in reality, not declared


def _group(api_version: str) -> str:
    # apiVersion is "group/version" (e.g. "apps/v1") or bare "v1" for core (no group).
    return api_version.split("/", 1)[0] if "/" in api_version else ""


def _identity(res: dict) -> str:
    group = _group(res.get("apiVersion") or "")
    parts = [group, res.get("kind"), res.get("namespace"), res.get("name")]
    return "/".join(p for p in parts if p)


def _change_type(state: str) -> ChangeType:
    if state in _ADDED_STATES:
        return ChangeType.ADDED
    if state in _REMOVED_STATES:
        return ChangeType.REMOVED
    return ChangeType.MODIFIED


def drifts_from_fleet_gitrepo(gitrepo: dict) -> list[Drift]:
    """Parse a Fleet GitRepo into Drift records. Pure + testable."""
    out: list[Drift] = []
    status = gitrepo.get("status") or {}
    for res in status.get("resources") or []:
        state = res.get("state") or "Ready"
        if state == "Ready":
            continue
        identity = _identity(res)
        out.append(
            Drift(
                identity=identity,
                kind=res.get("kind", "unknown"),
                change_type=_change_type(state),
                provenance=Provenance(source="rancher", address=identity),
                observed={"state": state},
            )
        )
    return out


class RancherSource:
    """A DriftSource. Construct with a captured GitRepo dict (testing / CI) or a
    Rancher server base_url + bearer token to fetch one live."""

    name = "rancher"

    def __init__(
        self,
        gitrepo: dict | None = None,
        gitrepo_name: str | None = None,
        namespace: str = "fleet-default",
        base_url: str | None = None,
        token: str | None = None,
    ) -> None:
        self._gitrepo = gitrepo
        self.gitrepo_name = gitrepo_name
        self.namespace = namespace
        self.base_url = base_url or os.environ.get("RANCHER_URL")
        self.token = token or os.environ.get("RANCHER_TOKEN")

    def collect_drift(self) -> list[Drift]:
        gitrepo = self._gitrepo if self._gitrepo is not None else self._fetch()
        return drifts_from_fleet_gitrepo(gitrepo)

    def _fetch(self) -> dict:
        if not self.base_url or not self.gitrepo_name:
            raise ValueError("RancherSource needs gitrepo or base_url + gitrepo_name")
        url = (
            f"{self.base_url.rstrip('/')}/apis/fleet.cattle.io/v1alpha1"
            f"/namespaces/{self.namespace}/gitrepos/{self.gitrepo_name}"
        )
        req = urllib.request.Request(url)
        if self.token:
            req.add_header("Authorization", f"Bearer {self.token}")
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read())
