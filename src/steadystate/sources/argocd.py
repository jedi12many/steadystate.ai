"""ArgoCD source -- v0.

ArgoCD already reconciles declared (Git) state against the live cluster, so we
ride its own sync status instead of re-deriving it: read an Application's
`status.resources[]` and turn every non-Synced resource into a Drift.

Each resource carries group/kind/namespace/name plus a per-resource `status`
(e.g. "Synced" / "OutOfSync"); anything that isn't Synced is divergence.
"""

from __future__ import annotations

import json
import os
import urllib.request

from .._http import safe_urlopen
from ..model import ChangeType, Drift, Provenance
from .base import Capabilities


def _identity(res: dict) -> str:
    parts = [res.get("group"), res.get("kind"), res.get("namespace"), res.get("name")]
    return "/".join(p for p in parts if p)


def drifts_from_argocd_app(app: dict) -> list[Drift]:
    """Parse an ArgoCD Application into Drift records. Pure + testable."""
    out: list[Drift] = []
    status = app.get("status") or {}
    for res in status.get("resources") or []:
        if (res.get("status") or "Synced") == "Synced":
            continue
        identity = _identity(res)
        out.append(
            Drift(
                identity=identity,
                kind=res.get("kind", "unknown"),
                change_type=ChangeType.MODIFIED,
                provenance=Provenance(source="argocd", address=identity),
                observed={"status": res.get("status")},
            )
        )
    return out


class ArgoCDSource:
    """A DriftSource. Construct with a captured Application dict (testing / CI) or
    a server base_url + bearer token to fetch one live."""

    name = "argocd"
    # Observe-only: steadystate reads an Application's sync status; ArgoCD owns the syncing.
    commands = Capabilities(observe=("GET /api/v1/applications/{app}",))

    def __init__(
        self,
        app: dict | None = None,
        app_name: str | None = None,
        base_url: str | None = None,
        token: str | None = None,
    ) -> None:
        self._app = app
        self.app_name = app_name
        self.base_url = base_url or os.environ.get("ARGOCD_SERVER")
        self.token = token or os.environ.get("ARGOCD_TOKEN")

    def collect_drift(self) -> list[Drift]:
        app = self._app if self._app is not None else self._fetch()
        return drifts_from_argocd_app(app)

    def _fetch(self) -> dict:
        if not self.base_url or not self.app_name:
            raise ValueError("ArgoCDSource needs app or base_url + app_name")
        url = f"{self.base_url.rstrip('/')}/api/v1/applications/{self.app_name}"
        req = urllib.request.Request(url)
        if self.token:
            req.add_header("Authorization", f"Bearer {self.token}")
        with safe_urlopen(req) as resp:
            return json.loads(resp.read())
