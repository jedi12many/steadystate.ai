"""ArgoCD health probe -- originate Symptoms from ArgoCD's own per-resource health.

The cleanest "rent the detection" of all: ArgoCD already computes a health status for every
resource in an Application (`status.resources[].health.status`: Healthy / Degraded / Progressing
/ Missing / Suspended / Unknown), *separate* from its sync status. The ArgoCD *source* rides the
**sync** status into Drift; this probe rides the **health** status into Symptoms. A resource that
is both OutOfSync (a Drift) and Degraded (a Symptom) -- same identity -- diagnoses into one Alert.

Reads the same Application snapshot the source consumes (no extra access); identities match the
source exactly, so co-located drift + symptom correlate.
"""

from __future__ import annotations

from ..model import Provenance, Resource
from ..reason.alert import Severity
from ..sources.base import Capabilities
from .base import Symptom

# ArgoCD health.status -> severity. Healthy/Progressing/Suspended are fine or transient (skipped);
# Degraded is a real failure, Missing/Unknown are not-OK-but-softer.
_UNHEALTHY = {
    "Degraded": Severity.HIGH,
    "Missing": Severity.MEDIUM,
    "Unknown": Severity.MEDIUM,
}


def _identity(res: dict) -> str:
    parts = [res.get("group"), res.get("kind"), res.get("namespace"), res.get("name")]
    return "/".join(part for part in parts if part)


def symptoms_from_argocd_app(app: dict) -> list[Symptom]:
    """Parse an ArgoCD Application's per-resource health into Symptoms. Pure + testable."""
    out: list[Symptom] = []
    for res in (app.get("status") or {}).get("resources") or []:
        health = res.get("health") or {}
        status = str(health.get("status") or "")
        severity = _UNHEALTHY.get(status)
        if severity is None:  # Healthy / Progressing / Suspended / no health block -> not a symptom
            continue
        identity = _identity(res)
        message = str(health.get("message") or "").strip()
        detail = f"ArgoCD health: {status}" + (f" -- {message}" if message else "")
        out.append(
            Symptom(
                identity=identity,
                kind=res.get("kind") or "unknown",
                category=status,
                severity=severity,
                title=f"{res.get('name') or identity} is {status}",
                detail=detail,
                provenance=Provenance(source="argocd", address=identity),
            )
        )
    return out


class ArgoCDProbe:
    """Produces a Symptom per ArgoCD-managed resource whose health is Degraded / Missing / Unknown.
    Constructed with the captured Application dict (the same snapshot the source reads)."""

    name = "argocd"
    # Reads the per-resource health.status from the captured Application snapshot (same doc the
    # source rides for sync) -- no live command of its own, hence an empty observe manifest.
    commands = Capabilities(observe=())

    def __init__(self, app: dict | None = None) -> None:
        self._app = app or {}

    def probe(self, resources: list[Resource]) -> list[Symptom]:
        # Health lives in the Application snapshot, not in `resources` -- argocd is a drift-only
        # source, so `resources` is empty here; we read the snapshot we were built with.
        return symptoms_from_argocd_app(self._app)
