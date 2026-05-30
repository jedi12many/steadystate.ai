"""Kubernetes health probe -- originate Symptoms for declared workloads.

For any *declared* workload whose pods are failing (`unhealthy_pods`), produces a first-class
`Symptom` -- so a malfunction surfaces even with no drift, and correlates with a drift when there
is one. Reads via `kubectl`; any failure degrades to "no symptoms" (never invent a problem, never
break a scan).
"""

from __future__ import annotations

import json
import logging
import subprocess
from dataclasses import dataclass

from ..model import Provenance, Resource
from ..reason.alert import Severity
from .base import Symptom

logger = logging.getLogger(__name__)

# Container waiting-state reasons that mean it can't run at all.
_UNHEALTHY_WAITING = frozenset(
    {
        "CrashLoopBackOff",
        "ImagePullBackOff",
        "ErrImagePull",
        "CreateContainerConfigError",
        "CreateContainerError",
        "RunContainerError",
    }
)
_RESTART_THRESHOLD = 5  # restarts above this read as unhealthy even if currently Running


@dataclass(frozen=True)
class PodHealth:
    """One unhealthy pod of a workload: its name, why, and its restart count."""

    name: str
    reason: str  # a bad waiting reason, "Failed", or "N restarts"
    restarts: int


def unhealthy_pods(pods: dict, workload: str) -> list[PodHealth]:
    """The unhealthy pods belonging to ``workload`` in a ``kubectl get pods -o json`` document.

    A pod belongs to the workload if its name is the workload or starts with ``<workload>-``
    (the Deployment/ReplicaSet/StatefulSet/Job naming). Unhealthy = a container stuck in a known
    bad waiting state, a Failed phase, or a restart count over the threshold. Pure + testable."""
    out: list[PodHealth] = []
    for pod in pods.get("items") or []:
        name = (pod.get("metadata") or {}).get("name") or ""
        if name != workload and not name.startswith(f"{workload}-"):
            continue
        status = pod.get("status") or {}
        container_statuses = status.get("containerStatuses") or []
        restarts = sum(int(cs.get("restartCount") or 0) for cs in container_statuses)
        reason = ""
        for cs in container_statuses:
            waiting = (cs.get("state") or {}).get("waiting") or {}
            if waiting.get("reason") in _UNHEALTHY_WAITING:
                reason = waiting["reason"]
                break
        if not reason and status.get("phase") == "Failed":
            reason = "Failed"
        if not reason and restarts > _RESTART_THRESHOLD:
            reason = f"{restarts} restarts"
        if reason:
            out.append(PodHealth(name=name, reason=reason, restarts=restarts))
    return out


# Waiting reasons where the container can't run at all -> HIGH. A flapping-but-running pod
# (over the restart threshold, reason "N restarts") is MEDIUM.
_CANNOT_RUN = frozenset(
    {
        "CrashLoopBackOff",
        "ImagePullBackOff",
        "ErrImagePull",
        "CreateContainerConfigError",
        "CreateContainerError",
        "RunContainerError",
        "Failed",
    }
)


def _name(identity: str) -> str:
    """The bare workload name -- last `/`- or `.`-segment (apps/Deployment/prod/web -> web)."""
    return identity.replace("/", ".").rsplit(".", 1)[-1]


def _namespace(identity: str) -> str:
    """The namespace segment of a slash identity, else "" (apps/Deployment/prod/web -> prod)."""
    if "/" not in identity:
        return ""
    segments = identity.split("/")
    return segments[-2] if len(segments) >= 2 else ""


def category_and_severity(sick: list[PodHealth]) -> tuple[str, Severity]:
    """The dominant category + its severity. A "cannot-run" reason on any pod wins (HIGH);
    otherwise a flapping/restarting workload is MEDIUM. Pure + testable."""
    worst = max(sick, key=lambda pod: (pod.reason in _CANNOT_RUN, pod.restarts))
    severity = Severity.HIGH if any(pod.reason in _CANNOT_RUN for pod in sick) else Severity.MEDIUM
    return worst.reason, severity


class KubectlProbe:
    """Produces a Symptom per declared kubernetes workload whose pods are unhealthy now."""

    name = "kubectl"

    def __init__(self, log_tail: int = 20, timeout: float = 10.0) -> None:
        self.log_tail = log_tail
        self.timeout = timeout

    def probe(self, resources: list[Resource]) -> list[Symptom]:
        symptoms: list[Symptom] = []
        pods_by_namespace: dict[str, dict] = {}  # one `kubectl get pods` per namespace, cached
        for resource in resources:
            if resource.provenance.source != "kubernetes":
                continue
            namespace = _namespace(resource.identity) or "default"
            workload = _name(resource.identity)
            pods = pods_by_namespace.setdefault(namespace, self._get_pods(namespace))
            sick = unhealthy_pods(pods, workload)
            if sick:
                symptoms.append(self._symptom(resource, namespace, sick))
        return symptoms

    def _symptom(self, resource: Resource, namespace: str, sick: list[PodHealth]) -> Symptom:
        category, severity = category_and_severity(sick)
        worst = max(sick, key=lambda pod: pod.restarts)
        tail = self._last_log_line(namespace, worst.name)
        detail = f"{len(sick)} pod(s) {category}" + (f"; last log: {tail}" if tail else "")
        return Symptom(
            identity=resource.identity,
            kind=resource.kind,
            category=category,
            severity=severity,
            title=f"{_name(resource.identity)} is {category}",
            detail=detail,
            provenance=Provenance(source="kubernetes", address=resource.identity),
        )

    def _get_pods(self, namespace: str) -> dict:
        text = self._run_text(["kubectl", "get", "pods", "-n", namespace, "-o", "json"])
        if not text:
            return {}
        try:
            parsed = json.loads(text)
        except ValueError:
            return {}
        return parsed if isinstance(parsed, dict) else {}

    def _last_log_line(self, namespace: str, pod: str) -> str:
        tail = str(self.log_tail)
        text = self._run_text(
            ["kubectl", "logs", pod, "-n", namespace, "--tail", tail, "--previous"]
        )
        if not text:
            text = self._run_text(["kubectl", "logs", pod, "-n", namespace, "--tail", tail])
        lines = [line for line in (text or "").splitlines() if line.strip()]
        return lines[-1][:200] if lines else ""

    def _run_text(self, argv: list[str]) -> str:
        try:
            result = subprocess.run(
                argv, check=True, capture_output=True, text=True, timeout=self.timeout
            )
            return result.stdout
        except (subprocess.SubprocessError, OSError) as exc:
            logger.warning("kubectl probe (%s) failed: %s", " ".join(argv[:3]), exc)
            return ""
