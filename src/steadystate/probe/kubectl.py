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
from ..sources.base import Capabilities
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


def _controller(pod: dict) -> tuple[str, str]:
    """The pod's controller owner as ``(name, kind)`` -- the ReplicaSet for a Deployment, the
    StatefulSet/DaemonSet/Job directly -- or ``("", "")`` for a bare pod with no controller (then
    the caller falls back to the pod's own name). Pure."""
    for ref in (pod.get("metadata") or {}).get("ownerReferences") or []:
        if isinstance(ref, dict) and ref.get("controller"):
            return str(ref.get("name") or ""), str(ref.get("kind") or "")
    return "", ""


def _owner_belongs(name: str, kind: str, workload: str) -> bool:
    """Does a controller ``(name, kind)`` belong to ``workload``? A Deployment's pods are owned by a
    ReplicaSet ``<workload>-<pod-template-hash>`` (the hash is a single dash-free segment) -- so we
    require that exact shape, which distinguishes ``squid`` from a sibling ``squid-proxy`` (whose RS
    leaves the suffix ``proxy-<hash>``, not a bare hash). Every other controller (StatefulSet,
    DaemonSet, Job) owns its pods *directly*, so the owner name IS the workload. Pure."""
    if kind == "ReplicaSet":
        return name.startswith(f"{workload}-") and "-" not in name[len(workload) + 1 :]
    return name == workload


def _pod_belongs(pod: dict, workload: str) -> bool:
    """Whether ``pod`` is part of ``workload``. Precise when the pod has a controller owner (the
    normal case -- match the ReplicaSet/StatefulSet/DaemonSet, so ``squid`` never claims
    ``squid-proxy``'s pods); falls back to the legacy name-prefix match for a bare pod with no
    controller. Pure."""
    name, kind = _controller(pod)
    if name:
        return _owner_belongs(name, kind, workload)
    pod_name = (pod.get("metadata") or {}).get("name") or ""
    return pod_name == workload or pod_name.startswith(f"{workload}-")


def unhealthy_pods(pods: dict, workload: str) -> list[PodHealth]:
    """The unhealthy pods belonging to ``workload`` in a ``kubectl get pods -o json`` document.

    A pod belongs to the workload via its controller ``ownerReference`` (the ReplicaSet for a
    Deployment, the StatefulSet/DaemonSet directly) -- so two deployments in one namespace with
    overlapping names (``squid`` / ``squid-proxy``) never claim each other's pods; a bare pod with
    no controller falls back to the name-prefix match. Unhealthy = a container stuck in a known bad
    waiting state, a Failed phase, or a restart count over the threshold. Pure + testable."""
    out: list[PodHealth] = []
    for pod in pods.get("items") or []:
        name = (pod.get("metadata") or {}).get("name") or ""
        if not _pod_belongs(pod, workload):
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
    # Observe-only: a probe reads health, it never changes a workload. Declared so the manifest
    # is honest -- `kubectl logs` (the failing pod's evidence) hits the `pods/log` subresource,
    # which a least-privilege RBAC must grant `pods` AND `pods/log` for.
    commands = Capabilities(
        observe=("kubectl get pods -A -o json", "kubectl logs --tail --previous"),
    )

    def __init__(self, log_tail: int = 20, timeout: float = 10.0) -> None:
        self.log_tail = log_tail
        self.timeout = timeout
        self._context: str | None = None

    def use_context(self, context: str) -> None:
        """Aim every `kubectl` call at this kube context (a target = a cluster), so a fleet sweep
        probes each cluster in turn. '' clears it (the ambient current-context). Driven by
        `build_report(context=...)`; matches the live source's same-named seam."""
        self._context = context or None

    def _kubectl(self, *args: str) -> list[str]:
        """A `kubectl` argv with `--context` appended when one is set."""
        argv = ["kubectl", *args]
        if self._context:
            argv += ["--context", self._context]
        return argv

    def probe(self, resources: list[Resource]) -> list[Symptom]:
        # Fetch every pod in ONE `kubectl get pods -A` rather than one call per namespace -- across
        # a fleet with many namespaces that's 1 round-trip instead of N. Skip the read entirely when
        # no kubernetes resource is present (a non-k8s scan never touches kubectl).
        k8s_resources = [r for r in resources if r.provenance.source == "kubernetes"]
        if not k8s_resources:
            return []
        pods_by_namespace = self._all_pods()
        symptoms: list[Symptom] = []
        for resource in k8s_resources:
            namespace = _namespace(resource.identity) or "default"
            workload = _name(resource.identity)
            sick = unhealthy_pods(pods_by_namespace.get(namespace, {"items": []}), workload)
            if sick:
                symptoms.append(self._symptom(resource, namespace, sick))
        return symptoms

    def _symptom(self, resource: Resource, namespace: str, sick: list[PodHealth]) -> Symptom:
        category, severity = category_and_severity(sick)
        worst = max(sick, key=lambda pod: pod.restarts)
        tail = self._last_log_line(namespace, worst.name)
        detail = f"{len(sick)} pod(s) {category}" + (f"; last log: {tail}" if tail else "")
        # Name the WHERE in the title -- it's the one field every surface shows (the chat probe
        # summary, the scan panel, and the remembered `findings` row, which stores only the title).
        # With a fleet you need the cluster: `<context>/<namespace>`, else just the namespace.
        where = f"{self._context}/{namespace}" if self._context else namespace
        return Symptom(
            identity=resource.identity,
            kind=resource.kind,
            category=category,
            severity=severity,
            title=f"{_name(resource.identity)} is {category} in {where}",
            detail=detail,
            provenance=Provenance(source="kubernetes", address=resource.identity),
        )

    def _all_pods(self) -> dict[str, dict]:
        """Every pod in the cluster from ONE `kubectl get pods -A -o json`, grouped by namespace ->
        a ``{"items": [...]}`` doc (the shape ``unhealthy_pods`` reads). ``{}`` on any failure, so a
        missing/unreachable kubectl degrades to no symptoms rather than crashing the scan."""
        text = self._run_text(self._kubectl("get", "pods", "-A", "-o", "json"))
        if not text:
            return {}
        try:
            doc = json.loads(text)
        except ValueError:
            return {}
        items = doc.get("items") if isinstance(doc, dict) else None
        grouped: dict[str, dict] = {}
        for pod in items or []:
            namespace = (pod.get("metadata") or {}).get("namespace") or "default"
            grouped.setdefault(namespace, {"items": []})["items"].append(pod)
        return grouped

    def _last_log_line(self, namespace: str, pod: str) -> str:
        # Best-effort evidence: a failed `kubectl logs` is routine -- the `--previous` attempt has
        # no previous container on most pods, and the pod may have been deleted between the
        # `get pods` and now -- so failures stay quiet; the symptom still surfaces, just no tail.
        tail = str(self.log_tail)
        text = self._run_text(
            self._kubectl("logs", pod, "-n", namespace, "--tail", tail, "--previous"),
            best_effort=True,
        )
        if not text:
            text = self._run_text(
                self._kubectl("logs", pod, "-n", namespace, "--tail", tail), best_effort=True
            )
        lines = [line for line in (text or "").splitlines() if line.strip()]
        return lines[-1][:200] if lines else ""

    def _run_text(self, argv: list[str], *, best_effort: bool = False) -> str:
        try:
            result = subprocess.run(
                argv, check=True, capture_output=True, text=True, timeout=self.timeout
            )
            return result.stdout
        except (subprocess.SubprocessError, OSError) as exc:
            # A failed pod *list* means no symptoms surfaced -- warn. A failed `kubectl logs`
            # (``best_effort``) is expected churn (no previous container, or a pod deleted
            # mid-probe), so it's debug, not noise.
            logger.log(
                logging.DEBUG if best_effort else logging.WARNING,
                "kubectl probe (%s) failed: %s",
                " ".join(argv[:3]),
                exc,
            )
            return ""
