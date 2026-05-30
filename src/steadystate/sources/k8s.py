"""Kubernetes source -- v0.

A set of manifests *declares* the objects a cluster should hold; `kubectl get`
reports what is *actually* there. Like Compose, Kubernetes has no single built-in
plan diff that this source rides, so it enumerates both sides and reconciles them:

- declared: a JSON document of manifests. The project is stdlib-only and has NO
  YAML parser, so -- exactly like the docker-compose source consuming
  `docker compose config --format json` rather than raw YAML -- this source consumes
  **JSON**. Render manifests to JSON first, e.g. `kubectl ... -o json` or
  `kustomize build ... | kubectl create --dry-run=client -o json -f -`.
- observed: `kubectl get <...> -o json` output (a `List`).

Either side accepts a K8s `List` (`{"kind":"List","items":[...]}`), a bare top-level
array `[...]`, or a single object; all three normalize to a list of objects.

Drift is reported on **presence + container images** (plus `spec.replicas` when set):
a declared object absent from the cluster (ADDED), a cluster object not declared
(REMOVED), or an object whose images/replicas differ from declared (MODIFIED). Objects
declared without images are compared on presence only, and kinds with no containers
reconcile on presence alone, so neither shows as false drift.
"""

from __future__ import annotations

import json
import subprocess

from ..model import Drift, Provenance, Resource
from ..reconcile import reconcile
from .base import Capabilities

# Workload kinds whose containers live under spec.template.spec; a bare Pod keeps
# them under spec directly.
_WORKLOAD_KINDS = frozenset(
    {
        "Deployment",
        "StatefulSet",
        "DaemonSet",
        "ReplicaSet",
        "Job",
        "CronJob",
    }
)


def _normalize(doc: object) -> list[dict]:
    """Normalize a K8s `List`, a bare array, or a single object to a list of objects."""
    if isinstance(doc, list):
        return [obj for obj in doc if isinstance(obj, dict)]
    if isinstance(doc, dict):
        if doc.get("kind") == "List" and "items" in doc:
            items = doc.get("items") or []
            return [obj for obj in items if isinstance(obj, dict)]
        return [doc]
    return []


def _identity(obj: dict) -> str:
    """Stable id `[group/]kind/[namespace/]name`, mirroring the ArgoCD/Rancher sources:
    empty segments (core `v1`'s blank group, a cluster-scoped resource's blank namespace)
    are dropped rather than left as empty path parts."""
    api_version = obj.get("apiVersion") or ""
    group = api_version.split("/", 1)[0] if "/" in api_version else ""
    metadata = obj.get("metadata") or {}
    parts = [group, obj.get("kind"), metadata.get("namespace"), metadata.get("name")]
    return "/".join(p for p in parts if p)


def _pod_spec(obj: dict) -> dict:
    """The container-bearing pod spec for an object: spec.template.spec for workloads,
    spec for a bare Pod. CronJob nests one level deeper under jobTemplate."""
    spec = obj.get("spec") or {}
    kind = obj.get("kind")
    if kind == "CronJob":
        job = (spec.get("jobTemplate") or {}).get("spec") or {}
        return (job.get("template") or {}).get("spec") or {}
    if kind in _WORKLOAD_KINDS:
        return (spec.get("template") or {}).get("spec") or {}
    if kind == "Pod":
        return spec
    return {}


def _images(obj: dict) -> list[str]:
    """Sorted list of container + initContainer images for a workload or Pod."""
    pod_spec = _pod_spec(obj)
    images: list[str] = []
    for key in ("initContainers", "containers"):
        for container in pod_spec.get(key) or []:
            image = container.get("image")
            if image:
                images.append(image)
    return sorted(images)


def _properties(obj: dict) -> dict:
    """The drift-relevant projection: sorted container images and replicas when present.
    Kinds with no containers yield {}, so they reconcile on presence alone."""
    props: dict = {}
    images = _images(obj)
    if images:
        props["images"] = images
    spec = obj.get("spec") or {}
    if isinstance(spec, dict) and "replicas" in spec:
        props["replicas"] = spec.get("replicas")
    return props


def _resources_from_objects(objects: list[dict]) -> list[Resource]:
    """Project a list of K8s objects to canonical Resources. Pure + testable."""
    out: list[Resource] = []
    for obj in objects:
        identity = _identity(obj)
        out.append(
            Resource(
                kind=obj.get("kind") or "",
                identity=identity,
                provenance=Provenance(source="kubernetes", address=identity),
                properties=_properties(obj),
            )
        )
    return out


def resources_from_manifests(doc: object) -> list[Resource]:
    """Turn a declared manifest document into Resources. Pure."""
    return _resources_from_objects(_normalize(doc))


def observed_resources_from_kubectl(doc: object) -> list[Resource]:
    """Turn `kubectl get -o json` output into observed Resources. Pure. Identity matches
    the declared side so the two align."""
    return _resources_from_objects(_normalize(doc))


def reconcile_k8s(declared: list[Resource], observed: list[Resource]) -> list[Drift]:
    """Reconcile declared vs cluster objects on presence + images/replicas. Pure."""
    return reconcile(declared, observed)


class KubernetesSource:
    """A StateSource + ObservedSource + DriftSource for Kubernetes. Construct with
    parsed `declared`/`observed` docs (testing / CI) or args to run `kubectl get` live."""

    name = "kubernetes"
    commands = Capabilities(
        observe=("kubectl get -o json",),
        destructive=("kubectl apply -f", "kubectl delete", "kubectl rollout restart"),
    )

    def __init__(
        self,
        declared: object | None = None,
        observed: object | None = None,
        get_args: list[str] | None = None,
    ) -> None:
        self._declared = declared
        self._observed = observed
        self._get_args = get_args

    def collect_declared(self) -> list[Resource]:
        if self._declared is None:
            raise ValueError("KubernetesSource needs a declared document")
        return resources_from_manifests(self._declared)

    def collect_observed(self) -> list[Resource]:
        doc = self._observed if self._observed is not None else self._run_kubectl()
        return observed_resources_from_kubectl(doc)

    def collect_drift(self) -> list[Drift]:
        return reconcile_k8s(self.collect_declared(), self.collect_observed())

    # -- live kubectl -------------------------------------------------------

    def _run_kubectl(self) -> object:
        if self._get_args is None:
            raise ValueError("KubernetesSource needs observed or get_args")
        res = subprocess.run(
            ["kubectl", "get", *self._get_args, "-o", "json"],
            check=True,
            capture_output=True,
            text=True,
        )
        return json.loads(res.stdout)
