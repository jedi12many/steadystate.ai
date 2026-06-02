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

from ..model import Drift, Provenance, Resource
from ..reconcile import reconcile
from .base import Capabilities, loads_json, run_tool

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


def _truthy(value: object) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in ("true", "1", "yes")
    return bool(value)


def _security_concerns(obj: dict) -> dict:
    """The pod-security *posture* of an object, as a dict of only the concerns actually present
    (empty when clean). This feeds the standing-policy pack (security_k8s.py); it deliberately
    reports affirmative violations only -- a vanilla manifest projects to {} and so reads exactly
    as before, never getting a `security` key. Config-posture, NOT runtime detection."""
    pod = _pod_spec(obj)
    if not pod:
        return {}
    containers = [
        c
        for key in ("containers", "initContainers")
        for c in (pod.get(key) or [])
        if isinstance(c, dict)
    ]

    def sc(container: dict) -> dict:
        return container.get("securityContext") or {}

    concerns: dict = {}
    if any(_truthy(sc(c).get("privileged")) for c in containers):
        concerns["privileged"] = True
    if _truthy(pod.get("hostNetwork")):
        concerns["host_network"] = True
    if _truthy(pod.get("hostPID")):
        concerns["host_pid"] = True
    if _truthy(pod.get("hostIPC")):
        concerns["host_ipc"] = True
    caps = sorted(
        {str(cap) for c in containers for cap in (sc(c).get("capabilities") or {}).get("add") or []}
    )
    if caps:
        concerns["added_capabilities"] = caps
    host_paths = sorted(
        {
            str(path)
            for v in (pod.get("volumes") or [])
            if isinstance(v, dict) and (path := (v.get("hostPath") or {}).get("path"))
        }
    )
    if host_paths:
        concerns["host_path_volumes"] = host_paths
    if any(sc(c).get("allowPrivilegeEscalation") is True for c in containers):
        concerns["allow_privilege_escalation"] = True
    pod_sc = pod.get("securityContext") or {}
    runs_root = (
        pod_sc.get("runAsUser") == 0
        or pod_sc.get("runAsNonRoot") is False
        or any(
            sc(c).get("runAsUser") == 0 or sc(c).get("runAsNonRoot") is False for c in containers
        )
    )
    if runs_root:
        concerns["runs_as_root"] = True
    return concerns


def _resources_from_objects(objects: list[dict], *, with_security: bool) -> list[Resource]:
    """Project a list of K8s objects to canonical Resources. Pure + testable. ``with_security``
    attaches the posture projection (declared side only) under a ``security`` key when -- and
    only when -- a concern is present, so clean objects are unchanged."""
    out: list[Resource] = []
    for obj in objects:
        identity = _identity(obj)
        props = _properties(obj)
        if with_security:
            concerns = _security_concerns(obj)
            if concerns:
                props = {**props, "security": concerns}
        out.append(
            Resource(
                kind=obj.get("kind") or "",
                identity=identity,
                provenance=Provenance(source="kubernetes", address=identity),
                properties=props,
            )
        )
    return out


def resources_from_manifests(doc: object) -> list[Resource]:
    """Turn a declared manifest document into Resources -- with the security posture projection,
    since the policy-relevant fields (privileged, hostNetwork, capabilities, ...) live here on the
    declared side. Pure."""
    return _resources_from_objects(_normalize(doc), with_security=True)


def observed_resources_from_kubectl(doc: object) -> list[Resource]:
    """Turn `kubectl get -o json` output into observed Resources. Pure. Identity matches the
    declared side so they align. No security projection -- posture is audited declared-side."""
    return _resources_from_objects(_normalize(doc), with_security=False)


def _drift_only(resource: Resource) -> Resource:
    """A copy without the ``security`` key, so the posture projection (declared-only) can't read
    as drift when reconciled against the cluster. A no-op for clean objects (no security key)."""
    if "security" not in resource.properties:
        return resource
    return Resource(
        kind=resource.kind,
        identity=resource.identity,
        provenance=resource.provenance,
        properties={k: v for k, v in resource.properties.items() if k != "security"},
    )


def reconcile_k8s(declared: list[Resource], observed: list[Resource]) -> list[Drift]:
    """Reconcile declared vs cluster objects on presence + images/replicas. Pure. The security
    posture projection is dropped first so it never shows as drift."""
    return reconcile([_drift_only(r) for r in declared], [_drift_only(r) for r in observed])


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
        timeout: float = 30.0,  # `kubectl get` is a fast API read
    ) -> None:
        self._declared = declared
        self._observed = observed
        self._get_args = get_args
        self.timeout = timeout

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
        stdout = run_tool(
            ["kubectl", "get", *self._get_args, "-o", "json"],
            timeout=self.timeout,
            tool="kubectl get",
        )
        return loads_json(stdout, tool="kubectl get")


# The pod-owning controller kinds the live source enumerates -- exactly the workloads the kubectl
# probe health-checks. Bare Pods are covered transitively (the probe reads each workload's pods).
_LIVE_WORKLOAD_KINDS = "deployments,statefulsets,daemonsets"


class KubernetesLiveSource:
    """A live Kubernetes *health* source -- the "is anything on fire?" path for a cluster you can
    reach but have no declared manifests for (locked-down IaC, cloud backend, templated repos).

    It enumerates the cluster's own workloads (``kubectl get deploy,sts,ds -A``) and emits them as
    BOTH declared and observed, so it yields **zero drift by construction** -- its job isn't drift,
    it's to hand the kubectl probe a full list of live workloads to health-check. Point it at a
    kube context (a target = a cluster) and ``--probe auto`` reports the crash-looping /
    image-pull-failing / restart-storming workloads. Observe-only: it never acts.

    The kubectl read happens in ``collect_declared`` (what the engine calls for the probe), so an
    unreachable cluster surfaces as a loud `SourceError`, never a false "nothing on fire".
    """

    name = "k8s-live"
    commands = Capabilities(
        observe=(f"kubectl get {_LIVE_WORKLOAD_KINDS} --all-namespaces -o json",),
    )

    def __init__(self, observed: object | None = None, timeout: float = 30.0) -> None:
        self._observed = observed  # injectable for tests; else read live
        self._context: str | None = None
        self.timeout = timeout

    def use_context(self, context: str) -> None:
        """Aim every kubectl read at this kube context (a target = a cluster). '' clears it (the
        ambient current-context). This is the seam `build_report(context=...)` drives."""
        self._context = context or None

    def _qualify(self, resource: Resource) -> Resource:
        """Prefix this resource's identity with the (sanitized) context, so the SAME workload on two
        clusters reads as two distinct findings in a shared store -- a fleet sweep that reconciles
        many clusters into one db must not collide ``prod`` and ``staging``'s ``.../web``. Prefixing
        the *front* keeps the kubectl probe's namespace/name parse (last two `/`-segments) intact;
        any `/` in the context (an EKS ARN) is replaced so it can't add a phantom segment. A no-op
        when no context is set (a single ambient cluster needs no qualifier)."""
        if not self._context:
            return resource
        qid = f"{self._context.replace('/', '_')}/{resource.identity}"
        return Resource(
            kind=resource.kind,
            identity=qid,
            provenance=Provenance(source="kubernetes", address=qid),
            properties=resource.properties,
        )

    def _workloads(self) -> list[Resource]:
        doc = self._observed if self._observed is not None else self._run_kubectl()
        return [self._qualify(r) for r in observed_resources_from_kubectl(doc)]

    def collect_declared(self) -> list[Resource]:
        return self._workloads()

    def collect_observed(self) -> list[Resource]:
        return self._workloads()

    def collect_drift(self) -> list[Drift]:
        # declared == observed by construction -> always empty. The signal is health (Symptoms via
        # the kubectl probe), not drift -- so this is an honest constant [], not a swallowed error.
        return []

    def _run_kubectl(self) -> object:
        argv = ["kubectl", "get", _LIVE_WORKLOAD_KINDS, "--all-namespaces", "-o", "json"]
        if self._context:
            argv += ["--context", self._context]
        stdout = run_tool(argv, timeout=self.timeout, tool="kubectl get")
        return loads_json(stdout, tool="kubectl get")
