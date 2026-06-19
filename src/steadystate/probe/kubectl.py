"""Kubernetes health probe -- originate Symptoms for declared workloads.

For any *declared* workload whose pods are failing (`unhealthy_pods`), produces a first-class
`Symptom` -- so a malfunction surfaces even with no drift, and correlates with a drift when there
is one. Reads via `kubectl`; any failure degrades to "no symptoms" (never invent a problem, never
break a scan).
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
from dataclasses import dataclass, field

from ..evidence import EvidenceKeys
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
    require that exact shape, which distinguishes ``web`` from a sibling ``web-proxy`` (whose RS
    leaves the suffix ``proxy-<hash>``, not a bare hash). Every other controller (StatefulSet,
    DaemonSet, Job) owns its pods *directly*, so the owner name IS the workload. Pure."""
    if kind == "ReplicaSet":
        return name.startswith(f"{workload}-") and "-" not in name[len(workload) + 1 :]
    return name == workload


def _pod_belongs(pod: dict, workload: str) -> bool:
    """Whether ``pod`` is part of ``workload``. Precise when the pod has a controller owner (the
    normal case -- match the ReplicaSet/StatefulSet/DaemonSet, so ``web`` never claims
    ``web-proxy``'s pods); falls back to the legacy name-prefix match for a bare pod with no
    controller. Pure."""
    name, kind = _controller(pod)
    if name:
        return _owner_belongs(name, kind, workload)
    pod_name = (pod.get("metadata") or {}).get("name") or ""
    return pod_name == workload or pod_name.startswith(f"{workload}-")


def _workload_pod_names(pods: dict, workload: str) -> list[str]:
    """The names of every pod belonging to ``workload`` (healthy or not) in a `kubectl get pods`
    doc -- the candidates a `--deep` log scan reads. Pure."""
    return [
        name
        for pod in (pods.get("items") or [])
        if _pod_belongs(pod, workload) and (name := (pod.get("metadata") or {}).get("name"))
    ]


def unhealthy_pods(pods: dict, workload: str) -> list[PodHealth]:
    """The unhealthy pods belonging to ``workload`` in a ``kubectl get pods -o json`` document.

    A pod belongs to the workload via its controller ``ownerReference`` (the ReplicaSet for a
    Deployment, the StatefulSet/DaemonSet directly) -- so two deployments in one namespace with
    overlapping names (``web`` / ``web-proxy``) never claim each other's pods; a bare pod with
    no controller falls back to the name-prefix match. Unhealthy = a container stuck in a known bad
    waiting state, or a Failed phase. The restart *count* is NOT a trigger: it's cumulative over the
    pod's life, so a pod that churned during a past deploy but is fine now would read as a false
    positive, and a pod that's genuinely failing now is already caught by its bad waiting state /
    Failed phase -- the number adds no signal either way. (It's still carried as evidence.) Pure +
    testable."""
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
            # An evicted pod is a Failed pod with reason "Evicted" -- a dead tombstone (node
            # memory/disk pressure killed it), not a crash. Call it out distinctly: lower severity,
            # and the fix is a cleanup (delete it), not a restart.
            reason = "Evicted" if status.get("reason") == "Evicted" else "Failed"
        if reason:  # restarts ride along as evidence, never as the reason a pod is flagged
            out.append(PodHealth(name=name, reason=reason, restarts=restarts))
    return out


# Reasons where the container can't run at all -> HIGH. A reason not in here (today: Evicted, a
# dead tombstone from node pressure) is the lower-severity MEDIUM case.
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
    """The dominant category + its severity. A "cannot-run" reason on any pod wins (HIGH); a
    non-cannot-run reason (e.g. Evicted) is MEDIUM. The restart count is only a tiebreaker between
    equally-severe pods (which one to name), never a reason on its own. Pure + testable."""
    worst = max(sick, key=lambda pod: (pod.reason in _CANNOT_RUN, pod.restarts))
    severity = Severity.HIGH if any(pod.reason in _CANNOT_RUN for pod in sick) else Severity.MEDIUM
    return worst.reason, severity


# -- node health ------------------------------------------------------------------------------
# A node's own `status.conditions` are the cluster-infra signal the pod checks miss. A *pressure*
# condition reading "True" means the kubelet is at/over an eviction threshold: DiskPressure (the
# disk is filling -- e.g. logs/images -- which is what *causes* pod evictions), MemoryPressure,
# PIDPressure. And Ready != "True" means the node is down/unreachable. One `kubectl get nodes`.
_NODE_PRESSURE = ("DiskPressure", "MemoryPressure", "PIDPressure")


@dataclass(frozen=True)
class NodeIssue:
    """A node condition worth flagging: the node, the category, and the kubelet's message."""

    node: str
    category: str  # DiskPressure | MemoryPressure | PIDPressure | NotReady
    message: str


def node_issues(nodes_doc: dict) -> list[NodeIssue]:
    """Every flagged condition across the nodes in a `kubectl get nodes -o json` doc: each pressure
    condition that's "True", plus a node whose Ready condition isn't "True". Pure + testable."""
    out: list[NodeIssue] = []
    for node in nodes_doc.get("items") or []:
        name = (node.get("metadata") or {}).get("name") or ""
        conditions = {c.get("type"): c for c in (node.get("status") or {}).get("conditions") or []}
        for pressure in _NODE_PRESSURE:
            cond = conditions.get(pressure)
            if cond and cond.get("status") == "True":
                out.append(NodeIssue(name, pressure, cond.get("message") or pressure))
        ready = conditions.get("Ready")
        if ready is not None and ready.get("status") != "True":
            out.append(NodeIssue(name, "NotReady", ready.get("message") or "node not Ready"))
    return out


def _node_names(nodes_doc: dict) -> list[str]:
    """Every node name in a `kubectl get nodes` doc. Pure."""
    return [
        name
        for node in (nodes_doc.get("items") or [])
        if (name := (node.get("metadata") or {}).get("name"))
    ]


# Proactive disk warning (the `--deep` node pass): a node filling up BEFORE it trips DiskPressure.
# A warning at this % of any node filesystem, escalated to HIGH near full -- early enough to act.
_DISK_WARN_PCT = 80
_DISK_HIGH_PCT = 90


def _fs_pct(fs: dict) -> int | None:
    """A filesystem's used %, from a kubelet summary ``fs`` block (capacity + used/available).
    None when capacity is missing/zero. Pure."""
    capacity = fs.get("capacityBytes")
    if not capacity:
        return None
    used = fs.get("usedBytes")
    if used is None:
        available = fs.get("availableBytes")
        if available is None:
            return None
        used = capacity - available
    return round(used / capacity * 100)


def node_disk_pct(summary: dict) -> int | None:
    """The worst (highest) filesystem-used % for a node, from its kubelet ``stats/summary`` -- the
    root fs and the image/container fs (where logs + images live). None when neither is readable.
    Pure + testable."""
    node = summary.get("node") or {}
    filesystems = [node.get("fs"), (node.get("runtime") or {}).get("imageFs")]
    pcts = [pct for fs in filesystems if fs for pct in (_fs_pct(fs),) if pct is not None]
    return max(pcts) if pcts else None


# -- log-content detection (`probe --deep`) ---------------------------------------------------
# A pod can be Running + Ready yet failing in its LOGS -- a panic loop caught and restarted, a
# flood of errors, an OOM trace. Status detection misses that; a `--deep` probe reads the tail
# and matches these signatures. FATAL signatures are acute enough that ONE hit raises a symptom;
# the ERROR signatures are the kind a healthy app emits occasionally, so they must clear a
# threshold. Conservative on purpose -- favor precision over recall; a missed error log is less
# harmful than alert fatigue. `ERROR`/`FATAL` are matched case-sensitively (the log-level
# convention), so prose like "no error occurred" doesn't trip them.
_LOG_FATAL_RE = re.compile(
    r"panic:|fatal error:|SIGSEGV|segfault|segmentation fault|OOMKilled|out of memory|"
    r"cannot allocate memory|Traceback \(most recent call last\)",
    re.IGNORECASE,
)
_LOG_ERROR_RE = re.compile(
    r"\bERROR\b|\bFATAL\b|level=(?:error|fatal)|Exception in thread|\bException\b|"
    r"connection refused|context deadline exceeded|no route to host"
)


@dataclass(frozen=True)
class LogVerdict:
    """The outcome of scanning one pod's log tail: how many error lines, whether any was a
    fatal-class signature, a few sample lines (capped) for the evidence, and -- when a fatal
    signature is hit -- the **trace block** after it (the stack frames / call chain), captured
    so a later `analyze` can root-cause it even after the pod restarts and the logs roll."""

    error_count: int
    fatal: bool
    sample: list[str]
    trace: list[str] = field(default_factory=list)


_TRACE_LINES = 25  # how many lines from the fatal line onward to keep (the panic + a few frames)
_PRE_LINES = (
    40  # how many lines BEFORE the fatal to keep -- the LEAD-UP, where the cause usually is
)


def scan_log_text(text: str, threshold: int) -> LogVerdict | None:
    """Scan a log tail for trouble. Returns a verdict when a FATAL-class signature appears (one is
    enough) OR errors reach ``threshold``; else None (nothing actionable). On a fatal
    hit it captures a WINDOW around it -- the ``_PRE_LINES`` of LEAD-UP *before* the fatal line (the
    root cause is usually in what was happening before it failed, not the failure line itself) plus
    the block after it (the stack trace / call chain). That before-event context is the evidence
    `analyze` needs, which the matching-lines sample misses. Pure + testable."""
    lines = [raw.strip() for raw in text.splitlines() if raw.strip()]
    fatal = False
    count = 0
    sample: list[str] = []
    fatal_idx = -1
    for idx, line in enumerate(lines):
        is_fatal = bool(_LOG_FATAL_RE.search(line))
        if is_fatal or _LOG_ERROR_RE.search(line):
            count += 1
            fatal = fatal or is_fatal
            if len(sample) < 5:
                sample.append(line[:200])
        if is_fatal and fatal_idx < 0:  # anchor the window at the FIRST fatal signature
            fatal_idx = idx
    trace: list[str] = []
    if fatal_idx >= 0:  # the lead-up + the fatal line + the following frames, in order
        block = lines[max(0, fatal_idx - _PRE_LINES) : fatal_idx + _TRACE_LINES]
        trace = [line[:300] for line in block]
    if fatal or count >= threshold:
        return LogVerdict(error_count=count, fatal=fatal, sample=sample, trace=trace)
    return None


_LOG_WINDOW_LINES = 150  # the recent log tail kept as before-event context for `analyze`
_LOG_WINDOW_CHARS = 8000  # ...bounded for the store + the model's context window
_ANALYZE_TAIL = 400  # a bigger tail re-fetched at `analyze` time (on-demand) -- the lead-up matters


def cap_log(text: str) -> str:
    """Keep the TAIL of a log -- the lead-up is at the END of a `--previous` log -- bounded
    for the store + the model's context. Drops blank lines; keeps the last lines/chars."""
    lines = [ln for ln in text.splitlines() if ln.strip()][-_LOG_WINDOW_LINES:]
    return "\n".join(lines)[-_LOG_WINDOW_CHARS:]


def _event_ts(event: dict) -> str:
    """An event's timestamp for ordering -- ``lastTimestamp`` (the recurrence's latest), falling
    back to ``eventTime`` (the newer events API) then ``firstTimestamp``. '' sorts oldest."""
    return event.get("lastTimestamp") or event.get("eventTime") or event.get("firstTimestamp") or ""


def render_events(doc: dict, *, limit: int = 15) -> str:
    """A `kubectl get events -o json` doc as compact, oldest-last lines -- the cluster's account of
    the lead-up (`OOMKilled`, `FailedScheduling`, `BackOff`, probe failures). Bounded to the last
    ``limit``. Pure; '' when there are no events."""
    items = doc.get("items", []) if isinstance(doc, dict) else []
    lines: list[str] = []
    for event in sorted(items, key=_event_ts)[-limit:]:
        count = event.get("count")
        repeat = f" x{count}" if isinstance(count, int) and count > 1 else ""
        message = " ".join((event.get("message") or "").split())  # collapse whitespace/newlines
        lines.append(
            f"{_event_ts(event)}  {event.get('type', ''):<7} "
            f"{event.get('reason', '')}{repeat}: {message}"
        )
    return "\n".join(lines)


def render_pod_status(doc: dict) -> str:
    """A `kubectl get pod -o json` doc as the operational facts an RCA needs beyond the logs: phase,
    readiness, and per container the restart count + the LAST termination (reason + exit code --
    137/OOMKilled is the smoking gun a log tail can't show). Pure; '' when there's no status."""
    status = doc.get("status", {}) if isinstance(doc, dict) else {}
    lines: list[str] = []
    if status.get("phase"):
        lines.append(f"phase: {status['phase']}")
    for cond in status.get("conditions", []):
        if cond.get("type") == "Ready":
            reason = f" ({cond.get('reason')})" if cond.get("reason") else ""
            lines.append(f"Ready: {cond.get('status')}{reason}")
    for container in status.get("containerStatuses", []):
        parts = [
            f"container {container.get('name', '?')}: restarts={container.get('restartCount', 0)}"
        ]
        state = container.get("state", {})
        if "waiting" in state:
            parts.append(f"waiting={state['waiting'].get('reason', '')}")
        elif "running" in state:
            parts.append("running")
        terminated = container.get("lastState", {}).get("terminated")
        if terminated:
            parts.append(
                f"lastTerminated={terminated.get('reason', '')} "
                f"exit={terminated.get('exitCode', '')} at {terminated.get('finishedAt', '')}"
            )
        lines.append("  " + "  ".join(parts))
    return "\n".join(lines)


def render_rollout(doc: dict) -> str:
    """A `kubectl get deployment|statefulset -o json` doc as the rollout facts an RCA needs to spot
    a deploy as the trigger: the container images (what's running -- and what a bad bump changed),
    generation vs observedGeneration (a rollout still in flight), replica health, the StatefulSet
    revisions, and the Deployment's own conditions (`Progressing` carries WHEN it last rolled + the
    reason). Pure; '' when there's no usable doc."""
    if not isinstance(doc, dict):
        return ""
    spec = doc.get("spec", {})
    status = doc.get("status", {})
    lines: list[str] = []
    images = [
        c["image"]
        for c in spec.get("template", {}).get("spec", {}).get("containers", [])
        if c.get("image")
    ]
    if images:
        lines.append("images: " + ", ".join(images))
    generation = doc.get("metadata", {}).get("generation")
    observed = status.get("observedGeneration")
    if generation is not None:
        drift = "" if observed == generation else f" (observed {observed} -- rollout in progress)"
        lines.append(f"generation: {generation}{drift}")
    replicas = [("desired", spec.get("replicas"))] + [
        (label, status.get(key))
        for label, key in (
            ("updated", "updatedReplicas"),
            ("ready", "readyReplicas"),
            ("available", "availableReplicas"),
            ("unavailable", "unavailableReplicas"),
        )
    ]
    counts = " ".join(f"{label}={value}" for label, value in replicas if value is not None)
    if counts:
        lines.append("replicas: " + counts)
    current, update = status.get("currentRevision"), status.get("updateRevision")
    if current or update:  # StatefulSet: a mismatch means a rollout is mid-flight
        mid = "" if current == update else "  (mid-rollout: current != update)"
        lines.append(f"revision: current={current} update={update}{mid}")
    for cond in status.get("conditions", []):
        if cond.get("type") in {"Progressing", "Available"}:
            when = cond.get("lastUpdateTime") or cond.get("lastTransitionTime") or ""
            message = " ".join((cond.get("message") or "").split())
            lines.append(
                f"{cond.get('type')}: {cond.get('status')} "
                f"reason={cond.get('reason', '')} at {when}  {message}".rstrip()
            )
    return "\n".join(lines)


class KubectlProbe:
    """Produces a Symptom per declared kubernetes workload whose pods are unhealthy now. With log
    scanning enabled (`probe --deep`), it also reads the tail of the *Running* pods' logs and
    raises a symptom for a workload that's status-healthy but erroring in its logs."""

    name = "kubectl"
    # Observe-only: a probe reads health, it never changes a workload. Declared so the manifest
    # is honest -- `kubectl logs` (the failing pod's evidence) hits the `pods/log` subresource,
    # which a least-privilege RBAC must grant `pods` AND `pods/log` for.
    commands = Capabilities(
        observe=(
            "kubectl get pods -A -o json",
            "kubectl get nodes -o json",
            "kubectl get --raw /api/v1/nodes/<node>/proxy/stats/summary",  # --deep node disk %
            "kubectl logs --tail --previous",
            "kubectl get pod <pod> -n <ns> -o json",  # analyze: pod status / last termination
            "kubectl get events -n <ns> --field-selector involvedObject.name=<pod>",  # analyze
            "kubectl get deployment|statefulset <name> -n <ns> -o json",  # analyze: rollout trigger
        ),
    )

    def __init__(self, log_tail: int = 20, timeout: float = 10.0) -> None:
        self.log_tail = log_tail
        self.timeout = timeout
        self._context: str | None = None
        self._kubeconfig: str | None = None
        # Log scanning is opt-in (`probe --deep`): it costs one `kubectl logs` per pod, so it's off
        # on the fast path. ``_scan_tail`` lines per pod, raise at ``_log_threshold`` error lines
        # (a FATAL signature always trips), and cap how many pods per workload we read.
        self._scan_logs = False
        self._scan_tail = 200
        self._log_threshold = 3
        self._scan_max_pods = 5

    def use_context(self, context: str) -> None:
        """Aim every `kubectl` call at this kube context (a target = a cluster), so a fleet sweep
        probes each cluster in turn. '' clears it (the ambient current-context). Driven by
        `build_report(context=...)`; matches the live source's same-named seam."""
        self._context = context or None

    def use_kubeconfig(self, kubeconfig: str) -> None:
        """Point every `kubectl` call at this kubeconfig file (a context off the default path, e.g.
        a kubeconfig in the project dir). '' clears it (the ambient kubeconfig). Driven by
        `build_report(kubeconfig=...)`; matches the live source's same-named seam."""
        self._kubeconfig = kubeconfig or None

    def enable_log_scan(self) -> None:
        """Turn on the deep log-content pass (`probe --deep` / `build_report(scan_logs=True)`): scan
        the Running pods' log tails for error/fatal signatures, not just pod status. Off by default
        because it costs a `kubectl logs` per pod."""
        self._scan_logs = True

    def _kubectl(self, *args: str) -> list[str]:
        """A `kubectl` argv with `--context` / `--kubeconfig` appended when set."""
        argv = ["kubectl", *args]
        if self._context:
            argv += ["--context", self._context]
        if self._kubeconfig:
            argv += ["--kubeconfig", self._kubeconfig]
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
            pods = pods_by_namespace.get(namespace, {"items": []})
            sick = unhealthy_pods(pods, workload)
            if sick:
                symptoms.append(self._symptom(resource, namespace, sick))
            elif self._scan_logs:
                # Status-healthy workload + `--deep` -> scan its pods' logs for errors. (A
                # status-unhealthy workload already surfaced above; don't double-report it.)
                log_symptom = self._log_symptom(resource, namespace, pods, workload)
                if log_symptom is not None:
                    symptoms.append(log_symptom)
        # Cluster-infra health: a node out of disk (DiskPressure -- often logs filling up), memory,
        # or PIDs, or one gone NotReady. One `kubectl get nodes`; the root cause behind evictions.
        symptoms.extend(self._node_symptoms())
        return symptoms

    def _symptom(self, resource: Resource, namespace: str, sick: list[PodHealth]) -> Symptom:
        category, severity = category_and_severity(sick)
        worst = max(sick, key=lambda pod: pod.restarts)
        logs = self._recent_logs(namespace, worst.name)  # the before-event tail, not just one line
        last_line = logs.splitlines()[-1][:200] if logs else ""
        detail = f"{len(sick)} pod(s) {category}" + (
            f"; last log: {last_line}" if last_line else ""
        )
        # Name the WHERE in the title -- it's the one field every surface shows (the chat probe
        # summary, the scan panel, and the remembered `findings` row, which stores only the title).
        # With a fleet you need the cluster: `<context>/<namespace>`, else just the namespace.
        where = f"{self._context}/{namespace}" if self._context else namespace
        # Structured fields for `show <fp>` -- "which pods, where, the actual error, how flappy".
        # Insertion order is display order; the long log line goes last. The store keeps these
        # per fingerprint, so a later `show` can answer "what was the error, and was it recent?".
        evidence = {
            EvidenceKeys.WORKLOAD: _name(resource.identity),
            EvidenceKeys.KIND: resource.kind,
            EvidenceKeys.NAMESPACE: namespace,
            EvidenceKeys.CATEGORY: category,
            "unhealthy_pods": str(len(sick)),
            "pods": ", ".join(p.name for p in sick),
            "max_restarts": str(worst.restarts),
        }
        if self._context:
            evidence[EvidenceKeys.CLUSTER] = self._context
        if last_line:
            evidence[EvidenceKeys.LAST_LOG] = last_line
        if logs:  # the before-event logs -- the meat `analyze` reads, not just the headline line
            evidence[EvidenceKeys.LOG_WINDOW] = logs
        return Symptom(
            identity=resource.identity,
            kind=resource.kind,
            category=category,
            severity=severity,
            title=f"{_name(resource.identity)} is {category} in {where}",
            detail=detail,
            provenance=Provenance(source="kubernetes", address=resource.identity),
            evidence=evidence,
            recommended_action=self._fix_for(category, namespace),
        )

    def _fix_for(self, category: str, namespace: str) -> str | None:
        """A concrete remediation for a category that has a safe one-liner. Evicted pods are dead
        tombstones, so the fix is a scoped cleanup of Failed-phase pods (the field selector that
        matches evicted ones); the `--context` makes it copy-paste runnable for the right cluster.
        None for categories with no safe one-shot fix (a crashloop needs a real fix, not a delete).
        """
        if category != "Evicted":
            return None
        ctx = f" --context {self._context}" if self._context else ""
        return f"kubectl delete pods -n {namespace} --field-selector=status.phase=Failed{ctx}"

    def _log_symptom(
        self, resource: Resource, namespace: str, pods: dict, workload: str
    ) -> Symptom | None:
        """Scan the tail of a status-healthy workload's pods for error/fatal log signatures, and
        raise one ``Erroring`` Symptom for the workload if any pod trips. One `kubectl logs` per
        pod (capped); a failed/denied read is best-effort/quiet. None when nothing trips."""
        pod_names = _workload_pod_names(pods, workload)[: self._scan_max_pods]
        total = 0
        fatal = False
        sample: list[str] = []
        scanned: list[str] = []
        trace: list[str] = []  # the stack-trace block from the first fatal pod -- for `analyze`
        for pod in pod_names:
            text = self._run_text(
                self._kubectl("logs", pod, "-n", namespace, "--tail", str(self._scan_tail)),
                best_effort=True,
            )
            if not text:
                continue
            scanned.append(pod)
            verdict = scan_log_text(text, self._log_threshold)
            if verdict is None:
                continue
            total += verdict.error_count
            fatal = fatal or verdict.fatal
            if verdict.trace and not trace:  # keep the first pod's full trace as evidence
                trace = verdict.trace
            for line in verdict.sample:
                if len(sample) < 5:
                    sample.append(line)
        if not sample and not fatal:  # nothing tripped across the workload's pods
            return None
        severity = Severity.HIGH if fatal else Severity.MEDIUM  # fatal-class -> HIGH, else MEDIUM
        where = f"{self._context}/{namespace}" if self._context else namespace
        name = _name(resource.identity)
        detail = f"{total} error log line(s)" + (" incl. a fatal signature" if fatal else "")
        detail += f"; e.g. {sample[0]}" if sample else ""
        evidence = {
            EvidenceKeys.WORKLOAD: name,
            EvidenceKeys.KIND: resource.kind,
            EvidenceKeys.NAMESPACE: namespace,
            EvidenceKeys.CATEGORY: "Erroring",
            "error_lines": str(total),
            "fatal": "yes" if fatal else "no",
            "pods_scanned": ", ".join(scanned),
        }
        if self._context:
            evidence[EvidenceKeys.CLUSTER] = self._context
        if sample:
            evidence[EvidenceKeys.SAMPLE] = " | ".join(sample[:3])
        if trace:  # the captured stack-trace block -- the call chain `analyze` root-causes
            evidence[EvidenceKeys.TRACE] = "\n".join(trace)
        return Symptom(
            identity=resource.identity,
            kind=resource.kind,
            category="Erroring",
            severity=severity,
            title=f"{name} is Erroring in {where}",
            detail=detail,
            provenance=Provenance(source="kubernetes", address=resource.identity),
            evidence=evidence,
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

    def _node_symptoms(self) -> list[Symptom]:
        """A Symptom per flagged node condition (DiskPressure / MemoryPressure / PIDPressure /
        NotReady) from ONE `kubectl get nodes -o json`. Best-effort: a failed/denied read (`get
        nodes` is cluster-scoped RBAC) degrades to no node symptoms, never crashes the scan.

        With ``--deep`` it also adds a **proactive** disk warning: it reads each node's kubelet
        ``stats/summary`` and flags one filling up (>= the warn %) BEFORE it trips DiskPressure --
        the early warning. That's one `kubectl get --raw` per node and needs `nodes/proxy` RBAC, so
        it's gated behind `--deep` and degrades silently where the proxy stats aren't permitted."""
        text = self._run_text(self._kubectl("get", "nodes", "-o", "json"))
        if not text:
            return []
        try:
            doc = json.loads(text)
        except ValueError:
            return []
        issues = node_issues(doc)
        symptoms = [self._node_symptom(issue) for issue in issues]
        if (
            self._scan_logs
        ):  # --deep: proactive per-node disk %, skipping ones already at DiskPressure
            already = {i.node for i in issues if i.category == "DiskPressure"}
            for node in _node_names(doc):
                if node in already:
                    continue  # DiskPressure already flagged it (more severe); don't double-report
                disk = self._node_disk_symptom(node)
                if disk is not None:
                    symptoms.append(disk)
        return symptoms

    def _node_disk_symptom(self, node: str) -> Symptom | None:
        """Read a node's kubelet `stats/summary` and flag it if a filesystem is >= the warn %.
        MEDIUM, escalating to HIGH near full. None below the bar, or when the proxy stats aren't
        readable (RBAC/unsupported) -- best-effort, never raised."""
        raw = self._run_text(
            self._kubectl("get", "--raw", f"/api/v1/nodes/{node}/proxy/stats/summary"),
            best_effort=True,
        )
        if not raw:
            return None
        try:
            pct = node_disk_pct(json.loads(raw))
        except ValueError:
            return None
        if pct is None or pct < _DISK_WARN_PCT:
            return None
        severity = Severity.HIGH if pct >= _DISK_HIGH_PCT else Severity.MEDIUM
        where = f"{self._context}/" if self._context else ""
        on = f" on {self._context}" if self._context else ""
        identity = f"{where}Node/{node}"
        evidence = {EvidenceKeys.NODE: node, "disk_percent": str(pct)}
        if self._context:
            evidence[EvidenceKeys.CLUSTER] = self._context
        return Symptom(
            identity=identity,
            kind="Node",
            category="DiskFilling",
            severity=severity,
            title=f"node {node} disk {pct}% full{on}",
            detail=f"a node filesystem is {pct}% full -- free space before it evicts pods",
            provenance=Provenance(source="kubernetes", address=identity),
            evidence=evidence,
        )

    def _node_symptom(self, issue: NodeIssue) -> Symptom:
        # A node finding -- cluster-scoped, so identity carries the context (a target = a cluster)
        # but no namespace. DiskPressure/MemoryPressure/PIDPressure/NotReady are all serious (active
        # eviction / a down node) -> HIGH, so they surface, not just count.
        where = f"{self._context}/" if self._context else ""
        identity = f"{where}Node/{issue.node}"
        on = f" on {self._context}" if self._context else ""
        evidence = {
            EvidenceKeys.NODE: issue.node,
            "condition": issue.category,
            "message": issue.message,
        }
        if self._context:
            evidence[EvidenceKeys.CLUSTER] = self._context
        return Symptom(
            identity=identity,
            kind="Node",
            category=issue.category,
            severity=Severity.HIGH,
            title=f"node {issue.node} has {issue.category}{on}",
            detail=issue.message,
            provenance=Provenance(source="kubernetes", address=identity),
            evidence=evidence,
        )

    def _recent_logs(self, namespace: str, pod: str) -> str:
        """The recent log TAIL of a failing pod -- the **`--previous`** (crashed) container's logs
        when there is one (its tail IS the lead-up to the crash + the panic), else the current
        container's. The before-event context `analyze` needs, captured now so it survives the pod
        restarting and the logs rolling -- we used to keep only the last line, which starved the
        analysis of the lead-up where the cause lives. Best-effort: a failed read stays quiet (the
        symptom still surfaces, just no logs); the pod may be gone between the list and now.
        Bounded by ``cap_log``."""
        tail = str(self._scan_tail)  # generous -- the lead-up matters, not just the last line
        text = self._run_text(
            self._kubectl("logs", pod, "-n", namespace, "--tail", tail, "--previous"),
            best_effort=True,
        )
        if not text:
            text = self._run_text(
                self._kubectl("logs", pod, "-n", namespace, "--tail", tail), best_effort=True
            )
        return cap_log(text or "")

    def logs_for_analysis(self, namespace: str, pod: str) -> str:
        """Re-fetch a pod's logs FRESH for `analyze` -- the **`--previous`** (crashed) container's
        tail (the lead-up to the crash) AND the current container's (what's happened since the
        restart), each labelled and bounded. Pulled at analyze time, with a bigger tail than the
        scan snapshot, so the model investigates the live picture, not a stale capture. Best-effort:
        '' when the pod is gone / unreachable -- `analyze` falls back to the captured window."""
        tail = str(_ANALYZE_TAIL)
        parts: list[str] = []
        prev = self._run_text(
            self._kubectl("logs", pod, "-n", namespace, "--tail", tail, "--previous"),
            best_effort=True,
        )
        if prev.strip():
            parts.append("== previous (crashed) container ==\n" + cap_log(prev))
        cur = self._run_text(
            self._kubectl("logs", pod, "-n", namespace, "--tail", tail), best_effort=True
        )
        if cur.strip():
            parts.append("== current container ==\n" + cap_log(cur))
        return "\n\n".join(parts)

    def pod_status(self, namespace: str, pod: str) -> str:
        """The operational facts `analyze` needs beyond the logs -- restart count, the LAST
        termination (reason + exit code: 137 = OOMKilled, the smoking gun a log tail can miss), the
        current waiting reason, and readiness -- from one `kubectl get pod -o json`. Best-effort:
        '' when the pod is gone / unreadable. Read-only."""
        text = self._run_text(
            self._kubectl("get", "pod", pod, "-n", namespace, "-o", "json"), best_effort=True
        )
        if not text.strip():
            return ""
        try:
            return render_pod_status(json.loads(text))
        except json.JSONDecodeError:
            return ""

    def events_for(self, namespace: str, pod: str) -> str:
        """The cluster's recent events for this pod -- OOMKilled / FailedScheduling / image-pull /
        probe failures: the lead-up at the CLUSTER level the pod's own logs don't carry. One
        `kubectl get events`, oldest-last, bounded. Best-effort: '' when unreadable. Read-only."""
        text = self._run_text(
            self._kubectl(
                "get",
                "events",
                "-n",
                namespace,
                "--field-selector",
                f"involvedObject.name={pod}",
                "-o",
                "json",
            ),
            best_effort=True,
        )
        if not text.strip():
            return ""
        try:
            return render_events(json.loads(text))
        except json.JSONDecodeError:
            return ""

    def rollout_status(self, namespace: str, kind: str, name: str) -> str:
        """The owning controller's rollout facts for `analyze` -- images, generation, replicas,
        and the rollout conditions (when it last rolled) -- from one `kubectl get <kind> -o json`.
        ``kind`` is a Deployment / StatefulSet. Best-effort: '' when unreadable. Read-only."""
        text = self._run_text(
            self._kubectl("get", kind.lower(), name, "-n", namespace, "-o", "json"),
            best_effort=True,
        )
        if not text.strip():
            return ""
        try:
            return render_rollout(json.loads(text))
        except json.JSONDecodeError:
            return ""

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
