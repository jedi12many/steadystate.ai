"""Observability enrichment: cross-reference a surfaced Alert against live health.

A drift tells you declared and observed state diverge; it does NOT tell you whether
the drifted resource is *currently on fire*. This optional step closes that gap: for
each surfaced Alert it asks an external observability system (Prometheus today)
whether the drifted resource is unhealthy right now, and -- when it is -- annotates
the Alert with a short ``runtime_context`` note AND bumps its severity one level
toward CRITICAL. A drift on a resource that is failing this minute should page louder
than the same drift on a healthy one.

Like reconcile_state.reconcile, this runs *between* ``pipeline.run()`` and the
surfaces, mutating ``report.alerts`` in place. The Pipeline stays pure (no idea an
enricher exists) and the un-enriched path is byte-for-byte unchanged: enrichment is
opt-in via ``--enrich`` and honestly degrades to a no-op when unconfigured.

The enricher is a registered plugin seam, mirroring the correlator registry in
reason/pipeline.py: a name -> factory in ENRICHERS, resolved by build_enricher, with
``none`` (the default) meaning *no enrichment* (None, not an instance).
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from ..model import Drift
from .alert import Severity
from .report import Report

logger = logging.getLogger(__name__)

# One step toward CRITICAL. CRITICAL is the top, so it stays put -- we never lower a
# severity, only raise the floor for a drift that is actively failing.
_BUMP = {
    Severity.LOW: Severity.MEDIUM,
    Severity.MEDIUM: Severity.HIGH,
    Severity.HIGH: Severity.CRITICAL,
    Severity.CRITICAL: Severity.CRITICAL,
}


def _bump(severity: Severity) -> Severity:
    """Raise ``severity`` one level toward CRITICAL (CRITICAL stays). Never lowers."""
    return _BUMP[severity]


def _name(identity: str) -> str:
    """The resource's bare name: the last ``/``- or ``.``-separated segment of identity.

    terraform ``aws_s3_bucket.logs`` -> ``logs``; k8s/argocd ``apps/Deployment/prod/web``
    or ``Service/prod/web`` -> ``web``.
    """
    return identity.replace("/", ".").rsplit(".", 1)[-1]


def _namespace(identity: str) -> str:
    """The segment *before* the name for a slash identity, else ``""``.

    ``apps/Deployment/prod/web`` -> ``prod``; ``Service/prod/web`` -> ``prod``; a
    single-segment or dot-only (terraform) identity has no namespace -> ``""``.
    """
    if "/" not in identity:
        return ""
    segments = identity.split("/")
    return segments[-2] if len(segments) >= 2 else ""


@runtime_checkable
class Enricher(Protocol):
    """Mutates a Report's alerts in place with live-health context, between run + emit."""

    name: str

    def enrich(self, report: Report) -> None: ...


class PrometheusEnricher:
    """Annotate + escalate Alerts whose drifted resource is unhealthy in Prometheus now.

    The operator supplies a PromQL *template* that returns series ONLY when the resource
    is unhealthy, e.g. ``up{namespace="{namespace}",app="{name}"} == 0`` or
    ``rate(errors_total{app="{name}"}[{window}]) > 0``. We fill these placeholders per
    drift before querying:

      ``{identity}``  the full drift identity (``aws_s3_bucket.logs`` or ``g/Kind/ns/name``)
      ``{kind}``      the drift kind
      ``{source}``    the provenance source (``terraform``, ``argocd``, ...)
      ``{name}``      the bare resource name (last ``/``- or ``.``-segment of identity)
      ``{namespace}`` the segment before the name for slash identities, else ``""``
      ``{window}``    the configured rate window (default ``5m``)

    The template is filled with ``str.format_map``, so a *literal* brace in PromQL (the
    label selector braces) must be doubled: ``up{{app="{name}"}} == 0``. An absent
    placeholder fills empty (format_map over a defaultdict), never a KeyError -- the
    operator's template decides which placeholders matter. A query that returns ANY series
    means *unhealthy now*: we set ``runtime_context`` and bump the Alert's severity one
    level. A flaky Prometheus must never break a scan, so every network failure degrades
    to "no series" (treated as healthy).
    """

    name = "prometheus"

    def __init__(
        self,
        base_url: str | None = None,
        query_template: str | None = None,
        window: str = "5m",
        timeout: float = 10.0,
    ) -> None:
        self.base_url = base_url or os.environ.get("PROMETHEUS_URL")
        self.query_template = query_template or os.environ.get("STEADYSTATE_ENRICH_QUERY")
        self.window = window
        self.timeout = timeout

    def enrich(self, report: Report) -> None:
        # Honest degrade: without both a Prometheus URL and a template there's nothing to
        # ask, so we say so once and leave every Alert untouched (un-enriched path).
        if not self.base_url or not self.query_template:
            logger.warning(
                "Prometheus enrichment enabled but not configured "
                "(set PROMETHEUS_URL and STEADYSTATE_ENRICH_QUERY, or pass base_url + "
                "query_template); skipping enrichment of %d alert(s).",
                len(report.alerts),
            )
            return

        for alert in report.alerts:
            # One instant query per member drift; gather the distinct unhealthy series.
            results: list[dict] = []
            for drift in alert.drifts:
                results.extend(self._query(self._promql(drift)))
            if results:
                alert.runtime_context = self._summary(results)
                alert.severity = _bump(alert.severity)

    def _promql(self, drift: Drift) -> str:
        """Fill the operator's template for this drift; absent placeholders -> empty."""
        assert self.query_template is not None  # enrich() guards a configured template
        fields = defaultdict(
            str,
            identity=drift.identity,
            kind=drift.kind,
            source=drift.provenance.source,
            name=_name(drift.identity),
            namespace=_namespace(drift.identity),
            window=self.window,
        )
        return self.query_template.format_map(fields)

    def _summary(self, results: list[dict]) -> str:
        """A short one-line note for the Alert, sampling the first unhealthy series."""
        sample = results[0].get("metric", {})
        shown = ",".join(f"{k}={v}" for k, v in sorted(sample.items())) if sample else "no labels"
        return f"prometheus: {len(results)} unhealthy series ({shown})"

    def _query(self, promql: str) -> list[dict]:
        """GET an instant query; return ``data.result`` on success, else ``[]``.

        A flaky Prometheus must never break a scan, so any network/parse failure degrades
        to no series (the resource reads as healthy -- we don't escalate on uncertainty).
        """
        assert self.base_url is not None  # enrich() guards a configured base_url
        query_string = urllib.parse.urlencode({"query": promql})
        url = f"{self.base_url.rstrip('/')}/api/v1/query?{query_string}"
        try:
            with urllib.request.urlopen(url, timeout=self.timeout) as response:
                payload = json.loads(response.read())
        except (urllib.error.URLError, OSError, ValueError) as exc:
            logger.warning("Prometheus enrichment query failed: %s", exc)
            return []
        if payload.get("status") != "success":
            return []
        result = payload.get("data", {}).get("result", [])
        return result if isinstance(result, list) else []


# Container waiting-state reasons that mean it can't run (kubectl health enricher).
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
    """One unhealthy pod of a drifted workload: its name, why, and its restart count."""

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


class KubectlHealthEnricher:
    """Escalate a drifted Kubernetes resource whose pods are failing in the cluster right now.

    For each Alert's kubernetes drifts, list the pods in the drift's namespace, find the ones
    belonging to the drifted workload, and -- when any are unhealthy (CrashLoopBackOff, a failed
    phase, or restarts over the threshold) -- attach a one-line ``runtime_context`` (with the last
    log line from the worst pod, the crash's own evidence) and bump the Alert's severity. This is
    the differentiated bit: it *correlates the live failure to the drift* ("crashlooping since the
    image drifted"), rather than scanning all logs for errors (that's a metrics/log system's job).

    Reads via ``kubectl`` -- the same access the kubernetes source uses. Any failure (no cluster,
    no kubectl, RBAC) degrades to "healthy": never escalate on uncertainty, never break a scan."""

    name = "kubectl"

    def __init__(self, log_tail: int = 20, timeout: float = 10.0) -> None:
        self.log_tail = log_tail
        self.timeout = timeout

    def enrich(self, report: Report) -> None:
        for alert in report.alerts:
            notes: list[str] = []
            for drift in alert.drifts:
                if drift.provenance.source != "kubernetes":
                    continue  # this enricher only knows how to look up kubernetes resources
                namespace = _namespace(drift.identity) or "default"
                workload = _name(drift.identity)
                sick = unhealthy_pods(self._get_pods(namespace), workload)
                if sick:
                    notes.append(self._note(namespace, sick))
            if notes:
                alert.runtime_context = " · ".join(notes)
                alert.severity = _bump(alert.severity)

    def _note(self, namespace: str, sick: list[PodHealth]) -> str:
        reasons = ", ".join(sorted({pod.reason for pod in sick}))
        note = f"kubectl: {len(sick)} pod(s) unhealthy ({reasons})"
        worst = max(sick, key=lambda pod: pod.restarts)
        tail = self._last_log_line(namespace, worst.name)
        return f"{note}; last log: {tail}" if tail else note

    def _get_pods(self, namespace: str) -> dict:
        document = self._run_json(["kubectl", "get", "pods", "-n", namespace, "-o", "json"])
        return document or {}

    def _last_log_line(self, namespace: str, pod: str) -> str:
        """The last non-empty log line for ``pod`` -- the previous container (where a crash's
        final message lives), falling back to the current one. Best-effort: "" on any failure."""
        tail = str(self.log_tail)
        text = self._run_text(
            ["kubectl", "logs", pod, "-n", namespace, "--tail", tail, "--previous"]
        )
        if not text:
            text = self._run_text(["kubectl", "logs", pod, "-n", namespace, "--tail", tail])
        lines = [line for line in (text or "").splitlines() if line.strip()]
        return lines[-1][:200] if lines else ""

    def _run_json(self, argv: list[str]) -> dict | None:
        text = self._run_text(argv)
        if not text:
            return None
        try:
            parsed = json.loads(text)
        except ValueError:
            return None
        return parsed if isinstance(parsed, dict) else None

    def _run_text(self, argv: list[str]) -> str:
        try:
            result = subprocess.run(
                argv, check=True, capture_output=True, text=True, timeout=self.timeout
            )
            return result.stdout
        except (subprocess.SubprocessError, OSError) as exc:
            logger.warning("kubectl enrichment (%s) failed: %s", " ".join(argv[:3]), exc)
            return ""


# The enricher plugin registry: name -> zero-arg factory -> Enricher. Mirrors CORRELATORS
# in reason/pipeline.py (and the source/surface registries): a new enricher is one line
# here. "none" is the default and means *no enrichment* -- it is resolved in
# build_enricher to None, not registered as a name.
ENRICHERS: dict[str, Callable[[], Enricher]] = {
    "prometheus": PrometheusEnricher,
    "kubectl": KubectlHealthEnricher,
}


def build_enricher(mode: str) -> Enricher | None:
    """Construct the Enricher for ``mode`` (a registry name or ``none``), or raise.

    - ``none`` (default): None -- no enrichment step runs, the un-enriched path.
    - any registered name (``prometheus`` | an out-of-tree enricher): that enricher.
    - anything else: ValueError, the way build_correlator rejects unknown names (the CLI
      turns it into a clean typer.BadParameter).
    """
    if mode == "none":
        return None
    try:
        factory = ENRICHERS[mode]
    except KeyError:
        known = ", ".join(sorted(ENRICHERS))
        raise ValueError(f"unknown enricher '{mode}' (known: none, {known})") from None
    return factory()
