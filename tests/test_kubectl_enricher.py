"""Kubectl health enricher: pod-health parsing + drift-anchored escalation, no real kubectl."""

from __future__ import annotations

from steadystate.model import ChangeType, Drift, Provenance
from steadystate.reason.alert import Alert, Layer, Severity
from steadystate.reason.enrich import (
    KubectlHealthEnricher,
    build_enricher,
    unhealthy_pods,
)
from steadystate.reason.report import Report


def _pod(name: str, *, waiting: str | None = None, phase: str = "Running", restarts: int = 0):
    state = {"waiting": {"reason": waiting}} if waiting else {}
    return {
        "metadata": {"name": name},
        "status": {
            "phase": phase,
            "containerStatuses": [{"restartCount": restarts, "state": state}],
        },
    }


def _pods(*items: dict) -> dict:
    return {"items": list(items)}


def _drift(identity: str = "apps/Deployment/prod/web", source: str = "kubernetes") -> Drift:
    return Drift(
        identity=identity,
        kind="Deployment",
        change_type=ChangeType.MODIFIED,
        provenance=Provenance(source=source, address=identity),
    )


def _alert(drift: Drift, severity: Severity = Severity.MEDIUM) -> Alert:
    return Alert(
        title=drift.summary(),
        severity=severity,
        drifts=[drift],
        why_it_matters="declared and observed diverge",
        layer=Layer.ALERT,
    )


# -- unhealthy_pods (pure) ------------------------------------------------------


def test_detects_crashloop():
    pods = _pods(_pod("web-abc-123", waiting="CrashLoopBackOff", restarts=7))
    [health] = unhealthy_pods(pods, "web")
    assert (health.name, health.reason, health.restarts) == ("web-abc-123", "CrashLoopBackOff", 7)


def test_detects_image_pull_and_failed_phase():
    pods = _pods(_pod("web-1", waiting="ImagePullBackOff"), _pod("web-2", phase="Failed"))
    assert {p.reason for p in unhealthy_pods(pods, "web")} == {"ImagePullBackOff", "Failed"}


def test_detects_restart_threshold_even_when_running():
    [pod] = unhealthy_pods(_pods(_pod("web-x", phase="Running", restarts=6)), "web")
    assert pod.reason == "6 restarts"


def test_healthy_pods_are_ignored():
    assert unhealthy_pods(_pods(_pod("web-ok", phase="Running", restarts=0)), "web") == []


def test_matches_only_workload_pods_by_prefix():
    pods = _pods(
        _pod("web-abc", waiting="CrashLoopBackOff"),  # belongs to web
        _pod("api-abc", waiting="CrashLoopBackOff"),  # a different workload
    )
    assert [p.name for p in unhealthy_pods(pods, "web")] == ["web-abc"]


def test_aggregates_restarts_across_containers():
    pod = {
        "metadata": {"name": "web-1"},
        "status": {
            "phase": "Running",
            "containerStatuses": [
                {"restartCount": 3, "state": {}},
                {"restartCount": 4, "state": {}},
            ],
        },
    }
    [health] = unhealthy_pods(_pods(pod), "web")
    assert health.restarts == 7 and health.reason == "7 restarts"


# -- the enricher: drift-anchored escalation (no real kubectl) ------------------


def _enricher(monkeypatch, pods: dict, log: str = "fatal: missing DB_URL"):
    enricher = KubectlHealthEnricher()
    monkeypatch.setattr(enricher, "_get_pods", lambda namespace: pods)
    monkeypatch.setattr(enricher, "_last_log_line", lambda namespace, pod: log)
    return enricher


def test_enrich_escalates_and_correlates_a_failing_drift(monkeypatch):
    pods = _pods(_pod("web-abc", waiting="CrashLoopBackOff", restarts=9))
    enricher = _enricher(monkeypatch, pods)
    alert = _alert(_drift(), Severity.MEDIUM)
    enricher.enrich(Report(items=[alert]))
    assert alert.severity is Severity.HIGH  # bumped: the drift is live-failing
    assert "CrashLoopBackOff" in alert.runtime_context
    assert "missing DB_URL" in alert.runtime_context  # the crash's own evidence


def test_enrich_leaves_a_healthy_drift_untouched(monkeypatch):
    enricher = _enricher(monkeypatch, _pods(_pod("web-ok")))
    alert = _alert(_drift(), Severity.MEDIUM)
    enricher.enrich(Report(items=[alert]))
    assert alert.severity is Severity.MEDIUM and alert.runtime_context is None


def test_enrich_ignores_non_kubernetes_drifts(monkeypatch):
    looked_up: list[str] = []
    enricher = KubectlHealthEnricher()
    monkeypatch.setattr(enricher, "_get_pods", lambda ns: looked_up.append(ns) or _pods())
    alert = _alert(_drift(identity="aws_s3_bucket.logs", source="terraform"))
    enricher.enrich(Report(items=[alert]))
    assert looked_up == [] and alert.runtime_context is None  # never even looked up pods


def test_enrich_degrades_when_kubectl_unavailable(monkeypatch):
    def boom(*args, **kwargs):
        raise FileNotFoundError("kubectl not found")

    monkeypatch.setattr("steadystate.reason.enrich.subprocess.run", boom)
    alert = _alert(_drift(), Severity.MEDIUM)
    KubectlHealthEnricher().enrich(Report(items=[alert]))  # no cluster -> no escalation, no raise
    assert alert.severity is Severity.MEDIUM and alert.runtime_context is None


def test_registered_in_the_enricher_registry():
    assert isinstance(build_enricher("kubectl"), KubectlHealthEnricher)
