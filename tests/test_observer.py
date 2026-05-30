"""The observe seam: the Symptom value type, the KubectlObserver, and the registry."""

from __future__ import annotations

import pytest

from steadystate.model import Provenance, Resource
from steadystate.observe import OBSERVERS, build_observer
from steadystate.observe.base import Symptom
from steadystate.observe.kubectl import KubectlObserver, category_and_severity
from steadystate.reason.alert import Severity
from steadystate.reason.enrich import PodHealth


def _symptom(category: str = "CrashLoopBackOff", identity: str = "apps/Deployment/prod/web"):
    return Symptom(
        identity=identity,
        kind="Deployment",
        category=category,
        severity=Severity.HIGH,
        title=f"x is {category}",
        detail="2 pod(s)",
        provenance=Provenance(source="kubernetes", address=identity),
    )


def _pod(name: str, *, waiting: str | None = None, phase: str = "Running", restarts: int = 0):
    state = {"waiting": {"reason": waiting}} if waiting else {}
    container = {"restartCount": restarts, "state": state}
    status = {"phase": phase, "containerStatuses": [container]}
    return {"metadata": {"name": name}, "status": status}


def _resource(identity: str = "apps/Deployment/prod/web", source: str = "kubernetes") -> Resource:
    return Resource(
        kind="Deployment",
        identity=identity,
        provenance=Provenance(source=source, address=identity),
    )


# -- the Symptom value type -----------------------------------------------------


def test_fingerprint_stable_and_distinct_per_category():
    assert _symptom("CrashLoopBackOff").fingerprint == _symptom("CrashLoopBackOff").fingerprint
    assert _symptom("CrashLoopBackOff").fingerprint != _symptom("ImagePullBackOff").fingerprint
    assert _symptom(identity="a/b").fingerprint != _symptom(identity="a/c").fingerprint


def test_summary_reads_category_kind_identity():
    symptom = _symptom("CrashLoopBackOff")
    assert symptom.summary() == f"CrashLoopBackOff Deployment {symptom.identity}"


# -- category + severity (pure) -------------------------------------------------


def test_cannot_run_reason_is_high():
    sick = [PodHealth(name="web-1", reason="CrashLoopBackOff", restarts=9)]
    assert category_and_severity(sick) == ("CrashLoopBackOff", Severity.HIGH)


def test_restart_flap_is_medium():
    sick = [PodHealth(name="web-1", reason="7 restarts", restarts=7)]
    assert category_and_severity(sick) == ("7 restarts", Severity.MEDIUM)


def test_a_single_cannot_run_pod_makes_the_whole_symptom_high():
    sick = [
        PodHealth(name="web-1", reason="5 restarts", restarts=5),
        PodHealth(name="web-2", reason="CrashLoopBackOff", restarts=20),
    ]
    category, severity = category_and_severity(sick)
    assert severity is Severity.HIGH and category == "CrashLoopBackOff"


# -- the observer ---------------------------------------------------------------


def _observer(monkeypatch, pods: dict, log: str = "fatal: missing DB_URL"):
    observer = KubectlObserver()
    monkeypatch.setattr(observer, "_get_pods", lambda namespace: pods)
    monkeypatch.setattr(observer, "_last_log_line", lambda namespace, pod: log)
    return observer


def test_observe_produces_a_symptom_for_an_unhealthy_declared_workload(monkeypatch):
    pods = {"items": [_pod("web-abc", waiting="CrashLoopBackOff", restarts=9)]}
    observer = _observer(monkeypatch, pods)
    [symptom] = observer.observe([_resource()])
    assert symptom.identity == "apps/Deployment/prod/web"
    assert symptom.category == "CrashLoopBackOff" and symptom.severity is Severity.HIGH
    assert "missing DB_URL" in symptom.detail  # the failing pod's last log line


def test_observe_is_silent_on_a_healthy_workload(monkeypatch):
    observer = _observer(monkeypatch, {"items": [_pod("web-ok", phase="Running")]})
    assert observer.observe([_resource()]) == []


def test_observe_ignores_non_kubernetes_resources(monkeypatch):
    looked_up: list[str] = []
    observer = KubectlObserver()
    monkeypatch.setattr(observer, "_get_pods", lambda ns: looked_up.append(ns) or {"items": []})
    assert observer.observe([_resource(identity="aws_s3_bucket.logs", source="terraform")]) == []
    assert looked_up == []  # never even ran kubectl


def test_observe_degrades_when_kubectl_unavailable(monkeypatch):
    def boom(*args, **kwargs):
        raise FileNotFoundError("kubectl not found")

    monkeypatch.setattr("steadystate.observe.kubectl.subprocess.run", boom)
    assert KubectlObserver().observe([_resource()]) == []  # no cluster -> no symptoms, no raise


# -- the registry ---------------------------------------------------------------


def test_registry_builds_kubectl_and_rejects_unknown():
    assert isinstance(build_observer("kubectl"), KubectlObserver)
    assert build_observer("none") is None  # the default: no observe step
    assert "kubectl" in OBSERVERS
    with pytest.raises(ValueError, match="unknown observer"):
        build_observer("nope")
