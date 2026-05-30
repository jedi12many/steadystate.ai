"""The probe seam: the Symptom value type, the KubectlProbe, and the registry."""

from __future__ import annotations

import pytest

from steadystate.model import Provenance, Resource
from steadystate.probe import PROBES, auto_prober_for, build_prober
from steadystate.probe.base import Symptom
from steadystate.probe.kubectl import KubectlProbe, category_and_severity
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


# -- the probe ------------------------------------------------------------------


def _probe(monkeypatch, pods: dict, log: str = "fatal: missing DB_URL"):
    prober = KubectlProbe()
    monkeypatch.setattr(prober, "_get_pods", lambda namespace: pods)
    monkeypatch.setattr(prober, "_last_log_line", lambda namespace, pod: log)
    return prober


def test_probe_produces_a_symptom_for_an_unhealthy_declared_workload(monkeypatch):
    pods = {"items": [_pod("web-abc", waiting="CrashLoopBackOff", restarts=9)]}
    prober = _probe(monkeypatch, pods)
    [symptom] = prober.probe([_resource()])
    assert symptom.identity == "apps/Deployment/prod/web"
    assert symptom.category == "CrashLoopBackOff" and symptom.severity is Severity.HIGH
    assert "missing DB_URL" in symptom.detail  # the failing pod's last log line


def test_probe_is_silent_on_a_healthy_workload(monkeypatch):
    prober = _probe(monkeypatch, {"items": [_pod("web-ok", phase="Running")]})
    assert prober.probe([_resource()]) == []


def test_probe_ignores_non_kubernetes_resources(monkeypatch):
    looked_up: list[str] = []
    prober = KubectlProbe()
    monkeypatch.setattr(prober, "_get_pods", lambda ns: looked_up.append(ns) or {"items": []})
    assert prober.probe([_resource(identity="aws_s3_bucket.logs", source="terraform")]) == []
    assert looked_up == []  # never even ran kubectl


def test_probe_degrades_when_kubectl_unavailable(monkeypatch):
    def boom(*args, **kwargs):
        raise FileNotFoundError("kubectl not found")

    monkeypatch.setattr("steadystate.probe.kubectl.subprocess.run", boom)
    assert KubectlProbe().probe([_resource()]) == []  # no cluster -> no symptoms, no raise


# -- the registry ---------------------------------------------------------------


def test_registry_builds_probes_and_rejects_unknown(tmp_path):
    assert isinstance(build_prober("kubectl", tmp_path), KubectlProbe)
    assert build_prober("none", tmp_path) is None  # the default: no probe step
    assert {"kubectl", "docker", "argocd"} <= set(PROBES)
    with pytest.raises(ValueError, match="unknown prober"):
        build_prober("nope", tmp_path)


def test_auto_maps_each_source_with_a_health_signal():
    assert auto_prober_for("kubernetes") == "kubectl"
    assert auto_prober_for("docker-compose") == "docker"
    assert auto_prober_for("argocd") == "argocd"
    assert auto_prober_for("terraform") is None  # no health probe makes sense for terraform
    assert auto_prober_for("ansible") is None
