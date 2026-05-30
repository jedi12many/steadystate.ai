"""The docker health probe: container health -> Symptom for declared compose services."""

from __future__ import annotations

from steadystate.model import Provenance, Resource
from steadystate.probe.docker import DockerProbe, category_and_severity
from steadystate.reason.alert import Severity
from steadystate.reason.enrich import ContainerHealth


def _container(name: str, *, state: str = "running", status: str = "Up 2 hours", service="web"):
    return {
        "Names": name,
        "State": state,
        "Status": status,
        "Labels": f"com.docker.compose.service={service},com.docker.compose.project=app",
    }


def _resource(identity: str = "web", source: str = "docker-compose") -> Resource:
    return Resource(
        kind="docker_compose_service",
        identity=identity,
        provenance=Provenance(source=source, address=identity),
    )


# -- category + severity (pure) -------------------------------------------------


def test_a_down_container_is_high():
    assert category_and_severity([ContainerHealth(name="c", reason="restarting")]) == (
        "restarting",
        Severity.HIGH,
    )


def test_only_a_failing_healthcheck_is_medium():
    assert category_and_severity([ContainerHealth(name="c", reason="unhealthy")]) == (
        "unhealthy",
        Severity.MEDIUM,
    )


def test_down_wins_over_unhealthy():
    sick = [
        ContainerHealth(name="c1", reason="unhealthy"),
        ContainerHealth(name="c2", reason="dead"),
    ]
    _, severity = category_and_severity(sick)
    assert severity is Severity.HIGH


# -- the probe ------------------------------------------------------------------


def _probe(monkeypatch, entries: list[dict], log: str = "panic: cannot reach db"):
    prober = DockerProbe()
    monkeypatch.setattr(prober, "_ps", lambda service: entries)
    monkeypatch.setattr(prober, "_last_log_line", lambda name: log)
    return prober


def test_probe_produces_a_symptom_for_a_failing_service(monkeypatch):
    entries = [_container("app-web-1", state="restarting", status="Restarting (1) 2s ago")]
    [symptom] = _probe(monkeypatch, entries).probe([_resource()])
    assert symptom.identity == "web" and symptom.category == "restarting"
    assert symptom.severity is Severity.HIGH and "cannot reach db" in symptom.detail


def test_probe_is_silent_on_a_healthy_service(monkeypatch):
    prober = _probe(monkeypatch, [_container("app-web-1", state="running")])
    assert prober.probe([_resource()]) == []


def test_probe_ignores_non_compose_resources(monkeypatch):
    called: list[str] = []
    prober = DockerProbe()
    monkeypatch.setattr(prober, "_ps", lambda service: called.append(service) or [])
    assert prober.probe([_resource(identity="aws_s3_bucket.logs", source="terraform")]) == []
    assert called == []


def test_probe_degrades_when_docker_unavailable(monkeypatch):
    def boom(*args, **kwargs):
        raise FileNotFoundError("docker not found")

    monkeypatch.setattr("steadystate.probe.docker.subprocess.run", boom)
    assert DockerProbe().probe([_resource()]) == []  # no daemon -> no symptoms, no raise
