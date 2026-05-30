"""The docker health probe: container health -> Symptom for declared compose services."""

from __future__ import annotations

from steadystate.model import Provenance, Resource
from steadystate.probe.docker import (
    ContainerHealth,
    DockerProbe,
    category_and_severity,
    unhealthy_containers,
)
from steadystate.reason.alert import Severity


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


# -- unhealthy_containers (pure) ------------------------------------------------


def test_restarting_is_unhealthy():
    [health] = unhealthy_containers([_container("app-web-1", state="restarting")], "web")
    assert health.reason == "restarting" and health.name == "app-web-1"


def test_exited_nonzero_flagged_but_clean_exit_is_not():
    bad = _container("w1", state="exited", status="Exited (137) 1 minute ago")
    clean = _container("w2", state="exited", status="Exited (0) 1 minute ago")
    assert {h.reason for h in unhealthy_containers([bad, clean], "web")} == {"exited (137)"}


def test_failing_healthcheck_is_unhealthy():
    container = _container("w", state="running", status="Up 3 hours (unhealthy)")
    assert unhealthy_containers([container], "web")[0].reason == "unhealthy"


def test_dead_is_unhealthy():
    [health] = unhealthy_containers([_container("w", state="dead", status="Dead")], "web")
    assert health.reason == "dead"


def test_healthy_running_is_ignored():
    healthy = [_container("w", state="running", status="Up 2 hours")]
    assert unhealthy_containers(healthy, "web") == []


def test_only_the_named_service_matches():
    web = _container("web1", state="restarting", service="web")
    api = _container("api1", state="restarting", service="api")
    assert [h.name for h in unhealthy_containers([web, api], "web")] == ["web1"]


def test_labels_as_a_dict_also_match():
    container = {
        "Names": "w",
        "State": "dead",
        "Status": "Dead",
        "Labels": {"com.docker.compose.service": "web"},
    }
    assert unhealthy_containers([container], "web")[0].reason == "dead"


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
