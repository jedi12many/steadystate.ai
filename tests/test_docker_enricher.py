"""Docker health enricher: container-health parsing + drift-anchored escalation, no real docker."""

from __future__ import annotations

from steadystate.model import ChangeType, Drift, Provenance
from steadystate.reason.alert import Alert, Layer, Severity
from steadystate.reason.enrich import (
    DockerHealthEnricher,
    build_enricher,
    unhealthy_containers,
)
from steadystate.reason.report import Report


def _container(name: str, *, state: str = "running", status: str = "Up 2 hours", service="web"):
    return {
        "Names": name,
        "State": state,
        "Status": status,
        "Labels": f"com.docker.compose.service={service},com.docker.compose.project=app",
    }


def _drift(identity: str = "web", source: str = "docker-compose") -> Drift:
    return Drift(
        identity=identity,
        kind="docker_compose_service",
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


# -- ps parsing (newline-delimited JSON + array fallback) -----------------------


def test_ps_parses_newline_delimited_json(monkeypatch):
    enricher = DockerHealthEnricher()
    monkeypatch.setattr(
        enricher, "_run_text", lambda argv: '{"Names":"a","State":"running"}\n{"Names":"b"}\n'
    )
    assert [c["Names"] for c in enricher._ps("web")] == ["a", "b"]


def test_ps_parses_a_json_array(monkeypatch):
    enricher = DockerHealthEnricher()
    monkeypatch.setattr(enricher, "_run_text", lambda argv: '[{"Names":"a"},{"Names":"b"}]')
    assert len(enricher._ps("web")) == 2


# -- the enricher: drift-anchored escalation (no real docker) -------------------


def _enricher(monkeypatch, entries: list[dict], log: str = "panic: cannot reach db"):
    enricher = DockerHealthEnricher()
    monkeypatch.setattr(enricher, "_ps", lambda service: entries)
    monkeypatch.setattr(enricher, "_last_log_line", lambda name: log)
    return enricher


def test_enrich_escalates_and_correlates_a_failing_service(monkeypatch):
    entries = [_container("app-web-1", state="restarting", status="Restarting (1) 2 seconds ago")]
    enricher = _enricher(monkeypatch, entries)
    alert = _alert(_drift(), Severity.MEDIUM)
    enricher.enrich(Report(items=[alert]))
    assert alert.severity is Severity.HIGH  # bumped: the drift is live-failing
    assert "restarting" in alert.runtime_context
    assert "cannot reach db" in alert.runtime_context  # the crash's own evidence


def test_enrich_leaves_a_healthy_service_untouched(monkeypatch):
    enricher = _enricher(monkeypatch, [_container("app-web-1", state="running")])
    alert = _alert(_drift(), Severity.MEDIUM)
    enricher.enrich(Report(items=[alert]))
    assert alert.severity is Severity.MEDIUM and alert.runtime_context is None


def test_enrich_ignores_non_compose_drifts(monkeypatch):
    looked_up: list[str] = []
    enricher = DockerHealthEnricher()
    monkeypatch.setattr(enricher, "_ps", lambda service: looked_up.append(service) or [])
    alert = _alert(_drift(identity="aws_s3_bucket.logs", source="terraform"))
    enricher.enrich(Report(items=[alert]))
    assert looked_up == [] and alert.runtime_context is None


def test_enrich_degrades_when_docker_unavailable(monkeypatch):
    def boom(*args, **kwargs):
        raise FileNotFoundError("docker not found")

    monkeypatch.setattr("steadystate.reason.enrich.subprocess.run", boom)
    alert = _alert(_drift(), Severity.MEDIUM)
    DockerHealthEnricher().enrich(Report(items=[alert]))  # no daemon -> no escalation, no raise
    assert alert.severity is Severity.MEDIUM and alert.runtime_context is None


def test_registered_in_the_enricher_registry():
    assert isinstance(build_enricher("docker"), DockerHealthEnricher)
