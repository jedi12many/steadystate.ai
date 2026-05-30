"""Observability enrichment tests -- pure + no real network.

Covers the PromQL template fill (incl. name/namespace extraction from both ``a.b`` and
``g/Kind/ns/name`` identities and the {window} default), the _bump mapping (CRITICAL
stays), the enrich mutation (sets runtime_context + bumps severity on a hit, no-op on an
empty query), honest-degrade when unconfigured, a query exception that doesn't raise, and
the build_enricher registry dispatch -- mirroring test_correlators / test_registry.
"""

from __future__ import annotations

import urllib.error

import pytest

from steadystate.model import ChangeType, Drift, Provenance
from steadystate.reason.alert import Alert, Layer, Severity
from steadystate.reason.enrich import (
    ENRICHERS,
    Enricher,
    PrometheusEnricher,
    _bump,
    _name,
    _namespace,
    build_enricher,
)
from steadystate.reason.report import Report


def _drift(identity: str = "aws_s3_bucket.logs", source: str = "terraform") -> Drift:
    return Drift(
        identity=identity,
        kind="aws_s3_bucket",
        change_type=ChangeType.MODIFIED,
        provenance=Provenance(source=source),
    )


def _alert(drift: Drift, severity: Severity = Severity.MEDIUM) -> Alert:
    return Alert(
        title=drift.summary(),
        severity=severity,
        drifts=[drift],
        why_it_matters="declared and observed diverge",
        layer=Layer.ALERT,
    )


def _series(**labels: str) -> dict:
    return {"metric": labels, "value": [0, "1"]}


# -- name / namespace extraction -----------------------------------------------


def test_name_from_dot_and_slash_identities():
    assert _name("aws_s3_bucket.logs") == "logs"
    assert _name("apps/Deployment/prod/web") == "web"
    assert _name("Service/prod/web") == "web"
    assert _name("solo") == "solo"


def test_namespace_from_slash_identity_else_empty():
    assert _namespace("apps/Deployment/prod/web") == "prod"
    assert _namespace("Service/prod/web") == "prod"
    assert _namespace("aws_s3_bucket.logs") == ""  # dotted terraform identity has none
    assert _namespace("solo") == ""


# -- template fill -------------------------------------------------------------


def test_promql_fills_all_placeholders_for_a_slash_identity():
    enr = PrometheusEnricher(base_url="http://p", query_template="x", window="10m")
    drift = Drift(
        identity="apps/Deployment/prod/web",
        kind="Deployment",
        change_type=ChangeType.MODIFIED,
        provenance=Provenance(source="argocd"),
    )
    enr.query_template = "{identity}|{kind}|{source}|{name}|{namespace}|{window}"
    assert enr._promql(drift) == "apps/Deployment/prod/web|Deployment|argocd|web|prod|10m"


def test_promql_window_defaults_to_5m_and_dotted_namespace_is_empty():
    enr = PrometheusEnricher(
        base_url="http://p",
        query_template='up{{namespace="{namespace}",app="{name}"}}[{window}]',
    )
    # Dotted terraform identity: name=logs, namespace empty, window default 5m.
    assert enr._promql(_drift()) == 'up{namespace="",app="logs"}[5m]'


def test_promql_absent_placeholder_is_empty_never_keyerror():
    enr = PrometheusEnricher(base_url="http://p", query_template="{not_a_field}-{name}")
    assert enr._promql(_drift()) == "-logs"


# -- _bump ---------------------------------------------------------------------


def test_bump_steps_toward_critical_and_critical_stays():
    assert _bump(Severity.LOW) == Severity.MEDIUM
    assert _bump(Severity.MEDIUM) == Severity.HIGH
    assert _bump(Severity.HIGH) == Severity.CRITICAL
    assert _bump(Severity.CRITICAL) == Severity.CRITICAL


# -- enrich mutation -----------------------------------------------------------


def test_enrich_sets_context_and_bumps_when_query_returns_rows(monkeypatch):
    enr = PrometheusEnricher(base_url="http://p", query_template="q")
    monkeypatch.setattr(enr, "_query", lambda promql: [_series(app="web", namespace="prod")])

    alert = _alert(_drift(), severity=Severity.MEDIUM)
    report = Report(items=[alert])
    enr.enrich(report)

    assert alert.severity == Severity.HIGH  # bumped one level
    assert alert.runtime_context is not None
    assert "prometheus: 1 unhealthy series" in alert.runtime_context
    assert "app=web" in alert.runtime_context


def test_enrich_is_noop_when_queries_are_empty(monkeypatch):
    enr = PrometheusEnricher(base_url="http://p", query_template="q")
    monkeypatch.setattr(enr, "_query", lambda promql: [])

    alert = _alert(_drift(), severity=Severity.MEDIUM)
    report = Report(items=[alert])
    enr.enrich(report)

    assert alert.severity == Severity.MEDIUM  # unchanged
    assert alert.runtime_context is None  # no annotation


def test_enrich_critical_alert_stays_critical_on_hit(monkeypatch):
    enr = PrometheusEnricher(base_url="http://p", query_template="q")
    monkeypatch.setattr(enr, "_query", lambda promql: [_series(app="web")])

    alert = _alert(_drift(), severity=Severity.CRITICAL)
    report = Report(items=[alert])
    enr.enrich(report)
    assert alert.severity == Severity.CRITICAL  # already top, stays
    assert alert.runtime_context is not None  # still annotated


def test_enrich_queries_every_member_drift(monkeypatch):
    # A correlated Alert: any unhealthy member triggers the annotation + bump.
    enr = PrometheusEnricher(base_url="http://p", query_template="{name}")
    seen: list[str] = []

    def fake_query(promql: str) -> list[dict]:
        seen.append(promql)
        return [_series(app="b")] if promql == "b" else []

    monkeypatch.setattr(enr, "_query", fake_query)
    alert = Alert(
        title="2 correlated",
        severity=Severity.LOW,
        drifts=[_drift(identity="aws_s3_bucket.a"), _drift(identity="aws_s3_bucket.b")],
        why_it_matters="grouped",
        layer=Layer.ALERT,
    )
    enr.enrich(Report(items=[alert]))
    assert seen == ["a", "b"]  # one query per member
    assert alert.severity == Severity.MEDIUM  # bumped by the one unhealthy member


# -- honest degrade ------------------------------------------------------------


def test_enrich_degrades_to_noop_without_base_url(monkeypatch):
    monkeypatch.delenv("PROMETHEUS_URL", raising=False)
    enr = PrometheusEnricher(base_url=None, query_template="q")
    alert = _alert(_drift())
    report = Report(items=[alert])
    enr.enrich(report)
    assert alert.severity == Severity.MEDIUM
    assert alert.runtime_context is None


def test_enrich_degrades_to_noop_without_query_template(monkeypatch):
    monkeypatch.delenv("STEADYSTATE_ENRICH_QUERY", raising=False)
    enr = PrometheusEnricher(base_url="http://p", query_template=None)
    alert = _alert(_drift())
    enr.enrich(Report(items=[alert]))
    assert alert.runtime_context is None


def test_enrich_uses_env_fallbacks(monkeypatch):
    monkeypatch.setenv("PROMETHEUS_URL", "http://from-env")
    monkeypatch.setenv("STEADYSTATE_ENRICH_QUERY", "up == 0")
    enr = PrometheusEnricher()
    assert enr.base_url == "http://from-env"
    assert enr.query_template == "up == 0"


# -- _query: a flaky Prometheus never breaks a scan ----------------------------


def test_query_exception_returns_empty_and_does_not_raise(monkeypatch):
    enr = PrometheusEnricher(base_url="http://p", query_template="q")

    def boom(url, timeout):
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr("urllib.request.urlopen", boom)
    assert enr._query("up == 0") == []


def test_query_parses_success_result(monkeypatch):
    import io
    import json

    enr = PrometheusEnricher(base_url="http://p", query_template="q")
    payload = {"status": "success", "data": {"result": [_series(app="web")]}}

    class _Resp(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(
        "urllib.request.urlopen",
        lambda url, timeout: _Resp(json.dumps(payload).encode()),
    )
    result = enr._query("up == 0")
    assert result == [_series(app="web")]


def test_query_non_success_status_returns_empty(monkeypatch):
    import io
    import json

    enr = PrometheusEnricher(base_url="http://p", query_template="q")

    class _Resp(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(
        "urllib.request.urlopen",
        lambda url, timeout: _Resp(json.dumps({"status": "error"}).encode()),
    )
    assert enr._query("up == 0") == []


# -- registry dispatch ---------------------------------------------------------


def test_build_enricher_none_is_none():
    assert build_enricher("none") is None


def test_build_enricher_known_builds_and_conforms():
    for name in ENRICHERS:
        enricher = build_enricher(name)
        assert isinstance(enricher, Enricher)
        assert enricher.name == name


def test_build_enricher_unknown_raises_valueerror():
    with pytest.raises(ValueError, match="unknown enricher"):
        build_enricher("magic")


def test_prometheus_is_registered():
    assert "prometheus" in ENRICHERS
