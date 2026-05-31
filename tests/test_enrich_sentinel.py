"""The Sentinel enricher: escalate a drift that ALSO has an active SIEM incident right now.

The security analog of the Prometheus enricher -- it reads a verdict Sentinel already computed (an
open incident), never runs a detection itself. These mock the Azure AD token + Log Analytics query
(no network, no real secret) and pin: it escalates only on a returned row, degrades honestly when
unconfigured or on a flaky SIEM, and never escalates on uncertainty.
"""

from __future__ import annotations

import json

from steadystate.model import ChangeType, Drift, Provenance
from steadystate.reason import enrich as enrich_mod
from steadystate.reason.alert import Alert, Severity
from steadystate.reason.enrich import ENRICHERS, SentinelEnricher, build_enricher
from steadystate.reason.report import Report


def _alert(severity: Severity = Severity.MEDIUM) -> Alert:
    drift = Drift(
        identity="google_compute_firewall.open",
        kind="google_compute_firewall",
        change_type=ChangeType.MODIFIED,
        provenance=Provenance(source="terraform", address="google_compute_firewall.open"),
    )
    return Alert(title="firewall opened", severity=severity, drifts=[drift], why_it_matters="w")


def _configured(**kw) -> SentinelEnricher:
    return SentinelEnricher(
        workspace_id=kw.get("workspace_id", "ws-guid"),
        query_template=kw.get("query", "SecurityIncident | where Title has '{name}'"),
        tenant="tenant",
        client_id="cid",
        client_secret="secret",
    )


class _Resp:
    def __init__(self, payload: object) -> None:
        self._b = json.dumps(payload).encode()

    def __enter__(self) -> _Resp:
        return self

    def __exit__(self, *a: object) -> bool:
        return False

    def read(self) -> bytes:
        return self._b


def _route(monkeypatch, *, token="TOK", rows, calls=None):
    """Patch safe_urlopen: the token endpoint returns a token, the query endpoint returns rows.
    Dispatch on the request *path* (not a hostname substring -- that's the URL-validation
    anti-pattern CodeQL rightly flags, even in a mock)."""

    def fake(request, *, timeout):
        url = request.full_url
        if calls is not None:
            calls.append(url)
        if "/oauth2/v2.0/token" in url:
            return _Resp({"access_token": token} if token else {})
        if "/v1/workspaces/" in url:
            return _Resp({"tables": [{"name": "PrimaryResult", "rows": rows}]})
        raise AssertionError(f"unexpected {url}")

    monkeypatch.setattr(enrich_mod, "safe_urlopen", fake)


# -- registry ------------------------------------------------------------------


def test_sentinel_is_registered():
    assert "sentinel" in ENRICHERS
    assert isinstance(build_enricher("sentinel"), SentinelEnricher)


# -- degrade -------------------------------------------------------------------


def test_unconfigured_is_a_no_op():
    alert = _alert()
    SentinelEnricher(workspace_id=None).enrich(Report(items=[alert]))  # nothing set
    assert alert.severity is Severity.MEDIUM and alert.runtime_context is None


def test_auth_failure_degrades_without_escalating(monkeypatch):
    _route(monkeypatch, token=None, rows=[["x"]])  # token endpoint returns no access_token
    alert = _alert()
    _configured().enrich(Report(items=[alert]))
    assert alert.severity is Severity.MEDIUM and alert.runtime_context is None


# -- escalation ----------------------------------------------------------------


def test_active_incident_escalates_and_annotates(monkeypatch):
    _route(monkeypatch, rows=[["INC-42", "Suspicious access", "High"]])
    alert = _alert(Severity.MEDIUM)
    _configured().enrich(Report(items=[alert]))
    assert alert.severity is Severity.HIGH  # bumped one level toward CRITICAL
    assert "sentinel" in alert.runtime_context and "INC-42" in alert.runtime_context


def test_no_incident_leaves_the_alert_untouched(monkeypatch):
    _route(monkeypatch, rows=[])  # the KQL returned no active incident for this resource
    alert = _alert(Severity.MEDIUM)
    _configured().enrich(Report(items=[alert]))
    assert alert.severity is Severity.MEDIUM and alert.runtime_context is None


def test_token_is_fetched_once_for_the_scan(monkeypatch):
    calls: list[str] = []
    _route(monkeypatch, rows=[["INC-1"]], calls=calls)
    report = Report(items=[_alert(), _alert()])
    _configured().enrich(report)
    assert sum("/oauth2/v2.0/token" in u for u in calls) == 1  # one token, reused


# -- template fill -------------------------------------------------------------


def test_kql_template_fills_the_resource_name():
    enricher = _configured(query="SecurityIncident | where Title has '{name}'")
    drift = Drift(
        identity="aws_s3_bucket.logs",
        kind="aws_s3_bucket",
        change_type=ChangeType.MODIFIED,
        provenance=Provenance(source="terraform", address="aws_s3_bucket.logs"),
    )
    assert enricher._kql(drift) == "SecurityIncident | where Title has 'logs'"
