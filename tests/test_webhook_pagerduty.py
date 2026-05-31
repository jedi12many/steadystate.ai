"""The generic webhook + PagerDuty surfaces -- pure payloads, per-alert emit, honest degrade."""

from __future__ import annotations

import json

from steadystate.model import ChangeType, Drift, Provenance
from steadystate.notify import SURFACES
from steadystate.notify import pagerduty as pd_mod
from steadystate.notify import webhook as wh_mod
from steadystate.notify.pagerduty import PagerDutySurface, format_pagerduty_event
from steadystate.notify.webhook import WebhookSurface, alert_event
from steadystate.reason.alert import Alert, Severity
from steadystate.reason.report import Report


def _drift(ident: str = "aws_s3_bucket.logs") -> Drift:
    return Drift(
        identity=ident,
        kind="aws_s3_bucket",
        change_type=ChangeType.MODIFIED,
        provenance=Provenance(source="terraform", address=ident),
    )


def _alert(severity: Severity = Severity.HIGH, drifts=None) -> Alert:
    return Alert(
        title="bucket drifted",
        severity=severity,
        drifts=[_drift()] if drifts is None else drifts,
        why_it_matters="exposure changed",
        recommended_action="re-apply the declared ACL",
        references=[],
    )


def _capture(monkeypatch, module):
    """Patch the surface module's safe_urlopen to record POSTed payloads instead of sending."""
    sent: list[dict] = []

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return b""

    def fake(request, *, timeout):
        sent.append(json.loads(request.data.decode()))
        return _Resp()

    monkeypatch.setattr(module, "safe_urlopen", fake)
    return sent


# -- registration --------------------------------------------------------------


def test_surfaces_are_registered():
    assert {"webhook", "pagerduty"} <= set(SURFACES)
    assert SURFACES["webhook"]().name == "webhook"
    assert SURFACES["pagerduty"]().name == "pagerduty"


# -- webhook -------------------------------------------------------------------


def test_webhook_event_is_a_clean_provider_agnostic_payload():
    event = alert_event(_alert())
    assert event["title"] == "bucket drifted"
    assert event["severity"] == "high"
    assert event["source"] == "terraform"
    assert event["recommended_action"] == "re-apply the declared ACL"
    assert event["fingerprints"] == [_drift().fingerprint]


def test_webhook_posts_one_event_per_alert(monkeypatch):
    sent = _capture(monkeypatch, wh_mod)
    WebhookSurface(url="https://hook.test/in").emit(Report(items=[_alert(), _alert()]))
    assert len(sent) == 2
    assert sent[0]["producer"] == "steadystate" and sent[0]["event"] == "alert"
    assert sent[0]["source"] == "terraform"  # the drift's backend, distinct from the producer


def test_webhook_degrades_when_unconfigured(monkeypatch):
    sent = _capture(monkeypatch, wh_mod)
    WebhookSurface(url=None).emit(Report(items=[_alert()]))  # no URL -> no send, no raise
    assert sent == []


# -- pagerduty -----------------------------------------------------------------


def test_pagerduty_event_is_a_trigger_keyed_by_fingerprint():
    event = format_pagerduty_event(_alert(), routing_key="RK")
    assert event["routing_key"] == "RK"
    assert event["event_action"] == "trigger"
    assert event["dedup_key"] == _drift().fingerprint  # re-scans fold into one incident
    assert event["payload"]["summary"] == "bucket drifted"
    assert event["payload"]["source"]  # PD requires a non-empty source


def test_pagerduty_severity_maps_to_pd_vocabulary():
    sev = {s: format_pagerduty_event(_alert(s), "RK")["payload"]["severity"] for s in Severity}
    assert sev[Severity.LOW] == "info"
    assert sev[Severity.MEDIUM] == "warning"
    assert sev[Severity.HIGH] == "error"
    assert sev[Severity.CRITICAL] == "critical"


def test_pagerduty_posts_per_alert_to_the_events_api(monkeypatch):
    sent = _capture(monkeypatch, pd_mod)
    PagerDutySurface(routing_key="RK").emit(Report(items=[_alert()]))
    assert len(sent) == 1 and sent[0]["routing_key"] == "RK"


def test_pagerduty_degrades_when_unconfigured(monkeypatch):
    sent = _capture(monkeypatch, pd_mod)
    PagerDutySurface(routing_key=None).emit(Report(items=[_alert()]))  # no key -> no send
    assert sent == []
