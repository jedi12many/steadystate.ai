"""The ServiceNow surface -- pure incident payload, create-or-update upsert, honest degrade."""

from __future__ import annotations

import json
import urllib.error

from steadystate.model import ChangeType, Drift, Provenance
from steadystate.notify import SURFACES
from steadystate.notify import servicenow as sn_mod
from steadystate.notify.servicenow import ServiceNowSurface, format_servicenow_incident
from steadystate.probe.base import Symptom
from steadystate.reason.alert import Alert, Layer, Severity
from steadystate.reason.report import Report


def _drift(ident: str = "aws_s3_bucket.logs") -> Drift:
    return Drift(
        identity=ident,
        kind="aws_s3_bucket",
        change_type=ChangeType.MODIFIED,
        provenance=Provenance(source="terraform", address=ident),
    )


def _alert(severity: Severity = Severity.HIGH, **kw) -> Alert:
    return Alert(
        title="bucket drifted",
        severity=severity,
        drifts=[_drift()],
        why_it_matters="exposure changed",
        recommended_action="re-apply the declared ACL",
        **kw,
    )


def _sn(instance="dev12345", user="svc", password="pw", **kw) -> ServiceNowSurface:
    return ServiceNowSurface(instance=instance, user=user, password=password, **kw)


def _fake(monkeypatch, *, existing_sys_id=None, get_raises=False):
    """Patch safe_urlopen: record every request, answer the find GET with a configurable result."""
    calls: list[tuple[str, str, dict | None]] = []

    class _Resp:
        def __init__(self, body: bytes = b"{}") -> None:
            self._body = body

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return self._body

    def fake(request, *, timeout):
        body = json.loads(request.data.decode()) if request.data else None
        calls.append((request.method, request.full_url, body))
        if request.method == "GET":
            if get_raises:
                raise urllib.error.URLError("boom")
            result = [{"sys_id": existing_sys_id}] if existing_sys_id else []
            return _Resp(json.dumps({"result": result}).encode())
        return _Resp(b"{}")

    monkeypatch.setattr(sn_mod, "safe_urlopen", fake)
    return calls


# -- registration --------------------------------------------------------------


def test_servicenow_is_registered():
    assert "servicenow" in SURFACES
    assert SURFACES["servicenow"]().name == "servicenow"


# -- the pure payload ----------------------------------------------------------


def test_incident_payload_maps_the_alert():
    fields = format_servicenow_incident(_alert())
    assert fields["short_description"] == "bucket drifted"
    assert fields["urgency"] == "1" and fields["impact"] == "1"  # HIGH -> 1
    assert fields["correlation_id"] == _drift().fingerprint  # the dedup key
    assert "re-apply the declared ACL" in fields["description"]


def test_short_description_is_capped_at_160():
    big = Alert(title="x" * 300, severity=Severity.LOW, drifts=[], why_it_matters="y")
    assert len(format_servicenow_incident(big)["short_description"]) == 160


def test_severity_maps_to_urgency():
    got = {s: format_servicenow_incident(_alert(s))["urgency"] for s in Severity}
    assert got[Severity.LOW] == "3"
    assert got[Severity.MEDIUM] == "2"
    assert got[Severity.HIGH] == "1"
    assert got[Severity.CRITICAL] == "1"


def test_a_correlated_group_is_one_incident_keyed_by_its_group_fingerprint():
    symptom = Symptom(
        identity="prod/apps/Deployment/ns/squid",
        kind="Deployment",
        category="CrashLoopBackOff",
        severity=Severity.HIGH,
        title="squid is CrashLoopBackOff",
        detail="x",
        provenance=Provenance(source="kubernetes", address="x"),
    )
    grouped = Alert(
        title="squid is CrashLoopBackOff in 2 place(s)",
        severity=Severity.HIGH,
        drifts=[],
        why_it_matters="grouped",
        layer=Layer.ALERT,
        symptoms=[symptom],
        correlation_fingerprint="g" * 64,
    )
    assert format_servicenow_incident(grouped)["correlation_id"] == "g" * 64


# -- emit: create-or-update ----------------------------------------------------


def test_emit_creates_an_incident_when_none_is_open(monkeypatch):
    calls = _fake(monkeypatch)  # GET returns no result -> create
    _sn().emit(Report(items=[_alert()]))
    methods = [c[0] for c in calls]
    assert methods == ["GET", "POST"]
    get_url, post_url, post_body = calls[0][1], calls[1][1], calls[1][2]
    assert "dev12345.service-now.com/api/now/table/incident" in get_url
    assert post_url.endswith("/api/now/table/incident")
    assert post_body["correlation_id"] == _drift().fingerprint


def test_emit_updates_the_open_incident_instead_of_duplicating(monkeypatch):
    calls = _fake(monkeypatch, existing_sys_id="abc123")  # GET finds one -> update
    _sn().emit(Report(items=[_alert()]))
    assert [c[0] for c in calls] == ["GET", "PATCH"]
    patch_url, patch_body = calls[1][1], calls[1][2]
    assert patch_url.endswith("/api/now/table/incident/abc123")
    assert "work_notes" in patch_body  # a note on the existing incident, not a new record


def test_emit_skips_on_a_failed_lookup_to_avoid_duplicates(monkeypatch):
    calls = _fake(monkeypatch, get_raises=True)
    _sn().emit(Report(items=[_alert()]))
    assert [c[0] for c in calls] == ["GET"]  # lookup failed -> no blind create


def test_emit_degrades_when_unconfigured(monkeypatch):
    calls = _fake(monkeypatch)
    ServiceNowSurface(instance="dev12345", user=None, password="pw").emit(Report(items=[_alert()]))
    assert calls == []  # missing a credential -> no send, no raise


def test_a_full_base_url_instance_is_used_as_is(monkeypatch):
    calls = _fake(monkeypatch)
    _sn(instance="https://acme.example.com").emit(Report(items=[_alert()]))
    assert "https://acme.example.com/api/now/table/incident" in calls[1][1]


def test_basic_auth_header_is_sent(monkeypatch):
    seen = {}

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return b'{"result": []}'

    def fake(request, *, timeout):
        seen["auth"] = request.get_header("Authorization", "")
        return _Resp()

    monkeypatch.setattr(sn_mod, "safe_urlopen", fake)
    _sn().emit(Report(items=[_alert()]))
    assert seen["auth"].startswith("Basic ")
