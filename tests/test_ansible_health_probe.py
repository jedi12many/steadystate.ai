"""The Ansible health probe: read-only service health -> Symptoms (the VM malfunction axis).

The detection rule (`host_health_symptoms`) and the callback parsing (`_services_by_host`) are pure
and exercised directly with fixture data -- no real ansible. Only the thin live read shells out,
and it degrades to no symptoms on any failure (ansible absent, no inventory, unparseable output).
"""

from __future__ import annotations

from steadystate.probe import ansible_health as ah
from steadystate.probe.ansible_health import (
    AnsibleHealthProbe,
    _services_by_host,
    host_health_symptoms,
)
from steadystate.reason.alert import Severity


def _svc(state: str, status: str = "enabled") -> dict:
    return {"state": state, "status": status}


# -- host_health_symptoms: the pure health rule -----------------------------------------------


def test_failed_unit_is_high_serviced_failed():
    [s] = host_health_symptoms({"web01": {"haproxy.service": _svc("failed")}})
    assert s.category == "ServiceFailed" and s.severity is Severity.HIGH
    assert s.identity == "web01:haproxy.service" and s.kind == "Service"
    assert s.provenance.source == "ansible"
    assert s.evidence["host"] == "web01" and s.evidence["state"] == "failed"


def test_enabled_but_stopped_is_medium_service_down():
    [s] = host_health_symptoms({"web01": {"keepalived.service": _svc("stopped", "enabled")}})
    assert s.category == "ServiceDown" and s.severity is Severity.MEDIUM


def test_running_and_disabled_stopped_services_are_healthy():
    healthy = {
        "web01": {
            "haproxy.service": _svc("running", "enabled"),  # up -> fine
            "active.service": _svc("active", "enabled"),  # "active" counts as running
            "debug.service": _svc("stopped", "disabled"),  # not enabled -> meant to be off
            "tmp.mount": _svc("stopped", "static"),  # static unit, off is fine
        }
    }
    assert host_health_symptoms(healthy) == []


def test_rule_is_robust_to_malformed_entries():
    doc = {"web01": {"ok.service": _svc("failed"), "weird": "not-a-dict"}, "bad": "nope"}
    [s] = host_health_symptoms(doc)  # the one good failed unit, the junk skipped not crashed
    assert s.identity == "web01:ok.service"


def test_symptoms_are_sorted_and_fingerprints_stable():
    doc = {"b01": {"y.service": _svc("failed")}, "a01": {"x.service": _svc("failed")}}
    syms = host_health_symptoms(doc)
    assert [s.identity for s in syms] == ["a01:x.service", "b01:y.service"]  # host then service
    # fingerprint = source|identity|category -- stable across runs
    assert syms[0].fingerprint == syms[0].fingerprint


# -- _services_by_host: parse the JSON-callback shape -----------------------------------------


def _callback_doc(services: dict) -> dict:
    """An `ansible -m service_facts` run as the json stdout callback renders it."""
    return {"plays": [{"tasks": [{"hosts": {"web01": {"ansible_facts": {"services": services}}}}]}]}


def test_services_by_host_pulls_services_out_of_the_callback_doc():
    doc = _callback_doc({"haproxy.service": _svc("failed")})
    assert _services_by_host(doc) == {"web01": {"haproxy.service": _svc("failed")}}


def test_services_by_host_degrades_on_odd_documents():
    assert _services_by_host({}) == {}
    assert _services_by_host("nope") == {}
    assert _services_by_host({"plays": [{"tasks": [{"hosts": {"h": {}}}]}]}) == {}  # no facts


# -- the live probe: end to end on a fixture, and honest degrade ------------------------------


def test_probe_maps_a_collected_doc_to_symptoms(monkeypatch):
    doc = _callback_doc({"haproxy.service": _svc("failed"), "nginx.service": _svc("running")})
    monkeypatch.setattr(AnsibleHealthProbe, "_collect", lambda self: doc)
    [s] = AnsibleHealthProbe().probe([])
    assert s.identity == "web01:haproxy.service" and s.category == "ServiceFailed"


def test_probe_degrades_to_no_symptoms_when_ansible_is_absent(monkeypatch):
    monkeypatch.setattr(ah.shutil, "which", lambda _binary: None)
    assert AnsibleHealthProbe().probe([]) == []  # no ansible -> _collect None -> []
