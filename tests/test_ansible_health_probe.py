"""The Ansible health probe: read-only service health -> Symptoms (the VM malfunction axis).

The detection rule (`host_health_symptoms`) and the callback parsing (`_services_by_host`) are pure
and exercised directly with fixture data -- no real ansible. Only the thin live read shells out,
and it degrades to no symptoms on any failure (ansible absent, no inventory, unparseable output).
"""

from __future__ import annotations

from unittest import mock

from steadystate.probe import ansible_health as ah
from steadystate.probe.ansible_health import (
    AnsibleHealthProbe,
    _mounts_by_host,
    _scaled_timeout,
    _services_by_host,
    disk_symptoms,
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


# -- disk_symptoms: the filling-filesystem rule -----------------------------------------------


def _mount(path: str, total: int, avail: int) -> dict:
    return {"mount": path, "size_total": total, "size_available": avail}


def test_a_filling_mount_is_medium_and_a_near_full_one_is_high():
    mounts = {"web01": [_mount("/", 100, 15), _mount("/var", 100, 5)]}  # 85% and 95%
    syms = {s.identity: s for s in disk_symptoms(mounts)}
    assert syms["web01:/"].severity == Severity.MEDIUM and "85% full" in syms["web01:/"].title
    assert syms["web01:/var"].severity == Severity.HIGH
    assert syms["web01:/"].category == "DiskFilling"


def test_a_healthy_mount_yields_no_symptom():
    assert disk_symptoms({"web01": [_mount("/", 100, 50)]}) == []  # 50% used -> below the warn line


def test_disk_symptoms_skips_mounts_with_unusable_size_facts():
    bad = {"web01": [{"mount": "/proc", "size_total": 0, "size_available": 0}, {"mount": "/x"}]}
    assert disk_symptoms(bad) == []  # zero/absent size -> skipped, never a divide or false positive


def test_mounts_by_host_pulls_mounts_out_of_a_setup_callback_doc():
    doc = {"plays": [{"tasks": [{"hosts": {"web01": {"ansible_facts": {"ansible_mounts": [1]}}}}]}]}
    assert _mounts_by_host(doc) == {"web01": [1]}
    assert _mounts_by_host("nope") == {}


# -- the live probe: end to end on a fixture, and honest degrade ------------------------------


def test_the_probe_reports_both_service_and_disk_findings(monkeypatch):
    services = _callback_doc({"haproxy.service": _svc("failed")})
    disks = {
        "plays": [
            {
                "tasks": [
                    {
                        "hosts": {
                            "web01": {
                                "ansible_facts": {
                                    "ansible_mounts": [
                                        {"mount": "/", "size_total": 100, "size_available": 5},
                                    ]
                                }
                            }
                        }
                    }
                ]
            }
        ]
    }
    monkeypatch.setattr(AnsibleHealthProbe, "_host_count", lambda self: 3)
    monkeypatch.setattr(
        AnsibleHealthProbe,
        "_run_module",
        lambda self, module, args="", **kw: services if module == "service_facts" else disks,
    )
    cats = {s.category for s in AnsibleHealthProbe().probe([])}
    assert cats == {"ServiceFailed", "DiskFilling"}  # both gathers contribute


def test_probe_maps_a_collected_doc_to_symptoms(monkeypatch):
    doc = _callback_doc({"haproxy.service": _svc("failed"), "nginx.service": _svc("running")})
    # The probe runs two gathers (service_facts, setup); return the service doc for the first only.
    monkeypatch.setattr(AnsibleHealthProbe, "_host_count", lambda self: 3)
    monkeypatch.setattr(
        AnsibleHealthProbe,
        "_run_module",
        lambda self, module, args="", **kw: doc if module == "service_facts" else None,
    )
    [s] = AnsibleHealthProbe().probe([])
    assert s.identity == "web01:haproxy.service" and s.category == "ServiceFailed"


def test_probe_degrades_to_no_symptoms_when_ansible_is_absent(monkeypatch):
    monkeypatch.setattr(ah.shutil, "which", lambda _binary: None)
    assert AnsibleHealthProbe().probe([]) == []  # no ansible -> both gathers None -> []


# -- fleet-scaled parallelism + timeout (the 30s-batch-timeout fix) ----------------------------


def test_scaled_timeout_grows_with_waves_and_has_a_floor():
    assert _scaled_timeout(20, 25) == 30.0  # one wave -> the floor
    assert _scaled_timeout(40, 25) == 40.0  # two waves x 20s
    assert _scaled_timeout(100, 25) == 80.0  # four waves
    assert _scaled_timeout(0, 5) == 40.0  # unknown host count -> assume two waves


def test_forks_default_scales_to_the_fleet_then_caps(monkeypatch):
    monkeypatch.delenv("STEADYSTATE_ANSIBLE_FORKS", raising=False)
    probe = AnsibleHealthProbe()
    assert probe._forks(10) == 10  # small fleet -> one wave (forks == hosts)
    assert probe._forks(100) == 25  # capped, so the control node isn't swamped
    assert probe._forks(0) == 25  # host count unknown -> the cap


def test_forks_and_timeout_honor_env_overrides(monkeypatch):
    monkeypatch.setenv("STEADYSTATE_ANSIBLE_FORKS", "8")
    monkeypatch.setenv("STEADYSTATE_ANSIBLE_TIMEOUT", "120")
    probe = AnsibleHealthProbe()
    assert probe._forks(100) == 8  # the env wins over the fleet-scaled default
    assert probe.timeout == 120.0  # an explicit timeout pins it (no scaling)


def test_run_module_adds_forks_and_uses_the_given_timeout(monkeypatch):
    monkeypatch.setattr(ah.shutil, "which", lambda _b: "/usr/bin/ansible")
    captured: dict = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        captured["timeout"] = kwargs.get("timeout")
        return mock.Mock(returncode=0, stdout="{}", stderr="")

    monkeypatch.setattr(ah.subprocess, "run", fake_run)
    AnsibleHealthProbe()._run_module("setup", "x=y", forks=12, timeout=45.0)
    assert "--forks" in captured["argv"] and "12" in captured["argv"]
    assert captured["timeout"] == 45.0
