"""`ansible-live` -- a pathless live host-health target, the ansible analog of `k8s-live`, plus the
cwd inventory discovery that feeds it (ansible.cfg -> conventional names -> validate). These pin the
source (no drift, registered, pathless, auto-selects the ansible probe), the inventory resolution,
the target it builds, and that the inventory threads through to the probe's `-i`."""

from __future__ import annotations

from pathlib import Path
from unittest import mock

import steadystate.discover as disc
import steadystate.probe.ansible_health as ah
from steadystate.discover import ansible_live_target, cwd_inventory
from steadystate.engine import SupportsInventory, build_report
from steadystate.probe import auto_prober_for
from steadystate.sources import DRIFT_SOURCES, PATHLESS_SOURCES, build_drift_source
from steadystate.sources.ansible import AnsibleLiveSource
from steadystate.targets import Target, load_targets, save_targets

# -- the source -----------------------------------------------------------------


def test_ansible_live_reports_no_drift():
    assert AnsibleLiveSource().collect_drift() == []


def test_ansible_live_is_registered_pathless_and_probe_backed():
    assert "ansible-live" in DRIFT_SOURCES and "ansible-live" in PATHLESS_SOURCES
    assert isinstance(build_drift_source("ansible-live", Path(".")), AnsibleLiveSource)
    assert auto_prober_for("ansible-live") == "ansible"  # the health probe is the whole job


# -- inventory discovery (ansible.cfg -> conventional names -> validate) ---------


def test_cwd_inventory_prefers_what_ansible_cfg_declares(tmp_path: Path, monkeypatch):
    (tmp_path / "ansible.cfg").write_text("[defaults]\ninventory = hosts\n")
    (tmp_path / "hosts").write_text("[web]\nhost1\n")
    monkeypatch.setattr(disc.shutil, "which", lambda _b: None)  # no ansible -> trust the cfg signal
    assert cwd_inventory(tmp_path) == str(tmp_path / "hosts")


def test_cwd_inventory_falls_back_to_a_conventional_filename(tmp_path: Path, monkeypatch):
    (tmp_path / "inventory.ini").write_text("[web]\nhost1\n")  # no ansible.cfg
    monkeypatch.setattr(disc.shutil, "which", lambda _b: None)
    assert cwd_inventory(tmp_path) == str(tmp_path / "inventory.ini")


def test_cwd_inventory_validates_with_ansible_when_present(tmp_path: Path, monkeypatch):
    (tmp_path / "inventory").write_text("not really an inventory")
    monkeypatch.setattr(disc.shutil, "which", lambda _b: "/usr/bin/ansible-inventory")
    # ansible-inventory parses it but finds no hosts -> not a real inventory -> rejected.
    monkeypatch.setattr(disc, "_run_json", lambda _argv: {"_meta": {}, "all": {"children": []}})
    assert cwd_inventory(tmp_path) is None
    # now it parses into hosts -> accepted.
    monkeypatch.setattr(disc, "_run_json", lambda _argv: {"ungrouped": {"hosts": ["h1"]}})
    assert cwd_inventory(tmp_path) == str(tmp_path / "inventory")


def test_cwd_inventory_is_none_when_nothing_resolves(tmp_path: Path):
    assert cwd_inventory(tmp_path) is None


# -- the target it builds -------------------------------------------------------


def test_ansible_live_target_carries_the_inventory(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(disc, "cwd_inventory", lambda _cwd: "/etc/ansible/hosts")
    target = ansible_live_target(tmp_path)
    assert target is not None
    assert target.source == "ansible-live" and target.inventory == "/etc/ansible/hosts"
    assert target.probe == "auto" and target.path == ""


def test_ansible_live_target_is_none_without_an_inventory(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(disc, "cwd_inventory", lambda _cwd: None)
    assert ansible_live_target(tmp_path) is None


def test_inventory_survives_the_targets_file_round_trip(tmp_path: Path):
    target = Target(name="hosts", source="ansible-live", inventory="/etc/ansible/hosts")
    path = tmp_path / "targets.json"
    save_targets(path, {"hosts": target})
    assert load_targets(path)["hosts"].inventory == "/etc/ansible/hosts"


# -- threading: the inventory reaches the probe ---------------------------------


def test_the_probe_supports_inventory_and_passes_it_as_dash_i(monkeypatch):
    assert isinstance(ah.AnsibleHealthProbe(), SupportsInventory)
    monkeypatch.setattr(ah.shutil, "which", lambda _b: "/usr/bin/ansible")
    captured: dict[str, list[str]] = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        return mock.Mock(returncode=0, stdout="{}", stderr="")

    monkeypatch.setattr(ah.subprocess, "run", fake_run)
    probe = ah.AnsibleHealthProbe()
    probe.use_inventory("/x/hosts")
    probe._run_module("service_facts")
    assert "-i" in captured["argv"] and "/x/hosts" in captured["argv"]


def test_build_report_threads_inventory_to_the_ansible_probe(monkeypatch):
    seen: list[str] = []
    monkeypatch.setattr(ah.AnsibleHealthProbe, "use_inventory", lambda self, inv: seen.append(inv))
    monkeypatch.setattr(ah.AnsibleHealthProbe, "probe", lambda self, resources: [])  # no real I/O
    build_report("ansible-live", Path("."), probe="auto", inventory="/x/hosts")
    assert seen == ["/x/hosts"]
