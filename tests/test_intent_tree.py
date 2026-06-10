"""The in-tree intent rule -- inside a ``steadystate/`` tree (a silo at
``steadystate/silos/<name>/``), intent files resolve BARE, so a silo holds ``config.toml`` /
``targets.json`` / ``kb/`` directly with no inner ``steadystate/`` stutter. These pin the rule
itself, every resolver honoring it (config, targets, checks, solutions, mutes, kb), the
committed-prefix-still-wins ordering, fresh writes landing bare in-tree, the off-switch outside a
tree (an unrelated bare config.toml is never misread), and the broadened silo-discover marker."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from steadystate.config import config_path, in_steadystate_tree
from steadystate.mutes import resolve_mutes_path
from steadystate.probe.custom import resolve_checks_path
from steadystate.probe.solutions import resolve_solutions_path
from steadystate.reason.knowledge import kb_dir
from steadystate.silos import discover_silos
from steadystate.targets import load_targets_from_env, resolve_targets_path


@pytest.fixture
def _silo(tmp_path, monkeypatch):
    """A flat silo at <tmp>/steadystate/silos/my_cluster -- the new layout -- as the CWD."""
    silo = tmp_path / "steadystate" / "silos" / "my_cluster"
    silo.mkdir(parents=True)
    monkeypatch.chdir(silo)
    for var in (
        "STEADYSTATE_TARGETS",
        "STEADYSTATE_CHECKS",
        "STEADYSTATE_SOLUTIONS",
        "STEADYSTATE_MUTES",
        "STEADYSTATE_KB",
        "STEADYSTATE_CONFIG",
    ):
        monkeypatch.delenv(var, raising=False)
    return silo


def test_the_rule_is_path_based(tmp_path, monkeypatch, _silo):
    assert in_steadystate_tree()  # cwd = .../steadystate/silos/my_cluster
    monkeypatch.chdir(tmp_path)  # a normal repo root
    assert not in_steadystate_tree()


def test_every_intent_file_resolves_bare_inside_a_silo(_silo):
    (_silo / "config.toml").write_text('[knowledge]\ndir = "kb"\n')
    (_silo / "targets.json").write_text(json.dumps({"gw": {"source": "k8s-live"}}))
    (_silo / "checks.json").write_text("[]")
    (_silo / "solutions.json").write_text("[]")
    (_silo / "kb").mkdir()
    assert config_path() == Path("config.toml")
    assert resolve_targets_path() == "targets.json"
    assert list(load_targets_from_env()) == ["gw"]  # ... and it actually loads
    assert resolve_checks_path() == "checks.json"
    assert resolve_solutions_path() == "solutions.json"
    assert resolve_mutes_path() == "mutes.json"
    assert kb_dir() == Path("kb")  # via the config pointer; bare default holds without it too


def test_the_committed_prefix_still_wins_when_present(_silo):
    # A silo that kept the nested layout keeps working -- committed beats bare.
    (_silo / "steadystate").mkdir()
    (_silo / "steadystate" / "targets.json").write_text(json.dumps({"nested": {"source": "k8s"}}))
    (_silo / "targets.json").write_text(json.dumps({"bare": {"source": "k8s"}}))
    assert resolve_targets_path() == "steadystate/targets.json"


def test_fresh_writes_land_bare_inside_a_silo(_silo):
    # Nothing exists yet: discover --create / add-check / commit-mutes must not re-create the
    # steadystate/ stutter inside steadystate/silos/<name>/.
    assert resolve_targets_path() == "targets.json"
    assert resolve_checks_path() == "checks.json"
    assert resolve_solutions_path() == "solutions.json"
    assert resolve_mutes_path() == "mutes.json"


def test_outside_a_tree_a_bare_file_is_never_misread(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("STEADYSTATE_TARGETS", raising=False)
    (tmp_path / "targets.json").write_text(json.dumps({"other": {"source": "k8s"}}))
    (tmp_path / "config.toml").write_text("[tool]\n")  # some other tool's config
    assert resolve_targets_path() == "steadystate/targets.json"  # the bare file is NOT picked up
    assert config_path() == Path("steadystate/config.toml")
    assert load_targets_from_env() == {}


def test_silo_discover_finds_flat_and_fresh_silos(tmp_path):
    silos = tmp_path / "steadystate" / "silos"
    (silos / "flat-intent").mkdir(parents=True)
    (silos / "flat-intent" / "targets.json").write_text("{}")
    (silos / "ran-before").mkdir()
    (silos / "ran-before" / ".steadystate").mkdir()
    (silos / "nested-style").mkdir()
    (silos / "nested-style" / "steadystate").mkdir()
    (silos / "not-a-silo").mkdir()  # empty -- no intent, no memory
    found = discover_silos(str(silos))
    assert set(found) == {"flat-intent", "ran-before", "nested-style"}
