"""Out-of-tree plugin discovery -- the importlib.metadata entry-point seam.

These exercise the discovery engine (`plugins.discover` / `plugins.merged`) directly with a
patched `entry_points`, plus one end-to-end wiring test through the real source registry, so we
prove the contract without installing a second distribution:

- a plugin is loaded by name,
- a broken plugin is isolated (logged + skipped, never raised),
- built-ins win every name clash (discovery extends a seam, never hijacks a shipped name).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from steadystate import plugins


class _FakeEntryPoint:
    """Stands in for an importlib.metadata.EntryPoint: a name + a load() that returns the loaded
    object, or raises if it was given an exception (to model an import that blows up)."""

    def __init__(self, name: str, value: object) -> None:
        self.name = name
        self._value = value

    def load(self) -> object:
        if isinstance(self._value, Exception):
            raise self._value
        return self._value


def _patch_entry_points(monkeypatch, mapping: dict[str, list[_FakeEntryPoint]]) -> None:
    """Make plugins.entry_points(group=...) return the fakes registered for that group."""

    def fake_entry_points(*, group: str):
        return mapping.get(group, [])

    monkeypatch.setattr(plugins, "entry_points", fake_entry_points)


# -- discover ------------------------------------------------------------------


def test_discover_loads_entry_points_by_name(monkeypatch):
    sentinel = object()
    _patch_entry_points(monkeypatch, {"steadystate.sources": [_FakeEntryPoint("pulumi", sentinel)]})
    assert plugins.discover("sources") == {"pulumi": sentinel}


def test_discover_empty_when_group_has_no_plugins(monkeypatch):
    _patch_entry_points(monkeypatch, {})
    assert plugins.discover("sources") == {}


def test_discover_isolates_a_failing_plugin(monkeypatch, caplog):
    good = object()
    _patch_entry_points(
        monkeypatch,
        {
            "steadystate.domains": [
                _FakeEntryPoint("boom", ImportError("no module named acme")),
                _FakeEntryPoint("good", good),
            ]
        },
    )
    with caplog.at_level("WARNING"):
        loaded = plugins.discover("domains")
    assert loaded == {"good": good}  # the good one still loads
    assert "boom" in caplog.text  # and the failure is surfaced, not swallowed


def test_discover_survives_entry_points_itself_raising(monkeypatch, caplog):
    def explode(*, group: str):
        raise RuntimeError("malformed dist metadata")

    monkeypatch.setattr(plugins, "entry_points", explode)
    with caplog.at_level("WARNING"):
        assert plugins.discover("surfaces") == {}
    assert "discovery failed" in caplog.text


# -- merged --------------------------------------------------------------------


def test_merged_adds_a_discovered_name(monkeypatch):
    plugin = object()
    _patch_entry_points(monkeypatch, {"steadystate.sources": [_FakeEntryPoint("pulumi", plugin)]})
    out = plugins.merged("sources", {"terraform": "builtin-tf"})
    assert out == {"terraform": "builtin-tf", "pulumi": plugin}


def test_merged_builtin_wins_a_name_clash(monkeypatch, caplog):
    _patch_entry_points(
        monkeypatch, {"steadystate.sources": [_FakeEntryPoint("terraform", "evil-tf")]}
    )
    with caplog.at_level("WARNING"):
        out = plugins.merged("sources", {"terraform": "builtin-tf"})
    assert out == {"terraform": "builtin-tf"}  # the shipped one is kept, the plugin dropped
    assert "built-in already owns" in caplog.text


def test_merged_returns_a_fresh_dict(monkeypatch):
    _patch_entry_points(monkeypatch, {})
    builtins = {"terraform": "builtin-tf"}
    out = plugins.merged("sources", builtins)
    out["x"] = "y"
    assert "x" not in builtins  # caller can mutate the result without touching the built-ins


# -- end-to-end through a real registry ----------------------------------------


class _DummySource:
    name = "pulumi"

    def collect_drift(self):
        return []


def test_source_registry_wiring_discovers_a_plugin(monkeypatch):
    # Prove the sources package actually queries the `steadystate.sources` group and that a
    # discovered factory lands in a usable registry alongside the built-ins.
    from steadystate import sources

    def make_source(_path: Path) -> _DummySource:
        return _DummySource()

    _patch_entry_points(
        monkeypatch, {"steadystate.sources": [_FakeEntryPoint("pulumi", make_source)]}
    )
    registry = sources._build_sources()
    assert "pulumi" in registry  # discovered
    assert "terraform" in registry and "helm" in registry  # built-ins survive
    assert isinstance(registry["pulumi"](Path("ignored")), _DummySource)


def test_capabilities_pick_up_a_discovered_factorys_commands(monkeypatch):
    from steadystate.sources import Capabilities, _build_capabilities

    def make_source(_path: Path) -> _DummySource:
        return _DummySource()

    make_source.commands = Capabilities(observe=("pulumi preview",), destructive=("pulumi up",))  # type: ignore[attr-defined]
    caps = _build_capabilities({"pulumi": make_source})
    assert caps["pulumi"].destructive == ("pulumi up",)


def test_capabilities_skip_a_factory_with_no_commands():
    from steadystate.sources import _build_capabilities

    def make_source(_path: Path) -> _DummySource:
        return _DummySource()

    caps = _build_capabilities({"pulumi": make_source})
    assert "pulumi" not in caps  # no manifest advertised -> simply not listed, no crash


@pytest.mark.parametrize("seam", ["sources", "domains", "surfaces", "inbound", "executors"])
def test_every_seam_is_discoverable(seam, monkeypatch):
    # A light guard that each seam name resolves through discover without error (the group string
    # is wired). No plugins installed -> empty, which is the correct, quiet default.
    _patch_entry_points(monkeypatch, {})
    assert plugins.discover(seam) == {}


# -- domains: list-of-instances seam (built-ins win by `name`) ------------------


class _FakeDomain:
    def __init__(self, name: str) -> None:
        self.name = name

    def score(self, drift):
        return None


def test_domains_registry_appends_a_discovered_pack(monkeypatch):
    from steadystate import domains

    # A class entry point (callable) is instantiated; a ready instance is taken as-is.
    _patch_entry_points(
        monkeypatch,
        {
            "steadystate.domains": [
                _FakeEntryPoint("pci", lambda: _FakeDomain("pci")),
                _FakeEntryPoint("hipaa", _FakeDomain("hipaa")),
            ]
        },
    )
    names = [d.name for d in domains._discover_domains()]
    assert "pci" in names and "hipaa" in names
    assert "security" in names  # a built-in pack still present


def test_domains_registry_rejects_a_name_clash_with_a_builtin(monkeypatch, caplog):
    from steadystate import domains

    _patch_entry_points(
        monkeypatch,
        {"steadystate.domains": [_FakeEntryPoint("evil", lambda: _FakeDomain("security"))]},
    )
    with caplog.at_level("WARNING"):
        built = domains._discover_domains()
    # exactly one pack named "security" -- the built-in, not the impostor
    assert [d.name for d in built].count("security") == 1
    assert "clashes with a built-in" in caplog.text


def test_domains_registry_isolates_a_pack_that_fails_to_construct(monkeypatch, caplog):
    from steadystate import domains

    def boom():
        raise RuntimeError("bad config")

    _patch_entry_points(monkeypatch, {"steadystate.domains": [_FakeEntryPoint("broken", boom)]})
    with caplog.at_level("WARNING"):
        built = domains._discover_domains()
    assert all(getattr(d, "name", None) != "broken" for d in built)
    assert "construction failed" in caplog.text
