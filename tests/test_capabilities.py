"""Per-plugin command manifests: observe (pre-approved) vs destructive (needs approval)."""

from __future__ import annotations

import dataclasses

import pytest

from steadystate.cli import app
from steadystate.sources import CAPABILITIES, DRIFT_SOURCES, Capabilities


def _runner():
    typer_testing = pytest.importorskip("typer.testing")
    return typer_testing.CliRunner()


def test_every_registered_source_declares_commands():
    # The manifest stays in lockstep with the source registry: add a source, declare its
    # commands too (same guard idea as test_registry's representative inputs).
    assert set(CAPABILITIES) == set(DRIFT_SOURCES)


def test_every_plugin_can_observe():
    for name, caps in CAPABILITIES.items():
        assert caps.observe, f"{name} declares no observe commands"


def test_acting_plugins_declare_destructive_commands():
    for name in ("terraform", "docker-compose", "k8s"):
        assert CAPABILITIES[name].destructive  # these remediate -> need-approval commands


def test_gitops_plugins_are_observe_only():
    # ArgoCD / Rancher ride their own engine's syncing -- steadystate only reads them.
    assert CAPABILITIES["argocd"].destructive == ()
    assert CAPABILITIES["rancher"].destructive == ()


def test_capabilities_is_immutable():
    caps = Capabilities(observe=("a",))
    with pytest.raises(dataclasses.FrozenInstanceError):
        caps.observe = ("b",)  # type: ignore[misc]


def test_commands_cli_documents_both_categories():
    result = _runner().invoke(app, ["commands", "--source", "terraform"])
    assert result.exit_code == 0
    assert "observe (pre-approved):" in result.stdout
    assert "terraform plan" in result.stdout
    assert "potentially destructive (needs approval):" in result.stdout
    assert "terraform apply" in result.stdout


def test_commands_cli_marks_observe_only_plugins():
    result = _runner().invoke(app, ["commands", "--source", "rancher"])
    assert result.exit_code == 0
    assert "observe-only plugin" in result.stdout


def test_commands_cli_rejects_unknown_source():
    result = _runner().invoke(app, ["commands", "--source", "nope"])
    assert result.exit_code != 0
