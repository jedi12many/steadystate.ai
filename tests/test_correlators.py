"""Correlator registry tests -- the wiring guard for the correlate seam, mirroring
test_surfaces / test_registry.

A correlator registered without being reachable (or a renamed/broken factory) fails
here, the same way the source and surface registries fail on a built-but-unwired plugin.
"""

import json

import pytest

from steadystate.reason.correlate import (
    Correlator,
    DeterministicCorrelator,
    LLMCorrelator,
)
from steadystate.reason.llm import LLMAnalyst
from steadystate.reason.pipeline import CORRELATORS, build_correlator


@pytest.fixture(autouse=True)
def _no_provider(monkeypatch):
    # The built-in correlators must build with no provider configured; clear the env so
    # a developer's real keys never leak into the wiring assertions.
    for var in (
        "ANTHROPIC_API_KEY",
        "STEADYSTATE_LLM_BASE_URL",
        "STEADYSTATE_LLM_API_KEY",
        "STEADYSTATE_LLM_MODEL",
        "OPENAI_BASE_URL",
        "OPENAI_API_KEY",
        "STEADYSTATE_LLM_PROVIDER",
    ):
        monkeypatch.delenv(var, raising=False)


def test_known_correlators_registered():
    assert {"deterministic", "llm"} <= set(CORRELATORS)


def test_every_registered_correlator_builds_and_conforms():
    # A broken/renamed factory fails here; every entry must build via build_correlator,
    # be a Correlator, and report the name it registered under.
    analyst = LLMAnalyst()
    for name in CORRELATORS:
        correlator = build_correlator(name, analyst)
        assert isinstance(correlator, Correlator)
        assert callable(correlator.correlate)
        assert correlator.name == name


def test_build_correlator_auto_is_deterministic_without_provider():
    analyst = LLMAnalyst()
    assert analyst._provider() == "none"
    correlator = build_correlator("auto", analyst)
    assert isinstance(correlator, DeterministicCorrelator)
    assert correlator.name == "deterministic"


def test_build_correlator_auto_is_llm_with_provider():
    # A configured provider flips auto to the LLM correlator (force via api_key).
    analyst = LLMAnalyst(api_key="x")
    assert analyst._provider() == "anthropic"
    correlator = build_correlator("auto", analyst)
    assert isinstance(correlator, LLMCorrelator)
    assert correlator.name == "llm"


def test_build_correlator_auto_is_llm_with_provider_via_monkeypatch(monkeypatch):
    # Same flip, but forcing _provider directly -- independent of how the key is supplied.
    analyst = LLMAnalyst()
    monkeypatch.setattr(analyst, "_provider", lambda: "openai")
    correlator = build_correlator("auto", analyst)
    assert isinstance(correlator, LLMCorrelator)


def test_build_correlator_unknown_raises_valueerror():
    with pytest.raises(ValueError, match="unknown correlator"):
        build_correlator("magic", LLMAnalyst())


def test_cli_rejects_unknown_correlator_value(tmp_path):
    # End-to-end: an unknown --correlator is a clean non-zero CLI exit, not a stack trace.
    typer_testing = pytest.importorskip("typer.testing")
    from steadystate.cli import app

    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps({"resource_changes": []}))  # valid, empty source input

    runner = typer_testing.CliRunner()
    result = runner.invoke(app, ["scan", str(plan), "--correlator", "magic"])
    assert result.exit_code != 0
    assert "magic" in result.output.lower()


def test_cli_accepts_each_registered_correlator(tmp_path):
    # The wiring guard end-to-end: every registered name (and auto) round-trips through
    # the CLI cleanly, so a built-but-unregistered correlator can't ship unreachable.
    typer_testing = pytest.importorskip("typer.testing")
    from steadystate.cli import app

    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps({"resource_changes": []}))
    runner = typer_testing.CliRunner()
    for name in [*sorted(CORRELATORS), "auto"]:
        # --stateless: this guard is about correlator wiring, not the state store, so
        # keep it from touching the filesystem (state has its own tests).
        result = runner.invoke(app, ["scan", str(plan), "--correlator", name, "--stateless"])
        assert result.exit_code == 0, f"--correlator {name} failed: {result.output}"
