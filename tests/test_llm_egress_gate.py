"""The opt-in LLM egress gate (`--confirm-llm`): nothing reaches the model without a yes.

The gate is consulted right before any send, sees exactly what would go out (provider, model, and
the full prompt), and a decline degrades to deterministic -- the same honest path as no provider.
Default (no gate) is unchanged: send freely. These pin the contract without a real API call.
"""

from __future__ import annotations

import json

import pytest

from steadystate import engine
from steadystate.model import ChangeType, Drift, Provenance
from steadystate.reason.llm import LLMAnalyst


def _drift() -> Drift:
    return Drift(
        identity="aws_s3_bucket.logs",
        kind="aws_s3_bucket",
        change_type=ChangeType.MODIFIED,
        provenance=Provenance(source="terraform", address="aws_s3_bucket.logs"),
    )


def _forced(provider: str, **kw) -> LLMAnalyst:
    """An analyst with the provider forced, so the gate is reached without real credentials."""
    analyst = LLMAnalyst(enabled=True, **kw)
    analyst._provider = lambda: provider  # type: ignore[method-assign]
    return analyst


# -- the gate is consulted before a send, and a decline sends nothing ----------


def test_decline_skips_the_send_and_records_no_call():
    analyst = _forced("anthropic", gate=lambda *a: False)
    assert analyst._complete("sys", "user", caller="correlate") is None
    assert analyst.calls == []  # nothing was sent -> no spend recorded


def test_gate_sees_provider_model_and_the_full_prompt():
    seen: dict[str, str] = {}

    def gate(provider: str, model: str, system: str, user: str) -> bool:
        seen.update(provider=provider, model=model, system=system, user=user)
        return False  # decline so no real send is attempted

    analyst = _forced("anthropic", gate=gate)
    analyst._complete("THE-INSTRUCTION", "THE-DRIFT-JSON", caller="correlate")
    assert seen["provider"] == "anthropic" and seen["model"]  # destination shown
    assert seen["system"] == "THE-INSTRUCTION" and seen["user"] == "THE-DRIFT-JSON"  # exact bytes


def test_no_gate_allows_the_send_by_default():
    analyst = _forced("anthropic")  # no gate
    assert analyst._allowed("anthropic", "s", "u") is True


def test_gate_is_not_consulted_when_no_provider():
    # No provider -> nothing would be sent anyway, so the gate is moot (and never fired).
    fired = []
    analyst = _forced("none", gate=lambda *a: fired.append(True) or True)
    assert analyst._complete("s", "u", caller="correlate") is None
    assert fired == []


def test_analyze_declined_degrades_honestly():
    analyst = _forced("anthropic", gate=lambda *a: False)
    result = analyst.analyze(_drift())
    assert result.llm_backed is False
    assert "egress gate" in result.why_it_matters


# -- the gate threads through the engine ---------------------------------------


def _plan(tmp_path):
    path = tmp_path / "plan.json"
    path.write_text(json.dumps({"resource_changes": []}), encoding="utf-8")
    return path


def test_build_report_passes_the_gate_to_the_analyst(tmp_path, monkeypatch):
    captured: dict[str, object] = {}
    real = engine.LLMAnalyst

    def spy(**kwargs):
        captured.update(kwargs)
        return real(**kwargs)

    monkeypatch.setattr(engine, "LLMAnalyst", spy)
    sentinel = lambda *a: True  # noqa: E731
    engine.build_report("terraform", _plan(tmp_path), llm_gate=sentinel)
    assert captured.get("gate") is sentinel


# -- the CLI wiring: fail-closed without a terminal ----------------------------


def test_cli_confirm_llm_without_a_tty_runs_without_the_llm(tmp_path):
    typer_testing = pytest.importorskip("typer.testing")
    from steadystate.cli import app

    plan = _plan(tmp_path)
    result = typer_testing.CliRunner().invoke(
        app, ["scan", str(plan), "--source", "terraform", "--confirm-llm"]
    )
    assert result.exit_code == 0
    assert "no terminal to confirm on" in result.stdout  # fail-closed, nothing sent
