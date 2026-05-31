"""The local chat CLI: `steadystate chat` (REPL) and `steadystate probe <target>` (one-shot) --
the same command grammar + dispatch the chat adapters use, driven from a terminal, no provider."""

from __future__ import annotations

import json

import pytest


@pytest.fixture
def runner():
    return pytest.importorskip("typer.testing").CliRunner()


def _targets(tmp_path, monkeypatch, spec: dict) -> None:
    path = tmp_path / "targets.json"
    path.write_text(json.dumps(spec), encoding="utf-8")
    monkeypatch.setenv("STEADYSTATE_TARGETS", str(path))


def _empty_plan(tmp_path):
    path = tmp_path / "plan.json"
    path.write_text(json.dumps({"resource_changes": []}), encoding="utf-8")
    return path


# -- probe (one-shot, scriptable) -----------------------------------------------


def test_probe_resolves_a_target_and_reports_clean(runner, tmp_path, monkeypatch):
    from steadystate.cli import app

    _targets(
        tmp_path,
        monkeypatch,
        {"prod": {"source": "terraform", "path": str(_empty_plan(tmp_path)), "label": "prod"}},
    )
    result = runner.invoke(app, ["probe", "prod", "--state", str(tmp_path / "s.db")])
    assert result.exit_code == 0
    assert "prod: clean" in result.stdout


def test_probe_unknown_target_lists_the_known_ones(runner, tmp_path, monkeypatch):
    from steadystate.cli import app

    _targets(tmp_path, monkeypatch, {"prod": {"source": "terraform", "path": "/x"}})
    result = runner.invoke(app, ["probe", "nope", "--state", str(tmp_path / "s.db")])
    assert "Unknown target 'nope'" in result.stdout and "prod" in result.stdout


def test_probe_with_no_targets_configured(runner, tmp_path, monkeypatch):
    from steadystate.cli import app

    monkeypatch.delenv("STEADYSTATE_TARGETS", raising=False)
    result = runner.invoke(app, ["probe", "prod", "--state", str(tmp_path / "s.db")])
    assert "No targets configured" in result.stdout


# -- chat (interactive REPL) ----------------------------------------------------


def test_chat_runs_help_then_exits(runner, tmp_path):
    from steadystate.cli import app

    result = runner.invoke(app, ["chat", "--state", str(tmp_path / "s.db")], input="help\nexit\n")
    assert result.exit_code == 0
    assert "commands this listener accepts" in result.stdout
    assert "probe <target>" in result.stdout  # the Summon verb is discoverable from the terminal


def test_chat_reports_unrecognized_then_runs_pending(runner, tmp_path):
    from steadystate.cli import app

    result = runner.invoke(
        app, ["chat", "--state", str(tmp_path / "s.db")], input="frobnicate\npending\n"
    )
    assert "unrecognized" in result.stdout and "No remediations" in result.stdout


def test_chat_probe_runs_through_the_same_path(runner, tmp_path, monkeypatch):
    from steadystate.cli import app

    _targets(
        tmp_path,
        monkeypatch,
        {"prod": {"source": "terraform", "path": str(_empty_plan(tmp_path)), "label": "prod"}},
    )
    result = runner.invoke(app, ["chat", "--state", str(tmp_path / "s.db")], input="probe prod\n")
    assert "prod: clean" in result.stdout


def test_chat_exits_cleanly_on_eof(runner, tmp_path):
    from steadystate.cli import app

    result = runner.invoke(app, ["chat", "--state", str(tmp_path / "s.db")], input="")
    assert result.exit_code == 0
