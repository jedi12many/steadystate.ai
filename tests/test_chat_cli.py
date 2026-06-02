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


def test_probe_honors_mutes_and_unmute_flag(runner, tmp_path, monkeypatch):
    from datetime import UTC, datetime

    from steadystate.cli import app
    from steadystate.engine import build_report
    from steadystate.reconcile_state import _fingerprints
    from steadystate.state import StateStore

    plan = tmp_path / "plan.json"
    plan.write_text(
        json.dumps(
            {
                "resource_changes": [
                    {
                        "address": "aws_s3_bucket.logs",
                        "type": "aws_s3_bucket",
                        "name": "logs",
                        "change": {
                            "actions": ["update"],
                            "before": {"acl": "private"},
                            "after": {"acl": "public-read"},
                        },
                    }
                ]
            }
        )
    )
    _targets(
        tmp_path, monkeypatch, {"demo": {"source": "terraform", "path": str(plan), "label": "demo"}}
    )
    db = str(tmp_path / "s.db")
    with StateStore(db) as store:
        store.mute(
            _fingerprints(build_report("terraform", plan).alerts[0])[0],
            None,
            "me",
            datetime.now(UTC),
        )

    # default honors the mute
    hidden = runner.invoke(app, ["probe", "demo", "--state", db])
    assert "clean except 1 muted" in hidden.stdout
    # --unmute bypasses it
    shown = runner.invoke(app, ["probe", "demo", "--unmute", "--state", db])
    assert "1 alert" in shown.stdout


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


# -- command history (up-arrow recall) ------------------------------------------


def test_chat_history_helpers_never_raise(tmp_path):
    # The arrow-key history is best-effort: on Windows there's no stdlib readline (the console gives
    # its own recall), so the load/save helpers must be clean no-ops, never crashing the REPL.
    from steadystate.cli import _load_history, _save_history

    _load_history(tmp_path / "absent_history")  # no file yet, maybe no readline -> no-op
    _save_history(tmp_path / "absent_history")


def test_chat_history_roundtrips_when_readline_present(tmp_path):
    # Where readline exists (Linux/macOS, incl. the bastion/listener boxes), a command typed in one
    # session is recalled (up-arrow) in the next -- proven by save -> clear -> load -> read back.
    readline = pytest.importorskip("readline")
    from steadystate.cli import _load_history, _save_history

    history_path = tmp_path / "chat_history"
    readline.clear_history()
    readline.add_history("probe prod verbose")
    _save_history(history_path)
    assert history_path.exists()

    readline.clear_history()
    _load_history(history_path)
    assert readline.get_history_item(1) == "probe prod verbose"


def test_chat_writes_a_history_file_on_exit(runner, tmp_path):
    # The REPL persists history under .steadystate/ next to the state db (a `finally`, so Ctrl-D
    # still saves). On a readline-less platform this is a no-op -- so only assert when it's present.
    from steadystate.cli import app

    state = tmp_path / "state.db"
    result = runner.invoke(app, ["chat", "--state", str(state)], input="help\nexit\n")
    assert result.exit_code == 0
    pytest.importorskip("readline")
    assert (tmp_path / "chat_history").exists()
