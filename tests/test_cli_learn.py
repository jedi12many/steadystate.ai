"""CLI `learn` shares the one renderer with chat/MCP -- so it surfaces the runbook DRAFTS (a fix you
keep applying by hand), not just the lessons. Pins the June 2026 audit's CLI/chat `learn` drift:
before, the chat view offered the promotable `add-solution` and the CLI silently did not."""

from __future__ import annotations

from datetime import UTC, datetime

from typer.testing import CliRunner

from steadystate.cli import app
from steadystate.state import StateStore

runner = CliRunner()
_T0 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC)
_T1 = datetime(2026, 6, 2, 12, 0, 0, tzinfo=UTC)
_FIX = "kubectl delete pods --field-selector=status.phase=Failed -n prod"


def test_cli_learn_surfaces_a_promotable_runbook_draft(tmp_path):
    db = str(tmp_path / "s.db")
    with StateStore(db) as store:
        # the same category fixed by hand twice with ONE consistent command, resolved out-of-band
        # (no audit entry) -> a promotable runbook draft.
        for fp in ("a" * 64, "b" * 64):
            store.record({fp: ("high", "pods evicted")}, _T0, {fp: {"category": "Evicted"}})
            store.resolve(fp, _FIX, "amy", _T1)
    result = runner.invoke(app, ["learn", "--state", db])
    assert result.exit_code == 0
    # the drift fix: the CLI now shows the runbook-capture block the chat view always did
    assert "ready to capture as runbook solutions" in result.stdout
    assert "add-solution" in result.stdout and _FIX in result.stdout


def test_cli_learn_is_empty_on_a_fresh_store(tmp_path):
    result = runner.invoke(app, ["learn", "--state", str(tmp_path / "s.db")])
    assert result.exit_code == 0
    assert "Nothing learned yet" in result.stdout
