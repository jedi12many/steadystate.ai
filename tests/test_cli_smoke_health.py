"""CLI `smoke` and `health` gate from data, not a re-run / a string match (June 2026 audit defects):
`smoke` was executing every http endpoint TWICE (once to render, once for the exit code), and
`health` parsed its exit code from the rendered text via `startswith(WORKING)`. These pin: smoke
runs each check once, and both exit non-zero on failure."""

from __future__ import annotations

from types import SimpleNamespace

from typer.testing import CliRunner

from steadystate.cli import app

runner = CliRunner()


def _smoke(passed: bool = True):
    return SimpleNamespace(
        passed=passed, name="web", target="http://web/healthz", detail="" if passed else "503"
    )


def test_cli_smoke_runs_each_check_once(monkeypatch):
    # the fix: render AND gate from ONE run. Before, the CLI called the renderer (which runs the
    # checks) and then ran them again for the exit code -- doubled load, and a flaky endpoint could
    # make the printed result disagree with the exit code.
    calls: list[int] = []
    monkeypatch.setattr(
        "steadystate.probe.custom.run_smoke_checks",
        lambda checks_path="", match="": (calls.append(1), [_smoke()])[1],
    )
    result = runner.invoke(app, ["smoke"])
    assert result.exit_code == 0
    assert len(calls) == 1  # exactly one run, not two
    assert "PASS" in result.stdout


def test_cli_smoke_exits_nonzero_when_a_check_fails(monkeypatch):
    monkeypatch.setattr(
        "steadystate.probe.custom.run_smoke_checks",
        lambda checks_path="", match="": [_smoke(passed=False)],
    )
    result = runner.invoke(app, ["smoke"])
    assert result.exit_code == 1
    assert "FAIL" in result.stdout


def test_cli_health_gates_on_the_verdict(monkeypatch, tmp_path):
    # a failing smoke test -> the service isn't serving -> DOWN -> non-zero (the CI gate), decided
    # from the verdict value, not by string-matching the rendered head.
    monkeypatch.setattr(
        "steadystate.verbs.run_smoke_checks",
        lambda checks_path="", match="": [_smoke(passed=False)],
    )
    result = runner.invoke(app, ["health", "--state", str(tmp_path / "s.db")])
    assert result.exit_code == 1
    assert "DOWN" in result.stdout
