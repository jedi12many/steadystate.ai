"""`up` -- the one-process 'turn it on and the channel is live' verb: the chat listener plus the
background fleet sweep that keeps its answers fresh. These pin the startup validation (provider,
interval grammar, sweep-needs-targets -- each fails loudly at start, not silently at the first
question), the listener-only mode (`--sweep 0`), and the warm-keeper loop (sweeps immediately,
keeps ticking, and survives a failing sweep)."""

from __future__ import annotations

import threading

import pytest
from typer.testing import CliRunner

import steadystate.cli as cli
from steadystate.cli import _sweep_forever, app

runner = CliRunner()


@pytest.fixture
def _teams_ready(monkeypatch):
    """A configured Teams adapter (the HMAC token present) -- `ready()` passes."""
    monkeypatch.setenv("STEADYSTATE_TEAMS_SECURITY_TOKEN", "c2VjcmV0")


# -- startup validation: fail loudly at `up`, not silently at the first question --------------


def test_up_rejects_an_unknown_provider():
    result = runner.invoke(app, ["up", "--from", "carrier-pigeon"])
    assert result.exit_code != 0


def test_up_rejects_a_bad_sweep_interval(_teams_ready):
    result = runner.invoke(app, ["up", "--sweep", "soonish"])
    assert result.exit_code != 0
    assert "20s, 10m, 1h" in result.output


def test_up_with_a_sweep_needs_targets(_teams_ready, monkeypatch, tmp_path):
    monkeypatch.delenv("STEADYSTATE_TARGETS", raising=False)
    monkeypatch.chdir(tmp_path)  # no default .steadystate/targets.json here either
    result = runner.invoke(app, ["up", "--sweep", "10m"])
    assert result.exit_code != 0
    assert "needs targets" in result.output and "--sweep 0" in result.output


def test_up_reports_a_broken_targets_registry_cleanly(_teams_ready, monkeypatch, tmp_path):
    # A SET-but-missing registry fails loudly by design (a typo'd path must not read as "no
    # targets") -- `up` turns it into a clean startup error naming the reason, not a traceback.
    monkeypatch.setenv("STEADYSTATE_TARGETS", str(tmp_path / "nowhere.json"))
    result = runner.invoke(app, ["up", "--sweep", "10m"])
    assert result.exit_code != 0
    assert "can't read the targets registry" in result.output


def test_up_rejects_an_unconfigured_adapter(monkeypatch):
    monkeypatch.delenv("STEADYSTATE_TEAMS_SECURITY_TOKEN", raising=False)
    result = runner.invoke(app, ["up", "--from", "teams", "--sweep", "0"])
    assert result.exit_code != 0  # ready() failed -> a clean error at startup


# -- the two modes ----------------------------------------------------------------------------


def test_up_sweep_0_runs_the_listener_alone(_teams_ready, monkeypatch, tmp_path):
    served: dict = {}
    monkeypatch.setattr(cli, "serve", lambda a, p, s: served.update(name=a.name, port=p, state=s))
    result = runner.invoke(app, ["up", "--sweep", "0", "--state", str(tmp_path / "state.db")])
    assert result.exit_code == 0
    assert served["name"] == "teams" and served["port"] == 8723  # teams is up's default provider
    assert "sweep off" in result.output  # the banner says the answers won't self-refresh


def test_up_starts_the_sweep_then_serves(_teams_ready, monkeypatch, tmp_path):
    targets = tmp_path / "targets.json"
    targets.write_text('{"demo": {"source": "kubernetes", "path": "."}}')
    monkeypatch.setenv("STEADYSTATE_TARGETS", str(targets))
    monkeypatch.setattr(cli, "serve", lambda a, p, s: None)
    started: dict = {}

    def fake_sweeper(state_path, every_seconds, deep, stop=None):
        started.update(state=state_path, every=every_seconds, deep=deep)

    monkeypatch.setattr(cli, "_sweep_forever", fake_sweeper)
    result = runner.invoke(app, ["up", "--sweep", "20s", "--state", str(tmp_path / "state.db")])
    assert result.exit_code == 0
    assert "fleet sweep every 20s" in result.output
    for _ in range(100):  # the sweeper runs on a daemon thread -- give it a beat
        if started:
            break
        threading.Event().wait(0.01)
    assert started["every"] == 20.0 and started["deep"] is False


# -- the warm-keeper loop ---------------------------------------------------------------------


def test_sweep_forever_sweeps_immediately_and_keeps_ticking(monkeypatch, capsys):
    ticks: list[str] = []
    stop = threading.Event()

    def fake_run_sweep(state_path, flags):
        ticks.append(state_path)
        if len(ticks) >= 3:
            stop.set()
        return "Fleet sweep: 2 cluster(s) -- 0 on fire, 2 clear, 0 unreachable.\n  detail line"

    monkeypatch.setattr("steadystate.verbs._run_sweep", fake_run_sweep)
    _sweep_forever("state.db", 0.001, False, stop=stop)
    assert len(ticks) >= 3  # the first sweep ran immediately, then the loop kept ticking
    out = capsys.readouterr().out
    assert "Fleet sweep: 2 cluster(s)" in out  # the one-line tally, not the full digest
    assert "detail line" not in out


def test_sweep_forever_survives_a_failing_sweep(monkeypatch, capsys):
    stop = threading.Event()
    calls = {"n": 0}

    def exploding(state_path, flags):
        calls["n"] += 1
        if calls["n"] >= 2:
            stop.set()  # it got called AGAIN after the failure -- the loop lived on
        raise RuntimeError("cluster unreachable")

    monkeypatch.setattr("steadystate.verbs._run_sweep", exploding)
    _sweep_forever("state.db", 0.001, False, stop=stop)
    assert calls["n"] >= 2
    assert "sweep failed: cluster unreachable" in capsys.readouterr().out


def test_sweep_forever_passes_the_deep_flag(monkeypatch):
    seen: dict = {}
    stop = threading.Event()

    def fake_run_sweep(state_path, flags):
        seen["flags"] = flags
        stop.set()
        return "Fleet sweep: 1 cluster(s) -- 0 on fire, 1 clear, 0 unreachable."

    monkeypatch.setattr("steadystate.verbs._run_sweep", fake_run_sweep)
    _sweep_forever("state.db", 0.001, True, stop=stop)
    assert seen["flags"] == frozenset({"deep"})
