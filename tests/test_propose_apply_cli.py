"""The autonomy ARMING path -- the one CLI seam that turns the decider from 'proposes' to 'acts'.

``act_on_proposals`` (the actual within-bound execution) and ``decider_auto_enabled`` (the grant
helper) are unit-pinned in test_decider_auto.py. What was untested is the wiring in between: that
``propose --apply`` actually CONSULTS the grant before arming -- refusing (and never reaching
``act_on_proposals``) when STEADYSTATE_DECIDER_AUTO is unset, and arming only when it is set. The
gate is only as safe as the call site that checks it; this pins that call site (cli.py ~1566).

The scan seams (targets file, sweep, propose_for) are stubbed so the test exercises the grant
branch, not real infra; ``act_on_proposals`` is a spy so we can prove it is / isn't reached."""

from __future__ import annotations

from unittest import mock

from typer.testing import CliRunner

from steadystate import cli

runner = CliRunner()


def _stub_scan(monkeypatch, tmp_path, *, gated):
    """Make ``propose`` reach the --apply branch without touching infra: an existing targets file, a
    truthy registry, a stubbed sweep, and a stubbed gating that yields ``gated``."""
    targets = tmp_path / "targets.json"
    targets.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(cli, "_targets_file", lambda: targets)
    monkeypatch.setattr(cli, "load_targets", lambda _f: {"t": object()})
    monkeypatch.setattr(cli, "sweep_targets", lambda *a, **k: mock.Mock(report=mock.Mock()))
    monkeypatch.setattr(cli, "propose_for", lambda *a, **k: gated)


def test_apply_without_the_grant_refuses_and_never_arms(monkeypatch, tmp_path):
    monkeypatch.delenv("STEADYSTATE_DECIDER_AUTO", raising=False)  # grant OFF (default)
    _stub_scan(monkeypatch, tmp_path, gated=["a within-bound proposal would be here"])
    spy = mock.Mock(return_value=([], [], []))
    monkeypatch.setattr(cli, "act_on_proposals", spy)

    result = runner.invoke(cli.app, ["propose", "--apply", "--state", str(tmp_path / "s.db")])

    assert result.exit_code == 0
    assert "STEADYSTATE_DECIDER_AUTO" in result.stdout  # told how to grant
    spy.assert_not_called()  # THE point: no grant -> the executor is never reached


def test_apply_with_the_grant_arms_the_executor(monkeypatch, tmp_path):
    monkeypatch.setenv("STEADYSTATE_DECIDER_AUTO", "1")  # operator granted access
    _stub_scan(monkeypatch, tmp_path, gated=["a within-bound proposal would be here"])
    spy = mock.Mock(return_value=([], [], []))
    monkeypatch.setattr(cli, "act_on_proposals", spy)

    result = runner.invoke(cli.app, ["propose", "--apply", "--state", str(tmp_path / "s.db")])

    assert result.exit_code == 0
    spy.assert_called_once()  # the grant is the only difference -> now it arms
