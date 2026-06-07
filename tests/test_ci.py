"""`steadystate ci` -- the stateless GitOps gate. Pins the config loading, the fail-on threshold
(what trips the gate vs what's below it), and the exit code -- the contract a CI pipeline relies on.
Runs against the committed sample terraform plan (no terraform binary, no db, no LLM)."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from steadystate.cli import _load_ci_config, app

_PLAN = "examples/sample-plan.json"  # the sample plan -- a critical S3 public-access drift
_ABS_PLAN = Path(_PLAN).resolve()  # absolute, captured before any test chdir


def test_load_ci_config_reads_the_ci_table(tmp_path):
    cfg = tmp_path / "config.toml"
    cfg.write_text('[ci]\nsource = "terraform"\npath = "infra"\nfail_on = "high"\n')
    loaded = _load_ci_config(cfg)
    assert loaded == {"source": "terraform", "path": "infra", "fail_on": "high"}


def test_load_ci_config_is_empty_when_missing_or_malformed(tmp_path):
    assert _load_ci_config(tmp_path / "nope.toml") == {}  # no file
    bad = tmp_path / "bad.toml"
    bad.write_text("this is not = valid = toml ===")
    assert _load_ci_config(bad) == {}  # malformed -> {}, never a crash
    notable = tmp_path / "notable.toml"
    notable.write_text("[other]\nx = 1\n")  # no [ci] table
    assert _load_ci_config(notable) == {}


def test_gate_fails_on_a_finding_at_or_above_the_threshold():
    out = CliRunner().invoke(app, ["ci", _PLAN, "--source", "terraform", "--fail-on", "any"])
    assert out.exit_code == 1 and "FAIL" in out.stdout  # a critical drift trips `any`


def test_gate_passes_when_findings_are_below_the_threshold():
    # the sample's finding is critical; nothing is *above* critical, so a `none` gate never trips
    out = CliRunner().invoke(app, ["ci", _PLAN, "--source", "terraform", "--fail-on", "none"])
    assert out.exit_code == 0 and "PASS" in out.stdout


def test_an_unknown_fail_on_is_a_clean_error():
    out = CliRunner().invoke(app, ["ci", _PLAN, "--source", "terraform", "--fail-on", "huge"])
    assert out.exit_code != 0  # BadParameter, not a traceback


def test_config_supplies_source_and_path_so_ci_can_run_argless(tmp_path, monkeypatch):
    # a repo with steadystate/config.toml pointing at its plan -> bare `ci` (no args) works
    monkeypatch.chdir(tmp_path)
    (tmp_path / "steadystate").mkdir()
    (tmp_path / "steadystate" / "config.toml").write_text(
        f'[ci]\nsource = "terraform"\npath = "{_ABS_PLAN.as_posix()}"\n'
    )
    out = CliRunner().invoke(app, ["ci"])  # no path arg, no --source -- all from config
    assert out.exit_code == 1 and "steadystate ci:" in out.stdout  # ran the configured scan + gated
