"""The committed config (steadystate/config.toml): the loader, the precedence (config < env < flag),
and the two consumers wired here -- the BOUND (the autonomy envelope, reviewed in PRs) and the scan
[defaults] (source/path, so a configured repo runs bare). Read-only TOML; a bad file is empty."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from steadystate.act.bounds import Impact, Reversibility, bound_from_env
from steadystate.cli import app
from steadystate.config import config_table, load_config


def test_load_config_reads_tables_and_is_empty_on_a_bad_or_missing_file(tmp_path):
    cfg = tmp_path / "config.toml"
    cfg.write_text('[bound]\nrecoverable = "service"\n\n[defaults]\nsource = "argocd"\n')
    assert load_config(cfg)["bound"] == {"recoverable": "service"}
    assert config_table("defaults", cfg) == {"source": "argocd"}
    assert config_table("missing", cfg) == {}  # absent table -> {}
    assert load_config(tmp_path / "nope.toml") == {}  # no file
    bad = tmp_path / "bad.toml"
    bad.write_text("not = valid = toml ===")
    assert load_config(bad) == {}  # malformed -> {}, never a crash


# -- the bound: committed, with the env as the per-run override -------------------


def test_bound_reads_the_committed_config(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("STEADYSTATE_BOUND", raising=False)
    (tmp_path / "steadystate").mkdir()
    (tmp_path / "steadystate" / "config.toml").write_text('[bound]\nrecoverable = "tenant"\n')
    assert bound_from_env()[Reversibility.RECOVERABLE] == Impact.TENANT  # from the committed file


def test_env_bound_overrides_the_committed_config(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "steadystate").mkdir()
    (tmp_path / "steadystate" / "config.toml").write_text('[bound]\nrecoverable = "tenant"\n')
    monkeypatch.setenv("STEADYSTATE_BOUND", "recoverable=service")  # the per-run override wins
    assert bound_from_env()[Reversibility.RECOVERABLE] == Impact.SERVICE


def test_a_typo_in_the_config_bound_stays_conservative(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("STEADYSTATE_BOUND", raising=False)
    (tmp_path / "steadystate").mkdir()
    (tmp_path / "steadystate" / "config.toml").write_text('[bound]\nrecoverable = "galaxy"\n')
    # an unknown impact is skipped -> the default (None = never auto for recoverable) holds
    assert bound_from_env()[Reversibility.RECOVERABLE] is None


def test_passing_raw_bypasses_the_config(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "steadystate").mkdir()
    (tmp_path / "steadystate" / "config.toml").write_text('[bound]\nrecoverable = "fleet"\n')
    # explicit raw is pure -- it must NOT read the file or env (callers that pass a string mean it)
    assert bound_from_env("recoverable=service")[Reversibility.RECOVERABLE] == Impact.SERVICE


# -- scan [defaults]: a configured repo runs a bare `scan` ------------------------


def test_bare_scan_reads_source_and_path_from_defaults(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps({"resource_changes": []}))
    (tmp_path / "steadystate").mkdir()
    (tmp_path / "steadystate" / "config.toml").write_text(
        f'[defaults]\nsource = "terraform"\npath = "{Path(plan).as_posix()}"\n'
    )
    out = CliRunner().invoke(app, ["scan"])  # no path, no --target -- all from [defaults]
    assert out.exit_code == 0 and "give a path" not in out.stdout


def test_bare_scan_without_config_still_asks_for_a_path(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)  # no config -> a clean BadParameter (exit 2), never a crash (1)
    out = CliRunner().invoke(app, ["scan"])
    assert out.exit_code == 2  # typer usage error for the missing path, not a traceback


def test_ci_inherits_source_and_path_from_defaults(tmp_path, monkeypatch):
    # [ci] overrides [defaults] overrides the built-in -- so source/path need only be set once
    monkeypatch.chdir(tmp_path)
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps({"resource_changes": []}))
    (tmp_path / "steadystate").mkdir()
    (tmp_path / "steadystate" / "config.toml").write_text(
        f'[defaults]\nsource = "terraform"\npath = "{Path(plan).as_posix()}"\n\n'
        '[ci]\nfail_on = "any"\n'
    )
    out = CliRunner().invoke(app, ["ci"])  # source/path from [defaults], fail_on from [ci]
    assert out.exit_code == 0 and "PASS" in out.stdout  # ran the [defaults] scan, clean plan
