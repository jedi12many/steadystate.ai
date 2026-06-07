"""The named-target registry: load + default + reject, and the env entry point."""

from __future__ import annotations

import json
import re

import pytest

from steadystate.targets import TARGETS_ENV, Target, load_targets, load_targets_from_env


def _write(tmp_path, data: dict):
    path = tmp_path / "targets.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_load_parses_and_defaults_label_to_name_and_probe_to_auto(tmp_path):
    path = _write(tmp_path, {"prod-k8s": {"source": "k8s", "path": "/m"}})
    assert load_targets(path)["prod-k8s"] == Target(
        name="prod-k8s", source="k8s", path="/m", label="prod-k8s", probe="auto"
    )


def test_load_keeps_explicit_label_and_probe(tmp_path):
    path = _write(
        tmp_path, {"x": {"source": "argocd", "path": "/a", "label": "prod", "probe": "argocd"}}
    )
    target = load_targets(path)["x"]
    assert target.label == "prod" and target.probe == "argocd"


def test_load_rejects_a_target_missing_source(tmp_path):
    # source is the one required field; path is optional now (a live target reads live state).
    path = _write(tmp_path, {"bad": {"path": "/m"}})  # no source
    with pytest.raises(ValueError, match="needs at least"):
        load_targets(path)


def test_load_accepts_a_pathless_live_target_with_a_context(tmp_path):
    path = _write(tmp_path, {"prod": {"source": "k8s-live", "context": "prod-cluster"}})
    assert load_targets(path)["prod"] == Target(
        name="prod", source="k8s-live", path="", label="prod", probe="auto", context="prod-cluster"
    )


def test_load_rejects_a_non_object_document(tmp_path):
    path = tmp_path / "t.json"
    path.write_text('["nope"]', encoding="utf-8")
    with pytest.raises(ValueError, match="JSON object"):
        load_targets(path)


def test_from_env_is_empty_when_unset(monkeypatch):
    monkeypatch.delenv(TARGETS_ENV, raising=False)
    assert load_targets_from_env() == {}


def test_from_env_loads_the_file(monkeypatch, tmp_path):
    path = _write(tmp_path, {"a": {"source": "k8s", "path": "/m"}})
    monkeypatch.setenv(TARGETS_ENV, str(path))
    assert "a" in load_targets_from_env()


def test_from_env_falls_back_to_the_default_file(monkeypatch, tmp_path):
    # No env var, but a `discover --create` registry in the cwd -> the chat REPL picks it up.
    monkeypatch.delenv(TARGETS_ENV, raising=False)
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".steadystate").mkdir(exist_ok=True)
    (tmp_path / ".steadystate/targets.json").write_text(
        json.dumps({"prod": {"source": "k8s-live", "context": "prod"}})
    )
    assert "prod" in load_targets_from_env()


def test_from_env_ignores_an_unrelated_targets_json(monkeypatch, tmp_path):
    # A foreign `targets.json` in the cwd must NOT be read -- the default is steadystate-specific.
    monkeypatch.delenv(TARGETS_ENV, raising=False)
    monkeypatch.chdir(tmp_path)
    (tmp_path / "targets.json").write_text(json.dumps({"theirs": {"source": "x", "path": "/y"}}))
    assert load_targets_from_env() == {}


def test_env_var_wins_over_the_default_file(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".steadystate").mkdir(exist_ok=True)
    (tmp_path / ".steadystate/targets.json").write_text(
        json.dumps({"default": {"source": "k8s", "path": "/d"}})
    )
    explicit = tmp_path / "explicit.targets.json"
    explicit.write_text(json.dumps({"chosen": {"source": "k8s", "path": "/c"}}))
    monkeypatch.setenv(TARGETS_ENV, str(explicit))
    assert set(load_targets_from_env()) == {"chosen"}


# -- target_issues: the validator behind `targets --check` ------------------------------------


def test_target_issues_clean():
    from steadystate.targets import target_issues

    t = Target("x", "k8s", "/p", "x")
    assert target_issues(t, {"k8s"}, {"auto", "none"}, lambda _p: True) == []


def test_target_issues_flags_every_problem():
    from steadystate.targets import target_issues

    t = Target("x", "nope", "/missing", "x", probe="bogus")
    issues = target_issues(t, {"k8s"}, {"auto", "none"}, lambda _p: False)
    assert any("unknown source" in i for i in issues)
    assert any("unknown probe" in i for i in issues)
    assert any("path not found" in i for i in issues)


def test_target_issues_skips_path_check_for_a_pathless_live_target():
    from steadystate.targets import target_issues

    # A live target has no path; path_exists would say False, but a pathless source must not be
    # flagged "path not found" -- its reachability is the probe's job at run time.
    t = Target("prod", "k8s-live", context="prod-cluster")
    issues = target_issues(
        t, {"k8s-live"}, {"auto", "none"}, lambda _p: False, frozenset({"k8s-live"})
    )
    assert issues == []


# -- target_to_spec: the round-trip back to JSON ----------------------------------------------


def test_spec_round_trips_a_live_target_with_context_and_no_path():
    from steadystate.targets import target_to_spec

    t = Target("prod", "k8s-live", label="prod", context="prod-cluster")
    spec = target_to_spec(t)
    assert spec == {"source": "k8s-live", "context": "prod-cluster"}  # no path, label==name omitted
    assert "path" not in spec


def test_spec_omits_context_for_a_file_target():
    from steadystate.targets import target_to_spec

    spec = target_to_spec(Target("x", "k8s", "/m", "x"))
    assert spec == {"source": "k8s", "path": "/m"} and "context" not in spec


# -- CLI: `scan --target` and the `targets` command -------------------------------------------


def _targets_dir(tmp_path):
    """A cwd holding a k8s snapshot and a targets.json pointing 'demo' at it (a clean,
    tool-free scan: empty declared/observed -> no drift)."""
    snap = tmp_path / "snap.json"
    snap.write_text(json.dumps({"declared": [], "observed": []}))
    (tmp_path / ".steadystate").mkdir(exist_ok=True)
    (tmp_path / ".steadystate/targets.json").write_text(
        json.dumps({"demo": {"source": "k8s", "path": str(snap)}})
    )
    return tmp_path


_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _clean(output: str) -> str:
    """Strip ANSI styling so message assertions don't depend on whether rich colorized the output
    (it does on a color terminal / CI, not on a plain one) -- a BadParameter panel highlights
    `--target`, which otherwise breaks the substring match."""
    return _ANSI.sub("", output)


def _run(monkeypatch, tmp_path, args):
    from typer.testing import CliRunner

    from steadystate.cli import app

    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv(TARGETS_ENV, raising=False)
    # Wide + no-color so rich neither wraps the error message across the panel nor styles it.
    return CliRunner().invoke(app, args, env={"COLUMNS": "200", "NO_COLOR": "1"})


def test_scan_target_resolves_and_runs(monkeypatch, tmp_path):
    result = _run(monkeypatch, _targets_dir(tmp_path), ["scan", "--target", "demo", "--stateless"])
    assert result.exit_code == 0


def test_scan_target_unknown_name(monkeypatch, tmp_path):
    result = _run(monkeypatch, _targets_dir(tmp_path), ["scan", "--target", "ghost", "--stateless"])
    assert result.exit_code != 0
    assert "unknown target 'ghost'" in _clean(result.output)


def test_scan_target_and_path_are_mutually_exclusive(monkeypatch, tmp_path):
    result = _run(
        monkeypatch, _targets_dir(tmp_path), ["scan", "x.json", "--target", "demo", "--stateless"]
    )
    assert result.exit_code != 0
    assert "not both" in _clean(result.output)


def test_scan_needs_a_path_or_target(monkeypatch, tmp_path):
    result = _run(monkeypatch, _targets_dir(tmp_path), ["scan", "--stateless"])
    assert result.exit_code != 0
    assert "give a path, --target" in _clean(result.output)


def test_targets_command_lists(monkeypatch, tmp_path):
    result = _run(monkeypatch, _targets_dir(tmp_path), ["targets"])
    assert result.exit_code == 0
    assert "demo" in result.output and "k8s" in result.output


def test_targets_check_ok(monkeypatch, tmp_path):
    result = _run(monkeypatch, _targets_dir(tmp_path), ["targets", "--check"])
    assert result.exit_code == 0
    assert "[ok]" in result.output


def test_targets_check_flags_missing_path(monkeypatch, tmp_path):
    (tmp_path / ".steadystate").mkdir(exist_ok=True)
    (tmp_path / ".steadystate/targets.json").write_text(
        json.dumps({"bad": {"source": "k8s", "path": str(tmp_path / "gone.json")}})
    )
    result = _run(monkeypatch, tmp_path, ["targets", "--check"])
    assert result.exit_code != 0
    assert "path not found" in result.output


def test_targets_no_file(monkeypatch, tmp_path):
    result = _run(monkeypatch, tmp_path, ["targets"])  # empty dir
    assert result.exit_code == 0
    assert "no targets file" in result.output


# -- live (k8s-live) targets: a target = a cluster --------------------------------------------


def _live_targets_dir(tmp_path):
    (tmp_path / ".steadystate").mkdir(exist_ok=True)
    (tmp_path / ".steadystate/targets.json").write_text(
        json.dumps({"prod": {"source": "k8s-live", "context": "prod-cluster"}})
    )
    return tmp_path


def test_scan_live_target_threads_its_context_to_kubectl(monkeypatch, tmp_path):
    # `scan --target prod` resolves the live target and aims kubectl at its context -- no path.
    seen: list[list[str]] = []
    monkeypatch.setattr(
        "steadystate.sources.k8s.run_tool",
        lambda argv, **kw: seen.append(argv) or '{"kind": "List", "items": []}',
    )
    result = _run(
        monkeypatch, _live_targets_dir(tmp_path), ["scan", "--target", "prod", "--stateless"]
    )
    assert result.exit_code == 0, result.output
    assert seen and all(a[-2:] == ["--context", "prod-cluster"] for a in seen)


def test_scan_live_target_explicit_context_wins(monkeypatch, tmp_path):
    seen: list[list[str]] = []
    monkeypatch.setattr(
        "steadystate.sources.k8s.run_tool",
        lambda argv, **kw: seen.append(argv) or '{"kind": "List", "items": []}',
    )
    result = _run(
        monkeypatch,
        _live_targets_dir(tmp_path),
        ["scan", "--target", "prod", "--context", "staging", "--stateless"],
    )
    assert result.exit_code == 0, result.output
    assert seen and all(a[-1] == "staging" for a in seen)  # --context overrides the target's


def test_targets_check_ok_for_a_pathless_live_target(monkeypatch, tmp_path):
    result = _run(monkeypatch, _live_targets_dir(tmp_path), ["targets", "--check"])
    assert result.exit_code == 0  # no path, but a live target isn't flagged
    assert "[ok]" in result.output
    assert "context=prod-cluster" in result.output  # the cluster it reaches is shown
