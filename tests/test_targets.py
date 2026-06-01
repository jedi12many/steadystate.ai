"""The named-target registry: load + default + reject, and the env entry point."""

from __future__ import annotations

import json

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


def test_load_rejects_a_target_missing_required_fields(tmp_path):
    path = _write(tmp_path, {"bad": {"source": "k8s"}})  # no path
    with pytest.raises(ValueError, match="needs at least"):
        load_targets(path)


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


# -- CLI: `scan --target` and the `targets` command -------------------------------------------


def _targets_dir(tmp_path):
    """A cwd holding a k8s snapshot and a targets.json pointing 'demo' at it (a clean,
    tool-free scan: empty declared/observed -> no drift)."""
    snap = tmp_path / "snap.json"
    snap.write_text(json.dumps({"declared": [], "observed": []}))
    (tmp_path / "targets.json").write_text(
        json.dumps({"demo": {"source": "k8s", "path": str(snap)}})
    )
    return tmp_path


def _run(monkeypatch, tmp_path, args):
    from typer.testing import CliRunner

    from steadystate.cli import app

    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv(TARGETS_ENV, raising=False)
    return CliRunner().invoke(app, args)


def test_scan_target_resolves_and_runs(monkeypatch, tmp_path):
    result = _run(monkeypatch, _targets_dir(tmp_path), ["scan", "--target", "demo", "--stateless"])
    assert result.exit_code == 0


def test_scan_target_unknown_name(monkeypatch, tmp_path):
    result = _run(monkeypatch, _targets_dir(tmp_path), ["scan", "--target", "ghost", "--stateless"])
    assert result.exit_code != 0
    assert "unknown target 'ghost'" in result.output


def test_scan_target_and_path_are_mutually_exclusive(monkeypatch, tmp_path):
    result = _run(
        monkeypatch, _targets_dir(tmp_path), ["scan", "x.json", "--target", "demo", "--stateless"]
    )
    assert result.exit_code != 0
    assert "not both" in result.output


def test_scan_needs_a_path_or_target(monkeypatch, tmp_path):
    result = _run(monkeypatch, _targets_dir(tmp_path), ["scan", "--stateless"])
    assert result.exit_code != 0
    assert "give a path to scan, or --target" in result.output


def test_targets_command_lists(monkeypatch, tmp_path):
    result = _run(monkeypatch, _targets_dir(tmp_path), ["targets"])
    assert result.exit_code == 0
    assert "demo" in result.output and "k8s" in result.output


def test_targets_check_ok(monkeypatch, tmp_path):
    result = _run(monkeypatch, _targets_dir(tmp_path), ["targets", "--check"])
    assert result.exit_code == 0
    assert "[ok]" in result.output


def test_targets_check_flags_missing_path(monkeypatch, tmp_path):
    (tmp_path / "targets.json").write_text(
        json.dumps({"bad": {"source": "k8s", "path": str(tmp_path / "gone.json")}})
    )
    result = _run(monkeypatch, tmp_path, ["targets", "--check"])
    assert result.exit_code != 0
    assert "path not found" in result.output


def test_targets_no_file(monkeypatch, tmp_path):
    result = _run(monkeypatch, tmp_path, ["targets"])  # empty dir
    assert result.exit_code == 0
    assert "no targets file" in result.output
