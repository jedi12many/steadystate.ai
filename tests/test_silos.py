"""Named silos: the registry (name -> deployment folder) and the `--silo` selector that operates in
one. The point is keeping deployments separate -- each silo is its own folder/state -- with a clean
name instead of a long `--dir`. The registry is a tmp JSON file (STEADYSTATE_SILOS), never the real
one."""

from __future__ import annotations

import json

from typer.testing import CliRunner

from steadystate.cli import app
from steadystate.silos import add_silo, discover_silos, load_silos, remove_silo, resolve_silo


def _registry(monkeypatch, tmp_path):
    monkeypatch.setenv("STEADYSTATE_SILOS", str(tmp_path / "silos.json"))


# -- the registry --------------------------------------------------------------


def test_add_resolve_remove_round_trip(monkeypatch, tmp_path):
    _registry(monkeypatch, tmp_path)
    d1 = tmp_path / "akeyless-use1"
    d1.mkdir()
    stored = add_silo("akeyless-use1", str(d1))
    assert stored == str(d1.resolve())  # stored absolute, so it resolves from anywhere
    assert resolve_silo("akeyless-use1") == str(d1.resolve())
    assert resolve_silo("nope") is None
    assert remove_silo("akeyless-use1") is True and resolve_silo("akeyless-use1") is None
    assert remove_silo("akeyless-use1") is False  # already gone


def test_load_tolerates_a_missing_or_malformed_registry(monkeypatch, tmp_path):
    _registry(monkeypatch, tmp_path)
    assert load_silos() == {}  # missing file -> {}
    (tmp_path / "silos.json").write_text("{ not json")
    assert load_silos() == {}  # malformed -> {}, no crash


# -- the CLI: silo add / list / rm ---------------------------------------------


def test_silo_subcommands_register_and_list(monkeypatch, tmp_path):
    _registry(monkeypatch, tmp_path)
    d1, d2 = tmp_path / "dep1", tmp_path / "dep2"
    d1.mkdir()
    d2.mkdir()
    run = CliRunner()
    assert run.invoke(app, ["silo", "add", "dep1", str(d1)]).exit_code == 0
    assert run.invoke(app, ["silo", "add", "dep2", str(d2)]).exit_code == 0
    listed = run.invoke(app, ["silo", "list"]).output
    assert "dep1" in listed and "dep2" in listed and "2 silo(s)" in listed
    # a missing folder is flagged, not hidden
    saved = json.loads((tmp_path / "silos.json").read_text())
    saved["ghost"] = str(tmp_path / "gone")
    (tmp_path / "silos.json").write_text(json.dumps(saved))
    assert "MISSING" in run.invoke(app, ["silo", "list"]).output


def test_silo_add_rejects_a_missing_directory(monkeypatch, tmp_path):
    _registry(monkeypatch, tmp_path)
    out = CliRunner().invoke(app, ["silo", "add", "x", str(tmp_path / "nope")])
    assert out.exit_code == 1 and "not a directory" in out.output


# -- discovery: every subfolder with a .steadystate/ is a silo, named by the folder --------------


def test_discover_finds_subfolders_with_a_steadystate_dir(tmp_path):
    # a prod/ holding web1/ web2/ runners1/ (each with .steadystate/), and a non-silo subfolder
    for name in ("web1", "web2", "runners1"):
        (tmp_path / name / ".steadystate").mkdir(parents=True)
    (tmp_path / "notes").mkdir()  # no .steadystate/ -> not a silo
    found = discover_silos(str(tmp_path))
    assert sorted(found) == ["runners1", "web1", "web2"]  # the three silos, by folder name
    assert found["web1"] == str((tmp_path / "web1").resolve())
    assert discover_silos(str(tmp_path / "nope")) == {}  # not a dir -> {}


def test_silo_discover_registers_them_all(monkeypatch, tmp_path):
    _registry(monkeypatch, tmp_path)
    parent = tmp_path / "prod"
    for name in ("web1", "web2"):
        (parent / name / ".steadystate").mkdir(parents=True)
    out = CliRunner().invoke(app, ["silo", "discover", str(parent)])
    assert out.exit_code == 0 and "registered 2 silo(s)" in out.output
    assert sorted(load_silos()) == ["web1", "web2"]  # both now referenceable by name
    # nothing to discover -> a clean non-zero, no registry change
    assert CliRunner().invoke(app, ["silo", "discover", str(tmp_path / "empty")]).exit_code == 1


# -- the --silo selector: operate inside a named silo --------------------------


def test_silo_option_chdirs_into_the_named_silo(monkeypatch, tmp_path):
    _registry(monkeypatch, tmp_path)
    silo_dir = tmp_path / "akeyless-use1"
    silo_dir.mkdir()
    add_silo("akeyless-use1", str(silo_dir))
    seen: dict = {}
    monkeypatch.setattr("os.chdir", lambda p: seen.__setitem__("chdir", str(p)))
    # `summary` runs read-only; we only care that the callback chdir'd into the silo first
    CliRunner().invoke(app, ["--silo", "akeyless-use1", "summary"])
    assert seen["chdir"] == str(silo_dir.resolve())


def test_unknown_silo_is_a_clean_error(monkeypatch, tmp_path):
    _registry(monkeypatch, tmp_path)
    out = CliRunner().invoke(app, ["--silo", "ghost", "summary"])
    assert out.exit_code == 2 and "unknown silo" in out.output


def test_mcp_label_defaults_to_the_silo_name(monkeypatch, tmp_path):
    _registry(monkeypatch, tmp_path)
    silo_dir = tmp_path / "squid-euw1"
    silo_dir.mkdir()
    add_silo("squid-euw1", str(silo_dir))
    monkeypatch.setattr("os.chdir", lambda p: None)
    captured: dict = {}
    monkeypatch.setattr("steadystate.inbound.mcp.serve_stdio", lambda *a, **k: captured.update(k))
    CliRunner().invoke(app, ["--silo", "squid-euw1", "mcp"])
    assert captured["label"] == "squid-euw1"  # the silo self-identifies, no --label needed
