"""Surface registry tests -- the wiring guard for notify, mirroring test_registry.

A surface registered without being reachable (or a renamed/broken constructor)
fails here, the same way the source registry fails on a built-but-unwired source.
"""

import json

import pytest

from steadystate.notify import SURFACES, build_surfaces
from steadystate.notify.base import Surface


def test_known_surfaces_registered():
    assert {"console", "slack", "teams", "prometheus", "grafana"} <= set(SURFACES)


def test_every_registered_surface_builds_and_conforms():
    # A broken/renamed zero-arg constructor fails here.
    for name in SURFACES:
        surface = SURFACES[name]()
        assert isinstance(surface, Surface)
        assert surface.name == name


def test_build_surfaces_maps_each_registered_name():
    names = sorted(SURFACES)
    built = build_surfaces(names)
    assert len(built) == len(names)
    for name, surface in zip(names, built, strict=True):
        assert isinstance(surface, Surface)
        assert callable(surface.emit)
        assert surface.name == name


def test_build_surfaces_preserves_order_and_duplicates():
    built = build_surfaces(["console", "console"])
    assert [s.name for s in built] == ["console", "console"]


def test_build_surfaces_unknown_raises_valueerror():
    with pytest.raises(ValueError):
        build_surfaces(["console", "nope"])


def test_cli_rejects_unknown_to_value(tmp_path):
    # Robust end-to-end check: an unknown --to is a clean non-zero CLI exit, not a
    # stack trace. Skipped only if the CLI test deps aren't importable.
    typer_testing = pytest.importorskip("typer.testing")
    from steadystate.cli import app

    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps({"resource_changes": []}))  # valid, empty source input

    runner = typer_testing.CliRunner()
    result = runner.invoke(app, ["scan", str(plan), "--to", "nope"])
    assert result.exit_code != 0
    assert "nope" in result.output.lower()
