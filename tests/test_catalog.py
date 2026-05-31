"""The self-describing catalog: registry + CLI introspection, console + HTML renderers."""

from __future__ import annotations

import typer.main

from steadystate.catalog import (
    Catalog,
    CommandInfo,
    PluginItem,
    Seam,
    gather_catalog,
    render_html,
)
from steadystate.cli import app


def _catalog() -> Catalog:
    return gather_catalog(typer.main.get_command(app))


def _runner():
    import pytest

    return pytest.importorskip("typer.testing").CliRunner()


# -- gathering ------------------------------------------------------------------


def test_seams_cover_the_live_registries():
    seams = {s.title: [i.name for i in s.items] for s in _catalog().seams}
    assert "terraform" in seams["Sources"]
    assert "discord" in seams["Surfaces (out)"]
    assert "teams" in seams["Inbound (approvals)"]
    assert "terraform" in seams["Executors"]
    assert "auto" in seams["Correlators"]  # the non-registered default mode is listed too
    assert "kubectl" in seams["Probes"]


def test_source_items_carry_observe_act_counts():
    sources = next(s for s in _catalog().seams if s.title == "Sources")
    terraform = next(i for i in sources.items if i.name == "terraform")
    assert "observe" in terraform.detail and "act" in terraform.detail


def test_probe_items_carry_observe_counts():
    probes = next(s for s in _catalog().seams if s.title == "Probes")
    kubectl = next(i for i in probes.items if i.name == "kubectl")
    assert "observe" in kubectl.detail  # the probe's read-only command count is surfaced


def test_commands_include_scan_options_and_filter_the_help_flag():
    scan = next(c for c in _catalog().commands if c.name == "scan")
    flags = [o.flags for o in scan.options]
    assert "--source" in flags and "--to" in flags and "--autonomy" in flags
    assert "--help" not in flags  # the auto-added help flag is not listed
    assert all(o.help for o in scan.options)  # every listed option carries its help text


def test_catalog_lists_its_own_command():
    assert any(c.name == "catalog" for c in _catalog().commands)


# -- HTML rendering -------------------------------------------------------------


def test_html_is_a_self_contained_page_with_the_content():
    page = render_html(_catalog())
    assert page.startswith("<!doctype html>") and page.rstrip().endswith("</html>")
    assert "<style>" in page  # styles are inlined -- no external asset
    assert "terraform" in page and "scan" in page and "--source" in page


def test_html_escapes_dynamic_text():
    cat = Catalog(
        seams=[Seam("S", "--x", [PluginItem("a<b>")])],
        commands=[CommandInfo("c", "d & e", [])],
    )
    page = render_html(cat)
    assert "a&lt;b&gt;" in page and "a<b>" not in page
    assert "d &amp; e" in page


# -- the CLI command ------------------------------------------------------------


def test_catalog_command_renders_console():
    result = _runner().invoke(app, ["catalog"])
    assert result.exit_code == 0
    assert "Plugins" in result.stdout and "terraform" in result.stdout and "scan" in result.stdout


def test_catalog_command_emits_html():
    result = _runner().invoke(app, ["catalog", "--html"])
    assert result.exit_code == 0
    assert result.stdout.lstrip().startswith("<!doctype html>")
    assert "</html>" in result.stdout and "terraform" in result.stdout
