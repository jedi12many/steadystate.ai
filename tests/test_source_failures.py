"""Drift sources must not crash the scan on infra-tooling hiccups (M1).

A live `_run_*` shells out; a missing binary, a non-zero exit, a hang, or garbage output must
surface as a clean `SourceError` (which the CLI reports and exits non-zero on, and the listener
already catches) -- never a raw traceback, never an infinite block, and never a false "no drift"
(the source raises rather than returning empty).
"""

from __future__ import annotations

import subprocess

import pytest

from steadystate.sources.base import SourceError, loads_json, run_tool

# -- run_tool: every failure mode becomes a SourceError -----------------------


def _patch_run(monkeypatch, exc):
    def boom(*args, **kwargs):
        raise exc

    monkeypatch.setattr(subprocess, "run", boom)


def test_run_tool_missing_binary(monkeypatch):
    _patch_run(monkeypatch, FileNotFoundError())
    with pytest.raises(SourceError, match="not found on PATH"):
        run_tool(["terraform", "plan"], timeout=5, tool="terraform")


def test_run_tool_timeout(monkeypatch):
    _patch_run(monkeypatch, subprocess.TimeoutExpired(cmd="kubectl", timeout=5))
    with pytest.raises(SourceError, match="timed out after 5s"):
        run_tool(["kubectl", "get", "pods"], timeout=5, tool="kubectl")


def test_run_tool_nonzero_exit_surfaces_stderr_tail(monkeypatch):
    _patch_run(
        monkeypatch,
        subprocess.CalledProcessError(
            returncode=1, cmd="terraform", stderr="boom\nError: no creds"
        ),
    )
    with pytest.raises(SourceError, match="Error: no creds"):
        run_tool(["terraform", "plan"], timeout=5, tool="terraform")


def test_run_tool_passes_timeout_through(monkeypatch):
    seen = {}

    def fake_run(argv, **kwargs):
        seen.update(kwargs)
        return subprocess.CompletedProcess(argv, 0, stdout="{}", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    run_tool(["kubectl", "get"], timeout=12.5, tool="kubectl")
    assert seen["timeout"] == 12.5  # the hang guard is actually wired to subprocess


def test_loads_json_rejects_garbage():
    assert loads_json("[]", tool="helm") == []
    with pytest.raises(SourceError, match="no parseable JSON"):
        loads_json("not json at all", tool="helm")
    with pytest.raises(SourceError, match="no parseable JSON"):
        loads_json("", tool="helm")


# -- each live source raises SourceError, not a raw traceback ------------------


def test_terraform_source_raises_sourceerror_on_missing_binary(monkeypatch, tmp_path):
    from steadystate.sources.terraform import TerraformSource

    _patch_run(monkeypatch, FileNotFoundError())
    with pytest.raises(SourceError):
        TerraformSource(working_dir=tmp_path).collect_drift()


def test_k8s_source_raises_sourceerror_on_timeout(monkeypatch):
    from steadystate.sources.k8s import KubernetesSource

    _patch_run(monkeypatch, subprocess.TimeoutExpired(cmd="kubectl", timeout=30))
    src = KubernetesSource(declared=[], get_args=["pods"])
    with pytest.raises(SourceError):
        src.collect_observed()


def test_helm_source_raises_sourceerror_on_bad_json(monkeypatch):
    from steadystate.sources.helm import HelmSource

    def garbage(argv, **kwargs):
        return subprocess.CompletedProcess(argv, 0, stdout="<html>503</html>", stderr="")

    monkeypatch.setattr(subprocess, "run", garbage)
    with pytest.raises(SourceError):
        HelmSource().collect_drift()


def test_ansible_source_raises_sourceerror_on_missing_binary(monkeypatch):
    from steadystate.sources.ansible import AnsibleSource

    _patch_run(monkeypatch, FileNotFoundError())
    with pytest.raises(SourceError):
        AnsibleSource(playbook="site.yml").collect_drift()


# -- the CLI reports it cleanly (no traceback, non-zero exit) ------------------


def test_scan_reports_a_tool_failure_cleanly(monkeypatch, tmp_path):
    typer_testing = pytest.importorskip("typer.testing")
    from steadystate.cli import app

    # A terraform working dir (so it goes live), with terraform missing.
    _patch_run(monkeypatch, FileNotFoundError())
    result = typer_testing.CliRunner().invoke(
        app, ["scan", str(tmp_path), "--source", "terraform", "--no-llm"]
    )
    assert result.exit_code == 1  # a real failure, not a crash and not a false success
    assert "scan failed" in result.output and "not found on PATH" in result.output
    assert "Traceback" not in result.output  # never a raw traceback


def test_fix_reports_a_tool_failure_cleanly(monkeypatch, tmp_path):
    # `fix` collects drift the same way `scan` does, so the same live-tool failure must surface
    # cleanly (not a raw traceback) -- the residual of M1/M2 on the sibling command.
    typer_testing = pytest.importorskip("typer.testing")
    from steadystate.cli import app

    _patch_run(monkeypatch, FileNotFoundError())
    result = typer_testing.CliRunner().invoke(app, ["fix", str(tmp_path), "--source", "terraform"])
    assert result.exit_code == 1
    assert "fix failed" in result.output and "not found on PATH" in result.output
    assert "Traceback" not in result.output
