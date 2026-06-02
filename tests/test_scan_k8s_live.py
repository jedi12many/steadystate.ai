"""The `scan --source k8s-live` CLI path: a pathless live cluster-health scan.

The engine-level context threading + fire detection is covered in test_engine.py; here we cover the
CLI seam -- that a live source needs no positional path (while every other source still does), and
that the fire surfaces end-to-end through `scan`.
"""

from __future__ import annotations

import json

from typer.testing import CliRunner

from steadystate.cli import app

_WORKLOADS = {
    "kind": "List",
    "items": [
        {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"namespace": "prod", "name": "web"},
            "spec": {"template": {"spec": {"containers": [{"image": "web:1"}]}}},
        }
    ],
}
_CRASHING_PODS = {
    "items": [
        {
            "metadata": {"name": "web-abc"},
            "status": {
                "phase": "Running",
                "containerStatuses": [
                    {"restartCount": 9, "state": {"waiting": {"reason": "CrashLoopBackOff"}}}
                ],
            },
        }
    ]
}


def _mock_kubectl(monkeypatch):
    """Stub the live source's `run_tool` (workload enum) and the probe's `subprocess.run` (pods)."""
    monkeypatch.setattr(
        "steadystate.sources.k8s.run_tool", lambda argv, **kw: json.dumps(_WORKLOADS)
    )

    class _Result:
        stdout = json.dumps(_CRASHING_PODS)

    monkeypatch.setattr("steadystate.probe.kubectl.subprocess.run", lambda argv, **kw: _Result())


def test_scan_k8s_live_needs_no_path_and_surfaces_fires(monkeypatch):
    _mock_kubectl(monkeypatch)
    result = CliRunner().invoke(
        app,
        ["scan", "--source", "k8s-live", "--context", "prod", "--probe", "auto", "--stateless"],
    )
    assert result.exit_code == 0, result.output
    assert "CrashLoopBackOff" in result.output  # the fire surfaced, with no path given


def test_scan_non_pathless_source_still_requires_a_path():
    result = CliRunner().invoke(app, ["scan", "--source", "terraform"])
    assert result.exit_code != 0
    assert "give a path" in result.output or "--target" in result.output
