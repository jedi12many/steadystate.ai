"""Verify the left: render a Kustomize overlay and reconcile it against the live cluster."""

from __future__ import annotations

import json

from typer.testing import CliRunner

from steadystate.cli import app
from steadystate.model import ChangeType
from steadystate.sources.k8s import (
    KustomizeLiveSource,
    _objects_from_kubectl_json,
    render_kustomize,
)


def _dep(ns: str, name: str, image: str) -> dict:
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"namespace": ns, "name": name},
        "spec": {"template": {"spec": {"containers": [{"image": image}]}}},
    }


# -- the tolerant kubectl-JSON parser ---------------------------------------------------------


def test_objects_from_kubectl_json_handles_list_array_single_and_concatenated():
    a, b = _dep("p", "a", "a:1"), _dep("p", "b", "b:1")
    assert _objects_from_kubectl_json(json.dumps({"kind": "List", "items": [a, b]}), tool="t") == [
        a,
        b,
    ]
    assert _objects_from_kubectl_json(json.dumps([a, b]), tool="t") == [a, b]  # bare array
    assert _objects_from_kubectl_json(json.dumps(a), tool="t") == [a]  # single object
    # a stream of concatenated objects (some kubectl versions) -> decoded in sequence
    assert _objects_from_kubectl_json(json.dumps(a) + "\n" + json.dumps(b), tool="t") == [a, b]
    assert _objects_from_kubectl_json("   ", tool="t") == []


def test_render_kustomize_builds_then_converts_to_json(monkeypatch):
    seen: list[list[str]] = []

    def fake_run(argv, **kw):
        seen.append(argv)
        if "kustomize" in argv:
            return "apiVersion: apps/v1\nkind: Deployment\n..."  # the rendered YAML (non-empty)
        return json.dumps({"kind": "List", "items": [_dep("prod", "web", "web:2")]})  # the convert

    monkeypatch.setattr("steadystate.sources.k8s.run_tool", fake_run)
    objs = render_kustomize("overlay", context="prod")
    assert [o["metadata"]["name"] for o in objs] == ["web"]
    assert seen[0][:2] == ["kubectl", "kustomize"]  # build the overlay first
    assert "create" in seen[1] and "--dry-run=client" in seen[1]  # then convert offline


# -- the source: declared (Git) vs live, scoped to the overlay's namespaces -------------------


def test_kustomize_live_reconciles_git_against_live_scoped_to_namespaces():
    declared = [_dep("prod", "web", "web:2"), _dep("prod", "api", "api:1")]  # Git
    observed = {
        "kind": "List",
        "items": [
            _dep("prod", "web", "web:1"),  # running, but drifted from Git -> MODIFIED
            _dep(
                "prod", "extra", "x:1"
            ),  # running in the overlay's namespace, not in Git -> REMOVED
            _dep(
                "other", "z", "z:1"
            ),  # a namespace the overlay doesn't touch -> ignored (no noise)
        ],
    }
    src = KustomizeLiveSource("overlay", declared=declared, observed=observed)
    drifts = {d.identity: d.change_type for d in src.collect_drift()}
    assert drifts == {
        "apps/Deployment/prod/web": ChangeType.MODIFIED,
        "apps/Deployment/prod/api": ChangeType.ADDED,  # in Git, not running
        "apps/Deployment/prod/extra": ChangeType.REMOVED,  # running, not in Git
    }


def test_kustomize_live_clean_when_cluster_matches_git():
    declared = [_dep("prod", "web", "web:2")]
    observed = {"kind": "List", "items": [_dep("prod", "web", "web:2")]}
    assert (
        KustomizeLiveSource("overlay", declared=declared, observed=observed).collect_drift() == []
    )


# -- the CLI `verify` command, end to end -----------------------------------------------------


def test_verify_cli_surfaces_drift_from_git(monkeypatch):
    def fake_run(argv, **kw):
        if "kustomize" in argv:
            return "apiVersion: apps/v1\nkind: Deployment"  # rendered YAML (non-empty)
        if "create" in argv:  # render -> the declared 'left'
            return json.dumps({"kind": "List", "items": [_dep("prod", "web", "web:2")]})
        return json.dumps(
            {"kind": "List", "items": [_dep("prod", "web", "web:1")]}
        )  # live (drifted)

    monkeypatch.setattr("steadystate.sources.k8s.run_tool", fake_run)
    result = CliRunner().invoke(app, ["verify", "overlay", "--context", "prod", "--stateless"])
    assert result.exit_code == 0, result.output
    assert "web" in result.output  # the drifted workload surfaces
