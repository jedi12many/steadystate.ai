"""Verify the left: render a Kustomize overlay and reconcile it against the live cluster."""

from __future__ import annotations

import json

from typer.testing import CliRunner

from steadystate.cli import app
from steadystate.model import ChangeType
from steadystate.sources.k8s import (
    HelmLiveSource,
    KustomizeLiveSource,
    _objects_from_kubectl_json,
    render_helm,
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


# -- Helm: render a chart, reconcile vs live (same machinery as Kustomize) ---------------------


def test_render_helm_templates_then_converts_with_release_and_values(monkeypatch):
    seen: list[list[str]] = []

    def fake_run(argv, **kw):
        seen.append(argv)
        if argv[0] == "helm":
            return "apiVersion: apps/v1\nkind: Deployment"  # the rendered YAML
        return json.dumps(_dep("prod", "web", "web:2"))  # the convert

    monkeypatch.setattr("steadystate.sources.k8s.run_tool", fake_run)
    objs = render_helm("chart", release="myapp", values=["values.yaml"], namespace="prod")
    assert [o["metadata"]["name"] for o in objs] == ["web"]
    assert seen[0][:3] == ["helm", "template", "myapp"]  # release name passed
    assert "--namespace" in seen[0] and "-f" in seen[0]  # namespace + values threaded
    assert "create" in seen[1]  # then the offline kubectl convert


def test_helm_live_reconciles_chart_against_live():
    declared = [_dep("prod", "web", "web:2")]  # what the chart renders
    observed = {"kind": "List", "items": [_dep("prod", "web", "web:1")]}  # live (drifted)
    src = HelmLiveSource("chart", declared=declared, observed=observed)
    drifts = {d.identity: d.change_type for d in src.collect_drift()}
    assert drifts == {"apps/Deployment/prod/web": ChangeType.MODIFIED}


def test_helm_live_release_name_defaults_to_chart_dir():
    assert HelmLiveSource("charts/myapp")._release == "myapp"
    assert HelmLiveSource("charts/myapp", release="prod-myapp")._release == "prod-myapp"


# -- the CLI `verify` command, end to end (auto-detects Kustomize vs Helm) ---------------------


def test_verify_cli_surfaces_drift_from_a_kustomize_overlay(monkeypatch, tmp_path):
    (tmp_path / "kustomization.yaml").write_text("resources: []\n")  # auto-detected as Kustomize

    def fake_run(argv, **kw):
        if "kustomize" in argv:
            return "apiVersion: apps/v1\nkind: Deployment"  # rendered YAML (non-empty)
        if "create" in argv:  # render -> the declared 'left'
            return json.dumps({"kind": "List", "items": [_dep("prod", "web", "web:2")]})
        return json.dumps({"kind": "List", "items": [_dep("prod", "web", "web:1")]})  # live

    monkeypatch.setattr("steadystate.sources.k8s.run_tool", fake_run)
    result = CliRunner().invoke(app, ["verify", str(tmp_path), "--context", "prod", "--stateless"])
    assert result.exit_code == 0, result.output
    assert "web" in result.output  # the drifted workload surfaces


def test_verify_cli_detects_and_renders_a_helm_chart(monkeypatch, tmp_path):
    chart = tmp_path / "web"  # the dir name becomes the default release name
    chart.mkdir()
    (chart / "Chart.yaml").write_text("apiVersion: v2\nname: web\nversion: 0.1.0\n")  # -> Helm

    def fake_run(argv, **kw):
        if argv[0] == "helm":
            assert argv[1:3] == ["template", "web"]  # release defaults to the chart dir's name
            return "apiVersion: apps/v1\nkind: Deployment"
        if "create" in argv:
            return json.dumps({"kind": "List", "items": [_dep("prod", "web", "web:2")]})
        return json.dumps({"kind": "List", "items": [_dep("prod", "web", "web:1")]})  # live drifted

    monkeypatch.setattr("steadystate.sources.k8s.run_tool", fake_run)
    result = CliRunner().invoke(app, ["verify", str(chart), "--context", "prod", "--stateless"])
    assert result.exit_code == 0, result.output
    assert "web" in result.output


def test_verify_cli_rejects_a_dir_that_is_neither(tmp_path):
    result = CliRunner().invoke(app, ["verify", str(tmp_path), "--stateless"])
    assert result.exit_code != 0
    assert "neither" in result.output.lower()
