"""Tests for the environment-discovery command (src/steadystate/discover.py).

The verdict logic is pure (facts passed in), so it's exercised directly without a real shell or
filesystem; only the thin I/O gather + the CLI wiring touch the system, covered with a fake PATH.
"""

from __future__ import annotations

import json

from steadystate.discover import (
    ToolStatus,
    assess_probe,
    assess_source,
    probe_environment,
    render,
    required_bins,
    snapshot_source,
)

# -- required_bins: the registry-driven CLI extraction ----------------------------------------


def test_required_bins_first_token():
    assert required_bins(("kubectl get -o json",)) == ["kubectl"]


def test_required_bins_subcommand_keeps_binary():
    # `docker compose ...` -> the binary is docker, not compose
    assert required_bins(("docker compose config", "docker compose ps")) == ["docker"]


def test_required_bins_skips_leading_env_assignment():
    assert required_bins(("ANSIBLE_STDOUT_CALLBACK=json ansible-playbook --check",)) == [
        "ansible-playbook"
    ]


def test_required_bins_http_verb_has_no_local_cli():
    assert required_bins(("GET /api/v1/applications/{app}",)) == []


def test_required_bins_dedupes_in_order():
    assert required_bins(("helm list -o json", "helm status", "helm get manifest")) == ["helm"]


def test_required_bins_empty():
    assert required_bins(()) == []


# -- snapshot_source: structural shape heuristics ---------------------------------------------


def test_snapshot_source_k8s():
    assert snapshot_source({"declared": [], "observed": []}) == "k8s"


def test_snapshot_source_argocd():
    assert snapshot_source({"kind": "Application", "metadata": {}}) == "argocd"


def test_snapshot_source_terraform():
    assert snapshot_source({"resource_changes": [], "format_version": "1.0"}) == "terraform"


def test_snapshot_source_helm_release_array():
    assert snapshot_source([{"name": "web", "chart": "web-1.2.3"}]) == "helm"


def test_snapshot_source_unrecognized():
    assert snapshot_source({"something": "else"}) is None
    assert snapshot_source([]) is None
    assert snapshot_source("not a doc") is None


# -- assess_source: the readiness verdict -----------------------------------------------------


def test_assess_source_ready_when_tool_reachable_and_input_present():
    f = assess_source(
        "k8s",
        ("kubectl get -o json",),
        present={"kubectl"},
        reachable={"kubectl": True},
        inputs=(),
        snapshots=("snap.json",),
    )
    assert f.headline == "READY"
    assert f.tools == (ToolStatus("kubectl", installed=True, reachable=True),)
    assert f.auto_probe == "kubectl"  # the source carries its --probe auto pick


def test_assess_source_blocked_when_cli_missing():
    f = assess_source(
        "k8s",
        ("kubectl get -o json",),
        present=set(),
        reachable={},
        inputs=(),
        snapshots=(),
    )
    assert f.headline == "blocked -- install: kubectl"


def test_assess_source_unreachable_backend():
    f = assess_source(
        "k8s",
        ("kubectl get -o json",),
        present={"kubectl"},
        reachable={"kubectl": False},
        inputs=(),
        snapshots=("snap.json",),
    )
    assert "backend unreachable: kubectl" in f.headline


def test_assess_source_tools_ready_but_no_input():
    f = assess_source(
        "terraform",
        ("terraform plan",),
        present={"terraform"},
        reachable={},
        inputs=(),
        snapshots=(),
    )
    assert f.headline == "tools ready -- no input found in cwd"


def test_assess_source_snapshot_only_when_no_local_cli():
    # argocd reads via a GET API -> no binary -> always n/a, never "blocked"
    f = assess_source(
        "argocd",
        ("GET /api/v1/applications/{app}",),
        present=set(),
        reachable={},
        inputs=(),
        snapshots=(),
    )
    assert f.headline == "n/a -- reads a captured snapshot only"
    assert f.tools == ()


# -- assess_probe -----------------------------------------------------------------------------


def test_assess_probe_ready():
    f = assess_probe(
        "kubectl",
        ("kubectl get pods -o json",),
        present={"kubectl"},
        reachable={"kubectl": True},
        auto_for=("k8s",),
    )
    assert f.headline == "READY"
    assert f.auto_for == ("k8s",)


def test_assess_probe_blocked():
    f = assess_probe(
        "docker",
        ("docker ps",),
        present=set(),
        reachable={},
        auto_for=("docker-compose",),
    )
    assert f.headline == "blocked -- install: docker"


# -- probe_environment + render: the integrated path ------------------------------------------


def test_probe_environment_covers_every_registered_source_and_probe(monkeypatch):
    from steadystate import discover as disc
    from steadystate.probe import PROBE_CAPABILITIES
    from steadystate.sources import CAPABILITIES

    # Pretend nothing is installed so the gather never shells out for reachability.
    monkeypatch.setattr(disc.shutil, "which", lambda _binary: None)
    findings = probe_environment(cwd=disc.Path("/nonexistent-dir-for-test"))

    by_kind = {"source": set(), "probe": set()}
    for f in findings:
        by_kind[f.kind].add(f.name)
    assert by_kind["source"] == set(CAPABILITIES)
    assert by_kind["probe"] == set(PROBE_CAPABILITIES)


def test_probe_environment_detects_a_snapshot_in_cwd(tmp_path, monkeypatch):
    from steadystate import discover as disc

    (tmp_path / "snapshot.json").write_text(json.dumps({"declared": [], "observed": []}))
    monkeypatch.setattr(disc.shutil, "which", lambda _binary: None)
    findings = probe_environment(cwd=tmp_path)

    k8s = next(f for f in findings if f.name == "k8s")
    assert "snapshot.json" in k8s.snapshots


def test_render_lists_sources_and_probes_with_legend():
    findings = [
        assess_source(
            "k8s", ("kubectl get -o json",), {"kubectl"}, {"kubectl": True}, (), ("snap.json",)
        ),
        assess_probe(
            "kubectl", ("kubectl get pods -o json",), {"kubectl"}, {"kubectl": True}, ("k8s",)
        ),
    ]
    out = "\n".join(render(findings, cwd=__import__("pathlib").Path("/tmp/x")))
    assert "SOURCES (--source):" in out
    assert "PROBES (--probe):" in out
    assert "k8s" in out
    assert "auto for --source k8s" in out
    assert "legend:" in out


def test_discover_cli_runs(monkeypatch):
    from typer.testing import CliRunner

    from steadystate import discover as disc
    from steadystate.cli import app

    monkeypatch.setattr(disc.shutil, "which", lambda _binary: None)
    result = CliRunner().invoke(app, ["discover"])
    assert result.exit_code == 0
    assert "steadystate discovery" in result.stdout
    assert "SOURCES (--source):" in result.stdout
