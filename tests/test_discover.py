"""Tests for the environment-discovery command (src/steadystate/discover.py).

The verdict logic is pure (facts passed in), so it's exercised directly without a real shell or
filesystem; only the thin I/O gather + the CLI wiring touch the system, covered with a fake PATH.
"""

from __future__ import annotations

import json
import sys

from steadystate import discover as disc
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
    assert "DEEP INSPECTION" not in result.stdout  # opt-in only


# -- deep inspection: pure summarizers --------------------------------------------------------


def test_summarize_nodes_counts_ready_and_versions():
    doc = {
        "items": [
            {
                "status": {
                    "conditions": [{"type": "Ready", "status": "True"}],
                    "nodeInfo": {"kubeletVersion": "v1.29.4"},
                }
            },
            {
                "status": {
                    "conditions": [{"type": "Ready", "status": "False"}],
                    "nodeInfo": {"kubeletVersion": "v1.29.4"},
                }
            },
        ]
    }
    from steadystate.discover import summarize_nodes

    assert summarize_nodes(doc) == "2 node(s), 1 Ready; kubelet v1.29.4"


def test_summarize_nodes_handles_garbage():
    from steadystate.discover import summarize_nodes

    assert summarize_nodes(None) == "0 node(s), 0 Ready; kubelet unknown"


def test_namespace_names():
    from steadystate.discover import namespace_names

    doc = {"items": [{"metadata": {"name": "default"}}, {"metadata": {"name": "prod"}}]}
    assert namespace_names(doc) == ["default", "prod"]
    assert namespace_names("nope") == []


def test_summarize_releases():
    from steadystate.discover import summarize_releases

    releases = [{"name": "web", "namespace": "prod", "chart": "web-1.2.3", "status": "deployed"}]
    assert summarize_releases(releases) == ["web (ns=prod, chart=web-1.2.3, deployed)"]


def test_helm_snapshot_commands_uses_real_names():
    from steadystate.discover import helm_snapshot_commands

    releases = [
        {"name": "web", "namespace": "prod"},
        {"name": "api", "namespace": "staging"},
        {"missing": "name"},  # skipped
    ]
    cmds = helm_snapshot_commands(releases)
    assert cmds[0].startswith("helm get manifest web -n prod | kubectl create --dry-run=client")
    assert "api -n staging" in cmds[1]
    assert len(cmds) == 2


def test_backend_from_state():
    from steadystate.discover import backend_from_state

    assert backend_from_state({"backend": {"type": "s3"}}) == "s3"
    assert backend_from_state({"backend": {}}) is None
    assert backend_from_state({}) is None
    assert backend_from_state("nope") is None


# -- deep inspection: I/O probes (faked shell-outs) -------------------------------------------


def test_inspect_kubectl_skips_when_not_installed(monkeypatch):
    from steadystate import discover as disc

    monkeypatch.setattr(disc.shutil, "which", lambda _b: None)
    result = disc.inspect_kubectl()
    assert result.ok is False
    assert "not installed" in result.note


def test_inspect_kubectl_skips_when_cluster_unreachable(monkeypatch):
    from steadystate import discover as disc

    monkeypatch.setattr(disc.shutil, "which", lambda _b: "/usr/bin/kubectl")
    monkeypatch.setattr(disc, "_run_json", lambda _argv: None)  # nodes read fails
    result = disc.inspect_kubectl()
    assert result.ok is False
    assert "no reachable cluster" in result.note


def test_inspect_kubectl_reports_facts(monkeypatch):
    from steadystate import discover as disc

    nodes = {"items": [{"status": {"conditions": [{"type": "Ready", "status": "True"}]}}]}
    namespaces = {"items": [{"metadata": {"name": "default"}}]}
    monkeypatch.setattr(disc.shutil, "which", lambda _b: "/usr/bin/kubectl")
    monkeypatch.setattr(disc, "_run_json", lambda argv: nodes if "nodes" in argv else namespaces)
    monkeypatch.setattr(disc, "_run", lambda _argv: (True, "rancher-prod\n"))
    result = disc.inspect_kubectl()
    assert result.ok is True
    assert "context: rancher-prod" in result.facts[0]
    assert "1 node(s), 1 Ready" in result.facts[1]
    assert "namespaces (1): default" in result.facts[2]


def test_inspect_helm_tailors_commands_to_real_releases(monkeypatch):
    from steadystate import discover as disc

    releases = [{"name": "web", "namespace": "prod", "chart": "web-1", "status": "deployed"}]
    monkeypatch.setattr(disc.shutil, "which", lambda _b: "/usr/bin/helm")
    monkeypatch.setattr(disc, "_run_json", lambda _argv: releases)
    result = disc.inspect_helm()
    assert result.ok is True
    assert result.facts == ("release: web (ns=prod, chart=web-1, deployed)",)
    assert any("helm get manifest web -n prod" in rec for rec in result.recommendations)


def test_inspect_helm_no_releases(monkeypatch):
    from steadystate import discover as disc

    monkeypatch.setattr(disc.shutil, "which", lambda _b: "/usr/bin/helm")
    monkeypatch.setattr(disc, "_run_json", lambda _argv: [])
    result = disc.inspect_helm()
    assert result.ok is True
    assert result.facts == ("no Helm releases in any namespace",)


def test_inspect_terraform_reads_backend(tmp_path):
    from steadystate.discover import inspect_terraform

    (tmp_path / "main.tf").write_text("resource {}")
    dot = tmp_path / ".terraform"
    dot.mkdir()
    (dot / "terraform.tfstate").write_text(json.dumps({"backend": {"type": "s3"}}))
    result = inspect_terraform(tmp_path)
    assert result.ok is True
    assert "initialized: yes" in result.facts
    assert "backend: s3" in result.facts
    assert any("don't use -backend=false" in rec for rec in result.recommendations)


def test_inspect_terraform_skips_without_tf_files(tmp_path):
    from steadystate.discover import inspect_terraform

    assert inspect_terraform(tmp_path).ok is False


def test_render_inspections_skips_and_reports():
    from steadystate.discover import Inspection, render_inspections

    results = [
        Inspection("kubectl", ok=True, facts=("nodes: 3 node(s), 3 Ready; kubelet v1.29",)),
        Inspection("helm", ok=False, note="not installed"),
    ]
    out = "\n".join(render_inspections(results))
    assert "DEEP INSPECTION (live, read-only):" in out
    assert "nodes: 3 node(s), 3 Ready" in out
    assert "helm: skipped -- not installed" in out


def test_discover_deep_cli_path(monkeypatch):
    from typer.testing import CliRunner

    from steadystate import discover as disc
    from steadystate.cli import app

    monkeypatch.setattr(disc.shutil, "which", lambda _binary: None)  # everything skips cleanly
    result = CliRunner().invoke(app, ["discover", "--deep"])
    assert result.exit_code == 0
    assert "DEEP INSPECTION (live, read-only):" in result.stdout
    assert "kubectl: skipped" in result.stdout
    assert "docker: skipped" in result.stdout
    assert "argocd: skipped" in result.stdout


# -- deep inspection: docker + argocd ---------------------------------------------------------


def test_summarize_containers():
    from steadystate.discover import summarize_containers

    facts = summarize_containers([{"Names": "web", "Image": "nginx"}, {"Image": "redis"}])
    assert facts[0] == "2 running container(s)"
    assert facts[1] == "running: web, redis"  # Names preferred, falls back to Image


def test_summarize_containers_empty():
    from steadystate.discover import summarize_containers

    assert summarize_containers([]) == ["0 running container(s)"]


def test_compose_scan_commands_points_at_config_dir():
    from steadystate.discover import compose_scan_commands

    projects = [{"Name": "shop", "ConfigFiles": "/srv/shop/docker-compose.yml"}]
    cmds = compose_scan_commands(projects)
    assert "scan /srv/shop --source docker-compose --probe docker" in cmds[0]
    assert "# project shop" in cmds[0]


def test_compose_targets_point_at_real_project_dirs():
    from steadystate.discover import compose_targets

    targets = compose_targets([{"Name": "Shop API", "ConfigFiles": "/srv/shop/compose.yml"}])
    assert len(targets) == 1
    assert targets[0].name == "shop-api"  # slugified project name
    assert targets[0].source == "docker-compose"
    assert targets[0].path == "/srv/shop"  # the project's own dir (exists on disk)
    assert targets[0].probe == "docker"


def test_compose_targets_skips_unresolvable_or_unnamed():
    from steadystate.discover import compose_targets

    assert compose_targets([{"Name": "x", "ConfigFiles": "compose.yml"}]) == []  # no dir part
    assert compose_targets([{"ConfigFiles": "/srv/x/compose.yml"}]) == []  # no name
    assert compose_targets("garbage") == []


def test_deep_targets_flattens_inspection_targets():
    from steadystate.discover import Inspection, deep_targets
    from steadystate.targets import Target

    shop = Target("shop", "docker-compose", "/srv/shop", "shop", "docker")
    inspections = [
        Inspection("kubectl", ok=False, note="skipped"),  # no targets
        Inspection("docker", ok=True, targets=(shop,)),
    ]
    assert deep_targets(inspections) == [shop]


def test_summarize_argocd_apps():
    from steadystate.discover import summarize_argocd_apps

    apps = [
        {
            "metadata": {"name": "web"},
            "status": {"sync": {"status": "Synced"}, "health": {"status": "Healthy"}},
        }
    ]
    assert summarize_argocd_apps(apps) == ["web (sync=Synced, health=Healthy)"]
    # also accepts a kubectl List shape
    assert summarize_argocd_apps({"items": apps}) == ["web (sync=Synced, health=Healthy)"]


def test_argocd_capture_commands_names_real_apps():
    from steadystate.discover import argocd_capture_commands

    cmds = argocd_capture_commands([{"metadata": {"name": "web"}}, {"metadata": {}}])
    assert len(cmds) == 1
    assert cmds[0].startswith("argocd app get web -o json > web.json")
    assert "scan web.json --source argocd --probe argocd" in cmds[0]


def test_inspect_docker_reports_containers_and_compose(monkeypatch):
    from steadystate import discover as disc

    monkeypatch.setattr(disc.shutil, "which", lambda _b: "/usr/bin/docker")
    monkeypatch.setattr(disc, "_run_ndjson", lambda _argv: [{"Names": "web", "Image": "nginx"}])
    monkeypatch.setattr(
        disc,
        "_run_json",
        lambda _argv: [
            {"Name": "shop", "Status": "running(2)", "ConfigFiles": "/srv/shop/compose.yml"}
        ],
    )
    result = disc.inspect_docker()
    assert result.ok is True
    assert "1 running container(s)" in result.facts
    assert any("compose project: shop" in f for f in result.facts)
    assert any("scan /srv/shop --source docker-compose" in rec for rec in result.recommendations)
    # the structured counterpart of the rendered command: a target --create can register
    assert [t.name for t in result.targets] == ["shop"]
    assert result.targets[0].source == "docker-compose" and result.targets[0].path == "/srv/shop"


def test_inspect_docker_skips_when_daemon_down(monkeypatch):
    from steadystate import discover as disc

    monkeypatch.setattr(disc.shutil, "which", lambda _b: "/usr/bin/docker")
    monkeypatch.setattr(disc, "_run_ndjson", lambda _argv: None)
    result = disc.inspect_docker()
    assert result.ok is False
    assert "daemon unreachable" in result.note


def test_inspect_argocd_tailors_to_real_apps(monkeypatch):
    from steadystate import discover as disc

    apps = [{"metadata": {"name": "web"}, "status": {"sync": {"status": "OutOfSync"}}}]
    monkeypatch.setattr(disc.shutil, "which", lambda _b: "/usr/bin/argocd")
    monkeypatch.setattr(disc, "_run_json", lambda _argv: apps)
    result = disc.inspect_argocd()
    assert result.ok is True
    assert result.facts == ("app: web (sync=OutOfSync, health=?)",)
    assert any("argocd app get web" in rec for rec in result.recommendations)


def test_inspect_argocd_skips_when_not_logged_in(monkeypatch):
    from steadystate import discover as disc

    monkeypatch.setattr(disc.shutil, "which", lambda _b: "/usr/bin/argocd")
    monkeypatch.setattr(disc, "_run_json", lambda _argv: None)
    result = disc.inspect_argocd()
    assert result.ok is False
    assert "not logged in" in result.note


def test_deep_inspect_covers_every_inspectable_tool(monkeypatch):
    from steadystate import discover as disc

    monkeypatch.setattr(disc.shutil, "which", lambda _b: None)
    tools = {i.tool for i in disc.deep_inspect(cwd=disc.Path("/nonexistent"))}
    assert tools == {"kubectl", "helm", "terraform", "docker", "argocd", "ansible"}


# -- deep inspection: ansible -----------------------------------------------------------------


def test_inventory_hosts_from_meta_and_groups():
    from steadystate.discover import inventory_hosts

    doc = {
        "_meta": {"hostvars": {"web1": {}, "web2": {}}},
        "web": {"hosts": ["web1", "web2"]},
        "db": {"hosts": ["db1"]},  # a host only under a group, not in hostvars
    }
    assert inventory_hosts(doc) == ["web1", "web2", "db1"]
    assert inventory_hosts("garbage") == []


def test_summarize_inventory_counts_hosts_and_real_groups():
    from steadystate.discover import summarize_inventory

    doc = {
        "_meta": {"hostvars": {"web1": {}}},
        "all": {"children": ["web"]},  # synthetic -- not counted
        "ungrouped": {},  # synthetic -- not counted
        "web": {"hosts": ["web1"]},
    }
    assert summarize_inventory(doc) == "1 host(s) in 1 group(s)"


def test_ansible_capture_command_names_a_real_playbook(tmp_path):
    from steadystate.discover import ansible_capture_command

    assert "<playbook>" in ansible_capture_command(tmp_path)  # none present -> placeholder
    (tmp_path / "site.yml").write_text("- hosts: all")
    cmd = ansible_capture_command(tmp_path)
    assert "ansible-playbook --check --diff site.yml" in cmd
    assert "scan play.json --source ansible" in cmd


def test_inspect_ansible_reports_inventory(monkeypatch, tmp_path):
    from steadystate import discover as disc

    monkeypatch.setattr(disc.shutil, "which", lambda _b: "/usr/bin/ansible-inventory")
    monkeypatch.setattr(
        disc,
        "_run_json",
        lambda _argv: {"_meta": {"hostvars": {"web1": {}}}, "web": {"hosts": ["web1"]}},
    )
    result = disc.inspect_ansible(tmp_path)
    assert result.ok is True
    assert result.facts[0] == "inventory: 1 host(s) in 1 group(s)"
    assert "hosts: web1" in result.facts
    assert any("--source ansible" in rec for rec in result.recommendations)


def test_inspect_ansible_skips_when_not_installed(monkeypatch, tmp_path):
    from steadystate import discover as disc

    monkeypatch.setattr(disc.shutil, "which", lambda _b: None)
    result = disc.inspect_ansible(tmp_path)
    assert result.ok is False
    assert "not installed" in result.note


def test_inspect_ansible_skips_when_no_inventory(monkeypatch, tmp_path):
    from steadystate import discover as disc

    monkeypatch.setattr(disc.shutil, "which", lambda _b: "/usr/bin/ansible-inventory")
    monkeypatch.setattr(disc, "_run_json", lambda _argv: None)  # ansible-inventory failed
    result = disc.inspect_ansible(tmp_path)
    assert result.ok is False
    assert "no inventory resolved" in result.note


# -- playbook role suggestion (advisory; rides `ansible-playbook --list-tasks`) ---------------

_LIST_TASKS = """
playbook: site.yml

  play #1 (all): all\tTAGS: []
    tasks:
      common : Set hostname\tTAGS: []
      haproxy : Install haproxy\tTAGS: []
      haproxy : Configure haproxy\tTAGS: []
      keepalived : Configure VRRP\tTAGS: []
      Run a one-off task without a role\tTAGS: []
"""


def test_playbook_roles_extracts_distinct_roles_in_order():
    from steadystate.discover import playbook_roles

    # distinct, first-seen order; the role-less task line is ignored (no `<id> : ` prefix)
    assert playbook_roles(_LIST_TASKS) == ["common", "haproxy", "keepalived"]


def test_playbook_roles_empty_on_no_role_lines():
    from steadystate.discover import playbook_roles

    assert playbook_roles("") == []
    assert playbook_roles("playbook: x\n  play #1 (all): all\n") == []  # no role-prefixed tasks


def test_playbook_roles_skips_when_no_playbook_or_no_binary(monkeypatch, tmp_path):
    from steadystate import discover as disc

    # no playbook file in cwd -> [] without even needing ansible-playbook
    monkeypatch.setattr(disc.shutil, "which", lambda _b: "/usr/bin/ansible-playbook")
    assert disc._playbook_roles(tmp_path) == []
    # playbook present but the binary is absent -> still []
    (tmp_path / "site.yml").write_text("- hosts: all")
    monkeypatch.setattr(disc.shutil, "which", lambda _b: None)
    assert disc._playbook_roles(tmp_path) == []


def test_inspect_ansible_suggests_roles_advisorily(monkeypatch, tmp_path):
    from steadystate import discover as disc

    (tmp_path / "site.yml").write_text("- hosts: all")
    monkeypatch.setattr(disc.shutil, "which", lambda _b: "/usr/bin/ansible")
    monkeypatch.setattr(disc, "_run_json", lambda _argv: {"_meta": {"hostvars": {"web1": {}}}})
    monkeypatch.setattr(disc, "_run", lambda _argv: (True, _LIST_TASKS))  # --list-tasks output

    result = disc.inspect_ansible(tmp_path)
    assert result.ok is True
    assert any("playbook roles:" in f and "haproxy" in f for f in result.facts)
    assert any("advisory" in rec and "keepalived" in rec for rec in result.recommendations)


# -- target creation (--create) ---------------------------------------------------------------


def test_slug_sanitizes_names():
    from steadystate.discover import _slug

    assert _slug("Shop.API v2") == "shop-api-v2"
    assert _slug("steadystate.ai") == "steadystate-ai"
    assert _slug("__weird__") == "weird"


def _source_finding(name, *, inputs=(), snapshots=()):
    from steadystate.discover import assess_source

    observe = ("GET /api",) if name in ("argocd", "rancher") else (f"{name} do",)
    return assess_source(name, observe, set(), {}, inputs, snapshots)


def test_proposed_targets_single_hit_uses_bare_cwd_name():
    from pathlib import Path

    from steadystate.discover import proposed_targets

    findings = [_source_finding("terraform", inputs=("main.tf",))]
    targets = proposed_targets(findings, Path("/work/myapp"))
    assert len(targets) == 1
    assert targets[0].name == "myapp"  # single hit -> no suffix
    assert targets[0].source == "terraform"
    assert targets[0].path == str(Path("/work/myapp"))  # live dir source -> the dir


def test_proposed_targets_multiple_hits_get_source_suffix():
    from pathlib import Path

    from steadystate.discover import proposed_targets

    findings = [
        _source_finding("terraform", inputs=("main.tf",)),
        _source_finding("k8s", snapshots=("snap.json",)),
    ]
    targets = {t.name: t for t in proposed_targets(findings, Path("/work/myapp"))}
    assert set(targets) == {"myapp-terraform", "myapp-k8s"}
    assert targets["myapp-k8s"].path == str(Path("/work/myapp") / "snap.json")  # snapshot file


def test_proposed_targets_skips_sources_with_no_input():
    from pathlib import Path

    from steadystate.discover import proposed_targets

    # terraform with no *.tf and no snapshot -> not scannable here -> not proposed
    assert proposed_targets([_source_finding("terraform")], Path("/work/myapp")) == []


def test_merge_targets_does_not_clobber_existing():
    from steadystate.targets import Target, merge_targets

    existing = {"myapp": Target("myapp", "terraform", "/old", "myapp")}
    proposed = [
        Target("myapp", "k8s", "/new", "myapp"),  # name taken -> skipped
        Target("myapp-helm", "helm", "/h.json", "myapp-helm"),  # new -> added
    ]
    merged, added, skipped = merge_targets(existing, proposed)
    assert added == ["myapp-helm"]
    assert skipped == ["myapp"]
    assert merged["myapp"].source == "terraform"  # original kept
    assert "myapp-helm" in merged


def test_save_and_load_targets_round_trip(tmp_path):
    from steadystate.targets import Target, load_targets, save_targets

    path = tmp_path / ".steadystate/targets.json"
    save_targets(
        path,
        {
            "web": Target("web", "terraform", "/infra", "web"),  # defaults omitted
            "api": Target("api", "k8s", "/snap.json", "prod", probe="kubectl"),  # custom kept
        },
    )
    reloaded = load_targets(path)
    assert reloaded["web"].label == "web" and reloaded["web"].probe == "auto"
    assert reloaded["api"].label == "prod" and reloaded["api"].probe == "kubectl"


def test_discover_create_cli_writes_targets_file(tmp_path, monkeypatch):
    from typer.testing import CliRunner

    from steadystate import discover as disc
    from steadystate.cli import app
    from steadystate.targets import load_targets

    # A terraform dir: a *.tf file present so the source is a usable target.
    (tmp_path / "main.tf").write_text("resource {}")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(disc.shutil, "which", lambda _b: None)
    monkeypatch.delenv("STEADYSTATE_TARGETS", raising=False)

    result = CliRunner().invoke(app, ["discover", "--create"])
    assert result.exit_code == 0
    assert "TARGETS ->" in result.stdout

    from steadystate.discover import _slug

    name = _slug(tmp_path.name)  # named after the cwd (sanitized)
    written = load_targets(tmp_path / ".steadystate/targets.json")
    assert name in written
    assert written[name].source == "terraform"


def test_discover_create_reports_when_nothing_scannable(tmp_path, monkeypatch):
    from typer.testing import CliRunner

    from steadystate import discover as disc
    from steadystate.cli import app

    monkeypatch.chdir(tmp_path)  # empty dir
    monkeypatch.setattr(disc.shutil, "which", lambda _b: None)
    monkeypatch.delenv("STEADYSTATE_TARGETS", raising=False)

    result = CliRunner().invoke(app, ["discover", "--create"])
    assert result.exit_code == 0
    assert "nothing to create" in result.stdout
    assert not (tmp_path / ".steadystate/targets.json").exists()


def test_discover_deep_and_create_stack(tmp_path, monkeypatch):
    # The flags are orthogonal: one pass prints the base report + DEEP INSPECTION and writes the
    # targets file, all from the same findings. This is the one-shot "inspect and register" path.
    from typer.testing import CliRunner

    from steadystate import discover as disc
    from steadystate.cli import app
    from steadystate.discover import _slug
    from steadystate.targets import load_targets

    (tmp_path / "main.tf").write_text("resource {}")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(disc.shutil, "which", lambda _b: None)  # tools skip, file still written
    monkeypatch.delenv("STEADYSTATE_TARGETS", raising=False)

    result = CliRunner().invoke(app, ["discover", "--deep", "--create"])
    assert result.exit_code == 0
    # all three sections present, in order
    assert "SOURCES (--source):" in result.stdout
    assert "DEEP INSPECTION (live, read-only):" in result.stdout
    assert "TARGETS ->" in result.stdout
    # and the targets file was actually written from that same pass
    written = load_targets(tmp_path / ".steadystate/targets.json")
    assert written[_slug(tmp_path.name)].source == "terraform"


def test_discover_deep_create_registers_live_compose_project(tmp_path, monkeypatch):
    # --deep finds a running compose project rooted OUTSIDE the cwd; --create registers it (its dir
    # exists on disk). The cwd has nothing scannable, so this target is purely from the deep pass --
    # the value the base --create alone couldn't deliver.
    from typer.testing import CliRunner

    from steadystate import discover as disc
    from steadystate.cli import app
    from steadystate.targets import load_targets

    proj = tmp_path / "shop"
    proj.mkdir()
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        disc.shutil, "which", lambda b: "/usr/bin/docker" if b == "docker" else None
    )
    monkeypatch.setattr(disc, "_check_reachable", lambda _b: False)  # no real `docker info`
    monkeypatch.setattr(disc, "_run_ndjson", lambda _argv: [])  # docker ps: no containers
    monkeypatch.setattr(
        disc,
        "_run_json",
        lambda _argv: [
            {"Name": "shop", "Status": "running(1)", "ConfigFiles": str(proj / "c.yml")}
        ],
    )
    monkeypatch.delenv("STEADYSTATE_TARGETS", raising=False)

    result = CliRunner().invoke(app, ["discover", "--deep", "--create"])
    assert result.exit_code == 0
    written = load_targets(tmp_path / ".steadystate/targets.json")
    assert "shop" in written
    assert written["shop"].source == "docker-compose" and written["shop"].path == str(proj)


def test_discover_deep_create_dedupes_cwd_compose_project(tmp_path, monkeypatch):
    # A compose project IN the cwd is seen by both passes (base + deep). It must be written once,
    # under one name -- not registered twice via two different naming schemes.
    from typer.testing import CliRunner

    from steadystate import discover as disc
    from steadystate.cli import app
    from steadystate.targets import load_targets

    (tmp_path / "compose.yml").write_text("services: {}")  # a compose file in the cwd
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        disc.shutil, "which", lambda b: "/usr/bin/docker" if b == "docker" else None
    )
    monkeypatch.setattr(disc, "_check_reachable", lambda _b: False)
    monkeypatch.setattr(disc, "_run_ndjson", lambda _argv: [])
    monkeypatch.setattr(
        disc,
        "_run_json",
        lambda _argv: [{"Name": "proj", "ConfigFiles": str(tmp_path / "compose.yml")}],
    )
    monkeypatch.delenv("STEADYSTATE_TARGETS", raising=False)

    result = CliRunner().invoke(app, ["discover", "--deep", "--create"])
    assert result.exit_code == 0
    written = load_targets(tmp_path / ".steadystate/targets.json")
    assert len(written) == 1  # the cwd project, once -- not base + deep duplicated
    (only,) = written.values()
    assert only.source == "docker-compose" and only.path == str(tmp_path)


# -- CI emission (--emit-ci) ------------------------------------------------------------------


def test_emittable_sources_only_hits_with_a_recipe():
    from steadystate.discover import emittable_sources

    findings = [
        _source_finding("terraform", inputs=("main.tf",)),  # hit + recipe -> in
        _source_finding("k8s"),  # recipe but no input -> out
        _source_finding("rancher", snapshots=("gitrepo.json",)),  # hit but no recipe -> out
    ]
    assert emittable_sources(findings) == ["terraform"]


def test_emit_github_actions_tailors_to_terraform():
    from pathlib import Path

    from steadystate.discover import emit_github_actions

    out = "\n".join(
        emit_github_actions([_source_finding("terraform", inputs=("main.tf",))], Path("/work/app"))
    )
    assert "name: steadystate-drift" in out
    assert "uses: actions/checkout@v4" in out
    assert "uses: hashicorp/setup-terraform@v3" in out
    assert "terraform show -json tfplan > plan.json" in out
    assert "steadystate scan plan.json --source terraform --to console" in out
    assert "# --- terraform ---" in out
    assert "TODO: authenticate" in out  # auth left to the operator


def test_emit_github_actions_one_step_group_per_source():
    from pathlib import Path

    from steadystate.discover import emit_github_actions

    findings = [
        _source_finding("terraform", inputs=("main.tf",)),
        _source_finding("helm", inputs=("Chart.yaml",)),
    ]
    out = "\n".join(emit_github_actions(findings, Path("/work/app")))
    assert "# --- terraform ---" in out and "# --- helm ---" in out
    assert "helm list -A -o json > releases.json" in out
    # the shared scaffold appears once, not per source
    assert out.count("runs-on: ubuntu-latest") == 1


def test_discover_emit_ci_prints_only_the_workflow(tmp_path, monkeypatch):
    from typer.testing import CliRunner

    from steadystate import discover as disc
    from steadystate.cli import app

    (tmp_path / "main.tf").write_text("resource {}")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(disc.shutil, "which", lambda _b: None)

    result = CliRunner().invoke(app, ["discover", "--emit-ci"])
    assert result.exit_code == 0
    assert result.stdout.startswith("# Generated by")
    assert "name: steadystate-drift" in result.stdout
    assert "SOURCES (--source):" not in result.stdout  # the human report is suppressed


def test_discover_emit_ci_nothing_to_emit(tmp_path, monkeypatch):
    from typer.testing import CliRunner

    from steadystate import discover as disc
    from steadystate.cli import app

    monkeypatch.chdir(tmp_path)  # empty dir -- no scannable source
    monkeypatch.setattr(disc.shutil, "which", lambda _b: None)

    result = CliRunner().invoke(app, ["discover", "--emit-ci"])
    assert result.exit_code == 0
    assert "name: steadystate-drift" not in result.stdout  # nothing emitted to stdout


# -- registry-drift guard (the hand-maintained dicts must key off real sources) ---------------


def test_hint_and_recipe_keys_are_registered_sources():
    # Mirrors test_probe.test_auto_keys_are_registered_sources: a renamed/added source must not
    # silently lose its hint or CI recipe. _CI_STEPS/_REACHABILITY are intentional *subsets*, so
    # the assertion is <= (subset), not equality.
    from steadystate.discover import _CI_STEPS, _HINTS, _REACHABILITY, required_bins
    from steadystate.probe import PROBE_CAPABILITIES
    from steadystate.sources import CAPABILITIES

    sources = set(CAPABILITIES)
    assert set(_HINTS) <= sources, f"_HINTS keys not registered sources: {set(_HINTS) - sources}"
    assert set(_CI_STEPS) <= sources, f"_CI_STEPS keys not sources: {set(_CI_STEPS) - sources}"

    all_bins: set[str] = set()
    for caps in (*CAPABILITIES.values(), *PROBE_CAPABILITIES.values()):
        all_bins.update(required_bins(caps.observe))
    unknown = set(_REACHABILITY) - all_bins
    assert not unknown, f"_REACHABILITY names binaries no source/probe needs: {unknown}"


# -- scannable_now: the --check / --json signal -----------------------------------------------


def test_scannable_now_true_on_ready_source_or_present_snapshot():
    from steadystate.discover import scannable_now

    ready = assess_source("terraform", ("terraform plan",), {"terraform"}, {}, ("main.tf",), ())
    assert scannable_now([ready]) is True
    # snapshot present but tool absent: scanning a captured file needs no CLI -> still scannable.
    snap = assess_source("k8s", ("kubectl get -o json",), set(), {}, (), ("snap.json",))
    assert scannable_now([snap]) is True


def test_scannable_now_false_when_blocked_or_empty():
    from steadystate.discover import scannable_now

    blocked = assess_source("terraform", ("terraform plan",), set(), {}, ("main.tf",), ())
    assert scannable_now([blocked]) is False  # *.tf present but terraform not installed
    assert scannable_now([]) is False


# -- --json output + --check exit code --------------------------------------------------------


def test_discover_json_emits_machine_readable_report(tmp_path, monkeypatch):
    from typer.testing import CliRunner

    from steadystate import discover as disc
    from steadystate.cli import app

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(disc.shutil, "which", lambda _b: None)

    result = CliRunner().invoke(app, ["discover", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["scannable"] is False
    assert {f["name"] for f in payload["sources"]}  # every source serialized
    assert "deep" not in payload  # --deep not passed


def test_discover_check_exits_nonzero_when_nothing_scannable(tmp_path, monkeypatch):
    from typer.testing import CliRunner

    from steadystate import discover as disc
    from steadystate.cli import app

    monkeypatch.chdir(tmp_path)  # empty dir, no tools
    monkeypatch.setattr(disc.shutil, "which", lambda _b: None)

    result = CliRunner().invoke(app, ["discover", "--check"])
    assert result.exit_code == 1
    assert "SOURCES (--source):" in result.stdout  # report still printed before the exit


def test_discover_check_exits_zero_when_scannable(tmp_path, monkeypatch):
    from typer.testing import CliRunner

    from steadystate import discover as disc
    from steadystate.cli import app

    monkeypatch.chdir(tmp_path)
    (tmp_path / "main.tf").write_text("resource {}")  # a terraform live-dir signal
    # only terraform installed -> no _REACHABILITY bin present -> no real subprocess in the test
    monkeypatch.setattr(
        disc.shutil, "which", lambda b: "/usr/bin/terraform" if b == "terraform" else None
    )

    result = CliRunner().invoke(app, ["discover", "--check"])
    assert result.exit_code == 0


def test_discover_json_and_create_are_mutually_exclusive(tmp_path, monkeypatch):
    from typer.testing import CliRunner

    from steadystate import discover as disc
    from steadystate.cli import app

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(disc.shutil, "which", lambda _b: None)

    result = CliRunner().invoke(app, ["discover", "--json", "--create"])
    assert result.exit_code != 0
    assert "can't combine" in result.output


# -- hardening: a pathological cwd json file never crashes discovery --------------------------


def test_classify_snapshots_survives_deeply_nested_json(tmp_path):
    from steadystate.discover import _classify_snapshots

    # Deeply-nested JSON makes json.loads raise RecursionError (not ValueError) -- it must be
    # caught and the file skipped, not crash the scan.
    (tmp_path / "bomb.json").write_text("[" * 2000 + "]" * 2000)
    assert _classify_snapshots(tmp_path) == {}


# -- the real subprocess I/O: _run / _run_json / _run_ndjson / _check_reachable ---------------
#
# Everywhere else these are monkeypatched away, so the genuine subprocess path (capture, text,
# timeout, the OSError/SubprocessError swallow, the ndjson line skipping) was never exercised.
# Drive it with a controllable child -- the Python interpreter itself -- so the test needs no
# external CLI and runs identically on POSIX and Windows.


def _py(code: str) -> list[str]:
    """An argv that runs `code` in this interpreter -- a portable stand-in for a real tool."""
    return [sys.executable, "-c", code]


def test_run_captures_stdout_on_success():
    ok, out = disc._run(_py("print('hello')"))
    assert ok is True
    assert out.strip() == "hello"


def test_run_reports_failure_on_nonzero_exit():
    ok, out = disc._run(_py("import sys; print('partial'); sys.exit(3)"))
    assert ok is False  # returncode != 0 -> callers treat it as no data
    assert "partial" in out  # stdout is still captured


def test_run_swallows_missing_binary():
    # FileNotFoundError (an OSError) must degrade to a clean (False, "") -- never propagate.
    assert disc._run(["steadystate-no-such-binary-zzz", "--help"]) == (False, "")


def test_run_swallows_timeout(monkeypatch):
    # TimeoutExpired (a SubprocessError) must degrade to (False, "") -- a hung backend can't block.
    monkeypatch.setattr(disc, "_DEEP_TIMEOUT", 0.3)
    assert disc._run(_py("import time; time.sleep(5)")) == (False, "")


def test_run_json_parses_a_valid_object():
    assert disc._run_json(_py("import json; print(json.dumps({'a': 1}))")) == {"a": 1}


def test_run_json_none_on_failed_run():
    assert disc._run_json(_py("import sys; sys.exit(1)")) is None


def test_run_json_none_on_unparseable_output():
    assert disc._run_json(_py("print('not json at all')")) is None


def test_run_ndjson_parses_one_object_per_line():
    code = "import json; print(json.dumps({'a': 1})); print(json.dumps({'b': 2}))"
    assert disc._run_ndjson(_py(code)) == [{"a": 1}, {"b": 2}]


def test_run_ndjson_skips_blank_bad_and_non_object_lines():
    code = (
        "import json; print(json.dumps({'a': 1})); print(); print('garbage'); "
        "print(json.dumps([1, 2])); print(json.dumps({'b': 2}))"
    )
    # blank skipped, 'garbage' skipped (ValueError), [1, 2] skipped (not a dict) -> two dicts kept.
    assert disc._run_ndjson(_py(code)) == [{"a": 1}, {"b": 2}]


def test_run_ndjson_none_on_failed_run():
    assert disc._run_ndjson(_py("import sys; sys.exit(1)")) is None


def test_check_reachable_true_on_zero_exit(monkeypatch):
    monkeypatch.setitem(disc._REACHABILITY, "faketool", _py("import sys; sys.exit(0)"))
    assert disc._check_reachable("faketool") is True


def test_check_reachable_false_on_nonzero_exit(monkeypatch):
    monkeypatch.setitem(disc._REACHABILITY, "faketool", _py("import sys; sys.exit(1)"))
    assert disc._check_reachable("faketool") is False


def test_check_reachable_false_on_missing_binary(monkeypatch):
    monkeypatch.setitem(disc._REACHABILITY, "faketool", ["steadystate-no-such-binary-zzz"])
    assert disc._check_reachable("faketool") is False


def test_check_reachable_swallows_timeout(monkeypatch):
    monkeypatch.setattr(disc, "_REACHABILITY_TIMEOUT", 0.3)
    monkeypatch.setitem(disc._REACHABILITY, "faketool", _py("import time; time.sleep(5)"))
    assert disc._check_reachable("faketool") is False


# -- kube contexts -> live targets (discover --create registers your clusters) ----------------


def test_context_targets_one_per_context_slugged():
    from steadystate.discover import context_targets

    targets = context_targets(["prod-cluster", "gke_proj_zone_stg"])
    assert [t.name for t in targets] == ["prod-cluster", "gke-proj-zone-stg"]
    assert all(t.source == "k8s-live" and t.path == "" and t.probe == "auto" for t in targets)
    # the raw context drives kubectl + labels the alerts; the slug is just the friendly name.
    assert targets[0].context == "prod-cluster" and targets[0].label == "prod-cluster"
    assert targets[1].context == "gke_proj_zone_stg"


def test_kube_contexts_parses_and_dedups(monkeypatch):
    from steadystate import discover as disc

    monkeypatch.setattr(disc, "_run", lambda argv: (True, "prod\nstg\nprod\n\n"))
    assert disc.kube_contexts() == ["prod", "stg"]  # order preserved, deduped, blanks dropped


def test_kube_contexts_empty_when_kubectl_absent(monkeypatch):
    from steadystate import discover as disc

    monkeypatch.setattr(disc, "_run", lambda argv: (False, ""))
    assert disc.kube_contexts() == []  # degrades, never blocks a create


def test_discover_create_registers_a_target_per_kube_context(tmp_path, monkeypatch):
    from typer.testing import CliRunner

    from steadystate import cli
    from steadystate import discover as disc
    from steadystate.cli import app
    from steadystate.targets import load_targets

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(disc.shutil, "which", lambda _b: None)  # no cwd-local sources
    monkeypatch.setattr(cli, "kube_contexts", lambda: ["prod-cluster", "gke_proj_zone_stg"])
    monkeypatch.delenv("STEADYSTATE_TARGETS", raising=False)

    result = CliRunner().invoke(app, ["discover", "--create"])
    assert result.exit_code == 0, result.output
    written = load_targets(tmp_path / ".steadystate/targets.json")
    assert len(written) == 2
    assert {t.context for t in written.values()} == {"prod-cluster", "gke_proj_zone_stg"}
    assert all(t.source == "k8s-live" and t.path == "" for t in written.values())


def test_discover_create_kube_contexts_is_idempotent(tmp_path, monkeypatch):
    from typer.testing import CliRunner

    from steadystate import cli
    from steadystate import discover as disc
    from steadystate.cli import app
    from steadystate.targets import load_targets

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(disc.shutil, "which", lambda _b: None)
    monkeypatch.setattr(cli, "kube_contexts", lambda: ["prod-cluster"])
    monkeypatch.delenv("STEADYSTATE_TARGETS", raising=False)

    CliRunner().invoke(app, ["discover", "--create"])
    CliRunner().invoke(app, ["discover", "--create"])  # second run must not duplicate
    assert len(load_targets(tmp_path / ".steadystate/targets.json")) == 1
