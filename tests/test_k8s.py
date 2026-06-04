import json

from steadystate.model import ChangeType
from steadystate.sources.base import DriftSource, ObservedSource, StateSource
from steadystate.sources.k8s import (
    KubernetesLiveSource,
    KubernetesSource,
    observed_resources_from_kubectl,
    reconcile_k8s,
    resources_from_manifests,
)


def _deployment(image: str, *, name: str = "web", replicas: int = 3) -> dict:
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"namespace": "prod", "name": name},
        "spec": {
            "replicas": replicas,
            "template": {"spec": {"containers": [{"name": "app", "image": image}]}},
        },
    }


def _service(name: str = "web") -> dict:
    return {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {"namespace": "prod", "name": name},
        "spec": {"ports": [{"port": 80}]},
    }


def test_resources_from_manifests_projection():
    resources = resources_from_manifests([_deployment("nginx:1.27")])
    assert len(resources) == 1

    res = resources[0]
    assert res.kind == "Deployment"
    assert res.identity == "apps/Deployment/prod/web"
    assert res.provenance.source == "kubernetes"
    assert res.provenance.address == "apps/Deployment/prod/web"
    assert res.properties["images"] == ["nginx:1.27"]
    assert res.properties["replicas"] == 3
    assert (
        "posture" in res.properties
    )  # the compliance posture projection (seccomp, caps) rides along


def test_core_group_is_empty_and_non_workload_has_no_props():
    resources = resources_from_manifests([_service()])
    res = resources[0]
    assert res.identity == "Service/prod/web"  # core v1 -> blank group dropped
    assert res.properties == {}  # non-workload reconciles on presence alone


def test_init_containers_and_sorting():
    obj = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"namespace": "prod", "name": "web"},
        "spec": {
            "template": {
                "spec": {
                    "initContainers": [{"name": "init", "image": "busybox:1.36"}],
                    "containers": [{"name": "app", "image": "app:2"}],
                }
            }
        },
    }
    res = resources_from_manifests(obj)[0]
    assert res.properties["images"] == ["app:2", "busybox:1.36"]


def test_changed_image_is_modified():
    declared = resources_from_manifests([_deployment("nginx:1.28")])
    observed = observed_resources_from_kubectl(
        {"kind": "List", "items": [_deployment("nginx:1.27")]}
    )
    drifts = reconcile_k8s(declared, observed)
    assert len(drifts) == 1
    assert drifts[0].change_type == ChangeType.MODIFIED
    assert drifts[0].identity == "apps/Deployment/prod/web"
    assert drifts[0].declared == {"images": ["nginx:1.28"], "replicas": 3}
    assert drifts[0].observed == {"images": ["nginx:1.27"], "replicas": 3}


def test_identical_image_no_drift():
    declared = resources_from_manifests([_deployment("nginx:1.27")])
    observed = observed_resources_from_kubectl([_deployment("nginx:1.27")])
    assert reconcile_k8s(declared, observed) == []


def test_declared_not_in_cluster_is_added():
    declared = resources_from_manifests([_deployment("nginx:1.27")])
    drifts = reconcile_k8s(declared, [])
    assert len(drifts) == 1
    assert drifts[0].change_type == ChangeType.ADDED
    assert drifts[0].identity == "apps/Deployment/prod/web"


def test_cluster_not_declared_is_removed():
    observed = observed_resources_from_kubectl([_deployment("nginx:1.27")])
    drifts = reconcile_k8s([], observed)
    assert len(drifts) == 1
    assert drifts[0].change_type == ChangeType.REMOVED
    assert drifts[0].identity == "apps/Deployment/prod/web"


def test_non_workload_no_false_drift():
    # A Service present on both sides has empty props -> reconciles on presence only.
    declared = resources_from_manifests([_service()])
    observed = observed_resources_from_kubectl([_service()])
    assert reconcile_k8s(declared, observed) == []


def test_no_image_pod_compared_on_presence():
    # A Pod whose container has no image (e.g. mid-render) carries no drift-relevant props -> no
    # drift purely from a missing image, as long as it's present on both sides. (The compliance
    # posture projection rides along but is stripped before reconcile, so it can't manufacture one.)
    pod = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"namespace": "prod", "name": "p"},
        "spec": {"containers": [{"name": "c"}]},
    }
    declared = resources_from_manifests([pod])
    observed = observed_resources_from_kubectl([pod])
    assert "images" not in declared[0].properties and "replicas" not in declared[0].properties
    assert reconcile_k8s(declared, observed) == []


def test_three_input_shapes_normalize():
    dep = _deployment("nginx:1.27")

    as_list = resources_from_manifests({"kind": "List", "items": [dep]})
    as_array = resources_from_manifests([dep])
    as_single = resources_from_manifests(dep)

    ids = {r.identity for r in as_list}
    assert ids == {r.identity for r in as_array} == {r.identity for r in as_single}
    assert ids == {"apps/Deployment/prod/web"}
    assert len(as_list) == len(as_array) == len(as_single) == 1


def _risky_pod(name: str = "web") -> dict:
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"namespace": "prod", "name": name},
        "spec": {
            "hostPID": True,
            "containers": [
                {"name": "c", "image": "app:1", "securityContext": {"privileged": True}}
            ],
        },
    }


def test_clean_manifest_has_no_security_key():
    res = resources_from_manifests([_deployment("nginx:1.27")])[0]
    assert "security" not in res.properties  # affirmative-only -> clean stays clean


def test_security_posture_projected_for_a_risky_pod():
    res = resources_from_manifests([_risky_pod()])[0]
    assert res.properties["security"] == {"privileged": True, "host_pid": True}


def test_security_projection_never_shows_as_drift():
    # The same risky pod on both sides: posture is declared-only and stripped before reconcile,
    # so presence + image match -> zero drift (the projection can't manufacture a MODIFIED).
    declared = resources_from_manifests([_risky_pod()])
    observed = observed_resources_from_kubectl([_risky_pod()])
    assert "security" in declared[0].properties and "security" not in observed[0].properties
    assert reconcile_k8s(declared, observed) == []


def test_source_satisfies_protocols_and_collects_drift():
    source = KubernetesSource(
        declared=[_deployment("nginx:1.28")],
        observed={"kind": "List", "items": [_deployment("nginx:1.27")]},
    )
    assert isinstance(source, StateSource)
    assert isinstance(source, ObservedSource)
    assert source.name == "kubernetes"

    drifts = source.collect_drift()
    assert len(drifts) == 1
    assert drifts[0].change_type == ChangeType.MODIFIED


def test_source_requires_declared():
    source = KubernetesSource()
    try:
        source.collect_declared()
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError without a declared document")


def test_source_requires_observed_or_get_args():
    source = KubernetesSource(declared=[_deployment("nginx:1.27")])
    try:
        source.collect_observed()
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError without observed or get_args")


# -- the live cluster-health source (k8s-live) ------------------------------------------------


def test_live_source_emits_workloads_as_zero_drift():
    # declared == observed by construction -> no drift; the signal is health (the probe), not drift.
    src = KubernetesLiveSource(observed={"kind": "List", "items": [_deployment("nginx:1.27")]})
    assert isinstance(src, DriftSource) and isinstance(src, StateSource)
    assert src.collect_drift() == []
    resources = src.collect_declared()
    assert [r.identity for r in resources] == ["apps/Deployment/prod/web"]
    # provenance must be "kubernetes" so the kubectl probe (which filters on it) checks them.
    assert resources[0].provenance.source == "kubernetes"


def test_live_source_projects_security_posture_for_cis_audit():
    # The differentiated half: the live workloads carry the security posture (unlike the drift-path
    # observed projection), so the CIS standing-policy pass can audit what is ACTUALLY RUNNING.
    src = KubernetesLiveSource(observed={"kind": "List", "items": [_risky_pod()]})
    [res] = src.collect_declared()
    assert res.properties["security"] == {"privileged": True, "host_pid": True}
    assert src.collect_drift() == []  # still zero drift -- the projection can't manufacture one


def test_live_source_threads_context_into_kubectl(monkeypatch):
    seen = {}

    def fake_run_tool(argv, **kwargs):
        seen["argv"] = argv
        return '{"items": []}'

    monkeypatch.setattr("steadystate.sources.k8s.run_tool", fake_run_tool)
    src = KubernetesLiveSource()  # no injected observed -> reads live
    src.use_context("prod-cluster")
    src.collect_declared()
    assert seen["argv"][:2] == ["kubectl", "get"]
    assert "--all-namespaces" in seen["argv"]
    assert seen["argv"][-2:] == ["--context", "prod-cluster"]


def test_live_source_no_context_omits_the_flag(monkeypatch):
    seen = {}

    def fake_run_tool(argv, **kwargs):
        seen["argv"] = argv
        return '{"kind": "List", "items": []}'

    monkeypatch.setattr("steadystate.sources.k8s.run_tool", fake_run_tool)
    KubernetesLiveSource().collect_declared()  # ambient current-context
    assert "--context" not in seen["argv"]


def test_live_source_is_observe_only():
    assert KubernetesLiveSource.commands.destructive == ()


def test_live_source_qualifies_identity_with_context():
    # With a context set, identities are prefixed so the same workload on two clusters is two
    # distinct findings in a shared store (the fleet sweep reconciles many clusters into one db).
    src = KubernetesLiveSource(observed={"kind": "List", "items": [_deployment("nginx:1")]})
    src.use_context("prod-cluster")
    [r] = src.collect_declared()
    assert r.identity == "prod-cluster/apps/Deployment/prod/web"
    assert r.provenance.address == r.identity  # the address tracks the qualified identity


def test_live_source_sanitizes_slashes_in_context():
    # A '/' in the context (an EKS ARN) must not add a phantom path segment -- that would shift the
    # probe's namespace/name parse (the last two '/'-segments).
    src = KubernetesLiveSource(observed={"kind": "List", "items": [_deployment("nginx:1")]})
    src.use_context("arn:aws:eks:us-east-1:1:cluster/prod")
    [r] = src.collect_declared()
    assert r.identity == "arn:aws:eks:us-east-1:1:cluster_prod/apps/Deployment/prod/web"


# -- the baseline source (k8s-baseline): config drift vs a captured snapshot -------------------


def test_baseline_no_baseline_yields_no_drift():
    from steadystate.sources.k8s import KubernetesBaselineSource

    # No baseline captured -> nothing to diff against yet (health still works via the probe).
    src = KubernetesBaselineSource(observed={"kind": "List", "items": [_deployment("nginx:1")]})
    assert src.collect_drift() == []


def test_baseline_reports_image_change_as_drift():
    from steadystate.sources.k8s import KubernetesBaselineSource

    baseline = {"kind": "List", "items": [_deployment("nginx:1.27")]}
    live = {"kind": "List", "items": [_deployment("nginx:1.28")]}  # image bumped since the baseline
    src = KubernetesBaselineSource(baseline=baseline, observed=live)
    [drift] = src.collect_drift()
    assert drift.change_type == ChangeType.MODIFIED
    assert drift.identity == "apps/Deployment/prod/web"


def test_baseline_ignores_replicas_to_avoid_hpa_noise():
    from steadystate.sources.k8s import KubernetesBaselineSource

    # Same image, only replicas differ (HPA churn) -> NOT drift (compared on presence + images).
    baseline = {"kind": "List", "items": [_deployment("nginx:1.27", replicas=3)]}
    live = {"kind": "List", "items": [_deployment("nginx:1.27", replicas=9)]}
    assert KubernetesBaselineSource(baseline=baseline, observed=live).collect_drift() == []


def test_baseline_new_and_removed_workloads():
    from steadystate.sources.k8s import KubernetesBaselineSource

    baseline = {"kind": "List", "items": [_deployment("nginx:1", name="web")]}
    live = {"kind": "List", "items": [_deployment("nginx:1", name="api")]}  # web gone, api appeared
    changes = {
        d.change_type
        for d in KubernetesBaselineSource(baseline=baseline, observed=live).collect_drift()
    }
    assert ChangeType.ADDED in changes and ChangeType.REMOVED in changes


def test_baseline_qualifies_drift_identity_with_context():
    from steadystate.sources.k8s import KubernetesBaselineSource

    src = KubernetesBaselineSource(
        baseline={"kind": "List", "items": [_deployment("nginx:1.27")]},
        observed={"kind": "List", "items": [_deployment("nginx:1.28")]},
    )
    src.use_context("prod-cluster")
    [drift] = src.collect_drift()
    assert (
        drift.identity == "prod-cluster/apps/Deployment/prod/web"
    )  # cluster-distinct in the store


def test_capture_baseline_writes_the_snapshot(tmp_path, monkeypatch):
    from steadystate.sources import k8s as k8smod

    monkeypatch.chdir(tmp_path)
    workloads = {
        "kind": "List",
        "items": [_deployment("nginx:1"), _deployment("redis:7", name="cache")],
    }
    monkeypatch.setattr(k8smod, "run_tool", lambda argv, **kw: json.dumps(workloads))
    path, count = k8smod.capture_baseline("prod-cluster")
    assert count == 2
    assert path == k8smod.baseline_path("prod-cluster")
    assert path.exists() and json.loads(path.read_text())["items"]


def test_capture_baseline_passes_the_kubeconfig_and_keys_the_file_on_it(tmp_path, monkeypatch):
    from steadystate.sources import k8s as k8smod

    monkeypatch.chdir(tmp_path)
    captured: dict = {}

    def fake_run_tool(argv, **kw):
        captured["argv"] = argv
        return json.dumps({"kind": "List", "items": [_deployment("nginx:1")]})

    monkeypatch.setattr(k8smod, "run_tool", fake_run_tool)
    path, _ = k8smod.capture_baseline("prod", kubeconfig="/cwd/prod.kubeconfig")
    # the cwd kubeconfig is passed straight to kubectl (so an off-default-path context baselines)...
    argv = captured["argv"]
    assert "--kubeconfig" in argv and argv[argv.index("--kubeconfig") + 1] == "/cwd/prod.kubeconfig"
    # ...and the snapshot is keyed on it, distinct from the ambient-kubeconfig name.
    assert path == k8smod.baseline_path("prod", "/cwd/prod.kubeconfig")
    assert path != k8smod.baseline_path("prod")


def test_baseline_path_distinguishes_a_shared_context_across_kubeconfigs():
    from steadystate.sources.k8s import baseline_path

    # The collision this prevents: two clusters with the SAME default context name in different
    # kubeconfigs would otherwise diff each against the other's workloads.
    a = baseline_path("kubernetes-admin@kubernetes", "/cwd/cluster-a.kubeconfig")
    b = baseline_path("kubernetes-admin@kubernetes", "/cwd/cluster-b.kubeconfig")
    assert a != b
    assert a == baseline_path("kubernetes-admin@kubernetes", "/cwd/cluster-a.kubeconfig")  # stable


def test_baseline_source_loads_its_kubeconfig_keyed_snapshot(tmp_path, monkeypatch):
    from steadystate.sources import k8s as k8smod

    monkeypatch.chdir(tmp_path)
    workloads = {"kind": "List", "items": [_deployment("nginx:1")]}
    monkeypatch.setattr(k8smod, "run_tool", lambda argv, **kw: json.dumps(workloads))
    k8smod.capture_baseline("prod", kubeconfig="/cwd/prod.kubeconfig")
    # a baseline source aimed at the SAME (context, kubeconfig) loads that snapshot -> live matches
    # the captured baseline -> no drift. (Proves capture + load share the keyed path.)
    src = k8smod.KubernetesBaselineSource()
    src.use_context("prod")
    src.use_kubeconfig("/cwd/prod.kubeconfig")
    assert src.collect_drift() == []


def test_baseline_corrupt_file_is_a_loud_error(tmp_path, monkeypatch):
    import pytest

    from steadystate.sources.base import SourceError
    from steadystate.sources.k8s import KubernetesBaselineSource, baseline_path

    monkeypatch.chdir(tmp_path)
    src = KubernetesBaselineSource()
    src.use_context("prod")
    p = baseline_path("prod")
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("{ not json")
    with pytest.raises(SourceError, match="unreadable"):
        src.collect_drift()


def test_cli_baseline_captures_for_a_targets_context(tmp_path, monkeypatch):
    from typer.testing import CliRunner

    from steadystate.cli import app
    from steadystate.sources import k8s as k8smod
    from steadystate.targets import TARGETS_ENV

    monkeypatch.chdir(tmp_path)
    (tmp_path / "t.json").write_text(
        json.dumps({"prod": {"source": "k8s-live", "context": "prod-cluster"}})
    )
    monkeypatch.setenv(TARGETS_ENV, str(tmp_path / "t.json"))
    monkeypatch.setattr(
        k8smod,
        "run_tool",
        lambda argv, **kw: json.dumps({"kind": "List", "items": [_deployment("nginx:1")]}),
    )
    result = CliRunner().invoke(app, ["baseline", "prod"])
    assert result.exit_code == 0, result.output
    assert "baseline captured: 1 workload" in result.output
    assert k8smod.baseline_path("prod-cluster").exists()


def test_cli_baseline_rejects_a_target_without_a_context(tmp_path, monkeypatch):
    from typer.testing import CliRunner

    from steadystate.cli import app
    from steadystate.targets import TARGETS_ENV

    monkeypatch.chdir(tmp_path)
    (tmp_path / "t.json").write_text(json.dumps({"demo": {"source": "k8s", "path": "snap.json"}}))
    monkeypatch.setenv(TARGETS_ENV, str(tmp_path / "t.json"))
    result = CliRunner().invoke(app, ["baseline", "demo"], env={"COLUMNS": "200", "NO_COLOR": "1"})
    assert result.exit_code != 0
    assert "no context" in result.output
