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
    assert res.properties == {"images": ["nginx:1.27"], "replicas": 3}


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
    # A Pod whose container has no image (e.g. mid-render) projects to {} -> no drift
    # purely from a missing image, as long as it's present on both sides.
    pod = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"namespace": "prod", "name": "p"},
        "spec": {"containers": [{"name": "c"}]},
    }
    declared = resources_from_manifests([pod])
    observed = observed_resources_from_kubectl([pod])
    assert declared[0].properties == {}
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
