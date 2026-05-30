from steadystate.model import ChangeType
from steadystate.sources.base import ObservedSource, StateSource
from steadystate.sources.k8s import (
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
