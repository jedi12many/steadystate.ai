from steadystate.model import ChangeType
from steadystate.sources.rancher import RancherSource, drifts_from_fleet_gitrepo

_GITREPO = {
    "metadata": {"name": "fleet-examples"},
    "status": {
        "resources": [
            {
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "namespace": "default",
                "name": "frontend",
                "state": "Modified",
            },
            {
                "apiVersion": "v1",
                "kind": "Service",
                "namespace": "default",
                "name": "frontend",
                "state": "Ready",
            },
            {
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "namespace": "default",
                "name": "app-config",
                "state": "Missing",
            },
            {
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "ClusterRole",
                "name": "fleet-admin",
                "state": "Orphaned",
            },
        ],
    },
}


def test_only_non_ready_become_drift():
    drifts = drifts_from_fleet_gitrepo(_GITREPO)
    assert len(drifts) == 3  # the Ready Service is excluded


def test_modified_resource_is_one_modified_drift():
    drifts = drifts_from_fleet_gitrepo(_GITREPO)
    by_id = {d.identity: d for d in drifts}

    d = by_id["apps/Deployment/default/frontend"]
    assert d.kind == "Deployment"
    assert d.change_type is ChangeType.MODIFIED
    assert d.provenance.source == "rancher"
    assert d.observed == {"state": "Modified"}


def test_missing_resource_is_added():
    by_id = {d.identity: d for d in drifts_from_fleet_gitrepo(_GITREPO)}
    d = by_id["ConfigMap/default/app-config"]  # core v1: empty group
    assert d.change_type is ChangeType.ADDED


def test_orphaned_resource_is_removed():
    by_id = {d.identity: d for d in drifts_from_fleet_gitrepo(_GITREPO)}
    d = by_id["rbac.authorization.k8s.io/ClusterRole/fleet-admin"]
    assert d.change_type is ChangeType.REMOVED


def test_identity_assembles_group_kind_namespace_name():
    by_id = {d.identity: d for d in drifts_from_fleet_gitrepo(_GITREPO)}
    # grouped, namespaced
    assert "apps/Deployment/default/frontend" in by_id
    # core v1 -> empty group, namespaced
    assert "ConfigMap/default/app-config" in by_id
    # cluster-scoped -> no namespace
    assert "rbac.authorization.k8s.io/ClusterRole/fleet-admin" in by_id


def test_source_takes_gitrepo_dict_directly():
    drifts = RancherSource(gitrepo=_GITREPO).collect_drift()
    assert {d.identity for d in drifts} == {
        "apps/Deployment/default/frontend",
        "ConfigMap/default/app-config",
        "rbac.authorization.k8s.io/ClusterRole/fleet-admin",
    }


def test_empty_status_yields_no_drift():
    assert drifts_from_fleet_gitrepo({}) == []
    assert drifts_from_fleet_gitrepo({"status": {}}) == []
    assert drifts_from_fleet_gitrepo({"status": {"resources": []}}) == []
