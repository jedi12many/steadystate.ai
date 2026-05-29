from steadystate.model import ChangeType
from steadystate.sources.argocd import ArgoCDSource, drifts_from_argocd_app

_APP = {
    "metadata": {"name": "guestbook"},
    "status": {
        "resources": [
            {
                "group": "apps",
                "kind": "Deployment",
                "namespace": "guestbook",
                "name": "frontend",
                "status": "OutOfSync",
            },
            {
                "group": "",
                "kind": "Service",
                "namespace": "guestbook",
                "name": "frontend",
                "status": "Synced",
            },
            {
                "group": "rbac.authorization.k8s.io",
                "kind": "ClusterRole",
                "name": "guestbook-admin",
                "status": "OutOfSync",
            },
        ],
    },
}


def test_only_out_of_sync_become_drift():
    drifts = drifts_from_argocd_app(_APP)
    assert len(drifts) == 2  # the Synced Service is excluded

    by_id = {d.identity: d for d in drifts}
    assert "apps/Deployment/guestbook/frontend" in by_id
    assert "rbac.authorization.k8s.io/ClusterRole/guestbook-admin" in by_id  # cluster-scoped: no namespace

    d = by_id["apps/Deployment/guestbook/frontend"]
    assert d.kind == "Deployment"
    assert d.change_type is ChangeType.MODIFIED
    assert d.provenance.source == "argocd"
    assert d.observed == {"status": "OutOfSync"}


def test_source_takes_app_dict_directly():
    drifts = ArgoCDSource(app=_APP).collect_drift()
    assert {d.identity for d in drifts} == {
        "apps/Deployment/guestbook/frontend",
        "rbac.authorization.k8s.io/ClusterRole/guestbook-admin",
    }


def test_empty_status_yields_no_drift():
    assert drifts_from_argocd_app({}) == []
    assert drifts_from_argocd_app({"status": {}}) == []
