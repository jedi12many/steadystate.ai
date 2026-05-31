from steadystate.model import ChangeType
from steadystate.sources.helm import HelmSource, drifts_from_helm_releases

# A captured `helm list --output json --all-namespaces`: one healthy release and four kinds of
# departure from steady state.
_RELEASES = [
    {
        "name": "ingress-nginx",
        "namespace": "ingress",
        "status": "deployed",
        "chart": "ingress-nginx-4.11.0",
        "revision": "3",
    },
    {
        "name": "prometheus",
        "namespace": "monitoring",
        "status": "failed",
        "chart": "kube-prometheus-stack-61.3.0",
        "revision": "7",
    },
    {
        "name": "redis",
        "namespace": "cache",
        "status": "pending-upgrade",
        "chart": "redis-19.6.0",
        "revision": "4",
    },
    {
        "name": "loki",
        "namespace": "monitoring",
        "status": "pending-install",
        "chart": "loki-6.6.0",
        "revision": "1",
    },
    {
        "name": "old-app",
        "namespace": "default",
        "status": "uninstalling",
        "chart": "old-app-1.0.0",
        "revision": "12",
    },
]


def test_only_non_deployed_releases_become_drift():
    drifts = drifts_from_helm_releases(_RELEASES)
    assert len(drifts) == 4  # the deployed ingress-nginx is excluded


def test_failed_release_is_one_modified_drift():
    by_id = {d.identity: d for d in drifts_from_helm_releases(_RELEASES)}
    d = by_id["monitoring/prometheus"]
    assert d.kind == "HelmRelease"
    assert d.change_type is ChangeType.MODIFIED
    assert d.provenance.source == "helm"
    assert d.observed == {
        "status": "failed",
        "chart": "kube-prometheus-stack-61.3.0",
        "revision": "7",
    }


def test_pending_upgrade_is_modified():
    by_id = {d.identity: d for d in drifts_from_helm_releases(_RELEASES)}
    assert by_id["cache/redis"].change_type is ChangeType.MODIFIED


def test_pending_install_is_added():
    by_id = {d.identity: d for d in drifts_from_helm_releases(_RELEASES)}
    assert by_id["monitoring/loki"].change_type is ChangeType.ADDED


def test_uninstalling_is_removed():
    by_id = {d.identity: d for d in drifts_from_helm_releases(_RELEASES)}
    assert by_id["default/old-app"].change_type is ChangeType.REMOVED


def test_status_match_is_case_insensitive():
    drifts = drifts_from_helm_releases([{"name": "x", "namespace": "y", "status": "DEPLOYED"}])
    assert drifts == []


def test_identity_falls_back_to_name_when_namespace_absent():
    drifts = drifts_from_helm_releases([{"name": "cluster-wide", "status": "failed"}])
    assert drifts[0].identity == "cluster-wide"


def test_source_takes_releases_directly():
    drifts = HelmSource(releases=_RELEASES).collect_drift()
    assert {d.identity for d in drifts} == {
        "monitoring/prometheus",
        "cache/redis",
        "monitoring/loki",
        "default/old-app",
    }


def test_empty_release_list_yields_no_drift():
    assert drifts_from_helm_releases([]) == []
    assert HelmSource(releases=[]).collect_drift() == []
