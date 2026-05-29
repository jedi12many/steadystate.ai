"""The generic reconciler + the docker-compose reconcile (presence + image tag)."""

from steadystate.model import ChangeType, Provenance, Resource
from steadystate.reconcile import reconcile
from steadystate.sources.docker_compose import (
    DockerComposeSource,
    observed_resources_from_ps,
    reconcile_compose,
)


def _res(identity: str, image: str | None = None, **props) -> Resource:
    p = dict(props)
    if image is not None:
        p["image"] = image
    return Resource(
        kind="docker_compose_service",
        identity=identity,
        provenance=Provenance(source="docker-compose", address=identity),
        properties=p,
    )


# --- generic reconcile() ----------------------------------------------------


def test_reconcile_added_when_declared_not_observed():
    drifts = reconcile([_res("web", image="nginx:1")], [])
    assert len(drifts) == 1
    assert drifts[0].change_type is ChangeType.ADDED
    assert drifts[0].identity == "web"


def test_reconcile_removed_when_observed_not_declared():
    drifts = reconcile([], [_res("stray", image="redis:7")])
    assert len(drifts) == 1
    assert drifts[0].change_type is ChangeType.REMOVED


def test_reconcile_modified_when_properties_differ():
    drifts = reconcile([_res("web", image="nginx:1.27")], [_res("web", image="nginx:1.19")])
    assert len(drifts) == 1
    assert drifts[0].change_type is ChangeType.MODIFIED
    assert drifts[0].declared == {"image": "nginx:1.27"}
    assert drifts[0].observed == {"image": "nginx:1.19"}


def test_reconcile_quiet_when_matching():
    assert reconcile([_res("web", image="nginx:1.27")], [_res("web", image="nginx:1.27")]) == []


# --- observed_resources_from_ps --------------------------------------------


def test_observed_from_ps_uses_service_name_as_identity():
    obs = observed_resources_from_ps(
        [{"Service": "web", "Image": "nginx:1.27", "State": "running"}]
    )
    assert len(obs) == 1
    assert obs[0].identity == "web"
    assert obs[0].properties["image"] == "nginx:1.27"


def test_observed_from_ps_skips_nameless_entries():
    assert observed_resources_from_ps([{"Image": "x"}]) == []


# --- reconcile_compose (presence + image tag) ------------------------------


def test_compose_declared_service_not_running_is_added():
    declared = [_res("web", image="nginx:1.27"), _res("db", image="postgres:16")]
    observed = [_res("web", image="nginx:1.27")]  # db is not running
    drifts = {d.identity: d for d in reconcile_compose(declared, observed)}
    assert set(drifts) == {"db"}
    assert drifts["db"].change_type is ChangeType.ADDED


def test_compose_image_mismatch_is_modified():
    drifts = reconcile_compose([_res("web", image="nginx:1.27")], [_res("web", image="nginx:1.19")])
    assert len(drifts) == 1
    assert drifts[0].change_type is ChangeType.MODIFIED


def test_compose_extra_running_container_is_removed():
    declared = [_res("web", image="nginx:1.27")]
    observed = [_res("web", image="nginx:1.27"), _res("rogue", image="malware:latest")]
    drifts = {d.identity: d for d in reconcile_compose(declared, observed)}
    assert drifts["rogue"].change_type is ChangeType.REMOVED


def test_compose_build_only_service_has_no_false_image_drift():
    # Declared with no image (built locally); running with a concrete local image.
    declared = [_res("app")]
    observed = [_res("app", image="myproject-app:latest")]
    assert reconcile_compose(declared, observed) == []  # presence matches; image ignored


def test_compose_all_matching_is_quiet():
    assert (
        reconcile_compose([_res("web", image="nginx:1.27")], [_res("web", image="nginx:1.27")])
        == []
    )


# --- end to end through the source (captured config + ps, no Docker) -------


def test_source_collect_drift_from_captured_config_and_ps():
    config = {"services": {"web": {"image": "nginx:1.27"}, "db": {"image": "postgres:16"}}}
    ps = [{"Service": "web", "Image": "nginx:1.19", "State": "running"}]  # web drifted, db down
    source = DockerComposeSource(config=config, ps=ps)
    drifts = {d.identity: d.change_type for d in source.collect_drift()}
    assert drifts == {"web": ChangeType.MODIFIED, "db": ChangeType.ADDED}
