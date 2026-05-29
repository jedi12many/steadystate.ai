"""Unit tests for the Docker compliance pack (standing CIS-Docker baseline) and the
PolicyFinding value type it emits."""

from __future__ import annotations

import dataclasses

import pytest

from steadystate.domains import PolicyFinding, evaluate_with
from steadystate.domains.compliance import DockerComplianceDomain
from steadystate.model import ChangeType, Drift, Provenance, Resource
from steadystate.reason.alert import Severity

PACK = DockerComplianceDomain()


def _service(name: str = "web", **props: object) -> Resource:
    return Resource(
        kind="docker_compose_service",
        identity=name,
        provenance=Provenance(source="docker-compose", address=name),
        properties=props,
    )


def _rules(resource: Resource) -> dict[str, PolicyFinding]:
    return {f.rule_id: f for f in PACK.evaluate([resource])}


# -- the "clean" baseline + per-rule fire/silent --------------------------------


def test_hardened_service_produces_no_findings():
    clean = _service(image="nginx:1.25.3", user="1000", security_opt=["no-new-privileges:true"])
    assert PACK.evaluate([clean]) == []


def test_privileged_is_high_and_cites_cis_and_mitre():
    finding = _rules(_service(privileged=True))["docker-privileged"]
    assert finding.severity is Severity.HIGH
    frameworks = {r.framework for r in finding.references}
    assert {"CIS", "MITRE"} <= frameworks


def test_privileged_false_is_silent():
    assert "docker-privileged" not in _rules(_service(privileged=False))


def test_host_network_is_medium():
    assert _rules(_service(network_mode="host"))["docker-host-network"].severity is Severity.MEDIUM


def test_host_pid_is_medium():
    assert _rules(_service(pid="host"))["docker-host-pid"].severity is Severity.MEDIUM


def test_added_capabilities_is_medium_and_names_them():
    finding = _rules(_service(cap_add=["NET_ADMIN", "SYS_TIME"]))["docker-added-capabilities"]
    assert finding.severity is Severity.MEDIUM
    assert "NET_ADMIN" in finding.title


def test_missing_no_new_privileges_is_low():
    assert _rules(_service())["docker-no-new-privileges-missing"].severity is Severity.LOW


def test_no_new_privileges_set_is_silent():
    rules = _rules(_service(security_opt=["no-new-privileges:true"]))
    assert "docker-no-new-privileges-missing" not in rules


def test_root_user_unset_is_flagged_low():
    assert _rules(_service())["docker-root-user"].severity is Severity.LOW


def test_non_root_user_is_silent():
    assert "docker-root-user" not in _rules(_service(user="1000"))


def test_latest_image_is_unpinned():
    assert "docker-image-unpinned" in _rules(_service(image="nginx:latest"))


def test_implicit_tag_image_is_unpinned():
    assert "docker-image-unpinned" in _rules(_service(image="nginx"))


def test_tagged_image_is_pinned_enough():
    assert "docker-image-unpinned" not in _rules(_service(image="nginx:1.25.3"))


def test_digest_pinned_image_is_silent():
    assert "docker-image-unpinned" not in _rules(_service(image="nginx@sha256:abc123"))


# -- scoping --------------------------------------------------------------------


def test_non_compose_resource_is_ignored():
    other = Resource(kind="aws_s3_bucket", identity="b", provenance=Provenance(source="terraform"))
    assert PACK.evaluate([other]) == []


def test_score_never_flags_drift():
    # A baseline pack: it generates findings via evaluate, never scores a drift.
    drift = Drift(
        identity="web",
        kind="docker_compose_service",
        change_type=ChangeType.MODIFIED,
        provenance=Provenance(source="docker-compose"),
    )
    assert PACK.score(drift) is None


# -- the optional-capability seam -----------------------------------------------


def test_evaluate_with_probes_the_pack():
    findings = evaluate_with(PACK, [_service(privileged=True)])
    assert any(f.rule_id == "docker-privileged" for f in findings)


def test_evaluate_with_returns_empty_for_a_pack_without_evaluate():
    class Bare:
        name = "bare"

    assert evaluate_with(Bare(), [_service(privileged=True)]) == []


# -- PolicyFinding value semantics ----------------------------------------------


def _pf(rule_id: str, severity: Severity = Severity.LOW, title: str = "t") -> PolicyFinding:
    return PolicyFinding(
        rule_id=rule_id,
        identity="web",
        provenance=Provenance(source="docker-compose", address="web"),
        severity=severity,
        title=title,
        detail="d",
    )


def test_fingerprint_is_stable_under_severity_and_title_churn():
    assert _pf("r1").fingerprint == _pf("r1", severity=Severity.HIGH, title="other").fingerprint


def test_fingerprint_differs_per_rule():
    assert _pf("r1").fingerprint != _pf("r2").fingerprint


def test_policy_finding_is_frozen():
    finding = _pf("r1")
    with pytest.raises(dataclasses.FrozenInstanceError):
        finding.rule_id = "mutated"  # type: ignore[misc]
