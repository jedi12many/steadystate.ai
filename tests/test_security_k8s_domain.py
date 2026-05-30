"""Unit tests for the Kubernetes security pack (standing Pod Security baseline)."""

from __future__ import annotations

from steadystate.domains import evaluate_with
from steadystate.domains.security_k8s import KubernetesSecurityDomain
from steadystate.model import ChangeType, Drift, Provenance, Resource
from steadystate.reason.alert import Severity

PACK = KubernetesSecurityDomain()


def _res(security: dict | None, *, identity: str = "apps/Deployment/prod/web", source="kubernetes"):
    props: dict = {"images": ["x:1"]}
    if security:
        props["security"] = security
    return Resource(
        kind="Deployment",
        identity=identity,
        provenance=Provenance(source=source, address=identity),
        properties=props,
    )


def _ids(findings) -> set[str]:
    return {f.rule_id for f in findings}


def _has_t1611(finding) -> bool:
    return any(r.id == "T1611" for r in finding.references)


# -- the pack is a baseline (evaluate), not a drift-scorer ----------------------


def test_score_always_none():
    drift = Drift(
        identity="x",
        kind="Pod",
        change_type=ChangeType.MODIFIED,
        provenance=Provenance(source="kubernetes"),
    )
    assert PACK.score(drift) is None


def test_evaluate_is_discovered_off_the_protocol():
    # evaluate_with probes for the optional capability, the way the pipeline does.
    assert evaluate_with(PACK, [_res({"privileged": True})])


# -- individual rules -----------------------------------------------------------


def test_privileged_is_high_with_escape_technique():
    [finding] = PACK.evaluate([_res({"privileged": True})])
    assert finding.rule_id == "k8s-privileged" and finding.severity is Severity.HIGH
    assert _has_t1611(finding)
    assert any(r.framework == "CIS" and r.id == "Kubernetes-5.2.1" for r in finding.references)


def test_dangerous_capability_escalates_to_high():
    [finding] = PACK.evaluate([_res({"added_capabilities": ["SYS_ADMIN"]})])
    assert finding.severity is Severity.HIGH and _has_t1611(finding)
    assert "SYS_ADMIN" in finding.title


def test_benign_capability_is_medium_without_escape_technique():
    [finding] = PACK.evaluate([_res({"added_capabilities": ["NET_BIND_SERVICE"]})])
    assert finding.severity is Severity.MEDIUM and not _has_t1611(finding)


def test_host_path_and_host_pid_carry_escape_technique():
    findings = PACK.evaluate([_res({"host_path_volumes": ["/"], "host_pid": True})])
    assert all(_has_t1611(f) for f in findings)


def test_low_severity_ubiquitous_rules():
    findings = PACK.evaluate([_res({"allow_privilege_escalation": True, "runs_as_root": True})])
    assert {f.severity for f in findings} == {Severity.LOW}


# -- coverage + isolation -------------------------------------------------------


def test_every_concern_yields_one_distinct_finding():
    security = {
        "privileged": True,
        "host_network": True,
        "host_pid": True,
        "host_ipc": True,
        "added_capabilities": ["SYS_PTRACE"],
        "host_path_volumes": ["/var/run"],
        "allow_privilege_escalation": True,
        "runs_as_root": True,
    }
    findings = PACK.evaluate([_res(security)])
    assert _ids(findings) == {
        "k8s-privileged",
        "k8s-host-network",
        "k8s-host-pid",
        "k8s-host-ipc",
        "k8s-added-capabilities",
        "k8s-host-path",
        "k8s-allow-privilege-escalation",
        "k8s-runs-as-root",
    }
    assert len({f.fingerprint for f in findings}) == len(findings)  # stable + distinct per rule


def test_clean_resource_yields_nothing():
    assert PACK.evaluate([_res(None)]) == []


def test_only_kubernetes_resources_are_evaluated():
    foreign = _res({"privileged": True}, source="docker-compose")
    assert PACK.evaluate([foreign]) == []


def test_finding_identity_and_title_use_the_resource():
    [finding] = PACK.evaluate([_res({"privileged": True})])
    assert finding.identity == "apps/Deployment/prod/web"
    assert "web" in finding.title  # the short name, not the full path
