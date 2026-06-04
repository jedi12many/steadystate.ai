"""The stacked compliance report -- grouping policy + posture findings into one benchmark view."""

from __future__ import annotations

import json

from typer.testing import CliRunner

from steadystate.cli import app
from steadystate.compliance import (
    DISCLAIMER,
    compliance_report,
    compliance_report_as_dict,
    render_compliance_report,
)
from steadystate.domains.base import PolicyFinding, Reference
from steadystate.model import Provenance
from steadystate.reason.alert import Severity


def _pf(identity: str, rule_id: str, sev: Severity, refs: list[Reference]) -> PolicyFinding:
    return PolicyFinding(
        rule_id=rule_id,
        identity=identity,
        provenance=Provenance(source="kubernetes", address=identity),
        severity=sev,
        title=f"{identity} fails {rule_id}",
        detail="why",
        references=refs,
    )


def _cis(control_id: str, name: str, level: int = 1) -> Reference:
    return Reference(framework="CIS", id=control_id, name=name, level=level)


def _stig(control_id: str, name: str) -> Reference:
    return Reference(framework="STIG", id=control_id, name=name)  # STIG has no CIS-style level


# -- the stacked report -----------------------------------------------------------------------


def test_report_groups_by_check_citing_every_framework_and_level():
    # The same check cited by CIS (L1) AND STIG stacks onto one row -- not two separate controls.
    refs = [_cis("Kubernetes-5.2.1", "no privileged"), _stig("V-242400", "no privileged")]
    findings = [
        _pf("ns/a", "k8s-privileged", Severity.HIGH, refs),
        _pf("ns/b", "k8s-privileged", Severity.HIGH, refs),
        _pf("ns/a", "k8s-seccomp", Severity.LOW, [_cis("Kubernetes-5.7.2", "seccomp", level=2)]),
    ]
    results = compliance_report(findings)  # default: all frameworks + levels stacked
    assert [r.rule_id for r in results] == ["k8s-privileged", "k8s-seccomp"]  # worst-first
    assert {(c.framework, c.id) for c in results[0].controls} == {
        ("CIS", "Kubernetes-5.2.1"),
        ("STIG", "V-242400"),
    }  # one check, both frameworks cited
    assert results[0].resources == ("ns/a", "ns/b")  # both failing resources, deduped


def test_report_filters_by_level_and_framework():
    findings = [
        _pf("ns/a", "r1", Severity.HIGH, [_cis("Kubernetes-5.2.1", "L1")]),
        _pf("ns/a", "r2", Severity.LOW, [_cis("Kubernetes-5.7.2", "L2", level=2)]),
        _pf("ns/a", "r3", Severity.HIGH, [_stig("V-242400", "stig only")]),
    ]
    assert {r.rule_id for r in compliance_report(findings)} == {"r1", "r2", "r3"}  # all stacked
    assert {r.rule_id for r in compliance_report(findings, level=1)} == {"r1", "r3"}  # L1 + STIG
    assert {r.rule_id for r in compliance_report(findings, level=2)} == {"r2", "r3"}  # L2 + STIG
    assert {r.rule_id for r in compliance_report(findings, framework="stig")} == {"r3"}
    assert {r.rule_id for r in compliance_report(findings, framework="cis")} == {"r1", "r2"}


def test_report_ignores_non_benchmark_references():
    mitre = Reference(framework="MITRE", id="T1611", name="Escape to Host")
    assert compliance_report([_pf("ns/a", "r", Severity.HIGH, [mitre])]) == []


def test_render_includes_disclaimer_and_caps_resources():
    findings = [
        _pf(f"ns/{i}", "k8s-seccomp", Severity.LOW, [_cis("Kubernetes-5.7.2", "seccomp", level=2)])
        for i in range(15)
    ]
    text = "\n".join(render_compliance_report(compliance_report(findings), max_resources=10))
    assert DISCLAIMER in text  # the scope disclaimer prints on every report
    assert "Kubernetes-5.7.2 (L2)" in text  # the level chip
    assert "and 5 more" in text  # the resource list is capped
    # an all-clear still carries the disclaimer
    assert DISCLAIMER in "\n".join(render_compliance_report([]))


def test_json_shape():
    refs = [_cis("Kubernetes-5.2.1", "no privileged"), _stig("V-242400", "no privileged")]
    doc = compliance_report_as_dict(
        compliance_report([_pf("ns/a", "k8s-privileged", Severity.HIGH, refs)])
    )
    assert doc["checks_failing"] == 1 and doc["resources_affected"] == 1
    assert doc["checks"][0]["rule_id"] == "k8s-privileged"
    assert {c["framework"] for c in doc["checks"][0]["controls"]} == {"CIS", "STIG"}


# -- the CLI command, live ---------------------------------------------------------------------

_RISKY_WORKLOAD = {
    "kind": "List",
    "items": [
        {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"namespace": "prod", "name": "risky"},
            "spec": {
                "template": {
                    "spec": {
                        "hostNetwork": True,
                        "containers": [
                            {"image": "risky:1", "securityContext": {"privileged": True}}
                        ],
                    }
                }
            },
        }
    ],
}


def test_compliance_cli_stacks_l1_and_l2_from_live(monkeypatch):
    monkeypatch.setattr(
        "steadystate.sources.k8s.run_tool", lambda argv, **kw: json.dumps(_RISKY_WORKLOAD)
    )
    result = CliRunner().invoke(app, ["compliance", "--source", "k8s-live", "--context", "prod"])
    assert result.exit_code == 0, result.output
    assert "Kubernetes-5.2.1 (L1)" in result.output  # an affirmative L1 control
    assert "Kubernetes-5.7.2 (L2)" in result.output  # a compliance-only L2 posture gap
    assert "prod/risky" in result.output
    assert "node access" in result.output  # the disclaimer


def test_compliance_cli_json_and_level_filter(monkeypatch):
    monkeypatch.setattr(
        "steadystate.sources.k8s.run_tool", lambda argv, **kw: json.dumps(_RISKY_WORKLOAD)
    )
    result = CliRunner().invoke(
        app, ["compliance", "--source", "k8s-live", "--context", "prod", "--level", "2", "--json"]
    )
    assert result.exit_code == 0, result.output
    doc = json.loads(result.output)
    assert doc["level"] == 2
    ids = {ctrl["id"] for check in doc["checks"] for ctrl in check["controls"]}
    assert "Kubernetes-5.7.2" in ids and "Kubernetes-5.2.1" not in ids  # L2 only
