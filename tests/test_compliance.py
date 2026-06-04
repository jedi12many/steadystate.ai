"""The CIS compliance report -- grouping policy findings into a benchmark view, plus the CLI."""

from __future__ import annotations

import json

from typer.testing import CliRunner

from steadystate.cli import app
from steadystate.compliance import cis_report, cis_report_as_dict, render_cis_report
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


# -- the pure report --------------------------------------------------------------------------


def test_cis_report_groups_by_control_worst_first():
    findings = [
        _pf("ns/a", "k8s-privileged", Severity.HIGH, [_cis("Kubernetes-5.2.1", "no privileged")]),
        _pf("ns/b", "k8s-privileged", Severity.HIGH, [_cis("Kubernetes-5.2.1", "no privileged")]),
        _pf("ns/a", "k8s-host-net", Severity.MEDIUM, [_cis("Kubernetes-5.2.4", "no hostNetwork")]),
    ]
    results = cis_report(findings, level=1)
    assert [r.control_id for r in results] == ["Kubernetes-5.2.1", "Kubernetes-5.2.4"]  # worst 1st
    assert results[0].resources == ("ns/a", "ns/b")  # both resources failing the control, deduped
    assert results[0].severity == Severity.HIGH


def test_cis_report_filters_by_level():
    findings = [
        _pf("ns/a", "r1", Severity.HIGH, [_cis("Kubernetes-5.2.1", "L1 control", level=1)]),
        _pf("ns/a", "r2", Severity.LOW, [_cis("Kubernetes-5.7.2", "L2 control", level=2)]),
    ]
    assert [r.control_id for r in cis_report(findings, level=1)] == ["Kubernetes-5.2.1"]
    assert len(cis_report(findings, level=None)) == 2  # None -> every CIS level


def test_cis_report_ignores_non_cis_references():
    mitre = Reference(framework="MITRE", id="T1611", name="Escape to Host")
    assert cis_report([_pf("ns/a", "r", Severity.HIGH, [mitre])], level=1) == []


def test_render_all_clear_and_json_shape():
    assert "no failures" in render_cis_report([], level=1)[0]
    findings = [_pf("ns/a", "r", Severity.HIGH, [_cis("Kubernetes-5.2.1", "no privileged")])]
    results = cis_report(findings, level=1)
    text = "\n".join(render_cis_report(results, level=1))
    assert "CIS Level 1" in text and "Kubernetes-5.2.1" in text and "ns/a" in text
    doc = cis_report_as_dict(results, level=1)
    assert doc["level"] == 1 and doc["controls_failing"] == 1 and doc["resources_affected"] == 1
    assert doc["controls"][0]["id"] == "Kubernetes-5.2.1"


# -- the CLI command, live ---------------------------------------------------------------------

_PRIVILEGED_WORKLOAD = {
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


def test_compliance_cli_audits_live_cluster_posture(monkeypatch):
    monkeypatch.setattr(
        "steadystate.sources.k8s.run_tool", lambda argv, **kw: json.dumps(_PRIVILEGED_WORKLOAD)
    )
    result = CliRunner().invoke(app, ["compliance", "--source", "k8s-live", "--context", "prod"])
    assert result.exit_code == 0, result.output
    assert "CIS Level 1" in result.output
    assert "Kubernetes-5.2.1" in result.output and "Kubernetes-5.2.4" in result.output
    assert "prod/risky" in result.output  # the actually-running workload that fails


def test_compliance_cli_json(monkeypatch):
    monkeypatch.setattr(
        "steadystate.sources.k8s.run_tool", lambda argv, **kw: json.dumps(_PRIVILEGED_WORKLOAD)
    )
    result = CliRunner().invoke(
        app, ["compliance", "--source", "k8s-live", "--context", "prod", "--json"]
    )
    assert result.exit_code == 0, result.output
    doc = json.loads(result.output)
    assert doc["framework"] == "CIS" and doc["level"] == 1
    assert {c["id"] for c in doc["controls"]} == {"Kubernetes-5.2.1", "Kubernetes-5.2.4"}
