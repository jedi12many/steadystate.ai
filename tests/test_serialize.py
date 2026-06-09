"""The canonical JSON serialization (`scan --json` / `probe --json`): a stable, machine-readable
report object -- pure serializer + the CLI wiring."""

from __future__ import annotations

import json

from steadystate.model import ChangeType, Drift, Provenance
from steadystate.probe.base import Symptom
from steadystate.reason.alert import Alert, Layer, Severity
from steadystate.reason.report import Report
from steadystate.reconcile_state import ResolvedFinding
from steadystate.serialize import alert_to_dict, report_to_dict


def _drift() -> Drift:
    return Drift(
        identity="aws_s3_bucket.logs",
        kind="aws_s3_bucket",
        change_type=ChangeType.MODIFIED,
        provenance=Provenance(source="terraform", address="aws_s3_bucket.logs"),
        declared={"acl": "private"},
        observed={"acl": "public-read"},
    )


def _drift_alert() -> Alert:
    return Alert(
        title="bucket drifted",
        severity=Severity.HIGH,
        drifts=[_drift()],
        why_it_matters="exposure changed",
        recommended_action="re-apply the declared ACL",
        layer=Layer.ALERT,
    )


# -- the pure serializer -------------------------------------------------------


def test_alert_to_dict_carries_reasoning_action_keys_and_before_after():
    d = alert_to_dict(_drift_alert())
    assert d["title"] == "bucket drifted" and d["severity"] == "high"
    assert d["why"] == "exposure changed"
    assert d["recommended_action"] == "re-apply the declared ACL"
    assert d["remediable"] is False  # honest: no executor wired in this test
    assert d["source"] == "terraform"
    assert d["fingerprints"] == [_drift().fingerprint]
    assert d["correlation_fingerprint"] is None
    assert d["changes"] == [
        {
            "identity": "aws_s3_bucket.logs",
            "change_type": "modified",
            "declared": {"acl": "private"},
            "observed": {"acl": "public-read"},
        }
    ]


def test_alert_to_dict_merges_symptom_evidence_and_group_fingerprint():
    symptom = Symptom(
        identity="prod/apps/Deployment/ns/web",
        kind="Deployment",
        category="CrashLoopBackOff",
        severity=Severity.HIGH,
        title="web is CrashLoopBackOff",
        detail="x",
        provenance=Provenance(source="kubernetes", address="x"),
        evidence={"namespace": "ns", "last_log": "boom"},
    )
    alert = Alert(
        title="web is CrashLoopBackOff in 2 place(s)",
        severity=Severity.HIGH,
        drifts=[],
        why_it_matters="grouped",
        layer=Layer.ALERT,
        symptoms=[symptom],
        correlation_fingerprint="c" * 64,
    )
    d = alert_to_dict(alert)
    assert d["evidence"] == {"namespace": "ns", "last_log": "boom"}  # the probe-captured fields
    assert d["correlation_fingerprint"] == "c" * 64
    assert d["changes"] == []  # a symptom alert has no declared->observed


def test_report_to_dict_summary_resolved_and_spend():
    resolved = [ResolvedFinding(fingerprint="f" * 64, title="old thing")]
    doc = report_to_dict(Report(items=[_drift_alert()]), resolved=resolved, spend={"usd": 0.01})
    assert doc["summary"] == {"alerts": 1, "signals": 0, "resolved": 1}
    assert doc["resolved"] == [{"fingerprint": "f" * 64, "title": "old thing"}]
    assert doc["spend"] == {"usd": 0.01}
    assert len(doc["alerts"]) == 1


def test_report_to_dict_is_json_serializable():
    json.dumps(report_to_dict(Report(items=[_drift_alert()])))  # declared/observed dicts included


# -- the CLI wiring ------------------------------------------------------------


def _plan(tmp_path) -> str:
    plan = tmp_path / "plan.json"
    plan.write_text(
        json.dumps(
            {
                "resource_changes": [
                    {
                        "address": "aws_s3_bucket.logs",
                        "type": "aws_s3_bucket",
                        "name": "logs",
                        "change": {
                            "actions": ["update"],
                            "before": {"acl": "private"},
                            "after": {"acl": "public-read"},
                        },
                    }
                ]
            }
        )
    )
    return str(plan)


def test_scan_json_emits_a_structured_report(tmp_path):
    from typer.testing import CliRunner

    from steadystate.cli import app

    result = CliRunner().invoke(app, ["scan", _plan(tmp_path), "--stateless", "--json"])
    assert result.exit_code == 0
    doc = json.loads(result.stdout)  # stdout must be pure, parseable JSON
    assert doc["summary"]["alerts"] == 1
    alert = doc["alerts"][0]
    assert alert["fingerprints"] and alert["changes"][0]["change_type"] == "modified"


def test_scan_json_includes_memory_status_when_stateful(tmp_path):
    from typer.testing import CliRunner

    from steadystate.cli import app

    plan, db = _plan(tmp_path), str(tmp_path / "s.db")
    first = CliRunner().invoke(app, ["scan", plan, "--state", db, "--json"])
    assert json.loads(first.stdout)["alerts"][0]["status"] == "open"  # memory annotates it
    assert json.loads(first.stdout)["alerts"][0]["first_seen"] is not None
