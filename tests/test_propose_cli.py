"""`scan --autonomy propose --deliver patch-file` end to end.

build_report is stubbed (no terraform binary needed) so the test exercises the wiring: the
propose level probes the executor's Proposer capability, renders the artifact, and the
patch-file adapter drops a reviewable .patch -- with zero auth.
"""

from __future__ import annotations

import pytest

from steadystate import cli
from steadystate.model import ChangeType, Drift, Provenance
from steadystate.reason.alert import Alert, Severity
from steadystate.reason.report import Report

typer_testing = pytest.importorskip("typer.testing")


def _report_with_removed_drift() -> Report:
    drift = Drift(
        identity="aws_s3_bucket.logs",
        kind="aws_s3_bucket",
        change_type=ChangeType.REMOVED,
        provenance=Provenance(source="terraform", address="aws_s3_bucket.logs"),
        observed={"id": "my-logs-bucket"},
    )
    alert = Alert(
        title="Unmanaged resource",
        severity=Severity.MEDIUM,
        drifts=[drift],
        why_it_matters="A live resource is not under Terraform management.",
    )
    return Report(items=[alert])


def test_propose_writes_a_patch_file(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "build_report", lambda *a, **k: _report_with_removed_drift())
    out_dir = tmp_path / "patches"
    monkeypatch.setenv("STEADYSTATE_PATCH_DIR", str(out_dir))

    result = typer_testing.CliRunner().invoke(
        cli.app,
        ["scan", str(tmp_path), "--source", "terraform", "--autonomy", "propose", "--stateless"],
    )

    assert result.exit_code == 0, result.output
    assert "autonomy=propose: 1 code-change artifact(s)." in result.output
    assert "Adopt unmanaged aws_s3_bucket `logs`" in result.output
    patch = out_dir / "aws_s3_bucket.logs.patch"
    assert patch.exists()
    assert "import {" in patch.read_text(encoding="utf-8")


def test_propose_on_observe_only_source_says_so(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "build_report", lambda *a, **k: _report_with_removed_drift())
    # k8s is observe-only (no executor), so there's nothing to propose -- and it must say that,
    # not silently produce zero artifacts as if it had tried.
    result = typer_testing.CliRunner().invoke(
        cli.app,
        ["scan", str(tmp_path), "--source", "k8s", "--autonomy", "propose", "--stateless"],
    )
    assert result.exit_code == 0, result.output
    assert "has no code-change remediations" in result.output


def test_propose_rejects_unknown_delivery(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "build_report", lambda *a, **k: _report_with_removed_drift())
    result = typer_testing.CliRunner().invoke(
        cli.app,
        [
            "scan",
            str(tmp_path),
            "--source",
            "terraform",
            "--autonomy",
            "propose",
            "--deliver",
            "nope",
            "--stateless",
        ],
    )
    assert result.exit_code != 0
    assert "unknown delivery 'nope'" in result.output
