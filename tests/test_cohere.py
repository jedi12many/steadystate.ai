"""Cohere-batch: CLI source selector, executor-backed recommended_action, and the
security pack's word-boundary kind match."""

import json

from steadystate.cli import _drift_source
from steadystate.domains.security import SecurityDomain
from steadystate.model import ChangeType, Drift, Provenance
from steadystate.reason.pipeline import Pipeline


def _drift(change_type=ChangeType.MODIFIED, kind="aws_s3_bucket", **kw) -> Drift:
    return Drift(
        identity="aws_s3_bucket.logs",
        kind=kind,
        change_type=change_type,
        provenance=Provenance(source="terraform", address="aws_s3_bucket.logs"),
        declared=kw.get("declared"),
        observed=kw.get("observed"),
    )


def test_case_carries_recommended_action_from_executor(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    case = Pipeline().run([_drift(ChangeType.MODIFIED)]).surfaced[0]
    assert case.recommended_action  # populated, not None
    assert "Reconcile to declared state" in case.recommended_action


def test_removed_case_recommends_manual_review(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    case = Pipeline().run([_drift(ChangeType.REMOVED)]).surfaced[0]
    assert "Manual review" in case.recommended_action


def test_non_terraform_drift_has_no_terraform_action(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    drift = Drift(
        identity="Deployment/api",
        kind="Deployment",
        change_type=ChangeType.MODIFIED,
        provenance=Provenance(source="argocd"),
    )
    # No Terraform executor for an ArgoCD drift -> we don't fabricate a `terraform apply`.
    assert Pipeline().run([drift]).surfaced[0].recommended_action is None


def test_security_pab_match_is_word_boundary():
    dom = SecurityDomain()
    relaxed = {"declared": {"block_public_acls": False}, "observed": {"block_public_acls": True}}
    real = _drift(kind="aws_s3_bucket_public_access_block", **relaxed)
    assert dom.score(real) is not None  # real PAB resource still flagged
    bogus = _drift(kind="xpublic_access_block", **relaxed)
    assert dom.score(bogus) is None  # substring-but-not-word-boundary no longer matches


def test_cli_source_selector_builds_argocd(tmp_path):
    app = {
        "status": {
            "resources": [
                {"kind": "Deployment", "namespace": "prod", "name": "api", "status": "OutOfSync"},
                {"kind": "Service", "namespace": "prod", "name": "api", "status": "Synced"},
            ]
        }
    }
    f = tmp_path / "app.json"
    f.write_text(json.dumps(app))
    drifts = _drift_source("argocd", f).collect_drift()
    assert len(drifts) == 1  # only the OutOfSync resource
    assert drifts[0].kind == "Deployment"
