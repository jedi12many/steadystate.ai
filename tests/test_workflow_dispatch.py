"""The `workflow` solution kind -- a runbook entry dispatches a GitHub Actions workflow through
the same gate as every remediation. These pin the spec grammar (locator/@ref/inputs, basename for
a .github/workflows path), the dispatch call (URL, body, the token in the header and NOWHERE in a
message), the fail-closed paths (no token, API error, malformed spec), the offer path (sentinel
command; malformed entries never offered; placeholders fill inputs), the approve routing (sentinel
-> API call, never a subprocess), and the #253 rule: a workflow NEVER auto-applies on its author's
self-declared bound."""

from __future__ import annotations

import io
import json
import urllib.error
from datetime import UTC, datetime

import pytest

from steadystate.act import solution_remedy as remedy_mod
from steadystate.act import workflow as workflow_mod
from steadystate.act.solution_remedy import record_solution_remediations, run_solution
from steadystate.act.workflow import (
    DISPATCH_SENTINEL,
    WorkflowSpec,
    dispatch_workflow,
    parse_workflow_spec,
)
from steadystate.model import Provenance
from steadystate.probe.base import Symptom
from steadystate.reason.alert import Severity
from steadystate.state import PendingAction, StateStore


def _sym(category: str, title: str, evidence: dict | None = None) -> Symptom:
    return Symptom(
        identity=f"default/{title}",
        kind="Pod",
        category=category,
        severity=Severity.MEDIUM,
        title=title,
        detail="d",
        provenance=Provenance(source="k8s"),
        evidence=evidence or {},
    )


class _Alert:
    def __init__(self, *symptoms: Symptom) -> None:
        self.symptoms = list(symptoms)


class _Report:
    def __init__(self, *alerts: _Alert) -> None:
        self.alerts = list(alerts)


def _runbook(tmp_path, entries) -> str:
    path = tmp_path / "solutions.json"
    path.write_text(json.dumps(entries))
    return str(path)


def _workflow_solution(run: str) -> dict:
    return {
        "name": "redeploy-runners",
        "for": "RunnerPoolDegraded",
        "solution": {"kind": "workflow", "run": run},
        "impact": "low",
        "reversibility": "high",
        "author": "ops",
    }


# -- the spec grammar -------------------------------------------------------------------------


def test_parse_minimal_locator_defaults_ref_to_main():
    spec, problem = parse_workflow_spec(["acme/infra/redeploy.yml"])
    assert problem == ""
    assert spec == WorkflowSpec("acme", "infra", "redeploy.yml", "main", {})


def test_parse_ref_inputs_and_a_workflows_path_basename():
    spec, _ = parse_workflow_spec(
        ["acme/infra/.github/workflows/redeploy.yaml@release", "cluster=prod", "size=3"]
    )
    assert spec.workflow == "redeploy.yaml"  # the API takes the file NAME, not the path
    assert spec.ref == "release"
    assert spec.inputs == {"cluster": "prod", "size": "3"}


def test_parse_rejects_a_non_locator_and_a_non_pair_input():
    spec, problem = parse_workflow_spec(["kubectl", "delete", "pods"])
    assert spec is None and "isn't a workflow locator" in problem
    spec, problem = parse_workflow_spec(["acme/infra/x.yml", "justaword"])
    assert spec is None and "isn't input=value" in problem
    spec, problem = parse_workflow_spec([])
    assert spec is None and "empty" in problem


# -- the dispatch call ------------------------------------------------------------------------


class _NoContent:
    """A 204 response shell for the safe_urlopen context manager."""

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_dispatch_posts_the_event_and_links_the_runs_page(monkeypatch):
    seen: dict = {}

    def fake_urlopen(request, timeout=0):
        seen["url"] = request.full_url
        seen["method"] = request.get_method()
        seen["body"] = json.loads(request.data)
        seen["auth"] = request.get_header("Authorization")
        return _NoContent()

    monkeypatch.setenv("STEADYSTATE_GITHUB_TOKEN", "tok-123")
    monkeypatch.delenv("GITHUB_API_URL", raising=False)
    monkeypatch.setattr(workflow_mod, "safe_urlopen", fake_urlopen)
    ok, detail = dispatch_workflow(
        WorkflowSpec("acme", "infra", "redeploy.yml", "main", {"cluster": "prod"})
    )
    assert ok
    assert seen["url"] == (
        "https://api.github.com/repos/acme/infra/actions/workflows/redeploy.yml/dispatches"
    )
    assert seen["method"] == "POST"
    assert seen["body"] == {"ref": "main", "inputs": {"cluster": "prod"}}
    assert seen["auth"] == "Bearer tok-123"
    assert "https://github.com/acme/infra/actions/workflows/redeploy.yml" in detail
    assert "cluster=prod" in detail  # the approver sees exactly what was dispatched
    assert "tok-123" not in detail  # the token lives in the header, never a message


def test_dispatch_without_a_token_fails_closed(monkeypatch):
    monkeypatch.delenv("STEADYSTATE_GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    ok, detail = dispatch_workflow(WorkflowSpec("acme", "infra", "x.yml", "main"))
    assert not ok and "STEADYSTATE_GITHUB_TOKEN" in detail


def test_dispatch_reports_the_api_error_message(monkeypatch):
    def fail_urlopen(request, timeout=0):
        raise urllib.error.HTTPError(
            request.full_url, 404, "Not Found", {}, io.BytesIO(b'{"message": "No ref found"}')
        )

    monkeypatch.setenv("STEADYSTATE_GITHUB_TOKEN", "tok")
    monkeypatch.setattr(workflow_mod, "safe_urlopen", fail_urlopen)
    ok, detail = dispatch_workflow(WorkflowSpec("acme", "infra", "x.yml", "gone"))
    assert not ok and "404" in detail and "No ref found" in detail


def test_dispatch_links_the_ghe_host_for_an_enterprise_api(monkeypatch):
    monkeypatch.setenv("STEADYSTATE_GITHUB_TOKEN", "tok")
    monkeypatch.setenv("GITHUB_API_URL", "https://ghe.example.com/api/v3")
    monkeypatch.setattr(workflow_mod, "safe_urlopen", lambda request, timeout=0: _NoContent())
    ok, detail = dispatch_workflow(WorkflowSpec("acme", "infra", "x.yml", "main"))
    assert ok and "https://ghe.example.com/acme/infra/actions/workflows/x.yml" in detail


# -- the offer path ---------------------------------------------------------------------------


def test_a_matched_workflow_solution_is_offered_as_a_sentinel_pending(tmp_path, monkeypatch):
    monkeypatch.setenv(
        "STEADYSTATE_SOLUTIONS",
        _runbook(tmp_path, [_workflow_solution("acme/infra/redeploy.yml@main cluster={cluster}")]),
    )
    report = _Report(_Alert(_sym("RunnerPoolDegraded", "runners degraded", {"cluster": "prod"})))
    with StateStore(":memory:") as store:
        n = record_solution_remediations(store, report, datetime.now(UTC))
        pending = store.all_pending()
    assert n == 1
    assert pending[0].command == f"{DISPATCH_SENTINEL} acme/infra/redeploy.yml@main cluster=prod"
    assert pending[0].drift_identity == "redeploy-runners (author: ops)"  # the audit anchor


def test_a_malformed_workflow_entry_is_never_offered(tmp_path, monkeypatch):
    monkeypatch.setenv(
        "STEADYSTATE_SOLUTIONS",
        _runbook(tmp_path, [_workflow_solution("not a locator at all")]),
    )
    report = _Report(_Alert(_sym("RunnerPoolDegraded", "runners degraded")))
    with StateStore(":memory:") as store:
        assert record_solution_remediations(store, report, datetime.now(UTC)) == 0


def test_a_workflow_never_auto_applies_on_its_self_declared_bound(tmp_path, monkeypatch):
    # impact low / reversibility high WOULD sit inside the autonomous ceiling -- but a workflow's
    # body is arbitrary code, so the author's word never grants auto (issue #253). It must land as
    # a pending for a human, even with auto on.
    monkeypatch.delenv("STEADYSTATE_NO_SAFETY_NET", raising=False)
    monkeypatch.setenv(
        "STEADYSTATE_SOLUTIONS",
        _runbook(tmp_path, [_workflow_solution("acme/infra/redeploy.yml")]),
    )
    monkeypatch.setattr(
        remedy_mod, "dispatch_workflow", lambda spec: pytest.fail("must not auto-dispatch")
    )
    report = _Report(_Alert(_sym("RunnerPoolDegraded", "runners degraded")))
    with StateStore(":memory:") as store:
        record_solution_remediations(store, report, datetime.now(UTC), auto=True)
        assert len(store.all_pending()) == 1  # escalated to a human, not run


# -- the approve routing ----------------------------------------------------------------------


def _pending(command: str) -> PendingAction:
    return PendingAction(
        fingerprint="fp1",
        source="solution",
        path="",
        drift_identity="redeploy-runners (author: ops)",
        command=command,
    )


def test_run_solution_routes_the_sentinel_to_the_api_not_a_subprocess(monkeypatch):
    monkeypatch.setattr(
        remedy_mod, "dispatch_workflow", lambda spec: (True, f"dispatched {spec.workflow}")
    )
    monkeypatch.setattr(
        remedy_mod.subprocess, "run", lambda *a, **k: pytest.fail("a dispatch must not exec")
    )
    result = run_solution(_pending(f"{DISPATCH_SENTINEL} acme/infra/redeploy.yml cluster=prod"))
    assert result.applied and "redeploy.yml" in result.detail
    assert "GitHub Actions workflow" in result.plan.blast_radius  # the plan says what this is


def test_run_solution_refuses_a_sentinel_with_a_broken_spec(monkeypatch):
    monkeypatch.setattr(
        remedy_mod.subprocess, "run", lambda *a, **k: pytest.fail("must not exec a broken spec")
    )
    result = run_solution(_pending(f"{DISPATCH_SENTINEL} nonsense"))
    assert not result.applied and "workflow dispatch refused" in result.detail


def test_a_failed_dispatch_is_reported_not_raised(monkeypatch):
    monkeypatch.setattr(
        remedy_mod, "dispatch_workflow", lambda spec: (False, "workflow dispatch failed (404): x")
    )
    result = run_solution(_pending(f"{DISPATCH_SENTINEL} acme/infra/redeploy.yml"))
    assert not result.applied and "404" in result.detail
