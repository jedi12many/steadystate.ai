"""The `terraform-state` source: config-vs-state via `terraform plan -refresh=false` -- no
per-resource cloud refresh, so a CI gate can run on backend-state read access alone (not broad cloud
creds). Pins that it passes `-refresh=false` where plain `terraform` passes `-refresh=true`, and
that it's a registered, reachable source. subprocess is faked -- no terraform binary needed."""

from __future__ import annotations

import pytest

from steadystate.sources import DRIFT_SOURCES, build_drift_source


def _fake_terraform(monkeypatch, plan_changes="[]"):
    """Patch the source's run_tool: record argvs, return an empty plan for `show`, "" for `plan`."""
    calls: list[list[str]] = []

    def fake_run_tool(argv, **_kw):
        calls.append(argv)
        if argv[:2] == ["terraform", "show"]:
            return f'{{"resource_changes": {plan_changes}}}'
        return ""

    monkeypatch.setattr("steadystate.sources.terraform.run_tool", fake_run_tool)
    return calls


def _plan_argv(calls: list[list[str]]) -> list[str]:
    return next(a for a in calls if a[:2] == ["terraform", "plan"])


def test_terraform_state_is_registered_and_reachable():
    assert "terraform-state" in DRIFT_SOURCES


def test_terraform_state_runs_plan_without_a_refresh(monkeypatch, tmp_path):
    calls = _fake_terraform(monkeypatch)
    build_drift_source("terraform-state", tmp_path).collect_drift()  # tmp_path is a dir
    assert "-refresh=false" in _plan_argv(calls)  # config-vs-state only, no cloud refresh
    assert "-refresh=true" not in _plan_argv(calls)


def test_plain_terraform_still_refreshes(monkeypatch, tmp_path):
    calls = _fake_terraform(monkeypatch)
    build_drift_source("terraform", tmp_path).collect_drift()
    assert "-refresh=true" in _plan_argv(calls)  # the live drift path is unchanged


def test_a_precomputed_plan_file_ignores_the_refresh_choice(monkeypatch, tmp_path):
    # a plan already has its diff -> terraform-state reads it as-is, runs no plan (no refresh ask)
    plan = tmp_path / "plan.json"
    plan.write_text('{"resource_changes": []}')
    calls = _fake_terraform(monkeypatch)
    drifts = build_drift_source("terraform-state", plan).collect_drift()
    assert drifts == [] and not any(a[:2] == ["terraform", "plan"] for a in calls)  # no plan run


def test_terraform_state_parses_a_drift_like_terraform_does(monkeypatch, tmp_path):
    changes = (
        '[{"address": "aws_s3_bucket.x", "type": "aws_s3_bucket", "name": "x", '
        '"change": {"actions": ["update"], "before": {"acl": "private"}, '
        '"after": {"acl": "public-read"}}}]'
    )
    _fake_terraform(monkeypatch, plan_changes=changes)
    drifts = build_drift_source("terraform-state", tmp_path).collect_drift()
    assert len(drifts) == 1 and "aws_s3_bucket.x" in drifts[0].identity


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-q"])
