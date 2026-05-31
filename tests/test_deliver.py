"""The delivery seam: patch-file (auth-free floor) + github-pr (API, auth isolated).

The deterministic patch is computed elsewhere (codify.py); these cover *delivery* -- writing the
patch, and opening a PR over the GitHub REST API with everything mocked, so no network and no real
token. The load-bearing guarantees: the floor needs no auth, github-pr degrades honestly when
unconfigured, re-runs reuse the open PR (no spam), and a destructive / non-additive artifact is
skipped rather than mis-delivered.
"""

from __future__ import annotations

import json

import pytest

from steadystate.act.artifact import RemediationArtifact, files_from_patch, new_file_patch
from steadystate.act.deliver import DELIVERIES, build_deliveries
from steadystate.act.deliver import github_pr as gh_mod
from steadystate.act.deliver.github_pr import GitHubPRDelivery
from steadystate.act.deliver.patch_file import PatchFileDelivery
from steadystate.model import ChangeType

_CONTENT = 'resource "aws_s3_bucket" "logs" {\n  acl = "private"\n}\n'


def _artifact(*, destructive: bool = False, patch: str | None = None) -> RemediationArtifact:
    path = "steadystate-adopted/aws_s3_bucket.logs.tf"
    return RemediationArtifact(
        drift_identity="aws_s3_bucket.logs",
        change_type=ChangeType.REMOVED,
        path=path,
        patch=patch if patch is not None else new_file_patch(path, _CONTENT),
        destructive=destructive,
        title="Adopt unmanaged aws_s3_bucket `logs`",
        body="codify the live resource",
    )


# -- registry + floor ----------------------------------------------------------


def test_registry_has_both_rungs_and_rejects_unknown():
    assert {"patch-file", "github-pr"} <= set(DELIVERIES)
    assert [a.name for a in build_deliveries(["patch-file", "github-pr"])] == [
        "patch-file",
        "github-pr",
    ]
    with pytest.raises(ValueError, match="unknown delivery"):
        build_deliveries(["nope"])


def test_patch_file_writes_the_patch(tmp_path):
    adapter = PatchFileDelivery(out_dir=tmp_path)
    assert adapter.ready() is True
    receipt = adapter.deliver(_artifact())
    assert receipt.delivered is True
    written = (tmp_path / "aws_s3_bucket.logs.patch").read_text()
    assert 'resource "aws_s3_bucket" "logs"' in written


# -- files_from_patch ----------------------------------------------------------


def test_files_from_patch_recovers_new_file_content():
    files = files_from_patch(new_file_patch("a/b.tf", _CONTENT))
    assert files == {"a/b.tf": _CONTENT}


def test_files_from_patch_ignores_a_non_new_file_diff():
    edit = "diff --git a/x.tf b/x.tf\n--- a/x.tf\n+++ b/x.tf\n@@ -1 +1 @@\n-old\n+new\n"
    assert files_from_patch(edit) == {}  # not a whole-file addition -> nothing to deliver


# -- github-pr: readiness / degrade --------------------------------------------


def test_github_pr_not_ready_without_a_token():
    assert GitHubPRDelivery(token=None, repo="o/r").ready() is False


def test_github_pr_not_ready_without_a_repo(monkeypatch):
    monkeypatch.setattr(gh_mod, "_resolve_repo", lambda: None)
    assert GitHubPRDelivery(token="t", repo=None).ready() is False


def test_github_pr_ready_with_token_and_repo():
    assert GitHubPRDelivery(token="t", repo="o/r").ready() is True


# -- github-pr: the REST dance (mocked) ----------------------------------------


class _Resp:
    def __init__(self, payload: object) -> None:
        self._b = json.dumps(payload).encode()

    def __enter__(self) -> _Resp:
        return self

    def __exit__(self, *a: object) -> bool:
        return False

    def read(self) -> bytes:
        return self._b


def _router(monkeypatch, routes, calls=None):
    """Patch github_pr.safe_urlopen to answer by (method, url-substring) from ``routes``."""

    def fake(request, *, timeout):
        if calls is not None:
            calls.append((request.method, request.full_url, request.data))
        for method, sub, payload in routes:
            if request.method == method and sub in request.full_url:
                return _Resp(payload)
        raise AssertionError(f"unexpected {request.method} {request.full_url}")

    monkeypatch.setattr(gh_mod, "safe_urlopen", fake)


_HAPPY = [
    ("GET", "/git/ref/heads/main", {"object": {"sha": "BASE"}}),
    ("GET", "/git/commits/BASE", {"tree": {"sha": "BASETREE"}}),
    ("POST", "/git/trees", {"sha": "TREE"}),
    ("POST", "/git/commits", {"sha": "COMMIT"}),
    ("POST", "/git/refs", {"ref": "refs/heads/x"}),
    ("GET", "/pulls?head", []),
    ("POST", "/pulls", {"html_url": "https://github.com/o/r/pull/7"}),
]


def test_github_pr_opens_a_pull_request(monkeypatch):
    calls: list = []
    _router(monkeypatch, _HAPPY, calls)
    receipt = GitHubPRDelivery(token="t", repo="o/r", base="main").deliver(_artifact())
    assert receipt.delivered is True
    assert receipt.ref == "https://github.com/o/r/pull/7"
    # the tree POST carried the actual file content (the codified resource)
    tree_body = json.loads(next(d for m, u, d in calls if m == "POST" and "/git/trees" in u))
    assert tree_body["tree"][0]["content"] == _CONTENT
    assert tree_body["tree"][0]["path"] == "steadystate-adopted/aws_s3_bucket.logs.tf"


def test_github_pr_reuses_an_open_pr_no_duplicate(monkeypatch):
    routes = _HAPPY[:5] + [
        ("GET", "/pulls?head", [{"html_url": "https://github.com/o/r/pull/3"}]),  # already open
        ("POST", "/pulls", {"html_url": "SHOULD-NOT-BE-CALLED"}),
    ]
    calls: list = []
    _router(monkeypatch, routes, calls)
    receipt = GitHubPRDelivery(token="t", repo="o/r", base="main").deliver(_artifact())
    assert receipt.ref == "https://github.com/o/r/pull/3"
    assert not any(m == "POST" and u.endswith("/pulls") for m, u, _ in calls)  # no new PR


def test_github_pr_refuses_a_destructive_artifact(monkeypatch):
    _router(monkeypatch, [])  # no call should be made
    receipt = GitHubPRDelivery(token="t", repo="o/r").deliver(_artifact(destructive=True))
    assert receipt.delivered is False and "destructive" in receipt.detail


def test_github_pr_skips_a_non_additive_patch(monkeypatch):
    _router(monkeypatch, [])
    edit = "diff --git a/x.tf b/x.tf\n--- a/x.tf\n+++ b/x.tf\n@@ -1 +1 @@\n-a\n+b\n"
    receipt = GitHubPRDelivery(token="t", repo="o/r").deliver(_artifact(patch=edit))
    assert receipt.delivered is False and "addition" in receipt.detail


def test_github_pr_reports_an_api_failure_cleanly(monkeypatch):
    import urllib.error

    def boom(request, *, timeout):
        raise urllib.error.HTTPError(request.full_url, 401, "Unauthorized", {}, None)

    monkeypatch.setattr(gh_mod, "safe_urlopen", boom)
    receipt = GitHubPRDelivery(token="t", repo="o/r", base="main").deliver(_artifact())
    assert receipt.delivered is False and "failed" in receipt.detail  # no raw traceback


# -- CLI wiring (--deliver is orthogonal to --autonomy) ------------------------


def test_cli_deliver_writes_a_patch_for_a_removed_drift(tmp_path, monkeypatch):
    from steadystate import cli
    from steadystate.model import Drift, Provenance
    from steadystate.reason.alert import Alert, Severity
    from steadystate.reason.report import Report

    monkeypatch.setenv("STEADYSTATE_PATCH_DIR", str(tmp_path / "patches"))
    drift = Drift(
        identity="aws_s3_bucket.logs",
        kind="aws_s3_bucket",
        change_type=ChangeType.REMOVED,
        provenance=Provenance(source="terraform", address="aws_s3_bucket.logs"),
        observed={"id": "b", "acl": "private"},
    )
    alert = Alert(title="t", severity=Severity.HIGH, drifts=[drift], why_it_matters="w")
    cli._deliver("terraform", tmp_path, Report(items=[alert]), ["patch-file"])
    assert (tmp_path / "patches" / "aws_s3_bucket.logs.patch").exists()


def test_cli_scan_unknown_deliver_is_a_clean_error(tmp_path):
    runner = pytest.importorskip("typer.testing").CliRunner()
    from steadystate.cli import app

    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps({"resource_changes": []}))
    result = runner.invoke(
        app, ["scan", str(plan), "--source", "terraform", "--deliver", "nope", "--no-llm"]
    )
    assert result.exit_code != 0  # unknown delivery -> clean BadParameter, not a crash
