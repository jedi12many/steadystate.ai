"""github-pr delivery: open a pull request that codifies the drift, via the GitHub REST API.

The accept-reality patch becomes a real PR in *your* repo, so drift flows through your normal
review (CODEOWNERS / CI), not a steadystate-only approval UI. The headline workflow is CI: a
scheduled ``scan --deliver github-pr`` opens a PR per drift; humans review there.

**Auth lives only here.** A token is resolved from ``STEADYSTATE_GITHUB_TOKEN`` or ``GITHUB_TOKEN``
(priority that order) -- the latter is the per-workflow GitHub Actions token, which can open PRs
with ``permissions: { contents: write, pull-requests: write }`` and needs **no personal PAT**, the
path that works under tight credential controls. (A GitHub App installation token is a follow-up.)

Deliberately **API-only** -- create blob/tree/commit/ref/PR over HTTPS, no local ``git`` and no
push credential to juggle: the single secret is the API token, passed only in the Authorization
header, never logged, http(s)-gated by ``safe_urlopen``. Today's artifacts are whole-file additions
(adopt), which the API renders directly; edit/delete diffs are a follow-up.

Idempotent: the branch name is stable per artifact, so a re-scan updates the existing branch and
reuses the open PR instead of spamming new ones.
"""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import urllib.error
import urllib.request
from typing import Any

from ..._http import safe_urlopen
from ..artifact import RemediationArtifact, files_from_patch
from .base import DeliveryReceipt

logger = logging.getLogger(__name__)

_DEFAULT_API = "https://api.github.com"
_BRANCH_PREFIX = "steadystate/"


def _resolve_repo() -> str | None:
    """``owner/name`` from ``STEADYSTATE_GITHUB_REPO``, else parsed from ``git remote get-url
    origin`` (https or ssh GitHub URL). None when neither resolves."""
    explicit = os.environ.get("STEADYSTATE_GITHUB_REPO")
    if explicit:
        return explicit.strip()
    try:
        url = subprocess.run(
            ["git", "remote", "get-url", "origin"],
            capture_output=True,
            text=True,
            timeout=5,
        ).stdout.strip()
    except (subprocess.SubprocessError, OSError):
        return None
    match = re.search(r"github\.com[:/]([^/]+/[^/]+?)(?:\.git)?$", url)
    return match.group(1) if match else None


class GitHubPRDelivery:
    """Open a PR codifying one artifact, via the GitHub REST API."""

    name = "github-pr"

    def __init__(
        self,
        token: str | None = None,
        repo: str | None = None,
        base: str | None = None,
        api_url: str | None = None,
        timeout: float = 15.0,
    ) -> None:
        self.token = (
            token or os.environ.get("STEADYSTATE_GITHUB_TOKEN") or os.environ.get("GITHUB_TOKEN")
        )
        self.repo = repo or _resolve_repo()
        self.base = base or os.environ.get("STEADYSTATE_GITHUB_BASE")  # else the repo default
        self.api_url = (api_url or os.environ.get("GITHUB_API_URL") or _DEFAULT_API).rstrip("/")
        self.timeout = timeout

    def ready(self) -> bool:
        if not self.token:
            logger.warning(
                "github-pr delivery enabled but no token "
                "(set STEADYSTATE_GITHUB_TOKEN or GITHUB_TOKEN); skipping."
            )
            return False
        if not self.repo:
            logger.warning(
                "github-pr delivery enabled but no repo "
                "(set STEADYSTATE_GITHUB_REPO or run inside a git checkout); skipping."
            )
            return False
        return True

    def deliver(self, artifact: RemediationArtifact) -> DeliveryReceipt:
        if artifact.destructive:  # never auto-open a destroy PR; this rung is for safe changes
            return DeliveryReceipt(False, detail="refusing to deliver a destructive artifact")
        files = files_from_patch(artifact.patch)
        if not files:  # an edit/delete diff we can't render via the API yet -> honest skip
            return DeliveryReceipt(
                False, detail="github-pr supports whole-file additions only (for now)"
            )
        try:
            return self._open_pr(artifact, files)
        except (urllib.error.URLError, OSError, KeyError, ValueError) as exc:
            # Any API/transport failure is reported, never a raw traceback; the scan stood.
            return DeliveryReceipt(False, detail=f"github-pr delivery failed: {exc}")

    # -- the REST dance ---------------------------------------------------------

    def _open_pr(self, artifact: RemediationArtifact, files: dict[str, str]) -> DeliveryReceipt:
        base = self.base or self._get(f"/repos/{self.repo}")["default_branch"]
        base_sha = self._get(f"/repos/{self.repo}/git/ref/heads/{base}")["object"]["sha"]
        base_tree = self._get(f"/repos/{self.repo}/git/commits/{base_sha}")["tree"]["sha"]

        tree = self._post(
            f"/repos/{self.repo}/git/trees",
            {
                "base_tree": base_tree,
                "tree": [
                    {"path": path, "mode": "100644", "type": "blob", "content": content}
                    for path, content in files.items()
                ],
            },
        )["sha"]
        message = f"{artifact.title}\n\n{artifact.body}".strip()
        commit_sha = self._post(
            f"/repos/{self.repo}/git/commits",
            {"message": message, "tree": tree, "parents": [base_sha]},
        )["sha"]

        branch = f"{_BRANCH_PREFIX}{artifact.slug}"
        self._upsert_ref(branch, commit_sha)

        url = self._ensure_pr(branch, base, artifact)
        return DeliveryReceipt(
            True, ref=url, detail=f"opened/updated PR for {artifact.drift_identity}"
        )

    def _upsert_ref(self, branch: str, sha: str) -> None:
        """Create the branch ref, or fast-forward it if it already exists (re-scan idempotency)."""
        try:
            self._post(f"/repos/{self.repo}/git/refs", {"ref": f"refs/heads/{branch}", "sha": sha})
        except urllib.error.HTTPError as exc:
            if exc.code != 422:  # 422 == ref already exists -> update it
                raise
            self._patch(f"/repos/{self.repo}/git/refs/heads/{branch}", {"sha": sha, "force": True})

    def _ensure_pr(self, branch: str, base: str, artifact: RemediationArtifact) -> str:
        """Reuse an open PR for this branch, else open one. Returns the PR URL."""
        owner = self.repo.split("/", 1)[0] if self.repo else ""
        existing = self._get(f"/repos/{self.repo}/pulls?head={owner}:{branch}&state=open")
        if existing:
            return existing[0]["html_url"]
        pr = self._post(
            f"/repos/{self.repo}/pulls",
            {"title": artifact.title, "head": branch, "base": base, "body": artifact.body},
        )
        return pr["html_url"]

    # -- HTTP -------------------------------------------------------------------

    def _request(self, method: str, path: str, body: dict | None = None) -> Any:
        data = json.dumps(body).encode("utf-8") if body is not None else None
        request = urllib.request.Request(
            f"{self.api_url}{path}",
            data=data,
            method=method,
            headers={
                "Authorization": f"Bearer {self.token}",  # the only place the token is used
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "steadystate",
                "Content-Type": "application/json",
            },
        )
        with safe_urlopen(request, timeout=self.timeout) as response:
            return json.loads(response.read() or "null")

    def _get(self, path: str) -> Any:
        return self._request("GET", path)

    def _post(self, path: str, body: dict) -> Any:
        return self._request("POST", path, body)

    def _patch(self, path: str, body: dict) -> Any:
        return self._request("PATCH", path, body)
