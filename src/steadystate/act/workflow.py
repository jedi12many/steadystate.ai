"""Dispatch a GitHub Actions workflow as an authored remediation -- the ``workflow`` solution kind.

For a shop whose automation lives in its repos, "the fix" for a finding is usually "run that
workflow". A runbook entry can say exactly that:

    {"name": "redeploy-runners", "for": "RunnerPoolDegraded",
     "solution": {"kind": "workflow",
                  "run": "your-org/platform-infra/redeploy-runners.yml@main cluster={cluster}"},
     "impact": "medium", "reversibility": "high", "author": "ops"}

The ``run`` grammar: ``owner/repo/workflow.yml[@ref] [input=value ...]`` -- the workflow file (a
``.github/workflows/`` path is fine; the API takes its basename), the ref to run on (default
``main``), and the ``workflow_dispatch`` inputs, ``{placeholder}``-fillable from the finding's
evidence like any solution command.

Dispatch is a single stdlib ``urllib`` POST to the Actions API, riding the SAME token the GitHub
issues surface uses (``STEADYSTATE_GITHUB_TOKEN`` / ``GITHUB_TOKEN``; it needs ``actions:write``).
No ``gh`` CLI on the box, and the reply carries the workflow's runs page so the approver can watch
it land. Trust model: the workflow body is arbitrary code in another repo, so the kind joins
``command``/``playbook`` as an OPEN kind -- it never auto-applies on its author's self-declared
bound (issue #253); a human approves, and GitHub's own protections (environments, required
reviewers) remain a second gate on the Actions side.
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field

from .._http import safe_urlopen

WORKFLOW_KIND = "workflow"
# The argv[0] sentinel a stored pending command carries so `approve` knows this action is an API
# dispatch, not a binary to exec -- and so `pending` reads honestly ("workflow-dispatch org/...").
DISPATCH_SENTINEL = "workflow-dispatch"

_DEFAULT_API = "https://api.github.com"
_DEFAULT_REF = "main"
_TIMEOUT = 30.0
# owner/repo/path-to-workflow.yml[@ref] -- the path may be the bare file or .github/workflows/...
_LOCATOR = re.compile(
    r"^(?P<owner>[\w.-]+)/(?P<repo>[\w.-]+)/(?P<file>[\w./-]+\.ya?ml)(?:@(?P<ref>\S+))?$"
)


@dataclass(frozen=True)
class WorkflowSpec:
    """One parsed dispatch: which workflow, on which ref, with which inputs."""

    owner: str
    repo: str
    workflow: str  # the workflow FILE name (the dispatch API takes a basename or an id)
    ref: str
    inputs: dict[str, str] = field(default_factory=dict)


def parse_workflow_spec(tokens: list[str]) -> tuple[WorkflowSpec | None, str]:
    """Parse a workflow solution's ``run`` tokens -- ``owner/repo/workflow.yml[@ref]`` then
    ``input=value`` pairs -- into a :class:`WorkflowSpec`. Returns ``(spec, "")`` or ``(None,
    reason)``; the reason is human-readable so a malformed entry diagnoses itself instead of being
    silently unrunnable. Pure."""
    if not tokens:
        return None, "empty workflow spec -- expected owner/repo/workflow.yml[@ref] [input=value]"
    match = _LOCATOR.match(tokens[0])
    if match is None:
        return None, (
            f"'{tokens[0]}' isn't a workflow locator -- expected owner/repo/workflow.yml[@ref] "
            "(e.g. your-org/platform-infra/redeploy.yml@main)"
        )
    inputs: dict[str, str] = {}
    for token in tokens[1:]:
        key, sep, value = token.partition("=")
        if not sep or not key:
            return None, f"workflow input '{token}' isn't input=value"
        inputs[key] = value
    workflow = match.group("file").rsplit("/", 1)[-1]  # the API takes the file NAME
    ref = match.group("ref") or _DEFAULT_REF
    return WorkflowSpec(match.group("owner"), match.group("repo"), workflow, ref, inputs), ""


def _token() -> str:
    """The same token resolution as the GitHub issues surface -- one credential, both loops."""
    token = os.environ.get("STEADYSTATE_GITHUB_TOKEN") or os.environ.get("GITHUB_TOKEN") or ""
    return token.strip()


def _web_base(api: str) -> str:
    """The browse URL base for ``api`` -- github.com for the public API, the GHE host for
    ``https://ghe.example/api/v3``. Best-effort (it only feeds the runs link in the reply)."""
    if api.rstrip("/") == _DEFAULT_API:
        return "https://github.com"
    return re.sub(r"/api(/v3)?/?$", "", api.rstrip("/"))


def _error_message(err: urllib.error.HTTPError) -> str:
    """The API's ``message`` field from an error body, or the bare status line. Never raises."""
    try:
        body = json.loads(err.read() or b"{}")
        message = body.get("message") if isinstance(body, dict) else None
    except (OSError, ValueError):
        message = None
    return str(message) if message else err.reason or "request failed"


def dispatch_workflow(spec: WorkflowSpec) -> tuple[bool, str]:
    """POST the ``workflow_dispatch`` event for ``spec``. Returns ``(ok, detail)`` -- the detail
    names what was dispatched and links the workflow's runs page, or says exactly why not (a
    missing token, a 404 on the workflow/ref, an unreachable API). Fail closed, never raises;
    the token is used in the header and never appears in any message."""
    token = _token()
    if not token:
        return False, (
            "workflow dispatch needs a token -- set STEADYSTATE_GITHUB_TOKEN (or GITHUB_TOKEN) "
            "with actions:write on the workflow's repo."
        )
    api = (os.environ.get("GITHUB_API_URL") or _DEFAULT_API).rstrip("/")
    url = f"{api}/repos/{spec.owner}/{spec.repo}/actions/workflows/{spec.workflow}/dispatches"
    body: dict = {"ref": spec.ref}
    if spec.inputs:
        body["inputs"] = spec.inputs
    request = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",  # the only place the token is used
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "steadystate",
            "Content-Type": "application/json",
        },
    )
    try:
        with safe_urlopen(request, timeout=_TIMEOUT):
            pass  # 204 No Content on success -- the dispatch is accepted, not yet a run id
    except urllib.error.HTTPError as err:
        return False, f"workflow dispatch failed ({err.code}): {_error_message(err)}"
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return False, f"workflow dispatch failed: {exc}"
    filled = ", ".join(f"{k}={v}" for k, v in spec.inputs.items())
    with_inputs = f" with {filled}" if filled else ""
    runs = f"{_web_base(api)}/{spec.owner}/{spec.repo}/actions/workflows/{spec.workflow}"
    return True, (
        f"dispatched {spec.workflow}@{spec.ref} in {spec.owner}/{spec.repo}{with_inputs} "
        f"-- watch it: {runs}"
    )
