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


def agent_repo() -> str:
    """The **agent's workflows repo** -- the one whose committed workflows are the agent's own
    instruments (`runs` reads them, `dispatch` kicks them). Resolution, 12-factor:
    ``STEADYSTATE_WORKFLOWS_REPO`` > ``[workflows] repo`` in config.toml > the GitHub surface's
    repo resolution (``STEADYSTATE_GITHUB_REPO``, else the cwd's ``origin`` remote -- the agent
    repo usually IS the repo the listener runs from). '' when nothing resolves."""
    env = os.environ.get("STEADYSTATE_WORKFLOWS_REPO", "").strip()
    if env:
        return env
    from ..config import config_table

    configured = config_table("workflows").get("repo")
    if isinstance(configured, str) and configured.strip():
        return configured.strip()
    from ..notify.github import _resolve_repo

    return _resolve_repo() or ""


_NO_REPO_HINT = (
    "no workflows repo configured -- set `[workflows] repo` in steadystate/config.toml (or "
    "STEADYSTATE_WORKFLOWS_REPO), or run from a repo with a GitHub `origin` remote."
)
# Named to stay clear of bandit's B105 credential-name heuristic -- it's a hint, not a secret.
_MISSING_AUTH_HINT = (
    "needs a token -- set STEADYSTATE_GITHUB_TOKEN (or GITHUB_TOKEN) with actions read/write "
    "on the workflows repo."
)


def _get(url: str, token: str) -> dict:
    """One authenticated GET against the Actions API, parsed. Raises like urllib does -- the
    callers turn failures into honest one-liners."""
    request = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "steadystate",
        },
    )
    with safe_urlopen(request, timeout=_TIMEOUT) as response:
        body = json.loads(response.read() or b"{}")
    return body if isinstance(body, dict) else {}


def list_runs(workflow: str = "", *, limit: int = 8) -> str:
    """Recent GitHub Actions runs in the agent's workflows repo, rendered for chat/CLI -- the
    'did the nightly scan pass?' answer from real run history. ``workflow`` (a file name) scopes
    to one workflow; bare lists the repo's latest runs across workflows. Read-only; every miss is
    an honest one-liner (no repo, no token, an unknown workflow, an API error)."""
    repo = agent_repo()
    if not repo:
        return _NO_REPO_HINT
    token = _token()
    if not token:
        return f"`runs` {_MISSING_AUTH_HINT}"
    api = (os.environ.get("GITHUB_API_URL") or _DEFAULT_API).rstrip("/")
    scope = f"/actions/workflows/{workflow}/runs" if workflow else "/actions/runs"
    try:
        data = _get(f"{api}/repos/{repo}{scope}?per_page={limit}", token)
    except urllib.error.HTTPError as err:
        where = f"workflow '{workflow}' in {repo}" if workflow else repo
        return f"couldn't read runs for {where} ({err.code}): {_error_message(err)}"
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return f"couldn't read runs: {exc}"
    runs = data.get("workflow_runs") or []
    if not runs:
        scoped = f" for {workflow}" if workflow else ""
        return f"no runs{scoped} in {repo} yet."
    scoped = f" -- {workflow}:" if workflow else ":"
    lines = [f"{len(runs[:limit])} recent run(s) in {repo}{scoped}"]
    for run in runs[:limit]:
        name = (run.get("path") or "").rsplit("/", 1)[-1] or str(run.get("name") or "?")
        state = str(run.get("conclusion") or run.get("status") or "?")
        branch = str(run.get("head_branch") or "")
        when = str(run.get("updated_at") or "")
        lines.append(f"  {name:<28} {state:<12} {branch:<14} {when}  {run.get('html_url') or ''}")
    return "\n".join(lines)


def dispatch_named(workflow: str, input_tokens: list[str]) -> tuple[bool, str]:
    """Dispatch one of the **agent repo's own** workflows on demand -- the chat/CLI `dispatch`
    verb. ``workflow`` is the file (``redeploy.yml``, optionally ``@ref``); the repo is ALWAYS
    the configured agent repo, so the verb is structurally scoped to it -- the workflows committed
    there are the vetted menu. Returns ``(ok, detail)``, fail closed like the solution path."""
    repo = agent_repo()
    if not repo:
        return False, _NO_REPO_HINT
    spec, problem = parse_workflow_spec([f"{repo}/{workflow.strip()}", *input_tokens])
    if spec is None:
        return False, problem
    return dispatch_workflow(spec)


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
