"""Request recipes: a vetted ask in chat becomes a review-gated PR in another repo.

The Tier-1 fulfillment loop for a GitOps shop. Someone in the channel says *"I need outbound
access to microsoft.com to download a package"* -- and instead of pointing them at a wiki, the
agent opens the PR for them: a one-line, **deterministic** edit to the repo that owns that
decision, with the human review *in that repo* as the gate. A committed
``steadystate/requests.json`` defines what may be requested:

    {"name": "proxy-domain",
     "problem": "a server needs outbound access to a new domain",
     "repo": "your-org/proxy-outbound",
     "file": "allowlist.txt",
     "edit": "append-line",
     "value": "{domain}",
     "params": {"domain": "^[a-z0-9.-]+\\\\.[a-z]{2,}$"},
     "title": "request: allow outbound to {domain}",
     "author": "ops"}

The trust model is the runbook's, tightened for cross-repo writes: the **edit is operator
intent** (the recipe names the repo, the file, the edit kind, and the value template -- reviewed
in a PR like solutions); the requester (or the model suggesting the command) only ever fills
**named, regex-validated parameters** -- it never composes a diff, never names a repo or file.
`request` is effectful, so the NL layer echoes it for a human to send, MCP exposes it only at
``--write``, and every fulfillment is audited. The blast radius of the verb itself is "opens a
PR" -- reversible by close -- and the target repo's own review/merge protections remain the real
gate on the change.

Everything is the GitHub API over stdlib urllib -- **no local clone**: read the file, branch,
commit the one-line edit, open the PR, reply with the link. Deduped by a deterministic branch
name per (recipe, filled values): asking twice points at the existing open PR instead of filing
a second one. Fail closed and honest at every step.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from .._http import safe_urlopen
from .workflow import _DEFAULT_API, _error_message, _token, _web_base

DEFAULT_REQUESTS_FILE = "steadystate/requests.json"  # committed intent, beside solutions/checks
REQUESTS_ENV = "STEADYSTATE_REQUESTS"

_TIMEOUT = 30.0
_PLACEHOLDER = re.compile(r"\{(\w+)\}")
_EDIT_KINDS = frozenset({"append-line"})  # deterministic edits only; extensible by design


@dataclass(frozen=True)
class Request:
    """One vetted, fulfillable ask: which repo/file, the deterministic edit, and the named,
    regex-validated parameters a requester may fill. Everything else is operator intent."""

    name: str
    repo: str  # owner/name -- where the PR opens
    file: str  # the path edited
    value: str  # the line template, {param}-fillable
    title: str  # the PR title template, {param}-fillable
    author: str  # who vouched for this recipe -- the audit anchor
    edit: str = "append-line"
    problem: str = ""  # the human description (`requests` shows it)
    base: str = ""  # the base branch ("" = the repo's default branch)
    params: dict[str, str] = field(default_factory=dict)  # param -> the regex its value must match


def resolve_requests_path(explicit: str = "") -> str:
    """Where the recipes live: explicit > ``STEADYSTATE_REQUESTS`` > the committed convention."""
    if explicit:
        return explicit
    return os.environ.get(REQUESTS_ENV, "").strip() or DEFAULT_REQUESTS_FILE


def parse_request(raw: dict) -> Request | None:
    """Validate one recipe. Required: name, repo (owner/name), file, value, title, author (the
    audit anchor), a known deterministic ``edit`` kind, and a compilable regex per declared param.
    Returns None (skip) on any miss -- one bad recipe never breaks the catalog."""
    if not isinstance(raw, dict):
        return None
    name = str(raw.get("name") or "").strip()
    repo = str(raw.get("repo") or "").strip()
    file = str(raw.get("file") or "").strip()
    value = str(raw.get("value") or "").strip()
    title = str(raw.get("title") or "").strip()
    author = str(raw.get("author") or "").strip()
    edit = str(raw.get("edit") or "append-line").strip()
    if not (name and file and value and title and author):
        return None
    if not re.fullmatch(r"[\w.-]+/[\w.-]+", repo):
        return None
    if edit not in _EDIT_KINDS:
        return None
    raw_params = raw.get("params")
    params: dict[str, str] = {}
    if raw_params is not None:
        if not isinstance(raw_params, dict):
            return None
        for key, pattern in raw_params.items():
            try:
                re.compile(str(pattern))
            except re.error:
                return None
            params[str(key)] = str(pattern)
    # Every placeholder used in value/title must be a declared param -- an undeclared one could
    # never be validated, so the recipe is unfulfillable as written. Reject at load, loudly absent.
    used = set(_PLACEHOLDER.findall(value)) | set(_PLACEHOLDER.findall(title))
    if not used <= set(params):
        return None
    return Request(
        name=name,
        repo=repo,
        file=file,
        value=value,
        title=title,
        author=author,
        edit=edit,
        problem=str(raw.get("problem") or "").strip(),
        base=str(raw.get("base") or "").strip(),
        params=params,
    )


def load_requests(path: str = "") -> list[Request]:
    """The valid recipes (a JSON list). Missing/malformed file -> []; invalid entries skipped."""
    resolved = resolve_requests_path(path)
    if not Path(resolved).exists():
        return []
    try:
        raw = json.loads(Path(resolved).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    if not isinstance(raw, list):
        return []
    return [req for item in raw if (req := parse_request(item)) is not None]


def describe_requests(path: str = "") -> str:
    """The `requests` view: what may be asked for, and how -- discoverable from chat."""
    recipes = load_requests(path)
    if not recipes:
        return (
            "no request recipes here -- commit steadystate/requests.json (a vetted ask -> a "
            "review-gated PR in the repo that owns it); see examples/requests."
        )
    lines = [f"{len(recipes)} request(s) you can make -- each opens a review-gated PR:"]
    for req in recipes:
        params = " ".join(f"{p}=<{p}>" for p in sorted(req.params)) or "(no parameters)"
        problem = f" -- {req.problem}" if req.problem else ""
        lines.append(f"  request {req.name} {params}{problem}  [PR on {req.repo}]")
    return "\n".join(lines)


def _fill_params(recipe: Request, tokens: list[str]) -> tuple[dict[str, str] | None, str]:
    """Parse ``param=value`` tokens against the recipe's declared params: every declared param
    must be provided, match its regex, and carry no newline (it lands verbatim in a file line);
    an undeclared param is rejected (a typo must not silently vanish). Pure."""
    given: dict[str, str] = {}
    for token in tokens:
        key, sep, value = token.partition("=")
        if not sep or not key:
            return None, f"'{token}' isn't param=value"
        given[key] = value
    unknown = sorted(set(given) - set(recipe.params))
    if unknown:
        known = ", ".join(sorted(recipe.params)) or "(none)"
        return None, f"unknown parameter(s) {', '.join(unknown)} -- this request takes: {known}"
    missing = sorted(set(recipe.params) - set(given))
    if missing:
        return None, f"missing parameter(s): {', '.join(missing)}"
    for key, value in given.items():
        if "\n" in value or "\r" in value:
            return None, f"parameter '{key}' may not contain a newline"
        if not re.fullmatch(recipe.params[key], value):
            return None, f"parameter '{key}' doesn't match this request's pattern for it"
    return given, ""


def _fill(template: str, values: dict[str, str]) -> str:
    return _PLACEHOLDER.sub(lambda m: values.get(m.group(1), m.group(0)), template)


def _api(method: str, url: str, token: str, body: dict | None = None) -> dict:
    """One authenticated GitHub API call, parsed. Raises like urllib does."""
    data = json.dumps(body).encode("utf-8") if body is not None else None
    request = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "steadystate",
            "Content-Type": "application/json",
        },
    )
    with safe_urlopen(request, timeout=_TIMEOUT) as response:
        parsed = json.loads(response.read() or b"{}")
    return parsed if isinstance(parsed, dict) else {"items": parsed}


def fulfill_request(name: str, tokens: list[str], actor: str, path: str = "") -> tuple[bool, str]:
    """Fulfill one vetted request: validate the parameters, make the deterministic edit on a
    fresh branch in the target repo (API only, no clone), open the PR, and return its link.
    Deduped by a deterministic branch per (recipe, values): asking again points at the existing
    open PR. Honest, fail-closed one-liners at every step; the change itself is gated by the
    target repo's own review."""
    recipe = next((r for r in load_requests(path) if r.name == name.strip()), None)
    if recipe is None:
        known = ", ".join(r.name for r in load_requests(path)) or "(none defined)"
        return False, f"no request named '{name}' -- known: {known}. `requests` lists them."
    values, problem = _fill_params(recipe, tokens)
    if values is None:
        return False, f"request {recipe.name}: {problem}"
    token = _token()
    if not token:
        return False, (
            "requests need a token -- set STEADYSTATE_GITHUB_TOKEN (or GITHUB_TOKEN) with "
            f"contents+pull-requests write on {recipe.repo}."
        )
    api = (os.environ.get("GITHUB_API_URL") or _DEFAULT_API).rstrip("/")
    repo_url = f"{api}/repos/{recipe.repo}"
    line = _fill(recipe.value, values)
    title = _fill(recipe.title, values)
    # The dedup key: one branch per (recipe, exact values) -- ask twice, get the same PR.
    digest = hashlib.sha256(line.encode("utf-8")).hexdigest()[:10]
    branch = f"steadystate/request/{recipe.name}/{digest}"

    try:
        existing = _api(
            "GET", f"{repo_url}/pulls?state=open&head={recipe.repo.split('/')[0]}:{branch}", token
        )
        already_open = existing.get("items") or []
        if already_open:
            url = already_open[0].get("html_url", "")
            return True, f"already requested -- the PR is open and awaiting review: {url}"
        base = recipe.base or str(_api("GET", repo_url, token).get("default_branch") or "main")
        current = _api("GET", f"{repo_url}/contents/{recipe.file}?ref={base}", token)
        content = base64.b64decode(str(current.get("content") or "")).decode("utf-8", "replace")
        if line in content.splitlines():
            return True, (
                f"nothing to request -- '{line}' is already in {recipe.file} on {base} "
                f"of {recipe.repo}."
            )
        base_sha = str(_api("GET", f"{repo_url}/git/ref/heads/{base}", token)["object"]["sha"])
        try:
            _api(
                "POST",
                f"{repo_url}/git/refs",
                token,
                {"ref": f"refs/heads/{branch}", "sha": base_sha},
            )
        except urllib.error.HTTPError as err:
            if err.code == 422:  # the branch exists but no open PR -- a prior ask was declined
                return False, (
                    f"a branch for this exact request already exists ({branch}) with no open PR "
                    f"-- a previous ask may have been declined; delete the branch in "
                    f"{recipe.repo} to re-request."
                )
            raise
        updated = content + ("" if content.endswith("\n") or not content else "\n") + line + "\n"
        _api(
            "PUT",
            f"{repo_url}/contents/{recipe.file}",
            token,
            {
                "message": (
                    f"{title}\n\nRequested by {actor} via steadystate (`request {recipe.name}`)."
                ),
                "content": base64.b64encode(updated.encode("utf-8")).decode("ascii"),
                "sha": str(current.get("sha") or ""),
                "branch": branch,
            },
        )
        body_lines = [
            recipe.problem or f"A `{recipe.name}` request.",
            "",
            f"Adds to `{recipe.file}`:",
            "```",
            line,
            "```",
            "",
            f"Requested by **{actor}** via steadystate (`request {recipe.name}`); recipe vouched "
            f"by {recipe.author}. Review and merge to grant, close to decline.",
            f"<!-- steadystate-request: {recipe.name} {digest} -->",
        ]
        pr = _api(
            "POST",
            f"{repo_url}/pulls",
            token,
            {"title": title, "head": branch, "base": base, "body": "\n".join(body_lines)},
        )
    except urllib.error.HTTPError as err:
        return False, f"request {recipe.name} failed ({err.code}): {_error_message(err)}"
    except (urllib.error.URLError, OSError, ValueError, KeyError) as exc:
        return False, f"request {recipe.name} failed: {exc}"
    url = str(pr.get("html_url") or f"{_web_base(api)}/{recipe.repo}/pulls")
    return True, (
        f"opened the request as a PR on {recipe.repo} -- someone will review it soon: {url}"
    )
