"""Operator-authored SOLUTIONS -- the wall's runbook: "for problem X, the fix is Y." A declarative
map from a *detected* problem (a finding's category, a custom-check name, or a title pattern) to a
known fix (a command, a playbook, a reboot -- anything), each **signed by an author**. It's the
catalog you build yourself over time: your tribal knowledge, made structured, auditable, and (next)
automatable.

The counterpart to ``custom.py``: a CHECK teaches steadystate to *see* a problem; a SOLUTION teaches
it the *fix*. The split in trust is deliberate -- a check runs unattended, so its schema is strict
(vetted, read-only reads); a solution is **operator-vouched**, so the body is open (the engineer
says "here's the command / playbook / reboot"). The guardrail isn't restricting what you may
document -- it's that *acting* on a solution still passes the bound + approval + audit (the
automation, a follow-up). The ``author`` is the accountability; the version-controlled file is the
audit; surfacing a solution against a matching finding is the immediate payoff.

Matching is strict OR fuzzy, the engineer's call per entry: ``for`` pins it to a finding category /
custom-check name (exact); ``match`` is a title regex for the fuzzier shapes. Either, or both."""

from __future__ import annotations

import json
import os
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

DEFAULT_SOLUTIONS_FILE = ".steadystate/solutions.json"  # legacy/gitignored -- still read if present
COMMITTED_SOLUTIONS_FILE = "steadystate/solutions.json"  # version-controlled INTENT (preferred)
SOLUTIONS_ENV = "STEADYSTATE_SOLUTIONS"

_BOUND_LEVELS = frozenset({"low", "medium", "high"})


def resolve_solutions_path(explicit: str = "") -> str:
    """Where the runbook lives. Solutions are *intent* (IaC-grade), not ephemeral state, so the
    **committed** ``steadystate/`` is the home -- authored fixes are reviewed in PRs, shared across
    the team, and travel with the IaC, not lost in the gitignored ``.steadystate/``. Order: an
    ``explicit`` path, else ``STEADYSTATE_SOLUTIONS``, else committed ``steadystate/solutions.json``
    if it exists, else the legacy ``.steadystate/solutions.json`` if THAT exists -- and for a fresh
    write (neither yet), the committed location, so a new authored fix lands somewhere committed."""
    if explicit:
        return explicit
    env = os.environ.get(SOLUTIONS_ENV, "").strip()
    if env:
        return env
    if Path(COMMITTED_SOLUTIONS_FILE).exists():
        return COMMITTED_SOLUTIONS_FILE
    if Path(DEFAULT_SOLUTIONS_FILE).exists():
        return DEFAULT_SOLUTIONS_FILE
    return COMMITTED_SOLUTIONS_FILE


@dataclass(frozen=True)
class Solution:
    """One authored fix. ``for_category``/``match`` are the join to a detected problem (at least one
    is set); ``kind``+``run``/``target`` are the action; ``impact``/``reversibility`` are the bound
    the automation will honor; ``author``/``added`` are the audit."""

    name: str
    kind: str  # command | playbook | reboot | ... (open -- the operator vouches)
    run: str  # the command / playbook to run ("" for a kind that doesn't need one, e.g. reboot)
    target: str  # what to act on (e.g. a host/workload to reboot); "" when N/A
    for_category: str  # strict match: a finding category or a custom-check name ("" if unset)
    match: str  # OR a title regex ("" if unset)
    problem: str  # human description -- the "top problems I see" line
    impact: str  # low | medium | high -- the bound (a destructive fix still needs approval)
    reversibility: str  # high | medium | low
    author: str  # who vouched for this fix -- the accountability
    added: str  # ISO date it was authored
    proposed: bool = False  # a DRAFT: authored LIVE (e.g. by an agent at --author), not yet vouched
    # by a human. A draft is surfaced (`show`/`solutions`) but NEVER offered as a runnable pending
    # until `vouch`ed -- the self-declared fix isn't trusted on the author's word. A solution from a
    # committed/hand-edited file (no `proposed` key) defaults vouched: a human put it there.


def parse_solution(raw: dict) -> Solution | None:
    """Validate one runbook entry. Required: a ``name``, an ``author`` (the audit anchor), at least
    one matcher (``for`` or a compilable ``match`` regex), and a ``solution`` with a ``kind`` plus a
    ``run`` or ``target``. Permissive on the *content* of the fix by design -- the operator vouches,
    and the gate is at execution, not authoring. Returns None (skip this entry) on any miss."""
    if not isinstance(raw, dict):
        return None
    name = str(raw.get("name") or "").strip()
    author = str(raw.get("author") or "").strip()
    if not name or not author:  # an unsigned or unnamed solution isn't auditable -- reject it
        return None
    for_category = str(raw.get("for") or "").strip()
    match = str(raw.get("match") or "").strip()
    if not for_category and not match:  # nothing to join it to a finding
        return None
    if match:
        try:
            re.compile(match)
        except re.error:
            return None
    sol = raw.get("solution")
    if not isinstance(sol, dict):
        return None
    kind = str(sol.get("kind") or "").strip()
    run = str(sol.get("run") or "").strip()
    target = str(sol.get("target") or "").strip()
    if not kind or not (run or target):  # a fix with no action is just a note
        return None
    impact = str(raw.get("impact") or "medium").strip().lower()
    reversibility = str(raw.get("reversibility") or "medium").strip().lower()
    if impact not in _BOUND_LEVELS or reversibility not in _BOUND_LEVELS:
        return None
    return Solution(
        name=name,
        kind=kind,
        run=run,
        target=target,
        for_category=for_category,
        match=match,
        problem=str(raw.get("problem") or "").strip(),
        impact=impact,
        reversibility=reversibility,
        author=author,
        added=str(raw.get("added") or "").strip(),
        proposed=bool(raw.get("proposed", False)),
    )


def load_solutions(path: str = "") -> list[Solution]:
    """The valid solutions (a JSON list, from ``resolve_solutions_path``). Missing/malformed file ->
    [] ; invalid entries are skipped, valid ones kept -- one bad entry never breaks the runbook."""
    path = resolve_solutions_path(path)
    if not path or not Path(path).exists():
        return []
    try:
        raw = json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return []
    if not isinstance(raw, list):
        return []
    return [sol for item in raw if (sol := parse_solution(item)) is not None]


def diagnose_solutions(path: str = "") -> list[str]:
    """A human diagnosis of the runbook file for `doctor` -- like ``diagnose_checks``, because
    ``load_solutions`` SILENTLY drops what it can't parse (bad JSON -> [], a bad entry -> skipped,
    a wrong path -> not found). Turns each silent miss into a line: where it looked, whether the
    file parses, how many solutions loaded, and WHICH entries were skipped (most commonly: a missing
    ``author``, no matcher, or an uncompilable ``match`` regex)."""
    resolved = resolve_solutions_path(path)
    lines = [f"runbook (solutions) file: {resolved}"]
    target = Path(resolved)
    if not target.exists():
        looked = " or ".join(dict.fromkeys([COMMITTED_SOLUTIONS_FILE, DEFAULT_SOLUTIONS_FILE]))
        lines.append(f"  not found (looked: {looked}). Set STEADYSTATE_SOLUTIONS / --solutions.")
        return lines
    try:
        raw = json.loads(target.read_text())
    except (OSError, ValueError) as exc:
        lines.append(f"  INVALID JSON ({exc}) -- the WHOLE file is ignored. Fix the syntax.")
        return lines
    if not isinstance(raw, list):
        lines.append("  not a JSON list -- it must be a [ ... ] of solution objects.")
        return lines
    valid = 0
    for i, item in enumerate(raw):
        if parse_solution(item) is not None:
            valid += 1
        else:
            name = item.get("name", "?") if isinstance(item, dict) else "?"
            lines.append(f"  solution #{i} ('{name}'): SKIPPED -- doesn't match the schema.")
    lines.append(f"  {valid}/{len(raw)} solution(s) valid + loaded.")
    if valid < len(raw):
        lines.append(f"  schema: {SOLUTION_SCHEMA_HINT}")
    return lines


def solutions_for(category: str, title: str, solutions: list[Solution]) -> list[Solution]:
    """The authored fixes that apply to a finding -- matched **strictly** by ``for`` (its category
    or a custom-check name, exact, case-insensitive) OR **fuzzily** by the ``match`` title regex.
    Either hit includes it; an entry with both must satisfy *both* (a scope plus a title shape)."""
    cat = (category or "").strip().lower()
    text = title or ""
    out: list[Solution] = []
    for sol in solutions:
        strict_ok = bool(sol.for_category) and sol.for_category.lower() == cat
        regex_ok = bool(sol.match) and re.search(sol.match, text, re.IGNORECASE) is not None
        if sol.for_category and sol.match:  # both set -> both must hold (a scoped, shaped match)
            if strict_ok and regex_ok:
                out.append(sol)
        elif strict_ok or regex_ok:  # one set -> that one decides
            out.append(sol)
    return out


def solutions_for_alert(alert: object, solutions: list[Solution] | None = None) -> list[Solution]:
    """The authored runbook fixes that match an Alert -- by any of its symptoms' category, or its
    title (regex). De-duplicated, order-stable. **Duck-typed** (reads ``alert.title`` +
    ``alert.symptoms[*].category``) so a surface can enrich a ticket/issue/PR with "here's the
    documented fix" without coupling solutions to the alert model. Loads the runbook when not
    supplied; [] when there's none. A drift-only alert (no symptom categories) matches by title."""
    sols = solutions if solutions is not None else load_solutions()
    if not sols:
        return []
    title = str(getattr(alert, "title", "") or "")
    categories = {
        str(getattr(symptom, "category", "")) for symptom in getattr(alert, "symptoms", [])
    } or {""}
    seen: set[str] = set()
    out: list[Solution] = []
    for category in categories:
        for match in solutions_for(category, title, sols):
            if match.name not in seen:
                seen.add(match.name)
                out.append(match)
    return out


def describe_solution(sol: Solution) -> str:
    """One-line runbook entry for ``solutions`` / surfacing against a finding: the action + how it's
    matched + who vouched for it."""
    action = f"{sol.kind}: {sol.run}" if sol.run else f"{sol.kind} {sol.target}".strip()
    join = f"for={sol.for_category}" if sol.for_category else ""
    if sol.match:
        join = f"{join} ~/{sol.match}/" if join else f"~/{sol.match}/"
    bound = f"[{sol.impact}/{sol.reversibility}]"
    tag = (
        "DRAFT " if sol.proposed else ""
    )  # a drafted fix is surfaced but not offered until vouched
    return f"{tag}{sol.name} ({join}) -> {action} {bound} -- by {sol.author}"


SOLUTION_SCHEMA_HINT = (
    "A solution is JSON: {name, for?(a finding category or check name), match?(a title regex), "
    "problem?, solution:{kind, run?, target?}, impact?(low|medium|high), "
    "reversibility?(low|medium|high), author}. At least one of for/match (both -> AND); "
    "kind is command|playbook|reboot|workflow|... (open); a fix needs a run or a target; author is "
    "required (the audit). impact/reversibility default medium -- they're the bound when it's "
    "automated. kind `workflow` dispatches a GitHub Actions workflow: run is "
    "'owner/repo/workflow.yml[@ref] [input=value ...]' (inputs {placeholder}-fillable from the "
    "finding; needs STEADYSTATE_GITHUB_TOKEN with actions:write)."
)


def add_solution(
    raw: dict, author: str = "", path: str = "", *, proposed: bool = True
) -> tuple[Solution | None, str]:
    """Validate ``raw`` and, if valid, store it in the wall's solutions.json (replacing any of the
    same name). ``author`` (the caller) is stamped on the entry when set, and ``added`` defaults to
    today -- so every stored fix carries who/when. ``proposed`` marks it a DRAFT (default for the
    live/agent verb path): surfaced but not offered as runnable until a human ``vouch``es it -- the
    writer stamps this, so a submitted value can't override it. The CLI authoring path passes
    ``proposed=False`` (a human at the terminal vouches as they author). Returns (solution, msg)."""
    if author and not raw.get("author"):
        raw = {**raw, "author": author}
    if not raw.get("added"):
        raw = {**raw, "added": datetime.now(UTC).date().isoformat()}
    raw = {
        **raw,
        "proposed": proposed,
    }  # the writer stamps trust -- a submitted value never overrides
    sol = parse_solution(raw)
    if sol is None:
        return None, f"that didn't validate -- it must match the schema.\n{SOLUTION_SCHEMA_HINT}"
    target = Path(resolve_solutions_path(path))
    items: list = []
    if target.exists():
        try:
            loaded = json.loads(target.read_text())
            items = loaded if isinstance(loaded, list) else []
        except (OSError, ValueError):
            items = []
    items = [it for it in items if not (isinstance(it, dict) and it.get("name") == sol.name)]
    items.append(raw)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(items, indent=2))
    tail = f"DRAFT -- `vouch {sol.name}` to offer it" if proposed else "surfaces on a match"
    return sol, f"solution '{sol.name}' added [{sol.kind}] by {sol.author} -- {tail}."


def vouch_solution(name: str, actor: str = "", path: str = "") -> tuple[bool, str]:
    """Promote a DRAFTED solution to vouched -- the human gate that makes it offerable. Clears the
    ``proposed`` flag on the entry (and records ``vouched_by``), so the next scan OFFERS it as a
    runnable pending. Returns (found, message). An agent's draft never runs until a human (the write
    grant, an SSO identity, or a commit) vouches for it -- trust attaches to the channel, not the
    author string."""
    target = Path(resolve_solutions_path(path))
    if not target.exists():
        return False, f"no runbook at {target} -- author one first with `add-solution`."
    try:
        items = json.loads(target.read_text())
    except (OSError, ValueError):
        return False, f"the runbook at {target} didn't parse."
    if not isinstance(items, list):
        return False, "the runbook isn't a list of solutions."
    found = False
    for it in items:
        if isinstance(it, dict) and it.get("name") == name:
            it["proposed"] = False
            if actor:
                it["vouched_by"] = actor
            found = True
    if not found:
        return False, f"no solution named '{name}' in the runbook."
    target.write_text(json.dumps(items, indent=2))
    who = f" by {actor}" if actor else ""
    return True, f"solution '{name}' vouched{who} -- now offered as a runnable fix on a match."


_DEFINE_SYSTEM = (
    "You translate an operator's request into ONE steadystate solution (a problem->fix runbook "
    "entry), as JSON. Pick a short kebab-case name. Set `for` to the finding category it fixes (or "
    "`match` to a title regex). The `solution` is the fix the operator described -- a command, a "
    "playbook, or a reboot; use {namespace}/{workload} where it should be scoped to the finding. "
    "Set impact/reversibility honestly. Reply with ONLY the JSON object.\n\n" + SOLUTION_SCHEMA_HINT
)


def define_solution(text: str, complete: Callable[[str, str, str], str | None]) -> dict | None:
    """Translate a natural-language request into a solution dict via the LLM seam (``complete``), or
    None when no model is configured / the reply has no JSON. It only *proposes* the JSON -- the
    caller runs it through :func:`add_solution`, so the schema gate + the author still decide."""
    from ..reason.llm import _extract_json  # reuse the analyst's lenient JSON extraction

    reply = complete(_DEFINE_SYSTEM, text, "define-solution")
    if not reply:
        return None
    data = _extract_json(reply)
    return data if isinstance(data, dict) else None
