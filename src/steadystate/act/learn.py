"""The resolution learner: how steadystate learns a response it was never shown.

The whole premise of the homeostat is that *most of what goes wrong is known* -- the only variance
is the human who responds, and whether they know. But the human responds in their own terminal:
we never see the keystroke. So we don't learn from the keystroke. We are a continuous reconciler
that snapshots reality, so we learn from the *world*: a finding opens, a human does something
out-of-band, and on the next probe the finding is **gone**. The response is latent in that
transition -- and we can already attribute it, because the audit log knows what *we* did.

This module is the *attribution + proposal* half of that loop, built on what the store already
keeps (the finding lifecycle + the audit log):

  * A finding that resolved and is NOT in the audit log's acted set resolved **out-of-band** -- a
    human (or self-healing) fixed it. That's a **demonstration**.
  * Group demonstrations by category and **generalize** (anti-unify): the identity dimensions that
    vary across them (namespace, cluster) become free variables; the category is the constant.
  * Turn each into a **lesson**, never an action:
      - the category has a reflex we already possess but haven't switched on -> *you keep doing
        this by hand; promote the reflex* (close the loop on knowledge the human keeps supplying);
      - no reflex answers it, yet it keeps clearing on its own -> *this self-heals; stop paging*
        (the most valuable thing to learn is sometimes to do nothing).

A lesson is a **proposal**: it is surfaced (``steadystate learn``) and an operator promotes it. The
strength is the count -- "this would have been the right call N times on findings we already have"
-- not a model's confidence. The richer inference (diffing the world at open vs. resolve to tell a
human *delete* from a true *self-heal*, instead of inferring it from whether a reflex exists) plugs
into this same seam next; today the attribution is deliberately coarse, and honest about it.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from statistics import median

from ..state import RESOLVED, Finding
from .reflex import AUTO, reflex_for_category, reflex_recurrence

# Lesson kinds. ADOPT: we have a response for this category -- promote the reflex the human keeps
# re-supplying by hand. SELF_HEAL: nothing of ours answers it, yet it keeps clearing alone --
# a candidate to mute (stop paging).
ADOPT = "adopt-reflex"
SELF_HEAL = "self-heals"


@dataclass(frozen=True)
class Demonstration:
    """One out-of-band resolution -- a finding that cleared without steadystate acting, so a human
    (or self-healing) did it. The raw material a lesson generalizes from."""

    fingerprint: str
    category: str
    identity: str
    namespace: str
    cluster: str
    open_seconds: float  # how long it was open (first_seen -> last_seen) before it cleared
    solution: str = ""  # the operator's recorded fix (from `resolve <fp> "..."`), if any


@dataclass(frozen=True)
class Lesson:
    """A generalized, promotable recommendation for a category -- what steadystate *learned* from
    the demonstrations, stated as advice for a human to accept, never an action it takes."""

    category: str
    kind: str  # ADOPT | SELF_HEAL
    occurrences: int  # how many demonstrations back it -- the strength
    scope: str  # the generalized 'where' (anti-unified: the free variables)
    median_open: float  # median time-to-resolve across the demonstrations, seconds
    recommendation: str
    reflex_name: str | None  # the reflex to promote, for an ADOPT lesson; None for SELF_HEAL


def gather_demonstrations(findings: list[Finding], acted: set[str]) -> list[Demonstration]:
    """The out-of-band resolutions among ``findings`` -- resolved, NOT in ``acted`` (the audit
    log's applied/verified set), and carrying a malfunction ``category`` to learn about. A
    resolution steadystate itself caused is excluded: we already know that response. Pure."""
    demos: list[Demonstration] = []
    for finding in findings:
        if finding.status != RESOLVED or finding.fingerprint in acted:
            continue
        category = finding.details.get("category")
        if not category:  # a drift / non-health finding carries no category -- nothing to learn
            continue
        demos.append(
            Demonstration(
                fingerprint=finding.fingerprint,
                category=category,
                identity=finding.details.get("workload", finding.last_title),
                namespace=finding.details.get("namespace", ""),
                cluster=finding.details.get("cluster", ""),
                open_seconds=_open_seconds(finding.first_seen, finding.last_seen),
                solution=finding.note or "",  # the operator's recorded fix, if they used `resolve`
            )
        )
    return demos


def learn(findings: list[Finding], acted: set[str], *, min_occurrences: int = 2) -> list[Lesson]:
    """Derive the lessons -- generalized, promotable recommendations -- from the out-of-band
    resolutions in the store. A category needs at least ``min_occurrences`` demonstrations before
    it's a lesson (one resolution is an anecdote, not a pattern). Strongest (most-seen) first. Pure
    apart from reading the current reflex registry to ask 'do we already have a response?'."""
    by_category: dict[str, list[Demonstration]] = defaultdict(list)
    for demo in gather_demonstrations(findings, acted):
        by_category[demo.category].append(demo)
    recurred = reflex_recurrence(findings, acted)  # per-reflex fixes that DIDN'T hold (the caution)
    lessons: list[Lesson] = []
    for category, group in by_category.items():
        if len(group) < min_occurrences:
            continue
        lessons.append(_lesson_for(category, group, recurred))
    lessons.sort(key=lambda lesson: lesson.occurrences, reverse=True)
    return lessons


def _lesson_for(category: str, group: list[Demonstration], recurred: dict[str, int]) -> Lesson:
    reflex = reflex_for_category(category)
    med = median(sorted(d.open_seconds for d in group))
    scope = _scope(group)
    count = len(group)
    if reflex is not None:
        if reflex.autonomy == AUTO:
            rec = (
                f"'{reflex.name}' is auto but {count} {category} resolved out-of-band -- "
                "schedule `hold --apply` so it catches them"
            ) + _fix_hint(group)
        else:  # a dormant reflex you keep re-supplying by hand: is it ready to promote?
            rec = _promotion_recommendation(category, group, reflex, recurred.get(reflex.name, 0))
        return Lesson(category, ADOPT, count, scope, med, rec, reflex.name)
    rec = (
        f"{count} {category} cleared without intervention (median {_humanize(med)}) -- "
        "a candidate to mute (stop paging), or a future reflex"
    )
    return Lesson(category, SELF_HEAL, count, scope, med, rec + _fix_hint(group), None)


def _distinct_fixes(group: list[Demonstration]) -> list[str]:
    """The recorded fixes for this category, most-recent-first, de-duplicated -- the evidence a
    consistent (or inconsistent) response leaves. Empty when none were recorded."""
    fixes: list[str] = []
    for demo in reversed(group):  # most recent first
        if demo.solution and demo.solution not in fixes:
            fixes.append(demo.solution)
    return fixes


def _fix_hint(group: list[Demonstration]) -> str:
    """The operator's recorded fix(es), appended to a recommendation -- so `learn` shows *how* it
    was fixed and the decider's grounding can reuse it. '' when none recorded."""
    fixes = _distinct_fixes(group)
    if not fixes:
        return ""
    more = f" (+{len(fixes) - 1} other recorded)" if len(fixes) > 1 else ""
    return f' -- recorded fix: "{fixes[0]}"{more}'


def _promotion_recommendation(
    category: str, group: list[Demonstration], reflex, recurred: int
) -> str:
    """An **evidence-backed** promotion recommendation for a dormant reflex the operator keeps
    fixing by hand. Learning never flips the switch -- it hands the human the track record: the
    demand (how often, by hand), the *consistency* of the recorded fix (one repeated fix = a safe
    candidate; many different fixes = NOT a single safe action, don't promote), and the hold record
    (past auto-fixes that recurred -- the counterweight). The human still grants via the env var."""
    count = len(group)
    cta = f"STEADYSTATE_REFLEX_AUTO={reflex.name}"
    fixes = _distinct_fixes(group)
    caution = (
        f" (caution: {recurred} past auto-fix(es) recurred -- may not hold)" if recurred else ""
    )
    if not fixes:  # demand only, no recorded fix to judge consistency
        return (
            f"you resolved {count} {category} by hand -- promote '{reflex.name}' "
            f"({cta}) so hold reclaims them{caution}"
        )
    if len(fixes) == 1:  # one repeated, consistent fix -> a real promotion candidate
        return (
            f'you resolved {count} {category} by hand, one consistent fix ("{fixes[0]}") -- '
            f"this has earned a promotion review: promote with {cta}{caution}"
        )
    # several different fixes -> there isn't a single safe action to automate yet
    return (
        f"you resolved {count} {category} by hand but with {len(fixes)} different fixes (e.g. "
        f"\"{fixes[0]}\") -- not yet a single safe action; review before promoting '{reflex.name}'"
    )


def _scope(group: list[Demonstration]) -> str:
    """The anti-unified 'where': a dimension shared by every demonstration is named; one that varies
    is collapsed to a count -- that's the free variable a promoted reflex would range over."""
    namespaces = {d.namespace for d in group if d.namespace}
    clusters = {d.cluster for d in group if d.cluster}
    parts = []
    if clusters:
        parts.append(
            f"cluster {next(iter(clusters))}" if len(clusters) == 1 else f"{len(clusters)} clusters"
        )
    if namespaces:
        parts.append(
            f"namespace {next(iter(namespaces))}"
            if len(namespaces) == 1
            else f"{len(namespaces)} namespaces"
        )
    return "across " + ", ".join(parts) if parts else "fleet-wide"


def _open_seconds(first_seen: str, last_seen: str) -> float:
    """Seconds a finding was open (first_seen -> last_seen); 0 when either timestamp is unparseable
    so a malformed row never sinks the learner."""
    try:
        return max(
            0.0,
            (
                datetime.fromisoformat(last_seen) - datetime.fromisoformat(first_seen)
            ).total_seconds(),
        )
    except (TypeError, ValueError):
        return 0.0


def _humanize(seconds: float) -> str:
    """A terse duration for a recommendation: 45s / 12m / 3h / 2d."""
    if seconds < 90:
        return f"{int(seconds)}s"
    if seconds < 90 * 60:
        return f"{int(seconds / 60)}m"
    if seconds < 36 * 3600:
        return f"{int(seconds / 3600)}h"
    return f"{int(seconds / 86400)}d"
