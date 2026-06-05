"""The resolution learner: steadystate learning a response it was never shown. These pin the
attribution (a finding WE resolved vs one resolved out-of-band), the generalization (anti-unifying
the where), and the two lessons -- adopt a reflex you keep doing by hand, or flag a self-healer to
stop paging -- and that a lesson is only ever a proposal."""

from __future__ import annotations

from datetime import UTC, datetime

from steadystate.act.learn import (
    ADOPT,
    SELF_HEAL,
    gather_demonstrations,
    learn,
)
from steadystate.state import APPLIED, RESOLVED, AuditEntry, Finding, StateStore

_T0 = datetime(2026, 6, 2, 12, 0, 0, tzinfo=UTC)


def _finding(
    fp: str, category: str, *, namespace="prod", cluster="east", status=RESOLVED, mins=4, note=None
):
    first = _T0.isoformat()
    last = _T0.replace(minute=mins).isoformat()
    details = {"category": category, "namespace": namespace, "cluster": cluster, "workload": "web"}
    if category == "":  # a drift / non-health finding carries no category
        details.pop("category")
    return Finding(
        fingerprint=fp,
        first_seen=first,
        last_seen=last,
        last_severity="medium",
        last_title=f"web is {category}",
        status=status,
        details=details,
        note=note,  # the operator's recorded fix, from `resolve <fp> "..."`
    )


# -- attribution ----------------------------------------------------------------


def test_a_resolution_we_caused_is_not_a_demonstration():
    findings = [_finding("a" * 64, "Evicted")]
    # in the acted set -> steadystate resolved it -> we already know that response, skip it.
    assert gather_demonstrations(findings, acted={"a" * 64}) == []
    # out of the acted set -> resolved out-of-band -> a demonstration.
    assert len(gather_demonstrations(findings, acted=set())) == 1


def test_open_and_categoryless_findings_are_not_demonstrations():
    findings = [
        _finding("a" * 64, "Evicted", status="open"),  # still open -- nothing resolved
        _finding("b" * 64, ""),  # drift / no category -- nothing to learn
    ]
    assert gather_demonstrations(findings, acted=set()) == []


# -- the two lessons ------------------------------------------------------------


def test_a_category_we_have_a_dormant_reflex_for_proposes_promotion(monkeypatch):
    monkeypatch.delenv("STEADYSTATE_REFLEX_AUTO", raising=False)  # reclaim-evicted stays at propose
    findings = [_finding("a" * 64, "Evicted"), _finding("b" * 64, "Evicted", namespace="staging")]
    [lesson] = learn(findings, acted=set())
    assert lesson.kind == ADOPT and lesson.reflex_name == "reclaim-evicted"
    assert "promote" in lesson.recommendation and lesson.occurrences == 2


def test_a_category_with_no_reflex_proposes_to_stop_paging():
    # CrashLoopBackOff has no reflex (no safe one-shot fix) -- but it keeps clearing on its own.
    findings = [_finding(c * 64, "CrashLoopBackOff") for c in ("a", "b", "c")]
    [lesson] = learn(findings, acted=set())
    assert lesson.kind == SELF_HEAL and lesson.reflex_name is None
    assert "mute" in lesson.recommendation and "median 4m" in lesson.recommendation


# -- the recorded fix (resolve <fp> "..."): how it was fixed, fed into the lesson ----------------


def test_one_consistent_fix_earns_a_promotion_review(monkeypatch):
    monkeypatch.delenv("STEADYSTATE_REFLEX_AUTO", raising=False)
    fix = "raised the ephemeral-storage limit to 200Mi"
    findings = [_finding("a" * 64, "Evicted", note=fix), _finding("b" * 64, "Evicted", note=fix)]
    [lesson] = learn(findings, acted=set())
    # one repeated, consistent fix -> the lesson cites it as evidence the response is ready
    assert fix in lesson.recommendation and "consistent fix" in lesson.recommendation
    assert "earned a promotion review" in lesson.recommendation


def test_several_different_fixes_are_not_yet_a_safe_action_to_promote(monkeypatch):
    monkeypatch.delenv("STEADYSTATE_REFLEX_AUTO", raising=False)
    findings = [
        _finding("a" * 64, "Evicted", note="raised the storage limit"),
        _finding("b" * 64, "Evicted", note="deleted the pod"),
        _finding("c" * 64, "Evicted", note="cordoned the node"),
    ]
    [lesson] = learn(findings, acted=set())
    # inconsistent fixes -> there isn't a single safe action; learning withholds the promotion
    assert (
        "different fixes" in lesson.recommendation
        and "review before promoting" in lesson.recommendation
    )
    assert "earned a promotion review" not in lesson.recommendation


def test_a_recurring_fix_adds_a_caution_to_the_promotion(monkeypatch):
    monkeypatch.delenv("STEADYSTATE_REFLEX_AUTO", raising=False)
    fix = "deleted the evicted pods"
    findings = [
        _finding("a" * 64, "Evicted", note=fix),
        _finding("b" * 64, "Evicted", note=fix),
        _finding("d" * 64, "Evicted", status="open"),  # acted on, yet open again -> didn't hold
    ]
    [lesson] = learn(findings, acted={"d" * 64})  # the recurrence signal: a fix that didn't stick
    assert "caution" in lesson.recommendation and "recurred" in lesson.recommendation


def test_distinct_recorded_fixes_are_summarized_most_recent_first():
    findings = [
        _finding("a" * 64, "CrashLoopBackOff", note="rolled back the image"),
        _finding("b" * 64, "CrashLoopBackOff", note="bumped the memory limit"),
        _finding("c" * 64, "CrashLoopBackOff"),  # no fix recorded -- fine, just not shown
    ]
    [lesson] = learn(findings, acted=set())
    # most recent distinct fix, with a count of the others
    assert 'recorded fix: "bumped the memory limit" (+1 other recorded)' in lesson.recommendation


def test_no_recorded_fix_leaves_the_recommendation_unchanged():
    findings = [_finding(c * 64, "CrashLoopBackOff") for c in ("a", "b")]
    [lesson] = learn(findings, acted=set())
    assert "recorded fix" not in lesson.recommendation  # nothing recorded -> no fix clause


def test_a_promoted_reflex_still_resolving_out_of_band_says_schedule_hold(monkeypatch):
    monkeypatch.setenv("STEADYSTATE_REFLEX_AUTO", "reclaim-evicted")  # already auto
    findings = [_finding("a" * 64, "Evicted"), _finding("b" * 64, "Evicted")]
    [lesson] = learn(findings, acted=set())
    assert lesson.kind == ADOPT and "hold --apply" in lesson.recommendation


# -- thresholds + generalization ------------------------------------------------


def test_a_single_demonstration_is_an_anecdote_not_a_lesson():
    assert learn([_finding("a" * 64, "Evicted")], acted=set()) == []


def test_scope_names_a_constant_dimension_and_counts_a_varying_one():
    same_ns = [_finding(c * 64, "CrashLoopBackOff", namespace="prod") for c in ("a", "b")]
    assert "namespace prod" in learn(same_ns, acted=set())[0].scope
    spread = [_finding("a" * 64, "CrashLoopBackOff", namespace="prod")]
    spread.append(_finding("b" * 64, "CrashLoopBackOff", namespace="staging"))
    assert "2 namespaces" in learn(spread, acted=set())[0].scope


# -- the store path (audit-log attribution) -------------------------------------


def test_acted_fingerprints_excludes_what_we_applied():
    store = StateStore()
    store.record_audit(
        AuditEntry(
            fingerprint="a" * 64,
            source="kubectl-cleanup",
            drift_identity="prod/web",
            actor="hold",
            decision="approved",
            outcome=APPLIED,
        ),
        _T0,
    )
    acted = store.acted_fingerprints()
    assert "a" * 64 in acted
    # so a resolved finding with that fingerprint is attributed to us, not learned from.
    findings = [_finding("a" * 64, "Evicted"), _finding("b" * 64, "Evicted")]
    demos = gather_demonstrations(findings, acted)
    assert [d.fingerprint for d in demos] == ["b" * 64]
