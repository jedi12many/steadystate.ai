"""The authored runbook: parse + match (strict / regex / both) + store with an author, and the
surfacing of a matched solution against a finding in `show`. A solution is operator-vouched, so the
body is open -- the tests pin the *structure* + *matching* + *audit*, not a content restriction."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from steadystate.inbound.server import _render_show, _render_solutions
from steadystate.probe.solutions import (
    add_solution,
    describe_solution,
    load_solutions,
    parse_solution,
    solutions_for,
)
from steadystate.state import StateStore


def _entry(**over):
    base = {
        "name": "reclaim-evicted",
        "for": "Evicted",
        "problem": "evicted pods pile up as Failed",
        "solution": {"kind": "command", "run": "kubectl delete pods --field-selector=... -n {ns}"},
        "impact": "low",
        "reversibility": "high",
        "author": "jeff",
    }
    base.update(over)
    return base


# -- parse: the structure + the audit requirement --------------------------------


def test_parse_accepts_command_playbook_and_reboot_open_kinds():
    cmd = parse_solution(_entry())
    play = parse_solution(_entry(name="r", solution={"kind": "playbook", "run": "ansible x.yml"}))
    boot = parse_solution(_entry(name="b", solution={"kind": "reboot", "target": "{workload}"}))
    custom = parse_solution(_entry(name="w", solution={"kind": "anything-goes", "run": "do-it"}))
    assert cmd and play and boot and custom  # kind is open -- the operator vouches


def test_parse_rejects_unsigned_unmatched_no_action_and_bad_regex():
    assert parse_solution(_entry(author="")) is None  # unsigned -> not auditable
    no_match = {"name": "x", "author": "j", "solution": {"kind": "command", "run": "z"}}
    assert parse_solution(no_match) is None  # nothing to join it to a finding
    assert parse_solution(_entry(match="(")) is None  # an uncompilable regex
    assert parse_solution(_entry(solution={"kind": "command"})) is None  # a fix with no action
    assert parse_solution(_entry(impact="catastrophic")) is None  # bound must be low|medium|high


# -- match: strict, regex, both ---------------------------------------------------


def test_match_is_strict_by_category_or_fuzzy_by_title_regex():
    strict = parse_solution(_entry())  # for=Evicted
    regex = parse_solution(
        _entry(name="reboot-gw", **{"for": ""}, match=r"gateway.*(hung|not routing)",
               solution={"kind": "reboot", "target": "{workload}"})
    )
    sols = [strict, regex]

    def names(cat, title):
        return [s.name for s in solutions_for(cat, title, sols)]

    assert names("Evicted", "pod web Evicted") == ["reclaim-evicted"]  # strict, by category
    assert names("", "akeyless gateway not routing") == ["reboot-gw"]  # fuzzy, by title regex
    assert names("Healthy", "all is well") == []  # no hit


def test_match_with_both_set_requires_both():
    both = parse_solution(_entry(name="scoped", match="web"))  # for=Evicted AND title~web
    sols = [both]
    assert solutions_for("Evicted", "web Evicted", sols)  # category + title match
    assert solutions_for("Evicted", "api Evicted", sols) == []  # right category, wrong title
    assert solutions_for("Healthy", "web fine", sols) == []  # right title, wrong category


# -- store: the author + audit ---------------------------------------------------


def test_add_solution_stamps_author_and_date_and_replaces_same_name(tmp_path):
    path = str(tmp_path / "solutions.json")
    raw = {
        "name": "reclaim-evicted",
        "for": "Evicted",
        "solution": {"kind": "command", "run": "kubectl delete ..."},
    }
    sol, msg = add_solution(raw, author="dana", path=path)
    assert sol and sol.author == "dana" and sol.added  # author + date stamped on
    assert "by dana" in msg
    # re-add under the same name updates in place (not a duplicate)
    add_solution({**raw, "impact": "low"}, author="dana", path=path)
    stored = load_solutions(path)
    assert len(stored) == 1 and stored[0].name == "reclaim-evicted"


def test_load_skips_invalid_keeps_valid(tmp_path):
    path = tmp_path / "solutions.json"
    path.write_text(json.dumps([_entry(), {"name": "bad", "author": "j"}, _entry(name="ok")]))
    names = sorted(s.name for s in load_solutions(str(path)))
    assert names == ["ok", "reclaim-evicted"]  # the unmatched 'bad' entry is dropped, not fatal


# -- surfacing: the payoff -------------------------------------------------------


def test_show_surfaces_a_matched_solution_with_its_author(tmp_path, monkeypatch):
    sp = tmp_path / "solutions.json"
    sp.write_text(json.dumps([_entry()]))
    monkeypatch.setenv("STEADYSTATE_SOLUTIONS", str(sp))
    db = str(tmp_path / "s.db")
    with StateStore(db) as store:
        store.record(
            {"a" * 64: ("medium", "pod web Evicted in default")},
            datetime.now(UTC),
            {"a" * 64: {"category": "Evicted", "namespace": "default"}},
        )
    out = _render_show("a" * 64, db)
    assert "known solution" in out and "reclaim-evicted" in out and "by jeff" in out


def test_solutions_view_lists_the_runbook(tmp_path, monkeypatch):
    sp = tmp_path / "solutions.json"
    sp.write_text(json.dumps([_entry()]))
    monkeypatch.setenv("STEADYSTATE_SOLUTIONS", str(sp))
    assert "reclaim-evicted" in _render_solutions()
    assert "no solutions authored" in _render_solutions(str(tmp_path / "missing.json"))


def test_describe_solution_shows_action_join_bound_and_author():
    line = describe_solution(parse_solution(_entry()))
    assert "reclaim-evicted" in line and "for=Evicted" in line and "[low/high]" in line
    assert "by jeff" in line
