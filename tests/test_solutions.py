"""The authored runbook: parse + match (strict / regex / both) + store with an author, and the
surfacing of a matched solution against a finding in `show`. A solution is operator-vouched, so the
body is open -- the tests pin the *structure* + *matching* + *audit*, not a content restriction."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from steadystate.probe.solutions import (
    add_solution,
    describe_solution,
    load_solutions,
    parse_solution,
    solutions_for,
)
from steadystate.state import StateStore
from steadystate.verbs import _render_show, _render_solutions


def _entry(**over):
    base = {
        "name": "reclaim-evicted",
        "for": "Evicted",
        "problem": "evicted pods pile up as Failed",
        "solution": {"kind": "command", "run": "kubectl delete pods --field-selector=... -n {ns}"},
        "impact": "low",
        "reversibility": "high",
        "author": "ops",
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
        _entry(
            name="reboot-gw",
            **{"for": ""},
            match=r"gateway.*(hung|not routing)",
            solution={"kind": "reboot", "target": "{workload}"},
        )
    )
    sols = [strict, regex]

    def names(cat, title):
        return [s.name for s in solutions_for(cat, title, sols)]

    assert names("Evicted", "pod web Evicted") == ["reclaim-evicted"]  # strict, by category
    assert names("", "payments gateway not routing") == ["reboot-gw"]  # fuzzy, by title regex
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
    assert "known solution" in out and "reclaim-evicted" in out and "by ops" in out


def test_solutions_view_lists_the_runbook(tmp_path, monkeypatch):
    sp = tmp_path / "solutions.json"
    sp.write_text(json.dumps([_entry()]))
    monkeypatch.setenv("STEADYSTATE_SOLUTIONS", str(sp))
    assert "reclaim-evicted" in _render_solutions()
    assert "no solutions authored" in _render_solutions(str(tmp_path / "missing.json"))


def test_describe_solution_shows_action_join_bound_and_author():
    line = describe_solution(parse_solution(_entry()))
    assert "reclaim-evicted" in line and "for=Evicted" in line and "[low/high]" in line
    assert "by ops" in line


# -- solutions_for_alert: matching a runbook fix to an alert (for surfaces) --------


class _Sym:
    def __init__(self, category):
        self.category = category


class _Alert:
    def __init__(self, title, symptoms):
        self.title = title
        self.symptoms = symptoms


def test_solutions_for_alert_matches_by_symptom_category_or_drift_title():
    from steadystate.probe.solutions import solutions_for_alert

    alert = _Alert("web pods Evicted", [_Sym("Evicted")])
    by_cat = solutions_for_alert(alert, [parse_solution(_entry())])
    assert [s.name for s in by_cat] == ["reclaim-evicted"]  # matched on the symptom category
    # a drift-only alert (no symptom categories) still matches a title-regex solution
    regex = parse_solution(_entry(name="fw", **{"for": ""}, match="firewall"))
    drift_alert = _Alert("modified firewall opened to 0.0.0.0/0", [])
    assert [s.name for s in solutions_for_alert(drift_alert, [regex])] == ["fw"]


def test_solutions_for_alert_dedupes_and_is_empty_without_a_runbook():
    from steadystate.probe.solutions import solutions_for_alert

    alert = _Alert("web Evicted", [_Sym("Evicted"), _Sym("Evicted")])  # repeated category
    assert len(solutions_for_alert(alert, [parse_solution(_entry())])) == 1  # one solution, once
    assert solutions_for_alert(alert, []) == []  # no runbook -> nothing


# -- authoring: the verbs (an agent / plain English writes to the runbook) --------


def test_add_solution_handler_stores_with_the_calling_author(tmp_path, monkeypatch):
    from steadystate.verbs import _add_solution

    monkeypatch.setenv("STEADYSTATE_SOLUTIONS", str(tmp_path / "sol.json"))
    payload = json.dumps(
        {
            "name": "reclaim",
            "for": "Evicted",
            "solution": {"kind": "command", "run": "kubectl delete pods -n {namespace}"},
        }
    )
    msg = _add_solution(payload, author="copilot")
    assert "added" in msg and "by copilot" in msg  # the calling agent is the author
    assert load_solutions()[0].author == "copilot"
    # a non-JSON payload is a clean message, not a crash
    assert "couldn't parse" in _add_solution("not json", author="x")


def test_define_solution_proposes_json_via_the_llm_seam():
    from steadystate.probe.solutions import define_solution

    drafted = json.dumps(
        {
            "name": "reclaim-evicted",
            "for": "Evicted",
            "solution": {"kind": "command", "run": "kubectl delete pods -n {namespace}"},
            "author": "the-agent",
        }
    )
    proposed = define_solution("delete evicted pods", lambda _sys, _msg, _caller: drafted)
    assert proposed["name"] == "reclaim-evicted" and proposed["for"] == "Evicted"
    # no model / no JSON -> None (the caller falls back to add-solution with JSON)
    assert define_solution("x", lambda *_a: None) is None


def test_add_solution_is_exposed_only_at_the_author_tier():
    from steadystate.inbound.mcp import mcp_tools

    read_only = {t["name"] for t in mcp_tools(write=False, author=False)}
    authoring = {t["name"] for t in mcp_tools(write=False, author=True)}
    assert "add-solution" not in read_only  # not a read-only tool
    assert "add-solution" in authoring  # the --author middle tier exposes it (no full --write)


# -- the committed-intent convention: steadystate/ (committed) over .steadystate/ (gitignored) ----


def test_intent_paths_prefer_the_committed_steadystate_dir(tmp_path, monkeypatch):
    from steadystate.probe.custom import resolve_checks_path
    from steadystate.probe.solutions import resolve_solutions_path

    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("STEADYSTATE_SOLUTIONS", raising=False)
    monkeypatch.delenv("STEADYSTATE_CHECKS", raising=False)
    # a fresh repo -> the COMMITTED location (a new fix is version-controllable, not lost-as-state)
    assert resolve_solutions_path() == "steadystate/solutions.json"
    assert resolve_checks_path() == "steadystate/checks.json"
    # only the legacy gitignored file exists -> read it (back-compat for existing setups)
    (tmp_path / ".steadystate").mkdir()
    (tmp_path / ".steadystate" / "solutions.json").write_text("[]")
    assert resolve_solutions_path() == ".steadystate/solutions.json"
    # the committed file exists -> prefer it over the legacy one
    (tmp_path / "steadystate").mkdir()
    (tmp_path / "steadystate" / "solutions.json").write_text("[]")
    assert resolve_solutions_path() == "steadystate/solutions.json"
    # env + explicit still win over either default
    monkeypatch.setenv("STEADYSTATE_SOLUTIONS", "/custom.json")
    assert resolve_solutions_path() == "/custom.json"
    assert resolve_solutions_path("/explicit.json") == "/explicit.json"
