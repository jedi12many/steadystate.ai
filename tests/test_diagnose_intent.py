"""`doctor` diagnoses the authored intent files (checks.json / solutions.json) -- because they load
SILENTLY: a wrong path, a JSON syntax slip, or one bad entry all vanish with no word, so an authored
rule that 'doesn't show up' gives no clue. These pin that each silent miss becomes a clear line."""

from __future__ import annotations

import json

from steadystate.probe.custom import diagnose_checks
from steadystate.probe.solutions import diagnose_solutions

_GOOD_CHECK = {
    "name": "squid-up",
    "read": {"kind": "kubectl-log", "selector": "app=squid", "namespace": "proxy"},
    "when": {"pattern": "ready", "expect": "present"},
    "emit": {"severity": "high", "title": "squid down"},
}
_GOOD_SOLUTION = {
    "name": "reclaim",
    "for": "Evicted",
    "solution": {"kind": "command", "run": "kubectl delete pods"},
    "author": "jeff",
}


def test_missing_file_says_where_it_looked(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("STEADYSTATE_CHECKS", raising=False)
    out = "\n".join(diagnose_checks())
    assert "not found" in out and "steadystate/checks.json" in out  # names the path it looked for
    assert "STEADYSTATE_CHECKS" in out  # tells you how to point it elsewhere


def test_invalid_json_is_named_not_silently_ignored(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "steadystate").mkdir()
    (tmp_path / "steadystate" / "checks.json").write_text("{ not valid json ")
    out = "\n".join(diagnose_checks())
    assert "INVALID JSON" in out and "WHOLE file is ignored" in out  # the silent [] explained


def test_not_a_list_is_flagged(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "steadystate").mkdir()
    (tmp_path / "steadystate" / "checks.json").write_text('{"name": "x"}')  # an object, not a list
    assert "not a JSON list" in "\n".join(diagnose_checks())


def test_a_bad_entry_is_named_with_the_count_and_schema(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "steadystate").mkdir()
    (tmp_path / "steadystate" / "checks.json").write_text(
        json.dumps([_GOOD_CHECK, {"name": "broken", "read": {"kind": "not-real"}}])
    )
    out = "\n".join(diagnose_checks())
    assert "check #1 ('broken'): SKIPPED" in out  # the exact entry, by index + name
    assert "1/2 check(s) valid" in out  # the count -- 1 loaded, 1 silently dropped before
    assert "schema:" in out  # and the schema, so you can fix it


def test_all_valid_is_a_clean_count_with_no_skips(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "steadystate").mkdir()
    (tmp_path / "steadystate" / "checks.json").write_text(json.dumps([_GOOD_CHECK]))
    out = "\n".join(diagnose_checks())
    assert "1/1 check(s) valid" in out and "SKIPPED" not in out and "schema:" not in out


def test_solutions_diagnose_catches_an_unsigned_entry(tmp_path, monkeypatch):
    # the most common runbook slip: a solution with no author (rejected, silently, today)
    monkeypatch.chdir(tmp_path)
    (tmp_path / "steadystate").mkdir()
    unsigned = {**_GOOD_SOLUTION, "author": ""}
    (tmp_path / "steadystate" / "solutions.json").write_text(json.dumps([_GOOD_SOLUTION, unsigned]))
    out = "\n".join(diagnose_solutions())
    assert "runbook" in out and "solution #1" in out and "SKIPPED" in out
    assert "1/2 solution(s) valid" in out


def test_doctor_renders_the_intent_section(tmp_path, monkeypatch):
    from typer.testing import CliRunner

    from steadystate.cli import app

    monkeypatch.chdir(tmp_path)
    (tmp_path / "steadystate").mkdir()
    (tmp_path / "steadystate" / "checks.json").write_text("{ broken ")
    out = CliRunner().invoke(app, ["doctor"])
    assert out.exit_code == 0 and "Authored intent" in out.stdout and "INVALID JSON" in out.stdout
