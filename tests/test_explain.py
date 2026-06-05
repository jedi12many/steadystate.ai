"""`explain` -- the LLM's grounded read of a finding (or the whole state) at the CLI.

The pure reasoning (finding_facts / explain_finding / explain_state) is tested directly with a fake
`complete`; the command is driven through Typer's CliRunner, monkeypatching the analyst so no model
call leaves the process. The load-bearing guarantees: the model is grounded ONLY in stored facts,
the right caller tag is used (for cost accounting), and with no LLM the command degrades to the raw
facts rather than failing."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from steadystate.reason.explain import explain_finding, explain_state, finding_facts
from steadystate.state import Finding, StateStore

typer_testing = pytest.importorskip("typer.testing")


def _finding(**over) -> Finding:
    base = dict(
        fingerprint="a" * 64,
        first_seen="2026-06-04T00:00:00+00:00",
        last_seen="2026-06-05T00:00:00+00:00",
        last_severity="high",
        last_title="web is CrashLoopBackOff",
        status="open",
        details={"namespace": "demo", "last_log": "OOMKilled: memory limit"},
    )
    base.update(over)
    return Finding(**base)


# -- the pure reasoning ---------------------------------------------------------


def test_finding_facts_carries_identity_and_evidence():
    facts = finding_facts(_finding())
    assert "web is CrashLoopBackOff" in facts and "severity: high" in facts
    assert "namespace: demo" in facts and "OOMKilled" in facts  # the captured evidence is included


def test_explain_finding_grounds_the_model_and_tags_the_caller():
    seen: dict = {}

    def complete(system, user, caller):
        seen["system"], seen["user"], seen["caller"] = system, user, caller
        return "web keeps OOMing; raise its memory limit."

    out = explain_finding(_finding(), complete)
    assert out == "web keeps OOMing; raise its memory limit."
    assert seen["caller"] == "explain"  # spend lands under its own caller
    assert "OOMKilled" in seen["user"]  # the model sees only the stored facts


def test_explain_state_grounds_in_the_snapshot():
    seen: dict = {}

    def complete(system, user, caller):
        seen["user"], seen["caller"] = user, caller
        return "One high finding; look at web first."

    out = explain_state("Open findings:\n  aaaa  high  web is down", complete)
    assert out == "One high finding; look at web first."
    assert seen["caller"] == "explain" and "web is down" in seen["user"]


def test_explain_finding_degrades_to_none_when_the_model_is_unavailable():
    assert explain_finding(_finding(), lambda *_a: None) is None


# -- the CLI command ------------------------------------------------------------


def _run(args, **kw):
    from steadystate.cli import app

    return typer_testing.CliRunner().invoke(app, args, **kw)


def _seed(tmp_path, finding: Finding) -> str:
    db = str(tmp_path / "s.db")
    now = datetime(2026, 6, 5, tzinfo=UTC)
    with StateStore(db) as store:
        store.record(
            {finding.fingerprint: (finding.last_severity, finding.last_title)},
            now,
            evidence={finding.fingerprint: finding.details},
        )
    return db


def _force_llm(monkeypatch, reply: str):
    monkeypatch.setattr("steadystate.reason.llm.LLMAnalyst._provider", lambda self: "anthropic")
    monkeypatch.setattr("steadystate.reason.llm.LLMAnalyst._complete", lambda self, s, u, c: reply)


def _no_llm(monkeypatch):
    monkeypatch.setattr("steadystate.reason.llm.LLMAnalyst._provider", lambda self: "none")


def test_explain_a_finding_with_the_model(monkeypatch, tmp_path):
    db = _seed(tmp_path, _finding())
    _force_llm(monkeypatch, "web is OOMing -- raise the memory limit.")
    result = _run(["explain", "a" * 12, "--state", db])  # a prefix resolves
    assert result.exit_code == 0 and "raise the memory limit" in result.stdout


def test_explain_a_finding_degrades_to_raw_facts_without_an_llm(monkeypatch, tmp_path):
    db = _seed(tmp_path, _finding())
    _no_llm(monkeypatch)
    result = _run(["explain", "a" * 64, "--state", db])
    assert result.exit_code == 0
    assert "no LLM configured" in result.stdout and "OOMKilled" in result.stdout  # the raw facts


def test_explain_an_unknown_fingerprint_is_a_clean_error(monkeypatch, tmp_path):
    db = _seed(tmp_path, _finding())
    _no_llm(monkeypatch)
    result = _run(["explain", "ffff", "--state", db])
    assert result.exit_code == 1 and "No finding matches" in result.stdout


def test_explain_the_whole_state_with_the_model(monkeypatch, tmp_path):
    db = _seed(tmp_path, _finding())
    _force_llm(monkeypatch, "One high finding: web is crashlooping. Look there first.")
    result = _run(["explain", "--state", db])  # no fingerprint -> synthesis
    assert result.exit_code == 0 and "Look there first" in result.stdout


def test_explain_nothing_open_does_not_call_the_model(monkeypatch, tmp_path):
    db = str(tmp_path / "empty.db")
    with StateStore(db):
        pass  # create an empty store

    def _boom(self, s, u, c):
        raise AssertionError("must not call the model when nothing is open")

    monkeypatch.setattr("steadystate.reason.llm.LLMAnalyst._provider", lambda self: "anthropic")
    monkeypatch.setattr("steadystate.reason.llm.LLMAnalyst._complete", _boom)
    result = _run(["explain", "--state", db])
    assert result.exit_code == 0 and "looks clear" in result.stdout
