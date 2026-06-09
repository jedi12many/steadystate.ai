"""Auto-analyze: a fatal/panic shouldn't wait to be ASKED. A scan auto-runs the RCA for newly-found
crash findings (those carrying captured crash logs) and saves it, so `show <fp>` has the writeup
waiting and a scheduled scan produces it unattended -- once per fp, only with an LLM, capped."""

from __future__ import annotations

from datetime import UTC, datetime

from steadystate.cli import _auto_analyze, _is_crash
from steadystate.model import Provenance
from steadystate.probe.base import Symptom
from steadystate.reason.alert import Severity
from steadystate.state import Finding, StateStore

_NOW = datetime(2026, 6, 3, 12, 0, 0, tzinfo=UTC)


class _FakeAnalyst:
    """Stands in for LLMAnalyst -- a configured provider whose `_complete` returns a canned RCA, so
    the real analyze_finding runs (building the evidence bundle) without a network call."""

    def __init__(self, *a, **k) -> None:
        self.calls: list = []

    def _provider(self) -> str:
        return "anthropic"

    def _complete(self, system: str, user: str, caller: str) -> str:
        return f"RCA: nil deref ({len(user)} chars of evidence read)"


def _sym(category: str = "CrashLoopBackOff", title: str = "web crashed") -> Symptom:
    return Symptom(
        identity="apps/Deployment/prod/web",
        kind="Pod",
        category=category,
        severity=Severity.HIGH,
        title=title,
        detail="d",
        provenance=Provenance(source="k8s"),
        evidence={},
    )


class _Alert:
    def __init__(self, *symptoms: Symptom) -> None:
        self.symptoms = list(symptoms)


class _Report:
    def __init__(self, *alerts: _Alert) -> None:
        self.alerts = list(alerts)


def _store_with(fp: str, details: dict) -> StateStore:
    store = StateStore()
    store.record({fp: ("high", "web is CrashLoopBackOff")}, _NOW, {fp: details})
    return store


def test_is_crash_needs_captured_crash_logs():
    def f(details: dict) -> Finding:
        return Finding("a" * 64, "t", "t", "high", "web", "open", details=details)

    assert _is_crash(f({"trace": "panic: nil pointer"})) is True
    assert _is_crash(f({"log_window": "lead-up...\npanic"})) is True
    assert _is_crash(f({"change": "modified"})) is False  # a drift -> no RCA
    assert _is_crash(f({})) is False


def test_auto_analyze_runs_the_rca_for_a_crash_and_saves_it(monkeypatch):
    monkeypatch.setattr("steadystate.cli.LLMAnalyst", _FakeAnalyst)
    sym = _sym()
    store = _store_with(
        sym.fingerprint, {"category": "CrashLoopBackOff", "log_window": "panic: nil"}
    )
    n = _auto_analyze(store, _Report(_Alert(sym)), _NOW, None)
    assert n == 1
    assert "RCA" in store.get_analysis(sym.fingerprint)[0]  # the writeup is saved -> `show` has it


def test_auto_analyze_skips_a_non_crash_and_one_already_analyzed(monkeypatch):
    monkeypatch.setattr("steadystate.cli.LLMAnalyst", _FakeAnalyst)
    # a drift finding (no captured crash logs) -> not analyzed
    drift = _sym(category="modified", title="firewall opened")
    assert (
        _auto_analyze(
            _store_with(drift.fingerprint, {"change": "modified"}),
            _Report(_Alert(drift)),
            _NOW,
            None,
        )
        == 0
    )
    # a crash already analyzed -> skipped (don't re-pay the model)
    crash = _sym()
    store = _store_with(crash.fingerprint, {"log_window": "panic"})
    store.save_analysis(crash.fingerprint, "existing RCA", _NOW)
    assert _auto_analyze(store, _Report(_Alert(crash)), _NOW, None) == 0


def test_auto_analyze_is_a_no_op_without_an_llm(monkeypatch):
    class _NoLLM(_FakeAnalyst):
        def _provider(self) -> str:
            return "none"

    monkeypatch.setattr("steadystate.cli.LLMAnalyst", _NoLLM)
    crash = _sym()
    store = _store_with(crash.fingerprint, {"log_window": "panic"})
    assert _auto_analyze(store, _Report(_Alert(crash)), _NOW, None) == 0  # no model -> nothing
