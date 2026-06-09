"""`watch <target>` -- a bounded live-watch (default 5m, overridable) that re-probes and reports a
finding the moment it appears NEW since the watch began, then points at `analyze`. The repro tool:
trigger a transient failure, watch it land. Bounded by design; not a monitoring daemon."""

from __future__ import annotations

import re
import time
from datetime import UTC, datetime

from typer.testing import CliRunner

from steadystate.cli import _new_matches, app
from steadystate.state import Finding, StateStore


def _f(fp: str, title: str, status: str = "open") -> Finding:
    return Finding(
        fingerprint=fp,
        first_seen="t",
        last_seen="t",
        last_severity="high",
        last_title=title,
        status=status,
    )


# -- the 'what's new since last poll' core ---------------------------------------


def test_baseline_then_only_new_findings_report():
    seen: set[str] = set()
    base = [_f("a" * 64, "web CrashLoopBackOff"), _f("b" * 64, "gw Erroring")]
    _new_matches(base, None, seen)  # first poll = baseline; caller ignores the result
    assert seen == {"a" * 64, "b" * 64}
    # next poll: the same two + a NEW panic -> only the panic is fresh
    later = [*base, _f("c" * 64, "payments-gw panic")]
    fresh = _new_matches(later, None, seen)
    assert [f.fingerprint for f in fresh] == ["c" * 64]


def test_for_pattern_filters_but_still_marks_non_matches_seen():
    seen = {"a" * 64}  # 'a' already baselined
    findings = [_f("b" * 64, "noisy ERROR line"), _f("c" * 64, "fatal panic here")]
    fresh = _new_matches(findings, re.compile("panic", re.IGNORECASE), seen)
    assert [f.last_title for f in fresh] == ["fatal panic here"]  # only the match reports
    assert "b" * 64 in seen  # ...but the non-match is marked seen, so it won't re-report next poll


def test_resolved_findings_are_ignored():
    assert _new_matches([_f("a" * 64, "gone", status="resolved")], None, set()) == []


# -- the command, end to end (a finding that appears on the 2nd poll) -------------


def test_watch_catches_a_new_finding_and_points_at_analyze(tmp_path, monkeypatch):
    db = tmp_path / "s.db"
    polls = {"n": 0}

    def fake_probe(_target, _state_path, *, scan_logs):  # noqa: ARG001
        polls["n"] += 1
        if polls["n"] == 2:  # the panic shows up AFTER the baseline poll
            with StateStore(str(db)) as store:
                store.record(
                    {"a" * 64: ("high", "payments-gw panic Erroring")},
                    datetime.now(UTC),
                    {"a" * 64: {"category": "Erroring"}},
                )

    monkeypatch.setattr("steadystate.inbound.server.probe_report", fake_probe)
    monkeypatch.setattr(time, "sleep", lambda *_a: None)  # no real waiting
    out = CliRunner().invoke(
        app, ["watch", "payments", "--once", "--interval", "1s", "--state", str(db)]
    )
    assert out.exit_code == 1  # caught something -> non-zero (gate-friendly)
    assert "CAUGHT" in out.stdout and "payments-gw panic" in out.stdout
    assert "analyze a" in out.stdout  # the one-copy-paste hint to root-cause it


def test_a_bad_timeout_is_a_clean_error(tmp_path):
    args = ["watch", "t", "--timeout", "soon", "--state", str(tmp_path / "x")]
    out = CliRunner().invoke(app, args)
    assert out.exit_code == 2  # typer BadParameter, not a crash
