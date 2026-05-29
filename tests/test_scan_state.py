"""Integration: the memoryful scan (reconcile_state) + the state CLI commands.

These exercise the reconciliation that runs between a pure ``pipeline.run()`` and
``surface.emit()`` -- new/recurring annotation, resolved-since-last-scan, and
mute/snooze suppression -- plus the new ``mute``/``snooze``/``findings`` CLI verbs.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

from steadystate.model import ChangeType, Drift, Provenance
from steadystate.reason.alert import Alert, Layer, Severity
from steadystate.reason.report import Report
from steadystate.reconcile_state import reconcile
from steadystate.state import StateStore


def _drift(identity: str = "aws_s3_bucket.logs", source: str = "terraform") -> Drift:
    return Drift(
        identity=identity,
        kind="aws_s3_bucket",
        change_type=ChangeType.MODIFIED,
        provenance=Provenance(source=source),
    )


def _alert(drift: Drift, severity: Severity = Severity.MEDIUM) -> Alert:
    return Alert(
        title=drift.summary(),
        severity=severity,
        drifts=[drift],
        why_it_matters="declared and observed diverge",
        layer=Layer.ALERT,
    )


def _report(*alerts: Alert) -> Report:
    return Report(items=list(alerts))


def _t(day: int) -> datetime:
    return datetime(2026, 1, day, 12, 0, 0, tzinfo=UTC)


# -- reconcile: annotation ------------------------------------------------------


def test_first_scan_marks_new_then_recurring_marks_seen():
    store = StateStore()
    drift = _drift()

    report = _report(_alert(drift))
    reconcile(report, store, now=_t(1))
    alert = report.alerts[0]
    assert alert.status == "open"
    assert alert.first_seen == _t(1)  # first-seen this scan

    # A later scan of the same finding: still present, annotated as recurring (the
    # console renders an age, not NEW), first_seen preserved.
    report2 = _report(_alert(drift))
    reconcile(report2, store, now=_t(4))
    assert report2.alerts[0].first_seen == _t(1)
    assert report2.alerts[0].status == "open"


def test_muted_alert_is_dropped_from_the_report():
    store = StateStore()
    drift = _drift()
    store.mute(drift.fingerprint, "noise", "alice", _t(1))

    report = _report(_alert(drift))
    reconcile(report, store, now=_t(2))
    # Every member fingerprint is suppressed -> the Alert is dropped entirely.
    assert report.alerts == []


def test_snoozed_alert_dropped_until_expiry_then_returns():
    store = StateStore()
    drift = _drift()
    store.snooze(drift.fingerprint, until=_t(5), actor="bob", now=_t(1))

    dropped = _report(_alert(drift))
    reconcile(dropped, store, now=_t(2))
    assert dropped.alerts == []

    # After the snooze lapses the Alert surfaces again.
    returned = _report(_alert(drift))
    reconcile(returned, store, now=_t(6))
    assert len(returned.alerts) == 1


def test_partially_suppressed_alert_survives_and_shows_status():
    # A correlated Alert with one muted + one open member still surfaces (don't hide a
    # live finding because a sibling is muted), tagged with the operator state.
    store = StateStore()
    d1 = _drift(identity="aws_s3_bucket.a")
    d2 = _drift(identity="aws_s3_bucket.b")
    store.mute(d1.fingerprint, None, "alice", _t(1))

    alert = Alert(
        title="2 correlated",
        severity=Severity.HIGH,
        drifts=[d1, d2],
        why_it_matters="grouped",
        layer=Layer.ALERT,
    )
    report = _report(alert)
    reconcile(report, store, now=_t(2))
    assert len(report.alerts) == 1
    assert report.alerts[0].status == "muted"


def test_resolved_finding_is_reported_once():
    store = StateStore()
    drift = _drift()

    # Scan 1: the finding is present.
    reconcile(_report(_alert(drift)), store, now=_t(1))

    # Scan 2: it's gone -> reported as resolved this scan.
    empty = _report()
    resolved = reconcile(empty, store, now=_t(2))
    assert [r.fingerprint for r in resolved] == [drift.fingerprint]
    assert resolved[0].title == drift.summary()

    # Scan 3: still gone -> not reported again (already resolved).
    assert reconcile(_report(), store, now=_t(3)) == []


def test_signals_count_toward_presence_not_resolution():
    # A finding that drops below the Event bar to a Signal is still "present" -- it must
    # NOT be mistaken for resolved.
    store = StateStore()
    drift = _drift()
    reconcile(_report(_alert(drift)), store, now=_t(1))

    signal = Alert(
        title=drift.summary(),
        severity=Severity.LOW,
        drifts=[drift],
        why_it_matters="below bar",
        layer=Layer.SIGNAL,
    )
    resolved = reconcile(Report(items=[signal]), store, now=_t(2))
    assert resolved == []  # present as a signal -> not resolved


def test_reconcile_on_empty_report_is_noop():
    store = StateStore()
    assert reconcile(_report(), store, now=_t(1)) == []


# -- pipeline stays pure --------------------------------------------------------


def test_pipeline_run_does_not_annotate_without_a_store(monkeypatch):
    # The Pipeline never touches the store: a freshly-run Alert has no memory fields.
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    from steadystate.reason.pipeline import Pipeline

    drift = Drift(
        identity="aws_s3_bucket.logs",
        kind="aws_s3_bucket",
        change_type=ChangeType.REMOVED,
        provenance=Provenance(source="terraform"),
    )
    report = Pipeline().run([drift])
    assert report.alerts[0].first_seen is None
    assert report.alerts[0].status is None


# -- CLI ------------------------------------------------------------------------


def _plan_with_one_drift(tmp_path):
    """A minimal terraform plan JSON yielding one MODIFIED drift -> one Alert."""
    plan = {
        "resource_changes": [
            {
                "address": "aws_s3_bucket.logs",
                "type": "aws_s3_bucket",
                "change": {
                    "actions": ["update"],
                    "before": {"acl": "private"},
                    "after": {"acl": "public-read"},
                },
            }
        ]
    }
    f = tmp_path / "plan.json"
    f.write_text(json.dumps(plan))
    return f


def _runner():
    import pytest

    typer_testing = pytest.importorskip("typer.testing")
    return typer_testing.CliRunner()


def _stored_status(db, fingerprint: str) -> str | None:
    with StateStore(db) as store:
        return store.status(fingerprint)


def _only_fingerprint(db) -> str:
    with StateStore(db) as store:
        return next(f.fingerprint for f in store.all_findings())


def test_cli_mute_then_scan_suppresses_and_findings_lists(tmp_path, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    from steadystate.cli import app

    db = tmp_path / "state.db"
    plan = _plan_with_one_drift(tmp_path)
    runner = _runner()

    # First scan records + surfaces the finding (a Panel with the drift title).
    first = runner.invoke(app, ["scan", str(plan), "--state", str(db)])
    assert first.exit_code == 0, first.output
    assert "aws_s3_bucket.logs" in first.output

    # The fingerprint, read straight from the store, is what we mute.
    fp = _only_fingerprint(db)

    muted = runner.invoke(app, ["mute", fp, "--note", "expected", "--state", str(db)])
    assert muted.exit_code == 0, muted.output

    # `findings` lists the now-muted finding with its FULL fingerprint (copy-pasteable
    # into mute/snooze -- a truncated id would silently mis-target their upsert).
    listed = runner.invoke(app, ["findings", "--state", str(db)])
    assert listed.exit_code == 0, listed.output
    assert fp in listed.output
    assert "muted" in listed.output

    # A subsequent scan suppresses the muted finding's Alert -> its drift title no
    # longer appears (here it was the only finding, so the surface goes quiet).
    after = runner.invoke(app, ["scan", str(plan), "--state", str(db)])
    assert after.exit_code == 0, after.output
    assert "aws_s3_bucket.logs" not in after.output


def test_cli_snooze_then_unmute_roundtrip(tmp_path, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    from steadystate.cli import app

    db = tmp_path / "state.db"
    plan = _plan_with_one_drift(tmp_path)
    runner = _runner()
    runner.invoke(app, ["scan", str(plan), "--state", str(db)])

    fp = _only_fingerprint(db)

    snoozed = runner.invoke(app, ["snooze", fp, "--days", "7", "--state", str(db)])
    assert snoozed.exit_code == 0, snoozed.output
    assert _stored_status(db, fp) == "snoozed"

    unmuted = runner.invoke(app, ["unmute", fp, "--state", str(db)])
    assert unmuted.exit_code == 0, unmuted.output
    assert _stored_status(db, fp) == "open"


def test_cli_findings_token_mutes_without_creating_junk(tmp_path, monkeypatch):
    # Regression: the first token of a `findings` row must be the *full* fingerprint, so
    # muting that token targets the existing finding rather than upserting a new one.
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    from steadystate.cli import app

    db = tmp_path / "state.db"
    plan = _plan_with_one_drift(tmp_path)
    runner = _runner()
    runner.invoke(app, ["scan", str(plan), "--state", str(db)])

    listed = runner.invoke(app, ["findings", "--state", str(db)])
    token = listed.output.splitlines()[0].split()[0]  # what an operator would copy

    muted = runner.invoke(app, ["mute", token, "--state", str(db)])
    assert muted.exit_code == 0, muted.output

    # Exactly one finding -- the token matched the existing one, no junk row created.
    with StateStore(db) as store:
        findings = store.all_findings()
    assert len(findings) == 1
    assert findings[0].status == "muted"


def test_cli_findings_empty_message(tmp_path):
    from steadystate.cli import app

    runner = _runner()
    result = runner.invoke(app, ["findings", "--state", str(tmp_path / "state.db")])
    assert result.exit_code == 0
    assert "no findings" in result.output.lower()


def test_cli_scan_stateless_creates_no_db(tmp_path, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    from steadystate.cli import app

    db = tmp_path / "state.db"
    plan = _plan_with_one_drift(tmp_path)
    result = _runner().invoke(app, ["scan", str(plan), "--state", str(db), "--stateless"])
    assert result.exit_code == 0, result.output
    assert not db.exists()  # --stateless never opens the store
