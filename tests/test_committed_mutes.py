"""Committed mutes -- 'this is benign' survives any state.db. These pin the file format (object
keyed by fingerprint; malformed degrades to none), the import-on-scan (a FRESH db suppresses a
committed fingerprint on its first reconcile and first probe-record; idempotent; never fights a
snooze), the promotion paths (`mute --commit`, the bulk `commit-mutes` export -- merging,
reviewable, snoozes stay db-local), and the unmute honesty (a committed mute warns that the next
scan re-applies it)."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from typer.testing import CliRunner

from steadystate.cli import app
from steadystate.model import ChangeType, Drift, Provenance
from steadystate.mutes import (
    apply_committed_mutes,
    commit_mute,
    committed_warning,
    export_mutes,
    load_committed_mutes,
)
from steadystate.reason.alert import Alert, Severity
from steadystate.reason.report import Report
from steadystate.reconcile_state import reconcile
from steadystate.state import StateStore
from steadystate.verbs import _unmute_finding

runner = CliRunner()
NOW = datetime.now(UTC)


def _mutes_file(tmp_path, monkeypatch, entries: dict) -> str:
    path = tmp_path / "mutes.json"
    path.write_text(json.dumps(entries))
    monkeypatch.setenv("STEADYSTATE_MUTES", str(path))
    return str(path)


def _drift(ident: str = "aws_s3_bucket.logs") -> Drift:
    return Drift(
        identity=ident,
        kind="aws_s3_bucket",
        change_type=ChangeType.MODIFIED,
        provenance=Provenance(source="terraform", address=ident),
    )


def _report(drift: Drift) -> Report:
    alert = Alert(
        title="bucket drifted", severity=Severity.HIGH, drifts=[drift], why_it_matters="w"
    )
    return Report(items=[alert])


# -- the file format ----------------------------------------------------------------------------


def test_load_is_an_object_keyed_by_fingerprint(tmp_path, monkeypatch):
    _mutes_file(tmp_path, monkeypatch, {"abc123": {"title": "noise", "by": "ops"}})
    loaded = load_committed_mutes()
    assert loaded["abc123"]["title"] == "noise" and loaded["abc123"]["by"] == "ops"


def test_malformed_file_or_entries_degrade_to_no_committed_mutes(tmp_path, monkeypatch):
    path = tmp_path / "mutes.json"
    path.write_text("not json at all")
    monkeypatch.setenv("STEADYSTATE_MUTES", str(path))
    assert load_committed_mutes() == {}
    _mutes_file(tmp_path, monkeypatch, {"good": {"title": "t"}, "bad": "not-a-dict"})
    assert list(load_committed_mutes()) == ["good"]  # one bad row never silences the rest


def test_missing_file_means_opt_in_not_error(tmp_path, monkeypatch):
    monkeypatch.setenv("STEADYSTATE_MUTES", str(tmp_path / "nowhere.json"))
    assert load_committed_mutes() == {}


# -- import-on-scan -----------------------------------------------------------------------------


def test_a_fresh_db_self_heals_on_apply(tmp_path, monkeypatch):
    _mutes_file(tmp_path, monkeypatch, {"abc123": {"title": "known noise", "by": "ops"}})
    with StateStore(":memory:") as store:
        assert apply_committed_mutes(store, NOW) == 1
        assert store.is_suppressed("abc123", NOW)  # the decision survived the db loss
        assert apply_committed_mutes(store, NOW) == 0  # idempotent


def test_apply_never_fights_an_active_snooze(tmp_path, monkeypatch):
    _mutes_file(tmp_path, monkeypatch, {"abc123": {"title": "t"}})
    with StateStore(":memory:") as store:
        store.snooze("abc123", NOW + timedelta(days=1), "ops", NOW)
        assert apply_committed_mutes(store, NOW) == 0  # suppressed already -- left alone


def test_first_reconcile_of_a_fresh_db_suppresses_a_committed_finding(tmp_path, monkeypatch):
    drift = _drift()
    _mutes_file(tmp_path, monkeypatch, {drift.fingerprint: {"title": "known benign drift"}})
    report = _report(drift)
    with StateStore(":memory:") as store:
        reconcile(report, store, NOW)
    assert report.items == []  # suppressed on the very first scan -- no re-muting by hand


def test_probe_record_path_applies_committed_mutes_too(tmp_path, monkeypatch):
    drift = _drift()
    _mutes_file(tmp_path, monkeypatch, {drift.fingerprint: {"title": "known benign drift"}})
    from steadystate.verbs import _record_probe_findings

    state = str(tmp_path / "state.db")
    _record_probe_findings(_report(_drift()), state)
    with StateStore(state) as store:
        assert store.is_suppressed(drift.fingerprint, datetime.now(UTC))


# -- promotion: mute --commit and the bulk export -------------------------------------------------


def test_mute_commit_promotes_the_decision_to_the_file(tmp_path, monkeypatch):
    path = _mutes_file(tmp_path, monkeypatch, {})
    state = str(tmp_path / "state.db")
    result = runner.invoke(
        app, ["mute", "abc123", "--commit", "--note", "benign", "--state", state]
    )
    assert result.exit_code == 0 and "committed ->" in result.output
    entry = load_committed_mutes(path)["abc123"]
    assert entry["note"] == "benign" and entry["by"] == "cli" and entry["added"]


def test_commit_mutes_exports_permanent_mutes_only_and_merges(tmp_path, monkeypatch):
    path = _mutes_file(tmp_path, monkeypatch, {"pre-existing": {"title": "kept"}})
    with StateStore(str(tmp_path / "state.db")) as store:
        store.record({"noisy1": ("low", "noisy finding one")}, NOW)
        store.mute("noisy1", "benign", "jeff", NOW)
        store.snooze("temporal", NOW + timedelta(days=2), "jeff", NOW)  # snooze stays db-local
        added, total, written = export_mutes(store)
    assert (added, total, written) == (1, 2, path)
    committed = load_committed_mutes(path)
    assert committed["noisy1"]["title"] == "noisy finding one"  # reviewable context
    assert committed["noisy1"]["by"] == "jeff"
    assert "pre-existing" in committed and "temporal" not in committed


def test_commit_mutes_cli_round_trip(tmp_path, monkeypatch):
    _mutes_file(tmp_path, monkeypatch, {})
    state = str(tmp_path / "state.db")
    runner.invoke(app, ["mute", "abc123", "--state", state])
    result = runner.invoke(app, ["commit-mutes", "--state", state])
    assert result.exit_code == 0 and "committed 1 new mute(s)" in result.output
    # ... and a brand-new db re-applies it without anyone re-muting:
    with StateStore(":memory:") as fresh:
        apply_committed_mutes(fresh, NOW)
        assert fresh.is_suppressed("abc123", NOW)


# -- unmute honesty -----------------------------------------------------------------------------


def test_unmuting_a_committed_fingerprint_warns_it_will_remute(tmp_path, monkeypatch):
    _mutes_file(tmp_path, monkeypatch, {"abc123def456": {"title": "t"}})
    with StateStore(":memory:") as store:
        store.record({"abc123def456": ("low", "t")}, NOW)
        store.mute("abc123def456", None, "ops", NOW)
        reply = _unmute_finding(store, "abc123def456")
    assert "Unmuted" in reply and "COMMITTED" in reply and "mutes.json" in reply


def test_unmuting_an_uncommitted_fingerprint_carries_no_warning(tmp_path, monkeypatch):
    _mutes_file(tmp_path, monkeypatch, {})
    with StateStore(":memory:") as store:
        store.record({"abc123def456": ("low", "t")}, NOW)
        store.mute("abc123def456", None, "ops", NOW)
        reply = _unmute_finding(store, "abc123def456")
    assert "Unmuted" in reply and "COMMITTED" not in reply
    assert committed_warning("abc123def456") == ""


def test_commit_mute_helper_merges_not_clobbers(tmp_path, monkeypatch):
    path = _mutes_file(tmp_path, monkeypatch, {"other": {"title": "kept"}})
    commit_mute("abc123", title="new one", by="jeff")
    committed = load_committed_mutes(path)
    assert set(committed) == {"other", "abc123"}


# -- the archival export: `history --json` -------------------------------------------------------


def test_history_json_exports_full_entries_for_archival(tmp_path):
    import json as jsonlib

    from steadystate.state import APPLIED, APPROVED, AuditEntry

    state = str(tmp_path / "state.db")
    with StateStore(state) as store:
        store.record_audit(
            AuditEntry(
                fingerprint="fp1",
                source="workflow",
                drift_identity="dispatch redeploy.yml",
                actor="jeff",
                decision=APPROVED,
                outcome=APPLIED,
                detail="dispatched",
            ),
            NOW,
        )
    result = runner.invoke(app, ["history", "--json", "--state", state])
    assert result.exit_code == 0
    entries = jsonlib.loads(result.output)
    assert entries[0]["actor"] == "jeff" and entries[0]["detail"] == "dispatched"
    assert entries[0]["at"]  # the store's timestamp rides along -- a real archival record
