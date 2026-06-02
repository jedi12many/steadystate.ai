"""Tests for the Event fingerprint and the SQLite state store (ChatOps Phase 0)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from steadystate.model import ChangeType, Drift, Provenance
from steadystate.state import OPEN, RESOLVED, StateStore


def _drift(
    source: str = "terraform",
    identity: str = "aws_s3_bucket.logs",
    change_type: ChangeType = ChangeType.MODIFIED,
) -> Drift:
    return Drift(
        identity=identity,
        kind="aws_s3_bucket",
        change_type=change_type,
        provenance=Provenance(source=source),
    )


def _t(day: int) -> datetime:
    """A deterministic UTC instant on a given day in 2026-01."""
    return datetime(2026, 1, day, 12, 0, 0, tzinfo=UTC)


# -- fingerprint ----------------------------------------------------------------


def test_fingerprint_is_stable_and_idempotent():
    a = _drift()
    b = _drift()
    # Same source/identity/change_type -> identical fingerprint, re-ingest after re-ingest.
    assert a.fingerprint == b.fingerprint
    assert a.fingerprint == a.fingerprint
    # It's a hex sha256.
    assert len(a.fingerprint) == 64
    int(a.fingerprint, 16)  # parses as hex -> raises if not


def test_fingerprint_ignores_property_churn():
    # The grain is coarse on purpose: declared/observed details change underneath but
    # "this resource is drifting" stays one finding.
    a = _drift()
    a.declared = {"acl": "private"}
    a.observed = {"acl": "public"}
    b = _drift()
    b.observed = {"acl": "totally-different"}
    assert a.fingerprint == b.fingerprint


def test_fingerprint_varies_by_source_identity_and_change_type():
    base = _drift().fingerprint
    assert _drift(source="argocd").fingerprint != base
    assert _drift(identity="aws_s3_bucket.other").fingerprint != base
    assert _drift(change_type=ChangeType.REMOVED).fingerprint != base


# -- store: structured evidence (the `raw <fp>` view) ---------------------------


def test_record_persists_evidence_and_a_bare_re_sighting_preserves_it():
    store = StateStore()
    fp = _drift().fingerprint
    store.record({fp: ("high", "squid down")}, _t(1), {fp: {"namespace": "team-a", "pods": "2"}})
    got = store.get(fp)
    assert got is not None and got.details == {"namespace": "team-a", "pods": "2"}

    # a later, cheaper sighting with NO evidence must not erase the captured detail (COALESCE).
    store.record({fp: ("high", "squid down")}, _t(2))
    assert store.get(fp).details == {"namespace": "team-a", "pods": "2"}

    # but fresh evidence overwrites.
    store.record({fp: ("high", "squid down")}, _t(3), {fp: {"namespace": "team-a", "pods": "3"}})
    assert store.get(fp).details["pods"] == "3"


def test_find_by_prefix_resolves_a_short_fingerprint_and_escapes_wildcards():
    store = StateStore()
    fp = _drift().fingerprint
    store.record({fp: ("low", "t")}, _t(1))
    assert [f.fingerprint for f in store.find_by_prefix(fp[:8])] == [fp]
    assert store.find_by_prefix("nope") == []
    # `_` is a LIKE wildcard -- it must be escaped, not match any single char.
    assert store.find_by_prefix("_" + fp[1:8]) == []


# -- store: record / new-vs-recurring -------------------------------------------


def test_record_new_then_recurring_flips_is_new_and_preserves_first_seen():
    store = StateStore()
    fp = _drift().fingerprint
    first = store.record({fp: ("medium", "modified bucket")}, _t(1))
    assert first[fp]["is_new"] is True
    assert first[fp]["first_seen"] == _t(1).isoformat()
    assert first[fp]["status"] == OPEN

    second = store.record({fp: ("high", "modified bucket")}, _t(2))
    assert second[fp]["is_new"] is False
    # first_seen is preserved across re-sightings; last_severity tracks the latest.
    assert second[fp]["first_seen"] == _t(1).isoformat()
    finding = store.get(fp)
    assert finding is not None
    assert finding.last_seen == _t(2).isoformat()
    assert finding.last_severity == "high"


def test_resolve_absent_resolves_open_then_recurrence_reactivates():
    store = StateStore()
    fp = _drift().fingerprint
    store.record({fp: ("medium", "modified bucket")}, _t(1))

    # Next scan doesn't include fp -> it has cleared.
    resolved = store.resolve_absent(set(), _t(2))
    assert resolved == [fp]
    assert store.status(fp) == RESOLVED

    # Resolving again is idempotent: a resolved finding isn't re-resolved.
    assert store.resolve_absent(set(), _t(3)) == []

    # It drifts again -> reactivated to open, first_seen preserved.
    state = store.record({fp: ("medium", "modified bucket")}, _t(4))
    assert state[fp]["is_new"] is False
    assert state[fp]["status"] == OPEN
    assert state[fp]["first_seen"] == _t(1).isoformat()
    assert store.status(fp) == OPEN


def test_resolve_absent_keeps_present_findings_open():
    store = StateStore()
    fp = _drift().fingerprint
    store.record({fp: ("low", "t")}, _t(1))
    assert store.resolve_absent({fp}, _t(2)) == []
    assert store.status(fp) == OPEN


def test_resolve_absent_leaves_muted_findings_alone():
    # A muted finding that's absent stays muted -- only open findings resolve.
    store = StateStore()
    fp = _drift().fingerprint
    store.record({fp: ("low", "t")}, _t(1))
    store.mute(fp, "noise", "alice", _t(1))
    assert store.resolve_absent(set(), _t(2)) == []
    assert store.status(fp) == "muted"


# -- store: mute / snooze / suppression -----------------------------------------


def test_mute_then_is_suppressed_and_unmute_clears():
    store = StateStore()
    fp = _drift().fingerprint
    store.mute(fp, "known noise", "alice", _t(1))
    assert store.is_suppressed(fp, _t(1)) is True
    finding = store.get(fp)
    assert finding is not None
    assert finding.note == "known noise"
    assert finding.actor == "alice"

    store.unmute(fp, _t(2))
    assert store.is_suppressed(fp, _t(2)) is False
    assert store.status(fp) == OPEN
    cleared = store.get(fp)
    assert cleared is not None
    assert cleared.note is None and cleared.actor is None


def test_snooze_suppresses_until_expiry_then_lapses():
    store = StateStore()
    fp = _drift().fingerprint
    store.snooze(fp, until=_t(5), actor="bob", now=_t(1))
    # Before expiry -> suppressed.
    assert store.is_suppressed(fp, _t(3)) is True
    # Exactly at / after expiry -> no longer suppressed (the injected clock decides).
    assert store.is_suppressed(fp, _t(5)) is False
    assert store.is_suppressed(fp, _t(6)) is False


def test_record_folds_lapsed_snooze_back_to_open():
    # A snoozed finding seen again *after* its snooze lapses returns to open (and its
    # snooze_until is cleared) so it never lingers mislabelled snoozed once it surfaces.
    store = StateStore()
    fp = _drift().fingerprint
    store.snooze(fp, until=_t(3), actor="bob", now=_t(1))
    # Seen again before expiry: still snoozed.
    assert store.record({fp: ("low", "t")}, _t(2))[fp]["status"] == "snoozed"
    # Seen again after expiry: folded to open.
    assert store.record({fp: ("low", "t")}, _t(5))[fp]["status"] == OPEN
    finding = store.get(fp)
    assert finding is not None
    assert finding.snooze_until is None


def test_record_preserves_mute_across_resighting():
    store = StateStore()
    fp = _drift().fingerprint
    store.mute(fp, "noise", "alice", _t(1))
    assert store.record({fp: ("low", "t")}, _t(2))[fp]["status"] == "muted"


def test_is_suppressed_false_for_unknown_and_open():
    store = StateStore()
    fp = _drift().fingerprint
    assert store.is_suppressed(fp, _t(1)) is False  # never seen
    store.record({fp: ("low", "t")}, _t(1))
    assert store.is_suppressed(fp, _t(1)) is False  # open, not silenced


def test_status_none_for_unknown_fingerprint():
    assert StateStore().status("deadbeef") is None


def test_mute_upserts_unknown_fingerprint():
    # An operator can mute a fingerprint the store has never surfaced (pre-empt noise).
    store = StateStore()
    fp = _drift().fingerprint
    store.mute(fp, None, "alice", _t(1))
    assert store.status(fp) == "muted"
    finding = store.get(fp)
    assert finding is not None
    assert finding.first_seen == _t(1).isoformat()


def test_unmute_unknown_is_noop():
    store = StateStore()
    store.unmute("never-seen", _t(1))  # must not raise
    assert store.status("never-seen") is None


def test_all_findings_lists_every_row():
    store = StateStore()
    fp1 = _drift(identity="a.b").fingerprint
    fp2 = _drift(identity="c.d").fingerprint
    store.record({fp1: ("low", "one"), fp2: ("high", "two")}, _t(1))
    fps = {f.fingerprint for f in store.all_findings()}
    assert fps == {fp1, fp2}


def test_store_persists_to_file_and_reopens(tmp_path):
    # CREATE TABLE IF NOT EXISTS makes reopening an existing db a safe no-op migration.
    db = tmp_path / "nested" / "state.db"
    db.parent.mkdir(parents=True)
    fp = _drift().fingerprint
    with StateStore(db) as store:
        store.record({fp: ("medium", "t")}, _t(1))
    with StateStore(db) as reopened:
        assert reopened.status(fp) == OPEN
        # Recording again on the reopened db sees it as recurring, not new.
        assert reopened.record({fp: ("medium", "t")}, _t(2))[fp]["is_new"] is False


def test_record_returns_only_seen_fingerprints():
    store = StateStore()
    fp1 = _drift(identity="a.b").fingerprint
    fp2 = _drift(identity="c.d").fingerprint
    store.record({fp1: ("low", "one")}, _t(1))
    out = store.record({fp2: ("low", "two")}, _t(2))
    assert set(out) == {fp2}


def test_snooze_until_in_the_past_never_suppresses():
    store = StateStore()
    fp = _drift().fingerprint
    store.snooze(fp, until=_t(1), actor="bob", now=_t(5))
    assert store.is_suppressed(fp, _t(6)) is False


def test_default_store_path_is_in_memory():
    # The default :memory: store stays off disk -- handy for ad-hoc use and tests.
    store = StateStore()
    fp = _drift().fingerprint
    store.record({fp: ("low", "t")}, datetime.now(UTC) - timedelta(days=1))
    assert store.status(fp) == OPEN
