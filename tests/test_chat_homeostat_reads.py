"""Chat `hold` + `learn` -- surfacing the homeostat as cheap, no-arg reads. `hold` shows the
control-loop posture (each reflex's autonomy, what's not holding, the decider grant); `learn` shows
what resolved out-of-band and what to do about it. Both are read-only store reads -- no fresh scan
(that's `probe`). These pin both views end-to-end through the dispatch."""

from __future__ import annotations

from datetime import UTC, datetime

from steadystate.inbound.base import command_from_text
from steadystate.state import StateStore
from steadystate.verbs import run_command

_T0 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC)
_T1 = datetime(2026, 6, 2, 12, 0, 0, tzinfo=UTC)


# -- hold: the homeostat posture --------------------------------------------------------------


def test_chat_hold_shows_reflexes_and_decider_grant(tmp_path, monkeypatch):
    monkeypatch.delenv("STEADYSTATE_DECIDER_AUTO", raising=False)
    msg = run_command(command_from_text("hold", "amy"), str(tmp_path / "s.db"))
    assert "homeostat posture" in msg
    assert "reclaim-evicted" in msg  # the built-in reflex, with its autonomy + envelope
    assert "decider autonomy: off" in msg  # the grant is surfaced, default off


def test_chat_hold_reflects_the_decider_grant(tmp_path, monkeypatch):
    monkeypatch.setenv("STEADYSTATE_DECIDER_AUTO", "1")
    msg = run_command(command_from_text("hold", "amy"), str(tmp_path / "s.db"))
    assert "decider autonomy: ON" in msg


# -- learn: lessons from out-of-band resolutions ----------------------------------------------


def _resolved_evicted(store: StateStore, fp: str, namespace: str) -> None:
    store.record(
        {fp: ("high", "pods evicted")}, _T0, {fp: {"category": "Evicted", "ns": namespace}}
    )


def test_chat_learn_surfaces_out_of_band_lessons(tmp_path):
    db = str(tmp_path / "s.db")
    with StateStore(db) as store:
        _resolved_evicted(store, "a" * 64, "web")
        _resolved_evicted(store, "b" * 64, "api")
        store.resolve_absent(set(), _T1)  # both cleared with no audit -> out-of-band resolutions
    msg = run_command(command_from_text("learn", "amy"), db)
    assert "lesson" in msg and "Evicted" in msg  # learned from the two demonstrations


def test_chat_learn_is_empty_on_a_fresh_store(tmp_path):
    msg = run_command(command_from_text("learn", "amy"), str(tmp_path / "s.db"))
    assert "Nothing learned yet" in msg
