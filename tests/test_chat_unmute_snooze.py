"""Chat `unmute` + `snooze` -- closing the one-way-mute gap. You could silence a finding from chat
but had to go to the CLI to lift it; now `unmute <fp>` and `snooze <fp> <duration>` round it out.
These pin the duration parser, the two verbs end-to-end through the dispatch, and the parser shapes
(unmute one-arg, snooze two-arg)."""

from __future__ import annotations

from datetime import UTC, datetime

from steadystate.inbound.base import SNOOZE, UNMUTE, command_from_text
from steadystate.state import OPEN, SNOOZED, StateStore
from steadystate.verbs import _parse_duration, run_command

_NOW = datetime(2026, 6, 3, 12, 0, 0, tzinfo=UTC)


# -- the duration parser ----------------------------------------------------------------------


def test_parse_duration_units_and_bare_days():
    assert _parse_duration("2d").days == 2
    assert _parse_duration("3h").seconds == 3 * 3600
    assert _parse_duration("45m").seconds == 45 * 60
    assert _parse_duration("1w").days == 7
    assert _parse_duration("5").days == 5  # bare number -> days (the CLI snooze unit)


def test_parse_duration_rejects_junk():
    for bad in ("", "abc", "0d", "-1d", "d", "2x", "1.5d"):
        assert _parse_duration(bad) is None


# -- unmute -----------------------------------------------------------------------------------


def test_chat_unmute_lifts_a_mute(tmp_path):
    db = str(tmp_path / "s.db")
    fp = "a" * 64
    with StateStore(db) as store:
        store.record({fp: ("high", "web crashlooping")}, _NOW)
        store.mute(fp, None, "amy", _NOW)
    msg = run_command(command_from_text(f"unmute {fp}", "amy"), db)
    assert "Unmuted" in msg
    with StateStore(db) as store:
        assert store.status(fp) == OPEN  # back to surfacing


def test_chat_unmute_resolves_a_prefix_and_reports_unknown(tmp_path):
    db = str(tmp_path / "s.db")
    fp = "abcd" + "0" * 60
    with StateStore(db) as store:
        store.record({fp: ("high", "web")}, _NOW)
        store.mute(fp, None, "amy", _NOW)
    assert "Unmuted" in run_command(command_from_text("unmute abcd", "amy"), db)  # prefix
    assert "Unknown" in run_command(command_from_text("unmute zzzz", "amy"), db)  # not stored


# -- snooze -----------------------------------------------------------------------------------


def test_chat_snooze_silences_for_a_duration(tmp_path):
    db = str(tmp_path / "s.db")
    fp = "b" * 64
    with StateStore(db) as store:
        store.record({fp: ("high", "web")}, _NOW)
    msg = run_command(command_from_text(f"snooze {fp} 2d", "amy"), db)
    assert "Snoozed" in msg
    with StateStore(db) as store:
        assert store.status(fp) == SNOOZED


def test_chat_snooze_rejects_a_bad_duration(tmp_path):
    db = str(tmp_path / "s.db")
    fp = "c" * 64
    with StateStore(db) as store:
        store.record({fp: ("high", "web")}, _NOW)
    msg = run_command(command_from_text(f"snooze {fp} soon", "amy"), db)
    assert "isn't a duration" in msg
    with StateStore(db) as store:
        assert store.status(fp) == OPEN  # unchanged -- never defaulted


# -- the parser shapes ------------------------------------------------------------------------


def test_parser_unmute_one_arg_snooze_two_args():
    um = command_from_text("unmute deadbeef", "amy")
    assert um is not None and um.verb == UNMUTE and um.argument == "deadbeef"
    sn = command_from_text("snooze deadbeef 3h", "amy")
    assert (
        sn is not None and sn.verb == SNOOZE and sn.argument == "deadbeef" and sn.argument2 == "3h"
    )
    assert command_from_text("snooze deadbeef", "amy") is None  # both parts required
