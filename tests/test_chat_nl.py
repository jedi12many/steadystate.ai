"""Natural-language chat: the LLM maps free text to ONE vetted command, never executes. These pin
the read-vs-effectful tiering (a read runs, an effectful verb is echoed to confirm), the
verb-must-be-vetted guard, clarify/unmappable handling, and the live-state grounding snapshot."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from steadystate.inbound.base import PROBE, Command
from steadystate.inbound.translate import nl_to_command, state_snapshot
from steadystate.state import PendingAction, StateStore


def _complete_returning(payload: dict):
    """A fake LLM `complete` returning ``payload`` as JSON -- captures the prompt for assertions."""
    seen: dict = {}

    def complete(system: str, user: str, caller: str) -> str:
        seen["system"], seen["user"], seen["caller"] = system, user, caller
        return json.dumps(payload)

    return complete, seen


# -- the tiering: a read verb runs, an effectful verb is echoed to confirm --------------------


def test_read_verb_is_returned_ready_to_run():
    complete, seen = _complete_returning({"verb": "probe", "argument": "all", "flags": ["verbose"]})
    result = nl_to_command("how's the whole fleet looking?", "amy", complete)
    assert result.command == Command(PROBE, "amy", "all", flags=frozenset({"verbose"}))
    assert result.interpreted == "probe all"  # the canonical form, shown before the output
    assert result.message is None
    assert seen["caller"] == "chat-nl"  # rides the analyst seam under its own caller tag


def test_effectful_verb_is_never_run_only_echoed_to_confirm():
    complete, _ = _complete_returning({"verb": "approve", "argument": "a1b2c3"})
    result = nl_to_command("go ahead and approve the web restart", "amy", complete)
    assert result.command is None  # NOT executed from fuzzy text
    assert "approve a1b2c3" in result.message  # the concrete command to send
    assert "guardrailed-write" in result.message  # and it says what kind of action it is


def test_only_a_vetted_verb_is_accepted():
    complete, _ = _complete_returning({"verb": "rm-rf-everything", "argument": "prod"})
    result = nl_to_command("nuke prod", "amy", complete)
    assert result.command is None and "couldn't map" in result.message


def test_a_clarifying_question_is_passed_through():
    complete, _ = _complete_returning(
        {"verb": None, "clarify": "Which workload -- web or api? Both are crashlooping."}
    )
    result = nl_to_command("restart the broken one", "amy", complete)
    assert result.command is None
    assert result.message == "Which workload -- web or api? Both are crashlooping."


def test_unparseable_reply_degrades_to_help():
    result = nl_to_command("hi", "amy", lambda *_a: "not json at all")
    assert result.command is None and "help" in result.message
    # and an empty reply (model unreachable / kill switch) degrades too, never crashes
    assert nl_to_command("hi", "amy", lambda *_a: None).command is None


# -- grounding: the snapshot the model resolves references against ----------------------------


def test_state_snapshot_lists_pendings_and_findings(tmp_path):
    db = str(tmp_path / "s.db")
    now = datetime(2026, 6, 4, tzinfo=UTC)
    with StateStore(db) as store:
        store.record({"a" * 64: ("high", "web is CrashLoopBackOff")}, now)
        store.record_pending(
            PendingAction("b" * 64, "kubectl-catalog", "", "web", "kubectl x"), now
        )
    snap = state_snapshot(db)
    assert "Pending" in snap and "bbbbbbbbbbbb" in snap and "web" in snap
    assert "Open findings" in snap and "aaaaaaaaaaaa" in snap and "CrashLoopBackOff" in snap
    assert state_snapshot(str(tmp_path / "absent.db")) == ""  # no store yet -> empty, no crash
