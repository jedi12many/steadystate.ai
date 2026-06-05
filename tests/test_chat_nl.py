"""Natural-language chat: the LLM maps free text to ONE vetted command, never executes. These pin
the read-vs-effectful tiering (a read runs, an effectful verb is echoed to confirm), the
verb-must-be-vetted guard, clarify/unmappable handling, and the live-state grounding snapshot."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from steadystate.inbound.base import APPROVE, FINDINGS, PROBE, SHOW, Command
from steadystate.inbound.translate import confident_command, nl_to_command, state_snapshot
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


# -- ask mode: a question gets a grounded answer, not a command ------------------------------


def test_a_question_gets_a_grounded_answer():
    complete, _ = _complete_returning(
        {
            "verb": None,
            "answer": "web is CrashLoopBackOff -- its last log was OOMKilled, so it's hitting its "
            "memory limit.",
        }
    )
    result = nl_to_command("why is web unhealthy?", "amy", complete)
    assert result.command is None
    assert "OOMKilled" in result.message  # the model's prose answer, shown as-is


def test_a_command_still_wins_over_an_answer():
    # If the model fills both a verb and an answer, the action intent wins -- run the command.
    complete, _ = _complete_returning({"verb": "probe", "argument": "all", "answer": "looks busy"})
    result = nl_to_command("check everything", "amy", complete)
    assert result.command == Command(PROBE, "amy", "all")


def test_snapshot_evidence_carries_finding_fields_for_answering(tmp_path):
    db = str(tmp_path / "s.db")
    now = datetime(2026, 6, 4, tzinfo=UTC)
    with StateStore(db) as store:
        store.record(
            {"c" * 64: ("high", "web is CrashLoopBackOff")},
            now,
            evidence={"c" * 64: {"namespace": "demo", "last_log": "OOMKilled: memory limit"}},
        )
    plain = state_snapshot(db)
    rich = state_snapshot(db, with_evidence=True)
    assert "OOMKilled" not in plain  # compact view: titles only, no evidence
    assert "evidence:" in rich and "OOMKilled" in rich and "namespace=demo" in rich


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


# -- confident_command: the deterministic-first guard (don't mis-grab a sentence) -------------


def test_confident_command_runs_a_genuine_typed_command():
    # A real typed command parses and runs deterministically -- the model is never consulted.
    assert confident_command("probe all", "amy") == Command(PROBE, "amy", "all")
    assert confident_command("show a1b2c3d4", "amy") == Command(SHOW, "amy", "a1b2c3d4")
    assert confident_command("findings web", "amy") == Command(FINDINGS, "amy", "web")  # keyword ok


def test_confident_command_declines_a_verb_leading_sentence():
    # "show me the findings" must NOT run as `show me` (fingerprint 'me') -- 'me' isn't reference-
    # shaped, so confident_command declines and the REPL hands the line to the model instead.
    assert confident_command("show me the findings", "amy") is None
    assert confident_command("run the restart on web please", "amy") is None
    # bare numeric / hex references are still confident commands (ordinal + prefix resolution).
    assert confident_command("show 3", "amy") == Command(SHOW, "amy", "3")


def test_confident_command_guards_an_optional_fingerprint_but_not_a_bare_verb():
    # `approve` takes an OPTIONAL fingerprint: bare is a confident command (the only pending), but
    # "approve the web fix" ('approve the') must fall through to the model -- never fire it.
    assert confident_command("approve", "amy") == Command(APPROVE, "amy", "")
    assert confident_command("approve 2", "amy") == Command(APPROVE, "amy", "2")
    assert confident_command("go ahead and approve the web fix", "amy") is None


# -- grounding: the exact catalog action names, so `run` isn't filled with an abbreviation ----


def test_nl_prompt_grounds_run_with_the_exact_catalog_action_names():
    complete, seen = _complete_returning({"verb": "actions"})
    nl_to_command("what can I run?", "amy", complete)
    # The vetted action names ride in the prompt, so the model fills `run`'s action verbatim
    # (`rollout-restart-workload`) rather than inventing an abbreviation (`restart`).
    assert "Vetted actions" in seen["user"] and "rollout-restart-workload" in seen["user"]
