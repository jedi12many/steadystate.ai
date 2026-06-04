"""Chat fingerprint resolution -- the "not argument-heavy" core. An operator shouldn't copy a
64-char fingerprint to approve the obvious pending: `approve` bare takes the only one, `approve 2`
takes the second from the numbered `pending` list, and a short prefix resolves too. mute gains the
same prefix resolution while still pre-muting an unseen fingerprint. These pin the resolvers, the
parser changes (bare/ordinal approve), and one end-to-end approve through the chat dispatch."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest import mock

from steadystate.inbound.base import APPROVE, command_from_text
from steadystate.inbound.server import _resolve_mute_target, _resolve_pending, run_command
from steadystate.state import PendingAction, StateStore

_NOW = datetime(2026, 6, 3, 12, 0, 0, tzinfo=UTC)
_RESTART = "kubectl rollout restart deployment/web -n prod"


def _pending(store: StateStore, fp: str, command: str = "kubectl get pods") -> None:
    store.record_pending(
        PendingAction(fingerprint=fp, source="x", path="", drift_identity="web", command=command),
        _NOW,
    )


# -- _resolve_pending: ordinal / bare / prefix ------------------------------------------------


def test_resolve_pending_bare_takes_the_only_one():
    store = StateStore()
    _pending(store, "a" * 64)
    assert _resolve_pending(store, "") == ("a" * 64, "")


def test_resolve_pending_bare_with_many_asks_which():
    store = StateStore()
    _pending(store, "a" * 64)
    _pending(store, "b" * 64)
    fp, error = _resolve_pending(store, "")
    assert fp == "" and "pending" in error  # no guess when it's ambiguous


def test_resolve_pending_by_ordinal():
    store = StateStore()
    _pending(store, "a" * 64)
    _pending(store, "b" * 64)
    # `pending` lists oldest-first; created_at ties, so order is by (created_at, fingerprint) -> a,b
    assert _resolve_pending(store, "2")[0] == "b" * 64
    assert _resolve_pending(store, "9")[0] == ""  # out of range -> error, no fingerprint


def test_resolve_pending_by_prefix_and_ambiguity():
    store = StateStore()
    _pending(store, "abc" + "0" * 61)
    _pending(store, "abd" + "0" * 61)
    assert _resolve_pending(store, "abc")[0] == "abc" + "0" * 61  # unique prefix
    fp, error = _resolve_pending(store, "ab")  # matches both
    assert fp == "" and "matches 2" in error


def test_resolve_pending_none_pending():
    fp, error = _resolve_pending(StateStore(), "")
    assert fp == "" and "awaiting approval" in error


# -- _resolve_mute_target: prefix, but still pre-mutes the unseen ------------------------------


def test_resolve_mute_target_resolves_prefix_of_known_finding():
    store = StateStore()
    store.record({"a" * 64: ("high", "web crashlooping")}, _NOW)
    assert _resolve_mute_target(store, "aaaa")[0] == "a" * 64


def test_resolve_mute_target_passes_through_an_unseen_fingerprint():
    # pre-muting a `mute-all` correlation key or known noise the store hasn't recorded yet still
    # works -- an unmatched token is returned verbatim for the upsert.
    assert _resolve_mute_target(StateStore(), "z" * 64) == ("z" * 64, "")


# -- the parser now lets approve be bare / ordinal --------------------------------------------


def test_command_from_text_approve_can_be_bare_or_ordinal():
    bare = command_from_text("approve", "amy")
    assert bare is not None and bare.verb == APPROVE and bare.argument == ""
    ordinal = command_from_text("approve 2", "amy")
    assert ordinal is not None and ordinal.argument == "2"
    # the break-glass confirm token still rides as the optional second
    bg = command_from_text("approve abc123 worker-1234", "amy")
    assert bg is not None and bg.argument == "abc123" and bg.argument2 == "worker-1234"


# -- end to end through the chat dispatch -----------------------------------------------------


def test_chat_bare_approve_applies_the_sole_pending(tmp_path):
    db = str(tmp_path / "s.db")
    with StateStore(db) as store:
        store.record_pending(PendingAction("a" * 64, "kubectl-catalog", "", "web", _RESTART), _NOW)
    proc = mock.Mock(returncode=0, stdout="deployment.apps/web restarted", stderr="")
    with mock.patch("steadystate.act.execute.subprocess.run", return_value=proc) as run:
        msg = run_command(command_from_text("approve", "amy"), db)
    run.assert_called_once()  # bare approve found and ran the only pending
    assert "restarted" in msg


def test_chat_bare_approve_with_two_pending_asks_and_runs_nothing(tmp_path):
    db = str(tmp_path / "s.db")
    with StateStore(db) as store:
        _pending(store, "a" * 64)
        _pending(store, "b" * 64)
    with mock.patch("steadystate.act.execute.subprocess.run") as run:
        msg = run_command(command_from_text("approve", "amy"), db)
    run.assert_not_called()  # ambiguous -> guidance, never a guess
    assert "pending" in msg
