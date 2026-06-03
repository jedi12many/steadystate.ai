"""Break-glass: the out-of-bound, human-only action tier. These pin the whole safety story --
default-CLOSED authorization, the envelope-scaled confirmation friction (light vs. type-the-target),
the override that skips the bound but NEVER the allow-pattern, and that the autonomous path can't
reach any of it. The canonical example is `delete-node` -- your test command, now a vetted shape."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest import mock

from steadystate.act.bounds import Envelope, Impact, Reversibility, confirmation_tier
from steadystate.act.breakglass import BREAKGLASS_SOURCE, breakglass_allowed
from steadystate.act.execute import run_catalog_action
from steadystate.inbound.base import Command
from steadystate.inbound.server import run_command
from steadystate.state import PendingAction, StateStore

_NOW = datetime(2026, 6, 3, 12, 0, 0, tzinfo=UTC)


def _proc(returncode=0, stdout='node "worker-1234" deleted', stderr=""):
    return mock.Mock(returncode=returncode, stdout=stdout, stderr=stderr)


# -- friction tiers (from the envelope) + default-closed authorization -------------------------


def test_confirmation_tier_scales_with_the_envelope():
    assert confirmation_tier(Envelope(Reversibility.LOSSLESS, Impact.TENANT)) == 0  # within bound
    assert confirmation_tier(Envelope(Reversibility.RECOVERABLE, Impact.SERVICE)) == 1  # light
    assert confirmation_tier(Envelope(Reversibility.IRREVERSIBLE, Impact.NODE)) == 2  # strong
    assert (
        confirmation_tier(Envelope(Reversibility.SELF_HEALING, Impact.FLEET)) == 2
    )  # node+ -> strong


def test_breakglass_is_default_closed(monkeypatch):
    monkeypatch.delenv("STEADYSTATE_BREAKGLASS_USERS", raising=False)
    assert not breakglass_allowed("amy")  # empty allowlist -> nobody
    monkeypatch.setenv("STEADYSTATE_BREAKGLASS_USERS", "amy, bob")
    assert breakglass_allowed("amy") and breakglass_allowed("bob")
    assert not breakglass_allowed("eve")


# -- the override: skip the bound, NEVER the allow-pattern -------------------------------------


def _pending(command: str) -> PendingAction:
    return PendingAction(
        fingerprint="f" * 64,
        source=BREAKGLASS_SOURCE,
        path="",
        drift_identity="worker-1234",
        command=command,
    )


def test_an_out_of_bound_action_is_refused_without_break_glass():
    with mock.patch("steadystate.act.execute.subprocess.run") as run:
        result = run_catalog_action(_pending("kubectl delete node worker-1234"))
    run.assert_not_called()  # bound supreme on the autonomous path
    assert not result.applied and "outside the bound" in result.detail


def test_break_glass_overrides_the_bound_but_still_runs_a_vetted_shape():
    with mock.patch("steadystate.act.execute.subprocess.run", return_value=_proc()) as run:
        ok = run_catalog_action(_pending("kubectl delete node worker-1234"), break_glass=True)
    run.assert_called_once()
    assert ok.applied and "delete-node" in ok.detail
    # ...but break_glass does NOT loosen the shape vetting: an un-vetted command is still refused.
    with mock.patch("steadystate.act.execute.subprocess.run") as run:
        bad = run_catalog_action(_pending("kubectl drain worker-1234"), break_glass=True)
    run.assert_not_called()
    assert not bad.applied and "not a recognized catalog command" in bad.detail


# -- the chat flow, end to end ----------------------------------------------------------------


def _record_node(db, fp, node="worker-1234"):
    with StateStore(str(db)) as store:
        store.record(
            {fp: ("high", f"{node} disk full")},
            _NOW,
            {fp: {"category": "DiskFilling", "node": node, "cluster": "east"}},
        )


def _cmd(verb, actor, arg="", arg2=""):
    return Command(verb=verb, actor=actor, argument=arg, argument2=arg2)


def test_break_glass_is_refused_for_an_unauthorized_operator(tmp_path, monkeypatch):
    monkeypatch.delenv("STEADYSTATE_BREAKGLASS_USERS", raising=False)
    db = tmp_path / "s.db"
    fp = "a" * 64
    _record_node(db, fp)
    msg = run_command(_cmd("run", "amy", "delete-node", fp), str(db))
    assert "BREAK-GLASS" in msg and "aren't authorized" in msg
    with StateStore(str(db)) as store:
        assert store.all_pending() == []  # nothing recorded -> nothing to confirm


def test_strong_tier_challenges_then_runs_only_on_the_typed_target(tmp_path, monkeypatch):
    monkeypatch.setenv("STEADYSTATE_BREAKGLASS_USERS", "amy")
    db = tmp_path / "s.db"
    fp = "a" * 64
    _record_node(db, fp, node="worker-1234")

    # run delete-node -> a challenge that records a pending but runs nothing.
    with mock.patch("steadystate.act.execute.subprocess.run") as run:
        challenge = run_command(_cmd("run", "amy", "delete-node", fp), str(db))
    run.assert_not_called()
    assert "BREAK-GLASS" in challenge and "kubectl delete node worker-1234" in challenge
    assert "worker-1234" in challenge  # tells you to type the node name

    # approve WITHOUT the token -> refused, asks for the target.
    with mock.patch("steadystate.act.execute.subprocess.run") as run:
        nope = run_command(_cmd("approve", "amy", fp), str(db))
    run.assert_not_called()
    assert "type the target" in nope

    # approve with the WRONG token -> still refused.
    with mock.patch("steadystate.act.execute.subprocess.run") as run:
        wrong = run_command(_cmd("approve", "amy", fp, "worker-9999"), str(db))
    run.assert_not_called()
    assert "type the target" in wrong

    # approve with the right token -> runs, audited as a break-glass override.
    with mock.patch("steadystate.act.execute.subprocess.run", return_value=_proc()) as run:
        done = run_command(_cmd("approve", "amy", fp, "worker-1234"), str(db))
    run.assert_called_once()
    assert "deleted" in done
    with StateStore(str(db)) as store:
        [entry] = store.audit_log(limit=5)
    assert entry.actor == "amy" and entry.decision == "break-glass"


def test_confirm_re_checks_authorization(tmp_path, monkeypatch):
    # amy records the challenge while authorized; if she's then removed from the allowlist, the
    # confirm is refused -- the gate is re-checked at run time, not just at challenge time.
    monkeypatch.setenv("STEADYSTATE_BREAKGLASS_USERS", "amy")
    db = tmp_path / "s.db"
    fp = "a" * 64
    _record_node(db, fp)
    run_command(_cmd("run", "amy", "delete-node", fp), str(db))  # records the pending
    monkeypatch.delenv("STEADYSTATE_BREAKGLASS_USERS", raising=False)
    with mock.patch("steadystate.act.execute.subprocess.run") as run:
        msg = run_command(_cmd("approve", "amy", fp, "worker-1234"), str(db))
    run.assert_not_called()
    assert "not enabled for you" in msg
