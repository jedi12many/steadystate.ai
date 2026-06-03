"""The trusted ACTION catalog (act/catalog.py): each entry's command allow-pattern + its envelope.

A catalog entry is only as safe as (1) its validator -- which must pin the command so tightly that
no alternate verb, extra flag, selector, namespace-widener, or shell metacharacter slips through --
and (2) its envelope being honest. These tests are the adversarial vetting every entry gets: the
exact-shape command is accepted, and a battery of widen/inject/wrong-shape variants is rejected.
(Distinct from test_catalog.py, which covers the self-describing `steadystate catalog` command.)
"""

from __future__ import annotations

import pytest

from steadystate.act.bounds import bound_from_env, within_bounds
from steadystate.act.catalog import (
    ACTIONS,
    catalog_action,
    catalog_menu,
    is_safe_completed_cleanup,
    is_safe_rollout_restart,
)
from steadystate.act.decide import AUTHORIZED, ProposedAction, gate_proposal


def _proposal(action: str, command: str) -> ProposedAction:
    return ProposedAction(action, command, "apps/Deployment/prod/web", "f" * 64, "why", "test")


# -- delete-completed-pods: the Succeeded-phase cleanup validator -----------------------------


@pytest.mark.parametrize(
    "command",
    [
        "kubectl delete pods -n prod --field-selector=status.phase=Succeeded",
        "kubectl delete pods --field-selector=status.phase=Succeeded",  # default namespace
        "kubectl delete pods -n prod --field-selector=status.phase=Succeeded --context east",
    ],
)
def test_completed_cleanup_accepts_the_exact_shapes(command):
    assert is_safe_completed_cleanup(command) is True


@pytest.mark.parametrize(
    "command",
    [
        "kubectl delete pods -n prod --field-selector=status.phase=Failed",  # wrong phase
        "kubectl delete pods --all -n prod",  # --all blows up the blast radius
        "kubectl delete pods -A --field-selector=status.phase=Succeeded",  # all namespaces
        "kubectl delete pods --all-namespaces --field-selector=status.phase=Succeeded",
        "kubectl delete pods -n prod --field-selector=status.phase=Running",  # live pods!
        "kubectl delete pvc -n prod --field-selector=status.phase=Succeeded",  # wrong resource
        "kubectl delete pods -n prod --field-selector=status.phase=Succeeded; rm -rf /",  # inject
        "kubectl delete pods -n prod --field-selector=status.phase=Succeeded && kubectl delete ns",
        "kubectl delete pods -n prod --field-selector=status.phase=Succeeded --grace-period=0",
    ],
)
def test_completed_cleanup_rejects_widened_injected_or_wrong_shapes(command):
    assert is_safe_completed_cleanup(command) is False


# -- rollout-restart-workload: the validator (self-healing pinned by shape) -----------------


@pytest.mark.parametrize(
    "command",
    [
        "kubectl rollout restart deployment/web -n prod",
        "kubectl rollout restart statefulset/db -n prod",  # all three controllers are self-healing
        "kubectl rollout restart daemonset/agent -n kube-system",
        "kubectl rollout restart deployment/web -n prod --context east",
    ],
)
def test_rollout_restart_accepts_any_controller_shape(command):
    assert is_safe_rollout_restart(command) is True


@pytest.mark.parametrize(
    "command",
    [
        "kubectl rollout restart deployment/web",  # namespace not pinned (impact firewall)
        "kubectl rollout undo deployment/web -n prod",  # undo is a different, riskier action
        "kubectl rollout restart replicaset/web-abc -n prod",  # not a vetted controller kind
        "kubectl rollout restart deployment/web -n prod --replicas=0",  # smuggled extra flag
        "kubectl delete deployment/web -n prod",  # not a restart at all
        "kubectl rollout restart deployment/web -A",  # all namespaces
        "kubectl rollout restart deployment/web -n prod; kubectl delete ns prod",  # injection
        "kubectl rollout restart deploy -n prod",  # no target name
    ],
)
def test_rollout_restart_rejects_wrong_widened_or_injected_shapes(command):
    assert is_safe_rollout_restart(command) is False


# -- the entries are registered, honestly bounded, and on the model's menu --------------------


def test_new_actions_are_registered():
    assert catalog_action("delete-completed-pods") is not None
    assert catalog_action("rollout-restart-workload") is not None


def test_new_action_envelopes_are_within_the_default_bound():
    # Both must be auto-eligible under the conservative default: lossless/tenant and
    # self_healing/service both sit inside DEFAULT_BOUND. (A catalog entry that escalated even by
    # default would still be safe -- just never autonomous -- but these two are meant to act.)
    for name in ("delete-completed-pods", "rollout-restart-workload"):
        assert within_bounds(ACTIONS[name].envelope)


def test_rollout_restart_can_be_narrowed_out_by_the_operator():
    # The bound dial reaches catalog actions too: forbidding self-healing auto escalates it.
    narrowed = bound_from_env("self_healing=none")
    assert not within_bounds(ACTIONS["rollout-restart-workload"].envelope, narrowed)


def test_menu_lists_the_new_actions_with_their_command_shape():
    menu = catalog_menu()
    assert "delete-completed-pods" in menu and "status.phase=Succeeded" in menu
    assert "rollout-restart-workload" in menu
    assert "rollout restart <deployment|statefulset|daemonset>/<name>" in menu


# -- end-to-end: the gate authorizes a valid proposal for each new action ---------------------


def test_gate_authorizes_a_valid_completed_cleanup():
    cmd = "kubectl delete pods -n prod --field-selector=status.phase=Succeeded"
    assert gate_proposal(_proposal("delete-completed-pods", cmd)).verdict == AUTHORIZED


def test_gate_authorizes_a_valid_rollout_restart():
    cmd = "kubectl rollout restart deployment/web -n prod"
    assert gate_proposal(_proposal("rollout-restart-workload", cmd)).verdict == AUTHORIZED


def test_gate_rejects_a_rollout_restart_with_a_smuggled_command():
    # The action name is vetted, but the command isn't its shape -> REJECTED at the gate, not run.
    bad = "kubectl rollout restart deployment/web -n prod; rm -rf /"
    assert gate_proposal(_proposal("rollout-restart-workload", bad)).verdict != AUTHORIZED
