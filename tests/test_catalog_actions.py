"""The catalog's command discipline: the allow-patterns (now incl. `--kubeconfig`, injection-tight),
composing a command from a finding's keys, and the category -> offered-action map. All pure -- the
guarantee that everything `fix`/`run` could ever execute is a vetted, bounded shape."""

from __future__ import annotations

from steadystate.act.catalog import (
    FindingFields,
    action_for_command,
    is_safe_cleanup,
    is_safe_delete_node,
    is_safe_rollout_restart,
    is_safe_scale_to_zero,
    offered_action,
)
from steadystate.act.catalog import catalog_action as cat

# -- the allow-patterns now accept --kubeconfig, and stay injection-tight ----------------------


def test_rollout_restart_accepts_context_and_kubeconfig():
    base = "kubectl rollout restart deployment/web -n prod"
    assert is_safe_rollout_restart(base)
    assert is_safe_rollout_restart(base + " --context prod")
    assert is_safe_rollout_restart(base + " --context prod --kubeconfig ./prod.kubeconfig")
    assert is_safe_rollout_restart(base + " --kubeconfig /home/u/.kube/cfg")


def test_cleanup_accepts_kubeconfig():
    base = "kubectl delete pods -n prod --field-selector=status.phase=Failed"
    assert is_safe_cleanup(base + " --kubeconfig ./prod.kubeconfig")
    assert is_safe_cleanup(base + " --context prod --kubeconfig /a/b.yaml")


def test_kubeconfig_widening_does_not_open_an_injection():
    bad = [
        "kubectl rollout restart deployment/web -n prod --kubeconfig /x; rm -rf /",
        "kubectl rollout restart deployment/web -n prod --kubeconfig /x && curl evil",
        "kubectl rollout restart deployment/web -n prod --kubeconfig '/x; sh'",
        "kubectl delete pods -n prod --field-selector=status.phase=Failed --kubeconfig $(evil)",
        "kubectl rollout restart deployment/web -n prod --kubeconfig /x -- bash",
    ]
    assert not any(is_safe_rollout_restart(c) or is_safe_cleanup(c) for c in bad)


def test_rollout_restart_still_pins_one_namespace_and_a_controller():
    # the pre-existing guarantees must survive the widening
    assert not is_safe_rollout_restart("kubectl rollout restart deployment/web -A")
    assert not is_safe_rollout_restart("kubectl rollout restart pod/web -n prod")  # bare pod
    assert not is_safe_rollout_restart("kubectl delete deployment/web -n prod")  # not a restart


def test_validators_accept_flexible_argument_order():
    # The point of the flexible parser: a command that does EXACTLY the safe thing but writes its
    # flags in a different order (what an LLM proposer does) is no longer rejected on a technicality
    assert is_safe_scale_to_zero(
        "kubectl scale deployment/web -n demo --replicas=0 --context default"  # the soak's order
    )
    assert is_safe_scale_to_zero("kubectl scale deployment/web --replicas=0 --namespace=demo")
    assert is_safe_rollout_restart(
        "kubectl rollout restart deployment/web --context default -n demo"  # flags reordered
    )
    assert is_safe_cleanup("kubectl delete pods --field-selector=status.phase=Failed -n prod")


def test_validators_stay_strict_on_safety_despite_flexible_order():
    # Flexible on order, strict on safety: no extra flag, no wrong value, no bare pod, no injection.
    assert not is_safe_scale_to_zero("kubectl scale deployment/web --replicas=0 -n demo --force")
    assert not is_safe_scale_to_zero("kubectl scale deployment/web --replicas=5 -n demo")  # value
    assert not is_safe_scale_to_zero("kubectl scale pod/web --replicas=0 -n demo")  # bare pod
    assert not is_safe_scale_to_zero("kubectl scale deployment/web --replicas=0")  # ns required
    assert not is_safe_scale_to_zero(
        "kubectl scale deployment/web --replicas=0 -n demo && curl evil"  # injection
    )
    assert not is_safe_delete_node("kubectl delete node n1 -n kube-system")  # node takes no ns


# -- composing a command from a finding's keys ------------------------------------------------


def test_compose_rollout_restart_from_a_finding():
    action = cat("rollout-restart-workload")
    fields = FindingFields(kind="Deployment", name="web", namespace="prod", context="east")
    cmd = action.compose(fields)
    assert cmd == "kubectl rollout restart deployment/web -n prod --context east"
    assert action.validate(cmd)  # the composed command passes its own allow-pattern


def test_compose_includes_kubeconfig_when_present():
    action = cat("rollout-restart-workload")
    fields = FindingFields(kind="StatefulSet", name="db", namespace="data", kubeconfig="/cwd/kc")
    cmd = action.compose(fields)
    assert cmd == "kubectl rollout restart statefulset/db -n data --kubeconfig /cwd/kc"
    assert action.validate(cmd)


def test_compose_refuses_a_non_controller_or_missing_keys():
    action = cat("rollout-restart-workload")
    assert action.compose(FindingFields(kind="Pod", name="web", namespace="prod")) is None
    assert action.compose(FindingFields(kind="Deployment", name="web")) is None  # no namespace


# -- the offer map + run-time lookup ----------------------------------------------------------


def test_offered_action_maps_a_category_to_its_fix():
    assert offered_action("CrashLoopBackOff").name == "rollout-restart-workload"
    assert offered_action("Evicted").name == "reclaim-evicted-pods"
    assert offered_action("DiskFilling") is None  # no auto-fix for a full disk -> escalate


def test_action_for_command_recognizes_a_vetted_shape_and_rejects_others():
    assert action_for_command("kubectl rollout restart deployment/web -n prod").name == (
        "rollout-restart-workload"
    )
    # `delete node` IS a vetted shape now -- but a break-glass one (out of bound, handled by the
    # confirmation flow, not run here).
    assert action_for_command("kubectl delete node worker-1").name == "delete-node"
    # a command matching no vetted shape is still rejected.
    assert action_for_command("kubectl exec -it pod/web -- bash") is None
    assert action_for_command("kubectl drain worker-1") is None
