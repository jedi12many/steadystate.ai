"""Every catalog action's compose() must only ever produce a command its OWN validate() accepts --
else steadystate offers a fix the gate then refuses (the operator sees "it suggested X but won't run
X"). This pins that round-trip for every composing action over a battery of representative,
in-contract FindingFields: normal, with the --context/--kubeconfig tail, weird-but-legal names, and
missing-key variants (which compose to None -- nothing offered, nothing to validate)."""

from __future__ import annotations

import pytest

from steadystate.act.catalog import ACTIONS, FindingFields

# k8s identities are DNS-1123 (lowercase alnum + hyphens, no spaces/metachars) and a kubeconfig is a
# normal path -- the in-contract inputs a real finding supplies via _finding_fields.
_FIELDS = [
    FindingFields(kind="Deployment", name="web", namespace="prod"),
    FindingFields(kind="StatefulSet", name="db-0", namespace="data"),
    FindingFields(kind="DaemonSet", name="log-agent", namespace="kube-system"),
    FindingFields(kind="Deployment", name="web", namespace="prod", context="prod-cluster"),
    FindingFields(
        kind="Deployment",
        name="web",
        namespace="prod",
        context="prod-cluster",
        kubeconfig="/home/op/.kube/config",
    ),
    FindingFields(name="node-7"),  # a node finding (delete-node)
    FindingFields(name="node-7", context="prod-cluster"),
    FindingFields(),  # nothing -> every compose returns None
    FindingFields(
        kind="Pod", name="web", namespace="prod"
    ),  # not a controller -> None for restart/scale
]

_COMPOSING = {name: a for name, a in ACTIONS.items() if a.compose is not None}


@pytest.mark.parametrize("name", sorted(_COMPOSING))
def test_compose_output_always_passes_the_actions_own_validator(name):
    action = _COMPOSING[name]
    assert action.compose is not None  # narrows the type for the checker
    produced = 0
    for f in _FIELDS:
        command = action.compose(f)
        if command is None:
            continue  # a needed key is missing / not a fit -- nothing offered, nothing to validate
        produced += 1
        assert action.validate(command), (
            f"{name} composed a command its own gate rejects: {command!r}"
        )
    # the round-trip only means something if compose actually fired for this action at least once
    assert produced, f"{name}: no FindingFields produced a command -- validate was never exercised"
