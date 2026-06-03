"""Action envelopes + the bound: the one impact-and-reversibility calculus that governs autonomous
action across every backend. These pin the gate (what may run unattended), that it's ordinal and
policy-driven, and -- the cross-infra point -- that a terraform plan and a kubectl cleanup describe
themselves in the SAME envelope vocabulary, so one grid governs both."""

from __future__ import annotations

from steadystate.act.bounds import (
    DEFAULT_BOUND,
    Envelope,
    Impact,
    Reversibility,
    bound_from_env,
    within_bounds,
)


def _env(rev: Reversibility, impact: Impact) -> Envelope:
    return Envelope(rev, impact)


# -- the gate (default bound) ---------------------------------------------------


def test_lossless_runs_unattended_up_to_a_tenant_but_not_a_node():
    assert within_bounds(_env(Reversibility.LOSSLESS, Impact.ONE))
    assert within_bounds(_env(Reversibility.LOSSLESS, Impact.TENANT))
    assert not within_bounds(_env(Reversibility.LOSSLESS, Impact.NODE))
    assert not within_bounds(_env(Reversibility.LOSSLESS, Impact.FLEET))


def test_self_healing_is_allowed_only_to_a_single_service():
    assert within_bounds(_env(Reversibility.SELF_HEALING, Impact.SERVICE))
    assert not within_bounds(_env(Reversibility.SELF_HEALING, Impact.TENANT))


def test_recoverable_and_irreversible_never_run_unattended_by_default():
    for impact in Impact:
        assert not within_bounds(_env(Reversibility.RECOVERABLE, impact))
        assert not within_bounds(_env(Reversibility.IRREVERSIBLE, impact))


def test_a_widened_policy_lets_an_operator_open_the_bound():
    # The bound is the operator's to set: allow recoverable actions up to a service.
    policy = {**DEFAULT_BOUND, Reversibility.RECOVERABLE: Impact.SERVICE}
    assert within_bounds(_env(Reversibility.RECOVERABLE, Impact.SERVICE), policy)
    assert not within_bounds(_env(Reversibility.RECOVERABLE, Impact.TENANT), policy)


def test_the_envelope_label_is_human_readable():
    assert _env(Reversibility.LOSSLESS, Impact.TENANT).label == "lossless/tenant"


# -- the cross-infra point: the same vocabulary describes every backend ---------


def test_a_terraform_plan_and_a_kubectl_cleanup_share_the_envelope_vocabulary():
    from steadystate.act.cleanup import CLEANUP_ENVELOPE
    from steadystate.act.plan import assess
    from steadystate.model import ChangeType, Drift, Provenance

    def drift(change: ChangeType) -> Drift:
        return Drift(
            identity="aws_s3_bucket.logs",
            kind="aws_s3_bucket",
            change_type=change,
            provenance=Provenance(source="terraform", address="aws_s3_bucket.logs"),
        )

    removed = assess(drift(ChangeType.REMOVED)).envelope
    modified = assess(drift(ChangeType.MODIFIED)).envelope
    # terraform destroy is the irreversible case -> the bound escalates it (like eligible=False).
    assert removed is not None and removed.reversibility == Reversibility.IRREVERSIBLE
    assert not within_bounds(removed)
    # an in-place update is recoverable (snapshot first) -> also escalates under the default bound.
    assert modified is not None and not within_bounds(modified)
    # the kubectl cleanup, described in the SAME terms, is lossless/tenant -> within the bound.
    assert within_bounds(CLEANUP_ENVELOPE)


# -- the operator's bound dial: STEADYSTATE_BOUND overlays DEFAULT_BOUND -----------------------


def test_bound_from_env_empty_is_the_default():
    assert bound_from_env("") == DEFAULT_BOUND


def test_bound_from_env_widens_recoverable_to_re_enable_auto():
    policy = bound_from_env("recoverable=service")
    recoverable_modify = Envelope(Reversibility.RECOVERABLE, Impact.SERVICE)
    assert not within_bounds(recoverable_modify)  # escalates under the default
    assert within_bounds(recoverable_modify, policy)  # but runs once the operator widens
    # untouched reversibilities keep their default ceiling
    assert policy[Reversibility.LOSSLESS] == DEFAULT_BOUND[Reversibility.LOSSLESS]


def test_bound_from_env_none_narrows():
    policy = bound_from_env("lossless=none")
    lossless_tenant = Envelope(Reversibility.LOSSLESS, Impact.TENANT)  # the cleanup's envelope
    assert within_bounds(lossless_tenant)  # lossless/tenant is fine by default
    assert not within_bounds(lossless_tenant, policy)  # but the operator forbade lossless auto


def test_bound_from_env_skips_garbage_never_widening_on_a_typo():
    # A typo'd reversibility or impact must leave the bound conservative, never silently open it.
    assert bound_from_env("recoverble=fleet,recoverable=notatier,=service,junk") == DEFAULT_BOUND


def test_bound_from_env_accepts_multiple_pairs_and_separators():
    policy = bound_from_env("recoverable=service; irreversible=one")
    assert policy[Reversibility.RECOVERABLE] == Impact.SERVICE
    assert policy[Reversibility.IRREVERSIBLE] == Impact.ONE
