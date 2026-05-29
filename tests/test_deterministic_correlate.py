"""Deterministic correlation: grouping Events by shared attribute, no model call.

The grouping is pure and unit-testable; these tests pin the key priority (file, then
identity namespace, then singleton), the coverage invariant, the honest llm_backed
label, and that the pipeline now folds shared-attribute drifts into grouped Alerts
even with no provider. We also assert the `deterministic` correlator never calls the
model by monkeypatching LLMAnalyst._complete to raise if touched.
"""

import pytest

from steadystate.model import ChangeType, Drift, Provenance
from steadystate.reason.correlate import (
    DeterministicCorrelator,
    LLMCorrelator,
    correlate,
)
from steadystate.reason.llm import LLMAnalyst
from steadystate.reason.pipeline import Pipeline, build_correlator, select_correlator


def _drift(
    identity: str,
    *,
    file: str | None = None,
    change_type: ChangeType = ChangeType.REMOVED,
    kind: str = "node",
) -> Drift:
    return Drift(
        identity=identity,
        kind=kind,
        change_type=change_type,
        provenance=Provenance(source="terraform", address=identity, file=file),
    )


def _boom(self, system, user):  # pragma: no cover - only runs if wiring is wrong
    raise AssertionError("the model must not be called for deterministic correlation")


# --- pure grouping ----------------------------------------------------------


def test_groups_by_shared_file():
    drifts = [
        _drift("aws_instance.a", file="network.tf"),
        _drift("aws_subnet.b", file="network.tf"),
        _drift("aws_route.c", file="network.tf"),
        _drift("aws_bucket.d", file="storage.tf"),
    ]
    clusters = correlate(drifts)
    assert len(clusters) == 2
    network, storage = clusters
    assert network.drift_indexes == [0, 1, 2]
    assert "network.tf" in network.title
    assert "3" in network.title  # names the shared attribute + count
    assert storage.drift_indexes == [3]
    assert all(not c.llm_backed for c in clusters)  # honest: mechanical grouping


def test_groups_by_identity_namespace():
    # last dot-segment dropped: module.db.aws_instance.{primary,replica} -> module.db.aws_instance
    drifts = [
        _drift("module.db.aws_instance.primary"),
        _drift("module.db.aws_instance.replica"),
    ]
    clusters = correlate(drifts)
    assert len(clusters) == 1
    assert clusters[0].drift_indexes == [0, 1]
    assert "module.db.aws_instance" in clusters[0].title


def test_two_segment_identity_namespace_is_the_kind():
    # aws_s3_bucket.logs / aws_s3_bucket.audit -> namespace aws_s3_bucket
    clusters = correlate([_drift("aws_s3_bucket.logs"), _drift("aws_s3_bucket.audit")])
    assert len(clusters) == 1
    assert clusters[0].drift_indexes == [0, 1]
    assert "aws_s3_bucket" in clusters[0].title


def test_unrelated_drifts_are_separate_singletons():
    # different namespaces and no file -> nothing shared -> a Cluster of one each.
    clusters = correlate([_drift("aws_s3_bucket.logs"), _drift("aws_instance.web")])
    assert [c.drift_indexes for c in clusters] == [[0], [1]]
    assert all(len(c.drift_indexes) == 1 for c in clusters)


def test_single_segment_identities_never_merge():
    # no dot -> no namespace -> keyless -> each its own singleton (not one merged group).
    clusters = correlate([_drift("alpha"), _drift("beta")])
    assert [c.drift_indexes for c in clusters] == [[0], [1]]


def test_file_takes_priority_over_namespace():
    # same namespace but different files -> file wins -> two groups, not one.
    drifts = [
        _drift("aws_s3_bucket.logs", file="a.tf"),
        _drift("aws_s3_bucket.audit", file="b.tf"),
    ]
    clusters = correlate(drifts)
    assert len(clusters) == 2
    assert [c.drift_indexes for c in clusters] == [[0], [1]]


def test_coverage_invariant_every_index_exactly_once():
    drifts = [
        _drift("aws_s3_bucket.logs", file="net.tf"),
        _drift("module.db.aws_instance.primary"),
        _drift("module.db.aws_instance.replica"),
        _drift("solo"),
        _drift("aws_s3_bucket.audit", file="net.tf"),
    ]
    clusters = correlate(drifts)
    seen = [i for c in clusters for i in c.drift_indexes]
    assert sorted(seen) == list(range(len(drifts)))  # every index
    assert len(seen) == len(drifts)  # exactly once


def test_empty_input_is_empty():
    assert correlate([]) == []


def test_why_it_matters_is_honest_about_mechanical_grouping():
    clusters = correlate([_drift("x.a", file="f.tf"), _drift("x.b", file="f.tf")])
    why = clusters[0].why_it_matters.lower()
    assert "mechanical" in why or "not by analyzed root cause" in why
    assert clusters[0].recommended_action is None


def test_why_lists_multiple_kinds_in_a_group():
    # mixed kinds in one file -> the summary enumerates the distinct kinds.
    drifts = [
        _drift("aws_instance.a", file="net.tf", kind="aws_instance"),
        _drift("aws_subnet.b", file="net.tf", kind="aws_subnet"),
    ]
    why = correlate(drifts)[0].why_it_matters
    assert "aws_instance" in why and "aws_subnet" in why


# --- selection via build_correlator (auto / llm / deterministic) -------------
#
# Correlator selection is now the registry builder (build_correlator), which returns
# Correlator *instances*, not bare functions. select_correlator is kept as a thin
# back-compat wrapper; these tests pin both, preserving the old selection intent.


def test_build_deterministic_returns_deterministic_correlator(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    chosen = build_correlator("deterministic", LLMAnalyst())
    assert isinstance(chosen, DeterministicCorrelator)
    assert chosen.name == "deterministic"
    # still the pure grouping under the hood -- it delegates to correlate().
    assert chosen.correlate([]) == correlate([])


def test_build_llm_returns_llm_correlator(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    chosen = build_correlator("llm", LLMAnalyst())
    assert isinstance(chosen, LLMCorrelator)
    assert chosen.name == "llm"


def test_build_auto_uses_deterministic_without_provider(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("STEADYSTATE_LLM_BASE_URL", raising=False)
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    analyst = LLMAnalyst()
    assert analyst._provider() == "none"
    assert isinstance(build_correlator("auto", analyst), DeterministicCorrelator)


def test_build_auto_uses_llm_with_provider(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    analyst = LLMAnalyst()
    assert analyst._provider() == "anthropic"
    chosen = build_correlator("auto", analyst)
    assert isinstance(chosen, LLMCorrelator)  # not the deterministic one
    # the LLM correlator groups via this exact analyst.
    assert chosen._analyst is analyst


def test_build_rejects_unknown_mode():
    with pytest.raises(ValueError, match="unknown correlator"):
        build_correlator("magic", LLMAnalyst())


def test_select_correlator_is_back_compat_wrapper(monkeypatch):
    # The old entry point still resolves through the registry builder.
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert isinstance(select_correlator("deterministic", LLMAnalyst()), DeterministicCorrelator)
    with pytest.raises(ValueError, match="unknown correlator"):
        select_correlator("magic", LLMAnalyst())


# --- pipeline: grouped Alerts with no provider ------------------------------


def test_pipeline_groups_shared_file_into_one_alert(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    # Two HIGH (REMOVED) drifts sharing a file -> both Events -> ONE grouped Alert,
    # not two singletons, even with no model configured.
    drifts = [
        _drift("aws_instance.a", file="network.tf"),
        _drift("aws_subnet.b", file="network.tf"),
    ]
    report = Pipeline(correlator="deterministic").run(drifts)
    assert len(report.alerts) == 1
    alert = report.alerts[0]
    assert len(alert.drifts) == 2
    assert alert.llm_backed is False
    assert "network.tf" in alert.title
    assert report.event_count == 2


def test_pipeline_groups_namespace_into_one_alert(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    drifts = [
        _drift("module.db.aws_instance.primary"),
        _drift("module.db.aws_instance.replica"),
    ]
    report = Pipeline(correlator="deterministic").run(drifts)
    assert len(report.alerts) == 1
    assert len(report.alerts[0].drifts) == 2
    assert "module.db.aws_instance" in report.alerts[0].title


def test_default_degrade_now_groups_not_singletons(monkeypatch):
    # No correlator arg -> analyst.correlate. With no model it degrades to the
    # deterministic grouping (the new honest fallback), so shared-file drifts fold
    # into one Alert instead of one-per-drift singletons.
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("STEADYSTATE_LLM_BASE_URL", raising=False)
    drifts = [
        _drift("aws_instance.a", file="net.tf"),
        _drift("aws_subnet.b", file="net.tf"),
    ]
    report = Pipeline().run(drifts)
    assert len(report.alerts) == 1
    assert len(report.alerts[0].drifts) == 2
    assert report.alerts[0].llm_backed is False


def test_deterministic_correlator_makes_no_model_call(monkeypatch):
    # The whole point of `deterministic`: never touch the model, even if a key is set.
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.setattr(LLMAnalyst, "_complete", _boom)
    drifts = [
        _drift("aws_instance.a", file="net.tf"),
        _drift("aws_subnet.b", file="net.tf"),
    ]
    report = Pipeline(correlator="deterministic").run(drifts)  # _boom would raise if called
    assert len(report.alerts) == 1
    assert report.alerts[0].llm_backed is False


def test_llm_mode_degrades_to_grouping_on_failure(monkeypatch):
    # `llm` forces the LLM path, but a None/failed completion degrades to deterministic
    # grouping -- so shared-file Events still fold into one grouped Alert.
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.setattr(LLMAnalyst, "_complete", lambda self, system, user: None)
    drifts = [
        _drift("aws_instance.a", file="net.tf"),
        _drift("aws_subnet.b", file="net.tf"),
    ]
    report = Pipeline(correlator="llm").run(drifts)
    assert len(report.alerts) == 1
    assert len(report.alerts[0].drifts) == 2
    assert report.alerts[0].llm_backed is False
