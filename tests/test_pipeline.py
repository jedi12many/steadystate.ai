from steadystate.model import ChangeType, Drift, Provenance
from steadystate.reason.pipeline import Pipeline


def test_pipeline_degrades_honestly_without_llm(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    drift = Drift(
        identity="aws_s3_bucket.logs",
        kind="aws_s3_bucket",
        change_type=ChangeType.REMOVED,
        provenance=Provenance(source="terraform"),
        observed={"id": "b"},
    )
    cases = Pipeline().run([drift])
    assert len(cases) == 1
    assert cases[0].llm_backed is False  # honest: no fabricated reasoning
    assert cases[0].severity.value == "high"  # a removed declared resource
