from steadystate.model import ChangeType, Drift, Provenance


def test_drift_summary_and_json():
    drift = Drift(
        identity="aws_s3_bucket.logs",
        kind="aws_s3_bucket",
        change_type=ChangeType.MODIFIED,
        provenance=Provenance(source="terraform", address="aws_s3_bucket.logs"),
        declared={"acl": "private"},
        observed={"acl": "public-read"},
    )
    assert "modified" in drift.summary()
    assert "aws_s3_bucket.logs" in drift.summary()
    assert "public-read" in drift.to_json()
