from steadystate.domains.security import SecurityDomain
from steadystate.model import ChangeType, Drift, Provenance
from steadystate.reason.case import Severity
from steadystate.reason.pipeline import Pipeline


def _drift(kind, declared=None, observed=None, change_type=ChangeType.MODIFIED):
    return Drift(
        identity=f"{kind}.x",
        kind=kind,
        change_type=change_type,
        provenance=Provenance(source="terraform"),
        declared=declared,
        observed=observed,
    )


def test_public_access_block_disabled_is_critical():
    drift = _drift(
        "aws_s3_bucket_public_access_block",
        declared={"block_public_acls": False, "restrict_public_buckets": False},
        observed={"block_public_acls": True, "restrict_public_buckets": True},
    )
    assert SecurityDomain().score(drift) is Severity.CRITICAL


def test_public_access_block_still_blocking_is_ignored():
    drift = _drift(
        "aws_s3_bucket_public_access_block",
        declared={"block_public_acls": True},
        observed={"block_public_acls": True},
    )
    assert SecurityDomain().score(drift) is None


def test_ingress_opening_world_is_high():
    drift = _drift(
        "aws_security_group_rule",
        declared={"cidr_blocks": ["10.0.0.0/8", "0.0.0.0/0"]},
        observed={"cidr_blocks": ["10.0.0.0/8"]},
    )
    assert SecurityDomain().score(drift) is Severity.HIGH


def test_ingress_already_open_is_not_flagged_again():
    drift = _drift(
        "aws_security_group_rule",
        declared={"cidr_blocks": ["0.0.0.0/0"]},
        observed={"cidr_blocks": ["0.0.0.0/0"]},
    )
    assert SecurityDomain().score(drift) is None


def test_ipv6_world_open_is_high():
    drift = _drift(
        "aws_security_group_rule",
        declared={"ipv6_cidr_blocks": ["::/0"]},
        observed={"ipv6_cidr_blocks": []},
    )
    assert SecurityDomain().score(drift) is Severity.HIGH


def test_bucket_acl_going_public_is_critical():
    drift = _drift(
        "aws_s3_bucket_acl",
        declared={"acl": "public-read"},
        observed={"acl": "private"},
    )
    assert SecurityDomain().score(drift) is Severity.CRITICAL


def test_acl_staying_private_is_ignored():
    drift = _drift(
        "aws_s3_bucket",
        declared={"acl": "private"},
        observed={"acl": "private"},
    )
    assert SecurityDomain().score(drift) is None


def test_new_public_bucket_is_critical():
    drift = _drift(
        "aws_s3_bucket_acl",
        declared={"acl": "public-read-write"},
        observed=None,
        change_type=ChangeType.ADDED,
    )
    assert SecurityDomain().score(drift) is Severity.CRITICAL


def test_iam_policy_widening_to_wildcard_is_high():
    drift = _drift(
        "aws_iam_policy",
        declared={"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]},
        observed={
            "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:x"}]
        },
    )
    assert SecurityDomain().score(drift) is Severity.HIGH


def test_iam_policy_already_wildcard_is_not_reflagged():
    stmt = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
    drift = _drift("aws_iam_policy", declared=stmt, observed=stmt)
    assert SecurityDomain().score(drift) is None


def test_iam_deny_wildcard_is_ignored():
    drift = _drift(
        "aws_iam_policy",
        declared={"Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]},
        observed={
            "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:x"}]
        },
    )
    assert SecurityDomain().score(drift) is None


def test_unrelated_drift_returns_none():
    drift = _drift(
        "aws_instance",
        declared={"instance_type": "t3.large"},
        observed={"instance_type": "t3.medium"},
    )
    assert SecurityDomain().score(drift) is None


def test_missing_properties_never_crash_and_return_none():
    drift = _drift("aws_s3_bucket", declared=None, observed=None)
    assert SecurityDomain().score(drift) is None


def test_pipeline_raises_severity_via_security_domain(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    drift = _drift(
        "aws_security_group_rule",
        declared={"cidr_blocks": ["0.0.0.0/0"]},
        observed={"cidr_blocks": ["10.0.0.0/8"]},
    )
    case = Pipeline().run([drift])[0]
    assert case.severity is Severity.HIGH  # baseline MODIFIED=medium, raised to high
    assert case.flagged_by == "security"


def test_pipeline_keeps_baseline_when_no_security_angle(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    drift = _drift(
        "aws_instance",
        declared={"instance_type": "t3.large"},
        observed={"instance_type": "t3.medium"},
    )
    case = Pipeline().run([drift])[0]
    assert case.severity is Severity.MEDIUM
    assert case.flagged_by is None


def test_pipeline_does_not_lower_a_higher_baseline(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    drift = _drift(
        "aws_security_group_rule",
        declared={"cidr_blocks": ["0.0.0.0/0"]},
        observed=None,
        change_type=ChangeType.REMOVED,  # baseline HIGH, domain also HIGH -> stays HIGH, no flag
    )
    case = Pipeline().run([drift])[0]
    assert case.severity is Severity.HIGH
    assert case.flagged_by is None


def test_pipeline_empty_domains_uses_baseline_only(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    drift = _drift(
        "aws_s3_bucket_acl",
        declared={"acl": "public-read"},
        observed={"acl": "private"},
    )
    case = Pipeline(domains=[]).run([drift])[0]
    assert case.severity is Severity.MEDIUM  # no domain to raise it
    assert case.flagged_by is None
