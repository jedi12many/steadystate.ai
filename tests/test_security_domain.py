import dataclasses

import pytest

from steadystate.domains import Reference, references_for
from steadystate.domains.security import SecurityDomain
from steadystate.model import ChangeType, Drift, Provenance
from steadystate.reason.alert import Severity
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
    # Keyed off observed (reality): the drifted rule is open to the world in reality.
    drift = _drift(
        "aws_security_group_rule",
        declared={"cidr_blocks": ["10.0.0.0/8"]},
        observed={"cidr_blocks": ["10.0.0.0/8", "0.0.0.0/0"]},
    )
    assert SecurityDomain().score(drift) is Severity.HIGH


def test_ingress_open_in_reality_flagged_even_when_declared_also_open():
    # The union-encoding case (issue #26): terraform encodes a TypeSet's planned `after` as
    # the union of live + config, so `declared` carries 0.0.0.0/0 too. Keyed off observed,
    # reality being open is still the finding (a declared/observed diff would have missed it).
    drift = _drift(
        "aws_security_group_rule",
        declared={"cidr_blocks": ["0.0.0.0/0", "10.0.0.0/8"]},
        observed={"cidr_blocks": ["0.0.0.0/0"]},
    )
    assert SecurityDomain().score(drift) is Severity.HIGH


def test_ipv6_world_open_is_high():
    drift = _drift(
        "aws_security_group_rule",
        declared={"ipv6_cidr_blocks": []},
        observed={"ipv6_cidr_blocks": ["::/0"]},
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
        declared={"cidr_blocks": ["10.0.0.0/8"]},
        observed={"cidr_blocks": ["0.0.0.0/0"]},
    )
    case = Pipeline().run([drift]).alerts[0]
    assert case.severity is Severity.HIGH  # baseline MODIFIED=medium, raised to high
    assert case.flagged_by == "security"


def test_pipeline_keeps_baseline_when_no_security_angle(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    drift = _drift(
        "aws_instance",
        declared={"instance_type": "t3.large"},
        observed={"instance_type": "t3.medium"},
    )
    case = Pipeline().run([drift]).alerts[0]
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
    case = Pipeline().run([drift]).alerts[0]
    assert case.severity is Severity.HIGH
    assert case.flagged_by is None


def test_pipeline_empty_domains_uses_baseline_only(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    drift = _drift(
        "aws_s3_bucket_acl",
        declared={"acl": "public-read"},
        observed={"acl": "private"},
    )
    case = Pipeline(domains=[]).run([drift]).alerts[0]
    assert case.severity is Severity.MEDIUM  # no domain to raise it
    assert case.flagged_by is None


# --- framework references: config-exposure -> ATT&CK technique mapping ------
# Honest framing: each reference names the technique a recognized config change
# *enables*; this is mapping, not behavioral detection. The same predicates that
# raise severity pick the references, so the two can never disagree.


def _ids(refs) -> list[str]:
    return [ref.id for ref in refs]


def test_acl_going_public_references_t1530():
    drift = _drift(
        "aws_s3_bucket_acl", declared={"acl": "public-read"}, observed={"acl": "private"}
    )
    refs = SecurityDomain().references(drift)
    assert _ids(refs) == ["T1530"]
    assert refs[0].framework == "MITRE"
    assert refs[0].name == "Data from Cloud Storage"
    assert refs[0].url == "https://attack.mitre.org/techniques/T1530/"


def test_public_access_block_relaxed_references_t1562_and_t1530():
    drift = _drift(
        "aws_s3_bucket_public_access_block",
        declared={"block_public_acls": False, "restrict_public_buckets": False},
        observed={"block_public_acls": True, "restrict_public_buckets": True},
    )
    # Relaxing the guardrail both impairs a defense (T1562) and exposes storage (T1530).
    assert _ids(SecurityDomain().references(drift)) == ["T1562", "T1530"]


def test_ingress_opened_to_world_references_t1190():
    drift = _drift(
        "aws_security_group_rule",
        declared={"cidr_blocks": ["10.0.0.0/8"]},
        observed={"cidr_blocks": ["0.0.0.0/0"]},
    )
    assert _ids(SecurityDomain().references(drift)) == ["T1190"]


def test_wildcard_iam_policy_references_t1098():
    drift = _drift(
        "aws_iam_policy",
        declared={"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]},
        observed={
            "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:x"}]
        },
    )
    assert _ids(SecurityDomain().references(drift)) == ["T1098"]


def test_observed_not_open_yields_no_references():
    # Reality is NOT open (only a private range), even though declared shows 0.0.0.0/0:
    # keyed off observed, there is nothing exposed to flag, so no references either.
    drift = _drift(
        "aws_security_group_rule",
        declared={"cidr_blocks": ["0.0.0.0/0"]},
        observed={"cidr_blocks": ["10.0.0.0/8"]},
    )
    assert SecurityDomain().score(drift) is None
    assert SecurityDomain().references(drift) == []


def test_unrecognized_drift_yields_no_references():
    drift = _drift(
        "aws_instance",
        declared={"instance_type": "t3.large"},
        observed={"instance_type": "t3.medium"},
    )
    assert SecurityDomain().references(drift) == []


def test_references_never_disagree_with_score():
    # Anything score() flags carries at least one reference; anything it ignores carries none.
    domain = SecurityDomain()
    cases = [
        _drift("aws_s3_bucket_acl", declared={"acl": "public-read"}, observed={"acl": "private"}),
        _drift(
            "aws_security_group_rule",
            declared={"cidr_blocks": ["0.0.0.0/0"]},
            observed={"cidr_blocks": []},
        ),
        _drift("aws_instance", declared={"x": 1}, observed={"x": 2}),  # ignored
    ]
    for drift in cases:
        flagged = domain.score(drift) is not None
        assert bool(domain.references(drift)) is flagged


def test_references_for_falls_back_to_empty_for_a_pack_without_references():
    # A pack that doesn't implement references() must still work via the getattr fallback.
    class BareDomain:
        name = "bare"

        def score(self, drift):
            return None

    drift = _drift("aws_instance", declared={"x": 1}, observed={"x": 2})
    assert references_for(BareDomain(), drift) == []


def test_references_for_delegates_to_an_implementing_pack():
    drift = _drift(
        "aws_s3_bucket_acl", declared={"acl": "public-read"}, observed={"acl": "private"}
    )
    assert _ids(references_for(SecurityDomain(), drift)) == ["T1530"]


def test_reference_is_immutable():
    ref = Reference(framework="MITRE", id="T1530")
    with pytest.raises(dataclasses.FrozenInstanceError):
        ref.id = "T9999"  # type: ignore[misc]


def test_pipeline_carries_references_end_to_end(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    drift = _drift(
        "aws_security_group_rule",
        declared={"cidr_blocks": ["10.0.0.0/8"]},
        observed={"cidr_blocks": ["0.0.0.0/0"]},
    )
    case = Pipeline().run([drift]).alerts[0]
    assert case.flagged_by == "security"
    assert _ids(case.references) == ["T1190"]


def test_pipeline_no_security_angle_carries_no_references(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    drift = _drift(
        "aws_instance",
        declared={"instance_type": "t3.large"},
        observed={"instance_type": "t3.medium"},
    )
    case = Pipeline().run([drift]).alerts[0]
    assert case.flagged_by is None
    assert case.references == []
