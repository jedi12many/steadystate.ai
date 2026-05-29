from steadystate.domains import references_for
from steadystate.domains.security_gcp import GCPSecurityDomain
from steadystate.model import ChangeType, Drift, Provenance
from steadystate.reason.alert import Severity


def _drift(kind, declared=None, observed=None, change_type=ChangeType.MODIFIED):
    return Drift(
        identity=f"{kind}.x",
        kind=kind,
        change_type=change_type,
        provenance=Provenance(source="terraform"),
        declared=declared,
        observed=observed,
    )


def _ids(refs) -> list[str]:
    return [ref.id for ref in refs]


# --- 1. firewall opened to the world ---------------------------------------


def test_firewall_observed_open_to_world_is_high():
    drift = _drift(
        "google_compute_firewall",
        declared={"source_ranges": ["10.0.0.0/8"]},
        observed={"source_ranges": ["10.0.0.0/8", "0.0.0.0/0"]},
    )
    assert GCPSecurityDomain().score(drift) is Severity.HIGH
    assert _ids(GCPSecurityDomain().references(drift)) == ["T1190"]


def test_firewall_real_iap_case_drifting_to_world_is_high():
    # The real-world case: config allows only the IAP range, reality opened to the world.
    drift = _drift(
        "google_compute_firewall",
        declared={"source_ranges": ["35.235.240.0/20"]},
        observed={"source_ranges": ["0.0.0.0/0"]},
    )
    refs = GCPSecurityDomain().references(drift)
    assert GCPSecurityDomain().score(drift) is Severity.HIGH
    assert _ids(refs) == ["T1190"]
    assert refs[0].framework == "MITRE"
    assert refs[0].url == "https://attack.mitre.org/techniques/T1190/"


def test_firewall_ipv6_world_open_is_high():
    drift = _drift(
        "google_compute_firewall",
        declared={"source_ranges": ["fd00::/8"]},
        observed={"source_ranges": ["::/0"]},
    )
    assert GCPSecurityDomain().score(drift) is Severity.HIGH


def test_firewall_string_source_range_is_handled():
    drift = _drift(
        "google_compute_firewall",
        declared={"source_ranges": "10.0.0.0/8"},
        observed={"source_ranges": "0.0.0.0/0"},
    )
    assert GCPSecurityDomain().score(drift) is Severity.HIGH


def test_firewall_safe_direction_is_not_flagged():
    # Config is open, reality is closed -> reality is NOT more exposed -> None.
    drift = _drift(
        "google_compute_firewall",
        declared={"source_ranges": ["0.0.0.0/0"]},
        observed={"source_ranges": ["10.0.0.0/8"]},
    )
    assert GCPSecurityDomain().score(drift) is None
    assert GCPSecurityDomain().references(drift) == []


def test_firewall_already_open_both_sides_is_not_flagged():
    drift = _drift(
        "google_compute_firewall",
        declared={"source_ranges": ["0.0.0.0/0"]},
        observed={"source_ranges": ["0.0.0.0/0"]},
    )
    assert GCPSecurityDomain().score(drift) is None


def test_firewall_egress_open_is_ignored():
    drift = _drift(
        "google_compute_firewall",
        declared={"direction": "EGRESS", "source_ranges": ["10.0.0.0/8"]},
        observed={"direction": "EGRESS", "source_ranges": ["0.0.0.0/0"]},
    )
    assert GCPSecurityDomain().score(drift) is None


def test_firewall_ingress_default_when_direction_absent():
    drift = _drift(
        "google_compute_firewall",
        declared={"source_ranges": ["10.0.0.0/8"]},
        observed={"source_ranges": ["0.0.0.0/0"]},
    )
    assert GCPSecurityDomain().score(drift) is Severity.HIGH


# --- 2. bucket public-access guardrail relaxed -----------------------------


def test_bucket_public_access_prevention_relaxed_is_high():
    drift = _drift(
        "google_storage_bucket",
        declared={"public_access_prevention": "enforced"},
        observed={"public_access_prevention": "inherited"},
    )
    assert GCPSecurityDomain().score(drift) is Severity.HIGH
    assert _ids(GCPSecurityDomain().references(drift)) == ["T1530", "T1562"]


def test_bucket_public_access_prevention_dropped_to_absent_is_high():
    drift = _drift(
        "google_storage_bucket",
        declared={"public_access_prevention": "enforced"},
        observed={},
    )
    assert GCPSecurityDomain().score(drift) is Severity.HIGH


def test_bucket_uniform_access_disabled_is_high():
    drift = _drift(
        "google_storage_bucket",
        declared={"uniform_bucket_level_access": True},
        observed={"uniform_bucket_level_access": False},
    )
    assert GCPSecurityDomain().score(drift) is Severity.HIGH
    assert _ids(GCPSecurityDomain().references(drift)) == ["T1530", "T1562"]


def test_bucket_guardrail_unchanged_is_not_flagged():
    drift = _drift(
        "google_storage_bucket",
        declared={"public_access_prevention": "enforced"},
        observed={"public_access_prevention": "enforced"},
    )
    assert GCPSecurityDomain().score(drift) is None


def test_bucket_guardrail_tightened_is_not_flagged():
    # Reality is more locked down than config -> not an exposure increase -> None.
    drift = _drift(
        "google_storage_bucket",
        declared={"public_access_prevention": "inherited"},
        observed={"public_access_prevention": "enforced"},
    )
    assert GCPSecurityDomain().score(drift) is None


# --- 3. bucket made public via IAM -----------------------------------------


def test_bucket_iam_member_allusers_is_critical():
    drift = _drift(
        "google_storage_bucket_iam_member",
        declared={"member": "user:alice@example.com"},
        observed={"member": "allUsers"},
    )
    assert GCPSecurityDomain().score(drift) is Severity.CRITICAL
    assert _ids(GCPSecurityDomain().references(drift)) == ["T1530"]


def test_bucket_iam_binding_allauthenticated_is_critical():
    drift = _drift(
        "google_storage_bucket_iam_binding",
        declared={"members": ["group:team@example.com"]},
        observed={"members": ["group:team@example.com", "allAuthenticatedUsers"]},
    )
    assert GCPSecurityDomain().score(drift) is Severity.CRITICAL
    assert _ids(GCPSecurityDomain().references(drift)) == ["T1530"]


def test_bucket_iam_already_public_is_not_reflagged():
    drift = _drift(
        "google_storage_bucket_iam_member",
        declared={"member": "allUsers"},
        observed={"member": "allUsers"},
    )
    assert GCPSecurityDomain().score(drift) is None


def test_bucket_iam_private_member_is_not_flagged():
    drift = _drift(
        "google_storage_bucket_iam_member",
        declared={"member": "user:alice@example.com"},
        observed={"member": "user:bob@example.com"},
    )
    assert GCPSecurityDomain().score(drift) is None


# --- 4. over-broad project IAM ---------------------------------------------


def test_project_iam_role_broadened_to_owner_is_high():
    drift = _drift(
        "google_project_iam_member",
        declared={"role": "roles/viewer", "member": "user:alice@example.com"},
        observed={"role": "roles/owner", "member": "user:alice@example.com"},
    )
    assert GCPSecurityDomain().score(drift) is Severity.HIGH
    assert _ids(GCPSecurityDomain().references(drift)) == ["T1098"]


def test_project_iam_role_broadened_to_editor_is_high():
    drift = _drift(
        "google_project_iam_binding",
        declared={"role": "roles/storage.objectViewer", "members": ["user:a@x.com"]},
        observed={"role": "roles/editor", "members": ["user:a@x.com"]},
    )
    assert GCPSecurityDomain().score(drift) is Severity.HIGH
    assert _ids(GCPSecurityDomain().references(drift)) == ["T1098"]


def test_project_iam_public_member_is_high():
    drift = _drift(
        "google_project_iam_member",
        declared={"role": "roles/viewer", "member": "user:alice@example.com"},
        observed={"role": "roles/viewer", "member": "allUsers"},
    )
    assert GCPSecurityDomain().score(drift) is Severity.HIGH
    assert _ids(GCPSecurityDomain().references(drift)) == ["T1098"]


def test_project_iam_already_owner_is_not_reflagged():
    drift = _drift(
        "google_project_iam_member",
        declared={"role": "roles/owner", "member": "user:a@x.com"},
        observed={"role": "roles/owner", "member": "user:a@x.com"},
    )
    assert GCPSecurityDomain().score(drift) is None


def test_project_iam_narrowing_role_is_not_flagged():
    drift = _drift(
        "google_project_iam_member",
        declared={"role": "roles/owner", "member": "user:a@x.com"},
        observed={"role": "roles/viewer", "member": "user:a@x.com"},
    )
    assert GCPSecurityDomain().score(drift) is None


# --- negative / hygiene ----------------------------------------------------


def test_unrecognized_kind_returns_none():
    drift = _drift(
        "google_compute_instance",
        declared={"machine_type": "e2-small"},
        observed={"machine_type": "e2-medium"},
    )
    assert GCPSecurityDomain().score(drift) is None
    assert GCPSecurityDomain().references(drift) == []


def test_recognized_kind_no_exposure_change_returns_none():
    drift = _drift(
        "google_compute_firewall",
        declared={"source_ranges": ["10.0.0.0/8"]},
        observed={"source_ranges": ["192.168.0.0/16"]},
    )
    assert GCPSecurityDomain().score(drift) is None


def test_missing_properties_never_crash_and_return_none():
    drift = _drift("google_storage_bucket", declared=None, observed=None)
    assert GCPSecurityDomain().score(drift) is None
    assert GCPSecurityDomain().references(drift) == []


def test_references_never_disagree_with_score():
    domain = GCPSecurityDomain()
    cases = [
        _drift(
            "google_compute_firewall",
            declared={"source_ranges": ["10.0.0.0/8"]},
            observed={"source_ranges": ["0.0.0.0/0"]},
        ),
        _drift(
            "google_storage_bucket_iam_member",
            declared={"member": "user:a@x.com"},
            observed={"member": "allUsers"},
        ),
        _drift(
            "google_project_iam_member",
            declared={"role": "roles/viewer"},
            observed={"role": "roles/owner"},
        ),
        _drift("google_compute_instance", declared={"x": 1}, observed={"x": 2}),  # ignored
    ]
    for drift in cases:
        flagged = domain.score(drift) is not None
        assert bool(domain.references(drift)) is flagged


def test_references_for_delegates_to_gcp_pack():
    drift = _drift(
        "google_compute_firewall",
        declared={"source_ranges": ["35.235.240.0/20"]},
        observed={"source_ranges": ["0.0.0.0/0"]},
    )
    assert _ids(references_for(GCPSecurityDomain(), drift)) == ["T1190"]
