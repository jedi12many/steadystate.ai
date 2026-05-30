from steadystate.domains import references_for
from steadystate.domains.security_azure import AzureSecurityDomain
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


# --- 1. NSG inbound rule opened to the Internet ----------------------------


def test_nsg_rule_observed_open_to_world_is_high():
    drift = _drift(
        "azurerm_network_security_rule",
        declared={"source_address_prefix": "10.0.0.0/8"},
        observed={"source_address_prefix": "0.0.0.0/0"},
    )
    assert AzureSecurityDomain().score(drift) is Severity.HIGH
    assert _ids(AzureSecurityDomain().references(drift)) == ["T1190"]


def test_nsg_rule_star_source_is_high():
    drift = _drift(
        "azurerm_network_security_rule",
        declared={"source_address_prefix": "VirtualNetwork"},
        observed={"source_address_prefix": "*"},
    )
    assert AzureSecurityDomain().score(drift) is Severity.HIGH


def test_nsg_rule_internet_tag_is_high():
    drift = _drift(
        "azurerm_network_security_rule",
        declared={"source_address_prefix": "VirtualNetwork"},
        observed={"source_address_prefix": "Internet"},
    )
    refs = AzureSecurityDomain().references(drift)
    assert AzureSecurityDomain().score(drift) is Severity.HIGH
    assert _ids(refs) == ["T1190"]
    assert refs[0].framework == "MITRE"
    assert refs[0].url == "https://attack.mitre.org/techniques/T1190/"


def test_nsg_rule_prefixes_list_open_to_world_is_high():
    drift = _drift(
        "azurerm_network_security_rule",
        declared={"source_address_prefixes": ["10.0.0.0/8"]},
        observed={"source_address_prefixes": ["10.0.0.0/8", "0.0.0.0/0"]},
    )
    assert AzureSecurityDomain().score(drift) is Severity.HIGH


def test_nsg_nested_security_rule_open_to_world_is_high():
    # azurerm_network_security_group carries nested security_rule blocks.
    drift = _drift(
        "azurerm_network_security_group",
        declared={"security_rule": [{"source_address_prefix": "10.0.0.0/8"}]},
        observed={"security_rule": [{"source_address_prefix": "0.0.0.0/0"}]},
    )
    assert AzureSecurityDomain().score(drift) is Severity.HIGH
    assert _ids(AzureSecurityDomain().references(drift)) == ["T1190"]


def test_nsg_rule_open_in_reality_flagged_even_when_declared_also_open():
    # Union-encoding case (issue #26): terraform encodes a TypeSet's planned `after` as the
    # union of live + config, so `declared` carries 0.0.0.0/0 too. Keyed off observed, reality
    # being open is still the finding (a declared/observed diff would have missed it).
    drift = _drift(
        "azurerm_network_security_rule",
        declared={"source_address_prefixes": ["0.0.0.0/0", "10.0.0.0/8"]},
        observed={"source_address_prefixes": ["0.0.0.0/0"]},
    )
    assert AzureSecurityDomain().score(drift) is Severity.HIGH


def test_nsg_rule_safe_direction_is_not_flagged():
    # Config is open, reality is closed -> reality is NOT more exposed -> None.
    drift = _drift(
        "azurerm_network_security_rule",
        declared={"source_address_prefix": "0.0.0.0/0"},
        observed={"source_address_prefix": "10.0.0.0/8"},
    )
    assert AzureSecurityDomain().score(drift) is None
    assert AzureSecurityDomain().references(drift) == []


def test_nsg_rule_outbound_open_is_ignored():
    drift = _drift(
        "azurerm_network_security_rule",
        declared={"direction": "Outbound", "source_address_prefix": "10.0.0.0/8"},
        observed={"direction": "Outbound", "source_address_prefix": "0.0.0.0/0"},
    )
    assert AzureSecurityDomain().score(drift) is None


def test_nsg_rule_deny_open_is_ignored():
    drift = _drift(
        "azurerm_network_security_rule",
        declared={"access": "Deny", "source_address_prefix": "10.0.0.0/8"},
        observed={"access": "Deny", "source_address_prefix": "0.0.0.0/0"},
    )
    assert AzureSecurityDomain().score(drift) is None


def test_nsg_rule_inbound_allow_default_when_absent():
    drift = _drift(
        "azurerm_network_security_rule",
        declared={"source_address_prefix": "10.0.0.0/8"},
        observed={"source_address_prefix": "0.0.0.0/0"},
    )
    assert AzureSecurityDomain().score(drift) is Severity.HIGH


# --- 2. SQL/MSSQL server firewall opened to all ----------------------------


def test_sql_firewall_opened_to_all_is_high():
    drift = _drift(
        "azurerm_sql_firewall_rule",
        declared={"start_ip_address": "10.0.0.0", "end_ip_address": "10.0.0.255"},
        observed={"start_ip_address": "0.0.0.0", "end_ip_address": "255.255.255.255"},
    )
    assert AzureSecurityDomain().score(drift) is Severity.HIGH
    assert _ids(AzureSecurityDomain().references(drift)) == ["T1190"]


def test_mssql_firewall_opened_to_all_is_high():
    drift = _drift(
        "azurerm_mssql_firewall_rule",
        declared={"start_ip_address": "10.0.0.0", "end_ip_address": "10.0.0.255"},
        observed={"start_ip_address": "0.0.0.0", "end_ip_address": "255.255.255.255"},
    )
    assert AzureSecurityDomain().score(drift) is Severity.HIGH
    assert _ids(AzureSecurityDomain().references(drift)) == ["T1190"]


def test_sql_firewall_open_in_reality_flagged_even_when_declared_also_open():
    # Range-based union-encoding case (issue #26): declared also carries the all-IPs range,
    # but keyed off observed, reality spanning 0.0.0.0 - 255.255.255.255 is the finding.
    drift = _drift(
        "azurerm_sql_firewall_rule",
        declared={"start_ip_address": "0.0.0.0", "end_ip_address": "255.255.255.255"},
        observed={"start_ip_address": "0.0.0.0", "end_ip_address": "255.255.255.255"},
    )
    assert AzureSecurityDomain().score(drift) is Severity.HIGH


def test_sql_firewall_narrow_range_is_not_flagged():
    drift = _drift(
        "azurerm_sql_firewall_rule",
        declared={"start_ip_address": "0.0.0.0", "end_ip_address": "255.255.255.255"},
        observed={"start_ip_address": "10.0.0.0", "end_ip_address": "10.0.0.255"},
    )
    assert AzureSecurityDomain().score(drift) is None
    assert AzureSecurityDomain().references(drift) == []


# --- 3. storage account public access enabled ------------------------------


def test_storage_account_blob_public_relaxed_is_high():
    drift = _drift(
        "azurerm_storage_account",
        declared={"allow_nested_items_to_be_public": False},
        observed={"allow_nested_items_to_be_public": True},
    )
    assert AzureSecurityDomain().score(drift) is Severity.HIGH
    assert _ids(AzureSecurityDomain().references(drift)) == ["T1530"]


def test_storage_account_legacy_blob_public_relaxed_is_high():
    drift = _drift(
        "azurerm_storage_account",
        declared={"allow_blob_public_access": False},
        observed={"allow_blob_public_access": True},
    )
    assert AzureSecurityDomain().score(drift) is Severity.HIGH
    assert _ids(AzureSecurityDomain().references(drift)) == ["T1530"]


def test_storage_account_network_access_relaxed_is_high_with_t1562():
    drift = _drift(
        "azurerm_storage_account",
        declared={"public_network_access_enabled": False},
        observed={"public_network_access_enabled": True},
    )
    assert AzureSecurityDomain().score(drift) is Severity.HIGH
    # Disabling a network restriction both exposes data (T1530) and impairs a defense (T1562).
    assert _ids(AzureSecurityDomain().references(drift)) == ["T1530", "T1562"]


def test_storage_account_unchanged_is_not_flagged():
    drift = _drift(
        "azurerm_storage_account",
        declared={"allow_nested_items_to_be_public": True},
        observed={"allow_nested_items_to_be_public": True},
    )
    assert AzureSecurityDomain().score(drift) is None


def test_storage_account_tightened_is_not_flagged():
    # Reality is more locked down than config -> not an exposure increase -> None.
    drift = _drift(
        "azurerm_storage_account",
        declared={"allow_nested_items_to_be_public": True},
        observed={"allow_nested_items_to_be_public": False},
    )
    assert AzureSecurityDomain().score(drift) is None


# --- 4. storage container made public --------------------------------------


def test_storage_container_made_blob_public_is_critical():
    drift = _drift(
        "azurerm_storage_container",
        declared={"container_access_type": "private"},
        observed={"container_access_type": "blob"},
    )
    assert AzureSecurityDomain().score(drift) is Severity.CRITICAL
    assert _ids(AzureSecurityDomain().references(drift)) == ["T1530"]


def test_storage_container_made_container_public_from_absent_is_critical():
    drift = _drift(
        "azurerm_storage_container",
        declared={},
        observed={"container_access_type": "container"},
    )
    assert AzureSecurityDomain().score(drift) is Severity.CRITICAL
    assert _ids(AzureSecurityDomain().references(drift)) == ["T1530"]


def test_storage_container_private_is_not_flagged():
    drift = _drift(
        "azurerm_storage_container",
        declared={"container_access_type": "blob"},
        observed={"container_access_type": "private"},
    )
    assert AzureSecurityDomain().score(drift) is None


def test_storage_container_already_public_is_not_reflagged():
    drift = _drift(
        "azurerm_storage_container",
        declared={"container_access_type": "blob"},
        observed={"container_access_type": "blob"},
    )
    assert AzureSecurityDomain().score(drift) is None


# --- 5. broad role assignment ----------------------------------------------


def test_role_assignment_broadened_to_owner_is_high():
    drift = _drift(
        "azurerm_role_assignment",
        declared={"role_definition_name": "Reader"},
        observed={"role_definition_name": "Owner"},
    )
    assert AzureSecurityDomain().score(drift) is Severity.HIGH
    assert _ids(AzureSecurityDomain().references(drift)) == ["T1098"]


def test_role_assignment_broadened_to_contributor_is_high():
    drift = _drift(
        "azurerm_role_assignment",
        declared={"role_definition_name": "Reader"},
        observed={"role_definition_name": "Contributor"},
    )
    assert AzureSecurityDomain().score(drift) is Severity.HIGH
    assert _ids(AzureSecurityDomain().references(drift)) == ["T1098"]


def test_role_assignment_broadened_to_user_access_admin_is_high():
    drift = _drift(
        "azurerm_role_assignment",
        declared={"role_definition_name": "Reader"},
        observed={"role_definition_name": "User Access Administrator"},
    )
    assert AzureSecurityDomain().score(drift) is Severity.HIGH
    assert _ids(AzureSecurityDomain().references(drift)) == ["T1098"]


def test_role_assignment_already_owner_is_not_reflagged():
    drift = _drift(
        "azurerm_role_assignment",
        declared={"role_definition_name": "Owner"},
        observed={"role_definition_name": "Owner"},
    )
    assert AzureSecurityDomain().score(drift) is None


def test_role_assignment_narrowing_is_not_flagged():
    drift = _drift(
        "azurerm_role_assignment",
        declared={"role_definition_name": "Owner"},
        observed={"role_definition_name": "Reader"},
    )
    assert AzureSecurityDomain().score(drift) is None


# --- negative / hygiene ----------------------------------------------------


def test_unrecognized_kind_returns_none():
    drift = _drift(
        "azurerm_linux_virtual_machine",
        declared={"size": "Standard_B1s"},
        observed={"size": "Standard_B2s"},
    )
    assert AzureSecurityDomain().score(drift) is None
    assert AzureSecurityDomain().references(drift) == []


def test_recognized_kind_no_exposure_change_returns_none():
    drift = _drift(
        "azurerm_network_security_rule",
        declared={"source_address_prefix": "10.0.0.0/8"},
        observed={"source_address_prefix": "192.168.0.0/16"},
    )
    assert AzureSecurityDomain().score(drift) is None


def test_missing_properties_never_crash_and_return_none():
    drift = _drift("azurerm_storage_account", declared=None, observed=None)
    assert AzureSecurityDomain().score(drift) is None
    assert AzureSecurityDomain().references(drift) == []


def test_references_never_disagree_with_score():
    domain = AzureSecurityDomain()
    cases = [
        _drift(
            "azurerm_network_security_rule",
            declared={"source_address_prefix": "10.0.0.0/8"},
            observed={"source_address_prefix": "0.0.0.0/0"},
        ),
        _drift(
            "azurerm_sql_firewall_rule",
            declared={"start_ip_address": "10.0.0.0", "end_ip_address": "10.0.0.255"},
            observed={"start_ip_address": "0.0.0.0", "end_ip_address": "255.255.255.255"},
        ),
        _drift(
            "azurerm_storage_account",
            declared={"public_network_access_enabled": False},
            observed={"public_network_access_enabled": True},
        ),
        _drift(
            "azurerm_storage_container",
            declared={"container_access_type": "private"},
            observed={"container_access_type": "blob"},
        ),
        _drift(
            "azurerm_role_assignment",
            declared={"role_definition_name": "Reader"},
            observed={"role_definition_name": "Owner"},
        ),
        _drift("azurerm_linux_virtual_machine", declared={"x": 1}, observed={"x": 2}),  # ignored
    ]
    for drift in cases:
        flagged = domain.score(drift) is not None
        assert bool(domain.references(drift)) is flagged


def test_references_for_delegates_to_azure_pack():
    drift = _drift(
        "azurerm_network_security_rule",
        declared={"source_address_prefix": "10.0.0.0/8"},
        observed={"source_address_prefix": "0.0.0.0/0"},
    )
    assert _ids(references_for(AzureSecurityDomain(), drift)) == ["T1190"]
