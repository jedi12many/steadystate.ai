"""Azure security domain pack -- exposure-increasing drift on *real* Azure infra.

Like the GCP pack, this only raises severity when it can *positively* recognize that
drift makes a resource more reachable than it should be. Anything it does not recognize
returns None -- the core keeps its baseline and we never fabricate a security angle.

EXPOSURE DIRECTION
------------------
A drifted resource carries ``declared = {config}`` and ``observed = {reality}``. Set-typed
/ list / range exposure attributes (an NSG rule's ``source_address_prefixes`` list, a SQL
firewall's ip *range*) key off the OBSERVED (reality) side ALONE: terraform encodes a
TypeSet's / range's planned ``after`` (which we map to ``declared``) as the UNION of live +
config, so a declared-vs-observed diff silently misses real exposure (issue #26). A resource
only reaches us because it drifted, so "reality is open to the Internet" is itself the
finding. Scalar attributes (a storage account public-access bool, a container access type, a
role name) keep the declared-vs-observed comparison, which detects a *relaxation* without
false-flagging a posture that was always loose. The GCP/AWS packs use the same split.

Honest framing: this is *config-exposure -> ATT&CK technique mapping, NOT behavioral
detection*. We map a recognized exposure-increasing drift to the technique it *enables*;
we are not detecting an attack. The same predicates that raise severity in score() pick the
references in references(), so severity and references can never disagree.
"""

from __future__ import annotations

from ..model import Drift
from ..reason.alert import Severity
from .base import Reference

# Config-exposure -> ATT&CK technique map (same shape as the GCP pack).
_T1190 = Reference(
    framework="MITRE",
    id="T1190",
    name="Exploit Public-Facing Application",
    url="https://attack.mitre.org/techniques/T1190/",
)
_T1530 = Reference(
    framework="MITRE",
    id="T1530",
    name="Data from Cloud Storage",
    url="https://attack.mitre.org/techniques/T1530/",
)
_T1562 = Reference(
    framework="MITRE",
    id="T1562",
    name="Impair Defenses",
    url="https://attack.mitre.org/techniques/T1562/",
)
_T1098 = Reference(
    framework="MITRE",
    id="T1098",
    name="Account Manipulation",
    url="https://attack.mitre.org/techniques/T1098/",
)

# Azure spells "open to the Internet" several ways across CIDR and the named tag.
_OPEN_SOURCES = {"*", "0.0.0.0/0", "internet"}
# A SQL/MSSQL firewall rule spanning the whole IPv4 space is "allow all".
_ALL_IPS_START = "0.0.0.0"  # nosec B104 -- a detection literal we match against, never a bind
_ALL_IPS_END = "255.255.255.255"
# Public container access levels (private is the safe default).
_PUBLIC_CONTAINER_ACCESS = {"blob", "container"}
# Built-in roles that grant broad control of a scope.
_BROAD_ROLES = {"owner", "contributor", "user access administrator"}


def _as_dict(value: dict | None) -> dict:
    return value if isinstance(value, dict) else {}


def _truthy(value: object) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in ("true", "1", "yes")
    return bool(value)


def _as_list(value: object) -> list:
    """Coerce a prefix/list field that may be a string, list, or absent."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


def _norm(value: object) -> str:
    return value.strip().lower() if isinstance(value, str) else ""


# --- network security group (NSG) rules -------------------------------------


def _is_inbound(props: dict) -> bool:
    """Inbound is the default when ``direction`` is absent; outbound is ignored."""
    direction = props.get("direction")
    if not isinstance(direction, str):
        return True
    return direction.strip().lower() == "inbound"


def _is_allow(props: dict) -> bool:
    """Allow is the default when ``access`` is absent; deny is ignored."""
    access = props.get("access")
    if not isinstance(access, str):
        return True
    return access.strip().lower() == "allow"


def _rule_sources(props: dict) -> set[str]:
    """The source prefixes a single rule names, across the scalar and list fields."""
    out: set[str] = set()
    prefix = props.get("source_address_prefix")
    if prefix is not None:
        out.add(_norm(prefix))
    for value in _as_list(props.get("source_address_prefixes")):
        out.add(_norm(value))
    return out


def _rule_opens_to_world(rule: dict) -> bool:
    """An inbound, Allow rule whose source is one of `*` / 0.0.0.0/0 / Internet.

    ``source_address_prefixes`` is a LIST, so this keys off the OBSERVED rule alone (the
    union-encoding trap, issue #26) -- the caller only passes observed rules in.
    """
    if not _is_inbound(rule) or not _is_allow(rule):
        return False
    return bool(_rule_sources(rule) & _OPEN_SOURCES)


def _nsg_rules(observed: dict) -> list[dict]:
    """Rules to inspect, handling both shapes: a standalone ``azurerm_network_security_rule``
    (the props *are* the rule) and an ``azurerm_network_security_group`` carrying nested
    ``security_rule`` blocks (a list of rule dicts)."""
    nested = [r for r in _as_list(observed.get("security_rule")) if isinstance(r, dict)]
    if nested:
        return nested
    return [observed]


def _nsg_opened_to_world(observed: dict) -> bool:
    # Key off the OBSERVED (reality) side only -- NOT an observed-minus-declared diff. A
    # rule's source list is a TypeSet whose planned `after` (-> declared) terraform encodes
    # as the UNION of live + config, so a declared/observed diff comes back empty (issue #26).
    # Reality having an inbound Allow-from-Internet rule on a drifted NSG is the finding.
    return any(_rule_opens_to_world(rule) for rule in _nsg_rules(observed))


# --- SQL / MSSQL server firewall --------------------------------------------


def _sql_opened_to_all(observed: dict) -> bool:
    # Range-based (start/end IP), so keyed off OBSERVED for the same union-encoding reason as
    # NSG/firewall rules (issue #26): 0.0.0.0 - 255.255.255.255 in reality is the finding.
    return (
        _norm(observed.get("start_ip_address")) == _ALL_IPS_START
        and _norm(observed.get("end_ip_address")) == _ALL_IPS_END
    )


# --- storage account guardrails ---------------------------------------------


def _storage_blob_public_relaxed(declared: dict, observed: dict) -> bool:
    """allow_nested_items_to_be_public (or the legacy allow_blob_public_access) went
    false/absent -> true. Scalar bool, so a declared-vs-observed relaxation."""
    for key in ("allow_nested_items_to_be_public", "allow_blob_public_access"):
        if key in observed and _truthy(observed.get(key)) and not _truthy(declared.get(key)):
            return True
    return False


def _storage_network_relaxed(declared: dict, observed: dict) -> bool:
    """public_network_access_enabled went false/restricted -> true. Scalar bool relaxation;
    this is a network restriction being disabled (T1562 territory)."""
    key = "public_network_access_enabled"
    return key in observed and _truthy(observed.get(key)) and not _truthy(declared.get(key))


def _storage_account_relaxed(declared: dict, observed: dict) -> bool:
    return _storage_blob_public_relaxed(declared, observed) or _storage_network_relaxed(
        declared, observed
    )


# --- storage container access type ------------------------------------------


def _container_made_public(declared: dict, observed: dict) -> bool:
    """container_access_type went private/absent -> blob/container. Scalar string relaxation."""
    new_access = _norm(observed.get("container_access_type"))
    if new_access not in _PUBLIC_CONTAINER_ACCESS:
        return False
    return _norm(declared.get("container_access_type")) not in _PUBLIC_CONTAINER_ACCESS


# --- role assignment --------------------------------------------------------


def _role_broadened(declared: dict, observed: dict) -> bool:
    """role_definition_name broadened to a built-in admin role. Scalar string relaxation."""
    if _norm(observed.get("role_definition_name")) not in _BROAD_ROLES:
        return False
    return _norm(declared.get("role_definition_name")) not in _BROAD_ROLES


# --- kind matching (word-boundary, not loose substring) ---------------------

_NSG_RULE_KIND = "azurerm_network_security_rule"
_NSG_KIND = "azurerm_network_security_group"
_NSG_KINDS = (_NSG_RULE_KIND, _NSG_KIND)
_SQL_FIREWALL_KINDS = (
    "azurerm_sql_firewall_rule",
    "azurerm_mssql_firewall_rule",
)
_STORAGE_ACCOUNT_KIND = "azurerm_storage_account"
_STORAGE_CONTAINER_KIND = "azurerm_storage_container"
_ROLE_ASSIGNMENT_KIND = "azurerm_role_assignment"


class AzureSecurityDomain:
    name = "security-azure"

    def score(self, drift: Drift) -> Severity | None:
        declared = _as_dict(drift.declared)
        observed = _as_dict(drift.observed)
        kind = drift.kind.lower()

        if kind in _NSG_KINDS and _nsg_opened_to_world(observed):
            return Severity.HIGH
        if kind in _SQL_FIREWALL_KINDS and _sql_opened_to_all(observed):
            return Severity.HIGH
        if kind == _STORAGE_ACCOUNT_KIND and _storage_account_relaxed(declared, observed):
            return Severity.HIGH
        if kind == _STORAGE_CONTAINER_KIND and _container_made_public(declared, observed):
            return Severity.CRITICAL
        if kind == _ROLE_ASSIGNMENT_KIND and _role_broadened(declared, observed):
            return Severity.HIGH
        return None

    def references(self, drift: Drift) -> list[Reference]:
        """ATT&CK techniques the recognized exposure *enables* (not attacks observed).

        Reuses the exact predicates score() uses, so a drift that raises severity here
        always carries the matching technique(s) and the two can never disagree. Returns
        [] for recognized-but-unmapped or unrecognized drift -- we never fabricate a tie.
        """
        declared = _as_dict(drift.declared)
        observed = _as_dict(drift.observed)
        kind = drift.kind.lower()

        out: list[Reference] = []
        if kind in _NSG_KINDS and _nsg_opened_to_world(observed):
            out.append(_T1190)
        if kind in _SQL_FIREWALL_KINDS and _sql_opened_to_all(observed):
            out.append(_T1190)
        if kind == _STORAGE_ACCOUNT_KIND and _storage_account_relaxed(declared, observed):
            # Exposing the account's data is T1530; disabling a network restriction also
            # impairs a defense (T1562). Surface T1562 only when a restriction was disabled.
            out.append(_T1530)
            if _storage_network_relaxed(declared, observed):
                out.append(_T1562)
        if kind == _STORAGE_CONTAINER_KIND and _container_made_public(declared, observed):
            out.append(_T1530)
        if kind == _ROLE_ASSIGNMENT_KIND and _role_broadened(declared, observed):
            out.append(_T1098)
        return out
