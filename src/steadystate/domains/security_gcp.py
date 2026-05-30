"""GCP security domain pack -- exposure-increasing drift on *real* GCP infra.

Like the AWS pack, this only raises severity when it can *positively* recognize that
drift makes a resource more reachable than it should be. Anything it does not recognize
returns None -- the core keeps its baseline and we never fabricate a security angle.

EXPOSURE DIRECTION
------------------
A drifted resource carries ``declared = {config}`` and ``observed = {reality}``. Set-typed
exposure attributes (firewall ``source_ranges``, IAM member lists) key off the OBSERVED
(reality) side ALONE: terraform encodes a TypeSet's planned ``after`` (which we map to
``declared``) as the UNION of live + config, so a declared-vs-observed diff silently misses a
real open-to-world rule (issue #26). A resource only reaches us because it drifted, so "reality
is exposed to the world" is itself the finding. Scalar attributes (bucket
public_access_prevention / uniform access, IAM role) keep the declared-vs-observed comparison,
which detects a *relaxation* without false-flagging a posture that was always loose. The AWS
pack uses the same split.

Honest framing: this is *config-exposure -> ATT&CK technique mapping, NOT behavioral
detection*. We map a recognized exposure-increasing drift to the technique it *enables*;
we are not detecting an attack. The same predicates that raise severity in score() pick the
references in references(), so severity and references can never disagree.
"""

from __future__ import annotations

from ..model import Drift
from ..reason.alert import Severity
from .base import Reference

# Config-exposure -> ATT&CK technique map (same shape as the AWS pack).
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

_OPEN_CIDRS = {"0.0.0.0/0", "::/0"}
_PUBLIC_MEMBERS = {"allusers", "allauthenticatedusers"}
_BROAD_ROLES = {"roles/owner", "roles/editor"}


def _as_dict(value: dict | None) -> dict:
    return value if isinstance(value, dict) else {}


def _truthy(value: object) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in ("true", "1", "yes")
    return bool(value)


def _as_list(value: object) -> list:
    """Coerce a member/source_ranges field that may be a string, list, or absent."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


# --- firewall ---------------------------------------------------------------


def _is_ingress(props: dict) -> bool:
    """INGRESS is the default when ``direction`` is absent; egress is ignored."""
    direction = props.get("direction")
    if not isinstance(direction, str):
        return True
    return direction.strip().upper() == "INGRESS"


def _source_ranges(props: dict) -> set[str]:
    out: set[str] = set()
    for value in _as_list(props.get("source_ranges")):
        out.add(str(value))
    return out


def _firewall_opened_to_world(observed: dict) -> bool:
    # Egress firewalls don't grant inbound reachability; ignore them.
    if not _is_ingress(observed):
        return False
    # Key off the OBSERVED (reality) side only -- NOT an observed-minus-declared diff. The
    # resource only reaches us because it drifted, and terraform encodes a TypeSet's planned
    # `after` (-> declared) as the UNION of live + config, so declared also carries the open
    # CIDR and the diff comes back empty (issue #26). Reality having 0.0.0.0/0 on a drifted
    # ingress rule is the finding.
    return bool(_source_ranges(observed) & _OPEN_CIDRS)


# --- storage bucket guardrails ----------------------------------------------


def _pap_enforced(value: object) -> bool:
    return isinstance(value, str) and value.strip().lower() == "enforced"


def _bucket_guardrail_relaxed(declared: dict, observed: dict) -> bool:
    # public_access_prevention dropped from "enforced" to "inherited"/absent.
    if _pap_enforced(declared.get("public_access_prevention")) and not _pap_enforced(
        observed.get("public_access_prevention")
    ):
        return True
    # uniform_bucket_level_access dropped from true to false/absent.
    if "uniform_bucket_level_access" in declared and _truthy(
        declared.get("uniform_bucket_level_access")
    ):
        return not _truthy(observed.get("uniform_bucket_level_access"))
    return False


# --- IAM members ------------------------------------------------------------


def _members(props: dict) -> set[str]:
    """Members across the differently-nested member/members fields, normalized."""
    out: set[str] = set()
    for key in ("member", "members"):
        for value in _as_list(props.get(key)):
            if isinstance(value, str):
                out.add(value.strip().lower())
    return out


def _gained_public_members(observed: dict) -> bool:
    # Observed-keyed for the same reason as firewalls: member lists are a TypeSet, so a
    # declared/observed diff is defeated by terraform's union encoding (issue #26). A drifted
    # IAM resource whose reality grants allUsers/allAuthenticatedUsers is the finding.
    return bool(_members(observed) & _PUBLIC_MEMBERS)


def _role(props: dict) -> str:
    role = props.get("role")
    return role.strip().lower() if isinstance(role, str) else ""


def _role_broadened(declared: dict, observed: dict) -> bool:
    new_role = _role(observed)
    if new_role not in _BROAD_ROLES:
        return False
    return _role(declared) not in _BROAD_ROLES


# --- kind matching (word-boundary, not loose substring) ---------------------

_FIREWALL_KIND = "google_compute_firewall"
_BUCKET_KIND = "google_storage_bucket"
_BUCKET_IAM_KINDS = (
    "google_storage_bucket_iam_member",
    "google_storage_bucket_iam_binding",
)
_PROJECT_IAM_KINDS = (
    "google_project_iam_member",
    "google_project_iam_binding",
)


class GCPSecurityDomain:
    name = "security-gcp"

    def score(self, drift: Drift) -> Severity | None:
        declared = _as_dict(drift.declared)
        observed = _as_dict(drift.observed)
        kind = drift.kind.lower()

        if kind == _FIREWALL_KIND and _firewall_opened_to_world(observed):
            return Severity.HIGH
        if kind == _BUCKET_KIND and _bucket_guardrail_relaxed(declared, observed):
            return Severity.HIGH
        if kind in _BUCKET_IAM_KINDS and _gained_public_members(observed):
            return Severity.CRITICAL
        if kind in _PROJECT_IAM_KINDS and (
            _role_broadened(declared, observed) or _gained_public_members(observed)
        ):
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
        if kind == _FIREWALL_KIND and _firewall_opened_to_world(observed):
            out.append(_T1190)
        if kind == _BUCKET_KIND and _bucket_guardrail_relaxed(declared, observed):
            # Relaxing the bucket guardrail both impairs a defense (T1562) and exposes
            # the bucket's data (T1530); surface both.
            out.extend((_T1530, _T1562))
        if kind in _BUCKET_IAM_KINDS and _gained_public_members(observed):
            out.append(_T1530)
        if kind in _PROJECT_IAM_KINDS and (
            _role_broadened(declared, observed) or _gained_public_members(observed)
        ):
            out.append(_T1098)
        return out
