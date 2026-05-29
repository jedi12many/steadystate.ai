"""Security domain pack -- a small, honest rule set for exposure-increasing drift.

This pack only raises severity when it can *positively* recognize that drift makes
a resource more reachable than it was: a public-access-block being switched off, an
ingress rule opening to the whole internet, a bucket/object turning public, or an
IAM policy widening to wildcard. Anything it does not recognize returns None -- the
core keeps its own baseline and we never fabricate a security angle.
"""

from __future__ import annotations

from ..model import Drift
from ..reason.alert import Severity
from .base import Reference

# Config-exposure -> ATT&CK technique map. Honest framing: we map a recognized
# exposure-increasing config change to the technique it *enables*; this is NOT
# behavioral attack detection. The same predicates that raise severity in score()
# pick these references, so severity and references can never disagree.
_T1530 = Reference(
    framework="MITRE",
    id="T1530",
    name="Data from Cloud Storage",
    url="https://attack.mitre.org/techniques/T1530/",
)
_T1190 = Reference(
    framework="MITRE",
    id="T1190",
    name="Exploit Public-Facing Application",
    url="https://attack.mitre.org/techniques/T1190/",
)
_T1098 = Reference(
    framework="MITRE",
    id="T1098",
    name="Account Manipulation",
    url="https://attack.mitre.org/techniques/T1098/",
)
_T1562 = Reference(
    framework="MITRE",
    id="T1562",
    name="Impair Defenses",
    url="https://attack.mitre.org/techniques/T1562/",
)

_OPEN_CIDRS = {"0.0.0.0/0", "::/0"}
_PUBLIC_ACLS = {"public-read", "public-read-write", "authenticated-read"}
_PAB_KEYS = (
    "block_public_acls",
    "block_public_policy",
    "ignore_public_acls",
    "restrict_public_buckets",
)


def _as_dict(value: dict | None) -> dict:
    return value if isinstance(value, dict) else {}


def _truthy(value: object) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in ("true", "1", "yes")
    return bool(value)


def _cidrs(props: dict) -> set[str]:
    out: set[str] = set()
    for key in ("cidr_blocks", "ipv6_cidr_blocks", "cidr_ipv4", "cidr_ipv6"):
        value = props.get(key)
        if isinstance(value, str):
            out.add(value)
        elif isinstance(value, (list, tuple, set)):
            out.update(str(v) for v in value)
    return out


def _opened_to_world(declared: dict, observed: dict) -> bool:
    gained = _cidrs(declared) & _OPEN_CIDRS
    if not gained:
        return False
    return bool(gained - (_cidrs(observed) & _OPEN_CIDRS))


def _is_pab_kind(kind: str) -> bool:
    # word-boundary match, not a loose substring (avoids the over-match trap)
    return kind == "public_access_block" or kind.endswith("_public_access_block")


def _public_access_block_relaxed(declared: dict, observed: dict) -> bool:
    for key in _PAB_KEYS:
        if key not in declared:
            continue
        was_blocking = _truthy(observed.get(key, True))
        now_blocking = _truthy(declared.get(key))
        if was_blocking and not now_blocking:
            return True
    return False


def _acl_went_public(declared: dict, observed: dict) -> bool:
    new_acl = declared.get("acl")
    if not isinstance(new_acl, str) or new_acl.strip().lower() not in _PUBLIC_ACLS:
        return False
    old_acl = observed.get("acl")
    return not (isinstance(old_acl, str) and old_acl.strip().lower() in _PUBLIC_ACLS)


def _has_wildcard(value: object) -> bool:
    if value == "*":
        return True
    if isinstance(value, (list, tuple, set)):
        return any(_has_wildcard(v) for v in value)
    if isinstance(value, dict):
        return any(_has_wildcard(v) for v in value.values())
    return False


def _statement_is_open(stmt: object) -> bool:
    if not isinstance(stmt, dict):
        return False
    effect = stmt.get("Effect") or stmt.get("effect")
    if isinstance(effect, str) and effect.strip().lower() != "allow":
        return False
    action = stmt.get("Action", stmt.get("action"))
    resource = stmt.get("Resource", stmt.get("resource"))
    return _has_wildcard(action) and _has_wildcard(resource)


def _statements(props: dict) -> list:
    for key in ("Statement", "statement", "policy", "Policy"):
        value = props.get(key)
        if isinstance(value, dict):
            inner = value.get("Statement") or value.get("statement")
            if inner is not None:
                value = inner
        if isinstance(value, dict):
            return [value]
        if isinstance(value, list):
            return value
    return []


def _policy_widened(declared: dict, observed: dict) -> bool:
    declared_open = any(_statement_is_open(s) for s in _statements(declared))
    if not declared_open:
        return False
    observed_open = any(_statement_is_open(s) for s in _statements(observed))
    return not observed_open


class SecurityDomain:
    name = "security"

    def score(self, drift: Drift) -> Severity | None:
        declared = _as_dict(drift.declared)
        observed = _as_dict(drift.observed)
        kind = drift.kind.lower()

        if _is_pab_kind(kind) and _public_access_block_relaxed(declared, observed):
            return Severity.CRITICAL
        if _acl_went_public(declared, observed):
            return Severity.CRITICAL
        if _opened_to_world(declared, observed):
            return Severity.HIGH
        if _policy_widened(declared, observed):
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
        if _is_pab_kind(kind) and _public_access_block_relaxed(declared, observed):
            # Relaxing public-access-block both impairs a guardrail (T1562) and exposes
            # the bucket's data (T1530); surface both.
            out.extend((_T1562, _T1530))
        if _acl_went_public(declared, observed):
            out.append(_T1530)
        if _opened_to_world(declared, observed):
            out.append(_T1190)
        if _policy_widened(declared, observed):
            out.append(_T1098)
        return out
