"""Domain plugins: what drift *means* (security, compliance, cost, ...).

A Domain teaches the core which resources it cares about and scores their drift.
In-tree packs register by being appended to _BUILTIN_DOMAINS; the pipeline loads
them without being edited. This is how security & compliance (CIS, STIG, ...) enter
-- as packs, never as core.

Out-of-tree packs register the same way without editing this file: a separately
installed package declares a `steadystate.domains` entry point (a zero-arg callable
-- usually the Domain class -- or a ready instance), and discovery appends it. A pack
whose `name` clashes with a built-in is skipped (built-ins win). See plugins.py.
"""

from __future__ import annotations

import logging
from typing import cast

from ..plugins import discover
from .base import Domain, PolicyFinding, Reference, evaluate_with, references_for
from .compliance import DockerComplianceDomain
from .security import SecurityDomain
from .security_azure import AzureSecurityDomain
from .security_gcp import GCPSecurityDomain
from .security_k8s import KubernetesSecurityDomain

logger = logging.getLogger(__name__)

# The packs that ship in-tree. Append new in-tree packs here; pipeline.py does not change.
_BUILTIN_DOMAINS: list[Domain] = [
    SecurityDomain(),
    GCPSecurityDomain(),
    AzureSecurityDomain(),
    DockerComplianceDomain(),
    KubernetesSecurityDomain(),
]


def _discover_domains() -> list[Domain]:
    """Built-in packs, plus any from `steadystate.domains` entry points (built-ins first).

    Each entry point loads a Domain instance or a zero-arg callable returning one; a callable is
    invoked. A pack that fails to construct, or whose `name` collides with a built-in, is logged
    and skipped -- a third-party pack can extend the set but never replace a shipped one or crash
    the load."""
    domains = list(_BUILTIN_DOMAINS)
    taken = {getattr(d, "name", None) for d in domains}
    for ep_name, obj in discover("domains").items():
        try:
            domain = cast(Domain, obj() if callable(obj) else obj)
        except Exception as exc:
            logger.warning("skipping domain plugin %r: construction failed: %s", ep_name, exc)
            continue
        name = getattr(domain, "name", None)
        if name in taken:
            logger.warning(
                "skipping domain plugin %r: name %r clashes with a built-in", ep_name, name
            )
            continue
        domains.append(domain)
        taken.add(name)
    return domains


# The packs the pipeline loads by default: built-ins overlaid with discovered entry points.
DEFAULT_DOMAINS: list[Domain] = _discover_domains()

__all__ = [
    "DEFAULT_DOMAINS",
    "Domain",
    "PolicyFinding",
    "Reference",
    "default_domains",
    "evaluate_with",
    "references_for",
]


def default_domains() -> list[Domain]:
    """A fresh list of the default domain packs (packs are stateless, shared safely)."""
    return list(DEFAULT_DOMAINS)
