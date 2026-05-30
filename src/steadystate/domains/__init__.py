"""Domain plugins: what drift *means* (security, compliance, cost, ...).

A Domain teaches the core which resources it cares about and scores their drift.
Packs register here so the pipeline loads them without being edited: add a pack
module in this package, then append it to DEFAULT_DOMAINS. This is how security &
compliance (CIS, STIG, ...) enter -- as packs, never as core.
"""

from __future__ import annotations

from .base import Domain, PolicyFinding, Reference, evaluate_with, references_for
from .compliance import DockerComplianceDomain
from .security import SecurityDomain
from .security_azure import AzureSecurityDomain
from .security_gcp import GCPSecurityDomain

# The packs the pipeline loads by default. Append new packs here; pipeline.py
# does not change.
DEFAULT_DOMAINS: list[Domain] = [
    SecurityDomain(),
    GCPSecurityDomain(),
    AzureSecurityDomain(),
    DockerComplianceDomain(),
]

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
