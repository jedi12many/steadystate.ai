"""Domain plugins: what drift *means* (security, compliance, cost, ...).

No packs ship in v0 -- drift only. A Domain teaches the core which resources it
cares about, the rules, scoring inputs, and optional remediation recipes. This is
how security & compliance (CIS, STIG, ...) enter: as packs, never as core.
"""
