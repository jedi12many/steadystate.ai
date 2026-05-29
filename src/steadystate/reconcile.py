"""Generic reconciler: diff declared vs observed -> Drift.

v0's Terraform source rides terraform's own plan diff and yields Drift directly,
so it doesn't use this. This is the general path for sources that only know how
to enumerate declared and observed resources separately.
"""

from __future__ import annotations

from .model import ChangeType, Drift, Resource


def reconcile(declared: list[Resource], observed: list[Resource]) -> list[Drift]:
    by_declared = {r.identity: r for r in declared}
    by_observed = {r.identity: r for r in observed}
    drifts: list[Drift] = []

    for ident, d in by_declared.items():
        o = by_observed.get(ident)
        if o is None:
            drifts.append(
                Drift(
                    identity=ident,
                    kind=d.kind,
                    change_type=ChangeType.ADDED,
                    provenance=d.provenance,
                    declared=d.properties,
                )
            )
        elif d.properties != o.properties:
            drifts.append(
                Drift(
                    identity=ident,
                    kind=d.kind,
                    change_type=ChangeType.MODIFIED,
                    provenance=d.provenance,
                    declared=d.properties,
                    observed=o.properties,
                )
            )

    for ident, o in by_observed.items():
        if ident not in by_declared:
            drifts.append(
                Drift(
                    identity=ident,
                    kind=o.kind,
                    change_type=ChangeType.REMOVED,
                    provenance=o.provenance,
                    observed=o.properties,
                )
            )

    return drifts
