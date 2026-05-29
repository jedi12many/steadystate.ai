"""Deterministic correlation: group Events by shared attributes -- no model.

A lot of "these drifts belong together" is mechanical and needs no LLM: drifts
declared in the same file, or under the same identity namespace, almost certainly
share context. This correlator groups on those shared attributes and is honest that
the grouping is *mechanical* -- it names the shared attribute, it does not claim to
have reasoned about a common root cause (that is the LLM correlator's job).

It is the honest fallback: when no model is configured -- or the model call fails --
the pipeline still gets grouped Alerts instead of one singleton per drift.

Grouping key per drift, in priority order:

  (a) ``provenance.file`` when set -- drifts declared in the same file group together.
  (b) else the identity *namespace*: the identity with its last dot-separated segment
      removed, when it has >= 2 segments
      (``module.db.aws_instance.primary`` -> ``module.db.aws_instance``;
       ``aws_s3_bucket.logs`` -> ``aws_s3_bucket``).
  (c) else no shared key -> the drift is its own singleton.

Like the LLM parser, the output covers every input index exactly once.
"""

from __future__ import annotations

from ..model import Drift
from .llm import Cluster


def _namespace(identity: str) -> str | None:
    """Identity with its last dot-segment dropped, or None if it has < 2 segments."""
    head, sep, _tail = identity.rpartition(".")
    return head if sep and head else None


def _group_key(drift: Drift) -> str | None:
    """The shared-attribute key for a drift, or None when it shares nothing groupable."""
    if drift.provenance.file:
        return f"file:{drift.provenance.file}"
    namespace = _namespace(drift.identity)
    if namespace is not None:
        return f"ns:{namespace}"
    return None


def _title(key: str, drifts: list[Drift], indexes: list[int]) -> str:
    """Name the shared attribute that grouped these drifts."""
    if len(indexes) == 1:
        return drifts[indexes[0]].summary()
    kind, _, value = key.partition(":")
    if kind == "file":
        return f"{len(indexes)} related drifts in {value}"
    return f"{len(indexes)} drifts under {value}"


def _why(key: str, drifts: list[Drift], indexes: list[int]) -> str:
    """Honest summary: what was grouped and that it is a mechanical grouping."""
    if len(indexes) == 1:
        return f"{drifts[indexes[0]].summary()}: declared and observed state diverge."
    kind, _, value = key.partition(":")
    where = f"declared in {value}" if kind == "file" else f"under identity {value}"
    kinds = sorted({d.kind for d in (drifts[i] for i in indexes)})
    if len(kinds) > 1:
        shared = f"{len(indexes)} resources ({', '.join(kinds)})"
    else:
        shared = f"{len(indexes)} {kinds[0]} resources"
    return (
        f"{shared} {where} all drifted from their declared state. Grouped mechanically by "
        "shared attribute, not by analyzed root cause -- configure an LLM provider for "
        "root-cause reasoning."
    )


def correlate(drifts: list[Drift]) -> list[Cluster]:
    """Group drifts by shared attribute into Clusters -- deterministic, no model call.

    Drifts sharing a key (same file, else same identity namespace) fold into one
    Cluster; everything else is a singleton. Output covers every input index exactly
    once and is stable: groups appear in first-seen key order, indexes in input order.
    All clusters are ``llm_backed=False`` -- the grouping is mechanical.
    """
    order: list[str] = []
    groups: dict[str, list[int]] = {}
    for i, drift in enumerate(drifts):
        key = _group_key(drift)
        # Keyless drifts get a per-index sentinel so they never merge with each other.
        bucket = key if key is not None else f"solo:{i}"
        if bucket not in groups:
            groups[bucket] = []
            order.append(bucket)
        groups[bucket].append(i)
    return [
        Cluster(
            drift_indexes=groups[key],
            title=_title(key, drifts, groups[key]),
            why_it_matters=_why(key, drifts, groups[key]),
            recommended_action=None,
            llm_backed=False,
        )
        for key in order
    ]
