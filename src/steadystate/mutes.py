"""Committed mutes: an operator's "this is benign" survives any state.db.

A mute is not runtime memory -- it's a **decision**. Findings re-derive from live infra on the
next sweep, but "we judged this fingerprint benign" is judgment a team shouldn't have to repeat
because a host was rebuilt or a wall got a fresh db. Fingerprints are content-derived (the same
finding hashes the same everywhere), so the decision can live as committed intent:
``steadystate/mutes.json``, beside the runbook -- reviewed in a PR, so "why is this suppressed?"
has an answer in history instead of an invisible db row.

The mechanics are **import-on-scan**: every stateful reconcile (a scan, a sweep tick of `up`) and
every record-only probe first upserts any committed mute the db doesn't already suppress -- so a
brand-new state.db self-heals on its first pass, and every view (findings/summary/suppression)
works unchanged. Getting a mute INTO the file is an explicit, CLI-only act (``mute --commit`` for
one, ``commit-mutes`` to export the db's current mutes) -- chat/MCP mutes stay db-local until an
operator promotes them, the same trust-channel rule as vouching a solution. The flip side is
honest too: ``unmute`` on a committed fingerprint warns that the next scan will re-mute it, and
that lifting it permanently means removing it from the file (a PR).

The file is a JSON object keyed by fingerprint -- the key IS the identity, so merges dedup
naturally and a reviewer sees ``{fingerprint: {title, by, note, added}}`` with enough context to
judge the entry. Format errors degrade to "no committed mutes", never a crash.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .state import StateStore

COMMITTED_MUTES_FILE = "steadystate/mutes.json"  # committed intent, beside the runbook
MUTES_ENV = "STEADYSTATE_MUTES"
_META_KEYS = ("title", "by", "note", "added")  # what a reviewer sees next to the fingerprint


def resolve_mutes_path(explicit: str = "") -> str:
    """Where the committed mutes live: explicit > ``STEADYSTATE_MUTES`` > the convention."""
    if explicit:
        return explicit
    return os.environ.get(MUTES_ENV, "").strip() or COMMITTED_MUTES_FILE


def load_committed_mutes(path: str = "") -> dict[str, dict[str, str]]:
    """The committed mutes: fingerprint -> its review context (title/by/note/added). ``{}`` on a
    missing or malformed file (committed mutes are opt-in); a non-dict entry is skipped -- one bad
    row never silences the rest of the file's intent."""
    resolved = resolve_mutes_path(path)
    if not Path(resolved).exists():
        return {}
    try:
        raw = json.loads(Path(resolved).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(raw, dict):
        return {}
    out: dict[str, dict[str, str]] = {}
    for fingerprint, meta in raw.items():
        if not str(fingerprint).strip():
            continue
        if not isinstance(meta, dict):
            continue
        out[str(fingerprint)] = {k: str(meta.get(k) or "") for k in _META_KEYS}
    return out


def _write(mutes: dict[str, dict[str, str]], path: str) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    doc = {fp: {k: v for k, v in meta.items() if v} for fp, meta in sorted(mutes.items())}
    target.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")


def apply_committed_mutes(store: StateStore, now: datetime, path: str = "") -> int:
    """Upsert into ``store`` every committed mute it doesn't already suppress -- the
    import-on-scan half. A fresh db self-heals on its first pass; an already-muted (or currently
    snoozed) fingerprint is left alone, so this is idempotent and never fights a snooze (a lapsed
    snooze gets re-muted on the next pass). Returns how many were newly applied."""
    committed = load_committed_mutes(path)
    applied = 0
    for fingerprint, meta in committed.items():
        if store.is_suppressed(fingerprint, now):
            continue
        note = meta.get("note") or f"committed mute ({resolve_mutes_path(path)})"
        store.mute(fingerprint, note, meta.get("by") or "committed", now)
        applied += 1
    return applied


def commit_mute(
    fingerprint: str, *, title: str = "", by: str = "", note: str = "", path: str = ""
) -> str:
    """Add ONE mute to the committed file (merge -- re-committing updates its context). Returns
    the path written, so the caller can tell the operator what to commit."""
    resolved = resolve_mutes_path(path)
    mutes = load_committed_mutes(path)
    mutes[fingerprint] = {
        "title": title,
        "by": by,
        "note": note,
        "added": datetime.now(UTC).date().isoformat(),
    }
    _write(mutes, resolved)
    return resolved


def export_mutes(store: StateStore, path: str = "") -> tuple[int, int, str]:
    """Merge the db's current **permanent mutes** into the committed file (snoozes are temporal by
    nature and stay db-local). Existing entries keep their context; new ones carry the finding's
    title/actor/note so the file is reviewable. Returns ``(newly added, total, path)``."""
    from .state import MUTED

    resolved = resolve_mutes_path(path)
    mutes = load_committed_mutes(path)
    added = 0
    for finding in store.all_findings():
        if finding.status != MUTED:
            continue
        if finding.fingerprint in mutes:
            continue
        mutes[finding.fingerprint] = {
            "title": finding.last_title,
            "by": finding.actor or "",
            "note": finding.note or "",
            "added": datetime.now(UTC).date().isoformat(),
        }
        added += 1
    if added:
        _write(mutes, resolved)
    return added, len(mutes), resolved


def committed_warning(fingerprint: str, path: str = "") -> str:
    """The honesty note ``unmute`` appends when the fingerprint is COMMITTED: the db row is
    cleared, but the next scan re-imports it -- lifting it permanently is a file edit (a PR).
    '' when the fingerprint isn't committed."""
    if fingerprint not in load_committed_mutes(path):
        return ""
    return (
        f" NOTE: this mute is COMMITTED ({resolve_mutes_path(path)}) -- the next scan re-mutes "
        "it. Remove it from that file (a PR) to lift it permanently."
    )
