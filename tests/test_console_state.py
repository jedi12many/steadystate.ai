"""Console rendering of state annotations -- deterministic via an injected ``now``.

The console derives NEW vs "seen Nd" from the Alert's ``first_seen`` against the scan
time, shows muted/snoozed tags, and lists findings resolved since the last scan. These
assert the rendered text rather than poke internals, so they double as a spec for the
operator-facing output.
"""

from __future__ import annotations

import io
from datetime import UTC, datetime

from rich.console import Console

from steadystate.model import ChangeType, Drift, Provenance
from steadystate.notify.console import ConsoleSurface
from steadystate.reason.alert import Alert, Layer, Severity
from steadystate.reason.report import Report
from steadystate.reconcile_state import ResolvedFinding


def _drift() -> Drift:
    return Drift(
        identity="aws_s3_bucket.logs",
        kind="aws_s3_bucket",
        change_type=ChangeType.MODIFIED,
        provenance=Provenance(source="terraform"),
    )


def _alert(*, first_seen=None, status=None) -> Alert:
    return Alert(
        title="modified aws_s3_bucket aws_s3_bucket.logs",
        severity=Severity.MEDIUM,
        drifts=[_drift()],
        why_it_matters="declared and observed diverge",
        layer=Layer.ALERT,
        first_seen=first_seen,
        status=status,
    )


def _render(report: Report, *, resolved=None, now=None) -> str:
    # Render into a captured, width-fixed Console so wrapping is deterministic.
    surface = ConsoleSurface()
    surface._console = Console(file=io.StringIO(), width=200, no_color=True)
    surface.emit(report, resolved=resolved, now=now)
    return surface._console.file.getvalue()


def _t(day: int) -> datetime:
    return datetime(2026, 1, day, 12, 0, 0, tzinfo=UTC)


def test_new_finding_renders_new_marker():
    report = Report(items=[_alert(first_seen=_t(5), status="open")])
    out = _render(report, now=_t(5))
    assert "NEW" in out


def test_recurring_finding_renders_seen_days_not_new():
    report = Report(items=[_alert(first_seen=_t(1), status="open")])
    out = _render(report, now=_t(4))
    assert "seen 3d" in out
    assert "NEW" not in out


def test_muted_and_snoozed_render_their_tag():
    muted = _render(Report(items=[_alert(first_seen=_t(1), status="muted")]), now=_t(4))
    assert "MUTED" in muted
    snoozed = _render(Report(items=[_alert(first_seen=_t(1), status="snoozed")]), now=_t(4))
    assert "SNOOZED" in snoozed


def test_resolved_line_lists_titles():
    resolved = [ResolvedFinding(fingerprint="abc123", title="modified aws_s3_bucket old.thing")]
    out = _render(Report(items=[]), resolved=resolved, now=_t(4))
    assert "Resolved since last scan: 1" in out
    assert "old.thing" in out


def test_resolved_only_still_renders_not_steady_state():
    # Resolutions alone (no live items) must still print, not the "no drift" banner.
    resolved = [ResolvedFinding(fingerprint="abc", title="t")]
    out = _render(Report(items=[]), resolved=resolved, now=_t(4))
    assert "no drift detected" not in out
    assert "Resolved since last scan" in out


def test_stateless_alert_has_no_marker():
    # status=None (stateless scan) -> the title renders exactly as before, no badge.
    out = _render(Report(items=[_alert(first_seen=None, status=None)]), now=_t(4))
    assert "NEW" not in out
    assert "seen" not in out
    assert "MUTED" not in out
