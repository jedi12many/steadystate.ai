"""The deterministic remediability tag: whether steadystate can carry out an alert's fix.

The LLM proposes a fix in prose; a separate, deterministic layer decides whether the tool can
actually run it (the executor registry + apply eligibility), and the surfaces label the
recommendation accordingly. This pins both halves down:

- the LLM is *instructed* never to speculate about steadystate's own abilities (prompt guard),
- the tag is computed from the executor, not the model, and matches the suggest/approve path,
- a surface renders "can apply" vs "manual" from it.
"""

from __future__ import annotations

import io

from rich.console import Console

from steadystate.engine import _stamp_remediability
from steadystate.model import ChangeType, Drift, Provenance
from steadystate.notify.console import ConsoleSurface
from steadystate.reason import llm
from steadystate.reason.alert import Alert, Severity
from steadystate.reason.report import Report


def _drift(change: ChangeType = ChangeType.MODIFIED, source: str = "terraform") -> Drift:
    return Drift(
        identity="aws_s3_bucket.logs",
        kind="aws_s3_bucket",
        change_type=change,
        provenance=Provenance(source=source, address="aws_s3_bucket.logs"),
    )


def _alert(drifts=(), *, action: str | None = "rotate the key") -> Alert:
    return Alert(
        title="bucket drifted",
        severity=Severity.HIGH,
        drifts=list(drifts),
        why_it_matters="exposure changed",
        recommended_action=action,
    )


# -- the prompt guard (the LLM must not editorialize about the tool) ------------


def test_both_prompts_forbid_speculating_about_steadystate():
    for instruction in (llm._INSTRUCTION, llm._CORRELATE_INSTRUCTION):
        assert "do NOT speculate about what steadystate" in instruction
        assert "steadystate determines" in instruction


# -- the deterministic stamp (executor, never the LLM) -------------------------


def test_terraform_modified_drift_is_remediable(tmp_path):
    report = Report(items=[_alert([_drift(ChangeType.MODIFIED)])])
    _stamp_remediability(report, "terraform", tmp_path)
    assert report.alerts[0].remediable is True  # an eligible apply exists


def test_terraform_removed_drift_is_not_remediable(tmp_path):
    # A REMOVED drift would destroy a live resource -> never eligible -> not "can apply".
    report = Report(items=[_alert([_drift(ChangeType.REMOVED)])])
    _stamp_remediability(report, "terraform", tmp_path)
    assert report.alerts[0].remediable is False


def test_observe_only_source_is_never_remediable(tmp_path):
    # rancher has no executor -> nothing it surfaces is executable, even a MODIFIED drift.
    report = Report(items=[_alert([_drift(ChangeType.MODIFIED, source="rancher")])])
    _stamp_remediability(report, "rancher", tmp_path)
    assert report.alerts[0].remediable is False


def test_symptom_only_alert_is_not_remediable(tmp_path):
    # The pod-crashloop case: an alert with no drift has no executable fix, even under terraform.
    report = Report(items=[_alert([])])
    _stamp_remediability(report, "terraform", tmp_path)
    assert report.alerts[0].remediable is False


# -- the label the surfaces render ---------------------------------------------


def test_label_is_apply_when_remediable():
    alert = _alert([_drift()])
    alert.remediable = True
    assert "can apply" in alert.remediation_label


def test_label_is_manual_when_not_remediable_but_has_an_action():
    alert = _alert([], action="raise the memory limit")
    assert alert.remediation_label == "Manual -- outside what steadystate executes."


def test_label_is_none_when_nothing_to_say():
    alert = _alert([], action=None)
    assert alert.remediation_label is None


# -- a surface actually renders it ---------------------------------------------


def _render(alert: Alert) -> str:
    surface = ConsoleSurface()
    surface._console = Console(file=io.StringIO(), width=200, no_color=True)
    surface.emit(Report(items=[alert]))
    return surface._console.file.getvalue()


def test_console_renders_manual_for_an_unexecutable_recommendation():
    out = _render(_alert([], action="raise the memory limit"))
    assert "Manual -- outside what steadystate executes." in out


def test_console_renders_can_apply_for_a_remediable_alert():
    alert = _alert([_drift()])
    alert.remediable = True
    assert "steadystate can apply this" in _render(alert)
