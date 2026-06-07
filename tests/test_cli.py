"""CLI entry concerns. Notably: the model's output is unpredictable Unicode, and a Windows console
defaults to a non-UTF-8 codec -- so without forcing UTF-8, a single ``->`` in an LLM explanation
crashes a scan with UnicodeEncodeError. (Found by a real-GCP run; this pins the fix.)"""

from __future__ import annotations

import sys

from steadystate.cli import _ensure_utf8_streams


class _Reconfigurable:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    def reconfigure(self, **kwargs: object) -> None:
        self.calls.append(kwargs)


def test_streams_are_made_utf8_with_a_replace_fallback(monkeypatch):
    out, err = _Reconfigurable(), _Reconfigurable()
    monkeypatch.setattr(sys, "stdout", out)
    monkeypatch.setattr(sys, "stderr", err)
    _ensure_utf8_streams()
    # both streams reconfigured to UTF-8 with replace -- so an LLM's arrow/em-dash never crashes
    assert out.calls == [{"encoding": "utf-8", "errors": "replace"}]
    assert err.calls == [{"encoding": "utf-8", "errors": "replace"}]


def test_a_stream_without_reconfigure_is_a_safe_no_op(monkeypatch):
    # a redirected pipe may not expose reconfigure -- we must not crash trying
    monkeypatch.setattr(sys, "stdout", object())
    monkeypatch.setattr(sys, "stderr", object())
    _ensure_utf8_streams()  # no exception


# -- `fix --apply`: one failing remediation must not abort the rest (found by a real-GCP run) -----


def test_a_failed_remediation_is_reported_and_the_rest_still_run():
    import subprocess

    from steadystate.cli import _apply_remediations

    class _Plan:
        eligible = True

    class _Drift:
        def __init__(self, name: str) -> None:
            self.identity = name

    class _Executor:
        def __init__(self) -> None:
            self.attempts: list[str] = []

        def plan_for(self, _drift):
            return _Plan()

        def remediate(self, drift, confirm):  # noqa: ARG002
            self.attempts.append(drift.identity)
            if drift.identity == "boom":  # this apply fails, like the live VM resize did
                raise subprocess.CalledProcessError(1, ["terraform", "apply"])
            return "reconciled"

    ex = _Executor()
    items, failures = _apply_remediations([_Drift("boom"), _Drift("ok")], ex, apply=True)
    # the failure did NOT abort the loop -- the second drift was still attempted
    assert ex.attempts == ["boom", "ok"] and failures == 1
    assert items[0][1] is None and items[1][1] == "reconciled"  # failed -> no result; next succeeds


def test_remediations_are_not_run_without_apply():
    from steadystate.cli import _apply_remediations

    class _Plan:
        eligible = True

    class _Drift:
        identity = "x"

    class _Executor:
        def plan_for(self, _drift):
            return _Plan()

        def remediate(self, *_a, **_k):
            raise AssertionError("must not remediate on a dry run")

    items, failures = _apply_remediations([_Drift()], _Executor(), apply=False)
    assert failures == 0 and items[0][1] is None  # dry run: planned, never executed
