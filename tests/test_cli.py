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
