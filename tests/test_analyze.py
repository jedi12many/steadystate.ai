"""Grounded root-cause analysis: the probe captures the panic's trace block (the call chain, not
just matching error lines), and `analyze` feeds ONLY that captured evidence to the model with a
prompt that forbids inventing. The differentiator is the grounding -- so that's what these pin."""

from __future__ import annotations

from datetime import UTC, datetime

from steadystate.probe.kubectl import scan_log_text
from steadystate.reason.analyze import _RCA_SYSTEM, _evidence_bundle, analyze_finding
from steadystate.state import Finding, StateStore

_PANIC = """\
2026-06-08 worker starting
panic: runtime error: invalid memory address or nil pointer dereference
[signal SIGSEGV: segmentation violation code=0x1 addr=0x0]
goroutine 42 [running]:
hvclient.(*Client).Policy(0x0)
\t/app/hvclient/client.go:63 +0x2c
globalsign/atlas.NewClient(...)
\t/app/atlas.go:35
targets.ValidateTargetByType(...)
\t/app/targets.go:186
"""


# -- the probe captures the call chain, not just the matching lines --------------


def test_scan_captures_the_trace_block_after_a_fatal_signature():
    verdict = scan_log_text(_PANIC, threshold=5)
    assert verdict is not None and verdict.fatal
    block = "\n".join(verdict.trace)
    # the frames an RCA needs -- which AREN'T 'error' lines, so the sample alone would miss them
    assert "panic:" in block and "Policy(0x0)" in block
    assert "client.go:63" in block and "targets.go:186" in block
    # the trace starts at the panic, not the benign "worker starting" line before it
    assert verdict.trace[0].startswith("panic:")


def test_no_fatal_no_trace():
    assert scan_log_text("INFO all good\nINFO still good", threshold=5) is None


# -- analyze is grounded: only the captured evidence, told not to invent ----------


def _finding(details: dict) -> Finding:
    now = datetime.now(UTC).isoformat()
    return Finding(
        fingerprint="a" * 64,
        first_seen=now,
        last_seen=now,
        last_severity="high",
        last_title="akeyless-gw is Erroring in prod",
        status="open",
        details=details,
    )


def test_evidence_bundle_carries_the_fields_and_the_trace_verbatim():
    bundle = _evidence_bundle(_finding({"workload": "akeyless-gw", "trace": _PANIC}))
    assert "akeyless-gw is Erroring in prod" in bundle  # the headline
    assert "workload: akeyless-gw" in bundle  # a structured field
    assert "Policy(0x0)" in bundle and "client.go:63" in bundle  # the trace, verbatim


def test_the_rca_prompt_forbids_inventing_and_pins_to_the_evidence():
    system = _RCA_SYSTEM.lower()
    assert "only the captured evidence" in system
    assert "do not invent" in system and "never speculate" in system


def test_analyze_feeds_only_the_captured_evidence_to_the_model():
    seen = {}

    def fake_complete(system: str, user: str, caller: str):
        seen["system"], seen["user"], seen["caller"] = system, user, caller
        return "Root cause: nil hvclient.Client; .Policy() called on a 0x0 receiver."

    finding = _finding({"workload": "akeyless-gw", "trace": _PANIC})
    out = analyze_finding(finding, fake_complete)
    assert "nil hvclient.Client" in out
    assert seen["caller"] == "analyze"
    assert "Policy(0x0)" in seen["user"] and "client.go:63" in seen["user"]  # the real trace
    assert "do not invent" in seen["system"].lower()  # the grounding instruction rode along


def test_no_model_returns_none_so_the_caller_degrades_honestly():
    assert analyze_finding(_finding({"trace": _PANIC}), lambda *_a: None) is None


# -- the verb, end to end (a recorded finding -> the RCA, via a mocked analyst) ----


def test_analyze_verb_renders_the_rca_for_a_recorded_finding(tmp_path, monkeypatch):
    import steadystate.inbound.server as srv

    db = str(tmp_path / "s.db")
    with StateStore(db) as store:
        store.record(
            {"a" * 64: ("high", "akeyless-gw is Erroring in prod")},
            datetime.now(UTC),
            {"a" * 64: {"category": "Erroring", "workload": "akeyless-gw", "trace": _PANIC}},
        )

    class _Analyst:
        def _complete(self, _system, user, _caller):
            assert "Policy(0x0)" in user  # grounded in the captured trace
            return "Root cause: nil pointer on the GlobalSign Atlas client."

    monkeypatch.setattr(srv, "_nl_analyst", lambda: _Analyst())
    out = srv._render_analyze("a" * 64, db)
    assert "root-cause analysis" in out and "nil pointer on the GlobalSign Atlas client" in out
    # no LLM -> a clean, honest degrade (never a guess)
    monkeypatch.setattr(srv, "_nl_analyst", lambda: None)
    assert "analyze needs an LLM" in srv._render_analyze("a" * 64, db)


# -- the close-the-loop: save -> show displays -> send to a surface ---------------


def test_analyze_saves_the_rca_and_show_displays_it(tmp_path, monkeypatch):
    import steadystate.inbound.server as srv

    db = str(tmp_path / "s.db")
    with StateStore(db) as store:
        store.record(
            {"a" * 64: ("high", "akeyless-gw is Erroring")},
            datetime.now(UTC),
            {"a" * 64: {"category": "Erroring", "trace": _PANIC}},
        )

    class _A:
        def _complete(self, _s, _u, _c):
            return "Root cause: nil hvclient.Client on a 0x0 receiver."

    monkeypatch.setattr(srv, "_nl_analyst", lambda: _A())
    srv._render_analyze("a" * 64, db)  # produces + SAVES the RCA
    with StateStore(db) as store:
        assert store.get_analysis("a" * 64) is not None  # persisted (upsert), survives the terminal
    shown = srv._render_show("a" * 64, db)
    assert "root-cause analysis" in shown and "nil hvclient.Client" in shown  # rides along in show


def test_send_analysis_guards(tmp_path):
    import steadystate.inbound.server as srv

    db = str(tmp_path / "s.db")
    with StateStore(db) as store:
        store.record({"a" * 64: ("high", "x")}, datetime.now(UTC), {"category": "Erroring"})
    assert "only `github`" in srv._send_analysis(
        "a" * 64, db, "slack"
    )  # only github carries an RCA
    assert "analyze" in srv._send_analysis("a" * 64, db, "github")  # no saved RCA -> run analyze
