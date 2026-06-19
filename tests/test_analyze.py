"""Root-cause analysis: the probe captures the LEAD-UP to the failure (the lines before the panic,
where the cause lives -- not just the panic line and forward), and `analyze` feeds that before-event
window to the model with an INVESTIGATOR prompt (reason, quote what you cite, label inferences) --
not a transcriptionist one that forbids reasoning. These pin the capture window + the framing."""

from __future__ import annotations

from datetime import UTC, datetime

from steadystate.probe.kubectl import scan_log_text
from steadystate.reason.analyze import _RCA_SYSTEM, _evidence_bundle, analyze_finding
from steadystate.reason.collect import Evidence
from steadystate.state import Finding, StateStore

_PANIC = """\
2026-06-08 worker starting
panic: runtime error: invalid memory address or nil pointer dereference
[signal SIGSEGV: segmentation violation code=0x1 addr=0x0]
goroutine 42 [running]:
apiclient.(*Client).Policy(0x0)
\t/app/apiclient/client.go:63 +0x2c
vendor/caclient.NewClient(...)
\t/app/caclient.go:35
targets.ValidateTargetByType(...)
\t/app/targets.go:186
"""


# -- the probe captures the call chain, not just the matching lines --------------


def test_scan_captures_the_lead_up_plus_the_trace_block():
    verdict = scan_log_text(_PANIC, threshold=5)
    assert verdict is not None and verdict.fatal
    block = "\n".join(verdict.trace)
    # the frames an RCA needs -- which AREN'T 'error' lines, so the sample alone would miss them
    assert "panic:" in block and "Policy(0x0)" in block
    assert "client.go:63" in block and "targets.go:186" in block
    # the window now LEADS WITH the line before the panic -- the lead-up, where the cause lives
    assert verdict.trace[0].startswith("2026-06-08 worker starting")
    assert "worker starting" in block


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
        last_title="gateway is Erroring in prod",
        status="open",
        details=details,
    )


def test_evidence_bundle_carries_the_fields_and_the_trace_verbatim():
    bundle = _evidence_bundle(_finding({"workload": "gateway", "trace": _PANIC}))
    assert "gateway is Erroring in prod" in bundle  # the headline
    assert "workload: gateway" in bundle  # a structured field
    assert "Policy(0x0)" in bundle and "client.go:63" in bundle  # the trace, verbatim


def test_evidence_bundle_leads_with_the_before_event_log_window():
    # the crashloop path captures a `log_window` (the --previous tail = the lead-up) -- the meat
    bundle = _evidence_bundle(_finding({"workload": "gateway", "log_window": _PANIC}))
    assert "leading up to the failure" in bundle.lower()  # under its own header
    assert "worker starting" in bundle and "Policy(0x0)" in bundle  # the lead-up + the panic


def test_evidence_bundle_leads_with_live_refetched_logs_when_present():
    # logs re-fetched FRESH at analyze time arrive as a collected, cited block and lead the
    # scan-time capture, which follows as the fallback snapshot.
    fresh = Evidence(
        "logs re-fetched live at analyze time (current + previous container)",
        "fresh: nil pointer on the ca client",
        "kubectl logs gateway -n prod --tail --previous / (current)",
    )
    bundle = _evidence_bundle(
        _finding({"workload": "gateway", "log_window": "old scan snapshot"}),
        collected=[fresh],
    )
    assert "re-fetched live" in bundle.lower() and "fresh: nil pointer" in bundle
    assert bundle.index("fresh: nil pointer") < bundle.index("old scan snapshot")  # live first


def test_analyze_feeds_the_collected_evidence_to_the_model():
    seen = {}

    def fake(system: str, user: str, caller: str):
        seen["user"] = user
        return "rca"

    logs = Evidence("logs re-fetched live", "freshly re-fetched lead-up", "kubectl logs ...")
    analyze_finding(_finding({"trace": _PANIC}), fake, collected=[logs])
    assert "freshly re-fetched lead-up" in seen["user"]


def test_the_rca_prompt_says_investigate_the_lead_up_and_stay_honest():
    system = _RCA_SYSTEM.lower()
    assert "investigat" in system  # an investigator, not a transcriptionist
    assert "before" in system and "lead-up" in system  # examine what happened before the failure
    # still checkable: quote what you cite, label inferences -- honest, not gagged
    assert "quote" in system and "infer" in system


def test_analyze_feeds_only_the_captured_evidence_to_the_model():
    seen = {}

    def fake_complete(system: str, user: str, caller: str):
        seen["system"], seen["user"], seen["caller"] = system, user, caller
        return "Root cause: nil apiclient.Client; .Policy() called on a 0x0 receiver."

    finding = _finding({"workload": "gateway", "trace": _PANIC})
    out = analyze_finding(finding, fake_complete)
    assert "nil apiclient.Client" in out
    assert seen["caller"] == "analyze"
    assert "Policy(0x0)" in seen["user"] and "client.go:63" in seen["user"]  # the real trace
    assert "investigat" in seen["system"].lower()  # the investigator framing rode along


def test_no_model_returns_none_so_the_caller_degrades_honestly():
    assert analyze_finding(_finding({"trace": _PANIC}), lambda *_a: None) is None


# -- the verb, end to end (a recorded finding -> the RCA, via a mocked analyst) ----


def test_analyze_verb_renders_the_rca_for_a_recorded_finding(tmp_path, monkeypatch):
    import steadystate.verbs as srv

    db = str(tmp_path / "s.db")
    with StateStore(db) as store:
        store.record(
            {"a" * 64: ("high", "gateway is Erroring in prod")},
            datetime.now(UTC),
            {"a" * 64: {"category": "Erroring", "workload": "gateway", "trace": _PANIC}},
        )

    class _Analyst:
        def _complete(self, _system, user, _caller):
            assert "Policy(0x0)" in user  # grounded in the captured trace
            return "Root cause: nil pointer on the vendor CA client."

    monkeypatch.setattr(srv, "_nl_analyst", lambda: _Analyst())
    out = srv._render_analyze("a" * 64, db)
    assert "root-cause analysis" in out and "nil pointer on the vendor CA client" in out
    # no LLM -> a clean, honest degrade (never a guess)
    monkeypatch.setattr(srv, "_nl_analyst", lambda: None)
    assert "analyze needs an LLM" in srv._render_analyze("a" * 64, db)


# -- the close-the-loop: save -> show displays -> send to a surface ---------------


def test_analyze_saves_the_rca_and_show_displays_it(tmp_path, monkeypatch):
    import steadystate.verbs as srv

    db = str(tmp_path / "s.db")
    with StateStore(db) as store:
        store.record(
            {"a" * 64: ("high", "gateway is Erroring")},
            datetime.now(UTC),
            {"a" * 64: {"category": "Erroring", "trace": _PANIC}},
        )

    class _A:
        def _complete(self, _s, _u, _c):
            return "Root cause: nil apiclient.Client on a 0x0 receiver."

    monkeypatch.setattr(srv, "_nl_analyst", lambda: _A())
    srv._render_analyze("a" * 64, db)  # produces + SAVES the RCA
    with StateStore(db) as store:
        assert store.get_analysis("a" * 64) is not None  # persisted (upsert), survives the terminal
    shown = srv._render_show("a" * 64, db)
    assert "root-cause analysis" in shown and "nil apiclient.Client" in shown  # rides along in show


def test_send_analysis_guards(tmp_path):
    import steadystate.verbs as srv

    db = str(tmp_path / "s.db")
    with StateStore(db) as store:
        store.record({"a" * 64: ("high", "x")}, datetime.now(UTC), {"category": "Erroring"})
    assert "only `github`" in srv._send_analysis(
        "a" * 64, db, "slack"
    )  # only github carries an RCA
    assert "analyze" in srv._send_analysis("a" * 64, db, "github")  # no saved RCA -> run analyze


# -- grounding in prior RCAs: this fleet's history for the same failure ------------


def test_prior_incidents_surfaces_earlier_rcas_of_the_same_category():
    from steadystate.reason.analyze import prior_incidents

    store = StateStore()
    # an earlier CrashLoopBackOff that was analyzed...
    store.record(
        {"a" * 64: ("high", "web crashed (mon)")},
        datetime(2026, 6, 1, tzinfo=UTC),
        {"a" * 64: {"category": "CrashLoopBackOff"}},
    )
    store.save_analysis(
        "a" * 64, "Root cause: nil CA client.\n...more frames...", datetime(2026, 6, 1, tzinfo=UTC)
    )
    # ...and a NEW one of the same category today
    store.record(
        {"b" * 64: ("high", "web crashed (today)")},
        datetime(2026, 6, 8, tzinfo=UTC),
        {"b" * 64: {"category": "CrashLoopBackOff"}},
    )
    finding = {f.fingerprint: f for f in store.all_findings()}["b" * 64]
    out = prior_incidents(store, finding)
    assert "PRIOR RCAs" in out and "CrashLoopBackOff" in out
    assert (
        "web crashed (mon)" in out and "Root cause: nil CA client." in out
    )  # the prior root cause
    assert "more frames" not in out  # only the first line of the prior RCA, not the whole thing


def test_prior_incidents_is_empty_with_no_earlier_analyzed_incident():
    from steadystate.reason.analyze import prior_incidents

    store = StateStore()
    store.record(
        {"b" * 64: ("high", "web crashed")},
        datetime(2026, 6, 8, tzinfo=UTC),
        {"b" * 64: {"category": "CrashLoopBackOff"}},
    )
    finding = {f.fingerprint: f for f in store.all_findings()}["b" * 64]
    assert prior_incidents(store, finding) == ""  # no prior analyzed incident -> no context


def test_evidence_bundle_frames_with_prior_history_up_front():
    bundle = _evidence_bundle(
        _finding({"trace": _PANIC}), prior="PRIOR RCAs: - web: nil CA client last time"
    )
    assert "PRIOR RCAs" in bundle and "nil CA client last time" in bundle
    assert bundle.index("PRIOR RCAs") < bundle.index(
        "Policy(0x0)"
    )  # history frames before the logs
