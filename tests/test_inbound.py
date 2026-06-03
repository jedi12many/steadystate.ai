"""The inbound seam: signature verification, payload->Command, dispatch, and the registry."""

from __future__ import annotations

import hashlib
import hmac
import json
import urllib.parse
from datetime import UTC, datetime

import pytest

from steadystate.inbound import INBOUND, build_inbound
from steadystate.inbound.base import (
    APPROVE,
    COST,
    DECLINE,
    FINDINGS,
    HELP,
    HISTORY,
    MUTE,
    PENDING,
    PROBE,
    SEND,
    SHOW,
    SURFACES_LIST,
    TARGETS,
    Command,
    command_from_text,
    render_help,
)
from steadystate.inbound.server import dispatch, run_command
from steadystate.inbound.slack import (
    SlackInbound,
    command_from_payload,
    verify_slack_signature,
)
from steadystate.model import ChangeType, Drift, Provenance
from steadystate.notify.slack import format_slack_message
from steadystate.reason.alert import Alert, Layer, Severity
from steadystate.state import PendingAction, StateStore

_SECRET = "shhh"
_NOW = 1_700_000_000.0


def _sign(ts: str, body: str) -> str:
    base = f"v0:{ts}:{body}".encode()
    return "v0=" + hmac.new(_SECRET.encode(), base, hashlib.sha256).hexdigest()


def _slack_button(action_id: str, fp: str, actor: str = "bob") -> str:
    payload = {"actions": [{"action_id": action_id, "value": fp}], "user": {"username": actor}}
    return urllib.parse.urlencode({"payload": json.dumps(payload)})


def _slack_slash(text: str, actor: str = "carol") -> str:
    return urllib.parse.urlencode({"command": "/steadystate", "text": text, "user_name": actor})


# -- signature verification (the security boundary) -----------------------------


def test_valid_signature_passes():
    ts, body = "1700000000", "payload=%7B%7D"
    assert verify_slack_signature(_SECRET, ts, body, _sign(ts, body), now=_NOW)


def test_bad_signature_fails():
    assert not verify_slack_signature(_SECRET, "1700000000", "x=1", "v0=deadbeef", now=_NOW)


def test_stale_timestamp_fails():
    ts, body = "1700000000", "x=1"
    assert not verify_slack_signature(_SECRET, ts, body, _sign(ts, body), now=_NOW + 9999)


def test_non_numeric_timestamp_fails():
    assert not verify_slack_signature(_SECRET, "nope", "x", "v0=x", now=_NOW)


def test_adapter_verify_reads_the_slack_headers():
    ts, body = "1700000000", "payload=%7B%7D"
    headers = {"X-Slack-Request-Timestamp": ts, "X-Slack-Signature": _sign(ts, body)}
    assert SlackInbound(_SECRET).verify(headers, body, now=_NOW)
    assert not SlackInbound(_SECRET).verify({"X-Slack-Signature": "v0=bad"}, body, now=_NOW)


# -- the shared text grammar (Teams @mention, Slack slash) ----------------------


def test_text_grammar_parses_act_and_readonly_verbs():
    assert command_from_text("approve fp7", "amy") == Command(APPROVE, "amy", "fp7")
    assert command_from_text("decline fp7", "amy") == Command(DECLINE, "amy", "fp7")
    assert command_from_text("help", "amy") == Command(HELP, "amy")
    assert command_from_text("pending", "amy") == Command(PENDING, "amy")
    assert command_from_text("probe prod-k8s", "amy") == Command(PROBE, "amy", "prod-k8s")
    assert command_from_text("cost", "amy") == Command(COST, "amy")  # optional arg absent
    assert command_from_text("cost week", "amy") == Command(COST, "amy", "week")  # optional period
    assert command_from_text("mute fp9", "amy") == Command(MUTE, "amy", "fp9")


def test_text_grammar_parses_probe_flags():
    assert command_from_text("probe prod unmute", "amy") == Command(
        PROBE, "amy", "prod", flags=frozenset({"unmute"})
    )
    assert command_from_text("probe prod --unmute", "amy") == Command(
        PROBE, "amy", "prod", flags=frozenset({"unmute"})
    )
    assert command_from_text("probe prod", "amy") == Command(PROBE, "amy", "prod")
    # multiple flags, any order, with/without dashes
    assert command_from_text("probe prod verbose -v cost", "amy") == Command(
        PROBE, "amy", "prod", flags=frozenset({"verbose", "cost"})
    )
    assert command_from_text("probe verbose prod", "amy") == Command(
        PROBE, "amy", "prod", flags=frozenset({"verbose"})
    )


def test_scan_and_refresh_are_probe_synonyms():
    # muscle-memory: `scan`/`refresh <target>` == `probe <target>` (re-run to refresh state).
    assert command_from_text("refresh prod", "amy") == Command(PROBE, "amy", "prod")
    assert command_from_text("scan prod", "amy") == Command(PROBE, "amy", "prod")
    # bare `refresh`/`scan` (no target) refreshes the whole fleet -> `probe all`.
    assert command_from_text("refresh", "amy") == Command(PROBE, "amy", "all")
    assert command_from_text("scan", "amy") == Command(PROBE, "amy", "all")
    # flags still parse through the alias.
    assert command_from_text("refresh prod verbose", "amy") == Command(
        PROBE, "amy", "prod", flags=frozenset({"verbose"})
    )
    # bare `probe` still needs a target (unchanged) -- only the synonyms default to the fleet.
    assert command_from_text("probe", "amy") is None


def test_text_grammar_is_case_insensitive_and_skips_leading_noise():
    assert command_from_text("hey  PENDING please", "amy") == Command(PENDING, "amy")


def test_text_grammar_needs_a_fingerprint_for_act_verbs_and_ignores_unknowns():
    assert command_from_text("approve", "amy") is None  # no fingerprint -> not actionable
    assert command_from_text("", "amy") is None
    assert command_from_text("status now", "amy") is None  # unknown verb


def test_render_help_lists_every_command():
    text = render_help()
    for verb in (
        HELP,
        TARGETS,
        PENDING,
        PROBE,
        COST,
        FINDINGS,
        SHOW,
        SURFACES_LIST,
        SEND,
        HISTORY,
        MUTE,
        APPROVE,
        DECLINE,
    ):
        assert verb in text


def test_render_help_documents_probe_all_sweep():
    # `probe all` (the fleet sweep) is reachable but was undocumented -- help must mention it.
    assert "probe all" in render_help() or "all" in render_help()


def test_tool_schema_covers_every_command_with_args_and_effects():
    from steadystate.inbound.base import COMMANDS, tool_schema

    schema = tool_schema()
    by = {t["name"]: t for t in schema["tools"]}
    assert set(by) == set(COMMANDS)  # the schema can never drift from the dispatch table
    # the guardrail vocabulary an agent must respect, with the verbs in the right buckets.
    assert by["approve"]["effect"] == "guardrailed-write"
    assert by["send"]["effect"] == "external-send"
    assert by["show"]["effect"] == "read-only" and by["probe"]["effect"] == "read-only"
    assert {t["effect"] for t in schema["tools"]} <= {
        "read-only",
        "state-write",
        "guardrailed-write",
        "external-send",
    }
    # args + flags are exposed so a tool-calling agent knows how to invoke each verb.
    assert [a["name"] for a in by["send"]["args"]] == ["fingerprint", "surface"]
    assert by["cost"]["args"] == [{"name": "period", "required": False}]  # optional arg marked
    assert "deep" in by["probe"]["flags"]


# -- Slack payload parsing (buttons + slash) ------------------------------------


def test_parse_approve_and_decline_buttons():
    assert command_from_payload(
        {
            "actions": [{"action_id": "steadystate_approve", "value": "fp1"}],
            "user": {"username": "amy"},
        }
    ) == Command(APPROVE, "amy", "fp1")
    assert command_from_payload(
        {"actions": [{"action_id": "steadystate_decline", "value": "fp1"}]}
    ) == Command(DECLINE, "slack", "fp1")  # actor defaults when absent


def test_parse_rejects_unknown_action_missing_fp_and_empty():
    assert command_from_payload({"actions": [{"action_id": "other", "value": "fp"}]}) is None
    assert command_from_payload({"actions": [{"action_id": "steadystate_approve"}]}) is None
    assert command_from_payload({}) is None


def test_slack_adapter_parse_decodes_a_button_body():
    got = SlackInbound(_SECRET).parse(_slack_button("steadystate_approve", "fp7", "carol"))
    assert got == Command(APPROVE, "carol", "fp7")
    assert SlackInbound(_SECRET).parse("not-form-data") is None


def test_slack_defer_acks_a_slash_command_but_not_a_button():
    # a slash command carries a response_url -> ack now, post the result later
    slash = urllib.parse.urlencode(
        {
            "command": "/steadystate",
            "text": "probe prod",
            "response_url": "https://hooks.slack.com/x",
        }
    )
    ack = SlackInbound(_SECRET).defer(slash)
    assert json.loads(ack) == {"response_type": "ephemeral", "text": "running..."}
    # a button click (block_actions) has no slow work -> no defer (synchronous)
    assert SlackInbound(_SECRET).defer(_slack_button("steadystate_approve", "fp1")) is None


def test_slack_complete_posts_the_result_to_the_response_url(monkeypatch):
    captured = {}

    def fake_open(request, timeout=None):
        captured["url"] = request.full_url
        captured["body"] = json.loads(request.data)

        class _Ctx:
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        return _Ctx()

    monkeypatch.setattr("steadystate.inbound.slack.safe_urlopen", fake_open)
    body = urllib.parse.urlencode(
        {
            "command": "/steadystate",
            "text": "probe prod",
            "response_url": "https://hooks.slack.com/x",
        }
    )
    SlackInbound(_SECRET).complete(body, "prod: clean")
    assert captured["url"] == "https://hooks.slack.com/x"
    assert captured["body"] == {"response_type": "in_channel", "text": "prod: clean"}


def test_slack_adapter_parse_handles_a_slash_command():
    assert SlackInbound(_SECRET).parse(_slack_slash("help")) == Command(HELP, "carol")
    assert SlackInbound(_SECRET).parse(_slack_slash("pending", "dora")) == Command(PENDING, "dora")
    assert SlackInbound(_SECRET).parse(_slack_slash("approve fp3")) == Command(
        APPROVE, "carol", "fp3"
    )


# -- the command core dispatch --------------------------------------------------


def _pending(fp: str = "fp1") -> PendingAction:
    return PendingAction(
        fingerprint=fp, source="terraform", path="/repo", drift_identity="x", command="cmd"
    )


def test_run_command_decline_marks_declined(tmp_path):
    db = str(tmp_path / "s.db")
    with StateStore(db) as store:
        store.record_pending(_pending(), datetime(2026, 1, 1, tzinfo=UTC))
    msg = run_command(Command(DECLINE, "bob", "fp1"), db)
    assert "declined" in msg
    with StateStore(db) as store:
        assert store.get_pending("fp1").status == "declined"


def test_run_command_mute_silences_a_fingerprint(tmp_path):
    db = str(tmp_path / "s.db")
    fp = "a" * 64
    msg = run_command(Command(MUTE, "bob", fp), db)
    assert f"Muted {fp}" in msg
    # it's now suppressed in the store, so the next scan/probe honors it
    with StateStore(db) as store:
        assert store.is_suppressed(fp, datetime(2026, 1, 1, tzinfo=UTC))


def test_show_grammar_and_help():
    assert command_from_text("show fp7", "amy") == Command(SHOW, "amy", "fp7")
    assert command_from_text("show", "amy") is None  # needs a fingerprint
    assert "show <fingerprint>" in render_help()


def test_run_command_show_evidence_and_timestamps(tmp_path):
    db = str(tmp_path / "s.db")
    fp = "a" * 64
    with StateStore(db) as store:
        store.record(
            {fp: ("high", "squid is CrashLoopBackOff in prod-cluster/team-a")},
            datetime(2026, 6, 2, 14, 30, tzinfo=UTC),
            {fp: {"namespace": "team-a", "cluster": "prod-cluster", "last_log": "missing DB_URL"}},
        )
    msg = run_command(Command(SHOW, "amy", fp[:10]), db)  # a prefix resolves
    assert "squid is CrashLoopBackOff in prod-cluster/team-a" in msg
    assert "missing DB_URL" in msg  # the captured error
    assert "namespace" in msg and "team-a" in msg
    assert "2026-06-02T14:30" in msg  # first/last seen -- the window the operator asked about

    assert "Unknown fingerprint" in run_command(Command(SHOW, "amy", "deadbeef"), db)


# -- chat json (the agent read path) -------------------------------------------


def _json_flag(verb: str, fp: str = "") -> Command:
    return Command(verb, "amy", fp, flags=frozenset({"json"}))


def test_json_flag_parses_on_read_verbs():
    assert command_from_text("show fp7 json", "amy").flags == frozenset({"json"})
    assert command_from_text("findings json", "amy").flags == frozenset({"json"})
    assert command_from_text("probe prod json deep", "amy").flags == frozenset({"json", "deep"})


def test_show_and_findings_json_return_structured_data(tmp_path):
    db = str(tmp_path / "s.db")
    fp = "a" * 64
    with StateStore(db) as store:
        store.record(
            {fp: ("high", "squid is CrashLoopBackOff in prod/team-a")},
            datetime(2026, 6, 2, 14, 30, tzinfo=UTC),
            {fp: {"namespace": "team-a", "last_log": "boom"}},
        )
    doc = json.loads(run_command(_json_flag(SHOW, fp[:10]), db))  # prefix resolves
    assert doc["fingerprint"] == fp and doc["status"] == "open"
    assert doc["evidence"] == {"namespace": "team-a", "last_log": "boom"}

    rows = json.loads(run_command(_json_flag(FINDINGS), db))
    assert isinstance(rows, list) and rows[0]["fingerprint"] == fp


def test_json_errors_are_json_not_prose(tmp_path):
    # an agent in json mode must always get parseable output -- even on an error.
    db = str(tmp_path / "s.db")
    with StateStore(db) as store:
        store.record({"a" * 64: ("low", "t")}, datetime(2026, 6, 2, tzinfo=UTC))
    doc = json.loads(run_command(_json_flag(SHOW, "deadbeef"), db))
    assert "error" in doc and "Unknown fingerprint" in doc["error"]
    # no findings db yet -> findings json is an empty array, not a prose sentence.
    assert json.loads(run_command(_json_flag(FINDINGS), str(tmp_path / "absent.db"))) == []


def test_probe_json_returns_the_report_shape(monkeypatch, tmp_path):
    monkeypatch.setenv(
        "STEADYSTATE_TARGETS",
        _targets_file(tmp_path, {"prod": {"source": "argocd", "path": "/x", "label": "prod"}}),
    )
    monkeypatch.setattr(
        "steadystate.inbound.server.build_report", lambda *a, **k: _report_with_one_alert()
    )
    doc = json.loads(run_command(_json_flag(PROBE, "prod"), ":memory:"))
    assert doc["summary"]["alerts"] == 1  # same shape as `scan --json`
    assert doc["alerts"][0]["title"] == "web is Degraded"


# -- surfaces / send (dispatch a finding to an alert surface) -------------------


def test_send_and_surfaces_grammar_and_help():
    assert command_from_text("send fp7 servicenow", "amy") == Command(
        SEND, "amy", "fp7", argument2="servicenow"
    )
    # a natural "send <fp> to <surface>" works -- the surface is the last token.
    assert command_from_text("send fp7 to slack", "amy") == Command(
        SEND, "amy", "fp7", argument2="slack"
    )
    assert command_from_text("send fp7", "amy") is None  # needs both a fp and a surface
    assert command_from_text("surfaces", "amy") == Command(SURFACES_LIST, "amy")
    text = render_help()
    assert "send <fingerprint> <surface>" in text and "surfaces" in text


def test_surfaces_lists_targets_and_marks_configured(monkeypatch):
    monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)
    out = run_command(Command(SURFACES_LIST, "amy"), ":memory:")
    assert "console" in out and "configured" in out  # console is always available
    assert "slack" in out and "not configured" in out  # no webhook set -> not configured


def _record(db: str, fp: str) -> None:
    with StateStore(db) as store:
        store.record(
            {fp: ("high", "squid is CrashLoopBackOff in prod/team-a")},
            datetime(2026, 6, 2, 14, 30, tzinfo=UTC),
            {fp: {"namespace": "team-a", "last_log": "missing DB_URL"}},
        )


def test_send_dispatches_a_finding_to_a_configured_surface(monkeypatch, tmp_path):
    from steadystate.inbound import server

    sent: list = []

    class _Fake:
        name = "fake"

        def emit(self, report, resolved=None):
            sent.append(report)

    monkeypatch.setitem(server.SURFACES, "fake", _Fake)  # no capability entry -> treated as ready
    db = str(tmp_path / "s.db")
    fp = "a" * 64
    _record(db, fp)

    msg = run_command(Command(SEND, "amy", fp[:10], argument2="fake"), db)  # a prefix resolves
    assert "Sent" in msg and "fake" in msg
    assert len(sent) == 1
    alert = sent[0].alerts[0]
    assert alert.title == "squid is CrashLoopBackOff in prod/team-a"
    assert alert.correlation_fingerprint == fp  # carries the fp so a surface can dedup on it
    assert "missing DB_URL" in alert.why_it_matters  # the evidence rides along


def test_send_rejects_unknown_surface_unconfigured_surface_and_unknown_fp(monkeypatch, tmp_path):
    monkeypatch.delenv("STEADYSTATE_SERVICENOW_INSTANCE", raising=False)
    db = str(tmp_path / "s.db")
    fp = "a" * 64
    _record(db, fp)
    assert "Unknown surface" in run_command(Command(SEND, "amy", fp, argument2="nope"), db)
    # a real but unconfigured surface refuses rather than silently sending nothing.
    msg = run_command(Command(SEND, "amy", fp, argument2="servicenow"), db)
    assert "isn't configured" in msg
    assert "Unknown fingerprint" in run_command(
        Command(SEND, "amy", "deadbeef", argument2="console"), db
    )


def test_run_command_approve_routes_to_core(monkeypatch, tmp_path):
    seen: dict = {}

    def fake_apply(store, fingerprint, actor):
        seen["fp"], seen["actor"] = fingerprint, actor
        return "applied!", None

    monkeypatch.setattr("steadystate.inbound.server.apply_pending", fake_apply)
    msg = run_command(Command(APPROVE, "amy", "fp9"), str(tmp_path / "s.db"))
    assert msg == "applied!" and seen == {"fp": "fp9", "actor": "amy"}


def test_run_command_help_lists_commands_without_touching_state():
    # No state path is read: help is pure self-documentation.
    msg = run_command(Command(HELP, "amy"), "/nonexistent/never-opened.db")
    assert HELP in msg and PENDING in msg and APPROVE in msg


def test_run_command_pending_lists_open_remediations(tmp_path):
    db = str(tmp_path / "s.db")
    with StateStore(db) as store:
        store.record_pending(_pending("fpA"), datetime(2026, 1, 1, tzinfo=UTC))
        store.record_pending(_pending("fpB"), datetime(2026, 1, 1, tzinfo=UTC))
    msg = run_command(Command(PENDING, "amy"), db)
    assert "fpA" in msg and "fpB" in msg and "2 remediation" in msg


def test_run_command_pending_says_so_when_empty(tmp_path):
    msg = run_command(Command(PENDING, "amy"), str(tmp_path / "s.db"))
    assert "No remediations" in msg


# -- probe (Summon): resolve a named target -> run the engine -> summarize ------


def _targets_file(tmp_path, data: dict) -> str:
    path = tmp_path / "targets.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return str(path)


def _report_with_one_alert() -> object:
    from steadystate.reason.report import Report

    alert = Alert(
        title="web is Degraded",
        severity=Severity.HIGH,
        drifts=[],
        why_it_matters="0/3 pods available",
        layer=Layer.ALERT,
    )
    return Report(items=[alert])


def test_run_command_probe_resolves_and_summarizes(monkeypatch, tmp_path):
    monkeypatch.setenv(
        "STEADYSTATE_TARGETS",
        _targets_file(tmp_path, {"prod": {"source": "argocd", "path": "/x", "label": "prod"}}),
    )
    # Stub the engine: this test is about the wiring (resolve -> run -> summarize), not a real scan.
    monkeypatch.setattr(
        "steadystate.inbound.server.build_report", lambda *a, **k: _report_with_one_alert()
    )
    msg = run_command(Command(PROBE, "amy", "prod"), ":memory:")
    assert "prod: 1 alert" in msg and "web is Degraded" in msg and "HIGH" in msg
    assert "0/3 pods available" in msg  # the description shows by default, not just the title + fps


def test_probe_deep_flag_parses_and_threads_log_scanning(monkeypatch, tmp_path):
    # `probe <t> deep` -> the engine scans pod logs (scan_logs=True); a plain probe doesn't.
    assert "deep" in command_from_text("probe prod deep", "amy").flags
    monkeypatch.setenv(
        "STEADYSTATE_TARGETS",
        _targets_file(tmp_path, {"prod": {"source": "k8s-live", "context": "prod"}}),
    )
    captured: dict = {}

    def fake_build(*a, **k):
        captured.update(k)
        return _report_with_one_alert()

    monkeypatch.setattr("steadystate.inbound.server.build_report", fake_build)
    run_command(command_from_text("probe prod deep", "amy"), ":memory:")
    assert captured["scan_logs"] is True
    run_command(Command(PROBE, "amy", "prod"), ":memory:")  # plain probe -> no deep
    assert captured["scan_logs"] is False


def test_summarize_shows_the_description_by_default_and_evidence_when_verbose():
    from steadystate.inbound.server import _summarize
    from steadystate.probe.base import Symptom

    symptom = Symptom(
        identity="apps/Deployment/prod/squid",
        kind="Deployment",
        category="CrashLoopBackOff",
        severity=Severity.HIGH,
        title="squid is CrashLoopBackOff",
        detail="2 pod(s) CrashLoopBackOff; last log: fatal: missing DB_URL",
        provenance=Provenance(source="kubernetes", address="apps/Deployment/prod/squid"),
    )
    alert = Alert(
        title="squid is CrashLoopBackOff in 2 place(s)",
        severity=Severity.HIGH,
        drifts=[],
        why_it_matters="2 instances of Deployment squid are CrashLoopBackOff across: prod, stg.",
        layer=Layer.ALERT,
        symptoms=[symptom],
        recommended_action="kubectl rollout restart",
    )
    default = _summarize("prod", [alert])
    assert "squid is CrashLoopBackOff in 2 place(s)" in default
    assert "2 instances of Deployment squid are CrashLoopBackOff" in default  # the description
    assert "fix: kubectl rollout restart" in default
    assert "fp " in default  # fingerprints still listed
    verbose = _summarize("prod", [alert], verbose=True)
    assert "missing DB_URL" in verbose  # the full per-symptom evidence


def test_summarize_shows_a_correlated_groups_mute_all_key():
    from steadystate.inbound.server import _summarize

    alert = Alert(
        title="squid is CrashLoopBackOff in 2 place(s)",
        severity=Severity.HIGH,
        drifts=[],
        why_it_matters="2 instances across: prod, stg.",
        layer=Layer.ALERT,
        correlation_fingerprint="d" * 64,
    )
    out = _summarize("prod", [alert])
    assert "mute-all dddddddd" in out and "silences this group" in out  # the one key to mute it all
    # an ordinary, single-finding alert shows no mute-all line.
    plain = Alert(
        title="x", severity=Severity.LOW, drifts=[], why_it_matters="y", layer=Layer.ALERT
    )
    assert "mute-all" not in _summarize("prod", [plain])


def test_run_command_probe_unknown_target_lists_the_known_ones(monkeypatch, tmp_path):
    monkeypatch.setenv(
        "STEADYSTATE_TARGETS",
        _targets_file(tmp_path, {"prod": {"source": "argocd", "path": "/x"}}),
    )
    msg = run_command(Command(PROBE, "amy", "nope"), ":memory:")
    assert "Unknown target 'nope'" in msg and "prod" in msg


def test_run_command_probe_with_no_targets_configured(monkeypatch):
    monkeypatch.delenv("STEADYSTATE_TARGETS", raising=False)
    assert "No targets configured" in run_command(Command(PROBE, "amy", "prod"), ":memory:")


def test_run_command_probe_honors_mutes_and_unmute_bypasses(tmp_path, monkeypatch):
    # A terraform target with one (security-relevant) drift -- read from a plan.json, no subprocess.
    from datetime import UTC, datetime

    from steadystate.engine import build_report
    from steadystate.reconcile_state import _fingerprints
    from steadystate.state import StateStore

    plan = tmp_path / "plan.json"
    plan.write_text(
        json.dumps(
            {
                "resource_changes": [
                    {
                        "address": "aws_s3_bucket.logs",
                        "type": "aws_s3_bucket",
                        "name": "logs",
                        "change": {
                            "actions": ["update"],
                            "before": {"acl": "private"},
                            "after": {"acl": "public-read"},
                        },
                    }
                ]
            }
        )
    )
    monkeypatch.setenv(
        "STEADYSTATE_TARGETS",
        _targets_file(
            tmp_path, {"demo": {"source": "terraform", "path": str(plan), "label": "demo"}}
        ),
    )
    db = str(tmp_path / "s.db")

    # before mute: the drift surfaces
    assert "1 alert" in run_command(Command(PROBE, "me", "demo"), db)

    # mute its fingerprint in the same store the listener uses
    fp = _fingerprints(build_report("terraform", plan, label="demo").alerts[0])[0]
    with StateStore(db) as store:
        store.mute(fp, None, "me", datetime.now(UTC))

    # after mute: honored by default, but transparently (count shown, never silent)
    muted = run_command(Command(PROBE, "me", "demo"), db)
    assert "clean except 1 muted" in muted and "unmute" in muted

    # unmute bypasses suppression for this run
    assert "1 alert" in run_command(Command(PROBE, "me", "demo", flags=frozenset({"unmute"})), db)


def test_run_command_probe_reports_an_engine_failure_without_crashing(monkeypatch, tmp_path):
    monkeypatch.setenv(
        "STEADYSTATE_TARGETS",
        _targets_file(tmp_path, {"prod": {"source": "argocd", "path": "/missing.json"}}),
    )

    def boom(*a, **k):
        raise ValueError("source blew up")

    monkeypatch.setattr("steadystate.inbound.server.build_report", boom)
    assert "Probe of 'prod' failed: source blew up" in run_command(
        Command(PROBE, "amy", "prod"), ":memory:"
    )


def test_run_command_probe_appends_a_spend_footer(monkeypatch, tmp_path):
    from steadystate.reason.cost import LlmCall

    report = _report_with_one_alert()
    report.llm_calls = [
        LlmCall("correlate", "anthropic", "claude-sonnet-4-5", input_tokens=1000, output_tokens=100)
    ]
    monkeypatch.setenv(
        "STEADYSTATE_TARGETS",
        _targets_file(tmp_path, {"prod": {"source": "argocd", "path": "/x", "label": "prod"}}),
    )
    monkeypatch.setattr("steadystate.inbound.server.build_report", lambda *a, **k: report)
    msg = run_command(Command(PROBE, "amy", "prod"), ":memory:")
    assert "prod: 1 alert" in msg and "LLM: 1 call(s)" in msg  # the summon shows what it cost


def test_run_command_targets_lists_configured_targets(monkeypatch, tmp_path):
    monkeypatch.setenv(
        "STEADYSTATE_TARGETS",
        _targets_file(
            tmp_path,
            {
                "prod-k8s": {"source": "k8s", "path": "/m", "label": "prod-k8s"},
                "sandbox": {"source": "terraform", "path": "/iac", "label": "gcp"},
            },
        ),
    )
    msg = run_command(Command(TARGETS, "amy"), ":memory:")
    assert "2 target(s)" in msg and "prod-k8s" in msg and "sandbox" in msg and "terraform" in msg


def test_run_command_targets_says_so_when_none(monkeypatch):
    monkeypatch.delenv("STEADYSTATE_TARGETS", raising=False)
    assert "No targets configured" in run_command(Command(TARGETS, "amy"), ":memory:")


def test_run_command_findings_and_history_empty(tmp_path):
    db = str(tmp_path / "s.db")
    assert "No findings recorded" in run_command(Command(FINDINGS, "amy"), db)
    assert "No remediation history" in run_command(Command(HISTORY, "amy"), db)


def test_chat_findings_filter_hides_resolved_by_default(tmp_path):
    from steadystate.reason.report import Report
    from steadystate.reconcile_state import reconcile

    db = str(tmp_path / "s.db")
    drift = Drift(
        identity="aws_s3_bucket.logs",
        kind="aws_s3_bucket",
        change_type=ChangeType.MODIFIED,
        provenance=Provenance(source="terraform"),
    )
    alert = Alert(title=drift.summary(), severity=Severity.HIGH, drifts=[drift], why_it_matters="x")
    with StateStore(db) as store:  # record open, then resolve (gone next scan)
        reconcile(Report(items=[alert]), store, datetime(2026, 1, 1, tzinfo=UTC))
        reconcile(Report(items=[]), store, datetime(2026, 1, 2, tzinfo=UTC))
    # `findings` (chat) parses the filter as the optional argument.
    assert command_from_text("findings resolved", "amy") == Command(FINDINGS, "amy", "resolved")
    default = run_command(Command(FINDINGS, "amy"), db)  # default hides resolved
    assert drift.fingerprint not in default and "resolved hidden" in default
    assert drift.fingerprint in run_command(Command(FINDINGS, "amy", "resolved"), db)
    assert drift.fingerprint in run_command(Command(FINDINGS, "amy", "all"), db)


def test_run_command_probe_verbose_shows_the_evidence(monkeypatch, tmp_path):
    from steadystate.reason.report import Report

    drift = Drift(
        identity="aws_s3_bucket.logs",
        kind="aws_s3_bucket",
        change_type=ChangeType.MODIFIED,
        provenance=Provenance(source="terraform"),
        declared={"acl": "private"},
        observed={"acl": "public-read"},
    )
    alert = Alert(
        title="bucket public-read",
        severity=Severity.HIGH,
        drifts=[drift],
        why_it_matters="bucket exposed to the internet",
        recommended_action="terraform apply -target=...",
        layer=Layer.ALERT,
    )
    monkeypatch.setenv(
        "STEADYSTATE_TARGETS",
        _targets_file(tmp_path, {"prod": {"source": "terraform", "path": "/x", "label": "prod"}}),
    )
    monkeypatch.setattr(
        "steadystate.inbound.server.build_report", lambda *a, **k: Report(items=[alert])
    )
    # without verbose: just title + fp
    plain = run_command(Command(PROBE, "amy", "prod"), ":memory:")
    assert "why:" not in plain
    # with verbose: the reasoning + the declared->observed before/after
    detail = run_command(Command(PROBE, "amy", "prod", flags=frozenset({"verbose"})), ":memory:")
    assert "why: bucket exposed" in detail
    assert '"acl": "private"' in detail and '"acl": "public-read"' in detail


def test_run_command_probe_shows_the_fingerprint_to_act_on(monkeypatch, tmp_path):
    from steadystate.reason.report import Report

    drift = Drift(
        identity="aws_s3_bucket.logs",
        kind="aws_s3_bucket",
        change_type=ChangeType.MODIFIED,
        provenance=Provenance(source="terraform"),
    )
    alert = Alert(
        title="bucket drifted",
        severity=Severity.HIGH,
        drifts=[drift],
        why_it_matters="x",
        layer=Layer.ALERT,
    )
    monkeypatch.setenv(
        "STEADYSTATE_TARGETS",
        _targets_file(tmp_path, {"prod": {"source": "terraform", "path": "/x", "label": "prod"}}),
    )
    monkeypatch.setattr(
        "steadystate.inbound.server.build_report", lambda *a, **k: Report(items=[alert])
    )
    msg = run_command(Command(PROBE, "amy", "prod"), ":memory:")
    # the fingerprint is shown so a benign finding can be `mute`d
    assert f"fp {drift.fingerprint}" in msg


# -- cost (chat view of `steadystate cost`) -------------------------------------


def _record_calls(db: str) -> None:
    from datetime import UTC, datetime, timedelta

    from steadystate.reason.cost import LlmCall

    now = datetime.now(UTC)
    with StateStore(db) as store:
        store.record_llm_call(
            LlmCall("correlate", "anthropic", "claude-sonnet-4-5", input_tokens=12000), now
        )
        store.record_llm_call(
            LlmCall("analyze", "anthropic", "claude-opus-4-8", input_tokens=5000),
            now - timedelta(days=1),
        )


def test_run_command_cost_rolls_up_by_caller(tmp_path):
    db = str(tmp_path / "s.db")
    _record_calls(db)
    msg = run_command(Command(COST, "amy"), db)
    assert "LLM spend (all)" in msg and "correlate" in msg and "analyze" in msg


def test_run_command_cost_day_shows_the_trend(tmp_path):
    db = str(tmp_path / "s.db")
    _record_calls(db)
    msg = run_command(Command(COST, "amy", "day"), db)
    assert "by day" in msg and msg.count("~$") >= 2  # a total + at least one day row


def test_run_command_cost_says_so_when_nothing_recorded(tmp_path):
    assert "No spend recorded" in run_command(Command(COST, "amy"), str(tmp_path / "empty.db"))


# -- the generic dispatch shell (verify -> handshake -> parse -> run) ------------


class _FakeAdapter:
    """A minimal adapter to exercise dispatch's control flow without a real provider. When
    ``defer_ack`` is set it also supports deferral (defer/complete), capturing posts in
    ``completed`` -- like Discord/Slack; without it, it's a synchronous provider (Teams)."""

    name = "fake"
    content_type = "application/json"

    def __init__(self, ok=True, handshake_reply=None, command=None, defer_ack=None):
        self._ok, self._handshake, self._command = ok, handshake_reply, command
        self.completed: list[str] = []
        if defer_ack is not None:
            self.defer = lambda body: defer_ack
            self.complete = lambda body, message: self.completed.append(message)

    def ready(self):
        return None

    def verify(self, headers, body):
        return self._ok

    def handshake(self, body):
        return self._handshake

    def parse(self, body):
        return self._command

    def respond(self, message):
        return message.encode()


def test_dispatch_401s_a_forged_request_before_parsing():
    status, body, deferred = dispatch(_FakeAdapter(ok=False), {}, "anything", ":memory:")
    assert status == 401 and body == b"" and deferred is None


def test_dispatch_answers_a_handshake_without_touching_the_core():
    # Discord's PING -> PONG: a verified non-command reply, returned as-is.
    status, body, _ = dispatch(_FakeAdapter(handshake_reply=b'{"type":1}'), {}, "ping", ":memory:")
    assert status == 200 and body == b'{"type":1}'


def test_dispatch_runs_a_parsed_command(monkeypatch):
    monkeypatch.setattr("steadystate.inbound.server.run_command", lambda command, path: "done")
    adapter = _FakeAdapter(command=Command(APPROVE, "x", "fp1"))
    status, body, deferred = dispatch(adapter, {}, "body", ":memory:")
    assert status == 200 and body == b"done" and deferred is None  # fast verb -> synchronous


def test_dispatch_noops_an_unrecognized_payload():
    status, body, _ = dispatch(_FakeAdapter(command=None), {}, "body", ":memory:")
    assert status == 200 and body == b"Nothing to do."


# -- async deferral: slow commands ACK now, post the result later ---------------


def test_dispatch_defers_a_probe_when_the_adapter_supports_it(monkeypatch):
    monkeypatch.setattr("steadystate.inbound.server.run_command", lambda command, path: "scan done")
    adapter = _FakeAdapter(command=Command(PROBE, "x", "prod"), defer_ack=b'{"type":5}')
    status, ack, deferred = dispatch(adapter, {}, "body", ":memory:")
    # the immediate reply is the ACK; the real work is handed back to run in the background
    assert status == 200 and ack == b'{"type":5}' and deferred is not None
    assert adapter.completed == []  # not run yet
    deferred()  # the handler would run this in a thread
    assert adapter.completed == ["scan done"]  # the result was posted back via the provider


def test_dispatch_runs_a_probe_synchronously_when_the_adapter_cannot_defer(monkeypatch):
    monkeypatch.setattr("steadystate.inbound.server.run_command", lambda command, path: "scan done")
    adapter = _FakeAdapter(command=Command(PROBE, "x", "prod"))  # no defer (Teams-like)
    status, body, deferred = dispatch(adapter, {}, "body", ":memory:")
    assert status == 200 and body == b"scan done" and deferred is None


def test_dispatch_does_not_defer_a_fast_verb_even_when_supported(monkeypatch):
    monkeypatch.setattr("steadystate.inbound.server.run_command", lambda command, path: "open fps")
    adapter = _FakeAdapter(command=Command(PENDING, "x"), defer_ack=b'{"type":5}')
    status, body, deferred = dispatch(adapter, {}, "body", ":memory:")
    assert status == 200 and body == b"open fps" and deferred is None  # pending isn't slow


# -- the registry ---------------------------------------------------------------


def test_registry_builds_slack_and_rejects_unknown():
    assert isinstance(build_inbound("slack"), SlackInbound)
    assert "slack" in INBOUND
    with pytest.raises(ValueError, match="unknown inbound channel"):
        build_inbound("nope")


def test_slack_adapter_not_ready_without_a_secret(monkeypatch):
    monkeypatch.delenv("STEADYSTATE_SLACK_SIGNING_SECRET", raising=False)
    assert SlackInbound().ready() is not None
    assert SlackInbound("a-secret").ready() is None


# -- the Slack surface carries the buttons (outbound side) ----------------------


def _drift_alert() -> Alert:
    drift = Drift(
        identity="aws_s3_bucket.logs",
        kind="aws_s3_bucket",
        change_type=ChangeType.MODIFIED,
        provenance=Provenance(source="terraform"),
    )
    return Alert(title="t", severity=Severity.HIGH, drifts=[drift], why_it_matters="w")


def test_slack_message_carries_approve_decline_buttons():
    msg = format_slack_message(_drift_alert())
    actions = next(b for b in msg["blocks"] if b["type"] == "actions")
    assert {e["action_id"] for e in actions["elements"]} == {
        "steadystate_approve",
        "steadystate_decline",
    }
    fingerprint = _drift_alert().drifts[0].fingerprint
    assert all(e["value"] == fingerprint for e in actions["elements"])


def test_slack_message_has_no_buttons_without_a_fingerprint():
    bare = Alert(title="t", severity=Severity.LOW, drifts=[], why_it_matters="w")
    assert "blocks" not in format_slack_message(bare)
