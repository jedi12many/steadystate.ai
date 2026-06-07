"""steadystate as an MCP server: the JSON-RPC surface (initialize / tools/list / tools/call / ping)
and the safety model -- read-only verbs are exposed by default, effectful ones only behind the write
grant, and either way a call runs through the SAME `run_command` guardrails a chat user hits. These
pin the protocol shapes and that the grant actually gates what an agent can do."""

from __future__ import annotations

import json

from steadystate.inbound import mcp
from steadystate.inbound.base import APPROVE, PROBE, SUMMARY, Command
from steadystate.inbound.mcp import command_from_tool_call, handle_request, mcp_tools
from steadystate.state import StateStore


def _req(method, params=None, req_id=1):
    msg = {"jsonrpc": "2.0", "id": req_id, "method": method}
    if params is not None:
        msg["params"] = params
    return msg


# -- the handshake --------------------------------------------------------------


def test_initialize_reports_server_info_and_echoes_the_protocol_version():
    out = handle_request(
        _req("initialize", {"protocolVersion": "2025-06-18"}), ":memory:", write=False
    )
    result = out["result"]
    assert result["serverInfo"]["name"] == "steadystate"
    assert result["protocolVersion"] == "2025-06-18"  # echo the client's version
    assert result["capabilities"]["tools"] == {"listChanged": False}
    # an unversioned initialize falls back to our supported revision
    bare = handle_request(_req("initialize", {}), ":memory:", write=False)
    assert isinstance(bare["result"]["protocolVersion"], str)


def test_a_notification_gets_no_response():
    # no `id` -> a notification (notifications/initialized, ...) -> nothing to answer
    assert (
        handle_request(
            {"jsonrpc": "2.0", "method": "notifications/initialized"}, ":memory:", write=False
        )
        is None
    )


def test_ping_and_unknown_method():
    assert handle_request(_req("ping"), ":memory:", write=False)["result"] == {}
    err = handle_request(_req("frobnicate"), ":memory:", write=False)["error"]
    assert err["code"] == -32601  # method not found


# -- tools/list: the grant gates what's exposed ---------------------------------


def test_tools_list_is_read_only_by_default_and_widens_with_the_write_grant():
    read_only = mcp_tools(write=False)
    names = {t["name"] for t in read_only}
    assert SUMMARY in names and "findings" in names  # observe/diagnose verbs are there
    assert APPROVE not in names and "run" not in names  # effectful verbs are NOT, without the grant
    # every exposed read-only tool is annotated as such
    assert all(t["annotations"]["readOnlyHint"] for t in read_only)

    write = {t["name"]: t for t in mcp_tools(write=True)}
    assert APPROVE in write and "run" in write  # the grant exposes the effectful verbs
    assert write[APPROVE]["annotations"] == {
        "title": "approve",
        "readOnlyHint": False,
        "destructiveHint": True,  # a client should confirm a destructive call with the human
    }


def test_author_tier_exposes_check_authoring_without_infra_write():
    # the middle tier: an agent can write checks (observe-only, schema-gated) but NOT touch infra
    read_only = {t["name"] for t in mcp_tools(write=False)}
    author = {t["name"] for t in mcp_tools(write=False, author=True)}
    full = {t["name"] for t in mcp_tools(write=True)}
    assert "add-check" not in read_only  # not without a grant
    assert "add-check" in author and "add-check" in full  # author (and write) expose it
    assert APPROVE not in author and "run" not in author  # but author can't reach infra remediation
    assert "checks" in read_only  # listing checks is read-only, always available
    # tools/call honors the tier: approve is refused in the author tier
    out = handle_request(
        _req("tools/call", {"name": "approve", "arguments": {"fingerprint": "x"}}),
        ":memory:",
        write=False,
        author=True,
    )
    assert out["error"]["code"] == -32602  # approve is unavailable to an author-only agent


def test_tool_input_schema_declares_args_and_probe_flags():
    tools = {t["name"]: t for t in mcp_tools(write=True)}
    probe = tools[PROBE]["inputSchema"]
    assert probe["properties"]["target"]["type"] == "string" and probe["required"] == ["target"]
    assert probe["properties"]["flags"]["items"]["enum"]  # the modifier flags ride as an enum
    assert "required" not in tools[SUMMARY]["inputSchema"]  # a no-arg verb has no required props


# -- tools/call: dispatch + the gate --------------------------------------------


def test_tools_call_runs_a_read_only_verb_through_run_command(tmp_path):
    db = str(tmp_path / "s.db")
    with StateStore(db) as store:
        store.record(
            {"a" * 64: ("high", "web down")},
            __import__("datetime").datetime.now(__import__("datetime").UTC),
            evidence={"a" * 64: {"category": "Unavailable"}},  # a live symptom -> impaired
        )
    out = handle_request(_req("tools/call", {"name": "summary", "arguments": {}}), db, write=False)
    result = out["result"]
    assert result["isError"] is False and "impaired" in result["content"][0]["text"]


def test_tools_call_refuses_an_effectful_verb_without_the_write_grant():
    out = handle_request(
        _req("tools/call", {"name": "approve", "arguments": {"fingerprint": "x"}}),
        ":memory:",
        write=False,
    )
    assert out["error"]["code"] == -32602 and "approve" in out["error"]["message"]


def test_tools_call_with_the_grant_dispatches_an_effectful_verb_as_the_mcp_actor(monkeypatch):
    seen = {}

    def fake_run(command, state_path):
        seen["command"] = command
        return "approved!"

    monkeypatch.setattr(mcp, "run_command", fake_run)
    out = handle_request(
        _req("tools/call", {"name": "approve", "arguments": {"fingerprint": "abc123"}}),
        ":memory:",
        write=True,
    )
    assert out["result"]["content"][0]["text"] == "approved!"
    assert seen["command"] == Command(APPROVE, "mcp", "abc123")  # audited as the mcp actor


def test_tools_call_reports_a_failure_as_an_iserror_result(monkeypatch):
    def boom(command, state_path):
        raise RuntimeError("store is wedged")

    monkeypatch.setattr(mcp, "run_command", boom)
    out = handle_request(
        _req("tools/call", {"name": "summary", "arguments": {}}), ":memory:", write=False
    )
    # a tool failure is an isError *result* (the model sees it as output), not a protocol error
    assert out["result"]["isError"] is True and "wedged" in out["result"]["content"][0]["text"]


# -- the verb mapping -----------------------------------------------------------


def test_command_from_tool_call_maps_args_flags_and_the_actor():
    cmd = command_from_tool_call("probe", {"target": "prod", "flags": ["verbose", "deep"]})
    assert cmd == Command(PROBE, "mcp", "prod", flags=frozenset({"verbose", "deep"}))
    # a two-arg verb fills argument + argument2
    send = command_from_tool_call("send", {"fingerprint": "a1b2", "surface": "slack"})
    assert send == Command("send", "mcp", "a1b2", argument2="slack")
    # an unknown verb is dropped (never dispatched)
    assert command_from_tool_call("rm-rf", {}) is None


def test_stdio_messages_serialize_as_one_json_line_each():
    # the stdio transport is newline-delimited JSON; a response must round-trip and carry no newline
    out = handle_request(_req("initialize", {}), ":memory:", write=False)
    line = json.dumps(out)
    assert "\n" not in line and json.loads(line)["id"] == 1


def test_add_check_tool_carries_the_schema_and_accepts_a_structured_object():
    # the agent can't author a check it can't see the shape of -> the tool must expose the schema
    tool = next(t for t in mcp_tools(write=True) if t["name"] == "add-check")
    check_arg = tool["inputSchema"]["properties"]["check"]
    assert check_arg["type"] == "object"  # a structured object, not an opaque string
    assert (
        "kubectl-log" in check_arg["description"] and "ansible-service" in check_arg["description"]
    )
    assert "postfix-routing" in check_arg["description"]  # a worked example, inline
    # the agent fills `check` as an object -> serialized to a JSON arg for the handler
    obj = {
        "name": "squid-up",
        "read": {"kind": "ansible-service", "selector": "proxies", "service": "squid"},
        "when": {"expect": "active"},
        "emit": {"severity": "high", "title": "squid down"},
    }
    cmd = command_from_tool_call("add-check", {"check": obj})
    assert cmd is not None and json.loads(cmd.argument)["name"] == "squid-up"
    # a JSON string still works (backward compatible)
    cmd2 = command_from_tool_call("add-check", {"check": json.dumps(obj)})
    assert cmd2 is not None and json.loads(cmd2.argument)["name"] == "squid-up"


# -- resources: state an agent can pull into context ----------------------------


def _db_with_findings(tmp_path):
    from datetime import UTC, datetime

    db = str(tmp_path / "s.db")
    with StateStore(db) as store:
        store.record(
            {"a" * 64: ("high", "web is CrashLoopBackOff")},
            datetime(2026, 6, 5, tzinfo=UTC),
            evidence={"a" * 64: {"namespace": "demo", "last_log": "OOMKilled"}},
        )
    return db


def test_resources_list_includes_summary_findings_and_one_per_open_finding(tmp_path):
    db = _db_with_findings(tmp_path)
    out = handle_request(_req("resources/list"), db, write=False)
    uris = {r["uri"] for r in out["result"]["resources"]}
    assert "steadystate://summary" in uris and "steadystate://findings" in uris
    assert f"steadystate://finding/{'a' * 64}" in uris  # one resource per open finding


def test_resources_read_returns_the_view_and_errors_on_an_unknown_uri(tmp_path):
    db = _db_with_findings(tmp_path)
    summary = handle_request(
        _req("resources/read", {"uri": "steadystate://summary"}), db, write=False
    )
    content = summary["result"]["contents"][0]
    assert content["uri"] == "steadystate://summary" and "impaired" in content["text"]
    # a per-finding resource reads its `show` evidence
    finding = handle_request(
        _req("resources/read", {"uri": f"steadystate://finding/{'a' * 64}"}), db, write=False
    )
    assert "OOMKilled" in finding["result"]["contents"][0]["text"]
    # an unknown URI is a clean error, never a crash
    bad = handle_request(_req("resources/read", {"uri": "steadystate://nope"}), db, write=False)
    assert bad["error"]["code"] == -32602


# -- prompts: one-click templates that carry live state -------------------------


def test_prompts_list_and_get_fill_in_live_state(tmp_path):
    db = _db_with_findings(tmp_path)
    listed = {
        p["name"]
        for p in handle_request(_req("prompts/list"), db, write=False)["result"]["prompts"]
    }
    assert {"triage", "explain-finding"} <= listed
    # triage drops the summary + findings into the message
    triage = handle_request(_req("prompts/get", {"name": "triage"}), db, write=False)["result"]
    text = triage["messages"][0]["content"]["text"]
    assert "Which should I fix first" in text and "impaired" in text
    # explain-finding takes a fingerprint argument and reads that finding
    explain = handle_request(
        _req("prompts/get", {"name": "explain-finding", "arguments": {"fingerprint": "a" * 64}}),
        db,
        write=False,
    )
    assert "OOMKilled" in explain["result"]["messages"][0]["content"]["text"]
    # an unknown prompt errors cleanly
    assert (
        handle_request(_req("prompts/get", {"name": "nope"}), db, write=False)["error"]["code"]
        == -32602
    )


def test_initialize_advertises_tools_resources_and_prompts():
    caps = handle_request(_req("initialize", {}), ":memory:", write=False)["result"]["capabilities"]
    assert set(caps) == {"tools", "resources", "prompts"}


# -- the `mcp` CLI command: --dir makes the launch cwd-proof ---------------------


def test_mcp_dir_chdirs_into_the_wall_then_serves(tmp_path, monkeypatch):
    # A client launches the server from ITS cwd, so the relative defaults miss; --dir resolves them
    # against the wall folder by chdir-ing there before serving (like running it from there).
    import os

    from typer.testing import CliRunner

    from steadystate.cli import app

    monkeypatch.delenv("STEADYSTATE_MCP_WRITE", raising=False)
    seen: dict = {}
    monkeypatch.setattr(os, "chdir", lambda p: seen.__setitem__("chdir", str(p)))
    monkeypatch.setattr(
        "steadystate.inbound.mcp.serve_stdio",
        lambda *a, **k: seen.__setitem__("serve", k),
    )
    result = CliRunner().invoke(app, ["mcp", "--dir", str(tmp_path)])
    assert result.exit_code == 0
    assert seen["chdir"] == str(tmp_path)  # chdir'd into the wall before serving
    assert seen["serve"]["write"] is False and seen["serve"]["author"] is False  # read-only default


def test_mcp_dir_rejects_a_missing_directory(monkeypatch):
    from typer.testing import CliRunner

    from steadystate.cli import app

    monkeypatch.setattr(
        "steadystate.inbound.mcp.serve_stdio",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not serve on a bad --dir")),
    )
    result = CliRunner().invoke(app, ["mcp", "--dir", "/no/such/steadystate/wall"])
    assert result.exit_code == 1 and "not a directory" in result.output


def test_mcp_label_defaults_to_the_dir_basename_and_explicit_wins(tmp_path, monkeypatch):
    import os

    from typer.testing import CliRunner

    from steadystate.cli import app

    seen: dict = {}
    monkeypatch.setattr(os, "chdir", lambda p: None)
    monkeypatch.setattr(
        "steadystate.inbound.mcp.serve_stdio",
        lambda *a, **k: seen.update(k),
    )
    wall = tmp_path / "akeyless-use1"
    wall.mkdir()
    CliRunner().invoke(app, ["mcp", "--dir", str(wall)])
    assert seen["label"] == "akeyless-use1"  # defaults to the wall folder name
    CliRunner().invoke(app, ["mcp", "--dir", str(wall), "--label", "custom"])
    assert seen["label"] == "custom"  # an explicit --label wins
    # --author grants the authoring tier without full --write
    CliRunner().invoke(app, ["mcp", "--dir", str(wall), "--author"])
    assert seen["author"] is True and seen["write"] is False


def test_mcp_refresh_probes_before_serving(monkeypatch):
    from typer.testing import CliRunner

    import steadystate.cli as climod
    from steadystate.cli import app

    calls: list = []
    monkeypatch.setattr(
        "steadystate.inbound.mcp.serve_stdio", lambda *a, **k: calls.append("served")
    )
    monkeypatch.setattr(
        climod, "run_command", lambda cmd, sp: calls.append(("probe", cmd.verb, cmd.argument))
    )
    CliRunner().invoke(app, ["mcp", "--refresh", "prod"])
    # the probe runs FIRST (freshen the store), then we serve
    assert calls == [("probe", "probe", "prod"), "served"]


def test_initialize_carries_the_wall_label_and_live_state(tmp_path):
    db = _db_with_findings(tmp_path)  # one high CrashLoopBackOff finding
    out = handle_request(_req("initialize", {}), db, write=False, label="akeyless-use1")["result"]
    assert out["serverInfo"]["title"] == "steadystate (akeyless-use1)"  # the wall self-identifies
    instr = out["instructions"]
    assert "wall: akeyless-use1" in instr
    # the live summary is embedded, so a connecting agent resumes WITHOUT a tool round-trip
    assert "impaired" in instr and "CrashLoopBackOff" in instr


def test_initialize_without_a_label_omits_the_title():
    out = handle_request(_req("initialize", {}), ":memory:", write=False)["result"]
    assert "title" not in out["serverInfo"]  # no label -> no per-wall title
