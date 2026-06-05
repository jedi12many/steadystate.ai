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
        )
    out = handle_request(_req("tools/call", {"name": "summary", "arguments": {}}), db, write=False)
    result = out["result"]
    assert result["isError"] is False and "open finding" in result["content"][0]["text"]


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
