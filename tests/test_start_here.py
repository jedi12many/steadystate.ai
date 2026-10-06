"""`start-here`: the agent-orientation verb. The client-agnostic fix for an MCP client that drops
the server's `initialize.instructions` (many do) -- the how-to-drive guidance rides the one channel
every client injects, the tool list: a read-only verb whose DESCRIPTION tells the agent the verb set
is complete (don't read files), and whose body returns the guidance + live state."""

from __future__ import annotations

from steadystate.guidance import HOW_TO
from steadystate.inbound.base import START_HERE, Command, command_from_text, tool_schema
from steadystate.inbound.mcp import mcp_tools
from steadystate.verbs import run_command


def test_start_here_leads_the_tool_list_as_a_read_only_no_arg_verb():
    tools = tool_schema()["tools"]
    assert tools[0]["name"] == START_HERE  # leads the list -- the agent reads it first
    lead = tools[0]
    assert lead["effect"] == "read-only" and lead["args"] == []
    # the DESCRIPTION is the payload -- it lands even if the tool is never called
    summary = lead["summary"].lower()
    assert "complete" in summary and "never read files" in summary


def test_start_here_is_exposed_over_mcp_first_without_the_write_grant():
    names = [t["name"] for t in mcp_tools(write=False)]
    assert names[0] == START_HERE  # read-only -> always exposed, and first


def test_start_here_returns_the_shared_how_to_plus_state():
    out = run_command(Command(START_HERE, "mcp"), "")  # no state file -> guidance + an empty glance
    assert HOW_TO in out  # the shared text, verbatim
    assert "SMALL, FIXED set" in out and "read files" in out.lower()


def test_start_here_parses_from_chat_text():
    cmd = command_from_text("start-here", "op")
    assert cmd is not None and cmd.verb == START_HERE


def test_guidance_is_the_single_source_so_server_instructions_cant_drift():
    import steadystate.inbound.mcp as mcp

    assert mcp._HOW_TO is HOW_TO  # the MCP server's `initialize` instructions reuse the same object
