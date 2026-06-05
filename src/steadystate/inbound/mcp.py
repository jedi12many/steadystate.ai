"""steadystate as an MCP (Model Context Protocol) server -- so Claude Code/Desktop, or any agent,
can drive the vetted command grammar directly: read findings, summarize the fleet, and (with the
write grant) propose/run remediations *through the same guardrails* a human does.

This is a third inbound transport, parallel to the chat webhook adapters (server.py) and the local
REPL: where they take a typed/clicked/spoken command, this speaks **JSON-RPC 2.0 over stdio** (the
standard MCP local transport -- newline-delimited messages, the client launches us as a subprocess).
It is a thin shell over the same two seams the rest of the inbound layer uses -- ``tool_schema()``
(the verbs an agent may call, with their effect tags) and ``run_command()`` (the guardrailed
dispatch) -- so an agent can NEVER do anything a chat user couldn't: an effectful verb still flows
through the bound + catalog + audit, and the agent drives *what*, the gate decides *whether*.

Safe by default: only **read-only** verbs are exposed unless the operator grants ``write`` (the same
"autonomy is a switch" philosophy as the decider/reflex grants). With the grant, effectful verbs are
exposed too -- annotated so an MCP client confirms a destructive call with the human -- but each one
still runs the guardrails. Stdlib-only: no MCP SDK, just the small JSON-RPC surface a tools server
needs (initialize / tools/list / tools/call / ping).
"""

from __future__ import annotations

import json
import sys
from typing import Any

from .. import __version__
from .base import COMMANDS, PROBE, Command, tool_schema
from .server import run_command

# The MCP protocol revision we implement. We echo the client's requested version when it sends one
# (best-effort forward-compatibility), falling back to this.
_PROTOCOL_VERSION = "2025-06-18"
_MCP_ACTOR = "mcp"  # who the audit log credits an MCP-driven action to

# An effect tag (from tool_schema) -> MCP tool annotations: the hints a client uses to decide
# whether to auto-run a call or confirm it with the human. read-only is safe; the rest change
# state, and a guardrailed-write touches real infra (destructive hint), so a client should confirm.
_ANNOTATIONS: dict[str, dict[str, bool]] = {
    "read-only": {"readOnlyHint": True},
    "state-write": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True},
    "guardrailed-write": {"readOnlyHint": False, "destructiveHint": True},
    "external-send": {"readOnlyHint": False, "destructiveHint": False},
}


def _input_schema(tool: dict[str, Any]) -> dict[str, Any]:
    """A JSON Schema for one tool's arguments, derived from its ``tool_schema`` entry: each declared
    arg is a string property (required ones marked), plus ``flags`` (an enum array) for probe."""
    properties: dict[str, Any] = {arg["name"]: {"type": "string"} for arg in tool["args"]}
    required = [arg["name"] for arg in tool["args"] if arg["required"]]
    if "flags" in tool:  # probe's modifier flags
        properties["flags"] = {"type": "array", "items": {"type": "string", "enum": tool["flags"]}}
    schema: dict[str, Any] = {"type": "object", "properties": properties}
    if required:
        schema["required"] = required
    return schema


def mcp_tools(*, write: bool) -> list[dict[str, Any]]:
    """The vetted verbs as MCP tool definitions, built from the same ``tool_schema`` the chat
    listener dispatches (so it can never drift). Only **read-only** verbs unless ``write`` -- then
    the effectful verbs are exposed too, each annotated so a client confirms a destructive call."""
    tools: list[dict[str, Any]] = []
    for tool in tool_schema()["tools"]:
        effect = tool["effect"]
        if effect != "read-only" and not write:
            continue  # effectful verbs need the explicit write grant
        tools.append(
            {
                "name": tool["name"],
                "description": tool["summary"],
                "inputSchema": _input_schema(tool),
                "annotations": {"title": tool["name"], **_ANNOTATIONS.get(effect, {})},
            }
        )
    return tools


def command_from_tool_call(name: str, arguments: dict[str, Any]) -> Command | None:
    """Map an MCP ``tools/call`` (a verb name + an arguments object) onto a :class:`Command`, or
    None if the name isn't a vetted verb. The declared positional args fill ``argument`` /
    ``argument2``; probe's ``flags`` array fills the flag set. Actor is ``mcp`` for the audit."""
    from .base import _TOOL_ARGS

    if name not in COMMANDS:
        return None
    values = [str(arguments.get(arg_name, "")).strip() for arg_name, _ in _TOOL_ARGS[name]]
    argument = values[0] if values else ""
    argument2 = values[1] if len(values) >= 2 else ""
    flags: frozenset[str] = frozenset()
    if name == PROBE and isinstance(arguments.get("flags"), list):
        flags = frozenset(str(f) for f in arguments["flags"])
    return Command(name, _MCP_ACTOR, argument, flags=flags, argument2=argument2)


# -- JSON-RPC 2.0 plumbing ----------------------------------------------------------------------


def _result(req_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _error(req_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


def _tools_call(req_id: Any, params: dict[str, Any], state_path: str, *, write: bool) -> dict:
    """Run one tool call through ``run_command`` (the same guardrailed dispatch the chat path uses).
    A tool the grant doesn't expose, or an unknown one, is a JSON-RPC error -- never run. A command
    that runs but fails (a bad argument, a wedged store) is reported as an ``isError`` *result*, the
    MCP convention so the model sees the failure as tool output rather than a protocol fault."""
    name = params.get("name")
    arguments = params.get("arguments") or {}
    exposed = {t["name"] for t in mcp_tools(write=write)}
    if not isinstance(name, str) or name not in exposed:
        return _error(req_id, -32602, f"unknown or unavailable tool: {name!r}")
    command = command_from_tool_call(name, arguments if isinstance(arguments, dict) else {})
    if command is None:
        return _error(req_id, -32602, f"unknown or unavailable tool: {name!r}")
    try:
        output = run_command(command, state_path)
    except Exception as exc:  # never let a tool failure crash the server; report it as tool output
        return _result(
            req_id, {"content": [{"type": "text", "text": f"error: {exc}"}], "isError": True}
        )
    return _result(req_id, {"content": [{"type": "text", "text": output}], "isError": False})


def handle_request(request: Any, state_path: str, *, write: bool) -> dict[str, Any] | None:
    """Dispatch one parsed JSON-RPC message to its handler, returning the response object -- or None
    for a notification (no ``id``: ``notifications/initialized`` and friends need no reply). Pure
    given ``run_command``; the stdio loop is the only side-effecting part."""
    if not isinstance(request, dict) or "id" not in request:
        return None  # a notification (or junk) -> nothing to answer
    req_id = request.get("id")
    method = request.get("method")
    if method == "initialize":
        params = request.get("params") or {}
        version = params.get("protocolVersion") if isinstance(params, dict) else None
        return _result(
            req_id,
            {
                "protocolVersion": version if isinstance(version, str) else _PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "steadystate", "version": __version__},
                "instructions": (
                    "steadystate's infrastructure malfunction/drift detector. Use `summary` for a "
                    "one-glance status, `findings`/`show` to inspect, `probe` to scan a target. "
                    "Effectful verbs (approve/fix/run/...) are exposed only when the operator "
                    "grants write; they run through the bound + catalog guardrails and are audited."
                ),
            },
        )
    if method == "tools/list":
        return _result(req_id, {"tools": mcp_tools(write=write)})
    if method == "tools/call":
        params = request.get("params") or {}
        return _tools_call(
            req_id, params if isinstance(params, dict) else {}, state_path, write=write
        )
    if method == "ping":
        return _result(req_id, {})
    return _error(req_id, -32601, f"method not found: {method!r}")


def serve_stdio(state_path: str, *, write: bool) -> None:  # pragma: no cover -- the I/O loop
    """Run the MCP server over stdio until EOF: read newline-delimited JSON-RPC from stdin,
    dispatch, write each response as one line to stdout (kept clean -- only JSON-RPC; logs go to
    stderr)."""
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except ValueError:
            _write(_error(None, -32700, "parse error"))
            continue
        response = handle_request(request, state_path, write=write)
        if response is not None:
            _write(response)


def _write(obj: dict[str, Any]) -> None:  # pragma: no cover -- stdout I/O
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()
