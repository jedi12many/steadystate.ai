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
from ..probe.custom import CHECK_SCHEMA_HINT
from ..state import StateStore, filter_findings
from .base import ADD_CHECK, COMMANDS, FINDINGS, PROBE, SHOW, SUMMARY, Command, tool_schema
from .server import run_command

# The MCP protocol revision we implement. We echo the client's requested version when it sends one
# (best-effort forward-compatibility), falling back to this.
_PROTOCOL_VERSION = "2025-06-18"
_MCP_ACTOR = "mcp"  # who the audit log credits an MCP-driven action to

# A worked example for the add-check tool -- an agent fills `check` from this + the schema hint.
_ADD_CHECK_EXAMPLE = (
    '{"name": "postfix-routing", "read": {"kind": "kubectl-log", "selector": "app=postfix", '
    '"namespace": "mail"}, "when": {"pattern": "status=sent", "expect": "present"}, '
    '"emit": {"severity": "high", "title": "postfix is not routing mail"}}'
)

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
    arg is a string property (required ones marked), plus ``flags`` (an enum array) for probe. The
    ``add-check`` ``check`` arg gets the full check schema inline -- an agent can't author a check
    whose shape it can't see (the cause of 'the agent can't figure out add-check')."""
    properties: dict[str, Any] = {arg["name"]: {"type": "string"} for arg in tool["args"]}
    required = [arg["name"] for arg in tool["args"] if arg["required"]]
    if "flags" in tool:  # probe's modifier flags
        properties["flags"] = {"type": "array", "items": {"type": "string", "enum": tool["flags"]}}
    if tool["name"] == ADD_CHECK and "check" in properties:
        properties["check"] = {
            "type": "object",
            "description": (
                f"A custom health check as a JSON object. {CHECK_SCHEMA_HINT}\n\n"
                f"Example: {_ADD_CHECK_EXAMPLE}"
            ),
        }
    schema: dict[str, Any] = {"type": "object", "properties": properties}
    if required:
        schema["required"] = required
    return schema


# Write verbs that only author steadystate's own observe-only config (a custom check), not infra.
# The ``author`` grant exposes these WITHOUT the full ``write`` (approve/fix/run) grant, so an agent
# can help write safe, schema-gated checks without the power to remediate your infrastructure.
_AUTHORING = frozenset({ADD_CHECK})


def mcp_tools(*, write: bool, author: bool = False) -> list[dict[str, Any]]:
    """The vetted verbs as MCP tool definitions, built from the same ``tool_schema`` the chat
    listener dispatches (so it can never drift). Three tiers: **read-only** always; ``author`` adds
    the check-authoring verbs (observe-only config, schema-gated -- not infra); ``write`` adds every
    effectful verb (approve/fix/run/...). Each is annotated so a client can confirm a risky one."""
    tools: list[dict[str, Any]] = []
    for tool in tool_schema()["tools"]:
        effect = tool["effect"]
        granted = effect == "read-only" or write or (author and tool["name"] in _AUTHORING)
        if not granted:
            continue
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

    # An arg the agent fills as a structured object/array (e.g. add-check's `check`) is serialized
    # to JSON for the string-based handler; a plain value is stringified as before.
    def _as_text(value: Any) -> str:
        return json.dumps(value) if isinstance(value, dict | list) else str(value).strip()

    values = [_as_text(arguments.get(arg_name, "")) for arg_name, _ in _TOOL_ARGS[name]]
    argument = values[0] if values else ""
    argument2 = values[1] if len(values) >= 2 else ""
    flags: frozenset[str] = frozenset()
    if name == PROBE and isinstance(arguments.get("flags"), list):
        flags = frozenset(str(f) for f in arguments["flags"])
    return Command(name, _MCP_ACTOR, argument, flags=flags, argument2=argument2)


# -- resources: steadystate's state an agent can PULL into context (vs. a tool it invokes) -------
# MCP resources are read-only data the client browses/attaches as context. We expose the same
# views the read-only tools render -- so an agent can either *call* `summary` or *attach* the
# summary resource -- backed by the same guardrailed `run_command`. Per-finding resources are
# enumerated from the store, so the agent can browse open findings like files.
_FINDING_URI = "steadystate://finding/"


def mcp_resources(state_path: str) -> list[dict[str, Any]]:
    """The resources an agent can read: the fleet `summary` and `findings` list (always), plus one
    per open finding (its `show` evidence). Read-only; reads the last probe/sweep from the store."""
    resources: list[dict[str, Any]] = [
        {
            "uri": "steadystate://summary",
            "name": "summary",
            "description": "One-glance fleet status (open findings by severity, pending, posture).",
            "mimeType": "text/plain",
        },
        {
            "uri": "steadystate://findings",
            "name": "findings",
            "description": "The remembered findings (fingerprint, status, severity).",
            "mimeType": "text/plain",
        },
    ]
    from pathlib import Path

    if state_path and Path(state_path).exists():
        with StateStore(state_path) as store:
            for finding in filter_findings(store.all_findings(), ""):  # open view
                resources.append(
                    {
                        "uri": f"{_FINDING_URI}{finding.fingerprint}",
                        "name": f"finding: {finding.last_title}",
                        "description": f"{finding.last_severity} -- captured evidence (`show`).",
                        "mimeType": "text/plain",
                    }
                )
    return resources


def read_resource(uri: str, state_path: str) -> str | None:
    """The text of one resource, or None if the URI isn't one of ours. Each maps to the same
    read-only `run_command` view a chat user would see."""
    if uri == "steadystate://summary":
        return run_command(Command(SUMMARY, _MCP_ACTOR), state_path)
    if uri == "steadystate://findings":
        return run_command(Command(FINDINGS, _MCP_ACTOR), state_path)
    if uri.startswith(_FINDING_URI):
        return run_command(Command(SHOW, _MCP_ACTOR, uri[len(_FINDING_URI) :]), state_path)
    return None


# -- prompts: one-click templates that drop steadystate's state into the conversation ------------


def mcp_prompts() -> list[dict[str, Any]]:
    """Reusable prompt templates a client offers the operator -- each fills itself with live state.
    The client lists these; invoking one (`prompts/get`) returns ready-to-send messages."""
    return [
        {
            "name": "triage",
            "description": "Review steadystate's open findings and recommend what to fix first.",
            "arguments": [],
        },
        {
            "name": "explain-finding",
            "description": "Explain one finding (by fingerprint) in plain language.",
            "arguments": [
                {
                    "name": "fingerprint",
                    "description": "the finding's fingerprint",
                    "required": True,
                }
            ],
        },
    ]


def _prompt_message(text: str) -> dict[str, Any]:
    return {"role": "user", "content": {"type": "text", "text": text}}


def get_prompt(name: str, arguments: dict[str, Any], state_path: str) -> dict[str, Any] | None:
    """Render one prompt's messages, dropping the relevant live state in. None if unknown."""
    if name == "triage":
        summary = run_command(Command(SUMMARY, _MCP_ACTOR), state_path)
        findings = run_command(Command(FINDINGS, _MCP_ACTOR), state_path)
        text = (
            "Here is steadystate's current state.\n\n"
            f"Summary:\n{summary}\n\nFindings:\n{findings}\n\n"
            "Which should I fix first, and why? Be brief -- the worst one and the next step."
        )
        return {"description": "Triage the current findings", "messages": [_prompt_message(text)]}
    if name == "explain-finding":
        fingerprint = str(arguments.get("fingerprint", "")).strip()
        show = run_command(Command(SHOW, _MCP_ACTOR, fingerprint), state_path)
        text = (
            "Explain this steadystate finding in plain language -- what it is, why it matters, "
            f"and the one concrete next step:\n\n{show}"
        )
        return {"description": "Explain one finding", "messages": [_prompt_message(text)]}
    return None


# -- JSON-RPC 2.0 plumbing ----------------------------------------------------------------------


def _result(req_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _error(req_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


def _tools_call(
    req_id: Any, params: dict[str, Any], state_path: str, *, write: bool, author: bool = False
) -> dict:
    """Run one tool call through ``run_command`` (the same guardrailed dispatch the chat path uses).
    A tool the grant doesn't expose, or an unknown one, is a JSON-RPC error -- never run. A command
    that runs but fails (a bad argument, a wedged store) is reported as an ``isError`` *result*, the
    MCP convention so the model sees the failure as tool output rather than a protocol fault."""
    name = params.get("name")
    arguments = params.get("arguments") or {}
    exposed = {t["name"] for t in mcp_tools(write=write, author=author)}
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


_HOW_TO = (
    "steadystate's infrastructure malfunction/drift detector. Use `summary` for a one-glance "
    "status, `findings`/`show` to inspect, `probe` to refresh + scan a target. If `add-check` is "
    "available, you may author custom health checks (a vetted schema -- see the tool; "
    "observe-only, never code). Effectful verbs (approve/fix/run/...) are exposed only with the "
    "write grant; they run through the bound + catalog guardrails and are audited."
)


def _server_instructions(state_path: str, label: str) -> str:
    """The `initialize` instructions, made **stateful**: a header naming this wall, then the live
    summary (open findings, what's pending, how fresh the data is), then the how-to -- so an agent
    resumes already knowing the state, no tool round-trip. The summary is a cheap store read."""
    who = f"steadystate -- wall: {label}" if label else "steadystate"
    snapshot = run_command(Command(SUMMARY, _MCP_ACTOR), state_path).strip()
    header = (
        f"{who}\nCurrent state (call `summary` to refresh):\n{snapshot}\n\n" if snapshot else ""
    )
    return f"{header}{_HOW_TO}"


def handle_request(
    request: Any, state_path: str, *, write: bool, author: bool = False, label: str = ""
) -> dict[str, Any] | None:
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
        server_info: dict[str, Any] = {"name": "steadystate", "version": __version__}
        if label:  # a display title so a client can tell this wall's server from another's
            server_info["title"] = f"steadystate ({label})"
        return _result(
            req_id,
            {
                "protocolVersion": version if isinstance(version, str) else _PROTOCOL_VERSION,
                "capabilities": {
                    "tools": {"listChanged": False},
                    "resources": {"listChanged": False},
                    "prompts": {"listChanged": False},
                },
                "serverInfo": server_info,
                "instructions": _server_instructions(state_path, label),
            },
        )
    if method == "tools/list":
        return _result(req_id, {"tools": mcp_tools(write=write, author=author)})
    if method == "tools/call":
        params = request.get("params") or {}
        return _tools_call(
            req_id,
            params if isinstance(params, dict) else {},
            state_path,
            write=write,
            author=author,
        )
    if method == "resources/list":
        return _result(req_id, {"resources": mcp_resources(state_path)})
    if method == "resources/read":
        params = request.get("params") or {}
        uri = params.get("uri") if isinstance(params, dict) else None
        text = read_resource(uri, state_path) if isinstance(uri, str) else None
        if text is None:
            return _error(req_id, -32602, f"unknown resource: {uri!r}")
        return _result(req_id, {"contents": [{"uri": uri, "mimeType": "text/plain", "text": text}]})
    if method == "prompts/list":
        return _result(req_id, {"prompts": mcp_prompts()})
    if method == "prompts/get":
        params = request.get("params") or {}
        name = params.get("name") if isinstance(params, dict) else None
        args = params.get("arguments") or {} if isinstance(params, dict) else {}
        prompt = get_prompt(name, args, state_path) if isinstance(name, str) else None
        if prompt is None:
            return _error(req_id, -32602, f"unknown prompt: {name!r}")
        return _result(req_id, prompt)
    if method == "ping":
        return _result(req_id, {})
    return _error(req_id, -32601, f"method not found: {method!r}")


def serve_stdio(
    state_path: str, *, write: bool, author: bool = False, label: str = ""
) -> None:  # pragma: no cover -- I/O
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
        response = handle_request(request, state_path, write=write, author=author, label=label)
        if response is not None:
            _write(response)


def _write(obj: dict[str, Any]) -> None:  # pragma: no cover -- stdout I/O
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()
