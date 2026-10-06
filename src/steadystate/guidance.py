"""How an agent drives steadystate -- the one source of truth for the 'how to use the verbs'
guidance.

Shared by the ``start-here`` verb (verbs.py -- the orientation an agent can *call*) and the MCP
server's ``initialize`` instructions (inbound/mcp.py). Keeping the text here, in a neutral
dependency-free module, means those surfaces can't drift -- and it lives below both so neither has
to import the other.

The point of this text is to land on the ONE channel every MCP client reliably injects -- the tool
list -- via the ``start-here`` tool's body and description, since a client may silently drop the
server's ``initialize.instructions`` (many do). It tells the agent the verb set is complete, so it
never needs to read files/source to learn the tool.
"""

from __future__ import annotations

HOW_TO = (
    "steadystate watches deployed infrastructure: it detects drift + live malfunction, answers "
    "'is it WORKING?', carries the operator's runbook of fixes, and remediates within a committed "
    "bound.\n\n"
    "Working with the operator:\n"
    "- The verbs are a SMALL, FIXED set -- the tools listed here are ALL of them. You never need "
    "to search or guess a command, read files, or grep the source to learn how to use steadystate "
    "-- everything you need is in these tools. When the operator writes in "
    "plain English, treat it as a question to ANSWER, not a command to hunt for: reach for a tool "
    "only to GET data, otherwise just reply. Start at `summary` (the one-glance state), then "
    "`findings` / `show <fp>` to inspect, `health` for the working/degraded/down verdict, `analyze "
    "<fp>` for a crash's root cause -- and answer from that real data, never a guess.\n"
    "- COACH the operator -- there's a lot here and it's a lot to pick up, so be a guide, not a "
    "vending machine. After you answer, name the natural NEXT step AND the exact verb for it: a "
    "panic -> `analyze <fp>`; a fix they keep doing by hand -> capture it (`add-solution`); a "
    "finding that keeps recurring -> `learn`; 'are you bounding me?' -> `posture`. Surface the "
    "capability that fits the moment; don't make them already know the command exists.\n"
    "- Effectful verbs (approve / fix / run / ...) appear only with the write grant; they pass the "
    "impact x reversibility bound + the vetted catalog and are audited. Acting is ALWAYS the "
    "operator's call -- propose it WITH the verb and let them approve; never run one unasked."
)
