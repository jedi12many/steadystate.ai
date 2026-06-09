# copilot-ss — soft guardrails: Copilot uses steadystate, goes outside only on request

**The situation:** you drive ops from an agent (GitHub Copilot CLI / coding agent) and you want it to
*use steadystate* — to ask it what's wrong, root-cause a crash, and remediate through the gate —
rather than firing raw `kubectl` at live clusters. But you don't want a hard sandbox; Copilot still
has a shell for everything else (the repo, terraform, tests). You want a **soft** guardrail: *prefer
steadystate; ask before touching live infra outside it.*

That's the realistic middle, and it's the **best setup for dogfooding** — real agentic usage flows
*through* steadystate (which surfaces the gaps), while Copilot can still escape-hatch with your
express OK.

## The three postures

```
  unrestricted                soft guardrails (this)            hard fence (contained-agent)
  Copilot does whatever        Copilot CAN reach outside,         Copilot has NO shell;
  its creds allow;             but is INSTRUCTED to use ss        steadystate is its ONLY tool.
  the gate is its creds.       + ask before going off-road.       The gate is a real fence.
       (least safe)                  (the sweet spot)                  (most safe, least flexible)
```

A soft guardrail is an *instruction*, not a sandbox — so it relies on the agent honoring it (which
is why steadystate's [`posture`](../../LLM_SAFETY.md) is honest about it). If you need it to be
*impossible* to go around, use [`contained-agent`](../contained-agent/) instead.

## Setup

**1. Give Copilot the steadystate MCP server** (one per wall — see [`mcp-copilot`](../mcp-copilot/)
for the per-deployment walling). In Copilot's MCP config:

```jsonc
{
  "mcpServers": {
    "steadystate": {
      "command": "steadystate",
      "args": ["--silo", "gateway-use1", "mcp", "--author"]
      // read-only by default; --author lets it write checks + runbook solutions (not infra);
      // add --write only when you want it to approve/fix/run through the gate.
    }
  }
}
```

**2. Drop in the operating agreement.** [`AGENTS.md`](./AGENTS.md) is the soft guardrail itself —
the instructions that keep Copilot using steadystate and asking before it touches live infra outside
it. Put it where your Copilot reads instructions (e.g. `AGENTS.md` at the repo root, or
`.github/copilot-instructions.md`).

**3. Pick the grant.** The MCP tier *is* the floor under the soft guardrail:
- **read-only** (default) — Copilot can see everything, change nothing.
- **`--author`** — it can also write checks + runbook solutions (schema-gated, signed), still not infra.
- **`--write`** — it can approve/fix/run, through the bound + catalog + audit.

So even if the agent ignores the *soft* instruction, the *grant* caps what it can do **through
steadystate** — and the agreement governs what it does **outside** it.

## Why it dogfoods well

Every operational question Copilot answers, every fix it proposes, runs through steadystate — so you
feel exactly where the tool helps and where it's missing a verb (that's how `analyze`, `watch`, and
the `doctor` intent-diagnostics all got built). And because the guardrail makes "go outside" an
explicit, visible request, you *notice* every time steadystate couldn't do the job — which is the
most valuable signal there is.
