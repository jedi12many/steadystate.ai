# contained-agent — the sole-actuator setup, where the gates are a *real fence*

**The situation:** you want an AI agent to operate infrastructure, but you've read
[LLM_SAFETY.md](../../LLM_SAFETY.md) (or run `steadystate posture`) and you understand the honest
boundary: **steadystate's gates only bind what flows *through* steadystate.** An agent that *also*
has a shell and your cluster credentials can run `kubectl` directly and walk right past them — the
gate's strength is a function of the agent's **tool surface**, not the gate itself.

This example removes the off-road. The agent's **only** tool is the steadystate MCP server; it has
**no shell, no filesystem, no kubectl**, and it never sees a credential — *steadystate* holds the
kubeconfig. Now its entire authority is the vetted, bounded, audited catalog. It can't bypass the
gates because it has no other road.

## 1. The principle

```
  broad-access agent                         contained agent (this example)
  ┌───────────────┐                          ┌───────────────┐
  │  shell ───────┼──▶ raw kubectl  (BYPASS)  │  (no shell)   │
  │  kubeconfig ──┼──▶ any API      (BYPASS)  │  (no creds)   │
  │  steadystate ─┼──▶ gated path             │  steadystate ─┼──▶ gated path  ← the ONLY path
  └───────────────┘                          └───────────────┘
  gate = advisory                            gate = a real fence
```

steadystate is the *sole actuator*: the one and only way this agent can touch your infrastructure.

## 2. Stand up the wall (steadystate holds the creds)

Put the deployment's kubeconfig in a silo folder; register it by name (the agent never sees the file):

```sh
mkdir -p ~/ops/gateway-use1/.steadystate
cp /path/to/gateway-use1.kubeconfig ~/ops/gateway-use1/.steadystate/kubeconfig
# point targets.json at that kubeconfig by relative path (so the silo is self-contained)
steadystate silo add gateway-use1 ~/ops/gateway-use1
```

**Scope the kubeconfig's own RBAC to least privilege** — this is the *hard* limit (see step 5).

## 3. Configure the agent with ONLY steadystate (no shell)

Use an MCP client that exposes **no shell/filesystem tool** and configure **one** server — steadystate.
**Claude Desktop** is the simplest: it has no built-in shell; its tools are exactly the MCP servers
you list. `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "steadystate-gateway-use1": {
      "command": "steadystate",
      "args": ["--silo", "gateway-use1", "mcp"]
    }
  }
}
```

That's it — no other MCP servers, no shell extension. The agent can call `summary` / `findings` /
`health` / `smoke` / `posture`, and nothing else. (Any MCP-capable client with no shell works — a
headless API harness whose only tool is this server is equally contained.)

## 4. Pick how much rope — the grant tier

The same config, with the grant that matches your trust for *this* deployment:

```json
"args": ["--silo", "gateway-use1", "mcp"]              // read-only: observe + diagnose only
"args": ["--silo", "gateway-use1", "mcp", "--author"]  // + write custom health checks (no infra)
"args": ["--silo", "gateway-use1", "mcp", "--write"]   // + approve/fix/run, gated by bound + audit
```

Even at `--write`, every effectful action still runs the **catalog + impact×reversibility bound +
approval + immutable audit** — and the agent *cannot* invent an action outside the catalog, because
it has no shell to do so. This is the posture where "autonomous within the catalog" is genuinely safe.

## 5. Scope the credentials — the real hard limit

steadystate holds the kubeconfig, but *what that kubeconfig can do* is your backstop. Give it
**least-privilege RBAC/IAM**: read-only for an observe-only silo; for a `--write` silo, only the verbs
the catalog actually performs (e.g. patch/delete on the specific resources it remediates). RBAC says
what's *possible*; steadystate makes the one path *safe and recorded*. Both, together.

## 6. Verify it's actually contained

Ask the agent — it will tell you the truth:

```
you: are you bounded by steadystate's gates here?
agent: (calls `posture`) → "THROUGH steadystate ... a real boundary. I have no shell or
        credentials of my own, so steadystate is my only path to your infrastructure."
```

| | |
|---|---|
| **Shape** | an agent whose only tool is the steadystate MCP — no shell, no creds |
| **Reach** | one silo; steadystate holds the kubeconfig (the agent never sees it) |
| **Gate** | a **real fence** — the agent's whole authority is the vetted, bounded, audited catalog |
| **Grant** | read-only → `--author` → `--write`, per your trust for this deployment |
| **Backstop** | least-privilege RBAC/IAM on steadystate's own kubeconfig |

✅ This is the deployment `posture` and [LLM_SAFETY.md](../../LLM_SAFETY.md) point at: the one where the
gates aren't guardrails on a road but a fence around the car — because you took away every other road.
Contrast with **[mcp-copilot](../mcp-copilot/)**, where the agent (Copilot CLI) *does* have a shell, so
steadystate is the *governed, audited path* and resilience/DR is the net.
