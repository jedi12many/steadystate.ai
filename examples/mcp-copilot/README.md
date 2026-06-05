# mcp-copilot — drive steadystate from GitHub Copilot CLI on a Mac (walled per deployment)

**The situation:** you work from a Mac and already hold a **kubeconfig per deployment** — Akeyless
gateway clusters in one folder, Squid egress in another, each with the access for *just* that thing.
You want an agent — **GitHub Copilot CLI** — to ask steadystate what's drifting or on fire in each,
and (where you allow it) to act — *without one client seeing everything at once.*

steadystate runs as an **MCP server over stdio** (`steadystate mcp`), and an MCP server is bound to
exactly one **state db + targets registry**. So the wall is the server: you give Copilot CLI **one
server per wall**, and a question or a fix in one can never reach another. This is the same
"separate `--state` + `STEADYSTATE_TARGETS` per folder" isolation the CLI uses — just exposed to an
agent.

> The wall = the blast radius you're willing to let one action loop touch at once. Split a wall per
> deployment **and** per region, and "change everything everywhere" stops being possible from any
> single client.

## 1. Install on the Mac

```sh
# Python 3.11+; pipx keeps it isolated and puts `steadystate` on your PATH.
pipx install steadystate            # (not yet on PyPI? pipx install /path/to/steadystate.ai)
kubectl version --client            # kubectl must be on PATH for live probes
steadystate doctor                  # what's configured / missing
```

## 2. Make a wall — a folder per deployment × region

One leaf folder per wall, holding only *that* wall's kubeconfig, targets, and db:

```sh
mkdir -p ~/ssai/akeyless/us-east-1 ~/ssai/squid/us-east-1
cp /path/to/akeyless-use1.kubeconfig ~/ssai/akeyless/us-east-1/kubeconfig

cd ~/ssai/akeyless/us-east-1
export KUBECONFIG=$PWD/kubeconfig
# Discover INSIDE the leaf, so the registry is scoped to just this wall's clusters:
steadystate discover --create        # -> ./.steadystate/targets.json (this wall only)
steadystate sweep --state ./state.db # populate the db: probe this wall's fleet once
```

Run `discover --create` **inside each leaf** (with only that wall's kubeconfig visible) — never over
a parent folder that can see every region, or you've merged the walls back together.

## 3. Sanity-check the server before wiring it up

`steadystate mcp` speaks JSON-RPC over stdio. Drive it by hand to confirm the wall answers — and
point it at the wall with **`--dir`** (more on that next):

```sh
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{}}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"summary","arguments":{}}}' \
  | steadystate mcp --dir ~/ssai/akeyless/us-east-1
```

You'll get back the `initialize` handshake and this wall's `summary` — exactly what Copilot sees.

## 4. Register each wall with Copilot CLI

Copilot CLI reads `~/.copilot/mcp-config.json` (top-level `mcpServers`, `"type": "local"` for a
stdio server). **The one thing to get right:** Copilot launches the server from *its own* working
directory, not your wall folder — so the cwd-relative defaults (`.steadystate/state.db`, targets,
kubeconfigs) would miss. **`--dir <wall>` fixes that with a single absolute path** (it resolves
everything as if you'd `cd`'d there). Add **one server per wall** — note the *trust differs per
wall*:

```json
{
  "mcpServers": {
    "ssai-akeyless-use1": {
      "type": "local",
      "command": "steadystate",
      "args": ["mcp", "--dir", "/Users/you/ssai/akeyless/us-east-1", "--label", "akeyless-use1"],
      "tools": ["summary", "findings", "show", "probe", "hold"]
    },
    "ssai-squid-use1": {
      "type": "local",
      "command": "steadystate",
      "args": ["mcp", "--dir", "/Users/you/ssai/squid/us-east-1", "--label", "squid-use1", "--write"],
      "tools": ["*"]
    }
  }
}
```

`--label` names each wall in the server's identity + the connect summary (defaults to the `--dir`
folder name). On connect, the server hands the agent a **live status line** — *which wall, what's
open/pending, how fresh* — so it resumes without a "let me check" round-trip; add `--refresh
<target>` to probe that summary *current* at connect (trades a few seconds of startup for freshness).

One `--dir` per wall — no `--state`/`STEADYSTATE_TARGETS`/`KUBECONFIG` to keep in sync. (If your
`targets.json` references kubeconfigs by *absolute* path, they work regardless; by *relative* path,
`--dir` resolves those too.) Prefer to pin paths explicitly instead? Pass absolute `--state` +
`STEADYSTATE_TARGETS`/`KUBECONFIG` in `env` — but then *every* path, including kubeconfigs inside
`targets.json`, must be absolute.

Three independent walls of defense, one per concern:

- **Reach** — each server's `--dir` scopes it to *only* that deployment+region's targets + kubeconfig,
  so a sweep or an agent in `ssai-akeyless-use1` can't enumerate or touch Squid, or `eu-west-1`.
- **Write grant** — `akeyless-use1` is read-only (observe/diagnose only); `squid-use1` adds `--write`,
  so an agent can run guardrailed `approve`/`fix`/`run` there — and only there.
- **Tool allowlist** — Copilot's own `"tools"` field is a second gate: `akeyless-use1` exposes only
  read verbs even if you forget the write flag.

Prefer the wizard? `/mcp add` inside Copilot CLI walks the same fields (name → type STDIO →
command/args → env → tools); `Ctrl+S` saves and the server is live immediately, no restart.

## 5. Use it — walled, in Copilot CLI

In a Copilot CLI session, ask in plain English and watch it call the right wall's tools:

```
> Using ssai-akeyless-use1, what's the worst thing in that fleet right now?
        -> calls summary / findings / show on the akeyless/us-east-1 db only

> In ssai-squid-use1, a pod is evicted — reclaim it.
        -> calls approve/fix; runs through steadystate's bound + catalog, audited as `mcp`
```

The servers are separate namespaces, so a prompt aimed at one **cannot** read or act on another.

## 6. Roll out region by region

Because each region is its own wall, change lands **one region at a time, by construction**:

1. Open `--write` (and, if you want it autonomous, `STEADYSTATE_DECIDER_AUTO=1` in that server's
   `env`) on **one** region — a canary.
2. Verify it stays steady (`summary` shows it holding).
3. *Then* open the next region's wall. The other regions physically can't be touched until you do.

| | |
|---|---|
| **Shape** | `steadystate mcp` (stdio) per wall, driven by GitHub Copilot CLI on a Mac |
| **Source** | `k8s-live` per deployment+region (the cluster's own workloads, health-checked) |
| **Secrets** | one kubeconfig per wall, in that wall's leaf folder (OS file perms are the boundary) |
| **Surface** | Copilot CLI (an MCP client) — tools to call, resources to attach, prompts like `triage` |
| **State** | one SQLite db per wall — memoryful, and the wall for findings/pendings/history |
| **Act** | per-wall: read-only by default; `--write` (+ optional `STEADYSTATE_DECIDER_AUTO`) where granted |

✅ Uses only shipped pieces — no code change. The walls are folders, dbs, and one MCP server each;
the agent drives *what*, steadystate's gate still decides *whether* (see [LLM_SAFETY.md](../../LLM_SAFETY.md)).
