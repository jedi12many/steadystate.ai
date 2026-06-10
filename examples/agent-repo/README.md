# The agent repo — one repo is the Tier-1 agent's brain

This example is a complete deployment layout for running steadystate as a **Tier-1 channel agent**:
a Teams/Slack channel where anyone can ask *"how do I request a project?"* (answered from your
docs), *"are the runners ok?"* (answered from live state), get known fixes applied through the
gate, kick off your automation, and have requests fulfilled as review-gated PRs.

Everything the agent **knows** and **may do** lives in this repo, reviewed in PRs. Everything it
**learns at runtime** stays on the host. That split is the whole design:

| | Where | Why |
|---|---|---|
| **Intent** — KB docs, config, bound, targets, runbook, request recipes, workflows | committed (`steadystate/`, `silos/*/steadystate/`, `.github/workflows/`) | a human reviews what the agent knows and may do |
| **Memory** — findings, mutes, audit, cost ledger, saved RCAs | host-local, gitignored (`.steadystate/state.db`) | re-derived by the next sweep; committing it would churn, race the live listener, and publish operational history |

**Do not commit `state.db` (or convert it to text).** Losing it costs history and mutes, never
correctness — the next sweep rebuilds the picture from live infra. If audit durability matters,
back the file up like any host data.

## The layout

```
agent-repo/
├── .github/workflows/            # the agent's own automation -- `runs` reads it, `dispatch` kicks it,
│   └── redeploy-runners.yml      #   a `workflow`-kind solution targets it
├── steadystate/                  # SHARED intent (every silo points up here)
│   ├── kb/                       #   the `ask` knowledge base -- your team's docs
│   │   ├── services.md
│   │   ├── projects.md
│   │   └── runners.md
│   ├── solutions.json            #   the runbook (problem -> fix), shared across walls
│   └── requests.json             #   vetted asks -> review-gated PRs in other repos
├── silos/                        # one subfolder per WALL (deployment x region)
│   ├── prod-east/
│   │   └── steadystate/
│   │       ├── config.toml       #   this wall's bound, routing, knowledge pointer
│   │       └── targets.json      #   this wall's clusters, creds brokered per probe
│   └── prod-west/
│       └── steadystate/ ...
└── .gitignore                    # .steadystate/ -- runtime memory never enters git
```

**Do you need `silos/` at all?** Only for isolation walls. One wall = one state db + one targets
file + one credential domain + one listener. If a single credential domain covers all your
clusters, stay flat: put `config.toml` + `targets.json` at the repo root's `steadystate/`, list
every cluster in the one targets file (the sweep covers the fleet), and run one `up`. Reach for
`silos/` when deployments must not share creds or state — each silo is its own wall.

## Bring-up

```bash
pip install 'steadystate[llm]'
git clone <your agent repo> && cd agent-repo

# 1. register the walls (auto-named from the subfolders)
mkdir -p silos/prod-east/.steadystate silos/prod-west/.steadystate   # the (gitignored) memory dirs
steadystate silo discover silos/

# 2. the environment (per host; never committed -- see CONFIG.md)
export ANTHROPIC_API_KEY=...                      # the LLM (NL chat, ask synthesis, analyze)
export STEADYSTATE_GITHUB_TOKEN=...               # fine-grained: actions r/w on THIS repo (runs/dispatch
                                                  #   + workflow solutions), contents+PRs write on the
                                                  #   repos your requests.json names
export STEADYSTATE_TEAMS_SECURITY_TOKEN=...       # from the channel's Outgoing Webhook
# (no STEADYSTATE_TARGETS needed -- the committed steadystate/targets.json is the default, so
#  the CLI, the listener, and a client-spawned MCP server all find each silo's targets as-is)

# 3. one listener per wall, its own port
steadystate --silo prod-east up --from teams --port 8723 --sweep 10m
steadystate --silo prod-west up --from teams --port 8724 --sweep 10m
```

Point each channel's Outgoing Webhook (name it after your bot — `@platformbot`) at the matching
port. The first sweep runs immediately; the channel is live when the banner prints.

**From a laptop / an agent**, the same walls over MCP — `.mcp.json`:

```json
{ "mcpServers": { "prod-east": {
    "command": "steadystate",
    "args": ["mcp", "--dir", "/path/to/agent-repo/silos/prod-east"] } } }
```

## Per-silo config — sharing the KB, walling the rest

`--silo` chdirs into the wall, so every relative path in its `config.toml` resolves there. The
trick that keeps **one** knowledge base answering **every** channel: each silo points its
`[knowledge] dir` *up* at the repo-level docs (see
[silos/prod-east/steadystate/config.toml](silos/prod-east/steadystate/config.toml)):

```toml
[knowledge]
dir = "../../steadystate/kb"     # shared docs -- one KB, every wall
```

Targets are per-wall and committed ([targets.json](silos/prod-east/steadystate/targets.json)) —
they hold **pointers, never keys**: each cluster names a `kubeconfig_from` broker command
(akeyless / vault / rancher / your script) that mints a fresh, short-lived kubeconfig per probe
and deletes it after. The standing secret stays in the broker CLI's own auth. Shared runbook:
the silo config can also point `STEADYSTATE_SOLUTIONS` up, or keep per-wall fixes local.

## Keep it running

A long-running `up` per silo wants a supervisor — systemd (Linux):

```ini
[Service]
WorkingDirectory=/opt/agent-repo
EnvironmentFile=/etc/steadystate/agent.env
ExecStart=/usr/local/bin/steadystate --silo prod-east up --from teams --port 8723 --sweep 10m
Restart=on-failure
```

(or `launchd` on a Mac, with `KeepAlive`). Prefer scheduled scans over a resident sweep? Run
`up --sweep 0` for the listener alone and let cron/Actions run `steadystate --silo ... scan` on
its own cadence — same state db, same answers.

## What the channel can do, end to end

| Someone asks… | The agent… | Backed by |
|---|---|---|
| "how do I request a project?" | answers from the docs, source cited | `steadystate/kb/` (`ask`) |
| "are the runners ok?" | answers from state the sweep keeps fresh | `targets.json` + `up` |
| "why is web crashlooping?" | grounded RCA over captured + live logs | `analyze` |
| (a known failure recurs) | offers the runbook fix; a human approves | `solutions.json` (incl. `workflow` kind) |
| "did the nightly scan pass?" / "run it now" | reads / kicks this repo's workflows | `.github/workflows/` (`runs` / `dispatch`) |
| (a network problem) | tickets the right team's queue | `[servicenow]` routing in config |
| "I need outbound to example.com" | opens the review-gated PR, replies with the link | `requests.json` (`request`) |

Every effectful step is echo-to-confirm in chat, gated, and audited (`history`). Growing the
agent = PRs to this repo: a new KB doc, a new solution, a new request recipe — reviewed like code,
live on the next question.
