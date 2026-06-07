# Configuration reference

Every environment variable steadystate reads, grouped by what it switches on.

steadystate **never stores a credential** — secrets come from the environment (or a gitignored
`.env`) and are consumed by already-authenticated tooling (`terraform`, `kubectl`, `helm`, …). The
**live environment wins** over an `--env-file` / `.env`.

**See what's set:** `steadystate doctor` audits the capability variables (ready / partial / off —
never printing a secret value) and lists the **runtime dials** with their live values.
`steadystate init` walks the same set and writes a gitignored `.env`.

> Most of these are optional. The core runs with **nothing set** — point it at IaC and scan. You add
> a variable to switch on a capability (an LLM, a surface, a listener) or to turn a dial.

## Targeting & state

| Variable | Default | Effect |
|---|---|---|
| `STEADYSTATE_SILOS` | `~/.steadystate/silos.json` | The **named-silo** registry (name → deployment folder). Register with `steadystate silo add <name> <dir>`, then `--silo <name>` operates in that silo (chdir, like `git -C` but by name). Holds only paths, never secrets. |
| `STEADYSTATE_TARGETS` | `.steadystate/targets.json` | The named-targets registry a scan / chat / MCP server resolves. Splitting this per folder is how you **wall** environments. |
| `STEADYSTATE_CHECKS` | `.steadystate/checks.json` | The custom-health-checks file (also `--checks`). Checks are **intent, not runtime state** — point this at a *version-controlled* file (outside the gitignored `.steadystate/`) so authored/agent-written checks are reviewed in PRs and shared, not lost as local state. |
| `STEADYSTATE_SOLUTIONS` | `.steadystate/solutions.json` | The authored **runbook** (also `--solutions`): documented `problem → fix` entries (a command / playbook / reboot), each signed by an `author`, that surface against a matching finding in `show` and can be **approved to run**. A check teaches steadystate to *see* a problem; a solution teaches it the *fix*. Intent, not state — *version-control it* so fixes are reviewed and keep their audit. (Acting on one still passes the bound + approval + audit.) |
| `STEADYSTATE_SOLUTION_AUTO` | off | **Auto-apply** a matched solution without a human — but **only** one **within the bound** (low-impact + reversible; `STEADYSTATE_BOUND` widens it). A `reboot` / anything not low-and-reversible always waits for `approve`, even on. A deliberately **separate** opt-in from drift/decider autonomy: auto-running an authored command is its own trust decision. Audited as `auto`; runs once per fingerprint (a persisting symptom never loops). |
| `KUBECONFIG` | kube default | Cluster access for `kubernetes`/`k8s-live` sources, live probes, and `verify` (standard kubectl variable). |
| *(`--state`, not an env var)* | `.steadystate/state.db` | The SQLite memory db (findings / pendings / history / spend). One per wall; pass it explicitly to isolate. |

## LLM — optional (degrades to deterministic reasoning)

| Variable | Default | Effect |
|---|---|---|
| `ANTHROPIC_API_KEY` | — | Anthropic key; enables LLM reasoning. Needs the `anthropic` SDK (`pip install 'steadystate[llm]'`). |
| `STEADYSTATE_LLM_ENABLED` | on | Kill switch — `false`/`0`/`no`/`off` disables **every** model call (analysis degrades to drift facts, correlation to deterministic). |
| `STEADYSTATE_LLM_PROVIDER` | auto | Force `anthropic` or `openai`. Auto = Anthropic if a key is present, else an OpenAI-compatible endpoint. |
| `STEADYSTATE_LLM_BASE_URL` · `STEADYSTATE_LLM_API_KEY` · `STEADYSTATE_LLM_MODEL` | — | A custom OpenAI-compatible endpoint (stdlib urllib, no SDK). |
| `OPENAI_API_KEY` · `OPENAI_BASE_URL` | — | OpenAI-compatible fallbacks. |
| `STEADYSTATE_LLM_TIMEOUT` | `30` | Per-call timeout, in seconds. |
| `STEADYSTATE_MODEL` | `claude-sonnet-4-6` | The default model. |
| `STEADYSTATE_MODEL_CHEAP` | `claude-haiku-4-5` | The cheap tier — used for routing callers (e.g. `chat-nl` intent mapping) where a small model suffices. |
| `STEADYSTATE_MODEL_<CALLER>` | — | Override the model for one caller, e.g. `STEADYSTATE_MODEL_CHAT_NL`. Wins over the tiers above. |

## Autonomy & guardrails — the dials

These are **off / closed by default** (autonomy is a switch, granted not earned). Set them **per
wall** to control blast radius.

| Variable | Default | Effect |
|---|---|---|
| `STEADYSTATE_DECIDER_AUTO` | off | Let the LLM decider **act** autonomously — still only within the bound + the vetted catalog, and audited. |
| `STEADYSTATE_REFLEX_AUTO` | off | Let reflexes act autonomously on their known-safe categories (e.g. reclaim evicted pods). |
| `STEADYSTATE_MCP_AUTHOR` | off | Expose the check-**authoring** verbs (`add-check`) over MCP **without** full write (= `mcp --author`) — an agent can write observe-only, schema-gated checks but can't `approve`/`fix`/`run` infra. The middle tier between read-only and `--write`. |
| `STEADYSTATE_MCP_WRITE` | off | Expose the **effectful** verbs over MCP (identical to `steadystate mcp --write`) — `approve`/`fix`/`run`/mute/… infra remediation, gated + audited. |
| `STEADYSTATE_BOUND` | built-in | Override the impact×reversibility **bound** (what may auto-run vs. escalate). |
| `STEADYSTATE_BREAKGLASS_USERS` | *(nobody)* | Comma list of operators allowed to issue/confirm a break-glass (out-of-bound) action. Default-closed: unset = break-glass off. |
| `STEADYSTATE_PATCH_DIR` | `.steadystate/patches` | Where remediation patch artifacts are written. |

See **[LLM_SAFETY.md](./LLM_SAFETY.md)** for how these compose into the control model.

## Detection tuning

| Variable | Default | Effect |
|---|---|---|
| `STEADYSTATE_REACHABLE_TIMEOUT` | `8s` | Per-context cluster reachability probe timeout (`0` = no cap). Raise it for tunneled/slow clusters. |
| `STEADYSTATE_RESOLVE_AFTER` | `30m` | Grace before a no-longer-seen finding is marked resolved (`0` = resolve on first absence). Absorbs flaps. |
| `STEADYSTATE_PLATFORM_NAMESPACES` | *(built-in set)* | **Additive** comma list of *your* cluster's system namespaces, added to the built-in k8s/Rancher set the platform/app classifier uses (so `summary` leads with your apps, sets the plumbing aside). You name only what's unusual; built-ins always covered. |
| `STEADYSTATE_ENRICH_QUERY` | — | The PromQL bar for `--enrich prometheus` (escalate a drift whose resource is breaching it). |
| `STEADYSTATE_METRICS_SOURCE` | `prometheus` (if `PROMETHEUS_URL` set) | Which monitoring backend `metrics` reads from — a registered metric source (`prometheus` ships; Datadog/CloudWatch/… are one registry entry away). steadystate **rents** monitoring, never reimplements it. |
| `STEADYSTATE_METRIC_QUERIES` | `.steadystate/metrics.json` | A JSON `{name: query}` map of the readings `metrics` fetches (e.g. `{"p99_latency": "histogram_quantile(0.99, …)"}`) — the agent's metric context next to steadystate's findings, also folded into `health`. A `$WORKLOAD` placeholder in a query (`…{app="$WORKLOAD"}…`) is filled when `health <workload>` scopes; queries without it stay global. |

## Surfaces — outbound, where alerts go (`--to`)

| Variable(s) | Surface |
|---|---|
| `SLACK_WEBHOOK_URL` · `TEAMS_WEBHOOK_URL` · `DISCORD_WEBHOOK_URL` | Chat |
| `STEADYSTATE_WEBHOOK_URL` | Generic JSON webhook (Opsgenie / Jira / a bus) |
| `STEADYSTATE_PAGERDUTY_ROUTING_KEY` | PagerDuty (Events API v2, deduped by fingerprint) |
| `STEADYSTATE_SERVICENOW_INSTANCE` · `_USER` · `_PASSWORD` · `_TABLE` · `_AUTOCLOSE` · `_CLOSE_CODE` | ServiceNow incidents |
| `STEADYSTATE_GITHUB_TOKEN` (or `GITHUB_TOKEN`) · `_REPO` · `_SEVERITY` · `_AUTOCLOSE` · `GITHUB_API_URL` | **GitHub issues** (`--to github`) — opened only when *sure* (a severity gate, default `high`), **one per finding** (deduped by a fingerprint marker), and **auto-closed when it clears**. Closing the loop. |
| `PROMETHEUS_URL` · `PROMETHEUS_PUSHGATEWAY_URL` | Metrics |
| `GRAFANA_URL` · `GRAFANA_TOKEN` | Dashboard annotations |

An unconfigured surface says so and skips — it never pretends it delivered.

## Listeners — inbound chat-back (`listen`)

| Variable | Effect |
|---|---|
| `SLACK_LISTEN` · `TEAMS_LISTEN` · `DISCORD_LISTEN` | Enable a provider's inbound adapter |
| `STEADYSTATE_SLACK_SIGNING_SECRET` | Slack request signature — the inbound security boundary |
| `STEADYSTATE_TEAMS_SECURITY_TOKEN` | Teams HMAC token |
| `STEADYSTATE_DISCORD_PUBLIC_KEY` | Discord Ed25519 signature verification |

The network is **not** the security boundary: every inbound request's signature is verified before
anything acts.

## Sources — connections to interrogate

| Variable(s) | Source |
|---|---|
| `ARGOCD_SERVER` · `ARGOCD_TOKEN` | Argo CD |
| `RANCHER_URL` · `RANCHER_TOKEN` | Rancher |
| `STEADYSTATE_ANSIBLE_INVENTORY` · `_PLAYBOOK` · `_FORKS` · `_TIMEOUT` | Ansible |
| `STEADYSTATE_AZURE_TENANT_ID` · `_CLIENT_ID` · `_CLIENT_SECRET` | Azure (security pack) |
| `STEADYSTATE_SENTINEL_WORKSPACE_ID` · `_QUERY` | Microsoft Sentinel enrichment |

Terraform, Helm, Kustomize, and docker-compose are driven through their own CLIs/files — no
steadystate variable needed.
