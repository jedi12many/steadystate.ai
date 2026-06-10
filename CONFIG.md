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

## The committed config — `steadystate/config.toml`

Instead of scattering `STEADYSTATE_*` env vars, commit a **`steadystate/config.toml`** beside your
IaC (version-controlled, reviewed in PRs — the same convention as `checks.json` / `solutions.json`).
Precedence is 12-factor and non-breaking: **flag > env var > config > built-in default** — the file
is the *baseline*, env/flags still override per run.

```toml
[defaults]              # source/path for a bare `scan`/`ci` (the repo IS the wall)
source = "terraform-state"
path   = "."

[bound]                 # the autonomy envelope — reviewed in a PR, not a loose env var
self_healing = "service"    # highest blast radius that may run UNATTENDED, per reversibility
recoverable  = "none"       # ("none" forbids it). STEADYSTATE_BOUND overrides per run.

[ci]                    # the GitOps gate (inherits source/path from [defaults])
fail_on = "high"        # any | low | medium | high | critical | none
to      = "console"     # add "github" to open an issue; deliver = "github-pr" for a reconcile PR

[knowledge]             # where `ask` reads the team's committed docs from
dir = "steadystate/kb"  # the default; STEADYSTATE_KB overrides per run

[servicenow]                      # ticket ROUTING -- the right team gets the incident
assignment_group = "platform-ops" # the default queue (optional; STEADYSTATE_SERVICENOW_GROUP overrides)

[[servicenow.route]]              # first match wins, top-down (matched like solutions)
for = "NetworkUnreachable"        # exact finding category / check name -> the network team
group = "network-ops"

[[servicenow.route]]
match = "dns|gateway|proxy"       # OR a title regex
group = "network-ops"
```

`STEADYSTATE_CONFIG` points elsewhere; it's read CWD-relative, so `--silo` gets per-silo config.

## Targeting & state

| Variable | Default | Effect |
|---|---|---|
| `STEADYSTATE_SILOS` | `~/.steadystate/silos.json` | The **named-silo** registry (name → deployment folder). Register with `steadystate silo add <name> <dir>`, then `--silo <name>` operates in that silo (chdir, like `git -C` but by name). Holds only paths, never secrets. |
| `STEADYSTATE_TARGETS` | `.steadystate/targets.json` | The named-targets registry a scan / chat / MCP server resolves. Splitting this per folder is how you **wall** environments. A target may set **`kubeconfig_from`** — a broker command (e.g. `akeyless get-secret-value …`, `vault kv get …`) whose stdout is a **fresh kubeconfig, minted at probe time** and deleted when the probe finishes — so a long-running `up`/`mcp` never holds an expired or standing credential. Argv, no shell; fail-closed; see [examples/brokered-creds](./examples/brokered-creds/). |
| `STEADYSTATE_BROKER_TIMEOUT` | `30` | Seconds a `kubeconfig_from` broker command may take before the probe fails closed. |
| `STEADYSTATE_CHECKS` | `steadystate/checks.json` | The custom-health-checks file (also `--checks`). Checks are **intent, not runtime state**, so the default is the **committed** `steadystate/` (undotted) — reviewed in PRs, travels with the IaC — falling back to the legacy gitignored `.steadystate/checks.json` if a repo already has one. A fresh check lands in the committed location. |
| `STEADYSTATE_SOLUTIONS` | `steadystate/solutions.json` | The authored **runbook** (also `--solutions`), defaulting to the **committed** `steadystate/` (undotted) like checks (legacy `.steadystate/` still read): documented `problem → fix` entries (a command / playbook / reboot), each signed by an `author`, that surface against a matching finding in `show` and can be **approved to run**. A check teaches steadystate to *see* a problem; a solution teaches it the *fix*. Intent, not state — *version-control it* so fixes are reviewed and keep their audit. (Acting on one still passes the bound + approval + audit.) |
| `STEADYSTATE_SOLUTION_AUTO` | off | Opt-in to auto-apply a matched solution without a human. **Capped (issue #253):** an open `command`/`playbook` is **never** auto-applied on its *self-declared* bound — its `run` has no allow-pattern and the declared impact/reversibility is the author's word, so it always waits for `approve`. A safe unattended path returns only for a *vouched* solution (committed to `main`, or SSO-vouched in chat). A deliberately **separate** opt-in from drift/decider autonomy. Audited as `auto`; runs once per fingerprint. |
| `STEADYSTATE_KB` | `steadystate/kb` | The committed **knowledge base** folder `ask` answers from (also `[knowledge] dir` in config.toml): the team's own markdown -- services offered, how-tos, onboarding -- committed beside the IaC and reviewed in PRs like checks/solutions. Retrieval is deterministic (keyword scoring over heading-delimited sections); the model only synthesizes from the retrieved sections, citing the file. See [docs/knowledge-base.md](./docs/knowledge-base.md). |
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
| `STEADYSTATE_NO_SAFETY_NET` | off | **The operator's risk dial — you own the consequences.** Lifts the #253 *solution* trust gates: a `proposed` **draft** becomes offerable, and an open `command`/`playbook` becomes auto-eligible (still within the bound). Off by default; deliberately loud; surfaced in `posture`; every action it permits is audited `[no-safety-net]`. The deterministic catalog allow-pattern still governs catalog actions — this only affects authored solutions. |
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
| `STEADYSTATE_SERVICENOW_INSTANCE` · `_USER` · `_PASSWORD` · `_TABLE` · `_AUTOCLOSE` · `_CLOSE_CODE` · `_GROUP` | ServiceNow incidents — deduped by fingerprint, auto-resolved when the finding clears, and **routed to the right team's queue** via the committed `[servicenow]` routing map (category/title → `assignment_group`; `_GROUP` sets/overrides the default). |
| `STEADYSTATE_GITHUB_TOKEN` (or `GITHUB_TOKEN`) · `_REPO` · `_SEVERITY` · `_AUTOCLOSE` · `GITHUB_API_URL` | **GitHub issues** (`--to github`) — opened only when *sure* (a severity gate, default `high`), **one per finding** (deduped by a fingerprint marker), and **auto-closed when it clears**. Closing the loop. The same token also powers the **`workflow` solution kind** (a runbook fix that dispatches a `workflow_dispatch` — add `actions:write`). |
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
