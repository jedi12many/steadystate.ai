# steadystate.ai

**Detect drift *and* malfunction in your infrastructure, reason about what matters, and remediate — guardrailed.**

You already declared what your infrastructure *should* be (Terraform, Ansible, Kubernetes/Rancher, ArgoCD, docker-compose, Helm). steadystate.ai watches whether it's still in **steady state** — running *as declared* **and** *healthy* — and reasons about every departure: **drift** (config diverged) and **malfunction** (the config's fine, but it's failing). It surfaces only what matters and, at the autonomy level *you* choose, brings it back — guardrailed and approvable from your phone.

It's **not** a dashboard to babysit. Steady state is silence; you hear from it only when something departs in a way worth your attention.

```
detect → probe → reason → surface → suggest → approve → act
```

## Quickstart

```bash
pip install steadystate            # core (stdlib-only)
pip install 'steadystate[llm]'     # + optional LLM reasoning

steadystate discover    # what can I scan *here*? (per source/probe: ready, blocked, or how)
steadystate scan ./infra --source terraform                # drift scan
steadystate scan plan.json --source k8s --probe kubectl    # drift + live health
steadystate verify ./k8s --release web                     # verify the *live* cluster vs your Git
steadystate summary     # one-glance status: what's open, pending, and on fire right now
steadystate chat        # a local REPL -- ask in plain English when an LLM is configured
steadystate mcp         # run as an MCP server -- drive it from Claude Code/Desktop or any agent
steadystate init        # interactive setup wizard -> writes a gitignored .env
steadystate doctor      # what's configured, what's missing
steadystate catalog     # every source, pack, surface + command this build offers
```

No dashboard to babysit — point it at your IaC and run it in CI or as a scheduled job; operate it from the terminal, chat (Slack/Teams/Discord), or an agent over **MCP**.

## Getting started — point it at *your* setup

Not sure which `--source` fits, or what to feed it? Start from the directory holding your IaC and let the tool tell you. The four steps escalate: **what's possible → what's actually there → register it → scan it.**

```bash
cd your-infra/

# 1. What can I scan here? Per --source and --probe: is the CLI installed, the backend
#    reachable, an input present? — and the exact command to run for each.
steadystate discover

# 2. Go live (read-only): interrogate the reachable backends and tailor the advice to what's
#    really there — your actual cluster nodes, Helm releases, compose projects, Argo apps —
#    with commands carrying your real release/namespace names.
steadystate discover --deep

# 3. Register what it found as named targets (name -> source + path), so the CLI, a scheduled
#    job, and a chat-summoned `@steadystate probe <name>` all resolve it without hand-writing
#    JSON. Named after the directory; suffixed per source when several are found. Merges, never
#    clobbers. `steadystate targets [--check]` lists and validates the registry.
steadystate discover --create        # writes .steadystate/targets.json (or $STEADYSTATE_TARGETS)

# 4. Scan — by target name (source/path/label/probe come from the registry) ...
steadystate scan --target your-infra
#    ... or spell it out with the command discover handed you:
steadystate scan . --source terraform
```

`discover` is read-only and safe to run anywhere; `--deep` only runs `get`/`list` reads and skips any backend it can't reach. Nothing here writes to your infrastructure.

## What it does — the deterministic core

Everything here runs with **no model**: fully deterministic, fully testable.

- **Sources** (`--source`) — `terraform · ansible · kubernetes · rancher · argocd · docker-compose · helm`. Each rides the tool's own machine-readable output, never raw-file parsing.
- **Drift** — reconcile declared vs observed, score, and surface only what clears the bar.
- **Malfunction** (`--probe kubectl|docker|argocd`) — read the live health verdict the platform already computes into a first-class **Symptom**, even with no drift. If that resource *also* drifted, the Symptom and Drift fold into **one root-caused alert** (*"failing — likely cause: this drift"*).
- **Verify the left** (`steadystate verify <dir>`) — render your declared Git state (a **Kustomize** overlay or a **Helm** chart, auto-detected, with the platform's own tooling) and reconcile it against the live cluster, scoped to the namespaces it touches: *in Git but not running* (ADDED), *running but drifted* (an out-of-band image/replica change → MODIFIED), *running but not in Git* (REMOVED). Coarse on purpose, so it flags real divergence — including the kind `helm upgrade` leaves in place.
- **Domain packs + live compliance** — security (AWS · GCP · Azure, mapped to ATT&CK), Docker CIS, Kubernetes Pod Security; a stacked **CIS/STIG live-posture scan** flags standing violations, not just drift, with an honest disclaimer about what's checkable from the live side.
- **Enrichment** (`--enrich`) — escalate a drift that's *also* live-dangerous right now: `prometheus` (a resource breaching a PromQL bar) or `sentinel` (a resource with an active Microsoft Sentinel incident — the SIEM is firing on it). Reads a verdict the monitor/SIEM already computed; never detects itself.
- **Surfaces** (`--to`) — `console · slack · teams · discord · prometheus · grafana · webhook · pagerduty`. **`webhook`** POSTs each alert as JSON to any endpoint (Opsgenie/Jira/ServiceNow/a bus); **`pagerduty`** opens an incident per alert (Events API v2, deduped by fingerprint) — so a drift breaching a PromQL bar *right now* can page, not just post. An unconfigured surface says so and skips; it never pretends it delivered.
- **Guardrailed remediation** (`--autonomy observe|suggest|auto`) — apply-eligibility → snapshot → verify, with **advisory revert** guidance (Terraform/Ansible aren't transactional, so rollback is steps to run, not an automatic undo). Approve from the terminal or a chat button (Slack/Teams/Discord). A `REMOVED` drift is never auto-eligible, so it reconciles *toward* declared config and never destroys. **Applying is per-source: only `terraform` and `ansible` have executors** — the other five are *detect-only* (drift is surfaced, not applied), and each alert is tagged **`can apply`** vs **`manual`** so you know which is which.
- **Two ways to fix, picked at review** — a `suggest` suggestion carries both directions where they exist: the **enforce** command `approve` would run (change reality to match config), *and* an **accept-reality patch** — a reviewable code change (change config to match reality), computed **deterministically** (the model never authors it). The first patch case is a Terraform `REMOVED` drift, where enforcing would *destroy* the resource: instead, the patch **re-adds the deleted declaration** so the destroy is averted. `steadystate pending` shows the patch; you `git apply` + merge it, or **`scan --deliver github-pr`** opens it as a PR (via the GitHub API — the Actions `GITHUB_TOKEN` works, no personal PAT) so drift flows through your normal review (CODEOWNERS/CI). The tool never applies a code change itself — auth lives only in the delivery adapter, and `--deliver patch-file` needs none, so it works even where automation can't authenticate as a person (e.g. GitHub EMU).
- **Extensible** — sources, packs, surfaces, and probes are plugins; a third-party package adds one via an entry point, no fork.

Self-describing: `steadystate catalog` and `steadystate commands` print exactly what this build can do and run.

## The homeostat — act on the known-safe, escalate the rest

For live Kubernetes malfunctions, steadystate can do more than surface — it can **maintain steady state within a bound you set**.

- **A vetted catalog** — the only commands it can ever run are a fixed menu of safe shapes (reclaim evicted pods, rollout-restart a controller, …), each re-validated at run time against a **flexible-but-injection-proof allow-pattern**: argument order can vary, but a shell metacharacter, an unknown flag, a wrong value, or a bare-pod target is rejected.
- **The bound** — every action carries an envelope (*impact* × *reversibility*). A lossless, tenant-scoped reclaim is inside the default bound; scaling to zero or deleting a node is outside it and **escalates to a human**. The gate judges the *catalog's* envelope, never a proposer's claim.
- **A decider that proposes, a gate that decides** — a deterministic `CatalogDecider` (and, optionally, an `LLMDecider`) proposes one menu action; the gate authorizes it only if it's vetted, valid, and within the bound. **Autonomy is a switch** (`STEADYSTATE_DECIDER_AUTO` / `STEADYSTATE_REFLEX_AUTO`), off by default — granted by you, never earned by a track record.

Validated on a live cluster: it reclaimed evicted pods autonomously (in bound) and **escalated** a crash-loop's scale-to-zero (out of bound) rather than running it. The full control model is **[LLM_SAFETY.md](./LLM_SAFETY.md)**.

## Operate it — terminal, chat, and agents (MCP)

Same vetted command grammar, three ways in:

- **Terminal** — `steadystate summary` for a one-glance rollup; `findings` / `show` to inspect; `chat` for a local REPL.
- **Chat** (Slack / Teams / Discord) — signed webhooks; `@steadystate probe <target>`, approve from a button. With an LLM configured, **plain English works**: ask *"why is web crashlooping?"* and get a grounded answer (or `explain <finding>`); a read-only request runs, an effectful one is echoed back for you to confirm — chat is a trigger, never a bypass.
- **Agents over MCP** — `steadystate mcp` runs as a **Model Context Protocol** server (stdio, stdlib-only, no SDK) so Claude Code/Desktop or any agent can drive the *same* verbs through the *same* guardrails: **tools** to call, **resources** to pull state into context, and **prompts** like `triage`. Read-only by default; effectful verbs need `--write` and are audited as the `mcp` actor.

## LLM reasoning — optional add-on, with safety + cost controls

An LLM adds the plain-language **"why this matters"**, groups events by root cause, answers questions in chat, and — where you grant it — **proposes** a remediation or **drives** the tool as an agent. But detection, scoring, the packs, the correlation fallback, and the apply decision stay deterministic, and a proposed or agent-driven action runs only if a deterministic gate authorizes it: **the model proposes _what_; the gate decides _whether_.** The full control model — the bound, the vetted catalog, the egress + autonomy switches, the audit trail — is **[LLM_SAFETY.md](./LLM_SAFETY.md)**.

- **Providers** — Anthropic (`ANTHROPIC_API_KEY`) or any OpenAI-compatible endpoint (`STEADYSTATE_LLM_BASE_URL` / `_API_KEY` / `_MODEL`).
- **Safety**
  - **Kill switch** — `--no-llm` (or `STEADYSTATE_LLM_ENABLED=false`) makes zero model calls.
  - **Egress gate** — `--confirm-llm` shows the exact prompt + destination and asks *before* anything is sent; decline and nothing leaves the box (the scan degrades to deterministic). A per-call data-egress review, and a hard spend gate.
  - **Honest by construction** — the model recommends the fix only, never speculating about what the tool can do; the *can-apply* verdict is computed deterministically, not by the model; no capability or config data is added to the prompt.
- **Cost**
  - Every scan prints a one-line **`LLM: N calls · ~$X`** footer (`--cost` breaks it down by caller).
  - `steadystate cost` rolls up spend by caller over all / 24h / 60m, or as a `--by day|week` trend (priced at read time, cache-aware).
  - Surface `steadystate_llm_cost_usd_total` to **Prometheus → Grafana** for a time series.

## State — stateless by default, memory with SQLite

A scan is **stateless** by default (`--stateless` forces a pure, amnesiac run). Point `--state <file.db>` at a small **SQLite** file and it becomes memoryful:

- **new / recurring / resolved** — a finding is tracked across scans, so you see what *changed*, not the same wall every run.
- **mute / snooze** — silence a known-benign finding by fingerprint; suppression is honored on future scans and chat probes.
- **pending approvals + audit log** — `--autonomy suggest` records eligible remediations to approve later, and every approve / decline / auto-apply appends to an immutable `history`.
- **LLM spend history** — token usage stored and re-priced at read time.

It's one file — mount a volume to persist it across runs; the scheduled scan and the chat listener share it.

## Deploying

See **[`examples/`](./examples/)** — worked deployment scenarios (a CI drift check, an in-cluster CronJob, a persistent chat listener, and live **fleet health** from a dir of kubeconfigs), each a short walkthrough plus the model they share. The ready-to-adapt container image and manifests they apply live under [`deploy/`](./deploy/).

## Design

See **[ARCHITECTURE.md](./ARCHITECTURE.md)** — the thesis (drift **and** malfunction), the canonical state model (Drift · PolicyFinding · Symptom), the plugin seams, the guardrail model, and the build-vs-rent decisions.

## Built with

Python, stdlib-only at the core (HTTP/LLM via `urllib`; `typer` + `rich` for the CLI). Ship via `pip` or the container image.

## Security

A tool that can change live infrastructure should hold itself to the bar it enforces. Every PR is scanned — **CodeQL** (SAST), **pip-audit** (dependency CVEs), and **bandit** (Python SAST), plus Dependabot — and every outbound request goes through one http(s)-allow-listed gate. The remediation **guardrails** (apply-eligibility → snapshot → verify, with advisory revert guidance; chat and agents are triggers, never a bypass) are the highest-severity area: see **[SECURITY.md](./SECURITY.md)** for what's in scope and how to report a vulnerability privately, and **[LLM_SAFETY.md](./LLM_SAFETY.md)** for how a model or agent is kept inside the envelope you set.

## License

Apache-2.0. See [LICENSE](./LICENSE).
