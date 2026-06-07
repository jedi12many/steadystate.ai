# steadystate.ai

**The operational substrate for IT-Ops — whether a human or an agent drives it.** steadystate
watches your *deployed* infrastructure (live, and in CI), tells you whether it's actually
**working**, carries your team's **runbook**, and **closes the loop** — but only ever within a
**bound you commit**. A deterministic, stdlib-only core; an optional LLM that advises and proposes but
never decides.

The job isn't "find drift." It's the two things an operator — or an agent acting as one — actually
needs: **grounded truth** (what's declared, what's observed, *is it working*, what changed) and a
**governed way to act** (a vetted catalog, an impact×reversibility bound, approval, an immutable
audit). Rent your monitoring for the metrics; steadystate is the layer that knows your *desired*
state and can safely return you to it.

## Two postures, one core

steadystate runs in two shapes that share the same deterministic engine and the same committed
runbook:

| | **Live watcher** | **Repo-native (GitOps)** |
|---|---|---|
| Runs | a long-running server/CLI next to a deployment | **stateless, in CI**, inside the IaC repo |
| Holds | creds, a kubeconfig, a state db | **nothing** but the repo + a token |
| Acts by | guardrailed remediation on live infra (when you grant it) | **opening a PR / an issue** — a human merges |
| Driven by | you, or an agent over **MCP** | one CI line: `steadystate ci` |

Post-deploy and pre-deploy, the *same* tool. The PR-bot posture is the safest actuator there is — it
has **zero infra access**; its only power is a proposal you review. See
[`docs/repo-native-posture.md`](./docs/repo-native-posture.md).

## Is it *working*? — the verdict, function-first

Running ≠ working. steadystate leads with the question an operator actually asks — **is it
working?** — and answers `WORKING | DEGRADED | DOWN`:

- **Smoke tests** — the strongest signal is to *exercise* the service: an `http` check GETs an
  endpoint and asserts the response. A service that won't answer **is** the service being down.
- **Live malfunction (`Symptom`)** vs **drift** — a `CrashLoopBackOff` is the app *failing now*; a
  diverged config is drift. steadystate keeps them distinct, and when a failing resource *also*
  drifted, folds them into **one root-caused alert** (*"failing — likely cause: this drift"*).
- **Function-first triage** — `summary` leads with *what's impaired* (a live malfunction worth
  attention), not a wall of findings, so neither you nor an agent chases a red herring. A serious
  config drift (an opened firewall) is still **flagged for review** — never buried, never called a
  malfunction.
- **Correlation + enrichment** — scoped to a workload, it correlates the smoke result, the live
  symptoms, and the drift that likely caused them, and folds in live metrics from *your* monitoring
  (Prometheus) as context. It rents the metrics; it never reimplements monitoring.

## Your runbook — author a fix once, then it's everywhere

The other half of grounded truth is *what to do about it*. A **solution** is an operator-vouched
`problem → fix` — *"for evicted pods, run this; for a hung gateway, reboot it"* — committed to
`steadystate/solutions.json`, the catalog you grow over time:

- **Authored or learned.** Write one (`add-solution`), describe it in plain English
  (`define-solution`), or let `learn` notice a fix you keep applying by hand and hand you the exact
  command to capture it. Each is **signed by an author** — the audit anchor.
- **Matched + surfaced.** When a finding matches (by category or a title regex), `show` names the
  documented fix and who vouched, a CI-opened **issue carries it**, and an agent over MCP sees the
  same — your runbook, right where the problem is.
- **Run through the gate.** A matched fix becomes a one-`approve` remediation, run as an argv (no
  shell) and audited with author + approver. Opt in to **auto-apply** (`STEADYSTATE_SOLUTION_AUTO`)
  and a *low-impact, reversible* one runs unattended — anything bigger always waits for a human.

## Act — within a bound you *commit*

Acting is gated identically everywhere — terminal, chat, agent, CI:

- **A vetted catalog** — the only commands it can run are a fixed menu of safe shapes, re-validated
  at run time against an injection-proof allow-pattern; an authored solution is *your* extension of
  that catalog, vouched and audited.
- **The bound** — every action carries an envelope (*impact* × *reversibility*). The bound is the one
  decision that should never be casual, so you **commit it** in `steadystate/config.toml`'s `[bound]`
  table — *reviewed in a PR*, not a loose env var. A lossless, tenant-scoped fix runs in bound;
  scaling to zero or deleting a node escalates to a human.
- **Approval + an immutable audit** — nothing effectful runs unseen; every approve / decline /
  auto / break-glass appends to `history`.
- **Autonomy is a switch, not a track record** — off by default, granted by you (`STEADYSTATE_*_AUTO`),
  bounded by the envelope above.

> **The LLM proposes _what_; a deterministic gate decides _whether_.** The full control model — and,
> just as honestly, *where the guarantee ends* (a shell-enabled agent's real limit is its RBAC, not
> us) — is **[LLM_SAFETY.md](./LLM_SAFETY.md)**. Ask the tool itself with `steadystate posture`.

## Drive it — terminal, chat, agents, CI

The *same* vetted command grammar, four ways in:

- **Terminal** — `steadystate health` for the working/degraded/down verdict; `summary` for the
  one-glance rollup; `findings` / `show` to inspect; `chat` for a local REPL.
- **Chat** (Slack / Teams / Discord) — signed webhooks; `@steadystate probe <target>`, approve from a
  button. With an LLM, plain English works (*"why is web crashlooping?"*) — a read-only ask runs, an
  effectful one is echoed back to confirm. Chat is a trigger, never a bypass.
- **Agents over MCP** — `steadystate mcp` runs as a Model Context Protocol server (stdio, stdlib-only)
  so Claude Code/Desktop or any agent drives the same verbs through the same guardrails. Three grant
  tiers: **read-only** (default) → **`--author`** (write checks + runbook solutions, *not* infra) →
  **`--write`** (remediate). Make it an agent's *sole* actuator — no shell, steadystate holds the
  creds — and the gate becomes a real fence (see the `contained-agent` example).
- **CI** — `steadystate ci`: stateless, deterministic, no creds; scan the IaC, gate the merge
  (non-zero on a problem), and open a PR/issue that already says how to fix it.

## Detect — the grounded truth it's built on

Everything here runs with **no model**: fully deterministic, fully testable. It rides each tool's own
machine-readable output (`terraform show -json`, `kubectl`, `helm`, …), never raw-file parsing.

- **Sources** (`--source`) — `terraform · terraform-state · ansible · kubernetes · rancher · argocd ·
  docker-compose · helm`, plus live variants. **`terraform-state`** diffs config-vs-state with
  `-refresh=false` — *no per-resource cloud refresh*, so a CI gate needs only state-bucket read, not
  broad cloud creds.
- **Drift** vs **malfunction** (`--probe`) — config diverged vs failing-right-now, folded when both.
- **Custom checks** — declare what *healthy* means for **your** app (*is postfix routing mail? is
  squid up?*) as a vetted, read-only rule that emits a finding and **never runs code**; author by
  talking (`define-check`) or let an agent fill the schema (`add-check`).
- **Domain packs + live compliance** — security (AWS · GCP · Azure → ATT&CK), Docker CIS, k8s Pod
  Security; a CIS/STIG live-posture scan, honest about what's checkable live.
- **Surfaces** (`--to`) — `console · slack · teams · discord · github · servicenow · pagerduty ·
  prometheus · grafana · webhook`. **`github`** opens an issue *when sure* (deduped by fingerprint,
  auto-closed when it clears, and carrying the matched runbook fix); an unconfigured surface says so
  and skips.
- **Silos** — name your deployments (`silo add`, `--silo <name>` works like `git -C`) so a laptop
  drives deployment 1, 2, 3 — each its own db + targets + kubeconfig — without collision.
- **Extensible** — sources, packs, surfaces, probes, metric adapters are entry-point plugins; a
  third-party package adds one without a fork. Self-describing: `catalog` / `commands`.

## Config as code

The same convention all the way down: **committed beside your IaC, reviewed in PRs**.

```
your-iac-repo/
├── main.tf, ...
├── steadystate/                  # COMMITTED intent
│   ├── config.toml               # [defaults] source/path · [bound] the envelope · [ci] the gate
│   ├── solutions.json            # your runbook (problem → fix)
│   └── checks.json               # what "healthy" means for your app
└── .steadystate/                 # gitignored ephemeral state (state.db, patches)
```

Precedence is 12-factor and non-breaking: **flag > env var > config > built-in default**. Every
variable is in **[CONFIG.md](./CONFIG.md)**; `steadystate doctor` shows what's set and each dial's
live value.

## The optional LLM — advises, never decides

An LLM adds the plain-language *"why this matters"*, groups events by root cause, answers questions
in chat, drafts a check/solution from your words, and — where you grant it — *proposes* a remediation
or *drives* the tool as an agent. But detection, scoring, correlation-fallback, and the apply
decision stay deterministic, and a proposed action runs only if the gate authorizes it.

- **Providers** — Anthropic (`ANTHROPIC_API_KEY`) or any OpenAI-compatible endpoint.
- **Kill switch + egress gate** — `--no-llm` makes zero calls; `--confirm-llm` shows the exact prompt
  + destination and asks before anything is sent (decline → degrades to deterministic).
- **Cost** — every scan prints `LLM: N calls · ~$X`; `steadystate cost` rolls it up; surface
  `steadystate_llm_cost_usd_total` to Prometheus.

## Honest about what it is

The pieces aren't all novel — CI drift detection exists (Spacelift, env0, Terraform Cloud, driftctl)
and IaC PR-bots exist (Atlantis). What's different is the **combination**: a committed, *matched
runbook* (your problem→fix knowledge, not just a diff); a **function-first verdict** with the bound
(is it *working*, and is this *safe* to auto-fix?); **one substrate across both postures** sharing
that runbook; and the PR-bot as a *deliberately* zero-access actuator. A deployment model and a
coherence, more than a single unique feature — and the lowest-friction front door to all of it.

## Pointers

- **[CONFIG.md](./CONFIG.md)** — every variable + the committed `config.toml`.
- **[LLM_SAFETY.md](./LLM_SAFETY.md)** — the control model, and where the guarantee ends.
- **[docs/repo-native-posture.md](./docs/repo-native-posture.md)** — the GitOps posture, end to end.
- **[ARCHITECTURE.md](./ARCHITECTURE.md)** — the state model, the seams, build-vs-rent.
- **[examples/](./examples/)** — worked scenarios: repo-native CI, custom checks, the runbook, a
  contained agent, brokered creds, fleet health, an MCP-driven wall.
- **[SECURITY.md](./SECURITY.md)** — scope + how to report a vulnerability.

## Built with

Python, stdlib-only at the core (HTTP/LLM via `urllib`; `typer` + `rich` for the CLI). Ship via `pip`
or the container image. Apache-2.0 — see [LICENSE](./LICENSE).
