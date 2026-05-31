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

steadystate scan ./infra --source terraform                # drift scan
steadystate scan ./manifests --source k8s --probe auto     # drift + live health
steadystate init        # interactive setup wizard -> writes a gitignored .env
steadystate doctor      # what's configured, what's missing
steadystate catalog     # every source, pack, surface + command this build offers
```

No agent, no dashboard — point it at your IaC and run it in CI or as a scheduled job.

## What it does — the deterministic core

Everything here runs with **no model**: fully deterministic, fully testable.

- **Sources** (`--source`) — `terraform · ansible · kubernetes · rancher · argocd · docker-compose · helm`. Each rides the tool's own machine-readable output, never raw-file parsing.
- **Drift** — reconcile declared vs observed, score, and surface only what clears the bar.
- **Malfunction** (`--probe kubectl|docker|argocd`) — read the live health verdict the platform already computes into a first-class **Symptom**, even with no drift. If that resource *also* drifted, the Symptom and Drift fold into **one root-caused alert** (*"failing — likely cause: this drift"*).
- **Domain packs** — security (AWS · GCP · Azure, mapped to ATT&CK), Docker CIS, Kubernetes Pod Security. Severity rises only for *recognized* exposure; compliance baselines flag standing violations, not just drift.
- **Enrichment** (`--enrich prometheus`) — a drift on a resource breaching a PromQL bar *right now* pages louder.
- **Surfaces** (`--to`) — `console · slack · teams · discord · prometheus · grafana · webhook · pagerduty`. **`webhook`** POSTs each alert as JSON to any endpoint (Opsgenie/Jira/ServiceNow/a bus); **`pagerduty`** opens an incident per alert (Events API v2, deduped by fingerprint) — so a drift breaching a PromQL bar *right now* can page, not just post. An unconfigured surface says so and skips; it never pretends it delivered.
- **Guardrailed remediation** (`--autonomy observe|suggest|propose|auto`) — apply-eligibility → snapshot → verify, with **advisory revert** guidance (Terraform/Ansible aren't transactional, so rollback is steps to run, not an automatic undo). Approve from the terminal or a chat button (Slack/Teams/Discord). A `REMOVED` drift is never auto-eligible, so it reconciles *toward* declared config and never destroys. **Applying is per-source: only `terraform` and `ansible` have executors** — the other five are *detect-only* (drift is surfaced, not applied), and each alert is tagged **`can apply`** vs **`manual`** so you know which is which.
- **Remediation as a code change** (`--autonomy propose --deliver`) — instead of a live apply, emit the fix as a reviewable **patch** you merge. The patch is computed **deterministically** (the model never authors it). The first case is *adopt*: a resource that's live but not in Terraform becomes an additive block + an `import {}` block, so applying imports it into state — **nothing is created or destroyed** (the safe inverse of the destroy a `REMOVED` drift would otherwise require). `--deliver patch-file` (default) writes a `.patch` with **no credentials** — ideal where automation can't authenticate as a person (e.g. GitHub EMU); branch/PR delivery slots behind the same seam.
- **Extensible** — sources, packs, surfaces, and probes are plugins; a third-party package adds one via an entry point, no fork.

Self-describing: `steadystate catalog` and `steadystate commands` print exactly what this build can do and run.

## LLM reasoning — optional add-on, with safety + cost controls

An LLM adds only the plain-language **"why this matters"** and groups events by root cause. Detection, scoring, the packs, the correlation fallback, and the apply decision are all deterministic — **the model is never in a decision that changes your infrastructure.**

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

See **[DEPLOYMENT.md](./DEPLOYMENT.md)** — the model plus worked examples (in CI, an in-cluster CronJob, and a persistent chat listener), with a container image and ready-to-adapt manifests under [`deploy/`](./deploy/).

## Design

See **[ARCHITECTURE.md](./ARCHITECTURE.md)** — the thesis (drift **and** malfunction), the canonical state model (Drift · PolicyFinding · Symptom), the plugin seams, the guardrail model, and the build-vs-rent decisions.

## Built with

Python, stdlib-only at the core (HTTP/LLM via `urllib`; `typer` + `rich` for the CLI). Ship via `pip` or the container image.

## Security

A tool that can change live infrastructure should hold itself to the bar it enforces. Every PR is scanned — **CodeQL** (SAST), **pip-audit** (dependency CVEs), and **bandit** (Python SAST), plus Dependabot — and every outbound request goes through one http(s)-allow-listed gate. The remediation **guardrails** (apply-eligibility → snapshot → verify, with advisory revert guidance; chat is a trigger, never a bypass) are the highest-severity area: see **[SECURITY.md](./SECURITY.md)** for what's in scope and how to report a vulnerability privately.

## License

Apache-2.0. See [LICENSE](./LICENSE).
