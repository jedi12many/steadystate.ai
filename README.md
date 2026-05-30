# steadystate.ai

**Drift detection, reasoning, and guardrailed remediation for your infrastructure.**

You already declared what your infrastructure *should* be — in Terraform, Ansible, Kubernetes/Rancher, ArgoCD, or docker-compose. steadystate.ai watches the gap between that **declared state** and **observed reality**, reasons about the **drift** (security/compliance packs, root-cause correlation, live-health enrichment), surfaces only what matters (console, Slack/Teams, Prometheus/Grafana), and — at the autonomy level *you* choose — brings it back to steady state, guardrailed and approvable from your phone.

It is **not** another dashboard to babysit. Steady state is silence; you only hear from it when something has drifted in a way worth your attention.

> **Status:** the full loop works — **detect → reason → surface → suggest → approve → act**, up to `--autonomy auto` self-healing — across six sources and three clouds. Approvals come back through a provider-agnostic inbound seam (Slack today). More chat adapters (Discord, Teams) and a remediation audit log are the next increments.

## The idea

- **Drift is the universal signal.** Security regressions, compliance violations, latent outages — they all show up first as a divergence from what you declared.
- **The reasoning is the product.** Collection, storage, dashboards, and execution already exist and are better than we'd maintain — so we rent them. We build what nobody else has: the engine that decides *which drift matters and why*, and the guardrails that let it act safely.
- **Security & compliance are plugins** (the AWS/GCP/Azure security packs, Docker CIS), not the core. The core just understands drift; domain packs teach it what drift *means*.
- **You stay in control.** Observe-only by default; raise to suggest/auto when *you* decide. Every action — from a terminal or a Slack button — passes the same deterministic guardrails.

## The loop

```
steadystate scan ./infra --source terraform --to slack --enrich prometheus --autonomy suggest
  detect    each source rides its tool's own diff (terraform plan, ansible --check, kubectl get, Fleet status)
  reason    domain packs score it · correlate by root cause · escalate if the resource is unhealthy now
  surface   only what clears the bar -> console / Slack / Teams / Prometheus / Grafana
  suggest   record a gated remediation per eligible drift
  approve   `steadystate approve <fp>`  — or tap Approve on the Slack alert (`steadystate listen`)
  act       reconcile to declared, guardrailed: eligibility -> snapshot -> apply -> verify
```

No agent to install, no dashboard to learn. Point it at your IaC.

## Sources — declared state in (`--source`)

`terraform` · `ansible` · `kubernetes` · `rancher` (Fleet) · `argocd` · `docker-compose`. Each rides the tool's own machine-readable output (never raw-file parsing) and declares its read-only **observe** commands vs its **potentially destructive** ones — `steadystate commands` documents both. Adding a source is a one-line registry entry.

## Domains — what drift *means* (plugins)

- **Security packs (AWS · GCP · Azure):** raise severity only for *positively recognized* exposure-increasing drift, mapped to ATT&CK — open `0.0.0.0/0` ingress → **T1190**, public bucket / relaxed storage → **T1530**, broad IAM/role → **T1098**. Honest framing: config-exposure → technique, *not* behavioral detection.
- **Docker CIS compliance:** a standing-policy baseline (privileged, host net/pid, capabilities, image pinning, …), not just drift-scoring.

## Surfaces — out (`--to`)

`console` · `slack` · `teams` (alerts) · `prometheus` (Pushgateway metrics, incl. LLM cost) · `grafana` (annotations). An unconfigured surface says so once and skips — it never pretends it delivered.

## Enrichment — live health in

`--enrich prometheus` cross-references each alert against a PromQL query you supply; a drift on a resource that's **failing right now** pages louder (severity bumped). A flaky Prometheus never breaks a scan.

## Autonomy — observe → suggest → auto

A human-set level; the deterministic guardrails are the floor under *all* of it.

- `--autonomy observe` (default) — alert only.
- `--autonomy suggest` — record an eligible remediation per drift; approve/decline it later:
  - **from the terminal:** `steadystate pending` → `steadystate approve <fingerprint>` / `decline <fingerprint>`.
  - **from chat:** alerts carry **Approve/Decline** buttons; run `steadystate listen --from <channel>` (Slack today — the inbound seam is provider-agnostic) and point your chat app's interactivity URL at it — tap Approve from your phone and the same gated remediation runs.
- `--autonomy auto` — apply every eligible remediation *now*, through the **same** guardrailed core a human approval uses (recorded as actor `auto`). This is the self-healing end state, and it's safe by construction: the apply gate is **deterministic** ([act/plan.py](src/steadystate/act/plan.py)), so the LLM is never in the decision, and a `REMOVED` drift is never eligible — auto reconciles *toward declared config*, it never destroys a live resource. It needs the state store for its audit trail, so `--stateless` is rejected.

Acting is per-plugin: a source with an executor (terraform, ansible) can remediate; others are observe-only by declaration.

## LLM reasoning (optional)

The drift core is **deterministic** — detection, scoring, the security/compliance packs, correlation degrade, and the executor all run with no model. An LLM only adds the plain-language *"why this matters"* and groups events by root cause.

- **Anthropic** — `pip install steadystate[llm]`, set `ANTHROPIC_API_KEY`.
- **Any OpenAI-compatible endpoint** (OpenAI, Azure OpenAI, GitHub Models, a gateway) — set `STEADYSTATE_LLM_BASE_URL` / `_API_KEY` / `_MODEL`. No extra install.

Kill switch: `--no-llm` (or `STEADYSTATE_LLM_ENABLED=false`) makes zero model calls. Spend visibility: `steadystate cost` rolls up token spend by caller over all / 24h / 60m (priced at read time, cache-aware).

## Deploying

See **[DEPLOYMENT.md](./DEPLOYMENT.md)** — the model plus three worked examples (GitHub→Terraform→Azure with Vault; Rancher/K8s in-cluster; pet Linux servers + Ansible + Prometheus), with a container image and ready-to-adapt CI workflow + Kubernetes manifests under [`deploy/`](./deploy/).

## Design

See **[ARCHITECTURE.md](./ARCHITECTURE.md)** — the canonical state model, the five plugin seams (StateSource · Domain · Surface · Executor · Correlator) plus the Enricher, the guardrail model, and the build-vs-rent decisions.

## Built with

Python, stdlib-only at the core (HTTP/LLM via `urllib`; `typer` + `rich` for the CLI). Ship via `pip` or the container image.

## License

Apache-2.0. See [LICENSE](./LICENSE).
