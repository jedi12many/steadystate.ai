# steadystate.ai

**Drift detection, reasoning, and guardrailed remediation for your infrastructure.**

You already declared what your infrastructure *should* be — in Terraform, Ansible, Kubernetes/Rancher, ArgoCD, or docker-compose. steadystate.ai watches the gap between that **declared state** and **observed reality**, reasons about the **drift** (security/compliance packs, root-cause correlation, live-health enrichment), surfaces only what matters (console, Slack/Teams, Prometheus/Grafana), and — at the autonomy level *you* choose — brings it back to steady state, guardrailed and approvable from your phone.

It is **not** another dashboard to babysit. Steady state is silence; you only hear from it when something has drifted in a way worth your attention.

> **Status:** the full loop works — **detect → reason → surface → suggest → approve → act**, up to `--autonomy auto` self-healing — across six sources and three clouds. Approvals come back through a provider-agnostic inbound seam (Slack and Discord). A Teams inbound adapter and a remediation audit log are the next increments.

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

No agent to install, no dashboard to learn. Point it at your IaC. Run `steadystate catalog` for a live overview of every plugin and command this build offers (`catalog --html` writes a browsable page).

## Sources — declared state in (`--source`)

`terraform` · `ansible` · `kubernetes` · `rancher` (Fleet) · `argocd` · `docker-compose`. Each rides the tool's own machine-readable output (never raw-file parsing) and declares its read-only **observe** commands vs its **potentially destructive** ones — `steadystate commands` documents both. Adding a source is a one-line registry entry.

## Domains — what drift *means* (plugins)

- **Security packs (AWS · GCP · Azure):** raise severity only for *positively recognized* exposure-increasing drift, mapped to ATT&CK — open `0.0.0.0/0` ingress → **T1190**, public bucket / relaxed storage → **T1530**, broad IAM/role → **T1098**. Honest framing: config-exposure → technique, *not* behavioral detection.
- **Docker CIS compliance:** a standing-policy baseline (privileged, host net/pid, capabilities, image pinning, …), not just drift-scoring.
- **Kubernetes Pod Security (`security-k8s`):** a standing baseline over declared manifests — privileged → **T1611**, host namespaces, added capabilities (host-escape-grade like `SYS_ADMIN` → HIGH), hostPath mounts, runAsNonRoot — mapped to CIS Kubernetes 5.2 + ATT&CK.

## Surfaces — out (`--to`)

`console` · `slack` · `teams` · `discord` (alerts) · `prometheus` (Pushgateway metrics, incl. LLM cost) · `grafana` (annotations). An unconfigured surface says so once and skips — it never pretends it delivered.

## Enrichment — live health in

Cross-reference each alert against live operational state — a drift on a resource that's **failing right now** pages louder (severity bumped), correlating the symptom to the config change:

- `--enrich prometheus` — a PromQL query you supply returns series only when the resource is unhealthy.
- `--enrich kubectl` — for a Kubernetes drift, reads pod health (CrashLoopBackOff, restarts, the worst pod's last log line) so you see *"crashlooping since the image drifted,"* not just *"image drifted."* Same `kubectl` access the source uses.
- `--enrich docker` — for a docker-compose drift, reads container health (restarting / exited non-zero / failing healthcheck + the last log line) via `docker ps` on the compose-service label.

A flaky/absent backend degrades to a no-op — enrichment never breaks a scan.

## Observe — malfunction, not just drift (`--observe`)

Steady state means your system is running **as declared *and* healthy**. So a resource can leave it two ways: by **drifting** (config diverged) or by **malfunctioning** (config is fine, but it's failing). `--observe` surfaces the second kind — a first-class **Symptom**, even with *no drift*:

```
scan ./manifests --source k8s --observe kubectl --label prod-k8s
```

- A declared workload whose pods are `CrashLoopBackOff` / restarting / failing → a HIGH Symptom, even if its config never drifted.
- **The headline — diagnosis:** if that resource *also* drifted, the Symptom and the Drift fold into **one** root-caused alert — *"web is failing — likely root cause: image drift,"* recommending the drift's fix. The correlation no log monitor makes.

It stays true to the thesis, not a monitor: Symptoms are scoped to **your declared resources**, and detection is **rented** (it reads the verdict `kubectl` already computes — no metrics stored, no logs scraped). Degrades to a no-op with no cluster.

## Autonomy — observe → suggest → auto

A human-set level; the deterministic guardrails are the floor under *all* of it.

- `--autonomy observe` (default) — alert only.
- `--autonomy suggest` — record an eligible remediation per drift; approve/decline it later:
  - **from the terminal:** `steadystate pending` → `steadystate approve <fingerprint>` / `decline <fingerprint>`.
  - **from chat:** run `steadystate listen --from <channel>` and point your chat app's interactivity URL at it, then approve from your phone — the same gated remediation runs. **Slack:** tap the Approve/Decline button on the alert (HMAC-verified). **Teams:** @mention an Outgoing Webhook, `@steadystate approve <fingerprint>` (HMAC-verified — see [deploy/teams/](./deploy/teams/)). **Discord:** type `/steadystate approve <fingerprint>` (Ed25519-verified; needs `pip install steadystate[discord]` + a Discord app — see [deploy/discord/](./deploy/discord/)).
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
