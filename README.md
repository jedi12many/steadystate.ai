# steadystate.ai

**Detect drift *and* malfunction in your infrastructure, reason about what matters, and remediate — guardrailed.**

You already declared what your infrastructure *should* be — in Terraform, Ansible, Kubernetes/Rancher, ArgoCD, or docker-compose. steadystate.ai watches whether your system is still in **steady state** — running *as declared* **and** *healthy* — and reasons about every departure: **drift** (config diverged from what you declared) and **malfunction** (the config's fine, but it's failing). With security/compliance packs and root-cause correlation, it surfaces only what matters (console, Slack/Teams/Discord, Prometheus/Grafana) and — at the autonomy level *you* choose — brings it back to steady state, guardrailed and approvable from your phone.

It is **not** another dashboard to babysit. Steady state is silence; you only hear from it when something has drifted in a way worth your attention.

> **Status:** the full loop works — **detect → probe → reason → surface → suggest → approve → act**, up to `--autonomy auto` self-healing — across six sources and three clouds. Both departures ship: **drift** detection and **malfunction** probing (`--probe`), correlated into one root-caused alert. Chat is two-way (Slack · Teams · Discord): approvals come back, and **`@steadystate probe <target>`** summons an on-demand scan of a named target — plus an append-only remediation audit log (`history`). Next: async deferral for long-running summons; more sources (Pulumi, Helm).

## The idea

- **A departure from steady state is the signal.** Either your config **drifted** from what you declared, or the config is fine but the system is **malfunctioning** (crashloop, OOMKill, failing healthcheck). Both are departures; reasoning about any of them is the product.
- **The reasoning is the product.** Collection, storage, dashboards, and *detection* already exist and are better than we'd maintain — so we rent them (terraform's plan, kubectl's pod status, ArgoCD's health field). We build what nobody else has: the engine that decides *which departure matters and why* — including correlating a malfunction to the drift that caused it — and the guardrails that let it act safely.
- **Security & compliance are plugins** (the AWS/GCP/Azure security packs, Docker CIS, k8s Pod Security), not the core. The core just understands departures; domain packs teach it what a config change *means*.
- **You stay in control.** Alert-only by default; raise to suggest/auto when *you* decide. Every action — from a terminal or a chat button (Slack/Teams/Discord) — passes the same deterministic guardrails.

## The loop

```
steadystate scan ./infra --source k8s --probe auto --to slack --autonomy suggest
  detect    drift — each source rides its tool's own diff (terraform plan, kubectl get, ArgoCD sync, …)
  probe     malfunction — read live health (kubectl/docker/ArgoCD) into Symptoms, even with no drift
  reason    score · correlate by root cause · diagnose a Symptom against a co-located Drift → one alert
  surface   only what clears the bar -> console / Slack / Teams / Discord / Prometheus / Grafana
  suggest   record a gated remediation per eligible drift
  approve   `steadystate approve <fp>`  — or tap Approve on the alert in chat (`steadystate listen`)
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

## Enrichment — escalate a drift by live metrics (`--enrich`)

`--enrich prometheus` cross-references each alert against a PromQL query you supply — a drift on a resource that's **failing right now** pages louder (severity bumped). A flaky/absent Prometheus degrades to a no-op; enrichment never breaks a scan.

> For pod/container health, use **`--probe`** (below). An enricher only *escalates an existing drift*; a probe *originates* the malfunction as a first-class Symptom even with no drift — and the diagnosis correlation does the escalation for you. The old `--enrich kubectl` / `--enrich docker` are **retired** in favor of `--probe kubectl` / `--probe docker`. The metric-threshold `--enrich prometheus` stays — it's a distinct signal (a PromQL bar, not a health verdict).

## Probe — malfunction, not just drift (`--probe`)

Steady state means your system is running **as declared *and* healthy**. So a resource can leave it two ways: by **drifting** (config diverged) or by **malfunctioning** (config is fine, but it's failing). `--probe` surfaces the second kind — a first-class **Symptom**, even with *no drift*:

```
scan ./manifests --source k8s --probe auto --label prod-k8s
```

`--probe auto` picks the probe matching your source; there's one wherever health is a real signal distinct from drift:

- **`kubectl`** — k8s pod health (`CrashLoopBackOff` / restarts / failed phase).
- **`docker`** — compose container health (restarting / exited non-zero / dead / failing healthcheck).
- **`argocd`** — ArgoCD's *own* per-resource `health.status` (`Degraded` / `Missing`), read from the same Application snapshot the source rides for sync. *(terraform/ansible have none — cloud health is `--enrich prometheus`'s job; Ansible has no runtime.)*

- A declared resource that's failing → a Symptom, even if its config never drifted.
- **The headline — diagnosis:** if that resource *also* drifted, the Symptom and the Drift fold into **one** root-caused alert — *"web is failing — likely root cause: drift,"* recommending the drift's fix. (With ArgoCD: `OutOfSync` *and* `Degraded` → one alert.) The correlation no log monitor makes.

It stays true to the thesis, not a monitor: Symptoms are scoped to **your declared resources**, and detection is **rented** (it reads the verdict kubectl/docker/ArgoCD already computes — no metrics stored, no logs scraped). Degrades to a no-op when the backend is unreachable.

## Autonomy — observe → suggest → auto

A human-set level; the deterministic guardrails are the floor under *all* of it.

- `--autonomy observe` (default) — alert only.
- `--autonomy suggest` — record an eligible remediation per drift; approve/decline it later:
  - **from the terminal:** `steadystate pending` → `steadystate approve <fingerprint>` / `decline <fingerprint>`. No chat provider? **`steadystate chat`** is a local REPL over the *same* command grammar (`help` · `pending` · `probe <target>` · `approve`/`decline`), and **`steadystate probe <target>`** is the one-shot, scriptable Summon — both run the exact parser + dispatch the chat adapters use, so you can drive and test the whole mechanism without Slack/Teams/Discord.
  - **from chat:** run `steadystate listen --from <channel>` and point your chat app's interactivity URL at it, then approve from your phone — the same gated remediation runs. **Slack:** tap the Approve/Decline button on the alert (HMAC-verified). **Teams:** @mention an Outgoing Webhook, `@steadystate approve <fingerprint>` (HMAC-verified — see [deploy/teams/](./deploy/teams/)). **Discord:** type `/steadystate approve <fingerprint>` (Ed25519-verified; needs `pip install steadystate[discord]` + a Discord app — see [deploy/discord/](./deploy/discord/)).
  - **discover from chat:** an operator who didn't set up the deployment doesn't have to guess. The listener answers read-only commands — **`help`** (what it accepts), **`targets`** (what `probe` can reach), **`pending`** (what's awaiting approval, with fingerprints), **`findings`** (the remembered findings + status), **`history`** (the remediation audit log) — so you can see what you can do, and what's going on, without leaving the channel. Same grammar everywhere: `@steadystate help` (Teams) · `/steadystate help` (Slack/Discord). *(Slack: add a `/steadystate` slash command in your app pointing at the same listener URL; Discord: re-run `register.py`; Teams: nothing to register.)*
  - **summon a scan from chat:** **`@steadystate probe <target>`** runs an on-demand scan of a named target and posts what's wrong back to the thread — the operator-initiated counterpart to the scheduled run ("someone just pinged me about prod"). A *target* is a name in the listener's registry (`STEADYSTATE_TARGETS`) mapping to a source + path + label, so `probe prod-k8s` knows what to reach. It's **read-only** — drift + health, reported, never a change — so chat stays a trigger, not a bypass. It **honors the mutes/snoozes you've already set** (so known-benign noise stays quiet), tells you how many it hid, and `@steadystate probe <target> unmute` shows everything for that one run. Each finding shows its **fingerprint**, so a benign one is one **`@steadystate mute <fp>`** away from quiet — silenced from chat without leaving the channel (next probe honors it). The reply also carries a one-line **spend footer** so you see what the summon cost. Commands take flags: **`probe <target> verbose`** shows the full evidence per finding (the reasoning + the `declared → observed` before/after, so you can *audit* accuracy, not just trust the title), and `probe <target> cost` adds the per-caller spend. Needs a long-lived listener ([deploy/kubernetes/listener.yaml](deploy/kubernetes/listener.yaml)), the persistent counterpart to the scheduled scan.
  - **see spend from chat:** **`@steadystate cost`** posts the LLM spend rollup (the same `steadystate cost` view), or `cost day` / `cost week` for the trend — read from the listener's shared store, so it covers the scheduled scans + approvals too.
- `--autonomy auto` — apply every eligible remediation *now*, through the **same** guardrailed core a human approval uses (recorded as actor `auto`). This is the self-healing end state, and it's safe by construction: the apply gate is **deterministic** ([act/plan.py](src/steadystate/act/plan.py)), so the LLM is never in the decision, and a `REMOVED` drift is never eligible — auto reconciles *toward declared config*, it never destroys a live resource. It needs the state store for its audit trail, so `--stateless` is rejected.

Acting is per-plugin: a source with an executor (terraform, ansible) can remediate; others are observe-only by declaration.

## LLM reasoning (optional)

The drift core is **deterministic** — detection, scoring, the security/compliance packs, correlation degrade, and the executor all run with no model. An LLM only adds the plain-language *"why this matters"* and groups events by root cause.

- **Anthropic** — `pip install steadystate[llm]`, set `ANTHROPIC_API_KEY`.
- **Any OpenAI-compatible endpoint** (OpenAI, Azure OpenAI, GitHub Models, a gateway) — set `STEADYSTATE_LLM_BASE_URL` / `_API_KEY` / `_MODEL`. No extra install.

Kill switch: `--no-llm` (or `STEADYSTATE_LLM_ENABLED=false`) makes zero model calls. Spend visibility: every scan prints a one-line **`LLM: N calls · ~$X`** footer (so a paid call never goes unseen; `--cost` breaks it down by caller). `steadystate cost` rolls up token spend by caller over all / 24h / 60m, or as a trend with **`--by day|week`** (priced at read time, cache-aware). For a richer time series, surface to **Prometheus → Grafana** (`steadystate_llm_cost_usd_total`).

## Deploying

See **[DEPLOYMENT.md](./DEPLOYMENT.md)** — the model plus three worked examples (GitHub→Terraform→Azure with Vault; Rancher/K8s in-cluster; pet Linux servers + Ansible + Prometheus), with a container image and ready-to-adapt CI workflow + Kubernetes manifests under [`deploy/`](./deploy/).

## Design

See **[ARCHITECTURE.md](./ARCHITECTURE.md)** — the evolved thesis (drift **and** malfunction), the canonical state model (Drift · PolicyFinding · Symptom), the plugin seams (StateSource · Domain · Surface + Inbound · Executor · Correlator · Probe, plus the Enricher), the guardrail model, and the build-vs-rent decisions.

## Built with

Python, stdlib-only at the core (HTTP/LLM via `urllib`; `typer` + `rich` for the CLI). Ship via `pip` or the container image.

## Security

A tool that can change live infrastructure should hold itself to the bar it enforces. The project is scanned on every PR — **CodeQL** (SAST), **pip-audit** (dependency CVEs), and **bandit** (Python SAST), plus Dependabot — and every outbound request goes through one http(s)-allow-listed gate. The remediation **guardrails** (apply-eligibility → snapshot → verify → revert; chat is a trigger, never a bypass) are the highest-severity area: see **[SECURITY.md](./SECURITY.md)** for what's in scope and how to report a vulnerability privately.

## License

Apache-2.0. See [LICENSE](./LICENSE).
