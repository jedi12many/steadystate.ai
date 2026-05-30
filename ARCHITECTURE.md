# steadystate.ai — Architecture

> **Stateful monitoring.** You declared a desired steady state (in Terraform, ArgoCD, Docker, Ansible…). steadystate.ai reconciles that declared state against observed reality, reasons about the drift, surfaces only what's actionable — and, on your say-so, helps return you to steady state, safely.

Status: **the loop is built.** Detection across six sources (terraform · ansible · kubernetes · rancher · argocd · docker-compose), security/compliance domain packs (AWS/GCP/Azure security · Docker CIS), five surfaces + Prometheus enrichment, and a guardrailed **observe → suggest → approve → act** loop (from the terminal or a Slack button) all ship today. This doc describes the design those seams realize; the roadmap (§11) tracks what's done vs next.

---

## 1. Thesis

A system in *steady state* is running **as declared** and running **healthy**: `declared == observed`, *and* the observed system is actually working. It leaves steady state two ways:

- **Drift** — declared ≠ observed *config* (someone changed the firewall; the image isn't what you pinned).
- **Malfunction** — the config is fine, but the system is *failing*: a crashloop, an OOMKill, a restart storm, an expiring cert.

Both are **departures from steady state**, and *reasoning about any departure* — which ones matter, why, and what to do — is the product. Drift is the first-class signal and where the engine began; **malfunction** is the second (the `Symptom` type, §4; shipped via `--probe`). The name was always *steadystate*, not *driftfinder*: a problem that never touched your config is still a problem with your system, and blinding ourselves to it to protect a definition would serve the definition, not the operator.

steadystate.ai is **not** a security tool that happens to read config, nor a monitor that happens to know your config. It's a **steady-state reasoning engine** — security and compliance are the first *plugins*; the core never knows what "security" is, a domain pack teaches it.

This is a deliberate, lean reframe of an earlier custom-everything system (own agent + own brain + own dashboard). The lesson learned: **only the reasoning is differentiated.** Build that; rent the rest — *including the detection of a malfunction*. The platform already knows a pod is CrashLoopBackOff; we read that verdict and reason about it (correlate it to drift, remember it, explain it, fix it), we do not re-build alerting.

## 2. Principles

1. **Build the reasoning + the guardrails. Rent everything else.** Collection, storage, dashboards, and execution already exist and are better than we want to maintain.
2. **Modular from day one.** Five plugin seams + an enricher (below). Security/compliance/cost are packs, not core.
3. **Chat-first, thin UI.** Operators live in Slack/Teams. The tool comes to them and talks back. The web UI is config + a read-only view, nothing more.
4. **Default-quiet.** Steady state = silence. We only surface *departures* (drift, policy violations, malfunction) that clear the bar. (Borrowed, hard-won, from the predecessor.)
5. **The operator is authoritative.** If a human says "that drift is intentional," we believe them and stop nagging.
6. **No action without a guardrail.** Every remediation is apply-eligibility-checked, snapshotted, verified, and reversible — whether triggered from chat or anywhere else.

## 3. The pipeline

```
DECLARED state (plugins — must be EASY)        OBSERVED state (rented)
 terraform · argocd · docker-compose            the real cloud/cluster/host, via
 ansible · helm · k8s · pulumi                   each tool's own diff where possible
        │  via each tool's OWN machine-readable      │  (terraform plan, argocd live, …)
        │  output, never raw-file parsing            │
        ▼                                            ▼
   ┌──────────────────────────────────────────────────┐
   │   Canonical State Model   (desired ⇄ observed)     │   ← the spine (§4)
   └──────────────────────────────────────────────────┘
        ▼
   Departures from steady state — the inputs the engine reasons about (one normalized shape):
     DRIFT    declared ≠ observed config        (reconciler)                         [built]
     POLICY   declared violates a baseline      (domain.evaluate — CIS/STIG)         [built]
     SYMPTOM  observed unhealthy right now       (health probes — crashloop/…)       [built §4]
        ▼
   Reasoning core  (BUILD — the IP)
     Signals → Events → Alerts (3-tier scoring) · correlate ACROSS types · honest LLM "why this matters"
        ▼
   Domain packs score it:   [security]  [compliance]  [cost]  [reliability] …  (plugins, §6)
        ▼
   Guardrailed executor  (BUILD the guardrails / rent the execution)
     apply-eligibility · snapshot→verify→revert · would-break → your CD/Ansible/terraform
        ▼
   Operator (Slack/Teams ChatOps, §7)  ·  read-only UI / Grafana  ·  API
```

## 4. The spine: a canonical State Model

Everything reduces to one model so the core stays source-agnostic:

- **Resource** — `{ kind, identity, properties, provenance, observed_at }`. `provenance` traces back to the source + the declaring file/line.
- **DeclaredState** / **ObservedState** — sets of Resources from the desired and actual sides.

The model carries one entry per *departure from steady state*. Three kinds, all reduced to the same downstream shape:

- **Drift** *(built)* — a reconciled divergence: `{ identity, change_type (added/removed/modified), declared, observed, detected_at, provenance }`.
- **PolicyFinding** *(built — Docker CIS, k8s security)* — a standing-baseline violation generated from declared inventory, *not* from drift: `{ rule_id, identity, severity, references, provenance }`.
- **Symptom** *(built — `--probe`)* — an operational malfunction of a *declared* resource, observed now: `{ identity, kind, category (CrashLoopBackOff / Restarting / Unhealthy / Exited …), severity, evidence (last log line, restart count), provenance, detected_at }`. The parallel to Drift: where Drift says *config diverged*, Symptom says *config is fine but it's failing*.

All three normalize to a **Signal** that the 3-tier scorer, the correlator, the memory store (new/recurring/resolved), the surfaces, and the act loop already handle (`Alert` already carries `drifts` + `findings`; Symptom adds `symptoms`). Adding Symptom is the **same move PolicyFinding already made** — a new input type, not a new pipeline. The payoff is **correlation across types**: a Symptom (`web` crashlooping) grouped with a co-located Drift (its image changed) becomes one root-caused Alert no monitor produces. Two boundaries keep this from becoming a monitor: Symptoms are scoped to **declared resources** (we watch *your* system's steady state, not the whole cluster), and their **detection is rented** — we read the verdict the platform already computes (kubectl pod status, docker state, a firing Prometheus alert), we don't store metrics or scrape all logs.

Conventions (learned the hard way): **stable/idempotent resource IDs** (re-ingest is a no-op, not a duplicate), **source ranking** when two sources disagree, and provenance on everything so an Alert can point at the exact line that declared a thing.

## 5. Build vs rent

| Layer | Decision | Notes |
|---|---|---|
| **Collect** | **rent** (thin plugin per source) | Use each tool's own output: `terraform show/plan -json`, ArgoCD API (it already diffs!), `docker compose config`, `ansible-inventory`. |
| **Reason** | **BUILD — the IP** | Canonical model, reconciler, 3-tier scoring (Signal/Event/Alert), correlation, honest LLM analysis. |
| **Decide/Act** | **BUILD the guardrails / rent execution** | apply-eligibility + snapshot/revert + would-break; the actual change runs via your CD/terraform/ansible. |
| **Store** | rent / embed | SQLite when standalone; otherwise the host store. |
| **Surface** | **rent** | Slack/Teams (primary), API, optional Grafana app. No custom dashboard. |

## 6. Plugin model (five seams + an enricher)

The core defines the interfaces; everything domain- or vendor-specific is a plugin, registered in a one-line registry so adding one never edits the core or the CLI.

1. **StateSource** — declared state in: `terraform · ansible · kubernetes · rancher · argocd · docker-compose` (`DRIFT_SOURCES`). Each rides its tool's own machine-readable diff and declares its **observe** (read-only, pre-approved) vs **destructive** (needs approval) commands — the per-plugin permission manifest (`steadystate commands`).
2. **Domain** — what drift *means* (`DEFAULT_DOMAINS`): the AWS/GCP/Azure security packs map exposure-increasing drift to ATT&CK techniques; the Docker CIS pack evaluates a standing-policy baseline. A pack `score`s a drift and/or `evaluate`s the declared inventory, and attaches framework `references`. **This is how security & compliance enter — as packs, not core.**
3. **Surface** — push Alerts out, and take operator input back. Outbound: `console · slack · teams · discord · prometheus · grafana` (`SURFACES`). Inbound has its own registry (`INBOUND`, mirroring `SURFACES`) over a signed HTTP listener — `listen --from <channel>` — so accepting approvals from a new chat provider is an adapter (verify/handshake/parse/respond), not a fork. Slack (HMAC, buttons), Discord (Ed25519, slash command), and Teams (HMAC, @mention command) ship; the `verify`/`handshake` split is what lets three very different signing + handshake protocols share one listener. *(Designed, §7: these adapters generalize from parsing an approval to parsing a Command — `approve | decline | probe <target> | …` — so the same listener also handles on-demand "go check now.")*
4. **Executor** — perform a guardrailed remediation, keyed by source (`EXECUTORS`): `terraform`, `ansible`. A source with no executor is observe-only by declaration.
5. **Correlator** — group Events into Alerts (`CORRELATORS`): `llm` (root cause) or `deterministic` (shared attribute); `auto` chooses by whether a provider is configured.

Plus an **Enricher** (`ENRICHERS`): an optional step that cross-references an Alert against live health (`prometheus` · `kubectl` · `docker`) and escalates a drift whose resource is failing right now — attaching the symptom (e.g. *"crashlooping since the image drifted"*).

A **health probe** (`PROBES`, `--probe`) — *shipped: `kubectl`; docker next* — the producer of `Symptom`s (§4), the operational counterpart to a StateSource. Where a StateSource reconciles declared vs observed *config* into Drift, a health probe reads the live *health* of declared resources into Symptoms (reusing the very detection the `kubectl`/`docker` enrichers already have, promoted from "escalate a drift" to "originate a Symptom"). Same access the source uses; detection rented, reasoning ours. This is the seam that lets the engine see malfunction with no drift, without becoming a monitor. **It largely subsumes the `kubectl`/`docker` enrichers:** once a Symptom is a first-class peer, a Symptom + a co-located Drift *correlate* into one root-caused Alert automatically — which is what "the enricher escalates a drift" was hand-rolling, but stronger (the symptom is evidence in the root cause, not just a severity bump). The enrichers' container-health detection graduates into the probe; `--enrich prometheus` (metric-threshold escalation, a different shape) stays.

The engine itself is **not** a plugin inside someone else's product (it's a stateful service + an embeddable library). The *integrations* are the plugins.

## 7. Operator communication (ChatOps) — first-class

The tool **lives in Slack/Teams**, not in a dashboard you must remember to open.

1. **Detect → reason → push.** Drift → an Alert (what drifted, why it matters, recommended fix) → posted to the right channel/thread. Default-quiet.
2. **Summon — probe on demand** *(designed, roadmap §11).* `@steadystate probe <target>` dispatches a scan/probe of a named target *right now*, **regardless of the schedule** — someone just pinged you about prod, so you send the on-call agent to look rather than SSH-ing in yourself. It runs the full pipeline (drift + Symptoms + correlation) and posts the result back to the thread. This is the operator-**initiated** counterpart to the scheduled run; scheduling itself stays rented (cron / CI / a CronJob), and chat is the out-of-band trigger *and* the result surface. A `target` is a named, pre-registered scan config (source + access + `--label`), so `probe my_cluster` resolves to "k8s, this kubeconfig, env=prod-k8s."
3. **Converse** (operator replies in-thread, to the generative AI):
   - **Understand** — "what changed?", "why does it matter?", "show the diff", "who declared this?" → grounded answers (declared vs observed + git provenance).
   - **Acknowledge / declare intent** — "that was me, intentional" → acked, trusted, won't re-nag. Also snooze / false-positive.
   - **Remediate** — "fix it / bring it back to declared" → guardrailed executor (apply-eligibility → snapshot → apply → verify → offer revert). The AI states the action + blast radius and waits for go.
   - **Escalate** — page / open a ticket.
4. **Record.** The thread + actions become the Alert's audit trail. The conversation *is* the documentation.

**The inbound seam carries commands, not just approvals.** The same `INBOUND` adapters (§6) that today parse an approve/decline now normalize an operator message to a **Command** (`approve | decline | probe <target> | …`); `listen` becomes a ChatOps command surface, not only an approval listener.

**Bidirectional** (Events API + bot), not outbound-only. **Chat is a trigger, not a bypass:** operator identity → role, high-blast-radius needs explicit confirm, same guardrails as everywhere.

This is why the **web UI is thin**: onboarding/config, a read-only Alerts list, settings/audit. (Could even be a Grafana app → zero owned frontend.)

## 8. Decisions (locked)

- **Language: Python.** The maintainers' language; the AI ecosystem is Python-first; there's no hot-path agent anymore (collection is rented), so Rust/Go's perf isn't needed; integrations are subprocess + JSON + HTTP. Ship via `pip`/`uv`/Docker.
- **First source: Terraform.** Others as StateSource plugins later.
- **v0 = drift only.** Nail declared-vs-observed drift + reasoning before any domain pack. Then add packs (CIS, STIG, …) one at a time — modularity lets us try styles.
- **Positioning: separate / adjacent** to the predecessor product; clean-room, its own domain.
- **Thesis scope: drift + malfunction, not "monitoring."** Steady state includes *health*, not just config, so operational malfunction is a first-class departure (§1, §4) — the product is *steadystate*, not *driftfinder*. The boundary that keeps this from drifting into Datadog/Loki territory: Symptoms are scoped to **declared resources** and their **detection is rented** (we read existing health verdicts and reason about them; we don't store metrics, scrape all logs, or run alerting rules). *Decision: yes. Built: the `Symptom` type, the `kubectl` probe, and cross-type diagnosis (§11); docker probe + Summon next.*

## 9. v0 scope (the thinnest thing that proves the spine)

`steadystate scan ./infra` →
1. **Terraform StateSource**: run `terraform plan -json` (terraform already diffs declared vs real cloud state) → parse resource changes.
2. **Reconcile** those into **Drift** records (canonical model).
3. **Reason**: 3-tier scoring (signals → events → alerts) + an honest LLM "why this drift matters" → **Alerts**.
4. **Surface**: print to console (and a Slack push behind a flag).

No domain packs, no executor, no UI yet. Proves: ingest → reconcile → reason → surface, and the plugin seams.

## 10. Open decisions

- **License** — MIT vs Apache-2.0 (patent grant; common for infra OSS) vs a source-available license if open-core protection matters. *Owner: you.*
- **Surface order** — Slack first, then Teams? (Slack's bot/Events API is the faster build.)
- **Plugin mechanism for out-of-tree packs** — in-process Python entry points to start; gRPC/WASM later if we want language-agnostic third-party packs.
- **Observed-state beyond tf-plan** — ride each tool's native diff (tf plan, argocd live) first; a generic cloud-API observer is a later, bigger build.

## 11. Roadmap

**Done:**
1. Drift v0 — Terraform → Alerts (console / Slack / Teams).
2. Three-tier scoring + Brain Tuning; LLM **and** deterministic correlation (a registered seam).
3. Domain packs — AWS/GCP/Azure security (+ ATT&CK references) and Docker CIS compliance.
4. Memoryful scan — SQLite store: new/recurring/resolved, mute/snooze.
5. More sources — ArgoCD, docker-compose, Kubernetes, Rancher (Fleet), Ansible.
6. Observability — Prometheus/Grafana surfaces + Prometheus enrichment; LLM spend visibility + kill switch.
7. Guardrailed executor, per-plugin (terraform + ansible) and the **observe → suggest → approve → act** loop, approvable from the terminal or a Slack button.
8. `--autonomy auto` — self-apply every eligible remediation through that same guardrailed core; the apply gate is deterministic (the LLM never decides), so a REMOVED drift is never eligible and auto reconciles toward declared config without destroying.
9. Generalized **inbound seam** — the approval listener is a registry (`INBOUND`) of provider adapters over one stdlib HTTP shell; a new chat provider is an adapter, not a fork. Slack, Discord, and Teams ship.
10. Alerts self-identify (*which* resource drifted, and `--label` for *which* environment); a remediation **audit log** (`history`) — the append-only accountability trail every approve/decline/auto-apply writes to, the floor under turning `--autonomy auto` on for real.
11. Kubernetes security pack (`security-k8s`) — a standing Pod Security baseline (privileged, host namespaces, capabilities, hostPath) over declared manifests, mapped to CIS Kubernetes + ATT&CK; the same `evaluate`-the-baseline rail the Docker CIS pack rides.
12. Live-health enrichers (`--enrich prometheus | kubectl | docker`) — correlate a drift with the operational state of its resource (CrashLoopBackOff / restarts / unhealthy container + the failing pod/container's last log line), escalating *"failing since it drifted."* These became the detection the `Symptom` probe (below) promotes from "escalate" to "originate."
13. **Operational malfunction as a first-class departure** (the thesis evolution, §1/§4) — the `Symptom` type, the `probe/` seam (`--probe kubectl`) that produces Symptoms for declared workloads even with no drift, riding the same Signal/Event/Alert pipeline, and **cross-type diagnosis**: a Symptom co-located with a Drift folds into one root-caused Alert. Scope guardrails held: declared resources only, detection rented.

**Next:**
- **Docker probe** — `--probe docker` on the same rail (container health → Symptom), and retire the `kubectl`/`docker` *enrichers* now that the probe subsumes them.
- **Summon — chat-triggered probe** (§7): generalize the `INBOUND` adapters from parsing approvals to parsing Commands, so `@steadystate probe <target>` dispatches an on-demand scan/probe of a named target and posts the result to the thread — the operator-initiated counterpart to the scheduled run. Needs a small registry of named targets (name → source + access + label).
- More sources (Pulumi, Helm) · third-party plugin discovery (importlib entry points) · more domain packs (STIG, cost).
