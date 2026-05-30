# steadystate.ai — Architecture

> **Stateful monitoring.** You declared a desired steady state (in Terraform, ArgoCD, Docker, Ansible…). steadystate.ai reconciles that declared state against observed reality, reasons about the drift, surfaces only what's actionable — and, on your say-so, helps return you to steady state, safely.

Status: **the loop is built.** Detection across six sources (terraform · ansible · kubernetes · rancher · argocd · docker-compose), security/compliance domain packs (AWS/GCP/Azure security · Docker CIS), five surfaces + Prometheus enrichment, and a guardrailed **observe → suggest → approve → act** loop (from the terminal or a Slack button) all ship today. This doc describes the design those seams realize; the roadmap (§11) tracks what's done vs next.

---

## 1. Thesis

A system in *steady state* is one where **declared == observed**. Every meaningful problem — a security regression, a compliance violation, a cost surprise, an outage waiting to happen — shows up first as **drift** from the declared state. So drift is the universal signal, and *reasoning about drift* is the product.

steadystate.ai is **not** a security tool that happens to read config. It's a **drift-reasoning engine** with security and compliance as the first *plugins*. The core never knows what "security" is — a domain pack teaches it.

This is a deliberate, lean reframe of an earlier custom-everything system (own agent + own brain + own dashboard). The lesson learned: **only the reasoning is differentiated.** Build that; rent the rest.

## 2. Principles

1. **Build the reasoning + the guardrails. Rent everything else.** Collection, storage, dashboards, and execution already exist and are better than we want to maintain.
2. **Modular from day one.** Five plugin seams + an enricher (below). Security/compliance/cost are packs, not core.
3. **Chat-first, thin UI.** Operators live in Slack/Teams. The tool comes to them and talks back. The web UI is config + a read-only view, nothing more.
4. **Default-quiet.** Steady state = silence. We only surface drift that clears the bar. (Borrowed, hard-won, from the predecessor.)
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
   Reconciler → DRIFT records (what diverged, since when, traced to the declaring file)
        ▼
   Reasoning core  (BUILD — the IP)
     Signals → Events → Alerts (3-tier scoring) · correlate · honest LLM "why this matters"
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
- **Drift** — a reconciled divergence: `{ resource_identity, change_type (added/removed/modified), declared, observed, detected_at, provenance }`.

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
3. **Surface** — push Alerts out, and (Slack) take operator input back: `console · slack · teams · prometheus · grafana` (`SURFACES`). The Slack surface carries Approve/Decline buttons; the inbound half is a signed HTTP listener (`steadystate listen`).
4. **Executor** — perform a guardrailed remediation, keyed by source (`EXECUTORS`): `terraform`, `ansible`. A source with no executor is observe-only by declaration.
5. **Correlator** — group Events into Alerts (`CORRELATORS`): `llm` (root cause) or `deterministic` (shared attribute); `auto` chooses by whether a provider is configured.

Plus an **Enricher** (`ENRICHERS`): an optional step that cross-references an Alert against live observability (`prometheus`) and escalates a drift whose resource is failing right now.

The engine itself is **not** a plugin inside someone else's product (it's a stateful service + an embeddable library). The *integrations* are the plugins.

## 7. Operator communication (ChatOps) — first-class

The tool **lives in Slack/Teams**, not in a dashboard you must remember to open.

1. **Detect → reason → push.** Drift → an Alert (what drifted, why it matters, recommended fix) → posted to the right channel/thread. Default-quiet.
2. **Converse** (operator replies in-thread, to the generative AI):
   - **Understand** — "what changed?", "why does it matter?", "show the diff", "who declared this?" → grounded answers (declared vs observed + git provenance).
   - **Acknowledge / declare intent** — "that was me, intentional" → acked, trusted, won't re-nag. Also snooze / false-positive.
   - **Remediate** — "fix it / bring it back to declared" → guardrailed executor (apply-eligibility → snapshot → apply → verify → offer revert). The AI states the action + blast radius and waits for go.
   - **Escalate** — page / open a ticket.
3. **Record.** The thread + actions become the Alert's audit trail. The conversation *is* the documentation.

**Bidirectional** (Events API + bot), not outbound-only. **Chat is a trigger, not a bypass:** operator identity → role, high-blast-radius needs explicit confirm, same guardrails as everywhere.

This is why the **web UI is thin**: onboarding/config, a read-only Alerts list, settings/audit. (Could even be a Grafana app → zero owned frontend.)

## 8. Decisions (locked)

- **Language: Python.** The maintainers' language; the AI ecosystem is Python-first; there's no hot-path agent anymore (collection is rented), so Rust/Go's perf isn't needed; integrations are subprocess + JSON + HTTP. Ship via `pip`/`uv`/Docker.
- **First source: Terraform.** Others as StateSource plugins later.
- **v0 = drift only.** Nail declared-vs-observed drift + reasoning before any domain pack. Then add packs (CIS, STIG, …) one at a time — modularity lets us try styles.
- **Positioning: separate / adjacent** to the predecessor product; clean-room, its own domain.

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

**Next:** `--autonomy auto` (self-apply, opt-in) · a Teams inbound adapter (onto the same approval core) · a remediation audit log · a Kubernetes security pack · more sources (Pulumi, Helm).
