# steadystate.ai — Architecture

> **Stateful monitoring.** You declared a desired steady state (in Terraform, ArgoCD, Docker, Ansible…). steadystate.ai reconciles that declared state against observed reality, reasons about the drift, surfaces only what's actionable — and, on your say-so, helps return you to steady state, safely.

Status: **early / founding.** This doc is the north star; the code follows it.

---

## 1. Thesis

A system in *steady state* is one where **declared == observed**. Every meaningful problem — a security regression, a compliance violation, a cost surprise, an outage waiting to happen — shows up first as **drift** from the declared state. So drift is the universal signal, and *reasoning about drift* is the product.

steadystate.ai is **not** a security tool that happens to read config. It's a **drift-reasoning engine** with security and compliance as the first *plugins*. The core never knows what "security" is — a domain pack teaches it.

This is a deliberate, lean reframe of an earlier custom-everything system (own agent + own brain + own dashboard). The lesson learned: **only the reasoning is differentiated.** Build that; rent the rest.

## 2. Principles

1. **Build the reasoning + the guardrails. Rent everything else.** Collection, storage, dashboards, and execution already exist and are better than we want to maintain.
2. **Modular from day one.** Four plugin seams (below). Security/compliance/cost are packs, not core.
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

## 6. Plugin model (four seams)

The core defines four interfaces; everything domain- or vendor-specific is a plugin.

1. **StateSource** — declared state in (terraform, argocd, …). `discover()` + `collect() -> [Resource]`.
2. **Domain** — what drift *means* (security, compliance/CIS/STIG, cost, reliability). Contributes the resources/properties it cares about, the rules, scoring inputs, and optional remediation recipes. **This is how security & compliance enter — as packs, not core.**
3. **Surface** — push Alerts out + (bidirectionally) take operator input back (Slack, Teams, API).
4. **Executor** — perform a guardrailed remediation (run the terraform/ansible/kubectl).

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

1. **Drift v0** — Terraform → Alerts on the console (§9).
2. **Slack ChatOps** — push Alerts + bidirectional ack/ask/snooze.
3. **First domain pack** — prove the `Domain` seam (likely a small CIS or security rule set).
4. **Guardrailed executor** — "fix it from chat," reversibly.
5. **More sources** — ArgoCD (rides its own diff), docker-compose, ansible.
6. **More packs** — STIG, cost, reliability.
