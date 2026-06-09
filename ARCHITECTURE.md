# steadystate.ai — Architecture

> **The operational substrate for IT-Ops — human- or agent-driven.** You declared a desired steady state (Terraform, ArgoCD, Kubernetes/Rancher, Ansible, Docker, Helm). steadystate.ai watches your *deployed* infrastructure — live, and in CI — for any departure from it (**drift**: config diverged; **malfunction**: it's failing *now*), answers **is it working?**, carries your team's **runbook**, correlates a malfunction to the drift that caused it, and **closes the loop** — but only ever within a **bound you commit**.

Status: **the loop is built, in two postures.** A **live watcher** (a server/CLI next to a deployment, or driven by an agent over MCP) and a **repo-native GitOps** mode (`steadystate ci` — stateless, in the IaC repo, opening a PR/issue) share one deterministic core: drift + **malfunction** detection across the sources (terraform · terraform-state · ansible · kubernetes · rancher · argocd · docker-compose · helm), a **function-first verdict** (`WORKING | DEGRADED | DOWN` via `http` smoke tests + live symptoms), custom health checks, security/compliance domain packs, metric enrichment, an authored **runbook** (`problem → fix`, matched/offered/auto-applied/surfaced), and a guardrailed **observe → suggest → approve → act** loop — gated by an impact×reversibility **bound you commit** in `config.toml`, approvable from terminal / chat (Slack · Discord · Teams) / an agent (MCP), with an append-only audit. This doc describes the design those seams realize; the roadmap (§11) tracks what's done vs next.

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
2. **Modular from day one.** Five plugin seams + an enricher + a probe (below). Security/compliance/cost are packs, not core.
3. **Chat-first, no owned UI.** Operators live in Slack/Teams and drive from the terminal, CI, or an agent over MCP. The tool comes to them and talks back. *(There is no web UI today, by design; if one were ever added it would be a thin read-only view -- or a Grafana app -- never an owned frontend.)*
4. **Default-quiet.** Steady state = silence. We only surface *departures* (drift, policy violations, malfunction) that clear the bar. (Borrowed, hard-won, from the predecessor.)
5. **The operator is authoritative.** If a human says "that drift is intentional," we believe them and stop nagging.
6. **No action without a guardrail.** Every remediation is apply-eligibility-checked, snapshotted, verified, and reversible — whether triggered from chat or anywhere else.

## 3. The pipeline

```
DECLARED state (plugins — must be EASY)        OBSERVED state (rented)
 terraform · argocd · docker-compose            the real cloud/cluster/host, via
 ansible · helm · k8s · rancher                  each tool's own diff where possible
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

## 6. Plugin model (five seams + an enricher + a probe)

The core defines the interfaces; everything domain- or vendor-specific is a plugin, registered in a one-line registry so adding one never edits the core or the CLI.

1. **StateSource** — declared state in: `terraform · ansible · k8s · rancher · argocd · docker-compose · helm` (`DRIFT_SOURCES`). Each rides its tool's own machine-readable diff and declares its **observe** (read-only, pre-approved) vs **destructive** (needs approval) commands — the per-plugin permission manifest (`steadystate commands`).
2. **Domain** — what drift *means* (`DEFAULT_DOMAINS`): the AWS/GCP/Azure security packs map exposure-increasing drift to ATT&CK techniques; the Docker CIS pack evaluates a standing-policy baseline. A pack `score`s a drift and/or `evaluate`s the declared inventory, and attaches framework `references`. **This is how security & compliance enter — as packs, not core.**
3. **Surface** — push Alerts out, and take operator input back. Outbound: `console · slack · teams · discord · prometheus · grafana` (`SURFACES`). Inbound has its own registry (`INBOUND`, mirroring `SURFACES`) over a signed HTTP listener — `listen --from <channel>` — so accepting approvals from a new chat provider is an adapter (verify/handshake/parse/respond, plus an optional defer/complete for async — §11 item 16), not a fork. Slack (HMAC, buttons + slash command), Discord (Ed25519, slash command), and Teams (HMAC, @mention command) ship; the `verify`/`handshake` split is what lets three very different signing + handshake protocols share one listener. Each adapter parses its payload down to a provider-agnostic **Command** (`verb + actor + argument`) over a shared verb grammar — so the listener takes `help`, `pending` (read-only discovery), and `probe <target>` (an on-demand scan — §7) alongside `approve`/`decline`, and a new verb is one registry entry, not a change in every adapter. The listener is the long-lived counterpart to the scheduled scan ([deploy/kubernetes/listener.yaml](deploy/kubernetes/listener.yaml)): the CronJob pushes alerts out, the listener lets chat talk back.
4. **Executor** — perform a guardrailed remediation, keyed by source (`EXECUTORS`): `terraform`, `ansible`. A source with no executor is observe-only by declaration.
5. **Correlator** — group Events into Alerts (`CORRELATORS`): `llm` (root cause) or `deterministic` (shared attribute); `auto` chooses by whether a provider is configured.

Plus an **Enricher** (`ENRICHERS`): an optional step that cross-references an Alert against live metrics (`prometheus`) and escalates a drift whose resource breaches a PromQL bar right now — a metric threshold, distinct from a health verdict.

A **health probe** (`PROBES`, `--probe` / `--probe auto`) — *shipped: `kubectl`, `docker`, `argocd`* — the producer of `Symptom`s (§4), the operational counterpart to a StateSource. Live probes (kubectl, docker) shell out for health; a snapshot probe (argocd) reads the *same* document the source rides — ArgoCD's per-resource `health.status`, separate from its sync status, so OutOfSync (Drift) + Degraded (Symptom) diagnose into one Alert. Where a StateSource reconciles declared vs observed *config* into Drift, a health probe reads the live *health* of declared resources into Symptoms. Same access the source uses; detection rented, reasoning ours. Each probe declares its read-only **observe** commands the way a source does (`PROBE_CAPABILITIES`, surfaced in `steadystate commands` + the catalog) — so the kubectl probe's `kubectl logs` (the failing pod's evidence) is in the permission contract, and a least-privilege RBAC can be derived from it (`pods` *and* `pods/log`). This is the seam that lets the engine see malfunction with no drift, without becoming a monitor. **It retired the `kubectl`/`docker` enrichers:** once a Symptom is a first-class peer, a Symptom + a co-located Drift *correlate* into one root-caused Alert automatically — which is what "the enricher escalates a drift" was hand-rolling, but stronger (the symptom is evidence in the root cause, not just a severity bump). The pod/container-health detection now lives in the probe; only `--enrich prometheus` (metric-threshold escalation, a different shape) remains an enricher.

**Out-of-tree plugins (entry points).** Every registry above is built-in-by-default but *extensible across the packaging boundary*: a separately installed package contributes to a seam by declaring an [entry point](https://packaging.python.org/en/latest/specifications/entry-points/) — `steadystate.sources`, `steadystate.domains`, `steadystate.surfaces`, `steadystate.inbound`, `steadystate.executors`, `steadystate.correlators` — that loads the same shape the in-tree registry holds (a source factory, a `Surface` factory, a `Domain` class, …). At startup each registry overlays what it discovers (`plugins.py`, stdlib `importlib.metadata`) onto its built-ins, with two guarantees: a plugin that fails to import is logged and **skipped** (a broken third-party package never crashes the host or hides the plugins that load), and **built-ins win** every name clash (installing a package can *add* `--source pulumi` but never silently redirect `--source terraform` at its own code). So "add a pack, never edit core" holds for third parties too, not only within this repo.

```toml
# pyproject.toml of some third-party package — no fork, no PR to steadystate
[project.entry-points."steadystate.sources"]
pulumi = "acme_steadystate.pulumi:make_source"   # make_source(path) -> DriftSource
[project.entry-points."steadystate.domains"]
pci = "acme_steadystate.pci:PCIDomain"           # zero-arg -> a Domain
```

The engine itself is **not** a plugin inside someone else's product. You run it as a CLI from inside your IaC repo (the repo never imports *it*); it can also run as a long-running service or be driven over MCP. The *integrations* are the plugins.

## 7. Operator communication (ChatOps) — first-class

The tool **lives in Slack/Teams**, not in a dashboard you must remember to open.

1. **Detect → reason → push.** Drift → an Alert (what drifted, why it matters, recommended fix) → posted to the right channel/thread. Default-quiet.
2. **Summon — probe on demand** *(shipped).* `@steadystate probe <target>` dispatches a scan/probe of a named target *right now*, **regardless of the schedule** — someone just pinged you about prod, so you send the on-call agent to look rather than SSH-ing in yourself. It runs the full pipeline (drift + Symptoms + correlation) through the shared engine (`engine.build_report`, the same path the `scan` CLI runs) and posts the result back to the thread. This is the operator-**initiated** counterpart to the scheduled run; scheduling itself stays rented (cron / CI / a CronJob), and chat is the out-of-band trigger *and* the result surface. A `target` is a named, pre-registered scan config (`source` + `path` + `label`) in the listener's `STEADYSTATE_TARGETS` file, so `probe prod-k8s` resolves to "k8s, these manifests, env=prod-k8s." It runs **read-only**: it reports drift + health and never records or applies — so chat is a trigger, never a bypass. "Stateless" softened to "reads, never writes" for one reason — it **honors the operator's mutes/snoozes** by default (the same `is_suppressed` rule the reconcile uses, read-only), so silenced noise stays quiet on demand too; it says how many it withheld, and `unmute` bypasses suppression for that run so a stale mute can never hide a live incident.
3. **Converse** (operator replies in-thread, to the generative AI):
   - **Understand** — "what changed?", "why does it matter?", "show the diff", "who declared this?" → grounded answers (declared vs observed + git provenance).
   - **Acknowledge / declare intent** — "that was me, intentional" → acked, trusted, won't re-nag. Also snooze / false-positive.
   - **Remediate** — "fix it / bring it back to declared" → guardrailed executor (apply-eligibility → snapshot → apply → verify → offer revert). The AI states the action + blast radius and waits for go.
   - **Escalate** — page / open a ticket.
4. **Record.** The thread + actions become the Alert's audit trail. The conversation *is* the documentation.

**The inbound seam carries commands, not just approvals.** The `INBOUND` adapters (§6) normalize an operator message to a provider-agnostic **Command** (`verb + actor + argument`), not a fixed approve/decline pair — so `listen` is a ChatOps command surface, not only an approval listener. *Shipped:* the `Command` type and a shared verb grammar, with the read-only discovery commands **`help`** (renders itself from the command registry, so an operator who didn't set up the deployment can ask what this listener accepts) and **`pending`** (the open remediations + their fingerprints), plus **`probe <target>`** (Summon — resolves a named target and runs the read-only scan engine) — across all three providers (Teams @mention · Slack slash command · Discord slash subcommand).

**Bidirectional** (Events API + bot), not outbound-only. **Chat is a trigger, not a bypass:** operator identity → role, high-blast-radius needs explicit confirm, same guardrails as everywhere.

This is why there is **no owned web UI**: the surfaces are chat, the terminal, CI, and MCP. If a read-only view were ever wanted it'd be a Grafana app (zero owned frontend), not a console to maintain.

## 8. Decisions (locked)

- **Language: Python.** The maintainers' language; the AI ecosystem is Python-first; there's no hot-path agent anymore (collection is rented), so Rust/Go's perf isn't needed; integrations are subprocess + JSON + HTTP. Ship via `pip`/`uv`/Docker.
- **First source: Terraform.** Others as StateSource plugins later.
- **v0 = drift only.** Nail declared-vs-observed drift + reasoning before any domain pack. Then add packs (CIS, STIG, …) one at a time — modularity lets us try styles.
- **Positioning: separate / adjacent** to the predecessor product; clean-room, its own domain.
- **Thesis scope: drift + malfunction, not "monitoring."** Steady state includes *health*, not just config, so operational malfunction is a first-class departure (§1, §4) — the product is *steadystate*, not *driftfinder*. The boundary that keeps this from drifting into Datadog/Loki territory: Symptoms are scoped to **declared resources** and their **detection is rented** (we read existing health verdicts and reason about them; we don't store metrics, scrape all logs, or run alerting rules). *Decision: yes. Built: the `Symptom` type, the kubectl/docker/argocd probes, cross-type diagnosis (§11), and chat-summoned probes (§7).*

## 9. v0 scope (the thinnest thing that proves the spine) — *historical*

> The original v0 milestone, shipped long ago; the engine has grown well past it (see §11). Kept for
> the design narrative, not as a statement of current scope.

`steadystate scan ./infra` →
1. **Terraform StateSource**: run `terraform plan -json` (terraform already diffs declared vs real cloud state) → parse resource changes.
2. **Reconcile** those into **Drift** records (canonical model).
3. **Reason**: 3-tier scoring (signals → events → alerts) + an honest LLM "why this drift matters" → **Alerts**.
4. **Surface**: print to console (and a Slack push behind a flag).

No domain packs, no executor, no UI yet. Proves: ingest → reconcile → reason → surface, and the plugin seams.

## 10. Open decisions

*Most of the original open decisions are now settled (kept for the record):* **License** — Apache-2.0
(the patent grant). **Surface order** — Slack, Discord, and Teams all shipped over one inbound seam.
**Out-of-tree plugin mechanism** — in-process Python entry points shipped (`plugins.py`); gRPC/WASM
stays a later option only if language-agnostic third-party packs are wanted.

Still genuinely open:

- **Observed-state beyond a native diff** — ride each tool's own diff (`terraform plan`, the low-cred `terraform-state`, ArgoCD live, the k8s/ansible live variants) first; a *generic* cloud-API observer is a later, bigger build.

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
12. Live-health enrichers — a drift-anchored kubectl/docker correlation (CrashLoopBackOff / restarts / unhealthy container + the failing pod/container's last log line) that escalated *"failing since it drifted."* This was the detection the `Symptom` probe (below) promoted from "escalate" to "originate" — and then **retired** the enrichers (item 14).
13. **Operational malfunction as a first-class departure** (the thesis evolution, §1/§4) — the `Symptom` type and the `probe/` seam (`--probe auto | kubectl | docker | argocd`) that produces Symptoms for declared resources even with no drift, riding the same Signal/Event/Alert pipeline, and **cross-type diagnosis**: a Symptom co-located with a Drift folds into one root-caused Alert. A probe exists wherever health is distinct from drift (k8s pods, compose containers, ArgoCD's health field); terraform/ansible/rancher have none, by design. Scope guardrails held: declared resources only, detection rented.
14. **Retired the kubectl/docker enrichers** now that the probes subsume them — correlation does the escalation, stronger (the symptom is evidence in the root cause, not a severity bump). The pod/container-health detection moved into `probe/{kubectl,docker}.py`; `--enrich prometheus` (metric-threshold, a different shape) stays.
15. **Chat is two-way — the inbound `Command` seam + Summon** (§7): the `INBOUND` adapters parse a provider-agnostic `Command` (`verb + actor + flags`) over one shared grammar, so the listener takes `help` · `targets` · `pending` · `findings` · `history` (read-only discovery), **`probe <target> [verbose|cost]`** (Summon — an on-demand scan of a named target from `STEADYSTATE_TARGETS`, read-only, with `verbose` showing the declared→observed evidence), and `mute`/`approve`/`decline` (writes), across all three providers + a local `chat` REPL. Summon runs through the shared `engine.build_report` the `scan` CLI uses, so there's one reasoning path. The persistent listener ships as a Deployment ([deploy/kubernetes/listener.yaml](deploy/kubernetes/listener.yaml)) — the long-lived counterpart to the scheduled CronJob.
16. **Async summons** — a slow scan (a live `terraform plan`) can exceed a chat provider's ~3s interaction window. `dispatch` now returns an optional *deferred work* alongside the immediate reply: for a `probe` on a provider that supports it, the listener ACKs at once and runs the scan in a background thread, posting the result back through the provider's channel (Discord: edit the deferred message; Slack: POST the `response_url`). An optional `defer`/`complete` adapter capability (probed by attribute, like the rest of the seam), so Teams — which has no `response_url` — stays synchronous, unchanged. The result post is read-only and best-effort; a flaky post never crashes the listener.
17. **Out-of-tree plugin discovery** (§6) — the registries stop being repo-bound: every seam (sources · domains · surfaces · inbound · executors · correlators) now overlays `importlib.metadata` entry points (`steadystate.<seam>`) on its built-ins, so a *separately installed* package extends steadystate without a fork (`plugins.py`, stdlib only). Discovery is isolated (a plugin that fails to import is logged and skipped) and safe (built-ins win every name clash — a package can add a backend, never hijack a shipped name). This closes the last in-tree-only seam: "add a pack, never edit core" is now true for third parties too.
18. **Function-first verdict — "is it *working*?"** The `health` command answers `WORKING | DEGRADED | DOWN`: an `http` **smoke test** check kind (exercise the endpoint — a service that won't answer IS down) plus the live symptoms, scoped to a workload and **correlated** with the drift that likely caused them. `summary` leads with what's *impaired* (a live malfunction) over mere drift/posture, so neither a human nor an agent chases a red herring — but a high-severity drift (an opened firewall) is **flagged for review**, never buried. Custom **health checks** (`define-check`/`add-check`) and **metric enrichment** (a pluggable Prometheus adapter, consumed as context, never reimplemented) round out the live picture; **silos** (`--silo`, like `git -C`) name per-deployment walls.
19. **The honest gate, made legible** — a `posture` verb that states plainly what steadystate bounds *and where that ends* (a shell-enabled agent's real limit is its RBAC, not us); the **sole-actuator** (contained-agent) model where steadystate is an agent's only tool; and a middle MCP grant tier (**`--author`**) that lets an agent write checks + runbook solutions without the power to touch infra.
20. **The runbook (solutions)** — operator-vouched `problem → fix` entries (`solutions.json`), authored (`add-solution`/`define-solution`, signed), **learned** (`learn` surfaces a fix you keep applying by hand and hands you the capture), **matched** to a finding (category or title regex), **offered** as a one-`approve` remediation, optionally **auto-applied** within the bound (`STEADYSTATE_SOLUTION_AUTO`), and **surfaced** wherever the problem lands (`show`, a CI-opened issue). Your tribal knowledge as a first-class, gated, auditable artifact — the catalog you grow yourself.
21. **Two postures + config as code** — a **repo-native GitOps** mode alongside the live watcher: `steadystate ci` (stateless, deterministic, no creds) scans the IaC, gates the merge, and opens a PR/issue (the github-issues surface dedups, auto-closes, and carries the matched runbook fix). A **`terraform-state`** source diffs config-vs-state with `-refresh=false` (state-bucket read, no broad cloud creds). And a committed **`steadystate/config.toml`** — `[defaults]` (source/path), `[bound]` (the autonomy envelope, *reviewed in a PR*), `[ci]` — unifies config beside `checks.json`/`solutions.json`, 12-factor (`flag > env > config > default`). See [docs/repo-native-posture.md](docs/repo-native-posture.md).

**Next:**
- More `config.toml` tables (`[autonomy]`, surfaces) · the matched runbook fix in more surfaces (ServiceNow/Slack) · a live kube-prometheus enrichment run.
- More sources (Pulumi) · more domain packs (STIG, cost) · Dockerfile reader for the CIS pack.
