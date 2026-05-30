# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project is pre-1.0 (0.x): per [SemVer](https://semver.org/), anything MAY
change between releases until 1.0.0. Releases are published as GitHub Releases.

## [Unreleased]

### Added

- Drift core (v0): canonical state model + reconciler + reasoning pipeline emitting Alerts.
- Terraform StateSource: declared-vs-real drift via `terraform show/plan -json`.
- Guardrailed Terraform executor: apply-eligibility check + snapshot/verify/revert; nothing applies without both eligibility and explicit confirm.
- Console surface: render Alerts and remediation plans to the terminal.
- Slack surface: outbound Alert push (stdlib urllib, no new dep) behind `scan --slack`.
- ArgoCD drift source: ingest an Application's own diff as Drift.
- docker-compose source: declared services (`docker compose config`) reconciled against running containers (`docker compose ps`) on presence + image tag, surfaced via `scan --source docker-compose` (proves the declared-vs-observed reconcile path for non-Drift StateSources).
- Security domain pack: raises severity only for positively-recognized exposure-increasing drift (open CIDR, public ACL/bucket, relaxed public-access-block, wildcard IAM).
- CLI `--source` selector dispatched through the source registry.
- Executor-backed `fix` command surfacing guardrailed recommended actions (`--apply` runs the eligible ones).
- Plugin registries: `DRIFT_SOURCES` (sources) and `DEFAULT_DOMAINS` (domains) so sources/packs register without editing the CLI or pipeline.
- Foundation: CI hardening, mypy + coverage gates, and tag-driven release automation cutting GitHub Releases.
- LLM provider abstraction: the analyst targets any OpenAI-compatible `/chat/completions` endpoint (OpenAI, Azure OpenAI, GitHub Models, internal gateway) via `STEADYSTATE_LLM_BASE_URL`/`STEADYSTATE_LLM_API_KEY`/`STEADYSTATE_LLM_MODEL`, alongside Anthropic (`ANTHROPIC_API_KEY`); auto-selected (Anthropic wins) or forced via `STEADYSTATE_LLM_PROVIDER`. No new dependency (stdlib urllib); still degrades honestly when unset.
- Microsoft Teams surface (`--to teams`, `TEAMS_WEBHOOK_URL`): posts one Adaptive Card per Alert to a Teams incoming webhook. Surfaces are now a registry (`console`/`slack`/`teams`), and `scan --to console,slack,teams` dispatches to any combination (replaces the old `--slack` flag). Stdlib urllib, no new dependency.
- Three-tier reasoning (Signal -> Event -> Alert) + Brain Tuning: every drift is a Signal (counted); filtering records Events, and analysis + correlation raise Alerts (surfaced, with or without a recommended action). A single `--tuning lenient|default|strict` knob moves the Signal->Event bar. Console shows the full breakdown; Slack/Teams page on Alerts only.
- Correlation: Events are sent to the LLM in one batch and grouped by root cause -- several signals from different sources (e.g. a node out of storage) fold into a single Alert. Deterministic up to Events; without a model each Event becomes its own uncorrelated Alert (honest degrade). Alerts now come from correlation, not a severity threshold.
- Deterministic correlator + correlator plugin seam: `--correlator auto|llm|deterministic` (registry + protocol + `build_correlator`). The deterministic correlator groups Events by shared attribute (declaring file / identity namespace) with no model; `auto` uses the LLM when a provider is configured, else degrades honestly to deterministic grouping (never one-Alert-per-Event noise).
- Memoryful scan (ChatOps Phase 0): a stdlib SQLite state store keyed off a stable Event fingerprint (`sha256(source|identity|change_type)`) makes a scan know new / recurring / resolved findings, with `mute` / `snooze` / `findings` CLI verbs and suppression.
- Framework references on the Domain seam: a pack maps recognized exposure-increasing drift to ATT&CK techniques, rendered as chips on Alerts and every surface. Config-exposure -> technique mapping, NOT behavioral detection.
- GCP and Azure security packs (alongside AWS): NSG/firewall opened to `0.0.0.0/0`/`::/0` -> T1190, public storage / relaxed bucket guardrail -> T1530 (+T1562), broad IAM role / `allUsers` -> T1098. Set-based exposure checks key off the OBSERVED/reality side, robust to terraform's union-encoding of TypeSet plan output (the AWS pack's CIDR check too).
- Docker CIS compliance pack: a standing-policy baseline (privileged, host net/pid, capabilities, no-new-privileges, non-root, image pinning) -- a Domain that *generates* findings from the declared inventory (`evaluate`), not only from drift (`score`).
- Kubernetes and Rancher (Fleet) sources: `k8s` reconciles declared manifests vs `kubectl get -o json` on presence + container images (JSON in, stdlib-only); `rancher` rides a Fleet GitRepo's `status.resources[]` sync status.
- Ansible source + executor: the source rides `ansible-playbook --check` (json callback) -> Drift per `host:task`; the executor reconciles a host by re-running the playbook (`--limit <host>`), guardrailed (honest that Ansible isn't transactional -- no auto-revert).
- Prometheus + Grafana surfaces: `prometheus` pushes a scan snapshot to a Pushgateway (alert/signal counts + `steadystate_llm_cost_usd`); `grafana` posts one annotation per Alert. Stdlib urllib.
- Prometheus enrichment (`--enrich prometheus`): cross-reference each Alert against an operator PromQL template and escalate a drift whose resource is unhealthy now (severity bumped); a flaky/slow Prometheus degrades to no-op, never breaks a scan.
- LLM spend visibility + kill switch: per-call token records (incl. cache tokens and failures) in the store, priced at read time; `steadystate cost` rolls up by caller over all / 24h / 60m. Kill switch `--no-llm` (or `STEADYSTATE_LLM_ENABLED=false`) makes zero model calls; a `steadystate_llm_cost_usd` Prometheus metric.
- Per-plugin command manifest: each source declares its `observe` (pre-approved, read-only) vs `destructive` (needs approval) commands; `steadystate commands` documents them. Observe-only plugins declare an empty destructive set.
- Per-plugin executor registry: `EXECUTORS` keyed by source + `fix --source <name>` dispatch (terraform, ansible); an observe-only source is rejected with a clean error.
- Autonomy + approval loop: `scan --autonomy observe|suggest|auto`. `suggest` records an eligible remediation per drift; `pending` / `approve` / `decline` drive it through the gated executor. Approve from the terminal, or via `steadystate listen` -- an Approve/Decline button on a Slack alert hits a signed interactive endpoint (HMAC-verified) and runs the same guardrailed path. `auto` applies every eligible remediation immediately through that *same* core (recorded as actor "auto") -- the apply gate is deterministic (`act/plan.py`), so the LLM is never in the decision and a REMOVED drift is never eligible (auto creates/updates toward declared config, never destroys); it requires the state store, so `--stateless` is rejected.
- Terraform plan parsing: dedupe a resource appearing in both `resource_drift` and `resource_changes` (one finding, correct declared/observed orientation); mark refresh-only drift non-actionable (floored to LOW baseline, no bogus `terraform apply` suggestion).
- Deployment guide + artifacts: `DEPLOYMENT.md` (the model + three worked environment examples), a multi-stage `Dockerfile`, and ready-to-adapt GitHub Actions workflow + Kubernetes CronJob/RBAC under `deploy/`.
- Provider-agnostic inbound seam: the approval listener moved into an `inbound/` package with an `INBOUND` registry mirroring outbound `SURFACES`. `listen --from <channel>` dispatches to an adapter (Slack today); a new chat provider (Discord, Teams, email) is a plugin -- implement `verify` / `handshake` / `parse` / `respond` -- not a fork. The routing (`dispatch`) verifies the signature first, so a forged or replayed click is rejected (401) before anything parses it; `handshake` accommodates providers that must answer a non-interaction ping (e.g. Discord PING -> PONG).
- Discord plugin: an outbound surface (`--to discord`, `DISCORD_WEBHOOK_URL`) posts one severity-colored embed per Alert via a channel webhook (stdlib urllib), and an inbound adapter accepts approvals via a `/steadystate approve|decline <fingerprint>` slash command. Discord signs interactions with Ed25519 (not HMAC) and requires a PING -> PONG handshake, both handled by the inbound seam; the crypto rides an optional extra (`pip install steadystate[discord]`, PyNaCl) so the core stays stdlib-only, with `ready()` reporting a missing key or dependency. Setup notes + a stdlib slash-command registration helper under `deploy/discord/`.

### Changed

- Security exposure checks for set-typed attributes (CIDR ranges, IAM member lists) key off the observed/reality side rather than a declared-vs-observed diff, so terraform's union-encoding of a `TypeSet`'s planned value can't hide a real open-to-world rule.

- Version is single-sourced from `__version__` in `src/steadystate/__init__.py` via `[tool.hatch.version]`.
- Security match uses word-boundary kind matching instead of loose substring (avoids the over-match trap).
