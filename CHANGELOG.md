# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project is pre-1.0 (0.x): per [SemVer](https://semver.org/), anything MAY
change between releases until 1.0.0. Releases are published as GitHub Releases.

## [Unreleased]

### Added

- Drift core (v0): canonical state model + reconciler + reasoning pipeline emitting Cases.
- Terraform StateSource: declared-vs-real drift via `terraform show/plan -json`.
- Guardrailed Terraform executor: apply-eligibility check + snapshot/verify/revert; nothing applies without both eligibility and explicit confirm.
- Console surface: render Cases and remediation plans to the terminal.
- Slack surface: outbound Case push (stdlib urllib, no new dep) behind `scan --slack`.
- ArgoCD drift source: ingest an Application's own diff as Drift.
- docker-compose declared-state source (declared-only StateSource; reconcile path deferred).
- Security domain pack: raises severity only for positively-recognized exposure-increasing drift (open CIDR, public ACL/bucket, relaxed public-access-block, wildcard IAM).
- CLI `--source` selector dispatched through the source registry.
- Executor-backed `fix` command surfacing guardrailed recommended actions (`--apply` runs the eligible ones).
- Plugin registries: `DRIFT_SOURCES` (sources) and `DEFAULT_DOMAINS` (domains) so sources/packs register without editing the CLI or pipeline.
- Foundation: CI hardening, mypy + coverage gates, and tag-driven release automation cutting GitHub Releases.
- LLM provider abstraction: the analyst targets any OpenAI-compatible `/chat/completions` endpoint (OpenAI, Azure OpenAI, GitHub Models, internal gateway) via `STEADYSTATE_LLM_BASE_URL`/`STEADYSTATE_LLM_API_KEY`/`STEADYSTATE_LLM_MODEL`, alongside Anthropic (`ANTHROPIC_API_KEY`); auto-selected (Anthropic wins) or forced via `STEADYSTATE_LLM_PROVIDER`. No new dependency (stdlib urllib); still degrades honestly when unset.
- Microsoft Teams surface (`--to teams`, `TEAMS_WEBHOOK_URL`): posts one Adaptive Card per Case to a Teams incoming webhook. Surfaces are now a registry (`console`/`slack`/`teams`), and `scan --to console,slack,teams` dispatches to any combination (replaces the old `--slack` flag). Stdlib urllib, no new dependency.
- Three-layer surfacing + Brain Tuning: every drift is an Event (counted); deterministic scoring promotes the ones that matter into Alerts (recorded) and Cases (page-worthy, full narrative + recommended action). A single `--tuning lenient|default|strict` knob moves all the bars together, and the LLM analyst runs only on what clears the bar. Console shows the full breakdown; Slack/Teams page on Cases only.

### Changed

- Version is single-sourced from `__version__` in `src/steadystate/__init__.py` via `[tool.hatch.version]`.
- Security match uses word-boundary kind matching instead of loose substring (avoids the over-match trap).
