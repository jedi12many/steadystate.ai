# Security Policy

## Supported versions

steadystate.ai is early (pre-1.0). Security fixes target the current `0.x`
release line; please be on the latest tag before reporting.

| Version | Supported |
| ------- | --------- |
| 0.x     | yes       |

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Report privately through GitHub's **Private Vulnerability Reporting**: on this
repository, go to the **Security** tab -> **Report a vulnerability** ("Advisories"
-> "Report a vulnerability"). This opens a private advisory thread with the
maintainers. See GitHub's guide on [privately reporting a security
vulnerability](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
if the button isn't visible.

Please include:

- affected version / commit,
- a description and the impact,
- the steps (or a minimal proof of concept) to reproduce.

We'll acknowledge your report, work a fix on a private branch, and coordinate
disclosure with you.

## Especially in scope: the guardrails

steadystate.ai can execute **guardrailed remediations against live
infrastructure** -- `steadystate fix --apply` reaches
`TerraformExecutor.remediate(...)`, which runs `terraform` against the real
environment. A live apply is supposed to require **both** apply-eligibility
**and** an explicit confirm (`--apply` / `confirm=True`); destructive
reconciliations (e.g. a `REMOVED` drift, which would destroy a live resource not
in declared config) are never automatically eligible.

So we are particularly interested in reports about anything that **bypasses the
guardrails**, for example:

- an apply running without an explicit confirm, or without being
  apply-eligible;
- an ineligible drift (e.g. a destroy) being treated as eligible;
- circumventing the snapshot / verify / revert path;
- a Surface input (chat / API) reaching an apply without the same eligibility +
  confirmation checks (chat is a trigger, never a bypass).

Findings that turn a read-only drift scan into an unintended change to real
infrastructure are the highest severity.
