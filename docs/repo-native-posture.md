# Repo-native posture — steadystate as a stateless GitOps bot

> Status: phase 1 (the `steadystate/` committed-intent convention) **shipped**; phase 2 (`steadystate
> ci`, below) **shipped**. Phases 3–4 (a state-only source; the runbook-in-the-PR/issue) remain.

steadystate has two deployment postures, and they share one core:

| | **Live watcher** (today's primary) | **Repo-native** (this doc) |
|---|---|---|
| Where it runs | a long-running silo / MCP server next to a deployment | **stateless, in CI** (or a laptop), inside the IaC repo |
| What it holds | creds, a kubeconfig, the state db | **nothing** but the repo + a token |
| How it acts | guardrailed remediation on live infra | **opens a PR / an issue** — a human merges |
| Loop | detect → act → verify, live | detect → **propose in the PR flow** |

They are complements: **post-deploy (live) + pre-deploy (GitOps).** The same deterministic core, the
same authored runbook (`solutions.json`) — one in the repo, one watching reality.

## 1. The file-layout split (phase 1 — shipped)

The `.terraform/` vs `*.tf` convention, applied to us:

| Path | Contents | Git |
|---|---|---|
| `.steadystate/` (dotted) | **ephemeral state** — `state.db`, patches, caches | **gitignored** (per-machine) |
| `steadystate/` (undotted) | **authored intent** — `solutions.json`, `checks.json` | **committed** (reviewed in PRs) |

Checks and solutions are *intent* (IaC-grade), not runtime state — so they belong in version control,
next to the IaC, reviewed like any other change. Path resolution now **prefers the committed
`steadystate/`** (falling back to the legacy `.steadystate/` if that's what a repo already has), and a
**fresh** authored check/solution lands in the committed location, so it's never lost in a gitignored
dir. A fresh clone gets the team's runbook + checks for free.

Recommended `.gitignore` in a consuming repo:

```gitignore
.steadystate/        # ephemeral state — ignore
# steadystate/       # intent — commit it (do NOT ignore)
```

## 2. Sitting next to the IaC (phase 2)

A `steadystate/config.toml` makes explicit what's implicit today: `source = "terraform"`, `path =
"."`, where intent lives. The **repo is the wall** — no silo registry, no kubeconfig to juggle.
`steadystate scan .` already works; this is the zero-config convention over it.

## 3. Access to the backend state (phase 3)

`terraform plan` already reads the configured backend, but it needs the terraform binary, **cloud
read creds**, and a full **refresh** (live API calls). Direct **state access** (just the `.tfstate`
from S3 / GCS / TF Cloud) is a *lighter, lower-privilege* source:

- **config (HCL) vs state** → "code changed but wasn't applied" — cheap, **no cloud creds**, no refresh.
- **state vs reality** → live drift (the opened-firewall case) — still needs the refresh.
- The state is also the **real managed inventory** — the declared set + a fingerprint→resource-ID map
  without parsing all the HCL.

A **state-only source** is the right fit for a CI check that shouldn't hold broad cloud creds: it
answers "is the code in sync with what's deployed?" with nothing but **read access to the state
bucket**. The full plan stays the option when you want live drift.

## 4. The headline: `steadystate ci` (phase 2 — shipped)

One command that needs **nothing but the repo and a token** — stateless, deterministic, **no db, no
LLM**:

```
steadystate ci
  → scan the repo's IaC          (config / state / reality, per what's reachable)
  → match the committed runbook  (steadystate/solutions.json)
  → close the loop on GitHub:
       • a code-reconcilable drift → open a PR     (the github-pr deliverer we already have)
       • a confirmed problem + fix → open an issue  (the github-issues surface, #228)
  → exit non-zero on an unreconciled problem  (a CI gate, like `health` already does)
```

So it's **both** a CI gate (block the merge) **and** a PR-bot (propose the fix).

**The learn division falls out cleanly:** *learning* needs history, so it happens in the **live**
posture → you **commit the learned solution** to `steadystate/solutions.json` → the **stateless CI**
run *uses* it. **Learn live → commit → apply stateless.**

## How it fits the mission

- **The honest gate, taken to its limit.** A PR-bot's only power is a proposal a human reviews — the
  ultimate sole-actuator / contained posture (no shell, no creds, *cannot* touch infra).
- **Closes the loop where the loop already lives** — the PR + review flow, beside the IaC.
- **The adoption wedge.** The live server needs walls, kubeconfigs, a deployment. This needs
  `git clone` + a token + a CI line. *"Try steadystate in your CI in 5 minutes"* is a far lower-friction
  front door than standing up a watcher.

## How this compares to what's out there (the honest read)

The individual *pieces* are not novel: CI **drift detection** exists (Spacelift / env0 / Terraform
Cloud drift detection, the archived driftctl, Firefly), and **PR automation** for IaC exists
(Atlantis runs plan/apply in PRs). "Detect drift in CI" and "a terraform PR bot" are both done.

What is **less common is the combination**, and it's the part worth leaning on:

1. **A committed, matched runbook.** Drift tools tell you *what* drifted; they don't carry your team's
   **problem → fix** knowledge and surface/apply it. The `solutions.json` next to the IaC, matched to
   findings, is ours.
2. **Function-first verdict + correlation + the bound.** Not "here's a diff" but "is it *working*,
   what's the *likely cause*, and is this *safe to auto-fix within a bound*." Drift tools don't reason
   about that.
3. **One substrate spanning both postures, sharing the runbook.** The drift tools are pre-deploy only.
   steadystate is the *same* tool pre-deploy (GitOps PR-bot) **and** post-deploy (live watcher), and
   the learned runbook flows between them. That continuity is the differentiated bit.
4. **The PR-bot as the deliberately safest actuator** — a design *posture*, not a missing capability.

So: not a brand-new capability, but a **deployment model and a coherence** that the drift/PR tools
don't offer — your runbook + the verdict/bound + one tool across the whole lifecycle. That's the claim
to make, honestly, without overstating novelty on drift-in-CI alone.
