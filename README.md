# steadystate.ai

**Stateful monitoring for your infrastructure.**

You already declared what your infrastructure *should* be — in Terraform, ArgoCD, Docker, Ansible. steadystate.ai watches the gap between that **declared state** and **observed reality**, reasons about the **drift**, and tells you — in Slack or Teams, in plain language — what actually matters and what to do about it. On your say-so, it can bring things back to steady state, safely and reversibly.

It is **not** another dashboard to babysit. Steady state is silence; you only hear from it when something has drifted in a way worth your attention, and you answer it by chatting back.

> Status: **early.** Building the drift core first (Terraform). Everything else — more sources, security/compliance checks, auto-remediation — is a plugin that comes after.

## The idea

- **Drift is the universal signal.** Security regressions, compliance violations, cost surprises, latent outages — they all show up first as a divergence from what you declared.
- **The reasoning is the product.** Collection, storage, dashboards, and execution already exist and are better than we want to maintain — so we rent them. We build the part nobody else has: the engine that decides *which drift matters and why*, and the guardrails that let it act safely.
- **Security & compliance are plugins** (CIS, STIG, …), not the core. The core just understands drift; domain packs teach it what drift *means*.
- **You talk to it.** It pushes findings to Slack/Teams; you reply conversationally — "what changed?", "that was intentional", "fix it" — and a generative-AI operator handles the back-and-forth. That's why there's barely any UI.

## How it'll work (v0)

```
steadystate scan ./infra
  → reads your Terraform's own plan (declared vs real cloud state)
  → reconciles the drift into a canonical model
  → reasons about it (what matters, why) and writes Cases
  → surfaces the Cases (console now; Slack next)
```

No agent to install, no dashboard to learn. Point it at your IaC.

## Enabling AI reasoning (optional)

The drift core runs with **no LLM** — detection, scoring, the security pack, and the guardrailed executor are all deterministic. An LLM only adds the plain-language *"why this matters"* narrative, and the analyst degrades honestly when none is configured.

Point it at whichever model you're allowed to use:

- **Anthropic** — `pip install steadystate[llm]`, then set `ANTHROPIC_API_KEY`.
- **Any OpenAI-compatible endpoint** (OpenAI, Azure OpenAI, GitHub Models, an internal gateway) — no extra install:

  ```sh
  export STEADYSTATE_LLM_BASE_URL=...   # your /chat/completions endpoint
  export STEADYSTATE_LLM_API_KEY=...    # your token
  export STEADYSTATE_LLM_MODEL=...      # a model that endpoint serves
  ```

When both are set, Anthropic wins unless you set `STEADYSTATE_LLM_PROVIDER=openai`.

## Design

See **[ARCHITECTURE.md](./ARCHITECTURE.md)** for the full design: the canonical state model, the four plugin seams (StateSource / Domain / Surface / Executor), the ChatOps operator model, and the build-vs-rent decisions.

## Built with

Python. (No hot-path agent to write — the reasoning engine is I/O- and LLM-bound, and the maintainers speak Python.)

## License

Apache-2.0. See [LICENSE](./LICENSE).
