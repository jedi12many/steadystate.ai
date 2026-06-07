# Repo-native — steadystate as a stateless CI gate

steadystate **checked into the IaC repo**, run **stateless in CI**, whose only actuator is a PR or an
issue. No db, no LLM, no standing creds — `git clone` + a token + one line. (Full design:
[`docs/repo-native-posture.md`](../../docs/repo-native-posture.md).)

## Layout

```
your-iac-repo/
├── main.tf, ...                 # your IaC
├── steadystate/                 # COMMITTED intent (reviewed in PRs)
│   ├── config.toml              # what `ci` scans + how it gates
│   └── solutions.json           # your runbook (problem -> fix)
└── .steadystate/                # gitignored ephemeral state (not in CI)
```

`.gitignore`:
```gitignore
.steadystate/      # ephemeral state — ignore
# steadystate/     # intent — commit it
```

## The gate

```sh
steadystate ci                 # reads steadystate/config.toml; exits non-zero on a problem
```

- **Stateless + deterministic** — no state db, no model calls, reproducible, no surprise spend.
- **A CI gate** — `fail_on` (any | low | medium | high | critical | none) sets what trips a non-zero
  exit, so it blocks a merge on real drift/malfunction.
- **Closes the loop** (opt-in, outward — so it's explicit):
  - `deliver = "github-pr"` → open an accept-reality **PR** for code-reconcilable drift.
  - `to = "github"` → open an **issue** per problem (needs `GITHUB_TOKEN`).

## In a workflow

```yaml
# .github/workflows/steadystate.yml
- run: pipx install git+https://github.com/jedi12many/steadystate.ai   # `pip install steadystate` once on PyPI
- run: steadystate ci          # config.toml drives it; non-zero fails the check
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}   # only needed for --to github / --deliver github-pr
```

Flags override the config for a one-off: `steadystate ci ./infra --source terraform --fail-on critical`.
