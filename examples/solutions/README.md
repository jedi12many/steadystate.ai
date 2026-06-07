# Solutions — the authored runbook

`custom-checks` teach steadystate to **see** a problem. **Solutions** teach it the **fix**: a
declarative `problem → fix` map you build over time — your tribal knowledge, made structured,
auditable, and (next) automatable. It's the catalog you grow yourself.

A solution is **operator-vouched**, so the body is open — you say *here's the command, the playbook,
the reboot*. The guardrail isn't restricting what you may document; it's that **acting** on a
solution still passes the bound + approval + audit. The `author` is the accountability; the
version-controlled file is the audit; surfacing the fix against a matching finding is the payoff.

## The format — [`solutions.json`](./solutions.json)

```jsonc
{
  "name": "reclaim-evicted-pods",
  "for": "Evicted",                       // STRICT match: a finding category or a custom-check name
  "match": "gateway.*(hung|not routing)", // OR a title REGEX (use either, or both -> AND)
  "problem": "Evicted pods pile up as Failed.",
  "solution": { "kind": "command",        // command | playbook | reboot | ... (open)
                "run": "kubectl delete pods --field-selector=status.phase=Failed -n {namespace}" },
  "impact": "low", "reversibility": "high", // the bound -- a destructive fix still needs approval
  "author": "jeff", "added": "2026-06-07"   // the audit anchor
}
```

- **`for`** pins it to a problem **strictly** (exact category / check name); **`match`** is a title
  **regex** for fuzzier shapes. Set one, or both (both must hold). `{namespace}`/`{workload}` are
  filled from the matched finding.
- **`impact` + `reversibility`** are the **bound** — so when this is automated, a low-impact /
  reversible fix can auto-apply (only with autonomy granted), while anything destructive still
  escalates to a human.
- **`author`** is required — an unsigned fix isn't auditable, so it's rejected.

## Use it

```sh
export STEADYSTATE_SOLUTIONS=./examples/solutions/solutions.json   # version-control this

steadystate solutions                 # list the runbook
steadystate show <fingerprint>        # a matching finding shows its known fix + who vouched
```

When a finding matches (e.g. an `Evicted` pod, or a title like "akeyless **gateway not routing**"),
`show` surfaces the documented fix and its author. An agent driving steadystate over MCP sees the
same thing — your runbook, right where the problem is.

> **Next:** automation — a matched solution offered as a *pending remediation* you `approve` (or, with
> autonomy granted and within the bound, applied automatically), then audited. Same gate as the
> built-in catalog; the author is the vetting.
