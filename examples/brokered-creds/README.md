# brokered-creds — no static kubeconfig: broker a short-lived one at launch

**The situation:** mature shops don't leave long-lived kubeconfigs lying on disk. The cluster
credential lives in a secrets manager (**Vault**); a cluster manager (**Rancher**)
mints a **short-lived** kubeconfig on demand. You want steadystate to operate the same way — pull the
secret, mint a kubeconfig, use it, and never persist the standing credential.

The lowest-commitment way to do that is a **pre-launch wrapper**: a few lines that broker the
kubeconfig into the [silo](../mcp-copilot/) right before steadystate runs. No new steadystate code,
and the **secret never lands on disk** — only the short-lived kubeconfig it derives.

## The wrapper

```bash
#!/usr/bin/env bash
set -euo pipefail   # fail CLOSED -- never run steadystate with a half-brokered credential

SILO="$HOME/ops/gateway-use1"
RANCHER_URL="https://rancher.example.com"
CLUSTER_ID="c-m-xxxxxxxx"

# 1. fetch a short-lived Rancher API token from your secrets manager
TOKEN="$(vault kv get -field=token secret/rancher/api-token)"

# 2. exchange it for a FRESH kubeconfig -- Rancher mints it, scoped + time-limited
curl -fsSL -X POST -H "Authorization: Bearer ${TOKEN}" \
     "${RANCHER_URL}/v3/clusters/${CLUSTER_ID}?action=generateKubeconfig" \
  | jq -r '.config' > "${SILO}/.steadystate/kubeconfig"
chmod 600 "${SILO}/.steadystate/kubeconfig"
unset TOKEN   # the secret is gone; only the short-lived kubeconfig remains

#   Rancher CLI alternative for step 2:
#   rancher login "${RANCHER_URL}" --token "${TOKEN}"
#   rancher cluster kubeconfig "${CLUSTER_ID}" > "${SILO}/.steadystate/kubeconfig"

# 3. go to work -- steadystate uses the kubeconfig in the silo (targets.json points at it
#    by relative path, so the silo is self-contained)
steadystate --silo gateway-use1 probe all
steadystate --silo gateway-use1 health
```

Run it from `cron` (or your scheduler) on a cadence shorter than the kubeconfig's lifetime, and every
scan operates on a freshly-brokered, short-lived credential — no standing kubeconfig to leak.

## Why this is the right shape

- **steadystate holds no standing credential.** The Rancher token is fetched, used, and `unset` in
  one breath; only the derived kubeconfig touches disk, briefly, `chmod 600`. This is "steadystate
  holds the creds the agent never sees" ([contained-agent](../contained-agent/)) made even tighter —
  it doesn't even *store* a long-lived one.
- **The agent never sees *or* triggers the secret.** It calls `health` / `summary`; the brokering
  happened before the process started, outside the agent's reach. The sole-actuator posture is intact.
- **Rent the vault, don't rebuild it.** Vault / Rancher do this already; the wrapper is
  just glue. steadystate stays out of the secrets-management business.

## The built-in connector — `kubeconfig_from` (for long-running processes)

The wrapper above re-brokers per **run**, which fits cron. A long-running process — `steadystate up`
(the chat listener + sweep) or the MCP server — holds whatever it launched with, so a short-lived
kubeconfig expires mid-session. For those, skip the wrapper and let the target broker **itself**, at
probe time, in `targets.json`:

```json
{
  "prod-gateway": {
    "source": "k8s-live",
    "context": "prod",
    "kubeconfig_from": "akeyless get-secret-value --name /k8s/prod/kubeconfig"
  }
}
```

Any CLI that prints a kubeconfig to stdout works — `akeyless get-secret-value`,
`vault kv get -field=config secret/k8s/prod`, a `rancher`/`gcloud` one-liner, or your own script.
Every probe (every sweep tick of `up`, every chat `probe`, every MCP call) runs the command fresh:
the credential lands in a private temp file, is used for exactly that probe, and is **deleted the
moment the probe finishes**. The standing secret (the vault token) never touches steadystate at
all — it lives in the broker CLI's own auth.

Discipline (the same as authored solutions): the command runs as an **argv, no shell** — pipes and
redirection won't work; wrap any unwrapping (a JSON field, two commands) in a script and point
`kubeconfig_from` at it. Failure is **closed**: a failed/hung/missing broker marks the target
unreachable with the exit code and *stderr* (never stdout — that's the credential), and the probe
simply doesn't run. Output that doesn't look like a kubeconfig is refused, so a vault error message
is never handed to kubectl as creds. `STEADYSTATE_BROKER_TIMEOUT` (default 30s) caps the wait, and
`steadystate targets` marks brokered targets so you see at a glance which credentials are minted
fresh.

## Honest limits

- **The wrapper fits one-shot / scheduled runs; the connector fits long-running ones.** A `cron`
  probe re-brokers every run — keep the wrapper there if you like its explicitness. A long-running
  `up` / `mcp` process should use `kubeconfig_from`, so every probe re-brokers on its own.
- **`kubeconfig_from` is operator intent — review it like code.** It's a command steadystate will
  execute; it lives in the targets registry you commit and review. Nothing live (chat / MCP) can
  author a target, so the only way to plant a broker command is write access to the repo or the
  machine — the same trust the wrapper script already required.
- **Never log the secret.** No `echo "$TOKEN"`, no `set -x` around step 1. `set -euo pipefail` so a
  failed fetch aborts rather than running with stale or empty creds.
- **Least privilege is still the hard limit.** Scope the Rancher token (and the kubeconfig's RBAC) to
  exactly what this silo needs — read-only for an observe silo; only the catalog's verbs for a
  `--write` one. The broker makes the credential *short-lived*; RBAC makes it *small*. Both.

| | |
|---|---|
| **Shape** | a pre-launch wrapper (scheduled runs), or `kubeconfig_from` (long-running `up`/`mcp`) |
| **Secret path** | secrets manager → token (in memory) → a fresh kubeconfig is minted → token discarded |
| **On disk** | only the short-lived kubeconfig (0600) — per run (wrapper) or per probe (connector) |
| **Best for** | wrapper: `cron` / scheduled probes · connector: `up`, the MCP server, the listener |
| **Backstop** | least-privilege RBAC on what the broker hands out |

✅ Either way it rents your existing vault — Vault, Akeyless, Rancher, a cloud CLI. The credential is
short-lived and never persisted beyond its use; the agent never touches it, and the standing secret
never enters steadystate.
