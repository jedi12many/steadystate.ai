# brokered-creds — no static kubeconfig: broker a short-lived one at launch

**The situation:** mature shops don't leave long-lived kubeconfigs lying on disk. The cluster
credential lives in a secrets manager (**Akeyless**, **Vault**); a cluster manager (**Rancher**)
mints a **short-lived** kubeconfig on demand. You want steadystate to operate the same way — pull the
secret, mint a kubeconfig, use it, and never persist the standing credential.

The lowest-commitment way to do that is a **pre-launch wrapper**: a few lines that broker the
kubeconfig into the [silo](../mcp-copilot/) right before steadystate runs. No new steadystate code,
and the **secret never lands on disk** — only the short-lived kubeconfig it derives.

## The wrapper

```bash
#!/usr/bin/env bash
set -euo pipefail   # fail CLOSED -- never run steadystate with a half-brokered credential

SILO="$HOME/ops/akeyless-use1"
RANCHER_URL="https://rancher.example.com"
CLUSTER_ID="c-m-xxxxxxxx"

# 1. fetch a short-lived Rancher API token from your secrets manager
TOKEN="$(akeyless get-secret-value --name /rancher/api-token)"
#   Vault:  TOKEN="$(vault kv get -field=token secret/rancher/api-token)"

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
steadystate --silo akeyless-use1 probe all
steadystate --silo akeyless-use1 health
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
- **Rent the vault, don't rebuild it.** Akeyless / Vault / Rancher do this already; the wrapper is
  just glue. steadystate stays out of the secrets-management business.

## Honest limits

- **This fits one-shot / scheduled runs.** A `cron` probe re-brokers every run — perfect. But a
  **long-running `steadystate mcp` server** holds the kubeconfig it launched with, so a short-lived
  one will expire mid-session. For that, either restart the server on a schedule, or use a built-in
  *credential connector* (a seam that re-brokers at probe time) — a deliberate future option, not in
  this example.
- **Never log the secret.** No `echo "$TOKEN"`, no `set -x` around step 1. `set -euo pipefail` so a
  failed fetch aborts rather than running with stale or empty creds.
- **Least privilege is still the hard limit.** Scope the Rancher token (and the kubeconfig's RBAC) to
  exactly what this silo needs — read-only for an observe silo; only the catalog's verbs for a
  `--write` one. The broker makes the credential *short-lived*; RBAC makes it *small*. Both.

| | |
|---|---|
| **Shape** | a pre-launch wrapper brokers a short-lived kubeconfig into the silo |
| **Secret path** | secrets manager → token (in memory) → Rancher mints a kubeconfig → token discarded |
| **On disk** | only the short-lived kubeconfig (`chmod 600`); no standing credential |
| **Best for** | `cron` / scheduled probes (re-brokers each run); restart-on-schedule for a live server |
| **Backstop** | least-privilege RBAC on what Rancher hands out |

✅ No new steadystate code — it rents your existing Akeyless/Vault + Rancher. The credential is
short-lived and never persisted; the agent never touches it. (If you later want a long-running server
to re-broker on its own, that's the built-in *credential connector* seam — ask when you need it.)
