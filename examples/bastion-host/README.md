# bastion-host — run it on a jump box, nothing in the cluster

**The situation:** you want to try steadystate against your real clusters **without deploying
anything into them**. You already have a Linux bastion / jump host that can reach the clusters (it's
how you `kubectl` in) and holds the kubeconfigs. Run steadystate right there — it's a stdlib-only
CLI, so it's just a process on a VM. Start fully interactive, add a schedule or a listener later if
you want.

This is the lowest-commitment way to run the [fleet-health](../fleet-health/) flow: no in-cluster
ServiceAccount, no CronJob, no manifests — just the binary on a host you already trust.

## 1. Install on the host

```sh
# Python 3.11+; pipx keeps it isolated. kubectl must be on PATH and able to reach your clusters.
pipx install steadystate            # or: pipx install 'steadystate[llm]' for LLM reasoning
steadystate doctor                  # what's configured / missing
```

## 2. Use a read-only kubeconfig (recommended)

Don't point steadystate at your cluster-admin credentials. The live health path only needs
**read** — `get`/`list` on workloads + pods, and `pods/log`. The built-in **`view`** ClusterRole
covers exactly that. Create a read-only ServiceAccount per cluster and put *its* kubeconfig on the
bastion:

```sh
# Run once per cluster (with your admin context), then export a kubeconfig for the SA token.
kubectl create serviceaccount steadystate-ro -n kube-system
kubectl create clusterrolebinding steadystate-ro --clusterrole=view \
  --serviceaccount=kube-system:steadystate-ro
# Mint a kubeconfig that uses the SA token (see your platform's docs for token kubeconfig export),
# save it as ~/.kube/clusters/<cluster>.yaml
```

So even on a shared bastion, steadystate can only *read* — it never holds a credential that can
change a cluster. (`k8s-live` is observe-only anyway; this just makes the *connection* least-privilege.)

## 3. Discover your clusters → targets

```sh
export KUBECONFIG="$(ls -1 ~/.kube/clusters/*.yaml | paste -sd:)"   # merge the read-only configs
steadystate discover --create        # one k8s-live target per context -> ./targets.json
steadystate targets --check          # see your clusters
```

## 4. Run it — interactive first

```sh
steadystate sweep                    # probe every cluster, roll up what's on fire
steadystate scan --target prod-cluster --probe auto   # one cluster, in detail
steadystate chat                     # a local REPL: `probe all`, `probe prod-cluster`, `targets`
```

`steadystate chat` needs **no network endpoint, no provider, no signing** — it drives the same
command grammar the chat providers use, locally. It's the ideal way to exercise the whole thing
from a bastion. State lives in a local SQLite file (`--state`, default `.steadystate/state.db`), so
the sweep is memoryful (new/recurring/resolved) run after run.

## 5. (Optional) schedule it — outbound only, no inbound endpoint

A bastion behind a firewall can still **push** alerts without exposing a port: a cron entry that
scans each cluster to your surface. (The fleet `sweep` is a console digest today — for outward
alerting, scan per target with `--to`; `sweep --to` is a natural follow-up.)

```sh
# /etc/cron.d/steadystate  -- hourly, push each cluster's fires to Slack
0 * * * *  ops  KUBECONFIG=/home/ops/.kube/merged  bash -lc '\
  for ctx in prod-cluster stg-cluster gke-eu-prod; do \
    steadystate scan --target "$ctx" --to slack --state /home/ops/.steadystate/state.db ; \
  done'
```

Set the surface's env var (`SLACK_WEBHOOK_URL` / `TEAMS_WEBHOOK_URL` / …) in the cron environment.
Outbound HTTPS only — nothing listens.

## 6. (Optional) chat-back — the listener as a systemd service

To approve from chat or run `@steadystate probe all` on demand, run the listener as a plain process
— **no Kubernetes needed**:

```ini
# /etc/systemd/system/steadystate-listener.service
[Service]
ExecStart=/usr/local/bin/steadystate listen --from=slack --port=8723 \
  --state=/home/ops/.steadystate/state.db
Environment=STEADYSTATE_TARGETS=/home/ops/targets.json
Environment=KUBECONFIG=/home/ops/.kube/merged
Environment=STEADYSTATE_SLACK_SIGNING_SECRET=...   # the inbound security boundary
User=ops
Restart=on-failure
[Install]
WantedBy=multi-user.target
```

Chat providers POST to a public URL, so inbound chat needs the port reachable over HTTPS — front it
with your reverse proxy, or a tunnel for testing. **The network is not the security boundary:** the
listener verifies every request's signature (HMAC / Ed25519) before acting. If you'd rather not
expose anything, stick to the local `chat` REPL (step 4) and the scheduled push (step 5).

| | |
|---|---|
| **Shape** | a process on a Linux host you already use to reach the clusters — nothing in-cluster |
| **Source** | `k8s-live` (the cluster's own workloads, health-checked) |
| **Secrets** | a read-only (`view`) kubeconfig per cluster, on the host |
| **Surface** | `chat` REPL + `sweep` (interactive) · `scan --target ... --to slack` (scheduled push) · the listener (chat-back) |
| **State** | a local SQLite file — memoryful sweeps with no infra |
| **Act** | none — `k8s-live` is observe-only |

✅ Uses only shipped pieces — no in-cluster footprint. The fastest way to try steadystate against
real clusters before you decide where it should live.
