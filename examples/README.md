# Deployment scenarios

steadystate is a stdlib-only Python CLI. You run it as a **scheduled job (or a persistent
listener), close to where the declared state and the observed reality both live**, and it
surfaces drift and malfunction to the alerting you already use.

Each folder here is one **worked scenario** — a narrative walkthrough that wires steadystate into a
real environment. The ready-to-adapt artifacts the scenarios apply (the `Dockerfile`, GitHub
Actions workflow, Kubernetes CronJob / listener / RBAC) live under [`../deploy/`](../deploy/);
the scenarios reference them and add the environment-specific glue.

## Scenarios

| Scenario | Shape | Reach the state via |
|---|---|---|
| [bastion-host](./bastion-host/) | a process on a jump box | a read-only kubeconfig per cluster — nothing in-cluster |
| [ci-terraform](./ci-terraform/) | in CI (pull) | a Terraform plan JSON produced in your pipeline |
| [k8s-cronjob](./k8s-cronjob/) | in-cluster CronJob | a read-only ServiceAccount (the K8s API) |
| [chat-listener](./chat-listener/) | long-lived Deployment | named targets + a chat provider, shared SQLite |
| [fleet-health](./fleet-health/) | listener over many clusters | a dir of kubeconfigs, discovered into targets |

New to steadystate? Start on a **[bastion-host](./bastion-host/)** — run it on a jump box you
already use, deploy nothing into the cluster, and probe the live clusters with `steadystate chat`.
It's the lowest-commitment way to run the **[fleet-health](./fleet-health/)** flow.

## The model

The scan loop is always the same: **collect declared → reconcile against observed → reason
(domain packs + correlation + optional enrichment) → surface → optionally act, behind the
approval gate.** What changes per environment is *where it runs* and *how it reaches the two
states*. Four principles hold across every scenario:

- **steadystate is secrets-agnostic.** It never stores a credential. The *runner* integrates your
  secret manager (Vault, a kubeconfig, your cloud's secret manager, …) and injects creds as env
  vars or files; steadystate consumes the already-authenticated tooling (terraform, kubectl,
  ansible, helm) or reads a token from the env. One less thing to trust.
- **Observe-first.** Default autonomy is **observe** (alert only). Raise a plugin/environment to
  **suggest** (a human approves) or **auto** (self-heals within the guardrails) per the per-plugin
  command manifest (`steadystate commands`) — observe commands run freely, the
  potentially-destructive ones always pass the approval gate.
- **Run it where the state is.** In CI when the plan is a CI artifact; in-cluster when the truth is
  the K8s API; on a central listener when you're reaching out to a fleet.
- **Surface to what you have.** `--to console,slack,teams` for alerts; `prometheus`/`grafana` for
  metrics + annotations; `--enrich prometheus` to escalate a drift whose resource is unhealthy
  *right now*.

**State** — memory (new/recurring/resolved, mute/snooze) and LLM spend — lives in a small SQLite
file (`--state`). Mount a volume so it persists across runs, and **share that one file** between a
scheduled scan and the persistent listener so a chat approval acts on the same pending remediation
a scan recorded.
