# deploy/

Ready-to-adapt deployment artifacts. The worked walkthroughs that apply them — and the deployment
model they share — live in [`../examples/`](../examples/).

- **[`../Dockerfile`](../Dockerfile)** — container image (Python + steadystate + kubectl).
  `docker build -t ghcr.io/jedi12many/steadystate:latest .` then push to your registry.
- **[`github-actions/drift.yml`](github-actions/drift.yml)** — GitHub → Terraform → Azure drift
  scan, secrets via Vault ([ci-terraform](../examples/ci-terraform/)). Copy into
  `.github/workflows/` in your IaC repo.
- **[`kubernetes/`](kubernetes/)** — in-cluster CronJob + read-only RBAC, Rancher/Fleet by default
  ([k8s-cronjob](../examples/k8s-cronjob/)).
  `kubectl apply -f kubernetes/rbac.yaml -f kubernetes/cronjob.yaml`.
- **[`kubernetes/listener.yaml`](kubernetes/listener.yaml)** — the **persistent inbound listener**
  (Deployment + Service + Ingress + a targets ConfigMap): the long-lived counterpart to the
  CronJob, so chat can talk *back* — approve/decline, `pending`/`help`, and `probe <target>`
  (Summon). Powers both [chat-listener](../examples/chat-listener/) and
  [fleet-health](../examples/fleet-health/). Needs a public HTTPS endpoint (the Ingress) and the
  provider's signing secret. Apply `rbac.yaml` first (namespace, read-only ServiceAccount, state PVC).

All scanning starts **observe-only** (alert, don't act); the Summon `probe` verb is read-only too.
See [`../examples/`](../examples/) for the autonomy model and how each scenario maps to
steadystate's sources and surfaces. These are templates — adjust paths, secret names, surfaces, and
the schedule for your environment.
