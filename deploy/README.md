# deploy/

Ready-to-adapt deployment artifacts for the examples in [../DEPLOYMENT.md](../DEPLOYMENT.md).

- **[`../Dockerfile`](../Dockerfile)** — container image (Python + steadystate + kubectl).
  `docker build -t ghcr.io/jedi12many/steadystate:latest .` then push to your registry.
- **[`github-actions/drift.yml`](github-actions/drift.yml)** — Example 1: GitHub → Terraform →
  Azure drift scan, secrets via Vault. Copy into `.github/workflows/` in your IaC repo.
- **[`kubernetes/`](kubernetes/)** — Example 2: in-cluster CronJob + read-only RBAC
  (Rancher/Fleet by default). `kubectl apply -f kubernetes/rbac.yaml -f kubernetes/cronjob.yaml`.

All start **observe-only** (alert, don't act). See DEPLOYMENT.md for the autonomy model and how
each maps to steadystate's sources and surfaces. These are templates — adjust paths, secret
names, surfaces, and the schedule for your environment.
