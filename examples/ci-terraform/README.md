# ci-terraform — GitHub → Terraform → Azure, secrets in Vault

**Shape: in CI (pull).** The Terraform plan is already produced in your pipeline, so steadystate
just reads it. Vault → Azure auth is the *workflow's* job; steadystate sees only the plan JSON —
no credential ever touches it.

A runnable version of this workflow ships at
[`../../deploy/github-actions/drift.yml`](../../deploy/github-actions/drift.yml) — copy it into
`.github/workflows/` in your IaC repo and adjust the Vault paths and `--to` surfaces.

```yaml
# .github/workflows/drift.yml
name: drift
on:
  schedule: [{ cron: "0 * * * *" }]   # hourly drift sweep
  pull_request:                        # and pre-merge review
jobs:
  scan:
    runs-on: ubuntu-latest
    permissions: { id-token: write, contents: read }   # OIDC -> Vault
    steps:
      - uses: actions/checkout@v4
      - uses: hashicorp/vault-action@v3                 # Vault issues short-lived Azure creds
        with:
          method: jwt
          secrets: |
            azure/creds/terraform  client_id  | ARM_CLIENT_ID ;
            azure/creds/terraform  client_secret | ARM_CLIENT_SECRET
      - uses: hashicorp/setup-terraform@v3
      - run: |
          terraform init
          terraform plan -out tfplan
          terraform show -json tfplan > plan.json
      - run: pipx run steadystate scan plan.json --source terraform --to console,teams
        env:
          TEAMS_WEBHOOK_URL: ${{ secrets.TEAMS_WEBHOOK_URL }}
```

> Tip: `steadystate discover --emit-ci` generates a workflow like this **tailored to the sources it
> finds in your repo** — a good starting point you then add auth to.

| | |
|---|---|
| **Source** | `terraform` (reads the plan JSON) |
| **Domain** | `security-azure` (NSG to Internet → T1190, storage public → T1530, broad role → T1098) |
| **Secrets** | Vault → Azure creds **in the workflow**; steadystate sees none |
| **Surface** | console (the CI log / PR check) + Teams |
| **Act** | `terraform apply` is the plugin's declared destructive command — gate it through `fix` once you raise autonomy |
| **Autonomy** | observe (alert) → suggest (approve in Teams) |

✅ **shipped** — see [`../../deploy/github-actions/drift.yml`](../../deploy/github-actions/drift.yml).
