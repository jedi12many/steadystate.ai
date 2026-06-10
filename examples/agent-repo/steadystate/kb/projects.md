# Projects

A **project** is the unit of tenancy: a namespace per cluster, a storage bucket, and quota.

## Requesting a new project

Open a PR against `your-org/tenant-projects` adding one file under `projects/` — copy
[`projects/_template.yaml`](https://github.com/your-org/tenant-projects) and fill in the project
name, owning team, and quota tier. The platform team reviews within one business day; the merge
provisions everything.

## Quota increases

Edit your project's file in the same repo (the `quota:` block) and open a PR. Increases above the
`large` tier need a capacity note in the PR description.

## Decommissioning

Delete the project file in a PR. Storage is retained for 30 days after the merge, then purged.
