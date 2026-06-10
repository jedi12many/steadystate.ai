# Services we offer

The platform team provides shared infrastructure for product teams:

- **Managed Kubernetes clusters** — per-region, with tenant namespaces. See
  [projects.md](projects.md) to get one.
- **CI runners** — the shared runner pool every repo builds on. Ownership and escalation in
  [runners.md](runners.md).
- **Object storage** — per-project buckets, provisioned with the project.
- **Outbound proxy** — all egress goes through the proxy; new destinations are allowlisted by
  request (ask the bot: `request proxy-domain domain=<your-domain>`).

## Getting started

New team? Start with a project ([projects.md](projects.md)) — everything else hangs off it.
Questions this doc doesn't answer: ask in the platform channel; the bot answers from these docs
and can check live status (`summary`, `health`).
