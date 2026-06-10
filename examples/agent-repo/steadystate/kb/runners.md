# CI runners

The shared runner pool is owned by the platform team and runs in each region's `runners` cluster.

## Checking runner health

Ask the bot in the channel — `are the runners ok?` — it answers from the latest sweep of the
`runners` target. `runs nightly-scan.yml` shows whether the scheduled checks passed.

## When the pool is degraded

The documented fix is a redeploy: the bot offers it when it detects the condition (a human
approves), or kick it directly with `dispatch redeploy-runners.yml`. If a redeploy doesn't clear
it, the platform on-call is paged automatically via the incident the bot opens.

## Escalation

Sev-1 (no builds at all): page `platform-oncall`. Anything else: the channel — the bot opens and
routes the ticket.
