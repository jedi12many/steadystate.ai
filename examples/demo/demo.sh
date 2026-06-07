#!/usr/bin/env bash
# steadystate -- the 60-second GitOps demo. Deterministic + offline (a captured terraform plan;
# no cloud, no token). Record it with asciinema or a screen recorder -- see README.md.
#
#   pip install steadystate   (or run from a checkout)
#   ./demo.sh

cd "$(dirname "$0")" || exit 1
DB=".demo.db"
PAUSE="${DEMO_PAUSE:-2}"   # set DEMO_PAUSE=0 for a fast, un-paced run

say()  { printf '\n\033[1;36m# %s\033[0m\n' "$1"; sleep "$PAUSE"; }
run()  { printf '\033[1;32m$ %s\033[0m\n' "$*"; sleep 1; "$@"; sleep "$PAUSE"; }

clear
say "A normal IaC repo -- with steadystate committed right beside it."
run ls steadystate
run cat steadystate/config.toml

say "Someone opened an S3 *logs* bucket to the world (removed its public-access-block)."
say "On the pull request, CI runs one line:"
run steadystate ci || true

say "Blocked. A CRITICAL exposure (MITRE T1530) -- the merge can't land on a hole like that."
say "And steadystate already knows the fix: it's in your committed runbook, signed."
rm -f "$DB"
steadystate scan plan.json --source terraform --state "$DB" >/dev/null 2>&1
FP=$(steadystate findings --state "$DB" 2>/dev/null | grep -oE '^[a-f0-9]{64}' | head -1)
run steadystate show "${FP:0:12}" --state "$DB"   # a unique prefix is enough

say "Detect -> gate the merge -> hand you the documented fix. No cloud creds, no agent, no server."
say "That's steadystate in CI:  git clone  +  a token  +  one line."
rm -f "$DB"
