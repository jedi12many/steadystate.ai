"""The inbound seam: turn a signed chat-provider webhook into an operator Command.

This is the bidirectional half of the surface seam. Outbound Surfaces (notify/) push
Alerts out; an InboundAdapter takes an operator's reply back -- a button click, a slash
command, an @mention -- parses it into a provider-agnostic ``Command``, and runs it through
the shared cores in server.py. A new chat provider (Slack, Discord, Teams, an email gateway)
is a plugin here, NOT a fork of the listener: implement the four provider-specific steps
below and register one line.

The steps are deliberately small and provider-shaped so very different protocols fit the
same shell: Slack signs with HMAC and has no handshake; Discord signs with Ed25519 and
must answer a PING with a PONG before it will deliver any interaction.

The ``Command`` grammar is shared, so adding a verb is one entry in ``COMMANDS`` (and ``help``
lists it automatically) rather than a change in every adapter. An operator who didn't set up
the deployment can type ``help`` to discover what this listener accepts, and ``pending`` to see
what's actually awaiting them -- the two read-only commands that make the rest usable.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

# The verbs the listener understands. Kept as plain strings and provider-agnostic on purpose:
# every adapter parses its own payload shape down to one of these, so the cores never see a
# vendor field. approve/decline act (and carry a fingerprint); help/pending are read-only.
APPROVE = "approve"
ASK = "ask"
DECLINE = "decline"
DISPATCH = "dispatch"
RUNS = "runs"
HELP = "help"
PENDING = "pending"
SUMMARY = "summary"
PROBE = "probe"
COST = "cost"
MUTE = "mute"
UNMUTE = "unmute"
SNOOZE = "snooze"
TARGETS = "targets"
HISTORY = "history"
HOLD = "hold"
LEARN = "learn"
CHECKS = "checks"
ADD_CHECK = "add-check"
SOLUTIONS = "solutions"
ADD_SOLUTION = "add-solution"
VOUCH = "vouch"
SMOKE = "smoke"
HEALTH = "health"
POSTURE = "posture"
METRICS = "metrics"
FINDINGS = "findings"
SHOW = "show"
ANALYZE = "analyze"
SURFACES_LIST = "surfaces"
SEND = "send"
FIX = "fix"
RUN = "run"
ACTIONS_LIST = "actions"

# The command grammar, in the order ``help`` lists them: verb -> (usage, one-line summary).
# ``help`` renders itself from this table, so a newly added verb is discoverable the moment it
# lands -- the table is the single source of truth for both dispatch and self-documentation.
COMMANDS: dict[str, tuple[str, str]] = {
    HELP: ("help", "list the commands this listener accepts"),
    SUMMARY: (
        "summary",
        "a one-glance status -- open findings by severity, what's pending your approval, the "
        "homeostat's posture, and the single worst thing right now",
    ),
    ASK: (
        "ask <question>",
        "answer a question from the team's committed knowledge base (steadystate/kb/*.md) -- "
        "'how do I request a new project?', 'what services do you offer?' -- the Tier-1 half of "
        "chat: process/how-to answers come from the docs (source cited), live answers from "
        "summary/health/findings",
    ),
    TARGETS: ("targets", "list the probe targets this listener knows"),
    PENDING: ("pending", "show remediations awaiting approval, with their fingerprints"),
    PROBE: (
        "probe <target>|all [verbose|cost|unmute|deep|json]",
        "check a target's health now -- or `probe all` for the whole fleet; aliases "
        "`scan`/`refresh` (bare = the fleet); `verbose` shows evidence, `unmute` shows muted, "
        "`deep` also scans pod logs + node disk %, `json` returns the report as JSON",
    ),
    COST: ("cost [day|week]", "show LLM spend -- a rollup, or a day/week trend"),
    FINDINGS: (
        "findings [open|resolved|muted|all] [keyword] [json]",
        "list remembered findings (fingerprint, status, severity); resolved hidden by default "
        "(`resolved`/`all` to show, `open`/`muted` to filter). Add a keyword to grep them in chat "
        "-- `findings web`, `findings all timeout` (matches title/evidence). `json` for JSON",
    ),
    SHOW: (
        "show <fingerprint> [json]",
        "show a finding's captured evidence -- the fields (namespace, cluster, pod count, the "
        "failing pod's last log) plus when it was first/last seen; `json` returns it as JSON",
    ),
    ANALYZE: (
        "analyze <fingerprint>",
        "grounded root-cause analysis of a captured crash/panic -- root cause, the call chain, the "
        "smoking gun, the trigger, the operational facts -- anchored to the captured evidence (the "
        "stack trace), told to cite it and never invent. Needs an LLM",
    ),
    HISTORY: ("history", "show the remediation audit log (newest first)"),
    HOLD: (
        "hold",
        "the homeostat's posture -- each reflex's earned autonomy, what's NOT holding "
        "(recurring fixes), and whether the decider is granted autonomy",
    ),
    LEARN: (
        "learn",
        "what steadystate has learned from findings that resolved on their own (out-of-band) -- "
        "categories to adopt a reflex for, or that self-heal",
    ),
    HEALTH: (
        "health",
        "the one-glance 'is it actually working?' verdict (WORKING | DEGRADED | DOWN) -- runs the "
        "`http` smoke tests live and folds in the live malfunctions. Add a workload name to scope "
        "to it and correlate (smoke + symptom + the drift that likely caused it). The headline Q",
    ),
    POSTURE: (
        "posture",
        "the honest answer to 'am I bounded by your gates?' -- what steadystate enforces on its "
        "own path (catalog + bound + audit), where that ends (it can't constrain your other tools, "
        "e.g. a shell), and how to make it a real boundary (the sole-actuator setup)",
    ),
    METRICS: (
        "metrics",
        "the live metric readings from your monitoring (Prometheus / ...) -- the agent's metric "
        "context alongside steadystate's findings. Configure {name: query} in "
        "STEADYSTATE_METRIC_QUERIES; steadystate rents the monitoring, never reimplements it",
    ),
    RUNS: (
        "runs [workflow]",
        "recent GitHub Actions runs in the agent's workflows repo -- status, branch, when, link; "
        "name a workflow file to scope (`runs nightly-scan.yml`). The repo's own automation as "
        "the agent's instruments: 'did the nightly scan pass?' answered from real run history",
    ),
    DISPATCH: (
        "dispatch <workflow>[@ref] [input=value ...]",
        "kick off a GitHub Actions workflow in the agent's workflows repo NOW -- a fresh run "
        "instead of waiting for its cron (`dispatch nightly-scan.yml`). Structurally scoped to "
        "that one repo (committing a workflow there is the vetting); audited with who asked; "
        "needs a token with actions:write",
    ),
    CHECKS: ("checks", "list this wall's custom health checks (.steadystate/checks.json)"),
    SOLUTIONS: ("solutions", "list this wall's authored runbook of problem->fix entries"),
    SMOKE: (
        "smoke",
        "run this wall's `http` smoke tests live and report PASS/FAIL each -- the affirmative "
        "'is it actually working?' answer (exercises the endpoint), and a close-the-loop verify",
    ),
    ADD_CHECK: (
        "add-check",
        "define a custom health check from a JSON object -- validated against the vetted schema "
        "(read kind + condition + emit), then stored in this wall. Authors observe-only checks; "
        "never code. e.g. is the mailer routing mail, is the proxy running, is a pod's CPU too low",
    ),
    ADD_SOLUTION: (
        "add-solution",
        "add an authored fix to this wall's runbook from a JSON object -- a problem->fix entry "
        "(for/match + a command/playbook/reboot), signed by an author. Authored live it lands a "
        "DRAFT (surfaced, not runnable); a human `vouch`es it. Acting passes the bound + audit",
    ),
    VOUCH: (
        "vouch <name>",
        "vouch a DRAFTED solution by name -- the gate that promotes a live/agent-drafted fix "
        "to a runnable one (offered against a matching finding). Writes the runbook; needs write",
    ),
    SURFACES_LIST: (
        "surfaces",
        "list the alert surfaces you can `send` to, and which are configured",
    ),
    SEND: (
        "send <fingerprint> <surface>",
        "dispatch one finding to an alert surface now (e.g. `send <fp> servicenow`) -- ad-hoc "
        "escalation, no full scan",
    ),
    MUTE: (
        "mute <fingerprint>",
        "silence a finding on future scans -- a single fp, or a correlated group's `mute-all` fp "
        "to silence the whole group at once",
    ),
    UNMUTE: (
        "unmute <fingerprint>",
        "lift a mute or snooze -- the finding surfaces again on the next scan (prefix ok)",
    ),
    SNOOZE: (
        "snooze <fingerprint> <duration>",
        "silence a finding for a while, then let it return -- e.g. `snooze <fp> 2d` "
        "(units h/m/d/w; a bare number is days)",
    ),
    FIX: (
        "fix <fingerprint>",
        "apply the OFFERED fix for a finding (e.g. roll-restart a wedged workload) -- a vetted, "
        "bounded action, run through the guardrail + audited",
    ),
    RUN: (
        "run <action> <fingerprint>",
        "run a specific vetted action against a finding (e.g. `run rollout-restart-workload <fp>`) "
        "-- when you want to pick the action rather than take the offered one; see `actions`",
    ),
    ACTIONS_LIST: (
        "actions",
        "list the vetted actions you can `fix`/`run` -- name, what it does, and its blast radius",
    ),
    APPROVE: (
        "approve [<n>|<fingerprint>] [<confirm>]",
        "apply a pending remediation (guardrailed) -- by its number from `pending`, a fingerprint "
        "(prefix ok), or bare when only one is pending; for break-glass `<confirm>` is the target "
        "name you type to confirm (e.g. `approve <fp> worker-1234`)",
    ),
    DECLINE: (
        "decline [<n>|<fingerprint>]",
        "dismiss a pending remediation -- by number, fingerprint (prefix ok), or the only one",
    ),
}
# Verbs that require an argument to mean anything (a fingerprint for mute, a target name for probe);
# the rest take none or an optional one.
_NEEDS_ARGUMENT = frozenset({PROBE, MUTE, UNMUTE, SHOW, FIX, VOUCH})
# Verbs that need TWO arguments: `send <fingerprint> <surface>`, `run <action> <fingerprint>`,
# `snooze <fingerprint> <duration>`. The second plain token is the *last* one, so a natural filler
# word in the middle is ignored.
_NEEDS_TWO = frozenset({SEND, RUN, SNOOZE})
# Verbs that take an *optional* argument (cost's period; findings' status filter; runs' workflow
# scope); absent it, they still dispatch. approve/decline live here too: a bare `approve` resolves
# to the sole pending, and the argument may be an ordinal (`approve 2`) or a fingerprint prefix --
# the server resolves it.
_OPTIONAL_ARGUMENT = frozenset({COST, FINDINGS, APPROVE, DECLINE, RUNS})
# Verbs that take an *optional second* token after their required first: `approve <fp> [<token>]`,
# where the token is the break-glass confirm target (e.g. the node name for a `delete-node`).
_OPTIONAL_SECOND = frozenset({APPROVE})

# Muscle-memory synonyms for `probe` -- re-running a probe is what "refresh / capture state" means
# (re-read live state and record the findings). Bare (no target) refreshes the whole fleet, so
# `refresh` alone == `probe all`; with a target, `refresh <t>` == `probe <t>`.
_VERB_ALIASES = {"scan": PROBE, "refresh": PROBE}

# Recognized modifier flags (with or without dashes) -> the canonical name a command checks for.
# `verbose` = show the full evidence; `cost` = the per-caller spend breakdown; `unmute` = probe
# bypasses mute/snooze suppression this run; `deep` = also scan pod logs for errors (costlier);
# `json` = return the result as JSON, not prose (for an agent -- probe/show/findings). One row each.
_FLAG_ALIASES = {
    "unmute": "unmute", "--unmute": "unmute",
    "cost": "cost", "--cost": "cost",
    "verbose": "verbose", "--verbose": "verbose", "-v": "verbose",
    "deep": "deep", "--deep": "deep",
    "json": "json", "--json": "json",
}  # fmt: skip


@dataclass(frozen=True)
class Command:
    """A parsed operator instruction: a verb, who sent it, an optional argument, and any flags.

    The argument is the pending remediation's fingerprint for approve/decline/mute, or the target
    name for probe; many verbs take none. ``flags`` is the set of recognized modifiers present
    (e.g. ``{"verbose"}``, ``{"unmute", "cost"}``). Provider-agnostic by design -- the cores in
    server.py act on this, never on a Slack/Discord/Teams payload."""

    verb: str  # one of COMMANDS
    actor: str  # who sent it -- recorded for the audit trail
    argument: str = ""  # the fingerprint for approve/decline/mute, the target for probe; else ""
    flags: frozenset[str] = frozenset()  # canonical modifier flags present (see _FLAG_ALIASES)
    argument2: str = ""  # the second positional, for two-arg verbs (`send <fp> <surface>`)


def render_help() -> str:
    """The text an operator sees for ``help``: the command grammar, generated from ``COMMANDS``
    so it can never drift from what the listener actually dispatches."""
    lines = ["steadystate -- commands this listener accepts:"]
    lines += [f"  {usage}  --  {summary}" for usage, summary in COMMANDS.values()]
    return "\n".join(lines)


# The positional argument(s) each verb takes, for the machine tool schema -- (name, required).
# A two-arg verb (send) lists both; a verb with an optional arg marks it not-required.
_TOOL_ARGS: dict[str, tuple[tuple[str, bool], ...]] = {
    HELP: (),
    SUMMARY: (),
    ASK: (("question", True),),  # the question, free text -- taken verbatim
    TARGETS: (),
    PENDING: (),
    HEALTH: (("workload", False),),  # optional: scope the verdict to one workload + correlate
    POSTURE: (),
    METRICS: (),
    RUNS: (("workflow", False),),  # optional: scope to one workflow file
    DISPATCH: (("workflow", True), ("inputs", False)),  # the file[@ref]; then input=value pairs
    CHECKS: (),
    SOLUTIONS: (),
    SMOKE: (),
    ADD_CHECK: (("check", True),),  # one arg: the check as a JSON object/string
    ADD_SOLUTION: (("solution", True),),  # one arg: the solution as a JSON object/string
    VOUCH: (("name", True),),  # one arg: the drafted solution's name
    PROBE: (("target", True),),  # a target name, or "all" for the fleet
    COST: (("period", False),),  # day | week, optional
    FINDINGS: (("filter", False),),  # an optional status word and/or keyword to grep
    SHOW: (("fingerprint", True),),
    ANALYZE: (("fingerprint", True),),
    HISTORY: (),
    HOLD: (),
    LEARN: (),
    SURFACES_LIST: (),
    SEND: (("fingerprint", True), ("surface", True)),
    FIX: (("fingerprint", True),),
    RUN: (("action", True), ("fingerprint", True)),
    ACTIONS_LIST: (),
    MUTE: (("fingerprint", True),),
    UNMUTE: (("fingerprint", True),),
    SNOOZE: (("fingerprint", True), ("duration", True)),
    APPROVE: (("fingerprint", False),),  # optional: a number, a prefix, or bare (the only pending)
    DECLINE: (("fingerprint", False),),
}
# Each verb's effect on the world -- the guardrail an agent (a Teams Copilot) must respect:
# read-only (no change), state-write (mutes/dismissals -- reversible, no infra), guardrailed-write
# (approve -> applies a remediation through the executor guardrails), external-send (push outward).
_TOOL_EFFECT: dict[str, str] = {
    HELP: "read-only",
    SUMMARY: "read-only",
    ASK: "read-only",  # reads the committed docs + an LLM egress (like analyze); never mutates
    HEALTH: "read-only",  # runs smoke (GET/HEAD) + reads findings -- active but never mutates
    POSTURE: "read-only",  # a self-report; an agent can always ask "am I bounded?" (no grant)
    METRICS: "read-only",  # reads your monitoring (GET) -- consumes it, never mutates
    RUNS: "read-only",  # reads Actions run history (GET) -- never mutates
    # Kicking a workflow sends an event to GitHub; what runs is the agent repo's own committed
    # automation. Effectful -> NL echoes it for a human to confirm, and MCP needs the write grant.
    DISPATCH: "external-send",
    CHECKS: "read-only",
    SOLUTIONS: "read-only",  # lists the authored runbook -- showing a fix isn't running it
    SMOKE: "read-only",  # active (GET/HEAD probes) but idempotent -- reads, never mutates
    ADD_CHECK: "state-write",  # writes the wall's checks.json -- reversible config, no infra
    ADD_SOLUTION: "state-write",  # writes the wall's solutions.json -- reversible config, no infra
    VOUCH: "state-write",  # flip a draft to vouched (runbook write) -- needs write, not author
    TARGETS: "read-only",
    PENDING: "read-only",
    PROBE: "read-only",  # scans + records findings, never acts on infra
    COST: "read-only",
    FINDINGS: "read-only",
    SHOW: "read-only",
    ANALYZE: "read-only",  # reads a finding + reasons (an LLM egress); never mutates infra/state
    HISTORY: "read-only",
    HOLD: "read-only",
    LEARN: "read-only",
    SURFACES_LIST: "read-only",
    SEND: "external-send",  # emits a finding to an external alert surface
    FIX: "guardrailed-write",  # applies the offered vetted action (allow-pattern + bound + audit)
    RUN: "guardrailed-write",  # applies a chosen vetted action (allow-pattern + bound + audit)
    ACTIONS_LIST: "read-only",
    MUTE: "state-write",
    UNMUTE: "state-write",
    SNOOZE: "state-write",
    APPROVE: "guardrailed-write",  # applies a pending remediation (executor-guardrailed)
    DECLINE: "state-write",
}


def tool_schema() -> dict:
    """steadystate's chat verbs as a machine tool/function-call schema -- so an LLM agent (e.g. a
    Teams Copilot) can register them as tools and *drive* steadystate, not just read its output.
    Built from the same ``COMMANDS`` table ``help`` renders, so the schema can never drift from
    what the listener dispatches; each tool carries its args, its ``effect`` (the guardrail the
    agent must respect), and -- for ``probe`` -- its modifier flags. Pure."""
    tools = []
    for verb, (usage, summary) in COMMANDS.items():
        tool: dict = {
            "name": verb,
            "summary": summary,
            "usage": usage,
            "args": [{"name": name, "required": req} for name, req in _TOOL_ARGS[verb]],
            "effect": _TOOL_EFFECT[verb],
        }
        if verb == PROBE:  # the only verb with modifier flags today
            tool["flags"] = sorted(set(_FLAG_ALIASES.values()))
        tools.append(tool)
    return {"version": 1, "tools": tools}


def command_from_text(text: str, actor: str) -> Command | None:
    """Parse a free-text instruction (a Teams @mention or a Slack slash command) into a Command,
    or None if no known verb appears. Scans tokens for the first verb (resolving a synonym like
    ``scan``/``refresh`` to its canonical verb), then splits the rest into recognized flags
    (verbose / cost / unmute) and plain tokens; the first plain token is the argument. A verb that
    *requires* an argument is skipped when none follows -- except a bare probe-synonym, which means
    the whole fleet (``refresh`` == ``probe all``)."""
    tokens = text.split()
    for index, token in enumerate(tokens):
        low = token.lower()
        is_alias = low in _VERB_ALIASES
        verb = _VERB_ALIASES.get(low, low)
        if verb not in COMMANDS:
            continue
        rest = tokens[index + 1 :]
        if verb == ASK:
            # The question is free text, taken VERBATIM -- no flag/argument splitting, so a
            # question containing a flag word ("how much does the llm cost?") isn't eaten.
            if rest:
                return Command(ASK, actor, " ".join(rest))
            continue  # a bare `ask` carries no question -> not actionable
        if verb == DISPATCH:
            # `dispatch <workflow> [input=value ...]`: the inputs ride VERBATIM in argument2 --
            # no flag extraction, so an input value that happens to be a flag word survives.
            if rest:
                return Command(DISPATCH, actor, rest[0], argument2=" ".join(rest[1:]))
            continue  # a bare `dispatch` names no workflow -> not actionable
        flags = frozenset(_FLAG_ALIASES[t.lower()] for t in rest if t.lower() in _FLAG_ALIASES)
        args = [t for t in rest if t.lower() not in _FLAG_ALIASES]
        if verb in _NEEDS_TWO:
            if len(args) >= 2:  # `send <fp> <surface>` (or `send <fp> to <surface>`)
                return Command(verb, actor, args[0], flags=flags, argument2=args[-1])
            continue  # both parts required -> not actionable
        if verb in _NEEDS_ARGUMENT:
            if args:
                return Command(verb, actor, args[0], flags=flags)
            if is_alias:  # bare `scan`/`refresh` -> refresh the whole fleet (probe all)
                return Command(verb, actor, "all", flags=flags)
            continue  # a required argument is absent (e.g. bare `probe`) -> not actionable
        # Optional-argument verbs (cost/findings) and approve/decline, which may be bare. `findings`
        # takes a status word and/or a free-text keyword filter, joined here -- the handler splits
        # them (`findings resolved timeout`). approve takes an OPTIONAL second token -- the
        # break-glass confirm target (`approve <fp> <name>`).
        if verb == FINDINGS:
            argument = " ".join(args)
        else:
            argument = args[0] if (verb in _OPTIONAL_ARGUMENT and args) else ""
        second = args[1] if (verb in _OPTIONAL_SECOND and len(args) >= 2) else ""
        return Command(verb, actor, argument, flags=flags, argument2=second)
    return None


@runtime_checkable
class InboundAdapter(Protocol):
    """A chat provider's inbound half. Mirrors the outbound Surface seam (notify/__init__.py):
    register a factory in INBOUND and `listen --from <name>` dispatches to it."""

    name: str
    content_type: str  # the Content-Type the provider expects on the reply

    def ready(self) -> str | None:
        """None when configured (signing secret / public key present), else a human-readable
        reason the CLI turns into a clean error -- so a misconfigured listener fails loudly at
        startup, not silently on the first click."""
        ...

    def verify(self, headers: Mapping[str, str], body: str) -> bool:
        """True iff the request is an authentic, fresh call from the provider. THE security
        boundary -- a forged or replayed request must never reach a core."""
        ...

    def handshake(self, body: str) -> bytes | None:
        """A protocol reply that isn't a Command (e.g. Discord PING -> PONG), or None to proceed
        to parse(). Providers without a handshake (Slack interactivity) return None."""
        ...

    def parse(self, body: str) -> Command | None:
        """The operator's command, or None when the payload isn't a recognized one of ours."""
        ...

    def respond(self, message: str) -> bytes:
        """Wrap an outcome message as the provider's reply body."""
        ...

    # Optional, duck-typed (NOT declared as a protocol method, so an adapter without it -- e.g.
    # Discord's structured slash commands -- still satisfies InboundAdapter): an adapter MAY define
    #     def message(self, body: str) -> tuple[str, str] | None
    # returning the operator's *free text* + actor for a slash command / @mention. The listener
    # uses it for the natural-language fallback when `parse` finds no typed command; None (or no
    # method) means no free text, so the deterministic `parse` path stands.
