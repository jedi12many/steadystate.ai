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
DECLINE = "decline"
HELP = "help"
PENDING = "pending"
PROBE = "probe"
COST = "cost"
MUTE = "mute"
TARGETS = "targets"
HISTORY = "history"
FINDINGS = "findings"
SHOW = "show"
SURFACES_LIST = "surfaces"
SEND = "send"

# The command grammar, in the order ``help`` lists them: verb -> (usage, one-line summary).
# ``help`` renders itself from this table, so a newly added verb is discoverable the moment it
# lands -- the table is the single source of truth for both dispatch and self-documentation.
COMMANDS: dict[str, tuple[str, str]] = {
    HELP: ("help", "list the commands this listener accepts"),
    TARGETS: ("targets", "list the probe targets this listener knows"),
    PENDING: ("pending", "show remediations awaiting approval, with their fingerprints"),
    PROBE: (
        "probe <target>|all [verbose|cost|unmute|deep|json]",
        "check a target's health now -- or `probe all` for the whole fleet; aliases "
        "`scan`/`refresh` (bare = the fleet); `verbose` shows evidence, `unmute` shows muted, "
        "`deep` also scans pod logs, `json` returns the report as JSON",
    ),
    COST: ("cost [day|week]", "show LLM spend -- a rollup, or a day/week trend"),
    FINDINGS: (
        "findings [open|resolved|muted|all] [json]",
        "list remembered findings (fingerprint, status, severity); resolved are hidden by default "
        "-- `findings resolved`/`all` to show them, `open`/`muted` to filter, `json` for JSON",
    ),
    SHOW: (
        "show <fingerprint> [json]",
        "show a finding's captured evidence -- the fields (namespace, cluster, pod count, the "
        "failing pod's last log) plus when it was first/last seen; `json` returns it as JSON",
    ),
    HISTORY: ("history", "show the remediation audit log (newest first)"),
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
    APPROVE: ("approve <fingerprint>", "apply a pending remediation (guardrailed)"),
    DECLINE: ("decline <fingerprint>", "dismiss a pending remediation"),
}
# Verbs that require an argument to mean anything (a fingerprint for approve/decline/mute, a
# target name for probe); the rest take none or an optional one.
_NEEDS_ARGUMENT = frozenset({APPROVE, DECLINE, PROBE, MUTE, SHOW})
# Verbs that need TWO arguments: `send <fingerprint> <surface>`. The surface is the *last* plain
# token, so a natural `send <fp> to servicenow` works (the "to" is ignored as a middle token).
_NEEDS_TWO = frozenset({SEND})
# Verbs that take an *optional* argument (cost's period; findings' status filter); absent it, they
# still dispatch.
_OPTIONAL_ARGUMENT = frozenset({COST, FINDINGS})

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
    TARGETS: (),
    PENDING: (),
    PROBE: (("target", True),),  # a target name, or "all" for the fleet
    COST: (("period", False),),  # day | week, optional
    FINDINGS: (),
    SHOW: (("fingerprint", True),),
    HISTORY: (),
    SURFACES_LIST: (),
    SEND: (("fingerprint", True), ("surface", True)),
    MUTE: (("fingerprint", True),),
    APPROVE: (("fingerprint", True),),
    DECLINE: (("fingerprint", True),),
}
# Each verb's effect on the world -- the guardrail an agent (a Teams Copilot) must respect:
# read-only (no change), state-write (mutes/dismissals -- reversible, no infra), guardrailed-write
# (approve -> applies a remediation through the executor guardrails), external-send (push outward).
_TOOL_EFFECT: dict[str, str] = {
    HELP: "read-only",
    TARGETS: "read-only",
    PENDING: "read-only",
    PROBE: "read-only",  # scans + records findings, never acts on infra
    COST: "read-only",
    FINDINGS: "read-only",
    SHOW: "read-only",
    HISTORY: "read-only",
    SURFACES_LIST: "read-only",
    SEND: "external-send",  # emits a finding to an external alert surface
    MUTE: "state-write",
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
        argument = args[0] if (verb in _OPTIONAL_ARGUMENT and args) else ""
        return Command(verb, actor, argument, flags=flags)
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
