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

# The command grammar, in the order ``help`` lists them: verb -> (usage, one-line summary).
# ``help`` renders itself from this table, so a newly added verb is discoverable the moment it
# lands -- the table is the single source of truth for both dispatch and self-documentation.
COMMANDS: dict[str, tuple[str, str]] = {
    HELP: ("help", "list the commands this listener accepts"),
    PENDING: ("pending", "show remediations awaiting approval, with their fingerprints"),
    PROBE: (
        "probe <target> [unmute]",
        "scan a named target now; honors mutes (`unmute` shows all)",
    ),
    COST: ("cost [day|week]", "show LLM spend -- a rollup, or a day/week trend"),
    MUTE: ("mute <fingerprint>", "silence a finding (e.g. a benign probe result) on future scans"),
    APPROVE: ("approve <fingerprint>", "apply a pending remediation (guardrailed)"),
    DECLINE: ("decline <fingerprint>", "dismiss a pending remediation"),
}
# Verbs that require an argument to mean anything (a fingerprint for approve/decline/mute, a
# target name for probe); help/pending take none.
_NEEDS_ARGUMENT = frozenset({APPROVE, DECLINE, PROBE, MUTE})
# The bypass flag (probe): show muted/snoozed findings too, for this one run.
_UNMUTE_FLAGS = frozenset({"unmute", "--unmute"})
# Verbs that take an *optional* argument (cost's period); absent it, they still dispatch.
_OPTIONAL_ARGUMENT = frozenset({COST})


@dataclass(frozen=True)
class Command:
    """A parsed operator instruction: a verb, who sent it, an optional argument, and a flag.

    The argument is the pending remediation's fingerprint for approve/decline, or the target name
    for probe; the read-only help/pending take none. ``bypass`` is probe's ``unmute`` -- show
    muted/snoozed findings too for this run. Provider-agnostic by design -- the cores in server.py
    act on this, never on a Slack/Discord/Teams payload."""

    verb: str  # one of COMMANDS
    actor: str  # who sent it -- recorded for the audit trail
    argument: str = ""  # the fingerprint for approve/decline, the target for probe; else ""
    bypass: bool = False  # probe `unmute`: skip mute/snooze suppression for this run


def render_help() -> str:
    """The text an operator sees for ``help``: the command grammar, generated from ``COMMANDS``
    so it can never drift from what the listener actually dispatches."""
    lines = ["steadystate -- commands this listener accepts:"]
    lines += [f"  {usage}  --  {summary}" for usage, summary in COMMANDS.values()]
    return "\n".join(lines)


def command_from_text(text: str, actor: str) -> Command | None:
    """Parse a free-text instruction (a Teams @mention or a Slack slash command) into a Command,
    or None if no known verb appears. Scans tokens for the first verb; approve/decline/probe take
    the first following non-flag token as their argument (and are skipped if none follows),
    help/pending take none. A trailing ``unmute`` / ``--unmute`` sets ``bypass`` (probe)."""
    tokens = text.split()
    for index, token in enumerate(tokens):
        verb = token.lower()
        if verb in _NEEDS_ARGUMENT:
            rest = tokens[index + 1 :]
            args = [t for t in rest if t.lower() not in _UNMUTE_FLAGS]
            if args:  # the first non-flag token is the argument; an `unmute` token sets bypass
                return Command(verb, actor, args[0], bypass=len(args) < len(rest))
        elif verb in COMMANDS:
            # cost takes an optional period (day|week); help/pending take nothing.
            if verb in _OPTIONAL_ARGUMENT and index + 1 < len(tokens):
                return Command(verb, actor, tokens[index + 1])
            return Command(verb, actor)
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
