"""Natural-language chat: map an operator's free text to ONE vetted chat command, via the LLM.

The deterministic grammar (:func:`command_from_text`) handles anything that already parses -- free,
instant, no egress. This is the fallback for genuinely free-form text ("why is the demo namespace
unhappy?", "restart the web deployment"): ask the model to pick a single verb from the *same*
``tool_schema`` the listener dispatches, fill its args (resolving "the web one" to a fingerprint
from the live findings), and return it. The model **parses, it never executes** -- whatever it
returns runs through the exact same ``run_command`` + guardrails the typed grammar does.

The one safety rule that matters: **effect-tiered confirmation.** A *read-only* verb (probe,
findings, show, ...) runs directly. An *effectful* one (approve/decline/fix/run/mute/snooze/send)
is **never fired from fuzzy text** -- it's echoed back as the concrete command for the human to
confirm by sending it. So the model can suggest a remediation, but only a human (re)typing the
exact command runs it. Off unless an LLM is configured; with none, chat degrades to exactly the
typed grammar it has today. Rides the analyst's ``_complete`` seam (kill switch, honest degrade)."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from ..state import StateStore, filter_findings
from .base import (
    _TOOL_EFFECT,
    APPROVE,
    COMMANDS,
    DECLINE,
    FIX,
    MUTE,
    RUN,
    SEND,
    SHOW,
    SNOOZE,
    UNMUTE,
    Command,
    command_from_text,
    tool_schema,
)

# Verbs whose required argument is a finding fingerprint -- a *reference*, not free text. A natural
# sentence that merely starts with one of these ("show me the findings" -> `show me`) must not be
# run as a command; the fingerprint-shape guard in confident_command() sends it to the model.
# (For `run` the fingerprint is the *second* argument, the first being the action -- handled below.)
_FINGERPRINT_ARG_VERBS = frozenset({SHOW, FIX, MUTE, UNMUTE, SNOOZE, SEND})
# Verbs whose fingerprint is *optional* (a bare `approve`/`decline` acts on the only pending). Bare
# is a confident command; a NON-empty argument, though, must still be reference-shaped -- so "go
# ahead and approve the web fix" ('approve the') falls through to the model instead of (on a
# listener) firing an effectful approve against a bogus reference.
_OPTIONAL_FINGERPRINT_VERBS = frozenset({APPROVE, DECLINE})


def _reference_shaped(arg: str) -> bool:
    """Whether ``arg`` could be a finding reference: an ordinal (`approve 3`) or a hex fingerprint
    prefix (>= 4 hex chars). A plain English word -- 'me', 'the', 'web' -- is neither, which is the
    tell that the line is prose, not a typed command. Pure."""
    low = arg.lower()
    return low.isdigit() or (len(low) >= 4 and all(c in "0123456789abcdef" for c in low))


def confident_command(text: str, actor: str) -> Command | None:
    """The deterministic parse, but only when it's confidently a *typed command* -- the guard on
    the chat REPL's deterministic-first shortcut. ``command_from_text`` scans for the first verb
    anywhere and takes the next token as its argument, so a natural sentence that merely contains a
    verb gets mis-grabbed ('show me the findings' -> ``show me``). When a fingerprint verb's
    reference isn't fingerprint-shaped, decline -- the line then falls through to the model, which
    reads it as English. (The webhook adapters keep the tolerant ``command_from_text`` for typed
    commands; this gates the model fallback in the REPL and the listener.)"""
    command = command_from_text(text, actor)
    if command is None:
        return None
    # `run <action> <fingerprint>`: the fingerprint is the second arg; for the rest it's the first.
    reference = command.argument2 if command.verb == RUN else command.argument
    # Guard a finding reference: required ones always, an optional one only when it's actually
    # present (a bare approve/decline -- no argument -- stays a confident command).
    guarded = command.verb in _FINGERPRINT_ARG_VERBS or command.verb == RUN
    if command.verb in _OPTIONAL_FINGERPRINT_VERBS and command.argument:
        guarded = True
    if guarded and not _reference_shaped(reference):
        return None
    return command


@dataclass(frozen=True)
class NLResult:
    """The outcome of translating one free-text line. Exactly one of: a read-only ``command`` to
    run now, or a ``message`` to show as-is (an effectful command echoed for confirmation, a
    clarifying question, a grounded answer to a question about the cluster, or a 'couldn't map
    that'). ``interpreted`` is the canonical command form, shown before a read command's output so
    the operator sees how their words were read."""

    command: Command | None = None
    message: str | None = None
    interpreted: str | None = None


_SYSTEM = (
    "You are steadystate's chat assistant. Turn an operator's message into exactly ONE of: a "
    "steadystate command to run, a single clarifying question, a short grounded ANSWER to a "
    "question about the cluster, or nothing. Prefer a command when one cleanly does what they ask "
    "(it runs real, deterministic data). Use an answer for a genuine question that no single "
    "command settles -- a 'why', a 'should I', a summary across findings -- answering ONLY from "
    "the live state given below; never invent a fact, and if the answer isn't in that state say "
    "which command would surface it (e.g. `probe`, `show <fp>`). Keep an answer to 1-3 plain "
    "sentences. For a command: you may ONLY use a verb from the tool list -- never invent a verb "
    "or an argument outside it. Use the verb name EXACTLY as listed; do not abbreviate it. For "
    "`run`, the action argument MUST be one of the vetted action names listed verbatim (e.g. "
    "`rollout-restart-workload`, not `restart`). Resolve a reference like 'the web deployment' to "
    "fingerprint from the findings/pending list (shortest unambiguous prefix). Reply with ONLY "
    'JSON: {"verb": <tool name or null>, "argument": <string>, "argument2": <string>, "flags": '
    '[<flag>], "clarify": <a question or empty string>, "answer": <prose or empty string>}. Set '
    "verb null when you are answering or clarifying; verb null with empty clarify AND empty answer "
    "when it names no command and asks nothing you can address."
)


def _tool_lines() -> str:
    """The dispatchable verbs as 'name: usage [effect]' lines -- the menu the model picks from,
    built from the same ``tool_schema`` the listener dispatches so it can never drift."""
    return "\n".join(
        f"  {t['name']}: {t['usage']}  [{t['effect']}]" for t in tool_schema()["tools"]
    )


def _evidence_line(details: dict[str, str], *, max_fields: int = 6, clip: int = 120) -> str:
    """A finding's captured evidence flattened to one compact `k=v; k=v` line (truncated), so the
    model can answer 'why is web crashlooping?' from the real fields (last log, namespace, ...)
    without the full `show` view bloating the prompt. '' when there's no evidence. Pure."""
    items = list(details.items())[:max_fields]
    if not items:
        return ""
    rendered = "; ".join(f"{k}={(v[:clip] + '...') if len(v) > clip else v}" for k, v in items)
    return f"      evidence: {rendered}"


def state_snapshot(state_path: str, *, max_items: int = 25, with_evidence: bool = False) -> str:
    """A compact view of what's live -- numbered pendings + open findings (short fingerprint +
    title) -- so the model can resolve 'approve the web restart' / 'the crashlooping one' to a real
    fingerprint. With ``with_evidence``, each finding also carries a compact line of its captured
    evidence (the `show` fields: namespace, last log, ...), so the model can *answer* a question
    about it, not just name it. '' when there's no store yet. Read-only."""
    if not state_path or not Path(state_path).exists():
        return ""
    with StateStore(state_path) as store:
        pendings = store.all_pending()
        findings = filter_findings(store.all_findings(), "")  # default view: hide resolved
    lines: list[str] = []
    if pendings:
        lines.append("Pending remediations (approve <n>):")
        lines += [
            f"  {i}. {p.fingerprint[:12]}  {p.drift_identity}" for i, p in enumerate(pendings, 1)
        ]
    if findings:
        lines.append("Open findings (fingerprint -- severity -- title):")
        for f in findings[:max_items]:
            lines.append(f"  {f.fingerprint[:12]}  {f.last_severity}  {f.last_title}")
            evidence = _evidence_line(f.details) if with_evidence else ""
            if evidence:
                lines.append(evidence)
    return "\n".join(lines)


def _action_lines() -> str:
    """The vetted catalog actions `run`/`fix` accept -- name + what it does -- so the model fills
    `run`'s action argument with an exact catalog name (`rollout-restart-workload`) instead of an
    abbreviation it invents (`restart`). Built from the same catalog the gate validates against."""
    from ..act.catalog import catalog_menu

    return catalog_menu()


def _user_prompt(text: str, snapshot: str) -> str:
    grounding = f"What's live in this cluster now:\n{snapshot}\n\n" if snapshot else ""
    return (
        f"Tool list (name: usage [effect]):\n{_tool_lines()}\n\n"
        f"Vetted actions for `run`/`fix` (use the exact name):\n{_action_lines()}\n\n"
        f"{grounding}"
        f"Operator message: {text}\n\n"
        "Map it to one command, ask one clarifying question, answer their question from the state "
        "above, or return verb null."
    )


def nl_to_command(
    text: str, actor: str, complete: Callable[[str, str, str], str | None], *, state_path: str = ""
) -> NLResult:
    """Translate one free-text line to an :class:`NLResult`. ``complete(system, user, caller)`` is
    the analyst's LLM seam (so this carries no provider/egress/cost logic of its own). The model can
    only ever NAME a vetted verb -- a reply naming anything else is dropped here, before dispatch.
    A read-only verb is returned ready to run; an effectful one is returned as a confirm ``message``
    (the concrete command for the human to send), never auto-run. When the operator is *asking*
    rather than commanding, the model's grounded prose answer is returned as the ``message``."""
    from ..reason.llm import _extract_json  # reuse the analyst's lenient JSON extraction

    snapshot = state_snapshot(state_path, with_evidence=True)
    reply = complete(_SYSTEM, _user_prompt(text, snapshot), "chat-nl")
    if not reply:
        return NLResult(message="(couldn't reach the model -- type `help` for the exact commands.)")
    data = _extract_json(reply)
    if not data:
        return NLResult(message="I couldn't turn that into a command -- try `help`.")
    verb = data.get("verb")
    if not isinstance(verb, str) or verb not in COMMANDS:
        # Not a command: a clarifying question, a grounded answer, or genuinely nothing we can map.
        clarify = data.get("clarify")
        if isinstance(clarify, str) and clarify.strip():
            return NLResult(message=clarify.strip())
        answer = data.get("answer")
        if isinstance(answer, str) and answer.strip():
            return NLResult(message=answer.strip())
        return NLResult(message="I couldn't map that to a command -- type `help` for the list.")
    raw_arg, raw_arg2, raw_flags = data.get("argument"), data.get("argument2"), data.get("flags")
    argument = raw_arg.strip() if isinstance(raw_arg, str) else ""
    argument2 = raw_arg2.strip() if isinstance(raw_arg2, str) else ""
    flags = frozenset(str(f) for f in raw_flags) if isinstance(raw_flags, list) else frozenset()
    canonical = " ".join(p for p in [verb, argument, argument2] if p)
    if _TOOL_EFFECT.get(verb, "read-only") == "read-only":
        return NLResult(
            command=Command(verb, actor, argument, flags=flags, argument2=argument2),
            interpreted=canonical,
        )
    # Effectful: never fire from fuzzy text -- echo the concrete command for the human to send.
    return NLResult(
        message=f"I read that as:  {canonical}\nSend that to run it (it's a {_TOOL_EFFECT[verb]})."
    )
