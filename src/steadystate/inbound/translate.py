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
from .base import _TOOL_EFFECT, COMMANDS, Command, tool_schema


@dataclass(frozen=True)
class NLResult:
    """The outcome of translating one free-text line. Exactly one of: a read-only ``command`` to
    run now, or a ``message`` to show as-is (an effectful command echoed for confirmation, a
    clarifying question, or a 'couldn't map that'). ``interpreted`` is the canonical command form,
    shown before a read command's output so the operator sees how their words were read."""

    command: Command | None = None
    message: str | None = None
    interpreted: str | None = None


_SYSTEM = (
    "You translate an operator's chat message into exactly ONE steadystate command, OR a single "
    "clarifying question, OR nothing. You may ONLY use a verb from the tool list given -- never "
    "invent a verb or an argument outside it. Resolve a reference like 'the web deployment' to a "
    "fingerprint from the findings/pending list provided (use the shortest unambiguous prefix). "
    'Reply with ONLY JSON: {"verb": <tool name or null>, "argument": <string>, '
    '"argument2": <string>, "flags": [<flag>], "clarify": <a question or empty string>}. '
    "Use clarify (with verb null) when the request is ambiguous; verb null AND empty clarify when "
    "it names no command you can map."
)


def _tool_lines() -> str:
    """The dispatchable verbs as 'name: usage [effect]' lines -- the menu the model picks from,
    built from the same ``tool_schema`` the listener dispatches so it can never drift."""
    return "\n".join(
        f"  {t['name']}: {t['usage']}  [{t['effect']}]" for t in tool_schema()["tools"]
    )


def state_snapshot(state_path: str, *, max_items: int = 25) -> str:
    """A compact view of what's live -- numbered pendings + open findings (short fingerprint +
    title) -- so the model can resolve 'approve the web restart' / 'the crashlooping one' to a real
    fingerprint. '' when there's no store yet. Read-only."""
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
        lines += [
            f"  {f.fingerprint[:12]}  {f.last_severity}  {f.last_title}"
            for f in findings[:max_items]
        ]
    return "\n".join(lines)


def _user_prompt(text: str, snapshot: str) -> str:
    grounding = f"What's live in this cluster now:\n{snapshot}\n\n" if snapshot else ""
    return (
        f"Tool list (name: usage [effect]):\n{_tool_lines()}\n\n"
        f"{grounding}"
        f"Operator message: {text}\n\n"
        "Map it to one command, or ask one clarifying question, or return verb null."
    )


def nl_to_command(
    text: str, actor: str, complete: Callable[[str, str, str], str | None], *, state_path: str = ""
) -> NLResult:
    """Translate one free-text line to an :class:`NLResult`. ``complete(system, user, caller)`` is
    the analyst's LLM seam (so this carries no provider/egress/cost logic of its own). The model can
    only ever NAME a vetted verb -- a reply naming anything else is dropped here, before dispatch.
    A read-only verb is returned ready to run; an effectful one is returned as a confirm ``message``
    (the concrete command for the human to send), never auto-run."""
    from ..reason.llm import _extract_json  # reuse the analyst's lenient JSON extraction

    reply = complete(_SYSTEM, _user_prompt(text, state_snapshot(state_path)), "chat-nl")
    if not reply:
        return NLResult(message="(couldn't reach the model -- type `help` for the exact commands.)")
    data = _extract_json(reply)
    if not data:
        return NLResult(message="I couldn't turn that into a command -- try `help`.")
    verb = data.get("verb")
    if not isinstance(verb, str) or verb not in COMMANDS:
        clarify = data.get("clarify")
        if isinstance(clarify, str) and clarify.strip():
            return NLResult(message=clarify.strip())
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
