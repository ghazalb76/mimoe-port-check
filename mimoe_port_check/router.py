"""Tool routing: ask the model to pick a tool via small JSON, validate it in
code, and fall back to keyword matching if the model's output is invalid.

SmolLM2-360M is small and not reliable at structured output (confirmed by
hand: it drifted off-topic on a plain "say hello" prompt). So the model's
JSON is a suggestion, never trusted directly — every field is validated
against a strict whitelist/schema before any tool runs, and any parse or
validation failure falls back to a keyword-based router over the user's
own text (not the model's output).

Routing investigation (see evals/run_routing_eval.py and NOTES.md): with
few-shot examples written as prose inside the system message (the original
design), the model attempted valid JSON 0/16 times on a varied question set
-- it consistently just answered the question conversationally instead,
even when told "Output exactly: <json>" with nothing else in the prompt.
Restructuring the same examples as real (user, assistant) message turns
below got the model attempting JSON some of the time, though tool choice
within that JSON is still often wrong. This is a real, reproducible
improvement over 0%, but the keyword fallback remains the mechanism this
agent actually relies on for correctness -- see NOTES.md for exact numbers.

_parse_and_validate also strips <think>...</think> reasoning blocks (as
emitted by e.g. Qwen3) before extracting JSON, so a model's visible
reasoning doesn't interfere with finding its actual answer. That alone
wasn't enough for Qwen3-1.7B, though: at max_tokens=60 its <think> block
alone consumed the whole budget, so no JSON was ever reached (confirmed by
raising max_tokens well past 60 and watching it still be mid-thought).
ROUTING_SYSTEM_PROMPT includes the literal directive "/no_think", which
Qwen3 recognizes to skip its reasoning step -- this took it from
consistently truncated mid-thought to reliably answering within the
existing token budget (see NOTES.md for the measured before/after). It's
inert text to models that don't recognize it (e.g. SmolLM2).
"""
import json
import re
from dataclasses import dataclass
from typing import Any

from .client import chat_completion
from .config import Config

WHITELISTED_TOOLS = {"list_ports", "inspect_process", "check_exposure"}

ROUTING_SYSTEM_PROMPT = """You are a tool router for a local security check agent. \
Given the user's question, choose exactly one tool and respond with ONLY a single \
JSON object, no other text. /no_think

Tools:
- list_ports: args {} -- list all listening ports and what process owns each one.
- inspect_process: args {"pid": <integer>} -- get details on one process by its PID.
- check_exposure: args {"port": <integer>} -- check if one specific port is exposed \
to the network or only to localhost."""

# Real (user, assistant) example turns, not prose examples embedded in the
# system message -- see the module docstring for why this structural change
# was made and what it did/didn't fix.
ROUTING_FEW_SHOT_EXAMPLES: list[tuple[str, str]] = [
    ("What's open on my machine?", '{"tool": "list_ports", "args": {}}'),
    ("Tell me about process 512", '{"tool": "inspect_process", "args": {"pid": 512}}'),
    ("Is port 5432 exposed to the network?", '{"tool": "check_exposure", "args": {"port": 5432}}'),
]

_PID_PATTERN = re.compile(r"\b(?:pid|process)\s*#?\s*(\d+)\b", re.IGNORECASE)
_PORT_PATTERN = re.compile(r"\b(?:port|on)\s*#?\s*(\d{1,5})\b", re.IGNORECASE)
_JSON_OBJECT_PATTERN = re.compile(r"\{.*\}", re.DOTALL)

# Some models (e.g. Qwen3) emit a <think>...</think> reasoning block before
# the actual answer. If that reasoning happens to mention any {braces} (it
# often does, when reasoning about "the JSON format"), the greedy
# first-brace-to-last-brace search below would span across it and the real
# answer, producing an invalid combined blob. Stripping complete think
# blocks first keeps JSON extraction scoped to the actual answer.
#
# Not private to this module: agent.py's explain step uses the same model
# and has the same problem (a <think> block would otherwise get printed to
# the user as if it were the explanation), so it reuses this directly rather
# than duplicating the regex.
_THINK_BLOCK_PATTERN = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)


def strip_think_blocks(raw_model_output: str) -> str:
    return _THINK_BLOCK_PATTERN.sub("", raw_model_output)


class RoutingError(ValueError):
    """The model's routing output didn't parse or validate."""


@dataclass
class Route:
    tool: str
    args: dict[str, Any]
    source: str  # "model" or "fallback"


def route(question: str, config: Config, debug: bool = False) -> Route:
    """Ask the model to pick a tool; validate; fall back to keywords on failure.

    debug=True prints the model's raw tool-choice output before parsing, to
    diagnose why a question routed via the model vs. the keyword fallback
    (see evals/run_routing_eval.py, which uses this)."""
    messages = [{"role": "system", "content": ROUTING_SYSTEM_PROMPT}]
    for example_question, example_answer in ROUTING_FEW_SHOT_EXAMPLES:
        messages.append({"role": "user", "content": example_question})
        messages.append({"role": "assistant", "content": example_answer})
    messages.append({"role": "user", "content": question})

    raw = chat_completion(config, messages, temperature=0.0, max_tokens=60)
    if debug:
        print(f"[debug] raw routing output for {question!r}: {raw!r}")

    try:
        tool, args = _parse_and_validate(raw)
        if not _args_grounded_in_question(tool, args, question):
            raise RoutingError(
                f"Model chose {tool} {args}, but that number doesn't appear in the question "
                "-- likely parroting a few-shot example rather than reasoning about this one"
            )
        return Route(tool=tool, args=args, source="model")
    except RoutingError:
        return keyword_fallback(question)


def _parse_and_validate(raw_model_output: str) -> tuple[str, dict[str, Any]]:
    raw_model_output = strip_think_blocks(raw_model_output)
    match = _JSON_OBJECT_PATTERN.search(raw_model_output)
    if not match:
        raise RoutingError("No JSON object found in model output")

    try:
        parsed = json.loads(match.group(0))
    except json.JSONDecodeError as exc:
        raise RoutingError(f"Model output was not valid JSON: {exc}") from exc

    if not isinstance(parsed, dict):
        raise RoutingError("Parsed JSON was not an object")

    tool = parsed.get("tool")
    if tool not in WHITELISTED_TOOLS:
        raise RoutingError(f"Tool '{tool}' is not whitelisted")

    args = parsed.get("args", {})
    if not isinstance(args, dict):
        raise RoutingError("'args' was not an object")

    if tool == "list_ports":
        return tool, {}

    if tool == "inspect_process":
        pid = _coerce_int(args.get("pid"))
        if pid is None or pid <= 0:
            raise RoutingError("inspect_process requires a positive integer 'pid'")
        return tool, {"pid": pid}

    if tool == "check_exposure":
        port = _coerce_int(args.get("port"))
        if port is None or not (1 <= port <= 65535):
            raise RoutingError("check_exposure requires an integer 'port' in 1-65535")
        return tool, {"port": port}

    raise RoutingError(f"Unhandled tool '{tool}'")  # unreachable given the whitelist check


_GROUNDED_PORT_PATTERN = re.compile(r"\bports?\b\s*#?\s*(\d{1,5})\b", re.IGNORECASE)


def _args_grounded_in_question(tool: str, args: dict[str, Any], question: str) -> bool:
    """A port/pid the model chose must appear in the *matching role* in the
    user's own question, not just anywhere in it. Observed live: "tell me
    about process 12977" -- a real number, but a PID reference -- got
    routed to check_exposure/port=12977; the old check (any digit match
    anywhere) let that through since 12977 genuinely appears in the
    question. A port is only grounded if it directly follows "port"/
    "ports"; a pid only if it directly follows "pid"/"process" (reusing
    _PID_PATTERN, the same rule keyword_fallback already uses). list_ports
    takes no args, so it's always grounded."""
    if tool == "list_ports":
        return True

    if tool == "check_exposure":
        return str(args.get("port")) in _GROUNDED_PORT_PATTERN.findall(question)

    if tool == "inspect_process":
        return str(args.get("pid")) in _PID_PATTERN.findall(question)

    return False


def _coerce_int(value: Any) -> int | None:
    """Accept a real int, or a digit-only string (models often quote numbers)."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().lstrip("-").isdigit():
        return int(value.strip())
    return None


def keyword_fallback(question: str) -> Route:
    """Deterministic routing over the user's own text, used when model output is invalid."""
    pid_match = _PID_PATTERN.search(question)
    if pid_match:
        return Route(tool="inspect_process", args={"pid": int(pid_match.group(1))}, source="fallback")

    port_match = _PORT_PATTERN.search(question)
    if port_match:
        return Route(tool="check_exposure", args={"port": int(port_match.group(1))}, source="fallback")

    return Route(tool="list_ports", args={}, source="fallback")
