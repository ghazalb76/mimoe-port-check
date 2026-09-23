"""Tool routing: ask the model to pick a tool via small JSON, validate it in
code, and fall back to keyword matching if the model's output is invalid.

SmolLM2-360M is small and not reliable at structured output (confirmed by
hand: it drifted off-topic on a plain "say hello" prompt). So the model's
JSON is a suggestion, never trusted directly — every field is validated
against a strict whitelist/schema before any tool runs, and any parse or
validation failure falls back to a keyword-based router over the user's
own text (not the model's output).
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
JSON object, no other text.

Tools:
- list_ports: args {} -- list all listening ports and what process owns each one.
- inspect_process: args {"pid": <integer>} -- get details on one process by its PID.
- check_exposure: args {"port": <integer>} -- check if one specific port is exposed \
to the network or only to localhost.

Examples:
Q: What's open on my machine?
{"tool": "list_ports", "args": {}}

Q: Tell me about process 512
{"tool": "inspect_process", "args": {"pid": 512}}

Q: Is port 5432 exposed to the network?
{"tool": "check_exposure", "args": {"port": 5432}}

Respond with ONLY the JSON object."""

_PID_PATTERN = re.compile(r"\b(?:pid|process)\s*#?\s*(\d+)\b", re.IGNORECASE)
_PORT_PATTERN = re.compile(r"\b(?:port|on)\s*#?\s*(\d{1,5})\b", re.IGNORECASE)
_JSON_OBJECT_PATTERN = re.compile(r"\{.*\}", re.DOTALL)


class RoutingError(ValueError):
    """The model's routing output didn't parse or validate."""


@dataclass
class Route:
    tool: str
    args: dict[str, Any]
    source: str  # "model" or "fallback"


def route(question: str, config: Config) -> Route:
    """Ask the model to pick a tool; validate; fall back to keywords on failure."""
    messages = [
        {"role": "system", "content": ROUTING_SYSTEM_PROMPT},
        {"role": "user", "content": question},
    ]

    try:
        raw = chat_completion(config, messages)
        tool, args = _parse_and_validate(raw)
        return Route(tool=tool, args=args, source="model")
    except RoutingError:
        return keyword_fallback(question)


def _parse_and_validate(raw_model_output: str) -> tuple[str, dict[str, Any]]:
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
