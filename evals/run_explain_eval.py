#!/usr/bin/env python3
"""Explain-step quality check: for each question in routing_questions.txt,
run its *expected* tool for real (bypassing routing -- that's measured by
run_routing_eval.py) and print the model's explain-step output on the
resulting findings.

This hits real, live system data (ports, processes, command lines) on
whatever machine it's run on. Output is printed to the terminal only --
never written to a file by this script. If you're recording results
elsewhere (NOTES.md, a report, etc.), summarize/paraphrase rather than
pasting raw output, since it includes real local process names and paths.

Usage:
    python evals/run_explain_eval.py
    python evals/run_explain_eval.py --model qwen3-1.7b
    python evals/run_explain_eval.py --questions evals/routing_questions.txt
"""
import argparse
import dataclasses
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mimoe_port_check.agent import (  # noqa: E402
    EXPLAIN_SYSTEM_PROMPT,
    deterministic_explanation,
    has_nothing_to_explain,
    summarize_notable,
)
from mimoe_port_check.client import MimOEError, chat_completion  # noqa: E402
from mimoe_port_check.config import NonLocalEndpointError, load_config  # noqa: E402
from mimoe_port_check.router import Route, strip_think_blocks  # noqa: E402
from mimoe_port_check.tools import check_exposure, inspect_process, list_ports  # noqa: E402

DEFAULT_QUESTIONS_PATH = Path(__file__).resolve().parent / "routing_questions.txt"


def load_questions(path: Path) -> list[tuple[str, str, dict]]:
    """Parse `question ||| expected_tool ||| expected_args_json` lines."""
    questions = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        question, expected_tool, expected_args_json = (part.strip() for part in line.split("|||"))
        questions.append((question, expected_tool, json.loads(expected_args_json)))
    return questions


def run_real_tool(tool: str, tool_args: dict):
    if tool == "list_ports":
        return list_ports()
    if tool == "inspect_process":
        return inspect_process(tool_args["pid"])
    if tool == "check_exposure":
        return check_exposure(tool_args["port"])
    raise ValueError(f"Unknown tool '{tool}'")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--questions", type=Path, default=DEFAULT_QUESTIONS_PATH)
    parser.add_argument(
        "--model",
        help="Model ID to compare against (must already be loaded in mimOE). "
        "Overrides config for this run only -- never touches .env or the "
        "package default.",
    )
    args = parser.parse_args()

    try:
        config = load_config()
    except NonLocalEndpointError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    if args.model:
        config = dataclasses.replace(config, model=args.model)
        print(f"Using model override: {config.model}\n")

    latencies_seconds: list[float] = []

    for question, expected_tool, expected_args in load_questions(args.questions):
        route = Route(tool=expected_tool, args=expected_args, source="eval")
        result = run_real_tool(expected_tool, expected_args)

        print(f"> {question}")
        if has_nothing_to_explain(route, result):
            print(f"  [skipped model -- nothing to explain] {deterministic_explanation(route, result)}\n")
            continue

        notable_summary = summarize_notable(route, result)
        messages = [
            {"role": "system", "content": EXPLAIN_SYSTEM_PROMPT},
            {"role": "user", "content": f"Question: {question}\n\n{notable_summary}"},
        ]
        try:
            start = time.perf_counter()
            answer = chat_completion(config, messages, temperature=0.1, max_tokens=120)
            latencies_seconds.append(time.perf_counter() - start)
        except MimOEError as exc:
            print(f"  [could not reach mimOE] {exc}\n")
            continue

        print(f"  ({latencies_seconds[-1] * 1000:.0f}ms) model explanation: {strip_think_blocks(answer).strip()}\n")

    print(f"Model: {config.model}")
    if latencies_seconds:
        avg_latency_ms = sum(latencies_seconds) / len(latencies_seconds) * 1000
        print(f"Average explain request latency ({len(latencies_seconds)} calls): {avg_latency_ms:.0f}ms")
    else:
        print("No explain-step model calls were made (every question skipped the model).")


if __name__ == "__main__":
    main()
