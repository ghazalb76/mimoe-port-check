#!/usr/bin/env python3
"""Reproducible routing-accuracy check: run evals/routing_questions.txt
through the live router and report how often the model's tool-choice JSON
was used vs. how often it fell back to keyword matching.

Requires mimOE to be running (this hits the real endpoint, not a mock --
that's the point: it measures the actual model's behavior).

Usage:
    python evals/run_routing_eval.py
    python evals/run_routing_eval.py --debug     # also print raw model output
    python evals/run_routing_eval.py --questions evals/routing_questions.txt
    python evals/run_routing_eval.py --model qwen3-1.7b   # compare a model
                                                            # already loaded
                                                            # in mimOE, without
                                                            # touching .env
"""
import argparse
import dataclasses
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mimoe_port_check.config import NonLocalEndpointError, load_config  # noqa: E402
from mimoe_port_check.router import route  # noqa: E402

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


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--questions", type=Path, default=DEFAULT_QUESTIONS_PATH)
    parser.add_argument("--debug", action="store_true", help="Print the model's raw tool-choice output per question.")
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

    questions = load_questions(args.questions)
    model_correct = 0
    model_incorrect = 0
    fallback_count = 0
    latencies_seconds: list[float] = []

    for question, expected_tool, expected_args in questions:
        start = time.perf_counter()
        result = route(question, config, debug=args.debug)
        latencies_seconds.append(time.perf_counter() - start)
        matched_expected = result.tool == expected_tool and result.args == expected_args

        if result.source == "fallback":
            fallback_count += 1
            status = "FALLBACK"
        elif matched_expected:
            model_correct += 1
            status = "model OK"
        else:
            model_incorrect += 1
            status = "model WRONG"

        print(
            f"[{status:11}] {latencies_seconds[-1] * 1000:6.0f}ms "
            f"{question!r} -> {result.tool} {result.args} (expected {expected_tool} {expected_args})"
        )

    total = len(questions)
    routed_by_model = model_correct + model_incorrect
    avg_latency_ms = sum(latencies_seconds) / len(latencies_seconds) * 1000
    print()
    print(f"Model: {config.model}")
    print(f"Total questions: {total}")
    print(f"  Routed by model:   {routed_by_model} ({model_correct} correct, {model_incorrect} wrong)")
    print(f"  Fell back to keywords: {fallback_count}")
    if routed_by_model:
        print(f"  Model accuracy when it did route: {model_correct / routed_by_model:.0%}")
    print(f"  Overall correct-and-via-model rate: {model_correct / total:.0%}")
    print(f"  Average routing request latency: {avg_latency_ms:.0f}ms")


if __name__ == "__main__":
    main()
