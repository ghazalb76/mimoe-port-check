"""Shared helpers for the eval scripts (run_routing_eval.py, run_explain_eval.py)."""
import json
from pathlib import Path

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
