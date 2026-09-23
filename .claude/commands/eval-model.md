---
description: Run routing + explain evals against a mimOE model
argument-hint: <model-id>
---
Model to test: `$ARGUMENTS` (must already be loaded in mimOE -- mimOE only keeps one model loaded at a time).

1. Confirm mimOE is actually reachable: a quick request against `MIMOE_BASE_URL`
   (default `http://localhost:8083/mimik-ai/openai/v1`, from `.env` if set). If
   it's not reachable, stop and say so -- don't run the evals against a dead
   endpoint.
2. Run `python3 evals/run_routing_eval.py --model $ARGUMENTS` and
   `python3 evals/run_explain_eval.py --model $ARGUMENTS`.
3. Summarize both: routing accuracy (model-correct / fallback / wrong),
   average latency, and explain-step quality (coherence, grounding,
   hallucination behavior observed) -- same shape as the README's "Model
   comparison" table.
4. If any number changed from what's already recorded, update the
   README's "Model comparison" section in all three places: the two
   `xychart-beta` Mermaid charts (routing accuracy, explain latency) and
   the table -- they must stay in sync with each other, not just with the
   raw eval output.

Never paste raw process names, paths, command-line args, or other real
system data into the summary -- paraphrase, per the no-real-output rule in
CLAUDE.md. Don't edit `.env` or change the package default model; this is a
comparison run, not a migration.
