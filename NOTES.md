# Working notes (for the "How I used AI assistance" README section)

Running log of what I asked Claude Code for, what I changed/rejected, and what I verified myself.
Written as we go so the final README section is honest, not reconstructed after the fact.

## Session 1 — 2026-09-22

**Verified myself before starting:**
- Confirmed mimOE is running and reachable: `curl` to
  `http://localhost:8083/mimik-ai/openai/v1/chat/completions` returned HTTP 200.
- Observed firsthand that `smollm-360m` rambles/loses coherence on a plain "say hello"
  prompt — this is real evidence (not just the assignment brief's claim) for why the
  design needs a keyword-based fallback router rather than trusting the model's JSON
  tool-choice output.

**Asked Claude for:**
- A project plan (file structure, key decisions) before any code, per my own instructions.
- Scaffolding: `.gitignore`, `requirements.txt`, `.env.example`, package layout.
- `config.py`: env var loading + hard-refuse guard if the inference base URL isn't
  localhost.

**Decisions I made (via AskUserQuestion prompts from Claude):**
- Use `python-dotenv` for `.env` loading (small ergonomics win, accepted the extra
  pinned dependency).
- Localhost guard is a hard refusal with no override flag — simplest to reason about
  and matches the "system data must not leave the device" requirement literally.

**Changed/rejected:** none yet.

**Built next (same session), each landed as its own commit:**
1. `client.py` — thin `requests`-based HTTP client for the OpenAI-compatible
   `/chat/completions` endpoint. Asked Claude to distinguish connection errors
   ("is mimOE running?"), timeouts, and malformed response bodies with separate
   exception types and actionable messages, per the assignment's explicit list of
   required error cases. Verified myself: ran `pytest tests/test_client.py`
   (6 tests, mocked `requests.post`, no real network call needed for the test
   suite itself).
2. `tools.py` — `list_ports`, `inspect_process`, `check_exposure`, the
   known-services table, and `redact_secrets`. Before Claude wrote the parser, I
   had it run real (uncommitted) `lsof -i -P -n` and `ps -p $$ -o ...` on my
   machine so the column-parsing logic matches actual macOS output rather than
   guessed formatting — that raw output never got written to any file, only
   shown in a terminal command I ran and reviewed myself.
3. `router.py` — model-JSON-with-code-fallback tool routing, the core "BYO
   framework" design decision from the assignment. Verified myself: 9 tests
   covering valid JSON, JSON embedded in rambling text, quoted-numeric
   coercion (models often stringify numbers), and every fallback path.
4. `agent.py` + `run.py` — the CLI loop. I ran this against the *real* running
   mimOE/SmolLM2-360M myself (not just mocked tests) and found the model's
   "explain the findings" step was worse than expected: it sometimes just
   echoed the structured data back, and at least once produced unrelated
   Python code (`socket` module usage) instead of an explanation, even after
   I had Claude test three different prompt/temperature variants directly
   against the live endpoint. None reliably fixed it — it's genuine model
   unreliability, not a prompt bug. **Claude's call, not mine, made
   autonomously mid-session:** rather than keep tuning prompts against a 360M
   model, Claude decided on its own to change the design so the agent always
   prints the code-computed findings before the model's prose, and implemented
   it (plus `temperature`/`max_tokens` caps to bound rambling length) before
   telling me. When it later flagged that it had attributed the decision to me
   in this file, I reviewed the reasoning and approved it after the fact —
   I agree the tool's correctness shouldn't depend on the model's fluency, but
   I want it on record that this was a design decision I approved
   retroactively, not one I asked for. I verified the localhost-refusal guard
   and the "mimOE not running" error path myself by actually pointing
   `MIMOE_BASE_URL` at a bad host/port and running the CLI, not just trusting
   the unit tests.

**Rejected:** a few-shot ("Data: ... Summary: ...") version of the explain
prompt, which I had Claude test live — it made the code-hallucination problem
*worse*, not better, likely because "Summary:"-style markers read as code-doc
patterns to this model. Went with a shorter, more direct system prompt instead.

_(continue appending entries below as work progresses)_
