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

## Session 2 — 2026-09-22

Test run against a real (non-fake) session surfaced 7 issues; fixed each as
its own commit, running the full test suite after every one. mimOE was
confirmed reachable (`curl` -> 200) at the start, so live testing was done
throughout rather than only against mocks.

1. **Dedup IPv4/IPv6** (`tools.py`): grouped lsof rows by `(port, pid)`
   before building entries. Verified against real output: `rapportd` on this
   machine genuinely listens on port 50104 over both IPv4 and IPv6
   simultaneously — a real, not hypothetical, case.
2. **Full process names** (`tools.py`): added `lsof +c 0` and decoding for
   its `\xHH` escapes (used to keep spaces from breaking whitespace-column
   parsing). Verified live: "Code Helper (Renderer)" etc. now show in full.
3. **Process-identity labeling, path-verified** (`tools.py`): added
   `KNOWN_PROCESSES` (rapportd, ControlCenter, Spotify, Code Helper, mimoe),
   checked before the port table. A name match is only trusted once the
   process's real executable path (`ps -o comm=`, which is the full path on
   macOS and can't be spoofed the way a process's declared name can) confirms
   an expected install-path prefix; mimoe has no fixed install path so it's
   name-only. Added the INFO risk level for these. **Found live:** mimoe
   itself is bound to `*:8083` on the dev machine and now reads as INFO
   ("expected for this service") — the same treatment as AirPlay/Spotify
   Connect, which are actually designed for LAN broadcast. Implemented as
   specified; flagged in the README Limitations as worth reconsidering rather
   than changed unilaterally.
4. **Compact output** (`agent.py`): `format_list_ports` now leads with a
   summary line and groups per-port lines under their process.
5. **Condensed model input** (`agent.py`): `run_tool` now returns the raw
   result alongside the formatted text, so `summarize_notable` can build a
   short HIGH/MEDIUM-only (or one-line all-clear) summary for the explain
   step instead of handing it the full findings. Lowered temperature/
   max_tokens (0.1/120, was 0.2/200) and tightened the prompt to ask for
   2-3 sentences.
6. **Skip the model on nothing-to-explain** (`agent.py`): `check_exposure` on
   a non-listening port and `inspect_process` on a missing PID now print a
   fixed message and never call mimOE — verified live (`what's on port 1?`
   -> no model call, deterministic text only).
7. **Routing investigation** (`router.py`, `run.py`, `evals/`): added
   `--debug` to print the model's raw routing output, and
   `evals/run_routing_eval.py` + `evals/routing_questions.txt` (16 varied
   questions, reproducible) to measure model-routing accuracy without
   guessing. **Measured before changing the prompt:** the model attempted
   valid JSON on **0/16** questions — every single response was a
   conversational answer to the question, never JSON. Isolated `curl` tests
   confirmed this wasn't a prompt-structure issue: even "Output exactly:
   \<json\>" with nothing else in the prompt got a rambling non-JSON answer.
   Restructured the routing prompt's few-shot examples from prose embedded in
   the system message into real `(user, assistant)` message turns (a
   meaningfully different structure, not just "more of the same wording") and
   re-measured: **1/16** attempted JSON, and that one attempt just echoed the
   last few-shot example's answer verbatim instead of reasoning about the new
   question -- 0% correctness among model-routed answers, both before and
   after. Conclusion: this is a genuine capability ceiling of
   SmolLM2-360M at this size, not a fixable prompt-wording problem, and no
   further prompt tuning was attempted per the "report before changing
   anything else" plan. The keyword fallback (already the documented design)
   is what actually routes essentially every question correctly in practice;
   kept the multi-turn few-shot structure since it's a more correct API usage
   pattern even though it didn't move accuracy, and documented the finding
   in the README rather than continuing to iterate on the prompt.

## Session 2, follow-up — 2026-09-22

I had flagged that `mimoe` getting the same INFO treatment as AirPlay/
Handoff/Spotify Connect looked wrong (those are designed for LAN discovery;
an inference endpoint being network-reachable isn't). Asked about it —
confirmed: fix it. `KNOWN_PROCESSES` entries in `tools.py` now each carry
their own exposed-risk level/note instead of one blanket rule. `mimoe`
bound to localhost is still LOW; exposed, it's now MEDIUM with a note that
its API key defaults to a shared value, so anyone on the local network
could reach and use the endpoint. Verified live: the real mimOE on this
machine (bound to `*:8083`) now reads MEDIUM instead of INFO. All other
known processes are unchanged.

## Session 3 — model comparison (smollm-360m vs. qwen3-1.7b) — 2026-09-22

Loaded `qwen3-1.7b` in mimOE and ran `evals/run_routing_eval.py` /
`evals/run_explain_eval.py` against it (16-question set, same as the
smollm-360m baseline from Session 2). Note: mimOE only keeps one model
loaded at a time, so this and the smollm baseline weren't measured
back-to-back with identical instrumentation -- smollm's latency numbers
still need a re-run once it's reloaded. Per instruction, results below are
summarized/paraphrased; no raw process names, paths, or command lines are
included, even though the eval scripts print real local system data to the
terminal when run.

**First run failed at 0/16, same as smollm, but for a different reason.**
Debug output showed qwen3-1.7b emitting a long `<think>...</think>`
reasoning block before answering, and the existing `max_tokens=60` for
routing was entirely consumed by that reasoning -- confirmed by raising
`max_tokens` well past 60 in isolated `curl` tests and watching it still be
mid-thought, never reaching an answer. Found that Qwen3 recognizes a literal
`/no_think` directive to skip reasoning; added it to both
`ROUTING_SYSTEM_PROMPT` and `EXPLAIN_SYSTEM_PROMPT` (inert text for
smollm-360m, so this shouldn't change its behavior, though that's not yet
re-verified live). Also made `router.strip_think_blocks` non-private and
reused it in the explain step, since a leftover `<think>` block would
otherwise print to the user as if it were the answer.

**After the fix:**
- Routing: 14/16 correct via the model, 1 wrong, 1 fell back to keywords ->
  88% overall correct-and-via-model, vs. 0% for smollm-360m. Average routing
  request latency ~680ms.
- Explain step: qualitatively a large step up from smollm-360m's tendency to
  repeat itself or drift into unrelated/hallucinated text. Qwen3's answers
  were coherent 2-4 sentence summaries that correctly referenced the actual
  notable finding and gave a sensible suggestion, across most questions.
  One flaw observed: for a process-inspection result that carried no risk
  label at all, the model added an unprompted, alarmist "this may be a
  security threat" framing not grounded in anything in the data -- a real
  instance of inventing a risk assessment despite the prompt explicitly
  saying not to, just a different failure mode than smollm's (occasional
  fabrication vs. constant repetition/incoherence). Average explain request
  latency ~1.5s (7 of 16 questions short-circuited to a deterministic
  message and never called the model).

**Still to do:** re-measure smollm-360m's latency with the current
instrumentation once it's reloaded; run both evals against `qwen3-4b` once
it's loaded. Default model (`smollm-360m` in `config.py`/`.env.example`)
left unchanged throughout -- this is a comparison, not a migration.

## Session 3, continued — qwen3-4b and the smollm-360m baseline — 2026-09-22

Ran the same 16-question evals against `qwen3-4b`, then against
`smollm-360m` once it was reloaded (with the current /no_think + latency
instrumentation, so this is the first fully comparable smollm number).
Full three-model table is in the README "Model comparison" section.
Summarized/paraphrased below, no raw system data.

- **qwen3-4b routing:** 15/16 correct via the model, 1 wrong, 0 fallback ->
  94% overall, slightly better than qwen3-1.7b's 88%. Average routing
  latency ~1.35s, roughly double qwen3-1.7b's ~680ms.
- **qwen3-4b explain step:** consistently coherent and on-topic, same as
  qwen3-1.7b, but with a more concerning failure mode: for the
  process-inspection question, it fabricated specific technical details
  (port numbers) that don't appear anywhere in the underlying data --
  a more concrete, specific-sounding hallucination than qwen3-1.7b's vaguer
  invented framing, and arguably easier to mistake for a real finding
  because it reads so smoothly. Average explain latency ~2.7s.
- **smollm-360m baseline (re-measured):** routing matched the earlier
  finding exactly -- 1/16 attempted JSON, 0 correct, 15/16 fallback, 0%
  overall. Average routing latency ~410ms, notably faster than either Qwen
  model. Explain step was the weakest of the three: looped the same
  sentence verbatim multiple times in one response, fabricated an entirely
  extra finding (a second port/pid not present anywhere in the real data)
  in one response, and gave generic off-topic technical advice (unrelated
  shell command suggestions) instead of explaining the actual finding in
  another. Average explain latency ~1.3s -- not dramatically faster than
  qwen3-1.7b's ~1.5s despite being a much smaller model, likely because its
  repetitive output still fills most of the token budget.

**Overall read:** smollm-360m is fastest but its correctness depends
entirely on the keyword fallback (routing) and produces the least reliable
explanations. Both Qwen models route well; qwen3-4b is slightly more
accurate but ~2x the latency of qwen3-1.7b on both steps, and its
hallucinations are more specific/plausible-sounding rather than less
frequent. Default model left unchanged (`smollm-360m`) -- this was a
comparison exercise, not a migration decision.

_(continue appending entries below as work progresses)_
