# Working notes (for the "How I used AI assistance" README section)

Running log of what I asked Claude Code for, what I changed/rejected, and what I verified myself.
Written as we go so the final README section is honest, not reconstructed after the fact.

## Session 1: 2026-09-22

**Verified myself before starting:**
- Confirmed mimOE is running and reachable: `curl` to
  `http://localhost:8083/mimik-ai/openai/v1/chat/completions` returned HTTP 200.
- Observed firsthand that `smollm-360m` rambles/loses coherence on a plain "say hello"
  prompt. This is my own firsthand evidence for why the
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
- Localhost guard is a hard refusal with no override flag, simplest to reason about
  and matches the "system data must not leave the device" requirement literally.

**Changed/rejected:** none yet.

**Built next (same session), each as its own step:**
1. `client.py`: thin `requests`-based HTTP client for the OpenAI-compatible
   `/chat/completions` endpoint. Asked Claude to distinguish connection errors
   ("is mimOE running?"), timeouts, and malformed response bodies with separate
   exception types and actionable messages, per my own requirement that
   each of those failure cases be handled separately. Verified myself: ran
   `pytest tests/test_client.py` (6 tests, mocked `requests.post`, no real network call needed for the test
   suite itself).
2. `tools.py`: `list_ports`, `inspect_process`, `check_exposure`, the
   known-services table, and `redact_secrets`. Before Claude wrote the parser, I
   had it run real (uncommitted) `lsof -i -P -n` and `ps -p $$ -o ...` on my
   machine so the column-parsing logic matches actual macOS output rather than
   guessed formatting, that raw output never got written to any file, only
   shown in a terminal command I ran and reviewed myself.
3. `router.py`: model-JSON-with-code-fallback tool routing, the core "BYO
   framework" design decision from the assignment. Verified myself: 9 tests
   covering valid JSON, JSON embedded in rambling text, quoted-numeric
   coercion (models often stringify numbers), and every fallback path.
4. `agent.py` + `run.py`: the CLI loop. I ran this against the *real* running
   mimOE/SmolLM2-360M myself (not just mocked tests) and found the model's
   "explain the findings" step was worse than expected: it sometimes just
   echoed the structured data back, and at least once produced unrelated
   Python code (`socket` module usage) instead of an explanation, even after
   I had Claude test three different prompt/temperature variants directly
   against the live endpoint. None reliably fixed it: it's genuine model
   unreliability, not a prompt bug. **Claude's call, not mine, made
   autonomously mid-session:** rather than keep tuning prompts against a 360M
   model, Claude decided on its own to change the design so the agent always
   prints the code-computed findings before the model's prose, and implemented
   it (plus `temperature`/`max_tokens` caps to bound rambling length) before
   telling me. When it later flagged that it had attributed the decision to me
   in this file, I reviewed the reasoning and approved it after the fact.
   I agree the tool's correctness shouldn't depend on the model's fluency, but
   I want it on record that this was a design decision I approved
   retroactively, not one I asked for. I verified the localhost-refusal guard
   and the "mimOE not running" error path myself by actually pointing
   `MIMOE_BASE_URL` at a bad host/port and running the CLI, not just trusting
   the unit tests.

**Rejected:** a few-shot ("Data: ... Summary: ...") version of the explain
prompt, which I had Claude test live: it made the code-hallucination problem
*worse*, not better, likely because "Summary:"-style markers read as code-doc
patterns to this model. Went with a shorter, more direct system prompt instead.

## Session 2: 2026-09-22

Test run against a real (non-fake) session surfaced 7 issues; fixed each as
its own step, running the full test suite after every one. mimOE was
confirmed reachable (`curl` -> 200) at the start, so live testing was done
throughout rather than only against mocks.

1. **Dedup IPv4/IPv6** (`tools.py`): grouped lsof rows by `(port, pid)`
   before building entries. Verified against real output: a real macOS
   system process on this machine genuinely listens on the same port over
   both IPv4 and IPv6 simultaneously, a real, not hypothetical, case.
2. **Full process names** (`tools.py`): added `lsof +c 0` and decoding for
   its `\xHH` escapes (used to keep spaces from breaking whitespace-column
   parsing). Verified live: multi-word process names with escaped spaces
   now show in full instead of truncated/still-escaped.
3. **Process-identity labeling, path-verified** (`tools.py`): added
   `KNOWN_PROCESSES` (rapportd, ControlCenter, Spotify, Code Helper, mimoe),
   checked before the port table. A name match is only trusted once the
   process's real executable path (`ps -o comm=`, which is the full path on
   macOS and reflects the actual executable rather than the name the
   process reports, so renaming alone can't spoof it) confirms
   an expected install-path prefix; mimoe has no fixed install path so it's
   name-only. Added the INFO risk level for these. **Found live:** mimoe
   itself is bound to `*:8083` on the dev machine and now reads as INFO
   ("expected for this service"): the same treatment as AirPlay/Spotify
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
   fixed message and never call mimOE: verified live (`what's on port 1?`
   -> no model call, deterministic text only).
7. **Routing investigation** (`router.py`, `run.py`, `evals/`): added
   `--debug` to print the model's raw routing output, and
   `evals/run_routing_eval.py` + `evals/routing_questions.txt` (16 varied
   questions, reproducible) to measure model-routing accuracy without
   guessing. **Measured before changing the prompt:** the model attempted
   valid JSON on **0/16** questions: every single response was a
   conversational answer to the question, never JSON. Isolated `curl` tests
   confirmed this wasn't a prompt-structure issue: even "Output exactly:
   \<json\>" with nothing else in the prompt got a rambling non-JSON answer.
   Restructured the routing prompt's few-shot examples from prose embedded in
   the system message into real `(user, assistant)` message turns (a
   meaningfully different structure, not just "more of the same wording") and
   re-measured: **1/16** attempted JSON, and that one attempt just echoed the
   last few-shot example's answer verbatim instead of reasoning about the new
   question. 0% correctness among model-routed answers, both before and
   after. Conclusion: this is a genuine capability ceiling of
   SmolLM2-360M at this size, not a fixable prompt-wording problem, and no
   further prompt tuning was attempted per the "report before changing
   anything else" plan. The keyword fallback (already the documented design)
   is what actually routes essentially every question correctly in practice;
   kept the multi-turn few-shot structure since it's a more correct API usage
   pattern even though it didn't move accuracy, and documented the finding
   in the README rather than continuing to iterate on the prompt.

## Session 2, follow-up: 2026-09-22

I had flagged that `mimoe` getting the same INFO treatment as AirPlay/
Handoff/Spotify Connect looked wrong (those are designed for LAN discovery;
an inference endpoint being network-reachable isn't). Asked about it.
Confirmed: fix it. `KNOWN_PROCESSES` entries in `tools.py` now each carry
their own exposed-risk level/note instead of one blanket rule. `mimoe`
bound to localhost is still LOW; exposed, it's now MEDIUM with a note that
its API key defaults to a shared value, so anyone on the local network
could reach and use the endpoint. Verified live: the real mimOE on this
machine (bound to `*:8083`) now reads MEDIUM instead of INFO. All other
known processes are unchanged.

## Session 3, model comparison (smollm-360m vs. qwen3-1.7b), 2026-09-22

Loaded `qwen3-1.7b` in mimOE and ran `evals/run_routing_eval.py` /
`evals/run_explain_eval.py` against it (16-question set, same as the
smollm-360m baseline from Session 2). Note: mimOE only keeps one model
loaded at a time, so this and the smollm baseline weren't measured
back-to-back with identical instrumentation: smollm's latency numbers
still need a re-run once it's reloaded. Per instruction, results below are
summarized/paraphrased; no raw process names, paths, or command lines are
included, even though the eval scripts print real local system data to the
terminal when run.

**First run failed at 0/16, same as smollm, but for a different reason.**
Debug output showed qwen3-1.7b emitting a long `<think>...</think>`
reasoning block before answering, and the existing `max_tokens=60` for
routing was entirely consumed by that reasoning, confirmed by raising
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
  security threat" framing not grounded in anything in the data, a real
  instance of inventing a risk assessment despite the prompt explicitly
  saying not to, just a different failure mode than smollm's (occasional
  fabrication vs. constant repetition/incoherence). Average explain request
  latency ~1.5s (7 of 16 questions short-circuited to a deterministic
  message and never called the model).

**Still to do:** re-measure smollm-360m's latency with the current
instrumentation once it's reloaded; run both evals against `qwen3-4b` once
it's loaded. Default model (`smollm-360m` in `config.py`/`.env.example`)
left unchanged throughout. This is a comparison, not a migration.

## Session 3, continued: qwen3-4b and the smollm-360m baseline, 2026-09-22

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
  (port numbers) that don't appear anywhere in the underlying data:
  a more concrete, specific-sounding hallucination than qwen3-1.7b's vaguer
  invented framing, and arguably easier to mistake for a real finding
  because it reads so smoothly. Average explain latency ~2.7s.
- **smollm-360m baseline (re-measured):** routing matched the earlier
  finding exactly: 1/16 attempted JSON, 0 correct, 15/16 fallback, 0%
  overall. Average routing latency ~410ms, notably faster than either Qwen
  model. Explain step was the weakest of the three: looped the same
  sentence verbatim multiple times in one response, fabricated an entirely
  extra finding (a second port/pid not present anywhere in the real data)
  in one response, and gave generic off-topic technical advice (unrelated
  shell command suggestions) instead of explaining the actual finding in
  another. Average explain latency ~1.3s, not dramatically faster than
  qwen3-1.7b's ~1.5s despite being a much smaller model, likely because its
  repetitive output still fills most of the token budget.

**Overall read:** smollm-360m is fastest but its correctness depends
entirely on the keyword fallback (routing) and produces the least reliable
explanations. Both Qwen models route well; qwen3-4b is slightly more
accurate but ~2x the latency of qwen3-1.7b on both steps, and its
hallucinations are more specific/plausible-sounding rather than less
frequent. Default model left unchanged (`smollm-360m`). This was a
comparison exercise, not a migration decision.

## Session 4: live-testing bugs, one step each, 2026-09-22

Live testing (not the eval scripts but actual back-and-forth against the
running CLI) surfaced 5 bugs. Fixed each as its own step, full test suite
green after every one.

1. **Ungrounded tool arguments** (`router.py`): the model parroted its last
   few-shot example's answer (`check_exposure`/port 5432) verbatim for both
   "tell me about process abc" and "what's the weather?": syntactically
   valid JSON, but not actually about the question asked.
   `_args_grounded_in_question` now requires a chosen port/pid's literal
   digits to appear somewhere in the question; otherwise `route()` falls
   through to the keyword fallback.
2. **Off-topic handling** (`agent.py`): `is_on_topic()` checks the question
   against a fixed keyword set; if none match, `resolve_route` returns an
   `off_topic` sentinel that `main()` intercepts before calling the model or
   any tool, printing a short capability message. Verified the keyword set
   against all 16 questions in `evals/routing_questions.txt`: none
   misclassified.
3. **Invalid input** (`agent.py`): "process abc" mentions "process" (still
   on-topic) but has no digits at all, and previously fell through to
   `keyword_fallback`'s default case, silently running `list_ports`.
   `_looks_like_invalid_pid_reference` (mentions pid/process AND zero
   digits anywhere in the question) now short-circuits to a clear "please
   give a numeric PID" message instead. Deliberately requires *zero* digits
   in the whole question, not just next to the keyword, so it doesn't
   misfire on "process id 900"-style phrasing.
4. **Contradiction check** (`agent.py`): a real explanation read "It is not
   exposed to all network interfaces. It is not exposed to any network
   interfaces." for a summary that said MEDIUM/exposed, the opposite of
   the findings. Tricky part: the explanation contains "not exposed" twice
   and no standalone "exposed" at all, so a naive substring check for
   "exposed" would have wrongly concluded it *agreed* with the summary.
   `_mentions_exposed` strips "not exposed"-style phrases before checking
   for a standalone "exposed" claim specifically to handle this.
   `find_exposure_contradiction` only fires when both texts are unambiguous
   in one direction.
5. **Truncation** (`agent.py`): `trim_to_complete_sentence` cuts a response
   to its last complete sentence, so a mid-sentence cutoff (observed live,
   trailing off as "...on port 8") doesn't get shown. Punctuation only
   counts as a sentence end when followed by whitespace or the end of the
   text: without that, a naive "last '.' anywhere" search would cut
   inside an IP address like `127.0.0.1` or right after "e.g." mid-sentence,
   since both have periods immediately followed by more of the same
   sentence or another digit.

## Session 5: web UI live-testing feedback, 2026-09-23

More live testing, this time of the web UI on the `ui` branch. Also
noticed partway through that another session was concurrently committing
a model-picker feature (dropdown to switch `MIMOE_MODEL` at runtime,
`POST /api/model`) to the same branch, unrelated to this feedback, and
folded in rather than untangled, since everything tested compatible.

1. **Explanation repetition**: smollm-360m looped the same sentence up to
   8 times in one response (same underlying issue documented earlier, just
   observed again via the web UI this time). `dedupe_consecutive_sentences`
   collapses an immediately-repeated sentence to one occurrence, wired
   into `process_question`, so both the CLI and the web UI get it for
   free through the shared pipeline.
2. **Layout**: the web UI showed the findings table before the
   explanation, and never showed the "N listening ports, M exposed, K
   high risk" summary line at all (it only existed inside the CLI's
   preformatted text, never sent over the JSON API). Extracted
   `list_ports_summary()`, added it to the API response, and reordered
   the page to summary + explanation first, findings table below. CLI
   terminal output unchanged. This was UI-layout-specific feedback.
3. **Sort + collapse**: findings are now sorted HIGH/MEDIUM/LOW/INFO
   (client-side), with INFO rows (AirPlay, Handoff, etc., expected/
   benign) collapsed behind a "Show N expected services" toggle so they
   don't bury the notable rows.
4. **Own port unrecognized**: the web UI's own listening port showed up
   as "Unknown service" in its own findings. Since the port number is
   configurable (`--port`), this couldn't be a static table entry; instead
   `_relabel_own_port()` matches on the server's actual bound port AND
   `os.getpid()` together (port alone isn't enough: a different process
   could coincidentally sit on the same port number) and only relabels to
   LOW when confirmed not exposed to the network, leaving the normal risk
   label alone if that's ever not the case. Needed a small `tools.py`
   addition: `ExposureReport` didn't carry a `pid` field at all, even
   though `check_exposure()` already had it available internally from the
   `list_ports()` lookup it does, added the field and threaded it
   through, which also unlocked pid-matching for `check_exposure`
   findings, not just `list_ports`.

## Session 6: final changes, 2026-09-23

Later work that supersedes parts of the entries above. The entries
themselves are left as written. Also, the step-by-step history described
above was later consolidated into a smaller set of milestone commits, so
`git log` no longer shows one commit per step.

- **Model default:** "Default model left unchanged (`smollm-360m`)" no
  longer holds. `MIMOE_MODEL` is now unset by default, and the agent
  auto-selects from whatever is loaded in mimOE, preferring `qwen3-1.7b`,
  then `qwen3-4b`, then `smollm-360m`. Setting `MIMOE_MODEL` still
  overrides this.
- **Model-picker dropdown removed:** the dropdown from Session 5 is gone.
  mimOE only reports what is currently loaded and there is no reliable way
  from here to trigger a load, so it had nothing to switch to. Switching
  models stays a mimOE Studio task.
- **Own-port labeling moved:** the Session 5 `_relabel_own_port()` step in
  the web layer was folded into `tools.label_risk` (via a `self_pid`
  parameter), so risk labels have one source of truth again. Behavior is
  the same: port and PID must both match, and only a localhost-bound port
  is labeled LOW.
- **Markdown stripping:** the model sometimes returns markdown in its
  explanation. It is now stripped before display, since the UI renders plain
  text as an XSS safeguard.
- **Contradiction-check false positive:** advice phrasing such as "ensure
  they're not exposed" was being read as a claim that the service is not
  exposed, and flagged against a summary saying it was. The check now
  matches claim-style phrasing only and skips negations that follow advice
  verbs.
- **Architecture diagram:** the ASCII diagram became a Mermaid flowchart,
  then a static SVG (`docs/architecture.svg`), so it renders the same
  everywhere.
- **README pass:** reworded to mirror the assignment's wording, with
  "Approach" and "Framework and tooling choices" as separate sections, plus
  an endpoint-exploration section, a web UI screenshot, and a few accuracy
  and voice fixes.
- **Quick start:** commands now use `python3` (and `python3 -m pytest`) to
  match how the venv is created.
- **Keyword fallback fixes:** the smollm-360m re-run showed the fallback
  sending two eval questions to `list_ports`. "process id N" now routes to
  `inspect_process`, and a bare number counts as a port when the question
  also mentions open, exposed, listening, or network. The number rule skips
  IP-address octets, counts like "the 10 open ports", and values outside
  1-65535. Both questions were already in the eval set, so only tests were
  added. This took the fallback from 14/16 to 16/16 on the eval questions.
- **Shared PID pattern:** the fallback and the model's grounding check use
  the same PID pattern, so the widening also lets the grounding check accept
  a correct model answer for "process id 900" instead of rejecting it and
  falling back.
- **Explain eval:** it now runs `strip_markdown` in the same order as the
  real agent, so it measures what users see. Its output no longer shows
  raw markdown bullets or bold.
- **Final re-run of all three models on one commit:** earlier tables mixed
  measurements from different code. All three were re-run on the same
  commit, one run each. smollm-360m attempted 0/16 via the model and got
  16/16 end to end through the fallback. qwen3-1.7b routed 81% via the
  model and got 15/16 end to end. qwen3-4b routed 88% via the model and got
  15/16 end to end. This supersedes the 88% and 94% figures recorded for the
  two Qwen models in Session 3. The earlier qwen3-4b result of fabricated
  port numbers did not reproduce, so the docs now call it an earlier-run
  observation and say hallucinations vary between runs. Both Qwen models
  invented an unsupported risk framing on the no-risk-label process question
  in this run. The auto-select order is unchanged, since 4b's one-question
  edge is within run-to-run spread at about twice the routing latency.
- **Eval caveats, now disclosed:** smollm-360m's 16/16 comes entirely from a
  fallback that was tuned using two of the same 16 eval questions, so it is
  likely optimistic on new phrasings. Three of the routing few-shot
  examples also appear in the eval set, so the Qwen routing numbers are
  somewhat optimistic too. Separating the two is listed under "What's next"
  in the README.
