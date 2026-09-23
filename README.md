# mimoe-port-check

A small local security-check agent: it inspects listening ports and processes
on **this machine only**, labels risk in code (a known-services/known-processes
table — never the model), and asks a model running in mimOE to explain the
findings in plain language. Why local inference matters here: what's
listening, which processes own it, and their command-line arguments are
sensitive — this agent refuses to run against anything but a localhost mimOE
endpoint, so that data never crosses a network boundary.

```
> what's open on my machine?

Findings:
3 listening ports, 2 exposed to network, 1 high risk

sshd:
  pid 411, port 22/tcp, bind=*, exposed_to_network=True, service=SSH, risk=HIGH (Exposed to all network interfaces — high risk.)
postgres:
  pid 812, port 5432/tcp, bind=127.0.0.1, exposed_to_network=False, service=PostgreSQL, risk=LOW (Bound to localhost only.)
someapp:
  pid 930, port 51999/tcp, bind=*, exposed_to_network=True, service=Unknown service, risk=MEDIUM (Unrecognized port — not in the known-services table. Also exposed to all network interfaces.)

Model explanation: SSH on port 22 is open to the whole network, not just this
machine — worth checking that's intentional. Postgres on 5432 is only reachable
from localhost, which is fine. Port 51999 is an unrecognized service exposed to
the network too; if you don't recognize "someapp", it's worth a closer look.

(routed via model: list_ports {})
```

_(Fake sample data — see [Security](#security) for why real output never gets
committed.)_

## Quick start

1. In mimOE Studio, load a model. `qwen3-1.7b` is recommended (see
   [Model comparison](#model-comparison)); `smollm-360m` also works, just with
   much weaker routing — the agent auto-selects whichever of these you have
   loaded.

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env      # edit if your mimOE setup differs from the defaults
python run.py
```

Then ask things like:
- `what's open on my machine?`
- `what's on port 5432?`
- `is anything risky listening?`
- a follow-up like `is it risky?` (reuses the port/process from your last question)

Type `exit` or Ctrl-D to quit.

## Web UI

A minimal local alternative to the CLI, same agent underneath:

```bash
python run_web.py               # http://127.0.0.1:8090, Ctrl-C to stop
python run_web.py --port 8123   # pick a different port
```

Open the printed URL in a browser: it shows the model in use (and the
SmolLM tip, if applicable), a question box, findings as a table with
colored risk badges, the explanation, any warnings, and how the question
was routed. Follow-ups work the same as the CLI (e.g. ask about a port,
then "is it risky?").

It's `mimoe_port_check/web.py` (a stdlib-only `http.server`, no new
dependency) plus one static `mimoe_port_check/static/index.html` (plain
HTML/CSS/JS, no build step) calling `GET /api/status` and
`POST /api/ask`. Both the CLI and the web UI call the exact same
`agent.process_question()` — the web UI doesn't reimplement any agent
logic, just renders its structured result.

**Security choices specific to the web UI** (see [Security](#security) for
everything shared with the CLI, like redaction and the localhost-only
inference guard, which apply here unchanged):
- Binds to `127.0.0.1` only, and refuses to start otherwise.
- Single-threaded (`HTTPServer`, not `ThreadingHTTPServer`): there's one
  global, process-wide "last question" used for follow-ups (a deliberate
  simplification — this is a single-operator tool, not a multi-user
  service), and single-threading makes it impossible for two concurrent
  requests to race on it.
- The `Host` header must resolve to `localhost`/`127.0.0.1`/`::1` (parsed,
  not prefix-matched, so `127.0.0.1.evil.com` is correctly rejected) —
  the standard defense against DNS rebinding, where a page on an
  attacker-controlled domain gets your browser to connect to `127.0.0.1`
  while still sending that domain in the `Host` header.
- `Origin`, when a browser sends one, must be exactly this server's own
  origin; absent is allowed (non-browser clients and same-origin `fetch()`
  calls don't send one).
- No CORS headers, ever, and the API only accepts
  `Content-Type: application/json`. Both are real CSRF defenses, not just
  omissions: a cross-origin `fetch()` with a JSON body triggers a
  preflight `OPTIONS` request first, which gets no CORS permission here,
  so the browser blocks the real request before it's sent — and a plain
  HTML `<form>` (which can fire a simple, non-preflighted cross-origin
  POST) can't set `Content-Type: application/json` in the first place.
- Request bodies are capped at 4KB and questions at 500 characters,
  rejected before `process_question` ever runs.
- The frontend JS only ever writes system- or model-derived text (process
  names, args, the model's explanation, warnings) via `textContent`,
  never `innerHTML` — that data is untrusted, per the same reasoning as
  the CLI's prompt-injection note in Security.

## Approach and design decisions

**Model picks a tool via JSON; code validates and falls back to keywords.**
Small local models aren't reliable at structured output — confirmed by hand
early on (SmolLM2-360M drifted off-topic even on a plain "say hello"). So
instead of trusting a framework's function-calling machinery, the agent asks
the model for one small JSON object (`{"tool": "...", "args": {...}}`) from a
3-tool menu, and every field is validated in code against a whitelist before
anything runs. If the JSON is missing, malformed, or names a tool/argument
that doesn't fit, a deterministic keyword matcher routes the question instead
— over the *user's own text*, never over whatever the model produced. See
[`router.py`](mimoe_port_check/router.py).

**No agent framework (LangChain, etc.); raw `requests`; `python-dotenv` for
config.** Given the structured-output unreliability above, a framework's
function-calling layer wouldn't have been more reliable than hand-rolled JSON
+ code validation — it would have added a dependency and an abstraction layer
without solving the actual problem. Talking to mimOE is a couple of calls to
one local OpenAI-compatible endpoint, so a raw `requests` client keeps every
request/response detail visible and easy to explain in review, at the cost of
an SDK's retries/typed models (not needed at this scale). `python-dotenv` is
the one small exception: a single pinned dependency for `.env` loading, worth
it for the ergonomics over manual `os.environ` parsing.

**Risk labels come from code, not the model.** A known-services table
(`KNOWN_SERVICES` in [`tools.py`](mimoe_port_check/tools.py)) maps ports like 22
(SSH) or 5432 (PostgreSQL) to a name and note; risk level is derived from that plus
whether the port is bound to all interfaces (`0.0.0.0`/`*`) or localhost only. The
model only explains results that are already computed — it never invents or
adjusts a risk label.

There are four risk levels:

| Risk   | Meaning |
|--------|---------|
| HIGH   | A sensitive service (SSH, a database, VNC, etc.) exposed to all network interfaces. |
| MEDIUM | Any other service — known or unknown — exposed to all network interfaces (this includes `mimoe` itself, see below). |
| LOW    | Bound to localhost only, so not reachable from the network. |
| INFO   | A recognized macOS *broadcast/discovery* service (see below) that's exposed to the network as part of its normal function — e.g. AirPlay or Spotify Connect broadcasting on the LAN. |

**Known processes are labeled by identity first, then by port, and the
identity match is path-verified.** A process's declared name (`argv[0]`) is
easy to spoof, so `KNOWN_PROCESSES` in `tools.py` only trusts a name match
(e.g. `rapportd`, `ControlCenter`, `Spotify`, `Code Helper`, `mimoe`) once
the process's actual executable path (from `ps -o comm=`, which the process
can't fake) starts with the path that service is expected to run from (e.g.
`/System/Library/CoreServices/ControlCenter.app/...` for ControlCenter). A
name match with a mismatched path falls back to the ordinary port-based
table instead of being trusted. `mimoe` is checked by name only, since it
has no fixed install location — it runs from wherever the user set it up.

Each `KNOWN_PROCESSES` entry sets its own network-exposed risk level, not a
blanket rule. Most of them (rapportd, ControlCenter, Spotify, Code Helper)
are broadcast/discovery services that are *meant* to be reachable on the
LAN, so exposure there is expected and gets INFO. `mimoe` is the deliberate
exception: it isn't meant to be reachable by other machines, and its API key
defaults to a fixed, shared value (see `.env.example`) — so if it's exposed,
anyone on the local network can use this machine's inference endpoint. That
gets MEDIUM, with a note explaining why, the same as any other unexpectedly
network-exposed service.

## How the components connect

```
CLI (run.py)
  │  user question
  ▼
agent loop (agent.py)
  │  startup: auto-select a model from what's loaded in mimOE if MIMOE_MODEL
  │  isn't set (client.select_model) -- see "Model comparison"
  │  resolve_route(): reuse context for short follow-ups; off-topic question
  │  (no port/pid/process/network keyword) or unmistakably non-numeric PID
  │  reference -> a fixed message, no tool or model call at all
  ▼
tool router (router.py)
  │  ask model for {"tool", "args"} → validate against whitelist
  │  a chosen port/pid not literally present in the question is rejected too
  │  invalid/missing/rejected → deterministic keyword fallback over the question
  ▼
tools (tools.py) — list_ports / inspect_process / check_exposure
  │  subprocess.run([...]) with argument lists only, no shell=True
  │  PID/port validated as int in range; secrets redacted from command lines
  ▼
mimOE endpoint (client.py) — POST /chat/completions
  │  explains the (already-computed, already-redacted) findings
  │  trimmed to its last complete sentence (agent.trim_to_complete_sentence)
  ▼
grounding + contradiction checks (agent.py)
  │  flag a mentioned port/pid not in what the model was given, or a stated
  │  exposure conclusion that disagrees with the findings
  ▼
findings + explanation (+ warning, if flagged) printed to the user
```

## Model comparison

The agent auto-selects a model at startup from whatever's actually loaded in
mimOE (see `client.select_model`) — `MIMOE_MODEL` in `.env` overrides this
if set. This section is informational and reproducing it doesn't change
that selection logic or any default. Run it yourself with:

```bash
python evals/run_routing_eval.py --model <model-id>
python evals/run_explain_eval.py --model <model-id>
```

| Model | Size | Routing accuracy (16 Qs) | Avg routing latency | Explain-step quality | Avg explain latency |
|---|---|---|---|---|---|
| `smollm-360m` | 360M | 0% correct via model (1/16 attempted, 0 correct; 100% effectively via keyword fallback) | ~410ms | Weakest of the three: frequently loops the same sentence verbatim, sometimes fabricates an entirely nonexistent second finding (an extra port/pid not in the data), and occasionally gives generic off-topic technical advice (e.g. suggesting unrelated shell commands) instead of explaining the actual finding | ~1.3s |
| `qwen3-1.7b` | 1.7B | 88% correct via model (14/16; 1 wrong, 1 fallback) | ~680ms | Coherent, grounded 2-4 sentence summaries referencing the actual finding and a sensible suggestion, on most questions; one observed case invented an unsupported "security threat" framing for a result that carried no risk label, despite the prompt saying not to invent risk assessments | ~1.5s |
| `qwen3-4b` | 4B | 94% correct via model (15/16; 1 wrong, 0 fallback) | ~1.35s | Similarly coherent and consistent; one observed case fabricated specific technical details (port numbers) that did not appear anywhere in the underlying data — a more concrete, specific-sounding hallucination than qwen3-1.7b's, even though the prose read smoothly | ~2.7s |

**Why `select_model` prefers `qwen3-1.7b`, then `qwen3-4b`, then
`smollm-360m`:** `qwen3-1.7b` gets the best balance of the three — routing
correctness the keyword fallback doesn't have to carry, and the lowest
latency of the two models that actually route well. `qwen3-4b` is second:
slightly more accurate (94% vs. 88%) but at roughly 2x the latency of
`qwen3-1.7b` on both steps, and its hallucinations run more
specific/plausible-sounding (fabricated port numbers) rather than less
frequent — arguably a worse failure mode to trust at a glance than
`qwen3-1.7b`'s vaguer invented framing. `smollm-360m` is last on the list,
not because it's fast (it is, ~410ms vs. ~680ms+), but because it ships
with mimOE by default and something has to be the fallback when neither
Qwen model happens to be loaded — its routing is carried entirely by the
keyword fallback, and its explanations are the least reliable of the three.
The grounding-check warning below the explain step exists precisely because
none of these three models is hallucination-free.

**Qwen3 needed one fix to be usable at all:** it's a reasoning model that
emits a `<think>...</think>` block before answering, and at this agent's
existing token budgets (`max_tokens=60` for routing, `120` for explaining)
that reasoning consumed the *entire* budget, leaving no room for the actual
answer — confirmed by raising `max_tokens` well past those limits in
isolated testing and watching it still be mid-thought. Adding the literal
`/no_think` directive (which Qwen3 recognizes) to both system prompts fixed
this immediately; it's inert text to models that don't recognize it, so it
doesn't change `smollm-360m`'s behavior. `router.strip_think_blocks` also
strips any `<think>` block that does slip through before anything is
displayed, as a second layer.

## Security

- **Argument-list subprocess calls only, never `shell=True`.** `list_ports` runs
  `lsof -i -P -n`; `inspect_process` runs `ps -p <pid> -o ...`. No string is ever
  built and handed to a shell.
- **All tool arguments are validated in code.** A PID or port from the model or
  the keyword fallback is checked to be an `int` (bools are explicitly rejected,
  since `bool` is a subclass of `int` in Python) in the expected range before it's
  used in a command.
- **The model only picks from a whitelist of 3 read-only tools.** Its raw text
  output is never executed or interpreted as a command — it's parsed as JSON,
  and only a recognized tool name proceeds.
- **Process names and command lines are treated as untrusted, attacker-influenceable
  text** (prompt-injection risk: a process could name itself something like
  "ignore previous instructions..."). The explain-step system prompt explicitly
  tells the model to treat this data as plain text to describe, never as
  instructions — but the real backstop is architectural: that data can only ever
  reach the *explain* step (which only produces printed prose), never the
  *routing* step or a command argument.
- **Secrets are redacted before printing or sending anything to the model.**
  `redact_secrets()` in `tools.py` strips likely passwords, tokens, API keys, and
  `user:pass@host`-style connection strings out of command-line text, applied at
  the tool boundary — before the data leaves `tools.py` at all.
- **No raw output is logged.** What's printed to the terminal is the same
  already-redacted data sent to the model; nothing extra is written to disk.
- **No real system output is committed.** README, NOTES.md, tests, and evals
  all use fabricated or genuinely non-identifying sample data.
- **Hard refusal on a non-localhost inference URL.** `config.py` checks the
  hostname in `MIMOE_BASE_URL` and refuses to start if it isn't
  `localhost`/`127.0.0.1`/`::1` — no override flag, since sending local system
  data to a non-local endpoint should require a deliberate code change, not a
  runtime flag. This is what makes local inference the actual security
  property here, not just a performance choice.
- **No `sudo`, no state-changing actions.** Every tool is read-only and
  informational; the agent never kills a process or changes a system setting.
- **`.env` is gitignored**; dependencies are minimal and pinned
  (`requests`, `python-dotenv`).

## Limitations

- **The model's explanation step is unreliable, so it's kept off the critical
  path.** The agent always prints the code-computed findings *before* the
  model's prose (findings are the source of truth), skips the model
  entirely when there's nothing to explain, sends it only a short
  pre-filtered summary of notable findings rather than the full results,
  trims a truncated mid-sentence response to its last complete sentence, and
  runs best-effort grounding and exposure-contradiction checks afterward to
  flag invented specifics or a stated conclusion that disagrees with the
  findings. None of this makes the model reliable — see
  [Model comparison](#model-comparison) for how unreliable, concretely — it
  just keeps the tool's correctness from depending on the model's fluency.
- **Routing correctness depends heavily on which model is loaded, and isn't
  fully delegated to the model even when one is.** `evals/run_routing_eval.py`
  (16 varied questions, reproducible) is how the numbers in the Model
  comparison table were measured; the keyword fallback is what actually
  routes every question when `smollm-360m` is loaded, not the model. On top
  of that, a model-chosen port/pid is rejected (and the question falls
  through to the keyword fallback) unless that exact number actually appears
  in the user's question -- live testing found a model parroting its last
  few-shot example's answer verbatim for unrelated questions, which this
  catches regardless of which model is loaded. An off-topic question (no
  port/pid/process/network keyword at all) or an unmistakably non-numeric
  PID reference (e.g. "process abc") never reaches the model at all.
- **The grounding, contradiction, and off-topic/invalid-input checks are all
  conservative keyword heuristics, not guarantees.** The grounding check
  only catches a fabricated number immediately preceded by
  "port"/"pid"/"process"; the contradiction check only fires when both texts
  are unambiguous in one direction; the off-topic gate is a fixed keyword
  list, so a legitimately on-topic question that happens to avoid all of
  them would be misclassified. Each was chosen to avoid false positives at
  the cost of missing some real issues -- see the code comments in
  `agent.py` for the specific tradeoffs.
- **SmolLM2 sometimes contradicts the risk level it was given, and there's
  no check for this.** E.g. calling a LOW-risk, localhost-only port "not
  safe" -- the opposite problem from the exposure-contradiction check above
  (which only compares *exposure* direction, not risk-level wording). The
  code-computed findings are shown before the model's prose specifically so
  a wrong risk-level characterization doesn't stand alone as the only thing
  the user sees; larger models (see Model comparison) make this less
  frequent but haven't eliminated it in testing.
- **macOS only, for now.** `list_ports`/`inspect_process` parse `lsof`/`ps` output
  in their macOS (BSD) format.
- **UDP sockets are excluded from `list_ports`.** UDP has no connection state
  comparable to TCP's `LISTEN`, so "is this port open" is ambiguous for UDP in a
  way that seemed worth flagging rather than guessing at.
- **Follow-up context is a single-slot memory** (the last tool+args), not a full
  conversation history passed back to the model — kept deliberately simple given
  how unreliable the model already is with a *single* turn of structured input.

## What's next

- **Linux support.** `list_ports`/`inspect_process` would need `/proc` or
  GNU `ps`/`ss` output parsing instead of macOS `lsof`/`ps` (BSD) format.
- **Deploy as a mim inside mimOE itself**, instead of a standalone CLI —
  would remove the separate client/server hop entirely.
- **Mesh discovery.** mimOE can discover other mimOE instances on the local
  network; this agent doesn't use that today. Any future use would need to
  preserve the localhost-only guarantee for the *data being inspected* even
  if inference itself became distributed across the mesh — worth exploring
  carefully rather than adopting by default, since it's in tension with the
  "this data never leaves the machine" property the agent currently enforces.
- **Stricter output grammar/constrained decoding for the explain step**, if
  mimOE exposes one, as a stronger alternative to the current
  prompt-plus-grounding-check approach to reducing hallucination.

## How I used AI assistance

I used Claude Code throughout, with a workflow I set upfront: curl the endpoint
first to confirm it actually worked, get a plan approved before any code, and land
a commit after each small step with an explanation of the reasoning. A full,
running log of what I asked for, what I changed, and what I verified myself is in
[`NOTES.md`](NOTES.md) — written as we went, not reconstructed afterward.

The short version: I asked for a design that anticipated the model's
unreliability (JSON tool choice with a code fallback, code-owned risk labels)
rather than one that assumed a capable model. While testing the running agent
against the live SmolLM2-360M, Claude saw the explanation step degrade into
hallucinated Python code, tried a few prompt/temperature variants live against
the endpoint, and — on its own, without asking me first — changed the design so
the deterministic findings are always shown above the model's prose. I reviewed
that reasoning after the fact and agreed with it, but it's logged in `NOTES.md`
as what it was: a call Claude made autonomously, not one I asked for. I verified
the security-relevant behavior myself: the localhost-refusal guard, the
connection-error path, and the argument-list subprocess calls, by running the
CLI directly against real conditions (a bad URL, a wrong port, real PIDs) rather
than only trusting the test suite.
