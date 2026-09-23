# mimoe-port-check

A small local security check agent. It inspects listening ports and processes on
**this machine only**, labels risk from a known-services table in code, and asks a
local LLM (via mimOE Studio, OpenAI-compatible API) to explain the findings in plain
language.

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

_(The transcript above uses fake sample data — see [Security](#security) for why
real output never gets committed. The [Limitations](#limitations) section is
honest about where the model's explanation is less reliable than this.)_

## How to run it

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

## Approach and design decisions

**Model picks a tool via JSON; code validates and falls back to keywords.**
SmolLM2-360M is small and, confirmed by hand while building this, not reliable at
structured output — it drifts off-topic even on a plain "say hello." So instead of
trusting a framework's function-calling machinery, the agent asks the model for one
small JSON object (`{"tool": "...", "args": {...}}`) from a 3-tool menu, and every
field is validated in code against a whitelist before anything runs. If the JSON is
missing, malformed, or names a tool/argument that doesn't fit, a deterministic
keyword matcher routes the question instead — over the *user's own text*, never
over whatever the model produced. See [`router.py`](mimoe_port_check/router.py).

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
| MEDIUM | Any other service — known or unknown — exposed to all network interfaces. |
| LOW    | Bound to localhost only, so not reachable from the network. |
| INFO   | A recognized macOS system/app service (see below) that's exposed to the network as part of its normal function — e.g. AirPlay or Spotify Connect broadcasting on the LAN. |

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

**Raw `requests` over the `openai` SDK.** This is one POST to one endpoint
(`/chat/completions`, non-streaming). Writing the HTTP call by hand keeps every
request/response detail visible and easy to explain in a review, at the cost of
the SDK's retries and typed response models — not worth pulling in a dependency
for, at this scale.

**Why local inference matters here.** The data this agent handles — what's
listening, what process owns it, command-line arguments — is exactly the kind of
thing you don't want leaving the machine. Running inference locally via mimOE means
that data never crosses a network boundary. The agent enforces this itself: it
refuses to start if the configured inference URL isn't `localhost` (see
[Security](#security)).

## How the components connect

```
CLI (run.py)
  │  user question
  ▼
agent loop (agent.py)
  │  resolve_route(): reuse context for short follow-ups, else...
  ▼
tool router (router.py)
  │  ask model for {"tool", "args"} → validate against whitelist
  │  invalid/missing → deterministic keyword fallback over the question text
  ▼
tools (tools.py) — list_ports / inspect_process / check_exposure
  │  subprocess.run([...]) with argument lists only, no shell=True
  │  PID/port validated as int in range; secrets redacted from command lines
  ▼
mimOE endpoint (client.py) — POST /chat/completions
  │
  ▼
SmolLM2-360M — explains the (already-computed, already-redacted) findings
  │
  ▼
answer printed to the user, alongside the raw findings
```

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
- **No real system output is committed.** README, tests, and this transcript all
  use fabricated sample data (fake PIDs, fake hostnames).
- **Hard refusal on a non-localhost inference URL.** `config.py` checks the
  hostname in `MIMOE_BASE_URL` and refuses to start if it isn't
  `localhost`/`127.0.0.1`/`::1` — no override flag, since sending local system
  data to a non-local endpoint should require a deliberate code change, not a
  runtime flag.
- **No `sudo`, no state-changing actions.** Every tool is read-only and
  informational; the agent never kills a process or changes a system setting.
- **`.env` is gitignored**; dependencies are minimal and pinned
  (`requests`, `python-dotenv`).

## Limitations

- **The model's explanation step is unreliable.** Hand-testing against the real
  running SmolLM2-360M showed it sometimes just echoes the findings back, and
  sometimes hallucinates unrelated Python code, even at low temperature —
  documented in `NOTES.md` as it was found. This is why the agent always prints
  the code-computed findings *before* the model's prose: the findings are the
  source of truth, the explanation is a best-effort layer on top that may degrade
  without the tool's correctness degrading with it.
- **macOS only, for now.** `list_ports`/`inspect_process` parse `lsof`/`ps` output
  in their macOS (BSD) format. Linux support (`/proc`, or GNU `ps`/`ss` output
  parsing) would be a natural next step.
- **UDP sockets are excluded from `list_ports`.** UDP has no connection state
  comparable to TCP's `LISTEN`, so "is this port open" is ambiguous for UDP in a
  way that seemed worth flagging rather than guessing at.
- **Follow-up context is a single-slot memory** (the last tool+args), not a full
  conversation history passed back to the model — kept deliberately simple given
  how unreliable the model already is with a *single* turn of structured input.
- **What's next:** Linux support; deploying this as a mim inside mimOE itself
  instead of a standalone CLI; possibly a stricter output grammar/constrained
  decoding for the explain step if mimOE exposes one, to reduce the rambling
  described above.

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
