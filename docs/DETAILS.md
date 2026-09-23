# Details

Extended reasoning and full results referenced from the main [README](../README.md).
See [NOTES.md](../NOTES.md) for the running session-by-session log this was
written from.

## Sample transcript

_(Fake sample data, see [README Security](../README.md#security) for why real
output never gets committed.)_

```
> what's open on my machine?

Findings:
3 listening ports, 2 exposed to network, 1 high risk

sshd:
  pid 411, port 22/tcp, bind=*, exposed_to_network=True, service=SSH, risk=HIGH (Exposed to all network interfaces, high risk.)
postgres:
  pid 812, port 5432/tcp, bind=127.0.0.1, exposed_to_network=False, service=PostgreSQL, risk=LOW (Bound to localhost only.)
someapp:
  pid 930, port 51999/tcp, bind=*, exposed_to_network=True, service=Unknown service, risk=MEDIUM (Unrecognized port, not in the known-services table. Also exposed to all network interfaces.)

Model explanation: SSH on port 22 is open to the whole network, not just this
machine. Worth checking that's intentional. Postgres on 5432 is only reachable
from localhost, which is fine. Port 51999 is an unrecognized service exposed to
the network too; if you don't recognize "someapp", it's worth a closer look.

(routed via model: list_ports {})
```

## Known process labeling

A process's declared name (`argv[0]`) is easy to spoof, so `KNOWN_PROCESSES`
in `tools.py` only trusts a name match (`rapportd`, `ControlCenter`,
`Spotify`, `Code Helper`, `mimoe`) once the process's actual executable path
(from `ps -o comm=`, which the process can't fake) starts with the path that
service is expected to run from, e.g.
`/System/Library/CoreServices/ControlCenter.app/...` for ControlCenter. A
name match with a mismatched path falls back to the ordinary port-based
table instead of being trusted. `mimoe` is checked by name only, since it
has no fixed install location. It runs from wherever the user set it up.

Each `KNOWN_PROCESSES` entry sets its own network-exposed risk level, not a
blanket rule. Most of them (rapportd, ControlCenter, Spotify, Code Helper)
are broadcast/discovery services that are *meant* to be reachable on the
LAN, so exposure there is expected and gets INFO. `mimoe` is the deliberate
exception: it isn't meant to be reachable by other machines, and its API key
defaults to a fixed, shared value (see `.env.example`), so if it's exposed,
anyone on the local network can use this machine's inference endpoint. That
gets MEDIUM, with a note explaining why, the same as any other unexpectedly
network-exposed service.

## Model comparison

Full table (16-question routing eval + explain-step spot checks):

| Model | Size | Routing accuracy (16 Qs) | Avg routing latency | Explain-step quality | Avg explain latency |
|---|---|---|---|---|---|
| `smollm-360m` | 360M | 0% correct via model (1/16 attempted, 0 correct; 15/16 via keyword fallback) | ~410ms | Weakest of the three: frequently loops the same sentence verbatim, sometimes fabricates an entirely nonexistent second finding (an extra port/pid not in the data), and occasionally gives generic off-topic technical advice (e.g. suggesting unrelated shell commands) instead of explaining the actual finding | ~1.3s |
| `qwen3-1.7b` | 1.7B | 88% correct via model (14/16; 1 wrong, 1 fallback) | ~680ms | Coherent, grounded 2-4 sentence summaries referencing the actual finding and a sensible suggestion, on most questions; one observed case invented an unsupported "security threat" framing for a result that carried no risk label, despite the prompt saying not to invent risk assessments | ~1.5s |
| `qwen3-4b` | 4B | 94% correct via model (15/16; 1 wrong, 0 fallback) | ~1.35s | Similarly coherent and consistent; one observed case fabricated specific technical details (port numbers) that did not appear anywhere in the underlying data: a more concrete, specific-sounding hallucination than qwen3-1.7b's, even though the prose read smoothly | ~2.7s |

**Why `select_model` prefers `qwen3-1.7b`, then `qwen3-4b`, then
`smollm-360m`:** `qwen3-1.7b` gets the best balance of the three: routing
correctness the keyword fallback doesn't have to carry, and the lowest
latency of the two models that actually route well. `qwen3-4b` is second:
slightly more accurate (94% vs. 88%) but at roughly 2x the latency of
`qwen3-1.7b` on both steps, and its hallucinations run more
specific/plausible-sounding (fabricated port numbers) rather than less
frequent, arguably a worse failure mode to trust at a glance than
`qwen3-1.7b`'s vaguer invented framing. `smollm-360m` is last because its
routing depends on the keyword fallback and its explanations are the least
reliable of the three. It stays in the list because it ships with mimOE, so
it's the fallback when no Qwen model is loaded. It is the fastest, at ~410ms
routing.
The grounding-check warning below the explain step exists precisely because
none of these three models is hallucination-free.

**Qwen3 needed one fix to be usable at all:** it's a reasoning model that
emits a `<think>...</think>` block before answering, and at this agent's
existing token budgets (`max_tokens=60` for routing, `120` for explaining)
that reasoning consumed the *entire* budget, leaving no room for the actual
answer: confirmed by raising `max_tokens` well past those limits in
isolated testing and watching it still be mid-thought. Adding the literal
`/no_think` directive (which Qwen3 recognizes) to both system prompts fixed
this immediately; it's inert text to models that don't recognize it, so it
doesn't change `smollm-360m`'s behavior. `router.strip_think_blocks` also
strips any `<think>` block that does slip through before anything is
displayed, as a second layer.

Reproduce with `python3 evals/run_routing_eval.py --model <model-id>` and
`python3 evals/run_explain_eval.py --model <model-id>`, see
[evals/routing_questions.txt](../evals/routing_questions.txt) for the exact
16 questions.

## Web UI security

- Binds to `127.0.0.1` only, and refuses to start otherwise.
- Single-threaded (`HTTPServer`, not `ThreadingHTTPServer`): there's one
  global, process-wide "last question" used for follow-ups (a deliberate
  simplification, this is a single-operator tool, not a multi-user
  service), and single-threading makes it impossible for two concurrent
  requests to race on it.
- The `Host` header must resolve to `localhost`/`127.0.0.1`/`::1` (parsed,
  not prefix-matched, so `127.0.0.1.evil.com` is correctly rejected):
  the standard defense against DNS rebinding, where a page on an
  attacker-controlled domain gets your browser to connect to `127.0.0.1`
  while still sending that domain in the `Host` header.
- `Origin`, when present, must exactly match this server's own origin.
  Absent is allowed because non-browser clients like `curl` don't send one.
- No CORS headers, ever, and the API only accepts
  `Content-Type: application/json`. Both are real CSRF defenses, not just
  omissions: a cross-origin `fetch()` with a JSON body triggers a
  preflight `OPTIONS` request first, which gets no CORS permission here,
  so the browser blocks the real request before it's sent, and a plain
  HTML `<form>` (which can fire a simple, non-preflighted cross-origin
  POST) can't set `Content-Type: application/json` in the first place.
- Request bodies are capped at 4KB and questions at 500 characters,
  rejected before `process_question` ever runs.
- The frontend JS only ever writes system- or model-derived text (process
  names, args, the model's explanation, warnings) via `textContent`,
  never `innerHTML`: that data is untrusted, per the same reasoning as
  the "untrusted text" note in the main README's Security section.
