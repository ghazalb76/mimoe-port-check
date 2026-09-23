---
description: Audit the repo against this project's security invariants
---
Check each of these, and report pass/fail per item -- don't fix anything
found broken without asking first (per CLAUDE.md's "ask before design
decisions"):

1. **No real system output committed.** Scan `README.md`, `NOTES.md`,
   `tests/`, and `evals/` (including `evals/routing_questions.txt`) for
   anything that looks like real local data rather than the established
   fake/paraphrased examples -- an actual hostname, username, absolute
   path, or specific port/pid tied to a real running process.
2. **Redaction tests exist and pass.** Confirm `tests/test_tools.py` still
   covers `redact_secrets()` (passwords, tokens, API keys, `user:pass@host`
   connection strings), and run `python3 -m pytest tests/test_tools.py`.
3. **Localhost guards are intact.**
   - `mimoe_port_check/config.py`: `_assert_localhost` / `NonLocalEndpointError`
     still rejects a non-localhost `MIMOE_BASE_URL`, with no override flag.
   - `mimoe_port_check/web.py`: still binds to `127.0.0.1` only and refuses
     otherwise; `Host`/`Origin` checks and the no-CORS/JSON-only handling
     are still in place.
4. **No attribution lines in recent commits.** `git log -n 20 --format=%B`
   and confirm none contain `Co-Authored-By` or similar generated-attribution
   lines.

Summarize as a short pass/fail list, one line per item.
