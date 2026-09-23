# mimoe-port-check

A local security-check agent: code computes findings and risk labels, a
model running in mimOE explains them in plain language. See `README.md` for
architecture and design rationale, and `NOTES.md` for the running log of how
this repo was actually built.

## Project rules

- **Ask before design decisions.** Don't make an architectural or behavioral
  call unilaterally: surface it and get a decision before implementing. If a
  call must be made mid-task, implement it and flag it clearly for review
  afterward.
- **Never commit real system output.** README, NOTES.md, tests, and evals
  must only ever use fabricated or genuinely non-identifying sample data:
  real `lsof`/`ps` output, process names, ports, PIDs, or paths from any
  actual machine never get written to a tracked file. The README's web UI
  screenshot (`docs/screenshot.png`) is the one deliberate exception,
  cropped to show only mimOE and a local test server, no identifying
  system data.
- **The model only picks tools and explains findings; it never computes
  risk.** Risk labels come from code (`KNOWN_SERVICES`/`KNOWN_PROCESSES` in
  `mimoe_port_check/tools.py`) and are never invented or adjusted by the
  model. The model's role is limited to (1) choosing a tool via JSON,
  validated against a whitelist, and (2) explaining already-computed
  findings in plain language.
- **Tools are read-only, argument-list `subprocess` calls only.** No
  `shell=True`, ever. Every PID/port argument (from the model or the keyword
  fallback) is validated as an `int` in range before use.
- **Localhost-only, no exceptions.** Both the mimOE inference endpoint
  (`config.py`'s `NonLocalEndpointError` guard) and the web UI (binds to
  `127.0.0.1` only) must refuse to run against anything but
  `localhost`/`127.0.0.1`/`::1`. No override flag for either.
- **No attribution lines in commits.**
- **Run the full test suite (`python3 -m pytest`) before each commit; commit
  only when green.**
- **Group commits by logical unit, not by every small change.** One
  meaningful commit per feature, per fix-with-its-tests, or per docs pass,
  not a commit per tiny edit. Write the message like a senior full-stack
  engineer: an imperative subject line under 72 characters that says what
  changed, a blank line, then a short body explaining why and any notable
  tradeoff. No filler.
