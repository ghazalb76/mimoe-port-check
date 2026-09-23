# mimoe-port-check

A local security-check agent: code computes findings and risk labels, a
model running in mimOE explains them in plain language. See `README.md` for
architecture and design rationale, and `NOTES.md` for the running log of how
this repo was actually built.

## Project rules

- **Ask before design decisions.** Don't make an architectural or behavioral
  call unilaterally -- surface it and get a decision before implementing. If
  a call has to be made mid-task, implement it, but flag clearly afterward
  that it was made autonomously and needs review (see `NOTES.md` Session 1
  for how this has been handled before: a decision was implemented, then
  logged and approved after the fact rather than presented as if it had been
  asked for).
- **Never commit real system output.** README, NOTES.md, tests, and evals
  must only ever use fabricated or genuinely non-identifying sample data --
  real `lsof`/`ps` output, process names, ports, PIDs, or paths from any
  actual machine never get written to a tracked file.
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
- **Run the full test suite (`pytest`) after each commit.**
