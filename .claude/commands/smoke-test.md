---
description: End-to-end live smoke test against controlled fixture listeners
---
Reproduce the hand-run live testing from NOTES.md (Sessions 2, 4, 5), but
against controlled fixtures instead of whatever happens to be listening on
this machine, so results are deterministic and repeatable.

1. Confirm mimOE is reachable (see `eval-model`'s first step). Stop if not.
2. Start two throwaway TCP listeners for the duration of this test:
   - `0.0.0.0:8765` -- exposed to all interfaces.
   - `127.0.0.1:8766` -- localhost only.
   (A trivial `socket.socket(...).listen()` per port is enough; they don't
   need to speak any protocol.)
3. Run the CLI (or web UI) against these questions and check actual output
   against expected:
   - "what's open on my machine?" -> `list_ports`; both 8765 and 8766 appear.
   - "is port 8765 exposed to the network?" -> `check_exposure`; exposed,
     unrecognized-service risk (MEDIUM, since it's not in `KNOWN_SERVICES`).
   - "is port 8766 exposed to the network?" -> `check_exposure`; LOW,
     bound to localhost only.
   - "is it risky?" immediately after -- a referential follow-up; must reuse
     the last port/pid without a number in the question.
   - "tell me about process <a real pid from one of the listeners>" ->
     `inspect_process`; found, correct pid/command.
   - "process abc" -> invalid-PID message, no tool run, no model call.
   - "what's the weather?" -> off-topic message, no tool run, no model call.
4. Report pass/fail per question against the expected result above.
5. Stop both listeners before finishing, even on failure.

Don't print or log real process names/paths from anything other than the
two fixture listeners started in step 2.
