---
description: Run tests; if green, commit this logical unit with a clear message
---
1. Run the full test suite: `pytest`.
2. If anything fails, stop here and report the failures -- don't commit.
3. If green, `git status`/`git diff` to see what's actually staged/changed.
4. Group related work into one commit per logical unit (a feature, a fix
   with its tests, a docs pass), not a commit per small change. Stage what
   belongs to this unit, not an unrelated `git add -A`.
5. Write the commit message like a senior full-stack engineer: an
   imperative subject line under 72 characters that says what changed, a
   blank line, then a short body explaining why and any notable tradeoff.
   No filler, no attribution lines (per `CLAUDE.md`). Example:

   ```
   Tighten explanation checks for live model output

   The contradiction check flagged advice like "ensure they're not
   exposed" as a claim. Match only claim-style phrasing and skip
   negations after advice verbs. Also strip markdown the model adds,
   since the UI renders plain text for XSS safety.
   ```

If the working tree has changes from more than one logical unit, ask which
to commit first rather than bundling them.
