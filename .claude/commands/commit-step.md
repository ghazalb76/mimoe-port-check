---
description: Run tests; if green, commit this step with the reasoning explained
---
1. Run the full test suite: `pytest`.
2. If anything fails, stop here and report the failures -- don't commit.
3. If green, `git status`/`git diff` to see what's actually staged/changed,
   stage only the files relevant to this step (not an unrelated `git add
   -A`), and commit.
4. Write the commit message around *why* this step was needed, not just a
   restatement of the diff -- matches how every commit in this repo's
   history was landed (see `NOTES.md`).
5. No `Co-Authored-By` or other attribution lines, per `CLAUDE.md`.

This is one small step, not a batch of unrelated changes -- if the working
tree has changes from more than one logical step, ask which to commit first
rather than bundling them.
