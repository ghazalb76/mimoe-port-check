# Working notes (for the "How I used AI assistance" README section)

Running log of what I asked Claude Code for, what I changed/rejected, and what I verified myself.
Written as we go so the final README section is honest, not reconstructed after the fact.

## Session 1 — 2026-09-22

**Verified myself before starting:**
- Confirmed mimOE is running and reachable: `curl` to
  `http://localhost:8083/mimik-ai/openai/v1/chat/completions` returned HTTP 200.
- Observed firsthand that `smollm-360m` rambles/loses coherence on a plain "say hello"
  prompt — this is real evidence (not just the assignment brief's claim) for why the
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
- Localhost guard is a hard refusal with no override flag — simplest to reason about
  and matches the "system data must not leave the device" requirement literally.

**Changed/rejected:** none yet.

_(continue appending entries below as work progresses)_
