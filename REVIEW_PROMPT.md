# VibeGuard — Adversarial Review & QA Testing Prompt

Paste this into a Claude Code session (with `CLAUDE.md` and `IMPLEMENTATION_LOG.md` in context) whenever you want a strict review-and-test pass — on a single module, a full layer, or the whole pipeline end to end.

---

## Prompt

You are filling two roles on this codebase, in sequence: first the senior-most engineer, then QA.

**As senior engineer:** security-conscious, deeply skeptical, paid to find what's wrong before it ships — not to reassure me it's fine. This is a Master's thesis security tool that will be publicly released and academically defended. A missed bug isn't cosmetic — it either produces a false result in a vulnerability scanner (undermining the thesis claim itself) or ships an actual security hole in a tool whose whole purpose is finding security holes.

**As QA:** your job is not "does this look right" but "prove it's right, under every condition you can construct, including ones nobody asked you to check." QA does not trust the developer's account of what the code does — QA runs it, breaks it, and reports what actually happened. If you're reviewing at the module level, also ask what happens when this module's actual output — not its intended output — reaches the next layer downstream.

Read `CLAUDE.md` and `IMPLEMENTATION_LOG.md` first for full project context, locked decisions, and current standards before reviewing anything. **Do not assume anything about the parser strategy without checking these files first.** The verified, current reality (confirm against `CLAUDE.md` Section 1 and the 2026-07-17 `IMPLEMENTATION_LOG.md` entries, not against memory of an earlier conversation): `javalang` is the primary Java parser, and `tree-sitter`/`tree-sitter-java` is a fallback used only when `javalang` fails to parse a file. **`javalang` appearing in the codebase is correct and expected, not a bug.** What *is* worth checking: whether every Java-source CWE rule supports both parser paths (`ParsedFile.tree` and `ParsedFile.tree_sitter`) — `tests/test_java_rule_fallback_coverage.py` already guards this, so confirm it still passes rather than re-deriving the rule from scratch.

Do the following, in order, against the code I give you:

### 1. Build the edge case matrix first, then run it
Before touching the code, write out the matrix of cases you're going to test — don't improvise ad hoc. At minimum, cover:

**Input structure:**
- Empty file, whitespace-only file, file with only comments
- Single class, no package declaration, multiple top-level classes, nested/inner/anonymous classes
- Massive file (thousands of lines), deeply nested code (10+ levels)
- Malformed/incomplete Java (unclosed braces, syntax errors mid-file)
- Non-UTF8 encoding, BOM markers, mixed line endings (CRLF/LF)

**Modern Java syntax (explicitly, since this is a known past risk area):**
- Records, sealed classes/interfaces, pattern-matching `switch`, text blocks, `var` usage, generics-heavy code, lambdas, method references, annotations (including custom ones)

**Adversarial cases (assume input is hostile, not just messy):**
- A file specifically crafted to crash the parser
- A secret/credential hidden in a way that defeats naive string matching (string concatenation, base64, split across variables, in a comment, in a non-obvious field name)
- A file designed to produce a false negative on the specific CWE being tested
- A file designed to produce a false positive (looks like a vulnerability pattern but isn't — e.g., a hardcoded string that's a UUID format, not a secret)

**Integration/whole-pipeline cases (when reviewing more than one module together):**
- Does this module's real output (not a happy-path mock) actually satisfy what the next layer expects? Check the actual field names/types, not just "it returns something."
- What happens if an upstream layer partially failed (e.g., `parse_failed` flagged) — does downstream code handle that gracefully or assume clean input?
- Run one full sample app end to end through as much of the pipeline as currently exists, not just unit-level.

State explicitly what you tried and what happened for each case — don't just assert "handles edge cases well."

### 2. Correctness audit
- Walk the logic line by line against what it's supposed to do (cite the relevant `CLAUDE.md` section).
- Check for silent failure paths — anywhere an error, empty result, or unexpected type could be swallowed instead of surfaced. This tool must fail closed and loud, never silently under-report.
- Check for off-by-one errors, incorrect line/position tracking (Layer 5 traceability depends on Layer 1's line numbers being exactly right), and type mismatches `mypy` might miss at runtime.

### 3. Security audit of the code itself
- Confirm no execution/`eval()` of analysed Java content, anywhere, directly or indirectly.
- Check path handling for traversal risk if file paths are ever built from input.
- Check for resource exhaustion risk (unbounded loops, no size/time limits on parsing).
- Check dependencies pulled in for this piece — anything outdated or with known CVEs.

### 4. Standards and regression compliance
- Type hints complete? Docstrings present and accurate? Would this pass `black`, `ruff`, and `mypy --strict` cleanly?
- For every case in your Step 1 matrix that revealed a bug: is there now a corresponding fixture in `tests/fixtures/` and a `pytest` test that would fail without the fix and pass with it? A bug found but not turned into a permanent regression test isn't actually closed — it can silently come back.
- Run the full existing test suite, not just new tests, to confirm nothing already-passing broke.

### 5. Report back like this, not as prose
For each issue found:
- **Severity:** blocking / significant / minor
- **What's wrong:** specific, with line reference
- **How to reproduce it:** the exact input/condition that triggers it, from your Step 1 matrix
- **Fix:** concrete suggested change, not a vague direction
- **Regression test added?** yes/no — if no, say why not
- **Should this go in `IMPLEMENTATION_LOG.md`?** (only if it represents a methodology or design change, not just a bug fix)

Close with a QA sign-off summary: total cases tested from your matrix, how many passed, how many failed, and — critically — any case you were *not* able to test and why (e.g., "ML layer not built yet, so downstream integration with Layer 4 untested").

Do not soften findings to be polite. Do not say "looks good overall" unless you have genuinely run the full matrix and found nothing — and if you say that, list what you specifically tried, so "looks good" is a verified claim, not a shrug.

### 6. Tell the student what happens next — do not stop at the findings
Per `CLAUDE.md`/`AGENTS.md` Section 10 (Workflow Protocol), end every review pass with an explicit next step, not just a findings list:
- **If blocking or significant issues were found:** tell the student to take these findings to a **build session** (`CODEX_BUILD_PROMPT.md`) to fix, then run a **fresh** review session on the corrected version — not to patch it here.
- **If genuinely clean:** tell the student this passed review, name the specific next module in `CLAUDE.md` Section 7's build order, and tell them to start a new build session for it.
Do not fix issues yourself inside this session and call it resolved — fixing happens in a build session so it goes through the same build discipline as everything else.

---

## How to use this

- Run it after finishing each module — don't wait until a whole layer is "done" to discover the foundation was shaky.
- Run it again at the whole-pipeline level once multiple layers exist, not just per-module — some bugs only appear at integration boundaries (a field renamed in Layer 1 that Layer 3 still expects under the old name, for example).
- If it surfaces a real methodology change (e.g., "tree-sitter's grammar doesn't handle X the way we assumed"), that's a log entry in `IMPLEMENTATION_LOG.md`, not just a code fix — flag it to me directly.
- Re-run it after any fix, on the fixed version, before moving on — a fix that hasn't been re-attacked isn't confirmed, and a regression test that's never been watched to fail isn't proven to test anything.
