# VibeGuard Implementation Log

Running, append-only history of deviations from CLAUDE.md's original plan.
See CLAUDE.md Section 8 for the rules governing this file. Where this log
and CLAUDE.md conflict, this log reflects current reality.

---

## [2026-07-10] - Project scaffolding and Python version pin
**What the plan said:** CLAUDE.md Section 6 specifies the approved directory
structure and Section 4/6 specify tooling (black, ruff, mypy, pytest) and
dependencies, without pinning a Python interpreter version.
**What we actually did / found:** The system default `python3` is 3.14.3
(via Homebrew), which is too new for reliable prebuilt wheels of
`shap`/`xgboost`/`scikit-learn` at the time of writing. Created the project
virtualenv against `pyenv`-managed Python 3.10.13 instead and pinned
`requires-python = ">=3.10,<3.11"` in `pyproject.toml`.
**Why:** Avoids build-from-source failures and version-compatibility
churn for the ML dependency stack (Layer 4) later in the project.
**Effect on thesis chapters:** Chapter 4 (implementation/environment
description) should state Python 3.10 as the target interpreter, not
"latest Python."

---

## [2026-07-10] - Layer 1 `ast_parser.py`: parse-timeout is a soft mitigation
**What the plan said:** CLAUDE.md Section 5 requires "limits on input size
and parse time per file (a large or adversarial file must not hang or OOM
the process)."
**What we actually did / found:** File-size limiting is a hard guarantee
(`_check_size`, enforced before any parsing happens). Parse-time limiting
is not: `_run_with_timeout` runs `javalang.parse.parse` on a `daemon=True`
background thread and gives up waiting after `timeout_seconds`, so the
*caller* never hangs and the *process* can still exit — but CPython has no
supported way to forcibly kill a running thread, so a truly pathological
input keeps burning CPU on an orphaned thread in the background rather
than being terminated outright. True isolation would need a subprocess
per file, which was judged unnecessary overhead for this project's local,
single-machine scope. Verified against a fixture test (`javalang.parse.parse`
monkeypatched to sleep) that the caller gets `ParseStatus.PARSE_TIMEOUT`
back promptly rather than blocking.
**Why:** A subprocess-per-file architecture would meaningfully complicate
`scanner.py`'s orchestration (process pools, IPC of the AST result) for a
threat model — adversarial Java source designed to hang a parser — that's
a secondary robustness concern, not the thesis's core contribution.
**Effect on thesis chapters:** Chapter 4/5 robustness evaluation section
should describe this explicitly as a documented limitation (soft
wall-clock budget, not hard process isolation) rather than claim full
adversarial-input isolation.
