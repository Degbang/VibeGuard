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

---

## [2026-07-11] - Layer 1 scope extended to non-Java config files for CWE-798
**What the plan said:** CLAUDE.md Section 1/2 frame Layer 1 as "AST
detection" via `javalang`, implicitly scoped to `.java` source only.
**What we actually did / found:** In real Quarkus/Spring projects,
hardcoded credentials targeted by CWE-798 (e.g.
`quarkus.datasource.password=...`) are at least as likely to live in
`application.properties`/`application.yml` as in `.java` source -
arguably more likely, since externalizing config to these files is the
idiomatic pattern these frameworks encourage. Since the evaluation
dataset is planned to include real public repos (not only
self-generated sample apps), restricting CWE-798 detection to `.java`
AST findings would systematically under-detect the most common
real-world instance of this exact CWE. Added
`vibeguard/layer1_static/config_parser.py` as a sibling to
`ast_parser.py`: a non-AST (`javalang` cannot parse non-Java syntax)
key-value parser for `.properties` and `.yml`/`.yaml`, producing a
`ParsedConfigFile` with flattened, dotted keys (e.g.
`quarkus.datasource.password`) and line numbers, in the same
fail-closed style as `ast_parser.py` (explicit `ConfigParseStatus`,
size limit, soft timeout - YAML anchor/alias expansion is a known DoS
vector, so the timeout guard applies there specifically). Added
`pyyaml` to `requirements.txt` (not in CLAUDE.md Section 6's original
dependency list) to parse YAML safely (`SafeLoader`) rather than
hand-rolling a YAML parser. Refactored the shared size-limit/safe-read
and soft-timeout logic out of `ast_parser.py` into
`vibeguard/layer1_static/_parsing_guards.py` so both parsers get
identical, single-sourced safety guarantees instead of duplicated
(and potentially drifting) copies.
**Why:** A CWE-798 rule module built only on top of `ast_parser.py`
would be defensible for synthetic, self-generated sample apps but not
for a real-world evaluation against public repositories, where this
is the dominant hardcoded-secret pattern for the Java/Quarkus
ecosystem this thesis targets.
**Effect on thesis chapters:** Chapter 3 (methodology) should describe
Layer 1 as covering two input types - Java AST and flattened config
key-value pairs - not `javalang`/AST alone. Chapter 4 should list
`pyyaml` as an added dependency with its justification. Chapter 5's
CWE-798 evaluation should report findings split by source type
(Java source vs. config file) to make this coverage decision visible
in the results, not just in this log.

---

## [2026-07-13] - Dependency vulnerability remediation
**What the plan said:** CLAUDE.md Section 5 asks for "periodically
check for known-vulnerable dependencies," calling out that a security
thesis's own tooling passing a dependency audit is a rigor point worth
noting in Chapter 5.
**What we actually did / found:** Ran `safety check` against
`requirements.txt` for the first time since the baseline dependency
list was pinned. Found 12 known vulnerabilities across 6 packages:
`pytest` (8.0.0, DoS via insecure temp directory handling,
CVE-2025-71176), `black` (24.1.1, two issues, one a ReDoS), `requests`
(2.31.0, three issues including a URL-parsing flaw), `jinja2` (3.1.3,
four issues including a sandbox escape via the `|attr` filter,
CVE-2025-27516), `python-dotenv` (1.0.1, arbitrary file overwrite via
unsafe symlink handling, CVE-2026-28684), and `scikit-learn` (1.4.0, a
`TfidfVectorizer` data-leakage issue, CVE-2024-5206). Bumped all six to
the minimum version each advisory lists as fixed (not latest, to
minimize unrelated breaking-change risk): `pytest==9.0.3`,
`black==26.3.1`, `requests==2.33.0`, `jinja2==3.1.6`,
`python-dotenv==1.2.2`, `scikit-learn==1.5.0`. `safety` itself
(3.0.1) also turned out to be broken against its own current
transitive `typer` dependency (`AttributeError: module 'typer' has no
attribute 'rich_utils'`) independent of any CVE - bumped to `3.8.1` to
get a working scanner, not because 3.0.1 itself was flagged.
Rebuilt the venv from a clean state against the updated
`requirements.txt` and re-ran the full test suite (25 tests passing at
the time) plus `black`/`ruff`/`mypy` to confirm the bumps introduced
no breakage. Re-ran `safety check`: 0 vulnerabilities across all 17
pinned dependencies.
**Why:** None of these vulnerabilities were exploitable in VibeGuard's
current Layer 1 code specifically (no Jinja2 templates or `.env`
loading exist yet, for instance), but leaving known-CVE versions
pinned in a security thesis's own `requirements.txt` is exactly the
kind of thing a reviewer would flag, and the fix is cheap.
**Effect on thesis chapters:** Chapter 5 gets the intended rigor point
- "the tool's own dependency chain was audited and found (after
remediation) to carry zero known vulnerabilities" - with a concrete
before/after count.

---

## [2026-07-13] - Added `scanner.py`; reordered ahead of CWE rule modules; fixed a real path-traversal gap
**What the plan said:** CLAUDE.md Section 7's build order lists all
five CWE rule modules before `scanner.py`. Section 5 separately
requires "resolve all file paths with `Path.resolve()` and verify they
remain inside the expected sample-apps root before reading," and
requires the "never execute/eval a target file" statement to appear
explicitly as a comment in `scanner.py` specifically.
**What we actually did / found:** Neither requirement was actually
satisfied yet: `scanner.py` didn't exist, and the path-containment
check had only ever been described in docstrings as "the caller's
responsibility" - no caller actually implemented it, including
`main.py`. Verified this was a real, exploitable gap (not a
theoretical one) by constructing an actual symlink inside a scan
directory pointing to a file outside it (`root/SneakyFile.java ->
../outside/Secret.java`) and confirming the pre-existing `rglob`-based
collection in `main.py` would happily discover and parse it,
misattributing an external file's contents to the scanned project.
Separately confirmed Python 3.10's `pathlib.rglob` does *not* recurse
into symlinked *directories* by default (tested empirically), so the
real residual risk was specifically file-level symlinks, not directory
ones.
Built `vibeguard/layer1_static/scanner.py`: walks a directory via
`os.walk(followlinks=False)` (rules out symlinked-directory recursion
and symlink-cycle infinite loops at the traversal level), then
independently re-resolves and verifies containment for every candidate
file before handing it to a parser (`Path.is_relative_to`) - defense
in depth against the file-level symlink case, which traversal-level
`followlinks=False` alone does not catch. Files that fail containment
are returned as `RejectedPath(path, reason)` entries, never silently
dropped, matching the project's fail-closed philosophy. The
"never execute/eval" statement CLAUDE.md Section 5 requires now
appears explicitly in `scanner.py`'s module docstring. `main.py` was
rewired to delegate all directory scanning to `scan_directory()`,
removing its previously duplicated `_collect_java_files`/
`_collect_config_files` glob logic, and now prints a third report
table for rejected paths. Two new regression tests construct real
symlink-escape scenarios (one file-level, one directory-level) and
assert the escape is caught - same "prove it, don't just claim it"
standard as the YAML alias-bomb test.
While doing this, also consolidated `ast_parser.ParseStatus` and
`config_parser.ConfigParseStatus` (two independently-defined but
near-identical enums) into a single shared `ParseStatus` in
`_parsing_guards.py`, since `scanner.py` needed to compare both
parsers' results uniformly and maintaining two drifting copies of the
same vocabulary was the same class of duplication already fixed once
for the guard functions. `config_parser.py` also gained a `_guard_failure`
helper (mirroring `ast_parser.py`'s) and warning-level logging on its
failure paths, which it previously lacked entirely - an inconsistency
found during this audit, not a new requirement.
**Why:** `scanner.py`'s core responsibility (safe directory
orchestration) doesn't depend on any CWE rule existing yet, and the
path-traversal gap it closes is a concrete, already-proven security
issue - reordering ahead of the rule modules fixes a real problem
sooner rather than leaving it open for the remaining build-order
items. The enum/logging consolidation was found while building this
and was cheap enough to fix in the same pass rather than deferring it
into inconsistent, harder-to-untangle territory.
**Effect on thesis chapters:** Chapter 4 should note the build order
deviation (scanner before CWE rules) and its justification. Chapter 5
should describe the symlink-escape finding as a concrete robustness
result (constructed attack, demonstrated failure of the naive
approach, demonstrated fix) rather than a hypothetical threat model -
this is a stronger, more specific claim than "we resolve paths for
safety."

---

## [2026-07-13] - Deferred: public GitHub repo ingestion, deferred entirely: hosted scanning service
**What was proposed:** Add a `scan_repository(url, ref=None)` layer that
clones/downloads a public GitHub repo into a temp directory, runs the
existing `scan_directory()` on it, then deletes the checkout - exposed
via a `--repo <github-url>` CLI flag - as a first step toward
eventually hosting VibeGuard as a public web service that accepts
repo URLs directly.
**What we actually did:** Did not build either. Evaluated both against
CLAUDE.md before writing any code:
- The *repo-ingestion wrapper* (clone to temp dir, scan locally,
  delete) is technically compatible with Section 3's "runs entirely
  locally" constraint, since the scan step itself would stay local -
  the network call is just how the input arrives, no different in
  kind from a user running `git clone` themselves first. Not ruled
  out architecturally.
- It is, however, not on Section 7's build order, and Layer 1 itself
  is not finished (zero CWE rule modules exist yet - `rules/` is
  still just `__init__.py`). Building ingestion now would mean
  working ahead of/outside the approved sequence without the
  "genuinely necessary" justification Section 8 requires for doing
  that.
- The *hosted API/web service* idea is a different, larger claim that
  nothing in CLAUDE.md supports: "public release intent" (Section 3)
  means the GitHub repository is public, not that infrastructure is
  operated to execute analysis on arbitrary internet-submitted input.
  That also introduces new attack surface Section 5 doesn't cover at
  all (SSRF via arbitrary fetched URLs, zip-slip/decompression bombs
  from archive downloads, disk exhaustion from large repos, host
  allowlisting) - none of which has been designed, let alone
  reviewed. Section 9 notes the topic was approved specifically for
  its narrow scope; a hosted service is a materially different
  commitment than what was approved.
**Why:** Chose to stay on the approved build order (`rules/cwe_798.py`
next) rather than add a new capability while Layer 1's actual
vulnerability-detection logic still doesn't exist. This is a "not
now," not a "no" - the ingestion-wrapper half is architecturally
sound and can be picked up later without touching any existing code
(it would sit entirely in front of `scan_directory()`).
**Effect on thesis chapters:** None yet, since nothing was built. If
the repo-ingestion wrapper is picked up later, Chapter 3/4 should
frame it explicitly as an ingestion/deployment-convenience extension,
not a change to the five-layer analysis core, per this log entry's
reasoning. The hosted-service idea should not appear in the thesis at
all unless it is separately discussed with and approved by the
supervisor, given it falls outside the approved narrow scope.
