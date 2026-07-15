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

---

## [2026-07-14] - scanner.py excludes build/IDE output directories
**What the plan said:** CLAUDE.md doesn't specify directory-exclusion
behavior for `scanner.py`; the original implementation only excluded
`.git`.
**What we actually did / found:** Reproduced a real correctness bug
using an actual compiled Java project (`my-test-app`, a local scratch
app run through `mvn compile`): scanning the repo root found
`application.properties` three times - once under
`src/main/resources/`, and again as build-tool copies under
`target/classes/` and a Gradle-equivalent `build/resources/main/`.
Any later feature extraction, scoring, or evaluation count built on
top of scan results would double- or triple-count the same underlying
finding purely because of how the project happens to be built.
Expanded `_EXCLUDED_DIR_NAMES` in `scanner.py` to also skip `target`,
`build`, `out`, `bin` (compiled output), `.gradle`, `.mvn`
(build-tool caches/metadata), `node_modules` (occasionally present in
monorepos), and `.idea`/`.vscode`/`.settings` (IDE metadata). Added
two regression tests that reconstruct the Maven and Gradle
double-copy scenarios directly and assert only the `src/` copy is
found.
**Why:** This is a correctness issue, not a UX nicety - CLAUDE.md's
evaluation methodology depends on finding counts meaning something,
and a scanner that silently multiplies findings by however many build
tools happened to run against a repo undermines that regardless of
how accurate the underlying CWE rules eventually are.
**Effect on thesis chapters:** Chapter 4/5 should note that
`scanner.py` excludes build output and IDE metadata directories, and
that this was found via a real compiled-repo reproduction, not
assumed necessary.

---

## [2026-07-14] - Java 17-21 syntax gap: assessed, and records specifically closed
**What the plan said:** CLAUDE.md doesn't commit to a specific
supported Java syntax version; "AI-generated Java microservices" was
implicitly assumed to mean whatever `javalang` (the Section 6 baseline
dependency) could parse.
**What we actually did / found:** Verified directly (not assumed) that
`javalang` 0.13.0 fails to parse most Java 14-21 syntax: text blocks
(15), records (16), pattern-matching `instanceof` (16), sealed classes
(17), switch expressions and pattern-matching `switch` (14/21) all
raise `JavaSyntaxError`. Only `var` (10) works. Records are the
standout problem: they are the dominant modern pattern for DTO/config
value classes in generated Spring/Quarkus code, so failing on them
entirely is a large real-world gap, not an edge case.
Searched for an actively-maintained alternative parser
(`javalang17` - a GitHub fork, not published to PyPI; `javalang-ext` -
published to PyPI but of unknown provenance/maintenance quality).
Did not install or evaluate either: pulling an unvetted third-party
parser into a security thesis's dependency chain, sight unseen, was
judged higher-risk than the problem it would solve, and the project's
own safety tooling correctly blocked the attempt to install one
without review.
Instead, built `vibeguard/layer1_static/_record_preprocessor.py`: a
narrow, self-contained, fully-owned regex-based rewrite that converts
*simple* (empty-bodied - no compact constructor, no extra methods)
`record` declarations into an equivalent `class` with one field per
component, applied to source text immediately before it's handed to
`javalang.parse.parse`. Verified against records with generics,
`implements` clauses, and varargs. Deliberately does **not** attempt
sealed classes, pattern matching, switch expressions, or text blocks -
those remain `PARSE_FAILED`, same as before this change. A record with
a non-empty body is left completely untouched (verified by test) so
it fails exactly as it did before, rather than being silently
mistranslated into something structurally wrong.
The one property verified most carefully: the rewrite **never changes
the file's total newline count**, even for a record declaration
spread across multiple lines - proven with a test that puts a real
class after a multi-line record and asserts it still reports its
correct original line number. File/line traceability is Layer 1's
core value proposition (CLAUDE.md Section 2); a fix that silently
broke it for every line after a record would have been worse than not
fixing records at all.
**Why:** Records specifically were worth a targeted, fully-audited fix
because of how common they are in the exact kind of code this thesis
targets, and because the fix could be scoped narrowly enough (regex
match on an empty record body only) to be simple, fully own-authored,
and independently testable - unlike sealed classes/pattern
matching/switch expressions/text blocks, which would each need
meaningfully more work to handle safely and were judged not worth the
risk of a rushed, under-tested implementation.
**Effect on thesis chapters:** Chapter 3/4 must not claim "Java 17-21
support." The accurate claim is: Java syntax up to and including
Java 13, plus `var` (10) and `record` declarations with an empty body
(16) as a targeted extension. Sealed classes, pattern matching,
switch expressions, and text blocks are an explicit, stated
limitation, not an oversight - Chapter 5/6 should list this as a
concrete "future work" item (most plausibly: properly vetting a
maintained modern-Java parser, or extending the same
targeted-preprocessing approach to the next-highest-value construct).

---

## [2026-07-14] - Two correctness bugs found by review: record field line traceability, fully-qualified type names
**What the plan said:** N/A - both bugs were introduced by prior work
in this log (the record preprocessor, and `_type_name` since Layer 1's
initial implementation), not a deviation from CLAUDE.md itself.
Documented here per Section 8's spirit of tracking every real
correctness finding, not just methodology deviations.
**What we actually did / found:**
1. The record preprocessor's first version compressed an entire
   multiline record onto one output line, correctly preserving *total*
   newline count (so content *after* a record kept its right line
   number) but not per-field position *within* the record: a
   `password` field on line 3 of a 4-line record declaration was
   reported as line 1. Verified directly before fixing. Rewrote
   `_rewrite_match`/`_fields_by_relative_line` in
   `_record_preprocessor.py` to track each component's actual
   newline-relative offset within the matched span and place its
   synthesized field declaration on that same relative output line,
   rather than joining all fields onto the header line. Verified fixed:
   a field on original line 3 now reports line 3.
2. `_type_name()` read `.name` off only the outermost javalang type
   node. For a fully-qualified type, javalang represents each dotted
   segment as its own `ReferenceType` chained via `sub_type`
   (`java` -> `util` -> `List`), so the outermost node's `.name` is
   the *first package segment*, not the type. Verified directly:
   `java.util.List<java.util.Map<String, Integer>> values;` summarized
   as `type_name="java"`. Not a missing-generics gap, a wrong-answer
   bug - any CWE rule pattern-matching on `type_name` (e.g. "is this a
   `List`/`Map`/collection field") would silently fail for any
   fully-qualified type usage, which is a common style choice, not an
   edge case. Added `_base_type_name()`, which walks the `sub_type`
   chain to its end (array `dimensions` still read from the *outer*
   node, confirmed via a qualified-array-type test that this is where
   javalang actually puts them).
**Why:** Both are silent-wrong-answer bugs rather than crashes or
`PARSE_FAILED` results, which makes them more dangerous than a loud
failure: nothing in the existing output would have signaled that a
line number or a type name was incorrect. Found by direct verification
against constructed repro cases, not by re-reading the code, matching
this project's standing practice of proving a fix rather than assuming
one.
**Effect on thesis chapters:** No new limitation to document - these
are fixes to features already claimed as working (record support;
Java AST field/parameter type summarization), not new scope. Worth a
line in Chapter 5 as evidence of iterative verification (a second
review pass over already-"working" code found two real, non-obvious
bugs, both fixed with regression tests) rather than treating a
passing test suite as proof of correctness on its own.

---

## [2026-07-14] - _type_name fix from the previous entry was itself incomplete
**What the plan said:** N/A - a correction to the fix logged in the
entry immediately above, not a new deviation.
**What we actually did / found:** The previous fix for fully-qualified
types (`_base_type_name` walking javalang's `sub_type` chain) returned
only the *innermost* segment's name - `java.util.List` summarized to
`"List"`. That's no longer wrong in the "returns the wrong identifier"
sense the original bug had, but it's still lossy: it silently
discards the package qualification, so `java.sql.Date` and
`java.util.Date` both summarize to `"Date"` and become
indistinguishable. Verified this collapse directly before fixing.
Changed `_base_type_name` to join every segment's name with `.`,
reconstructing the type's full original dotted name
(`java.util.List`, `java.sql.Date`) rather than truncating to the last
segment. Unqualified types are unaffected (a single segment joins to
itself). Updated the existing regression test to assert the fully
reconstructed name and added the `java.sql.Date`/`java.util.Date`
ambiguity case directly.
**Why:** A future CWE rule pattern-matching on `type_name` may need to
distinguish types that share a simple name but come from different
packages (a common case for `Date`, and plausible for
security-relevant types too, e.g. distinguishing a project's own
`Cipher`-named class from `javax.crypto.Cipher`). Truncating to the
simple name forecloses that distinction permanently; reconstructing
the full name preserves it at zero extra cost.
**Effect on thesis chapters:** None beyond the previous entry - same
feature, corrected to actually be non-lossy this time.

---

## [2026-07-14] - First CWE rule: `rules/cwe_798.py` (hardcoded credentials)
**What the plan said:** CLAUDE.md Section 7 build order item 2:
`rules/cwe_798.py` validates the parser's string-literal extraction,
first rule module.
**What we actually did / found:** Implemented `detect_in_java()` and
`detect_in_config()`, both returning a shared `Finding` dataclass
(`cwe_id`, `file_path`, `line`, `identifier`, `redacted_value`,
`message`) - the first shared data shape future CWE rule modules will
likely reuse. Detection logic: a case-insensitive substring match
against a credential-keyword list (password, secret, api key, token,
...) applied to field/local-variable names (Java) or dotted config
keys, combined with a literal string value that isn't empty, isn't a
Spring/Quarkus `${...}` property reference (externalized, not
hardcoded), and doesn't match an obvious-placeholder marker
(`CHANGE_ME`, `TODO`, etc.).

For Java, walks `ParsedFile.tree` directly via javalang's
`.filter(VariableDeclarator)` rather than `ParsedClass.fields` -
neither field nor local-variable initializer *values* are captured in
Layer 1's flattened summary, only structure (name/type/modifiers).
This is exactly the "traverse beyond what `classes` summarizes" use
case `ParsedFile.tree`'s docstring was written for back when
`ast_parser.py` was built. `.filter()` finds both class-field and
method-local declarations uniformly (both are realistic places for a
hardcoded secret), with line numbers read from the literal node's own
`position` rather than the parent declaration's.

Findings never carry the real matched value: `redacted_value` masks
everything except the first/last character. Decided this deliberately
rather than including the raw value - a security tool whose own
reports/logs echo back the real secrets it finds becomes a secondary
disclosure vector, which matters more once real public repos (not
just synthetic sample apps) are being scanned.

Added `tests/fixtures/HardcodedSecretService.java` (the CWE-specific
fixture CLAUDE.md Section 4 requires) with both a true-positive case
and three deliberate non-matches (property reference, placeholder,
empty value) in the same file, plus reused the existing
`application.properties`/`application.yml` fixtures (which already
contained a real `quarkus.datasource.password=hunter2` from earlier
work) as config-side true positives. 11 new tests, 58 total passing.
**Why:** The `${...}` and placeholder exclusions exist because a naive
"credential-shaped name + any literal value" rule would flag the
correct, idiomatic way to *avoid* CWE-798 (externalizing to
environment/config substitution) as if it were an instance of the
vulnerability - a false positive that would actively mislead a
report's reader. Known accepted false-positive source (not solved
here): a `*Hash`-suffixed field holding a literal hashed value (e.g.
bcrypt) still matches on name; distinguishing "this looks like a hash"
from "this looks like a plaintext secret" was judged out of scope for
a first rule module - noted for Chapter 5's limitations discussion if
evaluation results show it matters in practice.
**Effect on thesis chapters:** Chapter 4 should describe the `Finding`
dataclass as the common output shape rule modules converge on.
Chapter 5's CWE-798 evaluation should report the property-reference/
placeholder exclusions explicitly, since they're precision-improving
design decisions, not incidental behavior - and should flag the
hash-field false-positive source as a known limitation rather than
something the evaluation numbers might quietly hide.

---

## [2026-07-14] - Second CWE rule (`cwe_284.py`); extended ParsedMethod; extracted shared Finding
**What the plan said:** CLAUDE.md Section 7 build order item 3:
remaining CWE rule modules, after `cwe_798.py`.
**What we actually did / found:** Before writing `cwe_284.py`
(Improper Access Control), addressed a design gap identified in
review: `ParsedMethod` didn't carry annotations at all (`ParsedClass`
already did), so a rule needing `@RolesAllowed`/`@PermitAll`/etc.
would have had to walk the raw AST directly, same as `cwe_798.py` did
for literal values. Judged this differently from the literal-value
case, though: annotation *names* are structural information broadly
useful to any future rule (not just this one CWE), the same way
modifiers or a method's return type already are, whereas literal
*values* are genuinely rule-specific. Extended `ParsedMethod` with
`annotations: tuple[str, ...]` (mirroring `ParsedClass`'s existing
field) rather than having `cwe_284.py` re-walk the tree - a one-line
change to `_build_method` since javalang already exposes
`node.annotations` on `MethodDeclaration` the same way it does on
`ClassDeclaration`. As a result `cwe_284.py` needed no raw-tree
access at all, working entirely off the Layer 1 structural summary.

Also extracted `Finding` (previously defined locally inside
`cwe_798.py`, flagged in review as due for extraction "by the second
rule") into `vibeguard/layer1_static/rules/_finding.py`, shared by
both rule modules now. Added an optional `redacted_value: str | None
= None` since not every CWE's findings revolve around a literal value
to redact - `cwe_284.py`'s findings are about a missing annotation,
not a value.

`cwe_284.py` itself: flags a method carrying a JAX-RS/Spring endpoint
annotation (`@GET`/`@POST`/`@GetMapping`/etc.) that has no
authorization annotation (`@RolesAllowed`/`@PermitAll`/`@Secured`/
`@PreAuthorize`/etc.) at either the method or the enclosing class
level - class-level coverage matters because "secure by default,
annotate per-method to opt out" is a common real pattern, and without
checking the class a rule would flag every method in a
class-protected resource as a false positive. Deliberately does not
flag an endpoint with an *explicit* `@PermitAll`, even on a
sensitive-sounding method name: that's a made access-control decision,
not a missing one, and judging whether a specific decision is
*appropriate* needs semantic understanding of the app's authorization
model that pattern matching can't provide - same "detect candidacy,
not make the final call" scoping as `cwe_798.py`.

Two new fixtures (`UnprotectedResource.java` - true positive plus
`@RolesAllowed`/`@PermitAll`/non-endpoint negative cases in one file;
`ClassLevelSecuredResource.java` - proves class-level coverage). 7 new
tests, 65 total passing, all tooling clean. Verified against the real
fixtures before writing tests, same discipline as `cwe_798.py`.
**Why:** Promoting annotation names to `ParsedMethod` avoids every
future annotation-driven rule needing its own raw-tree walk for the
same structural information `ast_parser.py` can capture once. The
`Finding` extraction avoids a third near-identical local definition
appearing in `cwe_20.py`/`cwe_287.py`/`cwe_1035.py` next.
**Effect on thesis chapters:** Chapter 4 should describe
`ParsedMethod.annotations` as part of the Layer 1 summary (not a
rule-specific addition) and `Finding` as the common cross-CWE output
shape. Chapter 5's CWE-284 evaluation should state the scope
explicitly: detects missing access control, not misconfigured access
control, and does not evaluate whether a given role/policy is
semantically appropriate for an endpoint.

---

## [2026-07-14] - Adversarial pass over cwe_798.py/cwe_284.py found 4 real bugs
**What the plan said:** N/A - a deliberate "try to break what we just
built" pass, same discipline already applied to the parsers (symlink
escape, YAML alias bomb), not previously applied to the rule modules.
**What we actually did / found:** Constructed inputs specifically
designed to break each rule's matching logic rather than waiting for
review to find them:
- `cwe_284.py`'s `_ENDPOINT_ANNOTATIONS`/`_AUTHORIZATION_ANNOTATIONS`
  matched `annotation.name` by exact string, but javalang gives that
  name exactly as written in source - fully qualified
  (`javax.ws.rs.GET`) if the source used the fully-qualified form
  instead of a simple-name import. This broke detection in *both*
  directions from one root cause: a fully-qualified `@javax.ws.rs.GET`
  wasn't recognized as an endpoint at all (false negative - a real
  unprotected endpoint invisible to the rule), and a fully-qualified
  `@javax.annotation.security.RolesAllowed` wasn't recognized as an
  authorization annotation (false positive - a genuinely protected
  endpoint flagged as unprotected). Verified both directions
  concretely before fixing. Fixed by comparing against the last
  dot-separated segment (`_simple_name()`) instead of the full string.
- `cwe_798.py` flagged the literal string `"null"` assigned to a
  credential-named field as a hardcoded secret. Added an exact-match
  (not substring) `_LITERAL_NON_VALUES` check.
- `cwe_798.py`'s property-reference exclusion only matched
  Spring/Quarkus `${...}` syntax, not Spring Expression Language
  `#{...}` syntax - an equally common way to externalize a value in
  Spring apps, wrongly flagged as hardcoded. Extended
  `_PROPERTY_REFERENCE_PATTERN` to match either prefix.

Also checked (and confirmed correct, not bugs): duplicate YAML keys
are preserved as separate `ConfigEntry` values rather than silently
overwritten by the last one - safer for security scanning, matches
the project's fail-closed philosophy. A broken symlink inside a scan
root correctly resolves as still-in-root (passes containment) and
then fails with an explicit `PARSE_FAILED` rather than crashing or
being silently dropped.

4 new regression tests, 69 total passing, all tooling clean.
**Why:** All four were found by deliberately trying to break the
matching logic with realistic inputs (fully-qualified annotations,
SpEL expressions, and the literal word "null" are all things a real
Java/Spring codebase produces routinely), not by waiting for someone
else to report them - the same standard already applied to the
parsers earlier in this project. The `cwe_284.py` bug in particular
was the most serious found so far in a rule module: it undermined the
rule's core trustworthiness in both directions simultaneously, on a
CWE (Improper Access Control) where a false negative is the worse of
the two failure modes.
**Effect on thesis chapters:** Chapter 5 should describe this
adversarial-testing pass as part of the evaluation methodology for the
rule modules specifically (not just the parsers), and can cite the
fully-qualified-annotation bug as a concrete example of why static
pattern-matching rules need testing against realistic naming variation,
not just the "canonical" form of an annotation/expression.

---

## [2026-07-14] - External review found 4 more real issues; scanner now excludes test roots; CLI now runs rules
**What the plan said:** N/A - fixes from an external code-review pass,
plus completing work already flagged as owed ("wire the CLI up once
more rules exist").
**What we actually did / found:** Verified all four reported issues
before fixing, same discipline as always:
1. `cwe_798.py` over-flagged *references to* a secret as the secret
   itself: `secretName = "orders-db-credential"` and
   `quarkus.kubernetes.env.secrets=orders-db-secret` both produced
   findings, but neither holds credential material - one names a
   secret to look up, the other lists which Kubernetes Secret
   resources to mount. Fixed by extracting an identifier's *last word*
   (splitting camelCase and `./_/-` separators - `"secretName"` ->
   `"name"`, `"quarkus.kubernetes.env.secrets"` -> `"secrets"`) and
   excluding names whose last word is itself a reference/metadata term
   (name, id, ref, path, alias, arn, uri, url, secrets) - deliberately
   not excluding "key", since "secretKey" must still match.
2. `cwe_798.py` missed compile-time-constant secrets split across
   literals (`"hunter" + "2"`), since `_string_literal_value` only
   handled a plain `Literal` node. Extended it to recursively fold a
   `+`-chained `BinaryOperation` when every operand resolves
   statically; anything involving a variable/call still can't be
   resolved and correctly returns nothing found (this rule only
   inspects source text, never evaluates anything). Also added
   `_initializer_line` to recover a usable line number for the
   concatenated case, since `BinaryOperation` itself carries no
   `position` in javalang - falls back to the leftmost literal
   operand's line rather than losing traceability entirely.
3. `scanner.py` scanned `src/test/...` by default, so a repo's test
   fixtures (which routinely contain deliberately fake secrets like
   `"hunter2"` for test setup) got scanned and flagged as if they were
   production findings - directly distorting evaluation precision/
   recall against real repositories. Added `test`/`tests` to the
   existing `_EXCLUDED_DIR_NAMES` traversal-pruning set (same
   mechanism already used for `target`/`build`), matched
   case-insensitively. Known, accepted false-exclusion risk: a
   production package genuinely named exactly `test`/`tests` would be
   silently skipped too - judged acceptable given how consistently
   Maven/Gradle both use this convention.
4. The implemented rules (`cwe_798.py`, `cwe_284.py`) were not run by
   `main.py` at all - a file with an obvious hardcoded secret parsed
   as `ok` and the process exited `0`. Wired `main.py` to run every
   implemented rule against every successfully-parsed file (skipping
   files that failed to parse - no AST/entries to inspect, and that
   failure is already surfaced separately) and print a findings table.
   Changed the exit-code contract: `0` now requires zero findings, not
   just clean parses - documented as provisional in both the
   docstring and `--help` text, since with no Layer 3 scoring yet
   "any finding at all" is the only threshold available.

Also (found and fixed independently while this was in progress, not
part of the reported review): `_parsing_guards.read_text_within_limit`
now strips a UTF-8 BOM (reads with `utf-8-sig` instead of `utf-8`) -
BOM markers are common in real repositories and would otherwise be
handed to `javalang`/PyYAML as an invalid first token, causing an
avoidable `PARSE_FAILED`.

New fixtures (`Cwe798AdversarialService.java`,
`cwe798-reference.properties`) covering both the reference-suffix and
concatenated-literal cases together. 77 tests total passing (up from
69), all tooling clean.
**Why:** Items 1-2 are precision/recall corrections to an existing
rule, same category as the earlier adversarial-testing fixes - found
by someone actually trying to break the tool against realistic naming
conventions rather than only the cases the rule's own author thought
to test. Item 3 changes what "scanning a repository" means and
directly affects evaluation methodology, so it's logged distinctly
from 1-2 (which are just bugfixes). Item 4 was flagged as "owed" in
the previous CWE-284 log entry's working-style note
("keep unit-test-first, don't touch CLI wiring yet") - now that two
rules exist and the reviewer pointed out the practical cost of
deferring it further (a real secret silently reported as `ok`), it was
the right time to close that gap rather than let it compound with a
third rule.
**Effect on thesis chapters:** Chapter 4 should note the test-root
exclusion as a scan-scope decision with its false-exclusion tradeoff
stated explicitly, not left implicit. Chapter 5's evaluation
methodology should state plainly that default scans exclude test
source, and that the CLI's exit code is a provisional "any finding"
threshold pending Layer 3 scoring, not yet a graded pass/fail
judgment.

---

## [2026-07-15] - Adversarial QA matrix found cwe_284's flattened-summary dependency was a real nested-class blind spot
**What the plan said:** N/A - a structured edge-case QA pass (empty/
malformed input, modern Java syntax, adversarial secret-hiding,
integration boundaries) run against the current Layer 1 surface.
**What we actually did / found:** Before running the matrix, verified
and rejected a false premise in the QA prompt itself: it asserted this
project uses `tree-sitter`/`tree-sitter-java` and that any `javalang`
usage should be reported as a bug. Checked `CLAUDE.md` (Section 6's
baseline dependency list, Section 7's build order) and every prior log
entry: `javalang` is and has always been the locked-in parser: no
`tree-sitter` reference exists anywhere in this project's history. Did
not act on that part of the prompt.

Ran the rest of the matrix (CRLF line endings, non-UTF-8/Latin-1
encoding, multiple top-level classes in one file, 15-level-deep
nesting, a 5000-field file, anonymous inner classes) against
`ast_parser.py`/`cwe_798.py`/`cwe_284.py` - all correct, no bugs found
in those cases specifically.

Two real findings:
- `cwe_798.py` does not resolve a secret assembled from separate
  variable declarations (`password = part1 + part2` where `part1`/
  `part2` are themselves other fields) - only a literal-to-literal `+`
  chain within a single expression is folded. Checked the existing
  docstring first: this exact boundary was already stated explicitly
  ("Anything involving a variable/method call... can't be resolved
  statically and returns None"), so this is a *confirmed, correctly-
  scoped, already-documented limitation*, not an undocumented bug -
  added a regression test locking in that the documented behavior is
  the actual behavior, since an accurate docstring that silently
  drifted from reality would be worse than no docstring at all.
- `cwe_284.py` relied entirely on `ParsedFile.classes` (Layer 1's
  flattened summary, top-level types only per `ParsedClass`'s own
  docstring) - a real bug, not a documented limitation: an unprotected
  endpoint inside a nested/inner static class (a real JAX-RS/Spring
  pattern for grouping related resources) was completely invisible to
  this rule. `cwe_798.py` never had this problem because it already
  walked the raw tree via `.filter()`; `cwe_284.py` was rewritten to do
  the same, using `.filter(MethodDeclaration)` and resolving each
  method's *nearest* enclosing class/interface from the traversal path
  (not every ancestor - confirmed via a dedicated test that an outer
  class's `@RolesAllowed` does not protect a nested class's own
  methods, matching real JAX-RS/Spring per-resource-class authorization
  resolution, not lexical-scope inheritance).

`ParsedMethod.annotations`/`ParsedClass.annotations` (added for
`cwe_284.py` originally) remain in Layer 1's summary - still valid and
useful for anything that only needs top-level-class information - but
`cwe_284.py` itself no longer depends on them.

4 new regression tests (nested-class detection, method-level
protection still works inside a nested class, outer-class annotation
does *not* leak protection to an inner class, the documented variable-
split limitation). 81 tests total (was 77), all tooling clean, `safety`
still 0 vulnerabilities.
**Why:** This is the second time in this project a rule module's
reliance on Layer 1's *flattened* summary (rather than the raw tree)
produced a real false negative - the first was `cwe_798.py`'s original
design already avoiding this by walking the tree directly for literal
values. The lesson generalizes: any structural summary that is
deliberately scoped to top-level types (documented as such in
`ParsedClass`) will silently under-represent nested/inner/anonymous
code for *any* rule that only consults it - each new rule module needs
to explicitly decide whether raw-tree access is required, not assume
the summary is complete.
**Effect on thesis chapters:** Chapter 5 should describe this as a
concrete example of the "test module-level, then test end-to-end at
integration boundaries" methodology explicitly recommended in the QA
process this project follows - the bug was invisible at the granularity
of "does cwe_284 find its own test fixtures" and only surfaced when
deliberately testing a structural edge case (nesting) the original
fixtures never exercised. Chapter 4 should note that CWE rule modules
are not uniformly raw-tree-based vs. summary-based by design - each
decides based on what information it actually needs, and that decision
should be stated per rule, not assumed globally.

---

## [2026-07-15] - Java 17+ parser support promoted from limitation to evaluation risk
**What the plan said:** CLAUDE.md approved `javalang` as the baseline
Java parser, and the earlier Java 17-21 syntax-gap entry documented
modern syntax failures as limitations, with only simple empty-body
records handled by a narrow preprocessor.
**What we actually did / found:** Reassessed that limitation against
the intended evaluation target: AI-generated and public Java
microservice repositories. Modern Spring/Quarkus applications
increasingly target Java 17+, and Spring Boot 3 requires Java 17. That
means records, text blocks, sealed classes, modern switch syntax,
pattern matching, and other Java 17-21 constructs are likely to appear
in realistic evaluation data. If VibeGuard cannot parse those files,
the result is not just reduced syntax coverage; it can create false
negatives because CWE rules never run on parse-failed files.
**Why:** A Java 8-era parser is acceptable as a temporary Layer 1
development backend, but it is not defensible as the final parser
strategy for public-repo or AI-generated Java microservice evaluation
unless the dataset is explicitly constrained to older/simple Java.
Constraining the dataset that way would weaken the thesis claim. The
project should not keep expanding regex preprocessors as the long-term
solution; that approach does not scale safely and risks breaking
source-line traceability.
**Decision / next step:** Before serious public-repo evaluation,
perform a parser-compatibility spike. Build Java 8/11/17/21 fixture
coverage, compare current `javalang` behavior against a modern parser
candidate such as `tree-sitter-java`, and decide whether to migrate
parser backends behind the existing `ParsedFile`/rule interface. Keep
the current `javalang` implementation only as a temporary development
backend until that decision is made. Also define the evaluation
dataset explicitly: a controlled AI-generated/vibe-coded app set for
ground truth, plus a real public-repo sample for parser coverage and
noise analysis.
**Effect on thesis chapters:** Chapter 3 must describe dataset
selection and Java-version inclusion criteria. Chapter 4 must describe
parser support and any backend migration. Chapter 5 must report parse
success/failure rates by Java version so vulnerability results are not
interpreted without parser-coverage context.

---

## [2026-07-15] - Third CWE rule (`cwe_287.py`); deferred the parser spike; extracted shared credential-name heuristic
**What the plan said:** CLAUDE.md Section 7 build order item 3:
remaining CWE rule modules, after `cwe_798.py`/`cwe_284.py`. The Java
17+ parser-risk entry immediately above recommended a
parser-compatibility spike as the next step.
**What we actually did / found:** Explicitly asked whether to pivot to
the parser spike or continue the rule build order; chose to finish the
CWE rules first and revisit the parser decision once all five exist
and Layer 1 is feature-complete, rather than mid-course-correct on a
partial rule set.

Implemented `cwe_287.py` (Improper Authentication): flags Java's
classic authentication-bypass bug, comparing a credential-shaped value
with `==`/`!=` instead of `.equals()` - `==` on `String`/object types
compares reference identity, not value, so the check does not reliably
verify the claimed credential is correct. Walks `ParsedFile.tree` via
`.filter(BinaryOperation)` (same raw-tree approach as `cwe_284.py`,
for the same reason: Layer 1's flattened summary doesn't capture
expressions at all). Excludes `null`/numeric/boolean literal
comparisons specifically to avoid flagging ordinary null-checks and
coincidental keyword matches like `passwordAttempts == 3`.

Found and fixed one real bug via self-directed adversarial testing
before calling it done (not from external review this time): the
initial implementation only recognized a bare `MemberReference`
(`password`) as a credential-shaped operand, missing `this.password`
entirely - javalang represents a `this`-qualified field access as a
`This` node with the field access nested in `.selectors`, not as a
`MemberReference` with a "this" qualifier. `this.field` is a very
common way to disambiguate a field from a same-named parameter (e.g.
in a constructor), so this was a real, meaningful false negative, not
an edge case. Fixed by also checking a `This` node's selectors;
fixing it exposed a second related bug in the "which side is the
*other* operand" logic (it compared node identity against the
top-level operand, which breaks once the credential match comes from
inside a nested selector rather than the operand itself) - restructured
to track which side matched directly instead of via identity
comparison.

Also extracted `CREDENTIAL_KEYWORDS`/`is_credential_name`/`last_word`
out of `cwe_798.py` into a new shared
`vibeguard/layer1_static/rules/_credential_names.py`, since `cwe_287.py`
needed the identical "does this identifier look like it holds a
credential" question - same duplication-avoidance pattern already
applied twice this project (`Finding`, `_parsing_guards`). `cwe_798.py`
keeps its own reference-suffix exclusion layered on top of the shared
base check, since that narrowing (distinguishing "secretName" from
"secret") is specific to its own concern.

Before writing any of this, re-verified a QA prompt's claim from the
previous session that this project uses `tree-sitter` (still false -
`javalang` remains the locked parser per `CLAUDE.md`/every prior log
entry) was not silently re-introduced by the parser-risk entry above;
the parser-risk entry itself correctly describes `javalang` as the
current backend and frames migration as a future decision, not a
completed one.

10 new tests (91 total, was 81), all tooling clean. Verified live
through `main.py`'s CLI, not just unit tests, before logging this.
**Why:** The `this.field` bug is the third time in this project that
an initial implementation correctly handled the "obvious" case but
missed a syntactically-different-but-semantically-identical form
(fully-qualified annotations for `cwe_284.py`, `this`-qualified field
access for `cwe_287.py`) - a pattern worth naming explicitly: javalang
frequently represents the "same" Java construct differently depending
on how it's written, and every rule module needs to be tested against
that variation, not just its most common textual form.
**Effect on thesis chapters:** Chapter 4 should describe
`_credential_names.py` as the second shared cross-rule utility module
(after `_finding.py`) and note the general pattern it and
`_parsing_guards.py` both follow: extract on the second real need, not
speculatively on the first. Chapter 5's CWE-287 evaluation should
state its scope precisely: detects the `==`/`!=` reference-equality
anti-pattern specifically, not authentication bypass via other means
(missing checks entirely, trusting unverified client data, weak
credential storage) - those would need separate detection logic this
rule does not attempt.
