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

---

## [2026-07-15] - Fourth CWE rule (`cwe_20.py`); extracted shared endpoint-annotation heuristic; applied the this-qualifier lesson proactively
**What the plan said:** CLAUDE.md Section 7 build order item 3:
remaining CWE rule modules. Four of five now exist.
**What we actually did / found:** Implemented `cwe_20.py` (Improper
Input Validation): flags a Spring MVC `@RequestBody` endpoint
parameter lacking `@Valid`/`@Validated`. Bean Validation (JSR 380)
constraints on a DTO's own fields are only enforced by Spring's
request pipeline when the parameter carrying that DTO is itself
annotated - without it, a malformed/malicious request body reaches
application code completely unvalidated. Scoped to Spring specifically
(not JAX-RS): JAX-RS has no exact equivalent of `@RequestBody` - a
JAX-RS body parameter is identified implicitly by the *absence* of a
param-source annotation like `@QueryParam`, a materially more
ambiguous signal than Spring's explicit marker, left for a future
pass rather than guessed at now. Excludes `@RequestBody` parameters
of "not validatable" types (`String`, `Object`, `Map`, `List`,
primitives/wrappers) - nothing for `@Valid` to cascade into, so
flagging those would be noise.

Extracted `ENDPOINT_ANNOTATIONS`/`has_endpoint_annotation`/
`simple_name` out of `cwe_284.py` into a new shared
`vibeguard/layer1_static/rules/_endpoint_annotations.py`, since
`cwe_20.py` needed the identical "is this method a reachable HTTP
endpoint" question - third shared-module extraction this project
(`_finding.py`, `_credential_names.py`, now this), same
extract-on-second-real-need pattern each time.

Applied the lesson from the previous two entries proactively rather
than reactively this time: `cwe_284.py` and `cwe_287.py` were each
initially built against only the "obvious" textual form of their
target construct and needed a follow-up fix once adversarial testing
found a syntactically-different-but-equivalent form javalang
represents differently (fully-qualified annotations; `this.field`
access). For `cwe_20.py`, walked `ParsedFile.tree` directly from the
first draft (not after discovering a flattened-summary gap), and
tested fully-qualified annotations (`@javax.validation.Valid`,
`@org.springframework.web.bind.annotation.RequestBody`) and a
nested-class endpoint *before* writing fixtures, not after. Both
passed on the first implementation - no follow-up bug this time.

9 new tests (102 total, was 91), all tooling clean. Verified live
through `main.py`'s CLI, including confirming that multiple rules
(`CWE-284` and `CWE-20` both) correctly fire independently on the same
fixture file without interfering with each other.
**Why:** The Spring-only / JAX-RS-deferred scoping decision keeps this
rule's precision high rather than guessing at a more ambiguous
JAX-RS signal that would need its own careful false-positive analysis
- consistent with every other rule module's "one well-scoped mechanism
first" approach. Proactively testing the annotation-qualification and
nested-class cases before writing fixtures (rather than after a bug
report) is the direct, intended payoff of naming that pattern
explicitly in the previous log entry.
**Effect on thesis chapters:** Chapter 4 should describe
`_endpoint_annotations.py` as the third shared cross-rule utility
module and can cite this entry as evidence the "test against
javalang's representational variation up front" methodology, once
identified, was successfully applied to prevent a recurrence rather
than just documented after the fact. Chapter 5's CWE-20 evaluation
should state the Spring-only scope explicitly - a JAX-RS-only
codebase would show zero CWE-20 findings from this rule regardless of
actual input-validation posture, which must not be misread as "no
CWE-20 issues found."

---

## [2026-07-15] - Fifth and final CWE rule (`cwe_1035.py`); new `pom_parser.py`; offline vulnerability database, not a live API
**What the plan said:** CLAUDE.md Section 7 build order item 3: the
last of five CWE rule modules. Section 3's non-negotiable constraint:
"Runs entirely locally... no external API calls for core scanning."
**What we actually did / found:** CWE-1035 (Using Components with
Known Vulnerabilities) is architecturally unlike the other four rules:
nothing in Java *source* looks vulnerable, so it needs a dependency
manifest (Maven's `pom.xml`) and something to check declared versions
against. The natural real-world approach - a live query against
OSV.dev/NVD - was explicitly rejected before writing any code: that
would put an external network call directly in the core scanning path
on every run, which is a materially different thing from the one-off,
manually-triggered `safety` dependency audit this project's own
tooling gets, and would directly violate the "no external API calls
for core scanning" constraint. Went with a small, curated, offline
snapshot of well-known, independently-verifiable CVEs
(`_KNOWN_VULNERABILITIES` in `cwe_1035.py`: Log4Shell, a
jackson-databind deserialization RCE, the classic commons-collections
gadget-chain CVE, a snakeyaml deserialization CVE) instead - the
explicit tradeoff (this rule is only ever as current as that hardcoded
list, not a live feed) is stated in the module docstring, not hidden.

Built `vibeguard/layer1_static/pom_parser.py` as a proper Layer 1
module (matching `ast_parser.py`/`config_parser.py`'s architecture -
`ParseStatus`, shared `_parsing_guards`, structured dataclass output)
rather than ad-hoc XML parsing inside the rule itself, for the same
consistency reasons `config_parser.py` was built as its own module
instead of parsing config text inline in `cwe_798.py`. Scoped to
Maven only: Gradle's `build.gradle`/`build.gradle.kts` are executable
Groovy/Kotlin DSL code, not declarative data, and parsing that
correctly is a materially harder, different problem than structured
XML - left for a future pass rather than guessed at with regex.
Resolves Maven `${property}` references against the local
`<properties>` block only; a property from an inaccessible parent POM
resolves to `None` ("unknown"), never a guess, and `cwe_1035.py`
explicitly never flags a dependency with an unresolved version.

Verified empirically, not assumed, that parsing untrusted `pom.xml`
files is safe against XML's two classic attacks before writing a
single line of the rule: a "billion laughs" entity-expansion payload
is already rejected by CPython's bundled expat parser with a
`ParseError` (a native protection added in Python 3.7.1+, itself a
CVE response) rather than hanging or exhausting memory; external
entity references (XXE, e.g. reading local files via
`<!ENTITY xxe SYSTEM "file:///etc/passwd">`) are not resolved by
`ET.fromstring` at all - it raises `undefined entity` instead. No
extra dependency (`defusedxml`) was needed once this was actually
tested rather than assumed safe or assumed unsafe.

Found and fixed one real bug via self-directed testing before
shipping: naive tuple comparison of parsed version numbers treats
`"2.15"` as *less than* `"2.15.0"` (a shorter tuple that is a prefix
of a longer one compares as "less" in Python), which would have
flagged the fixed version of a dependency as still vulnerable purely
because someone omitted a trailing zero patch segment - a real,
plausible false positive. Fixed by padding both version tuples to
equal length with trailing zeros before comparing.

Wired into `scanner.py` (`pom.xml` is matched by exact filename, not
suffix like every other format - a new discovery mechanism, added
`ScanResult.pom_files`) and `main.py` (`_run_rules`, a new
`_print_pom_report`, `--help` text, single-file mode). Verified live
end-to-end: a directory containing both a hardcoded-secret Java file
and a Log4Shell-vulnerable `pom.xml` correctly produced findings from
`cwe_798.py` and `cwe_1035.py` together in one scan.

28 new tests (123 total, was 102), all tooling clean, `safety` 0
vulnerabilities. All five CWE rule modules from CLAUDE.md's target
list now exist.
**Why:** The offline-database decision is the single most consequential
architectural choice in this entry: it trades comprehensiveness for
compliance with a non-negotiable constraint stated on day one of this
project, and that tradeoff needs to be visible to anyone reading this
rule's output, not just to whoever wrote it. The XXE/entity-expansion
verification follows the same standard already applied to the YAML
parser (verify the specific untrusted-input attack classes relevant to
the format being parsed, don't assume a stdlib parser is safe by
default) - it happened to already be safe here, which is itself worth
recording rather than silently taking for granted.
**Effect on thesis chapters:** Chapter 3 (methodology) should describe
the offline-vs-live vulnerability database decision explicitly as a
consequence of the "runs entirely locally" constraint, not as an
oversight or a resource limitation - this was a deliberate, principled
choice with a stated cost. Chapter 4 should list `pom_parser.py`
alongside `ast_parser.py`/`config_parser.py` as Layer 1's third input
parser and note the Gradle-not-yet-supported scope explicitly. Chapter
5 should report `_KNOWN_VULNERABILITIES`'s exact size and contents as
part of describing CWE-1035's evaluation methodology, since the rule's
recall is fundamentally bounded by that list's size - this must not be
conflated with or presented as equivalent to a comprehensive CVE
database's coverage. With all five CWE rules now complete, this is
also the natural point to revisit the deferred Java 17+ parser-
compatibility spike, as previously agreed.

## [2026-07-15] - Java 17-21 parser coverage extended via text preprocessing, not a parser migration

**What the plan said:** The Java 17+ parser-compatibility gap (`javalang`
0.13.0 predates Java 16 and cannot parse records-with-bodies, sealed
classes/interfaces, pattern-matching `instanceof`, text blocks, or
switch expressions/pattern-matching `switch`) had been repeatedly
logged as a deferred risk across earlier entries, to be revisited once
all five CWE rules existed.

**What we actually did / found:** Empirically re-tested javalang's
actual Java 8-21 support surface directly (both raw
`javalang.parse.parse()` and the real `ast_parser.parse_file()` entry
point) rather than relying on the earlier entries' characterization.
Confirmed already-working: `var`, lambdas, method references,
try-with-resources, and simple (empty-bodied) records (the existing
`desugar_simple_records` shim). Confirmed still-failing: sealed
classes/interfaces, pattern-matching `instanceof`, text blocks, and
switch expressions/pattern-matching `switch`.

Extended the existing text-preprocessing technique (already proven for
records) to three of the four remaining gaps, renaming
`_record_preprocessor.py` to `_modern_java_preprocessor.py` (`git mv`,
all references and its test file updated) and adding a single
`preprocess()` entry point that `ast_parser._parse_source` now calls
instead of calling record desugaring directly:

- **Sealed classes/interfaces**: `sealed`/`non-sealed` modifiers and
  the trailing `permits ...` clause are stripped from a type's header,
  leaving an ordinary class/interface declaration. Only the header is
  touched; the `permits` list isn't needed by any current CWE rule.
- **Pattern-matching `instanceof`** (`o instanceof String s`): the
  bound variable name is stripped, leaving a plain `instanceof` check.
  Safe because javalang has no semantic/symbol resolution - it never
  checks whether a later reference to the now-unbound name was
  actually declared - and no current CWE rule needs the binding
  itself.
- **Text blocks** (`"""..."""`): re-emitted as an equivalent escaped
  string literal, implementing JEP 378's indentation-stripping
  algorithm directly (minimum common leading whitespace across content
  lines, trailing whitespace stripped per line, and - verified against
  real `javac` semantics, not assumed - a closing delimiter on its own
  line contributes a trailing `\n` to the value).

**Deliberately not extended:** switch expressions and pattern-matching
`switch` (arrow-style `case X -> ...`). Converting an arrow-style case
body (which can be a single expression, a block, or a `throw`) back to
colon-style `case X: yield ...; break;` needs real structural
understanding of the body, not a text substitution - getting it wrong
risks silently corrupting the AST rather than producing a clean
`PARSE_FAILED`, which is a materially worse failure mode for a
security tool. Left as an explicit, documented gap in
`_modern_java_preprocessor.py`'s module docstring rather than
attempted and possibly gotten wrong.

Three real bugs were found and fixed during self-verification, before
anything was committed:
1. A naive `.replace('"', '\\"')` approach to escaping text-block
   content would double-escape a `"` that was already part of a
   pre-existing `\"` sequence in the source, corrupting the literal's
   value. Fixed with a character-by-character escape-state-tracking
   function (`_escape_for_string_literal`) that only escapes a
   character when the previous one wasn't itself an unescaped
   backslash.
2. `strip_sealed_modifiers` and `strip_pattern_matching_bindings`
   originally used plain `pattern.sub("", source)`, which deletes any
   newlines embedded in a multi-line match (e.g. a `permits` clause
   wrapped across lines) without replacing them - silently shifting
   the reported line number of everything after the match. Verified
   directly (not assumed) with a multi-line `sealed class ... permits`
   example: a `password` field two lines later reported line 2
   instead of the correct line 3. Fixed by adding `_blank_out()`/
   `_keep_group_one()` helpers that replace a match with only its own
   newline count, matching the discipline `desugar_simple_records`
   already had.
3. The original pattern-matching-`instanceof` regex's lookahead only
   permitted `)`, `&`, or `|` after the bound variable name, so a
   binding used in contexts like `return o instanceof List<String>
   items;` (terminated by `;`, not one of those three characters) was
   silently left unstripped, and the file would still fail to parse.
   Found via a dedicated test case, not assumed correct because
   simpler cases passed. Fixed by broadening the lookahead to the full
   set of valid Java boundaries after a pattern binding (`)`, `&`,
   `|`, `;`, `,`, `?`, `:`, `{`, or end of string).

Added 12 new tests to `tests/test_modern_java_preprocessor.py`
covering all three new transforms individually, the composed
`preprocess()` pipeline, newline-count preservation for each
multi-line case, and an end-to-end proof that a hardcoded secret
embedded inside a Java text block is still detected by
`cwe_798.detect_in_java()` with the correct identifier - not just that
the file parses. Full suite: 135 passed (was 123), `black`/`ruff`/
`mypy` all clean.

**Why:** A full parser migration (e.g. to `tree-sitter-java`) was
considered and explicitly rejected as disproportionate for this task -
the student's own framing was "make this clean and direct,
straightforward," and the existing record-preprocessing technique was
already proven, low-risk, and directly extensible to the remaining
constructs that don't require structural understanding to rewrite.
Switch expressions were the one construct where that same technique
would require real structural parsing to do safely, so it was scoped
out rather than forced.

**Effect on thesis chapters:** Chapter 3 (methodology) should describe
the text-preprocessing/desugaring approach as the deliberate
alternative to a parser migration, with the same tradeoff framing
already used for the offline CVE database decision - proportionate
engineering effort against a stated, bounded gap, not silent avoidance
of a hard problem. Chapter 4 should list the exact construct coverage
(records, sealed types, pattern-matching `instanceof`, text blocks)
and the exact, deliberate exclusion (switch expressions) as part of
Layer 1's parser scope. Chapter 5's robustness/limitations discussion
should note that any Java 17-21 sample using switch expressions or
pattern-matching `switch` will report `PARSE_FAILED`, not a wrong
result - consistent with the project's fail-closed principle - and
that this is a known, bounded, and now-documented limitation rather
than an unbounded one.

## [2026-07-15] - Java 17-21 preprocessor re-attacked; string/comment mutation bug fixed

**What we re-tested:** After extending Layer 1's Java 17-21 coverage
via `_modern_java_preprocessor.py`, re-ran the parser/rule pipeline
against adversarial modern-Java inputs rather than only "happy path"
construct examples: sealed declarations with hardcoded secrets, text
blocks containing secrets, pattern-matching `instanceof` inside Spring
controllers, empty-bodied records, records with bodies, switch
expressions, and literal/comment text that merely *looked like* modern
Java syntax.

**What broke:** The regex rewrites for sealed modifiers, `permits`
clauses, pattern-matching `instanceof`, and records were still running
globally over the whole source file. That meant ordinary string
literals, text-block values after desugaring, and comments could be
silently mutated if they contained words like `sealed`, `non-sealed`,
`permits`, or `o instanceof String value`. Example failure before the
fix: `String password = "sealed secret";` was rewritten into
`String password = "secret";`. For CWE-798 this is a significant
correctness bug because the scanner reasons about literal values; a
parseable but corrupted value is worse than a clean `PARSE_FAILED`.

**Fix:** Added a source-index-preserving mask used by every regex
preprocessor substitution. The mask blanks string literals, character
literals, line comments, and block comments while preserving all
indexes and newlines, then applies regex matches found on the masked
"real code only" view back to the original source spans. This keeps
line-number preservation intact while preventing code transforms from
touching literal/comment content.

**Regression tests added:** `tests/test_modern_java_preprocessor.py`
now covers sealed/permits text inside normal string literals and
comments, pattern-matching-`instanceof` text inside string literals,
and text-block contents that contain sealed/permits/instanceof-looking
text. The tests assert the literal value is preserved, not merely that
the rewritten file parses.

**Current verified behavior:** Java 17 constructs that are safe to
preprocess still parse and feed the CWE rules correctly: sealed class
with `password` -> CWE-798 finding, text block assigned to `password`
-> CWE-798 finding, Spring endpoint using pattern-matching
`instanceof` -> CWE-284 finding, empty-bodied record -> parses.
Known deliberate gaps remain unchanged: switch expressions and
records with non-empty bodies still fail closed as `PARSE_FAILED`.
Full verification after the fix: 139 tests passed, `mypy`, `ruff`,
`black --check`, and `git diff --check` all clean.

## [2026-07-16] - Code review round: fail-closed scanner bug, pom.xml entity-expansion gap, text-block escape gap

**What the plan said:** The prior two entries treated `scanner.py`'s
test-root exclusion, `pom_parser.py`'s XML-attack hardening, and the
Java 17-21 text-block desugaring as done and verified.

**What we actually did / found:** An independent code review surfaced
three real defects the earlier verification passes missed, none
hypothetical - each was reproduced directly before being fixed.

1. **(Blocking, fail-closed violation)** `scanner.py`'s directory walk
   excluded *any* directory segment named `test`/`tests` anywhere in
   the tree, not just conventional test roots. A production package
   genuinely named `test` (e.g. `com.example.test`, a plausible name
   for a testing-utilities module shipped as part of the app) was
   silently dropped from the scan with **no** `rejected_paths` entry -
   a direct violation of CLAUDE.md's fail-closed requirement that a
   file never be dropped from results without a trace. Reproduced with
   `src/main/java/com/example/test/ProdSecret.java` containing a
   hardcoded password: `scan_directory()` returned it in neither
   `java_files` nor `rejected_paths`. Fixed by scoping the exclusion to
   two conventional shapes only - directly under a `src` directory
   (Maven/Gradle's `src/test/...` layout, matched by immediate parent
   name, so it still works in multi-module repos) or directly under
   the scan root itself (`<root>/test(s)/...`) - via a new
   `_is_conventional_test_root` helper. A nested directory named
   `test`/`tests` anywhere else is now scanned like any other
   directory. Two new regression tests lock this in:
   `test_scan_does_not_skip_a_production_package_named_test` and
   `test_scan_skips_root_level_test_directory` (the existing
   `test_scan_skips_test_source_roots` continues to pass unchanged,
   since `src/test/...` is still excluded).

2. **(Significant, security-relevant)** `pom_parser.py`'s module
   docstring claimed internal entity-expansion ("billion laughs") was
   "already rejected" by CPython's expat amplification-ceiling
   protection - true only for large payloads. A small, deliberately
   crafted `<!DOCTYPE>`/`<!ENTITY>` payload (well under that ceiling)
   parsed *successfully*, with its expansion silently substituted into
   the tree - a real gap the earlier verification's single "billion
   laughs"-scale test case didn't exercise. Fixed by rejecting any
   `pom.xml` containing a `<!DOCTYPE` declaration outright, before
   `ET.fromstring` ever runs: a real Maven POM never declares one, so
   this has no false-positive cost and removes internal entity
   expansion as an attack surface entirely, not just above some size
   threshold. The module docstring's inaccurate claim was corrected in
   place rather than left standing next to the fix. New regression
   test `test_parse_rejects_small_entity_expansion_not_just_large_bombs`
   locks in the previously-unguarded small-payload case; the existing
   large-bomb and XXE tests continue to pass unchanged (both already
   asserted `PARSE_FAILED`, which the new check also produces, for a
   more direct reason).

3. **(Significant)** `_modern_java_preprocessor.py`'s text-block
   desugaring didn't interpret the two escape sequences that exist
   only inside real Java text blocks: `\s` (an explicit trailing space
   that JEP 378's trailing-whitespace stripping would otherwise
   remove) and a backslash immediately followed by a line terminator
   (line continuation, suppressing that line break). This had been
   flagged as a "known simplification" in the prior entry, but a
   concrete repro showed the actual failure mode was worse than
   documented: `String password = """\n abc\s\n """;` - valid Java
   15+ syntax found in real repos - returned `PARSE_FAILED` ("Illegal
   escape character"), not merely an inexact value. Fixed by adding
   `_interpret_text_block_escapes`, run on the stripped text-block
   value before the existing `_escape_for_string_literal` step:
   resolves `\s` to a literal space and drops a backslash-newline pair
   entirely (removing that newline only changes the text block's
   *value*, not the surrounding file's line count, since it operates
   on the value-internal `"\n".join(...)` joiner, not a real source
   newline - verified directly with a dedicated newline-count-
   preservation test). Three new regression tests cover both escapes
   individually and newline-count preservation across a line
   continuation.

All three fixes are additive/narrowing (tighten a check, correct
documentation, add previously-missing interpretation) - no existing
passing test needed its assertions changed to accommodate them, and
the full existing coverage (`test_scan_skips_test_source_roots`, the
large-entity-bomb and XXE tests, all prior text-block tests) still
passes unmodified.

**Regression tests added:** 8 new tests total across
`tests/test_scanner.py` (2), `tests/test_pom_parser.py` (1), and
`tests/test_modern_java_preprocessor.py` (5 - two escape-specific plus
one newline-preservation case; the newline-count and double-escape
existing tests already exercised the general text-block path). Full
suite: 145 passed (was 139). `black --check`, `ruff`, and `mypy` all
clean.

**Why:** These are exactly the class of bug this project's own
fail-closed and "verify, don't assume" principles exist to catch -
each was a place where an earlier entry's *claim* ("already rejected,"
"documented as a limitation," "verified... not just does it parse")
turned out to not fully match the code's actual behavior once tested
with a more targeted adversarial input than the original pass used.
Catching this via review rather than in the thesis's own evaluation
chapter is the cheaper place for it to surface.

**Effect on thesis chapters:** Chapter 4 should describe the
test-root-exclusion scoping (`src/test` and root-level `test(s)/` only,
not a blanket name match) as the final, corrected version of that
design decision - the earlier blanket-exclusion version should not be
presented as the implemented behavior. Chapter 5's robustness
discussion should cite the small-entity-expansion finding as a
concrete example of why "verified against a known attack pattern" must
specify the *size/shape* of payload tested, not just the attack class
- the large-bomb test alone gave a false sense of completeness.
Chapter 5 should also drop the `\s`/line-continuation "known
simplification" framing from the parser-coverage discussion, since
both are now handled; the switch-expression gap remains the only
documented, deliberate Java 17-21 exclusion.

## [2026-07-17] - Java parser fallback migrated to Tree-sitter for Java 17-21 coverage

**What the plan said:** The earlier Java 17-21 parser entries accepted
targeted text preprocessing as the proportional fix and left records
with bodies plus modern switch forms as fail-closed limitations.

**What we actually did / found:** The project scope changed: Java 17+
coverage now needs to work across all Layer 1 Java rules, not merely
avoid parser crashes. Added `tree-sitter==0.26.0` and
`tree-sitter-java==0.23.5` as a modern Java parser fallback behind the
existing `ast_parser.parse_file()` API. The fallback only runs when
the existing javalang/preprocessor path fails, so current behavior for
already-supported Java files remains stable while valid Java 17-21
syntax no longer stops the scan.

The new `vibeguard/layer1_static/_tree_sitter_java.py` module
centralizes Tree-sitter parsing and traversal helpers instead of
scattering parser-specific logic through the codebase. `ParsedFile`
now has two explicit AST slots: `tree` for javalang and `tree_sitter`
for Tree-sitter fallback parses. Java rule modules dispatch on that
field and run equivalent Tree-sitter logic for the four Java-source
rules:

- **CWE-798** inspects Tree-sitter `variable_declarator` nodes and
  still folds literal string concatenation.
- **CWE-284** inspects endpoint method declarations and their nearest
  enclosing class/interface/record authorization annotations.
- **CWE-287** inspects `==`/`!=` binary expressions involving
  credential-shaped identifiers or field accesses.
- **CWE-20** inspects endpoint parameters for unvalidated
  `@RequestBody` DTOs.

Verified directly that the fallback parses records with compact
constructors/method bodies, switch expressions, arrow-style switch
statements, `yield` switch forms, and pattern-matching switch without
returning `PARSE_FAILED`. Also verified that rule findings still fire
on fallback-parsed files: hardcoded secrets inside a record body,
unprotected Spring endpoint using switch expression, unsafe credential
comparison in a switch-expression method, and unvalidated
`@RequestBody` on a fallback-parsed endpoint.

**Regression tests added:** 7 new tests:
`test_parse_record_with_compact_constructor_uses_tree_sitter_fallback`,
`test_parse_switch_expression_uses_tree_sitter_fallback`,
`test_tree_sitter_fallback_preserves_extends_and_implements_summary`,
and one Tree-sitter-fallback coverage test each for CWE-798, CWE-284,
CWE-287, and CWE-20. Full suite: 151 passed (was 145). `mypy`,
`ruff`, and `black --check` all clean.

**Why:** At this point, continuing to extend regex/text preprocessing
would create exactly the risk previously documented for switch
expressions: a parser-shaped rewrite layer that could silently produce
wrong ASTs. Tree-sitter is the cleaner boundary: it is still local,
does not execute analysed Java, supports modern Java grammar, and lets
VibeGuard fail closed on actual syntax errors while continuing to run
all Java CWE rules on valid Java 17-21 files.

**Effect on thesis chapters:** Chapter 3 should update the methodology
from "javalang plus targeted preprocessing only" to "javalang first,
Tree-sitter fallback for modern Java syntax." Chapter 4 should list
Tree-sitter as part of Layer 1's parser implementation and explain the
dual-parser contract (`ParsedFile.tree` vs `ParsedFile.tree_sitter`).
Chapter 5 should remove the previous "switch expressions are an
accepted limitation" statement and replace it with the new verified
coverage claim, while still noting that the rules remain heuristic and
name/annotation based rather than semantic type analyses.

## [2026-07-17] - Tree-sitter fallback parity hardened with shared literal decoding

**What the plan said:** The Tree-sitter fallback entry moved modern
Java parsing behind `ParsedFile.tree_sitter` and added equivalent rule
paths for the four Java-source CWE rules.

**What we actually did / found:** A QA pass found two follow-up risks:
the javalang and Tree-sitter paths had separate Java string-literal
decoding logic, and there was no guardrail preventing a future Java
rule from accidentally supporting only javalang. This was not an
immediate false-negative in the existing tests, but it was a realistic
maintenance gap: any divergence in literal decoding directly affects
CWE-798's core judgment, and any future Java rule missing a
Tree-sitter path would silently under-report modern Java files.

Added `vibeguard/layer1_static/_java_literals.py` as the single shared
decoder for Java normal string literals and text blocks. Both
`cwe_798.py`'s javalang path and `_tree_sitter_java.py` now call this
decoder. The decoder covers standard escapes used by realistic
credentials (`\n`, `\t`, escaped quotes/backslashes, Unicode escapes)
and Java text-block normalization (indent stripping, `\s`, and
line-continuation escapes) without executing or evaluating Java code.

Added parser-path guardrails:

- `tests/test_java_literals.py` locks down shared literal decoding.
- `test_detect_in_java_decodes_text_block_secret_on_tree_sitter_fallback`
  proves CWE-798 still detects a text-block secret when Tree-sitter is
  the active AST path.
- `tests/test_java_rule_fallback_coverage.py` fails if any Java-source
  CWE rule lacks a Tree-sitter fallback path. CWE-1035 is excluded
  because it is POM-only.

**Why:** The Tree-sitter migration is only defensible if the fallback
path is not a second-class parser path. Literal-value parity and
rule-path parity are the two immediate places where the dual-parser
design could drift and create under-reporting. These tests make that
failure mode visible during development instead of during evaluation.

**Effect on thesis chapters:** Chapter 4 should mention that
parser-specific AST traversal is hidden behind shared helpers where
possible, and Chapter 5 should treat Java string-literal/text-block
handling as a tested robustness point rather than an incidental parser
detail.

## [2026-07-17] - CWE-798 assignment-expression coverage added

**What the QA pass found:** CWE-798 detected hardcoded credentials in
field/local variable declarations, but not in later assignments. This
created false negatives for real Java patterns such as:

```java
String password;
password = "hunter2";
this.token = "abc123";
```

The same gap existed on the Tree-sitter fallback path, which meant
Java 17 constructs such as compact record constructors could parse
successfully while still hiding an assigned secret:

```java
public record Config(String password) {
    public Config {
        password = "hunter2";
    }
}
```

**What changed:** `cwe_798.py` now inspects assignment expressions in
both parser paths in addition to variable declarations. The rule only
flags plain `=` assignments whose left side resolves to a
credential-shaped identifier/field and whose right side is still a
statically known Java string literal or literal concatenation. Existing
safe-value exclusions still apply (`${...}`, `#{...}`, placeholders,
empty values, and `"null"`).

**Regression tests added:** CWE-798 now has tests for assignment after
declaration, `this.field` assignment, safe assignment values, and a
Tree-sitter-parsed compact record constructor assignment.

**Why:** After the Tree-sitter migration, parser coverage was no longer
the main issue for these examples; rule parity was. Adding assignment
coverage keeps CWE-798 aligned with how Java code is commonly written
without introducing broader data-flow or constant-propagation scope.

## [2026-07-17] - Java Unicode escape normalization added before parsing

**What the QA pass found:** Valid Java can hide identifier text behind
source-level Unicode escapes because Java translates `\uXXXX` escapes
before lexical analysis. A file containing `pass\u0077ord` is parsed by
javac as `password`, but the parser pipeline could fail or miss the
credential-shaped name.

**What changed:** Added `translate_java_unicode_escapes()` and now
normalize Java source before both the javalang/preprocessor path and
the Tree-sitter fallback path. This keeps parser behavior closer to
Java's actual lexical rules and prevents an adversarial source file
from hiding credential identifiers with Unicode escapes.

**Regression tests added:** Unit coverage for standard and repeated-u
Unicode escape forms, parser coverage for escaped identifiers, and a
CWE-798 regression proving `String pass\u0077ord = "hunter2";` is
reported as a hardcoded `password`.

**Scope note:** This fixes the realistic identifier-evasion case while
preserving the existing line-number behavior for normal escapes. Unicode
escapes that intentionally introduce new line terminators are valid Java
too, but exact original-source traceability for those cases would
require a line-map layer; that remains out of scope for this patch.

## [2026-07-17] - CWE-798 call-site literal coverage added

**What the adversarial QA pass found:** CWE-798 handled declarations
and assignments but still missed common hardcoded-secret call-site
patterns that parse cleanly:

```java
config.setPassword("hunter2");
User.builder().apiKey("sk-live-abc123").build();
values.put("password", "hunter2");
new PasswordAuthentication("admin", "hunter2".toCharArray());
```

These are realistic in Spring/Quarkus code, generated config/client
setup, and Java authentication APIs. Because the files parsed
successfully, missing them was a false-negative rule gap rather than a
parser limitation.

**What changed:** `cwe_798.py` now inspects literal arguments at Java
call sites in both parser paths. It flags:

- credential-shaped method names with literal arguments, including
  setter and fluent-builder style calls;
- `Map.put("credentialKey", "literalSecret")` style calls;
- credential-shaped constructor/type names with literal arguments,
  preferring later arguments so `PasswordAuthentication("user",
  "password".toCharArray())` reports the password value.

Existing safe-value exclusions still apply, so property references,
placeholders, empty values, and `"null"` remain suppressed. The rule
still does not perform data-flow or constant propagation; it remains a
literal-source heuristic.

**Regression tests added:** CWE-798 now covers setter calls, fluent
builder calls, map puts, credential constructors, safe call-site values,
Tree-sitter fallback call sites, and text-block redaction normalization.

## [2026-07-17] - Adversarial literal-expression and getter comparison gaps closed

**What the adversarial QA pass found:** After call-site coverage,
several successful-parse patterns still produced false negatives:

```java
password = prod ? "real-prod-secret" : "dev-secret";
token = switch (level) { case 1 -> "abc123"; default -> "def456"; };
String[] passwords = {"hunter2", "backup"};
char[] password = {'h','u','n','t','e','r','2'};
System.setProperty("db.password", "hunter2");
@Value("${db.password:hunter2}") String password;
return user.getPassword() == input;
```

**What changed:** CWE-798 literal extraction now handles ternary
expressions, Tree-sitter switch expressions, string-array literals,
char-array reconstruction, `System.setProperty(key, value)`, and Spring
`@Value("${key:default}")` defaults when the key/default is
credential-shaped. CWE-287 now treats zero-argument credential-shaped
getter calls, such as `getPassword()`, as credential operands for
unsafe `==`/`!=` comparisons in both parser paths.

**Scope boundary:** This still deliberately avoids data-flow and
constant propagation. Secrets split across variables remain out of
scope for Layer 1's current heuristic design. Custom/meta authorization
annotation expansion for CWE-284 and Unicode original-line source maps
remain separate larger-scope issues.

**Regression tests added:** CWE-798 now covers ternary secrets,
switch-expression secrets, string arrays, char arrays,
`System.setProperty`, Spring `@Value` defaults, and safe `@Value`
references. CWE-287 now covers credential getter comparisons on both
javalang and Tree-sitter fallback parses.

## [2026-07-17] - Layer 1 static analysis freeze and handoff

**Freeze decision:** Layer 1 is stable enough to hand off to the next
pipeline layer. The final validation before this decision was clean:
181 tests passed, `mypy .` clean, `ruff check .` clean,
`black --check .` clean, and `git diff --check` clean.

**Current Layer 1 guarantees:**

- Java source is parsed with javalang first and Tree-sitter fallback for
  modern Java syntax, including records with bodies and switch
  expressions.
- Java source is never compiled, executed, imported, or evaluated.
- Parser guards cover file-size rejection, invalid UTF-8/read failures,
  malformed syntax, and parse timeout reporting.
- Scanner traversal rejects symlink escapes, skips build output and
  conventional test roots, and preserves production packages named
  `test`/`tests`.
- Java Unicode escapes are normalized before parsing so escaped
  identifiers such as `pass\u0077ord` are treated like Java treats them.
- CWE-798 covers credential-shaped declarations, assignments,
  setters/builders, map puts, credential constructors, ternaries,
  Tree-sitter switch expressions, string arrays, char arrays,
  `System.setProperty`, Spring `@Value` defaults, config files, and
  common placeholder/property-reference suppressions.
- CWE-287 covers unsafe `==`/`!=` comparisons involving credential
  variables, fields, `this.field`, string literals, and zero-argument
  credential getters such as `getPassword()`.
- CWE-284 covers unprotected endpoint methods, including nested methods
  and Tree-sitter fallback files, with method-level and nearest
  enclosing type authorization annotations.
- CWE-20 covers Spring `@RequestBody` parameters missing
  `@Valid`/`@Validated`, including fully qualified annotations and
  Tree-sitter fallback files.

**Accepted Layer 1 limitations:**

- CWE-284 does not expand custom/meta authorization annotations such as
  a project-specific `@AdminOnly` annotated with `@RolesAllowed`.
- Unicode escapes that introduce line terminators are parsed according
  to Java semantics, but findings report translated-source line numbers
  rather than original raw-file coordinates. Exact original traceability
  would require a source line-map layer.
- Layer 1 does not perform cross-variable constant propagation or
  general data-flow analysis. Secrets split across separate variables
  remain out of scope for this layer.
- Rule logic remains heuristic and name/annotation based. Deeper
  semantic validation, deduplication, prioritization, and risk scoring
  belong in later layers.

**Next-layer handoff contract:** Downstream layers can treat Layer 1 as
the source of normalized, file/line-traceable candidate findings, not
final vulnerability judgments. The next layer should focus on
deduplication, context enrichment, confidence/risk scoring, and
preserving traceability from each higher-level decision back to the
Layer 1 finding that triggered it.

## [2026-07-17] - Layer 2 feature extraction contract started

**What the plan said:** Layer 2 converts Layer 1 findings and parsed
AST context into structured numeric/categorical features consumed by
Layer 3 scoring and Layer 4 ML.

**What we actually did / found:** Layer 2 was still only a package
stub. Added `vibeguard/layer2_features/extractor.py` with a minimal,
deliberately stable contract: raw Layer 1 `Finding` objects are
converted into immutable `FindingFeature` rows while preserving
traceability (`cwe_id`, resolved file path, line, identifier, original
message, and redacted value). Added conservative deduplication by
`(cwe_id, file_path, line, identifier)` so later scoring does not count
the same raw finding twice while still preserving separate occurrences
on different lines.

The first feature set is intentionally simple and deterministic:
source extension, whether a line number exists, whether a redacted value
exists, identifier length, and message length. These are not final ML
features; they are the stable handoff shape Layer 3/4 can now build on.

**Why:** Layer 1 is frozen as a candidate-finding layer. The next
pipeline stage needs a normalized feature row that is traceable and
deduplicated before any scoring or ML can be defensibly added. Starting
with this narrow extractor avoids prematurely designing ML features
before the rule-based scoring contract is in place.

**Effect on thesis chapters:** Chapter 4 should describe Layer 2 as the
normalization/deduplication boundary between raw static findings and
later risk scoring. Chapter 5 can report that the first Layer 2
contract preserves traceability rather than replacing it.

## [2026-07-21] - Layer 2 adversarial QA hardening pass

**Scope:** Layer 2 feature extraction only:
`vibeguard/layer2_features/extractor.py` and its regression tests.
Layer 1 remained frozen; no CWE rule or parser behavior was changed.

**What the QA pass tried:** Re-attacked the Layer 2 boundary with
inputs that should not become downstream feature rows: missing/non-real
paths, bool line values (`line=True`), negative lines, unsupported CWE
IDs, unsupported file extensions, blank identifiers/messages, embedded
newlines/NUL/control characters, Unicode format-control characters
used for report spoofing, blank redacted values, and valid config/POM
source variants.

**What we actually did / found:** Three real Layer 2 boundary gaps:

- `line=True` was accepted because Python treats `bool` as a subclass
  of `int`. This produced a feature with `line=True` instead of a
  concrete source line number.
- Identifiers/messages/redacted values could contain control or
  invisible Unicode format characters. That is unsafe for later
  reports/logs because a finding could inject newlines or spoof display
  direction.
- A finding from an unsupported source extension became
  `source_type="unknown"` instead of failing loud. Current Layer 1
  findings are expected to originate from Java source, config files, or
  POM files only; silently allowing unknown sources weakens the Layer 2
  contract.

**What changed:** Layer 2 now rejects bool/non-integer line values,
control/invisible text in all normalized string fields, blank
`redacted_value` values, and unsupported source extensions. Valid
findings are still normalized as before: CWE IDs are canonicalized,
text fields are stripped, file paths are resolved, source type flags are
derived, and duplicates collapse only on `(cwe_id, file_path, line,
identifier)`.

**Tests/adversarial checks run:**

- `pytest tests/test_layer2_extractor.py -q`: 15 passed.
- `mypy vibeguard/layer2_features tests/test_layer2_extractor.py`: clean.
- `ruff check vibeguard/layer2_features tests/test_layer2_extractor.py`: clean.
- `black --check vibeguard/layer2_features tests/test_layer2_extractor.py`: clean.
- Full repo gates: `mypy .`, `ruff check .`, `black --check .`, and
  `git diff --check` clean.
- Full `pytest -q`: 196 passed. A first run printed the passing
  summary but was slow to return to the shell; a controlled rerun
  confirmed clean process exit (`196 passed in 59.48s`, exit code 0).

**Remaining limitations:** Layer 2 still intentionally extracts a
minimal deterministic feature set. Richer contextual features for ML
and risk weighting belong in Layer 3/4 design, not in this hardening
pass. `path_depth` is still based on the resolved absolute path and
should not be treated as a high-value ML signal without reevaluating
dataset portability.

**Effect on thesis chapters:** Chapter 4 can describe Layer 2 as a
fail-closed normalization boundary, not just a data reshaping step.
Chapter 5 can cite this pass as robustness testing for traceability and
report-safety inputs before scoring/ML were introduced.

## [2026-07-21] - Layer 2 removed absolute `path_depth` feature

**Decision:** Remove `path_depth` from `FindingFeature`.

**Why:** `path_depth` was computed from `Path.resolve().parts`, which
means it measured the local machine's absolute filesystem layout, not a
stable property of the Java project. The same finding could receive
different values under `/Users/...`, `/tmp/...`, a CI checkout, or a
dataset extraction directory. That makes it a weak ML/scoring signal and
creates a portability risk before any scoring model even exists.

**What changed:** `FindingFeature` no longer exposes `path_depth`, and
the tests now assert that absolute path depth is not part of the Layer 2
contract. Traceability is unchanged: `file_path` remains resolved and
`trace_key` still uses `(cwe_id, file_path, line, identifier)`.

**What to do if path context is needed later:** Add an explicit
project-relative path feature only after the scanner/extractor contract
passes a scan root or repository root into Layer 2. Do not infer project
structure from absolute paths.

**Effect on thesis chapters:** Chapter 4 should describe Layer 2's
current features as deterministic source/type/text/traceability
features only. Do not claim path-structure features until a
project-relative design is implemented and tested.

## [2026-07-21] - Aggressive QA pass over Layers 1 and 2; properties parser false negative fixed

**Scope:** Final QA pass over Layer 1 static analysis and Layer 2
feature extraction. Layer 1 was treated as frozen except for blocking
correctness regressions found by the QA pass; Layer 2 was treated as
freeze-ready pending this pass. Layers 3-5 remained out of scope.

**What the QA pass tried:** Existing full test suite and static gates;
dependency vulnerability audit; no-execution grep; secret-hygiene grep;
generated malformed/empty/oversized/invalid-UTF-8 Java files; Java
17-21 fallback syntax (records, compact constructors, sealed types,
pattern switch); deep nested classes; large but under-limit Java files;
scanner symlink escape and test-root behavior; YAML cycles/duplicates;
POM DOCTYPE rejection and property resolution; all five CWE rules on
direct adversarial examples; Layer 2 deduplication and invalid field
rejection.

**What we actually found:** One real Layer 1 false-negative path in
`.properties` config parsing. Java `.properties` syntax allows
whitespace-only key/value separators and `\uXXXX` escapes. Before this
pass:

```properties
db.pass\u0077ord=hunter2
db.password hunter2
```

parsed successfully but did not produce the expected CWE-798 finding
for `db.password`.

**What changed:** `config_parser.py` now supports the Java properties
basics needed for Spring/Quarkus config: unescaped `=`, `:`, or
whitespace separators, optional whitespace around separators, line
continuation, and standard backslash escape decoding including
`\uXXXX`. Malformed escape sequences are preserved rather than raised,
so a malformed config line cannot abort a batch scan. Existing
continuation tests were updated to reflect the new, more spec-correct
behavior: backslash escape decoding happens after logical-line joining.

**Regression tests added:** `tests/test_config_parser.py` now covers
whitespace-separated properties and escaped key/value text.
`tests/test_cwe_798.py` now proves CWE-798 detects hardcoded secrets
when the credential key is Unicode-escaped or whitespace-separated in
`.properties`.

**Tests/adversarial checks run after the fix:**

- Targeted parser/rule/Layer 2 tests: 71 passed.
- Full `pytest -q`: 201 passed, exit code 0.
- `mypy .`: clean.
- `ruff check .`: clean.
- `black --check .`: clean.
- `git diff --check`: clean.
- `safety check -r requirements.txt`: 0 vulnerabilities reported
  across 19 scanned packages. The command itself is deprecated by
  Safety in favor of `safety scan`, but it completed successfully.
- Custom adversarial Layer 1/2 matrix: 27 checks passed after the fix.
- Generated stress pass: 9 checks passed.

**Other QA observations:** No runtime execution/eval path for analysed
Java content was found. The grep hits for `exec`/`eval` were regex
patterns, docstrings, or the documented timeout helper, not execution of
target code. The secret-hygiene grep found fake fixture values such as
`hunter2` inline in unit-test source files as well as under
`tests/fixtures`; this is not a Layer 1/2 correctness bug, but before
public release the project should decide whether to move inline Java
test snippets containing fake secrets into dedicated fixtures or clearly
label them as test-only fixture data.

**Freeze decision:** Layer 1 is re-frozen after the narrow
`.properties` parser fix. Layer 2 is frozen: its current contract is
normalization, validation, conservative deduplication, source-type
feature extraction, and traceability preservation. Do not reopen either
layer unless Layer 3+ exposes a blocking correctness issue.

**Effect on thesis chapters:** Chapter 4 should describe `.properties`
support as covering Unicode escapes and whitespace separators, not only
`key=value`/`key:value`. Chapter 5 can cite this pass as evidence that
the implementation was attacked across parser, scanner, rule, and
feature-extraction boundaries before moving to scoring.

## [2026-07-22] - Layer 3 deterministic rule-based scoring started

**Scope:** Layer 3 rule-based scoring, plus minimal CLI integration so
the runnable tool no longer reports Layer 1 findings as "not yet
scored." Layers 1 and 2 remained frozen; Layers 4-5 remained out of
scope.

**What the plan said:** CLAUDE.md defines Layer 3 as rule-based scoring
after Layer 2 feature extraction and before Layer 4 ML classification.

**What we actually did:** Added
`vibeguard/layer3_scoring/scorer.py` with immutable `ScoredFinding`
rows and a `RiskSeverity` enum. `score_features()` consumes validated
Layer 2 `FindingFeature` rows and returns one scored row per feature,
preserving input order and the original Layer 2 `trace_key`.

The initial rubric is deterministic and deliberately simple:

- CWE-798: base 90.
- CWE-1035: base 85.
- CWE-284: base 80.
- CWE-287: base 75.
- CWE-20: base 65.
- CWE-798 in config receives `+5` because deployment config secrets are
  commonly broad-impact.
- CWE-1035 in `pom.xml` receives `+5` because it is a declared vulnerable
  dependency.
- Any finding without a line number receives `-5` to reflect reduced
  traceability confidence, not because the vulnerability is necessarily
  less severe.
- Scores are clamped to `0-100` and mapped to severity bands:
  `critical >= 85`, `high >= 70`, `medium >= 40`, otherwise `low`.

Layer 3 also validates feature consistency instead of trusting malformed
rows blindly: unsupported CWE IDs, unsupported source types,
source-type flag mismatches, source-extension/source-type mismatches,
impossible CWE/source-type combinations, missing CWE-798 redacted
values, and unexpected redacted values on non-CWE-798 findings all raise
`ValueError`.

`main.py` now routes raw rule findings through Layer 2 and Layer 3, then
prints scored findings with score and severity. The CLI exit behavior is
still conservative: any scored finding returns non-zero until a later
severity-threshold policy is explicitly designed.

**Regression tests added:** `tests/test_layer3_scorer.py` covers score
values, severity bands, traceability preservation, order preservation,
empty input, missing-line adjustment, config/POM adjustments, and
adversarial invalid feature rows. `tests/test_main.py` now asserts that
CLI findings include score and severity.

**Tests/adversarial checks run:**

- Targeted Layer 3/CLI tests: 21 passed.
- Custom Layer 3 adversarial probe: 6 checks passed, including deduped
  Layer 2 input, stable score vector, trace-key preservation, missing
  line factor, and invalid feature rejection.
- Full `pytest -q`: 214 passed, exit code 0.
- `mypy .`: clean.
- `ruff check .`: clean.
- `black --check .`: clean.
- `git diff --check`: clean.

**Remaining limitations:** This is not CVSS and not ML. The weights are
transparent thesis-baseline heuristics, not an empirically trained risk
model. Layer 4 should treat these scores as deterministic baseline
labels/features to compare against or refine, not as final ground truth.
No severity threshold policy has been added yet; the CLI still fails on
any scored finding.

**Freeze decision:** The scoped Layer 3 scorer is frozen as the
deterministic baseline scoring layer. Reopen it only if Layer 4 exposes
a blocking contract issue or the thesis methodology explicitly changes
the rule-based scoring policy.

**Effect on thesis chapters:** Chapter 4 should describe Layer 3 as a
deterministic, explainable baseline scorer over Layer 2 features.
Chapter 5 should evaluate this separately from Layer 4 ML: Layer 3
provides transparent heuristic scoring, while Layer 4 will test whether
ML improves or changes the ranking/classification behavior.

## [2026-07-22] - Layer 4 project-level ML classifier started and tested

**Scope:** Layer 4 ML classification only, built on frozen Layers 1-3.
No source parsing, CWE detection, rule scoring, CLI deployment, or SHAP
reporting changes were made in this pass.

**What the plan said:** CLAUDE.md requires ML usage (Random Forest /
XGBoost) and frames Layer 4 as ML classification after rule-based
scoring. The thesis justification is that static analysis detects
individual vulnerabilities, while ML learns how combinations and context
affect overall risk priority.

**What we actually did:** Added a first local Random Forest
implementation:

- `vibeguard/layer4_ml/predictor.py` builds deterministic project-level
  feature vectors from Layer 3 `ScoredFinding` rows and predicts
  `MLRiskLabel` values.
- `vibeguard/layer4_ml/trainer.py` trains a local
  `RandomForestClassifier` over labelled project examples.
- `vibeguard/layer4_ml/__init__.py` exports the public Layer 4 API.

Layer 4 is intentionally project-level, not finding-level. It does not
re-detect vulnerabilities. Its vector includes counts and combinations:
finding count, max/mean Layer 3 score, severity counts, per-CWE counts,
source-type counts, missing-line count, project-wide CWE co-occurrence
features, and same-file combination features such as CWE-798+CWE-284
and CWE-284+CWE-20. This directly supports the thesis claim that ML can
learn interaction risk beyond one-by-one rule additions.

Training fails closed on unusable data: empty training sets and
single-class datasets raise `ValueError`. Prediction fails closed if the
trained model's feature schema differs from the current feature vector
schema.

**Regression tests added:** `tests/test_layer4_ml.py` covers empty
project vectors, CWE/source/combination feature extraction, training
input validation, prediction on seen synthetic patterns, confidence
range, and schema mismatch rejection.

**Tests/adversarial checks run:**

- Targeted Layer 4 tests: 6 passed.
- Custom Layer 4 adversarial probe: 8 checks passed, including feature
  order invariance, unique schema names, zero-vector empty projects,
  same-seed prediction stability, probability-like confidence, and
  invalid training-set rejection.
- Full `pytest -q`: 220 passed, exit code 0.
- `mypy .`: clean.
- `ruff check .`: clean.
- `black --check .`: clean.
- `git diff --check`: clean.

**Remaining limitations:** This is a first testable ML layer, not final
evaluation. The model still needs a real labelled dataset of AI-generated
or vibe-coded Java microservices before thesis-quality metrics can be
reported. XGBoost remains a planned comparison/extension; the current
implementation starts with Random Forest because it is deterministic,
fast, local, and easier to validate on small labelled datasets. Layer 4
is not yet wired into `main.py`; doing so should wait until there is a
trained model persistence/loading contract and a labelled-data workflow.

**Effect on thesis chapters:** Chapter 3 should state that ML operates
on project-level feature vectors derived from static findings and rule
scores, not raw source code. Chapter 4 should document the initial
Random Forest implementation and feature schema. Chapter 5 must evaluate
Layer 4 only after labelled examples exist, comparing ML predictions
against the Layer 3 deterministic baseline.

## [2026-07-22] - Full-suite pytest cleanup hang fixed with local basetemp

**Scope:** Test-runner hygiene only. No parser, scanner, rule, feature,
scoring, or ML behavior changed.

**What we found:** Full `pytest -q` executed all tests successfully, but
the process could hang after reaching 100% while pytest cleaned retained
numbered `tmp_path` directories under the system temp root. The hang was
observed in pytest's `cleanup_numbered_dir` / dead-symlink cleanup path
after symlink-heavy scanner tests had run. This made the test outcome
ambiguous even though the suite itself reported all tests passing.

**What changed:** `pyproject.toml` now sets pytest to use a project-local
ignored base temp directory with no retained tmp-path sessions:
`--basetemp=.pytest-tmp`, `tmp_path_retention_policy = "none"`, and
`tmp_path_retention_count = 0`. `.pytest-tmp/` was added to `.gitignore`.

**Why:** The scanner intentionally tests symlink attack cases. Those
tests should stay, but stale pytest temp-session cleanup should not be
allowed to make the full QA gate hang after completion. A local
single-run basetemp keeps the adversarial tests intact while making the
test runner deterministic and self-cleaning.

**Tests run after the fix:**

- Full `pytest -q`: 220 passed, clean exit code 0.
- `mypy .`: clean.
- `ruff check .`: clean.
- `black --check .`: clean.
- `git diff --check`: clean.

**Effect on thesis chapters:** No methodology change to the VibeGuard
analysis pipeline. Chapter 4/5 can simply rely on the full-suite QA gate
as cleanly repeatable after this test-infrastructure fix.

## [2026-07-22] - Layer 4 labelled-data loader and evaluation metrics added

**Scope:** Layer 4 ML dataset and evaluation workflow only, building on
the existing project-level Random Forest classifier. Layers 1-3 stayed
frozen. CLI wiring, model persistence/loading, XGBoost comparison, and
Layer 5 SHAP/reporting remained out of scope.

**What the plan said:** Layer 4 needed a labelled-data workflow and
evaluation metrics before it could become thesis-defensible. The earlier
Layer 4 implementation could train and predict from in-memory synthetic
examples, but there was no durable dataset schema or metrics output.

**What we actually did:** Added `vibeguard/layer4_ml/dataset.py` with
`load_training_examples()`, a strict JSON loader for labelled project
examples. The dataset shape is explicit: each project has a
`project_id`, `label`, and a list of Layer 1-style finding records
(`cwe_id`, project-relative `file_path`, `line`, `identifier`,
`message`, and optional `redacted_value`). The loader converts those
records through Layer 2 feature extraction and Layer 3 scoring before
returning Layer 4 `TrainingExample` rows, so training data uses the same
pipeline shape as real scans.

The loader fails loud on malformed JSON, missing/incorrect field types,
invalid labels, invalid line numbers, control characters, absolute
finding paths, and `..` path traversal. Dataset finding paths are
treated as portable project-relative references; the loader does not
read or execute the referenced Java files.

Added `vibeguard/layer4_ml/evaluator.py` with
`evaluate_project_risk_model()`. It reports per-project predictions,
accuracy, macro-F1, and non-zero confusion-matrix cells. Metrics are
implemented locally and deterministically; this is evaluation of the ML
classifier, not SHAP explanation.

**Regression tests added:** `tests/test_layer4_ml.py` now covers valid
JSON labelled-dataset loading, invalid label rejection, non-portable
path rejection, empty evaluation-set rejection, and exact
accuracy/macro-F1/confusion output using a deterministic fake classifier.

**Tests run after the change:**

- Targeted Layer 4 tests: 11 passed.
- Targeted Layer 4 `mypy`: clean.
- Targeted Layer 4 `ruff`: clean.
- Targeted Layer 4 `black --check`: clean.
- Full `pytest -q`: 225 passed, clean exit code 0.
- `mypy .`: clean.
- `ruff check .`: clean.
- `black --check .`: clean.
- `git diff --check`: clean.

**Remaining limitations:** Layer 4 still cannot be frozen until an
actual labelled dataset of AI-generated/vibe-coded Java microservices
exists and the model persistence/loading contract is designed. Model
persistence was deliberately not added in this pass because sklearn
pickle/joblib artifacts execute code when loaded; VibeGuard needs an
explicit trusted-local-artifact policy before accepting model files.
XGBoost remains a planned comparison/extension after the labelled
dataset exists.

**Effect on thesis chapters:** Chapter 3 should describe the labelled
dataset schema and state that ML training consumes scored findings, not
raw source. Chapter 4 should document the JSON loader and evaluation
metrics. Chapter 5 can now report accuracy, macro-F1, and confusion
matrix once real labelled projects are collected.

## [2026-07-22] - Layer 1 config discovery narrowed to conventional application config only

**Scope:** Narrow reopen of frozen Layer 1 scanner/config discovery
only, triggered by a confirmed blocking whole-pipeline correctness
failure in the final Layers 1-3 QA pass. Layers 2-5 remained out of
scope except for regression verification through the existing CLI path.

**What the plan said:** Layer 1's config-side CWE-798 support was
implemented against `.properties`/`.yml`/`.yaml` files generally, with
the implicit assumption that relevant files in a Java microservice repo
would be application configuration.

**What we actually did / found:** A real end-to-end CLI scan against the
public `spring-petclinic-rest` repository showed that assumption was too
broad. The scanner treated every YAML/properties resource file as
application config, which let `cwe_798.py` flag OpenAPI schema metadata
inside `src/main/resources/openapi.yml` as six `critical` hardcoded
credential findings (`password.title`, `password.description`,
`password.type`, `password.maxLength`, `password.minLength`,
`password.example`). Those false positives survived Layer 2
normalization and Layer 3 scoring unchanged, so the runnable tool
reported the repository as failing due to bogus CWE-798 findings - a
blocking whole-pipeline correctness issue, not a cosmetic one.

Fixed this at the Layer 1 discovery boundary instead of trying to make
`cwe_798.py` semantically understand arbitrary YAML documents. Added
`is_conventional_config_path()` in `config_parser.py` and changed
`scanner.py`/`main.py` to feed only conventional application config
filenames into the config pipeline:

- `application*.properties|yml|yaml`
- `bootstrap*.properties|yml|yaml`
- `microprofile-config*.properties`

Arbitrary YAML/properties resources such as OpenAPI specs and i18n
bundles are now left out of config scanning entirely. Regression tests
lock this in directly: a scan tree containing `application.properties`,
`openapi.yml`, and `messages_de.properties` now only produces one
config parse target; an explicit single-file CLI call to `openapi.yml`
now returns the existing "nothing found" path rather than pretending it
is application config.

Re-ran the real repository scan after the fix. Result changed from
`14/15` config files parsed with `7` scored findings (1 real CWE-284
candidate plus 6 bogus CWE-798 findings from `openapi.yml`) to `5/5`
config files parsed with only the single remaining CWE-284 candidate.
This also removed the incidental `messages_de.properties`
ISO-8859-1 parse failure from the scan path because that file is an i18n
bundle, not application config.

**Why:** The bug was fundamentally about scan scope, not parser
robustness or later-layer scoring. Restricting config discovery to
conventional application-config names is the smallest change that makes
the Layers 1-3 pipeline defensible on real repositories without
teaching a simple heuristic secret rule to reason about every YAML or
properties dialect found under `src/main/resources/`.

**Tests run after the fix:**

- Targeted regression path: `tests/test_scanner.py`,
  `tests/test_main.py`, `tests/test_cwe_798.py`,
  `tests/test_layer2_extractor.py`, `tests/test_layer3_scorer.py`:
  `91 passed`.
- `mypy` on the touched Layer 1-3 surface: clean.
- `ruff check` on the touched Layer 1-3 surface: clean.
- `black --check` on the touched files: clean.
- `git diff --check`: clean.
- Real CLI scan of `spring-petclinic-rest`: false-positive CWE-798
  cluster removed; config parse coverage now `5/5`.
- Full `pytest -q` printed `227 passed in 44.54s`, but in this shell the
  process did not return promptly after the passing summary, so this
  pass should not yet be cited as a clean full-suite exit-code
  confirmation.

**Effect on thesis chapters:** Chapter 3 should describe config-side
CWE-798 input scope precisely as *conventional application
configuration*, not "all YAML/properties resources in a repository."
Chapter 4 should document the filename-based config-discovery rule and
why it exists. Chapter 5 should use the `spring-petclinic-rest`
reproduction as the concrete justification: without the narrower
boundary, realistic repositories can produce blocking false positives
from non-config resource files.

## [2026-07-22] - Layer 4 frozen: labelled dataset, trusted model contract, deterministic evaluation

**Scope:** Finish Layer 4 to a frozen state only. Layers 1-3 remained
frozen except for consuming their existing scan/feature/score outputs.
Layer 5 SHAP/reporting remained out of scope.

**What the plan said:** Layer 4 was implemented and testable but not
frozen. The missing pieces were explicit: a real labelled dataset of
AI-generated/vibe-coded Java microservices and a trusted model
persistence/loading contract that did not rely on unsafe arbitrary
pickle/joblib loading.

**What we actually did:** Completed both missing pieces and validated
them end-to-end.

1. **Controlled labelled dataset added.**
   Added a local controlled corpus of eight small AI-generated Spring-
   style Java microservice projects under
   `data/sample_apps/layer4_training/`, with two manually-labelled
   projects each for `low`, `medium`, `high`, and `critical` risk.
   Their findings come from actual Layers 1-3 scans, not invented ML
   rows. Added `data/labeled/layer4_projects.json` as the real Layer 4
   dataset, with each project record carrying:
   - `project_id`
   - `source_path` (repo-relative path back to the actual sample app)
   - `label`
   - the exact Layer 1-style findings used to derive Layer 2 features
     and Layer 3 scores

   `layer4_ml.dataset` was extended so `source_path` can resolve finding
   file paths back to the real repo sample-app location rather than an
   artificial dataset-relative placeholder path. Existing tests without
   `source_path` still work through the prior fallback behavior.

2. **Trusted model persistence/loading contract added.**
   Added `vibeguard/layer4_ml/contract.py`. Layer 4 now deliberately
   persists a JSON **contract**, not an executable serialized sklearn
   artifact. The contract stores:
   - schema version
   - model kind (`random_forest_retrain_v1`)
   - dataset path relative to the contract file
   - SHA-256 hash of the dataset file
   - random seed
   - expected feature schema
   - expected label set
   - training example count

   Loading the contract re-loads the labelled dataset, verifies the hash
   and shape, and deterministically re-trains the local Random Forest.
   This gives VibeGuard a repeatable model-loading contract without
   accepting arbitrary pickle/joblib artifacts that can execute code on
   load. Committed the real contract as
   `data/labeled/layer4_random_forest_contract.json`.

3. **Deterministic leave-one-project-out evaluation added.**
   Added `leave_one_out_evaluate_project_risk_model()` to
   `layer4_ml.evaluator`. This trains on `N-1` labelled projects and
   predicts the held-out project for every fold, so the reported metrics
   are not just train-set self-evaluation. On the committed controlled
   dataset, the deterministic evaluation result is:
   - accuracy: `1.0`
   - macro-F1: `1.0`
   - confusion matrix: perfectly diagonal (`2` correct predictions in
     each of the four classes)

4. **Pytest teardown drag fixed without reopening production Layer 1.**
   While validating Layer 4, the earlier full-suite `pytest -q`
   post-summary delay was traced to Layer 1 timeout-adversarial tests
   leaving daemon threads behind in the main pytest process. Fixed this
   narrowly by moving the two timeout tests into child Python processes
   while keeping the production timeout guard unchanged. Result: full
   suite now exits promptly again (`234 passed in 5.43s`, clean process
   exit).

**Tests/adversarial checks run:**

- `pytest tests/test_layer4_ml.py -q`: `18 passed`.
- Full `pytest -q`: `234 passed in 5.43s`, clean exit.
- `mypy vibeguard/layer4_ml tests/test_layer4_ml.py`: clean.
- `ruff check vibeguard/layer4_ml tests/test_layer4_ml.py`: clean.
- `black --check vibeguard/layer4_ml tests/test_layer4_ml.py`: clean.
- Full repo gates:
  - `mypy .`: clean.
  - `ruff check .`: clean.
  - `black --check .`: clean.
  - `git diff --check`: clean.
- Real Layer 4 evaluation pass on `data/labeled/layer4_projects.json`:
  accuracy `1.0`, macro-F1 `1.0`, diagonal confusion matrix.
- Trusted contract generation/load round-trip verified both in tests and
  against the committed real dataset/contract pair.

**Remaining limitations:** This is now a frozen, thesis-defensible local
baseline Layer 4, not the end of the ML story. The dataset is small and
controlled by design, so the metrics are appropriate for validating the
Layer 4 workflow and contract, not for claiming broad real-world model
generalization. XGBoost remains a future comparison, not part of the
frozen baseline. Layer 5 SHAP/reporting is still not started.

**Freeze decision:** Layer 4 is frozen. Do not reopen it unless:
- the thesis methodology explicitly changes the ML approach; or
- Layer 5 exposes a blocking contract issue in the frozen Layer 4 API.

**Effect on thesis chapters:** Chapter 3 should now describe the real
labelled dataset, its controlled AI-generated sample-app origin, and the
leave-one-out evaluation method. Chapter 4 should document the trusted
retraining-based model contract and the exact dataset/feature workflow.
Chapter 5 can now report actual Layer 4 metrics (`accuracy`, `macro-F1`,
confusion matrix) on a real labelled dataset rather than only describing
the ML layer abstractly. The next default implementation step is now
Layer 5 SHAP explainability and reporting.

## [2026-07-22] - Layer 5 SHAP explainability and console reporting implemented

**Scope:** Implement Layer 5 only: SHAP explainability over the frozen
Layer 4 Random Forest and final human-readable reporting through the
existing CLI. Layers 1-4 stayed frozen except for the minimal CLI/model
integration needed to consume their existing outputs.

**What the plan said:** Layer 5 had not started. The next approved work
item was SHAP explainability and reporting, with the thesis explicitly
requiring both SHAP feature attribution and Layer 1 file/line
traceability in the final output.

**What we actually did:** Added a real Layer 5 implementation under
`vibeguard/layer5_report/` and wired it into `main.py`.

1. **Project-level SHAP explanation added.**
   Added `layer5_report/explainer.py` with:
   - `SHAPContribution`
   - `ProjectRiskExplanation`
   - `explain_project_risk()`

   The implementation uses `shap.TreeExplainer` against the existing
   trusted Layer 4 Random Forest and explains the **predicted class
   probability**, not a generic feature-importance average. For the
   predicted label, Layer 5 now records:
   - the Layer 4 prediction and confidence;
   - the SHAP baseline probability for that label; and
   - a full feature-attribution vector sorted by absolute impact.

   Verified against the live model shape in this environment that SHAP
   returns a 3D tensor for the multi-class Random Forest
   (`samples x features x classes`), and explicitly collapse it to the
   predicted output class. The implementation also checks the output
   shape and fails closed if SHAP returns something unexpected.

2. **Final report object and renderer added.**
   Added `layer5_report/report.py` with:
   - `ProjectRiskReport`
   - `build_project_risk_report()`
   - `render_console_report()`

   The final CLI output now includes two new report sections:
   - Layer 4 project-risk prediction summary
   - Layer 5 SHAP attribution table for the predicted label

   This intentionally keeps Layer 1-3 traceability separate: the
   existing scored-findings table still carries file, line, CWE,
   severity, and identifier context, while Layer 5 explains why the
   project-level ML classifier reached its label from the aggregated
   feature vector.

3. **CLI upgraded from Layers 1-3 to the full five-layer path.**
   `main.py` now:
   - loads the trusted Layer 4 contract from
     `data/labeled/layer4_random_forest_contract.json` by default;
   - supports `--model-contract` to override that path; and
   - builds/renders the final Layer 5 report for every successful scan.

   The existing conservative exit-code contract was preserved: scored
   findings still fail the scan regardless of the ML label, so adding
   Layer 4/5 explainability does not silently relax scan behavior.

4. **Tests added for the new layer and CLI surface.**
   Added `tests/test_layer5_report.py` and extended `tests/test_main.py`
   so Layer 5 is exercised directly and through the real CLI path.

**Tests/adversarial checks run:**

- `pytest -q tests/test_layer5_report.py tests/test_main.py tests/test_layer4_ml.py`:
  `30 passed`.
- Full `pytest -q`: `239 passed in 6.71s`, clean exit.
- `ruff check main.py tests/test_main.py tests/test_layer5_report.py vibeguard/layer5_report`:
  clean.
- `black --check main.py tests/test_main.py tests/test_layer5_report.py vibeguard/layer5_report`:
  clean.
- `mypy main.py vibeguard/layer5_report`: clean.
- `git diff --check`: clean.
- Direct live-environment SHAP probe against the trusted model contract:
  confirmed the predicted-class baseline plus summed SHAP contributions
  reconstruct the model's predicted class probability.

**Remaining limitations:** Layer 5 currently renders a console report,
not an HTML/PDF export. SHAP explanations are intentionally at the
project-feature level; file/line traceability still comes from Layers
1-3 rather than from SHAP itself. The trusted contract still retrains
the local Random Forest on load by design; Layer 5 did not change that
security boundary.

**Freeze decision:** Implementation is complete and the full suite is
green, but because this session built the layer, recommend a fresh
session run adversarial QA against Layer 5 before treating it as frozen.
If that QA is clean, Layer 5 can be frozen and the next default work
item becomes thesis-evaluation/reporting polish rather than core
pipeline implementation.

**Effect on thesis chapters:** Chapter 3 can now describe the complete
five-layer pipeline as implemented, including the exact boundary between
Layer 1-3 traceability and Layer 5 SHAP attribution. Chapter 4 should
document the trusted-contract -> retrained Random Forest -> SHAP
explanation flow and the new CLI report surface. Chapter 5 can now show
concrete feature-level explanations for predicted project risk labels,
not just rule findings and aggregate ML metrics.

## [2026-07-22] - `evaluation/evaluate.py` added for thesis-evaluation reporting

**Scope:** Reporting/evaluation polish only. No Layer 1-5 detection,
scoring, ML feature, model, or SHAP logic changes were in scope; this
pass added a runnable evaluation harness around the already-frozen Layer
4 interfaces.

**What the plan said:** `AGENTS.md` Section 7 still listed
`evaluation/evaluate.py` as not started and described it as a later
thesis-evaluation convenience wrapper around the frozen workflow rather
than a new core-pipeline layer.

**What we actually did:** Added `evaluation/evaluate.py` as a real CLI
evaluation harness and covered it with tests.

1. **Trusted-contract-driven evaluation report added.**
   `evaluation/evaluate.py` now:
   - loads the trusted Layer 4 contract by default from
     `data/labeled/layer4_random_forest_contract.json`;
   - resolves the exact labelled dataset referenced by that contract;
   - evaluates the retrained trusted Random Forest in-sample against
     the committed dataset; and
   - runs deterministic leave-one-out evaluation using the same random
     seed recorded in the contract.

2. **Human-readable thesis summary added.**
   The harness renders four console tables:
   - dataset/contract overview;
   - in-sample vs. leave-one-out metrics;
   - per-project leave-one-out predictions; and
   - the non-zero leave-one-out confusion-matrix cells.

   This keeps the output directly usable for Chapter 4/5 write-up work
   without introducing any new serialized artifact format or changing
   the frozen Layer 4 API surface.

3. **Regression coverage added.**
   Added `tests/test_evaluation.py` covering:
   - the real committed contract/dataset pair;
   - CLI rendering of the evaluation summary; and
   - fail-closed handling for a contract whose dataset path is missing.

**Tests/adversarial checks run:**

- `pytest -q tests/test_evaluation.py tests/test_layer4_ml.py`:
  `21 passed`.
- Full `pytest -q`: `245 passed`, clean exit.
- `ruff check evaluation/evaluate.py tests/test_evaluation.py`: clean.
- `black --check evaluation/evaluate.py tests/test_evaluation.py`:
  clean.
- `mypy evaluation/evaluate.py tests/test_evaluation.py`: clean.
- Full repo gates:
  - `ruff check .`: clean.
  - `black --check .`: clean.
  - `mypy .`: clean.
  - `git diff --check`: clean.

**Remaining limitations:** This is a console-first evaluation harness,
not an export-to-CSV/JSON reporting pipeline. It reports the committed
controlled dataset's metrics and fold predictions, which is appropriate
for thesis evidence and reproducibility, but it does not yet generate a
standalone artifact bundle for appendix material.

**Freeze decision:** `evaluation/evaluate.py` is implemented and tested
as a reporting/evaluation convenience wrapper. It does not reopen the
frozen Layer 4 baseline or the pending Layer 5 freeze decision.

**Effect on thesis chapters:** Chapter 4 can now cite a concrete,
runnable evaluation command rather than describing Layer 4 metrics only
abstractly. Chapter 5 can lift the harness's exact accuracy, macro-F1,
per-project leave-one-out predictions, and confusion-matrix summary
directly into the evaluation/results narrative.

## [2026-07-22] - JSON export mode added to `evaluation/evaluate.py`

**Scope:** Reporting/evaluation polish only. This pass did not change
Layer 1-5 detection behavior, Layer 4 feature/model logic, or Layer 5
SHAP/report generation; it extended the evaluation harness with a
machine-readable export path.

**What the plan said:** The immediately previous evaluation-harness
entry explicitly called out a remaining limitation: console-first
output only, with no export-to-JSON/CSV artifact suitable for direct
reuse in thesis tables/appendices.

**What we actually did:** Added a JSON export mode to the existing
evaluation harness.

1. **Machine-readable export added.**
   `evaluation/evaluate.py` now supports `--json-out <path>`. When
   provided, the harness writes a JSON report instead of rendering the
   Rich console tables. The exported payload includes:
   - contract path;
   - dataset path;
   - random seed;
   - project/example count;
   - in-sample metrics plus per-project predictions/confusion cells; and
   - leave-one-out metrics plus per-project predictions/confusion cells.

2. **Fail-closed write handling added.**
   JSON serialization/writes now sit on the same CLI failure boundary as
   contract/dataset loading: an unwritable output path returns exit code
   `1` and reports a clear `Evaluation failed: ...` error rather than
   partially succeeding or crashing.

3. **Regression coverage added.**
   Extended `tests/test_evaluation.py` to cover:
   - JSON payload construction from the real committed contract/dataset;
   - end-to-end JSON file export; and
   - fail-closed behavior for an unwritable JSON output path.

**Tests/adversarial checks run:**

- `pytest -q tests/test_evaluation.py tests/test_layer4_ml.py`:
  `24 passed`.
- Full `pytest -q`: `248 passed`, clean exit.
- `ruff check evaluation/evaluate.py tests/test_evaluation.py`: clean.
- `black --check evaluation/evaluate.py tests/test_evaluation.py`:
  clean.
- `mypy evaluation/evaluate.py tests/test_evaluation.py`: clean.
- Full repo gates:
  - `ruff check .`: clean.
  - `black --check .`: clean.
  - `mypy .`: clean.
  - `git diff --check`: clean.

**Remaining limitations:** The export format is JSON only. It is enough
for thesis reproducibility and for lifting exact metrics/predictions
into tables, but there is still no narrower CSV export for
spreadsheet-first workflows and no bundling of scan-time Layer 5 report
artifacts with evaluation outputs.

**Freeze decision:** This is a tested reporting/evaluation polish step
on top of the existing harness. It does not reopen the frozen Layer 4
baseline or alter the pending Layer 5 freeze process.

**Effect on thesis chapters:** Chapter 4 can now point to both a
human-readable evaluation command and a reproducible machine-readable
artifact path. Chapter 5 appendix/table preparation can reuse exact JSON
metric/prediction/confusion data without manual console transcription.

## [2026-07-22] - CSV export mode added for leave-one-out evaluation outputs

**Scope:** Reporting/evaluation polish only. This pass stayed inside
`evaluation/evaluate.py` and its tests; it did not alter the frozen
Layer 4 model/evaluator logic or the Layer 5 reporting pipeline.

**What the plan said:** The previous JSON-export log entry explicitly
left one spreadsheet-oriented limitation open: there was still no
narrower CSV export for Chapter 5 tables built from the leave-one-out
predictions/confusion summary.

**What we actually did:** Added a CSV export mode to the evaluation
harness.

1. **CSV directory export added.**
   `evaluation/evaluate.py` now supports `--csv-dir <directory>`. When
   provided, the harness writes two files:
   - `leave_one_out_predictions.csv`
   - `leave_one_out_confusion.csv`

   This keeps the CSV scope intentionally narrow and spreadsheet-ready:
   only the leave-one-out prediction rows and confusion summary are
   exported, without duplicating the whole JSON payload structure.

2. **Export-mode ambiguity removed.**
   `--json-out` and `--csv-dir` are now mutually exclusive CLI options,
   so the operator cannot accidentally request two machine-readable
   output modes at once and get branch-order-dependent behavior.

3. **Fail-closed CSV write handling added.**
   CSV directory/file creation now sits on the same `Evaluation failed:
   ...` boundary as the existing contract/dataset/JSON export paths. An
   invalid CSV output target returns exit code `1` with a clear error
   instead of partially succeeding or crashing.

4. **Regression coverage added.**
   Extended `tests/test_evaluation.py` to cover:
   - end-to-end CSV export into a fresh directory;
   - expected headers/row presence for both CSV files; and
   - fail-closed behavior when `--csv-dir` points at a file instead of a
     writable directory.

**Tests/adversarial checks run:**

- `pytest -q tests/test_evaluation.py tests/test_layer4_ml.py`:
  `26 passed`.
- Full `pytest -q`: `250 passed`, clean exit.
- `ruff check evaluation/evaluate.py tests/test_evaluation.py`: clean.
- `black --check evaluation/evaluate.py tests/test_evaluation.py`:
  clean.
- `mypy evaluation/evaluate.py tests/test_evaluation.py`: clean.
- Full repo gates:
  - `ruff check .`: clean.
  - `black --check .`: clean.
  - `mypy .`: clean.
  - `git diff --check`: clean.

**Remaining limitations:** Evaluation export is now split across JSON
and two CSV files, but there is still no single bundled artifact
containing both evaluation outputs and scan-time Layer 5 report outputs
for one appendix-ready run.

**Freeze decision:** This is another tested reporting/evaluation polish
step on top of the existing harness. It does not reopen the frozen
Layer 4 baseline or alter the pending Layer 5 freeze process.

**Effect on thesis chapters:** Chapter 5 table preparation can now move
directly from the committed evaluation harness into spreadsheet tooling
without manually reshaping JSON or transcribing console output.

## [2026-07-22] - Bundled evaluation artifact export added

**Scope:** Reporting/evaluation polish only. This pass stayed inside
`evaluation/evaluate.py` and `tests/test_evaluation.py`; it did not
change Layer 1-5 scanning, scoring, ML behavior, or Layer 5 rendering.

**What the plan said:** The previous CSV-export pass explicitly left one
appendix/workflow limitation open: there was still no single command
that emitted JSON plus CSV evaluation artifacts together as one
appendix-ready bundle.

**What we actually did:** Added a bundled artifact export mode to the
evaluation harness.

1. **Timestamped bundle export added.**
   `evaluation/evaluate.py` now supports `--bundle-dir <parent>`. When
   used, the harness creates a timestamped directory under that parent
   and writes:
   - `evaluation.json`
   - `leave_one_out_predictions.csv`
   - `leave_one_out_confusion.csv`

   This gives one-command, one-directory evaluation artifact capture
   without changing the underlying JSON or CSV payload formats.

2. **Export-mode contract extended cleanly.**
   `--bundle-dir` was added as a third mutually-exclusive export mode
   alongside `--json-out` and `--csv-dir`, so the CLI still has one
   unambiguous output behavior per invocation.

3. **Fail-closed bundle creation added.**
   Invalid/uncreatable bundle parents now fail closed with
   `Evaluation failed: could not create evaluation artifact bundle: ...`
   rather than partially succeeding or relying on branch-order quirks.

4. **Regression coverage added.**
   Extended `tests/test_evaluation.py` to cover:
   - deterministic bundled export creation via a monkeypatched bundle
     name;
   - presence of all three emitted artifacts; and
   - fail-closed behavior when `--bundle-dir` points at a file instead
     of a writable parent directory.

**Tests/adversarial checks run:**

- `pytest -q tests/test_evaluation.py tests/test_layer4_ml.py`:
  `28 passed`.
- Full `pytest -q`: `252 passed`, clean exit.
- `ruff check evaluation/evaluate.py tests/test_evaluation.py`: clean.
- `black --check evaluation/evaluate.py tests/test_evaluation.py`:
  clean.
- `mypy evaluation/evaluate.py tests/test_evaluation.py`: clean.
- Full repo gates:
  - `ruff check .`: clean.
  - `black --check .`: clean.
  - `mypy .`: clean.
  - `git diff --check`: clean.

**Remaining limitations:** The evaluation harness now emits either
console output, JSON, CSV, or a bundled evaluation artifact directory,
but it still does not package scan-time Layer 5 report output and
evaluation output together from a single top-level command.

**Freeze decision:** This is another tested reporting/evaluation polish
step layered on top of the existing harness. It does not reopen the
frozen Layer 4 baseline or alter the pending Layer 5 freeze process.

**Effect on thesis chapters:** Chapter 5 appendix preparation can now
cite a single reproducible command that emits the full evaluation
artifact set used to support metrics/prediction tables.

## [2026-07-22] - Bundle manifest added for self-describing evaluation artifacts

**Scope:** Reporting/evaluation polish only. This pass stayed inside
the bundled export path of `evaluation/evaluate.py` and its tests; it
did not alter Layer 1-5 analysis behavior or the underlying evaluation
metrics logic.

**What the plan said:** The bundled export pass still left one
portability gap: once the evaluation artifact directory was moved
outside the repository, nothing inside it recorded which mode produced
it, which contract/dataset it came from, or which files it was expected
to contain.

**What we actually did:** Added a self-describing manifest file to the
bundled evaluation export directory.

1. **Bundle manifest added.**
   Every `--bundle-dir` export now writes `bundle_manifest.json`
   alongside:
   - `evaluation.json`
   - `leave_one_out_predictions.csv`
   - `leave_one_out_confusion.csv`

   The manifest records:
   - `export_mode` (`bundle`);
   - `contract_path`;
   - `dataset_path`;
   - `random_state`;
   - `example_count`;
   - `bundle_directory`; and
   - the emitted filenames list.

2. **Self-description stays local to the bundle.**
   The manifest deliberately records only the concrete provenance needed
   to interpret the copied artifact set; it does not introduce a new
   external registry or alter the existing JSON/CSV payload formats.

3. **Regression coverage added.**
   Extended `tests/test_evaluation.py` so the deterministic bundled
   export test now asserts the manifest exists and contains the expected
   mode, provenance, directory name, and emitted-file list.

**Tests/adversarial checks run:**

- `pytest -q tests/test_evaluation.py tests/test_layer4_ml.py`:
  `28 passed`.
- Full `pytest -q`: `252 passed`, clean exit.
- `ruff check evaluation/evaluate.py tests/test_evaluation.py`: clean.
- `black --check evaluation/evaluate.py tests/test_evaluation.py`:
  clean.
- `mypy evaluation/evaluate.py tests/test_evaluation.py`: clean.
- Full repo gates:
  - `ruff check .`: clean.
  - `black --check .`: clean.
  - `mypy .`: clean.
  - `git diff --check`: clean.

**Remaining limitations:** The evaluation bundle is now self-describing,
but scan-time Layer 5 output and evaluation output still come from
separate top-level commands rather than one combined thesis-run
orchestrator.

**Freeze decision:** This is another tested reporting/evaluation polish
step on top of the existing harness. It does not reopen the frozen
Layer 4 baseline or alter the pending Layer 5 freeze process.

**Effect on thesis chapters:** Chapter 5 appendix artifacts can now be
moved or archived outside the repo without losing the immediate context
needed to explain what generated them and what files the bundle should
contain.

## [2026-07-22] - Top-level thesis-run wrapper and bundle README added

**Scope:** Reporting/evaluation polish only. This pass stayed within the
evaluation artifact workflow: a thin wrapper entrypoint plus a README
inside bundled exports. It did not change the frozen Layer 4 evaluator
or any Layer 5 scan/report behavior.

**What the plan said:** The previous bundle-manifest pass still left one
workflow gap: evaluation output and scan-time output remained separate
top-level commands, and the bundle itself lacked a plain-language README
for a reviewer opening the directory directly.

**What we actually did:** Added both a thin wrapper entrypoint and a
bundle README.

1. **Top-level thesis-run wrapper added.**
   Added `evaluation/thesis_run.py` as a small CLI entrypoint that:
   - loads the trusted Layer 4 contract;
   - builds the evaluation report; and
   - writes the default timestamped bundle to a chosen parent
     directory.

   The wrapper prints the resulting bundle path on success and fails
   closed with `Thesis run failed: ...` on error.

2. **Bundle README added.**
   Every bundled export now includes `README.txt` describing:
   - what the directory is;
   - which contract/dataset generated it; and
   - how to interpret `evaluation.json`,
     `leave_one_out_predictions.csv`,
     `leave_one_out_confusion.csv`, and `bundle_manifest.json`.

   This keeps the copied artifact set usable even when opened outside
   the repository or without immediately reading source code.

3. **Manifest/file list updated.**
   `bundle_manifest.json` now includes `README.txt` in the emitted-file
   list so the bundle stays internally consistent about its expected
   contents.

4. **Regression coverage added.**
   Added `tests/test_thesis_run.py` for:
   - end-to-end wrapper execution with deterministic bundle naming; and
   - fail-closed behavior for an invalid bundle parent.

   Extended `tests/test_evaluation.py` so the bundled export test now
   asserts the README exists and the manifest includes it.

**Tests/adversarial checks run:**

- `pytest -q tests/test_evaluation.py tests/test_thesis_run.py tests/test_layer4_ml.py`:
  `30 passed`.
- Full `pytest -q`: `254 passed`, clean exit.
- `ruff check evaluation/evaluate.py evaluation/thesis_run.py tests/test_evaluation.py tests/test_thesis_run.py`:
  clean.
- `black --check evaluation/evaluate.py evaluation/thesis_run.py tests/test_evaluation.py tests/test_thesis_run.py`:
  clean.
- `mypy evaluation/evaluate.py evaluation/thesis_run.py tests/test_evaluation.py tests/test_thesis_run.py`:
  clean.
- Full repo gates:
  - `ruff check .`: clean.
  - `black --check .`: clean.
  - `mypy .`: clean.
  - `git diff --check`: clean.

**Remaining limitations:** There is still no single orchestrator that
combines scan-time Layer 5 project output with the evaluation bundle in
one command; the wrapper currently packages evaluation artifacts only.

**Freeze decision:** This is another tested reporting/evaluation polish
step layered on top of the existing harness. It does not reopen the
frozen Layer 4 baseline or alter the pending Layer 5 freeze process.

**Effect on thesis chapters:** Chapter 5 appendix preparation now has a
single evaluation-focused command that emits a reviewer-readable bundle
without requiring the reviewer to infer artifact meaning from filenames
alone.

## [2026-07-23] - Bundle manifest now records the exact module invocation

**Scope:** Reporting/evaluation polish only. This pass stayed within the
evaluation bundle manifest path and the thesis wrapper entrypoint; it
did not change Layer 1-5 analysis behavior, Layer 4 metrics, or Layer 5
report rendering.

**What the plan said:** The previous wrapper/bundle pass still left one
reproducibility gap: the bundle manifest recorded provenance inputs, but
not the literal module entrypoint and arguments that produced the
artifact set.

**What we actually did:** Added invocation capture to bundled
evaluation manifests.

1. **Invocation metadata added to bundle manifests.**
   `bundle_manifest.json` now records:
   - `invocation_argv`: the module-style command vector used to produce
     the bundle; and
   - `invocation_command`: the same invocation flattened into a readable
     single-line command string.

   This applies both to direct `evaluation.evaluate --bundle-dir ...`
   use and to the higher-level `evaluation.thesis_run` wrapper.

2. **Shared bundle writer now accepts invocation context.**
   `evaluation/evaluate.py`'s bundle writer now accepts optional
   invocation metadata, while both `evaluation.evaluate` and
   `evaluation.thesis_run` pass their own module entrypoint and args
   through a shared helper. This keeps the manifest source single-sited
   instead of reimplemented in each caller.

3. **Regression coverage added.**
   Extended:
   - `tests/test_evaluation.py` to assert the direct bundle path records
     `evaluation.evaluate` plus its exact arguments; and
   - `tests/test_thesis_run.py` to assert the wrapper path records
     `evaluation.thesis_run` plus its exact arguments.

**Tests/adversarial checks run:**

- `pytest -q tests/test_evaluation.py tests/test_thesis_run.py tests/test_layer4_ml.py`:
  `30 passed`.
- Full `pytest -q`: `254 passed`, clean exit.
- `ruff check evaluation/evaluate.py evaluation/thesis_run.py tests/test_evaluation.py tests/test_thesis_run.py`:
  clean.
- `black --check evaluation/evaluate.py evaluation/thesis_run.py tests/test_evaluation.py tests/test_thesis_run.py`:
  clean.
- `mypy evaluation/evaluate.py evaluation/thesis_run.py tests/test_evaluation.py tests/test_thesis_run.py`:
  clean.
- Full repo gates:
  - `ruff check .`: clean.
  - `black --check .`: clean.
  - `mypy .`: clean.
  - `git diff --check`: clean.

**Remaining limitations:** The evaluation bundle now records the exact
evaluation command used, but scan-time Layer 5 output and evaluation
output still come from separate top-level commands rather than one
combined thesis-run orchestrator.

**Freeze decision:** This is another tested reporting/evaluation polish
step layered on top of the existing harness. It does not reopen the
frozen Layer 4 baseline or alter the pending Layer 5 freeze process.

**Effect on thesis chapters:** Chapter 5 reproducibility language can
now point to bundle-local evidence of the exact entrypoint and arguments
used to generate each archived evaluation artifact set.

## [2026-07-23] - Combined thesis orchestrator added for scan and evaluation artifacts

**Scope:** Reporting/evaluation polish only. This pass added a thin
top-level orchestrator around the existing scan CLI and thesis
evaluation wrapper. It did not change Layer 1-5 detection/scoring/ML
logic or the semantics of the existing evaluation bundle contents.

**What the plan said:** The previous bundle-manifest pass still left one
top-level workflow gap: scan-time Layer 5 output and evaluation
artifacts required separate commands, even though both are part of the
same thesis evidence story.

**What we actually did:** Added a combined thesis orchestrator that
captures both artifact roots together.

1. **Top-level combined wrapper added.**
   Added `evaluation/thesis_orchestrator.py` as a small CLI entrypoint
   that:
   - runs the existing `main.py` scan CLI against a chosen file or
     directory;
   - captures its stdout/stderr into a dedicated scan artifact
     directory;
   - runs the existing `evaluation.thesis_run` wrapper to build the
     evaluation bundle; and
   - prints the resulting combined run directory path on success.

2. **Two artifact roots now tied together.**
   Each combined run creates:
   - `scan/` containing `scan_stdout.txt`, `scan_stderr.txt`, and
     `scan_manifest.json`; and
   - `evaluation/<timestamped-bundle>/` containing the existing thesis
     evaluation bundle.

   A top-level `run_manifest.json` now records both artifact roots in
   one place, alongside the orchestrator invocation, the scan
   invocation, the evaluation-wrapper invocation, and the scan exit
   code.

3. **Artifact-generation success separated from scan findings.**
   The orchestrator records the scan exit code but still succeeds when a
   real scan produces findings (the normal VibeGuard `exit_code == 1`
   path), as long as both artifact sets are written successfully. This
   is deliberate: the thesis-run wrapper's job is evidence capture, not
   reinterpreting the scan CLI's conservative findings policy.

4. **Regression coverage added.**
   Added `tests/test_thesis_orchestrator.py` covering:
   - a clean scan plus evaluation bundle in one deterministic run;
   - a vulnerable scan whose non-zero scan exit code is recorded while
     the orchestrator still succeeds; and
   - fail-closed behavior for an invalid output root.

**Tests/adversarial checks run:**

- `pytest -q tests/test_evaluation.py tests/test_thesis_run.py tests/test_thesis_orchestrator.py tests/test_layer4_ml.py tests/test_main.py`:
  `44 passed`.
- Full `pytest -q`: `257 passed`, clean exit.
- `ruff check evaluation/evaluate.py evaluation/thesis_run.py evaluation/thesis_orchestrator.py tests/test_evaluation.py tests/test_thesis_run.py tests/test_thesis_orchestrator.py`:
  clean.
- `black --check evaluation/evaluate.py evaluation/thesis_run.py evaluation/thesis_orchestrator.py tests/test_evaluation.py tests/test_thesis_run.py tests/test_thesis_orchestrator.py`:
  clean.
- `mypy evaluation/evaluate.py evaluation/thesis_run.py evaluation/thesis_orchestrator.py tests/test_evaluation.py tests/test_thesis_run.py tests/test_thesis_orchestrator.py`:
  clean.
- Full repo gates:
  - `ruff check .`: clean.
  - `black --check .`: clean.
  - `mypy .`: clean.
  - `git diff --check`: clean.

**Remaining limitations:** The combined orchestrator now ties together
scan-time and evaluation artifact roots, but it still captures scan
output as console text rather than as a structured machine-readable scan
report artifact.

**Freeze decision:** This is another tested reporting/evaluation polish
step on top of the existing harnesses. It does not reopen the frozen
Layer 4 baseline or alter the pending Layer 5 freeze process.

**Effect on thesis chapters:** Chapter 5 can now point to a single
top-level reproducible command that captures both the project-specific
scan evidence and the evaluation bundle used to discuss the ML layer's
performance.

## [2026-07-23] - Structured scan artifact added to the combined thesis run

**Scope:** Reporting/evaluation polish only. This pass stayed inside the
combined thesis orchestrator and its tests; it did not change `main.py`'s
public CLI contract or the frozen Layer 1-5 detection/scoring/ML logic.

**What the plan said:** The combined thesis orchestrator already tied
scan-time and evaluation artifact roots together, but the scan side
still relied on captured console text (`scan_stdout.txt`) as its only
substantive artifact.

**What we actually did:** Added a machine-readable scan artifact beside
the captured scan console logs.

1. **Structured scan report added.**
   The combined thesis run now writes `scan/scan_report.json` alongside:
   - `scan_stdout.txt`
   - `scan_stderr.txt`
   - `scan_manifest.json`

   The JSON report records:
   - scan path/root;
   - parse outcomes for Java/config/pom inputs;
   - rejected paths;
   - raw Layer 1 findings;
   - Layer 3 scored findings; and
   - the final Layer 4/5 project-risk summary when the scan reaches the
     report stage.

2. **Console capture now mirrors a single internal execution state.**
   Instead of invoking `main.py` once for console capture and inferring a
   separate structured artifact afterward, the orchestrator now executes
   the same underlying scan pipeline once, renders the existing console
   output from that in-memory result, and serializes the matching JSON
   artifact from the same data. This avoids scan/output drift between the
   text and machine-readable artifacts.

3. **Scan-side failure semantics preserved.**
   The orchestrator still treats a real vulnerability hit (`scan_exit_code
   == 1`) as a successful evidence-capture run, while the structured scan
   artifact records that non-zero exit code explicitly. Early scan-side
   failure paths like "nothing found", scoring failure, or ML/reporting
   failure are also captured through `error_message` in the scan report.

4. **Regression coverage added.**
   Extended `tests/test_thesis_orchestrator.py` so the combined-run tests
   now assert:
   - `scan_report.json` exists;
   - clean runs record zero findings and a `low` predicted label; and
   - vulnerable runs record non-zero findings/scores and a `critical`
     project-risk label while still producing the combined artifact set.

**Tests/adversarial checks run:**

- `pytest -q tests/test_evaluation.py tests/test_thesis_run.py tests/test_thesis_orchestrator.py tests/test_layer4_ml.py tests/test_main.py`:
  `44 passed`.
- Full `pytest -q`: `257 passed`, clean exit.
- `ruff check evaluation/evaluate.py evaluation/thesis_run.py evaluation/thesis_orchestrator.py tests/test_evaluation.py tests/test_thesis_run.py tests/test_thesis_orchestrator.py`:
  clean.
- `black --check evaluation/evaluate.py evaluation/thesis_run.py evaluation/thesis_orchestrator.py tests/test_evaluation.py tests/test_thesis_run.py tests/test_thesis_orchestrator.py`:
  clean.
- `mypy evaluation/evaluate.py evaluation/thesis_run.py evaluation/thesis_orchestrator.py tests/test_evaluation.py tests/test_thesis_run.py tests/test_thesis_orchestrator.py`:
  clean.
- Full repo gates:
  - `ruff check .`: clean.
  - `black --check .`: clean.
  - `mypy .`: clean.
  - `git diff --check`: clean.

**Remaining limitations:** The combined thesis run now has a structured
scan artifact and a structured evaluation bundle, but there is still no
single normalized schema spanning both halves for downstream analysis
outside the repo.

**Freeze decision:** This is another tested reporting/evaluation polish
step layered on top of the existing harnesses. It does not reopen the
frozen Layer 4 baseline or alter the pending Layer 5 freeze process.

**Effect on thesis chapters:** Chapter 5 can now point to both a
human-readable scan transcript and a structured scan-side artifact within
the same combined run, which makes appendix evidence and reproducibility
material stronger and easier to audit.

## [2026-07-23] - Normalized top-level JSON summary added to combined thesis runs

**Scope:** Reporting/evaluation polish only. This pass stayed inside the
combined thesis orchestrator and its tests; it did not alter Layer 1-5
analysis behavior, evaluation metrics, or any existing scan/evaluation
artifact payload formats.

**What the plan said:** The previous combined thesis run pass produced
two adjacent structured roots - `scan/scan_report.json` and the
evaluation bundle's `evaluation.json`/`bundle_manifest.json` - but still
left downstream consumers to stitch them together themselves.

**What we actually did:** Added a normalized top-level summary file to
the combined thesis run directory.

1. **Normalized summary added.**
   Each combined run now writes `thesis_summary.json` at the run root.
   It references the existing structured scan artifact and evaluation
   bundle outputs while also exposing a compact, downstream-friendly
   summary of the key result fields:
   - scan artifact/report path;
   - scan exit code;
   - finding/scored-finding counts;
   - scan-side project-risk label/confidence when available;
   - evaluation bundle directory/report/manifest paths;
   - evaluation example count;
   - in-sample accuracy; and
   - leave-one-out accuracy/macro-F1.

2. **No new parallel payloads introduced.**
   The summary is deliberately a lightweight normalization layer over
   the existing `scan_report.json`, `evaluation.json`, and
   `bundle_manifest.json` files. It does not replace them or fork their
   schemas; it reads them and republishes only the cross-cutting fields
   most useful for downstream thesis/result aggregation.

3. **Fail-closed summary generation added.**
   The orchestrator now validates that the referenced scan/evaluation
   JSON files exist and contain the expected fields before writing the
   summary. If they do not, the combined run fails loudly rather than
   emitting a partial or misleading top-level artifact.

4. **Regression coverage added.**
   Extended `tests/test_thesis_orchestrator.py` so the clean and
   vulnerable combined-run tests now assert:
   - `thesis_summary.json` exists;
   - it points at the scan-side `scan_report.json`;
   - it points at the evaluation bundle directory; and
   - it carries the expected normalized scan/evaluation values.

**Tests/adversarial checks run:**

- `pytest -q tests/test_evaluation.py tests/test_thesis_run.py tests/test_thesis_orchestrator.py tests/test_layer4_ml.py tests/test_main.py`:
  `44 passed`.
- Full `pytest -q`: `257 passed`, clean exit.
- `ruff check evaluation/evaluate.py evaluation/thesis_run.py evaluation/thesis_orchestrator.py tests/test_evaluation.py tests/test_thesis_run.py tests/test_thesis_orchestrator.py`:
  clean.
- `black --check evaluation/evaluate.py evaluation/thesis_run.py evaluation/thesis_orchestrator.py tests/test_evaluation.py tests/test_thesis_run.py tests/test_thesis_orchestrator.py`:
  clean.
- `mypy evaluation/evaluate.py evaluation/thesis_run.py evaluation/thesis_orchestrator.py tests/test_evaluation.py tests/test_thesis_run.py tests/test_thesis_orchestrator.py`:
  clean.
- Full repo gates:
  - `ruff check .`: clean.
  - `black --check .`: clean.
  - `mypy .`: clean.
  - `git diff --check`: clean.

**Remaining limitations:** The combined thesis run now has a normalized
top-level JSON summary, but scan-side and evaluation-side detailed
payloads still use separate domain-specific schemas underneath that
summary rather than a single universal artifact schema end-to-end.

**Freeze decision:** This is another tested reporting/evaluation polish
step layered on top of the existing harnesses. It does not reopen the
frozen Layer 4 baseline or alter the pending Layer 5 freeze process.

**Effect on thesis chapters:** Chapter 5 and any downstream aggregation
scripts can now consume one compact, normalized top-level JSON file for
the combined thesis run instead of manually joining separate scan and
evaluation artifact roots first.

## [2026-07-23] - `thesis_summary.json` made portable with relative-path fields

**Scope:** Reporting/evaluation polish only. This pass stayed within the
combined thesis orchestrator's normalized top-level summary; it did not
change scan/evaluation artifact generation semantics or any frozen
Layer 1-5 behavior.

**What the plan said:** The new `thesis_summary.json` already gave a
compact normalized view over the scan-side and evaluation-side artifact
roots, but it still relied entirely on absolute paths, which weakens
portability when a combined run directory is moved or archived
elsewhere.

**What we actually did:** Added explicit relative-path fields and bumped
the summary schema version.

1. **Relative-path fields added.**
   `thesis_summary.json` now includes relative paths from the combined
   run root for:
   - `scan.artifact_dir_relative`
   - `scan.report_file_relative`
   - `evaluation.bundle_dir_relative`
   - `evaluation.report_file_relative`
   - `evaluation.manifest_file_relative`

   The prior absolute-path fields remain in place for convenience, but
   the summary no longer depends on them for bundle portability.

2. **Summary schema version bumped.**
   `schema_version` was increased from `1` to `2` because the top-level
   summary payload shape changed in a backward-visible way. This makes
   the portability upgrade explicit to any downstream reader.

3. **Regression coverage added.**
   Extended `tests/test_thesis_orchestrator.py` so the clean and
   vulnerable combined-run tests now assert the new schema version and
   the expected relative-path fields inside `thesis_summary.json`.

**Tests/adversarial checks run:**

- `pytest -q tests/test_evaluation.py tests/test_thesis_run.py tests/test_thesis_orchestrator.py tests/test_layer4_ml.py tests/test_main.py`:
  `44 passed`.
- Full `pytest -q`: `257 passed`, clean exit.
- `ruff check evaluation/evaluate.py evaluation/thesis_run.py evaluation/thesis_orchestrator.py tests/test_evaluation.py tests/test_thesis_run.py tests/test_thesis_orchestrator.py`:
  clean.
- `black --check evaluation/evaluate.py evaluation/thesis_run.py evaluation/thesis_orchestrator.py tests/test_evaluation.py tests/test_thesis_run.py tests/test_thesis_orchestrator.py`:
  clean.
- `mypy evaluation/evaluate.py evaluation/thesis_run.py evaluation/thesis_orchestrator.py tests/test_evaluation.py tests/test_thesis_run.py tests/test_thesis_orchestrator.py`:
  clean.
- Full repo gates:
  - `ruff check .`: clean.
  - `black --check .`: clean.
  - `mypy .`: clean.
  - `git diff --check`: clean.

**Remaining limitations:** The combined run summary is now portable at
the path-reference level, but the underlying scan/evaluation detailed
artifacts still use their own separate nested schemas rather than one
unified end-to-end schema.

## [2026-07-23] - `thesis_summary.json` now ships with an explicit JSON Schema

**Scope:** Reporting/evaluation polish only. This pass stayed within the
combined thesis orchestrator's top-level artifact contract; it did not
change scan semantics, evaluation semantics, or any frozen Layer 1-5
logic.

**What the plan said:** The combined run already emitted a normalized
`thesis_summary.json`, and the previous portability pass made its path
references archive-friendly, but downstream consumers still had to infer
the summary contract from implementation code and tests.

**What we actually did:** Added a machine-readable schema artifact for
the top-level summary and locked it in with regression coverage.

1. **Schema artifact emitted alongside each combined run.**
   The orchestrator now writes `thesis_summary.schema.json` next to
   `thesis_summary.json` in the combined run root, so each exported run
   carries its own explicit schema contract.

2. **Schema version 2 contract documented explicitly.**
   The emitted schema uses JSON Schema Draft 2020-12 and encodes the
   current top-level contract directly, including:
   - `schema_version: 2`
   - `export_mode: "combined_thesis_summary"`
   - required `scan` and `evaluation` sections
   - nullable-vs-object handling for `scan.project_risk`
   - required evaluation provenance field
     `bundle_invocation_command`

3. **Regression coverage added.**
   `tests/test_thesis_orchestrator.py` now asserts that the schema file
   is emitted and that key schema constraints match the runtime summary
   contract for both clean and vulnerable scan cases.

**Tests/adversarial checks run:**

- `pytest -q tests/test_thesis_orchestrator.py`: `3 passed`.
- Full `pytest -q`: `257 passed`, clean exit.
- `ruff check .`: clean.
- `black --check .`: clean.
- `mypy .`: clean.
- `git diff --check`: clean.

**Remaining limitations:** This adds an explicit contract for the
normalized top-level summary only. It does not yet introduce standalone
schema documents for `scan_report.json`, `evaluation.json`, or
`bundle_manifest.json`.

**Effect on thesis chapters:** Chapter 5 and any external analysis or
archival scripts can now reference a concrete machine-readable contract
for the combined thesis summary instead of reverse-engineering the
payload shape from code or tests.

**Freeze decision:** This is another tested reporting/evaluation polish
step layered on top of the existing harnesses. It does not reopen the
frozen Layer 4 baseline or alter the pending Layer 5 freeze process.

**Effect on thesis chapters:** Archived or shared combined thesis runs
can now be relocated without breaking the top-level summary's ability to
point to the scan-side and evaluation-side artifacts that support the
reported results.

## [2026-07-23] - `run_manifest.json` made portable with relative artifact roots

**Scope:** Reporting/evaluation polish only. This pass stayed within the
combined thesis orchestrator's top-level run manifest contract; it did
not change scan behavior, evaluation behavior, or any frozen Layer 1-5
logic.

**What the plan said:** The top-level summary and summary schema were
already portable enough to survive run-directory relocation, but
`run_manifest.json` still exposed only absolute `scan_artifact_dir` and
`evaluation_bundle_dir` paths for the main nested artifact roots.

**What we actually did:** Added relative-path companions for the two
main nested artifact directories and locked them with regression tests.

1. **Portable run-manifest artifact roots added.**
   `run_manifest.json` now includes:
   - `scan_artifact_dir_relative`
   - `evaluation_bundle_dir_relative`

   The existing absolute-path fields remain for convenience, but the
   manifest no longer depends on them when the combined run directory is
   moved or archived elsewhere.

2. **Regression coverage added.**
   `tests/test_thesis_orchestrator.py` now asserts the new relative
   artifact-root fields for both the clean and vulnerable combined-run
   cases.

**Tests/adversarial checks run:**

- `pytest -q tests/test_thesis_orchestrator.py`: `3 passed`.
- Full `pytest -q`: `257 passed`, clean exit.
- `ruff check .`: clean.
- `black --check .`: clean.
- `mypy .`: clean.
- `git diff --check`: clean.

**Remaining limitations:** The combined run's top-level manifests are
now portable at the directory-reference level, but the detailed nested
artifact payloads still keep their own separate schemas and contracts.

**Effect on thesis chapters:** Chapter 5 artifact bundles and any
external review scripts can now resolve the run's scan/evaluation roots
without depending on machine-specific absolute directories.

## [2026-07-23] - `run_manifest.json` now ships with an explicit JSON Schema

**Scope:** Reporting/evaluation polish only. This pass stayed within the
combined thesis orchestrator's top-level manifest contract; it did not
change scan semantics, evaluation semantics, or any frozen Layer 1-5
logic.

**What the plan said:** The combined run manifest was portable after the
relative-path pass, but unlike `thesis_summary.json` it still had no
standalone machine-readable schema describing its required fields.

**What we actually did:** Added a schema sidecar for the run manifest
and regression coverage that locks the contract down.

1. **Manifest schema artifact emitted.**
   The orchestrator now writes `run_manifest.schema.json` beside
   `run_manifest.json` at the combined run root.

2. **Run-manifest contract documented explicitly.**
   The emitted schema uses JSON Schema Draft 2020-12 and encodes the
   current manifest contract directly, including:
   - `export_mode: "combined_thesis_run"`
   - required summary artifact references
   - required portable scan/evaluation artifact-root references
   - required invocation provenance fields for orchestrator, scan, and
     evaluation sub-steps

3. **Regression coverage added.**
   `tests/test_thesis_orchestrator.py` now asserts that the new schema
   file is emitted and that key schema constraints match the runtime
   manifest contract for both clean and vulnerable combined-run cases.

**Tests/adversarial checks run:**

- `pytest -q tests/test_thesis_orchestrator.py`: `3 passed`.
- Full `pytest -q`: `257 passed`, clean exit.
- `ruff check .`: clean.
- `black --check .`: clean.
- `mypy .`: clean.
- `git diff --check`: clean.

**Remaining limitations:** The top-level combined-run artifacts now have
explicit schemas, but the nested `scan_report.json`,
`scan_manifest.json`, `evaluation.json`, and `bundle_manifest.json`
payloads still rely on their own code/tests rather than dedicated
sidecar schema documents.

**Effect on thesis chapters:** Chapter 5 artifact bundles and any
external analysis or archival scripts can now validate the top-level
run manifest contract mechanically instead of inferring it from the
orchestrator implementation.

## [2026-07-23] - `scan_manifest.json` now ships with an explicit JSON Schema

**Scope:** Reporting/evaluation polish only. This pass stayed within the
combined thesis orchestrator's scan-artifact metadata contract; it did
not change scan execution semantics, evaluation semantics, or any
frozen Layer 1-5 logic.

**What the plan said:** The top-level combined-run artifacts already had
explicit schema sidecars, but the nested `scan_manifest.json` file in
`scan/` still relied on code and tests alone for its contract.

**What we actually did:** Added a schema sidecar for the scan manifest
and regression coverage for its required fields.

1. **Scan-manifest schema artifact emitted.**
   Each combined thesis run now writes `scan/scan_manifest.schema.json`
   beside `scan/scan_manifest.json`.

2. **Scan-manifest contract documented explicitly.**
   The emitted schema uses JSON Schema Draft 2020-12 and encodes the
   current manifest contract directly, including:
   - required `scan_path` and `exit_code`
   - required invocation provenance
   - fixed emitted filenames for `scan_report.json`,
     `scan_stdout.txt`, and `scan_stderr.txt`

3. **Regression coverage added.**
   `tests/test_thesis_orchestrator.py` now asserts that the new schema
   file is emitted and that key schema constraints match the runtime
   scan-manifest contract for both clean and vulnerable combined-run
   cases.

**Tests/adversarial checks run:**

- `pytest -q tests/test_thesis_orchestrator.py`: `3 passed`.
- Full `pytest -q`: `257 passed`, clean exit.
- `ruff check .`: clean.
- `black --check .`: clean.
- `mypy .`: clean.
- `git diff --check`: clean.

**Remaining limitations:** The nested scan/evaluation structured
artifacts still do not all have dedicated sidecar schema documents;
`scan_report.json`, `evaluation.json`, and `bundle_manifest.json`
remain the next candidates if explicit contracts are needed.

**Effect on thesis chapters:** Chapter 5 artifact bundles and any
external validation scripts can now validate the scan-artifact manifest
mechanically instead of inferring its shape from orchestrator code.

## [2026-07-23] - `bundle_manifest.json` now ships with an explicit JSON Schema

**Scope:** Reporting/evaluation polish only. This pass stayed within the
evaluation bundle metadata contract; it did not change Layer 4 metrics,
bundle-generation semantics, scan execution, or any frozen Layer 1-5
logic.

**What the plan said:** The combined-run and scan-side manifests already
had schema sidecars, but the evaluation bundle's own
`bundle_manifest.json` still relied on code and tests alone for its
contract.

**What we actually did:** Added a schema sidecar for the evaluation
bundle manifest, exposed it in the bundle inventory, and locked it with
regression coverage.

1. **Bundle-manifest schema artifact emitted.**
   Each evaluation bundle now writes `bundle_manifest.schema.json`
   beside `bundle_manifest.json`.

2. **Bundle inventory/readme updated.**
   The new schema file is now listed in both:
   - `bundle_manifest.json`'s `emitted_files`
   - `README.txt`'s file inventory

3. **Bundle-manifest contract documented explicitly.**
   The emitted schema uses JSON Schema Draft 2020-12 and encodes the
   current manifest contract directly, including:
   - `export_mode: "bundle"`
   - required contract/dataset provenance
   - required random state and example count
   - required emitted-file inventory
   - required invocation provenance

4. **Regression coverage added.**
   `tests/test_evaluation.py` now asserts that the new schema file is
   emitted and that key schema constraints match the runtime bundle
   manifest contract.

**Tests/adversarial checks run:**

- `pytest -q tests/test_evaluation.py`: `10 passed`.
- Full `pytest -q`: `257 passed`, clean exit.
- `ruff check .`: clean.
- `black --check .`: clean.
- `mypy .`: clean.
- `git diff --check`: clean.

**Remaining limitations:** The remaining nested structured artifacts
without dedicated sidecar schemas are `scan_report.json` and
`evaluation.json`.

**Effect on thesis chapters:** Chapter 5 evaluation bundles and any
external archival/validation scripts can now validate the evaluation
bundle manifest mechanically instead of inferring its shape from the
evaluation harness implementation.

## [2026-07-23] - `evaluation.json` now ships with an explicit JSON Schema

**Scope:** Reporting/evaluation polish only. This pass stayed within the
evaluation bundle's machine-readable Layer 4 metrics report contract; it
did not change Layer 4 metric computation, scan behavior, or any frozen
Layer 1-5 logic.

**What the plan said:** The evaluation bundle manifest already had a
schema sidecar, but the core `evaluation.json` payload still relied on
code and tests alone for its contract.

**What we actually did:** Added a schema sidecar for `evaluation.json`,
listed it in the bundle inventory, and locked its key structure with
regression coverage.

1. **Evaluation-report schema artifact emitted.**
   Each evaluation bundle now writes `evaluation.schema.json` beside
   `evaluation.json`.

2. **Bundle inventory/readme updated.**
   The new schema file is now listed in both:
   - `bundle_manifest.json`'s `emitted_files`
   - `README.txt`'s file inventory

3. **Evaluation-report contract documented explicitly.**
   The emitted schema uses JSON Schema Draft 2020-12 and encodes the
   current report contract directly, including:
   - required top-level contract/dataset provenance
   - required random state and example count
   - required `in_sample` and `leave_one_out` metric blocks
   - required prediction and confusion item shapes

4. **Regression coverage added.**
   `tests/test_evaluation.py` now asserts that the new schema file is
   emitted and that key schema constraints match the runtime
   `evaluation.json` contract.

**Tests/adversarial checks run:**

- `pytest -q tests/test_evaluation.py`: `10 passed`.
- Full `pytest -q`: `257 passed`, clean exit.
- `ruff check .`: clean.
- `black --check .`: clean.
- `mypy .`: clean.
- `git diff --check`: clean.

**Remaining limitations:** The only remaining nested structured artifact
without a dedicated sidecar schema is `scan_report.json`.

**Effect on thesis chapters:** Chapter 5 evaluation bundles and any
external archival/validation scripts can now validate the core
machine-readable evaluation report mechanically instead of inferring its
shape from the evaluation harness implementation.

## [2026-07-30] - Layer 5 SHAP multiclass output validation hardened

**Scope:** Layer 5 SHAP explainability/reporting only. This pass stayed
within `vibeguard/layer5_report/` and its regression tests; it did not
change Layers 1-4 detection, feature extraction, scoring, model
training, or evaluation semantics.

**What the plan said:** Layer 5 was implemented on 2026-07-22 and then
held pending an independent adversarial QA pass before freeze.

**What we actually did / found:** The fresh QA pass found a real
fail-closed gap in the SHAP shape guards for the frozen multiclass
Random Forest contract. Ambiguous SHAP outputs could be accepted as if
they were valid explanations instead of being rejected loudly.

1. **Multiclass SHAP shape checks tightened.**
   Layer 5 now validates SHAP outputs against the classifier's expected
   class count before selecting the predicted-label slice. In
   particular, it now rejects:
   - single-row 2D SHAP value arrays for multiclass models;
   - scalar/size-1 SHAP base values for multiclass models; and
   - mismatched class-axis widths on SHAP values/base values.

2. **Fail-closed behavior made consistent.**
   Previously, some malformed SHAP outputs could slip through when the
   predicted class happened to be an index that did not trigger an
   out-of-range access. Those paths now raise controlled `ValueError`
   exceptions instead of silently producing an explanation that does not
   reconstruct the model's predicted probability.

3. **Regression coverage added.**
   `tests/test_layer5_report.py` now covers:
   - rejection of single-row 2D SHAP value arrays for multiclass
     models;
   - rejection of scalar SHAP base values for multiclass models; and
   - end-to-end rejection of an inconsistent patched SHAP explainer
     output through `explain_project_risk()`.

**Tests/adversarial checks run:**

- `pytest -q tests/test_layer5_report.py tests/test_main.py tests/test_layer4_ml.py`:
  `36 passed`.
- Full `pytest -q`: `260 passed`, clean exit.
- `ruff check .`: clean.
- `black --check .`: clean.
- `mypy .`: clean.
- `git diff --check`: clean.

**Remaining limitations:** Layer 5 still explains project-level ML
features rather than directly attributing findings/files/lines. That is
an intentional methodology boundary, not a bug. The remaining freeze
question after this fix is whether the independent QA rerun stays clean.

**Effect on thesis chapters:** Chapter 5 should describe SHAP
explanations as fail-closed against unexpected multiclass output shapes,
not just "sorted feature attributions." This strengthens the claim that
the explainability layer was adversarially tested rather than assumed
correct because the happy-path report rendered successfully.

## [2026-07-30] - Layer 5 CLI reporting failures now fail closed

**Scope:** Layer 5 SHAP/reporting and the minimal `main.py` integration
boundary around it. Layers 1-4 stayed frozen; no detection, feature,
scoring, model, or evaluation semantics were changed.

**What the plan said:** After the earlier Layer 5 hardening pass, the
next required step was a fresh adversarial QA rerun before freeze.

**What we actually did / found:** The follow-up QA pass reproduced one
remaining fail-closed gap: if SHAP itself raised a non-`ValueError`
during report generation, the CLI printed a Python traceback instead of
returning a controlled `ML/reporting failed: ...` error. Tightened the
Layer 4/5 exception boundary in `main.py` so reporting failures now
return exit code `1` with the existing controlled error prefix rather
than leaking an internal traceback to the terminal. Added a regression
test in `tests/test_main.py` that patches `shap.TreeExplainer` to raise
`RuntimeError("boom")` through the real `main.main()` path and asserts
the fail-closed behavior.

**Tests/adversarial checks run:**

- `pytest -q tests/test_main.py tests/test_layer5_report.py tests/test_layer4_ml.py`:
  `37 passed`.
- Full `pytest -q`: `261 passed`, clean exit.
- `ruff check .`: clean.
- `black --check .`: clean.
- `mypy .`: clean.
- `git diff --check`: clean.
- Direct adversarial rerun of the patched SHAP runtime failure path:
  now prints `ML/reporting failed: boom` with exit code `1`, no
  traceback.
- Manual Layer 5 post-fix probes rechecked:
  malformed multi-sample SHAP outputs still reject cleanly; Unicode
  secret values remain redacted from CLI/report output.

**Remaining limitations:** This session both fixed the bug and reran the
QA gates, so it is a strong post-fix review pass but not fully
session-independent in the strict handoff sense. Technically, Layer 5
is clean on the current tree; if the workflow wants literal
build-session/QA-session separation, one final QA-only pass can be run
without expecting further code changes.

**Freeze decision:** No Layer 5 findings remain in this pass. Layer 5 is
clean enough to freeze on the current codebase.

**Effect on thesis chapters:** Chapter 5 can now state that Layer 5 was
tested not only for malformed SHAP tensor shapes but also for runtime
explanation-engine failures at the CLI boundary, and that those failures
are surfaced as controlled scan errors rather than internal tracebacks.

---

## [2026-09-02] - Layer 4 labelled dataset expanded to test whether ML actually beats the rule-based baseline; DRAFT, pending student review

**What the plan said:** CLAUDE.md Section 8 lists Layer 4 as frozen,
reopenable only if "the thesis methodology explicitly changes the ML
approach." An independent review of the frozen Layer 4/5 pair (not a
build session; a separate review pass, per Section 11) found that the
committed 8-project labelled dataset could not support the thesis's own
justification for including ML at all: every project in it had zero or
exactly one finding, and every label was a direct restatement of Layer
3's own severity-band mapping for that one finding. Leave-one-out
accuracy of 1.0 on that dataset was not evidence of a working
classifier - a lookup table keyed on "which single rule fired" would
score identically, and the six CWE-combination/same-file features in
`build_project_features` (`has_secret_and_access_control`,
`same_file_secret_and_access_control`, `has_secret_and_authentication`,
`has_secret_and_vulnerable_dependency`,
`has_access_control_and_input_validation`,
`same_file_access_control_and_input_validation`) had never once been
non-zero in training or evaluation, so nothing about whether Layer 4
could learn from combinations was actually being tested.

**What we actually did / found:** Reopened Layer 4's *dataset* only -
not the predictor/trainer/contract/evaluator code, all of which are
unchanged - on the "methodology explicitly changes" ground above, with
the student's explicit agreement to proceed and to review this entry
before it stands.

1. **Seven new controlled sample apps added**, same small Spring-style
   service format as the original eight, under
   `data/sample_apps/layer4_training/`: `multi-issue-gateway-service`,
   `insecure-admin-service`, `leaky-session-service`,
   `legacy-deps-service`, `open-intake-service`,
   `duplicate-validation-gaps-service`, and
   `vibe-coded-disaster-service`. Between them they exercise every one
   of the six combination/same-file features listed above at least
   once, plus a project with two same-CWE findings
   (`duplicate-validation-gaps-service`) to exercise `finding_count`/
   `medium_count` behaving sensibly for more than one instance of the
   same rule firing.

2. **Labels were written down, with rationale, before the new apps were
   scanned** - each project's intended `label_rationale` was decided
   from the app's design intent, not from re-running the tool and
   copying its output, specifically to avoid repeating the circularity
   that made the original 8-project dataset degenerate. Five of the
   seven new projects were labelled `critical` because they combine a
   real secret/RCE-class finding with something else, which was
   expected to agree with Layer 3's own max-severity rubric.
   `open-intake-service` (missing auth + missing validation on the same
   endpoint, no secret, no vulnerable dependency) was deliberately kept
   at `high`, not `critical`, as a boundary case. `duplicate-validation-
   gaps-service` (the same CWE-20 gap recurring across two endpoints)
   was deliberately labelled `high`, not `medium`: a max-severity
   reading of its single finding type would say `medium` (CWE-20's base
   score of 65 never changes with repetition), but the judgment
   recorded in its `label_rationale` is that the *same* gap recurring
   across a codebase signals a systemic weakness, not an isolated
   miss - this project exists specifically to be a case where a
   max-severity baseline and a considered human judgment diverge. All
   findings for all seven new apps were then produced by actually
   running Layers 1-3 against the real files (verified via a one-off
   script calling `scan_directory`/the CWE rule modules/directly, not
   hand-typed), confirming every app produced exactly the intended
   finding set with no parse failures or rejections before anything was
   added to `data/labeled/layer4_projects.json`.

3. **A fixed, non-learned baseline was added specifically to make "does
   ML add value" a testable comparison, not a narrative claim.** Added
   `baseline_label_from_max_severity()` and
   `evaluate_baseline_severity_model()` to
   `vibeguard/layer4_ml/evaluator.py`: the baseline predicts a
   project's label as the severity band of its single highest-scoring
   Layer 3 finding (or `low` for no findings), with no fitted
   parameters and no training step, so evaluating it in-sample carries
   no leakage risk the way it would for a fitted model. Exported from
   `vibeguard.layer4_ml.__init__`. Wired into
   `evaluation/evaluate.py`'s `EvaluationReport` as a third row
   alongside in-sample/leave-one-out, in the JSON export payload and its
   `evaluation.schema.json` contract (`required`/`properties` both
   extended with `"baseline"`), and in the bundle README's
   interpretation section.

4. **The trusted model contract was regenerated** via the existing
   `write_trusted_model_contract()` (no code change needed there) against
   the 15-project dataset:
   `data/labeled/layer4_random_forest_contract.json` now records
   `training_example_count: 15` and the updated dataset hash.

**Actual result, reported honestly rather than assumed:** Leave-one-out
accuracy dropped from the old dataset's 1.0/1.0 to **0.933 accuracy /
0.914 macro-F1** (14 of 15 held-out projects predicted correctly). The
one miss is `duplicate-validation-gaps-service` (index 13): held out,
trained on the other 14, Layer 4 predicts `medium`, not the labelled
`high`. This is the expected, defensible outcome of that project's
design, not a bug - it is the *only* project in the dataset that needs
the "repeated same-CWE finding elevates risk" pattern to be predicted
correctly, so leave-one-out (which necessarily trains without it when
it is the held-out example) has exactly zero supporting examples of
that pattern available on the one fold where it matters.

The more consequential number: **the fixed max-severity baseline scores
identically - 0.933 accuracy, the same macro-F1, and the same single
miss on the same project** (verified directly, prediction-by-prediction,
in `test_real_layer4_dataset_baseline_matches_leave_one_out_exactly`).
**On the dataset as it stands today, Layer 4's Random Forest is not
demonstrating any predictive value the deterministic Layer 3 rubric
does not already provide on its own.** This is the honest current answer
to the thesis's own "does project-level ML add value beyond static
rules" question - not yet, with 15 controlled examples and only one
instance of the pattern that would require ML (rather than a single
max-severity number) to get right. Recorded here rather than smoothed
over, per this project's stated standard that a suspiciously perfect
score should prompt suspicion, not a shipped claim.

**Regression tests added/updated:**
`tests/test_layer4_ml.py::test_real_layer4_dataset_loads_and_leave_one_out_evaluates`
updated to assert the real 15-example result (was pinned to the old
8-example 1.0/1.0 result); new
`test_real_layer4_dataset_baseline_matches_leave_one_out_exactly`,
`test_baseline_label_from_max_severity_uses_highest_scoring_finding`,
`test_evaluate_baseline_severity_model_rejects_empty_examples`.
`tests/test_evaluation.py` and `tests/test_thesis_orchestrator.py`
updated everywhere they had `8`/`1.0` hardcoded against the real
committed dataset/contract, plus new assertions for the `baseline` field
in the JSON payload and schema.

**Tests/adversarial checks run:**
- Full `pytest -q`: `264 passed` (was 261), clean exit.
- `mypy .`: clean.
- `ruff check .`: clean.
- `black --check .`: clean.
- `git diff --check`: clean.
- Live CLI smoke test against `vibe-coded-disaster-service`: Layer 1-5
  renders end to end; the Layer 5 SHAP table now shows a nonzero
  combination feature (`has_secret_and_access_control`) attributed for
  the first time in this project's history, since no prior training
  example ever set one to a nonzero value.

**Remaining limitations:** 15 controlled, synthetic, self-authored
projects is still a small dataset for a generalization claim - this
change fixes the *degeneracy* (labels no longer collapse to a restated
Layer 3 number, and combination features are now exercised), not the
*sample size*. The one interesting divergence case
(`duplicate-validation-gaps-service`) has exactly one supporting example
in the entire dataset, which is why leave-one-out cannot currently
credit Layer 4 with learning it; adding two or three more
repeated-finding-pattern projects would let leave-one-out actually test
whether Layer 4 can pick that pattern up with adequate support, rather
than testing whether it can with none. That is the concrete next step
if this entry is accepted, not a rewrite of anything built so far.

**Why:** The alternative - leaving the 8-project dataset as "frozen" -
would mean shipping a thesis chapter claiming ML classification without
ever having constructed a single test case that could have falsified
it. A perfect leave-one-out score on a dataset where every combination
feature is permanently zero is not a validated model; it is an
untested one that happened to look validated. Fixing the data, not the
architecture or the pipeline code, was judged the correct scope: the
predictor, trainer, contract, and evaluator all still behave exactly as
frozen, and the fix is entirely about what evidence they were asked to
be tested against.

**Effect on thesis chapters:** Chapter 3 (methodology) should describe
the labelled dataset as 15 controlled projects including seven that
combine multiple CWE findings by design, with labels assigned from
written design-intent rationale before scanning, not derived from the
tool's own output. Chapter 4 should document
`evaluate_baseline_severity_model()`/`baseline_label_from_max_severity()`
as the fixed comparison point Layer 4 is evaluated against. **Chapter 5
must report the baseline-tie result plainly**: leave-one-out
accuracy/macro-F1 of 0.933/0.914, identical to the non-learned baseline,
with the single shared miss explained by its cause (one supporting
example of the relevant pattern) rather than omitted or described only
as "the model achieves 93% accuracy" without the baseline context that
makes that number meaningful. This is a stronger, more defensible result
for a viva than the previous unexamined 1.0, and the limitations section
above gives a concrete, scoped next step rather than an open-ended one.

**Status: DRAFT.** This entry, the dataset change, the new sample apps,
the baseline-comparison code, and the regenerated contract were all
produced in this session per the student's request ("you draft
everything, I review") and have not yet been reviewed or accepted by
the student. Per Section 9, do not treat this entry as settled project
history, and do not build further on top of it, until the student has
reviewed the seven new sample apps' label rationale and the honest
result above and confirmed it.

---

## [2026-09-02] - Real-repo QA pass finds two Layer 1 precision gaps; CWE-284 gets a fail-closed caveat, CWE-1035 gets explicit unchecked-dependency reporting

**What the plan said:** Layer 1 is frozen. The next step after the
Layer 4 dataset fix above was to run the tool against real, independently-
maintained open-source Java projects (`.qa-repos/spring-petclinic-rest`,
`.qa-repos/quarkus-super-heroes`) to get real precision numbers rather
than numbers from purpose-built sample apps, per the student's request.

**What we actually did / found:** Ran the full CLI against both real
repos and verified every finding against the actual source by hand, not
just trusted the tool's own report.

1. **CWE-1035's version-omission blind spot, confirmed on two real,
   differently-structured projects.** `spring-petclinic-rest`'s `pom.xml`
   declares 24 dependencies; 23 have no explicit `<version>` at all,
   inherited from `spring-boot-starter-parent`. `quarkus-super-heroes`
   (10 modules) shows the identical pattern via the Quarkus platform BOM.
   CWE-1035 reported zero vulnerable dependencies on both - not because
   either is clean, but because it can only ever check a dependency that
   states its own version, and almost none do in idiomatically-written
   modern Spring Boot/Quarkus code. This was previously a documented but
   unquantified limitation; it is now measured: 19/24 unchecked on
   petclinic, 162/204 (79%) unchecked across quarkus-super-heroes'
   ten modules.

2. **A previously-undocumented CWE-284 blind spot, found by tracing why
   only 1 of ~10 petclinic controllers was flagged.** The other
   controllers use `@PreAuthorize` per method; `RootRestControllerV1`
   (a Swagger-redirect endpoint) has no annotation at all. Reading
   `BasicAuthenticationConfig.java` showed the real reason it's still
   arguably covered: a `SecurityFilterChain` bean with
   `http.authorizeHttpRequests().anyRequest().authenticated()` applies a
   single, project-wide rule this rule's annotation-only detection has no
   way to see. Centralizing authorization this way, instead of annotating
   every controller, is at minimum as common a real Spring Security
   pattern as the annotation style this rule already understood.

   It goes further: the same repo also ships `DisableSecurityConfig`
   (`anyRequest().permitAll()`), active when `petclinic.security.enable`
   is unset or `false` - which is exactly its *actual default*
   `application.properties` value. `@EnableMethodSecurity` itself lives
   inside the conditional `BasicAuthenticationConfig`, so in the real
   default deployment, `@PreAuthorize` enforcement is not even switched
   on. The honest picture is close to the opposite of what static
   analysis can report: VibeGuard says "1 endpoint unprotected, ~9
   protected"; the actual default runtime configuration protects none of
   them. No static analysis can resolve this specific case - the decisive
   value lives in a property that does not exist in source at all until
   something sets it at deploy time.

3. **CWE-798's "token" name-matching is confirmed too broad in principle,
   unconfirmed as an actual false positive in the wild.** Neither real
   repo contains a literal credential-shaped `token` field, so this was
   tested directly against `is_credential_name` instead:
   `pageToken`/`nextPageToken`/`refreshToken`/`continuationToken` all
   match. The practical risk is narrower than the name match alone
   suggests, though, since CWE-798 additionally requires a *literal*
   string value - pagination/continuation tokens are almost always
   runtime values, not literals - so this remains a real but
   lower-probability gap, left undisturbed rather than narrowed on no
   real evidence either way.

4. **CWE-798 produced a confirmed true positive on real code**:
   `rest-fights/src/main/resources/application.properties` in
   quarkus-super-heroes hardcodes `supersecretquarkuspassword` as a
   Quarkus remote-dev live-reload password - a real, non-placeholder,
   non-referenced literal, correctly flagged critical. Useful evidence
   the core detection logic holds up outside synthetic fixtures, not
   just a source of gaps.

**What we built, and what we deliberately did not:** Considered and
rejected fully closing both gaps before writing any code.

- Fully resolving CWE-1035's unchecked dependencies means either running
  Maven's actual resolver (network calls to Maven Central, or a
  guaranteed-populated local cache) or bundling external BOM files this
  tool doesn't have - either breaks CLAUDE.md Section 3's non-negotiable
  "runs entirely locally... no external API calls for core scanning"
  constraint, or requires an artifact this tool cannot guarantee exists.
  Not attempted.
- Fully closing the CWE-284 gap means understanding Spring Security's
  fluent `HttpSecurity` API, its path-matching precedence across
  multiple rules, and - per the petclinic case specifically - a
  property value that is not determined until deploy time and so cannot
  be resolved by source-only static analysis under any amount of
  engineering effort. Not attempted as a full solution for that reason,
  not effort.

Instead, built two bounded, locally-safe improvements that stay inside
the existing rule-module design philosophy (coarse, name/pattern-based
signals, not semantic understanding) and that directly address what was
actually found:

1. **`cwe_284.has_centralized_authorization_rule()` /
   `apply_centralized_authorization_context()`.** Detects a method
   returning `SecurityFilterChain` that contains both an `anyRequest`
   call and one of `authenticated`/`permitAll`/`denyAll` anywhere in its
   body (both javalang and Tree-sitter paths) - the same coarse,
   name-based pattern matching every other check in this module already
   uses, not a semantic reconstruction of Spring Security's actual
   behavior. When present anywhere in a scan, every CWE-284 finding's
   *message* gains an explicit caveat naming the SecurityFilterChain and
   stating plainly that runtime configuration not visible to static
   analysis may already cover it. Findings are never suppressed or
   dropped by this - deliberately, to stay fail-closed: a security tool
   that hides a candidate because of a coarse, best-effort heuristic is a
   worse failure mode than one that keeps flagging it with an honest
   caveat attached. Wired into `main.py`'s `_run_rules` as a
   post-processing step over the full findings list, not into
   `cwe_284.detect_in_java()` itself, so Layer 1's existing per-file
   rule contract and test suite are unaffected.

2. **`main.py`'s pom.xml report now states how much it could not check.**
   Added an "Unchecked (no resolvable version)" column plus a summary
   line ("N/M declared dependencies have no resolvable version... and
   could not be checked"). This does not close the recall gap - it
   cannot - but it removes the silent, misleading part of it: previously
   a clean scan of a real Spring Boot/Quarkus project reported "0
   findings" in a way indistinguishable from "0 vulnerable dependencies,
   all checked," when the real situation on both test repos was "most
   dependencies were never evaluated at all."

**Verified against the real repos again after the fix**, not just unit
tests: petclinic's `RootRestControllerV1` finding now carries the exact
SecurityFilterChain/anyRequest caveat; quarkus-super-heroes (which has no
Spring Security at all) correctly shows zero caveat text anywhere,
confirming the new signal doesn't fire indiscriminately; petclinic's pom
report now states "19/24 declared dependencies have no resolvable
version..."; quarkus-super-heroes' combined report states "162/204."

**Regression tests added:** `tests/test_cwe_284.py` gained coverage for
`has_centralized_authorization_rule` (positive on
`anyRequest().authenticated()`, positive on `anyRequest().permitAll()`,
negative with no `SecurityFilterChain` present, negative for a
path-scoped rule with no `anyRequest()` - proving this doesn't
over-trigger on narrowly-scoped security config, Tree-sitter fallback
parity) and `apply_centralized_authorization_context` (caveat appended
when present, no-op when absent, and an explicit assertion that finding
*count* never changes - the fail-closed guarantee stated as a test, not
just a docstring claim).

**Tests/adversarial checks run:**
- `pytest tests/test_cwe_284.py tests/test_main.py -q`: `35 passed`.
- Full `pytest -q`: `272 passed` (was 264), clean exit.
- `mypy .`: clean.
- `ruff check .`: clean.
- `black --check .`: clean.
- `git diff --check`: clean.
- Live re-scan of both real repos post-fix, confirmed by hand as above.

**Remaining limitations, stated plainly rather than implied solved:**
CWE-1035 still cannot evaluate the large majority of dependencies in a
typical modern Spring Boot/Quarkus project - the new reporting makes
that visible instead of silent, it does not fix the recall gap itself.
CWE-284's caveat correctly flags *that* static analysis might be
incomplete for a given finding; it cannot and does not attempt to say
*which* endpoints are actually covered, since that depends on
path-matching precedence and, in at least one real case found today, a
property value that does not exist in source code at all. The
`is_credential_name`("token") breadth issue is confirmed in principle
and left unchanged, since narrowing it on zero real-world evidence of
an actual false positive risked trading a known, bounded gap for an
unmeasured one in the other direction.

**Why:** Both fixes were scoped specifically to stay inside two
constraints that mattered more than closing the gap completely: Section
3's locked "runs entirely locally" rule, and this project's repeated,
explicit preference for a security tool that discloses what it cannot
determine over one that either guesses or stays silent. A rushed,
deeper fix for either gap risked trading a well-understood, honestly
documented limitation for a less-understood one under time pressure -
judged the wrong trade for a thesis tool whose credibility depends on
its stated boundaries being accurate.

**Effect on thesis chapters:** Chapter 5's CWE-1035 evaluation should
report the exact unchecked-dependency counts from both real repos (19/24
and 162/204) as a concrete, measured recall limitation, not a
theoretical one, and should state explicitly that resolving it fully
would require either violating the local-execution constraint or
bundling external BOM data this tool does not have. Chapter 5's CWE-284
evaluation should describe the SecurityFilterChain caveat as a
deliberate fail-closed design choice (annotate, never suppress) and use
the petclinic `petclinic.security.enable` case as a concrete, real
example of why static analysis has a hard - not merely
engineering-difficulty - limit here. Chapter 3/4 should document
`apply_centralized_authorization_context` as a project-level
enrichment step distinct from `detect_in_java`'s per-file candidate
detection, and the pom.xml report's unchecked-dependency count as part
of Layer 1's stated output contract.

---

## [2026-09-02] - Deeper real-repo evaluation: a major CWE-284/CWE-20 blind spot found and precisely characterized (not fixed); systematic false-negative sweep; real repos kept out of the Layer 4 training set

**What the plan said:** Continue evaluating precision/recall against
`.qa-repos/spring-petclinic-rest` and `.qa-repos/quarkus-super-heroes`
beyond the two gaps already fixed in the entry above, per Section 7's
stated next step, and assess whether real-repo scan results belong in
the Layer 4 labelled dataset.

**What we actually did / found:**

1. **Root-caused why petclinic scanned almost clean, and it is not the
   SecurityFilterChain caveat from the previous entry.** `OwnerRestControllerV1
   implements OwnersApi`, where `OwnersApi` is a Spring-generated
   interface (`openapi-generator-maven-plugin`) carrying the actual
   `@RequestMapping`/`@PostMapping` annotations; the concrete
   implementing method carries only `@PreAuthorize` and `@Override` -
   no endpoint annotation of its own at all. Checked systematically:
   **9 of petclinic's ~10 controllers** use this `implements XApi`
   pattern (`grep -rln "implements.*Api\b"` across `src/main/java`
   confirms it - only the one-off `RootRestControllerV1` doesn't).
   `has_endpoint_annotation()` (shared by `cwe_284.py` and `cwe_20.py`)
   only inspects a method's own annotation list, so it never recognizes
   the overridden methods as endpoints at all - not "checked and found
   protected," genuinely invisible. This is the real explanation for why
   a full REST CRUD API produced one finding: not because the app is
   well-protected, but because the tool cannot see most of its endpoint
   surface in the first place.

   It compounds with a second, independent factor: the generated
   `OwnersApi.java` interface exists only under
   `target/generated-sources/openapi/...` - confirmed gitignored in
   petclinic's own repo (`git check-ignore` on `target/`), present
   locally only because a Maven build already ran here. `scanner.py`
   deliberately excludes `target/` (correct, for its original reason -
   build output duplicating committed source). So even a full fix
   resolving `@Override` methods against implemented interfaces would
   not change this specific repo's result unless the interface were
   committed to `src/` directly (a legitimate alternative to codegen)
   or the scan ran after `mvn generate-sources` - a real,
   build-state-dependent reproducibility wrinkle stacked on top of the
   detection gap itself.

   Confirmed this is Spring-specific, not general: none of Quarkus's
   REST resource classes in `rest-heroes`/`rest-villains`/`rest-fights`
   use a generated-interface layer; they are hand-written JAX-RS
   resources directly, so this exact gap does not apply to the Quarkus
   half of the evaluation.

2. **Assessed, did not attempt, a full fix - larger and riskier than
   either gap fixed in the previous entry.** A real fix means resolving
   `@Override` methods against every interface a class implements,
   across files in the same scan (architecturally similar to the
   SecurityFilterChain project-wide pass added today), but goes further:
   the specific annotations that matter for CWE-20 (`@RequestBody`,
   `@Valid`) live at *parameter* level, and `ParsedParameter` (Layer 1's
   structural summary) does not capture parameter annotations at all
   today - closing this fully would need a new index keyed by
   (interface name, method name, parameter position), multiple-interface
   handling, and only helps at all for projects that commit their
   interface source (the target/-exclusion case above cannot benefit
   regardless). Judged this too large and too edge-case-prone to build
   under today's time pressure without risking the same mistake already
   avoided twice this session: trading a well-understood, precisely
   documented gap for a half-built, less-understood one. Logged as
   future work, not attempted.

3. **Systematic false-negative sweep found no additional gaps.**
   Beyond the annotation-visibility issue above:
   - `grep`-searched both repos for `==`/`!=` comparisons against
     credential-shaped names (CWE-287): zero matches in either repo -
     a genuine true negative, not a miss.
   - Searched both repos for secret patterns outside
     `CREDENTIAL_KEYWORDS`' vocabulary: AWS-style keys
     (`AKIA[0-9A-Z]{16}`), PEM private-key blocks, and connection
     strings with embedded credentials (`://user:pass@host`) - none
     found. Also checked field names using vocabulary the credential
     list doesn't cover (`passphrase`, `signingKey`, `dsn`) - none
     found in either repo.
   - Confirmed petclinic's zero CWE-20 findings are not a rule miss on
     their own terms: it does not use `@RequestBody` anywhere in
     committed `src/main/java` at all (confirmed by direct grep), so
     there is nothing for CWE-20 to have found even before accounting
     for finding #1's annotation-visibility gap.

4. **Per-module breakdown of quarkus-super-heroes**, scanning each of
   its independently-deployable services separately rather than as one
   monorepo blob (more methodologically correct for a project-level risk
   tool, since each module is its own real deployment unit):
   `rest-heroes` (1: CWE-284, public HTML browse page), `rest-villains`
   (1: CWE-284, same pattern), `rest-fights` (2: CWE-798, the real
   `supersecretquarkuspassword` secret under two different config keys),
   `ui-super-heroes` (1: CWE-284, a frontend-config endpoint serving a
   non-secret base URL), `rest-narration`/`event-statistics`/
   `grpc-locations` (0, all with 100% clean parses - genuine true
   negatives, not scan failures).

5. **Precision assessment across all 6 findings from both repos**: every
   one is a true positive *by the rule's own stated definition* (a real
   instance of the pattern each rule looks for) - zero outright false
   positives observed in this pass. But three of the six (the two
   `UIResource`-style browse pages plus the frontend-config endpoint) are
   low real-world severity despite Layer 3's fixed CWE-284 base score of
   80 ("high") - they are architecturally-public informational endpoints
   with no sensitive data, not under-protected sensitive ones. This is a
   distinct, real critique from "false positive": the rule correctly
   identifies "no access-control decision was made," but Layer 3's rubric
   cannot distinguish "and that matters" from "and it doesn't," since
   severity is assigned per-CWE, not per-endpoint-sensitivity - not
   attempted to fix today, noted as a limitation.

6. **Decided, with the student, not to fold real-repo results into the
   Layer 4 labelled training dataset.** The synthetic sample apps'
   ground-truth labels are authoritative by construction - the label is
   defined by design intent before scanning, per the previous entry's
   methodology. A real, third-party, actively-maintained repository has
   no equivalent authority behind an assigned label: it would be the
   author's own after-the-fact judgment on someone else's software, with
   no incident history, audit, or maintainer input behind it - a
   meaningfully weaker source of ground truth that should not be mixed
   into the same dataset as the by-construction synthetic labels without
   being distinguishable, and the student's judgment (asked directly,
   not decided unilaterally) was to keep the two separate rather than
   flag-and-mix. Real repos remain what they were already being used
   for: independent precision/recall evaluation evidence, not training
   data.

**Tests/adversarial checks run:** No code changed in this entry (root-cause
investigation, evaluation, and a scoping decision only) - existing 272-test
suite and all four static gates from the previous entry remain the
relevant verification and were not re-run redundantly.

**Remaining limitations:** The `@Override`-through-interface annotation
blind spot is now a precisely characterized, real gap affecting CWE-284
and CWE-20 for any Spring project using API-first/codegen controller
interfaces (a common enterprise pattern) - not fixed. Layer 3's
per-CWE (not per-endpoint) severity rubric cannot distinguish a
genuinely sensitive missing-auth endpoint from an intentionally-public
informational one - not fixed. Neither should be presented as solved.

**Why:** Root-causing precisely and stopping short of a rushed fix was
judged the right trade twice already today (CWE-1035, CWE-284's
SecurityFilterChain gap); this is the same discipline applied a third
time to a gap that turned out to be larger and more consequential than
either of the first two once actually investigated. The training-data
question was escalated rather than decided alone because it changes
what "ground truth" means in the thesis's own evaluation methodology,
not because it was technically difficult.

**Effect on thesis chapters:** Chapter 5 gets its single strongest
piece of real-world evaluation evidence from this entry: a precisely
root-caused explanation (not a vague "the tool missed some things") for
why a full real REST API scanned nearly clean, with an exact count (9 of
10 controllers) and an exact mechanism (interface-inherited annotations,
compounded by a gitignored generated-source directory). Chapter 5 should
report the full precision breakdown (6/6 true positives by rule
definition, 3/6 low real-world severity despite high Layer 3 scores) and
state plainly that recall could not be fully assessed on petclinic
specifically, since the tool cannot see most of its endpoint surface to
begin with - a materially different and more honest claim than "no false
negatives found." Chapter 3/6 (limitations/future work) should list
full `@Override`-through-interface resolution, including parameter-level
annotations, as a scoped, concrete, and now well-justified future-work
item rather than an abstract one. Chapter 3 (methodology) should state
explicitly that real-repo scan results were deliberately kept separate
from the Layer 4 labelled training set, and why - this is itself a
methodology decision worth defending in a viva, not an incidental
implementation detail.

---

## [2026-09-03] - First genuinely on-target evaluation: 7 Codex-generated Java microservices; a real CWE-798 false positive found and fixed; three independent confirmations of already-logged CWE-284/Layer 3 limitations

**What the plan said:** Every prior evaluation sample was either a
synthetic, hand-built fixture (the Layer 4 sample apps) or a real but
human-written open-source repository (`.qa-repos`). Neither is actually
what this thesis is about - AI-generated Java microservices. The student
generated real projects with Codex (an external AI coding tool,
unrelated to this Claude Code session) specifically to close that gap.

**What we actually did / found:** Scanned 7 Codex-generated Spring Boot
microservices with the full CLI - one built earlier
(`runnable-ai-orders-service`) plus six built from deliberately
realistic, non-leading prompts (a user-accounts service, a payments
service, a file-upload service, a notifications service, an admin
dashboard, and a public product catalog - the prompts asked for features,
never for a specific vulnerability, so what was found reflects Codex's
own unprompted behavior, not an engineered test) - then verified every
finding against the actual generated source by hand, same standard as
the `.qa-repos` pass.

1. **A real, previously-undiscovered CWE-798 false positive, found and
   fixed.** `ai-notifications-service` correctly externalizes its
   webhook signing secret via `@Value(...)`, then does
   `new SecretKeySpec(signingSecret.getBytes(), "HmacSHA256")` - entirely
   idiomatic, correct Java. VibeGuard flagged it as a critical hardcoded
   credential named `SecretKeySpec` anyway. Root cause:
   `"SecretKeySpec"` matches the credential-shaped-constructor-name check
   (it contains "secret"), and `_check_class_creator`'s
   reversed-argument scan - a deliberate choice for cases like
   `PasswordAuthentication("user", "pass".toCharArray())`, where the real
   secret is the *last* argument - hits `"HmacSHA256"` (a standard,
   public JCA algorithm name, not secret material) before ever reaching
   the actual key expression, and stops there since it's a reportable
   literal. `SecretKeySpec(byte[], String algorithm)` is a standard JDK
   crypto constructor; this exact shape is common, idiomatic real Java,
   not an edge case - this false positive would recur constantly in any
   codebase doing HMAC/AES work this way.

   Fixed by adding `_JCA_ALGORITHM_NAMES`, a small, curated, exact-match
   (case-sensitive - JCA names are case-sensitive standard identifiers)
   set of standard algorithm/transformation names to `_is_safe_value()`,
   the same architectural pattern already used for `_LITERAL_NON_VALUES`
   ("null"). Verified the fix does not blind the rule to a real secret
   in an earlier argument position when a later one is now excluded
   (`test_detect_in_java_still_flags_real_secret_before_a_safe_algorithm_name`)
   and re-ran the actual file that surfaced the bug: the false positive
   is gone, the one genuine CWE-284 finding on the same file is
   unaffected. 2 new regression tests, full suite 274 passed (was 272),
   `mypy`/`ruff`/`black --check`/`git diff --check` all clean.

2. **A natural experiment on security omission, not engineered.** Across
   the 6 non-leading prompts, only `ai-user-accounts-service` pulled in
   any Spring Security dependency at all (`spring-security-crypto`, for
   password hashing only - no `SecurityFilterChain`, no
   `@PreAuthorize`), and none of the 6 added access control to their own
   endpoints. This held even where the prompt strongly implied it
   mattered: a payments-charge endpoint, and a user-account service where
   `get`/`update` operate on any `{id}` with zero ownership check
   (functionally an IDOR - any caller can view or modify any other
   user's profile). `ai-user-accounts-service` did get password handling
   right where it mattered: `BCryptPasswordEncoder.encode`/`.matches()`,
   never `==` - CWE-798 and CWE-287 correctly found nothing there, a
   useful confirmation the rules stay quiet on genuinely correct code,
   not just noisy on broken code.

3. **A third independent real-world confirmation of the already-logged
   CWE-284 annotation-blindness limitation**, via a new mechanism not
   seen before: `ai-admin-dashboard-service` hand-rolls its own
   authorization - every sensitive method checks an `X-Admin-Key` header
   against an environment-provided value via a private `authorized()`
   helper, called explicitly at the top of each handler. A real access-
   control decision was made; it is simply imperative code, not a
   Spring/JAX-RS annotation, a `SecurityFilterChain`, or an implemented
   interface - none of which this rule can recognize as a decision.
   Between yesterday's SecurityFilterChain and codegen-interface findings
   and this one, real Java code now demonstrably expresses "an
   access-control decision was made" through at least three structurally
   different mechanisms invisible to annotation-based detection.
   Deliberately not chased as a fourth special case: the space of
   possible hand-rolled authorization implementations is unbounded by
   construction (it is just arbitrary code), unlike the previous two
   fixes, which were each one bounded, nameable Spring API pattern.
   Recorded as cumulative evidence for the same limitation, not treated
   as three separate bugs each needing their own patch.

4. **A third independent confirmation of Layer 3's per-CWE (not
   per-endpoint) severity-calibration limitation.** `ai-product-catalog-
   service` was prompted explicitly with "no auth needed since it's
   public data," and Codex built exactly that - a genuinely public,
   read-only, non-sensitive endpoint. CWE-284 still fires (correctly, by
   its own stated definition: no access-control decision of any kind was
   made) and Layer 3 still scores it 80/high, indistinguishable in the
   report from a sensitive endpoint with the same gap. This is the same
   limitation observed on real `.qa-repos` findings yesterday
   (`UIResource`, `EnvResource`), now confirmed a third time with an
   explicit prompt instruction removing any doubt about intent.

**Tests/adversarial checks run:**
- `pytest tests/test_cwe_798.py -q`: `41 passed`.
- Full `pytest -q`: `274 passed` (was 272), clean exit.
- `mypy .` / `ruff check .` / `black --check .` / `git diff --check`:
  all clean.
- Live re-scan of `ai-notifications-service` post-fix: false positive
  gone, genuine CWE-284 finding unaffected.
- All 7 AI-generated apps' findings verified against actual source by
  hand (not just the tool's own report) before being characterized here.

**Remaining limitations:** `_JCA_ALGORITHM_NAMES` is a curated list, not
exhaustive - extend on the next real false positive found, same
"add on real need" practice as everywhere else in this project. The
CWE-284 annotation-blindness and Layer 3 severity-calibration
limitations remain open, now with three independent pieces of real-world
evidence each rather than one; still not attempted, for the same reasons
logged yesterday (unbounded pattern space for the former, a materially
larger rubric-design change for the latter).

**Why:** The SecretKeySpec bug was fixed because it was genuinely
tractable - bounded, no external data, no runtime ambiguity, and common
enough in real cryptographic code that leaving it would actively mislead
a reader of this tool's output. The admin-dashboard case was
deliberately *not* chased into a fix for the opposite reason: unlike a
named API shape (SecurityFilterChain, an implemented interface),
"arbitrary imperative authorization logic" has no bounded pattern to
build a rule against - attempting one would mean guessing at an
open-ended space of hand-written code shapes, the same category of
overreach avoided twice yesterday.

**Effect on thesis chapters:** Chapter 5 gains its first truly on-target
evaluation sample set (7 AI-generated microservices, not synthetic
fixtures or human-written repos) and should report the natural-experiment
finding directly: absent an explicit security requirement in the prompt,
5 of 6 generated services added no access control at all, including for
a payments endpoint and a user-account service with a functional IDOR.
Chapter 5 should also report the SecretKeySpec false positive as a
concrete example of iterative, evidence-driven hardening - a real bug
found on real (if AI-generated) code, not a hypothetical - and should
cite the admin-dashboard and product-catalog findings as the third
independent confirmation each of the two limitations already logged
2026-09-02, strengthening rather than merely repeating that entry's
claims. Chapter 3 (methodology) can now describe the AI-generated
evaluation sample construction discipline explicitly: realistic,
non-leading prompts, generated independently of this tool, findings
verified against source by hand before being reported.

---

## [2026-09-03] - The 7 AI-generated projects added to the Layer 4 training set; result is a precisely diagnosed feature-set gap, not a clean win

**What the plan said:** The previous entry's 7 Codex-generated projects
were evaluation-only evidence, deliberately kept out of the Layer 4
labelled dataset per the 2026-09-02 methodology decision (real-repo
labels are the author's after-the-fact judgment, a weaker source of
ground truth than the synthetic set's by-construction labels). Unlike
`.qa-repos`, the student has real authority over these 7 - they were
commissioned for this purpose - so, asked directly, the student decided
to add them to the training set rather than keep them evaluation-only.

**What we actually did:** Wrote a `label_rationale` for each of the 7
from genuine security judgment of what the generated code actually
does (an unauthenticated profile-edit endpoint on an accounts service is
a functional account-takeover path; an unconditional, always-on
SecurityFilterChain means a project with "high"-scored CWE-284 findings
is actually well-protected; a hand-rolled header-checked admin
endpoint has real, if weaker-than-idiomatic, access control) rather than
copying Layer 3's raw score, same discipline as the synthetic set - with
one honest difference stated in each rationale: these labels were
necessarily written after the code already existed and had been scanned,
since Codex's output could not be dictated in advance the way the
synthetic apps' vulnerabilities were designed in advance. Added all 7 to
`data/labeled/layer4_projects.json` (8 -> 15 -> 22 total), regenerated
the trusted contract, re-ran leave-one-out and baseline evaluation.

**The result, reported honestly rather than the good-looking number
being sought:** Leave-one-out accuracy **dropped** from 0.933 (15
projects) to 0.591 (13/22). More importantly, the fixed max-severity
baseline now **measurably beats** Layer 4's learned model - 0.682 vs.
0.591 - a reversal from the previous dataset, where the two tied
exactly. In-sample accuracy (fitting and evaluating on the same full 22
projects, the most favourable possible condition) is only 0.864, not
1.0.

**Root-caused, not just observed.** Directly computed and compared
feature vectors: `ai-payments-service` (labelled critical - an
unauthenticated payment-charge endpoint) and `ai-product-catalog-service`
(labelled low - a genuinely public, read-only catalog, prompted
explicitly as such) produce a **byte-identical** Layer 4 feature vector:
`{finding_count: 2, max_rule_score: 80, mean_rule_score: 80,
high_count: 2, cwe_284_count: 2, java_source_count: 2}`. `runnable-ai-
orders-service` (low) shares the same vector too. No classifier, however
well-tuned, can separate genuinely identical inputs carrying different
labels - this is not a "need more data" problem or a modelling failure,
it is a **feature-set gap**: none of Layer 4's current features
(finding/severity counts, missing-line count, six specific CWE-pair
combination flags) encode the real-world signal that actually
distinguishes these projects - endpoint domain/business sensitivity
(a payment mutation vs. a public catalog read). A human reviewer sees
this instantly from the code; Layer 4 cannot see it at all, because it
was never extracted into a number anywhere in the pipeline.

This generalizes the exact same root cause already documented twice this
week from a different angle: CWE-284's rule-level blindness to
non-annotation authorization (SecurityFilterChain, codegen interfaces,
hand-rolled header checks) and Layer 3's inability to distinguish
"public by design" from "insecure by accident" both stem from static
analysis only ever seeing *pattern*, not *context*. This entry shows
that same gap propagates all the way up through Layer 4: the ML layer
can only ever be as good as the features it is given, and those features
currently carry no context signal at all.

**Regression tests updated/added:**
`tests/test_layer4_ml.py::test_real_layer4_dataset_loads_and_leave_one_out_evaluates`
updated to the real 22-project result (was pinned to 15/0.933);
`test_real_layer4_dataset_baseline_matches_leave_one_out_exactly` replaced
with `test_real_layer4_dataset_baseline_now_beats_leave_one_out` (the old
test's premise - baseline ties Layer 4 - is no longer true and rewriting
it to assert the new, opposite relationship is the honest fix, not a
weakening); new
`test_ai_payments_and_catalog_projects_share_an_identical_feature_vector`
locks in the concrete proof above as a permanent regression check, not
just a one-off observation in this log. `tests/test_evaluation.py` and
`tests/test_thesis_orchestrator.py` updated everywhere they had
15-project/0.933/1.0 values hardcoded against the real committed
dataset/contract.

**Tests/adversarial checks run:**
- Full `pytest -q`: `276 passed` (was 274), clean exit.
- `mypy .` / `ruff check .` / `black --check .` / `git diff --check`:
  all clean.
- `evaluation.evaluate` re-run against the regenerated contract; console
  output verified directly to contain the real 0.864/0.591/0.682 numbers
  cited above, not assumed from the underlying test values alone.

**Remaining limitations:** The concrete next step this finding points to
- adding features that capture endpoint domain/business-sensitivity
  signal (for example, path or naming-pattern heuristics distinguishing
  payment/auth/admin-shaped endpoints from general CRUD, in the same
  coarse, name-based spirit as every other heuristic in this project) -
  was not attempted today. It is a real feature-engineering task, not a
  quick fix, and doing it well would need its own scoped pass with its
  own adversarial testing, not an addition bolted onto this entry under
  time pressure.

**Why:** The dataset was expanded because the student asked for it
directly, understanding the tradeoff explained beforehand: unlike the
`.qa-repos` projects, these 7 are within the student's real authority to
label. The honest result - baseline now winning, not tying - was kept
and explained rather than treated as a problem to hide or an accident to
revert: reverting a real, harder, more representative dataset back to an
easier one specifically because it produces a worse-looking number would
be the same mistake already rejected on 2026-09-02 (never let a good
number be the goal instead of an honest one), now at one layer of
removal instead of repeated blindly.

**Effect on thesis chapters:** Chapter 5 gets a materially stronger,
more honest evaluation narrative: not "the ML model matches a simple
baseline" (2026-09-02's finding) but "expanding to a more realistic,
context-varied dataset caused the baseline to *outperform* the ML model,
and the reason is precisely identified: a feature-set gap between what
static analysis can extract and what real risk judgment requires."
That is a defensible, interesting research finding in its own right, not
a failure to bury - a viva panel is far more likely to respect "we found
exactly why this doesn't work yet and what feature would fix it" than an
unexamined tie. Chapter 3 (methodology) should describe the dataset's
final composition explicitly: 15 synthetic, by-construction-labelled
projects plus 7 real, Codex-generated, post-hoc-labelled projects, with
the labelling-authority distinction between the two stated plainly.
Chapter 6 (future work) gains a concrete, well-motivated, and now
evidence-backed item: endpoint domain/context features for Layer 4,
not a vague "improve the model" gesture.

---

## [2026-09-03] - Built the feature-set fix the previous entry deferred; caught and fixed a real bug in it before it shipped; small-data ceiling confirmed, not solved

**What the plan said:** The immediately preceding entry diagnosed, but
deliberately did not fix, the feature-set gap behind Layer 4's baseline
now beating leave-one-out: no feature captured endpoint domain/business
sensitivity. Asked directly whether to build it now, the student said
yes.

**What we actually did:**

1. **Added `has_sensitive_domain_signal`** to
   `vibeguard/layer4_ml/predictor.py`: a coarse, curated, substring-match
   keyword list (payment/billing/charge/checkout/..., account/user/
   profile/auth/login/..., admin/administrator/staff/internal/...)
   checked against each finding's file name and identifier, same
   "match names, not semantics" heuristic style already used everywhere
   in this project (e.g. `CREDENTIAL_KEYWORDS`). Wired into
   `build_project_features()`/`_feature_names()` as a 23rd feature.

2. **Caught a real bug in the first version before it shipped.** The
   initial implementation matched against `item.feature.file_path`
   directly - a *resolved absolute path*
   (`FindingFeature.file_path = finding.file_path.resolve()`, per Layer
   2's contract). On this development machine, every single path begins
   `/Users/alfreddomegil/...`, so `.lower()` on the full path made
   `"user"` match on *every project scanned on this machine*, regardless
   of its actual code - confirmed directly:
   `ai-product-catalog-service` and `runnable-ai-orders-service` both
   showed `has_sensitive_domain_signal = 1.0` despite neither having
   anything to do with accounts. This is the identical failure mode that
   got `path_depth` removed from Layer 2 on 2026-07-21 (a feature
   computed from local absolute-path structure is not a property of the
   project, it is a property of where it happens to be checked out) -
   recurring here because the lesson from that entry wasn't re-derived
   before writing this feature. Fixed by matching only
   `item.feature.file_path.name` (the file's own name, e.g.
   `"PaymentController.java"`) plus the identifier, never the full path.
   Verified the fix directly: re-computed feature vectors for all 22
   projects post-fix, confirmed only the 6 projects with a genuinely
   domain-relevant file name (`PaymentController`, `UserController`,
   `AdminController`, `AuthService`, `LoginService`, and the earlier
   `insecure-admin-service`'s `AdminController`) show the signal, catalog
   and orders correctly show 0.0.

3. **Regenerated the trusted contract** (schema changed: 22 -> 23
   features) and re-ran leave-one-out/baseline evaluation.

**The result, reported honestly:** In-sample accuracy rose from 0.864 to
**0.955** (21/22) - direct confirmation the fix resolved the training-set
contradiction the previous entry proved (payments/catalog/orders are no
longer feature-identical). **Leave-one-out accuracy did not move: still
0.591 (13/22), and the baseline (0.682, 15/22) still wins.** Root cause,
this time a small-data problem rather than a missing-feature problem:
`has_sensitive_domain_signal` is supported by only 6 of the 22 labelled
projects, split unevenly across labels (four critical, one high, one
medium). Holding any one of those 6 out for leave-one-out testing leaves
too few, too skewed examples for the model to learn a reliable rule from
the signal - e.g. `ai-admin-dashboard-service` (medium, the dataset's
only medium-labelled sensitive-domain project) is predicted `critical`
when held out, because the other 5 sensitive-domain examples it must
generalize from are overwhelmingly critical. This is now a precisely
diagnosed, ordinary small-N generalization limit, not a design flaw in
the feature and not the earlier identical-input contradiction.

**Regression tests added/updated:** `tests/test_layer4_ml.py` -
`test_real_layer4_dataset_loads_and_leave_one_out_evaluates` updated to
the real post-fix confusion matrix;
`test_real_layer4_dataset_baseline_matches_leave_one_out_exactly`
replaced with `test_real_layer4_dataset_baseline_still_beats_leave_one_out`
(new docstring explaining the small-data cause, not the old
identical-vector cause); `test_ai_payments_and_catalog_projects_share_an_identical_feature_vector`
(whose premise the fix falsified) replaced with
`test_has_sensitive_domain_signal_distinguishes_payments_from_catalog`;
new `test_has_sensitive_domain_signal_does_not_leak_from_the_absolute_checkout_path`
locks in the specific bug found and fixed above as a permanent
regression guard, constructing a path with `"user"` in a parent
directory segment and a domain-irrelevant file name, asserting the
signal stays off; new `test_has_sensitive_domain_signal_matches_common_domain_file_names`/
`test_has_sensitive_domain_signal_false_for_generic_file_names` cover the
positive/negative cases directly. `tests/test_evaluation.py` updated
everywhere it had the pre-fix in-sample accuracy (0.864) hardcoded
against the real committed dataset/contract.

**Tests/adversarial checks run:**
- `pytest tests/test_layer4_ml.py -q`: `26 passed`.
- Full `pytest -q`: `279 passed` (was 276), clean exit.
- `mypy .` / `ruff check .` / `black --check .` / `git diff --check`:
  all clean.
- Post-fix feature vectors for all 22 projects recomputed and read
  directly (not assumed) to confirm the leak was gone and the intended 6
  domain-relevant projects were the only ones flagged.

**Remaining limitations:** The dataset does not yet have enough
sensitive-domain examples, evenly enough distributed across risk labels,
for leave-one-out to generalize the new signal reliably. The concrete,
now-precise next lever is more labelled examples specifically in this
under-represented bucket (more payment/account/admin-domain projects
across more than one label each), not a different feature or a different
model - a materially more specific future-work item than either of the
two entries preceding this one produced.

**Why:** Built because the student asked directly, understanding
beforehand (per the previous entry) that this closes one specific,
diagnosed gap and does not guarantee the aggregate leave-one-out number
improves - which is exactly what happened, and was reported as such
rather than the in-sample improvement being presented as if it were the
generalization result. The absolute-path bug was caught by checking the
actual computed values against the real dataset before regenerating the
contract, not by trusting the implementation because it read correctly -
the same "verify, don't assume" discipline applied throughout this
project's history, catching a mistake this session itself introduced
just as readily as one inherited from earlier work.

**Effect on thesis chapters:** Chapter 5 now has a complete three-part
Layer 4 narrative across three same-day entries: (1) the original
dataset was degenerate, fixed with diverse synthetic labels; (2)
expanding to real AI-generated projects surfaced a genuine feature-set
gap, precisely identified; (3) fixing that gap improved in-sample fit
substantially but left leave-one-out unchanged, for a different and
now-also-precisely-identified reason (insufficient, unevenly-distributed
support for the new signal). That progression - each step diagnosing
exactly why the previous one didn't fully resolve the question - is
itself evidence of a rigorous evaluation methodology, and is worth
presenting as the narrative arc, not just the final numbers. Chapter 6
(future work)'s item from the previous entry should be sharpened: not
"add domain-context features" (done) but "collect more labelled
examples in the sensitive-domain bucket, across more than one risk
label each."

---

## [2026-09-03] - Second AI-generated batch (10 more, targeted); Layer 4 beats the baseline for the first time, with a caveat that must be stated plainly; the dominant real-world CWE-284 blind-spot pattern is now confirmed, not anecdotal

**What the plan said:** The previous entry's concrete next lever was
"more labelled examples in the sensitive-domain bucket, across more than
one risk label each." The student's thesis proposal commits to
evaluating against 50 sample apps; asked to continue toward that, 10
more were generated, this time with prompts deliberately spread across
payment/account/admin/auth sub-domains and deliberately mixed - some
explicitly requesting protection, some not - specifically to get labels
other than "critical" in the under-supported bucket, not just more
volume.

**What we actually did / found:**

1. **The dominant real-world pattern from the previous entry is now
   confirmed, not a one-off.** Every one of the 4 explicitly-protection-
   requested apps (`ai-payment-refunds-service`, `ai-account-deletion-
   service`, `ai-role-management-service`, `ai-two-factor-service`)
   implements real, working access control - and none of them use
   Spring Security. All four use the same hand-rolled shape as
   `ai-admin-dashboard-service` from the previous batch: a caller-
   supplied header compared against an externalized key
   (`@Value(...)` + `.equals()`/`MessageDigest.isEqual`) before the
   handler runs. More strikingly, 4 of the 6 *unprompted* apps
   (`ai-audit-log-service`, `ai-login-sessions-service`, `ai-staff-
   timesheet-service`, `ai-card-storage-service`) added the identical
   pattern on their own, inferring restriction from domain framing
   alone ("staff", "internal", "trusted upstream service") without
   being asked. Across both AI-generated batches combined, 9 of the 10
   real protection mechanisms observed are this hand-rolled shape;
   exactly 1 (`runnable-ai-orders-service`) is real Spring Security.
   This is no longer an interesting edge case - it is Codex's
   observed *default* way of adding access control to a small Java
   microservice, which makes CWE-284's blindness to it a materially
   more consequential limitation than a single example could show.

2. **One implementation partially, not fully, delivers what it was
   asked for.** `ai-account-deletion-service` was prompted to ensure
   "only the account owner can trigger this for their own account." It
   does check a caller key and a target id - but against a single
   global `ACCOUNT_OWNER_ID` configuration value, not a per-user
   identity lookup, so it does not actually generalize to multiple
   users each owning their own account the way the prompt implied.
   Labelled accordingly (medium, not low): a real improvement over
   `ai-user-accounts-service`'s identical-shaped, completely open
   endpoints in batch 1, but not a full, correct solution either.

3. **One implementation is measurably more careful than its nine
   siblings.** `ai-two-factor-service` is the only one of all 17
   AI-generated projects scanned across both batches to use
   `MessageDigest.isEqual` (constant-time comparison) rather than plain
   `.equals()` for its key/code checks - correctly avoiding a timing
   side-channel none of the others bothered with. Labelled low, crediting
   that directly, even though it shares the same CWE-284 blind spot as
   every other hand-rolled implementation.

4. **`ai-password-reset-service` is a second, structurally different
   kind of true-positive-but-inconsequential case.** Unlike `ai-product-
   catalog-service` (batch 1: correct because the data is genuinely
   public), this one is correct because a password-reset flow must, by
   definition, be reachable by someone who cannot currently log in - and
   the actual security-relevant mechanics (32-byte `SecureRandom` token,
   SHA-256-hashed before storage, 15-minute expiry, possession of the
   token required to confirm) are implemented correctly. Labelled low.

5. **All 10 added to the labelled training set** (22 -> 32 projects),
   trusted contract regenerated, leave-one-out and baseline re-run.

**The result, and the caveat that makes it honest:** Leave-one-out
accuracy is **0.531** (17/32); the fixed baseline is **0.469** (15/32).
**This is the first time in this project that Layer 4 outperforms the
baseline** - but verified directly, not just asserted: the baseline gets
**zero of the 10 new batch-2 projects correct**, because `baseline_label_from_max_severity`
only ever reads a project's raw Layer 3 severity band, a lone CWE-284
finding's band is always "high," and not one of the 10 new labels is
"high" (they are low/medium/critical, assigned from the real,
if-often-weak, hand-rolled protection each project actually has). The
baseline was therefore structurally guaranteed to fail this entire batch
before a single prediction was made. Layer 4 gets **3 of the 10** right
- using `has_sensitive_domain_signal` and finding-count features the
baseline has no access to at all - which is a real, demonstrated
advantage over a strategy that cannot succeed here, but is *not* yet
evidence that Layer 4 reliably predicts real-world risk: it is still
wrong on the other 7. Both numbers are reported in `IMPLEMENTATION_LOG.md`
and locked into
`tests/test_layer4_ml.py::test_real_layer4_dataset_leave_one_out_now_beats_baseline_with_a_caveat`,
which asserts the 0/10 and 3/10 splits directly, not just the aggregate
accuracy figures, so the caveat cannot silently disappear from the test
suite the way an unqualified "Layer 4 wins" assertion would let it.

**Regression tests updated:**
`tests/test_layer4_ml.py::test_real_layer4_dataset_loads_and_leave_one_out_evaluates`
updated to the real 32-project confusion matrix;
`test_real_layer4_dataset_baseline_still_beats_leave_one_out` replaced
with `test_real_layer4_dataset_leave_one_out_now_beats_baseline_with_a_caveat`
(the old test's premise - baseline wins - is now false, and the
replacement encodes the caveat as an assertion, not just a comment);
`test_real_layer4_dataset_baseline_predictions_smoke` updated to 32.
`tests/test_evaluation.py` and `tests/test_thesis_orchestrator.py`
updated everywhere they had 22-project/0.591/0.682 values hardcoded
against the real committed dataset/contract.

**Tests/adversarial checks run:**
- Full `pytest -q`: `279 passed`, clean exit.
- `mypy .` / `ruff check .` / `black --check .` / `git diff --check`:
  all clean.
- Every finding for all 10 new projects verified against the actual
  generated source by hand before being labelled (same discipline as
  every AI-generated project so far) - in particular, each hand-rolled
  `allowed()`/`owner()` check was read directly to confirm it actually
  gates the endpoint, not assumed from the docstring alone.
- `evaluation.evaluate` re-run against the regenerated 32-project
  contract; the 0.531/0.469 figures and the 0/10 vs. 3/10 batch-2 split
  were read directly from computed output, not assumed from the test
  values.

**Remaining limitations:** 32 of the thesis's stated 50 sample apps are
now in place; reaching 50 needs at least one more batch. The
`has_sensitive_domain_signal` feature still only distinguishes *that* a
finding touches a sensitive domain, not *how well-protected* it actually
is (the hand-rolled-auth quality spectrum this batch surfaced - from
`ai-billing-service`'s nothing at all, to `ai-role-management-service`'s
weak shared key, to `ai-two-factor-service`'s constant-time comparison -
is entirely invisible to Layer 4's current feature set, even though it
is exactly the signal that separated most of this batch's labels). That
is a second, more specific future-work item than "more sensitive-domain
examples" alone.

**Why:** Reported the 0/10-vs-3/10 split alongside the headline accuracy
numbers, rather than letting "Layer 4 beats baseline" stand as an
unqualified claim, for the same reason the previous three Layer 4
entries this week did the same thing: a good-looking number that would
not survive a direct follow-up question in a viva is worse than a
correctly-qualified one. The batch itself was deliberately constructed
to probe exactly the case the baseline cannot handle, which is why the
result reads as a clean win in aggregate - stating that construction
choice explicitly is part of reporting the result honestly, not
undermining it.

**Effect on thesis chapters:** Chapter 5 gets its first genuine, if
qualified, evidence that project-level ML can add value beyond the
deterministic rule-based scorer - reported with the exact mechanism
(access to signals the baseline cannot see) and the exact limit (still
wrong most of the time on the very projects producing the edge) stated
together, not separately. Chapter 5 should also report the 9-of-10
hand-rolled-vs-Spring-Security finding as a substantive, now
statistically-supported (not anecdotal) result about how this
generation of AI coding tools implements access control by default,
independent of whether VibeGuard can detect it - a finding about the
target population the thesis studies, not just about the tool. Chapter 6
(future work) should add: a feature (or separate signal) distinguishing
hand-rolled authentication *quality* would likely matter more than
further growing example count alone, per the remaining-limitations note
above. Chapter 3 should note the dataset stands at 32 of the stated 50
sample apps.

---

## [2026-09-03] - Third AI-generated batch (10 more, new use cases); CWE-798's algorithm-name fix generalized on its second real occurrence; Layer 4's edge over baseline confirmed on a genuinely held-out batch, not just re-observed on the batch that motivated it

**What the plan said:** Asked directly whether the next batch toward
the thesis's 50-app target should revisit the sensitive-domain bucket
again or move to new territory, the student chose to stay in that
bucket - specifically to test whether the leave-one-out edge over the
baseline found in the previous entry was real or an artifact of that
one batch's composition. 10 more prompts were written deliberately as
new use cases within payment/account/admin/auth (webhooks, invoicing,
email verification, account linking, feature flags, system health,
bulk import, API key issuance, OAuth refresh, account lockout), not
repeats of batch 2's shapes.

**What we actually did / found:**

1. **CWE-798's algorithm-name false positive generalized, on its second
   real occurrence, per this project's own established practice.**
   `ai-oauth-refresh-service` produced `new Token(accessToken,
   refreshToken, "Bearer", 3600)` flagged as a critical hardcoded
   secret - the exact same structural bug as the `SecretKeySpec`/
   `"HmacSHA256"` false positive fixed after batch 1, this time with
   `"Token"` (itself a credential keyword) as the constructor name and
   `"Bearer"` (a standard OAuth `token_type` value, RFC 6749) as the
   literal the reversed-argument scan picked up instead of the actual
   token values. Rather than add a second narrow allowlist,
   `_JCA_ALGORITHM_NAMES` was renamed and broadened to
   `_KNOWN_NON_SECRET_DESCRIPTOR_LITERALS`, now covering both JCA
   algorithm names and OAuth/HTTP auth-scheme names (`Bearer`, `Basic`,
   `Digest`, `MAC`) under one documented pattern: short, publicly-
   standard identifiers defined by a spec, never real secret material,
   regardless of which credential-shaped constructor they appear
   alongside. Verified against the real file that surfaced it (false
   positive gone, both genuine CWE-284 findings unaffected) and against
   a new regression test proving the generalization, not just the one
   new case.

2. **Every one of the 10 new projects again implements real, hand-
   rolled access control** (a header/API-key check against an
   externalized value), continuing the pattern from batch 2 on entirely
   new use cases - now 19 of 20 real protection mechanisms observed
   across three AI-generated batches are this shape, 1 is Spring
   Security. One project, `ai-payment-webhooks-service`, is the first
   asymmetric case in the dataset: its write endpoint verifies an
   HMAC-SHA256 signature over the payload (the correct, standard way to
   secure a webhook receiver, arguably better than a shared bearer key
   since it is tied to payload integrity), but its read endpoint has no
   gate at all and returns every stored raw webhook body - plausibly
   real payment/customer detail - to any caller. Labelled high, not
   medium: a well-designed write path does not offset a completely open
   read path leaking the actual event data. `ai-email-verification-
   service` is a second, more nuanced case than batch 2's
   `ai-password-reset-service`: reachable pre-auth by design (correct),
   but its 6-digit numeric verification code (900,000 possible values)
   has no rate-limiting anywhere, making it brute-forceable in a way
   the earlier 32-byte-token password-reset flow is not - labelled
   medium specifically for that reason, not just because a similar
   shape exists elsewhere.

3. **Added all 10, retrained, re-evaluated: 42 projects total (8 -> 15
   -> 22 -> 32 -> 42).** Leave-one-out accuracy is **0.595 (25/42)**;
   the fixed baseline is **0.381 (16/42)** - a wider margin than the
   previous entry's 0.531-vs-0.469. Broken down by batch, computed
   directly rather than assumed:
   - Original 22 (synthetic + first AI batch): baseline 15/22, LOO
     14/22 - Layer 4 is roughly at parity here, very slightly behind.
   - Batch 2 (10 projects): baseline 0/10, LOO 5/10 (up from 3/10 in
     the previous entry - more supporting examples of the same pattern
     improved LOO's prediction of these previously-seen-shape
     projects).
   - **Batch 3 (10 new projects, indices 32-41): baseline 1/10, LOO
     6/10.** This is the entry's central result: batch 3 was not used
     to design or motivate `has_sensitive_domain_signal` the way batch
     2 was, and the edge held up anyway on genuinely new use cases. The
     model's advantage is not an artifact of the specific batch that
     produced it.

**Regression tests updated:** `tests/test_layer4_ml.py` -
`test_real_layer4_dataset_loads_and_leave_one_out_evaluates` updated to
the real 42-project confusion matrix;
`test_real_layer4_dataset_leave_one_out_now_beats_baseline_with_a_caveat`
replaced with
`test_real_layer4_dataset_leave_one_out_beats_baseline_on_held_out_batch`,
which asserts the per-batch correct-count breakdown directly (15/22,
0->5/10, 1->6/10), not just the aggregate figures, so the held-out-
generalization claim is enforced by the test suite, not just stated in
this log; `test_real_layer4_dataset_baseline_predictions_smoke` updated
to 42. `tests/test_cwe_798.py` gained
`test_detect_in_java_does_not_flag_oauth_bearer_token_type`, proving
the generalized fix on the new case. `tests/test_evaluation.py` and
`tests/test_thesis_orchestrator.py` updated everywhere they had
32-project/0.531/0.469 values hardcoded against the real committed
dataset/contract.

**Tests/adversarial checks run:**
- Full `pytest -q`: `280 passed` (was 279), clean exit.
- `mypy .` / `ruff check .` / `black --check .` / `git diff --check`:
  all clean.
- Every finding for all 10 new projects verified against the actual
  generated source by hand before labelling, including reading each
  hand-rolled gate function directly to confirm it actually restricts
  the endpoint (not assumed from a docstring or comment).
- `ai-oauth-refresh-service` re-scanned post-fix: the "Bearer" false
  positive is gone, both genuine CWE-284 findings unaffected.
- `evaluation.evaluate` re-run against the regenerated 42-project
  contract; the 0.595/0.381 figures and the per-batch 15/22, 5/10, 6/10
  splits were read directly from computed output.

**Remaining limitations:** 42 of the thesis's stated 50 sample apps are
now in place. `_KNOWN_NON_SECRET_DESCRIPTOR_LITERALS` is still a
curated, non-exhaustive list - a third structurally-identical false
positive in a different vocabulary (neither JCA nor OAuth/HTTP) would
still need its own addition, though the pattern for recognizing and
fixing one is now established. The dataset's label distribution has
become heavily medium-weighted in this batch (7 of 10) - an honest
reflection of what was actually found (most of these real, hand-rolled
protections cluster around similar real-world severity), but worth
naming as a distribution skew for the next batch to correct if broader
label diversity is wanted again.

**Why:** Held-out validation - deliberately not reusing batch 2's
shapes for batch 3 - was the point of this batch, not an afterthought:
a result that only holds on the data that produced it is a much weaker
claim than one that holds on data that did not. The CWE-798 fix was
generalized rather than patched narrowly a second time because this
project's own established practice (extract/generalize on the second
real occurrence, not the first) applies exactly as well to a detection-
rule false positive as it does to a shared utility module.

**Effect on thesis chapters:** Chapter 5 gets its strongest Layer 4
result yet, and the per-batch breakdown is the evidence that makes it
credible rather than a single aggregate number: report all three rows
(original mix roughly at parity, batch 2 improved with more support,
batch 3 held out and still ahead), not just the 0.595-vs-0.381 headline.
Chapter 5 should also report the `ai-payment-webhooks-service` finding
as a concrete illustration that a per-project risk label is a
simplification - this project's two findings have genuinely different
real severity, which the current one-label-per-project schema cannot
represent, worth naming explicitly as a modelling-granularity
limitation rather than leaving implicit. Chapter 4 should describe
`_KNOWN_NON_SECRET_DESCRIPTOR_LITERALS`'s generalization as an example
of this project's iterative, evidence-driven hardening process applied
to itself, not just to detection rules discovered once. Chapter 3
should note the dataset stands at 42 of 50, with 8 remaining.

---

## [2026-09-04] - Fourth batch (8 apps, dataset reaches the stated 50): a deliberate stress-test batch found Layer 4's edge is not universal; a severity-floor fix was tried and reverted for making things worse; a new Layer 1 CWE-287 detector was built instead and measurably helps without any collateral damage

**What the plan said:** With the dataset at 42 of the thesis's stated 50,
the student chose to spend the final batch specifically stress-testing
the previous entry's "held-out generalization" result, rather than
simply padding the count: 4 apps in sensitive-vocabulary domains
(employee profile, user consent, account recovery, admin report
export) and 4 in boring-vocabulary domains (product reviews, shipping
labels, newsletter, inventory adjustment) that do not trip
`has_sensitive_domain_signal`'s keyword list at all - chosen so a
correct answer would require reasoning past the domain-name shortcut in
either direction.

**What we actually did / found:**

1. **The stress test did not produce what it was designed to test, and
   that turned out to be more informative than if it had.** The design
   assumed at least some of the sensitive-vocabulary apps would ship
   with real (if hand-rolled) protection, the way ~19/20 of batches 1-3
   did. None of the 8 did - every one of the 8 shipped with zero access
   control on its sensitive endpoints, including `ai-admin-report-
   export-service`, whose prompt explicitly said "admin-only" and whose
   generated code ignored that requirement outright. Each project's
   findings and label rationale were written by hand-reading the actual
   generated source, per this project's established post-hoc labelling
   discipline - not assumed from the prompt.

2. **One of the 8, `ai-account-recovery-service`, is a genuine full
   account-takeover bug, not just a missing annotation.** Its
   `request(email)` endpoint takes only an email address (no proof of
   ownership) and returns the freshly generated recovery token directly
   in the HTTP response body, instead of delivering it out-of-band
   (e.g. email); `complete(token, newCredential)` then has no
   authentication either. Net effect: anyone who knows or guesses a
   user's email can obtain a working recovery token and set a new
   credential in the same request chain. Labelled critical. Because all
   8 apps happen to share a near-identical shape of finding (2-3
   CWE-284 "missing annotation" findings, nothing else), this batch
   became an unplanned but sharp natural experiment: 4 projects with
   `has_sensitive_domain_signal=1` and near-identical true severity to
   4 projects with the signal off.

3. **Added all 8, retrained: 50 projects total (8 -> 15 -> 22 -> 32 ->
   42 -> 50 - the thesis's full stated target reached).** Leave-one-out
   accuracy is 0.58 (29/50), the fixed baseline is 0.40 (20/50) - Layer
   4 still wins in aggregate. But the honest per-batch breakdown
   reverses on this batch specifically: baseline 4/8 correct vs.
   leave-one-out 2/8. Most strikingly, leave-one-out predicted the
   account-recovery critical bug as "low" - not a near-miss, the single
   worst finding in the entire dataset scored at the bottom of the
   scale. The batch-2/3 "held-out generalization" claim from the
   previous entry needs narrowing, not retracting: Layer 4's edge holds
   on the sensitive-domain-with-hand-rolled-auth pattern those batches
   exercise, but breaks down on this batch's low-finding-count/high-
   severity-per-finding profile, which the feature vector genuinely
   cannot distinguish from a well-protected project - two projects with
   identical features and opposite true risk is a feature collision, not
   a training problem, and no amount of retraining fixes that on its
   own.

4. **A severity-floor fix was designed, built, tested, and reverted -
   not shipped.** The idea: never let Layer 4's predicted label fall
   below the severity of the single worst individual Layer 3 finding
   (`predict_project_risk` in `vibeguard/layer4_ml/predictor.py`,
   implemented with a `_severity_floor_label` helper and a
   `floor_applied` field on `MLPrediction`). Directly measured against
   the full 50-project leave-one-out evaluation before deciding whether
   to keep it: accuracy dropped from 0.58 to 0.40, identical to the
   baseline's own accuracy, because CWE-284's "missing annotation"
   finding is scored "high" uniformly regardless of context, and the
   floor forced nearly every project with any CWE-284 finding - which
   is most of the dataset, including many correctly-labelled "low"/
   "medium" projects with real hand-rolled protection invisible to that
   rule - up to "high" or above. The floor did not fix the one bad case
   without erasing Layer 4's value everywhere else; it just re-
   implemented the baseline under a different name. Reverted via `git
   checkout` before any commit. Logged here specifically so a later
   session does not re-attempt the same idea blind.

5. **Built a real, tested Layer 1 detector instead:
   `cwe_287.py`'s new `_check_unguarded_secret_return` /
   `_check_tree_sitter_unguarded_secret_return`.** Flags an endpoint
   method that generates or looks up a credential-shaped value (name-
   matched via the existing shared `_credential_names.py` heuristic)
   and returns it unconditionally, with neither a preceding hand-
   written `if` guard in the method body (tracked by AST list order,
   not source line - these Codex-generated files put an entire class on
   one line, so line numbers cannot distinguish "before" from "after")
   nor a framework authorization annotation (`@PreAuthorize` etc. -
   its annotation set extracted into a new shared
   `_authorization_annotations.py` module, following this project's
   established "extract on the second real need" practice, now used by
   both `cwe_284.py` and `cwe_287.py`). Deliberately narrower than a
   bare "any credential-shaped identifier in the return" match: only a
   bare variable/field *value* reference counts, not a credential-named
   *method call* (`_credential_value_reference` excludes
   `MethodInvocation`; the Tree-sitter path's
   `_is_call_qualifier_or_name` excludes an identifier used as a call's
   object/name) - a real false positive was found and fixed during
   testing, where the sibling `complete(Complete complete)` endpoint's
   `complete.token()` (validating an incoming token, not returning a
   freshly issued one) was initially caught by a too-broad first draft
   of the Tree-sitter matcher.

**Tests/adversarial checks run:**
- Full `pytest -q`: `288 passed` (was 279 before this entry's work).
- `mypy .` / `ruff check .` / `black --check .` / `git diff --check`:
  all clean.
- 9 new unit tests in `tests/test_cwe_287.py` covering: the real
  vulnerable shape; guarded-by-if; guarded-by-annotation; a token
  generated but never returned (the real `ai-password-reset-service`
  shape); the `complete.token()` method-call false positive found and
  fixed; a non-endpoint method (unreachable, correctly not flagged);
  and both the flagging and non-flagging cases again on the Tree-sitter
  fallback path (required - `tests/test_java_rule_fallback_coverage.py`
  enforces dual-parser support for every Java rule module).
- Ran the new detector against the *entire* 50-project labelled
  dataset (not just the motivating case): exactly one new finding
  anywhere - `ai-account-recovery-service`'s `request` method - zero
  new findings, zero false positives, on the other 49 projects,
  including the batch-2/3 "well protected" ones whose CWE-284 findings
  this detector could plausibly have also mismatched.
- Ran it against both real, independently-maintained repositories
  under `.qa-repos/` (155 non-test Java files across
  `spring-petclinic-rest` and `quarkus-super-heroes`, via the real
  `scanner.py` entry point, not a raw glob): zero findings, zero
  crashes.
- Found and ruled out of scope: an unrelated, pre-existing crash in
  `ast_parser.py`'s Tree-sitter fallback path (`_build_tree_sitter_
  parsed_file`, a `TypeError` in `node_text`), reproducible only by
  bypassing `scanner.py`'s own `target/` build-output exclusion via a
  raw `rglob` (real `scan_directory()` never reaches the file that
  triggers it) and only when parsing ~278 files in one long-running
  process, not in isolation - confirmed present with this session's
  changes fully reverted (`git stash`), i.e. genuinely pre-existing,
  not introduced by this work. Not fixed here: out of this task's
  scope, and does not affect real scanning through the normal CLI path.
  Logged as a candidate item for a future Layer 1 robustness pass.
- `ai-account-recovery-service`'s dataset entry updated with the new
  CWE-287 finding (verified against the actual regenerated scan
  output, not hand-typed) and its `label_rationale` extended to explain
  the detector; contract regenerated and confirmed
  `training_example_count: 50`.
- Isolated exactly what changed in the full 50-project leave-one-out
  evaluation by diffing against a temporary contract built from a copy
  of the dataset with only the new CWE-287 finding removed: **exactly
  one prediction changed anywhere in the dataset** -
  `ai-account-recovery-service` moved from predicted "low" to predicted
  "medium" (true label: critical) - every other one of the 50
  leave-one-out predictions is byte-identical before and after. Real,
  measurable, narrowly-targeted improvement with zero side effects,
  not a full fix (still under-predicts relative to the true "critical"
  label) and not a coincidence (isolated and measured directly, not
  assumed from the aggregate number, which is unchanged at 0.58 since
  a wrong-to-less-wrong move doesn't cross an accuracy threshold on its
  own).
- Ran the real CLI (`main.py`) against `ai-account-recovery-service`
  end-to-end post-fix: the *in-sample* model (the one `main.py` and
  real end users actually use, trained on the full 50-project dataset
  including this project) now predicts **critical** with 0.684
  confidence, and Layer 5's SHAP breakdown shows `cwe_287_count` as the
  single largest positive contributor (+0.173) - the new detector is
  not just present in the dataset, it is the dominant signal driving
  the correct in-sample prediction. The more conservative leave-one-out
  number (medium, not critical) is the honest generalization estimate
  for an unseen project of this exact shape, not a contradiction of the
  in-sample result.

**Remaining limitations:** `_check_unguarded_secret_return` is method-
level only, unlike `cwe_284.py`'s method-or-enclosing-class check - a
class-wide authorization annotation with no method-level guard and a
freshly-issued secret is a narrower, unobserved-so-far edge case,
deliberately not built speculatively (see the module docstring). The
detector only recognises a bare bare variable/field reference flowing
into the return statement, not deeper data-flow (e.g. a token passed
through an intermediate builder or wrapper method before being
returned) - consistent with every other rule in this codebase's
name/shape-based, not full-dataflow, approach. Leave-one-out still
under-predicts the account-recovery project relative to its true
"critical" label (now "medium", not "low") - the new finding gives the
model real signal, but with only one example of this exact pattern in
the training set, leave-one-out (which excludes that one example from
its own training fold) cannot yet learn to weight it as strongly as
the in-sample model does. The pre-existing `ast_parser.py` Tree-sitter
crash found during real-repo testing (see above) remains open, logged
as a candidate future Layer 1 item, not fixed in this entry.

**Why:** The student's explicit instruction after seeing the account-
recovery miss was "we need to fix this and we can do it" - not to
document the limitation and move on. The floor-rule fix was tried
first because it looked cheap and general; it was reverted, not
shipped, the moment the full-dataset leave-one-out measurement showed
it made the tool worse, not better - a decision made from measured
evidence, not intuition, consistent with this project's standing
practice of computing exact numbers before trusting a change. The
CWE-287 detector was built afterward specifically because the floor's
failure diagnosed *why* a blunt fix couldn't work here (Layer 3's
CWE-284 severity is uniformly noisy) and pointed at what a real fix
needed: genuinely new information Layer 1 wasn't extracting yet, not a
different way of weighting the same information.

**Effect on thesis chapters:** Chapter 3: the dataset is complete at
50 of 50 stated sample apps. Chapter 4 should document
`_check_unguarded_secret_return` as a second real CWE-287 pattern
(alongside the existing `==`/`!=` comparison check) and should
document the severity-floor attempt and its revert as a worked example
of this project's "measure before shipping" discipline - a fix that
looks obviously correct until it is actually measured against the
full dataset is a legitimate, citable methodology point, not something
to omit because it didn't ship. Chapter 5 needs the fullest, most
nuanced Layer 4 result of the whole project: report all four per-batch
rows (original mix at parity, batch 2 and 3 favouring Layer 4, batch 4
favouring the baseline), the account-recovery critical-miss as a
concrete illustrated failure case, and the in-sample-vs-leave-one-out
distinction the CLI run surfaced (dominant SHAP signal in-sample,
partial-not-complete improvement under the stricter held-out estimate)
as an explicit, honest discussion of what "the model works" can and
cannot mean with a labelled dataset this size. This is a stronger,
more defensible chapter than a single clean win would have been.

---

## [2026-09-04] - Two more real, independently-maintained repositories added to `.qa-repos/`: the new CWE-287 detector validated itself independently on OWASP WebGoat; two more real Layer 1 gaps found and fixed, same shape as previous ones

**What the plan said:** With the labelled dataset at its full stated
target (50/50) and the CWE-287 fix from earlier today logged, the
highest-value remaining work per this file's own Section 7 build order
is more real-repo QA, not more synthetic/Codex apps - only two real
repositories had ever been scanned. The student was offered a choice
between a repo that would stress precision (another well-built
reference app, same character as the two already tested) and one that
would stress recall for the first time (a repo with known, documented,
planted vulnerabilities to check findings against, not just "does it
crash or false-positive"); the student chose both.

**What we actually did / found:**

1. **Added `.qa-repos/spring-boot-realworld-example-app-20260904`**
   (`gothinkster/spring-boot-realworld-example-app`, the official
   RealWorld API spec reference backend - real JWT auth, DDD, CRUD) and
   `.qa-repos/webgoat-20260904` (`WebGoat/WebGoat`, OWASP's official
   deliberately-vulnerable teaching application), both shallow clones,
   matching the existing two repos' naming/depth convention. VibeGuard
   only ever parses Java source text into an AST - scanning WebGoat's
   source is exactly as safe as scanning any other repository; nothing
   in this pass ever executed or ran either application.

2. **The new CWE-287 unguarded-secret-return detector (built earlier
   today from exactly one observed case) validated itself
   independently: 5/5 findings on WebGoat are genuine, correctly-
   identified, deliberately-planted vulnerability lessons it had never
   seen before** - a JWT secret leaked via `JWTSecretKeyEndpoint`, a
   password salt returned from the "Missing Function Level Access
   Control" lesson, a leaked API key from the Spring Boot Actuator-
   misconfiguration lesson, and two JWT encode/decode helpers in the
   WebWolf companion app. Zero manual tuning for WebGoat specifically.
   WebGoat scanned cleanly (319/319 Java files parsed, no crashes) and
   VibeGuard correctly rated the whole project **critical** at 0.843
   confidence.

3. **A genuine CWE-798 true positive on the RealWorld app**: a real,
   high-entropy JWT signing secret
   (`jwt.secret=nRvyYC4...`) committed directly in
   `application.properties` in a real, public, actively-maintained
   repository - further validation of CWE-798 on real code, not a
   synthetic fixture.

4. **Found and fixed: CWE-284's centralized-authorization detector was
   blind to the older `WebSecurityConfigurerAdapter` Spring Security
   style.** The RealWorld app's `WebSecurityConfig` extends
   `WebSecurityConfigurerAdapter` and overrides a void-returning
   `configure(HttpSecurity http)` method - not a bean method returning
   `SecurityFilterChain`, the only shape
   `has_centralized_authorization_rule` recognized (added
   2026-09-02 after a different real-repo finding on
   spring-petclinic-rest). The override contains the exact same
   `.anyRequest().authenticated()` blanket rule the existing detector
   already knows how to recognize once it looks at the right method -
   this is a real, working, application-wide auth policy invisible to
   CWE-284's annotation-only scan, same shape of gap as before, just a
   different (older, still extremely common - it wasn't deprecated
   until Spring Security 5.7 and not removed until 6.0) Spring Security
   API generation. Fixed in both `has_centralized_authorization_rule`
   (javalang) and `_has_centralized_rule_tree_sitter`: a method now
   also counts as a plausible centralized-authorization site if it is
   named `configure` with a single `HttpSecurity`-typed parameter
   (`_is_legacy_web_security_configure_method` /
   `_is_tree_sitter_centralizing_method`), matched by signature alone
   (not by verifying the enclosing class actually extends
   `WebSecurityConfigurerAdapter`) - the same coarse, name/shape-based
   precision the rest of this module already uses, and unambiguous
   enough in practice given how specific that exact signature is.
   `_CENTRALIZED_AUTH_CAVEAT`'s wording updated from naming only
   "SecurityFilterChain" to covering both styles, since it was now
   factually incomplete. Verified against the real file: all 19 of the
   RealWorld app's CWE-284 findings now correctly carry the caveat
   (0 of 19 did before).

5. **Found and fixed: `scanner.py`'s test-root exclusion didn't
   recognize `src/it/`**, Maven Failsafe's standard integration-test
   source root (distinct from `src/test/`, which was already handled).
   WebGoat uses this convention for its integration tests; 14 of 241
   findings (5.8%) were integration-test fixture literals (e.g. a
   login form field literally named/valued `"password"` in test code)
   being scanned as production credentials. `"it"` added to
   `_TEST_DIR_NAMES`, carrying the exact same narrow, two-location
   protection already relied on for `"test"`/`"tests"` (only a
   top-level `src/it/` or `<root>/it/` is excluded; a package segment
   named `"it"` nested deeper in the tree is left alone) - the same
   false-exclusion risk this module's own docstring already documents
   for `"test"`, extended consistently rather than re-litigated.
   Verified against the real file: WebGoat's finding count dropped from
   241 to 227 (exactly the 14 `src/it/` findings gone), and its
   critical-severity count dropped from 32 to 18 (test-fixture
   `"password"`-named literals no longer counted) - the project's
   overall risk verdict is unaffected (still correctly critical), only
   the noise is gone.

**Tests/adversarial checks run:**
- Full `pytest -q`: `293 passed` (was 288). `mypy .` / `ruff check .` /
  `black --check .` / `git diff --check`: all clean.
- 3 new tests for the legacy-`configure` detection
  (`tests/test_cwe_284.py`): the real vulnerable-looking shape (which
  is actually a real *protection*, correctly recognized), a negative
  case (`configure(String name)` - a same-named method with a
  different signature, must not match), and the Tree-sitter fallback
  path. All 26 `test_cwe_284.py` tests pass, including the 23 that
  predate today - no regression in the annotation-based detection this
  extends.
- 2 new tests for the `src/it/` exclusion (`tests/test_scanner.py`),
  mirroring the existing `test`/`tests` tests exactly: the exclusion
  itself, and the matching false-exclusion guard (a production package
  literally named `it` nested deeper in the tree must still be
  scanned). All 16 `test_scanner.py` tests pass.
- Re-ran both fixes against the real files that motivated them (not
  just the unit tests): confirmed above in items 4 and 5.
- **A reproducible-but-out-of-scope finding**: an ad-hoc diagnostic
  Python one-liner that calls `cwe_284`/`cwe_287`/`cwe_798`/`cwe_20`
  directly over WebGoat's ~400 files in one long-running process
  crashes (`exit 139`, native segfault) - but the real, user-facing
  paths do not: `main.py`'s actual scan of the same repository
  succeeded cleanly (twice, verified before and after these fixes),
  and the full `pytest` suite (which exercises every rule module
  extensively) passes cleanly with no crash. Bisected with `git
  stash`: reproduces with the scanner.py `src/it/` change alone, and
  also reproduces with all of today's changes fully reverted back to
  this file's previous 2026-09-04 entry's committed state - i.e. it is
  not caused by any of today's logic changes, only newly *encountered*
  because excluding 14 files shifts which file lands in whatever
  process-state-dependent position triggers it. Same character as the
  pre-existing Tree-sitter-fallback crash already found and logged
  earlier today (reproducible only in a specific position within a
  long single-process batch, never in isolation, never through a real
  entry point) - not re-investigated further for the same reason: out
  of this task's scope, and does not affect real scanning through
  `main.py` or the test suite.

**Remaining limitations:** The legacy-`configure` detection is
signature-only, same documented imprecision as the rest of this
module - a coincidentally-named `configure(HttpSecurity http)` method
that is not actually a Spring Security override would also match,
though this is a vanishingly unlikely false positive given how
specific that exact signature is in practice. The `src/it/` exclusion
inherits the same narrow false-exclusion risk already accepted for
`test`/`tests`. Both real-repo QA passes (this one and the earlier
spring-petclinic-rest/quarkus-super-heroes one) still only cover 4
repositories total - real-world coverage remains thin relative to the
labelled dataset's 50 controlled/AI-generated projects, and more of it
is still the highest-value remaining evaluation work per Section 7.
The two long-running-process crashes found across today's real-repo
QA (this entry and the earlier one) remain open, unfixed, logged as
candidate future Layer 1 robustness items - real, but not user-facing
through any currently-shipped entry point.

**Why:** The student's direction was explicit ("fix both") once both
gaps were reported with their evidence - both fixes are small,
low-risk extensions of an already-established, already-successful
pattern (this is the *third* time `has_centralized_authorization_rule`
has needed broadening for a differently-styled real Spring Security
config, and the *second* time the test-root exclusion has needed a
new conventional name), not novel design work, which is why they were
built and shipped in the same session rather than only logged as
limitations the way the larger, riskier CWE-1035/OpenAPI-codegen gaps
were deliberately left for later.

**Effect on thesis chapters:** Chapter 5 gets a second real-repo QA
round with a genuinely different, stronger character than the first:
the first round mostly answered "does it crash or false-positive on
real code," while this round is the project's first real recall check
against an authoritative corpus of *known* vulnerabilities (WebGoat),
and the CWE-287 detector's 5-for-5 result on lessons it was never
tuned against is a strong, citable, independent validation point -
built from one synthetic example, generalized correctly to real,
unrelated, deliberately-planted vulnerabilities. Chapter 4 should note
`has_centralized_authorization_rule` has now been broadened three
times by real-repo findings (SecurityFilterChain, then this legacy
`configure` style) and `_TEST_DIR_NAMES` twice (`test`/`tests`, then
`it`) - a pattern of the same kind of gap recurring across different
real codebases, worth naming explicitly as evidence that "scan more
real repositories" is not a one-time evaluation step but a genuinely
open-ended source of real findings. Chapter 3 should list all four
`.qa-repos/` targets and their distinct roles (two general reference
apps for false-positive/precision testing, RealWorld for
auth-pattern-diversity testing, WebGoat for recall against known
ground truth).

---

## [2026-09-08] - Full-project execution pass fixes combined thesis artifact failures

**What the plan said:** Run the current project end to end, preserve existing
work and the approved five-layer design, and fix confirmed operational blockers.
The working tree already contained uncommitted Layer 1 rules, dataset, sample-app,
test, and log changes on arrival; those were retained. No detection methodology,
training labels, scoring policy, parser strategy, or dependencies changed in this
pass.

**What we actually did / found:** The initial suite passed all 293 tests and
static gates, but a real `python -m evaluation.thesis_orchestrator` invocation
failed while writing the combined manifest. The evaluation bundle path was
resolved to an absolute path, while the run directory retained either a relative
path or macOS's `/var` alias for `/private/var`. Consequently, `relative_to()`
failed for the default relative output directory and for aliased absolute paths.
The orchestrator now resolves its output root before creating any artifacts.

Two related evaluation-workflow defects were also reproduced and corrected:
- All three evaluation entrypoints parsed actual CLI arguments correctly but
  recorded an empty argument list when called through `main()` without an
  explicit list. They now record `sys.argv[1:]` in that case, preserving explicit
  argument-list behavior.
- The combined scan caught only `ValueError` from model/SHAP reporting, whereas
  `main.py` already handled general reporting exceptions. An injected SHAP
  `RuntimeError` escaped and prevented artifact capture. The combined scan now
  uses the same exception boundary, retains findings and scores in JSON, and
  records a controlled error with scan exit code 1 and no project-risk report.

README instructions now cover the full scanner, combined artifact command,
evaluation command, verification gates, and the distinction between scan exit
status and successful evidence capture.

**Tests/adversarial checks run:**
- Reproduction tests failed before the fixes: 6 failed, 2 passed. They covered
  absolute/relative/symlinked output paths, actual `sys.argv` handling, and an
  injected SHAP runtime failure with existing findings to preserve.
- The same targeted regression selection passed after the fixes: 8 passed.
- Final full suite: **296 passed in 61.30 seconds**, clean exit code 0.
- `mypy .`, `ruff check .`, `black --check .`, and `git diff --check`: clean.
  Python 3.10.13; `pip check`: no broken requirements. No new CVE audit was run.
- Rescanned all 50 labelled projects: 174 supported files, 99 candidate findings,
  zero parse failures or rejected paths. Every project's finding trace keys and
  rule scores matched its stored training example. All 50 SHAP baseline-plus-
  contribution sums reconstructed the predicted probability within 1e-6.
- Ran the real CLI and structured scan path against all four local QA checkouts:
  555 supported files, zero parse failures/rejected paths, no runtime errors;
  5 candidates on Quarkus Super Heroes, 20 on RealWorld, 1 on Petclinic, and
  227 on WebGoat. These are execution checks and candidate counts, not a fresh
  manual precision/recall adjudication. Exact checkout commits are recorded in
  `dist/full-project-qa-20260908/real-repo-results.json`.
- Real combined CLI runs succeeded after the fix with both relative output and
  the macOS `/var` alias. Verified artifact inventory and relative references.
  The account-recovery sample produced 3 candidates and an in-sample critical
  prediction at approximately 0.684 confidence. Its complete scan/evaluation
  bundle is under `dist/thesis_artifacts/vibeguard-thesis-run-20260908-173848/`.

**Remaining limitations:** Current 50-project evaluation remains 0.70 in-sample
accuracy, 0.58 leave-one-out accuracy (macro-F1 0.498148), and 0.40 fixed-baseline
accuracy (macro-F1 0.422582). Working execution does not establish reliable
generalization. Previously documented annotation/data-flow and dependency-
resolution limits remain. The previously logged long-process native parser
failures were not encountered in these runs and are not claimed fixed.
AGENTS.md/CLAUDE.md still describe a 15-project dataset and two QA repositories;
the current dataset/log describe 50 and four. Their historical overview needs
synchronization in a documentation pass. Evidence under `dist/` is local and
ignored by Git.

**Why:** Existing tests exercised explicit Python argument lists and canonical
absolute temporary paths, so they missed failures of the real shell invocation.
The fixes restore the existing artifact contract without changing the analysis
pipeline or interpreting candidate findings as confirmed vulnerabilities.

**Effect on thesis chapters:** Chapter 4 can use the README's working combined
command. Chapter 5 can cite the current measured results and artifact provenance,
while retaining the limits above. No methodology change is introduced.

**Freeze / handoff:** Layers 1-5 were not reopened by these evaluation-wrapper
fixes. Recommend a fresh session run adversarial QA against the evaluation
workflow changes before treating this repair scope as frozen. After that review,
continue the independently adjudicated real-repository evaluation track.

---

## [2026-09-09] - Blind human-rater baseline added as a fourth evaluation signal alongside ground truth, Layer 4, and Layer 3

**What the plan said:** Section 7's stated next work was continuing
precision/recall evaluation against real, independently-maintained
repositories. Separately from that track, the student ran a "Blind Risk
Review" survey outside this codebase: 3 raters, each shown only a
natural-language description of one project's endpoint/config behavior
(no source code, no CWE labels), rating overall risk Low/Medium/High/
Critical across 20 cases. The stated purpose was to get an independent
human signal on what should count as "critical" or not, to complement
the project's own single-rater ground-truth labels - not to replace or
retrain against them.

**What we actually did / found:**

1. **Hand-mapped all 20 anonymized case descriptions to real projects**,
   verified by exact route-string and config-literal matches rather than
   inference (e.g. Case 14's quoted `gateway.upstream.apikey=sk-live-
   gw-9f8e7d` is a literal, verbatim match against `multi-issue-gateway-
   service/application.properties`). 15 cases map to `data/sample_apps/
   ai-*` projects, 5 to `data/sample_apps/layer4_training/*` (the
   original controlled Layer 4 training set) - the survey was drawn from
   both dataset generations, not just the newest batch.

2. **Built `evaluation/human_baseline.py`**, following `evaluation/
   evaluate.py`'s existing shape (dataclasses, rich console tables,
   optional `--json-out`). It re-runs the existing frozen Layer 1-5
   pipeline unchanged on each mapped project and reports agreement
   between the human median rating and three VibeGuard-side signals:
   the committed dataset's ground-truth label, Layer 4's ML prediction,
   and Layer 3's raw maximum rule-based finding severity. No detection
   rule, scoring weight, or ML code was touched. Full pytest suite: 300
   passed (up from 296 in the prior entry - 4 new tests added for this
   module). `black`, `ruff`, `mypy` (strict): clean on the new files.

3. **Quantitative result** (n=20 cases, n=3 raters - both small; stated
   plainly, not smoothed over):

   | Signal | Exact match vs. human median | Within 1 level | Mean signed distance |
   |---|---|---|---|
   | Ground-truth label (this project's manual labels) | 5/20 (25%) | 18/20 (90%) | +0.35 |
   | Layer 4 ML predicted label | 7/20 (35%) | 18/20 (90%) | -0.15 |
   | Layer 3 raw max rule severity | 6/19 (32%, 1 project had no findings) | 15/19 (79%) | +0.68 |

   Human inter-rater agreement itself: exact 3-way agreement on only
   3/20 cases, within-1-level on 16/20, mean spread 1.15 of 3 ordinal
   levels - the humans disagreed with each other on this scale about as
   often as any signal disagreed with their median, which bounds how
   much weight any single number above should carry.

4. **The clearest pattern: Layer 3's raw severity over-flags "High" on
   exactly the hand-rolled-auth projects this project already knows
   about and already corrects for.** Cases 08 (`ai-card-storage-
   service`), 10 (`ai-api-key-service`), 11 (`ai-oauth-refresh-
   service`), and 19 (`ai-password-reset-service`) - all of which use
   the header/API-key-vs-configured-value or hashed-token pattern
   documented as CWE-284's dominant real-world blind spot in the
   2026-09-02 and 2026-09-03 entries - got a raw Layer 3 "High" in every
   case, while independent blind humans rated 3 of the 4 uniformly
   "Low" (case 11's raters: Low/Low/Low; case 19's: Low/Low/Low; case
   08's: Low/Low/Low; case 10's median: Low). This is not a new
   discovery - it corroborates, via a channel with no visibility into
   this project's source or prior reasoning, a limitation already
   identified and already the reason this project's ground-truth labels
   are hand-corrected rather than taken from raw rule severity.

5. **One new, specific observation: Case 17 (`ai-admin-report-export-
   service`) is Layer 4's worst miss in this set.** Ground truth "high",
   Layer 3 max severity "high", human median "medium" - all three point
   the same direction - but Layer 4 predicts "low". Not investigated
   further in this pass; flagged as a candidate for the ongoing
   real-repository evaluation track rather than grounds to reopen the
   frozen Layer 4 module on an n=1 disagreement.

6. **One case where VibeGuard's judgment plausibly exceeds the human
   raters':** Case 16 (`runnable-ai-orders-service`), the only project
   in the whole labelled dataset secured by real Spring Security (HTTP
   Basic required on every endpoint). Ground truth and Layer 4 both say
   "low"; 2 of 3 human raters said "medium", plausibly reacting to the
   case description's literal mention that "cross-site request forgery
   protection [is] disabled" without the context that CSRF protection is
   not meaningful for a non-cookie, stateless Basic-auth JSON API. Not
   a tool defect - a reminder that a blind human baseline is itself
   noisy in the opposite direction on specifics it lacks context for.

7. **Committed data was de-identified before being added to a
   public-release-intended repository.** One respondent submitted a
   full name; `data/labeled/human_baseline_survey.csv` replaces all
   three respondents' names/initials with `Rater 1`/`Rater 2`/`Rater 3`
   (ordered by submission time) before being committed. The original
   export is not part of this repository.

**Why:** The student's stated goal was an independent check on the
project's own notion of "critical", separate from and not derived from
this codebase's existing labels or rules. Building it as a real
evaluation module (rather than a one-off script) makes the comparison
reproducible and re-runnable as more survey responses arrive, and
keeps it consistent with how `evaluation/evaluate.py` already wraps the
Layer 4 contract for thesis reporting.

**Effect on thesis chapters:** Chapter 4/5 gains a genuine independent
human baseline, not just ground-truth-vs-prediction metrics computed
from labels this project itself assigned. It also gives Chapter 5 a
concrete, quantified illustration of *why* this project's ground-truth
labels are hand-corrected rather than taken directly from raw Layer 3
severity: independent blind humans track the corrected labels
(exact-match 25-35%, within-one 90%) better than they track raw rule
severity (exact-match 32%, within-one 79%) on this sample. No change to
Chapters 1-3's locked design decisions.

**Freeze / handoff:** No frozen layer (1-5) was reopened; this is purely
a new evaluation-track addition, same category as `evaluation/
evaluate.py`. Recommend, as with the prior entry's own evaluation-
wrapper changes: a fresh session should adversarially review
`evaluation/human_baseline.py` (CSV parsing edge cases, the hand-built
case-to-project map, the ordinal-distance math) before this specific
module is treated as settled. Only 3 of a presumably larger distribution
list have responded as of this entry (submitted 2026-09-04 to
2026-09-06); whether to wait for more responses before citing this in
the thesis narrative, or use it as-is with the small-n caveat stated
above, is the student's call. Case 17's Layer 4 miss is a candidate data
point for the ongoing real-repository evaluation track, not
independently actioned here.

---

## [2026-09-10] - CWE-284 extended with a per-method hand-rolled-authorization caveat, targeting the dominant blind-spot pattern the human-baseline comparison just confirmed

**What the plan said:** The previous entry's human-baseline comparison
flagged four candidate fixes for known limitations. Reviewed together
with the student, three were judged either architecturally locked
(CWE-1035's offline-only scope, per Section 3's no-network-calls
constraint), not yet warranted by a concrete observed case (deeper
dataflow tracing), or bigger than a quick fix (the Tree-sitter native
crash, investigated further below but not resolved). The fourth -
extending CWE-284's centralized-authorization caveat mechanism to also
cover the hand-rolled header/API-key pattern - was scoped and approved
for this session.

**What we actually did / found:**

1. **Investigated the Tree-sitter crash further before setting it aside.**
   Reproduced it directly (a raw multi-repo `rglob` across all four
   `.qa-repos/`, bypassing `scanner.py`'s own exclusions, the same way
   the original finding did): a genuine `SIGSEGV` (exit 139), not a
   catchable Python exception. Ruled out the two cheapest explanations
   before stopping: the specific file that crashed
   (`UserInterceptor.java`) parses correctly in isolation, and 200
   repeated parses of that same file in one process never crash: it is
   not the file. Patching `_tree_sitter_java.py` in-memory to build a
   fresh `Parser`/`Language` per call instead of reusing the
   module-level singleton pushed the crash later in the run but did
   **not** eliminate it - ruling out simple parser-object reuse as the
   sole cause too. What is left points at something inside the
   `tree-sitter`/`tree-sitter-java` 0.26.0/0.23.5 Python binding itself,
   accumulating native state across many *distinct* ASTs in one
   long-running process. A Python `try/except` cannot catch a segfault
   at all, so the only real structural fix (isolating each file's parse
   in its own subprocess, extending `_parsing_guards.py`'s existing
   hang-timeout philosophy to native crashes) is a genuine architecture
   change, not a patch. Confirmed once more that the real CLI path
   (`scanner.py`) never reaches the file volume/variety that triggers
   this. Not fixed - documented precisely instead of left as the vaguer
   "278 files" note from the entry that first found it.

2. **Built the CWE-284 extension**, in `vibeguard/layer1_static/rules/cwe_284.py`:
   `has_inline_header_guard()` (javalang) and its Tree-sitter counterpart
   detect a method with an `@RequestHeader`-annotated parameter compared
   via `.equals()`/`.contentEquals()`/`MessageDigest.isEqual()` against
   another value, on an `if` branch that bails out (`return`/`throw`) -
   the exact shape of `ai-api-key-service`'s and `ai-oauth-refresh-
   service`'s real endpoints (`if (!adminKey.equals(supplied)) return
   ResponseEntity.status(401).build();`), including the `||`-combined
   condition in `oauth-refresh-service.refresh()`. `apply_hand_rolled_
   guard_context()` appends a caveat to the matching CWE-284 finding's
   message - never suppresses it, same fail-closed discipline as the
   existing `apply_centralized_authorization_context`. Unlike that
   project-wide mechanism, this one is scoped **per-method**: a guarded
   endpoint's caveat does not leak onto an unguarded sibling endpoint in
   the same file, which is more precise than the existing centralized
   case and was verified directly with a dedicated test
   (`test_apply_hand_rolled_guard_context_appends_caveat_only_to_guarded_method`).
   Wired into both real call sites (`main.py`'s `_run_rules` and
   `evaluation/human_baseline.py`'s `_run_all_rules`;
   `evaluation/thesis_orchestrator.py` reuses `main.py`'s function, so it
   is covered automatically). Fixing a latent bug the new code exposed:
   both call sites previously passed the same generator expression to
   what is now two sequential consumers - a generator is single-use, so
   the second call would silently have seen zero parsed files. Now
   materialized to a tuple once and reused.

3. **A real gap the first version of the matcher had, caught by its own
   test, not shipped silently.** The initial `MessageDigest.isEqual`
   test used `isEqual(vaultKey, supplied)` conceptually but the matcher
   only recognised a header parameter referenced as a bare variable, not
   as `supplied.getBytes()` - the argument `MessageDigest.isEqual`
   actually requires (`byte[]`, not `String`), and therefore the
   *realistic*, idiomatic shape for this exact constant-time-comparison
   pattern, not an edge case. Fixed in both parser paths before this was
   logged as done.

4. **Deliberately scoped out: a second real shape already in the
   dataset.** `ai-card-storage-service`'s guard is delegated through a
   private helper method (`if (!allowed(key)) ...` where `allowed(String
   key)` does the actual `vaultKey.equals(key)` comparison) - one hop of
   indirection this version does not follow. Verified directly: it still
   correctly gets no caveat (neither a false suppression nor a crash).
   Deferred rather than built now, for the same reason this project has
   repeatedly deferred similar one-hop extensions elsewhere (see the
   2026-09-04 CWE-287 entry's own "unobserved-so-far edge case" framing):
   each hop of indirection followed is a meaningfully bigger, harder-to-
   review unit of work, and this session's real, observed need (the two
   inline-comparison endpoints) is already fully addressed without it.

5. **Verified this cannot change any severity, prediction, or accuracy
   number, only finding text**, before treating the scope as done: grepped
   `message`/`message_length` through `layer3_scoring/scorer.py` and
   `layer4_ml/predictor.py` - neither is read by either. Confirmed
   directly: `evaluation/evaluate.py`'s in-sample/leave-one-out/baseline
   numbers (0.700/0.580/0.400 accuracy) and `evaluation/human_baseline.py`'s
   agreement summary (5/18/6 exact-match counts) are byte-identical before
   and after this change. `data/labeled/layer4_projects.json`'s stored
   finding text for `ai-api-key-service`/`ai-oauth-refresh-service` is now
   stale relative to a fresh scan (cosmetically only - a live rescan would
   now attach the new caveat to those two projects' CWE-284 findings); not
   regenerated in this pass, logged as a known, low-priority follow-up
   rather than expanding this session's scope.

**Tests/adversarial checks run:**
- 10 new unit/integration tests in `tests/test_cwe_284.py`: direct
  comparison guard; the `||`-combined-condition guard
  (`oauth-refresh-service.refresh()`'s exact shape);
  `MessageDigest.isEqual()` with `.getBytes()` arguments (caught the real
  gap in point 3 above); a blank-check with no caller-supplied reference
  (`ai-payments-service`'s exact shape) correctly *not* matching; an
  unguarded method correctly not matching; a header parameter with no
  comparison at all correctly not matching; per-method caveat precision
  (guarded/unguarded siblings in one file); no-op when absent; never
  drops findings; and the Tree-sitter fallback path via a `switch`-
  expression-forcing fixture, per `tests/test_java_rule_fallback_coverage.py`'s
  dual-parser requirement.
- Full `pytest -q`: **310 passed** (up from 300). `mypy .` / `ruff check .`
  / `black --check .` / `git diff --check`: all clean.
- Ran the real CLI (`main.py`) against `ai-api-key-service`: both
  `issue` and `revoke` findings now carry the caveat in the actual
  console report, not just in a unit test.
- Ran the detector directly against five real sample apps to confirm
  precision against every real shape in the dataset at once:
  `ai-api-key-service` (2/2 caveated, correct), `ai-oauth-refresh-service`
  (2/2 caveated, correct), `ai-payments-service` (0/2 caveated, correct -
  blank-check only), `ai-card-storage-service` (0/2 caveated, correct -
  helper-indirection, deliberately out of scope), `ai-account-recovery-
  service` (0/2 caveated, correct - genuinely unguarded, the real
  account-takeover bug from the 2026-09-04 entry must never be
  suppressed by this).

**Remaining limitations:** The helper-indirection shape (point 4) is
undetected by design, not by oversight. The Tree-sitter native crash
(point 1) is now more precisely characterized but still open - a real
fix needs subprocess-level isolation, a bigger change than this
session's scope. `data/labeled/layer4_projects.json`'s stored finding
text for the two affected projects is stale relative to a fresh scan
(point 5) - cosmetic only, does not affect any label, feature, or score.

**Why:** The human-baseline comparison independently confirmed (blind
raters converging on "Low" for exactly the projects this pattern
affects) what the dataset's hand-corrected ground-truth labels already
encoded but the raw Layer 3 rule severity could not see. Section 4's
fail-closed discipline ruled out a suppression from the start: this adds
an honest caveat to a finding that must keep existing, the same
precedent already set for the centralized Spring Security case, extended
to the pattern this project's own data shows is actually dominant (~19
of 20 real protection mechanisms observed across the AI-generated
batches, not Spring Security).

**Effect on thesis chapters:** Chapter 4 gains a second, more common
real-world CWE-284 caveat mechanism, and a concretely diagnosed (if not
yet resolved) native-crash investigation with a stated real fix
(subprocess isolation) rather than a vague "278 files" note. Chapter 5's
discussion of CWE-284's annotation-blindness limitation can now cite a
partial, measured mitigation for the dominant pattern specifically,
while stating plainly what remains uncovered (helper-indirection) and
why it was deferred rather than built speculatively.

**Freeze / handoff:** Layer 1 is reopened by this entry, on the same
"real-world/human-validation evidence found a blocking gap" grounds
already established repeatedly for it - re-freeze once a fresh session
has run adversarial QA against this specific change (the fail-closed
guarantee, the per-method precision boundary, and false-positive risk on
an unrelated header comparison that happens to use `.equals()` for
non-auth reasons, are the three things most worth trying to break).
Recommend that session also decide whether to regenerate
`layer4_projects.json`'s stale finding text (point 5) while it is there.
The Tree-sitter crash investigation (point 1) and the helper-indirection
gap (point 4) are both logged as open, scoped candidates for a future
session, not silently dropped.

---

## [2026-09-10] - Tree-sitter native crash: root cause narrowed further, real risk found to be near-zero through the actual CLI, and a fail-closed supervisor built for main.py specifically

**What the plan said:** The previous entry's investigation characterized
the Tree-sitter crash precisely but left it open, proposing subprocess
isolation as "the real fix" without having actually scoped what that
would require. Asked directly to fix it, the scoping work below found
that proposal was understated - true per-file process isolation is
blocked by `tree_sitter.Tree`/`Node` objects not being picklable, not
just "more overhead." Given a choice between building a whole-process
supervisor for `main.py` only, extending the same pattern to all three
entry points, or documenting only, the first was chosen.

**What we actually did / found:**

1. **The crash does not reproduce through the actual product CLI, at
   all, even under deliberately maximal stress - re-confirmed, not
   assumed.** `main.py` run directly against `.qa-repos/webgoat-20260904`
   (the single worst real case on file count/variety): 3/3 clean runs,
   matching the original 2026-09-04 finding. Escalated further than the
   previous entry did: ran `main.py` against **all four** `.qa-repos/`
   combined in one invocation (898 Java files, the same scale that
   reliably crashed a bare `scan_directory()` call) - still clean, still
   a valid `critical` report (253 findings, 0.843-class confidence
   range consistent with the single-repo run). The crash is real, but
   through every real invocation path tested, it is confined to small,
   minimal-import-graph processes calling `scan_directory()` directly,
   not to `main.py` itself.

2. **Ruled out both cheap causes precisely, this time with a controlled
   comparison, not just "it still crashed."** Confirmed `subprocess.run`
   reports a negative returncode (`-11` for `SIGSEGV`) on this platform
   via a minimal `ctypes` null-dereference, establishing the detection
   mechanism works before building anything around it. Confirmed
   `tree-sitter` (0.26.0) and `tree-sitter-java` (0.23.5) are both
   already the latest available release on PyPI - no upgrade path
   exists to test. The remaining, unfalsified explanation: this is a
   real bug in the native binding that is sensitive to the *overall*
   process memory footprint at the time of the crash, not to file count,
   thread reuse, or parser-object reuse alone - a small script with only
   this project's Layer 1 imports loaded triggers it; `main.py`'s full
   import graph (`rich`, `scikit-learn`, `shap`, `numpy`, every
   `vibeguard` layer) does not, consistently, across every test run.
   This was not fully explained at the C-extension level (out of
   proportion to chase further for a thesis-scope robustness item) but
   is now precisely characterized, not vaguely gestured at.

3. **Built a whole-process supervisor in `main.py`, scoped to `main.py`
   only** (the actual product entry point - `evaluation/human_baseline.py`
   and `evaluation/thesis_orchestrator.py` call the scanning code
   in-process and remain unprotected, a deliberate scope choice, not an
   oversight). `__main__` now re-execs itself as a child process
   (`subprocess.run([sys.executable, __file__, *argv], env=...)`) unless
   an internal `VIBEGUARD_SUPERVISOR_WORKER` environment variable is
   already set, in which case it runs `main()` directly - this is what
   the child sees, so there is no unbounded re-exec recursion. A normal
   exit (0 or 1, `main()`'s existing contract) passes through completely
   unchanged - the wrapper is invisible on the success and ordinary-error
   paths, verified directly. A negative returncode (child killed by a
   signal) is translated into an explicit stderr message plus a new,
   distinct exit code (`3`, chosen specifically not to collide with
   `main()`'s existing 0/1 meanings) instead of a silent process death -
   this is the actual fail-closed guarantee Section 4 requires and the
   status quo did not provide for this specific failure mode (a segfault
   cannot be caught by any Python `try/except` anywhere in this
   codebase, so before this change it would have looked like the tool
   just stopped, with zero diagnostic output and no indication results
   were incomplete).

4. **Could not validate the crash-handling branch with a genuinely live
   segfault through the real worker path, because it does not reproduce
   there** (see point 1) - this is itself informative, not a testing
   gap papered over. Validated instead with the standard, correct
   technique for this situation: `subprocess.run` mocked to return a
   negative code, confirming the detection/translation logic is correct
   in isolation, plus a real subprocess-level test of the actual
   `__main__` dispatch (`python main.py <clean file>` invoked for real,
   no worker env var set) confirming the supervisor is transparent on
   the success path end to end. Deliberately did not attempt to bake a
   live, unreliable native crash into the test suite - flaky-by-design
   native-crash tests are worse than mocked ones, not more rigorous.

**Tests/adversarial checks run:**
- 4 new tests in `tests/test_main.py`: normal-exit pass-through (both 0
  and 1, plus verifying the exact subprocess command/env constructed);
  signal-death detection and fail-closed translation; a real end-to-end
  subprocess invocation of the actual `__main__` entry point confirming
  transparency on success.
- Full `pytest -q`: **313 passed** (up from 310). `mypy .` / `ruff check .`
  / `black --check .` / `git diff --check`: all clean.
- Manual verification beyond the automated tests: `main.py` against a
  clean fixture (exit 0, unchanged), against `ai-api-key-service` (exit
  1, output byte-identical with and without the supervisor wrapper via
  the worker env var), and the 898-file four-repo stress run described
  in point 1.

**Remaining limitations:** The underlying native-binding bug itself is
contained, not fixed or explained at the root-cause level - a genuine
explanation would require instrumenting the C extension directly
(valgrind/ASan on the native library), disproportionate to this
project's scope. `evaluation/human_baseline.py` and `evaluation/
thesis_orchestrator.py` remain exposed to the same failure mode in
principle, though neither has ever reproduced it in any test run either
(both go through the same `scan_directory()`/`_run_rules()` path
`main.py`'s successful stress test exercised, just not via `main.py`'s
own subprocess boundary). Given the crash has never reproduced through
any process with this project's full import graph loaded, real-world
risk through any of the three entry points looks low - this session's
choice was to protect the one with a real audience (a thesis reviewer
or downstream user running the CLI directly) rather than build the same
plumbing three times for a risk that has not materialized anywhere it
was tested.

**Why:** A segfault is unlike every other failure mode this codebase
already guards against (parse timeout, oversized file, malformed
syntax) in one specific way: it cannot be caught, at all, by any code
this project controls. Every other robustness guarantee in Section 5
assumes Python-level exception handling works; this is the one case
where that assumption is false, which is exactly why it needed a
process-boundary answer rather than another `try/except`.

**Effect on thesis chapters:** Chapter 4/5's robustness discussion
(Section 5's stated "legitimate 'robustness' evaluation point") gains a
concrete, non-hypothetical example: a real native crash was found, its
trigger conditions were narrowed as far as reasonably possible without
native-level tooling, and a fail-closed guarantee was built for it where
none existed before - a defensible answer to "what happens if the
parser itself crashes," which a purely rule-based static-analysis
thesis chapter would otherwise have no story for at all.

**Freeze / handoff:** This is a CLI-entry-point robustness addition, not
a change to any of Layer 1-5's detection/scoring/ML logic - no frozen
layer's detection behavior changed. Recommend a fresh session
specifically try to break the supervisor itself (a child that hangs
instead of crashing - already covered by the existing per-file timeout,
worth confirming; a child that exits with an unusual but legitimate
positive code; environment-variable injection edge cases) before
treating this as settled. Extending the same pattern to `evaluation/
human_baseline.py` and `evaluation/thesis_orchestrator.py` remains a
logged, deliberately deferred option, not a plan.

---

## [2026-09-10] - Supervisor QA: hang and env-var bypass reproduced and fixed

**What the plan said:** The previous entry handed off "recommend a fresh
session specifically try to break the supervisor itself (a child that
hangs instead of crashing - already covered by the existing per-file
timeout, worth confirming; a child that exits with an unusual but
legitimate positive code; environment-variable injection edge cases)
before treating this as settled."

**What we actually did / found:**

1. **The "covered by the existing per-file timeout" assumption was only
   half true.** `_parsing_guards.run_with_timeout` bounds Layer 1
   parsing only (`ast_parser.py`/`config_parser.py`/`pom_parser.py`).
   CWE rule execution (`_run_rules`), Layer 4 ML training/prediction,
   and Layer 5 SHAP/report rendering all run afterward, inside the same
   supervised child, with zero timeout of their own - and
   `_run_as_supervised_subprocess`'s `subprocess.run(...)` call itself
   had no `timeout=` kwarg either. Reproduced directly: patched the
   call to wait on a real, genuinely hanging child process and bounded
   the *test* itself with an outer kill-after-8s harness (since the
   call under test has no bound of its own) - it blocked for the full
   8s and had to be force-killed. Fixed by adding a
   `_SUPERVISOR_TIMEOUT_SECONDS` (1800s, a generous last-resort
   backstop chosen to clear the largest real scan exercised so far -
   898 files across all four `.qa-repos` combined - without a false
   trip) wall-clock budget around the whole `subprocess.run` call, a
   new distinct exit code (`_SUPERVISOR_TIMEOUT_EXIT_CODE = 4`,
   separate from the existing crash code `3`), and a clear stderr
   message. Re-verified post-fix with a real (not mocked-away) hung
   child process and a real `subprocess.TimeoutExpired`: returns in
   ~2s against a patched-down 2s budget instead of blocking.

2. **The environment-variable bypass reproduced exactly as described.**
   `VIBEGUARD_SUPERVISOR_WORKER` used a fixed `"1"` sentinel to tell a
   re-exec'd child not to re-wrap itself. If that exact variable is
   already `"1"` in the invoking shell/CI environment for any unrelated
   reason (a copied `.env` file, a CI variable set at workflow rather
   than step scope, a leftover shell export), `__main__` takes the
   "already a worker" branch directly - completely skipping
   `_run_as_supervised_subprocess`, with no warning printed anywhere.
   Reproduced with a structural mirror of the real dispatch logic (same
   env var name, same subprocess.run shape) substituting a guaranteed
   `ctypes` null-pointer-dereference segfault for the real scan (the
   same substitution technique the original crash-detection logic was
   itself validated with): with the var unset, the crash was caught and
   cleanly translated to exit code 3 with a diagnostic message; with
   `VIBEGUARD_SUPERVISOR_WORKER=1` pre-set, the identical crash escaped
   completely raw as exit code 139, with no VibeGuard message at all -
   the exact silent-death failure mode this feature exists to prevent.
   Fixed by replacing the fixed `"1"` sentinel with a fresh
   `secrets.token_hex(16)` per supervisor invocation, checked by a new
   `_looks_like_supervisor_worker_token()` heuristic (exact-length
   lowercase hex) instead of an equality check - not a cryptographic
   guarantee (a child has no independent way to verify a value actually
   came from its own parent), but it makes *coincidental* collision
   with an unrelated pre-existing environment variable astronomically
   unlikely, where a single-character sentinel was not. Re-verified
   post-fix with the same crash-mirror technique: `VIBEGUARD_SUPERVISOR_
   WORKER=1` pre-set no longer bypasses supervision - the segfault is
   still caught and translated to exit code 3.

3. **The "unusual but legitimate positive exit code" case (argparse's
   own pre-existing usage-error code, `2`) was checked and found not to
   be a bug.** Confirmed via real invocation (missing required `path`
   arg; an invalid `--timeout` value) that `main.py` exits `2` in both
   cases, and the supervisor's `completed.returncode < 0` check correctly
   leaves it untouched (a positive code is never treated as a crash).
   The only issue was documentation: the wrapper's docstring described
   the "normal" pass-through contract as strictly 0/1, without
   mentioning this third, pre-existing, already-legitimate code -
   fixed by updating the docstring rather than the logic.

**Tests/adversarial checks run:** 5 new tests in `tests/test_main.py`
(fresh-token-per-invocation, a parametrized table of values the token
heuristic must reject including the literal old `"1"` sentinel, a real
`secrets.token_hex(16)` value it must accept, and mocked-`TimeoutExpired`
detection/translation) plus updates to the 2 existing supervisor tests
(token-shaped env value instead of literal `"1"`; asserting the new
`timeout=` kwarg is passed to `subprocess.run`). Full `pytest -q`: 324
passed (up from 313: +11 from this session, the rest already pending in
the working tree from other in-progress work - see `git status`).
`mypy main.py tests/test_main.py` / `ruff check` / `black --check` /
`git diff --check`: all clean. Beyond the automated suite: two live,
non-mocked reproductions (before fix: forced-kill after an 8s bound
proving the hang had no ceiling at all; after fix: a real hung child
process, with a real `subprocess.TimeoutExpired`, returning in ~2s
against a patched-down budget) and two live crash-mirror reproductions
(before fix: a real `ctypes` segfault escaping raw once the env var was
pre-set; after fix: the same segfault still caught and translated).

**Limitations:** The 1800s default timeout is a judgment call, not a
measured one - chosen to comfortably clear the largest scan exercised
so far with margin, not derived from a formal analysis of expected
scan duration vs. file count. It is currently a module constant, not
exposed as a CLI flag (kept out of scope to keep this fix minimal); if
a real scan legitimately needs longer than 30 minutes, this will need
revisiting. The worker-token heuristic defends against *coincidental*
collision only, not a deliberate adversary who reads this source file -
that was always the actual, and only relevant, threat model for this
specific gap (accidental environment interference), not adversarial
input to the tool's own detection logic.

**Why:** Both gaps were exactly the "worth confirming" items the
previous session flagged rather than assumed fixed - reproducing them
for real (not just reasoning about them) is what turned "plausible
concern" into "confirmed bug, now fixed with a regression test",
consistent with this project's fail-closed requirement (Section 4) and
the QA/build session separation this project's workflow protocol
(Section 11) is built around.

**Effect on thesis chapters:** Extends the same Chapter 4/5 robustness
story the original supervisor entry started: a second, independently-
reproduced fail-closed gap in the *same* new mechanism, found and
closed within one QA cycle rather than shipped unexamined - itself a
small but concrete data point for a methodology chapter about this
project's build/QA session discipline actually catching real issues,
not just process for its own sake.

**Freeze / handoff:** Recommend one more fresh session specifically
re-attack these two fixes before treating the supervisor as settled -
in particular, whether the 1800s default is actually reasonable for
this project's real scan workloads, and whether the token-heuristic
approach has any gap not covered by the parametrized rejection table
above. This is a CLI-entry-point robustness fix, not a change to any
of Layer 1-5's detection/scoring/ML logic - no frozen layer's
detection behavior changed.

---

## [2026-09-10] - Supervisor re-attack: timeout retuned with a real measurement, token heuristic re-attacked and holds

**What the plan said:** The previous entry's handoff asked a fresh
session to re-attack exactly two things before calling the supervisor
settled: whether 1800s is actually reasonable for this project's real
workloads, and whether the token heuristic has any gap the existing
parametrized table doesn't cover.

**What we actually did / found:**

1. **The 1800s value was never actually timed against the reference
   workload it cites - it was a file-count guess.** Ran `main.py`
   against the same corpus its own justification names (`.qa-repos`, all
   four repos combined) for real, timed: **9.22s wall-clock** (526/526
   Java files parsed OK, 17/17 config, 12/12 pom.xml, 253 findings -
   consistent with the earlier entry's numbers). That is a ~195x margin,
   not merely "comfortable." Retuned `_SUPERVISOR_TIMEOUT_SECONDS` from
   1800.0 to **300.0** (5 minutes): still ~32x the measured baseline
   (still a last-resort backstop, not the per-file throttle), while
   cutting the worst-case silent-hang wait from 30 minutes to 5. Updated
   the constant's comment block in `main.py` to cite the measured number
   instead of the file-count reasoning it replaces.

2. **The token heuristic was re-attacked directly, not just re-read.**
   Beyond the existing 8-case parametrized table, tried a 33-char value
   (the untested mirror of the existing "31 chars, one short" case), a
   single uppercase character mixed into an otherwise-valid token, a
   Unicode fullwidth-digit lookalike (`０`×32), a trailing newline, and
   tab-padding - all five correctly rejected by
   `_looks_like_supervisor_worker_token` as-is. No logic gap found. Added
   the missing `"a"*33 -> False` case to `tests/test_main.py`'s
   parametrized table for symmetric regression coverage of both boundary
   directions (previously only the "too short" side was tested). The
   residual risk is exactly what the function's own docstring already
   names and scopes out - a genuine, correctly-shaped token surviving in
   a developer's shell from a forgotten manual export - which is
   inherent to any env-var handshake and not closable by a tighter shape
   check.

**Tests/adversarial checks run:** Full `pytest -q`: 324 passed
(pre-existing suite, unaffected by the retune since tests reference
`main._SUPERVISOR_TIMEOUT_SECONDS` symbolically, not a hardcoded value)
plus the new 33-char parametrized case. `mypy` / `ruff check` /
`black --check` / `git diff --check`: all clean.

**Limitations:** 300s is still a judgment call, now anchored to one
measured data point rather than zero - it has not been validated against
a real project larger than the 526-file `.qa-repos` corpus, because no
larger real corpus was available to test against.

**Why:** This is exactly the "reproduce it, don't just reason about it"
standard the previous two supervisor QA entries were held to - the
1800s value's own justification cited a file count but never a timing,
so timing it was the direct way to answer "is this reasonable," not
another round of reasoning about the existing reasoning.

**Effect on thesis chapters:** Sharpens the same Chapter 4/5 robustness
story further: the backstop timeout is now grounded in a measured
number, not an estimate, and its stated margin is precise.

**Freeze / handoff:** Both items from the previous handoff are now
settled - the supervisor mechanism (crash detection, hang detection,
env-token heuristic, timeout value) is not being reopened again absent
a new blocking finding. Next real gap is the one found by a broader
defense-readiness audit run in the same session - see the entry below.

---

## [2026-09-10] - Defense-readiness audit: verified claims against real runs, found a real Layer 4 blind spot, corrected an inaccurate dependency-audit claim, added inter-rater agreement reporting and measured test coverage

**What the plan said:** Asked directly "is this ready for a defense,
what are the gaps," with an explicit instruction not to just re-narrate
the log's own claims. The scope was verification first (run the actual
test suite, static gates, evaluation script, and dependency audit rather
than trust prior entries), then fix what was safely fixable without
reopening a frozen layer without cause.

**What we actually did / found:**

1. **Verified, not just re-read:** 324/324 tests passed, `mypy`/`ruff`/
   `black --check` all clean, no `TODO`/`FIXME`/`NotImplementedError` in
   the source tree, 50 projects confirmed in
   `data/labeled/layer4_projects.json`, `evaluation/evaluate.py` run for
   real (in-sample acc 0.700/F1 0.681, leave-one-out acc 0.580/F1 0.498,
   fixed-severity baseline acc 0.400/F1 0.423 - matches `CLAUDE.md`'s
   existing claim exactly).

2. **A real Layer 4 gap the aggregate metric was hiding.** Broke down
   the leave-one-out predictions by label instead of trusting the
   aggregate: across all 50 folds, VibeGuard's Random Forest **never
   once predicts "high"** (predicted-label distribution: 18 low / 25
   medium / 7 critical / 0 high), despite 10 of the 50 actual labels
   being "high" - all 10 fall into "low" or "medium" instead, and never
   into "critical" either. Checked whether this is a simple class-count
   imbalance fix: it is not - `RandomForestClassifier` already uses
   `class_weight="balanced"` (`vibeguard/layer4_ml/trainer.py`), and
   "low" (9 examples, the smallest class) is predicted correctly 8/9
   times, so raw example count alone doesn't explain the collapse. Most
   consistent with "high" sitting in a feature-space dead zone between
   "medium" and "critical" given the current project-level feature
   vector (`vibeguard/layer4_ml/predictor.py`'s CWE/source/severity
   count features), with too few "high" examples (10) for the forest to
   carve out that boundary. **Not fixed** - Layer 4 is frozen, and a fix
   here means changing feature engineering, label thresholds, or
   hyperparameters, which is a methodology decision for the thesis
   owner, not something to silently retune. Flagged as a candidate for a
   deliberate, separately-scoped Layer 4 reopening, not done in this
   pass.

3. **Human baseline was real (a genuine Tally CSV export,
   `data/labeled/human_baseline_survey.csv`) but had no rigor around how
   much the 3 raters agreed with each other before being compared to
   VibeGuard's signals.** Added `InterRaterAgreementSummary` and
   `summarize_inter_rater_agreement()` to
   `evaluation/human_baseline.py` (computed from the `human_spread`
   field that already existed per case but was never aggregated),
   rendered as a new console table and added to the JSON report. Run
   against the real committed survey: raters agreed exactly on only
   **3/20 cases**, within one ordinal level on 16/20, mean spread 1.15,
   max spread 3 (i.e., at least one case spanned the full Low-to-Critical
   range across the 3 raters). This number now sits next to the
   VibeGuard-vs-human-median agreement numbers so a reader can judge the
   latter against how consistent the raters were with each other, rather
   than assuming a stable reference point. Updated the module docstring
   to state plainly that n=3 is exploratory/qualitative evidence, not a
   statistically powered validation.

4. **The "security tool passes its own dependency audit" claim in
   `CLAUDE.md`/`AGENTS.md` Section 6 was not true as stated.** Ran
   `safety check` for real: 2 CVEs reported - one in `pip` itself, one in
   `cryptography`, both pulled in transitively by `safety`'s own
   dependency chain (Authlib/joserfc), not by anything VibeGuard's code
   imports. Confirmed `safety==3.8.1` is already the latest release on
   PyPI (`pip index versions safety`), so there is no upgrade path that
   clears the `cryptography` finding today. Corrected the claim in both
   `CLAUDE.md` and `AGENTS.md` (kept identical, per this project's own
   rule) to state the precise, current truth instead of the "nice irony
   point" framing: not a clean audit, but no known vulnerability in the
   tool's own runtime import graph either.

5. **"Meaningful coverage" was asserted (Section 4) but never measured.**
   Added `pytest-cov==7.1.0` to `requirements.txt` and ran it for real:
   **89% overall statement coverage** across `vibeguard/` + `evaluation/`
   + `main.py`. Per Section 4's own stated priority (detection logic over
   glue code), the parts that matter most measure well: `cwe_1035.py`
   100%, `layer2_features/extractor.py` 100%, `layer4_ml/predictor.py`
   100%, `layer3_scoring/scorer.py` 98%, `cwe_20.py` 94%, `cwe_284.py`/
   `cwe_287.py` 89% each. Two real soft spots: `cwe_798.py` at 81% (the
   largest rule module, 390 statements) and `layer5_report/explainer.py`
   (the SHAP attribution code) at 69% - the latter is worth a look given
   explainability is a core thesis claim, not incidental code. Added a
   report-only (non-blocking - no `--cov-fail-under` threshold imposed)
   coverage step to `.github/workflows/ci.yml` so this number is visible
   on every CI run going forward instead of being a one-off manual
   check; deliberately did not add a hard coverage gate, since picking a
   threshold and which modules it should apply to is a scope decision
   for the thesis owner, not something to impose unilaterally.

**Tests/adversarial checks run:** New tests added:
`test_summarize_inter_rater_agreement_computes_spread_buckets` (hand-
picked spread values covering the exact/within-one/neither buckets) and
`test_end_to_end_inter_rater_agreement_on_real_survey_is_computable`
(sanity bounds against the real 3-rater CSV) in
`tests/test_human_baseline.py`. Full `pytest -q`: 327 passed (up from
324: +3 from this session - the missing 33-char supervisor-token case
from the entry above, plus these 2). `mypy .` / `ruff check .` /
`black --check .` (after one auto-reformat of `human_baseline.py`) /
`git diff --check`: all clean.

**Limitations:** Point 2 (the Layer 4 "high"-class blind spot) is
reported, not fixed - this is the single most significant open item
from this audit and is a real, defensible thing to be asked about in a
viva. Point 3's inter-rater number makes the human baseline's limits
legible but does not and cannot fix the small-n problem itself; growing
the panel past 3 raters is a data-collection task for the thesis owner,
not something addressable in code. Point 4's dependency findings are
outside VibeGuard's own runtime import graph but are still real CVEs
present in the development/audit environment; there is currently no
version bump that clears them given `safety` itself has no newer
release.

**Why:** Directly asked "prove it, stop hallucinating, is this ready
for a defense" - the only honest way to answer that is to run the real
artifacts (tests, evaluation script, dependency audit, coverage) rather
than summarize what earlier log entries already claimed, and to report
what the raw data shows even when it's less flattering than the
aggregate metric already on record (point 2 specifically).

**Effect on thesis chapters:** Chapter 4/5 gains a concrete, honest limitation
to state explicitly (Layer 4's zero recall on "high" in leave-one-out)
rather than letting the 0.58-vs-0.40 aggregate stand alone; the human-
baseline discussion (Chapter 4/5) gains a defensible answer to "how much
did your raters agree with each other"; Chapter 5's dependency-hygiene
line needs to read as stated in the corrected `CLAUDE.md`/`AGENTS.md`
text, not the original "clean audit" framing; and a coverage number now
exists to cite instead of an unmeasured "meaningful coverage" assertion.

**Freeze / handoff:** No frozen layer's detection/scoring/classification
*behavior* changed in this entry - Layer 4's model, features, and
training logic are untouched. The one item that would require reopening
a frozen layer (point 2) was deliberately left as a reported finding,
not acted on, pending the thesis owner's explicit decision on whether
and how to address it (candidate directions: revisit the "high" label's
threshold definition from Chapter 3's scoring rubric, add features that
better separate "high" from its neighbors, or accept and document it as
a known model limitation). Growing the human-rater panel (point 3) is
the other open, non-code item. Everything else in this entry (timeout
retune, token-heuristic symmetry, dependency-claim correction,
inter-rater reporting, measured coverage) is applied and tested, not
pending.

---

## [2026-09-10] - Layer 4 reopened to fix zero recall on "high": root cause found and confirmed, a targeted feature fix was built, tested, and reverted after empirically failing; one legitimate dataset fix kept

**What the plan said:** Explicitly authorized by the thesis owner to fix
the previous entry's point 2 (Layer 4 never predicts "high" in
leave-one-out). Scope: Layer 4 only (`vibeguard/layer4_ml/`), narrowly
targeting this one recall gap - no changes to Layers 1/2/3/5's detection
or scoring behavior unless the root cause required it.

**What we actually did / found:**

1. **Found the exact root cause, not a guess.** Built every project's
   full 22-feature Layer 4 vector and grouped by exact vector equality:
   50 labelled projects collapse to only **20 distinct vectors**, and 4
   of those groups span more than one severity label - one group alone
   has 12 members spanning low/medium/high. This is not a class-
   imbalance problem (ruled out directly: `RandomForestClassifier`
   already uses `class_weight="balanced"`, and "low," the smallest
   class at 9 examples, predicts correctly 8/9 times). It is an
   information-insufficiency problem: several projects with genuinely
   different human-assigned risk are indistinguishable to the current
   feature vector, so no classifier - Random Forest or otherwise - can
   separate them without a new feature.

2. **Traced one duplicate-vector group to an exact, real cause and
   confirmed it two different ways before touching any code.** For the
   12-member low/medium/high group: `ai-api-key-service` (label "low")
   and `ai-employee-profile-service`/`ai-user-consent-service`/
   `ai-admin-report-export-service` (label "high") all produce the
   identical CWE-284-only vector. Live-rescanned all four against
   current Layer 1 rules: `ai-api-key-service`'s two CWE-284 findings
   both carry the `_HAND_ROLLED_GUARD_CAVEAT` annotation (a caller-
   header-comparison guard is present, even if unverifiable); the three
   "high" projects' findings carry no caveat at all (genuinely
   unguarded). This distinction is real, current, and exactly what a
   human labeller would use - but it lives only in `Finding.message`
   prose, which Layer 4's feature vector never reads.

3. **Also checked, before assuming: is the labelled dataset's frozen
   `findings` data itself stale relative to current Layer 1 rules?**
   First pass (CWE-id/count comparison only, live-rescanning all 50
   projects against current rules): zero drift, seemed to rule this out.
   Second, more careful pass (comparing full `message` text, not just
   counts): **9 of 50 projects had stale messages** - missing the
   `_HAND_ROLLED_GUARD_CAVEAT`/`_CENTRALIZED_AUTH_CAVEAT` annotations
   entirely, because those two caveat mechanisms were built earlier
   *today* (see this file's earlier 2026-09-04/09-10 entries) and the
   dataset's hand-authored JSON records were never refreshed after. This
   was a real gap in the first check, not a false alarm - counting CWE
   ids can't detect a message-only annotation.

4. **Built the fix, verified it addressed exactly the traced cause, then
   tested it empirically rather than shipping on that verification
   alone.** Promoted `_CENTRALIZED_AUTH_CAVEAT`/`_HAND_ROLLED_GUARD_CAVEAT`
   to public constants in `cwe_284.py` (pure rename, zero behavior
   change - confirmed via `git diff` showing no other change to that
   file), added a `has_unverified_guard_signal` feature to
   `vibeguard/layer4_ml/predictor.py` matching on those literal
   constants (not a guessed substring), refreshed the 9 stale dataset
   messages via a live re-scan (matched by `(cwe_id, identifier)` per
   finding, every other field left untouched, dataset JSON round-trip
   verified byte-identical before editing), and regenerated the trusted
   model contract. Result: the specific traced collision *did* resolve
   (`ai-api-key-service` no longer shares a vector with the three "high"
   projects). But re-running the real leave-one-out evaluator end to end
   showed the fix **did not achieve its goal and made overall
   performance worse**: leave-one-out accuracy dropped from 0.580 to
   **0.420** (barely above the 0.400 fixed baseline) and macro-F1 dropped
   from 0.498 to **0.413** (now *below* the 0.423 baseline). True "high"
   recall stayed at **0/10** - the "high" predictions that did appear
   (10 of them) were all mispredictions of *other* classes' projects as
   "high," never a correct identification of an actual "high" project.

5. **Diagnosed why before deciding whether to salvage or revert.**
   Checked the new feature's value across all 50 projects by class: mean
   0.33 for low, 0.25 for medium, 0.10 for high, 0.0 for critical - the
   signal is real but sparse (only 9/50 projects have it at all) and
   does not uniquely mark "high": the large majority of low/medium/
   critical projects *also* score 0 on it, so it narrows "definitely not
   the traced group" without helping separate "high" from the bulk of
   its neighbors. Recomputed duplicate-vector groups with the new
   23-feature vector: **5 groups still span multiple labels**, including
   one 9-member group (3 low, 3 medium, 3 high) with *zero* separation
   from the new feature at all - the guard-caveat signal only ever
   applied to the one group it was traced from. Ran a bounded
   hyperparameter sweep (`max_depth` in {3,5,8}, `min_samples_leaf` in
   {2,3}, `n_estimators=300`, `class_weight="balanced_subsample"`) on
   top of the new feature to check whether regularization could recover
   the loss: best configuration (`max_depth=5`) reached 0.520/0.459 -
   still below the original 0.580/0.498 with high recall still 0-1/10.
   No tested configuration recovered the original performance while
   fixing "high" recall.

6. **Reverted the ML feature change; kept the dataset fix.** Removed
   `has_unverified_guard_signal` from `predictor.py` entirely (import,
   feature function, schema entries), reverted the two `cwe_284.py`
   constants back to their original private names (`git diff` on that
   file now shows zero residual change from this entry), and
   regenerated the trusted model contract back to the original 22-
   feature schema. Re-ran leave-one-out: **confirmed back to exactly
   0.580 accuracy / 0.498 macro-F1**, matching the frozen baseline
   exactly. Kept the 9 refreshed dataset messages - this is a real,
   independent data-accuracy correction (the committed dataset should
   reflect what current Layer 1 rules actually produce), and re-running
   leave-one-out after the message refresh but before the reverted
   feature confirmed it is fully inert against the original feature
   schema (message content was never read by any of the original 22
   features), so keeping it carries zero risk to the frozen model's
   behavior.

**Tests/adversarial checks run:** Full `pytest -q`: 327 passed
(unchanged from the previous entry - no test additions in this entry,
since the shipped change is a pure revert plus an inert dataset-text
correction). `mypy .` / `ruff check .` / `black --check .` /
`git diff --check`: all clean. The empirical falsification itself *is*
the adversarial check for this entry: the fix was not accepted on the
strength of tracing one root cause and confirming it twice - it was
built, and then run through the real `leave_one_out_evaluate_project_
risk_model` end to end, which is what caught the regression a purely
logical argument for the feature would have missed.

**Limitations:** The zero-recall-on-"high" gap is now root-caused, not
just observed, but it is **not fixed** - it remains exactly as reported
in the previous entry. What's now known precisely, that wasn't before:
it is a genuine information/data-density problem (50 examples, 4
classes, an unknown number of distinct real-world "why is this worse"
signals none of which are captured single-handedly by any one available
feature), not a quick feature-engineering fix, and not a hyperparameter
tuning problem either (both were tried and both failed empirically).
Closing it for real most likely needs one of: (a) substantially more
labelled examples so each duplicate-vector cluster has enough members
for a majority-vote signal to be statistically meaningful, (b) a
research-scale feature-engineering effort investigating each of the
(at least 5) remaining duplicate-vector clusters individually, the way
this entry did for exactly one of them, or (c) accepting and precisely
documenting this as a stated Chapter 4/5 limitation of a 50-project
labelled dataset for 4-way project-risk classification.

**Why:** The thesis owner explicitly asked to fix this after the
previous entry's report. The honest, rigorous path was to trace a real
root cause (not assume one), build the smallest fix that addressed it,
and then verify the fix against the actual evaluation harness rather
than accept "the traced collision resolved" as proof of success. It
didn't hold up under that test, and shipping it anyway - a change that
makes the model measurably worse while still not achieving the stated
goal - would have been worse for the thesis than reporting the
attempt honestly and reverting it. This is exactly the "reproduce it,
don't just reason about it" standard this project's QA discipline has
been held to all session (see the two supervisor entries above).

**Effect on thesis chapters:** This substantially strengthens Chapter
4/5's honesty and rigor on Layer 4's known limitation: rather than "the
model never predicts 'high,' cause unknown," the thesis can now state
precisely *why* (dataset information density: 20 distinct feature
vectors for 50 labelled projects, several spanning 3+ severity labels),
show a concrete, traced example, and show that a natural first fix was
tried, measured, and found insufficient - a stronger, more defensible
research narrative for a limitations section than either an unexamined
gap or a fix that looks plausible but wasn't actually verified end to
end. Chapter 3's dataset-labelling methodology may also warrant a note
that some project pairs are, by the current feature vector's own
information content, indistinguishable - a methodology-level finding,
not just an implementation one.

**Freeze / handoff:** Layer 4's model, features, and training logic are
back to exactly their pre-session state (verified: identical leave-one-
out accuracy/macro-F1) and remain frozen. The only non-reverted change
is the 9-project dataset message refresh, which is inert for the
current model and does not need separate freezing/QA beyond what this
entry already did. The next real option for point 2 above is a
deliberate, separately-scoped decision by the thesis owner among the
three directions in **Limitations** above - not something to attempt
again inside this same session's momentum.

---

## [2026-09-14] - Layer 5 plain-language summary added alongside the SHAP table

**Status: DRAFT, pending student review** (see note at end).

**What the plan said:** Layer 5 is frozen (passed independent adversarial
QA 2026-07-30); reopen only for a blocking correctness issue. This is not
one - it is a student-requested additive feature on top of the existing
SHAP report, not a fix.

**What we actually did:** The SHAP attribution table is precise but
assumes familiarity with SHAP values, baseline probabilities, and Layer
4's feature schema. Added a third panel to the console report - a short
prose paragraph translating the same numbers into plain English (label,
confidence, baseline, then one sentence per top contributing feature with
its real direction) - printed alongside the existing prediction table and
SHAP table, not replacing either.

1. **`vibeguard/layer5_report/_feature_descriptions.py`** - a hand-
   maintained dict translating each of Layer 4's 21 fixed feature names
   into plain English, with a safe fallback (de-slugify the raw name) for
   anything not in the map.
2. **`vibeguard/layer5_report/plain_summary.py`** - `build_plain_summary()`
   takes the same `ProjectRiskExplanation` the SHAP table already renders
   and produces the prose paragraph. No new computation; a pure
   formatting layer over existing SHAP output.
3. **`report.py`/`__init__.py`** - wired the new panel into
   `render_console_report()` as a third, always-shown section; added a
   `max_summary_features` parameter (default 3) alongside the existing
   `max_contributions`, both validated up front the same way.

**Tests/adversarial checks run:**
- New `tests/test_layer5_plain_summary.py`: label/confidence wording,
  correct toward/away direction per feature, `max_features` truncation,
  the "no notable contributions" fallback sentence, negative-argument
  rejection, and a coverage test asserting every name Layer 4's
  `build_project_features()` can currently produce has an entry in the
  description dict - so a future Layer 4 schema change fails a test
  instead of silently degrading everywhere.
- Two assertions added to the existing `tests/test_layer5_report.py`
  (panel title appears in rendered output; negative
  `max_summary_features` rejected).
- Full `pytest -q`: 335 passed at the time, `black`/`ruff`/`mypy` clean.
- Verified live against both ends of the spectrum: a real scan of the
  `vibe-coded-disaster-service` sample app (critical, 87% confidence) and
  a clean, findings-free file (low, 89% confidence) - both render
  sensible, correctly-directed prose without crashing.

**Remaining limitations:** Purely a presentation layer; does not change
what SHAP computes or which features it attributes. The low-risk/all-zero
case's prose reads slightly awkwardly ("the total number of issues found
in the project pushed the rating toward low" at value 0) but is accurate
and was judged acceptable rather than over-engineered for a first pass.

**Why:** The student's own feedback mid-session was that the raw SHAP
table was "too technical" to read without translation. Keeping SHAP
itself as the rigorous, citable computation and layering a simpler
representation on top - rather than replacing SHAP with a less rigorous
method - was the explicit alternative considered and rejected (SHAP is
the only one of the realistic alternatives, LIME included, with a
mathematical guarantee that per-feature attributions sum exactly to the
prediction).

**Effect on thesis chapters:** Chapter 5 can note the console report has
a plain-language explanation panel alongside the technical SHAP table,
useful for a thesis defense audience less familiar with SHAP mechanics.
No change to Chapter 3/4's methodology description of SHAP itself.

**Freeze / handoff:** This reopens frozen Layer 5 on student request, not
a blocking-issue ground - flagged as such rather than silently treated as
in-scope maintenance. Recommend a fresh session review this addition
(the description-dict coverage guarantee and the fallback wording
specifically) before re-freezing Layer 5. This entry was drafted by the
same session that built the feature, at the student's explicit request,
and has not yet been independently reviewed or confirmed - per Section 9,
do not treat it as settled project history until the student confirms it.

---

## [2026-09-14] - Whole-process crash/hang supervisor extended from main.py to all three CLI entry points

**Status: DRAFT, pending student review** (see note at end).

**What the plan said:** The 2026-09-10 supervisor entries built and
hardened a whole-process crash/hang guard for `main.py` only, deliberately
scoped there because it is "the actual product entry point... a real
audience" - `evaluation/human_baseline.py` and
`evaluation/thesis_orchestrator.py` were explicitly left unprotected as "a
deliberate scope choice, not an oversight," logged as a candidate for
later extension.

**What we actually did:** Asked directly whether to close that gap;
student chose to extend the existing mechanism rather than leave it
scoped to one entry point, since both other entry points run the same
Layer 1-5 pipeline in-process and share the identical native-crash
exposure.

1. **Extracted the mechanism into a new shared module,
   `process_supervisor.py`**, at the repo root - the same "extract on the
   second real need" practice this project has applied repeatedly in
   Layer 1 (`_finding.py`, `_credential_names.py`,
   `_endpoint_annotations.py`, `_java_literals.py`,
   `_authorization_annotations.py`), now applied to this exact
   security-relevant crash-detection logic once a third caller needed it -
   copy-pasting it a third time was judged a real divergence risk, not
   just duplication. `run_as_supervised_subprocess()`,
   `looks_like_supervisor_worker_token()`, and the env-var name/exit-code
   constants moved out of `main.py` unchanged in behavior; `main.py`'s
   `__main__` dispatch now delegates to the shared module instead of its
   own private copy.
2. **Wired the identical protection into `evaluation/human_baseline.py`
   and `evaluation/thesis_orchestrator.py`**: both `__main__` blocks now
   check the same worker-token env var and, if absent, re-exec themselves
   via `python -m evaluation.<module>` inside
   `run_as_supervised_subprocess()`, exactly mirroring `main.py`'s own
   dispatch shape.
3. **Added `process_supervisor` to the CI coverage report**
   (`.github/workflows/ci.yml`) - it had been silently absent from the
   tracked module list.

**Tests/adversarial checks run:**
- Moved the generic crash/hang/token-heuristic tests out of
  `tests/test_main.py` into a new `tests/test_process_supervisor.py`,
  testing the shared module directly rather than through any one entry
  point; kept `main.py`'s own real end-to-end subprocess test
  (`python main.py <fixture>`, no worker token set) unchanged, and added
  the equivalent real end-to-end test for both `human_baseline.py`
  (`python -m evaluation.human_baseline --help`) and
  `thesis_orchestrator.py` (`--help`).
- Full `pytest -q`: 339 passed at the time, all four static gates clean.
- Live verification beyond the automated suite: ran all three entry
  points for real end to end (`main.py` against a clean fixture,
  `python -m evaluation.human_baseline` against the real committed
  survey/dataset, `python -m evaluation.thesis_orchestrator` against a
  clean fixture into a scratch output directory) - all three exit 0 and
  produce correct output through the real supervised-subprocess path.
- Independent QA (fresh session, no memory of the build): verified the
  extraction byte-identical to the original mechanism (env var name,
  token-shape heuristic, exit codes 3/4, 300s default timeout) by
  reproducing a real segfault (`ctypes.string_at(0)` in a child) and a
  real hang through the extracted module directly; confirmed
  `thesis_orchestrator.py`'s `import main as scan_cli` does not cause
  double-supervision (its calls are plain function calls, never
  triggering `main.py`'s own `__main__` guard). Found one real,
  unrelated regression in the same diff: a pre-existing assertion in
  `tests/test_main.py`
  (`test_main_returns_nonzero_when_shap_reporting_raises_runtime_error`)
  had been silently deleted while editing that file for this change, with
  no connection to the supervisor work. Reproduced the scenario directly
  and confirmed the underlying behavior was never actually broken - only
  its test coverage had vanished. Restored the assertion; re-verified it
  passes.

**Remaining limitations:** None new. Same underlying native-binding
uncertainty already documented in the 2026-09-10 entries - this only
widens which entry points are protected against it, does not change the
mechanism itself.

**Why:** Copy-pasting security-relevant crash-detection logic a third
time was judged the wrong call the moment a third caller needed it,
consistent with this project's established practice everywhere else.
Extending coverage to all three entry points closes a gap the original
supervisor entry explicitly flagged as deliberately deferred, not
discovered new.

**Effect on thesis chapters:** Chapter 4/5's robustness discussion can
now state that all three CLI entry points (not just the primary scan
command) are protected against the documented native-crash failure mode,
not only the one with "a real audience."

**Freeze / handoff:** This is a CLI-entry-point robustness change, not a
change to any of Layer 1-5's detection/scoring/ML logic. This entry was
drafted by the same session that built the feature, at the student's
explicit request, following one independent QA pass (which found and this
session then fixed the unrelated test-assertion regression above) - per
Section 9, do not treat it as settled project history until the student
confirms it.

---

## [2026-09-14] - CWE-284 extended to recognize endpoint annotations inherited from an implemented interface

**Status: DRAFT, pending student review** (see note at end).

**What the plan said:** Logged 2026-09-02 as a real, precisely
characterized, deliberately unfixed gap: 9 of `spring-petclinic-rest`'s
10 controllers implement an auto-generated interface (Spring's
`openapi-generator-maven-plugin` output) carrying the real
`@RequestMapping`/`@PostMapping` annotations, with the concrete
`@Override` method carrying none of its own - invisible to
`has_endpoint_annotation()`, which only ever inspects a method's own
annotation list. Judged "too large and too edge-case-prone to build under
today's time pressure" at the time, logged as future work. Section 7
named continued real-repo evaluation as the highest-value remaining work;
asked directly whether to build this specific fix now, student said yes.

**What we actually did:**

1. **Scoped to CWE-284 only, explicitly not CWE-20.** CWE-20's equivalent
   gap needs parameter-level annotations (`@RequestBody`, `@Valid`), and
   Layer 1's `ParsedParameter` does not capture parameter annotations at
   all today, on either parser path - extending this same approach to
   CWE-20 would need that new AST capability first. Attempting both in
   one pass was judged the same mistake already avoided repeatedly in
   this project's history (a half-built fix for a harder problem);
   deferred, not attempted.

2. **New shared module,
   `vibeguard/layer1_static/rules/_interface_annotations.py`**: builds a
   project-wide index of every top-level type's methods by
   `(type_name, method_name) -> annotations`, and a per-file lookup of
   what each of that file's own top-level types implements. Built
   entirely from `ParsedFile.classes` (Layer 1's existing flattened
   summary), which is already parser-path-agnostic - both javalang and
   Tree-sitter populate the identical `ParsedClass`/`ParsedMethod` shape
   (confirmed by reading `_build_parsed_file`/`_build_tree_sitter_class`
   before writing anything), so this needed zero new parser-specific
   code. Deliberately scoped to top-level types only, since
   `ParsedFile.classes` only ever represents those by design - a nested
   class's implemented interfaces are not resolved by this feature (a
   narrower limitation than the general nested-class support `cwe_284.py`'s
   own per-file detection already has).

3. **`cwe_284.detect_in_java()` gained an optional
   `interface_annotations` parameter** (default: an empty index, so every
   existing single-file call/test keeps its exact current behavior
   unchanged). `main.py`'s `_run_rules()` and
   `evaluation/human_baseline.py`'s `_run_all_rules()` (a near-duplicate
   of `_run_rules`, per its own docstring) both now build the index once
   per scan from all successfully-parsed Java files and pass it through.
   `evaluation/evaluate.py`/`thesis_run.py` need no equivalent change -
   confirmed by grep that neither calls `cwe_284.detect_in_java` at all;
   they only ever work off the already-frozen labelled dataset.

4. **A design correction made before shipping, not after.** The first
   draft let an interface's `@PreAuthorize` silently suppress a finding
   the same way an endpoint annotation was widened. This is wrong: Spring
   MVC always resolves an interface-declared routing annotation against
   the real bean regardless of proxy style (a documented, proxy-independent
   framework feature), but an AOP-based authorization annotation declared
   the same way is only actually *enforced* if Spring is using
   interface-based JDK dynamic proxies - CGLIB class proxies, Spring
   Boot's default, typically do not honor it. Neither is visible to
   static analysis. Caught this asymmetry before shipping and split the
   design accordingly: `resolve_effective_annotations()` widens the
   *endpoint* check unconditionally (safe, fail-toward-more-findings
   direction); a separate `interface_annotations_for_method()` is used
   only to attach a new, explicit caveat
   (`_INTERFACE_AUTHORIZATION_CAVEAT`) when an interface method's
   authorization annotation is not repeated on the concrete override -
   the finding still fires either way, matching the exact "caveat, never
   silently suppress" discipline already established twice in this same
   file (`apply_centralized_authorization_context`,
   `apply_hand_rolled_guard_context`).

5. **Independent QA (fresh session) found one real, serious bug before
   this was treated as done.** `build_interface_method_index()`'s first
   version keyed its index by simple type name only; if two distinct
   top-level types anywhere in a scan shared a simple name, the index
   silently resolved to whichever declaration was scanned *last* -
   confirmed to actually happen, not merely theoretical: 14 colliding
   simple names across this project's own `.qa-repos` real-repo test
   corpus (`UserService`x4, `User`x4, `UserRepository`x4,
   `WebSecurityConfig`x3, etc.). This meant the exact same source code
   could either correctly find or silently miss the same unprotected
   endpoint purely depending on file-processing order - a real,
   non-deterministic false-negative risk in exactly the CWE this project
   has repeatedly treated as its worst-failure-mode category. Fixed by
   detecting when two *distinct* declarations (identified by
   `(file_path, line)`) share a simple name and excluding that name from
   the index entirely, rather than guessing - degrading back to exactly
   the pre-this-feature behavior (annotation not found) for that name,
   the same "when genuinely unresolvable, admit it rather than guess"
   principle already used for CWE-1035's unresolved dependency versions.
   New regression test builds the exact colliding scenario in both file
   orderings and asserts identical (empty) results; traced by hand that
   this test would have failed under the pre-fix code (0 findings one
   order, 1 finding the other) before confirming it passes now.

6. **The same QA pass also found and this session fixed** an unrelated,
   accidentally-deleted test assertion in `tests/test_main.py` (logged in
   the supervisor-extension entry above, since it was found during the
   same QA pass but is unrelated to this feature).

7. **Honestly measured, not assumed: the fix currently has zero
   real-world effect against the repository that originally motivated
   it.** `spring-petclinic-rest`'s `OwnersApi` interface only exists under
   `target/generated-sources/openapi/...`, which `scanner.py` correctly
   excludes as build output - so in this repo's committed-source
   snapshot, the interface-widening mechanism never fires at all. Live
   `.qa-repos` scan finding count is unchanged at 253, identical to
   before this change. Not a bug - the module's own docstring already
   states this ceiling - but it had not been verified end-to-end until
   this QA pass did so, and it should be stated plainly rather than
   assumed to have closed the original gap.

**Tests/adversarial checks run:**
- 7 new tests in `tests/test_cwe_284.py`: the real motivating shape
  (interface has `@GetMapping`, concrete override has neither annotation
  - now correctly found, was previously invisible); the interface-auth
  caveat case (interface has `@PreAuthorize` too - still found, now with
  the caveat, never suppressed); the own-class-authorization case (own
  `@PreAuthorize` on the override - still correctly suppressed, no
  caveat, since this coverage is not proxy-dependent); the
  unimplemented-interface non-leak case (a second, unrelated interface
  sharing a method name must never contribute); the Tree-sitter fallback
  parity case; and the order-independence regression test for the
  collision fix.
- Full `pytest -q`: 345 passed (was 344 before the collision-fix
  regression test), all four static gates clean.
- Independent QA (fresh session): constructed and ran, not just reasoned
  about, every scenario above via real fixture files through
  `cwe_284.detect_in_java()` directly; traced the overload-false-positive
  limitation (an interface method sharing a name with an unrelated,
  differently-signed concrete method) and confirmed it produces exactly
  the documented failure mode (an over-broad false positive) and never a
  suppression; confirmed the nested-class exclusion produces zero
  findings without crashing; confirmed
  `evaluation/evaluate.py`/`thesis_run.py` have zero `cwe_284`/
  `detect_in_java` references by grep; confirmed
  `data/labeled/layer4_projects.json`/the trusted model contract are
  untouched by this change (their diffs are unrelated carryover from
  the earlier, separately-logged Layer-4 dataset-message-refresh work).
- Live re-verification against the real `.qa-repos` corpus after the
  collision fix: identical 253-finding count across two separate runs.

**Remaining limitations:** CWE-20's parameter-annotation equivalent
remains unbuilt (needs a new `ParsedParameter` annotation capability
first, on both parser paths). The name-only, no-overload-resolution
matching is a stated, coarse-match limitation consistent with every
other heuristic in this codebase - confirmed by QA to fail only in the
safe direction (over-broad false positive on an unrelated same-named
overload), never a suppression. The interface-widening mechanism has
zero measured effect on the real `.qa-repos` corpus today, since the
motivating interface lives under correctly-excluded build output in that
repo's current snapshot - it would need either a project that commits
its generated interface source, or a scan run after `mvn
generate-sources`, to demonstrate real-world effect.

**Why:** Endpoint-annotation widening was made unconditional because
Spring MVC's interface-annotation resolution is a genuine, always-true
framework feature - there is no proxy-style ambiguity for routing,
unlike authorization. Authorization was deliberately kept caveat-only
because the CGLIB-vs-JDK-proxy distinction is real, not visible to static
analysis, and silently trusting it would have traded a well-understood,
already-logged gap for a less-understood, silently-introduced one - the
same mistake this project has explicitly avoided multiple times before
(e.g. the severity-floor revert on 2026-09-04). The collision bug was
fixed by exclusion rather than by picking a "best guess" candidate for
the same reason CWE-1035 refuses to flag a dependency with an unresolved
version: a coarse heuristic that guesses when it can't actually resolve
something is a worse failure mode for a security tool than one that
admits the limit.

**Effect on thesis chapters:** Chapter 5's CWE-284 evaluation gains a
third caveat mechanism (project-wide centralized-auth, per-method
hand-rolled-guard, and now per-method interface-authorization), each
targeting a structurally different way real Java code expresses "an
access-control decision was made" that annotation-only detection alone
cannot see - worth presenting as a cumulative pattern, not three
unrelated patches. Chapter 5 should also report the honest zero-effect
finding against `.qa-repos` plainly, alongside the fix's real, positive
effect demonstrated in the accompanying test suite - a defensible,
precisely-scoped result rather than an overstated "gap closed" claim.
Chapter 6 (future work) should list CWE-20's parameter-annotation
equivalent as a concrete, now well-motivated next item, and package-aware
(not just simple-name) interface resolution as a second, smaller
possible refinement if broader real-repo testing finds the current
exclusion-on-collision behavior too conservative in practice.

**Second independent QA pass (fresh session, specifically re-attacking
the collision fix, not the feature as a whole): confirmed correct.**
Beyond the two file orderings the existing regression test already
covers, verified all 6 permutations of the 3-file fixture (with and
without unrelated files padded before/after - not position-sensitive),
a 3-way collision (generalizes past the pairwise case), and that parsing
the same file twice into two distinct `ParsedFile` objects is correctly
*not* treated as a collision with itself (`Path` equality is value-based,
confirmed directly). Proved the regression test is non-vacuous, not just
present: reverted `build_interface_method_index` to the old last-write-
wins logic, reran the test, confirmed it **fails** exactly as expected
(order `(a, b, controller)` finds nothing, order `(b, a, controller)`
finds the violation), then restored the file byte-identical (md5-verified)
and reran the full suite clean.

That pass also found one new, real, but narrowly-scoped bug this fix did
not touch: the sibling function `top_level_interfaces_by_type_name` has
an analogous, unfixed collision - but only within a *single file*
declaring two top-level types with the identical simple name, which is
not valid Java (`javac` rejects this as a duplicate-class compile error)
and therefore cannot occur in any real, compiling source file, unlike the
cross-file collision this entry's fix addresses (confirmed 14 times in
real, compiling `.qa-repos` code). It is also a false-positive-direction
failure, not a false negative - the less severe of the two directions per
this project's own stated CWE-284 priority. Logged here as a known,
deliberately-unfixed limitation (malformed-input-only) rather than
chased, consistent with this project's practice of not building defenses
against inputs that cannot arise from valid source.

**Freeze / handoff:** This reopens frozen Layer 1 on the same "real-world
QA found a blocking gap" grounds already established repeatedly for it.
Two independent QA passes have now run: the first found the collision
bug and the unrelated test-assertion deletion (both fixed by this
session), the second specifically re-verified the collision fix itself
and found it correct, using a revert-and-confirm-failure technique
against its own regression test rather than only reading the code. This
entry was drafted by the same session that built the feature, at the
student's explicit request - per Section 9, do not treat it as settled
project history until the student confirms it.

---

## [2026-09-14] - CWE-20 extended to recognize @RequestBody/@Valid inherited from an implemented interface's parameters

**Status: DRAFT, pending student review** (see note at end).

**What the plan said:** The CWE-284 interface-annotation entry immediately
above deliberately scoped CWE-20 out: "the annotations that matter for
CWE-20 (`@RequestBody`, `@Valid`) live at *parameter* level, and Layer 1's
`ParsedParameter` does not capture parameter annotations at all today -
extending this same approach to CWE-20 needs that additional AST
capability first." Asked directly whether to build that missing piece
now that the method-level half existed and was independently QA'd,
student said yes.

**What we actually did:**

1. **`ParsedParameter` gained an `annotations: tuple[str, ...] = ()`
   field**, populated on both parser paths (javalang's `_build_method`,
   Tree-sitter's `_tree_sitter_method`) - the exact missing AST capability
   the deferral named. Default-valued for backward compatibility; no
   existing call site constructs `ParsedParameter` directly (confirmed by
   grep before changing the dataclass).

2. **`_interface_annotations.py` gained `build_interface_parameter_index()`**,
   keyed by `(type_name, method_name, parameter_index)` - matched by
   *position*, not parameter name, since an overriding method may legally
   rename its parameters relative to the interface (parameter names are
   not part of the method contract in Java). Reuses the same ambiguous-
   simple-type-name exclusion as the method-level index, refactored into
   a shared `_collect_ambiguous_type_names()` both index builders now
   call, rather than duplicating that logic a second time. Also extracted
   `nearest_enclosing_type()` (a javalang AST-traversal helper) out of
   `cwe_284.py`'s private copy into this shared module, since `cwe_20.py`
   needed the identical thing - `cwe_284.py` updated to import and reuse
   it instead of keeping its own copy.

3. **A deliberate asymmetry, more conservative than CWE-284's own
   method-level treatment.** Method-level routing-annotation inheritance
   (reused unchanged from `cwe_284.py`'s `resolve_effective_annotations`)
   widens freely - Spring MVC's route registration is a documented,
   proxy-independent framework feature. Parameter-level inheritance is
   treated more cautiously on *both* sides, not just the authorization
   side the way CWE-284 split it: an interface-inherited `@RequestBody`
   still widens which parameters get checked at all (the same
   fail-toward-more-scrutiny direction), but an interface-inherited
   `@Valid`/`@Validated` never silently suppresses a finding - it adds an
   explicit caveat (`_INTERFACE_VALIDATION_CAVEAT`) instead, because
   whether Spring's `HandlerMethod`/argument-resolution machinery actually
   honors a parameter annotation declared only on the interface (rather
   than the concrete override's own parameter) depends on which `Method`
   object gets resolved at runtime - not visible to static analysis, and
   not established as a proxy-independent guarantee the way method-level
   routing annotations are.

4. **`main.py`'s `_run_rules()` and `evaluation/human_baseline.py`'s
   `_run_all_rules()`** both updated to build the new parameter index
   once per scan (alongside the existing method index) and pass both into
   `cwe_20.detect_in_java()`.

**Tests/adversarial checks run:**
- 5 new tests in `tests/test_cwe_20.py`: the real motivating shape
  (interface has `@RequestBody`, concrete override has neither annotation
  - now correctly found, was previously invisible); the interface-
  validation caveat case (interface also has `@Valid` - still found, with
  caveat, never suppressed); the own-parameter-validation case (own
  `@Valid` on the override - fully suppressed, no caveat, since that
  coverage is not proxy-dependent); position-based matching when the
  override renames its parameters; Tree-sitter fallback parity.
- Full `pytest -q`: 350 passed (was 345), all four static gates clean.
- Verified live end-to-end against a real two-file reproduction of the
  codegen-controller pattern through the actual `main.py` CLI, not just
  unit tests.
- Independent QA (fresh session, no memory of the build): traced and
  confirmed the asymmetric caveat logic directly (both directions);
  confirmed position-based matching including an out-of-range-index probe
  (returns `()` safely, no crash) and a 3-parameter case where only the
  middle position carries an annotation; confirmed `cwe_284.py`'s
  behavior and its 42-test suite are unaffected by the
  `nearest_enclosing_type` extraction; confirmed the `_NOT_VALIDATABLE_TYPES`
  exclusion still works when the triggering annotation is interface-
  inherited; ran the real CLI against all four `.qa-repos` with no
  crashes. **Found and reproduced a real bug in the new parameter index's
  collision handling before confirming the shipped code prevents it**:
  disabled the ambiguous-name filter in `build_interface_parameter_index`,
  reproduced a genuine order-dependent false positive (two files
  declaring distinct `PaymentApi` interfaces sharing a simple name - a
  controller implementing the unannotated one still incorrectly inherited
  `@RequestBody` from the unrelated annotated one, purely depending on
  file-processing order), then restored the filter and confirmed all 4
  orderings correctly yield zero findings. No bugs found in the shipped
  code itself.
- One incident during this QA pass, disclosed for completeness: the QA
  agent accidentally ran `git checkout` on `_interface_annotations.py`
  mid-review, discarding its uncommitted diff, and reconstructed it from
  a previously-captured diff. This session independently re-read the
  reconstructed file in full against what was actually authored, and
  independently re-ran the full suite and all four gates - both confirm
  the reconstruction is correct, not merely the QA agent's own claim.

**Real-world effect, measured not assumed:** Like its CWE-284 sibling,
this currently has **zero measurable effect** against the real
`.qa-repos` corpus (CWE-20 counts: 0, 0, 0, 5 across the four repos,
unchanged; no "interface" mentions in any report). None of the four
repos commits a non-generated interface declaring `@RequestBody` - the
same `target/generated-sources/` ceiling already logged for CWE-284.
Real and correct, currently dormant until it meets a project that commits
its generated interface source.

**Remaining limitations:** Name-only (not full-signature) matching
between an interface method and its override is the same coarse
precision every heuristic in this codebase already accepts - confirmed
by QA to fail only in the safe direction (an unrelated same-named
overload can produce an over-broad false positive, never a suppression).
JAX-RS's body-parameter equivalent remains out of scope, unchanged from
before this entry.

**Why:** The parameter-level asymmetry was made more conservative than
CWE-284's method-level split (caveat on *both* `@RequestBody` recognition
and `@Valid` suppression, not just suppression) because the mechanism
Spring actually uses to resolve a parameter annotation at argument-
binding time is less clearly documented as proxy-independent than route
registration is - erring toward "flag and caveat" rather than "silently
trust" on both counts was judged the safer default for a tool whose
stated priority is false negatives over false positives for exactly this
kind of candidate.

**Effect on thesis chapters:** Chapter 4 should describe
`build_interface_parameter_index` and its position-based (not name-based)
matching rationale, and the collision-safety mechanism as reused,
independently-tested infrastructure, not a one-off. Chapter 5's CWE-20
evaluation should report the same honest zero-effect-on-`.qa-repos`
finding as CWE-284's, for the same underlying reason, and should
highlight the asymmetric caveat design (endpoint-recognition widens
freely, parameter-level annotations never silently suppress) as a
deliberate methodology choice, citable as evidence of a considered,
not reflexive, extension of the CWE-284 pattern.

**Freeze / handoff:** This reopens frozen Layer 1 on the same "a bounded,
well-scoped extension of an already-established, already-QA'd pattern"
grounds as its CWE-284 sibling. One independent QA pass has run and found
no bugs in the shipped parameter-matching/caveat logic (it did find and
confirm the fix for a collision-handling bug, the same class already
fixed once for the method-level index). This entry was drafted by the
same session that built the feature, at the student's explicit request -
per Section 9, do not treat it as settled project history until the
student confirms it.

---

## [2026-10-02] - Local environment repaired; a real `requirements.txt` bug found and fixed (missing `pandas`); dependency audit re-verified clean

**What the plan said:** N/A - this entry starts from a broken local dev
environment found at the start of a session, not a planned task. The
machine's macOS build had changed (Darwin 25.6.0 -> 27.0.0, i.e. a major
OS update) between sessions with no corresponding code change in the
repository.

**What we actually did / found:**

1. **A real, reproducible local breakage, root-caused rather than
   papered over.** `pytest -q` failed to even collect 8 test modules:
   anything importing `vibeguard.layer4_ml` (and therefore `main.py`,
   `evaluation/*`) failed with `ImportError: dlopen(...): section
   '__DATA/__thread_bss' has a zero-fill section type, but offset field
   is not zero` inside `scipy.sparse.linalg._propack._spropack` - a
   compiled extension three imports deep inside `scikit-learn`'s own
   `import scipy.linalg`, not anything VibeGuard's code touches directly.
   Force-reinstalling the same pinned versions (`scipy`, then `numpy`)
   did not fix it; no newer `scipy` wheel exists for Python 3.10. Built a
   completely fresh scratch venv from `requirements.txt` alone and
   reproduced the identical failure there too - confirmed this is not
   specific to one checkout's venv state, but a genuine incompatibility
   between PyPI's prebuilt `scipy` 1.15.3 wheel and this particular macOS
   build. Anyone cloning this repo on the same OS build hits this.

2. **Fixed by building `scipy` from source against the local toolchain**,
   not by chasing a wheel that doesn't exist: installed `gcc` (bundles
   `gfortran`) and `openblas` via Homebrew, then
   `pip install --no-binary scipy --force-reinstall scipy==1.15.3` with
   `PKG_CONFIG_PATH` pointed at the Homebrew OpenBLAS - produced a wheel
   tagged `macosx_27_0_arm64` (built natively for the installed OS,
   unlike the stale PyPI wheel) that imports correctly. Restored the
   pinned `numpy==1.26.3` afterward (the source build's own dependency
   resolution had drifted it to 2.2.6). Documented the fix in README.md's
   Setup section so a future session (or the student, on the same
   machine) doesn't have to re-diagnose this from scratch.

3. **A real, previously-undetected bug in `requirements.txt` found as a
   direct consequence of rebuilding the environment: `pandas` is missing,
   and it is not dead weight.** The 2026-09-02 dependency-cleanup entry
   removed `pandas` as "pinned early on but never actually used anywhere
   in the codebase" - true of VibeGuard's own direct imports, but that
   check missed that `shap` imports `pandas` unconditionally at its own
   top level (`shap/_explanation.py`). This had silently worked until now
   only because the venvs in use already had a stale `pandas` installed
   from before the 2026-09-02 removal; `pip install -r requirements.txt`
   never re-installs a package that isn't listed, so the gap was invisible
   unless something forced a fresh environment. Confirmed directly: a
   genuinely fresh venv built from the current `requirements.txt` fails
   `import shap` outright with `ModuleNotFoundError: No module named
   'pandas'`. Restored `pandas` (pinned to `2.3.3`, the current release,
   verified compatible with the pinned `numpy==1.26.3`) to
   `requirements.txt` and to `CLAUDE.md`/`AGENTS.md`'s Section 6
   dependency list and its explanatory note, which both repeated the
   incorrect "dead weight" characterization. Also added `pytest-cov`
   (already correctly pinned in `requirements.txt` and used in CI, but
   missing from that same illustrative Section 6 list) so the two don't
   drift again.

4. **Dependency audit re-run and found genuinely clean for the first time
   since this was last checked.** `CLAUDE.md`/`AGENTS.md` carried an
   explicit, precise caveat since 2026-09-10 that the audit was *not*
   clean (2 CVEs, both via `safety`'s own transitive chain, with no
   available upgrade path at the time). Re-running `safety check` against
   the full installed environment today found that picture had changed:
   6 CVEs now (5 in `nltk`, 1 in `cryptography` - both still pulled in
   only by `safety` itself, specifically `nltk>=3.9` and Authlib/joserfc's
   `cryptography` pin; confirmed via `pipdeptree --reverse`, neither is
   imported by VibeGuard's own runtime code). Checked for an upgrade path
   before re-documenting this as a permanent limitation, per this
   project's own stated practice: both `nltk` and `cryptography` had
   newer releases available on PyPI. Upgraded both
   (`pip install --upgrade nltk cryptography`), confirmed `safety` itself
   still functions correctly afterward, and re-ran the audit: **0
   vulnerabilities reported**, across the full installed environment, not
   just the subset `requirements.txt` pins directly. Corrected
   `CLAUDE.md`/`AGENTS.md`'s claim accordingly, while keeping the prior
   finding's history visible (append-only) rather than quietly replacing
   it - this list has now moved in both directions (clean -> not clean ->
   clean again) as upstream packages shipped and un-shipped fixes, which
   is itself worth stating plainly rather than treating either snapshot
   as permanent.

**Tests/adversarial checks run:**
- Full `pytest -q`: 350 passed, clean exit, both before touching
  `requirements.txt` (confirming the scipy fix alone was sufficient) and
  after (confirming the `pandas`/`nltk`/`cryptography` changes introduced
  no regression).
- `black --check .`, `ruff check .`, `mypy .`, `git diff --check`: all
  clean.
- The `requirements.txt` gap was verified by actually building a fresh
  venv from it end to end (not inferred from reading the file) - the
  failure reproduced exactly as described, confirming this was a real,
  not hypothetical, gap for anyone starting from a clean checkout.
- `safety check` re-run against the full installed environment (not just
  `requirements.txt`'s own pins) before and after the `nltk`/`cryptography`
  upgrade, confirming the before-count (6) and after-count (0) directly
  rather than assuming the upgrade worked.

**Remaining limitations:** The underlying `scipy`/macOS incompatibility
is a real upstream packaging gap on Apple's side (or at least outside
this project's control) for very new macOS builds specifically - the fix
documented here (build from source against Homebrew's toolchain) is a
workaround, not something VibeGuard's own `requirements.txt` can pin
around, since no alternative prebuilt wheel exists. A different machine
on an older, more common macOS release (or Linux, which is what CI
actually runs on) would likely never hit this at all. The dependency
audit's clean state is a snapshot, not a guarantee - restated explicitly
in `CLAUDE.md`/`AGENTS.md` this time, after already being wrong once in
each direction.

**Why:** The scipy failure was diagnosed to a real root cause (a stale
prebuilt wheel incompatible with a newer OS) rather than worked around
with an unrelated dependency downgrade, because downgrading `numpy`/
`scikit-learn` to dodge it would have drifted further from the project's
own pinned, audited dependency set for a problem that isn't actually
caused by those pins. The `pandas` gap was fixed at the source
(`requirements.txt` and the two architecture docs) rather than only in
the local venv, specifically because the local venv's accidental
staleness is exactly what let this real bug go undetected for a month -
fixing only the symptom here would have left the same trap for the next
fresh clone.

**Effect on thesis chapters:** Chapter 4/5's dependency-hygiene discussion
should cite the corrected, current audit result (0 vulnerabilities) and
the honest history of how that number has moved, rather than only the
snapshot from whichever entry is read. Chapter 4 should note `pandas` as
a genuine transitive runtime dependency (via `shap`), not incidental
bloat - the 2026-09-02 dead-weight removal pass's methodology (checking
only direct imports) should itself be named as a limitation of that
audit technique, since it is exactly what let a real dependency go
missing from `requirements.txt` for over a month without being caught by
CI (which had never run against a connection cold enough, or an OS
combination unusual enough, to force a truly from-scratch install that
would have caught it immediately).

**Freeze / handoff:** Not a reopening of any frozen Layer 1-5 behavior -
purely environment/dependency hygiene. No code in `vibeguard/`,
`evaluation/`, or `main.py` changed in this entry. Safe to treat as
settled: the fix was verified by reconstructing the exact failure from a
genuinely fresh environment, not merely patching the one venv already in
use.

---

## [2026-10-02] - CWE-1035 resolves dependency versions inherited from a local multi-module (reactor) parent POM

**Status: DRAFT, pending student review** (see note at end).

**What the plan said:** `pom_parser.py`'s own module docstring had always
stated this plainly as a known limitation: "Maven property substitution
(`${propertyName}`) is resolved against the local `<properties>` block
only; a property inherited from a parent POM this parser doesn't have
access to resolves to `None` (unresolved), not a guess." The 2026-09-02
real-repo entry measured the resulting recall gap directly (19/24
unresolved on `spring-petclinic-rest`, 162/204 on
`quarkus-super-heroes`) and the CLI's "Unchecked" column (also added
that day) made the gap visible rather than silent, but neither entry
attempted to close any of it. Asked directly whether a bounded, still
fully local fix existed, found one: when a project's parent is itself a
sibling `pom.xml` within the same scanned directory tree (a genuine
multi-module "reactor" project, as opposed to a third-party BOM resolved
from Maven Central/`~/.m2`), that parent's `<dependencyManagement>` and
`<properties>` are already sitting right there, unread.

**What we actually did:**

1. **`ParsedPomFile` gained three new fields**: `dependency_management`
   (a POM's own `<dependencyManagement>/<dependencies>` entries -
   version *constraints*, never themselves used dependencies, already
   the case for the direct-dependencies extraction and locked in by the
   pre-existing `test_parse_ignores_dependency_management_entries`),
   `parent` (a new `MavenParentReference` capturing the `<parent>`
   element's `groupId`/`artifactId`/`version`/`relativePath` - defaulting
   to Maven's own `../pom.xml` convention when `<relativePath>` is
   absent, and preserving an *explicitly empty* `<relativePath/>` as
   Maven's own "never resolve this parent locally" marker rather than
   falling back to the default), and `properties` (exposing what was
   already computed internally for single-file resolution, now needed
   cross-file too).

2. **New `resolve_inherited_versions()`** - a project-wide post-processing
   pass, run once per scan (the same architectural shape as Layer 1's
   existing interface-annotation indexes): for every parsed POM with a
   `<parent>` reference, walks up the chain of locally-available
   ancestors (stopping at the first ancestor not present in the same
   scan, an explicitly empty `relativePath`, a detected cycle, or a
   depth cap - never raises, never hangs on adversarial/malformed
   parent-chain input, verified directly with a constructed two-POM
   mutual-parent cycle), and fills in any dependency whose `version` was
   `None` using the nearest ancestor's `dependency_management` entry
   that itself resolves to a concrete version - a deliberate, stated
   simplification from Maven's own strict nearest-wins precedence
   (favouring successful resolution, this rule's whole purpose, over
   exact fidelity in the rarer case the two disagree). `raw_version`
   (what the child literally declared) is never altered, only `version`
   (the best resolved answer) - consistent with every other
   resolve-vs-report distinction already in this codebase.

3. **Wired into all three call sites that touch `pom_files`**:
   `main.py`'s `main()` (applied once, right after scanning, before both
   `_run_rules()` and `_print_pom_report()` see `result.pom_files`, so
   the "Unchecked" count and CWE-1035's findings stay consistent with
   each other), `evaluation/human_baseline.py`'s `_run_all_rules()`, and
   `evaluation/thesis_orchestrator.py`'s `_execute_scan()` (which calls
   `main.py`'s `_run_rules()` and renders its own pom report directly,
   bypassing `main()` entirely - missing this third site would have
   reproduced the exact "fixed in two places, forgotten in the third"
   pattern this project has hit before with the crash supervisor).

**Tests/adversarial checks run:**
- 6 new tests in `tests/test_pom_parser.py`: the real motivating shape
  (child has no `<version>` at all, parent's `dependencyManagement`
  resolves it); the dominant real-world case correctly doing nothing (no
  local parent in the scan - degrades to the pre-fix behavior, not a
  crash or a guess); the explicit-empty-`relativePath` marker correctly
  overriding the default-path fallback; a 3-level chain (grandparent's
  entry reached through an intermediate parent with no matching entry of
  its own); a constructed mutual-parent cycle correctly terminating
  rather than hanging; and the nearest-match-vs-resolved-match
  simplification.
- Full `pytest -q`: 356 passed (was 350), all four static gates clean.
- Verified live end-to-end through the actual `main.py` CLI against a
  constructed two-module reactor fixture carrying a real Log4Shell
  dependency with no declared version: before the fix, 1 unchecked
  dependency and 0 findings; after, 0 unchecked and a correct critical
  CWE-1035 finding, matched against the known-vulnerable entry.
- **Honestly measured against the real `.qa-repos` corpus, not assumed**:
  precisely diffed before/after dependency resolution across all of
  `quarkus-super-heroes`'s 10 POMs (204 total declared dependencies, 162
  unresolved) - **zero newly resolved**. Root-caused, not just observed:
  none of its 9 service modules declares a `<parent>` element at all,
  despite being listed as `<module>`s of the root aggregator POM - each
  manages its own dependencies independently, importing the external
  `quarkus-bom` directly rather than inheriting from a local parent. This
  is a different (and here, equally unresolvable locally) Maven pattern
  than the one this fix targets - not a bug in the implementation, and
  not fixable by also supporting BOM-`<scope>import</scope>` resolution
  either, since the referenced BOM is still a third-party artifact not
  present in this repository either way. The other three `.qa-repos`
  have no local parent/reactor relationships to test against at all.

**Remaining limitations:** Only helps when a project's parent (or an
ancestor further up the chain) is genuinely committed as a sibling file
within the same scanned directory tree - the dominant real-world pattern
actually observed so far (both repos tested at 2026-09-02, and now also
`quarkus-super-heroes`'s own module structure) is inheriting from a
third-party, externally-published parent or BOM, which no local-only
tool can resolve without either a network call or a local Maven
repository cache consultation - both rejected, the latter specifically
because it would make scan results depend on what happens to be cached
on the machine running the scan, undermining reproducibility between
machines scanning the identical repository. BOM import via
`<dependencyManagement>`'s `<scope>import</scope>` (a different Maven
mechanism than `<parent>` inheritance) is not resolved by this entry -
investigated and found it would not have helped either real case tested,
for the reason above, so not built speculatively.

**Why:** Scoped to local-parent-only resolution, explicitly excluding
both a live Maven Central query and a `~/.m2` cache consultation, for
the same "runs entirely locally, reproducibly" reason CWE-1035's offline
vulnerability database was chosen over a live lookup back on 2026-07-15 -
a tool whose results depend on what's cached on whichever machine
happens to run it is a worse outcome for a thesis evaluation methodology
than one that stays honestly unresolved in a stated, bounded way.

**Effect on thesis chapters:** Chapter 4 should document
`resolve_inherited_versions` as a project-wide Layer 1 pass, architecturally
parallel to the interface-annotation indexes, and state its exact scope
(local `<parent>` chains only, not BOM imports, not `~/.m2`). Chapter 5's
CWE-1035 evaluation should report the honest real-world measurement
plainly: a real, demonstrated fix for a genuine Maven pattern, with zero
effect so far on any of the four `.qa-repos` tested, each for its own
specific, now precisely diagnosed reason (two inherit from a third-party
parent; `quarkus-super-heroes`'s modules don't use `<parent>` inheritance
at all). This is the third time this exact honest-zero-effect finding
has been reported for a real, correctly-built fix (alongside the
CWE-284/CWE-20 interface-annotation work) - worth naming as a pattern in
its own right: `.qa-repos`'s four repositories, while valuable for
precision testing, do not currently exercise several of the specific
structural patterns this project's later fixes have targeted, which is
itself a scoped, concrete argument for the standing "add a fifth
real repo" item in Section 7.

**Freeze / handoff:** This reopens frozen Layer 1 on the same "a bounded,
local, deterministic improvement with a clear and honestly-stated
ceiling" grounds as this project's other real-repo-motivated fixes. Not
yet independently QA'd by a fresh session - recommend one before this is
treated as settled, specifically targeting the parent-chain cycle/depth
guard and the nearest-vs-resolved-match precedence choice, the two
places most likely to hide a subtle bug. This entry was drafted by the
same session that built the feature, at the student's explicit request -
per Section 9, do not treat it as settled project history until the
student confirms it.

---

## [2026-10-02] - CWE-284's hand-rolled guard detection follows a one-hop helper-method delegation

**Status: DRAFT, pending student review** (see note at end).

**What the plan said:** `has_inline_header_guard`'s own docstring stated
this plainly since 2026-09-10: "this intentionally only recognises the
guard inline in the endpoint method itself; a guard delegated to a
private helper method (one further hop) is a known, deliberately
deferred scope limit." The real motivating example was named explicitly
in that same entry - `ai-card-storage-service`'s `allowed(key)` helper,
observed but not built against at the time since the session's actual
need (two inline-comparison endpoints) was already fully addressed
without it. Asked directly whether to close that named, deferred gap
now, student said yes.

**What we actually did:**

1. **`has_inline_header_guard` gained an optional
   `sibling_methods_by_name` parameter** (default: empty mapping, so
   every existing call site without class context sees exactly the
   prior, inline-only behavior). When the direct, inline comparison
   isn't found, a new `_bails_out_via_helper_call` checks whether the
   bailing-out condition instead calls a **same-class** helper method
   (bare, e.g. `allowed(key)`, or `this`-qualified, e.g.
   `this.allowed(key)` - handling that qualifier distinction proactively
   this time, rather than waiting for adversarial testing to find it the
   way `cwe_287.py`'s `this.field` gap originally was) with a header
   parameter as one of its arguments, and if so, whether the helper's
   **own corresponding parameter** (matched by argument *position*, not
   name, since a helper's parameter name need not match the caller's) is
   itself compared via `.equals()`/`.contentEquals()`/`MessageDigest.isEqual()`
   anywhere in the helper's body - reusing the existing
   `_references_header_comparison` unchanged, just pointed at the
   helper's parameter name instead of an `@RequestHeader` one.

2. **New `_sibling_methods_by_name`** resolves a method's own enclosing
   class's other direct members (via the already-shared
   `nearest_enclosing_type`, extracted for the interface-annotation work
   earlier this session) - the same bounded, this-class-only scope
   already used throughout this module, not a cross-file or
   cross-inheritance resolution.

3. **Tree-sitter fallback mirror built alongside, not after** -
   `_tree_sitter_sibling_methods_by_name` and
   `_tree_sitter_bails_out_via_helper_call`, wired into
   `_hand_rolled_guard_methods_tree_sitter` (which switched from a plain
   `ts_walk` to `ts_walk_with_ancestors` to get the ancestor chain
   sibling resolution needs) - satisfying
   `tests/test_java_rule_fallback_coverage.py`'s dual-parser requirement
   from the start, the same proactive practice already applied to
   `cwe_20.py` earlier this session.

4. **A real process hiccup, caught by verification, not assumed fixed.**
   The first attempt at the javalang-path edit did not actually persist
   to disk - a subsequent `grep` confirmed only the Tree-sitter mirror
   had landed, with `has_inline_header_guard`'s signature and
   `_hand_rolled_guard_methods`'s caller still showing their pre-edit
   form. Caught immediately by re-grepping after the edit (a habit, not
   a one-off), not by trusting the edit tool's own success report;
   reapplied both changes and re-verified with `grep`/`mypy` before
   proceeding, then ran the full suite and gates twice more before
   calling this done. Logged here as a reminder that this project's
   "verify, don't assume" discipline applies to the build session's own
   tooling, not only to the code being built.

**Tests/adversarial checks run:**
- 7 new tests in `tests/test_cwe_284.py`: the real motivating shape
  (bare `allowed(key)` call, helper does the actual comparison); the
  pre-extension default behavior preserved when no sibling context is
  given; the `this.allowed(key)` qualifier variant; a call through an
  unrelated object (`other.allowed(key)`) correctly not followed even
  when a same-named method exists in this class; a helper that doesn't
  actually compare its forwarded parameter correctly not matching; the
  full per-file, end-to-end path (`detect_in_java` +
  `apply_hand_rolled_guard_context`, which builds the sibling map
  itself, not a hand-built one); and the Tree-sitter fallback parity
  case.
- Full `pytest -q`: 363 passed (was 356), all four static gates clean.
- Verified live end-to-end through the actual `main.py` CLI against a
  constructed reproduction of the real `ai-card-storage-service` shape -
  the finding correctly carries the hand-rolled-guard caveat.
- Re-ran the real `.qa-repos` corpus: no crashes, finding count unchanged
  at 253 (matching the established baseline), zero new hand-rolled-guard
  caveats - an honest, measured result, not assumed: none of the four
  real repositories happens to use this specific helper-delegation
  shape, so this extension (like the CWE-284/CWE-20 interface-annotation
  work and the CWE-1035 reactor-POM fix earlier this session) has
  real-world effect only against the AI-generated dataset it was
  originally observed in, not the current `.qa-repos` corpus.

**Remaining limitations:** Still exactly one hop - a guard delegated
through two or more levels of helper indirection (the helper itself
calls another helper) is not followed, an even narrower, unobserved-so-far
case than the one just closed. Matching by argument position assumes the
helper's parameter order corresponds to how it's called at each call
site actually used by this detection (always exactly one call site
matters, enforced implicitly by only acting on the first matching
condition found) - not a general call-site/parameter-binding resolver.

**Why:** Built now because the gap had a named, real, specific
motivating example already in the dataset (not a speculative future
case), and the one-hop bound keeps this addition as narrowly scoped and
auditable as the rest of this module's existing hand-rolled-guard logic
- extending to arbitrary-depth helper chains would need something closer
to real call-graph analysis, a materially larger undertaking this
project has consistently declined to build speculatively.

**Effect on thesis chapters:** Chapter 4 should describe this as closing
a specifically-named, previously-logged scope limit (not a newly
discovered gap), and can cite the `this`-qualifier handling as a second
instance of this project proactively applying a lesson (javalang's
representational variation for `this`-qualified access) rather than
waiting to be bitten by it again. Chapter 5's CWE-284 evaluation should
report the same honest zero-effect-on-`.qa-repos` finding as the other
two extensions built this session, continuing to support the standing
argument that a fifth, structurally different real repository remains
the highest-value remaining evaluation step.

**Freeze / handoff:** This reopens frozen Layer 1 on the same
"closing a specifically-named, already-logged deferred gap" grounds as
the rest of this session's Layer 1 work. Not yet independently QA'd by a
fresh session - recommend one before this is treated as settled,
specifically targeting the `this`-qualifier detection on both parser
paths and the argument-position-matching logic, the two places most
likely to hide a subtle bug. This entry was drafted by the same session
that built the feature, at the student's explicit request - per Section
9, do not treat it as settled project history until the student confirms
it.

## [2026-10-03] - Layer 5 explainer.py test coverage closed from 69% to 100%
**What the plan said:** no explicit prior plan targeted this file; it surfaced
as an item in a full-project gap analysis as the lowest-covered module in the
codebase, on the part of the pipeline that is itself a thesis claim (Layer 5
explainability).
**What we actually did / found:** `vibeguard/layer5_report/explainer.py` was
at 69% coverage (26 of 84 statements uncovered), almost entirely the
fail-closed `ValueError` shape-validation branches inside
`_select_predicted_feature_values()` (ndim==3/2/1 SHAP value arrays) and
`_select_predicted_base_value()` (ndim==2/1/0 baseline arrays), plus one
defense-in-depth check at the top of `_explain_row()`. Added 21 new tests to
`tests/test_layer5_report.py`, each constructing a hand-built numpy array of
a specific wrong shape and asserting the correct `ValueError` message, for
every branch identified: all three 3D rejection branches (wrong sample
count, wrong class axis, out-of-range index), the 2D single-output valid
path, both 2D rejection branches, both 1D branches (reject-for-multiclass
and valid-for-single-output), the unexpected-ndim catch-all, and the
equivalent set for `_select_predicted_base_value` including the previously
untested 1-element-1D case (genuinely distinct from the already-covered
0-dimensional scalar case). `_explain_row`'s own line 106-107 defense-in-depth
check — unreachable via real numpy indexing given the exhaustive validation
already inside `_select_predicted_feature_values` — was exercised by
monkeypatching `_select_predicted_feature_values` directly to return a
non-1D array, bypassing its own internal validation, confirming the second
guard independently catches what the first guard's contract is supposed to
rule out.
**Why:** this file validates the exact SHAP shape-handling logic the 2026-07-30
independent QA pass hardened; the previously-uncovered branches were the
fail-closed guards protecting against SHAP ever returning a shape this
project's own code doesn't expect. Closing coverage here means a future
change to this file that breaks one of these guards will be caught by a
failing test, not discovered later against a real multiclass model.
**Tests/adversarial checks run:** `pytest tests/test_layer5_report.py
tests/test_layer5_plain_summary.py --cov=vibeguard.layer5_report
--cov-report=term-missing` → 100% coverage across all five files in
`layer5_report/` (was 69% on `explainer.py` specifically). Full suite:
`pytest -q` → 384 passed. All four gates (`black --check`, `ruff check`,
`mypy`, `git diff --check`) clean.
**Effect on thesis chapters:** Chapter 4/5 - strengthens the "Layer 5 is
independently verified, not just QA'd once" claim with a concrete coverage
number (100%, up from 69%) for the module doing the actual SHAP output
interpretation. No behavioral change to the tool; test-only addition.

Status: DRAFT, pending student review.
