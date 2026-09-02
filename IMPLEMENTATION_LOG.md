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
