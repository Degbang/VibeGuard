"""Layer 1 Gradle build.gradle/build.gradle.kts parsing: extracts declared dependencies.

**Deliberately a narrow text heuristic, not a Gradle parser.**
``build.gradle``/``build.gradle.kts`` are executable Groovy/Kotlin DSL
code, not declarative data - correctly parsing either language in
full would need a real grammar (``tree-sitter-groovy``/
``tree-sitter-kotlin``), a materially larger undertaking than this
module attempts (see ``pom_parser.py``'s own docstring, which first
named this exact tradeoff and deferred it). This module only
recognizes one specific, extremely common shape: a dependency
configuration call (``implementation``, ``api``, ``compileOnly``,
``compileOnlyApi``, ``runtimeOnly``, ``testImplementation``,
``testCompileOnly``, ``testRuntimeOnly``, ``annotationProcessor``,
``testAnnotationProcessor``, and the legacy pre-Gradle-7
``compile``/``testCompile``) followed by a single-quoted or
double-quoted ``"group:artifact[:version]"`` string literal, in
either Groovy's space-separated form (``implementation
"group:artifact:version"``) or Kotlin DSL's parenthesized form
(``implementation("group:artifact:version")``).

**Known, accepted, out-of-scope limitations** (not failures - this
module never claims to recognize these, and a dependency declared only
this way is simply never extracted, never guessed at):
- Gradle version catalogs (``implementation(libs.log4j.core)``,
  ``libs.versions.toml``) - no string literal at all to match.
- A dependency assembled from a variable or Groovy/Kotlin string
  interpolation (``"$group:$artifact:$version"``,
  ``"group:artifact:${version}"``) - see
  ``_RESOLVED_VERSION_PATTERN`` below for why this is specifically
  guarded against, not just an accident of the regex.
- ``ext``/``project.ext`` properties, ``buildSrc`` convention plugins,
  platform/BOM-only imports beyond the plain group:artifact (no
  version) shape.
- A single configuration call declaring more than one dependency via
  Groovy's comma-separated argument list (``runtimeOnly 'group:a:v',
  'group:b:v'``) - only the first is extracted; the second has no
  configuration-name keyword immediately before it, so it's invisible
  to this heuristic. Confirmed as a real, not just anticipated, gap by
  running this parser against a real repository's ``build.gradle``
  (``.qa-repos/spring-boot-realworld-example-app-20260904`` - see
  IMPLEMENTATION_LOG.md's 2026-10-10 entry) and finding exactly this
  shape.
- Dependency declarations inside a ``buildscript { dependencies { ... } }``
  block (Gradle's own build-time plugin classpath, not the application's
  own runtime/compile dependencies) are *not specifically excluded* -
  but in practice this is a non-issue rather than an unhandled gap:
  real ``buildscript`` blocks exclusively use the ``classpath``
  configuration name, which is deliberately *not* in the recognized
  list above (it has no meaning in a Java/Kotlin application's own
  ``dependencies {}`` block), so a real buildscript-only dependency
  simply never matches at all.

Only ever extracts a GAV (group:artifact:version) string into a
``MavenDependency`` - reused directly rather than defining a parallel
Gradle-specific record, since CWE-1035's own checking logic
(``cwe_1035._check_dependency``) only ever needs group/artifact/
version/line, nothing Maven-specific. Only ever parses text with
Python's ``re`` module and plain string scanning - never executes or
evaluates any part of the Groovy/Kotlin DSL content, the same
never-execute guarantee every other Layer 1 parser in this codebase
makes.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from vibeguard.layer1_static._parsing_guards import (
    ParseStatus,
    ParsingGuardError,
    read_text_within_limit,
    run_with_timeout,
)
from vibeguard.layer1_static.pom_parser import MavenDependency

DEFAULT_MAX_FILE_BYTES = 2_000_000
DEFAULT_PARSE_TIMEOUT_SECONDS = 5.0

# Longer, more specific names first (e.g. "compileOnly" before "compile")
# so the alternation's first-match-wins semantics can never accidentally
# prefer a shorter generic name over a more specific one that also
# matches at the same position - defensive, since in practice a
# camelCase boundary (no \b between "test" and "Implementation") already
# rules out the cross-matches this would otherwise guard against.
_DEPENDENCY_CONFIGURATIONS = tuple(
    sorted(
        (
            "implementation",
            "api",
            "compileOnly",
            "compileOnlyApi",
            "runtimeOnly",
            "testImplementation",
            "testCompileOnly",
            "testRuntimeOnly",
            "annotationProcessor",
            "testAnnotationProcessor",
            "compile",
            "testCompile",
        ),
        key=len,
        reverse=True,
    )
)

_DEPENDENCIES_BLOCK_PATTERN = re.compile(r"\bdependencies\s*\{")
_DEPENDENCY_DECLARATION_PATTERN = re.compile(
    r"\b(" + "|".join(_DEPENDENCY_CONFIGURATIONS) + r")\b\s*[(]?\s*['\"]([^'\"]+)['\"]"
)
# A real artifact version is virtually always digit-leading
# ("2.15.0", "4.0.0.Final", "5.3.1-SNAPSHOT"). A Groovy/Kotlin variable
# or string-interpolation reference ("$version", "${version}", a bare
# property name) never is - matching this is what keeps an unresolved
# template string from being passed through as if it were a real,
# comparable version (which would otherwise make CWE-1035's own version
# comparison treat it as version "0", a real false-positive risk this
# was checked against directly, not just assumed safe).
_RESOLVED_VERSION_PATTERN = re.compile(r"^[0-9][\w.+-]*$")


@dataclass(frozen=True)
class ParsedGradleFile:
    """Structured result of parsing one ``build.gradle``/``build.gradle.kts`` file."""

    path: Path
    status: ParseStatus
    dependencies: tuple[MavenDependency, ...] = ()
    error_message: str | None = None


def parse_gradle_file(
    path: Path,
    *,
    max_bytes: int = DEFAULT_MAX_FILE_BYTES,
    timeout_seconds: float = DEFAULT_PARSE_TIMEOUT_SECONDS,
) -> ParsedGradleFile:
    """Parse a single Gradle build file into its recognizable declared dependencies.

    Returns:
        A ParsedGradleFile whose ``status`` reflects exactly what
        happened (too large, unreadable, empty, timed out); every
        failure mode is a value, never an exception, so one bad build
        file can never abort a batch scan. ``status == OK`` with zero
        dependencies means either "this file declares none" or "every
        dependency here uses a shape this heuristic doesn't recognize"
        - indistinguishable by design, the same honest limitation every
        other heuristic-based rule in this codebase already carries.
    """
    resolved = path.resolve()

    try:
        text = read_text_within_limit(resolved, max_bytes)
    except ParsingGuardError as exc:
        status = ParseStatus.FILE_TOO_LARGE if exc.too_large else ParseStatus.PARSE_FAILED
        return ParsedGradleFile(path=resolved, status=status, error_message=str(exc))

    if not text.strip():
        return ParsedGradleFile(path=resolved, status=ParseStatus.EMPTY_FILE)

    try:
        dependencies = run_with_timeout(
            _extract_dependencies, text, timeout_seconds=timeout_seconds
        )
    except TimeoutError:
        return ParsedGradleFile(
            path=resolved,
            status=ParseStatus.PARSE_TIMEOUT,
            error_message=f"parse exceeded {timeout_seconds}s budget",
        )

    return ParsedGradleFile(path=resolved, status=ParseStatus.OK, dependencies=dependencies)


def _extract_dependencies(text: str) -> tuple[MavenDependency, ...]:
    dependencies: list[MavenDependency] = []
    for block_text, block_offset in _find_dependencies_blocks(text):
        for match in _DEPENDENCY_DECLARATION_PATTERN.finditer(block_text):
            parsed = _parse_coordinate(match.group(2))
            if parsed is None:
                continue
            group_id, artifact_id, version, raw_version = parsed
            absolute_offset = block_offset + match.start(2)
            dependencies.append(
                MavenDependency(
                    group_id=group_id,
                    artifact_id=artifact_id,
                    version=version,
                    raw_version=raw_version,
                    line=text.count("\n", 0, absolute_offset) + 1,
                )
            )
    return tuple(dependencies)


def _parse_coordinate(coordinate: str) -> tuple[str, str, str | None, str | None] | None:
    """Split a ``group:artifact[:version]`` string into its parts.

    Returns ``None`` if it doesn't even look like a GAV coordinate (not
    exactly 2 or 3 non-empty colon-separated segments) - e.g. a project
    reference (``":some-module"``) or a plain URL, neither of which this
    heuristic should ever mistake for a real Maven coordinate.
    """
    parts = [part.strip() for part in coordinate.split(":")]
    if len(parts) == 2:
        group_id, artifact_id = parts
        if not group_id or not artifact_id:
            return None
        return group_id, artifact_id, None, None
    if len(parts) == 3:
        group_id, artifact_id, raw_version = parts
        if not group_id or not artifact_id or not raw_version:
            return None
        version = raw_version if _RESOLVED_VERSION_PATTERN.match(raw_version) else None
        return group_id, artifact_id, version, raw_version
    return None


def _find_dependencies_blocks(text: str) -> list[tuple[str, int]]:
    """Find every brace-matched ``dependencies { ... }`` block's inner text
    and its starting character offset within ``text``.

    Searches resume *after* each matched block's closing brace, not just
    past the opening one - otherwise a literal "dependencies {" occurring
    a second time *inside* an already-extracted block (e.g. a real but
    unusual nested wrapper) would be independently re-matched and
    re-walked, double-extracting every dependency inside it. A block
    whose opening brace has no matching close (malformed/truncated
    input) stops the search entirely rather than guessing past it -
    whatever was found before that point is still returned.
    """
    blocks: list[tuple[str, int]] = []
    search_start = 0
    while True:
        match = _DEPENDENCIES_BLOCK_PATTERN.search(text, search_start)
        if match is None:
            break
        open_brace_index = match.end() - 1
        close_brace_index = _find_matching_brace(text, open_brace_index)
        if close_brace_index is None:
            break
        inner_start = open_brace_index + 1
        blocks.append((text[inner_start:close_brace_index], inner_start))
        search_start = close_brace_index + 1
    return blocks


def _find_matching_brace(text: str, open_brace_index: int) -> int | None:
    """Find the index of the ``}`` that closes the ``{`` at ``open_brace_index``.

    Plain depth counting over every ``{``/``}`` character in the text -
    does not understand string literals or comments, so a literal brace
    character inside a quoted string or a comment is (rarely, but
    possibly) miscounted. Accepted as a known limitation of a
    deliberately narrow heuristic, not a correctness goal this module
    claims to meet in full.
    """
    depth = 0
    for index in range(open_brace_index, len(text)):
        character = text[index]
        if character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth == 0:
                return index
    return None
