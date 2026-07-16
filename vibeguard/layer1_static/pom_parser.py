"""Layer 1 Maven pom.xml parsing: extracts declared dependencies.

Scoped to Maven (``pom.xml``) only. Gradle's ``build.gradle``/
``build.gradle.kts`` are executable Groovy/Kotlin DSL code, not
declarative data - parsing them correctly is a materially different,
harder problem than parsing structured XML, left for a future pass
rather than guessed at with regex.

Only ever parses text into a tree via Python's stdlib
``xml.etree.ElementTree`` - never executes anything from the file.
Verified empirically (not assumed) against the classic XML attack
patterns before shipping, since this parses untrusted, potentially
adversarial ``pom.xml`` files from public repos: external entity
references (XXE, e.g. reading local files) are not resolved by
``ET.fromstring`` at all - it raises ``undefined entity`` instead.
Internal entity-expansion ("billion laughs") is only rejected by
CPython's bundled expat amplification-ceiling protection (a native
guard added in Python 3.7.1+) once a payload is large enough to trip
it - a small or moderate internal entity expands successfully and
returns a parsed tree, confirmed directly by testing a crafted
``<!DOCTYPE>``/``<!ENTITY>`` payload sized well under that ceiling
(see IMPLEMENTATION_LOG.md for the earlier, now-corrected claim that
this was fully rejected). To close that gap without a new dependency,
any ``pom.xml`` containing a ``<!DOCTYPE`` declaration is rejected
outright before parsing: a legitimate Maven POM never declares one, so
this has no cost in the false-positive direction and removes internal
entity expansion as an attack surface entirely, not just above some
size threshold.

Only *direct* ``<project>/<dependencies>/<dependency>`` entries are
extracted - not ``<dependencyManagement>`` (those are version
constraints for child modules, not necessarily used directly) and not
``<profiles>`` (conditionally-activated dependencies, deferred).
Maven property substitution (``${propertyName}``) is resolved against
the local ``<properties>`` block only; a property inherited from a
parent POM this parser doesn't have access to resolves to ``None``
(unresolved), not a guess.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

from vibeguard.layer1_static._parsing_guards import (
    ParseStatus,
    ParsingGuardError,
    read_text_within_limit,
    run_with_timeout,
)

DEFAULT_MAX_FILE_BYTES = 2_000_000
DEFAULT_PARSE_TIMEOUT_SECONDS = 5.0

_PROPERTY_REFERENCE_PATTERN = re.compile(r"^\$\{(.+)\}$")
_DOCTYPE_PATTERN = re.compile(r"<!DOCTYPE", re.IGNORECASE)


@dataclass(frozen=True)
class MavenDependency:
    """A single ``<dependency>`` declared directly under ``<dependencies>``.

    ``version`` is the *resolved* version (after ``${property}``
    substitution), or ``None`` if it references a property this parser
    couldn't find locally (e.g. inherited from an unavailable parent
    POM) - callers must treat ``None`` as "version unknown," never as
    "not vulnerable."
    """

    group_id: str
    artifact_id: str
    version: str | None
    raw_version: str | None
    line: int | None


@dataclass(frozen=True)
class ParsedPomFile:
    """Structured result of parsing one ``pom.xml`` file."""

    path: Path
    status: ParseStatus
    dependencies: tuple[MavenDependency, ...] = ()
    error_message: str | None = None


def parse_pom_file(
    path: Path,
    *,
    max_bytes: int = DEFAULT_MAX_FILE_BYTES,
    timeout_seconds: float = DEFAULT_PARSE_TIMEOUT_SECONDS,
) -> ParsedPomFile:
    """Parse a single ``pom.xml`` file into its declared dependencies.

    Returns:
        A ParsedPomFile whose ``status`` reflects exactly what
        happened; every failure mode (too large, unreadable, empty,
        timed out, malformed XML) is a value, never an exception, so
        one bad pom.xml can never abort a batch scan.
    """
    resolved = path.resolve()

    try:
        text = read_text_within_limit(resolved, max_bytes)
    except ParsingGuardError as exc:
        status = ParseStatus.FILE_TOO_LARGE if exc.too_large else ParseStatus.PARSE_FAILED
        return ParsedPomFile(path=resolved, status=status, error_message=str(exc))

    if not text.strip():
        return ParsedPomFile(path=resolved, status=ParseStatus.EMPTY_FILE)

    if _DOCTYPE_PATTERN.search(text):
        return ParsedPomFile(
            path=resolved,
            status=ParseStatus.PARSE_FAILED,
            error_message=(
                "pom.xml contains a <!DOCTYPE> declaration, which is never valid in a "
                "real Maven POM and is rejected outright to rule out XML entity injection"
            ),
        )

    try:
        root = run_with_timeout(ET.fromstring, text, timeout_seconds=timeout_seconds)
    except TimeoutError:
        return ParsedPomFile(
            path=resolved,
            status=ParseStatus.PARSE_TIMEOUT,
            error_message=f"parse exceeded {timeout_seconds}s budget",
        )
    except ET.ParseError as exc:
        return ParsedPomFile(path=resolved, status=ParseStatus.PARSE_FAILED, error_message=str(exc))

    properties = _extract_properties(root)
    dependencies = _extract_dependencies(root, properties, text)
    return ParsedPomFile(path=resolved, status=ParseStatus.OK, dependencies=dependencies)


def _local_tag(element: ET.Element) -> str:
    """Strip any XML namespace from an element's tag.

    Real pom.xml files almost always declare the Maven POM 4.0.0
    namespace, but not universally (some minimal/generated files omit
    it) - comparing local tag names rather than hardcoding the
    namespace URI handles both without guessing which one a given file
    uses.
    """
    return element.tag.rsplit("}", 1)[-1]


def _find_child(element: ET.Element, tag: str) -> ET.Element | None:
    for child in element:
        if _local_tag(child) == tag:
            return child
    return None


def _find_children(element: ET.Element, tag: str) -> list[ET.Element]:
    return [child for child in element if _local_tag(child) == tag]


def _child_text(element: ET.Element, tag: str) -> str | None:
    child = _find_child(element, tag)
    if child is None or child.text is None:
        return None
    return child.text.strip()


def _extract_properties(root: ET.Element) -> dict[str, str]:
    properties_element = _find_child(root, "properties")
    if properties_element is None:
        return {}
    return {_local_tag(child): (child.text or "").strip() for child in properties_element}


def _extract_dependencies(
    root: ET.Element, properties: dict[str, str], source_text: str
) -> tuple[MavenDependency, ...]:
    dependencies_element = _find_child(root, "dependencies")
    if dependencies_element is None:
        return ()

    result = []
    for dependency_element in _find_children(dependencies_element, "dependency"):
        group_id = _child_text(dependency_element, "groupId")
        artifact_id = _child_text(dependency_element, "artifactId")
        if group_id is None or artifact_id is None:
            continue
        raw_version = _child_text(dependency_element, "version")
        result.append(
            MavenDependency(
                group_id=group_id,
                artifact_id=artifact_id,
                version=_resolve_version(raw_version, properties),
                raw_version=raw_version,
                line=_find_line(source_text, artifact_id),
            )
        )
    return tuple(result)


def _resolve_version(raw_version: str | None, properties: dict[str, str]) -> str | None:
    """Resolve a ``${propertyName}`` reference against the local <properties> block."""
    if raw_version is None:
        return None
    match = _PROPERTY_REFERENCE_PATTERN.match(raw_version)
    if match is None:
        return raw_version
    return properties.get(match.group(1))


def _find_line(source_text: str, artifact_id: str) -> int | None:
    """Best-effort line lookup for a dependency's <artifactId> text.

    ElementTree does not expose source line numbers (a real stdlib
    limitation, unlike e.g. lxml). Falls back to a text search for
    "<artifactId>...</artifactId>"'s opening tag - if the same
    artifactId string appears more than once in the file (e.g. also
    under dependencyManagement, or in a comment), this can return the
    wrong occurrence. Accepted as a known limitation rather than adding
    a new XML library dependency for line tracking alone.
    """
    needle = f">{artifact_id}<"
    for line_number, line in enumerate(source_text.splitlines(), start=1):
        if needle in line:
            return line_number
    return None
