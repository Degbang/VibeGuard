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
extracted as used dependencies - not ``<profiles>`` (conditionally-
activated dependencies, deferred). ``<dependencyManagement>`` entries are
extracted separately (``ParsedPomFile.dependency_management``) - not
themselves used dependencies, but a real, common source of a *direct*
dependency's version in a multi-module project: see
``resolve_inherited_versions`` below.

Maven property substitution (``${propertyName}``) is resolved against
the local ``<properties>`` block only at the single-file level; a
property inherited from a parent POM not available in the same scan
resolves to ``None`` (unresolved), not a guess. ``resolve_inherited_versions``
extends this across files, but only for a parent genuinely present in
the same scan - never a network fetch, never a local Maven repository
cache (``~/.m2``) consultation, since the latter would make scan results
depend on whatever happens to be cached on the machine running the scan,
undermining reproducibility between different machines scanning the
identical repository.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path

from vibeguard.layer1_static._parsing_guards import (
    ParseStatus,
    ParsingGuardError,
    read_text_within_limit,
    run_with_timeout,
)

_DEFAULT_PARENT_RELATIVE_PATH = "../pom.xml"
_MAX_PARENT_CHAIN_DEPTH = 10

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
class MavenParentReference:
    """A child POM's ``<parent>`` declaration.

    ``relative_path`` is always populated - Maven's own default
    (``../pom.xml``) when the POM omits ``<relativePath>``, or the
    explicit value otherwise, including an explicitly empty one (Maven's
    own convention for "never resolve this parent locally, always use
    the repository copy") - callers must treat an empty string as "no
    local parent to look for," not as a relative path to resolve.
    """

    group_id: str
    artifact_id: str
    version: str | None
    relative_path: str


@dataclass(frozen=True)
class ParsedPomFile:
    """Structured result of parsing one ``pom.xml`` file.

    ``group_id``/``artifact_id``/``version`` are this POM's own literal
    ``<project>``-level self-declaration, used by ``resolve_inherited_versions``
    to confirm a POM found at a resolved ``<relativePath>`` is genuinely the
    declared parent, not just whatever file happens to sit at that path.
    ``artifact_id`` is always present on a well-formed POM (Maven never lets
    it be inherited); ``group_id``/``version`` may be ``None`` on a child POM
    that inherits them from its own parent.
    """

    path: Path
    status: ParseStatus
    dependencies: tuple[MavenDependency, ...] = ()
    dependency_management: tuple[MavenDependency, ...] = ()
    parent: MavenParentReference | None = None
    properties: Mapping[str, str] = field(default_factory=dict)
    group_id: str | None = None
    artifact_id: str | None = None
    version: str | None = None
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
    dependency_management = _extract_dependency_management(root, properties, text)
    parent = _extract_parent(root)
    return ParsedPomFile(
        path=resolved,
        status=ParseStatus.OK,
        dependencies=dependencies,
        dependency_management=dependency_management,
        parent=parent,
        properties=properties,
        group_id=_child_text(root, "groupId"),
        artifact_id=_child_text(root, "artifactId"),
        version=_child_text(root, "version"),
    )


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
    """Extract direct ``<project>/<dependencies>/<dependency>`` entries - the
    dependencies this POM actually declares using, as opposed to
    ``<dependencyManagement>``'s version constraints (see
    ``_extract_dependency_management``)."""
    dependencies_element = _find_child(root, "dependencies")
    if dependencies_element is None:
        return ()
    return _extract_dependency_entries(dependencies_element, properties, source_text)


def _extract_dependency_management(
    root: ET.Element, properties: dict[str, str], source_text: str
) -> tuple[MavenDependency, ...]:
    """Extract ``<project>/<dependencyManagement>/<dependencies>/<dependency>``
    entries - version *constraints* a child module can inherit, not
    themselves used dependencies of this POM (see
    ``test_parse_ignores_dependency_management_entries``, which locks in
    that these never appear in ``ParsedPomFile.dependencies``). Exposed
    separately specifically so ``resolve_inherited_versions`` can use a
    parent POM's management block to resolve a child's otherwise-unresolved
    direct dependency version."""
    management_element = _find_child(root, "dependencyManagement")
    if management_element is None:
        return ()
    dependencies_element = _find_child(management_element, "dependencies")
    if dependencies_element is None:
        return ()
    return _extract_dependency_entries(dependencies_element, properties, source_text)


def _extract_dependency_entries(
    dependencies_element: ET.Element, properties: dict[str, str], source_text: str
) -> tuple[MavenDependency, ...]:
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


def _extract_parent(root: ET.Element) -> MavenParentReference | None:
    """Extract the ``<project>/<parent>`` declaration, if any."""
    parent_element = _find_child(root, "parent")
    if parent_element is None:
        return None
    group_id = _child_text(parent_element, "groupId")
    artifact_id = _child_text(parent_element, "artifactId")
    if group_id is None or artifact_id is None:
        return None
    relative_path_element = _find_child(parent_element, "relativePath")
    if relative_path_element is None:
        relative_path = _DEFAULT_PARENT_RELATIVE_PATH
    else:
        # An explicitly empty <relativePath/> is Maven's own convention for
        # "never resolve this parent locally" - preserved as "" rather than
        # falling back to the default, so resolve_inherited_versions can
        # tell the two cases apart and correctly skip the empty one.
        relative_path = (relative_path_element.text or "").strip()
    return MavenParentReference(
        group_id=group_id,
        artifact_id=artifact_id,
        version=_child_text(parent_element, "version"),
        relative_path=relative_path,
    )


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


def resolve_inherited_versions(parsed_poms: Iterable[ParsedPomFile]) -> tuple[ParsedPomFile, ...]:
    """Re-resolve unresolved dependency versions against a parent POM that
    is genuinely part of the same scan - a real, common Maven pattern
    (a multi-module "reactor" project) found to matter in practice:
    most of a real project's dependencies typically have no ``<version>``
    at all, inherited from a parent's ``<dependencyManagement>`` rather
    than a ``${property}`` reference (see IMPLEMENTATION_LOG.md's
    2026-09-02 entry, which measured this directly against real
    Spring Boot/Quarkus repositories).

    This does **not** close that measured recall gap for every project:
    it only ever helps when the parent is a sibling ``pom.xml`` within
    the *same scanned directory tree* (a true multi-module reactor
    project where both the parent and child are in this repository).
    When a project's parent is a third-party artifact resolved from
    Maven Central or a local ``~/.m2`` cache at build time (the actual
    situation for both real repositories measured in that 2026-09-02
    entry, e.g. ``spring-boot-starter-parent``), this function correctly
    does nothing, by design - consulting ``~/.m2`` would make scan
    results depend on whatever happens to be cached on the machine
    running the scan, which is a worse tradeoff than staying honestly
    unresolved: two different machines scanning the identical repository
    could otherwise get different CWE-1035 results.

    Args:
        parsed_poms: Every ``ParsedPomFile`` from one scan, in any order.

    Returns:
        The same POMs, in the same order, with any dependency whose
        ``version`` was ``None`` replaced by a resolved version wherever
        one was found in a locally-available ancestor's
        ``dependency_management`` - ``raw_version`` (what the child
        itself literally declared) is never changed, only ``version``
        (the best resolved answer). A POM with no locally-resolvable
        parent, or with every dependency already resolved, is returned
        unchanged.
    """
    materialized = tuple(parsed_poms)
    by_path = {pom.path: pom for pom in materialized if pom.status == ParseStatus.OK}

    result = []
    for pom in materialized:
        if pom.status != ParseStatus.OK or pom.parent is None:
            result.append(pom)
            continue
        parent_chain = _walk_parent_chain(pom, by_path)
        if not parent_chain:
            result.append(pom)
            continue
        updated_dependencies = tuple(
            (
                dependency
                if dependency.version is not None
                else _resolve_from_chain(dependency, parent_chain)
            )
            for dependency in pom.dependencies
        )
        if updated_dependencies == pom.dependencies:
            result.append(pom)
        else:
            result.append(replace(pom, dependencies=updated_dependencies))
    return tuple(result)


def _walk_parent_chain(
    pom: ParsedPomFile, by_path: Mapping[Path, ParsedPomFile]
) -> list[ParsedPomFile]:
    """Return ``pom``'s locally-available ancestor chain, nearest first.

    Stops at the first ancestor not present in the same scan (the common
    case - a parent resolved from Maven Central or ``~/.m2``, not a
    sibling file), an explicitly empty ``<relativePath>`` (Maven's own
    "never resolve this parent locally" marker), a ``<relativePath>`` whose
    resolved file does not actually match the declared ``<parent>``
    coordinates (see ``_parent_identity_matches``), a cycle, or
    ``_MAX_PARENT_CHAIN_DEPTH`` hops, whichever comes first. Never raises
    and never guesses past what is actually available in this scan.
    """
    chain: list[ParsedPomFile] = []
    visited: set[Path] = {pom.path}
    current = pom
    for _ in range(_MAX_PARENT_CHAIN_DEPTH):
        if current.parent is None or not current.parent.relative_path:
            break
        candidate_path = (current.path.parent / current.parent.relative_path).resolve()
        if candidate_path.is_dir():
            candidate_path = candidate_path / "pom.xml"
        parent_pom = by_path.get(candidate_path)
        if parent_pom is None or parent_pom.path in visited:
            break
        if not _parent_identity_matches(current.parent, parent_pom):
            break
        chain.append(parent_pom)
        visited.add(parent_pom.path)
        current = parent_pom
    return chain


def _parent_identity_matches(parent_ref: MavenParentReference, candidate: ParsedPomFile) -> bool:
    """Confirm the POM found at a resolved ``<relativePath>`` is genuinely
    the declared ``<parent>``, not merely whatever file happens to sit at
    that path.

    A ``<relativePath>`` is a file-position hint, not an identity
    guarantee - Maven itself falls back to repository resolution when the
    coordinates don't match, and this parser must do the same rather than
    trusting position alone. ``artifact_id`` is the one Maven coordinate
    every POM must declare for itself (it is never inherited), so a
    mismatch there is conclusive. ``group_id``/``version`` are compared
    only when the candidate declares them itself; a child POM is allowed
    to omit both and inherit them from its own parent, so their absence is
    never treated as a mismatch.

    Note the asymmetry this implies: a *child's own* ``<parent>`` block
    omitting ``<version>`` (non-compliant with real Maven, which requires
    all three sub-elements there) is not given the same forgiveness - it
    compares the candidate's real, present version against ``None`` and
    fails the match. This is intentional, not an oversight: it fails
    toward the safe "unresolved" direction (a recall miss) rather than
    toward silently accepting a parent this parser cannot actually
    confirm, consistent with this function's whole purpose.
    """
    if candidate.artifact_id != parent_ref.artifact_id:
        return False
    if candidate.group_id is not None and candidate.group_id != parent_ref.group_id:
        return False
    if candidate.version is not None and candidate.version != parent_ref.version:
        return False
    return True


def _resolve_from_chain(
    dependency: MavenDependency, parent_chain: list[ParsedPomFile]
) -> MavenDependency:
    managed_version = _find_managed_version(
        dependency.group_id, dependency.artifact_id, parent_chain
    )
    if managed_version is None:
        return dependency
    return replace(dependency, version=managed_version)


def _find_managed_version(
    group_id: str, artifact_id: str, parent_chain: list[ParsedPomFile]
) -> str | None:
    """Search the ancestor chain, nearest first, for a resolved managed version.

    Maven's own precedence is strictly "nearest declaration wins," even
    if that nearest declaration doesn't itself fully resolve (e.g. it
    references a property only a grandparent defines). This function
    instead keeps searching past an unresolved nearest match for a
    *resolved* version further up the chain - a deliberate, stated
    simplification that favours successfully resolving a version (this
    rule's whole purpose) over exact Maven fidelity in the rarer case
    where the two disagree.
    """
    for ancestor in parent_chain:
        for managed in ancestor.dependency_management:
            if (
                managed.group_id == group_id
                and managed.artifact_id == artifact_id
                and managed.version is not None
            ):
                return managed.version
    return None
