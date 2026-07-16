"""Layer 1 scanner: orchestrates ast_parser/config_parser/pom_parser across a directory tree.

Never executes or evaluates any content from a target file: Java source
is only ever parsed into an AST via ``javalang``, config files are only
ever parsed into key-value pairs via a hand-rolled reader
(``.properties``) or PyYAML's ``SafeLoader`` (``.yml``/``.yaml``), and
``pom.xml`` is only ever parsed into an element tree via the stdlib
``xml.etree.ElementTree`` - none of these paths construct or run
arbitrary code from the file being analysed.

This module's one added responsibility beyond the individual parsers is
directory-tree orchestration with path-traversal containment: every file
handed to a parser is verified, after resolving symlinks, to sit inside
the configured scan root. A sample-apps repository can contain a symlink
(accidental, or adversarial in a public-repo dataset) that points outside
the intended root; without this check, such a file would be silently
parsed and its findings misattributed to the scanned project. See
IMPLEMENTATION_LOG.md for how this was verified with a real symlink
escape rather than assumed safe.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path

from vibeguard.layer1_static.ast_parser import (
    DEFAULT_MAX_FILE_BYTES,
    DEFAULT_PARSE_TIMEOUT_SECONDS,
    ParsedFile,
    parse_file,
)
from vibeguard.layer1_static.config_parser import (
    CONFIG_FILE_SUFFIXES,
    ParsedConfigFile,
    parse_config_file,
)
from vibeguard.layer1_static.pom_parser import ParsedPomFile, parse_pom_file

logger = logging.getLogger(__name__)

_JAVA_SUFFIX = ".java"
_POM_FILENAME = "pom.xml"
_RELEVANT_SUFFIXES = CONFIG_FILE_SUFFIXES | {_JAVA_SUFFIX}

# Build output, dependency caches, and IDE metadata: never *production*
# source. Build output contains verbatim *copies* of real source files
# (e.g. Maven copies src/main/resources/*.properties into
# target/classes/) that would double-count the same finding. Matched
# case-insensitively.
_EXCLUDED_DIR_NAMES = frozenset(
    {
        ".git",
        "target",  # Maven build output
        "build",  # Gradle build output
        "out",  # IntelliJ default build output
        "bin",  # Eclipse build output
        ".gradle",  # Gradle cache/wrapper
        ".mvn",  # Maven wrapper metadata
        "node_modules",  # JS deps, occasionally present in monorepos
        ".idea",  # IDE metadata
        ".vscode",  # IDE metadata
        ".settings",  # Eclipse project metadata
    }
)

# Test source roots are excluded too, but *only* when the directory name
# sits in a conventional location - directly under a "src" directory
# (Maven/Gradle's "src/test/..." layout) or at the scan root itself
# ("<root>/test(s)/..."). A bare name match anywhere in the tree would
# also exclude a *production* package that happens to be named "test"
# (e.g. "com.example.test"), which is a real, not hypothetical,
# false-exclusion risk - found via targeted testing, not assumed safe.
_TEST_DIR_NAMES = frozenset({"test", "tests"})


@dataclass(frozen=True)
class RejectedPath:
    """A discovered file that was excluded from the scan, and why."""

    path: Path
    reason: str


@dataclass(frozen=True)
class ScanResult:
    """Structured result of scanning one directory tree."""

    root: Path
    java_files: tuple[ParsedFile, ...]
    config_files: tuple[ParsedConfigFile, ...]
    pom_files: tuple[ParsedPomFile, ...]
    rejected_paths: tuple[RejectedPath, ...]


def scan_directory(
    root: Path,
    *,
    max_bytes: int = DEFAULT_MAX_FILE_BYTES,
    timeout_seconds: float = DEFAULT_PARSE_TIMEOUT_SECONDS,
) -> ScanResult:
    """Recursively parse every ``.java``/``.properties``/``.yml``/``.yaml``/
    ``pom.xml`` file under root.

    Args:
        root: Directory to scan. Resolved to its canonical, symlink-free
            form; every file discovered underneath it is re-verified to
            still resolve inside that canonical root before being
            parsed (see module docstring).
        max_bytes: Passed through to both parsers' per-file size limit.
        timeout_seconds: Passed through to both parsers' per-file soft
            timeout.

    Returns:
        A ScanResult. Files that fail the containment check are never
        parsed and never silently dropped - they show up in
        ``rejected_paths`` with a reason, the same fail-closed
        philosophy as the individual parsers' ``ParseStatus``.

    Raises:
        NotADirectoryError: If ``root`` doesn't resolve to an existing
            directory. This is a caller usage error, not adversarial
            scan input, so it's raised immediately rather than folded
            into the result.
    """
    resolved_root = root.resolve()
    if not resolved_root.is_dir():
        raise NotADirectoryError(f"{root} is not a directory")

    java_results: list[ParsedFile] = []
    config_results: list[ParsedConfigFile] = []
    pom_results: list[ParsedPomFile] = []
    rejected: list[RejectedPath] = []

    for candidate in _discover_candidate_files(resolved_root):
        rejection = _containment_rejection(candidate, resolved_root)
        if rejection is not None:
            rejected.append(rejection)
            continue
        if candidate.name.lower() == _POM_FILENAME:
            pom_results.append(
                parse_pom_file(candidate, max_bytes=max_bytes, timeout_seconds=timeout_seconds)
            )
        elif candidate.suffix.lower() == _JAVA_SUFFIX:
            java_results.append(
                parse_file(candidate, max_bytes=max_bytes, timeout_seconds=timeout_seconds)
            )
        else:
            config_results.append(
                parse_config_file(candidate, max_bytes=max_bytes, timeout_seconds=timeout_seconds)
            )

    return ScanResult(
        root=resolved_root,
        java_files=tuple(java_results),
        config_files=tuple(config_results),
        pom_files=tuple(pom_results),
        rejected_paths=tuple(rejected),
    )


def _discover_candidate_files(resolved_root: Path) -> list[Path]:
    """Walk ``resolved_root`` without following symlinked directories.

    ``os.walk``'s default ``followlinks=False`` means a symlinked
    subdirectory is listed but never descended into - this rules out
    symlink-cycle infinite recursion and directory-level escapes at the
    traversal level itself. A file-level symlink (a file *named* like a
    ``.java`` file that itself points outside root) can still appear
    here; that's what ``_containment_rejection`` guards against, as
    defense in depth.

    Directories in ``_EXCLUDED_DIR_NAMES`` are skipped unconditionally
    (case-insensitively): build output/IDE metadata (``.git``,
    ``target``/``build``) is skipped for correctness, since a compiled
    repo's build output often contains verbatim *copies* of source
    config files (Maven copies ``src/main/resources/*.properties`` into
    ``target/classes/``) that would otherwise be scanned as separate,
    duplicate findings.

    Test source roots (``test``/``tests``) are skipped too, but only
    when found in a conventional location - see ``_is_conventional_test_root``.
    Test fixtures routinely contain intentionally fake secrets (e.g.
    `"hunter2"` in a test setup), which would otherwise inflate finding
    counts and distort evaluation precision/recall against real
    repositories; scoping the exclusion to conventional roots keeps
    that benefit without silently dropping a production package that
    happens to be named ``test`` anywhere else in the tree (e.g.
    ``com.example.test``) - a real false-exclusion found via targeted
    testing, not a hypothetical one.
    """
    matches: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(resolved_root, followlinks=False):
        dirpath_obj = Path(dirpath)
        dirnames[:] = [
            d
            for d in dirnames
            if d.lower() not in _EXCLUDED_DIR_NAMES
            and not _is_conventional_test_root(dirpath_obj, d, resolved_root)
        ]
        for filename in filenames:
            candidate = dirpath_obj / filename
            if candidate.suffix.lower() in _RELEVANT_SUFFIXES or filename.lower() == _POM_FILENAME:
                matches.append(candidate)
    return sorted(matches)


def _is_conventional_test_root(dirpath: Path, dirname: str, resolved_root: Path) -> bool:
    """Whether ``dirpath/dirname`` is a conventional test source root.

    Only two shapes count: directly under a ``src`` directory (Maven/
    Gradle's ``src/test/...`` layout, including in a multi-module repo
    where ``src`` isn't at the scan root) or directly under the scan
    root itself (``<root>/test(s)/...``). Anything else - a nested
    package that happens to be named ``test``/``tests`` deeper in the
    tree without one of these two parents - is left alone and scanned
    like any other directory, since that shape is at least as likely to
    be production code as a real test root.
    """
    if dirname.lower() not in _TEST_DIR_NAMES:
        return False
    return dirpath == resolved_root or dirpath.name.lower() == "src"


def _containment_rejection(candidate: Path, resolved_root: Path) -> RejectedPath | None:
    """Return a RejectedPath if ``candidate`` resolves outside ``resolved_root``."""
    try:
        resolved_candidate = candidate.resolve()
    except OSError as exc:
        logger.warning("Rejecting %s: cannot resolve: %s", candidate, exc)
        return RejectedPath(path=candidate, reason=f"cannot resolve path: {exc}")

    if resolved_candidate.is_relative_to(resolved_root):
        return None

    logger.warning(
        "Rejecting %s: resolves to %s, outside scan root %s (possible symlink escape)",
        candidate,
        resolved_candidate,
        resolved_root,
    )
    return RejectedPath(
        path=candidate,
        reason=f"resolves to {resolved_candidate}, outside scan root {resolved_root}",
    )
