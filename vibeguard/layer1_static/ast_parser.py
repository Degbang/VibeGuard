"""Layer 1 AST parsing: converts Java source files into structured ParsedFile objects.

This module only ever tokenizes and parses Java source text via
``javalang``. It never executes, compiles, or ``eval``s any content from
a target file — VibeGuard analyses untrusted, AI-generated code and must
never run it.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import TypeAlias

import javalang
from javalang.tree import (
    ClassDeclaration,
    CompilationUnit,
    FieldDeclaration,
    InterfaceDeclaration,
    MethodDeclaration,
)

logger = logging.getLogger(__name__)

DEFAULT_MAX_FILE_BYTES = 2_000_000
DEFAULT_PARSE_TIMEOUT_SECONDS = 5.0

_ClassOrInterfaceDeclaration: TypeAlias = ClassDeclaration | InterfaceDeclaration


class ParseStatus(str, Enum):
    """Outcome of attempting to parse a single Java source file.

    Every outcome is represented explicitly so a file that can't be
    parsed is always flagged in results, never silently dropped.
    """

    OK = "ok"
    EMPTY_FILE = "empty_file"
    FILE_TOO_LARGE = "file_too_large"
    PARSE_TIMEOUT = "parse_timeout"
    PARSE_FAILED = "parse_failed"


@dataclass(frozen=True)
class ParsedParameter:
    """A single method parameter."""

    name: str
    type_name: str


@dataclass(frozen=True)
class ParsedField:
    """A class field declaration."""

    name: str
    type_name: str
    modifiers: frozenset[str]
    line: int | None


@dataclass(frozen=True)
class ParsedMethod:
    """A method declaration within a class or interface."""

    name: str
    line: int | None
    modifiers: frozenset[str]
    parameters: tuple[ParsedParameter, ...]
    return_type: str


@dataclass(frozen=True)
class ParsedClass:
    """A top-level class or interface declaration.

    Nested/inner types, enums, and annotation declarations are not
    flattened into ``ParsedClass`` in this version of the parser; see
    IMPLEMENTATION_LOG.md for the scope decision.
    """

    name: str
    line: int | None
    modifiers: frozenset[str]
    annotations: tuple[str, ...]
    superclass: str | None
    interfaces: tuple[str, ...]
    fields: tuple[ParsedField, ...]
    methods: tuple[ParsedMethod, ...]


@dataclass(frozen=True)
class ParsedFile:
    """Structured result of parsing one Java source file.

    ``tree`` retains the full javalang AST so downstream CWE rule
    modules can traverse beyond what ``classes`` summarizes (e.g.
    locating string literals or call expressions anywhere in the file).
    It is ``None`` whenever ``status`` is not ``ParseStatus.OK``.
    """

    path: Path
    status: ParseStatus
    package: str | None = None
    imports: tuple[str, ...] = ()
    classes: tuple[ParsedClass, ...] = ()
    error_message: str | None = None
    tree: CompilationUnit | None = field(default=None, repr=False, compare=False)


def parse_file(
    path: Path,
    *,
    max_bytes: int = DEFAULT_MAX_FILE_BYTES,
    timeout_seconds: float = DEFAULT_PARSE_TIMEOUT_SECONDS,
) -> ParsedFile:
    """Parse a single Java source file into a ParsedFile.

    Args:
        path: Path to the ``.java`` source file. The caller (e.g.
            ``scanner.py``) is responsible for resolving this path and
            verifying it lies inside the expected sample-apps root
            before calling this function; that containment check is not
            repeated here.
        max_bytes: Reject files larger than this to bound memory and
            parse time on adversarial input.
        timeout_seconds: Soft wall-clock budget for the parse call. See
            ``_run_with_timeout`` for the limitations of this guard.

    Returns:
        A ParsedFile whose ``status`` reflects exactly what happened.
        Every failure mode (too large, unreadable, empty, timed out,
        syntax error) is returned as a value, never raised, so a single
        bad file can never abort a batch scan.
    """
    resolved = path.resolve()

    size_failure = _check_size(resolved, max_bytes)
    if size_failure is not None:
        return size_failure

    source = _read_source(resolved)
    if isinstance(source, ParsedFile):
        return source
    if not source.strip():
        return ParsedFile(path=resolved, status=ParseStatus.EMPTY_FILE)

    return _parse_source(resolved, source, timeout_seconds)


def _check_size(path: Path, max_bytes: int) -> ParsedFile | None:
    """Return a failure ParsedFile if ``path`` can't be stat'd or is too large."""
    try:
        size = path.stat().st_size
    except OSError as exc:
        logger.warning("Cannot stat %s: %s", path, exc)
        return ParsedFile(path=path, status=ParseStatus.PARSE_FAILED, error_message=str(exc))
    if size > max_bytes:
        logger.warning("Rejecting %s: %d bytes exceeds max_bytes=%d", path, size, max_bytes)
        return ParsedFile(
            path=path,
            status=ParseStatus.FILE_TOO_LARGE,
            error_message=f"{size} bytes exceeds max_bytes={max_bytes}",
        )
    return None


def _read_source(path: Path) -> str | ParsedFile:
    """Read ``path`` as UTF-8 text, returning a failure ParsedFile on error."""
    try:
        return path.read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeDecodeError) as exc:
        logger.warning("Cannot read %s: %s", path, exc)
        return ParsedFile(path=path, status=ParseStatus.PARSE_FAILED, error_message=str(exc))


def _parse_source(path: Path, source: str, timeout_seconds: float) -> ParsedFile:
    """Run javalang over ``source`` and convert the outcome into a ParsedFile."""
    try:
        tree = _run_with_timeout(javalang.parse.parse, source, timeout_seconds=timeout_seconds)
    except TimeoutError:
        logger.warning("Parse timed out after %.1fs: %s", timeout_seconds, path)
        return ParsedFile(
            path=path,
            status=ParseStatus.PARSE_TIMEOUT,
            error_message=f"parse exceeded {timeout_seconds}s budget",
        )
    except javalang.parser.JavaSyntaxError as exc:
        message = _syntax_error_message(exc)
        logger.warning("Syntax error parsing %s: %s", path, message)
        return ParsedFile(path=path, status=ParseStatus.PARSE_FAILED, error_message=message)
    except Exception as exc:  # pragma: no cover - defensive: javalang internals are not fully typed
        logger.warning("Unexpected error parsing %s: %s", path, exc)
        return ParsedFile(path=path, status=ParseStatus.PARSE_FAILED, error_message=str(exc))

    return _build_parsed_file(path, tree)


def _syntax_error_message(exc: javalang.parser.JavaSyntaxError) -> str:
    """Extract a human-readable message from a JavaSyntaxError.

    ``str(exc)`` on this exception is empty in javalang 0.13 - the
    actual message (e.g. "Expected type") lives on ``exc.description``.
    """
    description = getattr(exc, "description", None)
    return description or str(exc) or exc.__class__.__name__


def _run_with_timeout(
    parse_func: Callable[[str], CompilationUnit], source: str, *, timeout_seconds: float
) -> CompilationUnit:
    """Run ``parse_func(source)`` on a daemon thread with a wall-clock budget.

    This is a soft mitigation, not true isolation: on timeout the
    background thread is abandoned (marked ``daemon=True`` so it can't
    block interpreter exit) rather than killed, since CPython has no
    supported way to forcibly stop a running thread. It bounds how long
    a caller waits on a single pathological file without hanging the
    overall scan; it does not bound the CPU the orphaned thread burns.
    True process-level isolation (subprocess per file) was considered
    unnecessary overhead for this project's scope — see
    IMPLEMENTATION_LOG.md.
    """
    thread_result: dict[str, object] = {}

    def _invoke_parse_func_in_background() -> None:
        try:
            thread_result["return_value"] = parse_func(source)
        except Exception as exc:  # re-raised on the caller's thread below
            thread_result["exception"] = exc

    parse_thread = threading.Thread(target=_invoke_parse_func_in_background, daemon=True)
    parse_thread.start()
    parse_thread.join(timeout=timeout_seconds)
    if parse_thread.is_alive():
        raise TimeoutError(f"parse exceeded {timeout_seconds}s budget")
    if "exception" in thread_result:
        raise thread_result["exception"]  # type: ignore[misc]
    return thread_result["return_value"]


def _build_parsed_file(path: Path, tree: CompilationUnit) -> ParsedFile:
    """Flatten a javalang CompilationUnit into a successful ParsedFile."""
    package = tree.package.name if tree.package is not None else None
    imports = tuple(imp.path for imp in tree.imports)

    parsed_classes = []
    for node in tree.types:
        if isinstance(node, ClassDeclaration | InterfaceDeclaration):
            parsed_classes.append(_build_class(node))
        else:
            logger.debug(
                "Skipping unsupported top-level declaration %s in %s", type(node).__name__, path
            )

    return ParsedFile(
        path=path,
        status=ParseStatus.OK,
        package=package,
        imports=imports,
        classes=tuple(parsed_classes),
        tree=tree,
    )


def _build_class(node: _ClassOrInterfaceDeclaration) -> ParsedClass:
    """Convert a javalang class/interface declaration into a ParsedClass."""
    fields = tuple(
        parsed_field
        for decl in node.body
        if isinstance(decl, FieldDeclaration)
        for parsed_field in _build_fields(decl)
    )
    methods = tuple(
        _build_method(member) for member in node.body if isinstance(member, MethodDeclaration)
    )
    return ParsedClass(
        name=node.name,
        line=_line_number_of(node),
        modifiers=frozenset(node.modifiers),
        annotations=tuple(annotation.name for annotation in node.annotations),
        superclass=_superclass_name(node),
        interfaces=_interface_names(node),
        fields=fields,
        methods=methods,
    )


def _build_fields(decl: FieldDeclaration) -> tuple[ParsedField, ...]:
    """Expand one FieldDeclaration into one ParsedField per declared variable."""
    type_name = _type_name(decl.type)
    modifiers = frozenset(decl.modifiers)
    line = _line_number_of(decl)
    return tuple(
        ParsedField(name=declarator.name, type_name=type_name, modifiers=modifiers, line=line)
        for declarator in decl.declarators
    )


def _build_method(node: MethodDeclaration) -> ParsedMethod:
    """Convert a javalang MethodDeclaration into a ParsedMethod."""
    parameters = tuple(
        ParsedParameter(name=parameter.name, type_name=_type_name(parameter.type))
        for parameter in node.parameters
    )
    return ParsedMethod(
        name=node.name,
        line=_line_number_of(node),
        modifiers=frozenset(node.modifiers),
        parameters=parameters,
        return_type=_type_name(node.return_type),
    )


def _line_number_of(node: object) -> int | None:
    """Extract the source line number from a javalang node, if available."""
    position = getattr(node, "position", None)
    return position.line if position is not None else None


def _type_name(type_node: object | None) -> str:
    """Render a javalang type node (or None, for ``void``) as a string.

    This is a summary for reporting/features, not a full generics-aware
    type printer: array dimensions are rendered as ``[]`` suffixes, but
    generic type arguments are not expanded.
    """
    if type_node is None:
        return "void"
    name = getattr(type_node, "name", None)
    if name is None:
        return type_node.__class__.__name__
    dimensions = getattr(type_node, "dimensions", None) or []
    return f"{name}{'[]' * len(dimensions)}"


def _superclass_name(node: _ClassOrInterfaceDeclaration) -> str | None:
    """Extract the superclass name for a class declaration.

    Interfaces have no superclass in this model: javalang represents
    ``interface Foo extends Bar, Baz`` as a list on ``extends``, which
    are extended interfaces, not a superclass — those are captured by
    ``_interface_names`` instead.
    """
    if isinstance(node, InterfaceDeclaration):
        return None
    extends = getattr(node, "extends", None)
    return _type_name(extends) if extends is not None else None


def _interface_names(node: _ClassOrInterfaceDeclaration) -> tuple[str, ...]:
    """Extract implemented/extended interface names.

    Handles both ``implements`` (classes) and interface ``extends``
    (which javalang models as a list for InterfaceDeclaration).
    """
    if isinstance(node, InterfaceDeclaration):
        extended_interfaces = getattr(node, "extends", None) or []
        return tuple(_type_name(interface_type) for interface_type in extended_interfaces)
    implemented_interfaces = getattr(node, "implements", None) or []
    return tuple(_type_name(interface_type) for interface_type in implemented_interfaces)
