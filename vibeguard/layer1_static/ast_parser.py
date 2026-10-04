"""Layer 1 AST parsing: converts Java source files into structured ParsedFile objects.

This module only ever tokenizes and parses Java source text via
``javalang``/Tree-sitter. It never executes, compiles, or ``eval``s any
content from a target file — VibeGuard analyses untrusted,
AI-generated code and must never run it.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
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
from tree_sitter import Node

from vibeguard.layer1_static._java_unicode import translate_java_unicode_escapes
from vibeguard.layer1_static._modern_java_preprocessor import preprocess
from vibeguard.layer1_static._parsing_guards import (
    ParseStatus,
    ParsingGuardError,
    read_text_within_limit,
    run_with_timeout,
)
from vibeguard.layer1_static._tree_sitter_java import (
    TreeSitterJavaFile,
    parse_java_source,
)
from vibeguard.layer1_static._tree_sitter_java import (
    annotation_names as ts_annotation_names,
)
from vibeguard.layer1_static._tree_sitter_java import (
    child_by_field as ts_child_by_field,
)
from vibeguard.layer1_static._tree_sitter_java import (
    declaration_name as ts_declaration_name,
)
from vibeguard.layer1_static._tree_sitter_java import (
    modifiers as ts_modifiers,
)
from vibeguard.layer1_static._tree_sitter_java import (
    node_line as ts_node_line,
)
from vibeguard.layer1_static._tree_sitter_java import (
    node_text as ts_node_text,
)
from vibeguard.layer1_static._tree_sitter_java import (
    type_name as ts_type_name,
)

logger = logging.getLogger(__name__)

DEFAULT_MAX_FILE_BYTES = 2_000_000
DEFAULT_PARSE_TIMEOUT_SECONDS = 5.0

_ClassOrInterfaceDeclaration: TypeAlias = ClassDeclaration | InterfaceDeclaration

__all__ = [
    "DEFAULT_MAX_FILE_BYTES",
    "DEFAULT_PARSE_TIMEOUT_SECONDS",
    "ParseStatus",
    "ParsedClass",
    "ParsedField",
    "ParsedFile",
    "ParsedMethod",
    "ParsedParameter",
    "parse_file",
]


@dataclass(frozen=True)
class ParsedParameter:
    """A single method parameter."""

    name: str
    type_name: str
    annotations: tuple[str, ...] = ()


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
    annotations: tuple[str, ...]
    parameters: tuple[ParsedParameter, ...]
    return_type: str


@dataclass(frozen=True)
class ParsedClass:
    """A top-level class or interface declaration.

    Nested/inner types, enums, and annotation declarations are not
    flattened into ``ParsedClass`` in this version of the parser; see
    IMPLEMENTATION_LOG.md for the scope decision.

    ``is_interface`` distinguishes an ``interface`` declaration from a
    ``class``/``record`` one - needed because an interface is never
    itself an instantiable, deployable type the way a class is; a rule
    that needs to know "is this type actually concrete" (see
    ``_interface_annotations.build_implementors_index``) cannot infer
    that from ``interfaces``/``superclass`` alone, since both a class's
    ``implements`` list and an interface's own ``extends`` list are
    already flattened into the same ``interfaces`` field.
    """

    name: str
    line: int | None
    modifiers: frozenset[str]
    annotations: tuple[str, ...]
    superclass: str | None
    interfaces: tuple[str, ...]
    fields: tuple[ParsedField, ...]
    methods: tuple[ParsedMethod, ...]
    is_interface: bool = False


@dataclass(frozen=True)
class ParsedFile:
    """Structured result of parsing one Java source file.

    ``tree`` retains the full javalang AST when javalang handled the
    file. ``tree_sitter`` retains the full Tree-sitter AST when the
    modern-Java fallback handled the file. Both are ``None`` whenever
    ``status`` is not ``ParseStatus.OK``.
    """

    path: Path
    status: ParseStatus
    package: str | None = None
    imports: tuple[str, ...] = ()
    classes: tuple[ParsedClass, ...] = ()
    error_message: str | None = None
    tree: CompilationUnit | None = field(default=None, repr=False, compare=False)
    tree_sitter: TreeSitterJavaFile | None = field(default=None, repr=False, compare=False)


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
            ``_parsing_guards.run_with_timeout`` for the limitations of
            this guard.

    Returns:
        A ParsedFile whose ``status`` reflects exactly what happened.
        Every failure mode (too large, unreadable, empty, timed out,
        syntax error) is returned as a value, never raised, so a single
        bad file can never abort a batch scan.
    """
    resolved = path.resolve()

    try:
        source = read_text_within_limit(resolved, max_bytes)
    except ParsingGuardError as exc:
        return _guard_failure(resolved, exc)
    if not source.strip():
        return ParsedFile(path=resolved, status=ParseStatus.EMPTY_FILE)

    return _parse_source(resolved, source, timeout_seconds)


def _guard_failure(path: Path, exc: ParsingGuardError) -> ParsedFile:
    """Translate a ParsingGuardError into the right ParseStatus."""
    status = ParseStatus.FILE_TOO_LARGE if exc.too_large else ParseStatus.PARSE_FAILED
    logger.warning("Rejecting %s: %s", path, exc)
    return ParsedFile(path=path, status=status, error_message=str(exc))


def _parse_source(path: Path, source: str, timeout_seconds: float) -> ParsedFile:
    """Run javalang, then Tree-sitter fallback, and return a ParsedFile.

    ``source`` is desugared (text blocks, sealed-class modifiers,
    pattern-matching ``instanceof`` bindings, and simple ``record``
    declarations rewritten into javalang-parseable equivalents - see
    ``_modern_java_preprocessor.py`` for exactly what's covered and
    why) before being handed to javalang. Every rewrite preserves the
    file's total newline count, so reported line numbers stay correct
    for everything outside a rewritten construct's own declaration.
    """
    java_source = translate_java_unicode_escapes(source)
    parseable_source = preprocess(java_source)
    try:
        tree = run_with_timeout(
            javalang.parse.parse, parseable_source, timeout_seconds=timeout_seconds
        )
    except TimeoutError:
        logger.warning("Parse timed out after %.1fs: %s", timeout_seconds, path)
        return ParsedFile(
            path=path,
            status=ParseStatus.PARSE_TIMEOUT,
            error_message=f"parse exceeded {timeout_seconds}s budget",
        )
    except javalang.parser.JavaSyntaxError as exc:
        message = _syntax_error_message(exc)
        logger.info("javalang could not parse %s, trying Tree-sitter: %s", path, message)
        return _parse_source_with_tree_sitter(path, java_source, timeout_seconds, message)
    except Exception as exc:  # pragma: no cover - defensive: javalang internals are not fully typed
        message = str(exc)
        logger.info("javalang errored on %s, trying Tree-sitter: %s", path, message)
        return _parse_source_with_tree_sitter(path, java_source, timeout_seconds, message)

    return _build_parsed_file(path, tree)


def _parse_source_with_tree_sitter(
    path: Path, source: str, timeout_seconds: float, javalang_error: str
) -> ParsedFile:
    """Parse ``source`` with Tree-sitter after javalang failed."""
    try:
        parsed = run_with_timeout(parse_java_source, source, timeout_seconds=timeout_seconds)
    except TimeoutError:
        logger.warning("Tree-sitter parse timed out after %.1fs: %s", timeout_seconds, path)
        return ParsedFile(
            path=path,
            status=ParseStatus.PARSE_TIMEOUT,
            error_message=f"parse exceeded {timeout_seconds}s budget",
        )
    except Exception as exc:  # pragma: no cover - defensive: parser internals are external
        logger.warning("Tree-sitter error parsing %s: %s", path, exc)
        return ParsedFile(path=path, status=ParseStatus.PARSE_FAILED, error_message=str(exc))

    if parsed.tree.root_node.has_error:
        logger.warning("Syntax error parsing %s: %s", path, javalang_error)
        return ParsedFile(path=path, status=ParseStatus.PARSE_FAILED, error_message=javalang_error)

    return _build_tree_sitter_parsed_file(path, parsed)


def _syntax_error_message(exc: javalang.parser.JavaSyntaxError) -> str:
    """Extract a human-readable message from a JavaSyntaxError.

    ``str(exc)`` on this exception is empty in javalang 0.13 - the
    actual message (e.g. "Expected type") lives on ``exc.description``.
    """
    description = getattr(exc, "description", None)
    return description or str(exc) or exc.__class__.__name__


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


def _build_tree_sitter_parsed_file(path: Path, parsed: TreeSitterJavaFile) -> ParsedFile:
    """Flatten a Tree-sitter Java tree into a successful ParsedFile."""
    root = parsed.tree.root_node
    package = _tree_sitter_package_name(parsed)
    imports = tuple(
        ts_node_text(parsed.source, node).removeprefix("import").removesuffix(";").strip()
        for node in root.children
        if node.type == "import_declaration"
    )
    classes = tuple(
        _build_tree_sitter_class(parsed, node)
        for node in root.children
        if node.type in {"class_declaration", "interface_declaration", "record_declaration"}
    )
    return ParsedFile(
        path=path,
        status=ParseStatus.OK,
        package=package,
        imports=imports,
        classes=classes,
        tree_sitter=parsed,
    )


def _tree_sitter_package_name(parsed: TreeSitterJavaFile) -> str | None:
    root = parsed.tree.root_node
    for child in root.children:
        if child.type != "package_declaration":
            continue
        for package_child in child.children:
            if package_child.is_named and package_child.type != "package":
                return ts_node_text(parsed.source, package_child)
    return None


def _build_tree_sitter_class(parsed: TreeSitterJavaFile, node: Node) -> ParsedClass:
    """Convert a Tree-sitter class/interface/record declaration into ParsedClass."""
    body = ts_child_by_field(node, "body")
    fields = _tree_sitter_fields(parsed, node, body)
    methods = _tree_sitter_methods(parsed, body)
    return ParsedClass(
        name=ts_declaration_name(parsed.source, node),
        line=ts_node_line(node),
        modifiers=ts_modifiers(node),
        annotations=ts_annotation_names(parsed.source, node),
        superclass=_tree_sitter_superclass(parsed, node),
        interfaces=_tree_sitter_interfaces(parsed, node),
        fields=fields,
        methods=methods,
        is_interface=node.type == "interface_declaration",
    )


def _tree_sitter_fields(
    parsed: TreeSitterJavaFile, declaration_node: Node, body: Node | None
) -> tuple[ParsedField, ...]:
    fields: list[ParsedField] = []
    if getattr(declaration_node, "type", None) == "record_declaration":
        parameters = ts_child_by_field(declaration_node, "parameters")
        if parameters is not None:
            for parameter in parameters.named_children:
                if parameter.type == "formal_parameter":
                    fields.append(_tree_sitter_field_from_parameter(parsed, parameter))
    if body is None:
        return tuple(fields)
    for child in body.children:
        if child.type == "field_declaration":
            fields.extend(_tree_sitter_fields_from_declaration(parsed, child))
    return tuple(fields)


def _tree_sitter_field_from_parameter(parsed: TreeSitterJavaFile, parameter: Node) -> ParsedField:
    return ParsedField(
        name=ts_declaration_name(parsed.source, parameter),
        type_name=ts_type_name(parsed.source, ts_child_by_field(parameter, "type")),
        modifiers=frozenset({"private", "final"}),
        line=ts_node_line(parameter),
    )


def _tree_sitter_fields_from_declaration(
    parsed: TreeSitterJavaFile, declaration: Node
) -> tuple[ParsedField, ...]:
    type_name = ts_type_name(parsed.source, ts_child_by_field(declaration, "type"))
    result = []
    for child in declaration.children:
        if child.type == "variable_declarator":
            result.append(
                ParsedField(
                    name=ts_declaration_name(parsed.source, child),
                    type_name=type_name,
                    modifiers=ts_modifiers(declaration),
                    line=ts_node_line(declaration),
                )
            )
    return tuple(result)


def _tree_sitter_methods(parsed: TreeSitterJavaFile, body: Node | None) -> tuple[ParsedMethod, ...]:
    if body is None:
        return ()
    return tuple(
        _tree_sitter_method(parsed, child)
        for child in body.children
        if child.type == "method_declaration"
    )


def _tree_sitter_method(parsed: TreeSitterJavaFile, node: Node) -> ParsedMethod:
    parameters_node = ts_child_by_field(node, "parameters")
    parameters = []
    if parameters_node is not None:
        for child in parameters_node.named_children:
            if child.type == "formal_parameter":
                parameters.append(
                    ParsedParameter(
                        name=ts_declaration_name(parsed.source, child),
                        type_name=ts_type_name(parsed.source, ts_child_by_field(child, "type")),
                        annotations=ts_annotation_names(parsed.source, child),
                    )
                )
    return ParsedMethod(
        name=ts_declaration_name(parsed.source, node),
        line=ts_node_line(node),
        modifiers=ts_modifiers(node),
        annotations=ts_annotation_names(parsed.source, node),
        parameters=tuple(parameters),
        return_type=ts_type_name(parsed.source, ts_child_by_field(node, "type")),
    )


def _tree_sitter_superclass(parsed: TreeSitterJavaFile, node: Node) -> str | None:
    superclass = ts_child_by_field(node, "superclass")
    if superclass is None:
        return None
    for child in superclass.named_children:
        if child.type not in {"extends", "superclass"}:
            return ts_node_text(parsed.source, child)
    return None


def _tree_sitter_interfaces(parsed: TreeSitterJavaFile, node: Node) -> tuple[str, ...]:
    interfaces = ts_child_by_field(node, "interfaces")
    if interfaces is None:
        return ()
    type_list = next(
        (child for child in interfaces.named_children if child.type == "type_list"),
        None,
    )
    if type_list is not None:
        return tuple(
            ts_node_text(parsed.source, child)
            for child in type_list.named_children
            if child.type.endswith("identifier")
        )
    return tuple(
        ts_node_text(parsed.source, child)
        for child in interfaces.named_children
        if child.type not in {"implements", "extends", "type_list"}
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
        is_interface=isinstance(node, InterfaceDeclaration),
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
        ParsedParameter(
            name=parameter.name,
            type_name=_type_name(parameter.type),
            annotations=tuple(annotation.name for annotation in parameter.annotations),
        )
        for parameter in node.parameters
    )
    return ParsedMethod(
        name=node.name,
        line=_line_number_of(node),
        modifiers=frozenset(node.modifiers),
        annotations=tuple(annotation.name for annotation in node.annotations),
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
    name = _base_type_name(type_node)
    if name is None:
        return type_node.__class__.__name__
    dimensions = getattr(type_node, "dimensions", None) or []
    return f"{name}{'[]' * len(dimensions)}"


def _base_type_name(type_node: object) -> str | None:
    """Reconstruct a type's full dotted name from javalang's segment chain.

    javalang represents a fully-qualified type like ``java.util.List``
    as a chain of ``ReferenceType`` nodes linked via ``sub_type`` - one
    node per dotted segment, in order ("java" -> "util" -> "List").
    Reading ``.name`` off only the outer node returns "java", the
    package prefix, not the type. Reading only the innermost node's
    name would return "List" but silently discard the qualification -
    ``java.sql.Date`` and ``java.util.Date`` would both collapse to
    "Date", losing real information a CWE rule might need. Joining
    every segment's name with "." reconstructs the original name
    (unqualified types are unaffected: a single segment joins to
    itself). Array ``dimensions`` live on the outermost node
    regardless, so that's read separately in ``_type_name``.
    """
    segments: list[str] = []
    node: object | None = type_node
    while node is not None:
        name = getattr(node, "name", None)
        if name is not None:
            segments.append(name)
        node = getattr(node, "sub_type", None)
    return ".".join(segments) if segments else None


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
