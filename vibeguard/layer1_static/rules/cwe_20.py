"""CWE-20: Improper Input Validation.

Flags a Spring MVC ``@RequestBody`` endpoint parameter that lacks
``@Valid``/``@Validated``. Bean Validation (JSR 380) constraints
declared on a DTO's own fields (``@NotNull``, ``@Size``, ``@Pattern``,
...) are only enforced by Spring's request-handling pipeline when the
controller parameter carrying that DTO is itself annotated with
``@Valid``/``@Validated`` - without it, a malformed or malicious
request body reaches application code completely unvalidated, which is
squarely CWE-20: the software does not validate input before use.

Deliberately narrow scope for a first pass, same reasoning as
``cwe_284.py``/``cwe_287.py``: this detects the presence/absence of a
validation *trigger*, not whether the underlying constraints are
correct or complete. Spring-specific (``@RequestBody`` has no exact
JAX-RS equivalent - a JAX-RS resource method's body parameter is
identified implicitly by the *absence* of a param-source annotation
like ``@QueryParam``, which is a materially different, more ambiguous
signal than Spring's explicit marker; left for a future pass rather
than guessed at now).

Walks ``ParsedFile.tree`` directly via ``.filter(MethodDeclaration)``,
the same approach ``cwe_284.py``/``cwe_287.py`` use - parameter-level
annotations aren't in Layer 1's flattened summary either.

Also recognises the same interface-inherited-annotation gap
``cwe_284.py`` closes, one level down: a concrete class implementing a
codegen-style interface can carry the real ``@PutMapping``/``@RequestBody``/
``@Valid`` annotations only on the interface's method/parameters, with
the ``@Override`` carrying none of its own. Method-level routing
annotations are widened the same unconditional way ``cwe_284.py`` already
established (reusing its ``resolve_effective_annotations``/
``build_interface_method_index`` - Spring MVC's route registration is a
documented, proxy-independent framework feature). Parameter-level
``@RequestBody``/``@Valid`` inheritance is treated more cautiously: unlike
method-level routing, whether Spring's argument-resolution machinery
actually honors a parameter annotation declared only on the interface
(rather than the concrete override's own parameter) is not established
the same way - it depends on which ``Method`` object Spring's
``HandlerMethod`` resolution actually invokes, which is not visible to
static analysis. So an interface-inherited ``@RequestBody`` still widens
which parameters get checked at all (the same fail-toward-more-scrutiny
direction ``cwe_284.py`` uses for endpoint recognition), but an
interface-inherited ``@Valid``/``@Validated`` never silently suppresses a
finding - it adds an explicit caveat instead, the same caveat-not-suppress
discipline ``cwe_284.py`` applies to inherited authorization annotations.
"""

from __future__ import annotations

from pathlib import Path

import javalang
from tree_sitter import Node

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
    nearest_enclosing_type as ts_nearest_enclosing_type,
)
from vibeguard.layer1_static._tree_sitter_java import (
    node_line as ts_node_line,
)
from vibeguard.layer1_static._tree_sitter_java import (
    type_name as ts_type_name,
)
from vibeguard.layer1_static._tree_sitter_java import (
    walk_with_ancestors as ts_walk_with_ancestors,
)
from vibeguard.layer1_static.ast_parser import ParsedFile
from vibeguard.layer1_static.rules._endpoint_annotations import (
    has_endpoint_annotation,
    simple_name,
)
from vibeguard.layer1_static.rules._finding import Finding
from vibeguard.layer1_static.rules._interface_annotations import (
    EMPTY_INTERFACE_INDEX,
    EMPTY_INTERFACE_PARAMETER_INDEX,
    InterfaceMethodAnnotations,
    InterfaceParameterAnnotations,
    interface_annotations_for_parameter,
    nearest_enclosing_type,
    resolve_effective_annotations,
    top_level_interfaces_by_type_name,
)

CWE_ID = "CWE-20"

# Mirrors cwe_284.py's _INTERFACE_AUTHORIZATION_CAVEAT exactly in spirit:
# an interface-declared @Valid/@Validated on the matching parameter must
# never silently suppress this finding, since whether Spring's argument
# resolvers actually see it depends on which Method object Spring's
# HandlerMethod machinery resolved to (the concrete override's own, or -
# only for certain proxy/dispatch configurations - the interface's),
# which is not visible to static analysis.
_INTERFACE_VALIDATION_CAVEAT = (
    "Note: an implemented interface's matching parameter carries @Valid/"
    "@Validated not repeated on this concrete override - whether Spring "
    "actually applies it here depends on which method object Spring's "
    "request-handling resolves to, which is not visible to static analysis."
)

_REQUEST_BODY_ANNOTATION = "RequestBody"
_VALIDATION_ANNOTATIONS = frozenset({"Valid", "Validated"})

# Types a @RequestBody parameter could plausibly be that have no bean
# fields for Bean Validation to cascade into - flagging these as
# "needs @Valid" would be noise, not signal, since there's nothing for
# @Valid to actually validate.
_NOT_VALIDATABLE_TYPES = frozenset(
    {
        "String",
        "Object",
        "Map",
        "List",
        "byte[]",
        "Integer",
        "Long",
        "Boolean",
        "Double",
        "Float",
    }
)


def detect_in_java(
    parsed_file: ParsedFile,
    interface_annotations: InterfaceMethodAnnotations = EMPTY_INTERFACE_INDEX,
    interface_parameter_annotations: InterfaceParameterAnnotations = (
        EMPTY_INTERFACE_PARAMETER_INDEX
    ),
) -> tuple[Finding, ...]:
    """Find endpoint methods whose @RequestBody parameter isn't @Valid/@Validated.

    Args:
        parsed_file: One successfully-parsed Java file.
        interface_annotations: Project-wide method-level index (see
            ``_interface_annotations.build_interface_method_index``) used
            to recognise an endpoint routing annotation declared only on
            an implemented interface's matching method. Defaults to an
            empty index, so a single-file call sees exactly the
            pre-existing, own-annotations-only behavior.
        interface_parameter_annotations: Project-wide parameter-level
            index (see ``build_interface_parameter_index``) used the same
            way for ``@RequestBody``/``@Valid`` living only on an
            implemented interface's matching parameter. Defaults to an
            empty index for the same reason.
    """
    if parsed_file.tree_sitter is not None:
        return _detect_in_tree_sitter_java(
            parsed_file, interface_annotations, interface_parameter_annotations
        )
    if parsed_file.tree is None:
        return ()

    interfaces_by_type_name = top_level_interfaces_by_type_name(parsed_file)
    findings = []
    for path, method in parsed_file.tree.filter(javalang.tree.MethodDeclaration):
        enclosing_type = nearest_enclosing_type(path)
        implemented_interfaces = (
            interfaces_by_type_name.get(enclosing_type.name, ())
            if enclosing_type is not None
            else ()
        )
        own_method_annotations = tuple(a.name for a in method.annotations)
        effective_method_annotations = resolve_effective_annotations(
            own_method_annotations, implemented_interfaces, method.name, interface_annotations
        )
        if not has_endpoint_annotation(effective_method_annotations):
            continue
        for index, parameter in enumerate(method.parameters):
            finding = _check_parameter(
                parsed_file.path,
                method,
                parameter,
                index,
                implemented_interfaces,
                interface_parameter_annotations,
            )
            if finding is not None:
                findings.append(finding)
    return tuple(findings)


def _detect_in_tree_sitter_java(
    parsed_file: ParsedFile,
    interface_annotations: InterfaceMethodAnnotations,
    interface_parameter_annotations: InterfaceParameterAnnotations,
) -> tuple[Finding, ...]:
    """Find unvalidated request bodies in a Tree-sitter fallback parse."""
    parsed = parsed_file.tree_sitter
    if parsed is None:
        return ()
    interfaces_by_type_name = top_level_interfaces_by_type_name(parsed_file)
    findings: list[Finding] = []
    for ancestors, method in ts_walk_with_ancestors(parsed.tree.root_node):
        if method.type != "method_declaration":
            continue
        enclosing_type = ts_nearest_enclosing_type(ancestors)
        method_name = ts_declaration_name(parsed.source, method)
        enclosing_type_name = (
            ts_declaration_name(parsed.source, enclosing_type)
            if enclosing_type is not None
            else None
        )
        implemented_interfaces = (
            interfaces_by_type_name.get(enclosing_type_name, ()) if enclosing_type_name else ()
        )
        own_method_annotations = ts_annotation_names(parsed.source, method)
        effective_method_annotations = resolve_effective_annotations(
            own_method_annotations, implemented_interfaces, method_name, interface_annotations
        )
        if not has_endpoint_annotation(effective_method_annotations):
            continue
        parameters = ts_child_by_field(method, "parameters")
        if parameters is None:
            continue
        formal_parameters = [
            child for child in parameters.named_children if child.type == "formal_parameter"
        ]
        for index, parameter in enumerate(formal_parameters):
            finding = _check_tree_sitter_parameter(
                parsed_file.path,
                parsed.source,
                method,
                parameter,
                method_name,
                index,
                implemented_interfaces,
                interface_parameter_annotations,
            )
            if finding is not None:
                findings.append(finding)
    return tuple(findings)


def _check_tree_sitter_parameter(
    file_path: Path,
    source: bytes,
    method: Node,
    parameter: Node,
    method_name: str,
    parameter_index: int,
    implemented_interfaces: tuple[str, ...],
    interface_parameter_annotations: InterfaceParameterAnnotations,
) -> Finding | None:
    own_param_annotations = ts_annotation_names(source, parameter)
    interface_param_annotations = interface_annotations_for_parameter(
        implemented_interfaces, method_name, parameter_index, interface_parameter_annotations
    )
    if not _has_annotation(own_param_annotations, _REQUEST_BODY_ANNOTATION) and not _has_annotation(
        interface_param_annotations, _REQUEST_BODY_ANNOTATION
    ):
        return None
    type_name = ts_type_name(source, ts_child_by_field(parameter, "type"))
    if type_name in _NOT_VALIDATABLE_TYPES:
        return None
    param_name = ts_declaration_name(source, parameter)
    if _has_annotation(own_param_annotations, *_VALIDATION_ANNOTATIONS):
        return None
    message = (
        f"Parameter '{param_name}' (@RequestBody) has no @Valid/@Validated "
        f"annotation - Bean Validation constraints on {type_name} won't be "
        "enforced automatically"
    )
    if _has_annotation(interface_param_annotations, *_VALIDATION_ANNOTATIONS):
        message = f"{message} {_INTERFACE_VALIDATION_CAVEAT}"
    return Finding(
        cwe_id=CWE_ID,
        file_path=file_path,
        line=ts_node_line(method),
        identifier=param_name,
        message=message,
    )


def _check_parameter(
    file_path: Path,
    method: javalang.tree.MethodDeclaration,
    parameter: javalang.tree.FormalParameter,
    parameter_index: int,
    implemented_interfaces: tuple[str, ...],
    interface_parameter_annotations: InterfaceParameterAnnotations,
) -> Finding | None:
    """Build a Finding if this is an unvalidated @RequestBody parameter."""
    own_param_annotations = tuple(a.name for a in parameter.annotations)
    interface_param_annotations = interface_annotations_for_parameter(
        implemented_interfaces, method.name, parameter_index, interface_parameter_annotations
    )
    if not _has_annotation(own_param_annotations, _REQUEST_BODY_ANNOTATION) and not _has_annotation(
        interface_param_annotations, _REQUEST_BODY_ANNOTATION
    ):
        return None
    type_name = getattr(parameter.type, "name", None)
    if type_name in _NOT_VALIDATABLE_TYPES:
        return None
    if _has_annotation(own_param_annotations, *_VALIDATION_ANNOTATIONS):
        return None
    line = method.position.line if method.position else None
    message = (
        f"Parameter '{parameter.name}' (@RequestBody) has no @Valid/@Validated "
        f"annotation - Bean Validation constraints on {type_name} won't be "
        "enforced automatically"
    )
    if _has_annotation(interface_param_annotations, *_VALIDATION_ANNOTATIONS):
        message = f"{message} {_INTERFACE_VALIDATION_CAVEAT}"
    return Finding(
        cwe_id=CWE_ID,
        file_path=file_path,
        line=line,
        identifier=parameter.name,
        message=message,
    )


def _has_annotation(annotations: tuple[str, ...], *names: str) -> bool:
    simple_names = {simple_name(a) for a in annotations}
    return bool(simple_names & set(names))
