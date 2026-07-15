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
"""

from __future__ import annotations

from pathlib import Path

import javalang

from vibeguard.layer1_static.ast_parser import ParsedFile
from vibeguard.layer1_static.rules._endpoint_annotations import (
    has_endpoint_annotation,
    simple_name,
)
from vibeguard.layer1_static.rules._finding import Finding

CWE_ID = "CWE-20"

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


def detect_in_java(parsed_file: ParsedFile) -> tuple[Finding, ...]:
    """Find endpoint methods whose @RequestBody parameter isn't @Valid/@Validated."""
    if parsed_file.tree is None:
        return ()

    findings = []
    for _path, method in parsed_file.tree.filter(javalang.tree.MethodDeclaration):
        method_annotations = tuple(a.name for a in method.annotations)
        if not has_endpoint_annotation(method_annotations):
            continue
        for parameter in method.parameters:
            finding = _check_parameter(parsed_file.path, method, parameter)
            if finding is not None:
                findings.append(finding)
    return tuple(findings)


def _check_parameter(
    file_path: Path,
    method: javalang.tree.MethodDeclaration,
    parameter: javalang.tree.FormalParameter,
) -> Finding | None:
    """Build a Finding if this is an unvalidated @RequestBody parameter."""
    param_annotations = tuple(a.name for a in parameter.annotations)
    if not _has_annotation(param_annotations, _REQUEST_BODY_ANNOTATION):
        return None
    if _has_annotation(param_annotations, *_VALIDATION_ANNOTATIONS):
        return None
    type_name = getattr(parameter.type, "name", None)
    if type_name in _NOT_VALIDATABLE_TYPES:
        return None
    line = method.position.line if method.position else None
    return Finding(
        cwe_id=CWE_ID,
        file_path=file_path,
        line=line,
        identifier=parameter.name,
        message=(
            f"Parameter '{parameter.name}' (@RequestBody) has no @Valid/@Validated "
            f"annotation - Bean Validation constraints on {type_name} won't be "
            "enforced automatically"
        ),
    )


def _has_annotation(annotations: tuple[str, ...], *names: str) -> bool:
    simple_names = {simple_name(a) for a in annotations}
    return bool(simple_names & set(names))
