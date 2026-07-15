"""CWE-284: Improper Access Control.

Flags REST endpoint methods (identified by common JAX-RS/Spring
request-mapping annotations) that carry no authorization annotation at
all, at either the method or the nearest enclosing class/interface
level. Walks ``ParsedFile.tree`` directly via javalang's
``.filter(MethodDeclaration)`` rather than the flattened
``ParsedFile.classes`` summary: that summary only represents top-level
types (see ``ast_parser.ParsedClass``'s docstring), so a method inside
a nested/inner/anonymous class would be entirely invisible to this
rule if it only looked there - a real false negative found and fixed
during adversarial testing, see IMPLEMENTATION_LOG.md.

Deliberately narrow scope for a first pass: this detects *missing*
access control, not *misconfigured* access control. An endpoint
carrying an explicit ``@PermitAll`` is a deliberate access-control
decision, not an instance of this CWE, even if that decision might be
questionable on a sensitive-sounding endpoint - judging whether a
specific role/policy is *appropriate* would need semantic understanding
of the application's authorization model that static analysis alone
can't provide. This rule only asks "was an access-control decision
made at all," not "was it the right one."
"""

from __future__ import annotations

from pathlib import Path
from typing import TypeAlias

import javalang

from vibeguard.layer1_static.ast_parser import ParsedFile
from vibeguard.layer1_static.rules._finding import Finding

CWE_ID = "CWE-284"

_TypeDeclaration: TypeAlias = javalang.tree.ClassDeclaration | javalang.tree.InterfaceDeclaration

# JAX-RS and Spring MVC annotations that mark a method as a reachable
# HTTP endpoint. Presence of any one of these is what makes "no
# authorization annotation" a meaningful finding at all - an ordinary
# private helper method needs no access-control annotation because
# nothing external can reach it.
_ENDPOINT_ANNOTATIONS = frozenset(
    {
        # JAX-RS / Quarkus RESTEasy
        "GET",
        "POST",
        "PUT",
        "DELETE",
        "PATCH",
        "HEAD",
        "OPTIONS",
        # Spring MVC
        "GetMapping",
        "PostMapping",
        "PutMapping",
        "DeleteMapping",
        "PatchMapping",
        "RequestMapping",
    }
)

# Annotations that represent an explicit access-control decision,
# whether restrictive or permissive. Any one of these present (on the
# method or the class) means this rule has nothing to flag - the
# *presence* of a decision is what's being checked for, not which one.
_AUTHORIZATION_ANNOTATIONS = frozenset(
    {
        "RolesAllowed",
        "PermitAll",
        "DenyAll",
        "Authenticated",  # Quarkus
        "Secured",  # Spring Security (legacy)
        "PreAuthorize",  # Spring Security
        "PostAuthorize",  # Spring Security
        "RequiresRoles",  # Apache Shiro
    }
)


def detect_in_java(parsed_file: ParsedFile) -> tuple[Finding, ...]:
    """Find endpoint methods with no authorization annotation anywhere in scope.

    An authorization annotation on the *nearest enclosing* class/
    interface covers a method that doesn't itself carry one (the
    common "secure by default, opt out per-endpoint" pattern) - only
    the nearest enclosing type is checked, not every ancestor, since
    annotations on an outer class don't apply to a nested class's own
    members in JAX-RS/Spring's actual runtime behavior.
    """
    if parsed_file.tree is None:
        return ()

    findings = [
        finding
        for path, node in parsed_file.tree.filter(javalang.tree.MethodDeclaration)
        if (finding := _check_method(parsed_file.path, node, path)) is not None
    ]
    return tuple(findings)


def _check_method(
    file_path: Path,
    method: javalang.tree.MethodDeclaration,
    path: tuple[object, ...],
) -> Finding | None:
    """Build a Finding if this method is an unprotected endpoint."""
    method_annotations = tuple(a.name for a in method.annotations)
    if not _has_endpoint_annotation(method_annotations):
        return None
    if _has_authorization_annotation(method_annotations):
        return None
    enclosing_type = _nearest_enclosing_type(path)
    if enclosing_type is not None:
        class_annotations = tuple(a.name for a in enclosing_type.annotations)
        if _has_authorization_annotation(class_annotations):
            return None
    line = method.position.line if method.position else None
    return Finding(
        cwe_id=CWE_ID,
        file_path=file_path,
        line=line,
        identifier=method.name,
        message=(
            f"Endpoint method '{method.name}' has no authorization annotation "
            "(no @RolesAllowed/@PermitAll/@Secured/@PreAuthorize/... on the "
            "method or its enclosing class)"
        ),
    )


def _nearest_enclosing_type(path: tuple[object, ...]) -> _TypeDeclaration | None:
    """Find the closest enclosing class/interface declaration in a filter() path.

    javalang's ``.filter()`` returns the full ancestor chain from the
    ``CompilationUnit`` down; walking it in reverse finds the nearest
    (innermost) enclosing type first, which is what "the method's own
    class" means for a nested/inner class.
    """
    for ancestor in reversed(path):
        if isinstance(
            ancestor, javalang.tree.ClassDeclaration | javalang.tree.InterfaceDeclaration
        ):
            return ancestor
    return None


def _has_endpoint_annotation(annotations: tuple[str, ...]) -> bool:
    return any(_simple_name(a) in _ENDPOINT_ANNOTATIONS for a in annotations)


def _has_authorization_annotation(annotations: tuple[str, ...]) -> bool:
    return any(_simple_name(a) in _AUTHORIZATION_ANNOTATIONS for a in annotations)


def _simple_name(annotation: str) -> str:
    """Strip any package qualification, e.g. "javax.ws.rs.GET" -> "GET".

    javalang gives an annotation's name exactly as written in source:
    "GET" for `@GET`, but "javax.ws.rs.GET" for
    `@javax.ws.rs.GET` - matching against the full string would miss
    (or wrongly flag) any endpoint/authorization annotation using its
    fully-qualified form instead of a simple-name import.
    """
    return annotation.rsplit(".", 1)[-1]
