"""CWE-284: Improper Access Control.

Flags REST endpoint methods (identified by common JAX-RS/Spring
request-mapping annotations) that carry no authorization annotation at
all, at either the method or the enclosing class level. Works entirely
off Layer 1's structural summary (``ParsedClass``/``ParsedMethod``
annotations) - no raw AST walk needed, since annotation *names* (not
values) are all this rule requires, and ``ast_parser.py`` already
promotes annotation names to that summary.

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

from vibeguard.layer1_static.ast_parser import ParsedFile, ParsedMethod
from vibeguard.layer1_static.rules._finding import Finding

CWE_ID = "CWE-284"

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

    An authorization annotation on the *class* covers every method
    that doesn't itself carry an authorization annotation (the common
    "secure by default, opt out per-endpoint" pattern), so a method is
    only flagged if neither it nor its class has one.
    """
    findings = []
    for cls in parsed_file.classes:
        class_has_authorization = _has_authorization_annotation(cls.annotations)
        for method in cls.methods:
            finding = _check_method(parsed_file.path, method, class_has_authorization)
            if finding is not None:
                findings.append(finding)
    return tuple(findings)


def _check_method(
    file_path: Path, method: ParsedMethod, class_has_authorization: bool
) -> Finding | None:
    """Build a Finding if this method is an unprotected endpoint."""
    if not _has_endpoint_annotation(method.annotations):
        return None
    if class_has_authorization or _has_authorization_annotation(method.annotations):
        return None
    return Finding(
        cwe_id=CWE_ID,
        file_path=file_path,
        line=method.line,
        identifier=method.name,
        message=(
            f"Endpoint method '{method.name}' has no authorization annotation "
            "(no @RolesAllowed/@PermitAll/@Secured/@PreAuthorize/... on the "
            "method or its class)"
        ),
    )


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
