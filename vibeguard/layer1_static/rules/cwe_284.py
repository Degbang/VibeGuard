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

import dataclasses
from collections.abc import Iterable
from pathlib import Path
from typing import TypeAlias

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
    node_text as ts_node_text,
)
from vibeguard.layer1_static._tree_sitter_java import (
    type_name as ts_type_name,
)
from vibeguard.layer1_static._tree_sitter_java import (
    walk as ts_walk,
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

CWE_ID = "CWE-284"

# A project that centralizes authorization in a Spring Security
# SecurityFilterChain bean (http.authorizeHttpRequests().anyRequest()...)
# makes an application-wide access-control decision that per-method/
# per-class annotation checks below cannot see at all - see
# has_centralized_authorization_rule's docstring and IMPLEMENTATION_LOG.md
# for a real example found by scanning a real Spring Boot application.
_SECURITY_FILTER_CHAIN_RETURN_TYPE = "SecurityFilterChain"
_ANY_REQUEST_CALL = "anyRequest"
_BLANKET_AUTHORIZATION_CALLS = frozenset({"authenticated", "permitAll", "denyAll"})
_CENTRALIZED_AUTH_CAVEAT = (
    "Note: this project also declares a Spring Security SecurityFilterChain "
    "with a project-wide '.anyRequest()' authorization rule elsewhere - this "
    "endpoint may already be covered by that rule depending on path-matching "
    "and runtime configuration (e.g. a conditional property) that is not "
    "visible to static analysis."
)

_TypeDeclaration: TypeAlias = javalang.tree.ClassDeclaration | javalang.tree.InterfaceDeclaration

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
_HTTP_CLIENT_TYPE_ANNOTATIONS = frozenset(
    {
        "RegisterRestClient",  # Quarkus / MicroProfile REST client
        "FeignClient",  # Spring OpenFeign client
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
    if parsed_file.tree_sitter is not None:
        return _detect_in_tree_sitter_java(parsed_file)
    if parsed_file.tree is None:
        return ()

    findings = [
        finding
        for path, node in parsed_file.tree.filter(javalang.tree.MethodDeclaration)
        if (finding := _check_method(parsed_file.path, node, path)) is not None
    ]
    return tuple(findings)


def _detect_in_tree_sitter_java(parsed_file: ParsedFile) -> tuple[Finding, ...]:
    """Find unprotected endpoints in a Tree-sitter fallback parse."""
    parsed = parsed_file.tree_sitter
    if parsed is None:
        return ()
    findings = [
        finding
        for ancestors, node in ts_walk_with_ancestors(parsed.tree.root_node)
        if node.type == "method_declaration"
        if (finding := _check_tree_sitter_method(parsed_file.path, parsed.source, node, ancestors))
        is not None
    ]
    return tuple(findings)


def _check_tree_sitter_method(
    file_path: Path, source: bytes, method: Node, ancestors: tuple[Node, ...]
) -> Finding | None:
    method_annotations = ts_annotation_names(source, method)
    if not has_endpoint_annotation(method_annotations):
        return None
    if _has_authorization_annotation(method_annotations):
        return None
    enclosing_type = ts_nearest_enclosing_type(ancestors)
    if enclosing_type is not None:
        type_annotations = ts_annotation_names(source, enclosing_type)
        if _is_http_client_type(type_annotations):
            return None
        if _has_authorization_annotation(type_annotations):
            return None
    method_name = ts_declaration_name(source, method)
    return Finding(
        cwe_id=CWE_ID,
        file_path=file_path,
        line=ts_node_line(method),
        identifier=method_name,
        message=(
            f"Endpoint method '{method_name}' has no authorization annotation "
            "(no @RolesAllowed/@PermitAll/@Secured/@PreAuthorize/... on the "
            "method or its enclosing class)"
        ),
    )


def _check_method(
    file_path: Path,
    method: javalang.tree.MethodDeclaration,
    path: tuple[object, ...],
) -> Finding | None:
    """Build a Finding if this method is an unprotected endpoint."""
    method_annotations = tuple(a.name for a in method.annotations)
    if not has_endpoint_annotation(method_annotations):
        return None
    if _has_authorization_annotation(method_annotations):
        return None
    enclosing_type = _nearest_enclosing_type(path)
    if enclosing_type is not None:
        type_annotations = tuple(a.name for a in enclosing_type.annotations)
        if _is_http_client_type(type_annotations):
            return None
        if _has_authorization_annotation(type_annotations):
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


def _has_authorization_annotation(annotations: tuple[str, ...]) -> bool:
    return any(simple_name(a) in _AUTHORIZATION_ANNOTATIONS for a in annotations)


def _is_http_client_type(annotations: tuple[str, ...]) -> bool:
    """Whether a type is an outbound HTTP client, not an inbound endpoint class."""
    return any(simple_name(a) in _HTTP_CLIENT_TYPE_ANNOTATIONS for a in annotations)


def has_centralized_authorization_rule(parsed_file: ParsedFile) -> bool:
    """Whether this file declares a Spring Security SecurityFilterChain bean
    with a blanket, application-wide authorization rule - ``.anyRequest()``
    followed by ``.authenticated()``/``.permitAll()``/``.denyAll()``.

    This is a coarse, name-based signal, the same kind of pattern match
    every other check in this module makes - not a semantic understanding
    of Spring Security's path-matching precedence, and not aware of
    whether a conditional property (e.g. ``@ConditionalOnProperty``)
    actually activates this bean at runtime. Scanning the real
    spring-petclinic-rest application found exactly this: a
    SecurityFilterChain with ``anyRequest().authenticated()`` covers an
    endpoint this rule would otherwise call unprotected, while a second,
    differently-conditional SecurityFilterChain elsewhere in the same
    project sets ``anyRequest().permitAll()`` - which one is actually
    active depends on a property value that does not exist in source
    code at all until something sets it at deploy time. Static analysis
    cannot resolve that either way, so this signal is used to add an
    explicit caveat to a finding (see ``apply_centralized_authorization_context``),
    never to silently drop it - a security tool that hides a candidate
    finding because of a coarse, best-effort heuristic is worse than one
    that flags too much.
    """
    if parsed_file.tree_sitter is not None:
        return _has_centralized_rule_tree_sitter(parsed_file)
    if parsed_file.tree is None:
        return False
    for _path, method in parsed_file.tree.filter(javalang.tree.MethodDeclaration):
        if _returns_security_filter_chain(method) and _has_blanket_authorization_call(method):
            return True
    return False


def _returns_security_filter_chain(method: javalang.tree.MethodDeclaration) -> bool:
    return getattr(method.return_type, "name", None) == _SECURITY_FILTER_CHAIN_RETURN_TYPE


def _has_blanket_authorization_call(method: javalang.tree.MethodDeclaration) -> bool:
    invocation_members = {
        node.member for _path, node in method.filter(javalang.tree.MethodInvocation)
    }
    return _ANY_REQUEST_CALL in invocation_members and bool(
        invocation_members & _BLANKET_AUTHORIZATION_CALLS
    )


def _has_centralized_rule_tree_sitter(parsed_file: ParsedFile) -> bool:
    parsed = parsed_file.tree_sitter
    if parsed is None:
        return False
    for node in ts_walk(parsed.tree.root_node):
        if node.type != "method_declaration":
            continue
        return_type_node = ts_child_by_field(node, "type")
        if return_type_node is None:
            continue
        if ts_type_name(parsed.source, return_type_node) != _SECURITY_FILTER_CHAIN_RETURN_TYPE:
            continue
        invocation_names = {
            ts_node_text(parsed.source, name_node)
            for child in ts_walk(node)
            if child.type == "method_invocation"
            for name_node in (ts_child_by_field(child, "name"),)
            if name_node is not None
        }
        if (
            _ANY_REQUEST_CALL in invocation_names
            and invocation_names & _BLANKET_AUTHORIZATION_CALLS
        ):
            return True
    return False


def apply_centralized_authorization_context(
    findings: tuple[Finding, ...], parsed_files: Iterable[ParsedFile]
) -> tuple[Finding, ...]:
    """Append a caveat to every CWE-284 finding when the scan also found a
    centralized Spring Security authorization rule somewhere in the project.

    Findings are never dropped or hidden by this: only their message gains
    an explicit caveat, so this stays fail-closed - a reader still sees
    every candidate, with an honest note about what static analysis could
    not resolve, rather than a finding silently disappearing because of a
    coarse, project-wide heuristic.

    Args:
        findings: All findings from a scan (not just CWE-284's) - findings
            for other CWEs pass through unchanged.
        parsed_files: Every successfully-parsed Java file from the same
            scan, checked for the centralized-authorization pattern.

    Returns:
        The same findings, with CWE-284 messages annotated if applicable.
    """
    if not any(has_centralized_authorization_rule(pf) for pf in parsed_files):
        return findings
    return tuple(
        (
            dataclasses.replace(finding, message=f"{finding.message} {_CENTRALIZED_AUTH_CAVEAT}")
            if finding.cwe_id == CWE_ID
            else finding
        )
        for finding in findings
    )
