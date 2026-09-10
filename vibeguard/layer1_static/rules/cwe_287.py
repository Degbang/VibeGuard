"""CWE-287: Improper Authentication.

Flags two independent Java patterns, both cases of insufficiently
proving a claimed identity/credential is correct:

1. The classic authentication-comparison bug: comparing a
   credential-shaped value (password, token, secret, ...) with ``==``/
   ``!=`` instead of ``.equals()``. ``==`` on ``String``/object types
   compares *reference* identity, not value - due to Java's string
   interning, two credential values that are character-for-character
   equal can still compare unequal with ``==`` (or, in narrower cases,
   accidentally compare equal when they shouldn't), so an
   authentication check written this way does not reliably prove the
   claimed credential is correct.
2. An endpoint that generates or looks up a credential-shaped value
   and returns it directly to the caller with no preceding guard - see
   ``_check_unguarded_secret_return``. Found scanning a real
   Codex-generated project (2026-09-04, IMPLEMENTATION_LOG.md): a
   self-service account-recovery endpoint handed its recovery token
   straight back to whoever asked for it (identified only by an email
   address, not proof of ownership) instead of delivering it
   out-of-band. Both patterns are the same underlying failure - the
   software does not adequately verify a claimed identity before
   trusting or granting it - just expressed differently in code.

Only Java source is relevant here - neither pattern has a config-file
equivalent the way CWE-798 does. Walks ``ParsedFile.tree`` directly via
``.filter()``, the same approach ``cwe_284.py`` uses for
``MethodDeclaration`` - Layer 1's flattened summary doesn't capture
expressions at all, only declarations.
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
    named_children as ts_named_children,
)
from vibeguard.layer1_static._tree_sitter_java import (
    node_line as ts_node_line,
)
from vibeguard.layer1_static._tree_sitter_java import (
    node_text as ts_node_text,
)
from vibeguard.layer1_static._tree_sitter_java import (
    walk as ts_walk,
)
from vibeguard.layer1_static.ast_parser import ParsedFile
from vibeguard.layer1_static.rules._authorization_annotations import (
    has_authorization_annotation,
)
from vibeguard.layer1_static.rules._credential_names import is_credential_name
from vibeguard.layer1_static.rules._endpoint_annotations import has_endpoint_annotation
from vibeguard.layer1_static.rules._finding import Finding

CWE_ID = "CWE-287"

_REFERENCE_EQUALITY_OPERATORS = frozenset({"==", "!="})

_UNGUARDED_ISSUANCE_MESSAGE = (
    "Endpoint method '{method}' returns '{identifier}', a credential-shaped "
    "value, directly in its response with no preceding guard (no if-check "
    "and no @RolesAllowed/@PermitAll/@Secured/@PreAuthorize/... on the "
    "method) - if this is a self-service recovery/reset/verification flow, "
    "the value should be delivered out-of-band (e.g. email/SMS) rather than "
    "handed back to whoever made the request"
)


def detect_in_java(parsed_file: ParsedFile) -> tuple[Finding, ...]:
    """Find unsafe credential comparisons and unguarded credential-issuing returns."""
    if parsed_file.tree_sitter is not None:
        return _detect_in_tree_sitter_java(parsed_file)
    if parsed_file.tree is None:
        return ()

    comparison_findings = [
        finding
        for _path, node in parsed_file.tree.filter(javalang.tree.BinaryOperation)
        if (finding := _check_comparison(parsed_file.path, node)) is not None
    ]
    issuance_findings = [
        finding
        for _path, node in parsed_file.tree.filter(javalang.tree.MethodDeclaration)
        if (finding := _check_unguarded_secret_return(parsed_file.path, node)) is not None
    ]
    return tuple(comparison_findings + issuance_findings)


def _detect_in_tree_sitter_java(parsed_file: ParsedFile) -> tuple[Finding, ...]:
    """Find both CWE-287 patterns in a Tree-sitter fallback parse."""
    parsed = parsed_file.tree_sitter
    if parsed is None:
        return ()
    findings: list[Finding] = []
    for node in ts_walk(parsed.tree.root_node):
        if node.type == "binary_expression":
            finding = _check_tree_sitter_comparison(parsed_file.path, parsed.source, node)
        elif node.type == "method_declaration":
            finding = _check_tree_sitter_unguarded_secret_return(
                parsed_file.path, parsed.source, node
            )
        else:
            continue
        if finding is not None:
            findings.append(finding)
    return tuple(findings)


def _check_tree_sitter_comparison(file_path: Path, source: bytes, node: Node) -> Finding | None:
    operator_node = ts_child_by_field(node, "operator")
    if operator_node is None:
        return None
    operator = ts_node_text(source, operator_node).strip()
    if operator not in _REFERENCE_EQUALITY_OPERATORS:
        return None
    left = ts_child_by_field(node, "left")
    right = ts_child_by_field(node, "right")
    left_ref = _tree_sitter_credential_operand(source, left)
    credential_ref, other = (
        (left_ref, right)
        if left_ref is not None
        else (_tree_sitter_credential_operand(source, right), left)
    )
    if credential_ref is None or other is None:
        return None
    if not _is_plausible_tree_sitter_credential_operand(other):
        return None
    return Finding(
        cwe_id=CWE_ID,
        file_path=file_path,
        line=ts_node_line(node),
        identifier=credential_ref,
        message=(
            f"'{credential_ref}' compared with '{operator}' instead of "
            ".equals() - Java's == compares object reference identity, not value, "
            "so this comparison does not reliably verify the credential"
        ),
    )


def _tree_sitter_credential_operand(source: bytes, operand: Node | None) -> str | None:
    if operand is None:
        return None
    if getattr(operand, "type", None) == "identifier":
        name = ts_node_text(source, operand)
        return name if is_credential_name(name) else None
    if getattr(operand, "type", None) == "field_access":
        field = ts_child_by_field(operand, "field")
        if field is not None:
            name = ts_node_text(source, field)
            return name if is_credential_name(name) else None
    if getattr(operand, "type", None) == "method_invocation":
        name_node = ts_child_by_field(operand, "name")
        arguments = ts_child_by_field(operand, "arguments")
        if name_node is not None and arguments is not None and not arguments.named_children:
            name = ts_node_text(source, name_node)
            return name if is_credential_name(name) else None
    return None


def _is_plausible_tree_sitter_credential_operand(operand: Node) -> bool:
    return getattr(operand, "type", None) in {
        "identifier",
        "field_access",
        "method_invocation",
        "string_literal",
    }


def _check_comparison(file_path: Path, node: javalang.tree.BinaryOperation) -> Finding | None:
    """Build a Finding if this is an unsafe reference-equality credential comparison."""
    if node.operator not in _REFERENCE_EQUALITY_OPERATORS:
        return None
    left_ref = _credential_operand(node.operandl)
    credential_ref, other = (
        (left_ref, node.operandr)
        if left_ref is not None
        else (_credential_operand(node.operandr), node.operandl)
    )
    if credential_ref is None:
        return None
    if not _is_plausible_credential_operand(other):
        return None
    line = _comparison_line(node)
    return Finding(
        cwe_id=CWE_ID,
        file_path=file_path,
        line=line,
        identifier=credential_ref,
        message=(
            f"'{credential_ref}' compared with '{node.operator}' instead of "
            ".equals() - Java's == compares object reference identity, not value, "
            "so this comparison does not reliably verify the credential"
        ),
    )


def _comparison_line(node: javalang.tree.BinaryOperation) -> int | None:
    """Return the best available source line for a comparison.

    javalang does not attach a ``position`` to a ``BinaryOperation``
    itself (confirmed empirically - same gap ``cwe_798.py`` hit for
    concatenated string literals), even though its operands do. Falls
    back to the left operand's position, then the right's, rather than
    losing traceability entirely.
    """
    for operand in (node.operandl, node.operandr):
        position = getattr(operand, "position", None)
        if position is not None:
            return position.line
    return None


def _credential_operand(operand: object) -> str | None:
    """Return the credential-shaped field/variable reference inside operand, if any.

    Handles both a bare reference (``password``) and a ``this``-
    qualified one (``this.password``) - javalang represents the latter
    as a ``This`` node with the field access in ``.selectors``, not as
    a ``MemberReference`` with a "this" qualifier, so checking only for
    a top-level ``MemberReference`` would miss every ``this.field``
    comparison, a very common way to disambiguate a field from a
    same-named parameter (as in a constructor or setter).
    """
    if isinstance(operand, javalang.tree.MemberReference) and is_credential_name(operand.member):
        return operand.member
    if isinstance(operand, javalang.tree.This):
        for selector in operand.selectors or []:
            if isinstance(selector, javalang.tree.MemberReference) and is_credential_name(
                selector.member
            ):
                return selector.member
    if (
        isinstance(operand, javalang.tree.MethodInvocation)
        and not operand.arguments
        and is_credential_name(operand.member)
    ):
        return operand.member
    return None


def _is_plausible_credential_operand(operand: object) -> bool:
    """Is the *other* side of the comparison something a credential could plausibly be?

    A variable/field reference (``MemberReference``) is always
    plausible - no type information is available without a symbol
    table, so this stays permissive there. A string literal is
    plausible too (``token == "abc123"``). ``null``, numeric, and
    boolean literals are excluded: ``password == null`` is a completely
    ordinary, correct null-check, not a credential-comparison bug, and
    a name like "passwordAttempts" matching the credential keyword
    "password" while being compared to an int literal is exactly the
    kind of false positive this guards against.
    """
    if isinstance(operand, javalang.tree.MemberReference):
        return True
    if isinstance(operand, javalang.tree.MethodInvocation):
        return True
    if isinstance(operand, javalang.tree.Literal):
        raw = operand.value
        return len(raw) >= 2 and raw.startswith('"') and raw.endswith('"')
    return False


def _check_unguarded_secret_return(
    file_path: Path, method: javalang.tree.MethodDeclaration
) -> Finding | None:
    """Build a Finding if an endpoint unconditionally returns a credential-shaped value.

    Scoped to endpoint methods only (``has_endpoint_annotation``) - a
    private helper method returning a token to its own caller inside the
    same class is not reachable from outside, so there's nothing to
    verify. "Guarded" means either an authorization annotation on the
    method (framework-enforced access control, e.g. Spring Security's
    ``@PreAuthorize``) or a hand-written ``if`` statement appearing
    before the return in the method's own top-level statement list - not
    a semantic understanding of what that ``if`` actually checks, the
    same coarse "presence of a decision, not whether it's the right one"
    philosophy ``cwe_284.py`` already uses. Walking javalang's
    ``method.body`` list directly (not by source line) matters here:
    these Codex-generated fixtures format an entire class body on one
    source line, so every statement shares ``position.line`` and line
    order cannot distinguish "before" from "after" - only AST list order
    can.

    Deliberately method-level only, not class-level like cwe_284.py's
    enclosing-type check: a class-wide authorization annotation with no
    method-level guard and a freshly-issued secret is a narrower,
    unobserved-so-far edge case, logged as a known scope limit rather
    than built speculatively.
    """
    if method.body is None:
        return None
    method_annotations = tuple(a.name for a in method.annotations)
    if not has_endpoint_annotation(method_annotations):
        return None
    if has_authorization_annotation(method_annotations):
        return None
    seen_guard = False
    for statement in method.body:
        if isinstance(statement, javalang.tree.IfStatement):
            seen_guard = True
            continue
        if seen_guard or not isinstance(statement, javalang.tree.ReturnStatement):
            continue
        identifier = _credential_value_reference(statement)
        if identifier is None:
            continue
        line = method.position.line if method.position else None
        return Finding(
            cwe_id=CWE_ID,
            file_path=file_path,
            line=line,
            identifier=identifier,
            message=_UNGUARDED_ISSUANCE_MESSAGE.format(method=method.name, identifier=identifier),
        )
    return None


def _credential_value_reference(node: object) -> str | None:
    """Find a bare credential-shaped variable/field reference anywhere inside a subtree.

    Mirrors ``_credential_operand``'s matching shapes (bare reference,
    ``this``-qualified field), but searches an entire subtree rather than
    comparing two specific operands: the value being returned may be
    nested arbitrarily deep (e.g. inside ``Map.of(...)``, a record
    constructor, or ``ResponseEntity.ok(...)``). Deliberately does not
    match zero-arg ``MethodInvocation`` the way ``_credential_operand``
    does for the comparison check: a method *call* named like a
    credential (e.g. ``complete.token()``, validating an incoming token)
    is not the same as a variable holding one, and matching it here
    produced a real false positive against a sibling project's token-
    verification endpoint during testing (2026-09-04).
    """
    if not hasattr(node, "filter"):
        return None
    for _path, ref in node.filter(javalang.tree.MemberReference):
        if is_credential_name(ref.member):
            return ref.member
    for _path, this_node in node.filter(javalang.tree.This):
        for selector in this_node.selectors or []:
            if isinstance(selector, javalang.tree.MemberReference) and is_credential_name(
                selector.member
            ):
                return selector.member
    return None


def _check_tree_sitter_unguarded_secret_return(
    file_path: Path, source: bytes, method: Node
) -> Finding | None:
    """Tree-sitter fallback counterpart to ``_check_unguarded_secret_return``."""
    method_annotations = ts_annotation_names(source, method)
    if not has_endpoint_annotation(method_annotations):
        return None
    if has_authorization_annotation(method_annotations):
        return None
    body = ts_child_by_field(method, "body")
    if body is None or body.type != "block":
        return None
    seen_guard = False
    for statement in ts_named_children(body):
        if statement.type == "if_statement":
            seen_guard = True
            continue
        if seen_guard or statement.type != "return_statement":
            continue
        identifier = _tree_sitter_credential_value_reference(source, statement)
        if identifier is None:
            continue
        method_name = ts_declaration_name(source, method)
        return Finding(
            cwe_id=CWE_ID,
            file_path=file_path,
            line=ts_node_line(method),
            identifier=identifier,
            message=_UNGUARDED_ISSUANCE_MESSAGE.format(method=method_name, identifier=identifier),
        )
    return None


def _tree_sitter_credential_value_reference(source: bytes, node: Node) -> str | None:
    """Find a credential-shaped identifier used as a value, not as a call/qualifier name."""
    for descendant in ts_walk(node):
        if descendant.type != "identifier":
            continue
        if _is_call_qualifier_or_name(descendant):
            continue
        name = ts_node_text(source, descendant)
        if is_credential_name(name):
            return name
    return None


def _is_call_qualifier_or_name(node: Node) -> bool:
    """Whether this identifier is a method-invocation's target/name, not a value.

    Tree-sitter, unlike javalang, represents a call's qualifier
    (``tokens`` in ``tokens.remove(...)``) as a full identifier node
    rather than a plain string attribute, so a naive "any credential-
    shaped identifier" walk would also match qualifiers and method
    names - e.g. ``tokens.remove(complete.token())`` contains "tokens"
    (matches the "token" keyword) and a method literally named "token".
    Excluding both keeps this path's precision equivalent to javalang's
    ``MemberReference``-only matching in ``_credential_value_reference``.
    """
    parent = node.parent
    if parent is None:
        return False
    if parent.type == "method_invocation":
        object_node = ts_child_by_field(parent, "object")
        name_node = ts_child_by_field(parent, "name")
        return (object_node is not None and object_node.id == node.id) or (
            name_node is not None and name_node.id == node.id
        )
    if parent.type == "field_access":
        object_node = ts_child_by_field(parent, "object")
        return object_node is not None and object_node.id == node.id
    return False
