"""CWE-287: Improper Authentication.

Flags Java's classic authentication-comparison bug: comparing a
credential-shaped value (password, token, secret, ...) with ``==``/
``!=`` instead of ``.equals()``. ``==`` on ``String``/object types
compares *reference* identity, not value - due to Java's string
interning, two credential values that are character-for-character
equal can still compare unequal with ``==`` (or, in narrower cases,
accidentally compare equal when they shouldn't), so an authentication
check written this way does not reliably prove the claimed credential
is correct. That is squarely CWE-287: the software insufficiently
proves that a claimed identity/credential is correct.

Only Java source is relevant here - this pattern doesn't have a
config-file equivalent the way CWE-798 does. Walks ``ParsedFile.tree``
directly via ``.filter(BinaryOperation)``, the same approach
``cwe_284.py`` uses for ``MethodDeclaration`` - Layer 1's flattened
summary doesn't capture expressions at all, only declarations.
"""

from __future__ import annotations

from pathlib import Path

import javalang
from tree_sitter import Node

from vibeguard.layer1_static._tree_sitter_java import (
    child_by_field as ts_child_by_field,
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
from vibeguard.layer1_static.rules._credential_names import is_credential_name
from vibeguard.layer1_static.rules._finding import Finding

CWE_ID = "CWE-287"

_REFERENCE_EQUALITY_OPERATORS = frozenset({"==", "!="})


def detect_in_java(parsed_file: ParsedFile) -> tuple[Finding, ...]:
    """Find ``==``/``!=`` comparisons involving a credential-shaped operand."""
    if parsed_file.tree_sitter is not None:
        return _detect_in_tree_sitter_java(parsed_file)
    if parsed_file.tree is None:
        return ()

    findings = [
        finding
        for _path, node in parsed_file.tree.filter(javalang.tree.BinaryOperation)
        if (finding := _check_comparison(parsed_file.path, node)) is not None
    ]
    return tuple(findings)


def _detect_in_tree_sitter_java(parsed_file: ParsedFile) -> tuple[Finding, ...]:
    """Find unsafe credential comparisons in a Tree-sitter fallback parse."""
    parsed = parsed_file.tree_sitter
    if parsed is None:
        return ()
    findings: list[Finding] = []
    for node in ts_walk(parsed.tree.root_node):
        if node.type != "binary_expression":
            continue
        finding = _check_tree_sitter_comparison(parsed_file.path, parsed.source, node)
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
