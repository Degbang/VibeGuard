"""Tree-sitter Java parsing helpers for modern Java syntax.

This module is intentionally small and query-oriented. ``ast_parser.py``
uses it as a fallback when ``javalang`` cannot parse newer Java syntax,
and rule modules use its traversal helpers to inspect that fallback tree
without each rule reimplementing Tree-sitter boilerplate.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass

import tree_sitter_java
from tree_sitter import Language, Node, Parser, Tree

from vibeguard.layer1_static._java_literals import decode_java_string_literal


@dataclass(frozen=True)
class TreeSitterJavaFile:
    """A parsed Tree-sitter Java file plus the exact bytes it was parsed from."""

    tree: Tree
    source: bytes


_JAVA_LANGUAGE = Language(tree_sitter_java.language())
_PARSER = Parser(_JAVA_LANGUAGE)


def parse_java_source(source: str) -> TreeSitterJavaFile:
    """Parse Java source with Tree-sitter.

    Tree-sitter is syntax-only: it never compiles, loads, or executes the
    Java content. It is used here only to recover AST coverage for modern
    Java constructs that ``javalang`` cannot represent.
    """
    source_bytes = source.encode("utf-8")
    return TreeSitterJavaFile(tree=_PARSER.parse(source_bytes), source=source_bytes)


def node_text(source: bytes, node: Node) -> str:
    """Return a node's original source text."""
    return source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def node_line(node: Node) -> int:
    """Return a 1-based source line for a Tree-sitter node."""
    return node.start_point.row + 1


def child_by_field(node: Node, field_name: str) -> Node | None:
    """Return a child selected by Tree-sitter field name."""
    return node.child_by_field_name(field_name)


def named_children(node: Node) -> tuple[Node, ...]:
    """Return named children only, hiding punctuation tokens."""
    return tuple(child for child in node.children if child.is_named)


def walk(node: Node) -> Iterator[Node]:
    """Yield ``node`` and all descendants depth-first."""
    yield node
    for child in node.children:
        yield from walk(child)


def walk_with_ancestors(node: Node) -> Iterator[tuple[tuple[Node, ...], Node]]:
    """Yield each node with its ancestor path, excluding the node itself."""
    yield from _walk_with_ancestors(node, ())


def _walk_with_ancestors(
    node: Node, ancestors: tuple[Node, ...]
) -> Iterator[tuple[tuple[Node, ...], Node]]:
    yield ancestors, node
    next_ancestors = (*ancestors, node)
    for child in node.children:
        yield from _walk_with_ancestors(child, next_ancestors)


def annotation_names(source: bytes, node: Node) -> tuple[str, ...]:
    """Extract annotation names from a declaration or parameter node."""
    names: list[str] = []
    modifiers = _first_child_of_type(node, "modifiers")
    if modifiers is None:
        return ()
    for child in modifiers.children:
        if child.type not in {"annotation", "marker_annotation"}:
            continue
        name_node = child_by_field(child, "name")
        if name_node is not None:
            names.append(node_text(source, name_node))
    return tuple(names)


def modifiers(node: Node) -> frozenset[str]:
    """Extract Java modifier keyword text from a declaration node."""
    modifiers_node = _first_child_of_type(node, "modifiers")
    if modifiers_node is None:
        return frozenset()
    return frozenset(
        child.type
        for child in modifiers_node.children
        if not child.is_named and child.type not in {"@", "(", ")", ","}
    )


def nearest_enclosing_type(ancestors: tuple[Node, ...]) -> Node | None:
    """Return the nearest enclosing class/interface/record declaration."""
    for ancestor in reversed(ancestors):
        if ancestor.type in {"class_declaration", "interface_declaration", "record_declaration"}:
            return ancestor
    return None


def type_name(source: bytes, node: Node | None) -> str:
    """Render a type node as source text, or ``void`` when absent."""
    if node is None:
        return "void"
    return node_text(source, node).strip()


def declaration_name(source: bytes, node: Node) -> str:
    """Return a class/interface/record/method/parameter/declarator name."""
    name_node = child_by_field(node, "name")
    return node_text(source, name_node).strip() if name_node is not None else ""


def string_literal_value(source: bytes, node: Node | None) -> str | None:
    """Return a statically-known string value, including literal concatenation."""
    if node is None:
        return None
    if node.type == "string_literal":
        return _plain_string_literal_value(source, node)
    if node.type == "binary_expression":
        operator = child_by_field(node, "operator")
        if operator is None or node_text(source, operator).strip() != "+":
            return None
        left = string_literal_value(source, child_by_field(node, "left"))
        right = string_literal_value(source, child_by_field(node, "right"))
        return None if left is None or right is None else left + right
    return None


def _plain_string_literal_value(source: bytes, node: Node) -> str | None:
    raw = node_text(source, node)
    return decode_java_string_literal(raw)


def _first_child_of_type(node: Node, node_type: str) -> Node | None:
    for child in node.children:
        if child.type == node_type:
            return child
    return None
