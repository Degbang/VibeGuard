"""CWE-798: Use of Hard-Coded Credentials.

Flags credential-shaped identifiers (password, secret, API key, token, ...)
that are assigned a literal, non-placeholder value - in Java declarations,
Java assignments, Java call sites, and flattened config-file entries
(``.properties``/``.yml``/``.yaml``). This never inspects runtime values or
executes anything; it is pure pattern matching over what Layer 1 already
parsed.

This is a detection rule, not a scorer: it decides *candidacy*, not
severity. Turning a list of Findings into a risk score is Layer 3's
job.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import TypeGuard

import javalang
from tree_sitter import Node

from vibeguard.layer1_static._java_literals import decode_java_string_literal
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
    string_literal_value as ts_string_literal_value,
)
from vibeguard.layer1_static._tree_sitter_java import (
    walk as ts_walk,
)
from vibeguard.layer1_static.ast_parser import ParsedFile
from vibeguard.layer1_static.config_parser import ParsedConfigFile
from vibeguard.layer1_static.rules._credential_names import (
    CREDENTIAL_KEYWORDS,
    is_credential_name,
    last_word,
)
from vibeguard.layer1_static.rules._finding import Finding

CWE_ID = "CWE-798"

# Known false-positive source in is_credential_name's keyword match
# (e.g. "passwordHash" matches too): Layer 1's job is to surface
# candidates, not make the final severity call - see the module
# docstring on Finding for where that narrowing happens. A hashed value
# (e.g. a bcrypt string) stored in a *Hash-suffixed field is not
# attempted to be distinguished from a real secret here.

# A name whose *last word* (see last_word) is one of these describes a
# reference to a secret - where to find it, what to call it - rather
# than the secret material itself. "secretName" holds the name of a
# secret to look up, not a value; "quarkus.kubernetes.env.secrets"
# names which Kubernetes Secret resources to mount, not an embedded
# credential. Deliberately excludes words like "key" that are
# themselves part of a real credential-shaped name (e.g. "secretKey"
# must still match).
_REFERENCE_SUFFIXES = frozenset(
    {"name", "id", "ref", "reference", "path", "alias", "arn", "uri", "url", "secrets"}
)

# Substrings that mark a value as an obvious placeholder rather than a
# real secret, checked case-insensitively.
_PLACEHOLDER_MARKERS = (
    "changeme",
    "change_me",
    "placeholder",
    "your_",
    "todo",
    "xxx",
    "example",
    "insert_",
    "replace_",
    "<",
    ">",
)

# Externalized-value syntax: Spring/Quarkus property substitution
# ("${DB_PASSWORD}") or Spring Expression Language ("#{systemProperties[
# 'secret']}"). Either means the value comes from config/env/a bean at
# runtime, not a literal in source - not hardcoded, despite being a
# string literal from javalang's point of view.
_PROPERTY_REFERENCE_PATTERN = re.compile(r"^[$#]\{.*\}$")

# Exact-match (not substring) values that are never a real secret
# regardless of the field/key name - "null" is a common accidental or
# deliberate non-value that a substring/placeholder check wouldn't
# catch (it isn't a "changeme"-style placeholder marker either).
_LITERAL_NON_VALUES = frozenset({"null"})

# Well-known, standard protocol/format/algorithm descriptor strings.
# Found as two real false positives scanning AI-generated code, both the
# same underlying structural cause: a credential-shaped constructor name
# (e.g. "SecretKeySpec" contains "secret"; "Token" is itself a
# credential keyword) combined with the reversed-argument scan below
# (deliberately preferring later arguments, for cases like
# PasswordAuthentication("user", "pass".toCharArray()) where the real
# secret genuinely is last) picking up a nearby literal that describes
# the *kind* of thing being constructed, not secret material - first
# "HmacSHA256" in new SecretKeySpec(keyBytes, "HmacSHA256"), then
# "Bearer" in new Token(accessToken, refreshToken, "Bearer", 3600).
# Both categories share the same property: a short, publicly-standard
# identifier defined by a spec (JCA algorithm names; OAuth/HTTP token
# and auth-scheme names per RFC 6749/RFC 7235), never real secret
# material regardless of which credential-shaped constructor or method
# it appears in - so an exact match (not substring, case-sensitive:
# these are case-sensitive standard identifiers) is safe. Not
# exhaustive; extend on the next real false positive found, same
# practice as everywhere else in this project.
_KNOWN_NON_SECRET_DESCRIPTOR_LITERALS = frozenset(
    {
        # JCA/JCE algorithm and transformation names.
        "AES",
        "DES",
        "DESede",
        "RSA",
        "Blowfish",
        "RC2",
        "RC4",
        "HmacMD5",
        "HmacSHA1",
        "HmacSHA224",
        "HmacSHA256",
        "HmacSHA384",
        "HmacSHA512",
        "MD5",
        "SHA-1",
        "SHA-224",
        "SHA-256",
        "SHA-384",
        "SHA-512",
        "PBKDF2WithHmacSHA1",
        "PBKDF2WithHmacSHA256",
        "PBKDF2WithHmacSHA512",
        "AES/CBC/PKCS5Padding",
        "AES/GCM/NoPadding",
        "AES/ECB/PKCS5Padding",
        "RSA/ECB/PKCS1Padding",
        "RSA/ECB/OAEPWithSHA-256AndMGF1Padding",
        # OAuth (RFC 6749) token_type values and HTTP (RFC 7235)
        # auth-scheme names.
        "Bearer",
        "Basic",
        "Digest",
        "MAC",
    }
)
_MAP_PUT_METHOD = "put"
_SYSTEM_SET_PROPERTY_METHOD = "setProperty"
_SPRING_VALUE_ANNOTATION = "value"
_LITERAL_PASSTHROUGH_METHODS = frozenset({"toCharArray"})
_SPRING_PROPERTY_DEFAULT_PATTERN = re.compile(r"^\$\{(?P<key>[^:}]+):(?P<default>[^}]*)\}$")


def detect_in_java(parsed_file: ParsedFile) -> tuple[Finding, ...]:
    """Find hardcoded-credential-shaped literals in a parsed Java file.

    Walks the raw parser AST rather than ``ParsedFile.classes``:
    declaration initializers and later assignments are not captured in
    that flattened summary.
    """
    if parsed_file.tree_sitter is not None:
        return _detect_in_tree_sitter_java(parsed_file)
    if parsed_file.tree is None:
        return ()

    findings = [
        finding
        for _path, node in parsed_file.tree.filter(javalang.tree.VariableDeclarator)
        if (finding := _check_declarator(parsed_file.path, node)) is not None
    ]
    findings.extend(
        finding
        for _path, node in parsed_file.tree.filter(javalang.tree.Assignment)
        if (finding := _check_assignment(parsed_file.path, node)) is not None
    )
    findings.extend(
        finding
        for _path, node in parsed_file.tree.filter(javalang.tree.MethodInvocation)
        if (finding := _check_method_invocation(parsed_file.path, node)) is not None
    )
    findings.extend(
        finding
        for _path, node in parsed_file.tree.filter(javalang.tree.ClassCreator)
        if (finding := _check_class_creator(parsed_file.path, node)) is not None
    )
    findings.extend(
        finding
        for _path, node in parsed_file.tree.filter(javalang.tree.Annotation)
        if (finding := _check_annotation(parsed_file.path, node)) is not None
    )
    return tuple(findings)


def _detect_in_tree_sitter_java(parsed_file: ParsedFile) -> tuple[Finding, ...]:
    """Find hardcoded credentials in a Tree-sitter fallback parse."""
    parsed = parsed_file.tree_sitter
    if parsed is None:
        return ()
    findings: list[Finding] = []
    for node in ts_walk(parsed.tree.root_node):
        if node.type == "variable_declarator":
            finding = _check_tree_sitter_declarator(parsed_file.path, parsed.source, node)
        elif node.type == "assignment_expression":
            finding = _check_tree_sitter_assignment(parsed_file.path, parsed.source, node)
        elif node.type == "method_invocation":
            finding = _check_tree_sitter_method_invocation(parsed_file.path, parsed.source, node)
        elif node.type == "object_creation_expression":
            finding = _check_tree_sitter_object_creation(parsed_file.path, parsed.source, node)
        elif node.type == "annotation":
            finding = _check_tree_sitter_annotation(parsed_file.path, parsed.source, node)
        else:
            continue
        if finding is not None:
            findings.append(finding)
    return tuple(findings)


def _check_tree_sitter_declarator(file_path: Path, source: bytes, node: Node) -> Finding | None:
    name_node = ts_child_by_field(node, "name")
    if name_node is None:
        return None
    name = ts_node_text(source, name_node)
    if not _is_credential_name(name):
        return None
    value_node = ts_child_by_field(node, "value")
    literal_value = _tree_sitter_expression_literal_value(source, value_node)
    if literal_value is None or _is_safe_value(literal_value):
        return None
    if _is_self_referential_constant(name, literal_value):
        return None
    line = _tree_sitter_expression_literal_line(source, value_node)
    if line is None and value_node is not None:
        line = ts_node_line(value_node)
    return _hardcoded_credential_finding(file_path, line, name, literal_value)


def _check_tree_sitter_assignment(file_path: Path, source: bytes, node: Node) -> Finding | None:
    operator = ts_child_by_field(node, "operator")
    if operator is None or ts_node_text(source, operator) != "=":
        return None
    target_node = ts_child_by_field(node, "left")
    name = _tree_sitter_assignment_target_name(source, target_node)
    if name is None or not _is_credential_name(name):
        return None
    value_node = ts_child_by_field(node, "right")
    literal_value = _tree_sitter_expression_literal_value(source, value_node)
    if literal_value is None or _is_safe_value(literal_value):
        return None
    if _is_self_referential_constant(name, literal_value):
        return None
    line = _tree_sitter_expression_literal_line(source, value_node) or ts_node_line(node)
    return _hardcoded_credential_finding(file_path, line, name, literal_value)


def _tree_sitter_assignment_target_name(source: bytes, node: Node | None) -> str | None:
    if node is None:
        return None
    if node.type == "identifier":
        return ts_node_text(source, node)
    if node.type != "field_access":
        return None
    field_node = ts_child_by_field(node, "field")
    if field_node is None:
        return None
    return ts_node_text(source, field_node)


def _check_tree_sitter_method_invocation(
    file_path: Path, source: bytes, node: Node
) -> Finding | None:
    method_name = _tree_sitter_call_name(source, node)
    arguments = _tree_sitter_arguments(node)
    if method_name is None or not arguments:
        return None
    if method_name == _SYSTEM_SET_PROPERTY_METHOD and len(arguments) >= 2:
        key = ts_string_literal_value(source, arguments[0])
        value = _tree_sitter_call_literal_value(source, arguments[1])
        if key is not None and _is_credential_name(key) and _is_reportable_literal(value):
            return _hardcoded_credential_finding(file_path, ts_node_line(arguments[1]), key, value)
    if method_name == _MAP_PUT_METHOD and len(arguments) >= 2:
        key = ts_string_literal_value(source, arguments[0])
        value = _tree_sitter_call_literal_value(source, arguments[1])
        if key is not None and _is_credential_name(key) and _is_reportable_literal(value):
            return _hardcoded_credential_finding(file_path, ts_node_line(arguments[1]), key, value)
    if not _is_credential_name(method_name):
        return None
    for argument in arguments:
        value = _tree_sitter_call_literal_value(source, argument)
        if _is_reportable_literal(value):
            return _hardcoded_credential_finding(
                file_path, ts_node_line(argument), method_name, value
            )
    return None


def _check_tree_sitter_object_creation(
    file_path: Path, source: bytes, node: Node
) -> Finding | None:
    type_node = ts_child_by_field(node, "type")
    if type_node is None:
        return None
    type_name = ts_node_text(source, type_node)
    if not _is_credential_name(type_name):
        return None
    for argument in reversed(_tree_sitter_arguments(node)):
        value = _tree_sitter_call_literal_value(source, argument)
        if _is_reportable_literal(value):
            return _hardcoded_credential_finding(
                file_path, ts_node_line(argument), type_name, value
            )
    return None


def _check_tree_sitter_annotation(file_path: Path, source: bytes, node: Node) -> Finding | None:
    name_node = ts_child_by_field(node, "name")
    if name_node is None or last_word(ts_node_text(source, name_node)) != _SPRING_VALUE_ANNOTATION:
        return None
    arguments = _tree_sitter_arguments(node)
    if not arguments:
        return None
    raw_value = ts_string_literal_value(source, arguments[0])
    parsed_default = _spring_property_default(raw_value)
    if parsed_default is None:
        return None
    key, default = parsed_default
    if not _is_credential_name(key) or _is_safe_value(default):
        return None
    return _hardcoded_credential_finding(file_path, ts_node_line(arguments[0]), key, default)


def _tree_sitter_call_name(source: bytes, node: Node) -> str | None:
    name_node = ts_child_by_field(node, "name")
    return ts_node_text(source, name_node) if name_node is not None else None


def _tree_sitter_arguments(node: Node) -> tuple[Node, ...]:
    arguments_node = ts_child_by_field(node, "arguments")
    if arguments_node is None:
        return ()
    return tuple(child for child in arguments_node.named_children)


def _tree_sitter_call_literal_value(source: bytes, node: Node | None) -> str | None:
    value = _tree_sitter_expression_literal_value(source, node)
    if value is not None:
        return value
    if node is None or node.type != "method_invocation":
        return None
    method_name = _tree_sitter_call_name(source, node)
    receiver = ts_child_by_field(node, "object")
    if method_name not in _LITERAL_PASSTHROUGH_METHODS:
        return None
    return ts_string_literal_value(source, receiver)


def _tree_sitter_expression_literal_value(source: bytes, node: Node | None) -> str | None:
    value = ts_string_literal_value(source, node)
    if value is not None:
        return value
    if node is None:
        return None
    if node.type == "ternary_expression":
        return _first_reportable_tree_sitter_literal(
            source,
            (
                ts_child_by_field(node, "consequence"),
                ts_child_by_field(node, "alternative"),
            ),
        )
    if node.type == "array_initializer":
        char_value = _tree_sitter_char_array_literal_value(source, node)
        if char_value is not None:
            return char_value
        return _first_reportable_tree_sitter_literal(source, tuple(node.named_children))
    if node.type in {
        "switch_expression",
        "switch_block",
        "switch_rule",
        "expression_statement",
    }:
        return _first_reportable_tree_sitter_literal(source, tuple(node.named_children))
    if node.type == "character_literal":
        return _tree_sitter_character_literal_value(source, node)
    return None


def _first_reportable_tree_sitter_literal(
    source: bytes, nodes: tuple[Node | None, ...]
) -> str | None:
    for node in nodes:
        value = _tree_sitter_expression_literal_value(source, node)
        if _is_reportable_literal(value):
            return value
    return None


def _tree_sitter_expression_literal_line(source: bytes, node: Node | None) -> int | None:
    if node is None:
        return None
    if _is_reportable_literal(_tree_sitter_expression_literal_value(source, node)):
        if node.type in {"string_literal", "character_literal"}:
            return ts_node_line(node)
        for child in node.named_children:
            line = _tree_sitter_expression_literal_line(source, child)
            if line is not None:
                return line
    return None


def _tree_sitter_character_literal_value(source: bytes, node: Node) -> str | None:
    raw = ts_node_text(source, node)
    if len(raw) < 2 or not (raw.startswith("'") and raw.endswith("'")):
        return None
    # Reuse the Java string decoder for the same escape forms.
    return decode_java_string_literal(f'"{raw[1:-1]}"')


def _tree_sitter_char_array_literal_value(source: bytes, node: Node) -> str | None:
    chars = []
    for child in node.named_children:
        if child.type != "character_literal":
            return None
        char = _tree_sitter_character_literal_value(source, child)
        if char is None:
            return None
        chars.append(char)
    return "".join(chars) if chars else None


def _check_declarator(file_path: Path, node: javalang.tree.VariableDeclarator) -> Finding | None:
    """Build a Finding if this declarator assigns a real secret-shaped value."""
    if not _is_credential_name(node.name):
        return None
    literal_value = _expression_literal_value(node.initializer)
    if literal_value is None or _is_safe_value(literal_value):
        return None
    if _is_self_referential_constant(node.name, literal_value):
        return None
    line = _initializer_line(node.initializer)
    return _hardcoded_credential_finding(file_path, line, node.name, literal_value)


def _check_assignment(file_path: Path, node: javalang.tree.Assignment) -> Finding | None:
    """Build a Finding if an assignment writes a real secret-shaped value."""
    if node.type != "=":
        return None
    name = _assignment_target_name(node.expressionl)
    if name is None or not _is_credential_name(name):
        return None
    literal_value = _expression_literal_value(node.value)
    if literal_value is None or _is_safe_value(literal_value):
        return None
    if _is_self_referential_constant(name, literal_value):
        return None
    line = _initializer_line(node.value)
    return _hardcoded_credential_finding(file_path, line, name, literal_value)


def _check_method_invocation(
    file_path: Path, node: javalang.tree.MethodInvocation
) -> Finding | None:
    if node.member == _SYSTEM_SET_PROPERTY_METHOD and len(node.arguments) >= 2:
        key = _string_literal_value(node.arguments[0])
        value = _call_literal_value(node.arguments[1])
        if key is not None and _is_credential_name(key) and _is_reportable_literal(value):
            return _hardcoded_credential_finding(
                file_path, _initializer_line(node.arguments[1]), key, value
            )
    if node.member == _MAP_PUT_METHOD and len(node.arguments) >= 2:
        key = _string_literal_value(node.arguments[0])
        value = _call_literal_value(node.arguments[1])
        if key is not None and _is_credential_name(key) and _is_reportable_literal(value):
            return _hardcoded_credential_finding(
                file_path, _initializer_line(node.arguments[1]), key, value
            )
    if not _is_credential_name(node.member):
        return None
    for argument in node.arguments:
        value = _call_literal_value(argument)
        if _is_reportable_literal(value):
            return _hardcoded_credential_finding(
                file_path, _initializer_line(argument), node.member, value
            )
    return None


def _check_annotation(file_path: Path, node: javalang.tree.Annotation) -> Finding | None:
    if last_word(node.name) != _SPRING_VALUE_ANNOTATION:
        return None
    raw_value = _string_literal_value(node.element)
    parsed_default = _spring_property_default(raw_value)
    if parsed_default is None:
        return None
    key, default = parsed_default
    if not _is_credential_name(key) or _is_safe_value(default):
        return None
    return _hardcoded_credential_finding(file_path, _initializer_line(node.element), key, default)


def _check_class_creator(file_path: Path, node: javalang.tree.ClassCreator) -> Finding | None:
    type_name = _javalang_type_name(node.type)
    if type_name is None or not _is_credential_name(type_name):
        return None
    for argument in reversed(node.arguments):
        value = _call_literal_value(argument)
        if _is_reportable_literal(value):
            return _hardcoded_credential_finding(
                file_path, _initializer_line(argument), type_name, value
            )
    return None


def _hardcoded_credential_finding(
    file_path: Path, line: int | None, name: str, literal_value: str
) -> Finding:
    return Finding(
        cwe_id=CWE_ID,
        file_path=file_path,
        line=line,
        identifier=name,
        redacted_value=_redact(literal_value),
        message=f"Hardcoded credential-like value assigned to '{name}'",
    )


def _assignment_target_name(target: object) -> str | None:
    if isinstance(target, javalang.tree.MemberReference):
        return target.member
    if isinstance(target, javalang.tree.This) and target.selectors:
        selector = target.selectors[-1]
        if isinstance(selector, javalang.tree.MemberReference):
            return selector.member
    return None


def _call_literal_value(argument: object | None) -> str | None:
    value = _expression_literal_value(argument)
    if value is not None:
        return value
    if not isinstance(argument, javalang.tree.MethodInvocation):
        return None
    if argument.member not in _LITERAL_PASSTHROUGH_METHODS:
        return None
    return _string_literal_value(argument.qualifier)


def _spring_property_default(value: str | None) -> tuple[str, str] | None:
    if value is None:
        return None
    match = _SPRING_PROPERTY_DEFAULT_PATTERN.match(value.strip())
    if match is None:
        return None
    return match.group("key"), match.group("default")


def _javalang_type_name(type_node: object) -> str | None:
    name = getattr(type_node, "name", None)
    if not isinstance(name, str):
        return None
    sub_type = getattr(type_node, "sub_type", None)
    if sub_type is None:
        return name
    sub_name = _javalang_type_name(sub_type)
    return name if sub_name is None else f"{name}.{sub_name}"


def _string_literal_value(initializer: object | None) -> str | None:
    """Return a string value's actual text, or None if not statically resolvable.

    Handles two shapes: a plain string literal, and a chain of ``+``
    concatenations where every operand is itself statically resolvable
    (e.g. ``"hunter" + "2"``) - a compile-time-constant secret split
    across literals is still a hardcoded secret, and this is common
    enough in practice (line-length formatting, minor obfuscation) to
    be worth folding rather than silently missing. Anything involving a
    variable/method call (``"a" + x``) can't be resolved statically and
    returns None - this rule only ever inspects source text, never
    evaluates anything.
    """
    if isinstance(initializer, javalang.tree.Literal):
        return _plain_literal_value(initializer)
    if isinstance(initializer, javalang.tree.BinaryOperation) and initializer.operator == "+":
        left = _string_literal_value(initializer.operandl)
        right = _string_literal_value(initializer.operandr)
        return None if left is None or right is None else left + right
    return None


def _expression_literal_value(initializer: object | None) -> str | None:
    value = _string_literal_value(initializer)
    if value is not None:
        return value
    if isinstance(initializer, javalang.tree.TernaryExpression):
        return _first_reportable_javalang_literal((initializer.if_true, initializer.if_false))
    if isinstance(initializer, javalang.tree.ArrayInitializer):
        char_value = _char_array_literal_value(initializer)
        if char_value is not None:
            return char_value
        return _first_reportable_javalang_literal(tuple(initializer.initializers))
    return None


def _first_reportable_javalang_literal(nodes: tuple[object | None, ...]) -> str | None:
    for node in nodes:
        value = _expression_literal_value(node)
        if _is_reportable_literal(value):
            return value
    return None


def _char_array_literal_value(initializer: javalang.tree.ArrayInitializer) -> str | None:
    chars = []
    for item in initializer.initializers:
        if not isinstance(item, javalang.tree.Literal):
            return None
        char = _character_literal_value(item)
        if char is None:
            return None
        chars.append(char)
    return "".join(chars) if chars else None


def _character_literal_value(literal: javalang.tree.Literal) -> str | None:
    raw = literal.value
    if len(raw) < 2 or not (raw.startswith("'") and raw.endswith("'")):
        return None
    return decode_java_string_literal(f'"{raw[1:-1]}"')


def _initializer_line(initializer: object | None) -> int | None:
    """Return the best source line for a static string initializer.

    javalang does not attach a position to a ``BinaryOperation`` like
    ``"hunter" + "2"``, even though its literal operands do have
    positions. For traceability, report the leftmost operand's line
    rather than losing the line number entirely.
    """
    position = getattr(initializer, "position", None)
    if position is not None:
        return position.line
    if isinstance(initializer, javalang.tree.BinaryOperation):
        return _initializer_line(initializer.operandl) or _initializer_line(initializer.operandr)
    if isinstance(initializer, javalang.tree.TernaryExpression):
        return _initializer_line(initializer.if_true) or _initializer_line(initializer.if_false)
    if isinstance(initializer, javalang.tree.ArrayInitializer):
        for item in initializer.initializers:
            line = _initializer_line(item)
            if line is not None:
                return line
    return None


def _plain_literal_value(literal: javalang.tree.Literal) -> str | None:
    """Return a Literal's string text, or None if it isn't a string literal.

    javalang keeps a literal's raw source token in ``.value``,
    including the surrounding quotes for strings (e.g. ``'"hunter2"'``)
    and no quotes for numbers/booleans (e.g. ``'5'``, ``'true'``) -
    that's how a string literal is distinguished from any other kind.
    Actual string decoding is centralized in ``_java_literals.py`` so
    the javalang and Tree-sitter paths cannot drift apart.
    """
    return decode_java_string_literal(literal.value)


def detect_in_config(parsed_config: ParsedConfigFile) -> tuple[Finding, ...]:
    """Find hardcoded-credential-shaped entries in a parsed config file."""
    return tuple(
        Finding(
            cwe_id=CWE_ID,
            file_path=parsed_config.path,
            line=entry.line,
            identifier=entry.key,
            redacted_value=_redact(entry.value),
            message=f"Hardcoded credential-like value assigned to '{entry.key}'",
        )
        for entry in parsed_config.entries
        if _is_credential_name(entry.key) and not _is_safe_value(entry.value)
    )


def _is_credential_name(name: str) -> bool:
    """Case-insensitive substring match against known credential keywords,
    excluding names that are a *reference* to a secret rather than the
    secret material itself - see ``_REFERENCE_SUFFIXES``."""
    if not is_credential_name(name):
        return False
    return last_word(name) not in _REFERENCE_SUFFIXES


def _is_self_referential_constant(name: str, value: str) -> bool:
    """Whether ``value`` is just ``name`` restated as a string literal -
    and ``name`` is more than merely the matched credential keyword itself.

    A real-world false-positive pattern found scanning Apache Syncope
    (``.qa-repos``): enterprise codebases commonly declare permission/
    entitlement/event-type constants as ``public static final String
    PASSWORD_MANAGEMENT_LIST = "PASSWORD_MANAGEMENT_LIST";`` - a string
    standing in for an enum value, not a credential. A value identical
    (case-insensitively) to its own declaring identifier can never be
    exploitable secret material in that shape: it reveals nothing an
    attacker couldn't already read from the field's own, already-public
    name.

    Independent QA found a real regression in an earlier version of this
    function that compared only ``name``/``value`` equality with no
    further check: ``String password = "password";`` is a real, well-
    known weak-default-credential anti-pattern (the "password is
    literally the word 'password'" shape) - textbook CWE-798 material -
    and was being silently suppressed by the same equality check that
    correctly excludes ``PASSWORD_MANAGEMENT_LIST``. The distinguishing
    signal, confirmed against every one of the 9 real Syncope findings
    this was built from: all 9 are *compound* identifiers (multiple
    words beyond the bare keyword); none is a bare credential keyword
    standing alone. This function now also requires ``name``, once
    separators are stripped, not to be *exactly* one of
    ``CREDENTIAL_KEYWORDS`` itself (covering ``apiKey = "apiKey"`` too -
    camelCase splits "apiKey" into two word-parts, but both parts
    together spell out exactly the ``apikey`` keyword, not a genuinely
    different, additional identifier like "management" or "list").
    """
    if name.strip().lower() != value.strip().lower():
        return False
    normalized_name = re.sub(r"[_-]", "", name.strip().lower())
    return not any(
        re.sub(r"[_-]", "", keyword) == normalized_name for keyword in CREDENTIAL_KEYWORDS
    )


def _is_safe_value(value: str) -> bool:
    """A value that isn't actually a hardcoded secret: empty, a property/
    SpEL reference, a literal non-value like "null", a well-known
    protocol/format/algorithm descriptor string, or an obvious
    placeholder."""
    stripped = value.strip()
    if not stripped:
        return True
    if _PROPERTY_REFERENCE_PATTERN.match(stripped):
        return True
    if stripped in _KNOWN_NON_SECRET_DESCRIPTOR_LITERALS:
        return True
    lowered = stripped.lower()
    if lowered in _LITERAL_NON_VALUES:
        return True
    return any(marker in lowered for marker in _PLACEHOLDER_MARKERS)


def _is_reportable_literal(value: str | None) -> TypeGuard[str]:
    return value is not None and not _is_safe_value(value)


def _redact(value: str) -> str:
    """Mask a matched value for safe inclusion in a Finding/report."""
    value = value.strip()
    if len(value) <= 2:
        return "*" * len(value)
    return f"{value[0]}{'*' * (len(value) - 2)}{value[-1]}"
