"""CWE-798: Use of Hard-Coded Credentials.

Flags credential-shaped identifiers (password, secret, API key, token,
...) that are assigned a literal, non-placeholder value - in Java source
(field and local variable declarations) and in flattened config-file
entries (``.properties``/``.yml``/``.yaml``). This never inspects
runtime values or executes anything; it is pure pattern matching over
what Layer 1 already parsed (``ParsedFile.tree``, ``ParsedConfigFile.
entries``).

This is a detection rule, not a scorer: it decides *candidacy*, not
severity. Turning a list of Findings into a risk score is Layer 3's
job.
"""

from __future__ import annotations

import re
from pathlib import Path

import javalang

from vibeguard.layer1_static.ast_parser import ParsedFile
from vibeguard.layer1_static.config_parser import ParsedConfigFile
from vibeguard.layer1_static.rules._finding import Finding

CWE_ID = "CWE-798"

# Case-insensitive substring match against field/variable/config-key
# names. Deliberately permissive (e.g. "passwordHash" also matches):
# Layer 1's job is to surface candidates, not make the final severity
# call - see the module docstring on Finding for where that narrowing
# happens. Known false-positive source: a hashed value (e.g. a bcrypt
# string) stored in a *Hash-suffixed field would still match if it's a
# literal - not attempted to be distinguished here.
_CREDENTIAL_KEYWORDS = (
    "password",
    "passwd",
    "pwd",
    "secret",
    "apikey",
    "api_key",
    "accesskey",
    "access_key",
    "authtoken",
    "auth_token",
    "token",
    "privatekey",
    "private_key",
    "clientsecret",
    "client_secret",
    "credential",
    "secretkey",
    "secret_key",
    "encryptionkey",
    "encryption_key",
)

# A name whose *last word* (see _last_word) is one of these describes a
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


def detect_in_java(parsed_file: ParsedFile) -> tuple[Finding, ...]:
    """Find hardcoded-credential-shaped literals in a parsed Java file.

    Walks the raw javalang AST via ``.filter()`` rather than
    ``ParsedFile.classes`` - neither field nor local-variable
    initializer values are captured in that flattened summary (see
    ``ParsedFile.tree``'s docstring for why the raw tree is kept
    around at all). Covers both class fields and local variables
    inside method bodies; ``VariableDeclarator`` is the node type
    javalang uses for the declared-name-plus-initializer part of both.
    """
    if parsed_file.tree is None:
        return ()

    findings = [
        finding
        for _path, node in parsed_file.tree.filter(javalang.tree.VariableDeclarator)
        if (finding := _check_declarator(parsed_file.path, node)) is not None
    ]
    return tuple(findings)


def _check_declarator(file_path: Path, node: javalang.tree.VariableDeclarator) -> Finding | None:
    """Build a Finding if this declarator assigns a real secret-shaped value."""
    if not _is_credential_name(node.name):
        return None
    literal_value = _string_literal_value(node.initializer)
    if literal_value is None or _is_safe_value(literal_value):
        return None
    line = _initializer_line(node.initializer)
    return Finding(
        cwe_id=CWE_ID,
        file_path=file_path,
        line=line,
        identifier=node.name,
        redacted_value=_redact(literal_value),
        message=f"Hardcoded credential-like value assigned to '{node.name}'",
    )


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
    return None


def _plain_literal_value(literal: javalang.tree.Literal) -> str | None:
    """Return a Literal's string text, or None if it isn't a string literal.

    javalang keeps a literal's raw source token in ``.value``,
    including the surrounding quotes for strings (e.g. ``'"hunter2"'``)
    and no quotes for numbers/booleans (e.g. ``'5'``, ``'true'``) -
    that's how a string literal is distinguished from any other kind.
    Unescapes only ``\\"`` and ``\\\\`` (not full Java string-escape
    handling) since that's sufficient to inspect realistic secret
    values without needing a full literal-escape parser.
    """
    raw = literal.value
    if len(raw) < 2 or not (raw.startswith('"') and raw.endswith('"')):
        return None
    return raw[1:-1].replace('\\"', '"').replace("\\\\", "\\")


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
    lowered = name.lower()
    if not any(keyword in lowered for keyword in _CREDENTIAL_KEYWORDS):
        return False
    return _last_word(name) not in _REFERENCE_SUFFIXES


_WORD_PATTERN = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z0-9]+")


def _last_word(identifier: str) -> str:
    """Extract an identifier's final word, splitting camelCase and ./_/- separators.

    "secretName" -> "name", "quarkus.kubernetes.env.secrets" -> "secrets",
    "APIKey" -> "key". Used to check *what kind of thing* the name's
    last component describes, without being fooled by where a
    credential keyword happens to sit earlier in the identifier.
    """
    normalized = re.sub(r"[._-]", " ", identifier)
    words = _WORD_PATTERN.findall(normalized)
    return words[-1].lower() if words else identifier.lower()


def _is_safe_value(value: str) -> bool:
    """A value that isn't actually a hardcoded secret: empty, a property/
    SpEL reference, a literal non-value like "null", or an obvious
    placeholder."""
    stripped = value.strip()
    if not stripped:
        return True
    if _PROPERTY_REFERENCE_PATTERN.match(stripped):
        return True
    lowered = stripped.lower()
    if lowered in _LITERAL_NON_VALUES:
        return True
    return any(marker in lowered for marker in _PLACEHOLDER_MARKERS)


def _redact(value: str) -> str:
    """Mask a matched value for safe inclusion in a Finding/report."""
    if len(value) <= 2:
        return "*" * len(value)
    return f"{value[0]}{'*' * (len(value) - 2)}{value[-1]}"
