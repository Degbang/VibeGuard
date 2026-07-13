"""Pre-parse text rewriting for a Java syntax javalang cannot parse.

``javalang`` 0.13.0 predates Java 16 and cannot parse ``record``
declarations at all (nor sealed classes, pattern matching, switch
expressions, or text blocks - see IMPLEMENTATION_LOG.md for the full
compatibility assessment). Records specifically are the dominant
modern pattern for DTO/config value classes in AI-generated
Spring/Quarkus code, so failing on them entirely is a disproportionate
real-world gap for a narrow, mechanical fix: before handing source
text to javalang, rewrite *simple* records - an empty-bodied
declaration with no compact constructor and no extra methods - into
an equivalent class with one field per record component.

This is a deliberately narrow fix, not a general Java 17-21 upgrade.
Sealed classes, pattern matching, switch expressions, and text blocks
are NOT handled here and remain ``PARSE_FAILED``. A record with a
non-empty body (a compact constructor, extra methods) is also left
untouched, so it fails exactly as before rather than being silently
mistranslated into something incorrect.
"""

from __future__ import annotations

import re

_RECORD_PATTERN = re.compile(
    r"""
    (?P<modifiers>(?:(?:public|private|protected|static|final|abstract)\s+)*)
    record\s+
    (?P<name>[A-Za-z_]\w*)
    (?P<type_params><[^>{]*>)?
    \s*\(\s*(?P<params>[^()]*)\)\s*
    (?P<implements>implements\s+[^{]+)?
    \{\s*\}
    """,
    re.VERBOSE,
)


def desugar_simple_records(source: str) -> str:
    """Rewrite empty-bodied ``record`` declarations into equivalent classes.

    Preserves the file's total newline count exactly, so line numbers
    reported for anything after a rewritten record stay correct - the
    record's own declaration and its synthesized fields are compressed
    onto one output line, which is an accepted, documented
    approximation for that specific declaration's own reported line
    only (not for anything else in the file).
    """
    return _RECORD_PATTERN.sub(_rewrite_match, source)


def _rewrite_match(match: re.Match[str]) -> str:
    modifiers = match.group("modifiers") or ""
    name = match.group("name")
    type_params = match.group("type_params") or ""
    implements = match.group("implements")
    fields = _fields_from_params(match.group("params").strip())

    implements_clause = f"{implements} " if implements else ""
    rewritten = f"{modifiers}class {name}{type_params} {implements_clause}{{ {fields} }}"
    return rewritten + ("\n" * match.group(0).count("\n"))


def _fields_from_params(params: str) -> str:
    """Turn a record's component list into field declaration text."""
    if not params:
        return ""
    field_decls = []
    for component in _split_top_level(params, ","):
        component = component.strip()
        if not component:
            continue
        field_type, field_name = _split_type_and_name(component)
        if field_name is None:
            continue
        field_decls.append(f"private final {field_type} {field_name};")
    return " ".join(field_decls)


def _split_top_level(text: str, separator: str) -> list[str]:
    """Split ``text`` on ``separator``, ignoring separators nested in <>/()/[]."""
    parts: list[str] = []
    depth = 0
    current: list[str] = []
    for char in text:
        if char in "<([":
            depth += 1
        elif char in ">)]":
            depth -= 1
        if char == separator and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    parts.append("".join(current))
    return parts


def _split_type_and_name(component: str) -> tuple[str, str | None]:
    """Split ``"Type name"`` into ``(type, name)``, stripping leading annotations."""
    component = re.sub(r"@\w+(\([^)]*\))?\s+", "", component).strip()
    if " " not in component:
        return component, None
    field_type, field_name = component.rsplit(None, 1)
    field_type = field_type.strip()
    if field_type.endswith("..."):
        field_type = field_type[:-3].strip() + "[]"
    return field_type, field_name.strip()
