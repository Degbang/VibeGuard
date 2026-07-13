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
    reported for anything after a rewritten record stay correct. It
    also preserves *per-field* line numbers within a multiline record:
    each synthesized field declaration is placed on the same relative
    line as the original component it came from, rather than
    compressing every field onto the record's first line - a CWE rule
    reporting a finding on a specific record field must still point at
    the field's real source line.
    """
    return _RECORD_PATTERN.sub(_rewrite_match, source)


def _rewrite_match(match: re.Match[str]) -> str:
    modifiers = match.group("modifiers") or ""
    name = match.group("name")
    type_params = match.group("type_params") or ""
    implements = match.group("implements")
    implements_clause = f"{implements} " if implements else ""

    total_lines = match.group(0).count("\n") + 1
    output_lines = ["" for _ in range(total_lines)]
    output_lines[0] = f"{modifiers}class {name}{type_params} {implements_clause}{{"

    for line_index, declarations in _fields_by_relative_line(match).items():
        joined = " ".join(declarations)
        output_lines[line_index] = f"{output_lines[line_index]} {joined}".strip()

    output_lines[-1] = f"{output_lines[-1]} }}".strip()
    return "\n".join(output_lines)


def _fields_by_relative_line(match: re.Match[str]) -> dict[int, list[str]]:
    """Map each record component to the line (relative to the match
    start) its parameter actually began on in the original source.

    javalang reports a FieldDeclaration's line from whatever text it
    was actually given; placing a synthesized field on the wrong line
    would make that reported line wrong too. This walks the params
    text tracking newlines precisely, rather than assuming every field
    lives on the record's opening line.
    """
    full_text = match.group(0)
    params_text = match.group("params")
    params_local_start = match.start("params") - match.start()
    base_line = full_text[:params_local_start].count("\n")

    fields_by_line: dict[int, list[str]] = {}
    for local_offset, raw_component in _split_top_level(params_text, ","):
        stripped = raw_component.strip()
        if not stripped:
            continue
        field_type, field_name = _split_type_and_name(stripped)
        if field_name is None:
            continue
        leading_whitespace = len(raw_component) - len(raw_component.lstrip())
        newlines_before = params_text[: local_offset + leading_whitespace].count("\n")
        line_index = base_line + newlines_before
        fields_by_line.setdefault(line_index, []).append(
            f"private final {field_type} {field_name};"
        )
    return fields_by_line


def _split_top_level(text: str, separator: str) -> list[tuple[int, str]]:
    """Split ``text`` on ``separator`` (ignoring separators nested in
    ``<>``/``()``/``[]``), returning each segment with its start offset.
    """
    parts: list[tuple[int, str]] = []
    depth = 0
    start = 0
    current: list[str] = []
    for index, char in enumerate(text):
        if char in "<([":
            depth += 1
        elif char in ">)]":
            depth -= 1
        if char == separator and depth == 0:
            parts.append((start, "".join(current)))
            current = []
            start = index + 1
        else:
            current.append(char)
    parts.append((start, "".join(current)))
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
