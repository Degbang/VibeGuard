"""Pre-parse text rewriting for Java syntax javalang cannot parse.

``javalang`` 0.13.0 predates Java 16 and cannot parse several
Java 16-21 constructs at all. Rather than a parser migration (a much
larger undertaking - see IMPLEMENTATION_LOG.md for why that was
deferred), each construct below is rewritten into javalang-parseable
equivalent source text before parsing, the same technique already
proven for records.

Current coverage, and why each one either is or isn't handled this way:

- **Records** (empty-bodied): rewritten into an equivalent class with
  one field per component. The dominant modern DTO/config-value
  pattern in AI-generated Spring/Quarkus code - too common a gap to
  leave unsupported. A record with a non-empty body (compact
  constructor, extra methods) is left untouched rather than guessed
  at incorrectly.
- **Sealed classes/interfaces**: the ``sealed``/``non-sealed``
  modifier and trailing ``permits ...`` clause are stripped, leaving
  an ordinary class/interface declaration. Low risk: this only touches
  the type's header, never its body, and permits-list information
  isn't needed by any current CWE rule.
- **Pattern-matching ``instanceof``** (``o instanceof String s``): the
  bound variable is stripped, leaving a plain ``instanceof`` check.
  Low risk for the same reason - javalang has no semantic/symbol
  resolution, so a later reference to the now-unbound variable name
  still parses fine (javalang never checks whether an identifier was
  declared); no current CWE rule needs the binding itself.
- **Text blocks** (triple-double-quote delimited): re-emitted as an
  equivalent escaped single-line string literal, implementing the JEP 378
  indentation-stripping algorithm directly (minimum common indentation
  across content lines, trailing whitespace stripped per line).
  Handled carefully, not skipped, specifically because getting a
  string's *value* wrong is worse than not supporting it at all for
  CWE-798, which reasons about literal string values - a wrong value
  could produce a wrong hardcoded-secret verdict, silently. Verified
  against JEP 378's own canonical example, not just "does it parse."
  Known simplification: text-block-specific escapes (``\\s`` for an
  explicit trailing space, ``\\<newline>`` for line continuation) are
  not interpreted, only the standard stripping/whitespace rules -
  documented as a limitation rather than guessed at.
- **Switch expressions / pattern-matching ``switch``** (arrow-style
  ``case X -> ...``): deliberately **not** handled here. Converting
  arrow-style case bodies (which can be a single expression, a block,
  or a throw) back to colon-style ``case X: yield ...; break;`` needs
  actual understanding of the body's structure, not a text
  substitution - getting it wrong risks silently corrupting the AST
  structure itself, a materially worse failure mode than a clean
  ``PARSE_FAILED``. Remains an explicit, documented gap.
"""

from __future__ import annotations

import re

_SEALED_MODIFIER_PATTERN = re.compile(r"\b(?:non-sealed|sealed)\s+")
_PERMITS_CLAUSE_PATTERN = re.compile(r"\s+permits\s+[^{]+(?=\{)")
_PATTERN_INSTANCEOF_PATTERN = re.compile(
    r"(instanceof\s+[A-Za-z_][\w.]*(?:<[^>]*>)?(?:\[\])*)\s+[A-Za-z_]\w*" r"(?=\s*(?:[)&|;,?:{]|$))"
)
_TEXT_BLOCK_PATTERN = re.compile(r'"""[ \t]*\r?\n(?P<content>.*?)"""', re.DOTALL)

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


def preprocess(source: str) -> str:
    """Apply every modern-Java rewrite in a safe order, then hand off to javalang.

    Text blocks are desugared *first*, before any other rewrite touches
    the source: a text block's raw content could otherwise coincidentally
    contain something that looks like a sealed-class header or a
    pattern-matching ``instanceof`` to the other regexes, corrupting the
    string's value. Once text blocks are gone, the remaining rewrites
    only ever operate on genuine code.
    """
    source = desugar_text_blocks(source)
    source = strip_sealed_modifiers(source)
    source = strip_pattern_matching_bindings(source)
    return desugar_simple_records(source)


def _blank_out(match: re.Match[str]) -> str:
    """Replace a match with nothing but its newlines, preserving line count."""
    return "\n" * match.group(0).count("\n")


def _keep_group_one(match: re.Match[str]) -> str:
    """Replace a match with only its first group, preserving the rest as newlines.

    Assumes group 1 is a prefix of the full match, true for
    ``_PATTERN_INSTANCEOF_PATTERN`` (the part being discarded - the
    bound variable name - always comes after it).
    """
    kept = match.group(1)
    discarded = match.group(0)[len(kept) :]
    return kept + "\n" * discarded.count("\n")


def strip_sealed_modifiers(source: str) -> str:
    """Strip ``sealed``/``non-sealed`` modifiers and trailing ``permits`` clauses.

    Only touches a type's header, never its body - javalang doesn't
    need the ``permits`` list to parse the rest of the file, and no
    current CWE rule needs it either. A real-world ``permits`` clause
    can itself span multiple lines (a long list of permitted types);
    deleting it outright would shift every subsequent line number, so
    each match is replaced with a run of blank lines matching however
    many newlines it contained, same as every other rewrite here.
    """
    without_modifier = _SEALED_MODIFIER_PATTERN.sub(_blank_out, source)
    return _PERMITS_CLAUSE_PATTERN.sub(_blank_out, without_modifier)


def strip_pattern_matching_bindings(source: str) -> str:
    """Strip the bound variable from a pattern-matching ``instanceof`` check.

    ``o instanceof String s`` becomes ``o instanceof String``. Safe
    because javalang has no semantic/symbol resolution: a later
    reference to the now-unbound variable name still parses fine (it
    never checks whether an identifier was actually declared), and no
    current CWE rule needs the binding itself. The (rare) case of a
    line break between the type and the bound variable name is still
    newline-count-safe, same as every other rewrite here.
    """
    return _PATTERN_INSTANCEOF_PATTERN.sub(_keep_group_one, source)


def desugar_text_blocks(source: str) -> str:
    """Rewrite triple-double-quote text blocks into equivalent escaped string literals.

    Implements JEP 378's indentation-stripping algorithm directly
    (minimum common leading whitespace across content lines, trailing
    whitespace stripped per line) and preserves the file's total
    newline count, the same line-preservation approach
    ``desugar_simple_records`` already uses, so nothing after a
    rewritten text block has its reported line number shifted.
    """
    return _TEXT_BLOCK_PATTERN.sub(_rewrite_text_block, source)


def _rewrite_text_block(match: re.Match[str]) -> str:
    lines = match.group("content").split("\n")
    stripped_lines = _strip_text_block_indentation(lines)
    value = "\n".join(stripped_lines)
    literal = _escape_for_string_literal(value)

    total_lines = match.group(0).count("\n") + 1
    padding = "\n" * (total_lines - 1)
    return f'"{literal}"{padding}'


def _strip_text_block_indentation(lines: list[str]) -> list[str]:
    """Apply JEP 378's whitespace rules: strip the minimum common leading

    indentation (spaces/tabs only, per the JLS) found across every
    non-blank line, then strip trailing whitespace from every line.
    A blank final entry (present when the closing delimiter sat on its
    own line) naturally becomes an empty string, which - once the
    lines are rejoined with ``\n`` - reproduces the trailing newline
    that case is supposed to have.
    """

    def leading_whitespace(line: str) -> int:
        return len(line) - len(line.lstrip(" \t"))

    non_blank_lines = [line for line in lines if line.strip() != ""]
    min_indent = min((leading_whitespace(line) for line in non_blank_lines), default=0)
    return [line[min_indent:].rstrip() for line in lines]


def _escape_for_string_literal(value: str) -> str:
    """Escape a text block's stripped value for embedding as a normal string literal.

    Walks the string tracking escape state so an already-escaped
    character (part of an existing ``\\"``, ``\\n``, ``\\\\``, ...
    sequence already present in the original text block) is left
    untouched - Java processes escape sequences identically in text
    blocks and normal strings, so re-escaping an already-escaped
    character would corrupt the value (turning ``\\"`` into ``\\\\"``,
    which means something different). Only a genuinely *raw*,
    unescaped double quote or an actual newline character (introduced
    by joining what was multi-line content into one line) gets
    escaped - those are the two characters a normal string literal
    can't contain raw.

    Known simplification: the two escapes that only exist inside text
    blocks (``\\s`` for an explicit trailing space, ``\\`` followed by
    a line break for line continuation) are not specially interpreted
    here, so a text block using either would carry a slightly
    different literal value after rewriting than true JEP 378 gives it
    - documented, not silently assumed correct.
    """
    result: list[str] = []
    previous_was_unescaped_backslash = False
    for char in value:
        if previous_was_unescaped_backslash:
            result.append(char)
            previous_was_unescaped_backslash = False
            continue
        if char == "\\":
            result.append(char)
            previous_was_unescaped_backslash = True
            continue
        if char == '"':
            result.append('\\"')
        elif char == "\n":
            result.append("\\n")
        else:
            result.append(char)
    return "".join(result)
