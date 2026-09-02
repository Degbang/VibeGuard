"""Java literal decoding shared by parser-specific Layer 1 code.

Both javalang and Tree-sitter expose string literals as raw source
tokens. CWE-798 reasons about the literal's value, so parser paths must
not each maintain subtly different decoding behavior.
"""

from __future__ import annotations

import re

_TEXT_BLOCK_PATTERN = re.compile(r'^"""[ \t]*(?:\r\n|\r|\n)(?P<content>.*)"""$', re.DOTALL)


def decode_java_string_literal(raw: str) -> str | None:
    """Decode a Java string or text-block literal token.

    Returns ``None`` for non-string tokens. This intentionally handles
    the escape forms relevant to static secret detection and text-block
    normalization; it does not attempt to be a full javac replacement.
    """
    if raw.startswith('"""') and raw.endswith('"""'):
        return _decode_text_block(raw)
    if len(raw) < 2 or not (raw.startswith('"') and raw.endswith('"')):
        return None
    return _decode_standard_escapes(raw[1:-1])


def _decode_text_block(raw: str) -> str | None:
    match = _TEXT_BLOCK_PATTERN.match(raw)
    if match is None:
        return None
    lines = match.group("content").split("\n")
    stripped = _strip_text_block_indentation(lines)
    value = "\n".join(stripped)
    value = _interpret_text_block_escapes(value)
    return _decode_standard_escapes(value)


def _strip_text_block_indentation(lines: list[str]) -> list[str]:
    def leading_whitespace(line: str) -> int:
        return len(line) - len(line.lstrip(" \t"))

    non_blank_lines = [line for line in lines if line.strip() != ""]
    min_indent = min((leading_whitespace(line) for line in non_blank_lines), default=0)
    return [line[min_indent:].rstrip() for line in lines]


def _interpret_text_block_escapes(value: str) -> str:
    result: list[str] = []
    index = 0
    while index < len(value):
        char = value[index]
        if char == "\\" and index + 1 < len(value):
            next_char = value[index + 1]
            if next_char == "s":
                result.append(" ")
                index += 2
                continue
            if next_char == "\n":
                index += 2
                continue
        result.append(char)
        index += 1
    return "".join(result)


def _decode_standard_escapes(value: str) -> str:
    result: list[str] = []
    index = 0
    while index < len(value):
        char = value[index]
        if char != "\\" or index + 1 >= len(value):
            result.append(char)
            index += 1
            continue
        escape = value[index + 1]
        if escape == "u":
            decoded, consumed = _decode_unicode_escape(value, index)
            if decoded is not None:
                result.append(decoded)
                index += consumed
                continue
        mapped = {
            "b": "\b",
            "t": "\t",
            "n": "\n",
            "f": "\f",
            "r": "\r",
            '"': '"',
            "'": "'",
            "\\": "\\",
        }.get(escape)
        if mapped is not None:
            result.append(mapped)
            index += 2
            continue
        result.append(escape)
        index += 2
    return "".join(result)


def _decode_unicode_escape(value: str, slash_index: int) -> tuple[str | None, int]:
    index = slash_index + 2
    while index < len(value) and value[index] == "u":
        index += 1
    digits = value[index : index + 4]
    if len(digits) != 4 or any(char not in "0123456789abcdefABCDEF" for char in digits):
        return None, 0
    return chr(int(digits, 16)), index + 4 - slash_index
