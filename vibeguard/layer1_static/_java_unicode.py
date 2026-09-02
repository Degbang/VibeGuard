"""Java Unicode escape translation before parsing.

Java translates ``\\uXXXX`` escapes before lexical analysis, including
escapes that appear in identifiers. Parser libraries do not necessarily
perform that source-level translation for us, so Layer 1 normalizes the
source first and then parses the Java text javac would see.
"""

from __future__ import annotations

_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


def translate_java_unicode_escapes(source: str) -> str:
    """Translate Java ``\\uXXXX`` escapes using Java's repeated-u form.

    Invalid or incomplete escape-like sequences are left untouched so a
    malformed file still fails in the parser rather than in this helper.
    """
    result: list[str] = []
    index = 0
    while index < len(source):
        if source[index] != "\\" or index + 1 >= len(source) or source[index + 1] != "u":
            result.append(source[index])
            index += 1
            continue

        unicode_index = index + 2
        while unicode_index < len(source) and source[unicode_index] == "u":
            unicode_index += 1
        digits = source[unicode_index : unicode_index + 4]
        if len(digits) != 4 or any(char not in _HEX_DIGITS for char in digits):
            result.append(source[index])
            index += 1
            continue

        result.append(chr(int(digits, 16)))
        index = unicode_index + 4

    return "".join(result)
