"""Tests for shared Java string-literal decoding."""

from __future__ import annotations

from vibeguard.layer1_static._java_literals import decode_java_string_literal


def test_decode_normal_string_literal_escapes() -> None:
    assert decode_java_string_literal(r'"hun\u0074er\n2"') == "hunter\n2"


def test_decode_text_block_strips_indentation() -> None:
    raw = '"""\n        hunter\n        2\n        """'

    assert decode_java_string_literal(raw) == "hunter\n2\n"


def test_decode_text_block_specific_escapes() -> None:
    raw = '"""\n        hunter\\\n        2\\s\n        """'

    assert decode_java_string_literal(raw) == "hunter2 \n"


def test_decode_non_string_token_returns_none() -> None:
    assert decode_java_string_literal("123") is None
