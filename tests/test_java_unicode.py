"""Tests for Java source-level Unicode escape translation."""

from vibeguard.layer1_static._java_unicode import translate_java_unicode_escapes


def test_translate_java_unicode_escapes_in_identifier() -> None:
    source = r'class C { String pass\u0077ord = "hunter2"; }'

    assert translate_java_unicode_escapes(source) == 'class C { String password = "hunter2"; }'


def test_translate_java_unicode_escapes_accepts_repeated_u_form() -> None:
    source = r"class C { String toke\uuu006E = value; }"

    assert translate_java_unicode_escapes(source) == "class C { String token = value; }"


def test_translate_java_unicode_escapes_leaves_invalid_sequences_for_parser() -> None:
    source = r"class C { String pass\u00ZZord = value; }"

    assert translate_java_unicode_escapes(source) == source
