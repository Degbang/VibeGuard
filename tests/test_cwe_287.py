"""Tests for vibeguard.layer1_static.rules.cwe_287."""

from __future__ import annotations

from pathlib import Path

from vibeguard.layer1_static.ast_parser import parse_file
from vibeguard.layer1_static.rules.cwe_287 import CWE_ID, detect_in_java

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_detect_in_java_finds_unsafe_equality_comparison() -> None:
    result = parse_file(FIXTURES_DIR / "UnsafeAuthComparison.java")

    findings = detect_in_java(result)

    assert len(findings) == 2
    lines = {f.line for f in findings}
    assert lines == {13, 35}
    assert all(f.cwe_id == CWE_ID and f.identifier == "password" for f in findings)


def test_detect_in_java_finds_this_qualified_unsafe_comparison() -> None:
    """this.password == input must be caught, not just a bare `password == input`.

    javalang represents this.password as a This node with the field
    access nested in .selectors, not as a MemberReference with a
    "this" qualifier - a real bug found by testing this specifically,
    not something the initial implementation handled.
    """
    result = parse_file(FIXTURES_DIR / "UnsafeAuthComparison.java")

    findings = detect_in_java(result)
    finding = next(f for f in findings if f.line == 35)

    assert finding.identifier == "password"


def test_detect_in_java_does_not_flag_equals_comparison() -> None:
    result = parse_file(FIXTURES_DIR / "UnsafeAuthComparison.java")

    findings = detect_in_java(result)

    # safeCheck's password.equals(input) must not appear - it's the correct form
    assert len(findings) == 2  # only unsafeCheck's and thisQualifiedUnsafeCheck's


def test_detect_in_java_does_not_flag_null_check() -> None:
    """password == null is a completely ordinary, correct null-check."""
    result = parse_file(FIXTURES_DIR / "UnsafeAuthComparison.java")

    findings = detect_in_java(result)
    lines = {f.line for f in findings}

    assert 21 not in lines  # the nullCheck method's line


def test_detect_in_java_does_not_flag_numeric_field_sharing_a_keyword() -> None:
    """passwordAttempts == 3 must not be flagged just because "password" is a substring."""
    result = parse_file(FIXTURES_DIR / "UnsafeAuthComparison.java")

    identifiers = {f.identifier for f in detect_in_java(result)}

    assert "passwordAttempts" not in identifiers


def test_detect_in_java_does_not_flag_boolean_literal_comparison() -> None:
    result = parse_file(FIXTURES_DIR / "UnsafeAuthComparison.java")

    identifiers = {f.identifier for f in detect_in_java(result)}

    assert "isValid" not in identifiers


def test_detect_in_java_flags_credential_compared_to_string_literal(tmp_path: Path) -> None:
    java_file = tmp_path / "Foo.java"
    java_file.write_text(
        'public class Foo { boolean m(String token) { return token == "abc123"; } }'
    )

    result = parse_file(java_file)

    findings = detect_in_java(result)
    assert len(findings) == 1
    assert findings[0].identifier == "token"


def test_detect_in_java_finds_nothing_in_clean_file() -> None:
    result = parse_file(FIXTURES_DIR / "CleanService.java")

    assert detect_in_java(result) == ()


def test_detect_in_java_handles_missing_tree_gracefully() -> None:
    malformed = parse_file(FIXTURES_DIR / "MalformedService.java")

    assert malformed.tree is None
    assert detect_in_java(malformed) == ()


def test_detect_in_java_does_not_resolve_non_credential_named_operand(
    tmp_path: Path,
) -> None:
    """Documented limitation: name-driven heuristic, not value-driven.

    input == "admin123" is a real hardcoded-credential comparison bug,
    but "input" isn't a credential-shaped name, so it isn't caught -
    consistent with every other rule module's name-based approach
    (e.g. cwe_798.py also only reasons about identifier names, not
    values, when deciding relevance).
    """
    java_file = tmp_path / "Foo.java"
    java_file.write_text(
        'public class Foo { boolean m(String input) { return input == "admin123"; } }'
    )

    result = parse_file(java_file)

    assert detect_in_java(result) == ()
