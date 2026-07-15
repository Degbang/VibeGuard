"""Tests for vibeguard.layer1_static.rules.cwe_20."""

from __future__ import annotations

from pathlib import Path

from vibeguard.layer1_static.ast_parser import parse_file
from vibeguard.layer1_static.rules.cwe_20 import CWE_ID, detect_in_java

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_detect_in_java_finds_unvalidated_request_body() -> None:
    result = parse_file(FIXTURES_DIR / "UnvalidatedRequestBody.java")

    findings = detect_in_java(result)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.cwe_id == CWE_ID
    assert finding.identifier == "dto"
    assert finding.line == 13


def test_detect_in_java_does_not_flag_valid_annotated_body() -> None:
    result = parse_file(FIXTURES_DIR / "UnvalidatedRequestBody.java")

    identifiers_by_line = {f.line: f.identifier for f in detect_in_java(result)}

    assert 18 not in identifiers_by_line


def test_detect_in_java_does_not_flag_string_body() -> None:
    """A String body has no bean fields for @Valid to cascade into."""
    result = parse_file(FIXTURES_DIR / "UnvalidatedRequestBody.java")

    lines = {f.line for f in detect_in_java(result)}

    assert 23 not in lines


def test_detect_in_java_does_not_flag_non_request_body_parameter() -> None:
    result = parse_file(FIXTURES_DIR / "UnvalidatedRequestBody.java")

    identifiers = {f.identifier for f in detect_in_java(result)}

    assert "id" not in identifiers


def test_detect_in_java_does_not_flag_non_endpoint_method() -> None:
    result = parse_file(FIXTURES_DIR / "UnvalidatedRequestBody.java")

    findings = detect_in_java(result)

    assert len(findings) == 1  # only the one true positive, helper() ignored


def test_detect_in_java_recognizes_validated_annotation(tmp_path: Path) -> None:
    """@Validated is an accepted alternative to @Valid."""
    java_file = tmp_path / "Foo.java"
    java_file.write_text(
        "@RestController\n"
        "public class Foo {\n"
        '    @PostMapping("/x")\n'
        "    public void m(@Validated @RequestBody Dto dto) {}\n"
        "}\n"
    )

    result = parse_file(java_file)

    assert detect_in_java(result) == ()


def test_detect_in_java_recognizes_fully_qualified_annotations(tmp_path: Path) -> None:
    java_file = tmp_path / "Foo.java"
    java_file.write_text(
        "@RestController\n"
        "public class Foo {\n"
        '    @PostMapping("/x")\n'
        "    public void m(@javax.validation.Valid "
        "@org.springframework.web.bind.annotation.RequestBody Dto dto) {}\n"
        "}\n"
    )

    result = parse_file(java_file)

    assert detect_in_java(result) == ()


def test_detect_in_java_finds_endpoint_inside_nested_class(tmp_path: Path) -> None:
    """Same nested-class coverage cwe_284.py needed - walked the raw tree from the start."""
    java_file = tmp_path / "Outer.java"
    java_file.write_text(
        "public class Outer {\n"
        "    public static class Inner {\n"
        '        @PostMapping("/x")\n'
        "        public void m(@RequestBody Dto dto) {}\n"
        "    }\n"
        "}\n"
    )

    result = parse_file(java_file)

    findings = detect_in_java(result)
    assert len(findings) == 1
    assert findings[0].identifier == "dto"


def test_detect_in_java_judges_multiple_parameters_independently(tmp_path: Path) -> None:
    java_file = tmp_path / "Foo.java"
    java_file.write_text(
        "@RestController\n"
        "public class Foo {\n"
        '    @PostMapping("/x")\n'
        "    public void m(@Valid @RequestBody GoodDto good, @RequestBody BadDto bad) {}\n"
        "}\n"
    )

    result = parse_file(java_file)

    findings = detect_in_java(result)
    assert len(findings) == 1
    assert findings[0].identifier == "bad"


def test_detect_in_java_finds_nothing_in_clean_file() -> None:
    result = parse_file(FIXTURES_DIR / "CleanService.java")

    assert detect_in_java(result) == ()


def test_detect_in_java_handles_missing_tree_gracefully() -> None:
    malformed = parse_file(FIXTURES_DIR / "MalformedService.java")

    assert malformed.tree is None
    assert detect_in_java(malformed) == ()
