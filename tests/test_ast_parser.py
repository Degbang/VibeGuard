"""Tests for vibeguard.layer1_static.ast_parser."""

from __future__ import annotations

import time
from pathlib import Path

import javalang
import pytest

from vibeguard.layer1_static import ast_parser
from vibeguard.layer1_static.ast_parser import ParseStatus, parse_file

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_parse_clean_file_succeeds() -> None:
    result = parse_file(FIXTURES_DIR / "CleanService.java")

    assert result.status == ParseStatus.OK
    assert result.error_message is None
    assert result.tree is not None
    assert result.package == "com.example.vibeguard.fixtures"
    assert "java.util.List" in result.imports
    assert "java.util.Optional" in result.imports

    assert len(result.classes) == 1
    cls = result.classes[0]
    assert cls.name == "CleanService"
    assert cls.superclass == "AbstractService"
    assert cls.interfaces == ("Runnable", "AutoCloseable")
    assert "public" in cls.modifiers


def test_parse_clean_file_flattens_multi_declarator_field() -> None:
    result = parse_file(FIXTURES_DIR / "CleanService.java")
    cls = result.classes[0]

    field_names = {f.name for f in cls.fields}
    assert field_names == {"name", "retryCount", "maxRetries"}

    retry_field = next(f for f in cls.fields if f.name == "retryCount")
    assert retry_field.type_name == "int"


def test_parse_clean_file_methods() -> None:
    result = parse_file(FIXTURES_DIR / "CleanService.java")
    cls = result.classes[0]

    methods_by_name = {m.name: m for m in cls.methods}
    assert set(methods_by_name) == {"run", "close", "findByName"}

    find_by_name = methods_by_name["findByName"]
    assert find_by_name.return_type == "Optional"
    assert [p.name for p in find_by_name.parameters] == ["query", "candidates"]
    assert [p.type_name for p in find_by_name.parameters] == ["String", "List"]

    run_method = methods_by_name["run"]
    assert run_method.return_type == "void"


def test_parse_malformed_file_reports_failure_not_exception() -> None:
    result = parse_file(FIXTURES_DIR / "MalformedService.java")

    assert result.status == ParseStatus.PARSE_FAILED
    assert result.error_message  # must be non-empty, not just non-None
    assert result.tree is None
    assert result.classes == ()


def test_parse_empty_file() -> None:
    result = parse_file(FIXTURES_DIR / "EmptyFile.java")

    assert result.status == ParseStatus.EMPTY_FILE
    assert result.classes == ()


def test_parse_missing_file_does_not_raise(tmp_path: Path) -> None:
    missing = tmp_path / "DoesNotExist.java"

    result = parse_file(missing)

    assert result.status == ParseStatus.PARSE_FAILED
    assert result.error_message is not None


def test_parse_file_too_large_is_rejected(tmp_path: Path) -> None:
    big_file = tmp_path / "Big.java"
    big_file.write_text("public class Big {}\n" + ("// padding\n" * 10))

    result = parse_file(big_file, max_bytes=10)

    assert result.status == ParseStatus.FILE_TOO_LARGE
    assert result.error_message is not None


def test_parse_timeout_is_reported_not_raised(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _slow_parse(source: str) -> object:
        time.sleep(0.3)
        return javalang.parse.parse(source)

    monkeypatch.setattr(javalang.parse, "parse", _slow_parse)

    slow_file = tmp_path / "Slow.java"
    slow_file.write_text("public class Slow {}\n")

    result = ast_parser.parse_file(slow_file, timeout_seconds=0.05)

    assert result.status == ParseStatus.PARSE_TIMEOUT
    assert result.error_message is not None


def test_parsed_file_is_frozen_and_hashable_when_no_tree() -> None:
    result = parse_file(FIXTURES_DIR / "EmptyFile.java")

    with pytest.raises(AttributeError):
        result.status = ParseStatus.OK  # type: ignore[misc]

    assert isinstance(hash(result), int)


def test_interface_extends_are_captured(tmp_path: Path) -> None:
    iface_file = tmp_path / "Foo.java"
    iface_file.write_text("public interface Foo extends Bar, Baz {\n    void doThing();\n}\n")

    result = parse_file(iface_file)

    assert result.status == ParseStatus.OK
    assert len(result.classes) == 1
    iface = result.classes[0]
    assert iface.interfaces == ("Bar", "Baz")
    assert iface.superclass is None


def test_parse_simple_java_record(tmp_path: Path) -> None:
    """javalang can't parse records natively; ast_parser desugars them first.

    Records are the dominant modern DTO pattern in AI-generated
    Spring/Quarkus code, so this is the highest-value part of the
    Java 14-21 syntax gap to close (see IMPLEMENTATION_LOG.md for the
    full compatibility assessment and why the rest - sealed classes,
    pattern matching, text blocks - remains unsupported).
    """
    record_file = tmp_path / "Credentials.java"
    record_file.write_text("public record Credentials(String username, String password) {}\n")

    result = parse_file(record_file)

    assert result.status == ParseStatus.OK
    cls = result.classes[0]
    assert cls.name == "Credentials"
    field_names = {f.name for f in cls.fields}
    assert field_names == {"username", "password"}
    password_field = next(f for f in cls.fields if f.name == "password")
    assert password_field.type_name == "String"


def test_parse_record_with_compact_constructor_still_fails(tmp_path: Path) -> None:
    """The record shim is intentionally narrow - a non-empty body doesn't parse."""
    record_file = tmp_path / "Validated.java"
    record_file.write_text(
        "public record Validated(String value) {\n"
        "    public Validated {\n"
        "        value = value.trim();\n"
        "    }\n"
        "}\n"
    )

    result = parse_file(record_file)

    assert result.status == ParseStatus.PARSE_FAILED


def test_multiline_record_field_reports_its_own_source_line(tmp_path: Path) -> None:
    record_file = tmp_path / "Credentials.java"
    record_file.write_text(
        "public record Credentials(\n" "    String username,\n" "    String password\n" ") {}\n"
    )

    result = parse_file(record_file)

    assert result.status == ParseStatus.OK
    lines_by_field = {f.name: f.line for f in result.classes[0].fields}
    assert lines_by_field == {"username": 2, "password": 3}


def test_fully_qualified_type_name_reconstructs_the_full_dotted_name(
    tmp_path: Path,
) -> None:
    """java.util.List<...> must summarize to "java.util.List", not "java".

    javalang represents a fully-qualified type as a chain of
    ReferenceType nodes linked by sub_type, one per dotted segment
    ("java" -> "util" -> "List"). Reading .name off only the outer
    node returns the package prefix, losing the actual type entirely.
    Taking only the innermost segment ("List") is also wrong: it
    silently discards the qualification, making java.sql.Date and
    java.util.Date indistinguishable. The full name must be
    reconstructed by joining every segment.
    """
    java_file = tmp_path / "Foo.java"
    java_file.write_text(
        "public class Foo {\n"
        "    java.util.List<java.util.Map<String, Integer>> values;\n"
        "    java.util.List<String>[] items;\n"
        "    java.sql.Date sqlDate;\n"
        "    java.util.Date utilDate;\n"
        "}\n"
    )

    result = parse_file(java_file)

    assert result.status == ParseStatus.OK
    types_by_field = {f.name: f.type_name for f in result.classes[0].fields}
    assert types_by_field == {
        "values": "java.util.List",
        "items": "java.util.List[]",
        "sqlDate": "java.sql.Date",
        "utilDate": "java.util.Date",
    }
