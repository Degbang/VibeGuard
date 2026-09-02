"""Tests for vibeguard.layer1_static.ast_parser."""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from vibeguard.layer1_static.ast_parser import ParseStatus, parse_file

FIXTURES_DIR = Path(__file__).parent / "fixtures"
REPO_ROOT = Path(__file__).resolve().parents[1]


def _run_child_python(snippet: str) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    existing_pythonpath = env.get("PYTHONPATH")
    env["PYTHONPATH"] = (
        str(REPO_ROOT)
        if not existing_pythonpath
        else f"{REPO_ROOT}{os.pathsep}{existing_pythonpath}"
    )
    return subprocess.run(
        [sys.executable, "-c", textwrap.dedent(snippet)],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )


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
    assert find_by_name.annotations == ()

    run_method = methods_by_name["run"]
    assert run_method.return_type == "void"
    assert run_method.annotations == ("Override",)


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


def test_parse_utf8_bom_file_succeeds(tmp_path: Path) -> None:
    java_file = tmp_path / "BomService.java"
    java_file.write_bytes(b"\xef\xbb\xbfpublic class BomService {}\n")

    result = parse_file(java_file)

    assert result.status == ParseStatus.OK
    assert result.classes[0].name == "BomService"


def test_parse_java_unicode_escape_in_identifier(tmp_path: Path) -> None:
    java_file = tmp_path / "EscapedIdentifier.java"
    java_file.write_text(r"public class EscapedIdentifier { String pass\u0077ord; }")

    result = parse_file(java_file)

    assert result.status == ParseStatus.OK
    assert result.classes[0].fields[0].name == "password"


def test_parse_file_too_large_is_rejected(tmp_path: Path) -> None:
    big_file = tmp_path / "Big.java"
    big_file.write_text("public class Big {}\n" + ("// padding\n" * 10))

    result = parse_file(big_file, max_bytes=10)

    assert result.status == ParseStatus.FILE_TOO_LARGE
    assert result.error_message is not None


def test_parse_timeout_is_reported_not_raised() -> None:
    completed = _run_child_python("""
        import tempfile
        import time
        from pathlib import Path

        import javalang

        from vibeguard.layer1_static import ast_parser
        from vibeguard.layer1_static.ast_parser import ParseStatus

        original_parse = javalang.parse.parse

        def _slow_parse(source: str) -> object:
            time.sleep(0.3)
            return original_parse(source)

        javalang.parse.parse = _slow_parse

        with tempfile.TemporaryDirectory() as tmpdir:
            slow_file = Path(tmpdir) / "Slow.java"
            slow_file.write_text("public class Slow {}\\n")
            result = ast_parser.parse_file(slow_file, timeout_seconds=0.05)
            assert result.status == ParseStatus.PARSE_TIMEOUT
            assert result.error_message is not None

        print("child-ok")
        """)

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "child-ok" in completed.stdout


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
    """Simple records stay on the lightweight javalang preprocessing path.

    Records are the dominant modern DTO pattern in AI-generated
    Spring/Quarkus code. Empty records remain handled by the existing
    preprocessor; records with bodies fall through to Tree-sitter.
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


def test_parse_record_with_compact_constructor_uses_tree_sitter_fallback(tmp_path: Path) -> None:
    """Records with bodies are valid modern Java and must parse via Tree-sitter."""
    record_file = tmp_path / "Validated.java"
    record_file.write_text(
        "public record Validated(String username, String password) {\n"
        "    public Validated {\n"
        "        username = username.trim();\n"
        "    }\n"
        "    public String normalized() { return username; }\n"
        "}\n"
    )

    result = parse_file(record_file)

    assert result.status == ParseStatus.OK
    assert result.tree is None
    assert result.tree_sitter is not None
    cls = result.classes[0]
    assert cls.name == "Validated"
    assert {f.name for f in cls.fields} == {"username", "password"}
    assert {m.name for m in cls.methods} == {"normalized"}


def test_parse_switch_expression_uses_tree_sitter_fallback(tmp_path: Path) -> None:
    java_file = tmp_path / "Switchy.java"
    java_file.write_text(
        "public class Switchy {\n"
        "    String role(int level) {\n"
        "        return switch (level) {\n"
        '            case 1 -> "admin";\n'
        '            default -> "user";\n'
        "        };\n"
        "    }\n"
        "}\n"
    )

    result = parse_file(java_file)

    assert result.status == ParseStatus.OK
    assert result.tree is None
    assert result.tree_sitter is not None
    assert result.classes[0].name == "Switchy"


def test_tree_sitter_fallback_preserves_extends_and_implements_summary(tmp_path: Path) -> None:
    java_file = tmp_path / "Modern.java"
    java_file.write_text(
        "interface I {}\n"
        "interface J {}\n"
        "class Base {}\n"
        "public class Modern extends Base implements I, J {\n"
        "    String role(int level) {\n"
        "        return switch (level) {\n"
        '            case 1 -> "admin";\n'
        '            default -> "user";\n'
        "        };\n"
        "    }\n"
        "}\n"
    )

    result = parse_file(java_file)

    assert result.status == ParseStatus.OK
    assert result.tree_sitter is not None
    modern = next(cls for cls in result.classes if cls.name == "Modern")
    assert modern.superclass == "Base"
    assert modern.interfaces == ("I", "J")


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
