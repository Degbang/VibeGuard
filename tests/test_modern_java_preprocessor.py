"""Tests for vibeguard.layer1_static._modern_java_preprocessor."""

from __future__ import annotations

from pathlib import Path

import javalang

from vibeguard.layer1_static._modern_java_preprocessor import (
    desugar_simple_records,
    desugar_text_blocks,
    preprocess,
    strip_pattern_matching_bindings,
    strip_sealed_modifiers,
)


def test_simple_record_becomes_parseable_class_with_fields() -> None:
    rewritten = desugar_simple_records("public record UserDto(String name, int age) {}")
    tree = javalang.parse.parse(rewritten)

    cls = tree.types[0]
    assert cls.name == "UserDto"
    field_names = [d.name for f in cls.body for d in f.declarators]
    assert field_names == ["name", "age"]


def test_record_with_generics_and_implements_is_parseable() -> None:
    rewritten = desugar_simple_records(
        "public record Point(int x, int y) implements Comparable<Point> {}"
    )
    tree = javalang.parse.parse(rewritten)

    cls = tree.types[0]
    assert cls.name == "Point"
    assert [i.name for i in cls.implements] == ["Comparable"]


def test_record_with_varargs_is_parseable() -> None:
    rewritten = desugar_simple_records("public record Args(String... values) {}")
    tree = javalang.parse.parse(rewritten)

    field = tree.types[0].body[0]
    assert field.type.name == "String"
    assert field.type.dimensions  # rewritten to an array type


def test_record_with_non_empty_body_is_left_untouched() -> None:
    """A record with a compact constructor is out of scope for this shim.

    Must not be silently mistranslated - left as-is, so it fails to
    parse exactly the same way it did before the preprocessor existed.
    """
    source = "public record Foo(String a) { public Foo { a = a.trim(); } }"
    assert desugar_simple_records(source) == source


def test_preserves_total_newline_count_for_multiline_record() -> None:
    """Content after a rewritten record must keep its original line number.

    File/line traceability is Layer 1's core value; a transform that
    shifted line numbers for everything following a record would be
    worse than not transforming at all.
    """
    source = (
        "public record UserDto(\n"
        "    String name,\n"
        "    int age\n"
        ") {}\n"
        "\n"
        "public class Next {\n"
        "    void marker() {}\n"
        "}\n"
    )
    rewritten = desugar_simple_records(source)

    assert rewritten.count("\n") == source.count("\n")

    tree = javalang.parse.parse(rewritten)
    next_class = next(t for t in tree.types if t.name == "Next")
    assert next_class.position.line == 6


def test_multiline_record_fields_report_their_own_original_line() -> None:
    """Each field must report its real source line, not the record's.

    Compressing every field onto the record's opening line would make
    a CWE finding on e.g. a `password` field point at the wrong line
    in any multiline record - a real traceability regression, not
    just a cosmetic one.
    """
    source = "public record UserDto(\n    String name,\n    int age\n) {}\n"
    rewritten = desugar_simple_records(source)

    tree = javalang.parse.parse(rewritten)
    fields_by_name = {
        d.name: field.position.line for field in tree.types[0].body for d in field.declarators
    }

    assert fields_by_name == {"name": 2, "age": 3}


def test_sealed_class_modifier_and_permits_clause_are_stripped() -> None:
    """javalang has no grammar for ``sealed``/``permits`` - both must go."""
    source = "public sealed class Shape permits Circle, Square {\n    int x;\n}\n"
    rewritten = strip_sealed_modifiers(source)
    tree = javalang.parse.parse(rewritten)

    assert tree.types[0].name == "Shape"


def test_non_sealed_modifier_is_stripped() -> None:
    rewritten = strip_sealed_modifiers("public non-sealed class Circle extends Shape {}")
    tree = javalang.parse.parse(rewritten)

    assert tree.types[0].name == "Circle"


def test_sealed_interface_is_stripped() -> None:
    rewritten = strip_sealed_modifiers(
        "public sealed interface Vehicle permits Car, Truck {}\n"
        "interface Car extends Vehicle {}\n"
        "interface Truck extends Vehicle {}\n"
    )
    tree = javalang.parse.parse(rewritten)

    assert tree.types[0].name == "Vehicle"


def test_sealed_stripping_preserves_line_number_across_multiline_permits() -> None:
    """A multi-line ``permits`` clause must not shift later line numbers.

    A real ``permits`` list can be long enough to wrap; deleting it
    outright (instead of blanking it to matching newlines) would make
    a CWE finding on ``password`` below report the wrong line - a real
    traceability regression, not a cosmetic one.
    """
    source = (
        "public sealed class Shape\n"
        "    permits Circle, Square {\n"
        '    private String password = "hunter2";\n'
        "}\n"
    )
    rewritten = strip_sealed_modifiers(source)

    assert rewritten.count("\n") == source.count("\n")

    tree = javalang.parse.parse(rewritten)
    field = tree.types[0].body[0]
    assert field.position.line == 3


def test_sealed_words_inside_string_literals_are_not_stripped() -> None:
    source = 'class A { String password = "sealed non-sealed secret permits X {"; }\n'
    rewritten = preprocess(source)
    tree = javalang.parse.parse(rewritten)

    field = tree.types[0].body[0]
    value = field.declarators[0].initializer.value
    assert value == '"sealed non-sealed secret permits X {"'


def test_sealed_words_inside_comments_are_not_rewritten() -> None:
    source = "// public sealed class Fake permits X {\nclass A { int marker = 1; }\n"
    rewritten = preprocess(source)

    assert rewritten.startswith("// public sealed class Fake permits X {")
    tree = javalang.parse.parse(rewritten)
    assert tree.types[0].name == "A"


def test_pattern_matching_instanceof_binding_is_stripped() -> None:
    """``o instanceof String s`` has no javalang grammar for the ``s`` binding."""
    source = (
        "public class Checker {\n"
        "    boolean check(Object o) {\n"
        "        return o instanceof String s && s.length() > 0;\n"
        "    }\n"
        "}\n"
    )
    rewritten = strip_pattern_matching_bindings(source)
    tree = javalang.parse.parse(rewritten)

    assert tree.types[0].name == "Checker"


def test_pattern_matching_instanceof_with_generics_is_stripped() -> None:
    source = "boolean check(Object o) { return o instanceof java.util.List<String> items; }"
    rewritten = strip_pattern_matching_bindings(source)

    assert "items" not in rewritten
    assert "instanceof java.util.List<String>" in rewritten


def test_pattern_matching_instanceof_preserves_line_number_across_linebreak() -> None:
    """A binding split across a line break must still preserve later line numbers."""
    source = (
        "public class Checker {\n"
        "    boolean check(Object o) {\n"
        "        if (o instanceof String\n"
        "                s) {\n"
        '            String secret = "hunter2";\n'
        "        }\n"
        "        return false;\n"
        "    }\n"
        "}\n"
    )
    rewritten = strip_pattern_matching_bindings(source)

    assert rewritten.count("\n") == source.count("\n")

    tree = javalang.parse.parse(rewritten)
    method = tree.types[0].body[0]
    local_var = method.body[0].then_statement.statements[0]
    assert local_var.position.line == 5


def test_pattern_instanceof_text_inside_string_literals_is_not_stripped() -> None:
    source = 'class A { String text = "o instanceof String value"; }\n'
    rewritten = preprocess(source)
    tree = javalang.parse.parse(rewritten)

    field = tree.types[0].body[0]
    value = field.declarators[0].initializer.value
    assert value == '"o instanceof String value"'


def test_text_block_is_rewritten_to_equivalent_string_literal() -> None:
    """JEP 378's canonical example: common leading indentation is stripped."""
    source = (
        "public class Html {\n"
        '    String page = """\n'
        "                  <html>\n"
        "                      <body>\n"
        "                      </body>\n"
        "                  </html>\n"
        '                  """;\n'
        "}\n"
    )
    rewritten = desugar_text_blocks(source)
    tree = javalang.parse.parse(rewritten)

    field = tree.types[0].body[0]
    value = field.declarators[0].initializer.value
    assert value == '"<html>\\n    <body>\\n    </body>\\n</html>\\n"'


def test_text_block_preserves_total_newline_count() -> None:
    source = (
        "public class Html {\n"
        '    String page = """\n'
        "        hello\n"
        '        """;\n'
        "\n"
        "    int marker = 1;\n"
        "}\n"
    )
    rewritten = desugar_text_blocks(source)

    assert rewritten.count("\n") == source.count("\n")

    tree = javalang.parse.parse(rewritten)
    marker_field = tree.types[0].body[1]
    assert marker_field.position.line == 6


def test_text_block_does_not_double_escape_existing_escape_sequences() -> None:
    """A pre-existing ``\\"`` or ``\\n`` in the source must not be re-escaped.

    Naively replacing every raw ``"`` with ``\\"`` would turn an
    already-escaped ``\\"`` into ``\\\\"`` - a literal backslash
    followed by an escaped quote, corrupting the string's real value.
    """
    source = 'String s = """\n    already \\"escaped\\" and a \\n literal\n    """;\n'
    rewritten = desugar_text_blocks(source)
    tree = javalang.parse.parse(f"class C {{ {rewritten} }}")

    field = tree.types[0].body[0]
    value = field.declarators[0].initializer.value
    # The closing delimiter sits on its own line, so JEP 378 counts that
    # as a trailing blank content line - real javac gives this value a
    # trailing "\n" too, not just this preprocessor.
    assert value == '"already \\"escaped\\" and a \\n literal\\n"'


def test_text_block_backslash_s_escape_becomes_literal_trailing_space() -> None:
    """``\\s`` marks a trailing space that JEP 378's rstrip would otherwise eat.

    Without interpreting this text-block-only escape, javalang rejected
    the rewritten literal outright ("Illegal escape character") since
    ``\\s`` has no meaning in an ordinary Java string - a real parse
    failure on valid Java 15+ source, not just an inexact value.
    """
    source = 'String s = """\n    abc\\s\n    def\n    """;\n'
    rewritten = desugar_text_blocks(source)
    tree = javalang.parse.parse(f"class C {{ {rewritten} }}")

    field = tree.types[0].body[0]
    value = field.declarators[0].initializer.value
    assert value == '"abc \\ndef\\n"'


def test_text_block_line_continuation_suppresses_the_line_break() -> None:
    """A backslash immediately before a newline joins the two lines with no break."""
    source = 'String s = """\n    abc\\\n    def\n    """;\n'
    rewritten = desugar_text_blocks(source)
    tree = javalang.parse.parse(f"class C {{ {rewritten} }}")

    field = tree.types[0].body[0]
    value = field.declarators[0].initializer.value
    assert value == '"abcdef\\n"'


def test_text_block_line_continuation_preserves_total_newline_count() -> None:
    """Consuming a value-internal newline must not shift real source line numbers.

    The newline removed by line-continuation lives inside the text
    block's *value* (produced by joining stripped lines), not in the
    surrounding file text - a subsequent declaration must still report
    its real source line.
    """
    source = (
        "public class Html {\n"
        '    String page = """\n'
        "        abc\\\n"
        "        def\n"
        '        """;\n'
        "\n"
        "    int marker = 1;\n"
        "}\n"
    )
    rewritten = desugar_text_blocks(source)

    assert rewritten.count("\n") == source.count("\n")

    tree = javalang.parse.parse(rewritten)
    marker_field = tree.types[0].body[1]
    assert marker_field.position.line == 7


def test_text_block_content_is_not_rewritten_by_later_code_transforms() -> None:
    source = (
        "public class Text {\n"
        '    String password = """\n'
        "        sealed class Fake permits X {\n"
        "        o instanceof String value\n"
        '        """;\n'
        "}\n"
    )
    rewritten = preprocess(source)
    tree = javalang.parse.parse(rewritten)

    field = tree.types[0].body[0]
    value = field.declarators[0].initializer.value
    assert "sealed class Fake permits X" in value
    assert "o instanceof String value" in value


def test_text_block_with_embedded_secret_is_detected_by_cwe_798(tmp_path: Path) -> None:
    """End-to-end proof: a secret inside a text block is still findable.

    Parsing without corrupting the string's value is necessary but not
    sufficient - this locks in that the full pipeline (parse_file, which
    already calls preprocess -> javalang -> cwe_798) produces a correct
    finding, not just a parse.
    """
    from vibeguard.layer1_static import ast_parser
    from vibeguard.layer1_static.rules import cwe_798

    source = (
        "public class Config {\n"
        '    String password = """\n'
        "        hunter2\n"
        '        """;\n'
        "}\n"
    )
    java_file = tmp_path / "Config.java"
    java_file.write_text(source)

    parsed = ast_parser.parse_file(java_file)
    assert parsed.status == ast_parser.ParseStatus.OK

    findings = cwe_798.detect_in_java(parsed)
    assert any("password" in f.identifier.lower() for f in findings)


def test_preprocess_pipeline_handles_all_modern_constructs_together() -> None:
    """The full pipeline must compose: records, sealed types, pattern matching, text blocks."""
    source = (
        "public sealed class Shape permits Circle {\n"
        "    record Point(int x, int y) {}\n"
        "    boolean isOrigin(Object o) {\n"
        "        return o instanceof Point p && p.x() == 0;\n"
        "    }\n"
        '    String label = """\n'
        "        origin\n"
        '        """;\n'
        "}\n"
    )
    rewritten = preprocess(source)
    tree = javalang.parse.parse(rewritten)

    assert tree.types[0].name == "Shape"
