"""Tests for vibeguard.layer1_static._record_preprocessor."""

from __future__ import annotations

import javalang

from vibeguard.layer1_static._record_preprocessor import desugar_simple_records


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
