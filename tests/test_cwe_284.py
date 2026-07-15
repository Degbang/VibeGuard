"""Tests for vibeguard.layer1_static.rules.cwe_284."""

from __future__ import annotations

from pathlib import Path

from vibeguard.layer1_static.ast_parser import parse_file
from vibeguard.layer1_static.rules.cwe_284 import CWE_ID, detect_in_java

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_detect_in_java_finds_endpoint_with_no_authorization_annotation() -> None:
    result = parse_file(FIXTURES_DIR / "UnprotectedResource.java")

    findings = detect_in_java(result)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.cwe_id == CWE_ID
    assert finding.identifier == "deleteAccount"
    assert finding.line == 13


def test_detect_in_java_does_not_flag_method_level_roles_allowed() -> None:
    result = parse_file(FIXTURES_DIR / "UnprotectedResource.java")

    identifiers = {f.identifier for f in detect_in_java(result)}

    assert "createUser" not in identifiers


def test_detect_in_java_does_not_flag_explicit_permit_all() -> None:
    """@PermitAll is a deliberate access-control decision, not a missing one."""
    result = parse_file(FIXTURES_DIR / "UnprotectedResource.java")

    identifiers = {f.identifier for f in detect_in_java(result)}

    assert "health" not in identifiers


def test_detect_in_java_does_not_flag_non_endpoint_methods() -> None:
    result = parse_file(FIXTURES_DIR / "UnprotectedResource.java")

    identifiers = {f.identifier for f in detect_in_java(result)}

    assert "internalHelper" not in identifiers


def test_detect_in_java_class_level_authorization_covers_unannotated_methods() -> None:
    """A class-level @RolesAllowed covers methods with no annotation of their own.

    The common "secure by default" pattern. Must not be flagged even
    though neither method has its own authorization annotation.
    """
    result = parse_file(FIXTURES_DIR / "ClassLevelSecuredResource.java")

    assert detect_in_java(result) == ()


def test_detect_in_java_finds_nothing_in_file_with_no_endpoints() -> None:
    result = parse_file(FIXTURES_DIR / "CleanService.java")

    assert detect_in_java(result) == ()


def test_detect_in_java_handles_missing_tree_gracefully() -> None:
    malformed = parse_file(FIXTURES_DIR / "MalformedService.java")

    assert malformed.tree is None
    assert detect_in_java(malformed) == ()


def test_detect_in_java_recognizes_fully_qualified_endpoint_annotation(
    tmp_path: Path,
) -> None:
    """@javax.ws.rs.GET must be recognized the same as @GET.

    javalang gives an annotation's name exactly as written - fully
    qualified if the source used the fully-qualified form rather than
    a simple-name import. Matching only the exact string "GET" would
    silently miss this endpoint entirely (a false negative, the
    dangerous direction for a security tool).
    """
    java_file = tmp_path / "Foo.java"
    java_file.write_text("public class Foo {\n    @javax.ws.rs.GET\n    public void x() {}\n}\n")

    result = parse_file(java_file)

    findings = detect_in_java(result)
    assert len(findings) == 1
    assert findings[0].identifier == "x"


def test_detect_in_java_recognizes_fully_qualified_authorization_annotation(
    tmp_path: Path,
) -> None:
    """A fully-qualified @RolesAllowed must not be treated as absent.

    Same root cause as the endpoint-side case above, opposite failure
    mode: matching only the exact string "RolesAllowed" would flag a
    genuinely protected endpoint as unprotected (a false positive that
    actively misleads a report's reader).
    """
    java_file = tmp_path / "Foo.java"
    java_file.write_text(
        "public class Foo {\n"
        '    @javax.annotation.security.RolesAllowed("ADMIN")\n'
        "    @GET\n"
        "    public void x() {}\n"
        "}\n"
    )

    result = parse_file(java_file)

    assert detect_in_java(result) == ()


def test_detect_in_java_finds_unprotected_endpoint_inside_nested_class() -> None:
    """A method inside a nested/inner class must not be invisible to this rule.

    ParsedFile.classes (the flattened Layer 1 summary) only represents
    top-level types - a rule that only iterated that summary would
    silently miss every endpoint inside a nested static resource
    class, a real pattern in JAX-RS/Spring codebases. This rule walks
    the raw AST specifically to avoid that blind spot.
    """
    result = parse_file(FIXTURES_DIR / "NestedResource.java")

    findings = detect_in_java(result)

    assert len(findings) == 1
    assert findings[0].identifier == "deleteAll"
    assert findings[0].line == 15


def test_detect_in_java_nested_class_method_level_protection_still_works() -> None:
    result = parse_file(FIXTURES_DIR / "NestedResource.java")

    identifiers = {f.identifier for f in detect_in_java(result)}

    assert "create" not in identifiers


def test_detect_in_java_outer_class_authorization_does_not_protect_inner_class(
    tmp_path: Path,
) -> None:
    """An outer class's @RolesAllowed must not protect an inner class's methods.

    JAX-RS/Spring resolve authorization per resource class, not by
    lexical nesting, so treating the outer class as sufficient would
    be a false negative.
    """
    java_file = tmp_path / "Foo.java"
    java_file.write_text(
        '@RolesAllowed("ADMIN")\n'
        "public class Outer {\n"
        "    public static class Inner {\n"
        "        @DELETE\n"
        "        public void x() {}\n"
        "    }\n"
        "}\n"
    )

    result = parse_file(java_file)

    findings = detect_in_java(result)
    assert len(findings) == 1
    assert findings[0].identifier == "x"
