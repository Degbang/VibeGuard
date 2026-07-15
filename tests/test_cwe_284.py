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
