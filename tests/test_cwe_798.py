"""Tests for vibeguard.layer1_static.rules.cwe_798."""

from __future__ import annotations

from pathlib import Path

from vibeguard.layer1_static.ast_parser import parse_file
from vibeguard.layer1_static.config_parser import parse_config_file
from vibeguard.layer1_static.rules.cwe_798 import (
    CWE_ID,
    detect_in_config,
    detect_in_java,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_detect_in_java_finds_field_and_local_variable_secrets() -> None:
    result = parse_file(FIXTURES_DIR / "HardcodedSecretService.java")

    findings = detect_in_java(result)
    findings_by_identifier = {f.identifier: f for f in findings}

    assert set(findings_by_identifier) == {"apiKey", "password"}

    api_key_finding = findings_by_identifier["apiKey"]
    assert api_key_finding.cwe_id == CWE_ID
    assert api_key_finding.line == 11

    password_finding = findings_by_identifier["password"]
    assert password_finding.line == 18


def test_detect_in_java_does_not_flag_property_reference_placeholder_or_empty() -> None:
    result = parse_file(FIXTURES_DIR / "HardcodedSecretService.java")

    findings_by_identifier = {f.identifier: f for f in detect_in_java(result)}

    assert "dbPassword" not in findings_by_identifier  # ${DB_PASSWORD} reference
    assert "secretToken" not in findings_by_identifier  # CHANGE_ME placeholder
    assert "authToken" not in findings_by_identifier  # empty string


def test_detect_in_java_does_not_flag_non_credential_field_with_string_literal() -> None:
    result = parse_file(FIXTURES_DIR / "HardcodedSecretService.java")

    findings_by_identifier = {f.identifier: f for f in detect_in_java(result)}

    assert "description" not in findings_by_identifier


def test_detect_in_java_finds_nothing_in_clean_file() -> None:
    result = parse_file(FIXTURES_DIR / "CleanService.java")

    assert detect_in_java(result) == ()


def test_detect_in_java_handles_missing_tree_gracefully() -> None:
    malformed = parse_file(FIXTURES_DIR / "MalformedService.java")

    assert malformed.tree is None
    assert detect_in_java(malformed) == ()


def test_redacted_value_never_contains_the_real_secret() -> None:
    result = parse_file(FIXTURES_DIR / "HardcodedSecretService.java")
    findings_by_identifier = {f.identifier: f for f in detect_in_java(result)}

    api_key_finding = findings_by_identifier["apiKey"]
    assert api_key_finding.redacted_value is not None
    assert "sk-live-abc123def456" not in api_key_finding.redacted_value
    assert api_key_finding.redacted_value.startswith("s")
    assert api_key_finding.redacted_value.endswith("6")
    assert "*" in api_key_finding.redacted_value


def test_detect_in_config_finds_hardcoded_password_in_properties() -> None:
    result = parse_config_file(FIXTURES_DIR / "application.properties")

    findings = detect_in_config(result)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.cwe_id == CWE_ID
    assert finding.identifier == "quarkus.datasource.password"
    assert finding.line == 4
    assert finding.redacted_value is not None
    assert "hunter2" not in finding.redacted_value


def test_detect_in_config_finds_hardcoded_password_in_yaml() -> None:
    result = parse_config_file(FIXTURES_DIR / "application.yml")

    findings = detect_in_config(result)

    assert len(findings) == 1
    assert findings[0].identifier == "quarkus.datasource.password"
    assert findings[0].line == 6


def test_detect_in_config_does_not_flag_property_reference(tmp_path: Path) -> None:
    props_file = tmp_path / "application.properties"
    props_file.write_text("quarkus.datasource.password=${DB_PASSWORD}\n")

    result = parse_config_file(props_file)

    assert detect_in_config(result) == ()


def test_detect_in_config_does_not_flag_empty_or_placeholder_values(tmp_path: Path) -> None:
    props_file = tmp_path / "application.properties"
    props_file.write_text("quarkus.datasource.password=\nquarkus.oidc.client-secret=CHANGE_ME\n")

    result = parse_config_file(props_file)

    assert detect_in_config(result) == ()


def test_detect_in_config_finds_nothing_when_no_credential_keys_present(tmp_path: Path) -> None:
    props_file = tmp_path / "application.properties"
    props_file.write_text("quarkus.http.port=8080\n")

    result = parse_config_file(props_file)

    assert detect_in_config(result) == ()


def test_detect_in_java_does_not_flag_literal_null_string(tmp_path: Path) -> None:
    """The literal string "null" is not a real secret regardless of the field name."""
    java_file = tmp_path / "Foo.java"
    java_file.write_text('public class Foo { String password = "null"; }')

    result = parse_file(java_file)

    assert detect_in_java(result) == ()


def test_detect_in_java_does_not_flag_spel_expression(tmp_path: Path) -> None:
    """SpEL references mean the value is resolved at runtime, not hardcoded.

    Like ${...} property references, #{...} SpEL expressions resolve
    from a bean or system property at runtime rather than being a
    literal secret in source.
    """
    java_file = tmp_path / "Foo.java"
    java_file.write_text(
        "public class Foo { String password = \"#{systemProperties['secret']}\"; }"
    )

    result = parse_file(java_file)

    assert detect_in_java(result) == ()


def test_detect_in_java_finds_concatenated_string_literal_secret() -> None:
    """A split compile-time literal is still a hardcoded credential."""
    result = parse_file(FIXTURES_DIR / "Cwe798AdversarialService.java")

    findings_by_identifier = {f.identifier: f for f in detect_in_java(result)}

    assert set(findings_by_identifier) == {"password"}
    assert findings_by_identifier["password"].line == 10


def test_detect_in_java_does_not_flag_secret_reference_names() -> None:
    """secretName/credentialRef name references, not the secret values."""
    result = parse_file(FIXTURES_DIR / "Cwe798AdversarialService.java")

    identifiers = {f.identifier for f in detect_in_java(result)}

    assert "secretName" not in identifiers
    assert "credentialRef" not in identifiers


def test_detect_in_config_does_not_flag_secret_reference_keys() -> None:
    """Secret resource names/refs are metadata, not embedded credentials."""
    result = parse_config_file(FIXTURES_DIR / "cwe798-reference.properties")

    assert detect_in_config(result) == ()
