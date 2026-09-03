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


def test_detect_in_config_finds_properties_unicode_escaped_credential_key(
    tmp_path: Path,
) -> None:
    props_file = tmp_path / "application.properties"
    props_file.write_text("quarkus.datasource.pass\\u0077ord=hunter2\n")

    result = parse_config_file(props_file)
    findings = detect_in_config(result)

    assert len(findings) == 1
    assert findings[0].identifier == "quarkus.datasource.password"


def test_detect_in_config_finds_properties_whitespace_separator(tmp_path: Path) -> None:
    props_file = tmp_path / "application.properties"
    props_file.write_text("quarkus.datasource.password hunter2\n")

    result = parse_config_file(props_file)
    findings = detect_in_config(result)

    assert len(findings) == 1
    assert findings[0].identifier == "quarkus.datasource.password"


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


def test_detect_in_java_finds_secret_assigned_after_declaration(tmp_path: Path) -> None:
    java_file = tmp_path / "AssignedSecret.java"
    java_file.write_text(
        "public class AssignedSecret {\n"
        "    void configure() {\n"
        "        String password;\n"
        '        password = "hunter2";\n'
        "    }\n"
        "}\n"
    )

    result = parse_file(java_file)

    findings = detect_in_java(result)
    assert [(finding.identifier, finding.line) for finding in findings] == [("password", 4)]


def test_detect_in_java_finds_secret_assigned_to_field(tmp_path: Path) -> None:
    java_file = tmp_path / "AssignedFieldSecret.java"
    java_file.write_text(
        "public class AssignedFieldSecret {\n"
        "    private String token;\n"
        "    void configure() {\n"
        '        this.token = "abc123";\n'
        "    }\n"
        "}\n"
    )

    result = parse_file(java_file)

    findings = detect_in_java(result)
    assert [(finding.identifier, finding.line) for finding in findings] == [("token", 4)]


def test_detect_in_java_finds_secret_assigned_from_ternary(tmp_path: Path) -> None:
    java_file = tmp_path / "TernarySecret.java"
    java_file.write_text(
        "public class TernarySecret {\n"
        "    void configure(boolean prod) {\n"
        "        String password;\n"
        '        password = prod ? "real-prod-secret" : "dev-secret";\n'
        "    }\n"
        "}\n"
    )

    result = parse_file(java_file)

    findings = detect_in_java(result)
    assert [(finding.identifier, finding.line) for finding in findings] == [("password", 4)]


def test_detect_in_java_finds_secret_in_string_array_initializer(tmp_path: Path) -> None:
    java_file = tmp_path / "ArraySecret.java"
    java_file.write_text('public class ArraySecret { String[] passwords = {"hunter2", "backup"}; }')

    result = parse_file(java_file)

    findings = detect_in_java(result)
    assert [(finding.identifier, finding.line) for finding in findings] == [("passwords", 1)]
    assert findings[0].redacted_value == "h*****2"


def test_detect_in_java_finds_secret_in_char_array_initializer(tmp_path: Path) -> None:
    java_file = tmp_path / "CharArraySecret.java"
    java_file.write_text(
        "public class CharArraySecret { char[] password = {'h','u','n','t','e','r','2'}; }"
    )

    result = parse_file(java_file)

    findings = detect_in_java(result)
    assert [(finding.identifier, finding.line) for finding in findings] == [("password", 1)]
    assert findings[0].redacted_value == "h*****2"


def test_detect_in_java_finds_secret_with_unicode_escaped_identifier(
    tmp_path: Path,
) -> None:
    java_file = tmp_path / "EscapedIdentifierSecret.java"
    java_file.write_text(
        r'public class EscapedIdentifierSecret { String pass\u0077ord = "hunter2"; }'
    )

    result = parse_file(java_file)

    findings = detect_in_java(result)
    assert [(finding.identifier, finding.line) for finding in findings] == [("password", 1)]


def test_detect_in_java_finds_secret_passed_to_setter(tmp_path: Path) -> None:
    java_file = tmp_path / "SetterSecret.java"
    java_file.write_text(
        "public class SetterSecret {\n"
        "    void configure(Config config) {\n"
        '        config.setPassword("hunter2");\n'
        "    }\n"
        "}\n"
    )

    result = parse_file(java_file)

    findings = detect_in_java(result)
    assert [(finding.identifier, finding.line) for finding in findings] == [("setPassword", 3)]


def test_detect_in_java_finds_secret_passed_to_builder_method(tmp_path: Path) -> None:
    java_file = tmp_path / "BuilderSecret.java"
    java_file.write_text(
        "public class BuilderSecret {\n"
        "    void configure() {\n"
        '        User.builder().apiKey("sk-live-abc123").build();\n'
        "    }\n"
        "}\n"
    )

    result = parse_file(java_file)

    findings = detect_in_java(result)
    assert [(finding.identifier, finding.line) for finding in findings] == [("apiKey", 3)]


def test_detect_in_java_finds_secret_passed_to_map_put(tmp_path: Path) -> None:
    java_file = tmp_path / "MapPutSecret.java"
    java_file.write_text(
        "import java.util.Map;\n"
        "public class MapPutSecret {\n"
        "    void configure(Map<String, String> values) {\n"
        '        values.put("password", "hunter2");\n'
        "    }\n"
        "}\n"
    )

    result = parse_file(java_file)

    findings = detect_in_java(result)
    assert [(finding.identifier, finding.line) for finding in findings] == [("password", 4)]


def test_detect_in_java_finds_secret_passed_to_system_set_property(tmp_path: Path) -> None:
    java_file = tmp_path / "SystemPropertySecret.java"
    java_file.write_text(
        "public class SystemPropertySecret {\n"
        "    void configure() {\n"
        '        System.setProperty("db.password", "hunter2");\n'
        "    }\n"
        "}\n"
    )

    result = parse_file(java_file)

    findings = detect_in_java(result)
    assert [(finding.identifier, finding.line) for finding in findings] == [("db.password", 3)]


def test_detect_in_java_finds_spring_value_default_secret(tmp_path: Path) -> None:
    java_file = tmp_path / "SpringValueSecret.java"
    java_file.write_text(
        "public class SpringValueSecret {\n"
        '    @org.springframework.beans.factory.annotation.Value("${db.password:hunter2}")\n'
        "    String password;\n"
        "}\n"
    )

    result = parse_file(java_file)

    findings = detect_in_java(result)
    assert [(finding.identifier, finding.line) for finding in findings] == [("db.password", 2)]


def test_detect_in_java_does_not_flag_spring_value_without_default(tmp_path: Path) -> None:
    java_file = tmp_path / "SpringValueReference.java"
    java_file.write_text(
        "public class SpringValueReference {\n"
        '    @org.springframework.beans.factory.annotation.Value("${db.password}")\n'
        "    String password;\n"
        "}\n"
    )

    result = parse_file(java_file)

    assert detect_in_java(result) == ()


def test_detect_in_java_finds_secret_passed_to_credential_constructor(
    tmp_path: Path,
) -> None:
    java_file = tmp_path / "ConstructorSecret.java"
    java_file.write_text(
        "public class ConstructorSecret {\n"
        "    void configure() {\n"
        '        new PasswordAuthentication("admin", "hunter2".toCharArray());\n'
        "    }\n"
        "}\n"
    )

    result = parse_file(java_file)

    findings = detect_in_java(result)
    assert [(finding.identifier, finding.line) for finding in findings] == [
        ("PasswordAuthentication", 3)
    ]
    assert findings[0].redacted_value == "h*****2"


def test_detect_in_java_does_not_flag_safe_call_site_values(tmp_path: Path) -> None:
    java_file = tmp_path / "SafeCallSiteSecret.java"
    java_file.write_text(
        "import java.util.Map;\n"
        "public class SafeCallSiteSecret {\n"
        "    void configure(Config config, Map<String, String> values) {\n"
        '        config.setPassword("${DB_PASSWORD}");\n'
        '        values.put("password", "CHANGE_ME");\n'
        '        values.put("description", "hunter2");\n'
        "    }\n"
        "}\n"
    )

    result = parse_file(java_file)

    assert detect_in_java(result) == ()


def test_detect_in_java_does_not_flag_safe_assignment_values(tmp_path: Path) -> None:
    java_file = tmp_path / "SafeAssignedSecret.java"
    java_file.write_text(
        "public class SafeAssignedSecret {\n"
        "    void configure() {\n"
        '        String password = "${DB_PASSWORD}";\n'
        '        password = "CHANGE_ME";\n'
        '        String description = "hunter2";\n'
        "    }\n"
        "}\n"
    )

    result = parse_file(java_file)

    assert detect_in_java(result) == ()


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


def test_detect_in_java_does_not_resolve_secret_split_across_variables(
    tmp_path: Path,
) -> None:
    """Documented limitation: a secret split across variables isn't resolved.

    _string_literal_value only folds a literal-to-literal `+` chain
    within a single expression (e.g. "hunter" + "2"); resolving
    `part1 + part2` where part1/part2 are themselves other
    declarations would require basic constant propagation across a
    class, a meaningfully bigger static-analysis capability this rule
    does not attempt. This test locks in that the documented boundary
    is the actual behavior, not accidentally different from what the
    docstring claims.
    """
    java_file = tmp_path / "Split.java"
    java_file.write_text(
        "public class Split {\n"
        '    private String part1 = "hunter";\n'
        '    private String part2 = "2";\n'
        "    private String password = part1 + part2;\n"
        "}\n"
    )

    result = parse_file(java_file)

    assert detect_in_java(result) == ()


def test_detect_in_java_finds_secret_when_tree_sitter_fallback_was_used(tmp_path: Path) -> None:
    """Modern Java that javalang cannot parse must still feed CWE-798."""
    java_file = tmp_path / "Modern.java"
    java_file.write_text(
        "public record Modern(String username) {\n"
        "    public Modern { username = username.trim(); }\n"
        "    public String role(int level) {\n"
        '        String password = "hunter2";\n'
        "        return switch (level) {\n"
        '            case 1 -> "admin";\n'
        '            default -> "user";\n'
        "        };\n"
        "    }\n"
        "}\n"
    )

    result = parse_file(java_file)

    assert result.tree_sitter is not None
    findings = detect_in_java(result)
    assert [(f.identifier, f.line) for f in findings] == [("password", 4)]


def test_detect_in_java_finds_compact_record_constructor_assignment(
    tmp_path: Path,
) -> None:
    java_file = tmp_path / "ModernAssignedSecret.java"
    java_file.write_text(
        "public record ModernAssignedSecret(String password) {\n"
        "    public ModernAssignedSecret {\n"
        '        password = "hunter2";\n'
        "    }\n"
        "}\n"
    )

    result = parse_file(java_file)

    assert result.tree_sitter is not None
    findings = detect_in_java(result)
    assert [(f.identifier, f.line) for f in findings] == [("password", 3)]


def test_detect_in_java_finds_call_site_secret_on_tree_sitter_fallback(
    tmp_path: Path,
) -> None:
    java_file = tmp_path / "ModernCallSiteSecret.java"
    java_file.write_text(
        "public record ModernCallSiteSecret(String username) {\n"
        "    public ModernCallSiteSecret { username = username.trim(); }\n"
        "    public String role(Config config, int level) {\n"
        '        config.setPassword("hunter2");\n'
        "        return switch (level) {\n"
        '            case 1 -> "admin";\n'
        '            default -> "user";\n'
        "        };\n"
        "    }\n"
        "}\n"
    )

    result = parse_file(java_file)

    assert result.tree_sitter is not None
    findings = detect_in_java(result)
    assert [(f.identifier, f.line) for f in findings] == [("setPassword", 4)]


def test_detect_in_java_finds_switch_expression_secret_on_tree_sitter_fallback(
    tmp_path: Path,
) -> None:
    java_file = tmp_path / "ModernSwitchSecret.java"
    java_file.write_text(
        "public class ModernSwitchSecret {\n"
        "    String secret(int level) {\n"
        "        String token;\n"
        "        token = switch (level) {\n"
        '            case 1 -> "abc123";\n'
        '            default -> "def456";\n'
        "        };\n"
        "        return token;\n"
        "    }\n"
        "}\n"
    )

    result = parse_file(java_file)

    assert result.tree_sitter is not None
    findings = detect_in_java(result)
    assert [(f.identifier, f.line) for f in findings] == [("token", 5)]


def test_detect_in_java_decodes_text_block_secret_on_tree_sitter_fallback(
    tmp_path: Path,
) -> None:
    """Tree-sitter fallback must use the same text-block decoding as javalang path."""
    java_file = tmp_path / "ModernTextBlock.java"
    java_file.write_text(
        "public class ModernTextBlock {\n"
        "    String role(int level) {\n"
        '        String password = """\n'
        "            hunter\\\n"
        "            2\\s\n"
        '            """;\n'
        "        return switch (level) {\n"
        '            case 1 -> "admin";\n'
        '            default -> "user";\n'
        "        };\n"
        "    }\n"
        "}\n"
    )

    result = parse_file(java_file)

    assert result.tree_sitter is not None
    findings = detect_in_java(result)
    assert len(findings) == 1
    assert findings[0].identifier == "password"
    assert findings[0].line == 3
    assert findings[0].redacted_value is not None
    assert "hunter2" not in findings[0].redacted_value
    assert "\n" not in findings[0].redacted_value


def test_detect_in_java_does_not_flag_secret_key_spec_algorithm_name(tmp_path: Path) -> None:
    """new SecretKeySpec(keyBytes, "HmacSHA256") must not flag the algorithm name.

    Found scanning real AI-generated code: the credential-shaped
    constructor name ("SecretKeySpec" contains "secret") combined with
    the reversed-argument scan (deliberately preferring later arguments
    for cases like PasswordAuthentication("user", "pass".toCharArray()))
    picked up the algorithm-name literal instead - a false positive on
    an idiomatic, standard JCA constructor call. The actual key material
    (a non-literal expression here) correctly still isn't flagged either,
    since this rule never evaluates non-literal values.
    """
    java_file = tmp_path / "Signer.java"
    java_file.write_text(
        "import javax.crypto.spec.SecretKeySpec;\n"
        "public class Signer {\n"
        "    void sign(String signingSecret) {\n"
        '        new SecretKeySpec(signingSecret.getBytes(), "HmacSHA256");\n'
        "    }\n"
        "}\n"
    )

    result = parse_file(java_file)

    assert detect_in_java(result) == ()


def test_detect_in_java_still_flags_real_secret_before_a_safe_algorithm_name(
    tmp_path: Path,
) -> None:
    """The algorithm-name exclusion must not blind the scan to an earlier real literal.

    Proves _check_class_creator's reversed-argument scan still falls
    through past a now-excluded safe literal (the last argument) and
    catches a genuine hardcoded secret in an earlier argument position,
    rather than the fix accidentally suppressing the whole constructor
    call.
    """
    java_file = tmp_path / "SecretHolder.java"
    java_file.write_text(
        "public class SecretHolder {\n"
        "    void configure() {\n"
        '        new SecretHolder("hunter2", "AES");\n'
        "    }\n"
        "}\n"
    )

    result = parse_file(java_file)

    findings = detect_in_java(result)
    assert len(findings) == 1
    assert findings[0].identifier == "SecretHolder"
