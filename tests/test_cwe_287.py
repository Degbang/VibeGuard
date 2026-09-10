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


def test_detect_in_java_flags_credential_getter_comparison(tmp_path: Path) -> None:
    java_file = tmp_path / "GetterComparison.java"
    java_file.write_text(
        "public class GetterComparison {\n"
        "    boolean ok(User user, String input) {\n"
        "        return user.getPassword() == input;\n"
        "    }\n"
        "}\n"
    )

    result = parse_file(java_file)

    findings = detect_in_java(result)
    assert [(finding.identifier, finding.line) for finding in findings] == [("getPassword", 3)]


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


def test_detect_in_java_finds_unsafe_comparison_with_modern_switch(tmp_path: Path) -> None:
    """Tree-sitter fallback files must still feed CWE-287."""
    java_file = tmp_path / "ModernAuth.java"
    java_file.write_text(
        "public class ModernAuth {\n"
        "    boolean check(String password, int level) {\n"
        "        String role = switch (level) {\n"
        '            case 1 -> "admin";\n'
        '            default -> "user";\n'
        "        };\n"
        '        return password == "hunter2";\n'
        "    }\n"
        "}\n"
    )

    result = parse_file(java_file)

    assert result.tree_sitter is not None
    findings = detect_in_java(result)
    assert [(f.identifier, f.line) for f in findings] == [("password", 7)]


def test_detect_in_java_flags_credential_getter_comparison_on_tree_sitter_fallback(
    tmp_path: Path,
) -> None:
    java_file = tmp_path / "ModernGetterComparison.java"
    java_file.write_text(
        "public record ModernGetterComparison(String name) {\n"
        "    boolean ok(User user, String input) {\n"
        "        String role = switch (input) {\n"
        '            case "x" -> "admin";\n'
        '            default -> "user";\n'
        "        };\n"
        "        return user.getPassword() == input;\n"
        "    }\n"
        "}\n"
    )

    result = parse_file(java_file)

    assert result.tree_sitter is not None
    findings = detect_in_java(result)
    assert [(f.identifier, f.line) for f in findings] == [("getPassword", 7)]


def test_detect_in_java_flags_unguarded_endpoint_that_returns_a_fresh_token(
    tmp_path: Path,
) -> None:
    """The exact real-world shape that motivated this check (2026-09-04).

    A self-service recovery endpoint that generates a token from only an
    email address (no proof of ownership) and hands it straight back in
    the response, instead of delivering it out-of-band.
    """
    java_file = tmp_path / "RecoveryController.java"
    java_file.write_text(
        "import org.springframework.web.bind.annotation.*;\n"
        "import java.util.*;\n"
        "public class RecoveryController {\n"
        '    @PostMapping("/request")\n'
        "    public String request(String email) {\n"
        "        String token = UUID.randomUUID().toString();\n"
        "        store.put(token, email);\n"
        '        return Map.of("recoveryToken", token).toString();\n'
        "    }\n"
        "}\n"
    )

    result = parse_file(java_file)

    findings = detect_in_java(result)

    assert len(findings) == 1
    assert findings[0].identifier == "token"
    assert "request" in findings[0].message
    assert "no preceding guard" in findings[0].message


def test_detect_in_java_does_not_flag_endpoint_guarded_by_if_statement(
    tmp_path: Path,
) -> None:
    """A manual header/key check before issuance is a real, if hand-rolled, guard."""
    java_file = tmp_path / "TokenController.java"
    java_file.write_text(
        "import org.springframework.web.bind.annotation.*;\n"
        "import java.util.*;\n"
        "public class TokenController {\n"
        '    @PostMapping("/issue")\n'
        "    public String issue(String supplied) {\n"
        '        if (!internalKey.equals(supplied)) return "no";\n'
        "        String token = UUID.randomUUID().toString();\n"
        "        return token;\n"
        "    }\n"
        "}\n"
    )

    result = parse_file(java_file)

    assert detect_in_java(result) == ()


def test_detect_in_java_does_not_flag_endpoint_guarded_by_authorization_annotation(
    tmp_path: Path,
) -> None:
    """Framework-enforced method security is a guard even with no manual if-check."""
    java_file = tmp_path / "AdminTokenController.java"
    java_file.write_text(
        "import org.springframework.web.bind.annotation.*;\n"
        "import org.springframework.security.access.prepost.PreAuthorize;\n"
        "import java.util.*;\n"
        "public class AdminTokenController {\n"
        "    @PreAuthorize(\"hasRole('ADMIN')\")\n"
        '    @PostMapping("/issue")\n'
        "    public String issue() {\n"
        "        String token = UUID.randomUUID().toString();\n"
        "        return token;\n"
        "    }\n"
        "}\n"
    )

    result = parse_file(java_file)

    assert detect_in_java(result) == ()


def test_detect_in_java_does_not_flag_a_token_that_is_never_returned(
    tmp_path: Path,
) -> None:
    """The real ai-password-reset-service shape: hash-and-store, return nothing."""
    java_file = tmp_path / "PasswordResetController.java"
    java_file.write_text(
        "import org.springframework.web.bind.annotation.*;\n"
        "import java.util.*;\n"
        "public class PasswordResetController {\n"
        '    @PostMapping("/request")\n'
        "    public String request(String email) {\n"
        "        String token = UUID.randomUUID().toString();\n"
        "        store.put(hash(token), email);\n"
        '        return "accepted";\n'
        "    }\n"
        "}\n"
    )

    result = parse_file(java_file)

    assert detect_in_java(result) == ()


def test_detect_in_java_does_not_flag_a_credential_named_method_call_in_the_return(
    tmp_path: Path,
) -> None:
    """The real ai-account-recovery-service `complete` shape: validating an

    incoming token, not returning a freshly issued one. `complete.token()`
    is a method call, not a value reference - must not be confused with the
    bare-variable pattern this check targets, a real false positive found
    and fixed during testing (2026-09-04).
    """
    java_file = tmp_path / "RecoveryController.java"
    java_file.write_text(
        "import org.springframework.web.bind.annotation.*;\n"
        "public class RecoveryController {\n"
        '    @PostMapping("/complete")\n'
        "    public String complete(Complete complete) {\n"
        '        return tokens.remove(complete.token()) == null ? "bad" : "ok";\n'
        "    }\n"
        "}\n"
    )

    result = parse_file(java_file)

    assert detect_in_java(result) == ()


def test_detect_in_java_does_not_flag_a_non_endpoint_method(tmp_path: Path) -> None:
    """A private/unreachable helper returning a token isn't externally exploitable."""
    java_file = tmp_path / "TokenHelper.java"
    java_file.write_text(
        "import java.util.*;\n"
        "public class TokenHelper {\n"
        "    public String mint() {\n"
        "        String token = UUID.randomUUID().toString();\n"
        "        return token;\n"
        "    }\n"
        "}\n"
    )

    result = parse_file(java_file)

    assert detect_in_java(result) == ()


def test_detect_in_java_flags_unguarded_issuance_on_tree_sitter_fallback(
    tmp_path: Path,
) -> None:
    """Tree-sitter fallback files must still feed the unguarded-issuance check."""
    java_file = tmp_path / "ModernRecoveryController.java"
    java_file.write_text(
        "import org.springframework.web.bind.annotation.*;\n"
        "import java.util.*;\n"
        "public class ModernRecoveryController {\n"
        "    int helper(int level) {\n"
        "        return switch (level) {\n"
        "            case 1 -> 1;\n"
        "            default -> 0;\n"
        "        };\n"
        "    }\n"
        '    @PostMapping("/request")\n'
        "    public String request(String email) {\n"
        "        String token = UUID.randomUUID().toString();\n"
        "        store.put(token, email);\n"
        "        return token;\n"
        "    }\n"
        "}\n"
    )

    result = parse_file(java_file)

    assert result.tree_sitter is not None
    findings = detect_in_java(result)
    assert [(f.identifier, f.line) for f in findings] == [("token", 10)]


def test_detect_in_java_does_not_flag_guarded_issuance_on_tree_sitter_fallback(
    tmp_path: Path,
) -> None:
    """Tree-sitter fallback must preserve the same if-guard exclusion."""
    java_file = tmp_path / "ModernTokenController.java"
    java_file.write_text(
        "import org.springframework.web.bind.annotation.*;\n"
        "import java.util.*;\n"
        "public class ModernTokenController {\n"
        "    int helper(int level) {\n"
        "        return switch (level) {\n"
        "            case 1 -> 1;\n"
        "            default -> 0;\n"
        "        };\n"
        "    }\n"
        '    @PostMapping("/issue")\n'
        "    public String issue(String supplied) {\n"
        '        if (!internalKey.equals(supplied)) return "no";\n'
        "        String token = UUID.randomUUID().toString();\n"
        "        return token;\n"
        "    }\n"
        "}\n"
    )

    result = parse_file(java_file)

    assert result.tree_sitter is not None
    assert detect_in_java(result) == ()
