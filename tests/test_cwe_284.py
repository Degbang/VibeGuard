"""Tests for vibeguard.layer1_static.rules.cwe_284."""

from __future__ import annotations

from pathlib import Path

import javalang

from vibeguard.layer1_static.ast_parser import parse_file
from vibeguard.layer1_static.rules._interface_annotations import (
    build_interface_hierarchy_index,
    build_interface_method_index,
)
from vibeguard.layer1_static.rules.cwe_284 import (
    CWE_ID,
    apply_centralized_authorization_context,
    apply_hand_rolled_guard_context,
    detect_in_java,
    has_centralized_authorization_rule,
    has_inline_header_guard,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures"

_SECURITY_FILTER_CHAIN_JAVA = (
    "import org.springframework.context.annotation.Bean;\n"
    "import org.springframework.security.web.SecurityFilterChain;\n"
    "public class SecurityConfig {\n"
    "    @Bean\n"
    "    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {\n"
    "        http\n"
    "            .authorizeHttpRequests(authz -> authz\n"
    "                .anyRequest().authenticated());\n"
    "        return http.build();\n"
    "    }\n"
    "}\n"
)


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


def test_detect_in_java_finds_unprotected_endpoint_with_modern_switch(
    tmp_path: Path,
) -> None:
    """Tree-sitter fallback files must still feed CWE-284."""
    java_file = tmp_path / "ModernResource.java"
    java_file.write_text(
        "import org.springframework.web.bind.annotation.*;\n"
        "@RestController\n"
        "public class ModernResource {\n"
        '    @PostMapping("/role")\n'
        "    public String role(int level) {\n"
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
    assert [(f.identifier, f.line) for f in findings] == [("role", 4)]


def test_detect_in_java_does_not_flag_quarkus_rest_client_interface(
    tmp_path: Path,
) -> None:
    """Outbound REST clients are not inbound access-control candidates."""
    java_file = tmp_path / "HeroClient.java"
    java_file.write_text(
        "import jakarta.ws.rs.GET;\n"
        "import jakarta.ws.rs.Path;\n"
        "import org.eclipse.microprofile.rest.client.inject.RegisterRestClient;\n"
        '@Path("/heroes")\n'
        "@RegisterRestClient\n"
        "interface HeroClient {\n"
        "    @GET\n"
        '    @Path("/random")\n'
        "    String findRandomHero();\n"
        "}\n"
    )

    result = parse_file(java_file)

    assert detect_in_java(result) == ()


def test_detect_in_java_does_not_flag_tree_sitter_rest_client_interface(
    tmp_path: Path,
) -> None:
    """Tree-sitter fallback must preserve the same REST-client exclusion."""
    java_file = tmp_path / "HeroClient.java"
    java_file.write_text(
        "import jakarta.ws.rs.GET;\n"
        "import jakarta.ws.rs.Path;\n"
        "import org.eclipse.microprofile.rest.client.inject.RegisterRestClient;\n"
        '@Path("/heroes")\n'
        "@RegisterRestClient\n"
        "interface HeroClient {\n"
        "    @GET\n"
        '    @Path("/random")\n'
        "    String findRandomHero();\n"
        "    default int helper(int level) {\n"
        "        return switch (level) {\n"
        "            case 1 -> 1;\n"
        "            default -> 0;\n"
        "        };\n"
        "    }\n"
        "}\n"
    )

    result = parse_file(java_file)

    assert result.tree_sitter is not None
    assert detect_in_java(result) == ()


def test_has_centralized_authorization_rule_detects_any_request_authenticated(
    tmp_path: Path,
) -> None:
    """A SecurityFilterChain with a blanket .anyRequest().authenticated() rule.

    This is the exact real-world pattern found by scanning
    spring-petclinic-rest (see IMPLEMENTATION_LOG.md): a project can
    centralize authorization this way instead of per-method annotations,
    which this rule's annotation-only detection cannot see at all.
    """
    java_file = tmp_path / "SecurityConfig.java"
    java_file.write_text(_SECURITY_FILTER_CHAIN_JAVA)

    result = parse_file(java_file)

    assert has_centralized_authorization_rule(result) is True


def test_has_centralized_authorization_rule_detects_permit_all(tmp_path: Path) -> None:
    """anyRequest().permitAll() is also a blanket decision, just a permissive one."""
    java_file = tmp_path / "SecurityConfig.java"
    java_file.write_text(
        "import org.springframework.security.web.SecurityFilterChain;\n"
        "public class SecurityConfig {\n"
        "    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {\n"
        "        http.authorizeHttpRequests(authz -> authz.anyRequest().permitAll());\n"
        "        return http.build();\n"
        "    }\n"
        "}\n"
    )

    result = parse_file(java_file)

    assert has_centralized_authorization_rule(result) is True


def test_has_centralized_authorization_rule_false_with_no_security_filter_chain() -> None:
    result = parse_file(FIXTURES_DIR / "UnprotectedResource.java")

    assert has_centralized_authorization_rule(result) is False


def test_has_centralized_authorization_rule_false_without_any_request(tmp_path: Path) -> None:
    """A SecurityFilterChain that only rules on specific paths is not a blanket decision.

    Must not be treated the same as a project-wide anyRequest() rule -
    that would risk masking a genuine gap for every path the chain
    doesn't actually mention.
    """
    java_file = tmp_path / "SecurityConfig.java"
    java_file.write_text(
        "import org.springframework.security.web.SecurityFilterChain;\n"
        "public class SecurityConfig {\n"
        "    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {\n"
        "        http.authorizeHttpRequests(authz -> authz\n"
        '            .requestMatchers("/admin/**").authenticated());\n'
        "        return http.build();\n"
        "    }\n"
        "}\n"
    )

    result = parse_file(java_file)

    assert has_centralized_authorization_rule(result) is False


def test_has_centralized_authorization_rule_tree_sitter_fallback(tmp_path: Path) -> None:
    """The same pattern must be detected on a Tree-sitter fallback parse."""
    java_file = tmp_path / "SecurityConfig.java"
    java_file.write_text(
        "import org.springframework.security.web.SecurityFilterChain;\n"
        "public class SecurityConfig {\n"
        "    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {\n"
        "        int level = switch (1) {\n"
        "            case 1 -> 1;\n"
        "            default -> 0;\n"
        "        };\n"
        "        http.authorizeHttpRequests(authz -> authz.anyRequest().authenticated());\n"
        "        return http.build();\n"
        "    }\n"
        "}\n"
    )

    result = parse_file(java_file)

    assert result.tree_sitter is not None
    assert has_centralized_authorization_rule(result) is True


def test_has_centralized_authorization_rule_detects_legacy_configure_override(
    tmp_path: Path,
) -> None:
    """The real gap found scanning gothinkster/spring-boot-realworld-example-app
    (IMPLEMENTATION_LOG.md 2026-09-04): WebSecurityConfigurerAdapter's
    void-returning `configure(HttpSecurity)` override, not a
    SecurityFilterChain bean - the deprecated (removed in Spring Security
    6) but still extremely common pre-5.7 style.
    """
    java_file = tmp_path / "WebSecurityConfig.java"
    java_file.write_text(
        "import org.springframework.security.config.annotation.web.builders.HttpSecurity;\n"
        "import org.springframework.security.config.annotation.web.configuration."
        "WebSecurityConfigurerAdapter;\n"
        "public class WebSecurityConfig extends WebSecurityConfigurerAdapter {\n"
        "    protected void configure(HttpSecurity http) throws Exception {\n"
        "        http.authorizeRequests()\n"
        '            .antMatchers("/public/**").permitAll()\n'
        "            .anyRequest().authenticated();\n"
        "    }\n"
        "}\n"
    )

    result = parse_file(java_file)

    assert has_centralized_authorization_rule(result) is True


def test_has_centralized_authorization_rule_false_for_unrelated_configure_method(
    tmp_path: Path,
) -> None:
    """A `configure` method with a different signature is not this pattern."""
    java_file = tmp_path / "Widget.java"
    java_file.write_text(
        "public class Widget {\n"
        "    public void configure(String name) {\n"
        "        this.name = name;\n"
        "    }\n"
        "}\n"
    )

    result = parse_file(java_file)

    assert has_centralized_authorization_rule(result) is False


def test_has_centralized_authorization_rule_detects_legacy_configure_tree_sitter_fallback(
    tmp_path: Path,
) -> None:
    """The same legacy-configure pattern must be detected on a Tree-sitter fallback parse."""
    java_file = tmp_path / "WebSecurityConfig.java"
    java_file.write_text(
        "import org.springframework.security.config.annotation.web.builders.HttpSecurity;\n"
        "public class WebSecurityConfig {\n"
        "    int helper(int level) {\n"
        "        return switch (level) {\n"
        "            case 1 -> 1;\n"
        "            default -> 0;\n"
        "        };\n"
        "    }\n"
        "    protected void configure(HttpSecurity http) throws Exception {\n"
        "        http.authorizeRequests().anyRequest().authenticated();\n"
        "    }\n"
        "}\n"
    )

    result = parse_file(java_file)

    assert result.tree_sitter is not None
    assert has_centralized_authorization_rule(result) is True


def test_apply_centralized_authorization_context_appends_caveat_when_present(
    tmp_path: Path,
) -> None:
    endpoint_file = tmp_path / "RootController.java"
    endpoint_file.write_text(
        "import org.springframework.web.bind.annotation.*;\n"
        "@RestController\n"
        "public class RootController {\n"
        '    @RequestMapping("/")\n'
        "    public void redirect() {}\n"
        "}\n"
    )
    security_file = tmp_path / "SecurityConfig.java"
    security_file.write_text(_SECURITY_FILTER_CHAIN_JAVA)

    endpoint_result = parse_file(endpoint_file)
    security_result = parse_file(security_file)
    findings = detect_in_java(endpoint_result)
    assert len(findings) == 1

    annotated = apply_centralized_authorization_context(
        findings, (endpoint_result, security_result)
    )

    assert len(annotated) == 1
    assert annotated[0].identifier == "redirect"
    assert "SecurityFilterChain" in annotated[0].message
    assert "anyRequest" in annotated[0].message


def test_apply_centralized_authorization_context_no_op_when_absent(tmp_path: Path) -> None:
    endpoint_file = tmp_path / "RootController.java"
    endpoint_file.write_text(
        "import org.springframework.web.bind.annotation.*;\n"
        "@RestController\n"
        "public class RootController {\n"
        '    @RequestMapping("/")\n'
        "    public void redirect() {}\n"
        "}\n"
    )
    endpoint_result = parse_file(endpoint_file)
    findings = detect_in_java(endpoint_result)

    unchanged = apply_centralized_authorization_context(findings, (endpoint_result,))

    assert unchanged == findings


def test_apply_centralized_authorization_context_never_drops_findings(tmp_path: Path) -> None:
    """The caveat must never suppress a finding - only annotate its message.

    A security tool that silently hides a candidate because of a coarse,
    best-effort heuristic is worse than one that keeps flagging it.
    """
    endpoint_file = tmp_path / "RootController.java"
    endpoint_file.write_text(
        "import org.springframework.web.bind.annotation.*;\n"
        "@RestController\n"
        "public class RootController {\n"
        '    @RequestMapping("/")\n'
        "    public void redirect() {}\n"
        "}\n"
    )
    security_file = tmp_path / "SecurityConfig.java"
    security_file.write_text(_SECURITY_FILTER_CHAIN_JAVA)

    endpoint_result = parse_file(endpoint_file)
    security_result = parse_file(security_file)
    findings = detect_in_java(endpoint_result)

    annotated = apply_centralized_authorization_context(
        findings, (endpoint_result, security_result)
    )

    assert len(annotated) == len(findings)


def _first_method(
    tree: javalang.tree.CompilationUnit, name: str
) -> javalang.tree.MethodDeclaration:
    for _path, method in tree.filter(javalang.tree.MethodDeclaration):
        if method.name == name:
            return method
    raise AssertionError(f"no method named {name!r} in {tree!r}")


# Mirrors the real ai-api-key-service/ai-oauth-refresh-service shape: a
# caller-supplied header compared directly against a configured value,
# bailing out on mismatch - see IMPLEMENTATION_LOG.md's 2026-09-10 entry.
_DIRECT_HEADER_GUARD_JAVA = (
    "import org.springframework.web.bind.annotation.*;\n"
    "@RestController\n"
    "public class ApiKeyController {\n"
    '    @Value("${API_KEY_ADMIN_KEY:}") private String adminKey;\n'
    "    @PostMapping\n"
    '    public String issue(@RequestHeader("X-Api-Key-Admin-Key") String supplied) {\n'
    '        if (!adminKey.equals(supplied)) return "unauthorized";\n'
    '        return "ok";\n'
    "    }\n"
    "}\n"
)


def test_has_inline_header_guard_detects_direct_comparison() -> None:
    tree = javalang.parse.parse(_DIRECT_HEADER_GUARD_JAVA)
    method = _first_method(tree, "issue")

    assert has_inline_header_guard(method) is True


def test_has_inline_header_guard_detects_combined_or_condition() -> None:
    """Mirrors ai-oauth-refresh-service's refresh(): the comparison is one
    operand of a larger ``||`` condition, not the whole condition."""
    java = (
        "import org.springframework.web.bind.annotation.*;\n"
        "public class TokenController {\n"
        '    @Value("${OAUTH_CLIENT_KEY:}") private String clientKey;\n'
        "    @PostMapping\n"
        '    public String refresh(@RequestHeader("X-OAuth-Client-Key") String supplied, '
        "String grantType) {\n"
        '        if (!clientKey.equals(supplied) || !"refresh_token".equals(grantType)) '
        'return "unauthorized";\n'
        '        return "ok";\n'
        "    }\n"
        "}\n"
    )
    tree = javalang.parse.parse(java)
    method = _first_method(tree, "refresh")

    assert has_inline_header_guard(method) is True


def test_has_inline_header_guard_detects_message_digest_is_equal() -> None:
    java = (
        "import org.springframework.web.bind.annotation.*;\n"
        "public class VaultController {\n"
        '    @Value("${VAULT_KEY:}") private String vaultKey;\n'
        "    @PostMapping\n"
        '    public String save(@RequestHeader("X-Vault-Key") String supplied) {\n'
        "        if (!MessageDigest.isEqual(vaultKey.getBytes(), supplied.getBytes())) "
        'return "unauthorized";\n'
        '        return "ok";\n'
        "    }\n"
        "}\n"
    )
    tree = javalang.parse.parse(java)
    method = _first_method(tree, "save")

    assert has_inline_header_guard(method) is True


def test_has_inline_header_guard_false_for_blank_check_without_caller_input() -> None:
    """Mirrors ai-payments-service: checks a config value is non-blank, but
    never compares it against anything the caller supplied - not an
    authorization check, must not match."""
    java = (
        "import org.springframework.web.bind.annotation.*;\n"
        "public class PaymentController {\n"
        '    @Value("${PAYMENT_PROVIDER_API_KEY:}") private String providerApiKey;\n'
        "    @PostMapping\n"
        '    public String charge(@RequestHeader("X-Trace-Id") String traceId) {\n'
        '        if (providerApiKey.isBlank()) return "unavailable";\n'
        '        return "ok";\n'
        "    }\n"
        "}\n"
    )
    tree = javalang.parse.parse(java)
    method = _first_method(tree, "charge")

    assert has_inline_header_guard(method) is False


def test_has_inline_header_guard_false_for_unguarded_method() -> None:
    java = (
        "import org.springframework.web.bind.annotation.*;\n"
        "public class OpenController {\n"
        "    @PostMapping\n"
        '    public String save(@RequestHeader("X-Trace-Id") String traceId) {\n'
        '        return "ok";\n'
        "    }\n"
        "}\n"
    )
    tree = javalang.parse.parse(java)
    method = _first_method(tree, "save")

    assert has_inline_header_guard(method) is False


def test_has_inline_header_guard_false_without_any_header_parameter() -> None:
    java = (
        "import org.springframework.web.bind.annotation.*;\n"
        "public class OpenController {\n"
        '    @Value("${KEY:}") private String key;\n'
        "    @PostMapping\n"
        "    public String save(String body) {\n"
        '        if (!key.equals(body)) return "unauthorized";\n'
        '        return "ok";\n'
        "    }\n"
        "}\n"
    )
    tree = javalang.parse.parse(java)
    method = _first_method(tree, "save")

    assert has_inline_header_guard(method) is False


def test_apply_hand_rolled_guard_context_appends_caveat_only_to_guarded_method(
    tmp_path: Path,
) -> None:
    """Per-method precision: an unguarded sibling endpoint in the same class
    must not be caveated just because another method in the same file has a
    guard - unlike the centralized-authorization caveat, which is
    deliberately project-wide, this one must stay narrowly scoped."""
    java_file = tmp_path / "ApiKeyController.java"
    assert _DIRECT_HEADER_GUARD_JAVA.endswith("}\n")
    java_file.write_text(
        _DIRECT_HEADER_GUARD_JAVA[: -len("}\n")]
        + '    @DeleteMapping("/{id}")\n'
        + '    public String revoke(String id) { return "ok"; }\n'
        + "}\n"
    )

    result = parse_file(java_file)
    findings = detect_in_java(result)
    assert {f.identifier for f in findings} == {"issue", "revoke"}

    annotated = apply_hand_rolled_guard_context(findings, (result,))

    by_identifier = {f.identifier: f for f in annotated}
    assert "hand-rolled authorization check" in by_identifier["issue"].message
    assert "hand-rolled authorization check" not in by_identifier["revoke"].message


def test_apply_hand_rolled_guard_context_no_op_when_absent(tmp_path: Path) -> None:
    java_file = tmp_path / "OpenController.java"
    java_file.write_text(
        "import org.springframework.web.bind.annotation.*;\n"
        "@RestController\n"
        "public class OpenController {\n"
        "    @PostMapping\n"
        '    public String save(@RequestHeader("X-Trace-Id") String traceId) {\n'
        '        return "ok";\n'
        "    }\n"
        "}\n"
    )
    result = parse_file(java_file)
    findings = detect_in_java(result)

    unchanged = apply_hand_rolled_guard_context(findings, (result,))

    assert unchanged == findings


def test_apply_hand_rolled_guard_context_never_drops_findings(tmp_path: Path) -> None:
    java_file = tmp_path / "ApiKeyController.java"
    java_file.write_text(_DIRECT_HEADER_GUARD_JAVA)
    result = parse_file(java_file)
    findings = detect_in_java(result)

    annotated = apply_hand_rolled_guard_context(findings, (result,))

    assert len(annotated) == len(findings)


def test_apply_hand_rolled_guard_context_tree_sitter_fallback(tmp_path: Path) -> None:
    """The same direct-comparison guard must be detected on a Tree-sitter
    fallback parse, and attach the same per-method caveat."""
    java_file = tmp_path / "ApiKeyController.java"
    java_file.write_text(
        "import org.springframework.web.bind.annotation.*;\n"
        "@RestController\n"
        "public class ApiKeyController {\n"
        '    @Value("${API_KEY_ADMIN_KEY:}") private String adminKey;\n'
        "    int helper(int level) {\n"
        "        return switch (level) {\n"
        "            case 1 -> 1;\n"
        "            default -> 0;\n"
        "        };\n"
        "    }\n"
        "    @PostMapping\n"
        '    public String issue(@RequestHeader("X-Api-Key-Admin-Key") String supplied) {\n'
        '        if (!adminKey.equals(supplied)) return "unauthorized";\n'
        '        return "ok";\n'
        "    }\n"
        "}\n"
    )

    result = parse_file(java_file)
    assert result.tree_sitter is not None
    findings = detect_in_java(result)
    assert len(findings) == 1

    annotated = apply_hand_rolled_guard_context(findings, (result,))

    assert "hand-rolled authorization check" in annotated[0].message


# -- Interface-inherited annotation resolution -------------------------------
#
# Reproduces the real gap found scanning spring-petclinic-rest: a concrete
# class implementing a codegen-style interface (Spring's
# openapi-generator-maven-plugin output) that carries the real
# @GetMapping/@PostMapping annotations only on the *interface* method,
# with the concrete @Override implementation carrying none of its own -
# see IMPLEMENTATION_LOG.md's 2026-09-02 entry.

_OWNERS_API_INTERFACE_JAVA = (
    "import org.springframework.web.bind.annotation.GetMapping;\n"
    "public interface OwnersApi {\n"
    '    @GetMapping("/owners/{id}")\n'
    "    String getOwner(int id);\n"
    "}\n"
)

_OWNERS_API_WITH_PREAUTHORIZE_JAVA = (
    "import org.springframework.web.bind.annotation.GetMapping;\n"
    "import org.springframework.security.access.prepost.PreAuthorize;\n"
    "public interface OwnersApi {\n"
    '    @GetMapping("/owners/{id}")\n'
    "    @PreAuthorize(\"hasRole('ADMIN')\")\n"
    "    String getOwner(int id);\n"
    "}\n"
)

_UNRELATED_INTERFACE_JAVA = (
    "import org.springframework.security.access.prepost.PreAuthorize;\n"
    "public interface UnrelatedApi {\n"
    "    @PreAuthorize(\"hasRole('ADMIN')\")\n"
    "    String getOwner(int id);\n"
    "}\n"
)


def test_detect_in_java_finds_endpoint_inherited_from_implemented_interface(
    tmp_path: Path,
) -> None:
    """A concrete @Override method with no annotations of its own must
    still be recognized as an endpoint when the interface it implements
    declares @GetMapping on the matching method - the exact real-world
    codegen-controller shape this index was built for."""
    (tmp_path / "OwnersApi.java").write_text(_OWNERS_API_INTERFACE_JAVA)
    controller_file = tmp_path / "OwnerRestControllerV1.java"
    controller_file.write_text(
        "public class OwnerRestControllerV1 implements OwnersApi {\n"
        "    @Override\n"
        "    public String getOwner(int id) {\n"
        '        return "owner";\n'
        "    }\n"
        "}\n"
    )
    interface_result = parse_file(tmp_path / "OwnersApi.java")
    controller_result = parse_file(controller_file)
    index = build_interface_method_index((interface_result, controller_result))

    # Without the index, the gap this fix targets reproduces exactly:
    # the method is invisible as an endpoint at all.
    assert detect_in_java(controller_result) == ()

    findings = detect_in_java(controller_result, index)

    assert len(findings) == 1
    assert findings[0].identifier == "getOwner"
    assert "interface" not in findings[0].message  # no auth-caveat: interface has none


def test_detect_in_java_adds_caveat_when_interface_method_has_authorization(
    tmp_path: Path,
) -> None:
    """An interface-declared @PreAuthorize on the matching method must
    NOT silently suppress the finding - whether it's actually enforced
    depends on Spring's proxy style (CGLIB vs. JDK dynamic proxy), which
    is not visible to static analysis. The finding must still fire, with
    an honest caveat attached."""
    (tmp_path / "OwnersApi.java").write_text(_OWNERS_API_WITH_PREAUTHORIZE_JAVA)
    controller_file = tmp_path / "OwnerRestControllerV1.java"
    controller_file.write_text(
        "public class OwnerRestControllerV1 implements OwnersApi {\n"
        "    @Override\n"
        "    public String getOwner(int id) {\n"
        '        return "owner";\n'
        "    }\n"
        "}\n"
    )
    interface_result = parse_file(tmp_path / "OwnersApi.java")
    controller_result = parse_file(controller_file)
    index = build_interface_method_index((interface_result, controller_result))

    findings = detect_in_java(controller_result, index)

    assert len(findings) == 1
    assert "proxy style" in findings[0].message
    assert "PreAuthorize" in findings[0].message


def test_detect_in_java_does_not_add_caveat_when_own_class_is_authorized(
    tmp_path: Path,
) -> None:
    """Coverage from the concrete method/class's own annotations - not
    proxy-dependent at all, since Spring always invokes the real bean's
    own annotations - must still fully suppress the finding, with no
    interface-authorization caveat attached."""
    (tmp_path / "OwnersApi.java").write_text(_OWNERS_API_INTERFACE_JAVA)
    controller_file = tmp_path / "OwnerRestControllerV1.java"
    controller_file.write_text(
        "import org.springframework.security.access.prepost.PreAuthorize;\n"
        "public class OwnerRestControllerV1 implements OwnersApi {\n"
        "    @Override\n"
        "    @PreAuthorize(\"hasRole('ADMIN')\")\n"
        "    public String getOwner(int id) {\n"
        '        return "owner";\n'
        "    }\n"
        "}\n"
    )
    interface_result = parse_file(tmp_path / "OwnersApi.java")
    controller_result = parse_file(controller_file)
    index = build_interface_method_index((interface_result, controller_result))

    assert detect_in_java(controller_result, index) == ()


def test_detect_in_java_does_not_borrow_annotations_from_an_unimplemented_interface(
    tmp_path: Path,
) -> None:
    """A same-named method on an interface this class does NOT implement
    must never contribute annotations - only types actually listed in
    the class's own ``implements`` clause are consulted."""
    (tmp_path / "OwnersApi.java").write_text(_OWNERS_API_INTERFACE_JAVA)
    (tmp_path / "UnrelatedApi.java").write_text(_UNRELATED_INTERFACE_JAVA)
    controller_file = tmp_path / "OwnerRestControllerV1.java"
    controller_file.write_text(
        "public class OwnerRestControllerV1 implements OwnersApi {\n"
        "    @Override\n"
        "    public String getOwner(int id) {\n"
        '        return "owner";\n'
        "    }\n"
        "}\n"
    )
    index = build_interface_method_index(
        (
            parse_file(tmp_path / "OwnersApi.java"),
            parse_file(tmp_path / "UnrelatedApi.java"),
            parse_file(controller_file),
        )
    )

    findings = detect_in_java(parse_file(controller_file), index)

    # OwnersApi contributes @GetMapping (endpoint, no auth) - found, no
    # caveat. UnrelatedApi's @PreAuthorize must not leak in even though
    # it shares the method name "getOwner".
    assert len(findings) == 1
    assert "proxy style" not in findings[0].message


def test_detect_in_java_finds_endpoint_inherited_from_interface_tree_sitter_fallback(
    tmp_path: Path,
) -> None:
    """The same interface-inherited-endpoint resolution must hold when
    the concrete file takes the Tree-sitter fallback path."""
    (tmp_path / "OwnersApi.java").write_text(_OWNERS_API_INTERFACE_JAVA)
    controller_file = tmp_path / "OwnerRestControllerV1.java"
    controller_file.write_text(
        "public class OwnerRestControllerV1 implements OwnersApi {\n"
        "    @Override\n"
        "    public String getOwner(int id) {\n"
        "        return switch (id) {\n"
        '            case 1 -> "first";\n'
        '            default -> "owner";\n'
        "        };\n"
        "    }\n"
        "}\n"
    )
    interface_result = parse_file(tmp_path / "OwnersApi.java")
    controller_result = parse_file(controller_file)
    assert controller_result.tree_sitter is not None
    index = build_interface_method_index((interface_result, controller_result))

    assert detect_in_java(controller_result) == ()
    findings = detect_in_java(controller_result, index)

    assert len(findings) == 1
    assert findings[0].identifier == "getOwner"


# -- Multi-level interface-extends chains ------------------------------------
#
# Found during log review, not by a QA pass: the interface-widening feature
# above only ever checked the single directly-implemented interface. If that
# interface itself extends a further interface (common for a shared base API
# interface, e.g. generated PetsApi extends BaseApi), the real annotation -
# declared on the grand-interface - was invisible entirely. Reproduced
# directly before fixing: a controller implementing PetsApi, where PetsApi
# extends BaseApi and @GetMapping lives only on BaseApi, produced zero
# findings. This is a false negative, the worst-case failure direction this
# project treats CWE-284 as having.

_BASE_API_JAVA = (
    "import org.springframework.web.bind.annotation.GetMapping;\n"
    "public interface BaseApi {\n"
    '    @GetMapping("/pets")\n'
    "    String getPets();\n"
    "}\n"
)

_PETS_API_EXTENDS_BASE_JAVA = "public interface PetsApi extends BaseApi {\n}\n"


def test_detect_in_java_finds_endpoint_inherited_through_a_two_level_interface_chain(
    tmp_path: Path,
) -> None:
    (tmp_path / "BaseApi.java").write_text(_BASE_API_JAVA)
    (tmp_path / "PetsApi.java").write_text(_PETS_API_EXTENDS_BASE_JAVA)
    controller_file = tmp_path / "PetsController.java"
    controller_file.write_text(
        "public class PetsController implements PetsApi {\n"
        "    @Override\n"
        '    public String getPets() { return "pets"; }\n'
        "}\n"
    )
    parsed = (
        parse_file(tmp_path / "BaseApi.java"),
        parse_file(tmp_path / "PetsApi.java"),
        parse_file(controller_file),
    )
    controller_result = parsed[2]
    index = build_interface_method_index(parsed)
    hierarchy = build_interface_hierarchy_index(parsed)

    # Without the hierarchy index, only the single directly-implemented
    # interface (PetsApi, which declares no annotations of its own) is
    # checked - the real gap this fix closes.
    assert detect_in_java(controller_result, index) == ()

    findings = detect_in_java(controller_result, index, hierarchy)

    assert len(findings) == 1
    assert findings[0].identifier == "getPets"


def test_detect_in_java_finds_endpoint_inherited_through_interface_chain_tree_sitter_fallback(
    tmp_path: Path,
) -> None:
    """The same two-hop resolution must hold on the Tree-sitter fallback path."""
    (tmp_path / "BaseApi.java").write_text(_BASE_API_JAVA)
    (tmp_path / "PetsApi.java").write_text(_PETS_API_EXTENDS_BASE_JAVA)
    controller_file = tmp_path / "PetsController.java"
    controller_file.write_text(
        "public class PetsController implements PetsApi {\n"
        "    @Override\n"
        "    public String getPets() {\n"
        "        return switch (1) {\n"
        '            case 1 -> "pets";\n'
        '            default -> "none";\n'
        "        };\n"
        "    }\n"
        "}\n"
    )
    parsed = (
        parse_file(tmp_path / "BaseApi.java"),
        parse_file(tmp_path / "PetsApi.java"),
        parse_file(controller_file),
    )
    controller_result = parsed[2]
    assert controller_result.tree_sitter is not None
    index = build_interface_method_index(parsed)
    hierarchy = build_interface_hierarchy_index(parsed)

    findings = detect_in_java(controller_result, index, hierarchy)

    assert len(findings) == 1
    assert findings[0].identifier == "getPets"


def test_build_interface_hierarchy_index_terminates_on_a_cycle(tmp_path: Path) -> None:
    """Not valid Java (javac rejects a cyclic interface extends chain as a
    compile error), but this indexes untrusted, AI-generated source, which
    must never be assumed well-formed - must terminate, not hang."""
    (tmp_path / "A.java").write_text("public interface A extends B {\n}\n")
    (tmp_path / "B.java").write_text("public interface B extends A {\n}\n")
    parsed = (parse_file(tmp_path / "A.java"), parse_file(tmp_path / "B.java"))

    hierarchy = build_interface_hierarchy_index(parsed)

    assert hierarchy == {"A": ("B",), "B": ("A",)}
    # The resolved closure must still terminate and contain each name once.
    controller_file = tmp_path / "C.java"
    controller_file.write_text("public class C implements A {\n    void m() {}\n}\n")
    c_result = parse_file(controller_file)
    index = build_interface_method_index((*parsed, c_result))

    assert detect_in_java(c_result, index, hierarchy) == ()


def test_build_interface_method_index_is_order_independent_on_colliding_simple_names(
    tmp_path: Path,
) -> None:
    """Two distinct top-level types sharing a simple name (real, not
    hypothetical - confirmed to occur repeatedly in real repositories,
    e.g. multiple unrelated ``UserService`` interfaces in different
    packages) must never let file-processing order decide whether a
    real vulnerability is found. An earlier version of this index let
    whichever declaration was scanned last silently win, which meant
    the exact same source code could either correctly flag or silently
    miss the same unprotected endpoint purely depending on scan order -
    the index must instead exclude the ambiguous name entirely,
    deterministically, regardless of which order the files are given in.
    """
    package_a_dir = tmp_path / "a"
    package_a_dir.mkdir()
    (package_a_dir / "Service.java").write_text(
        "package a;\n"
        "import org.springframework.web.bind.annotation.GetMapping;\n"
        "public interface Service {\n"
        '    @GetMapping("/a")\n'
        "    String run();\n"
        "}\n"
    )
    package_b_dir = tmp_path / "b"
    package_b_dir.mkdir()
    (package_b_dir / "Service.java").write_text(
        "package b;\npublic interface Service {\n    void run();\n}\n"
    )
    controller_file = tmp_path / "Controller.java"
    controller_file.write_text(
        "import a.Service;\n"
        "public class Controller implements Service {\n"
        "    @Override\n"
        "    public String run() {\n"
        '        return "ok";\n'
        "    }\n"
        "}\n"
    )

    a_result = parse_file(package_a_dir / "Service.java")
    b_result = parse_file(package_b_dir / "Service.java")
    controller_result = parse_file(controller_file)

    index_a_first = build_interface_method_index((a_result, b_result, controller_result))
    index_b_first = build_interface_method_index((b_result, a_result, controller_result))

    findings_a_first = detect_in_java(controller_result, index_a_first)
    findings_b_first = detect_in_java(controller_result, index_b_first)

    assert findings_a_first == findings_b_first
    # The ambiguous name is excluded entirely (degrading to pre-feature
    # behavior), not resolved to either candidate's annotations.
    assert findings_a_first == ()


# -- Hand-rolled guard delegated through a same-class helper method ---------
#
# Mirrors the real ai-card-storage-service shape: the comparison isn't
# inline in the endpoint method, it's delegated one hop to a private
# helper - previously a known, deliberately deferred scope limit (see
# IMPLEMENTATION_LOG.md's 2026-09-10 entry).

_HELPER_INDIRECTION_JAVA = (
    "import org.springframework.web.bind.annotation.*;\n"
    "@RestController\n"
    "public class VaultController {\n"
    '    @Value("${VAULT_KEY:}") private String vaultKey;\n'
    "    @PostMapping\n"
    '    public String store(@RequestHeader("X-Vault-Key") String key) {\n'
    "        if (!allowed(key)) {\n"
    '            return "denied";\n'
    "        }\n"
    '        return "ok";\n'
    "    }\n"
    "    private boolean allowed(String suppliedKey) {\n"
    "        return vaultKey.equals(suppliedKey);\n"
    "    }\n"
    "}\n"
)


def test_has_inline_header_guard_detects_helper_call_indirection() -> None:
    tree = javalang.parse.parse(_HELPER_INDIRECTION_JAVA)
    method = _first_method(tree, "store")
    siblings = {("allowed", 1): _first_method(tree, "allowed")}

    assert has_inline_header_guard(method, siblings) is True


def test_has_inline_header_guard_does_not_follow_helper_call_without_sibling_context() -> None:
    """Backward compatibility: a caller with no class context (the default
    empty mapping) must see only the inline case, exactly as before this
    extension existed."""
    tree = javalang.parse.parse(_HELPER_INDIRECTION_JAVA)
    method = _first_method(tree, "store")

    assert has_inline_header_guard(method) is False


def test_has_inline_header_guard_follows_this_qualified_helper_call() -> None:
    """``this.allowed(key)`` must be recognized the same as a bare
    ``allowed(key)`` call - javalang represents a this-qualified call
    differently, and this project has been burned by that exact
    representational variation before (see cwe_287.py's history)."""
    java = _HELPER_INDIRECTION_JAVA.replace("!allowed(key)", "!this.allowed(key)")
    tree = javalang.parse.parse(java)
    method = _first_method(tree, "store")
    siblings = {("allowed", 1): _first_method(tree, "allowed")}

    assert has_inline_header_guard(method, siblings) is True


def test_has_inline_header_guard_does_not_follow_a_call_on_another_object() -> None:
    """A call through a different qualifier (``other.allowed(key)``) is a
    different object's method, not this class's own helper - must not be
    followed, even if a same-named method happens to exist in this class."""
    java = _HELPER_INDIRECTION_JAVA.replace("!allowed(key)", "!other.allowed(key)")
    tree = javalang.parse.parse(java)
    method = _first_method(tree, "store")
    siblings = {("allowed", 1): _first_method(tree, "allowed")}

    assert has_inline_header_guard(method, siblings) is False


def test_has_inline_header_guard_does_not_match_an_unrelated_helper() -> None:
    """A called helper that doesn't compare the forwarded header parameter
    at all must not be mistaken for a guard."""
    java = _HELPER_INDIRECTION_JAVA.replace(
        "return vaultKey.equals(suppliedKey);", "return suppliedKey != null;"
    )
    tree = javalang.parse.parse(java)
    method = _first_method(tree, "store")
    siblings = {("allowed", 1): _first_method(tree, "allowed")}

    assert has_inline_header_guard(method, siblings) is False


def test_detect_in_java_and_apply_hand_rolled_guard_context_cover_helper_indirection(
    tmp_path: Path,
) -> None:
    """End-to-end through the real per-file wiring (_hand_rolled_guard_methods
    builds the sibling map itself), not just the inner function with a
    hand-built mapping."""
    java_file = tmp_path / "VaultController.java"
    java_file.write_text(_HELPER_INDIRECTION_JAVA)

    result = parse_file(java_file)
    findings = detect_in_java(result)
    assert {f.identifier for f in findings} == {"store"}

    annotated = apply_hand_rolled_guard_context(findings, (result,))

    assert "hand-rolled authorization check" in annotated[0].message


def test_has_inline_header_guard_helper_indirection_tree_sitter_fallback(
    tmp_path: Path,
) -> None:
    """The same helper-indirection resolution must hold on the Tree-sitter
    fallback path."""
    java_file = tmp_path / "VaultController.java"
    java_file.write_text(
        "import org.springframework.web.bind.annotation.*;\n"
        "@RestController\n"
        "public class VaultController {\n"
        '    @Value("${VAULT_KEY:}") private String vaultKey;\n'
        "    int helper(int level) {\n"
        "        return switch (level) {\n"
        "            case 1 -> 1;\n"
        "            default -> 0;\n"
        "        };\n"
        "    }\n"
        "    @PostMapping\n"
        '    public String store(@RequestHeader("X-Vault-Key") String key) {\n'
        "        if (!allowed(key)) {\n"
        '            return "denied";\n'
        "        }\n"
        '        return "ok";\n'
        "    }\n"
        "    private boolean allowed(String suppliedKey) {\n"
        "        return vaultKey.equals(suppliedKey);\n"
        "    }\n"
        "}\n"
    )

    result = parse_file(java_file)
    assert result.tree_sitter is not None
    findings = detect_in_java(result)
    assert {f.identifier for f in findings} == {"store"}

    annotated = apply_hand_rolled_guard_context(findings, (result,))

    assert "hand-rolled authorization check" in annotated[0].message


# -- Chained-call and overload false positives -------------------------------
#
# Found by independent QA of the helper-indirection feature above: both bugs
# reproduced here are false positives in the caveat text only (never a
# suppression, never a scoring/ML change - the underlying CWE-284 finding is
# always still raised), but they violate the feature's own stated "must not
# be followed" guarantees.


def _method_with_arity(
    tree: javalang.tree.CompilationUnit, name: str, parameter_count: int
) -> javalang.tree.MethodDeclaration:
    for _path, method in tree.filter(javalang.tree.MethodDeclaration):
        if method.name == name and len(method.parameters) == parameter_count:
            return method
    raise AssertionError(f"no method named {name!r} with {parameter_count} parameter(s)")


def test_has_inline_header_guard_does_not_follow_a_call_chained_off_another_call() -> None:
    """``getHelper().allowed(key)`` must not be mistaken for a same-class
    ``allowed(key)`` call - javalang gives the chained call's own
    ``qualifier`` the same ``None`` value as a genuinely bare call; the
    chain information lives only in ``getHelper()``'s own ``selectors``
    list. ``Helper.allowed`` (the method actually invoked) performs no
    real check at all; ``VaultController.allowed`` (the same-named
    same-class method) is never actually called here."""
    java = (
        "import org.springframework.web.bind.annotation.*;\n"
        "@RestController\n"
        "public class VaultController {\n"
        '    @Value("${VAULT_KEY:}") private String vaultKey;\n'
        "    @PostMapping\n"
        '    public String store(@RequestHeader("X-Key") String key) {\n'
        "        if (!getHelper().allowed(key)) {\n"
        '            return "denied";\n'
        "        }\n"
        '        return "ok";\n'
        "    }\n"
        "    private Helper getHelper() { return new Helper(); }\n"
        "    private boolean allowed(String suppliedKey) {\n"
        "        return vaultKey.equals(suppliedKey);\n"
        "    }\n"
        "}\n"
    )
    tree = javalang.parse.parse(java)
    method = _first_method(tree, "store")
    siblings = {
        ("getHelper", 0): _method_with_arity(tree, "getHelper", 0),
        ("allowed", 1): _method_with_arity(tree, "allowed", 1),
    }

    assert has_inline_header_guard(method, siblings) is False


def test_has_inline_header_guard_does_not_follow_a_this_qualified_chained_call() -> None:
    """``this.getHelper().allowed(key)`` must likewise not be followed -
    ``allowed`` here is invoked on ``getHelper()``'s return value, not
    directly on ``this``, even though both calls share the same flattened
    ``This.selectors`` list."""
    java = (
        "import org.springframework.web.bind.annotation.*;\n"
        "@RestController\n"
        "public class VaultController {\n"
        '    @Value("${VAULT_KEY:}") private String vaultKey;\n'
        "    @PostMapping\n"
        '    public String store(@RequestHeader("X-Key") String key) {\n'
        "        if (!this.getHelper().allowed(key)) {\n"
        '            return "denied";\n'
        "        }\n"
        '        return "ok";\n'
        "    }\n"
        "    private Helper getHelper() { return new Helper(); }\n"
        "    private boolean allowed(String suppliedKey) {\n"
        "        return vaultKey.equals(suppliedKey);\n"
        "    }\n"
        "}\n"
    )
    tree = javalang.parse.parse(java)
    method = _first_method(tree, "store")
    siblings = {
        ("getHelper", 0): _method_with_arity(tree, "getHelper", 0),
        ("allowed", 1): _method_with_arity(tree, "allowed", 1),
    }

    assert has_inline_header_guard(method, siblings) is False


def test_detect_in_java_does_not_raise_a_hand_rolled_guard_caveat_for_a_chained_helper_call(
    tmp_path: Path,
) -> None:
    """End-to-end through the real per-file wiring, matching QA's exact
    reproduction: the finding is still raised (CWE-284 never suppresses),
    but it must carry no false "hand-rolled authorization check" caveat."""
    java_file = tmp_path / "VaultController.java"
    java_file.write_text(
        "import org.springframework.web.bind.annotation.*;\n"
        "@RestController\n"
        "public class VaultController {\n"
        '    @Value("${VAULT_KEY:}") private String vaultKey;\n'
        "    @PostMapping\n"
        '    public String store(@RequestHeader("X-Key") String key) {\n'
        "        if (!getHelper().allowed(key)) {\n"
        '            return "denied";\n'
        "        }\n"
        '        return "ok";\n'
        "    }\n"
        "    private Helper getHelper() { return new Helper(); }\n"
        "    private boolean allowed(String suppliedKey) {\n"
        "        return vaultKey.equals(suppliedKey);\n"
        "    }\n"
        "}\n"
    )

    result = parse_file(java_file)
    findings = detect_in_java(result)
    assert {f.identifier for f in findings} == {"store"}

    annotated = apply_hand_rolled_guard_context(findings, (result,))

    assert "hand-rolled authorization check" not in annotated[0].message


def test_has_inline_header_guard_resolves_the_overload_actually_invoked() -> None:
    """A one-argument call to ``allowed(key)`` must resolve to the
    one-argument overload actually invoked, not a same-named two-argument
    overload declared later in the file. The one-argument overload here
    performs no real check at all; only the (uninvoked) two-argument
    overload does."""
    java = (
        "import org.springframework.web.bind.annotation.*;\n"
        "@RestController\n"
        "public class VaultController {\n"
        '    @Value("${VAULT_KEY:}") private String vaultKey;\n'
        "    @PostMapping\n"
        '    public String store(@RequestHeader("X-Key") String key) {\n'
        "        if (!allowed(key)) {\n"
        '            return "denied";\n'
        "        }\n"
        '        return "ok";\n'
        "    }\n"
        "    private boolean allowed(String suppliedKey) { return true; }\n"
        "    private boolean allowed(String a, String b) {\n"
        "        return vaultKey.equals(a);\n"
        "    }\n"
        "}\n"
    )
    tree = javalang.parse.parse(java)
    method = _first_method(tree, "store")
    siblings = {
        ("allowed", 1): _method_with_arity(tree, "allowed", 1),
        ("allowed", 2): _method_with_arity(tree, "allowed", 2),
    }

    assert has_inline_header_guard(method, siblings) is False


def test_has_inline_header_guard_overload_resolution_tree_sitter_fallback(
    tmp_path: Path,
) -> None:
    """The same overload-by-arity resolution must hold on the Tree-sitter
    fallback path."""
    java_file = tmp_path / "VaultController.java"
    java_file.write_text(
        "import org.springframework.web.bind.annotation.*;\n"
        "@RestController\n"
        "public class VaultController {\n"
        '    @Value("${VAULT_KEY:}") private String vaultKey;\n'
        "    int helper(int level) {\n"
        "        return switch (level) {\n"
        "            case 1 -> 1;\n"
        "            default -> 0;\n"
        "        };\n"
        "    }\n"
        "    @PostMapping\n"
        '    public String store(@RequestHeader("X-Key") String key) {\n'
        "        if (!allowed(key)) {\n"
        '            return "denied";\n'
        "        }\n"
        '        return "ok";\n'
        "    }\n"
        "    private boolean allowed(String suppliedKey) { return true; }\n"
        "    private boolean allowed(String a, String b) {\n"
        "        return vaultKey.equals(a);\n"
        "    }\n"
        "}\n"
    )

    result = parse_file(java_file)
    assert result.tree_sitter is not None
    findings = detect_in_java(result)
    assert {f.identifier for f in findings} == {"store"}

    annotated = apply_hand_rolled_guard_context(findings, (result,))

    assert "hand-rolled authorization check" not in annotated[0].message
