"""Tests for vibeguard.layer1_static.rules.cwe_284."""

from __future__ import annotations

from pathlib import Path

from vibeguard.layer1_static.ast_parser import parse_file
from vibeguard.layer1_static.rules.cwe_284 import (
    CWE_ID,
    apply_centralized_authorization_context,
    detect_in_java,
    has_centralized_authorization_rule,
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
