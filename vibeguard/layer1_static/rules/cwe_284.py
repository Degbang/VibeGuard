"""CWE-284: Improper Access Control.

Flags REST endpoint methods (identified by common JAX-RS/Spring
request-mapping annotations) that carry no authorization annotation at
all, at either the method or the nearest enclosing class/interface
level. Walks ``ParsedFile.tree`` directly via javalang's
``.filter(MethodDeclaration)`` rather than the flattened
``ParsedFile.classes`` summary: that summary only represents top-level
types (see ``ast_parser.ParsedClass``'s docstring), so a method inside
a nested/inner/anonymous class would be entirely invisible to this
rule if it only looked there - a real false negative found and fixed
during adversarial testing, see IMPLEMENTATION_LOG.md.

Deliberately narrow scope for a first pass: this detects *missing*
access control, not *misconfigured* access control. An endpoint
carrying an explicit ``@PermitAll`` is a deliberate access-control
decision, not an instance of this CWE, even if that decision might be
questionable on a sensitive-sounding endpoint - judging whether a
specific role/policy is *appropriate* would need semantic understanding
of the application's authorization model that static analysis alone
can't provide. This rule only asks "was an access-control decision
made at all," not "was it the right one."
"""

from __future__ import annotations

import dataclasses
from collections.abc import Iterable, Mapping
from pathlib import Path

import javalang
from tree_sitter import Node

from vibeguard.layer1_static._tree_sitter_java import (
    annotation_names as ts_annotation_names,
)
from vibeguard.layer1_static._tree_sitter_java import (
    child_by_field as ts_child_by_field,
)
from vibeguard.layer1_static._tree_sitter_java import (
    declaration_name as ts_declaration_name,
)
from vibeguard.layer1_static._tree_sitter_java import (
    named_children as ts_named_children,
)
from vibeguard.layer1_static._tree_sitter_java import (
    nearest_enclosing_type as ts_nearest_enclosing_type,
)
from vibeguard.layer1_static._tree_sitter_java import (
    node_line as ts_node_line,
)
from vibeguard.layer1_static._tree_sitter_java import (
    node_text as ts_node_text,
)
from vibeguard.layer1_static._tree_sitter_java import (
    type_name as ts_type_name,
)
from vibeguard.layer1_static._tree_sitter_java import (
    walk as ts_walk,
)
from vibeguard.layer1_static._tree_sitter_java import (
    walk_with_ancestors as ts_walk_with_ancestors,
)
from vibeguard.layer1_static.ast_parser import ParsedFile
from vibeguard.layer1_static.rules._authorization_annotations import has_authorization_annotation
from vibeguard.layer1_static.rules._endpoint_annotations import (
    has_endpoint_annotation,
    simple_name,
)
from vibeguard.layer1_static.rules._finding import Finding
from vibeguard.layer1_static.rules._interface_annotations import (
    EMPTY_INTERFACE_HIERARCHY,
    EMPTY_INTERFACE_INDEX,
    InterfaceHierarchy,
    InterfaceMethodAnnotations,
    interface_annotations_for_method,
    nearest_enclosing_type,
    resolve_effective_annotations,
    top_level_interfaces_by_type_name,
)

CWE_ID = "CWE-284"

# A project that centralizes authorization in a Spring Security
# SecurityFilterChain bean (http.authorizeHttpRequests().anyRequest()...)
# makes an application-wide access-control decision that per-method/
# per-class annotation checks below cannot see at all - see
# has_centralized_authorization_rule's docstring and IMPLEMENTATION_LOG.md
# for a real example found by scanning a real Spring Boot application.
_SECURITY_FILTER_CHAIN_RETURN_TYPE = "SecurityFilterChain"
_ANY_REQUEST_CALL = "anyRequest"
_BLANKET_AUTHORIZATION_CALLS = frozenset({"authenticated", "permitAll", "denyAll"})

# The now-deprecated (removed in Spring Security 6) WebSecurityConfigurerAdapter
# base class configures authorization inside a void-returning `configure`
# override rather than a bean method returning SecurityFilterChain - a
# real, still extremely common pattern in Spring Security 5.x-era code,
# found scanning a real repository (IMPLEMENTATION_LOG.md 2026-09-04).
# Matched by method name and single-parameter type only - the same
# coarse, name-based precision as everything else in this module - not by
# checking the enclosing class actually extends WebSecurityConfigurerAdapter,
# since that exact signature is unambiguous enough in practice on its own.
_LEGACY_CONFIGURE_METHOD_NAME = "configure"
_HTTP_SECURITY_PARAM_TYPE = "HttpSecurity"
_CENTRALIZED_AUTH_CAVEAT = (
    "Note: this project also declares centralized Spring Security configuration "
    "(a SecurityFilterChain bean or a WebSecurityConfigurerAdapter override) "
    "with a project-wide '.anyRequest()' authorization rule elsewhere - this "
    "endpoint may already be covered by that rule depending on path-matching "
    "and runtime configuration (e.g. a conditional property) that is not "
    "visible to static analysis."
)

# The dominant real-world pattern this rule cannot otherwise see at all:
# AI-generated Java microservices overwhelmingly protect an endpoint by
# hand (compare a caller-supplied header against a configured value, bail
# out on mismatch) rather than with a framework annotation - roughly 19 of
# 20 real protection mechanisms observed across this project's AI-generated
# sample batches take this shape, not Spring Security. See
# has_inline_header_guard's docstring and IMPLEMENTATION_LOG.md's
# 2026-09-10 entry for the real examples this was built against.
_EQUALITY_COMPARISON_METHODS = frozenset({"equals", "contentEquals", "isEqual"})
_HAND_ROLLED_GUARD_CAVEAT = (
    "Note: this endpoint method itself contains a conditional check comparing "
    "a caller-supplied header against another value before continuing (a "
    "hand-rolled authorization check) - this rule cannot verify whether that "
    "check is correct, complete, or even authorization-related, only that no "
    "framework authorization annotation covers it."
)

# An interface's routing annotation (@GetMapping etc.) on a method a
# concrete class @Overrides is always resolved by Spring MVC regardless
# of proxy style - a documented, proxy-independent framework feature, so
# widening endpoint recognition with it (see resolve_effective_annotations)
# is safe to do unconditionally. An interface's *authorization* annotation
# (@PreAuthorize etc.) is a different, AOP-based mechanism whose actual
# enforcement depends on whether Spring is using interface-based JDK
# dynamic proxies (honors it) or CGLIB class proxies (Spring Boot's
# default; typically does not) - not visible to static analysis, so this
# rule adds an honest caveat rather than silently trusting it to suppress
# a finding, the same fail-closed discipline as the two caveats above.
# See IMPLEMENTATION_LOG.md and spring-petclinic-rest's OwnersApi/
# OwnerRestControllerV1 pair for the real pattern this was built against.
_INTERFACE_AUTHORIZATION_CAVEAT = (
    "Note: an implemented interface's matching method carries an authorization "
    "annotation (e.g. @PreAuthorize) not repeated on this concrete override - "
    "whether Spring actually enforces it here depends on the proxy style in use "
    "(interface-based JDK dynamic proxies typically honor an interface-declared "
    "method-security annotation; CGLIB class proxies, Spring Boot's default, "
    "typically do not), which is not visible to static analysis."
)

_HTTP_CLIENT_TYPE_ANNOTATIONS = frozenset(
    {
        "RegisterRestClient",  # Quarkus / MicroProfile REST client
        "FeignClient",  # Spring OpenFeign client
    }
)


def detect_in_java(
    parsed_file: ParsedFile,
    interface_annotations: InterfaceMethodAnnotations = EMPTY_INTERFACE_INDEX,
    interface_hierarchy: InterfaceHierarchy = EMPTY_INTERFACE_HIERARCHY,
) -> tuple[Finding, ...]:
    """Find endpoint methods with no authorization annotation anywhere in scope.

    An authorization annotation on the *nearest enclosing* class/
    interface covers a method that doesn't itself carry one (the
    common "secure by default, opt out per-endpoint" pattern) - only
    the nearest enclosing type is checked, not every ancestor, since
    annotations on an outer class don't apply to a nested class's own
    members in JAX-RS/Spring's actual runtime behavior.

    Args:
        parsed_file: One successfully-parsed Java file.
        interface_annotations: A project-wide index (see
            ``_interface_annotations.build_interface_method_index``) used
            to recognise an endpoint/authorization annotation declared
            only on an implemented interface's matching method - e.g. a
            Spring codegen-interface controller whose concrete
            ``@Override`` method carries neither annotation itself.
            Defaults to an empty index, so a single-file call sees
            exactly the method/enclosing-class-only behavior described
            above with no cross-file information.
        interface_hierarchy: A project-wide index (see
            ``_interface_annotations.build_interface_hierarchy_index``)
            used to walk past a directly-implemented interface to
            whatever *that* interface itself extends, so an annotation
            declared two or more interface hops away is still found.
            Defaults to empty, so a single-file call sees only the
            single directly-implemented interface.
    """
    if parsed_file.tree_sitter is not None:
        return _detect_in_tree_sitter_java(parsed_file, interface_annotations, interface_hierarchy)
    if parsed_file.tree is None:
        return ()

    interfaces_by_type_name = top_level_interfaces_by_type_name(parsed_file, interface_hierarchy)
    findings = [
        finding
        for path, node in parsed_file.tree.filter(javalang.tree.MethodDeclaration)
        if (
            finding := _check_method(
                parsed_file.path, node, path, interfaces_by_type_name, interface_annotations
            )
        )
        is not None
    ]
    return tuple(findings)


def _detect_in_tree_sitter_java(
    parsed_file: ParsedFile,
    interface_annotations: InterfaceMethodAnnotations,
    interface_hierarchy: InterfaceHierarchy = EMPTY_INTERFACE_HIERARCHY,
) -> tuple[Finding, ...]:
    """Find unprotected endpoints in a Tree-sitter fallback parse."""
    parsed = parsed_file.tree_sitter
    if parsed is None:
        return ()
    interfaces_by_type_name = top_level_interfaces_by_type_name(parsed_file, interface_hierarchy)
    findings = [
        finding
        for ancestors, node in ts_walk_with_ancestors(parsed.tree.root_node)
        if node.type == "method_declaration"
        if (
            finding := _check_tree_sitter_method(
                parsed_file.path,
                parsed.source,
                node,
                ancestors,
                interfaces_by_type_name,
                interface_annotations,
            )
        )
        is not None
    ]
    return tuple(findings)


def _check_tree_sitter_method(
    file_path: Path,
    source: bytes,
    method: Node,
    ancestors: tuple[Node, ...],
    interfaces_by_type_name: Mapping[str, tuple[str, ...]],
    interface_annotations: InterfaceMethodAnnotations,
) -> Finding | None:
    own_method_annotations = ts_annotation_names(source, method)
    enclosing_type = ts_nearest_enclosing_type(ancestors)
    method_name = ts_declaration_name(source, method)
    enclosing_type_name = (
        ts_declaration_name(source, enclosing_type) if enclosing_type is not None else None
    )
    implemented_interfaces = (
        interfaces_by_type_name.get(enclosing_type_name, ()) if enclosing_type_name else ()
    )
    # Endpoint-routing annotations inherited from an interface are always
    # safe to widen with (see resolve_effective_annotations's docstring) -
    # only authorization is treated asymmetrically, below.
    effective_endpoint_annotations = resolve_effective_annotations(
        own_method_annotations, implemented_interfaces, method_name, interface_annotations
    )
    if not has_endpoint_annotation(effective_endpoint_annotations):
        return None
    if has_authorization_annotation(own_method_annotations):
        return None
    if enclosing_type is not None:
        type_annotations = ts_annotation_names(source, enclosing_type)
        if _is_http_client_type(type_annotations):
            return None
        if has_authorization_annotation(type_annotations):
            return None
    message = (
        f"Endpoint method '{method_name}' has no authorization annotation "
        "(no @RolesAllowed/@PermitAll/@Secured/@PreAuthorize/... on the "
        "method or its enclosing class)"
    )
    interface_auth_annotations = interface_annotations_for_method(
        implemented_interfaces, method_name, interface_annotations
    )
    if has_authorization_annotation(interface_auth_annotations):
        message = f"{message} {_INTERFACE_AUTHORIZATION_CAVEAT}"
    return Finding(
        cwe_id=CWE_ID,
        file_path=file_path,
        line=ts_node_line(method),
        identifier=method_name,
        message=message,
    )


def _check_method(
    file_path: Path,
    method: javalang.tree.MethodDeclaration,
    path: tuple[object, ...],
    interfaces_by_type_name: Mapping[str, tuple[str, ...]],
    interface_annotations: InterfaceMethodAnnotations,
) -> Finding | None:
    """Build a Finding if this method is an unprotected endpoint."""
    own_method_annotations = tuple(a.name for a in method.annotations)
    enclosing_type = nearest_enclosing_type(path)
    implemented_interfaces = (
        interfaces_by_type_name.get(enclosing_type.name, ()) if enclosing_type is not None else ()
    )
    # Endpoint-routing annotations inherited from an interface are always
    # safe to widen with (see resolve_effective_annotations's docstring) -
    # only authorization is treated asymmetrically, below.
    effective_endpoint_annotations = resolve_effective_annotations(
        own_method_annotations, implemented_interfaces, method.name, interface_annotations
    )
    if not has_endpoint_annotation(effective_endpoint_annotations):
        return None
    if has_authorization_annotation(own_method_annotations):
        return None
    if enclosing_type is not None:
        type_annotations = tuple(a.name for a in enclosing_type.annotations)
        if _is_http_client_type(type_annotations):
            return None
        if has_authorization_annotation(type_annotations):
            return None
    line = method.position.line if method.position else None
    message = (
        f"Endpoint method '{method.name}' has no authorization annotation "
        "(no @RolesAllowed/@PermitAll/@Secured/@PreAuthorize/... on the "
        "method or its enclosing class)"
    )
    interface_auth_annotations = interface_annotations_for_method(
        implemented_interfaces, method.name, interface_annotations
    )
    if has_authorization_annotation(interface_auth_annotations):
        message = f"{message} {_INTERFACE_AUTHORIZATION_CAVEAT}"
    return Finding(
        cwe_id=CWE_ID,
        file_path=file_path,
        line=line,
        identifier=method.name,
        message=message,
    )


def _is_http_client_type(annotations: tuple[str, ...]) -> bool:
    """Whether a type is an outbound HTTP client, not an inbound endpoint class."""
    return any(simple_name(a) in _HTTP_CLIENT_TYPE_ANNOTATIONS for a in annotations)


def has_centralized_authorization_rule(parsed_file: ParsedFile) -> bool:
    """Whether this file declares a Spring Security SecurityFilterChain bean
    with a blanket, application-wide authorization rule - ``.anyRequest()``
    followed by ``.authenticated()``/``.permitAll()``/``.denyAll()``.

    This is a coarse, name-based signal, the same kind of pattern match
    every other check in this module makes - not a semantic understanding
    of Spring Security's path-matching precedence, and not aware of
    whether a conditional property (e.g. ``@ConditionalOnProperty``)
    actually activates this bean at runtime. Scanning the real
    spring-petclinic-rest application found exactly this: a
    SecurityFilterChain with ``anyRequest().authenticated()`` covers an
    endpoint this rule would otherwise call unprotected, while a second,
    differently-conditional SecurityFilterChain elsewhere in the same
    project sets ``anyRequest().permitAll()`` - which one is actually
    active depends on a property value that does not exist in source
    code at all until something sets it at deploy time. Static analysis
    cannot resolve that either way, so this signal is used to add an
    explicit caveat to a finding (see ``apply_centralized_authorization_context``),
    never to silently drop it - a security tool that hides a candidate
    finding because of a coarse, best-effort heuristic is worse than one
    that flags too much.
    """
    if parsed_file.tree_sitter is not None:
        return _has_centralized_rule_tree_sitter(parsed_file)
    if parsed_file.tree is None:
        return False
    for _path, method in parsed_file.tree.filter(javalang.tree.MethodDeclaration):
        if not _has_blanket_authorization_call(method):
            continue
        if _returns_security_filter_chain(method) or _is_legacy_web_security_configure_method(
            method
        ):
            return True
    return False


def _returns_security_filter_chain(method: javalang.tree.MethodDeclaration) -> bool:
    return getattr(method.return_type, "name", None) == _SECURITY_FILTER_CHAIN_RETURN_TYPE


def _is_legacy_web_security_configure_method(method: javalang.tree.MethodDeclaration) -> bool:
    if method.name != _LEGACY_CONFIGURE_METHOD_NAME:
        return False
    if len(method.parameters) != 1:
        return False
    param_type = getattr(method.parameters[0].type, "name", None)
    return param_type == _HTTP_SECURITY_PARAM_TYPE


def _has_blanket_authorization_call(method: javalang.tree.MethodDeclaration) -> bool:
    invocation_members = {
        node.member for _path, node in method.filter(javalang.tree.MethodInvocation)
    }
    return _ANY_REQUEST_CALL in invocation_members and bool(
        invocation_members & _BLANKET_AUTHORIZATION_CALLS
    )


def _has_centralized_rule_tree_sitter(parsed_file: ParsedFile) -> bool:
    parsed = parsed_file.tree_sitter
    if parsed is None:
        return False
    for node in ts_walk(parsed.tree.root_node):
        if node.type != "method_declaration":
            continue
        if not _is_tree_sitter_centralizing_method(parsed.source, node):
            continue
        invocation_names = {
            ts_node_text(parsed.source, name_node)
            for child in ts_walk(node)
            if child.type == "method_invocation"
            for name_node in (ts_child_by_field(child, "name"),)
            if name_node is not None
        }
        if (
            _ANY_REQUEST_CALL in invocation_names
            and invocation_names & _BLANKET_AUTHORIZATION_CALLS
        ):
            return True
    return False


def _is_tree_sitter_centralizing_method(source: bytes, method: Node) -> bool:
    """Whether ``method`` is a plausible centralized-authorization declaration site.

    Either a ``SecurityFilterChain``-returning bean method (the current
    Spring Security style) or a legacy ``configure(HttpSecurity)``
    override - see ``_is_legacy_web_security_configure_method``'s
    docstring for why the latter is matched by signature alone.
    """
    return_type_node = ts_child_by_field(method, "type")
    if (
        return_type_node is not None
        and ts_type_name(source, return_type_node) == _SECURITY_FILTER_CHAIN_RETURN_TYPE
    ):
        return True
    name_node = ts_child_by_field(method, "name")
    if name_node is None or ts_node_text(source, name_node) != _LEGACY_CONFIGURE_METHOD_NAME:
        return False
    parameters_node = ts_child_by_field(method, "parameters")
    if parameters_node is None:
        return False
    parameters = ts_named_children(parameters_node)
    if len(parameters) != 1:
        return False
    param_type_node = ts_child_by_field(parameters[0], "type")
    return (
        param_type_node is not None
        and ts_type_name(source, param_type_node) == _HTTP_SECURITY_PARAM_TYPE
    )


def apply_centralized_authorization_context(
    findings: tuple[Finding, ...], parsed_files: Iterable[ParsedFile]
) -> tuple[Finding, ...]:
    """Append a caveat to every CWE-284 finding when the scan also found a
    centralized Spring Security authorization rule somewhere in the project.

    Findings are never dropped or hidden by this: only their message gains
    an explicit caveat, so this stays fail-closed - a reader still sees
    every candidate, with an honest note about what static analysis could
    not resolve, rather than a finding silently disappearing because of a
    coarse, project-wide heuristic.

    Args:
        findings: All findings from a scan (not just CWE-284's) - findings
            for other CWEs pass through unchanged.
        parsed_files: Every successfully-parsed Java file from the same
            scan, checked for the centralized-authorization pattern.

    Returns:
        The same findings, with CWE-284 messages annotated if applicable.
    """
    if not any(has_centralized_authorization_rule(pf) for pf in parsed_files):
        return findings
    return tuple(
        (
            dataclasses.replace(finding, message=f"{finding.message} {_CENTRALIZED_AUTH_CAVEAT}")
            if finding.cwe_id == CWE_ID
            else finding
        )
        for finding in findings
    )


_EMPTY_SIBLING_METHODS: Mapping[tuple[str, int], javalang.tree.MethodDeclaration] = {}


def has_inline_header_guard(
    method: javalang.tree.MethodDeclaration,
    sibling_methods_by_name: Mapping[
        tuple[str, int], javalang.tree.MethodDeclaration
    ] = _EMPTY_SIBLING_METHODS,
) -> bool:
    """Whether this method itself compares an ``@RequestHeader`` parameter
    against another value via ``.equals()``/``.contentEquals()``/
    ``MessageDigest.isEqual()``, on a branch that bails out (``return``/
    ``throw``) - the dominant hand-rolled authorization shape this
    project's AI-generated sample batches converge on (see
    IMPLEMENTATION_LOG.md's 2026-09-10 entry): a caller-supplied header
    checked against a configured value, e.g.
    ``if (!adminKey.equals(supplied)) return ResponseEntity.status(401).build();``.

    Deliberately requires the comparison to actually reference one of the
    method's own ``@RequestHeader`` parameters by name - a config value's
    plain blank-check (``if (providerApiKey.isBlank()) ...``, which never
    compares against anything the caller supplied) is not an
    authorization check at all and must not match here. Does not verify
    the *other* side of the comparison is genuinely config-sourced (e.g.
    an ``@Value``-annotated field) - the same coarse, name/shape-based
    precision every other check in this module already uses, not a
    symbol-table cross-reference.

    Args:
        method: The candidate endpoint method.
        sibling_methods_by_name: Other methods declared directly in this
            method's own enclosing class (see ``_sibling_methods_by_name``),
            used to resolve a guard delegated one hop to a private helper
            method (``if (!allowed(key)) ...`` where ``allowed`` does the
            actual comparison) - a real shape found in this project's
            AI-generated dataset (``ai-card-storage-service``), previously
            a known, deliberately deferred scope limit. Defaults to empty,
            so a caller with no class context sees only the inline case.
    """
    header_params = _endpoint_header_param_names(method)
    if not header_params:
        return False
    for _path, if_statement in method.filter(javalang.tree.IfStatement):
        if not _bails_out(if_statement.then_statement):
            continue
        if _references_header_comparison(if_statement.condition, header_params):
            return True
        if _bails_out_via_helper_call(
            if_statement.condition, header_params, sibling_methods_by_name
        ):
            return True
    return False


def _sibling_methods_by_name(
    path: tuple[object, ...],
) -> Mapping[tuple[str, int], javalang.tree.MethodDeclaration]:
    """Other methods declared directly in this method's nearest enclosing
    class - its own direct members only, not inherited or nested further,
    the same bounded scope as the rest of this module's hand-rolled-guard
    detection. Used to resolve a one-hop helper-method call; see
    ``_bails_out_via_helper_call``.

    Keyed by ``(name, parameter_count)``, not name alone: a plain
    name-keyed dict silently clobbers same-named overloads (whichever is
    declared last wins), which can resolve a call to an overload that
    isn't actually the one invoked at the call site - found by independent
    QA, confirmed to manufacture a false "may be guarded" caveat for an
    endpoint whose actually-invoked overload performs no check at all.
    """
    enclosing_type = nearest_enclosing_type(path)
    if enclosing_type is None:
        return {}
    return {
        (member.name, len(member.parameters)): member
        for member in enclosing_type.body
        if isinstance(member, javalang.tree.MethodDeclaration)
    }


def _is_bare_or_this_invocation(
    node: javalang.tree.MethodInvocation, path: tuple[object, ...]
) -> bool:
    """Whether ``node`` is called with no explicit receiver (``allowed(key)``)
    or directly on ``this`` (``this.allowed(key)``), as opposed to being
    chained onto some other expression's return value
    (``getHelper().allowed(key)``).

    javalang gives a chained call's own ``qualifier`` field the same
    ``None`` value as a genuinely bare call - the chain information lives
    only in the *owning* node's ``selectors`` list, which flattens an
    entire fluent chain (``a().b().c()``) into siblings of a single list
    rather than nesting each call inside the previous one's own
    ``selectors``. So only the first element of a ``This`` node's
    ``selectors`` is actually invoked on ``this`` itself; every other
    element - and every element of any other node's ``selectors`` - is
    invoked on whatever the previous call in the chain returned. Found by
    independent QA: the previous version of this check only looked at
    ``qualifier`` and so treated ``getHelper().allowed(key)`` exactly like
    a genuine same-class ``allowed(key)`` call.
    """
    if node.qualifier not in (None, ""):
        return False
    if len(path) < 2:
        return True
    owner, container = path[-2], path[-1]
    if container is not getattr(owner, "selectors", None):
        return True  # not chained at all - a true bare call
    if not isinstance(owner, javalang.tree.This):
        return False  # chained off some other call's return value, not `this`
    return bool(owner.selectors) and owner.selectors[0] is node


def _bails_out_via_helper_call(
    condition: object,
    header_params: frozenset[str],
    sibling_methods_by_name: Mapping[tuple[str, int], javalang.tree.MethodDeclaration],
) -> bool:
    """Whether ``condition`` calls a same-class helper method with a header
    parameter as an argument, where that helper itself compares its own
    corresponding parameter via an equality check - one hop of indirection
    beyond ``_references_header_comparison``'s direct, inline case.

    Only a bare (``allowed(key)``) or ``this``-qualified (``this.allowed(key)``)
    call counts - a call through any other qualifier
    (``other.allowed(key)``), or chained onto another call's return value
    (``getHelper().allowed(key)``), is not this class's own direct helper
    call and is correctly not followed (see ``_is_bare_or_this_invocation``).
    The helper is resolved by ``(name, argument count)``, not name alone,
    so a same-named overload that isn't actually the one being called is
    never mistaken for it.
    """
    if not hasattr(condition, "filter"):
        return False
    for path, invocation in condition.filter(javalang.tree.MethodInvocation):
        if not _is_bare_or_this_invocation(invocation, path):
            continue
        helper = sibling_methods_by_name.get((invocation.member, len(invocation.arguments)))
        if helper is None:
            continue
        for index, arg in enumerate(invocation.arguments):
            if index >= len(helper.parameters):
                continue
            if not _argument_references_header(arg, header_params):
                continue
            helper_param_name = helper.parameters[index].name
            if _references_header_comparison(helper, frozenset({helper_param_name})):
                return True
    return False


def _endpoint_header_param_names(method: javalang.tree.MethodDeclaration) -> frozenset[str]:
    """Names of this method's ``@RequestHeader``-annotated parameters."""
    return frozenset(
        param.name
        for param in method.parameters
        if any(simple_name(a.name) == "RequestHeader" for a in param.annotations)
    )


def _bails_out(statement: object) -> bool:
    """Whether ``statement`` (an if-branch's body) contains a return or throw."""
    if not hasattr(statement, "filter"):
        return False
    return any(True for _ in statement.filter(javalang.tree.ReturnStatement)) or any(
        True for _ in statement.filter(javalang.tree.ThrowStatement)
    )


def _references_header_comparison(condition: object, header_params: frozenset[str]) -> bool:
    """Whether an equality comparison anywhere in ``condition`` references a header param.

    A comparison operand can be the header parameter directly
    (``adminKey.equals(supplied)``) or a method called on it
    (``MessageDigest.isEqual(key.getBytes(), supplied.getBytes())`` -
    ``isEqual`` takes ``byte[]``, so a bare ``String`` header parameter
    can only appear this way, and this is the realistic, idiomatic shape
    for a constant-time comparison, not an edge case to skip).
    """
    if not hasattr(condition, "filter"):
        return False
    for _path, invocation in condition.filter(javalang.tree.MethodInvocation):
        if invocation.member not in _EQUALITY_COMPARISON_METHODS:
            continue
        if isinstance(invocation.qualifier, str) and invocation.qualifier in header_params:
            return True
        if any(_argument_references_header(arg, header_params) for arg in invocation.arguments):
            return True
    return False


def _argument_references_header(arg: object, header_params: frozenset[str]) -> bool:
    if isinstance(arg, javalang.tree.MemberReference):
        return arg.member in header_params
    if isinstance(arg, javalang.tree.MethodInvocation):
        return isinstance(arg.qualifier, str) and arg.qualifier in header_params
    return False


def _hand_rolled_guard_methods(parsed_file: ParsedFile) -> frozenset[tuple[str, int]]:
    """Return ``(method_name, line)`` for this file's methods with an inline header guard."""
    if parsed_file.tree_sitter is not None:
        return _hand_rolled_guard_methods_tree_sitter(parsed_file)
    if parsed_file.tree is None:
        return frozenset()
    guarded: set[tuple[str, int]] = set()
    for path, method in parsed_file.tree.filter(javalang.tree.MethodDeclaration):
        if not has_inline_header_guard(method, _sibling_methods_by_name(path)):
            continue
        line = method.position.line if method.position else None
        if line is not None:
            guarded.add((method.name, line))
    return frozenset(guarded)


def _tree_sitter_header_param_names(source: bytes, method: Node) -> frozenset[str]:
    parameters_node = ts_child_by_field(method, "parameters")
    if parameters_node is None:
        return frozenset()
    names: set[str] = set()
    for param in ts_named_children(parameters_node):
        if simple_name_set(ts_annotation_names(source, param)) & {"RequestHeader"}:
            name_node = ts_child_by_field(param, "name")
            if name_node is not None:
                names.add(ts_node_text(source, name_node))
    return frozenset(names)


def simple_name_set(annotations: tuple[str, ...]) -> frozenset[str]:
    """Strip package qualification from a tuple of annotation names."""
    return frozenset(simple_name(a) for a in annotations)


def _tree_sitter_bails_out(consequence: Node) -> bool:
    return any(
        child.type in {"return_statement", "throw_statement"} for child in ts_walk(consequence)
    )


def _tree_sitter_references_header_comparison(
    source: bytes, condition: Node, header_params: frozenset[str]
) -> bool:
    for node in ts_walk(condition):
        if node.type != "method_invocation":
            continue
        name_node = ts_child_by_field(node, "name")
        if name_node is None or ts_node_text(source, name_node) not in _EQUALITY_COMPARISON_METHODS:
            continue
        object_node = ts_child_by_field(node, "object")
        if (
            object_node is not None
            and object_node.type == "identifier"
            and ts_node_text(source, object_node) in header_params
        ):
            return True
        arguments_node = ts_child_by_field(node, "arguments")
        if arguments_node is not None and any(
            _tree_sitter_argument_references_header(source, arg, header_params)
            for arg in ts_named_children(arguments_node)
        ):
            return True
    return False


def _tree_sitter_argument_references_header(
    source: bytes, arg: Node, header_params: frozenset[str]
) -> bool:
    """Whether ``arg`` is the header parameter itself, or a method called on it
    (e.g. ``supplied.getBytes()`` in ``MessageDigest.isEqual(key.getBytes(),
    supplied.getBytes())``) - see ``_references_header_comparison``'s
    docstring for why the latter shape matters."""
    if arg.type == "identifier":
        return ts_node_text(source, arg) in header_params
    if arg.type == "method_invocation":
        object_node = ts_child_by_field(arg, "object")
        return (
            object_node is not None
            and object_node.type == "identifier"
            and ts_node_text(source, object_node) in header_params
        )
    return False


def _tree_sitter_parameter_count(method: Node) -> int:
    parameters_node = ts_child_by_field(method, "parameters")
    if parameters_node is None:
        return 0
    return sum(1 for child in parameters_node.named_children if child.type == "formal_parameter")


def _tree_sitter_sibling_methods_by_name(
    source: bytes, ancestors: tuple[Node, ...]
) -> Mapping[tuple[str, int], Node]:
    """Tree-sitter mirror of ``_sibling_methods_by_name``.

    Keyed by ``(name, parameter_count)`` for the same reason as the
    javalang version: a plain name-keyed dict silently clobbers same-named
    overloads, which can resolve a call to an overload that isn't actually
    the one invoked at the call site.
    """
    enclosing_type = ts_nearest_enclosing_type(ancestors)
    if enclosing_type is None:
        return {}
    body = ts_child_by_field(enclosing_type, "body")
    if body is None:
        return {}
    return {
        (ts_declaration_name(source, member), _tree_sitter_parameter_count(member)): member
        for member in body.named_children
        if member.type == "method_declaration"
    }


def _tree_sitter_bails_out_via_helper_call(
    source: bytes,
    condition: Node,
    header_params: frozenset[str],
    sibling_methods_by_name: Mapping[tuple[str, int], Node],
) -> bool:
    """Tree-sitter mirror of ``_bails_out_via_helper_call``."""
    for node in ts_walk(condition):
        if node.type != "method_invocation":
            continue
        object_node = ts_child_by_field(node, "object")
        if object_node is not None and not (
            object_node.type == "this" or ts_node_text(source, object_node) == "this"
        ):
            continue
        name_node = ts_child_by_field(node, "name")
        if name_node is None:
            continue
        arguments_node = ts_child_by_field(node, "arguments")
        if arguments_node is None:
            continue
        argument_count = len(arguments_node.named_children)
        helper = sibling_methods_by_name.get((ts_node_text(source, name_node), argument_count))
        if helper is None:
            continue
        helper_parameters_node = ts_child_by_field(helper, "parameters")
        if helper_parameters_node is None:
            continue
        helper_parameters = [
            child
            for child in helper_parameters_node.named_children
            if child.type == "formal_parameter"
        ]
        for index, arg in enumerate(arguments_node.named_children):
            if index >= len(helper_parameters):
                continue
            if not _tree_sitter_argument_references_header(source, arg, header_params):
                continue
            helper_param_name = ts_declaration_name(source, helper_parameters[index])
            if _tree_sitter_references_header_comparison(
                source, helper, frozenset({helper_param_name})
            ):
                return True
    return False


def _hand_rolled_guard_methods_tree_sitter(parsed_file: ParsedFile) -> frozenset[tuple[str, int]]:
    parsed = parsed_file.tree_sitter
    if parsed is None:
        return frozenset()
    guarded: set[tuple[str, int]] = set()
    for ancestors, node in ts_walk_with_ancestors(parsed.tree.root_node):
        if node.type != "method_declaration":
            continue
        header_params = _tree_sitter_header_param_names(parsed.source, node)
        if not header_params:
            continue
        sibling_methods_by_name = _tree_sitter_sibling_methods_by_name(parsed.source, ancestors)
        for if_node in ts_walk(node):
            if if_node.type != "if_statement":
                continue
            consequence = ts_child_by_field(if_node, "consequence")
            condition = ts_child_by_field(if_node, "condition")
            if consequence is None or condition is None:
                continue
            if not _tree_sitter_bails_out(consequence):
                continue
            if _tree_sitter_references_header_comparison(parsed.source, condition, header_params):
                guarded.add((ts_declaration_name(parsed.source, node), ts_node_line(node)))
                break
            if _tree_sitter_bails_out_via_helper_call(
                parsed.source, condition, header_params, sibling_methods_by_name
            ):
                guarded.add((ts_declaration_name(parsed.source, node), ts_node_line(node)))
                break
    return frozenset(guarded)


def apply_hand_rolled_guard_context(
    findings: tuple[Finding, ...], parsed_files: Iterable[ParsedFile]
) -> tuple[Finding, ...]:
    """Append a caveat to a CWE-284 finding when its own endpoint method
    contains an inline hand-rolled header-comparison guard.

    Unlike ``apply_centralized_authorization_context`` (project-wide: one
    centralized rule anywhere covers every CWE-284 finding in the whole
    project), this is scoped per-method - only the specific finding whose
    own method contains the guard is annotated, since a hand-rolled check
    in one endpoint says nothing about whether a different, unguarded
    endpoint elsewhere in the same file or project is actually protected.

    Findings are never dropped or hidden by this, matching
    ``apply_centralized_authorization_context``'s fail-closed discipline:
    only the message gains an honest, narrowly-worded caveat.

    Args:
        findings: All findings from a scan (not just CWE-284's) - findings
            for other CWEs, and CWE-284 findings on unguarded methods,
            pass through unchanged.
        parsed_files: Every successfully-parsed Java file from the same
            scan, checked for a same-method inline guard.

    Returns:
        The same findings, with matching CWE-284 messages annotated.
    """
    guarded_by_file = {pf.path: _hand_rolled_guard_methods(pf) for pf in parsed_files}
    result: list[Finding] = []
    for finding in findings:
        guarded_methods = guarded_by_file.get(finding.file_path, frozenset())
        if (
            finding.cwe_id == CWE_ID
            and finding.line is not None
            and (finding.identifier, finding.line) in guarded_methods
        ):
            result.append(
                dataclasses.replace(
                    finding, message=f"{finding.message} {_HAND_ROLLED_GUARD_CAVEAT}"
                )
            )
        else:
            result.append(finding)
    return tuple(result)
