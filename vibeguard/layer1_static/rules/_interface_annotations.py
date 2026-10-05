"""Shared project-wide interface-method-annotation index for Layer 1 CWE rules.

Resolves a real gap found scanning ``spring-petclinic-rest`` and logged
in IMPLEMENTATION_LOG.md's 2026-09-02 entry: a concrete class
implementing an interface (e.g. output from Spring's
``openapi-generator-maven-plugin``) often carries the real
``@GetMapping``/``@PreAuthorize`` annotations only on the *interface*
method, while the concrete ``@Override`` implementation carries none of
its own - invisible to any rule that only inspects a method's own
annotation list.

This module builds a coarse, name-based index (not full type/overload
resolution - the same precision every other heuristic in this codebase
already accepts) from every top-level type's flattened Layer 1 summary
(``ParsedFile.classes`` - already parser-path-agnostic, since both
javalang and Tree-sitter produce the same ``ParsedClass``/``ParsedMethod``
shape), keyed by ``(type_name, method_name)``. Deliberately scoped to
top-level types only: ``ParsedFile.classes`` only ever represents
top-level types by design (see ``ast_parser.ParsedClass``'s docstring),
so a nested class's implemented interfaces are not resolved here - a
narrower limitation than the general nested-class support ``cwe_284.py``'s
own per-file detection already has, stated explicitly rather than
silently assumed complete.

The interface whose annotations are being borrowed is very often only
present in source when a project commits its generated interface rather
than compiling it at build time - the common case (compiler-generated
into ``target/generated-sources/...``) is invisible to this index too,
since ``scanner.py`` correctly excludes build output. This narrows the
gap for projects that do commit the interface source; it does not close
it universally, and that ceiling is a property of what source is
available to scan, not a limitation of this indexing approach.

Also indexes *parameter*-level annotations (``build_interface_parameter_index``),
for CWE-20's equivalent gap: ``@RequestBody``/``@Valid`` live on a
method's parameters, not the method itself, so a concrete override's
parameter can inherit them from an implemented interface's matching
parameter the same way a method inherits routing/authorization
annotations. Unlike method-level routing annotations, whether Spring
actually binds/validates a parameter using an interface-only annotation
is not established the same way - ``cwe_20.py`` treats this with the
same caveat-not-suppress discipline already applied to authorization
annotations, not the same free-widening treatment given to routing
annotations.

Deliberately scoped to top-level types only for both indexes, same
reasoning as above.

Also indexes each type's own direct interface-``extends`` chain
(``build_interface_hierarchy_index``), so a class implementing an
interface that itself extends a further interface (e.g. a generated
``PetsApi extends BaseApi``, with the real annotation declared on
``BaseApi``) is resolved through both hops, not just the single
directly-implemented interface - found by direct reproduction to be a
real, silent false negative otherwise, the worst-case failure direction
this project treats CWE-284 as having. Bounded and cycle-safe (see
``_resolve_transitive_interfaces``), the same shape as CWE-1035's
parent-POM chain walk, for the same reason: this indexes untrusted,
AI-generated source.

Also builds the reverse of that relationship
(``build_implementors_index``): which concrete types implement a given
interface. Used to deduplicate a finding on an interface's own method
when a concrete implementing class elsewhere in the scan independently
flags the identical unprotected endpoint - the interface is never
itself a deployed HTTP resource, only its implementor is.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import TypeAlias

import javalang

from vibeguard.layer1_static.ast_parser import ParsedClass, ParsedFile

InterfaceMethodAnnotations = Mapping[tuple[str, str], tuple[str, ...]]
InterfaceParameterAnnotations = Mapping[tuple[str, str, int], tuple[str, ...]]
InterfaceHierarchy = Mapping[str, tuple[str, ...]]

_MAX_INTERFACE_HIERARCHY_DEPTH = 10

# Extracted from cwe_284.py once cwe_20.py needed the identical "find this
# method's nearest enclosing class/interface in a javalang .filter() path"
# question - both rules need it to look up what a method's enclosing type
# implements, same extract-on-second-real-need pattern used throughout
# this codebase.
JavalangTypeDeclaration: TypeAlias = (
    javalang.tree.ClassDeclaration
    | javalang.tree.InterfaceDeclaration
    | javalang.tree.AnnotationDeclaration
)


def nearest_enclosing_type(path: tuple[object, ...]) -> JavalangTypeDeclaration | None:
    """Find the closest enclosing class/interface/annotation-type
    declaration in a filter() path.

    javalang's ``.filter()`` returns the full ancestor chain from the
    ``CompilationUnit`` down; walking it in reverse finds the nearest
    (innermost) enclosing type first, which is what "the method's own
    class" means for a nested/inner class.

    Includes ``AnnotationDeclaration`` (``@interface Foo { ... }``)
    alongside ``ClassDeclaration``/``InterfaceDeclaration`` - javalang
    models it as a sibling of ``InterfaceDeclaration`` under
    ``TypeDeclaration``, not a subclass of it, so it was previously
    missed entirely. Found by independent QA: an annotation type's own
    fields are implicitly ``public static final`` under the JLS, the
    same rule that applies to plain interface fields - without this,
    ``cwe_798.py``'s self-referential-constant exclusion would
    reintroduce a false positive for an enterprise permission-constant
    declared as an annotation-type constant instead of a plain
    interface one.
    """
    for ancestor in reversed(path):
        if isinstance(
            ancestor,
            javalang.tree.ClassDeclaration
            | javalang.tree.InterfaceDeclaration
            | javalang.tree.AnnotationDeclaration,
        ):
            return ancestor
    return None


EMPTY_INTERFACE_INDEX: InterfaceMethodAnnotations = {}
EMPTY_INTERFACE_PARAMETER_INDEX: InterfaceParameterAnnotations = {}
EMPTY_INTERFACE_HIERARCHY: InterfaceHierarchy = {}


def _collect_ambiguous_type_names(
    parsed_files: Iterable[ParsedFile],
) -> tuple[set[str], list[ParsedFile]]:
    """Detect which top-level type names are declared more than once.

    If two *distinct* top-level type declarations anywhere in the scan
    share the same simple name (confirmed to actually happen in real,
    independently-maintained repositories, not just a theoretical edge
    case - a QA pass found 14 colliding simple names across this
    project's own ``.qa-repos`` test corpus, e.g. four separate
    ``UserService`` interfaces/classes in different packages), any index
    keyed by that simple name must refuse to resolve it rather than
    guess - see ``build_interface_method_index``'s docstring for the real
    false-negative bug this replaced ("last one scanned wins").

    Args:
        parsed_files: Every successfully-parsed Java file from one scan.
            Consumed into a list here (an ``Iterable`` may only support a
            single pass) so callers can safely iterate it again afterward.

    Returns:
        The set of ambiguous simple type names, and the materialized list
        of ``parsed_files`` for the caller to reuse without re-consuming
        the original iterable.
    """
    materialized = list(parsed_files)
    declared_at: dict[str, tuple[object, int | None]] = {}
    ambiguous_type_names: set[str] = set()
    for parsed_file in materialized:
        for parsed_class in parsed_file.classes:
            identity = (parsed_file.path, parsed_class.line)
            previous_identity = declared_at.get(parsed_class.name)
            if previous_identity is None:
                declared_at[parsed_class.name] = identity
            elif previous_identity != identity:
                ambiguous_type_names.add(parsed_class.name)
    return ambiguous_type_names, materialized


def build_interface_method_index(parsed_files: Iterable[ParsedFile]) -> InterfaceMethodAnnotations:
    """Index every top-level type's methods by ``(type_name, method_name)``.

    Args:
        parsed_files: Every successfully-parsed Java file from one scan.

    Returns:
        A mapping usable to look up a specific interface method's
        annotations by name, for any top-level type declared anywhere in
        the scan. Nothing here restricts the index to actual
        ``interface`` declarations - a class happening to share this
        shape is indexed identically, since Java's ``implements`` clause
        can only ever name an interface anyway, so a lookup against it
        never queries an unrelated class's methods by accident.

        A simple type name declared more than once anywhere in the scan
        (see ``_collect_ambiguous_type_names``) is excluded from the
        index entirely rather than resolved to whichever declaration
        happened to be scanned last. An earlier version of this function
        let the last-scanned declaration silently win, which meant the
        exact same source code could either correctly find or silently
        miss the same unprotected endpoint purely depending on
        file-processing order - a real, reproduced false-negative risk
        for CWE-284, the one CWE in this project where a false negative
        is explicitly treated as the worse failure mode. Excluding an
        ambiguous name degrades that lookup back to exactly the
        pre-this-feature behavior (annotation simply not found, same as
        before this module existed) rather than a non-deterministic
        wrong answer - the same "when genuinely unresolvable, admit it
        rather than guess" principle already used elsewhere in this
        codebase (e.g. CWE-1035 never flagging a dependency with an
        unresolved version).
    """
    ambiguous_type_names, materialized = _collect_ambiguous_type_names(parsed_files)
    methods_by_type: dict[str, dict[str, tuple[str, ...]]] = {}
    for parsed_file in materialized:
        for parsed_class in parsed_file.classes:
            type_methods = methods_by_type.setdefault(parsed_class.name, {})
            for method in parsed_class.methods:
                type_methods[method.name] = method.annotations

    return {
        (type_name, method_name): annotations
        for type_name, type_methods in methods_by_type.items()
        if type_name not in ambiguous_type_names
        for method_name, annotations in type_methods.items()
    }


def build_interface_parameter_index(
    parsed_files: Iterable[ParsedFile],
) -> InterfaceParameterAnnotations:
    """Index every top-level type's method parameters by
    ``(type_name, method_name, parameter_index)``.

    Matched by *position*, not parameter name: an overriding method is
    free to rename its parameters relative to the interface it
    implements (parameter names are not part of the method contract in
    Java), so name-based matching would be simply wrong here, not merely
    coarse.

    Args:
        parsed_files: Every successfully-parsed Java file from one scan.

    Returns:
        A mapping usable to look up a specific interface method
        parameter's annotations by position. Subject to the same
        ambiguous-simple-type-name exclusion as
        ``build_interface_method_index``, computed independently (a name
        ambiguous for method-level lookups is equally ambiguous here,
        for the same reason).
    """
    ambiguous_type_names, materialized = _collect_ambiguous_type_names(parsed_files)
    parameters_by_type: dict[str, dict[str, tuple[tuple[str, ...], ...]]] = {}
    for parsed_file in materialized:
        for parsed_class in parsed_file.classes:
            type_methods = parameters_by_type.setdefault(parsed_class.name, {})
            for method in parsed_class.methods:
                type_methods[method.name] = tuple(
                    parameter.annotations for parameter in method.parameters
                )

    return {
        (type_name, method_name, index): annotations
        for type_name, type_methods in parameters_by_type.items()
        if type_name not in ambiguous_type_names
        for method_name, parameter_annotations in type_methods.items()
        for index, annotations in enumerate(parameter_annotations)
    }


def _direct_ancestors(parsed_class: ParsedClass) -> tuple[str, ...]:
    """A type's own direct ``implements``/interface-``extends`` list,
    plus its ``superclass`` (class ``extends``) if it has one, as a
    single flat tuple of names to walk toward.

    Found missing by independent QA, logged as a separate limitation
    (not fixed at the time): a class's own ``interfaces`` field only
    ever holds what it *directly* implements - ``class RealController
    extends AbstractBase`` (where ``AbstractBase implements
    SomeInterface``), without ``RealController`` *also* explicitly
    re-declaring ``implements SomeInterface`` itself, was invisible to
    the whole interface-widening feature family, since nothing ever
    consulted the ``extends``/superclass chain, only ``implements``.
    Treating the superclass as one more edge to walk - exactly like an
    interface's own further ``extends`` - lets the existing, already
    bounded and cycle-safe ``_resolve_transitive_interfaces`` walk
    discover an ancestor's interfaces without any new algorithm: the
    walk doesn't care whether an edge came from ``implements`` or
    ``extends``, and ``build_interface_method_index`` already indexes
    every top-level type uniformly regardless of whether it's a class
    or an interface, so looking up a superclass name in it is already
    meaningful.
    """
    if parsed_class.superclass is None:
        return parsed_class.interfaces
    return (*parsed_class.interfaces, parsed_class.superclass)


def build_interface_hierarchy_index(parsed_files: Iterable[ParsedFile]) -> InterfaceHierarchy:
    """Index every top-level type's own *direct* ``implements``/``extends``
    list, plus its superclass (see ``_direct_ancestors``).

    Used by ``top_level_interfaces_by_type_name`` to walk past a
    directly-implemented interface to whatever *that* interface itself
    extends, and past a class's own superclass to whatever *that*
    superclass itself implements or extends - found necessary by direct
    reproduction: a concrete class implementing ``PetsApi``, where
    ``PetsApi extends BaseApi`` and the real ``@GetMapping`` lives on
    ``BaseApi``, was previously invisible entirely, since only the
    single directly-implemented interface was ever checked - and
    likewise for a class extending an abstract base that implements an
    interface, never checked at all before the superclass edge was
    added. This is a project-wide index (unlike
    ``top_level_interfaces_by_type_name``, which is per-file) because
    the interface/superclass being extended is very often declared in a
    different file than the one implementing/extending it.

    Args:
        parsed_files: Every successfully-parsed Java file from one scan.

    Returns:
        A mapping from each unambiguous top-level type name to its own
        direct ancestors (interfaces plus superclass). Subject to the
        same ambiguous-simple-type-name exclusion as
        ``build_interface_method_index`` - an ambiguous name cannot be
        walked past safely, since which type's own further ``extends``
        list it would be referring to is not knowable, so the walk
        correctly stops there rather than guessing.
    """
    ambiguous_type_names, materialized = _collect_ambiguous_type_names(parsed_files)
    return {
        parsed_class.name: _direct_ancestors(parsed_class)
        for parsed_file in materialized
        for parsed_class in parsed_file.classes
        if parsed_class.name not in ambiguous_type_names
    }


def build_implementors_index(parsed_files: Iterable[ParsedFile]) -> Mapping[str, tuple[str, ...]]:
    """Reverse of each type's own interface list: map every interface or
    supertype name to every concrete top-level type that (transitively)
    implements/extends it.

    An interface is never itself an instantiable, deployable HTTP
    resource - only a concrete class implementing it is. Used to
    recognise when a method flagged on an interface's own declaration is
    the identical unprotected endpoint a concrete implementing class
    elsewhere in the scan has *also* independently flagged, so the two
    can be deduplicated to one finding at the actually deployable
    location - see ``cwe_284.deduplicate_interface_implementation_findings``,
    built after scanning Apache Syncope's real JAX-RS resource-interface/
    CXF-implementation split, where every one of its unprotected
    interface contracts was independently re-flagged by its own
    implementation class too.

    Args:
        parsed_files: Every successfully-parsed Java file from one scan.

    Returns:
        A mapping from each interface/supertype name to every concrete
        type name whose resolved ``implements``/``extends`` closure
        includes it, subject to the same ambiguous-simple-type-name
        exclusion as the other indexes in this module.

        Only a genuinely concrete, instantiable type - not an interface,
        and not an abstract class - is ever recorded as an implementor.
        An interface or abstract class is still walked *through* when
        resolving the hierarchy (so a real concrete class further down
        the chain is still correctly recorded against every ancestor
        interface), but is never itself recorded as if it were a
        deploying implementor.

        Independent QA found two real bugs in earlier versions of this
        function that didn't draw this line precisely enough: (1) two
        interfaces with no concrete implementor anywhere in the scan
        (``interface B extends A``, nothing implementing either) were
        incorrectly treated as implementing each other, since only
        ``is_interface`` was excluded; (2) an *abstract* class
        implementing an interface - also never instantiated anywhere in
        the scan, structurally the same problem one level further down
        the hierarchy - was still being recorded as a genuine
        implementor, since ``is_interface`` alone doesn't distinguish a
        concrete class from an abstract one. Both cases silently dropped
        a genuine, undeployed finding with no actual evidence either
        type is ever deployed - the opposite of this feature's own
        stated fail-closed guarantee.
    """
    ambiguous_type_names, materialized = _collect_ambiguous_type_names(parsed_files)
    hierarchy = build_interface_hierarchy_index(materialized)
    implementors: dict[str, list[str]] = {}
    for parsed_file in materialized:
        for parsed_class in parsed_file.classes:
            if (
                parsed_class.name in ambiguous_type_names
                or parsed_class.is_interface
                or "abstract" in parsed_class.modifiers
            ):
                continue
            for interface_name in _resolve_transitive_interfaces(
                _direct_ancestors(parsed_class), hierarchy
            ):
                implementors.setdefault(interface_name, []).append(parsed_class.name)
    return {name: tuple(types) for name, types in implementors.items()}


def _resolve_transitive_interfaces(
    direct_interfaces: tuple[str, ...], hierarchy: InterfaceHierarchy
) -> tuple[str, ...]:
    """Expand a type's direct ancestors (interfaces plus superclass, see
    ``_direct_ancestors``) to the full ancestor closure.

    A breadth-first walk from ``direct_interfaces``, following each
    ancestor's own further ``implements``/``extends`` list (via
    ``hierarchy``, which also includes superclass edges - see
    ``build_interface_hierarchy_index``) up to
    ``_MAX_INTERFACE_HIERARCHY_DEPTH`` hops - the same bounded,
    cycle-safe shape as CWE-1035's parent-POM chain walk, for the same
    reason: this indexes untrusted, AI-generated source, and a malformed
    or adversarial mutual-``extends`` cycle (not valid Java, but not
    assumed impossible either) must terminate rather than hang or recurse
    without bound. The name says "interfaces" for historical reasons
    (that was this walk's original scope); the closure it returns may
    also include ancestor *class* names now that superclass edges are
    included, which is intentional - ``build_interface_method_index``
    already indexes every top-level type uniformly regardless of
    whether it's a class or an interface, so looking up a superclass
    name in it is already meaningful.
    """
    closure: list[str] = []
    seen: set[str] = set()
    frontier = list(direct_interfaces)
    for _ in range(_MAX_INTERFACE_HIERARCHY_DEPTH):
        if not frontier:
            break
        next_frontier: list[str] = []
        for interface_name in frontier:
            if interface_name in seen:
                continue
            seen.add(interface_name)
            closure.append(interface_name)
            next_frontier.extend(hierarchy.get(interface_name, ()))
        frontier = next_frontier
    return tuple(closure)


def top_level_interfaces_by_type_name(
    parsed_file: ParsedFile,
    hierarchy: InterfaceHierarchy = EMPTY_INTERFACE_HIERARCHY,
) -> Mapping[str, tuple[str, ...]]:
    """Map this file's own top-level type names to their effective ancestors.

    Used to look up what a method's *top-level* enclosing type
    implements, using exactly the same resolution Layer 1's flattened
    summary already performs (``ParsedClass.interfaces``), then expanded
    transitively through ``hierarchy`` (see
    ``_resolve_transitive_interfaces``) so a multi-level interface
    ``extends`` chain is visible, not just the single directly-implemented
    interface - and, since ``_direct_ancestors`` also seeds the walk with
    the type's own ``superclass``, a class extending an abstract (or
    concrete) base that itself implements an interface is visible too,
    even without re-declaring ``implements`` itself. A nested class's
    name is absent from this file's ``ParsedFile.classes`` by design, so
    looking up a nested enclosing type's name here correctly finds
    nothing rather than something wrong.

    Args:
        parsed_file: One successfully-parsed Java file.
        hierarchy: A project-wide index (see
            ``build_interface_hierarchy_index``) of every type's own
            direct ancestors, used to walk past a directly-implemented
            interface to whatever it itself extends, and past a
            superclass to whatever *it* itself implements or extends.
            Defaults to empty, so a caller with no project-wide context
            sees only the direct, single-hop ancestors - the exact
            pre-existing behavior, preserved for backward compatibility.
    """
    return {
        parsed_class.name: _resolve_transitive_interfaces(
            _direct_ancestors(parsed_class), hierarchy
        )
        for parsed_class in parsed_file.classes
    }


def interface_annotations_for_method(
    implemented_interfaces: tuple[str, ...],
    method_name: str,
    index: InterfaceMethodAnnotations,
) -> tuple[str, ...]:
    """Just the interface-contributed annotations for one method.

    Exposed separately from ``resolve_effective_annotations`` because
    callers should not always treat an interface-inherited annotation
    the same way regardless of *what* it is: whether Spring MVC resolves
    a routing annotation (``@GetMapping`` etc.) declared on an
    interface method against the real bean is a documented,
    proxy-independent framework feature, but whether an AOP-based
    authorization annotation (``@PreAuthorize`` etc.) declared the same
    way is actually *enforced* depends on the proxy style in use
    (interface-based JDK dynamic proxies typically honor it; CGLIB class
    proxies, Spring Boot's default, typically do not) - a distinction
    this function's caller, not this function, is responsible for
    making. See ``cwe_284.py``'s ``_check_method`` for where that
    distinction is actually applied.

    Args:
        implemented_interfaces: The enclosing top-level type's declared
            ``implements``/``extends`` list, as Layer 1 already resolves it.
        method_name: The method's own name - matched by name only against
            each implemented interface, the same coarse precision this
            module's own docstring already states.
        index: The project-wide index from ``build_interface_method_index``.

    Returns:
        Every annotation found on a same-named method of any type listed
        in ``implemented_interfaces``.
    """
    return tuple(
        annotation
        for interface_name in implemented_interfaces
        for annotation in index.get((interface_name, method_name), ())
    )


def resolve_effective_annotations(
    own_annotations: tuple[str, ...],
    implemented_interfaces: tuple[str, ...],
    method_name: str,
    index: InterfaceMethodAnnotations,
) -> tuple[str, ...]:
    """Widen a method's own annotations with any matching interface method's.

    Safe to use unconditionally for recognising whether a method is an
    HTTP endpoint at all (see ``interface_annotations_for_method``'s
    docstring for why the same is not necessarily true for authorization
    annotations specifically).

    Args:
        own_annotations: The concrete method's own declared annotations.
        implemented_interfaces: The enclosing top-level type's declared
            ``implements``/``extends`` list, as Layer 1 already resolves it.
        method_name: The method's own name, matched the same way
            ``interface_annotations_for_method`` does.
        index: The project-wide index from ``build_interface_method_index``.

    Returns:
        ``own_annotations`` plus every annotation found on a same-named
        method of any type listed in ``implemented_interfaces``, in that
        order, with duplicates removed.
    """
    inherited = interface_annotations_for_method(implemented_interfaces, method_name, index)
    if not inherited:
        return own_annotations
    seen: set[str] = set()
    combined: list[str] = []
    for annotation in (*own_annotations, *inherited):
        if annotation not in seen:
            seen.add(annotation)
            combined.append(annotation)
    return tuple(combined)


def interface_annotations_for_parameter(
    implemented_interfaces: tuple[str, ...],
    method_name: str,
    parameter_index: int,
    index: InterfaceParameterAnnotations,
) -> tuple[str, ...]:
    """Just the interface-contributed annotations for one method parameter,
    by position.

    Unlike ``interface_annotations_for_method``, this has no matching
    ``resolve_effective_annotations``-style unconditional-widening
    sibling: whether Spring MVC actually binds/validates a parameter
    using an annotation declared only on an implemented interface's
    matching parameter (rather than the concrete override's own
    parameter) is not established as a proxy-independent framework
    guarantee the way method-level routing annotations are - callers
    (``cwe_20.py``) must treat *both* an inherited ``@RequestBody`` and an
    inherited ``@Valid``/``@Validated`` as caveat-worthy, not silently
    authoritative either way.

    Args:
        implemented_interfaces: The enclosing top-level type's declared
            ``implements``/``extends`` list, as Layer 1 already resolves it.
        method_name: The method's own name - matched by name only against
            each implemented interface, the same coarse precision this
            module's own docstring already states.
        parameter_index: The parameter's position within the method's
            parameter list - matched by position, not name, since an
            override may rename its parameters relative to the interface.
        index: The project-wide index from ``build_interface_parameter_index``.

    Returns:
        Every annotation found on the same-position parameter of a
        same-named method on any type listed in ``implemented_interfaces``.
    """
    return tuple(
        annotation
        for interface_name in implemented_interfaces
        for annotation in index.get((interface_name, method_name, parameter_index), ())
    )
