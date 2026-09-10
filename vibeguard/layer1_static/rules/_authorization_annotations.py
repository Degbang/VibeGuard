"""Shared authorization-annotation heuristics for Layer 1 CWE rule modules.

Extracted out of ``cwe_284.py`` once ``cwe_287.py`` needed the same "does
this method already carry an explicit access-control decision" question -
see IMPLEMENTATION_LOG.md 2026-09-04. cwe_284.py asks whether an endpoint
has *any* authorization annotation at all (missing entirely is the CWE);
cwe_287.py asks the same question for a narrower reason - to avoid
flagging a credential-issuing endpoint that is already gated by
annotation-based method security (e.g. Spring Security's
``@PreAuthorize``) rather than a hand-written ``if`` guard.
"""

from __future__ import annotations

from vibeguard.layer1_static.rules._endpoint_annotations import simple_name

# Annotations that represent an explicit access-control decision, whether
# restrictive or permissive. Any one of these present (on the method or
# the class) means an access-control decision was made at all - which
# annotation, or whether it's the *right* one, is out of scope for a
# static, name-based check.
AUTHORIZATION_ANNOTATIONS = frozenset(
    {
        "RolesAllowed",
        "PermitAll",
        "DenyAll",
        "Authenticated",  # Quarkus
        "Secured",  # Spring Security (legacy)
        "PreAuthorize",  # Spring Security
        "PostAuthorize",  # Spring Security
        "RequiresRoles",  # Apache Shiro
    }
)


def has_authorization_annotation(annotations: tuple[str, ...]) -> bool:
    """Whether any annotation in ``annotations`` is an authorization decision.

    Args:
        annotations: Annotation names exactly as written in source (may
            be package-qualified, e.g. "javax.annotation.security.RolesAllowed");
            this strips qualification itself before matching.
    """
    return any(simple_name(a) in AUTHORIZATION_ANNOTATIONS for a in annotations)
