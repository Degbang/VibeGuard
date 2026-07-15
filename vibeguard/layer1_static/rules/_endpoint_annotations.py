"""Shared HTTP-endpoint-annotation heuristics for Layer 1 CWE rule modules.

Extracted out of ``cwe_284.py`` once ``cwe_20.py`` needed the same "is
this method a reachable HTTP endpoint" question - see
IMPLEMENTATION_LOG.md. Both rules care about identifying endpoints for
different reasons: cwe_284.py asks whether an endpoint has an
authorization annotation; cwe_20.py asks whether an endpoint's request
body parameter is validated.
"""

from __future__ import annotations

# JAX-RS/Quarkus RESTEasy and Spring MVC annotations that mark a method
# as a reachable HTTP endpoint. Matched against an annotation's *simple*
# name (see simple_name below) - presence of any one of these is what
# makes questions like "is this authorized" or "is this input
# validated" meaningful at all, since an ordinary private helper method
# needs neither because nothing external can reach it.
ENDPOINT_ANNOTATIONS = frozenset(
    {
        # JAX-RS / Quarkus RESTEasy
        "GET",
        "POST",
        "PUT",
        "DELETE",
        "PATCH",
        "HEAD",
        "OPTIONS",
        # Spring MVC
        "GetMapping",
        "PostMapping",
        "PutMapping",
        "DeleteMapping",
        "PatchMapping",
        "RequestMapping",
    }
)


def has_endpoint_annotation(annotations: tuple[str, ...]) -> bool:
    return any(simple_name(a) in ENDPOINT_ANNOTATIONS for a in annotations)


def simple_name(annotation: str) -> str:
    """Strip any package qualification, e.g. "javax.ws.rs.GET" -> "GET".

    javalang gives an annotation's name exactly as written in source:
    "GET" for `@GET`, but "javax.ws.rs.GET" for `@javax.ws.rs.GET" -
    matching against the full string would miss (or wrongly flag) any
    endpoint annotation using its fully-qualified form instead of a
    simple-name import.
    """
    return annotation.rsplit(".", 1)[-1]
