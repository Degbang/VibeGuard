"""Guardrails for Java rule support across both parser paths."""

from __future__ import annotations

from vibeguard.layer1_static.rules import cwe_20, cwe_284, cwe_287, cwe_798


def test_java_rules_expose_tree_sitter_fallback_paths() -> None:
    """Every Java-source rule must declare a Tree-sitter fallback entry
    point.

    Deliberately narrow, stated plainly rather than implied to be more
    than it is: this only confirms the function exists, never that any
    of its branches actually run or behave correctly on real Tree-
    sitter input - that is each rule module's own test file's job (see
    e.g. test_cwe_798.py's dedicated Tree-sitter-fallback tests), not
    this guardrail's. A rule could still have genuinely untested
    fallback logic and pass this check; this only catches someone
    deleting the fallback entirely.

    CWE-1035 is intentionally excluded: it runs on parsed pom.xml files,
    not Java ASTs.
    """
    for module in (cwe_20, cwe_284, cwe_287, cwe_798):
        assert hasattr(module, "_detect_in_tree_sitter_java"), module.__name__
