"""Guardrails for Java rule support across both parser paths."""

from __future__ import annotations

from vibeguard.layer1_static.rules import cwe_20, cwe_284, cwe_287, cwe_798


def test_java_rules_expose_tree_sitter_fallback_paths() -> None:
    """Every Java-source rule must handle modern Java fallback parses.

    CWE-1035 is intentionally excluded: it runs on parsed pom.xml files,
    not Java ASTs.
    """
    for module in (cwe_20, cwe_284, cwe_287, cwe_798):
        assert hasattr(module, "_detect_in_tree_sitter_java"), module.__name__
