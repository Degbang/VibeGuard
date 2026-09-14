"""Human-readable descriptions for Layer 4's fixed feature schema.

Layer 5's plain-language summary (``plain_summary.py``) translates SHAP
feature names into prose. This mapping is maintained by hand because the
Layer 4 feature schema is small and fixed; ``test_layer5_plain_summary.py``
asserts every name Layer 4 can currently produce has an entry here, so a
future schema change fails a test instead of silently degrading to raw
feature-name text everywhere.
"""

from __future__ import annotations

FEATURE_DESCRIPTIONS: dict[str, str] = {
    "finding_count": "the total number of issues found in the project",
    "max_rule_score": "the severity score of the single worst issue found",
    "mean_rule_score": "the average severity score across all issues found",
    "critical_count": "the number of critical-severity issues found",
    "high_count": "the number of high-severity issues found",
    "medium_count": "the number of medium-severity issues found",
    "low_count": "the number of low-severity issues found",
    "cwe_20_count": "the number of improper input validation (CWE-20) issues found",
    "cwe_284_count": "the number of improper access control (CWE-284) issues found",
    "cwe_287_count": "the number of improper authentication (CWE-287) issues found",
    "cwe_798_count": "the number of hardcoded credential (CWE-798) issues found",
    "cwe_1035_count": "the number of known-vulnerable dependency (CWE-1035) issues found",
    "java_source_count": "the number of issues found directly in Java source code",
    "config_source_count": "the number of issues found in configuration files",
    "pom_source_count": "the number of issues found in the Maven pom.xml dependency file",
    "missing_line_count": "the number of issues that could not be pinned to an exact source line",
    "has_access_control_and_input_validation": (
        "the project having both an access-control issue and an input-validation issue"
    ),
    "has_secret_and_access_control": (
        "the project having both a hardcoded secret and an access-control issue"
    ),
    "has_secret_and_authentication": (
        "the project having both a hardcoded secret and an authentication issue"
    ),
    "has_secret_and_vulnerable_dependency": (
        "the project having both a hardcoded secret and a known-vulnerable dependency"
    ),
    "same_file_access_control_and_input_validation": (
        "an access-control issue and an input-validation issue occurring in the same file"
    ),
    "same_file_secret_and_access_control": (
        "a hardcoded secret and an access-control issue occurring in the same file"
    ),
    "has_sensitive_domain_signal": (
        "the affected code appearing to handle sensitive functionality "
        "(payments, accounts, admin, etc.)"
    ),
}


def describe_feature(feature_name: str) -> str:
    """Return a plain-language description for a Layer 4 feature name.

    Args:
        feature_name: A name from Layer 4's ``ProjectFeatures.names``.

    Returns:
        A human-readable description. Falls back to a de-slugified
        version of the raw name for any feature not in the hand-
        maintained mapping, so an unrecognized name degrades to
        readable text instead of raising.
    """
    return FEATURE_DESCRIPTIONS.get(feature_name, feature_name.replace("_", " "))
