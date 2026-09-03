"""Layer 4 ML prediction over scored project findings.

Layer 4 does not re-detect vulnerabilities. It consumes Layer 3 scored
findings and turns their project-level combinations into a fixed feature
vector for a local ML classifier.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum
from statistics import mean
from typing import Any

from vibeguard.layer3_scoring import RiskSeverity, ScoredFinding

_CWE_IDS = ("CWE-20", "CWE-284", "CWE-287", "CWE-798", "CWE-1035")
_SOURCE_TYPES = ("java", "config", "pom")

# Coarse, name-based signal that a finding sits in a business-sensitive
# domain (payments, account/identity, admin) rather than general-purpose
# code - the same "match on names, not semantics" heuristic style already
# used throughout Layer 1's rules (e.g. CREDENTIAL_KEYWORDS), applied here
# at Layer 4 because none of Layer 4's other features carry any signal
# about *what* an endpoint is for. Found to matter concretely: scanning
# real AI-generated projects produced two with an identical Layer 4
# feature vector (2 CWE-284 findings, nothing else) but opposite labels -
# an unauthenticated payment-charge endpoint (critical) and a genuinely
# public product catalog (low) - because nothing in the feature vector
# encoded that distinction. See IMPLEMENTATION_LOG.md 2026-09-03.
# Matched against a finding's file path and identifier combined, case-
# insensitively, substring match - same coarse-match philosophy and same
# accepted imprecision as CREDENTIAL_KEYWORDS (e.g. "user" also matches
# an unrelated "houser"), not a semantic understanding of the endpoint.
_SENSITIVE_DOMAIN_KEYWORDS = frozenset(
    {
        "payment",
        "billing",
        "charge",
        "checkout",
        "invoice",
        "transaction",
        "wallet",
        "refund",
        "account",
        "user",
        "profile",
        "auth",
        "login",
        "signup",
        "register",
        "credential",
        "identity",
        "admin",
        "administrator",
        "staff",
        "internal",
        "management",
    }
)


class MLRiskLabel(str, Enum):
    """Risk labels predicted by Layer 4."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class ProjectFeatures:
    """Fixed project-level feature vector for Layer 4 ML."""

    names: tuple[str, ...]
    values: tuple[float, ...]


@dataclass(frozen=True)
class MLPrediction:
    """Layer 4 prediction for one scanned project."""

    label: MLRiskLabel
    confidence: float
    features: ProjectFeatures


@dataclass(frozen=True)
class RiskModel:
    """A trained local ML model plus the feature schema it expects."""

    classifier: Any
    feature_names: tuple[str, ...]


def predict_project_risk(model: RiskModel, findings: Iterable[ScoredFinding]) -> MLPrediction:
    """Predict a project-level risk label from Layer 3 scored findings.

    Args:
        model: Model returned by Layer 4 training.
        findings: Scored findings for one project.

    Returns:
        A project-level ML label and confidence.

    Raises:
        ValueError: If the model schema does not match the current
            feature extractor. This fails closed rather than making a
            prediction with shifted columns.
    """
    features = build_project_features(findings)
    if model.feature_names != features.names:
        raise ValueError("model feature schema does not match current Layer 4 schema")

    probabilities = model.classifier.predict_proba([features.values])[0]
    classes = tuple(str(label) for label in model.classifier.classes_)
    best_index = max(range(len(probabilities)), key=lambda index: probabilities[index])
    return MLPrediction(
        label=MLRiskLabel(classes[best_index]),
        confidence=float(probabilities[best_index]),
        features=features,
    )


def build_project_features(findings: Iterable[ScoredFinding]) -> ProjectFeatures:
    """Convert scored findings into a deterministic project-level vector."""
    items = tuple(findings)
    names = _feature_names()
    if not items:
        return ProjectFeatures(names=names, values=tuple(0.0 for _ in names))

    scores = tuple(float(item.score) for item in items)
    cwe_counts = _counts_by_cwe(items)
    source_counts = _counts_by_source(items)
    severity_counts = _counts_by_severity(items)
    values = (
        float(len(items)),
        max(scores),
        mean(scores),
        float(severity_counts[RiskSeverity.CRITICAL]),
        float(severity_counts[RiskSeverity.HIGH]),
        float(severity_counts[RiskSeverity.MEDIUM]),
        float(severity_counts[RiskSeverity.LOW]),
        *(float(cwe_counts[cwe_id]) for cwe_id in _CWE_IDS),
        *(float(source_counts[source_type]) for source_type in _SOURCE_TYPES),
        float(sum(1 for item in items if not item.feature.has_line)),
        _has_cwe_pair(items, "CWE-284", "CWE-20"),
        _has_cwe_pair(items, "CWE-798", "CWE-284"),
        _has_cwe_pair(items, "CWE-798", "CWE-287"),
        _has_cwe_pair(items, "CWE-798", "CWE-1035"),
        _has_same_file_pair(items, "CWE-284", "CWE-20"),
        _has_same_file_pair(items, "CWE-798", "CWE-284"),
        _has_sensitive_domain_signal(items),
    )
    return ProjectFeatures(names=names, values=values)


def _feature_names() -> tuple[str, ...]:
    return (
        "finding_count",
        "max_rule_score",
        "mean_rule_score",
        "critical_count",
        "high_count",
        "medium_count",
        "low_count",
        *(f"{cwe_id.lower().replace('-', '_')}_count" for cwe_id in _CWE_IDS),
        *(f"{source_type}_source_count" for source_type in _SOURCE_TYPES),
        "missing_line_count",
        "has_access_control_and_input_validation",
        "has_secret_and_access_control",
        "has_secret_and_authentication",
        "has_secret_and_vulnerable_dependency",
        "same_file_access_control_and_input_validation",
        "same_file_secret_and_access_control",
        "has_sensitive_domain_signal",
    )


def _counts_by_cwe(findings: tuple[ScoredFinding, ...]) -> dict[str, int]:
    return {
        cwe_id: sum(1 for item in findings if item.feature.cwe_id == cwe_id) for cwe_id in _CWE_IDS
    }


def _counts_by_source(findings: tuple[ScoredFinding, ...]) -> dict[str, int]:
    return {
        source_type: sum(1 for item in findings if item.feature.source_type == source_type)
        for source_type in _SOURCE_TYPES
    }


def _counts_by_severity(findings: tuple[ScoredFinding, ...]) -> dict[RiskSeverity, int]:
    return {
        severity: sum(1 for item in findings if item.severity is severity)
        for severity in RiskSeverity
    }


def _has_cwe_pair(findings: tuple[ScoredFinding, ...], first: str, second: str) -> float:
    cwes = {item.feature.cwe_id for item in findings}
    return 1.0 if first in cwes and second in cwes else 0.0


def _has_same_file_pair(findings: tuple[ScoredFinding, ...], first: str, second: str) -> float:
    by_file: dict[str, set[str]] = {}
    for item in findings:
        by_file.setdefault(str(item.feature.file_path), set()).add(item.feature.cwe_id)
    return 1.0 if any(first in cwes and second in cwes for cwes in by_file.values()) else 0.0


def _has_sensitive_domain_signal(findings: tuple[ScoredFinding, ...]) -> float:
    """Whether any finding's file name or identifier names a sensitive domain.

    Deliberately matches only the file's own *name* (e.g.
    "PaymentController.java"), never the full path: FindingFeature.file_path
    is a resolved absolute path, and matching against it leaks whatever
    happens to be in the local checkout location - e.g. this exact bug was
    caught in review, where "/Users/<name>/..." made every single project
    on this machine match "user" regardless of its actual code, the same
    portability failure mode that got path_depth removed from Layer 2 on
    2026-07-21. Scoped to the file name specifically for the same reason.
    """
    for item in findings:
        haystack = f"{item.feature.file_path.name} {item.feature.identifier}".lower()
        if any(keyword in haystack for keyword in _SENSITIVE_DOMAIN_KEYWORDS):
            return 1.0
    return 0.0
