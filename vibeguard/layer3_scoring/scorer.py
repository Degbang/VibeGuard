"""Layer 3 deterministic rule-based scoring for Layer 2 feature rows.

Layer 1 finds candidate CWE issues and Layer 2 normalizes them into
traceable feature rows. This module assigns a deterministic,
explainable baseline risk score to each feature row before Layer 4's ML
classifier is introduced. It never re-parses source files and never
executes analysed Java content.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum

from vibeguard.layer2_features import FindingFeature

_MIN_SCORE = 0
_MAX_SCORE = 100

_BASE_SCORES = {
    "CWE-798": 90,
    "CWE-1035": 85,
    "CWE-284": 80,
    "CWE-287": 75,
    "CWE-20": 65,
}
_SUPPORTED_SOURCE_TYPES = frozenset({"java", "config", "pom"})
_EXPECTED_SOURCE_EXTENSIONS = {
    "java": frozenset({"java"}),
    "config": frozenset({"properties", "yml", "yaml"}),
    "pom": frozenset({"pom.xml"}),
}
_EXPECTED_SOURCE_TYPES = {
    "CWE-20": frozenset({"java"}),
    "CWE-284": frozenset({"java"}),
    "CWE-287": frozenset({"java"}),
    "CWE-798": frozenset({"java", "config"}),
    "CWE-1035": frozenset({"pom"}),
}


class RiskSeverity(str, Enum):
    """Human-readable severity band for a rule-based risk score."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class ScoredFinding:
    """Layer 3 score attached to a single Layer 2 feature row."""

    feature: FindingFeature
    score: int
    severity: RiskSeverity
    factors: tuple[str, ...]

    @property
    def trace_key(self) -> tuple[str, str, int | None, str]:
        """Stable trace key inherited from the underlying Layer 2 feature."""
        return self.feature.trace_key


def score_features(features: Iterable[FindingFeature]) -> tuple[ScoredFinding, ...]:
    """Score normalized Layer 2 features with a deterministic rule rubric.

    Args:
        features: Layer 2 feature rows. They are expected to have already
            passed Layer 2 validation and deduplication.

    Returns:
        One scored row per input feature, preserving input order.

    Raises:
        ValueError: If a feature has a CWE or source type outside the
            Layer 2/3 contract. This fails closed rather than assigning
            an arbitrary default score to an unknown security category.
    """
    return tuple(_score_feature(feature) for feature in features)


def _score_feature(feature: FindingFeature) -> ScoredFinding:
    _validate_feature(feature)
    score = _BASE_SCORES[feature.cwe_id]
    factors = [f"base {feature.cwe_id} score {score}"]

    for adjustment, reason in _context_adjustments(feature):
        score += adjustment
        sign = "+" if adjustment >= 0 else ""
        factors.append(f"{sign}{adjustment}: {reason}")

    clamped_score = _clamp_score(score)
    if clamped_score != score:
        factors.append(f"clamped to {clamped_score}")

    return ScoredFinding(
        feature=feature,
        score=clamped_score,
        severity=_severity_for_score(clamped_score),
        factors=tuple(factors),
    )


def _validate_feature(feature: FindingFeature) -> None:
    if feature.cwe_id not in _BASE_SCORES:
        raise ValueError(f"unsupported CWE id for scoring: {feature.cwe_id}")
    if feature.source_type not in _SUPPORTED_SOURCE_TYPES:
        raise ValueError(f"unsupported source type for scoring: {feature.source_type}")
    expected_flags = (
        feature.is_java_source,
        feature.is_config_source,
        feature.is_pom_file,
    )
    if sum(expected_flags) != 1:
        raise ValueError("exactly one source-type flag must be true")
    expected_type = _source_type_from_flags(feature)
    if feature.source_type != expected_type:
        raise ValueError(f"source_type={feature.source_type!r} does not match source-type flags")
    if feature.source_extension not in _EXPECTED_SOURCE_EXTENSIONS[feature.source_type]:
        raise ValueError(
            f"source_extension={feature.source_extension!r} does not match "
            f"source_type={feature.source_type!r}"
        )
    if feature.source_type not in _EXPECTED_SOURCE_TYPES[feature.cwe_id]:
        raise ValueError(
            f"{feature.cwe_id} cannot be scored from source_type={feature.source_type!r}"
        )
    if feature.cwe_id == "CWE-798" and not feature.has_redacted_value:
        raise ValueError("CWE-798 scoring requires a redacted_value")
    if feature.cwe_id != "CWE-798" and feature.has_redacted_value:
        raise ValueError(f"{feature.cwe_id} scoring does not accept redacted_value")


def _source_type_from_flags(feature: FindingFeature) -> str:
    if feature.is_java_source:
        return "java"
    if feature.is_config_source:
        return "config"
    return "pom"


def _context_adjustments(feature: FindingFeature) -> tuple[tuple[int, str], ...]:
    adjustments: list[tuple[int, str]] = []
    if feature.cwe_id == "CWE-798" and feature.is_config_source:
        adjustments.append((5, "hardcoded credential is in deployment config"))
    if feature.cwe_id == "CWE-1035" and feature.is_pom_file:
        adjustments.append((5, "known vulnerable dependency is declared in pom.xml"))
    if not feature.has_line:
        adjustments.append((-5, "source line is unavailable, reducing traceability confidence"))
    return tuple(adjustments)


def _clamp_score(score: int) -> int:
    return max(_MIN_SCORE, min(_MAX_SCORE, score))


def _severity_for_score(score: int) -> RiskSeverity:
    if score >= 85:
        return RiskSeverity.CRITICAL
    if score >= 70:
        return RiskSeverity.HIGH
    if score >= 40:
        return RiskSeverity.MEDIUM
    return RiskSeverity.LOW
