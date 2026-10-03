"""Tests for Layer 5's plain-language SHAP summary."""

from __future__ import annotations

import pytest

from vibeguard.layer4_ml import MLPrediction, MLRiskLabel, ProjectFeatures
from vibeguard.layer4_ml.predictor import build_project_features
from vibeguard.layer5_report._feature_descriptions import (
    FEATURE_DESCRIPTIONS,
    describe_feature,
)
from vibeguard.layer5_report.explainer import ProjectRiskExplanation, SHAPContribution
from vibeguard.layer5_report.plain_summary import build_plain_summary


def _explanation(
    *,
    label: MLRiskLabel = MLRiskLabel.CRITICAL,
    confidence: float = 0.873,
    baseline_probability: float = 0.253,
    contributions: tuple[SHAPContribution, ...],
) -> ProjectRiskExplanation:
    names = tuple(contribution.feature_name for contribution in contributions)
    values = tuple(contribution.feature_value for contribution in contributions)
    prediction = MLPrediction(
        label=label,
        confidence=confidence,
        features=ProjectFeatures(names=names, values=values),
    )
    return ProjectRiskExplanation(
        prediction=prediction,
        baseline_probability=baseline_probability,
        contributions=contributions,
    )


def test_feature_descriptions_cover_current_layer4_schema() -> None:
    current_names = build_project_features(()).names
    missing = [name for name in current_names if name not in FEATURE_DESCRIPTIONS]
    assert not missing, f"Layer 4 feature(s) missing a plain-language description: {missing}"


def test_describe_feature_falls_back_for_unknown_name() -> None:
    assert describe_feature("totally_new_feature") == "totally new feature"


def test_build_plain_summary_states_label_and_confidence() -> None:
    explanation = _explanation(
        contributions=(
            SHAPContribution(feature_name="max_rule_score", feature_value=95.0, shap_value=0.149),
        )
    )

    summary = build_plain_summary(explanation)

    assert "CRITICAL" in summary
    assert "87%" in summary
    assert "25%" in summary


def test_build_plain_summary_describes_top_features_with_direction() -> None:
    explanation = _explanation(
        contributions=(
            SHAPContribution(feature_name="max_rule_score", feature_value=95.0, shap_value=0.149),
            SHAPContribution(feature_name="critical_count", feature_value=1.0, shap_value=0.124),
            SHAPContribution(
                feature_name="has_sensitive_domain_signal", feature_value=0.0, shap_value=-0.05
            ),
        )
    )

    summary = build_plain_summary(explanation, max_features=3)

    assert "severity score of the single worst issue found" in summary
    assert "pushed the rating toward critical" in summary
    assert "pushed the rating away from critical" in summary


def test_build_plain_summary_phrases_a_zero_count_feature_without_contradiction() -> None:
    """A count feature at exactly zero must not read as "with a value of 0,
    X pushed..." - a contradiction to a reader expecting "zero" to mean
    "nothing happened," when the absence itself is the informative signal
    (e.g. a clean scan's zero findings supporting a low-risk rating)."""
    explanation = _explanation(
        label=MLRiskLabel.LOW,
        confidence=0.89,
        contributions=(
            SHAPContribution(feature_name="finding_count", feature_value=0.0, shap_value=0.08),
        ),
    )

    summary = build_plain_summary(explanation)

    assert "The total number of issues found in the project was zero" in summary
    assert "with a value of 0" not in summary.lower()


def test_build_plain_summary_phrases_a_false_boolean_feature_as_did_not_apply() -> None:
    explanation = _explanation(
        label=MLRiskLabel.LOW,
        confidence=0.89,
        contributions=(
            SHAPContribution(
                feature_name="has_sensitive_domain_signal", feature_value=0.0, shap_value=0.05
            ),
        ),
    )

    summary = build_plain_summary(explanation)

    assert "did not apply, which pushed the rating toward low" in summary
    assert "with a value of 0" not in summary.lower()


def test_build_plain_summary_phrases_a_true_boolean_feature_without_a_raw_value() -> None:
    """A boolean feature that's true (1.0) reads naturally as a plain
    statement - "with a value of 1" adds nothing a reader can use."""
    explanation = _explanation(
        contributions=(
            SHAPContribution(
                feature_name="has_sensitive_domain_signal", feature_value=1.0, shap_value=0.05
            ),
        )
    )

    summary = build_plain_summary(explanation)

    assert "with a value of 1" not in summary.lower()
    assert "sensitive functionality" in summary
    assert "pushed the rating toward critical" in summary


def test_build_plain_summary_respects_max_features() -> None:
    explanation = _explanation(
        contributions=(
            SHAPContribution(feature_name="max_rule_score", feature_value=95.0, shap_value=0.149),
            SHAPContribution(feature_name="critical_count", feature_value=1.0, shap_value=0.124),
        )
    )

    summary = build_plain_summary(explanation, max_features=1)

    assert "single worst issue found" in summary
    assert "critical-severity issues found" not in summary


def test_build_plain_summary_handles_no_notable_contributions() -> None:
    explanation = _explanation(
        label=MLRiskLabel.LOW,
        confidence=0.4,
        baseline_probability=0.4,
        contributions=(
            SHAPContribution(feature_name="finding_count", feature_value=0.0, shap_value=0.0),
        ),
    )

    summary = build_plain_summary(explanation)

    assert "No single factor stood out" in summary


def test_build_plain_summary_rejects_negative_max_features() -> None:
    explanation = _explanation(
        contributions=(
            SHAPContribution(feature_name="finding_count", feature_value=1.0, shap_value=0.1),
        )
    )

    with pytest.raises(ValueError, match="max_features must be non-negative"):
        build_plain_summary(explanation, max_features=-1)
