"""Plain-language translation of Layer 5's SHAP feature attribution.

Layer 5's SHAP table (``report.py``) is precise but assumes familiarity
with SHAP values, baseline probabilities, and the Layer 4 feature schema.
This module builds a prose summary from the exact same
``ProjectRiskExplanation`` object produced by ``explainer.py`` - no new
computation, purely a human-readable restatement of the same numbers -
for readers who want the "why" without reading the table.
"""

from __future__ import annotations

from vibeguard.layer5_report._feature_descriptions import describe_feature
from vibeguard.layer5_report.explainer import ProjectRiskExplanation, SHAPContribution

_NEGLIGIBLE_SHAP_VALUE = 1e-6


def build_plain_summary(
    explanation: ProjectRiskExplanation,
    *,
    max_features: int = 3,
) -> str:
    """Render a project's SHAP explanation as a short prose summary.

    Args:
        explanation: The same Layer 5 explanation shown in the SHAP table.
        max_features: How many of the most influential features to
            describe in prose. Must be non-negative.

    Returns:
        A multi-sentence plain-language summary of the predicted label,
        confidence, and its most influential contributing features.

    Raises:
        ValueError: If max_features is negative.
    """
    if max_features < 0:
        raise ValueError("max_features must be non-negative")

    label = explanation.prediction.label.value
    confidence_pct = round(explanation.prediction.confidence * 100)
    baseline_pct = round(explanation.baseline_probability * 100)

    sentences = [
        f"This project was rated {label.upper()} risk, with {confidence_pct}% confidence.",
        (
            "Before looking at this project's specific details, the model's starting "
            f"expectation was a {baseline_pct}% chance of {label} risk."
        ),
    ]

    notable = [
        contribution
        for contribution in explanation.contributions
        if abs(contribution.shap_value) > _NEGLIGIBLE_SHAP_VALUE
    ][:max_features]

    if not notable:
        sentences.append(
            "No single factor stood out - the result reflects a broad mix of small "
            "signals across the project's findings rather than one dominant cause."
        )
    else:
        sentences.extend(_describe_contribution(item, label) for item in notable)

    return " ".join(sentences)


def _describe_contribution(contribution: SHAPContribution, label: str) -> str:
    """Render one SHAP contribution as a plain-language sentence."""
    direction = "toward" if contribution.shap_value >= 0 else "away from"
    value = contribution.feature_value
    formatted_value = str(int(value)) if value == int(value) else f"{value:.1f}"
    description = describe_feature(contribution.feature_name)
    return (
        f"With a value of {formatted_value}, {description} pushed the rating {direction} {label}."
    )
