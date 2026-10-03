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

# Layer 4's own naming convention (predictor.py's _feature_names()) prefixes
# every boolean composite feature this way; count/score features never use
# these prefixes. Used only to pick natural zero-value phrasing below - a
# count reading "was zero" and a boolean reading "did not apply" avoids the
# "with a value of 0, X pushed..." phrasing reading as a contradiction.
_BOOLEAN_FEATURE_PREFIXES = ("has_", "same_file_")


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
    """Render one SHAP contribution as a plain-language sentence.

    A value of exactly zero gets its own phrasing rather than "with a value
    of 0, X pushed..." - which reads as a contradiction, since a reader
    expects "zero of something" to mean nothing happened, when here the
    absence itself is the informative signal (e.g. a clean scan's zero
    findings supporting a low-risk rating).
    """
    direction = "toward" if contribution.shap_value >= 0 else "away from"
    value = contribution.feature_value
    description = describe_feature(contribution.feature_name)
    is_boolean = contribution.feature_name.startswith(_BOOLEAN_FEATURE_PREFIXES)

    if value == 0:
        if is_boolean:
            return (
                f"{_capitalize(description)} did not apply, "
                f"which pushed the rating {direction} {label}."
            )
        return f"{_capitalize(description)} was zero, which pushed the rating {direction} {label}."

    if is_boolean:
        return f"{_capitalize(description)} pushed the rating {direction} {label}."

    formatted_value = str(int(value)) if value == int(value) else f"{value:.1f}"
    return (
        f"With a value of {formatted_value}, {description} pushed the rating {direction} {label}."
    )


def _capitalize(text: str) -> str:
    """Capitalize only the first character, preserving the rest as-is."""
    return text[0].upper() + text[1:] if text else text
