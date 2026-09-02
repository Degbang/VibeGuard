"""Layer 5 SHAP explainability over Layer 4 project-risk predictions."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

import numpy as np

from vibeguard.layer3_scoring import ScoredFinding
from vibeguard.layer4_ml import MLPrediction, RiskModel, predict_project_risk


@dataclass(frozen=True)
class SHAPContribution:
    """One feature's SHAP contribution for the predicted risk label."""

    feature_name: str
    feature_value: float
    shap_value: float


@dataclass(frozen=True)
class ProjectRiskExplanation:
    """Layer 5 explanation for one Layer 4 project-risk prediction."""

    prediction: MLPrediction
    baseline_probability: float
    contributions: tuple[SHAPContribution, ...]


def explain_project_risk(
    model: RiskModel,
    findings: Iterable[ScoredFinding],
) -> ProjectRiskExplanation:
    """Explain a Layer 4 project-risk prediction with SHAP.

    Args:
        model: Trusted Layer 4 model.
        findings: Layer 3 scored findings for one scanned project.

    Returns:
        The project-level prediction plus SHAP contributions for the
        predicted label.

    Raises:
        ValueError: If the SHAP output shape does not match the current
            Layer 4 feature schema or classifier outputs.
    """
    prediction = predict_project_risk(model, findings)
    row = np.array([prediction.features.values], dtype=float)
    classes = tuple(str(label) for label in model.classifier.classes_)
    predicted_index = classes.index(prediction.label.value)
    shap_values, baseline_probability = _explain_row(
        model.classifier,
        row,
        predicted_index,
        expected_class_count=len(classes),
    )
    contributions = tuple(
        sorted(
            (
                SHAPContribution(
                    feature_name=name,
                    feature_value=value,
                    shap_value=shap_value,
                )
                for name, value, shap_value in zip(
                    prediction.features.names,
                    prediction.features.values,
                    shap_values,
                    strict=True,
                )
            ),
            key=lambda contribution: (-abs(contribution.shap_value), contribution.feature_name),
        )
    )
    return ProjectRiskExplanation(
        prediction=prediction,
        baseline_probability=baseline_probability,
        contributions=contributions,
    )


def _explain_row(
    classifier: Any,
    row: np.ndarray,
    predicted_index: int,
    *,
    expected_class_count: int,
) -> tuple[np.ndarray, float]:
    """Return SHAP values and baseline probability for the predicted label."""
    import shap  # type: ignore[import-untyped]

    explainer = shap.TreeExplainer(classifier)
    explanation = explainer(row, check_additivity=False)
    values = np.asarray(explanation.values, dtype=float)
    base_values = np.asarray(explanation.base_values, dtype=float)
    shap_values = _select_predicted_feature_values(values, predicted_index, expected_class_count)
    baseline_probability = _select_predicted_base_value(
        base_values,
        predicted_index,
        expected_class_count,
    )
    if shap_values.ndim != 1:
        raise ValueError("SHAP values for one prediction must collapse to a 1D feature vector")
    return shap_values, baseline_probability


def _select_predicted_feature_values(
    values: np.ndarray,
    predicted_index: int,
    expected_class_count: int,
) -> np.ndarray:
    """Collapse feature SHAP values to the predicted class for one sample."""
    if values.ndim == 3:
        if values.shape[0] != 1:
            raise ValueError("SHAP values must describe exactly one sample")
        if values.shape[2] != expected_class_count:
            raise ValueError(
                "SHAP values class axis did not match the classifier's expected output count"
            )
        if predicted_index >= values.shape[2]:
            raise ValueError(f"SHAP value index {predicted_index} is out of range")
        return values[0, :, predicted_index]
    if values.ndim == 2:
        if values.shape[0] == 1:
            if expected_class_count != 1:
                raise ValueError(
                    "2D SHAP values with one sample row are only valid for single-output models"
                )
            return values[0]
        if values.shape[1] != expected_class_count:
            raise ValueError("2D SHAP values must expose one column per classifier output class")
        if predicted_index >= values.shape[1]:
            raise ValueError(f"SHAP value index {predicted_index} is out of range")
        return values[:, predicted_index]
    if values.ndim == 1:
        if expected_class_count != 1:
            raise ValueError("1D SHAP values are only valid for single-output models")
        return values
    raise ValueError(f"SHAP values had unexpected shape {values.shape}")


def _select_predicted_base_value(
    base_values: np.ndarray,
    predicted_index: int,
    expected_class_count: int,
) -> float:
    """Return the baseline probability for the predicted label."""
    if base_values.ndim == 2:
        if base_values.shape[0] != 1:
            raise ValueError("SHAP base values must describe exactly one sample")
        if base_values.shape[1] != expected_class_count:
            raise ValueError(
                "SHAP base values class axis did not match the classifier's expected output count"
            )
        if predicted_index >= base_values.shape[1]:
            raise ValueError(f"SHAP base value index {predicted_index} is out of range")
        return float(base_values[0, predicted_index])
    if base_values.ndim == 1:
        if base_values.size == 1:
            if expected_class_count != 1:
                raise ValueError("Scalar SHAP base values are only valid for single-output models")
            return float(base_values[0])
        if base_values.size != expected_class_count:
            raise ValueError("SHAP base values must expose one value per classifier output class")
        if predicted_index >= base_values.size:
            raise ValueError(f"SHAP base value index {predicted_index} is out of range")
        return float(base_values[predicted_index])
    if base_values.ndim == 0:
        if expected_class_count != 1:
            raise ValueError("Scalar SHAP base values are only valid for single-output models")
        return float(base_values)
    raise ValueError(f"SHAP base values had unexpected shape {base_values.shape}")
