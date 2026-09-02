"""Layer 4 local ML training for project-level risk classification.

Training consumes Layer 3 scored findings grouped by project and
supervised project risk labels. The model learns how combinations of
already-detected findings affect project-level risk; it does not parse
source files or re-detect vulnerabilities.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from sklearn.ensemble import RandomForestClassifier  # type: ignore[import-untyped]

from vibeguard.layer3_scoring import ScoredFinding
from vibeguard.layer4_ml.predictor import MLRiskLabel, RiskModel, build_project_features


@dataclass(frozen=True)
class TrainingExample:
    """One labelled project used to train the Layer 4 classifier."""

    findings: tuple[ScoredFinding, ...]
    label: MLRiskLabel


def train_project_risk_model(
    examples: Iterable[TrainingExample],
    *,
    random_state: int = 42,
) -> RiskModel:
    """Train a local Random Forest project-risk classifier.

    Args:
        examples: Labelled projects. Each example contains the scored
            findings for one project plus its manually assigned risk
            label.
        random_state: Seed for deterministic thesis experiments.

    Returns:
        A RiskModel that can be passed to ``predict_project_risk``.

    Raises:
        ValueError: If there are no examples or fewer than two distinct
            labels. A classifier trained on one class gives a false
            sense of validation and cannot distinguish risk levels.
    """
    rows = tuple(examples)
    _validate_training_examples(rows)
    feature_rows = tuple(build_project_features(row.findings) for row in rows)
    schema = feature_rows[0].names
    if any(features.names != schema for features in feature_rows):
        raise ValueError("training examples produced inconsistent feature schemas")

    classifier = RandomForestClassifier(
        n_estimators=100,
        random_state=random_state,
        class_weight="balanced",
    )
    classifier.fit(
        [features.values for features in feature_rows],
        [row.label.value for row in rows],
    )
    return RiskModel(classifier=classifier, feature_names=schema)


def _validate_training_examples(examples: tuple[TrainingExample, ...]) -> None:
    if not examples:
        raise ValueError("at least one training example is required")
    labels = {example.label for example in examples}
    if len(labels) < 2:
        raise ValueError("at least two distinct risk labels are required")
