"""Layer 4 local evaluation metrics for trained project-risk models."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from vibeguard.layer3_scoring import ScoredFinding
from vibeguard.layer4_ml.predictor import MLPrediction, MLRiskLabel, RiskModel, predict_project_risk
from vibeguard.layer4_ml.trainer import TrainingExample, train_project_risk_model


@dataclass(frozen=True)
class ProjectPrediction:
    """Predicted and expected label for one evaluated project."""

    index: int
    actual: MLRiskLabel
    predicted: MLRiskLabel
    confidence: float


@dataclass(frozen=True)
class ConfusionCell:
    """One non-zero cell in the evaluation confusion matrix."""

    actual: MLRiskLabel
    predicted: MLRiskLabel
    count: int


@dataclass(frozen=True)
class EvaluationResult:
    """Deterministic Layer 4 evaluation summary."""

    predictions: tuple[ProjectPrediction, ...]
    accuracy: float
    macro_f1: float
    confusion: tuple[ConfusionCell, ...]


def evaluate_project_risk_model(
    model: RiskModel, examples: Iterable[TrainingExample]
) -> EvaluationResult:
    """Evaluate a trained model on labelled project examples.

    Args:
        model: Trained local model.
        examples: Labelled projects to evaluate.

    Returns:
        Accuracy, macro-F1, per-project predictions, and non-zero
        confusion-matrix cells.

    Raises:
        ValueError: If no examples are provided.
    """
    rows = tuple(examples)
    if not rows:
        raise ValueError("at least one evaluation example is required")

    predictions = tuple(
        _project_prediction(index, row, predict_project_risk(model, row.findings))
        for index, row in enumerate(rows)
    )
    return EvaluationResult(
        predictions=predictions,
        accuracy=_accuracy(predictions),
        macro_f1=_macro_f1(predictions),
        confusion=_confusion(predictions),
    )


def leave_one_out_evaluate_project_risk_model(
    examples: Iterable[TrainingExample], *, random_state: int = 42
) -> EvaluationResult:
    """Evaluate Layer 4 with deterministic leave-one-project-out retraining.

    This is the safest local evaluation path for a small labelled
    dataset: every project is held out once, the remaining projects are
    used to train the model afresh, and the held-out project is then
    predicted. No serialized model artifact is required.
    """
    rows = tuple(examples)
    if len(rows) < 2:
        raise ValueError("at least two labelled projects are required for leave-one-out evaluation")
    predictions = tuple(
        _leave_one_out_prediction(rows, holdout_index, random_state)
        for holdout_index in range(len(rows))
    )
    return EvaluationResult(
        predictions=predictions,
        accuracy=_accuracy(predictions),
        macro_f1=_macro_f1(predictions),
        confusion=_confusion(predictions),
    )


def _leave_one_out_prediction(
    rows: tuple[TrainingExample, ...], holdout_index: int, random_state: int
) -> ProjectPrediction:
    holdout = rows[holdout_index]
    training_rows = rows[:holdout_index] + rows[holdout_index + 1 :]
    try:
        model = train_project_risk_model(training_rows, random_state=random_state)
    except ValueError as exc:
        raise ValueError(
            "leave-one-out evaluation requires every training fold to retain at least two labels"
        ) from exc
    return _project_prediction(
        holdout_index, holdout, predict_project_risk(model, holdout.findings)
    )


def _project_prediction(
    index: int, row: TrainingExample, prediction: MLPrediction
) -> ProjectPrediction:
    return ProjectPrediction(
        index=index,
        actual=row.label,
        predicted=prediction.label,
        confidence=prediction.confidence,
    )


def _accuracy(predictions: tuple[ProjectPrediction, ...]) -> float:
    correct = sum(1 for prediction in predictions if prediction.actual is prediction.predicted)
    return correct / len(predictions)


def _macro_f1(predictions: tuple[ProjectPrediction, ...]) -> float:
    labels = tuple(
        label
        for label in MLRiskLabel
        if any(
            prediction.actual is label or prediction.predicted is label
            for prediction in predictions
        )
    )
    return sum(_f1_for_label(predictions, label) for label in labels) / len(labels)


def _f1_for_label(predictions: tuple[ProjectPrediction, ...], label: MLRiskLabel) -> float:
    true_positive = sum(
        1
        for prediction in predictions
        if prediction.actual is label and prediction.predicted is label
    )
    false_positive = sum(
        1
        for prediction in predictions
        if prediction.actual is not label and prediction.predicted is label
    )
    false_negative = sum(
        1
        for prediction in predictions
        if prediction.actual is label and prediction.predicted is not label
    )
    if true_positive == 0:
        return 0.0
    precision = true_positive / (true_positive + false_positive)
    recall = true_positive / (true_positive + false_negative)
    return 2 * precision * recall / (precision + recall)


def baseline_label_from_max_severity(findings: Iterable[ScoredFinding]) -> MLRiskLabel:
    """A fixed, non-learned baseline: the severity band of the single
    highest-scoring Layer 3 finding, or ``low`` for a project with none.

    This rule has no learned parameters and is not fit to any dataset -
    it is Layer 3's own deterministic severity mapping read straight off
    the worst finding present. It exists so Layer 4's project-level ML
    metrics can be reported next to a concrete floor: if Layer 4 cannot
    beat this on held-out projects, the ML layer is not demonstrating
    anything beyond what the rule-based scorer (Layer 3) already
    provides on its own.
    """
    items = tuple(findings)
    if not items:
        return MLRiskLabel.LOW
    worst = max(items, key=lambda item: item.score)
    return MLRiskLabel(worst.severity.value)


def evaluate_baseline_severity_model(examples: Iterable[TrainingExample]) -> EvaluationResult:
    """Evaluate the fixed max-severity baseline against labelled projects.

    The baseline has no learned parameters, so - unlike a fitted model -
    there is no train/test split to observe and evaluating it directly
    against every labelled example carries no leakage risk. ``confidence``
    is fixed at ``1.0`` for every prediction: the baseline does not
    produce a probability, so this is not a calibrated confidence value
    and must not be read as one.

    Raises:
        ValueError: If no examples are provided.
    """
    rows = tuple(examples)
    if not rows:
        raise ValueError("at least one evaluation example is required")
    predictions = tuple(
        ProjectPrediction(
            index=index,
            actual=row.label,
            predicted=baseline_label_from_max_severity(row.findings),
            confidence=1.0,
        )
        for index, row in enumerate(rows)
    )
    return EvaluationResult(
        predictions=predictions,
        accuracy=_accuracy(predictions),
        macro_f1=_macro_f1(predictions),
        confusion=_confusion(predictions),
    )


def _confusion(predictions: tuple[ProjectPrediction, ...]) -> tuple[ConfusionCell, ...]:
    cells: list[ConfusionCell] = []
    for actual in MLRiskLabel:
        for predicted in MLRiskLabel:
            count = sum(
                1
                for prediction in predictions
                if prediction.actual is actual and prediction.predicted is predicted
            )
            if count:
                cells.append(ConfusionCell(actual=actual, predicted=predicted, count=count))
    return tuple(cells)
