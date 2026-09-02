"""Layer 4: ML classification.

Builds project-level ML features from Layer 3 scored findings, trains a
local classifier, loads labelled datasets, and evaluates predictions.
Layer 4 does not re-detect vulnerabilities from source code.
"""

from vibeguard.layer4_ml.contract import (
    TrustedModelContract,
    load_trusted_model_contract,
    write_trusted_model_contract,
)
from vibeguard.layer4_ml.dataset import load_training_examples
from vibeguard.layer4_ml.evaluator import (
    ConfusionCell,
    EvaluationResult,
    ProjectPrediction,
    baseline_label_from_max_severity,
    evaluate_baseline_severity_model,
    evaluate_project_risk_model,
    leave_one_out_evaluate_project_risk_model,
)
from vibeguard.layer4_ml.predictor import (
    MLPrediction,
    MLRiskLabel,
    ProjectFeatures,
    RiskModel,
    build_project_features,
    predict_project_risk,
)
from vibeguard.layer4_ml.trainer import TrainingExample, train_project_risk_model

__all__ = [
    "MLPrediction",
    "MLRiskLabel",
    "ConfusionCell",
    "EvaluationResult",
    "ProjectFeatures",
    "ProjectPrediction",
    "RiskModel",
    "TrustedModelContract",
    "TrainingExample",
    "baseline_label_from_max_severity",
    "build_project_features",
    "evaluate_baseline_severity_model",
    "evaluate_project_risk_model",
    "leave_one_out_evaluate_project_risk_model",
    "load_trusted_model_contract",
    "load_training_examples",
    "predict_project_risk",
    "train_project_risk_model",
    "write_trusted_model_contract",
]
