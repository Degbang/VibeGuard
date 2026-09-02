"""Tests for Layer 4 project-level ML classification."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from vibeguard.layer1_static.rules._finding import Finding
from vibeguard.layer2_features import extract_features
from vibeguard.layer3_scoring import ScoredFinding, score_features
from vibeguard.layer4_ml import (
    MLRiskLabel,
    RiskModel,
    TrainingExample,
    baseline_label_from_max_severity,
    build_project_features,
    evaluate_baseline_severity_model,
    evaluate_project_risk_model,
    leave_one_out_evaluate_project_risk_model,
    load_training_examples,
    load_trusted_model_contract,
    predict_project_risk,
    train_project_risk_model,
    write_trusted_model_contract,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
REAL_DATASET_PATH = REPO_ROOT / "data" / "labeled" / "layer4_projects.json"
REAL_CONTRACT_PATH = REPO_ROOT / "data" / "labeled" / "layer4_random_forest_contract.json"


def _scored_finding(
    tmp_path: Path,
    cwe_id: str,
    filename: str,
    *,
    line: int | None = 1,
    identifier: str = "identifier",
) -> ScoredFinding:
    redacted_value = "h*****2" if cwe_id == "CWE-798" else None
    feature = extract_features(
        (
            Finding(
                cwe_id=cwe_id,
                file_path=tmp_path / filename,
                line=line,
                identifier=identifier,
                message="candidate finding",
                redacted_value=redacted_value,
            ),
        )
    )[0]
    return score_features((feature,))[0]


def _value(features: tuple[str, ...], values: tuple[float, ...], name: str) -> float:
    return values[features.index(name)]


def test_build_project_features_returns_zero_vector_for_no_findings() -> None:
    features = build_project_features(())

    assert len(features.names) == len(features.values)
    assert all(value == 0.0 for value in features.values)


def test_build_project_features_counts_cwes_sources_and_combinations(
    tmp_path: Path,
) -> None:
    same_file = "Controller.java"
    findings = (
        _scored_finding(tmp_path, "CWE-798", same_file, identifier="password"),
        _scored_finding(tmp_path, "CWE-284", same_file, identifier="login"),
        _scored_finding(tmp_path, "CWE-20", "OtherController.java", identifier="body"),
        _scored_finding(tmp_path, "CWE-1035", "pom.xml", line=None, identifier="log4j-core"),
    )

    features = build_project_features(findings)

    assert _value(features.names, features.values, "finding_count") == 4.0
    assert _value(features.names, features.values, "cwe_798_count") == 1.0
    assert _value(features.names, features.values, "cwe_284_count") == 1.0
    assert _value(features.names, features.values, "pom_source_count") == 1.0
    assert _value(features.names, features.values, "missing_line_count") == 1.0
    assert _value(features.names, features.values, "has_secret_and_access_control") == 1.0
    assert _value(features.names, features.values, "same_file_secret_and_access_control") == 1.0
    assert _value(features.names, features.values, "has_secret_and_vulnerable_dependency") == 1.0


def test_train_project_risk_model_rejects_empty_training_set() -> None:
    with pytest.raises(ValueError, match="at least one training example"):
        train_project_risk_model(())


def test_train_project_risk_model_rejects_single_class_dataset(tmp_path: Path) -> None:
    example = TrainingExample(
        findings=(_scored_finding(tmp_path, "CWE-20", "Controller.java"),),
        label=MLRiskLabel.MEDIUM,
    )

    with pytest.raises(ValueError, match="two distinct risk labels"):
        train_project_risk_model((example,))


def test_train_and_predict_project_risk_from_seen_patterns(tmp_path: Path) -> None:
    low_project: tuple[ScoredFinding, ...] = ()
    medium_project = (_scored_finding(tmp_path, "CWE-20", "Controller.java"),)
    critical_project = (
        _scored_finding(tmp_path, "CWE-798", "Controller.java", identifier="password"),
        _scored_finding(tmp_path, "CWE-284", "Controller.java", identifier="login"),
        _scored_finding(tmp_path, "CWE-1035", "pom.xml", identifier="log4j-core"),
    )
    examples = (
        TrainingExample(low_project, MLRiskLabel.LOW),
        TrainingExample(medium_project, MLRiskLabel.MEDIUM),
        TrainingExample(critical_project, MLRiskLabel.CRITICAL),
    )

    model = train_project_risk_model(examples, random_state=7)

    low_prediction = predict_project_risk(model, low_project)
    critical_prediction = predict_project_risk(model, critical_project)

    assert low_prediction.label is MLRiskLabel.LOW
    assert critical_prediction.label is MLRiskLabel.CRITICAL
    assert 0.0 <= low_prediction.confidence <= 1.0
    assert 0.0 <= critical_prediction.confidence <= 1.0


def test_predict_project_risk_rejects_schema_mismatch(tmp_path: Path) -> None:
    examples = (
        TrainingExample((), MLRiskLabel.LOW),
        TrainingExample(
            (_scored_finding(tmp_path, "CWE-20", "Controller.java"),),
            MLRiskLabel.MEDIUM,
        ),
    )
    model = train_project_risk_model(examples)
    mismatched_model = replace(model, feature_names=("wrong_schema",))

    with pytest.raises(ValueError, match="feature schema does not match"):
        predict_project_risk(mismatched_model, ())


def test_load_training_examples_from_json_dataset(tmp_path: Path) -> None:
    dataset_path = tmp_path / "labels.json"
    dataset_path.write_text(
        json.dumps(
            {
                "projects": [
                    {
                        "project_id": "clean-service",
                        "label": "low",
                        "findings": [],
                    },
                    {
                        "project_id": "risky-service",
                        "label": "critical",
                        "findings": [
                            {
                                "cwe_id": "CWE-798",
                                "file_path": "src/main/resources/application.properties",
                                "line": 4,
                                "identifier": "spring.datasource.password",
                                "message": "Hardcoded credential-like config value",
                                "redacted_value": "h*****2",
                            },
                            {
                                "cwe_id": "CWE-284",
                                "file_path": "src/main/java/App.java",
                                "line": 12,
                                "identifier": "login",
                                "message": "Unprotected endpoint",
                                "redacted_value": None,
                            },
                        ],
                    },
                ]
            }
        ),
        encoding="utf-8",
    )

    examples = load_training_examples(dataset_path)

    assert [example.label for example in examples] == [MLRiskLabel.LOW, MLRiskLabel.CRITICAL]
    assert len(examples[0].findings) == 0
    assert len(examples[1].findings) == 2
    assert examples[1].findings[0].score == 95


def test_load_training_examples_rejects_invalid_label(tmp_path: Path) -> None:
    dataset_path = tmp_path / "labels.json"
    dataset_path.write_text(
        json.dumps(
            {
                "projects": [
                    {
                        "project_id": "service",
                        "label": "urgent",
                        "findings": [],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="must be one of"):
        load_training_examples(dataset_path)


def test_load_training_examples_rejects_non_portable_finding_path(tmp_path: Path) -> None:
    dataset_path = tmp_path / "labels.json"
    dataset_path.write_text(
        json.dumps(
            {
                "projects": [
                    {
                        "project_id": "service",
                        "label": "critical",
                        "findings": [
                            {
                                "cwe_id": "CWE-284",
                                "file_path": "../outside/App.java",
                                "line": 1,
                                "identifier": "login",
                                "message": "Unprotected endpoint",
                                "redacted_value": None,
                            }
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="without '..'"):
        load_training_examples(dataset_path)


def test_load_training_examples_supports_repo_relative_source_path(tmp_path: Path) -> None:
    dataset_path = tmp_path / "labels.json"
    dataset_path.write_text(
        json.dumps(
            {
                "projects": [
                    {
                        "project_id": "service",
                        "source_path": "tests/fixtures",
                        "label": "medium",
                        "findings": [
                            {
                                "cwe_id": "CWE-20",
                                "file_path": "UnvalidatedRequestBody.java",
                                "line": 9,
                                "identifier": "request",
                                "message": "Unvalidated request body",
                                "redacted_value": None,
                            }
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    examples = load_training_examples(dataset_path)

    assert (
        examples[0].findings[0].feature.file_path
        == REPO_ROOT / "tests" / "fixtures" / "UnvalidatedRequestBody.java"
    )


def test_load_training_examples_rejects_non_portable_source_path(tmp_path: Path) -> None:
    dataset_path = tmp_path / "labels.json"
    dataset_path.write_text(
        json.dumps(
            {
                "projects": [
                    {
                        "project_id": "service",
                        "source_path": "../outside",
                        "label": "medium",
                        "findings": [],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="without '..'"):
        load_training_examples(dataset_path)


def test_evaluate_project_risk_model_rejects_empty_examples() -> None:
    model = RiskModel(classifier=object(), feature_names=build_project_features(()).names)

    with pytest.raises(ValueError, match="at least one evaluation example"):
        evaluate_project_risk_model(model, ())


def test_evaluate_project_risk_model_returns_accuracy_macro_f1_and_confusion(
    tmp_path: Path,
) -> None:
    class DeterministicClassifier:
        classes_ = ("low", "critical")

        def predict_proba(self, rows: list[tuple[float, ...]]) -> list[list[float]]:
            finding_count_index = build_project_features(()).names.index("finding_count")
            return [[1.0, 0.0] if row[finding_count_index] == 0.0 else [0.0, 1.0] for row in rows]

    low_project: tuple[ScoredFinding, ...] = ()
    critical_project = (
        _scored_finding(tmp_path, "CWE-798", "Controller.java", identifier="password"),
        _scored_finding(tmp_path, "CWE-284", "Controller.java", identifier="login"),
    )
    examples = (
        TrainingExample(low_project, MLRiskLabel.LOW),
        TrainingExample(critical_project, MLRiskLabel.CRITICAL),
    )
    model = RiskModel(
        classifier=DeterministicClassifier(),
        feature_names=build_project_features(()).names,
    )

    result = evaluate_project_risk_model(model, examples)

    assert result.accuracy == 1.0
    assert result.macro_f1 == 1.0
    assert [(cell.actual, cell.predicted, cell.count) for cell in result.confusion] == [
        (MLRiskLabel.LOW, MLRiskLabel.LOW, 1),
        (MLRiskLabel.CRITICAL, MLRiskLabel.CRITICAL, 1),
    ]


def test_leave_one_out_evaluate_project_risk_model_rejects_too_few_examples() -> None:
    with pytest.raises(ValueError, match="at least two labelled projects"):
        leave_one_out_evaluate_project_risk_model((TrainingExample((), MLRiskLabel.LOW),))


def test_write_and_load_trusted_model_contract_round_trip(tmp_path: Path) -> None:
    dataset_path = tmp_path / "labels.json"
    dataset_path.write_text(
        json.dumps(
            {
                "projects": [
                    {"project_id": "clean-service", "label": "low", "findings": []},
                    {
                        "project_id": "critical-service",
                        "label": "critical",
                        "findings": [
                            {
                                "cwe_id": "CWE-798",
                                "file_path": "src/main/resources/application.properties",
                                "line": 4,
                                "identifier": "spring.datasource.password",
                                "message": "Hardcoded credential-like config value",
                                "redacted_value": "h*****2",
                            }
                        ],
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    contract_path = tmp_path / "model_contract.json"

    contract = write_trusted_model_contract(contract_path, dataset_path, random_state=7)
    loaded_model = load_trusted_model_contract(contract_path)
    prediction = predict_project_risk(
        loaded_model, load_training_examples(dataset_path)[1].findings
    )

    assert contract.training_example_count == 2
    assert prediction.label is MLRiskLabel.CRITICAL


def test_load_trusted_model_contract_rejects_dataset_hash_mismatch(tmp_path: Path) -> None:
    dataset_path = tmp_path / "labels.json"
    dataset_path.write_text(
        json.dumps(
            {
                "projects": [
                    {"project_id": "clean-service", "label": "low", "findings": []},
                    {
                        "project_id": "critical-service",
                        "label": "critical",
                        "findings": [
                            {
                                "cwe_id": "CWE-798",
                                "file_path": "src/main/resources/application.properties",
                                "line": 4,
                                "identifier": "spring.datasource.password",
                                "message": "Hardcoded credential-like config value",
                                "redacted_value": "h*****2",
                            }
                        ],
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    contract_path = tmp_path / "model_contract.json"
    write_trusted_model_contract(contract_path, dataset_path)
    dataset_path.write_text(
        dataset_path.read_text(encoding="utf-8").replace("critical", "high"), encoding="utf-8"
    )

    with pytest.raises(ValueError, match="dataset hash does not match"):
        load_trusted_model_contract(contract_path)


def test_real_layer4_dataset_loads_and_leave_one_out_evaluates() -> None:
    # The dataset deliberately includes one project
    # (duplicate-validation-gaps-service, index 13) whose "high" label
    # depends on a pattern - the same CWE recurring across multiple
    # endpoints elevating risk beyond any single finding's own severity -
    # that appears exactly once in the labelled corpus. Leave-one-out
    # cannot learn a pattern from zero training examples of it, so this
    # project is expected to miss; that miss is itself the evidence this
    # dataset is no longer degenerate (see IMPLEMENTATION_LOG.md).
    examples = load_training_examples(REAL_DATASET_PATH)
    result = leave_one_out_evaluate_project_risk_model(examples, random_state=42)

    assert len(examples) == 15
    assert len(result.predictions) == 15
    assert result.accuracy == pytest.approx(14 / 15)
    assert result.predictions[13].actual is MLRiskLabel.HIGH
    assert result.predictions[13].predicted is MLRiskLabel.MEDIUM
    assert all(
        prediction.actual is prediction.predicted
        for index, prediction in enumerate(result.predictions)
        if index != 13
    )
    assert [(cell.actual, cell.predicted, cell.count) for cell in result.confusion] == [
        (MLRiskLabel.LOW, MLRiskLabel.LOW, 2),
        (MLRiskLabel.MEDIUM, MLRiskLabel.MEDIUM, 2),
        (MLRiskLabel.HIGH, MLRiskLabel.MEDIUM, 1),
        (MLRiskLabel.HIGH, MLRiskLabel.HIGH, 3),
        (MLRiskLabel.CRITICAL, MLRiskLabel.CRITICAL, 7),
    ]


def test_real_layer4_dataset_baseline_matches_leave_one_out_exactly() -> None:
    """The fixed max-severity baseline currently ties Layer 4's learned
    leave-one-out result on this dataset, including making the identical
    single error on the one under-represented "breadth" pattern (see the
    test above). This is the honest current answer to "does project-level
    ML add value beyond the deterministic rule-based scorer": not yet,
    on the data available - not a bug, and not the result the training
    apps were built to force either way."""
    examples = load_training_examples(REAL_DATASET_PATH)
    loo_result = leave_one_out_evaluate_project_risk_model(examples, random_state=42)
    baseline_result = evaluate_baseline_severity_model(examples)

    assert baseline_result.accuracy == loo_result.accuracy
    assert baseline_result.macro_f1 == pytest.approx(loo_result.macro_f1)
    for loo_prediction, baseline_prediction in zip(
        loo_result.predictions, baseline_result.predictions, strict=True
    ):
        assert baseline_prediction.actual is loo_prediction.actual
        assert baseline_prediction.predicted is loo_prediction.predicted


def test_baseline_label_from_max_severity_uses_highest_scoring_finding(tmp_path: Path) -> None:
    low = _scored_finding(tmp_path, "CWE-20", "Low.java")
    critical = _scored_finding(tmp_path, "CWE-798", "Crit.java")

    assert baseline_label_from_max_severity([low, critical]) is MLRiskLabel.CRITICAL
    assert baseline_label_from_max_severity([low]) is MLRiskLabel.MEDIUM
    assert baseline_label_from_max_severity([]) is MLRiskLabel.LOW


def test_evaluate_baseline_severity_model_rejects_empty_examples() -> None:
    with pytest.raises(ValueError, match="at least one evaluation example"):
        evaluate_baseline_severity_model([])


def test_real_layer4_contract_loads_trusted_model() -> None:
    model = load_trusted_model_contract(REAL_CONTRACT_PATH)
    prediction = predict_project_risk(model, load_training_examples(REAL_DATASET_PATH)[2].findings)

    assert prediction.label is MLRiskLabel.CRITICAL
