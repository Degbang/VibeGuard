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
    # Dataset expanded again 2026-09-03 with a second batch of 10
    # Codex-generated projects, deliberately targeting the
    # sensitive-domain bucket that batch 1 under-supported (see
    # IMPLEMENTATION_LOG.md). Most of batch 2 turned out to implement
    # real, hand-rolled access control (a header/API-key check) that
    # CWE-284 cannot see - the same pattern found once in batch 1
    # (ai-admin-dashboard-service), now confirmed as Codex's dominant
    # behaviour when it does add protection to a small Java service:
    # 9 of the 10 real protection mechanisms observed across both
    # AI-generated batches are this hand-rolled shape, versus 1 real
    # Spring Security usage. 32 projects total; leave-one-out accuracy
    # is 0.531 (17/32).
    examples = load_training_examples(REAL_DATASET_PATH)
    result = leave_one_out_evaluate_project_risk_model(examples, random_state=42)

    assert len(examples) == 32
    assert len(result.predictions) == 32
    assert result.accuracy == pytest.approx(17 / 32)
    assert [(cell.actual, cell.predicted, cell.count) for cell in result.confusion] == [
        (MLRiskLabel.LOW, MLRiskLabel.LOW, 6),
        (MLRiskLabel.LOW, MLRiskLabel.MEDIUM, 1),
        (MLRiskLabel.MEDIUM, MLRiskLabel.LOW, 3),
        (MLRiskLabel.MEDIUM, MLRiskLabel.MEDIUM, 4),
        (MLRiskLabel.MEDIUM, MLRiskLabel.HIGH, 2),
        (MLRiskLabel.MEDIUM, MLRiskLabel.CRITICAL, 1),
        (MLRiskLabel.HIGH, MLRiskLabel.MEDIUM, 5),
        (MLRiskLabel.CRITICAL, MLRiskLabel.MEDIUM, 3),
        (MLRiskLabel.CRITICAL, MLRiskLabel.CRITICAL, 7),
    ]


def test_real_layer4_dataset_leave_one_out_now_beats_baseline_with_a_caveat() -> None:
    """For the first time in this project, Layer 4's leave-one-out result
    (0.531, 17/32) beats the fixed max-severity baseline (0.469, 15/32).
    This must be reported with the caveat that makes it true, not as an
    unqualified win: every batch-2 project's single finding type is
    CWE-284, whose raw Layer 3 severity band is always "high" - and every
    batch-2 label was assigned as low/medium/critical, never high (see
    IMPLEMENTATION_LOG.md's per-project rationale - each label reflects a
    real, hand-rolled-but-invisible-to-CWE-284 protection mechanism of
    varying quality). The baseline, which only ever reads the raw
    severity band, is therefore *structurally guaranteed* to miss all 10
    batch-2 projects - confirmed directly, it gets 0/10. Layer 4 gets
    3/10 (still wrong on the other 7), using has_sensitive_domain_signal
    and finding-count features baseline has no access to at all. The
    honest framing: Layer 4 now has a real, demonstrated edge over a
    strategy that cannot ever succeed on this batch by construction - it
    is not yet evidence Layer 4 reliably predicts real-world risk, since
    it is still wrong most of the time on the very projects that produced
    the edge."""
    examples = load_training_examples(REAL_DATASET_PATH)
    loo_result = leave_one_out_evaluate_project_risk_model(examples, random_state=42)
    baseline_result = evaluate_baseline_severity_model(examples)

    assert loo_result.accuracy == pytest.approx(17 / 32)
    assert baseline_result.accuracy == pytest.approx(15 / 32)
    assert loo_result.accuracy > baseline_result.accuracy

    batch_two_start = 22
    baseline_batch_two_correct = sum(
        1
        for prediction in baseline_result.predictions[batch_two_start:]
        if prediction.actual is prediction.predicted
    )
    loo_batch_two_correct = sum(
        1
        for prediction in loo_result.predictions[batch_two_start:]
        if prediction.actual is prediction.predicted
    )
    assert baseline_batch_two_correct == 0
    assert loo_batch_two_correct == 3


def test_has_sensitive_domain_signal_distinguishes_payments_from_catalog(tmp_path: Path) -> None:
    """The fix: ai-payments-service and ai-product-catalog-service used to
    share a byte-identical feature vector; they must not anymore."""
    examples = load_training_examples(REAL_DATASET_PATH)
    data = json.loads(REAL_DATASET_PATH.read_text(encoding="utf-8"))
    by_id = {p["project_id"]: i for i, p in enumerate(data["projects"])}
    payments = examples[by_id["ai-payments-service"]]
    catalog = examples[by_id["ai-product-catalog-service"]]

    payments_features = build_project_features(payments.findings)
    catalog_features = build_project_features(catalog.findings)

    assert payments_features.values != catalog_features.values
    assert (
        _value(payments_features.names, payments_features.values, "has_sensitive_domain_signal")
        == 1.0
    )
    assert (
        _value(catalog_features.names, catalog_features.values, "has_sensitive_domain_signal")
        == 0.0
    )
    assert payments.label is MLRiskLabel.CRITICAL
    assert catalog.label is MLRiskLabel.LOW


def test_has_sensitive_domain_signal_does_not_leak_from_the_absolute_checkout_path(
    tmp_path: Path,
) -> None:
    """Regression test for a real bug caught in review before it shipped:
    the first implementation matched keywords against the full resolved
    file path rather than just the file name. Since FindingFeature.file_path
    is an absolute, resolved path, and this machine's home directory is
    /Users/<name>/..., that version made every single project match
    "user" via "/Users/" regardless of its actual code - the same class of
    portability bug that got path_depth removed from Layer 2 on
    2026-07-21. Constructs a path with "user" in a parent directory
    segment but a finding filename that has nothing to do with any
    sensitive domain, and asserts the signal stays off.
    """
    project_root = tmp_path / "userspace" / "checkout"
    findings = (
        _scored_finding(project_root, "CWE-284", "ProductController.java", identifier="list"),
    )

    features = build_project_features(findings)

    assert _value(features.names, features.values, "has_sensitive_domain_signal") == 0.0


def test_real_layer4_dataset_baseline_predictions_smoke() -> None:
    """Loose smoke check that the two evaluation modes are actually
    computing over the same real examples, not silently diverging."""
    examples = load_training_examples(REAL_DATASET_PATH)
    loo_result = leave_one_out_evaluate_project_risk_model(examples, random_state=42)
    baseline_result = evaluate_baseline_severity_model(examples)

    assert len(loo_result.predictions) == len(baseline_result.predictions) == 32
    for loo_prediction, baseline_prediction in zip(
        loo_result.predictions, baseline_result.predictions, strict=True
    ):
        assert baseline_prediction.actual is loo_prediction.actual
        assert isinstance(loo_prediction.predicted, MLRiskLabel)
        assert isinstance(baseline_prediction.predicted, MLRiskLabel)


def test_has_sensitive_domain_signal_matches_common_domain_file_names(tmp_path: Path) -> None:
    for filename in ("PaymentController.java", "AdminController.java", "UserController.java"):
        findings = (_scored_finding(tmp_path, "CWE-284", filename, identifier="handle"),)
        features = build_project_features(findings)
        assert (
            _value(features.names, features.values, "has_sensitive_domain_signal") == 1.0
        ), filename


def test_has_sensitive_domain_signal_false_for_generic_file_names(tmp_path: Path) -> None:
    for filename in ("ProductController.java", "OrderController.java", "FileController.java"):
        findings = (_scored_finding(tmp_path, "CWE-284", filename, identifier="list"),)
        features = build_project_features(findings)
        assert (
            _value(features.names, features.values, "has_sensitive_domain_signal") == 0.0
        ), filename


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
