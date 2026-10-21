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
    EvaluationResult,
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


def _write_minimal_dataset(dataset_path: Path) -> None:
    """Shared two-project fixture for the contract-tampering tests below -
    the exact content doesn't matter for any of them, only that it loads
    and trains cleanly before the contract itself gets tampered with."""
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


# The six tests below close a real coverage gap found by direct
# inspection of contract.py, not assumed from the percentage alone:
# load_trusted_model_contract's dataset-hash check
# (test_load_trusted_model_contract_rejects_dataset_hash_mismatch above)
# was tested, but its other four integrity checks - example-count
# mismatch, feature-schema mismatch, label-set mismatch, and
# _read_contract's own schema_version/model_kind/malformed-JSON/
# missing-field error paths - had no test reaching them at all. This is
# the trust boundary that lets Layer 4 avoid loading an arbitrary
# serialized model artifact; an untested comparison here is exactly the
# kind of place a subtle bug (an inverted condition, a wrong field)
# would go unnoticed.


def test_load_trusted_model_contract_rejects_example_count_mismatch(tmp_path: Path) -> None:
    dataset_path = tmp_path / "labels.json"
    _write_minimal_dataset(dataset_path)
    contract_path = tmp_path / "model_contract.json"
    write_trusted_model_contract(contract_path, dataset_path)

    contract_data = json.loads(contract_path.read_text(encoding="utf-8"))
    contract_data["training_example_count"] = 999
    contract_path.write_text(json.dumps(contract_data), encoding="utf-8")

    with pytest.raises(ValueError, match="example count does not match"):
        load_trusted_model_contract(contract_path)


def test_load_trusted_model_contract_rejects_feature_schema_mismatch(tmp_path: Path) -> None:
    dataset_path = tmp_path / "labels.json"
    _write_minimal_dataset(dataset_path)
    contract_path = tmp_path / "model_contract.json"
    write_trusted_model_contract(contract_path, dataset_path)

    contract_data = json.loads(contract_path.read_text(encoding="utf-8"))
    contract_data["feature_names"] = ["not", "the", "real", "schema"]
    contract_path.write_text(json.dumps(contract_data), encoding="utf-8")

    with pytest.raises(ValueError, match="feature schema does not match"):
        load_trusted_model_contract(contract_path)


def test_load_trusted_model_contract_rejects_label_set_mismatch(tmp_path: Path) -> None:
    dataset_path = tmp_path / "labels.json"
    _write_minimal_dataset(dataset_path)
    contract_path = tmp_path / "model_contract.json"
    write_trusted_model_contract(contract_path, dataset_path)

    contract_data = json.loads(contract_path.read_text(encoding="utf-8"))
    contract_data["label_names"] = ["low", "medium", "high", "critical", "extra"]
    contract_path.write_text(json.dumps(contract_data), encoding="utf-8")

    with pytest.raises(ValueError, match="label set does not match"):
        load_trusted_model_contract(contract_path)


def test_load_trusted_model_contract_rejects_unsupported_schema_version(
    tmp_path: Path,
) -> None:
    dataset_path = tmp_path / "labels.json"
    _write_minimal_dataset(dataset_path)
    contract_path = tmp_path / "model_contract.json"
    write_trusted_model_contract(contract_path, dataset_path)

    contract_data = json.loads(contract_path.read_text(encoding="utf-8"))
    contract_data["schema_version"] = 999
    contract_path.write_text(json.dumps(contract_data), encoding="utf-8")

    with pytest.raises(ValueError, match="unsupported trusted model contract schema_version"):
        load_trusted_model_contract(contract_path)


def test_load_trusted_model_contract_rejects_unsupported_model_kind(tmp_path: Path) -> None:
    dataset_path = tmp_path / "labels.json"
    _write_minimal_dataset(dataset_path)
    contract_path = tmp_path / "model_contract.json"
    write_trusted_model_contract(contract_path, dataset_path)

    contract_data = json.loads(contract_path.read_text(encoding="utf-8"))
    contract_data["model_kind"] = "gradient_boosted_tree"
    contract_path.write_text(json.dumps(contract_data), encoding="utf-8")

    with pytest.raises(ValueError, match="unsupported trusted model contract model_kind"):
        load_trusted_model_contract(contract_path)


def test_load_trusted_model_contract_rejects_malformed_json(tmp_path: Path) -> None:
    contract_path = tmp_path / "model_contract.json"
    contract_path.write_text("{not valid json", encoding="utf-8")

    with pytest.raises(ValueError, match="not valid JSON"):
        load_trusted_model_contract(contract_path)


def test_load_trusted_model_contract_rejects_a_missing_required_field(tmp_path: Path) -> None:
    dataset_path = tmp_path / "labels.json"
    _write_minimal_dataset(dataset_path)
    contract_path = tmp_path / "model_contract.json"
    write_trusted_model_contract(contract_path, dataset_path)

    contract_data = json.loads(contract_path.read_text(encoding="utf-8"))
    del contract_data["dataset_path"]
    contract_path.write_text(json.dumps(contract_data), encoding="utf-8")

    with pytest.raises(ValueError, match="dataset_path"):
        load_trusted_model_contract(contract_path)


def test_real_layer4_dataset_loads_and_leave_one_out_evaluates() -> None:
    # Dataset expanded a fifth time 2026-10-11 with 14 more Claude-
    # generated projects targeted at the four duplicate-feature-vector
    # clusters Case 17 traced (2026-09-10 entry) - testing whether more
    # carefully-labelled examples in exactly those clusters gives "high"
    # severity a real majority anywhere. On its own it did not (0/13
    # high recall, see IMPLEMENTATION_LOG.md's first 2026-10-11 entry).
    # That result pointed at the real bottleneck: _SENSITIVE_DOMAIN_KEYWORDS
    # was missing clean matches for several real high/critical projects
    # entirely (zero keyword overlap at all). Widening it (second
    # 2026-10-11 entry) combined with the new data gets "high" recall to
    # 6/13 - genuinely better than the keyword fix alone on the original
    # 50 projects (4/10) and far better than the new data alone (0/13).
    # A second keyword-widening pass (2026-10-21) added four action-verb
    # keywords (upload/download/replay/campaign, a different axis from
    # the business-domain nouns above) after three more high-severity
    # misses shared no business-domain keyword at all but did share an
    # unauthenticated state-changing/bulk-impact action - "high" recall
    # rises to 7/13, with zero per-class recall regression (see
    # IMPLEMENTATION_LOG.md). 64 projects total (8 -> 15 -> 22 -> 32 ->
    # 42 -> 50 -> 64); leave-one-out accuracy is 0.484375 (31/64),
    # macro-F1 0.5232.
    examples = load_training_examples(REAL_DATASET_PATH)
    result = leave_one_out_evaluate_project_risk_model(examples, random_state=42)

    assert len(examples) == 64
    assert len(result.predictions) == 64
    assert result.accuracy == pytest.approx(31 / 64)
    assert [(cell.actual, cell.predicted, cell.count) for cell in result.confusion] == [
        (MLRiskLabel.LOW, MLRiskLabel.LOW, 9),
        (MLRiskLabel.LOW, MLRiskLabel.MEDIUM, 5),
        (MLRiskLabel.MEDIUM, MLRiskLabel.LOW, 8),
        (MLRiskLabel.MEDIUM, MLRiskLabel.MEDIUM, 8),
        (MLRiskLabel.MEDIUM, MLRiskLabel.HIGH, 9),
        (MLRiskLabel.HIGH, MLRiskLabel.MEDIUM, 6),
        (MLRiskLabel.HIGH, MLRiskLabel.HIGH, 7),
        (MLRiskLabel.CRITICAL, MLRiskLabel.HIGH, 5),
        (MLRiskLabel.CRITICAL, MLRiskLabel.CRITICAL, 7),
    ]


def test_real_layer4_dataset_leave_one_out_beats_baseline_overall_but_not_on_every_batch() -> None:
    """Layer 4's leave-one-out result (0.484375, 31/64) beats the fixed
    max-severity baseline (0.359375, 23/64) in aggregate - the gap
    widened again (from 30/64) after a second keyword-widening pass
    (2026-10-21, action-verb keywords) closed a real, non-circular "high"
    recall miss on top of the 2026-10-11 business-domain-keyword fix -
    see IMPLEMENTATION_LOG.md for the full account, including why this
    one was checked for zero per-class recall regression before shipping,
    not just the aggregate numbers. Leave-one-out retrains on every
    *other* current example each fold, so any batch's own per-batch
    count can shift when the feature vector changes, even though those
    projects' own features never changed:
    - Original 22 (synthetic + first AI batch): baseline 15/22, LOO
      14/22 - unchanged throughout.
    - Batch 2 (10 projects, indices 22-31): baseline 0/10, LOO 3/10.
    - Batch 3 (10 projects, indices 32-41): baseline 1/10, LOO 4/10.
    - Batch 4 (8 projects, indices 42-49): baseline 4/8, LOO 5/8 - the
      baseline no longer beats leave-one-out here, unlike on the
      50-project/old-keyword dataset (2/8) - see IMPLEMENTATION_LOG.md
      2026-09-04 for that original finding.
    - Batch 5 (14 projects, indices 50-63, added 2026-10-11): baseline
      3/14, LOO 5/14 - the same four colliding clusters Case 17 traced,
      now with a real leave-one-out edge over the baseline, where there
      was none before the first keyword fix.
    """
    examples = load_training_examples(REAL_DATASET_PATH)
    loo_result = leave_one_out_evaluate_project_risk_model(examples, random_state=42)
    baseline_result = evaluate_baseline_severity_model(examples)

    assert loo_result.accuracy == pytest.approx(31 / 64)
    assert baseline_result.accuracy == pytest.approx(23 / 64)
    assert loo_result.accuracy > baseline_result.accuracy

    def _correct(result: EvaluationResult, start: int, stop: int) -> int:
        return sum(
            1
            for prediction in result.predictions[start:stop]
            if prediction.actual is prediction.predicted
        )

    assert _correct(baseline_result, 0, 22) == 15
    assert _correct(loo_result, 0, 22) == 14
    assert _correct(baseline_result, 22, 32) == 0
    assert _correct(loo_result, 22, 32) == 3
    assert _correct(baseline_result, 32, 42) == 1
    assert _correct(loo_result, 32, 42) == 4
    assert _correct(baseline_result, 42, 50) == 4
    assert _correct(loo_result, 42, 50) == 5
    assert _correct(baseline_result, 50, 64) == 3
    assert _correct(loo_result, 50, 64) == 5


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

    assert len(loo_result.predictions) == len(baseline_result.predictions) == 64
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


def test_has_sensitive_domain_signal_matches_action_verb_keywords(tmp_path: Path) -> None:
    """The 2026-10-21 addition: unlike every keyword above (what the data
    *is*), these name what an unauthenticated caller can *make happen* -
    an unauthenticated bulk/state-changing action, not a sensitive
    business domain. "FileController" alone is the existing false-for-
    generic-names case below; it's the "upload"/"download" identifiers
    that must now also be caught."""
    cases = (
        ("FileController.java", "upload"),
        ("FileController.java", "download"),
        ("WebhookReplayController.java", "replayEvent"),
        ("NewsletterController.java", "campaign"),
    )
    for filename, identifier in cases:
        findings = (_scored_finding(tmp_path, "CWE-284", filename, identifier=identifier),)
        features = build_project_features(findings)
        assert _value(features.names, features.values, "has_sensitive_domain_signal") == 1.0, (
            filename,
            identifier,
        )


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
