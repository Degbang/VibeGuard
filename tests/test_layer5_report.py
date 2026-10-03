"""Tests for Layer 5 SHAP explainability and reporting."""

from __future__ import annotations

from io import StringIO
from pathlib import Path
from typing import Any
from unittest.mock import patch

import numpy as np
import pytest
from rich.console import Console

from vibeguard.layer1_static.rules._finding import Finding
from vibeguard.layer2_features import extract_features
from vibeguard.layer3_scoring import ScoredFinding, score_features
from vibeguard.layer4_ml import MLRiskLabel, TrainingExample, train_project_risk_model
from vibeguard.layer5_report import (
    build_project_risk_report,
    explain_project_risk,
    render_console_report,
)
from vibeguard.layer5_report.explainer import (
    _explain_row,
    _select_predicted_base_value,
    _select_predicted_feature_values,
)


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


def test_explain_project_risk_returns_sorted_contributions_and_probability_sum(
    tmp_path: Path,
) -> None:
    low_project: tuple[ScoredFinding, ...] = ()
    medium_project = (_scored_finding(tmp_path, "CWE-20", "Controller.java"),)
    critical_project = (
        _scored_finding(tmp_path, "CWE-798", "Controller.java", identifier="password"),
        _scored_finding(tmp_path, "CWE-284", "Controller.java", identifier="login"),
        _scored_finding(tmp_path, "CWE-1035", "pom.xml", line=None, identifier="log4j-core"),
    )
    model = train_project_risk_model(
        (
            TrainingExample(low_project, MLRiskLabel.LOW),
            TrainingExample(medium_project, MLRiskLabel.MEDIUM),
            TrainingExample(critical_project, MLRiskLabel.CRITICAL),
        ),
        random_state=7,
    )

    explanation = explain_project_risk(model, critical_project)

    assert explanation.prediction.label is MLRiskLabel.CRITICAL
    assert len(explanation.contributions) == len(explanation.prediction.features.names)
    assert explanation.contributions == tuple(
        sorted(
            explanation.contributions,
            key=lambda contribution: (-abs(contribution.shap_value), contribution.feature_name),
        )
    )
    assert (
        pytest.approx(
            explanation.baseline_probability
            + sum(contribution.shap_value for contribution in explanation.contributions),
            rel=1e-6,
        )
        == explanation.prediction.confidence
    )


def test_build_and_render_project_risk_report(tmp_path: Path) -> None:
    findings = (
        _scored_finding(tmp_path, "CWE-798", "Controller.java", identifier="password"),
        _scored_finding(tmp_path, "CWE-284", "Controller.java", identifier="login"),
    )
    model = train_project_risk_model(
        (
            TrainingExample((), MLRiskLabel.LOW),
            TrainingExample(findings, MLRiskLabel.CRITICAL),
        ),
        random_state=11,
    )

    report = build_project_risk_report(tmp_path, model, findings)
    output = StringIO()
    console = Console(file=output, force_terminal=False, color_system=None)

    render_console_report(report, console=console, max_contributions=3)

    rendered = output.getvalue()
    assert report.scan_path == tmp_path
    assert report.scored_findings == findings
    assert "VibeGuard Layer 4 - Project Risk Prediction" in rendered
    assert "VibeGuard Layer 5 - SHAP Feature Attribution" in rendered
    assert "VibeGuard Layer 5 - Plain-Language Summary" in rendered
    assert report.explanation.prediction.label.value in rendered


def test_select_predicted_feature_values_supports_feature_by_class_2d_shape() -> None:
    values = np.array(
        [
            [0.1, 0.2],
            [0.3, 0.4],
            [0.5, 0.6],
        ],
        dtype=float,
    )

    result = _select_predicted_feature_values(values, predicted_index=1, expected_class_count=2)

    assert np.array_equal(result, np.array([0.2, 0.4, 0.6], dtype=float))


def test_select_predicted_feature_values_rejects_single_row_2d_shape_for_multiclass() -> None:
    values = np.zeros((1, 3), dtype=float)

    with pytest.raises(
        ValueError,
        match="only valid for single-output models",
    ):
        _select_predicted_feature_values(values, predicted_index=0, expected_class_count=4)


def test_select_predicted_base_value_rejects_scalar_for_multiclass() -> None:
    base_values = np.array(0.123, dtype=float)

    with pytest.raises(
        ValueError,
        match="only valid for single-output models",
    ):
        _select_predicted_base_value(base_values, predicted_index=0, expected_class_count=4)


def test_explain_project_risk_rejects_inconsistent_multiclass_shap_output(
    tmp_path: Path,
) -> None:
    findings = (
        _scored_finding(tmp_path, "CWE-798", "Controller.java", identifier="password"),
        _scored_finding(tmp_path, "CWE-284", "Controller.java", identifier="login"),
    )
    model = train_project_risk_model(
        (
            TrainingExample((), MLRiskLabel.LOW),
            TrainingExample(findings, MLRiskLabel.CRITICAL),
        ),
        random_state=11,
    )

    class FakeExplanation:
        def __init__(self, values: np.ndarray, base_values: np.ndarray) -> None:
            self.values = values
            self.base_values = base_values

    class FakeExplainer:
        def __call__(self, row: np.ndarray, check_additivity: bool = False) -> Any:
            del row, check_additivity
            return FakeExplanation(
                values=np.zeros((1, len(model.feature_names)), dtype=float),
                base_values=np.array(0.123, dtype=float),
            )

    with patch("shap.TreeExplainer", return_value=FakeExplainer()):
        with pytest.raises(
            ValueError,
            match="single-output models",
        ):
            explain_project_risk(model, findings)


def test_render_console_report_rejects_negative_max_contributions(tmp_path: Path) -> None:
    findings = (
        _scored_finding(tmp_path, "CWE-798", "Controller.java", identifier="password"),
        _scored_finding(tmp_path, "CWE-284", "Controller.java", identifier="login"),
    )
    model = train_project_risk_model(
        (
            TrainingExample((), MLRiskLabel.LOW),
            TrainingExample(findings, MLRiskLabel.CRITICAL),
        ),
        random_state=11,
    )
    report = build_project_risk_report(tmp_path, model, findings)

    with pytest.raises(ValueError, match="max_contributions must be non-negative"):
        render_console_report(report, console=Console(file=StringIO()), max_contributions=-1)


def test_render_console_report_rejects_negative_max_summary_features(tmp_path: Path) -> None:
    findings = (
        _scored_finding(tmp_path, "CWE-798", "Controller.java", identifier="password"),
        _scored_finding(tmp_path, "CWE-284", "Controller.java", identifier="login"),
    )
    model = train_project_risk_model(
        (
            TrainingExample((), MLRiskLabel.LOW),
            TrainingExample(findings, MLRiskLabel.CRITICAL),
        ),
        random_state=11,
    )
    report = build_project_risk_report(tmp_path, model, findings)

    with pytest.raises(ValueError, match="max_summary_features must be non-negative"):
        render_console_report(report, console=Console(file=StringIO()), max_summary_features=-1)


# -- Exhaustive shape-validation coverage for _select_predicted_feature_values
# and _select_predicted_base_value -------------------------------------------
#
# These are the fail-closed guards the 2026-07-30 independent QA pass added
# so an unexpected SHAP output shape is rejected outright rather than
# silently misread - exactly the kind of judgment-adjacent logic CLAUDE.md's
# coverage priority calls out (detection/explanation logic over glue code).
# Each branch is exercised directly, by calling these private functions with
# hand-built arrays, the same style the pre-existing tests for this file
# already use - not only through the full explain_project_risk() pipeline,
# which cannot easily reach every shape (a real trained classifier's own
# SHAP output shape is consistent across calls, so most of these inconsistent
# shapes can only arise from a genuinely different classifier/environment,
# not from this project's own code paths).


def test_select_predicted_feature_values_3d_rejects_wrong_sample_count() -> None:
    values = np.zeros((2, 5, 3), dtype=float)

    with pytest.raises(ValueError, match="exactly one sample"):
        _select_predicted_feature_values(values, predicted_index=0, expected_class_count=3)


def test_select_predicted_feature_values_3d_rejects_wrong_class_axis() -> None:
    values = np.zeros((1, 5, 3), dtype=float)

    with pytest.raises(ValueError, match="class axis did not match"):
        _select_predicted_feature_values(values, predicted_index=0, expected_class_count=4)


def test_select_predicted_feature_values_3d_rejects_out_of_range_index() -> None:
    values = np.zeros((1, 5, 3), dtype=float)

    with pytest.raises(ValueError, match="out of range"):
        _select_predicted_feature_values(values, predicted_index=3, expected_class_count=3)


def test_select_predicted_feature_values_2d_single_row_valid_for_single_output() -> None:
    values = np.array([[0.1, 0.2, 0.3]], dtype=float)

    result = _select_predicted_feature_values(values, predicted_index=0, expected_class_count=1)

    assert np.array_equal(result, np.array([0.1, 0.2, 0.3]))


def test_select_predicted_feature_values_2d_rejects_wrong_class_axis() -> None:
    values = np.zeros((5, 3), dtype=float)

    with pytest.raises(ValueError, match="one column per classifier output class"):
        _select_predicted_feature_values(values, predicted_index=0, expected_class_count=4)


def test_select_predicted_feature_values_2d_rejects_out_of_range_index() -> None:
    values = np.zeros((5, 3), dtype=float)

    with pytest.raises(ValueError, match="out of range"):
        _select_predicted_feature_values(values, predicted_index=3, expected_class_count=3)


def test_select_predicted_feature_values_1d_rejects_multiclass() -> None:
    values = np.array([0.1, 0.2, 0.3], dtype=float)

    with pytest.raises(ValueError, match="only valid for single-output models"):
        _select_predicted_feature_values(values, predicted_index=0, expected_class_count=2)


def test_select_predicted_feature_values_1d_valid_for_single_output() -> None:
    values = np.array([0.1, 0.2, 0.3], dtype=float)

    result = _select_predicted_feature_values(values, predicted_index=0, expected_class_count=1)

    assert np.array_equal(result, values)


def test_select_predicted_feature_values_rejects_unexpected_ndim() -> None:
    values = np.zeros((2, 2, 2, 2), dtype=float)

    with pytest.raises(ValueError, match="unexpected shape"):
        _select_predicted_feature_values(values, predicted_index=0, expected_class_count=1)


def test_select_predicted_base_value_2d_rejects_wrong_sample_count() -> None:
    base_values = np.zeros((2, 3), dtype=float)

    with pytest.raises(ValueError, match="exactly one sample"):
        _select_predicted_base_value(base_values, predicted_index=0, expected_class_count=3)


def test_select_predicted_base_value_2d_rejects_wrong_class_axis() -> None:
    base_values = np.zeros((1, 3), dtype=float)

    with pytest.raises(ValueError, match="class axis did not match"):
        _select_predicted_base_value(base_values, predicted_index=0, expected_class_count=4)


def test_select_predicted_base_value_2d_rejects_out_of_range_index() -> None:
    base_values = np.zeros((1, 3), dtype=float)

    with pytest.raises(ValueError, match="out of range"):
        _select_predicted_base_value(base_values, predicted_index=3, expected_class_count=3)


def test_select_predicted_base_value_2d_valid() -> None:
    base_values = np.array([[0.1, 0.2, 0.3]], dtype=float)

    result = _select_predicted_base_value(base_values, predicted_index=1, expected_class_count=3)

    assert result == pytest.approx(0.2)


def test_select_predicted_base_value_1d_size_one_rejects_multiclass() -> None:
    """A 1-element 1D array is a different shape from the scalar (ndim=0)
    case the pre-existing rejection test already covers - both must be
    rejected for a multiclass model, but they exercise different branches."""
    base_values = np.array([0.123], dtype=float)

    with pytest.raises(ValueError, match="only valid for single-output models"):
        _select_predicted_base_value(base_values, predicted_index=0, expected_class_count=4)


def test_select_predicted_base_value_1d_size_one_valid_for_single_output() -> None:
    base_values = np.array([0.123], dtype=float)

    result = _select_predicted_base_value(base_values, predicted_index=0, expected_class_count=1)

    assert result == pytest.approx(0.123)


def test_select_predicted_base_value_1d_rejects_wrong_size() -> None:
    base_values = np.array([0.1, 0.2, 0.3], dtype=float)

    with pytest.raises(ValueError, match="one value per classifier output class"):
        _select_predicted_base_value(base_values, predicted_index=0, expected_class_count=4)


def test_select_predicted_base_value_1d_rejects_out_of_range_index() -> None:
    base_values = np.array([0.1, 0.2, 0.3], dtype=float)

    with pytest.raises(ValueError, match="out of range"):
        _select_predicted_base_value(base_values, predicted_index=3, expected_class_count=3)


def test_select_predicted_base_value_1d_valid() -> None:
    base_values = np.array([0.1, 0.2, 0.3], dtype=float)

    result = _select_predicted_base_value(base_values, predicted_index=2, expected_class_count=3)

    assert result == pytest.approx(0.3)


def test_select_predicted_base_value_scalar_valid_for_single_output() -> None:
    base_values = np.array(0.123, dtype=float)

    result = _select_predicted_base_value(base_values, predicted_index=0, expected_class_count=1)

    assert result == pytest.approx(0.123)


def test_select_predicted_base_value_rejects_unexpected_ndim() -> None:
    base_values = np.zeros((2, 2, 2), dtype=float)

    with pytest.raises(ValueError, match="unexpected shape"):
        _select_predicted_base_value(base_values, predicted_index=0, expected_class_count=1)


def test_explain_row_rejects_a_collapsed_shape_that_is_not_1d() -> None:
    """Defense in depth: even if the two shape-selection helpers above were
    somehow fooled, _explain_row's own final ndim check must still catch a
    non-1D result rather than pass it on."""

    class BadShapeExplanation:
        def __init__(self) -> None:
            self.values = np.zeros((1, 3), dtype=float)
            self.base_values = np.array([0.5], dtype=float)

    class BadShapeExplainer:
        def __call__(self, row: np.ndarray, check_additivity: bool = False) -> Any:
            del row, check_additivity
            return BadShapeExplanation()

    with patch(
        "vibeguard.layer5_report.explainer._select_predicted_feature_values",
        return_value=np.zeros((2, 2), dtype=float),
    ):
        with patch("shap.TreeExplainer", return_value=BadShapeExplainer()):
            with pytest.raises(ValueError, match="must collapse to a 1D feature vector"):
                _explain_row(
                    classifier=object(),
                    row=np.zeros((1, 3), dtype=float),
                    predicted_index=0,
                    expected_class_count=1,
                )
