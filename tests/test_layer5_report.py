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
