"""Layer 5 final risk-report data model and console rendering."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from rich.console import Console
from rich.table import Table

from vibeguard.layer3_scoring import ScoredFinding
from vibeguard.layer4_ml import RiskModel
from vibeguard.layer5_report.explainer import ProjectRiskExplanation, explain_project_risk


@dataclass(frozen=True)
class ProjectRiskReport:
    """Final Layer 5 report for one scanned project path."""

    scan_path: Path
    scored_findings: tuple[ScoredFinding, ...]
    explanation: ProjectRiskExplanation


def build_project_risk_report(
    scan_path: Path,
    model: RiskModel,
    scored_findings: tuple[ScoredFinding, ...],
) -> ProjectRiskReport:
    """Build the final Layer 5 report object for one scan."""
    return ProjectRiskReport(
        scan_path=scan_path,
        scored_findings=scored_findings,
        explanation=explain_project_risk(model, scored_findings),
    )


def render_console_report(
    report: ProjectRiskReport,
    *,
    console: Console | None = None,
    max_contributions: int = 8,
) -> None:
    """Render Layer 4/5 output to the console."""
    if max_contributions < 0:
        raise ValueError("max_contributions must be non-negative")
    target_console = console or Console()
    _render_prediction_summary(report, target_console)
    _render_shap_contributions(report.explanation, target_console, max_contributions)


def _render_prediction_summary(report: ProjectRiskReport, console: Console) -> None:
    table = Table(title="VibeGuard Layer 4 - Project Risk Prediction")
    table.add_column("Scan Path", overflow="fold")
    table.add_column("Predicted Risk")
    table.add_column("Confidence")
    table.add_column("SHAP Baseline")
    table.add_row(
        str(report.scan_path),
        report.explanation.prediction.label.value,
        f"{report.explanation.prediction.confidence:.3f}",
        f"{report.explanation.baseline_probability:.3f}",
    )
    console.print(table)


def _render_shap_contributions(
    explanation: ProjectRiskExplanation,
    console: Console,
    max_contributions: int,
) -> None:
    table = Table(
        title=(
            "VibeGuard Layer 5 - SHAP Feature Attribution "
            f"for predicted '{explanation.prediction.label.value}' risk"
        )
    )
    table.add_column("Feature", overflow="fold")
    table.add_column("Value")
    table.add_column("SHAP Impact")
    table.add_column("Direction")

    for contribution in explanation.contributions[:max_contributions]:
        direction = "increase" if contribution.shap_value >= 0 else "decrease"
        table.add_row(
            contribution.feature_name,
            f"{contribution.feature_value:.3f}",
            f"{contribution.shap_value:.3f}",
            direction,
        )

    console.print(table)
