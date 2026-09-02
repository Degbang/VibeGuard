"""Layer 5: SHAP explainability and reporting.

Produces SHAP feature-attribution explanations for Layer 4 predictions
and renders final human-readable risk reports.
"""

from vibeguard.layer5_report.explainer import (
    ProjectRiskExplanation,
    SHAPContribution,
    explain_project_risk,
)
from vibeguard.layer5_report.report import (
    ProjectRiskReport,
    build_project_risk_report,
    render_console_report,
)

__all__ = [
    "ProjectRiskExplanation",
    "ProjectRiskReport",
    "SHAPContribution",
    "build_project_risk_report",
    "explain_project_risk",
    "render_console_report",
]
