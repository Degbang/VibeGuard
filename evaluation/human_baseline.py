"""Blind human-rater baseline comparison for thesis Chapter 4/5 evaluation.

Loads the "Blind Risk Review" survey export (human raters given only a
natural-language description of each project's endpoint behavior, no
source code, rating Low/Medium/High/Critical risk) and compares it
against three VibeGuard-side signals for the same underlying projects:
the committed Layer 4 dataset's ground-truth label, Layer 4's own ML
prediction, and Layer 3's raw maximum rule-based finding severity. This
module does not modify any Layer 1-5 detection, scoring, or
classification logic - it only re-runs the existing frozen pipeline and
reports agreement statistics against an independent human baseline.
"""

from __future__ import annotations

import argparse
import csv
import json
import statistics
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from rich.console import Console
from rich.table import Table

from vibeguard.layer1_static._parsing_guards import ParseStatus
from vibeguard.layer1_static.rules import cwe_20, cwe_284, cwe_287, cwe_798, cwe_1035
from vibeguard.layer1_static.rules._finding import Finding
from vibeguard.layer1_static.scanner import ScanResult, scan_directory
from vibeguard.layer2_features import extract_features
from vibeguard.layer3_scoring import score_features
from vibeguard.layer4_ml import MLRiskLabel, load_trusted_model_contract
from vibeguard.layer5_report import build_project_risk_report

_REPO_ROOT = Path(__file__).resolve().parents[1]
_DEFAULT_SURVEY_CSV = _REPO_ROOT / "data" / "labeled" / "human_baseline_survey.csv"
_DEFAULT_PROJECTS_JSON = _REPO_ROOT / "data" / "labeled" / "layer4_projects.json"
_DEFAULT_MODEL_CONTRACT = _REPO_ROOT / "data" / "labeled" / "layer4_random_forest_contract.json"

_RISK_ORDER: tuple[MLRiskLabel, ...] = (
    MLRiskLabel.LOW,
    MLRiskLabel.MEDIUM,
    MLRiskLabel.HIGH,
    MLRiskLabel.CRITICAL,
)
_ORDINAL_BY_LABEL: dict[str, int] = {label.value: index for index, label in enumerate(_RISK_ORDER)}

# Each case in the survey describes one project's endpoint/config behavior
# verbatim (no code shown to raters). Verified by hand against each
# project's actual route strings, annotations, and config literals -
# see IMPLEMENTATION_LOG.md's entry for this comparison.
CASE_PROJECT_MAP: dict[str, str] = {
    "case_01": "data/sample_apps/layer4_training/unvalidated-customers-service",
    "case_02": "data/sample_apps/ai-account-recovery-service",
    "case_03": "data/sample_apps/ai-shipping-labels-service",
    "case_04": "data/sample_apps/layer4_training/config-secret-service",
    "case_05": "data/sample_apps/ai-file-upload-service",
    "case_06": "data/sample_apps/layer4_training/clean-orders-service",
    "case_07": "data/sample_apps/ai-payment-webhooks-service",
    "case_08": "data/sample_apps/ai-card-storage-service",
    "case_09": "data/sample_apps/layer4_training/vibe-coded-disaster-service",
    "case_10": "data/sample_apps/ai-api-key-service",
    "case_11": "data/sample_apps/ai-oauth-refresh-service",
    "case_12": "data/sample_apps/layer4_training/unsafe-auth-service",
    "case_13": "data/sample_apps/ai-product-reviews-service",
    "case_14": "data/sample_apps/layer4_training/multi-issue-gateway-service",
    "case_15": "data/sample_apps/ai-newsletter-service",
    "case_16": "data/sample_apps/runnable-ai-orders-service",
    "case_17": "data/sample_apps/ai-admin-report-export-service",
    "case_18": "data/sample_apps/ai-payments-service",
    "case_19": "data/sample_apps/ai-password-reset-service",
    "case_20": "data/sample_apps/ai-inventory-adjustment-service",
}


@dataclass(frozen=True)
class SurveyResponse:
    """One rater's ratings across all cases, in survey column order."""

    rater_id: str
    ratings_by_case: dict[str, str]


@dataclass(frozen=True)
class VibeGuardSignals:
    """VibeGuard's own output for one mapped project."""

    ground_truth_label: str
    layer4_predicted_label: str
    layer4_confidence: float
    layer3_max_severity: str | None
    finding_count: int


@dataclass(frozen=True)
class CaseComparison:
    """One case's human ratings alongside VibeGuard's own signals."""

    case_id: str
    project_id: str
    human_ratings: tuple[str, ...]
    human_median_ordinal: float
    human_spread: int
    signals: VibeGuardSignals


@dataclass(frozen=True)
class AgreementSummary:
    """Agreement of one VibeGuard-side signal against the human median."""

    signal_name: str
    compared_case_count: int
    excluded_case_count: int
    exact_match_count: int
    within_one_level_count: int
    mean_absolute_distance: float
    mean_signed_distance: float


def load_survey_responses(csv_path: Path) -> tuple[SurveyResponse, ...]:
    """Parse the Blind Risk Review CSV export into per-rater case ratings.

    Args:
        csv_path: Path to the survey export (rater identity already
            anonymized to ``Rater N`` in the committed copy).

    Returns:
        One ``SurveyResponse`` per non-empty row, in submission order.

    Raises:
        ValueError: If the file has no columns starting with ``Case ``,
            or has a different number of case columns than
            ``CASE_PROJECT_MAP`` expects.
    """
    with csv_path.open(newline="", encoding="utf-8-sig") as handle:
        rows = list(csv.reader(handle))
    if not rows:
        raise ValueError(f"{csv_path} is empty")
    header = rows[0]
    case_column_indices = [i for i, column in enumerate(header) if column.startswith("Case ")]
    if len(case_column_indices) != len(CASE_PROJECT_MAP):
        raise ValueError(
            f"expected {len(CASE_PROJECT_MAP)} case columns, found {len(case_column_indices)}"
        )
    rater_id_index = header.index("Your name or initials")

    responses: list[SurveyResponse] = []
    for row in rows[1:]:
        if not row or not row[0].strip():
            continue
        ratings_by_case = {
            case_id: row[column_index].strip()
            for case_id, column_index in zip(CASE_PROJECT_MAP, case_column_indices, strict=True)
        }
        responses.append(
            SurveyResponse(rater_id=row[rater_id_index].strip(), ratings_by_case=ratings_by_case)
        )
    return tuple(responses)


def collect_vibeguard_signals(
    case_project_map: dict[str, str],
    *,
    ground_truth_by_project: dict[str, str],
    model_contract_path: Path,
) -> dict[str, VibeGuardSignals]:
    """Re-run VibeGuard's Layer 1-5 pipeline on each mapped project.

    Args:
        case_project_map: Case id to project path (relative to repo root).
        ground_truth_by_project: Project id to its committed dataset label.
        model_contract_path: Trusted Layer 4 model contract to load.

    Returns:
        One ``VibeGuardSignals`` per case id.
    """
    model = load_trusted_model_contract(model_contract_path.resolve())
    signals_by_case: dict[str, VibeGuardSignals] = {}
    for case_id, relative_path in case_project_map.items():
        project_path = (_REPO_ROOT / relative_path).resolve()
        project_id = project_path.name
        scan_result = scan_directory(project_path)
        findings = _run_all_rules(scan_result)
        scored_findings = score_features(extract_features(findings))
        report = build_project_risk_report(project_path, model, scored_findings)
        max_severity = (
            max(scored.severity.value for scored in scored_findings) if scored_findings else None
        )
        signals_by_case[case_id] = VibeGuardSignals(
            ground_truth_label=ground_truth_by_project[project_id],
            layer4_predicted_label=report.explanation.prediction.label.value,
            layer4_confidence=report.explanation.prediction.confidence,
            layer3_max_severity=max_severity,
            finding_count=len(scored_findings),
        )
    return signals_by_case


def _run_all_rules(result: ScanResult) -> tuple[Finding, ...]:
    """Run every implemented CWE rule, mirroring ``main.py``'s ``_run_rules``."""
    findings: list[Finding] = []
    for java_file in result.java_files:
        if java_file.status != ParseStatus.OK:
            continue
        findings.extend(cwe_798.detect_in_java(java_file))
        findings.extend(cwe_284.detect_in_java(java_file))
        findings.extend(cwe_287.detect_in_java(java_file))
        findings.extend(cwe_20.detect_in_java(java_file))
    for config_file in result.config_files:
        if config_file.status != ParseStatus.OK:
            continue
        findings.extend(cwe_798.detect_in_config(config_file))
    for pom_file in result.pom_files:
        if pom_file.status != ParseStatus.OK:
            continue
        findings.extend(cwe_1035.detect_in_pom(pom_file))
    return cwe_284.apply_centralized_authorization_context(
        tuple(findings),
        (jf for jf in result.java_files if jf.status == ParseStatus.OK),
    )


def build_case_comparisons(
    responses: tuple[SurveyResponse, ...],
    signals_by_case: dict[str, VibeGuardSignals],
) -> tuple[CaseComparison, ...]:
    """Join human ratings and VibeGuard signals into one row per case."""
    comparisons: list[CaseComparison] = []
    for case_id, relative_path in CASE_PROJECT_MAP.items():
        human_ratings = tuple(response.ratings_by_case[case_id] for response in responses)
        human_ordinals = [_ORDINAL_BY_LABEL[rating.lower()] for rating in human_ratings]
        comparisons.append(
            CaseComparison(
                case_id=case_id,
                project_id=Path(relative_path).name,
                human_ratings=human_ratings,
                human_median_ordinal=float(statistics.median(human_ordinals)),
                human_spread=max(human_ordinals) - min(human_ordinals),
                signals=signals_by_case[case_id],
            )
        )
    return tuple(comparisons)


def summarize_agreement(
    comparisons: tuple[CaseComparison, ...],
    *,
    signal_name: str,
    signal_selector: Callable[[CaseComparison], str | None],
) -> AgreementSummary:
    """Summarize one VibeGuard-side signal's agreement with the human median.

    Args:
        comparisons: Per-case rows to compare.
        signal_name: Human-readable label for the returned summary.
        signal_selector: Callable taking a ``CaseComparison`` and
            returning that signal's label, or ``None`` if unavailable
            for that case (excluded from the summary, not treated as
            disagreement).
    """
    distances: list[float] = []
    signed_distances: list[float] = []
    excluded = 0
    for comparison in comparisons:
        label = signal_selector(comparison)
        if label is None:
            excluded += 1
            continue
        signal_ordinal = _ORDINAL_BY_LABEL[label.lower()]
        signed = signal_ordinal - comparison.human_median_ordinal
        signed_distances.append(signed)
        distances.append(abs(signed))
    exact_match_count = sum(1 for distance in distances if distance == 0)
    within_one_level_count = sum(1 for distance in distances if distance <= 1)
    return AgreementSummary(
        signal_name=signal_name,
        compared_case_count=len(distances),
        excluded_case_count=excluded,
        exact_match_count=exact_match_count,
        within_one_level_count=within_one_level_count,
        mean_absolute_distance=statistics.mean(distances) if distances else 0.0,
        mean_signed_distance=statistics.mean(signed_distances) if signed_distances else 0.0,
    )


def render_console_report(
    comparisons: tuple[CaseComparison, ...],
    summaries: tuple[AgreementSummary, ...],
    *,
    console: Console | None = None,
) -> None:
    """Render the per-case comparison and agreement summaries to the console."""
    target_console = console or Console()

    case_table = Table(title="Human Baseline - Per-Case Comparison")
    case_table.add_column("Case")
    case_table.add_column("Project", overflow="fold")
    case_table.add_column("Human Ratings")
    case_table.add_column("Ground Truth")
    case_table.add_column("Layer 4")
    case_table.add_column("Layer 3 Max")
    for comparison in comparisons:
        case_table.add_row(
            comparison.case_id,
            comparison.project_id,
            ", ".join(comparison.human_ratings),
            comparison.signals.ground_truth_label,
            comparison.signals.layer4_predicted_label,
            comparison.signals.layer3_max_severity or "-",
        )
    target_console.print(case_table)

    summary_table = Table(title="Human Baseline - Agreement vs. Human Median")
    summary_table.add_column("Signal")
    summary_table.add_column("Exact Match")
    summary_table.add_column("Within 1 Level")
    summary_table.add_column("Mean Abs. Distance")
    summary_table.add_column("Mean Signed Distance")
    for summary in summaries:
        summary_table.add_row(
            summary.signal_name,
            f"{summary.exact_match_count}/{summary.compared_case_count}",
            f"{summary.within_one_level_count}/{summary.compared_case_count}",
            f"{summary.mean_absolute_distance:.2f}",
            f"{summary.mean_signed_distance:+.2f}",
        )
    target_console.print(summary_table)


def build_json_report(
    comparisons: tuple[CaseComparison, ...], summaries: tuple[AgreementSummary, ...]
) -> dict[str, object]:
    """Convert the comparison and summaries into a JSON-serializable mapping."""
    return {
        "cases": [
            {
                "case_id": comparison.case_id,
                "project_id": comparison.project_id,
                "human_ratings": list(comparison.human_ratings),
                "human_median_ordinal": comparison.human_median_ordinal,
                "human_spread": comparison.human_spread,
                "ground_truth_label": comparison.signals.ground_truth_label,
                "layer4_predicted_label": comparison.signals.layer4_predicted_label,
                "layer4_confidence": comparison.signals.layer4_confidence,
                "layer3_max_severity": comparison.signals.layer3_max_severity,
                "finding_count": comparison.signals.finding_count,
            }
            for comparison in comparisons
        ],
        "agreement_summaries": [
            {
                "signal_name": summary.signal_name,
                "compared_case_count": summary.compared_case_count,
                "excluded_case_count": summary.excluded_case_count,
                "exact_match_count": summary.exact_match_count,
                "within_one_level_count": summary.within_one_level_count,
                "mean_absolute_distance": summary.mean_absolute_distance,
                "mean_signed_distance": summary.mean_signed_distance,
            }
            for summary in summaries
        ],
    }


def main(argv: list[str] | None = None) -> int:
    """Run the human-baseline comparison from the command line."""
    args = _parse_args(argv)
    try:
        responses = load_survey_responses(args.survey_csv)
        projects = json.loads(args.projects_json.read_text(encoding="utf-8"))["projects"]
        ground_truth_by_project = {project["project_id"]: project["label"] for project in projects}
        signals_by_case = collect_vibeguard_signals(
            CASE_PROJECT_MAP,
            ground_truth_by_project=ground_truth_by_project,
            model_contract_path=args.model_contract,
        )
        comparisons = build_case_comparisons(responses, signals_by_case)
        summaries = (
            summarize_agreement(
                comparisons,
                signal_name="Ground-truth label",
                signal_selector=lambda c: c.signals.ground_truth_label,
            ),
            summarize_agreement(
                comparisons,
                signal_name="Layer 4 predicted label",
                signal_selector=lambda c: c.signals.layer4_predicted_label,
            ),
            summarize_agreement(
                comparisons,
                signal_name="Layer 3 max rule severity",
                signal_selector=lambda c: c.signals.layer3_max_severity,
            ),
        )
    except (ValueError, OSError, KeyError) as exc:
        print(f"Human-baseline comparison failed: {exc}", file=sys.stderr)
        return 1

    if args.json_out is not None:
        args.json_out.write_text(
            json.dumps(build_json_report(comparisons, summaries), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    else:
        render_console_report(comparisons, summaries)
    return 0


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m evaluation.human_baseline",
        description=(
            "Compare the Blind Risk Review human-rater survey against "
            "VibeGuard's own ground-truth labels, Layer 4 predictions, "
            "and Layer 3 rule-based severities for the same projects."
        ),
    )
    parser.add_argument("--survey-csv", type=Path, default=_DEFAULT_SURVEY_CSV)
    parser.add_argument("--projects-json", type=Path, default=_DEFAULT_PROJECTS_JSON)
    parser.add_argument("--model-contract", type=Path, default=_DEFAULT_MODEL_CONTRACT)
    parser.add_argument(
        "--json-out",
        type=Path,
        help="Write a machine-readable JSON report to this path instead of rendering to console.",
    )
    return parser.parse_args(argv)


if __name__ == "__main__":
    sys.exit(main())
