"""Tests for the blind human-rater baseline comparison harness."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from evaluation import human_baseline

REPO_ROOT = Path(__file__).resolve().parents[1]
REAL_SURVEY_CSV = REPO_ROOT / "data" / "labeled" / "human_baseline_survey.csv"
REAL_PROJECTS_JSON = REPO_ROOT / "data" / "labeled" / "layer4_projects.json"
REAL_MODEL_CONTRACT = REPO_ROOT / "data" / "labeled" / "layer4_random_forest_contract.json"


def test_real_script_invocation_is_supervised_and_transparent_on_success() -> None:
    """Running ``python -m evaluation.human_baseline --help`` as a genuine
    subprocess (no worker env var set, so __main__ takes the supervisor
    branch) must still exit 0 - proving the supervisor wrapper added for
    this entry point adds one layer of re-exec without changing its
    observable exit-code contract. Mirrors main.py's own equivalent test;
    the generic crash/hang/token behavior itself is covered by
    tests/test_process_supervisor.py."""
    completed = subprocess.run(
        [sys.executable, "-m", "evaluation.human_baseline", "--help"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0


def test_case_project_map_targets_exist_and_have_ground_truth_labels() -> None:
    projects = json.loads(REAL_PROJECTS_JSON.read_text(encoding="utf-8"))["projects"]
    known_project_ids = {project["project_id"] for project in projects}

    for relative_path in human_baseline.CASE_PROJECT_MAP.values():
        project_path = REPO_ROOT / relative_path
        assert project_path.is_dir(), f"{relative_path} does not exist"
        assert (
            project_path.name in known_project_ids
        ), f"{project_path.name} has no ground-truth label in layer4_projects.json"


def test_load_survey_responses_parses_real_committed_csv() -> None:
    responses = human_baseline.load_survey_responses(REAL_SURVEY_CSV)

    assert len(responses) == 3
    for response in responses:
        assert response.rater_id.startswith("Rater ")
        assert set(response.ratings_by_case) == set(human_baseline.CASE_PROJECT_MAP)
        for rating in response.ratings_by_case.values():
            assert rating.lower() in {"low", "medium", "high", "critical"}


def test_end_to_end_comparison_against_real_pipeline() -> None:
    responses = human_baseline.load_survey_responses(REAL_SURVEY_CSV)
    projects = json.loads(REAL_PROJECTS_JSON.read_text(encoding="utf-8"))["projects"]
    ground_truth_by_project = {project["project_id"]: project["label"] for project in projects}

    signals_by_case = human_baseline.collect_vibeguard_signals(
        human_baseline.CASE_PROJECT_MAP,
        ground_truth_by_project=ground_truth_by_project,
        model_contract_path=REAL_MODEL_CONTRACT,
    )
    comparisons = human_baseline.build_case_comparisons(responses, signals_by_case)

    assert len(comparisons) == 20
    for comparison in comparisons:
        assert len(comparison.human_ratings) == 3
        assert 0.0 <= comparison.human_median_ordinal <= 3.0
        assert comparison.signals.layer4_predicted_label in {"low", "medium", "high", "critical"}

    # config-secret-service (Case 04): plaintext datasource credentials plus
    # a role-restricted health endpoint - every signal should agree this is
    # critical, humans included (all 3 rated High or Critical).
    case_04 = next(c for c in comparisons if c.case_id == "case_04")
    assert case_04.signals.ground_truth_label == "critical"
    assert case_04.signals.layer4_predicted_label == "critical"
    assert case_04.human_median_ordinal >= 2.0


def test_summarize_agreement_computes_exact_and_within_one_and_excludes_missing() -> None:
    # case_a: layer3_max_severity "low" (ordinal 0) exactly matches human
    # median 0 - exact match, distance 0.
    # case_b: "high" (ordinal 2) vs human median 1 - within one level, not
    # exact, distance 1.
    # case_c: layer3_max_severity is None (a real state: a project with no
    # scored findings, e.g. clean-orders-service) - excluded, not scored
    # as either an exact match or a miss.
    comparisons = (
        _fake_comparison("case_a", human_median_ordinal=0.0, layer3_max_severity="low"),
        _fake_comparison("case_b", human_median_ordinal=1.0, layer3_max_severity="high"),
        _fake_comparison("case_c", human_median_ordinal=3.0, layer3_max_severity=None),
    )

    summary = human_baseline.summarize_agreement(
        comparisons,
        signal_name="test signal",
        signal_selector=lambda c: c.signals.layer3_max_severity,
    )

    assert summary.compared_case_count == 2
    assert summary.excluded_case_count == 1
    assert summary.exact_match_count == 1
    assert summary.within_one_level_count == 2
    assert summary.mean_absolute_distance == (0 + 1) / 2
    assert summary.mean_signed_distance == (0 + 1) / 2


def test_summarize_inter_rater_agreement_computes_spread_buckets() -> None:
    # case_a: all 3 raters agreed exactly (spread=0).
    # case_b: raters were 1 ordinal level apart at most (spread=1).
    # case_c: raters disagreed by 2+ ordinal levels (spread=2) - outside
    # both the exact and within-one-level buckets.
    comparisons = (
        _fake_comparison("case_a", human_median_ordinal=0.0, layer3_max_severity="low", spread=0),
        _fake_comparison("case_b", human_median_ordinal=1.0, layer3_max_severity="low", spread=1),
        _fake_comparison("case_c", human_median_ordinal=1.0, layer3_max_severity="low", spread=2),
    )

    summary = human_baseline.summarize_inter_rater_agreement(comparisons)

    assert summary.case_count == 3
    assert summary.exact_agreement_count == 1
    assert summary.within_one_level_count == 2
    assert summary.mean_spread == (0 + 1 + 2) / 3
    assert summary.max_spread == 2


def test_end_to_end_inter_rater_agreement_on_real_survey_is_computable() -> None:
    """Sanity check against the actual committed 3-rater survey, not just
    hand-picked cases - must produce a valid, in-range summary."""
    responses = human_baseline.load_survey_responses(REAL_SURVEY_CSV)
    projects = json.loads(REAL_PROJECTS_JSON.read_text(encoding="utf-8"))["projects"]
    ground_truth_by_project = {project["project_id"]: project["label"] for project in projects}
    signals_by_case = human_baseline.collect_vibeguard_signals(
        human_baseline.CASE_PROJECT_MAP,
        ground_truth_by_project=ground_truth_by_project,
        model_contract_path=REAL_MODEL_CONTRACT,
    )
    comparisons = human_baseline.build_case_comparisons(responses, signals_by_case)

    summary = human_baseline.summarize_inter_rater_agreement(comparisons)

    assert summary.case_count == 20
    assert 0 <= summary.exact_agreement_count <= 20
    assert summary.exact_agreement_count <= summary.within_one_level_count <= 20
    assert 0.0 <= summary.mean_spread <= 3.0
    assert 0 <= summary.max_spread <= 3


def _fake_comparison(
    case_id: str,
    *,
    human_median_ordinal: float,
    layer3_max_severity: str | None,
    spread: int = 0,
) -> human_baseline.CaseComparison:
    return human_baseline.CaseComparison(
        case_id=case_id,
        project_id=f"{case_id}-project",
        human_ratings=("low", "low", "low"),
        human_median_ordinal=human_median_ordinal,
        human_spread=spread,
        signals=human_baseline.VibeGuardSignals(
            ground_truth_label="low",
            layer4_predicted_label="low",
            layer4_confidence=1.0,
            layer3_max_severity=layer3_max_severity,
            finding_count=0,
        ),
    )
