"""Tests for the thesis-evaluation harness."""

from __future__ import annotations

import csv
import json
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import cast

import pytest

from evaluation import evaluate

REPO_ROOT = Path(__file__).resolve().parents[1]
REAL_CONTRACT_PATH = REPO_ROOT / "data" / "labeled" / "layer4_random_forest_contract.json"


def test_build_evaluation_report_uses_real_contract_and_dataset() -> None:
    report = evaluate.build_evaluation_report(REAL_CONTRACT_PATH)

    # Dataset expanded a third time 2026-09-03 - two more batches of 10
    # Codex-generated projects targeting the sensitive-domain bucket, 42
    # projects total. Most of these turned out to implement real, hand-
    # rolled access control invisible to CWE-284's annotation-based
    # detection - see IMPLEMENTATION_LOG.md. Leave-one-out accuracy
    # (0.595) exceeds the fixed baseline (0.381) by a wider margin than
    # the previous (32-project) dataset, and - checked directly in
    # tests/test_layer4_ml.py - the edge holds up specifically on the
    # third batch's 10 projects, which were not used to design or
    # motivate the sensitive-domain feature the way the second batch was.
    assert report.contract_path == REAL_CONTRACT_PATH.resolve()
    assert report.dataset_path.name == "layer4_projects.json"
    assert report.example_count == 42
    assert report.in_sample.accuracy == pytest.approx(32 / 42)
    assert report.in_sample.macro_f1 == pytest.approx(0.7582070707070706)
    assert report.leave_one_out.accuracy == pytest.approx(25 / 42)
    assert report.baseline.accuracy == pytest.approx(16 / 42)
    assert report.leave_one_out.accuracy > report.baseline.accuracy
    assert len(report.leave_one_out.predictions) == report.example_count
    assert len(report.baseline.predictions) == report.example_count


def test_evaluation_main_renders_summary(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = evaluate.main(["--model-contract", str(REAL_CONTRACT_PATH)])

    assert exit_code == 0
    output = capsys.readouterr().out
    assert "Layer 4 Dataset Overview" in output
    assert "Layer 4 Metrics" in output
    assert "Baseline (max Layer 3 severity, not learned)" in output
    assert "Leave-One-Out Predictions" in output
    assert "Leave-One-Out Confusion Matrix" in output
    assert "0.762" in output


def test_build_json_report_returns_machine_readable_summary() -> None:
    report = evaluate.build_evaluation_report(REAL_CONTRACT_PATH)

    payload = evaluate.build_json_report(report)
    in_sample = cast(Mapping[str, object], payload["in_sample"])
    leave_one_out = cast(Mapping[str, object], payload["leave_one_out"])
    baseline = cast(Mapping[str, object], payload["baseline"])

    assert payload["contract_path"] == str(REAL_CONTRACT_PATH.resolve())
    assert payload["example_count"] == 42
    assert in_sample["accuracy"] == pytest.approx(32 / 42)
    assert leave_one_out["macro_f1"] == pytest.approx(report.leave_one_out.macro_f1)
    assert len(cast(list[object], leave_one_out["predictions"])) == 42
    assert baseline["accuracy"] == pytest.approx(16 / 42)
    assert len(cast(list[object], baseline["predictions"])) == 42


def test_evaluation_main_writes_json_export(tmp_path: Path) -> None:
    output_path = tmp_path / "evaluation.json"

    exit_code = evaluate.main(
        ["--model-contract", str(REAL_CONTRACT_PATH), "--json-out", str(output_path)]
    )

    assert exit_code == 0
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["dataset_path"].endswith("layer4_projects.json")
    assert payload["in_sample"]["accuracy"] == pytest.approx(32 / 42)
    assert payload["leave_one_out"]["confusion"]
    assert payload["baseline"]["confusion"]


def test_evaluation_main_writes_csv_exports(tmp_path: Path) -> None:
    output_dir = tmp_path / "csv"

    exit_code = evaluate.main(
        ["--model-contract", str(REAL_CONTRACT_PATH), "--csv-dir", str(output_dir)]
    )

    assert exit_code == 0
    predictions_path = output_dir / "leave_one_out_predictions.csv"
    confusion_path = output_dir / "leave_one_out_confusion.csv"
    assert predictions_path.is_file()
    assert confusion_path.is_file()

    with predictions_path.open(encoding="utf-8", newline="") as handle:
        prediction_rows = list(csv.DictReader(handle))
    with confusion_path.open(encoding="utf-8", newline="") as handle:
        confusion_rows = list(csv.DictReader(handle))

    assert len(prediction_rows) == 42
    assert prediction_rows[0].keys() == {"index", "actual", "predicted", "confidence"}
    assert confusion_rows
    assert confusion_rows[0].keys() == {"actual", "predicted", "count"}


def test_evaluation_main_writes_bundle_exports(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output_dir = tmp_path / "bundle-root"
    monkeypatch.setattr(evaluate, "_bundle_directory_name", lambda: "bundle-20260722-120000")

    exit_code = evaluate.main(
        ["--model-contract", str(REAL_CONTRACT_PATH), "--bundle-dir", str(output_dir)]
    )

    assert exit_code == 0
    bundle_dir = output_dir / "bundle-20260722-120000"
    assert (bundle_dir / "evaluation.json").is_file()
    assert (bundle_dir / "evaluation.schema.json").is_file()
    assert (bundle_dir / "leave_one_out_predictions.csv").is_file()
    assert (bundle_dir / "leave_one_out_confusion.csv").is_file()
    assert (bundle_dir / "bundle_manifest.schema.json").is_file()
    readme_text = (bundle_dir / "README.txt").read_text(encoding="utf-8")
    assert "VibeGuard Evaluation Artifact Bundle" in readme_text
    assert "evaluation.schema.json" in readme_text
    assert "leave_one_out_predictions.csv" in readme_text
    assert "bundle_manifest.schema.json" in readme_text
    evaluation_schema = json.loads(
        (bundle_dir / "evaluation.schema.json").read_text(encoding="utf-8")
    )
    manifest = json.loads((bundle_dir / "bundle_manifest.json").read_text(encoding="utf-8"))
    manifest_schema = json.loads(
        (bundle_dir / "bundle_manifest.schema.json").read_text(encoding="utf-8")
    )
    assert evaluation_schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert evaluation_schema["title"] == "VibeGuard Evaluation Report"
    assert evaluation_schema["required"] == [
        "contract_path",
        "dataset_path",
        "random_state",
        "example_count",
        "in_sample",
        "leave_one_out",
        "baseline",
    ]
    assert evaluation_schema["properties"]["leave_one_out"]["properties"]["predictions"]["items"][
        "required"
    ] == ["index", "actual", "predicted", "confidence"]
    assert manifest["export_mode"] == "bundle"
    assert manifest["contract_path"] == str(REAL_CONTRACT_PATH.resolve())
    assert manifest["dataset_path"].endswith("layer4_projects.json")
    assert manifest["bundle_directory"] == "bundle-20260722-120000"
    assert manifest_schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert manifest_schema["title"] == "VibeGuard Evaluation Bundle Manifest"
    assert manifest_schema["properties"]["export_mode"]["const"] == "bundle"
    assert "emitted_files" in manifest_schema["required"]
    assert manifest["invocation_argv"] == [
        Path(sys.executable).name,
        "-m",
        "evaluation.evaluate",
        "--model-contract",
        str(REAL_CONTRACT_PATH),
        "--bundle-dir",
        str(output_dir),
    ]
    assert "evaluation.evaluate" in manifest["invocation_command"]
    assert manifest["emitted_files"] == [
        "evaluation.json",
        "evaluation.schema.json",
        "leave_one_out_predictions.csv",
        "leave_one_out_confusion.csv",
        "README.txt",
        "bundle_manifest.schema.json",
    ]


def test_evaluation_main_fails_closed_for_missing_dataset_in_contract(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    bad_contract = tmp_path / "bad_contract.json"
    payload = json.loads(REAL_CONTRACT_PATH.read_text(encoding="utf-8"))
    payload["dataset_path"] = "missing.json"
    bad_contract.write_text(json.dumps(payload), encoding="utf-8")

    exit_code = evaluate.main(["--model-contract", str(bad_contract)])

    assert exit_code == 1
    assert "Evaluation failed:" in capsys.readouterr().err


def test_evaluation_main_fails_closed_for_unwritable_json_output(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    output_path = tmp_path / "missing-dir" / "evaluation.json"

    exit_code = evaluate.main(
        ["--model-contract", str(REAL_CONTRACT_PATH), "--json-out", str(output_path)]
    )

    assert exit_code == 1
    assert "Evaluation failed: could not write JSON evaluation report" in capsys.readouterr().err


def test_evaluation_main_fails_closed_for_unwritable_csv_output(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    output_path = tmp_path / "occupied"
    output_path.write_text("not a directory\n", encoding="utf-8")

    exit_code = evaluate.main(
        ["--model-contract", str(REAL_CONTRACT_PATH), "--csv-dir", str(output_path)]
    )

    assert exit_code == 1
    assert "Evaluation failed: could not write CSV evaluation report" in capsys.readouterr().err


def test_evaluation_main_fails_closed_for_uncreatable_bundle_output(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    output_path = tmp_path / "occupied"
    output_path.write_text("not a directory\n", encoding="utf-8")

    exit_code = evaluate.main(
        ["--model-contract", str(REAL_CONTRACT_PATH), "--bundle-dir", str(output_path)]
    )

    assert exit_code == 1
    assert "Evaluation failed: could not create evaluation artifact bundle" in (
        capsys.readouterr().err
    )
