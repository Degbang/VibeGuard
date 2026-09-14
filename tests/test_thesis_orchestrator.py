"""Tests for the combined thesis orchestrator."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from evaluation import thesis_orchestrator

REPO_ROOT = Path(__file__).resolve().parents[1]
REAL_CONTRACT_PATH = REPO_ROOT / "data" / "labeled" / "layer4_random_forest_contract.json"
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures"


def test_real_script_invocation_is_supervised_and_transparent_on_success() -> None:
    """Running ``python -m evaluation.thesis_orchestrator --help`` as a
    genuine subprocess (no worker env var set, so __main__ takes the
    supervisor branch) must still exit 0 - proving the supervisor wrapper
    added for this entry point adds one layer of re-exec without changing
    its observable exit-code contract. Mirrors main.py's own equivalent
    test; the generic crash/hang/token behavior itself is covered by
    tests/test_process_supervisor.py."""
    completed = subprocess.run(
        [sys.executable, "-m", "evaluation.thesis_orchestrator", "--help"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0


@pytest.mark.parametrize("output_kind", ["absolute", "relative", "symlink"])
def test_thesis_orchestrator_writes_scan_and_evaluation_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    output_kind: str,
) -> None:
    output_dir = tmp_path / "artifacts"
    if output_kind == "relative":
        monkeypatch.chdir(tmp_path)
        output_dir = Path("artifacts")
    elif output_kind == "symlink":
        output_dir = tmp_path / "linked artifacts"
        output_dir.symlink_to(tmp_path, target_is_directory=True)
    monkeypatch.setattr(thesis_orchestrator, "_run_directory_name", lambda: "run-20260723-120000")
    monkeypatch.setattr(
        "evaluation.evaluate._bundle_directory_name", lambda: "bundle-20260723-120100"
    )

    invocation_args = [
        str(FIXTURES_DIR / "CleanService.java"),
        "--model-contract",
        str(REAL_CONTRACT_PATH),
        "--output-dir",
        str(output_dir),
    ]
    monkeypatch.setattr(sys, "argv", ["thesis_orchestrator.py", *invocation_args])
    exit_code = thesis_orchestrator.main()

    assert exit_code == 0
    run_dir = output_dir.resolve() / "run-20260723-120000"
    bundle_dir = run_dir / "evaluation" / "bundle-20260723-120100"
    manifest = json.loads((run_dir / "run_manifest.json").read_text(encoding="utf-8"))
    manifest_schema = json.loads((run_dir / "run_manifest.schema.json").read_text(encoding="utf-8"))
    scan_manifest = json.loads(
        (run_dir / "scan" / "scan_manifest.json").read_text(encoding="utf-8")
    )
    scan_manifest_schema = json.loads(
        (run_dir / "scan" / "scan_manifest.schema.json").read_text(encoding="utf-8")
    )
    scan_report = json.loads((run_dir / "scan" / "scan_report.json").read_text(encoding="utf-8"))
    thesis_summary = json.loads((run_dir / "thesis_summary.json").read_text(encoding="utf-8"))
    thesis_summary_schema = json.loads(
        (run_dir / "thesis_summary.schema.json").read_text(encoding="utf-8")
    )
    assert run_dir.is_dir()
    assert bundle_dir.is_dir()
    assert manifest["export_mode"] == "combined_thesis_run"
    assert manifest["summary_file"] == str(run_dir / "thesis_summary.json")
    assert manifest["summary_file_relative"] == "thesis_summary.json"
    assert manifest["summary_schema_file"] == str(run_dir / "thesis_summary.schema.json")
    assert manifest["summary_schema_file_relative"] == "thesis_summary.schema.json"
    assert manifest["scan_artifact_dir"] == str(run_dir / "scan")
    assert manifest["scan_artifact_dir_relative"] == "scan"
    assert manifest["evaluation_bundle_dir"] == str(bundle_dir.resolve())
    assert manifest["evaluation_bundle_dir_relative"] == "evaluation/bundle-20260723-120100"
    assert manifest["scan_exit_code"] == 0
    assert manifest_schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert manifest_schema["properties"]["export_mode"]["const"] == "combined_thesis_run"
    assert "summary_schema_file_relative" in manifest_schema["required"]
    assert "evaluation_bundle_dir_relative" in manifest_schema["required"]
    assert manifest["orchestrator_invocation_argv"] == [
        Path(sys.executable).name,
        "-m",
        "evaluation.thesis_orchestrator",
        str(FIXTURES_DIR / "CleanService.java"),
        "--model-contract",
        str(REAL_CONTRACT_PATH),
        "--output-dir",
        str(output_dir),
    ]
    assert "evaluation.thesis_orchestrator" in manifest["orchestrator_invocation_command"]
    assert scan_manifest["exit_code"] == 0
    assert scan_manifest["report_file"] == "scan_report.json"
    assert scan_manifest_schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert scan_manifest_schema["title"] == "VibeGuard Scan Manifest"
    assert scan_manifest_schema["properties"]["report_file"]["const"] == "scan_report.json"
    assert scan_manifest_schema["required"] == [
        "scan_path",
        "exit_code",
        "invocation_argv",
        "invocation_command",
        "report_file",
        "stdout_file",
        "stderr_file",
    ]
    assert scan_report["exit_code"] == 0
    assert scan_report["finding_count"] == 0
    assert scan_report["project_risk_report"]["predicted_label"] == "low"
    assert thesis_summary["schema_version"] == 2
    assert thesis_summary["export_mode"] == "combined_thesis_summary"
    assert thesis_summary["scan"]["report_file"] == str(run_dir / "scan" / "scan_report.json")
    assert thesis_summary["scan"]["artifact_dir_relative"] == "scan"
    assert thesis_summary["scan"]["report_file_relative"] == "scan/scan_report.json"
    assert thesis_summary["scan"]["project_risk"]["predicted_label"] == "low"
    assert thesis_summary["evaluation"]["bundle_dir"] == str(bundle_dir.resolve())
    assert (
        thesis_summary["evaluation"]["bundle_dir_relative"] == "evaluation/bundle-20260723-120100"
    )
    assert thesis_summary["evaluation"]["report_file_relative"] == (
        "evaluation/bundle-20260723-120100/evaluation.json"
    )
    assert thesis_summary["evaluation"]["manifest_file_relative"] == (
        "evaluation/bundle-20260723-120100/bundle_manifest.json"
    )
    assert thesis_summary["evaluation"]["leave_one_out_accuracy"] == pytest.approx(29 / 50)
    assert thesis_summary_schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert thesis_summary_schema["properties"]["schema_version"]["const"] == 2
    assert thesis_summary_schema["properties"]["export_mode"]["const"] == "combined_thesis_summary"
    assert thesis_summary_schema["properties"]["scan"]["properties"]["project_risk"]["oneOf"][1][
        "required"
    ] == ["predicted_label", "confidence"]
    assert (
        "bundle_invocation_command" in thesis_summary_schema["properties"]["evaluation"]["required"]
    )
    assert (run_dir / "scan" / "scan_stdout.txt").is_file()
    assert (run_dir / "scan" / "scan_stderr.txt").is_file()
    assert capsys.readouterr().out.strip() == str(run_dir)


def test_thesis_orchestrator_records_nonzero_scan_exit_code_but_succeeds(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output_dir = tmp_path / "artifacts"
    monkeypatch.setattr(thesis_orchestrator, "_run_directory_name", lambda: "run-20260723-120200")
    monkeypatch.setattr(
        "evaluation.evaluate._bundle_directory_name", lambda: "bundle-20260723-120300"
    )

    exit_code = thesis_orchestrator.main(
        [
            str(FIXTURES_DIR / "HardcodedSecretService.java"),
            "--model-contract",
            str(REAL_CONTRACT_PATH),
            "--output-dir",
            str(output_dir),
        ]
    )

    assert exit_code == 0
    run_dir = output_dir / "run-20260723-120200"
    manifest = json.loads((run_dir / "run_manifest.json").read_text(encoding="utf-8"))
    manifest_schema = json.loads((run_dir / "run_manifest.schema.json").read_text(encoding="utf-8"))
    scan_manifest_schema = json.loads(
        (run_dir / "scan" / "scan_manifest.schema.json").read_text(encoding="utf-8")
    )
    scan_report = json.loads((run_dir / "scan" / "scan_report.json").read_text(encoding="utf-8"))
    assert manifest["scan_exit_code"] == 1
    assert manifest["summary_schema_file_relative"] == "thesis_summary.schema.json"
    assert manifest["scan_artifact_dir_relative"] == "scan"
    assert manifest["evaluation_bundle_dir_relative"] == "evaluation/bundle-20260723-120300"
    assert manifest_schema["title"] == "VibeGuard Combined Thesis Run Manifest"
    assert scan_manifest_schema["properties"]["stderr_file"]["const"] == "scan_stderr.txt"
    assert manifest_schema["required"] == [
        "export_mode",
        "scan_path",
        "run_directory",
        "summary_file",
        "summary_file_relative",
        "summary_schema_file",
        "summary_schema_file_relative",
        "scan_artifact_dir",
        "scan_artifact_dir_relative",
        "scan_exit_code",
        "evaluation_bundle_dir",
        "evaluation_bundle_dir_relative",
        "orchestrator_invocation_argv",
        "orchestrator_invocation_command",
        "scan_invocation_argv",
        "scan_invocation_command",
        "evaluation_invocation_argv",
        "evaluation_invocation_command",
    ]
    assert scan_report["exit_code"] == 1
    assert scan_report["finding_count"] >= 1
    assert scan_report["scored_finding_count"] >= 1
    assert scan_report["project_risk_report"]["predicted_label"] == "critical"
    thesis_summary = json.loads((run_dir / "thesis_summary.json").read_text(encoding="utf-8"))
    thesis_summary_schema = json.loads(
        (run_dir / "thesis_summary.schema.json").read_text(encoding="utf-8")
    )
    assert thesis_summary["schema_version"] == 2
    assert thesis_summary["scan"]["exit_code"] == 1
    assert thesis_summary["scan"]["project_risk"]["predicted_label"] == "critical"
    assert thesis_summary_schema["title"] == "VibeGuard Combined Thesis Summary"
    assert thesis_summary_schema["required"] == [
        "schema_version",
        "export_mode",
        "run_directory",
        "scan_path",
        "scan",
        "evaluation",
    ]


def test_thesis_orchestrator_fails_closed_for_invalid_output(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    output_path = tmp_path / "occupied"
    output_path.write_text("not a directory\n", encoding="utf-8")

    exit_code = thesis_orchestrator.main(
        [
            str(FIXTURES_DIR / "CleanService.java"),
            "--model-contract",
            str(REAL_CONTRACT_PATH),
            "--output-dir",
            str(output_path),
        ]
    )

    assert exit_code == 1
    assert "Thesis orchestration failed:" in capsys.readouterr().err


def test_combined_scan_captures_shap_runtime_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failed explanation must still leave traceable scan evidence."""

    def fail_explainer(*args: object, **kwargs: object) -> None:
        raise RuntimeError("injected SHAP failure")

    monkeypatch.setattr("shap.TreeExplainer", fail_explainer)
    artifact_dir = tmp_path / "scan"
    artifacts = thesis_orchestrator._run_scan(
        FIXTURES_DIR / "HardcodedSecretService.java",
        artifact_dir,
        model_contract=REAL_CONTRACT_PATH,
        max_bytes=2_000_000,
        timeout=5.0,
    )

    report = json.loads(artifacts.report_path.read_text(encoding="utf-8"))
    assert artifacts.exit_code == 1
    assert report["error_message"] == "ML/reporting failed: injected SHAP failure"
    assert report["project_risk_report"] is None
    assert report["finding_count"] > 0
    assert report["scored_finding_count"] > 0
    stderr = (artifact_dir / "scan_stderr.txt").read_text(encoding="utf-8")
    assert "injected SHAP failure" in stderr
    assert "Traceback" not in stderr
