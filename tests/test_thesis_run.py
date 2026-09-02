"""Tests for the top-level thesis evaluation runner."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from evaluation import thesis_run

REPO_ROOT = Path(__file__).resolve().parents[1]
REAL_CONTRACT_PATH = REPO_ROOT / "data" / "labeled" / "layer4_random_forest_contract.json"


def test_thesis_run_writes_bundle_and_prints_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    output_dir = tmp_path / "artifacts"
    monkeypatch.setattr(thesis_run, "build_evaluation_report", thesis_run.build_evaluation_report)
    monkeypatch.setattr(thesis_run, "write_bundle_report", thesis_run.write_bundle_report)
    monkeypatch.setattr(
        "evaluation.evaluate._bundle_directory_name", lambda: "bundle-20260722-123000"
    )

    exit_code = thesis_run.main(
        ["--model-contract", str(REAL_CONTRACT_PATH), "--output-dir", str(output_dir)]
    )

    assert exit_code == 0
    bundle_dir = output_dir / "bundle-20260722-123000"
    assert bundle_dir.is_dir()
    manifest = json.loads((bundle_dir / "bundle_manifest.json").read_text(encoding="utf-8"))
    assert manifest["invocation_argv"] == [
        Path(sys.executable).name,
        "-m",
        "evaluation.thesis_run",
        "--model-contract",
        str(REAL_CONTRACT_PATH),
        "--output-dir",
        str(output_dir),
    ]
    assert "evaluation.thesis_run" in manifest["invocation_command"]
    assert capsys.readouterr().out.strip() == str(bundle_dir)


def test_thesis_run_fails_closed_for_invalid_output(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    output_path = tmp_path / "occupied"
    output_path.write_text("not a directory\n", encoding="utf-8")

    exit_code = thesis_run.main(
        ["--model-contract", str(REAL_CONTRACT_PATH), "--output-dir", str(output_path)]
    )

    assert exit_code == 1
    assert "Thesis run failed:" in capsys.readouterr().err
