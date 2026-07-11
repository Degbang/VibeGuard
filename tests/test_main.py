"""Smoke tests for the main.py CLI's exit-code contract."""

from __future__ import annotations

from pathlib import Path

import pytest

import main

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_main_returns_zero_when_all_files_parse_ok() -> None:
    exit_code = main.main([str(FIXTURES_DIR / "CleanService.java")])
    assert exit_code == 0


def test_main_returns_nonzero_when_any_file_fails_to_parse() -> None:
    exit_code = main.main([str(FIXTURES_DIR)])
    assert exit_code == 1


def test_main_returns_nonzero_when_no_java_files_found(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    exit_code = main.main([str(tmp_path)])

    assert exit_code == 1
    assert "No .java files found" in capsys.readouterr().err
