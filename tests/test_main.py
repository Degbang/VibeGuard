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


def test_main_returns_nonzero_when_nothing_found(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    exit_code = main.main([str(tmp_path)])

    assert exit_code == 1
    assert "No .java/config/pom.xml files found" in capsys.readouterr().err


def test_main_returns_zero_for_config_only_file_with_no_findings(tmp_path: Path) -> None:
    config_file = tmp_path / "application.properties"
    config_file.write_text("quarkus.http.port=8080\n")

    exit_code = main.main([str(config_file)])

    assert exit_code == 0


def test_main_returns_nonzero_and_reports_findings_for_config_secret(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config_file = tmp_path / "application.properties"
    config_file.write_text("password=hunter2\n")

    exit_code = main.main([str(config_file)])

    assert exit_code == 1
    output = capsys.readouterr().out
    assert "CWE-798" in output
    assert "password" in output


def test_main_returns_nonzero_and_reports_findings_for_java_secret(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = main.main([str(FIXTURES_DIR / "HardcodedSecretService.java")])

    assert exit_code == 1
    output = capsys.readouterr().out
    assert "CWE-798" in output
    assert "apiKey" in output


def test_main_returns_nonzero_when_config_file_fails_to_parse() -> None:
    exit_code = main.main([str(FIXTURES_DIR / "malformed.yml")])
    assert exit_code == 1


def test_main_returns_nonzero_when_a_path_is_rejected_on_containment_grounds(
    tmp_path: Path,
) -> None:
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    (outside_dir / "Secret.java").write_text("public class Secret {}\n")

    scan_root = tmp_path / "root"
    scan_root.mkdir()
    (scan_root / "SneakyFile.java").symlink_to(outside_dir / "Secret.java")

    exit_code = main.main([str(scan_root)])

    assert exit_code == 1
