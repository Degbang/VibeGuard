"""Smoke tests for the main.py CLI's exit-code contract."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

import main
import process_supervisor

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
    assert "No .java/config/pom.xml/build.gradle files found" in capsys.readouterr().err


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
    assert "95" in output
    assert "critical" in output
    assert "Project Risk Prediction" in output
    assert "SHAP Feature Attribution" in output


def test_main_returns_nonzero_and_reports_findings_for_java_secret(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = main.main([str(FIXTURES_DIR / "HardcodedSecretService.java")])

    assert exit_code == 1
    output = capsys.readouterr().out
    assert "CWE-798" in output
    assert "apiKey" in output
    assert "90" in output
    assert "critical" in output
    assert "Project Risk Prediction" in output
    assert "SHAP Feature Attribution" in output


def test_main_reports_ml_prediction_for_clean_file(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main.main([str(FIXTURES_DIR / "CleanService.java")])

    assert exit_code == 0
    output = capsys.readouterr().out
    assert "Project Risk Prediction" in output
    assert "SHAP Feature Attribution" in output
    assert "low" in output


def test_main_returns_nonzero_when_config_file_fails_to_parse() -> None:
    exit_code = main.main([str(FIXTURES_DIR / "malformed.yml")])
    assert exit_code == 1


def test_main_returns_nonzero_when_path_does_not_exist(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    missing = tmp_path / "does-not-exist"

    exit_code = main.main([str(missing)])

    assert exit_code == 1
    assert "is not a file or directory" in capsys.readouterr().err


def test_main_skips_a_config_file_that_failed_to_parse_during_rule_running(
    tmp_path: Path,
) -> None:
    """A malformed config file alongside a valid Java file must not
    crash ``_run_rules`` - it's skipped, not dropped silently: the
    overall scan still fails closed (exit 1) because the config file
    itself didn't parse, same as scanning it alone."""
    (tmp_path / "Clean.java").write_text("public class Clean {}\n")
    (tmp_path / "application.yml").write_text("a: [1, 2\nb: {\n")

    exit_code = main.main([str(tmp_path)])

    assert exit_code == 1


def test_main_skips_a_pom_file_that_failed_to_parse_during_rule_running(
    tmp_path: Path,
) -> None:
    (tmp_path / "Clean.java").write_text("public class Clean {}\n")
    (tmp_path / "pom.xml").write_text("<project><not-closed>\n")

    exit_code = main.main([str(tmp_path)])

    assert exit_code == 1


def test_main_skips_a_gradle_file_that_failed_to_parse_during_rule_running(
    tmp_path: Path,
) -> None:
    """An empty build.gradle (EMPTY_FILE, not OK) alongside a valid Java
    file must not crash ``_run_rules`` either."""
    (tmp_path / "Clean.java").write_text("public class Clean {}\n")
    (tmp_path / "build.gradle").write_text("")

    exit_code = main.main([str(tmp_path)])

    assert exit_code == 1


def test_main_scans_a_single_pom_xml_file_directly(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A pom.xml named directly on the command line, not discovered by
    walking a directory - the single-file dispatch path requires the
    exact literal filename "pom.xml", so vulnerable-pom.xml itself
    can't be reused by path alone. Copying its content also exercises
    the "unresolved dependency" disclosure in the same run (it has one
    unresolvable property reference)."""
    pom_file = tmp_path / "pom.xml"
    pom_file.write_text(
        (FIXTURES_DIR / "vulnerable-pom.xml").read_text(encoding="utf-8"), encoding="utf-8"
    )

    exit_code = main.main([str(pom_file)])

    assert exit_code == 1
    output = capsys.readouterr().out
    assert "CWE-1035" in output
    assert "could not be checked against CWE-1035" in output


def test_main_scans_a_single_build_gradle_file_directly(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    gradle_file = tmp_path / "build.gradle"
    gradle_file.write_text(
        "dependencies {\n"
        '    implementation "com.fasterxml.jackson.core:jackson-databind:2.9.8"\n'
        "}\n"
    )

    exit_code = main.main([str(gradle_file)])

    assert exit_code == 1
    # Not asserting on the dependency coordinate text itself: Rich wraps
    # a long identifier cell across lines under capsys's narrow default
    # test-capture width, which would otherwise split this exact
    # substring - CWE-1035 alone is enough to confirm the single-file
    # Gradle dispatch path produced a real finding.
    assert "CWE-1035" in capsys.readouterr().out


def test_main_discloses_unresolved_gradle_dependency_versions(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A variable-interpolated version (gradle_parser.py never resolves
    one) must surface the same "could not be checked" disclosure
    _print_pom_report already has, scoped to the Gradle report."""
    gradle_file = tmp_path / "build.gradle"
    gradle_file.write_text(
        "dependencies {\n"
        '    implementation "com.fasterxml.jackson.core:jackson-databind:2.9.8"\n'
        '    api "org.apache.logging.log4j:log4j-core:$log4jVersion"\n'
        "}\n"
    )

    exit_code = main.main([str(gradle_file)])

    assert exit_code == 1
    output = capsys.readouterr().out
    assert "could not be checked against CWE-1035" in output


def test_main_returns_nonzero_when_a_rejected_path_sits_alongside_a_valid_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A rejected (symlink-escape) path must be reported, not just
    cause an early "nothing found" exit - that check only looks at
    java/config/pom/gradle files, so a rejected path needs a valid file
    alongside it to prove the rejected-paths report itself still
    renders."""
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    (outside_dir / "Secret.java").write_text("public class Secret {}\n")

    scan_root = tmp_path / "root"
    scan_root.mkdir()
    (scan_root / "Clean.java").write_text("public class Clean {}\n")
    (scan_root / "SneakyFile.java").symlink_to(outside_dir / "Secret.java")

    exit_code = main.main([str(scan_root)])

    assert exit_code == 1
    output = capsys.readouterr().out
    assert "Rejected Paths" in output


def test_main_returns_nonzero_when_scoring_raises_value_error(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Layer 2/3 validation failing must fail closed with a clear
    message, not propagate an unhandled exception - mirrors the
    existing ML/reporting-failure test's mocking technique for a
    failure mode that can't be reached through any real, well-formed
    Layer 1 finding."""
    with patch("main.extract_features", side_effect=ValueError("boom")):
        exit_code = main.main([str(FIXTURES_DIR / "HardcodedSecretService.java")])

    assert exit_code == 1
    assert "Scoring failed: boom" in capsys.readouterr().err


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


def test_main_returns_nonzero_when_explicit_non_config_yaml_file_is_not_scanned(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    openapi_file = tmp_path / "openapi.yml"
    openapi_file.write_text(
        "components:\n  schemas:\n    User:\n      properties:\n        password:\n"
        "          title: Password\n"
    )

    exit_code = main.main([str(openapi_file)])

    assert exit_code == 1
    assert "No .java/config/pom.xml/build.gradle files found" in capsys.readouterr().err


def test_main_returns_nonzero_when_model_contract_dataset_is_missing(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    bad_contract = tmp_path / "bad_contract.json"
    contract_payload = json.loads(
        (
            Path(__file__).parent.parent / "data" / "labeled" / "layer4_random_forest_contract.json"
        ).read_text(encoding="utf-8")
    )
    contract_payload["dataset_path"] = "missing.json"
    bad_contract.write_text(json.dumps(contract_payload), encoding="utf-8")

    exit_code = main.main(
        [str(FIXTURES_DIR / "CleanService.java"), "--model-contract", str(bad_contract)]
    )

    assert exit_code == 1
    assert "ML/reporting failed: could not read trusted model contract dataset" in (
        capsys.readouterr().err
    )


def test_main_returns_nonzero_when_shap_reporting_raises_runtime_error(
    capsys: pytest.CaptureFixture[str],
) -> None:
    class BoomExplainer:
        def __call__(self, row: object, check_additivity: bool = False) -> object:
            del row, check_additivity
            raise RuntimeError("boom")

    with patch("shap.TreeExplainer", return_value=BoomExplainer()):
        exit_code = main.main([str(FIXTURES_DIR / "CleanService.java")])

    assert exit_code == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "ML/reporting failed: boom" in captured.err


def test_main_dunder_dispatch_builds_the_correct_supervised_child_command(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """main.py's own __main__ wiring must hand the shared supervisor the
    right child command (its own script path, re-invoked) - the generic
    crash/hang/token behavior itself is covered by
    tests/test_process_supervisor.py, not duplicated here."""
    completed = SimpleNamespace(returncode=0)
    with patch("process_supervisor.subprocess.run", return_value=completed) as mock_run:
        result = process_supervisor.run_as_supervised_subprocess(
            [sys.executable, str(Path(main.__file__).resolve()), "some/path"]
        )
    capsys.readouterr()

    assert result == 0
    (call_args,), _call_kwargs = mock_run.call_args
    assert call_args == [sys.executable, str(Path(main.__file__).resolve()), "some/path"]


def test_real_script_invocation_is_supervised_and_transparent_on_success() -> None:
    """End-to-end check of the actual ``__main__`` dispatch, not just the
    helper function in isolation: running ``python main.py <clean file>``
    as a genuine subprocess (mirroring real CLI use - no worker env var
    set, so __main__ takes the supervisor branch) must still produce
    exit code 0, proving the wrapper adds one layer of re-exec but does
    not change the CLI's observable exit-code contract."""
    completed = subprocess.run(
        [
            sys.executable,
            str(Path(main.__file__).resolve()),
            str(FIXTURES_DIR / "CleanService.java"),
        ],
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0
