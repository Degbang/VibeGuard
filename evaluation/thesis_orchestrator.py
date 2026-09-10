"""Combined thesis orchestrator for scan-time and evaluation artifacts."""

from __future__ import annotations

import argparse
import json
import sys
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import dataclass
from datetime import datetime
from io import StringIO
from pathlib import Path

import main as scan_cli
from evaluation import thesis_run
from evaluation.evaluate import _DEFAULT_MODEL_CONTRACT, _module_invocation
from vibeguard.layer1_static._parsing_guards import ParseStatus
from vibeguard.layer1_static.ast_parser import (
    DEFAULT_MAX_FILE_BYTES,
    DEFAULT_PARSE_TIMEOUT_SECONDS,
    ParsedFile,
)
from vibeguard.layer1_static.config_parser import ParsedConfigFile
from vibeguard.layer1_static.pom_parser import ParsedPomFile
from vibeguard.layer1_static.rules._finding import Finding
from vibeguard.layer1_static.scanner import ScanResult, scan_directory
from vibeguard.layer3_scoring import ScoredFinding
from vibeguard.layer4_ml import load_trusted_model_contract
from vibeguard.layer5_report import ProjectRiskReport, build_project_risk_report


@dataclass(frozen=True)
class ScanArtifacts:
    """Artifacts captured from one scan CLI run."""

    artifact_dir: Path
    exit_code: int
    invocation: tuple[str, ...]
    report_path: Path


@dataclass(frozen=True)
class EvaluationArtifacts:
    """Artifacts captured from one evaluation thesis-run wrapper execution."""

    bundle_dir: Path
    invocation: tuple[str, ...]


@dataclass(frozen=True)
class ScanExecution:
    """One full scan-pipeline execution captured for artifact output."""

    scan_path: Path
    result: ScanResult
    findings: tuple[Finding, ...]
    scored_findings: tuple[ScoredFinding, ...]
    final_report: ProjectRiskReport | None
    exit_code: int
    error_message: str | None


def main(argv: list[str] | None = None) -> int:
    """Run the scan CLI and evaluation bundle wrapper as one thesis artifact pass."""
    args = _parse_args(argv)
    invocation = _module_invocation(
        "evaluation.thesis_orchestrator", sys.argv[1:] if argv is None else argv
    )
    try:
        resolved_scan_path = args.scan_path.resolve()
        if not resolved_scan_path.exists():
            raise ValueError(f"scan path does not exist: {resolved_scan_path}")
        run_dir = _create_run_dir(args.output_dir)
        scan_artifacts = _run_scan(
            resolved_scan_path,
            run_dir / "scan",
            model_contract=args.model_contract.resolve(),
            max_bytes=args.max_bytes,
            timeout=args.timeout,
        )
        evaluation_artifacts = _run_evaluation_bundle(args.model_contract.resolve(), run_dir)
        _write_run_manifest(
            run_dir / "run_manifest.json",
            orchestrator_invocation=invocation,
            scan_path=resolved_scan_path,
            scan_artifacts=scan_artifacts,
            evaluation_artifacts=evaluation_artifacts,
        )
        _write_run_manifest_schema(run_dir / "run_manifest.schema.json")
        _write_run_summary(
            run_dir / "thesis_summary.json",
            scan_path=resolved_scan_path,
            scan_artifacts=scan_artifacts,
            evaluation_artifacts=evaluation_artifacts,
        )
        _write_run_summary_schema(run_dir / "thesis_summary.schema.json")
    except ValueError as exc:
        print(f"Thesis orchestration failed: {exc}", file=sys.stderr)
        return 1
    print(run_dir)
    return 0


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m evaluation.thesis_orchestrator",
        description=(
            "Run a VibeGuard project scan and the thesis evaluation bundle wrapper "
            "as one combined artifact-generation pass."
        ),
    )
    parser.add_argument(
        "scan_path", type=Path, help="Project file or directory to scan with VibeGuard."
    )
    parser.add_argument(
        "--model-contract",
        type=Path,
        default=_DEFAULT_MODEL_CONTRACT,
        help="Trusted Layer 4 model contract JSON used for both scan-time ML and evaluation.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("thesis_artifacts"),
        help="Parent directory where the timestamped combined thesis run will be created.",
    )
    parser.add_argument(
        "--max-bytes",
        type=int,
        default=DEFAULT_MAX_FILE_BYTES,
        help=(
            "Scan-time file-size limit passed through to the VibeGuard CLI "
            f"(default: {DEFAULT_MAX_FILE_BYTES})."
        ),
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_PARSE_TIMEOUT_SECONDS,
        help=(
            "Scan-time per-file parse timeout passed through to the VibeGuard CLI "
            f"(default: {DEFAULT_PARSE_TIMEOUT_SECONDS})."
        ),
    )
    return parser.parse_args(argv)


def _run_scan(
    scan_path: Path,
    artifact_dir: Path,
    *,
    model_contract: Path,
    max_bytes: int,
    timeout: float,
) -> ScanArtifacts:
    invocation = _script_invocation(
        "main.py",
        [
            str(scan_path),
            "--model-contract",
            str(model_contract),
            "--max-bytes",
            str(max_bytes),
            "--timeout",
            str(timeout),
        ],
    )
    execution = _execute_scan(
        scan_path,
        model_contract=model_contract,
        max_bytes=max_bytes,
        timeout=timeout,
    )
    stdout_buffer = StringIO()
    stderr_buffer = StringIO()
    with redirect_stdout(stdout_buffer), redirect_stderr(stderr_buffer):
        _render_scan_execution(execution)

    try:
        artifact_dir.mkdir(parents=True, exist_ok=True)
        stdout_path = artifact_dir / "scan_stdout.txt"
        stderr_path = artifact_dir / "scan_stderr.txt"
        report_path = artifact_dir / "scan_report.json"
        manifest_path = artifact_dir / "scan_manifest.json"
        manifest_schema_path = artifact_dir / "scan_manifest.schema.json"
        stdout_path.write_text(stdout_buffer.getvalue(), encoding="utf-8")
        stderr_path.write_text(stderr_buffer.getvalue(), encoding="utf-8")
        report_path.write_text(
            json.dumps(_scan_report_payload(execution), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        manifest_path.write_text(
            json.dumps(
                {
                    "scan_path": str(execution.scan_path),
                    "exit_code": execution.exit_code,
                    "invocation_argv": list(invocation),
                    "invocation_command": " ".join(invocation),
                    "report_file": report_path.name,
                    "stdout_file": stdout_path.name,
                    "stderr_file": stderr_path.name,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        _write_scan_manifest_schema(manifest_schema_path)
    except OSError as exc:
        raise ValueError(f"could not write scan artifacts: {exc}") from exc
    return ScanArtifacts(
        artifact_dir=artifact_dir,
        exit_code=execution.exit_code,
        invocation=invocation,
        report_path=report_path,
    )


def _write_scan_manifest_schema(schema_path: Path) -> None:
    """Write the JSON Schema contract for ``scan_manifest.json``."""
    try:
        schema_path.write_text(
            json.dumps(_scan_manifest_schema_payload(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    except OSError as exc:
        raise ValueError(f"could not write scan manifest schema: {exc}") from exc


def _scan_manifest_schema_payload() -> dict[str, object]:
    """Build the machine-readable schema for scan manifests."""
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "VibeGuard Scan Manifest",
        "description": "Manifest for one captured VibeGuard scan artifact directory.",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "scan_path",
            "exit_code",
            "invocation_argv",
            "invocation_command",
            "report_file",
            "stdout_file",
            "stderr_file",
        ],
        "properties": {
            "scan_path": {"type": "string"},
            "exit_code": {"type": "integer"},
            "invocation_argv": {
                "type": "array",
                "items": {"type": "string"},
            },
            "invocation_command": {"type": "string"},
            "report_file": {"type": "string", "const": "scan_report.json"},
            "stdout_file": {"type": "string", "const": "scan_stdout.txt"},
            "stderr_file": {"type": "string", "const": "scan_stderr.txt"},
        },
    }


def _run_evaluation_bundle(model_contract: Path, run_dir: Path) -> EvaluationArtifacts:
    evaluation_parent = run_dir / "evaluation"
    invocation_args = [
        "--model-contract",
        str(model_contract),
        "--output-dir",
        str(evaluation_parent),
    ]
    invocation = _module_invocation("evaluation.thesis_run", invocation_args)
    stdout_buffer = StringIO()
    stderr_buffer = StringIO()
    with redirect_stdout(stdout_buffer), redirect_stderr(stderr_buffer):
        exit_code = thesis_run.main(invocation_args)
    if exit_code != 0:
        message = stderr_buffer.getvalue().strip() or "evaluation thesis run failed"
        raise ValueError(message)
    bundle_text = stdout_buffer.getvalue().strip()
    if not bundle_text:
        raise ValueError("evaluation thesis run did not report a bundle path")
    bundle_dir = Path(bundle_text).resolve()
    return EvaluationArtifacts(bundle_dir=bundle_dir, invocation=invocation)


def _write_run_manifest(
    manifest_path: Path,
    *,
    orchestrator_invocation: tuple[str, ...],
    scan_path: Path,
    scan_artifacts: ScanArtifacts,
    evaluation_artifacts: EvaluationArtifacts,
) -> None:
    summary_path = manifest_path.parent / "thesis_summary.json"
    summary_schema_path = manifest_path.parent / "thesis_summary.schema.json"
    payload = {
        "export_mode": "combined_thesis_run",
        "scan_path": str(scan_path),
        "run_directory": str(manifest_path.parent),
        "summary_file": str(summary_path),
        "summary_file_relative": str(summary_path.relative_to(manifest_path.parent)),
        "summary_schema_file": str(summary_schema_path),
        "summary_schema_file_relative": str(summary_schema_path.relative_to(manifest_path.parent)),
        "scan_artifact_dir": str(scan_artifacts.artifact_dir),
        "scan_artifact_dir_relative": str(
            scan_artifacts.artifact_dir.relative_to(manifest_path.parent)
        ),
        "scan_exit_code": scan_artifacts.exit_code,
        "evaluation_bundle_dir": str(evaluation_artifacts.bundle_dir),
        "evaluation_bundle_dir_relative": str(
            evaluation_artifacts.bundle_dir.relative_to(manifest_path.parent)
        ),
        "orchestrator_invocation_argv": list(orchestrator_invocation),
        "orchestrator_invocation_command": " ".join(orchestrator_invocation),
        "scan_invocation_argv": list(scan_artifacts.invocation),
        "scan_invocation_command": " ".join(scan_artifacts.invocation),
        "evaluation_invocation_argv": list(evaluation_artifacts.invocation),
        "evaluation_invocation_command": " ".join(evaluation_artifacts.invocation),
    }
    try:
        manifest_path.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    except OSError as exc:
        raise ValueError(f"could not write thesis run manifest: {exc}") from exc


def _write_run_manifest_schema(schema_path: Path) -> None:
    """Write the JSON Schema contract for ``run_manifest.json``."""
    try:
        schema_path.write_text(
            json.dumps(_run_manifest_schema_payload(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    except OSError as exc:
        raise ValueError(f"could not write thesis run manifest schema: {exc}") from exc


def _run_manifest_schema_payload() -> dict[str, object]:
    """Build the machine-readable schema for combined thesis run manifests."""
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "VibeGuard Combined Thesis Run Manifest",
        "description": (
            "Top-level manifest for one combined VibeGuard scan and "
            "evaluation thesis artifact run."
        ),
        "type": "object",
        "additionalProperties": False,
        "required": [
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
        ],
        "properties": {
            "export_mode": {"type": "string", "const": "combined_thesis_run"},
            "scan_path": {"type": "string"},
            "run_directory": {"type": "string"},
            "summary_file": {"type": "string"},
            "summary_file_relative": {"type": "string"},
            "summary_schema_file": {"type": "string"},
            "summary_schema_file_relative": {"type": "string"},
            "scan_artifact_dir": {"type": "string"},
            "scan_artifact_dir_relative": {"type": "string"},
            "scan_exit_code": {"type": "integer"},
            "evaluation_bundle_dir": {"type": "string"},
            "evaluation_bundle_dir_relative": {"type": "string"},
            "orchestrator_invocation_argv": {
                "type": "array",
                "items": {"type": "string"},
            },
            "orchestrator_invocation_command": {"type": "string"},
            "scan_invocation_argv": {
                "type": "array",
                "items": {"type": "string"},
            },
            "scan_invocation_command": {"type": "string"},
            "evaluation_invocation_argv": {
                "type": "array",
                "items": {"type": "string"},
            },
            "evaluation_invocation_command": {"type": "string"},
        },
    }


def _write_run_summary(
    summary_path: Path,
    *,
    scan_path: Path,
    scan_artifacts: ScanArtifacts,
    evaluation_artifacts: EvaluationArtifacts,
) -> None:
    scan_report = _read_json_mapping(scan_artifacts.report_path, "scan report")
    evaluation_report = _read_json_mapping(
        evaluation_artifacts.bundle_dir / "evaluation.json",
        "evaluation report",
    )
    bundle_manifest = _read_json_mapping(
        evaluation_artifacts.bundle_dir / "bundle_manifest.json",
        "evaluation bundle manifest",
    )
    leave_one_out = _required_mapping(
        evaluation_report.get("leave_one_out"),
        "evaluation report.leave_one_out",
    )
    in_sample = _required_mapping(
        evaluation_report.get("in_sample"),
        "evaluation report.in_sample",
    )
    project_risk_report = scan_report.get("project_risk_report")
    risk_summary = None
    if project_risk_report is not None:
        risk_payload = _required_mapping(project_risk_report, "scan report.project_risk_report")
        risk_summary = {
            "predicted_label": _required_text(
                risk_payload.get("predicted_label"),
                "scan report.project_risk_report.predicted_label",
            ),
            "confidence": _required_float(
                risk_payload.get("confidence"),
                "scan report.project_risk_report.confidence",
            ),
        }

    payload = {
        "schema_version": 2,
        "export_mode": "combined_thesis_summary",
        "run_directory": str(summary_path.parent),
        "scan_path": str(scan_path),
        "scan": {
            "artifact_dir": str(scan_artifacts.artifact_dir),
            "artifact_dir_relative": str(
                scan_artifacts.artifact_dir.relative_to(summary_path.parent)
            ),
            "report_file": str(scan_artifacts.report_path),
            "report_file_relative": str(
                scan_artifacts.report_path.relative_to(summary_path.parent)
            ),
            "exit_code": _required_int(scan_report.get("exit_code"), "scan report.exit_code"),
            "finding_count": _required_int(
                scan_report.get("finding_count"),
                "scan report.finding_count",
            ),
            "scored_finding_count": _required_int(
                scan_report.get("scored_finding_count"),
                "scan report.scored_finding_count",
            ),
            "project_risk": risk_summary,
        },
        "evaluation": {
            "bundle_dir": str(evaluation_artifacts.bundle_dir),
            "bundle_dir_relative": str(
                evaluation_artifacts.bundle_dir.relative_to(summary_path.parent)
            ),
            "report_file": str(evaluation_artifacts.bundle_dir / "evaluation.json"),
            "report_file_relative": str(
                (evaluation_artifacts.bundle_dir / "evaluation.json").relative_to(
                    summary_path.parent
                )
            ),
            "manifest_file": str(evaluation_artifacts.bundle_dir / "bundle_manifest.json"),
            "manifest_file_relative": str(
                (evaluation_artifacts.bundle_dir / "bundle_manifest.json").relative_to(
                    summary_path.parent
                )
            ),
            "example_count": _required_int(
                evaluation_report.get("example_count"),
                "evaluation report.example_count",
            ),
            "in_sample_accuracy": _required_float(
                in_sample.get("accuracy"),
                "evaluation report.in_sample.accuracy",
            ),
            "leave_one_out_accuracy": _required_float(
                leave_one_out.get("accuracy"),
                "evaluation report.leave_one_out.accuracy",
            ),
            "leave_one_out_macro_f1": _required_float(
                leave_one_out.get("macro_f1"),
                "evaluation report.leave_one_out.macro_f1",
            ),
            "bundle_invocation_command": _required_text(
                bundle_manifest.get("invocation_command"),
                "evaluation bundle manifest.invocation_command",
            ),
        },
    }
    try:
        summary_path.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    except OSError as exc:
        raise ValueError(f"could not write thesis summary: {exc}") from exc


def _write_run_summary_schema(schema_path: Path) -> None:
    """Write the JSON Schema contract for ``thesis_summary.json``."""
    try:
        schema_path.write_text(
            json.dumps(_thesis_summary_schema_payload(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    except OSError as exc:
        raise ValueError(f"could not write thesis summary schema: {exc}") from exc


def _thesis_summary_schema_payload() -> dict[str, object]:
    """Build the machine-readable schema for combined thesis summaries."""
    project_risk_schema: dict[str, object] = {
        "type": "object",
        "additionalProperties": False,
        "required": ["predicted_label", "confidence"],
        "properties": {
            "predicted_label": {"type": "string"},
            "confidence": {"type": "number"},
        },
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "VibeGuard Combined Thesis Summary",
        "description": (
            "Normalized top-level summary for one combined VibeGuard scan "
            "and evaluation thesis artifact run."
        ),
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "export_mode",
            "run_directory",
            "scan_path",
            "scan",
            "evaluation",
        ],
        "properties": {
            "schema_version": {"type": "integer", "const": 2},
            "export_mode": {"type": "string", "const": "combined_thesis_summary"},
            "run_directory": {"type": "string"},
            "scan_path": {"type": "string"},
            "scan": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "artifact_dir",
                    "artifact_dir_relative",
                    "report_file",
                    "report_file_relative",
                    "exit_code",
                    "finding_count",
                    "scored_finding_count",
                    "project_risk",
                ],
                "properties": {
                    "artifact_dir": {"type": "string"},
                    "artifact_dir_relative": {"type": "string"},
                    "report_file": {"type": "string"},
                    "report_file_relative": {"type": "string"},
                    "exit_code": {"type": "integer"},
                    "finding_count": {"type": "integer"},
                    "scored_finding_count": {"type": "integer"},
                    "project_risk": {
                        "oneOf": [
                            {"type": "null"},
                            project_risk_schema,
                        ]
                    },
                },
            },
            "evaluation": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "bundle_dir",
                    "bundle_dir_relative",
                    "report_file",
                    "report_file_relative",
                    "manifest_file",
                    "manifest_file_relative",
                    "example_count",
                    "in_sample_accuracy",
                    "leave_one_out_accuracy",
                    "leave_one_out_macro_f1",
                    "bundle_invocation_command",
                ],
                "properties": {
                    "bundle_dir": {"type": "string"},
                    "bundle_dir_relative": {"type": "string"},
                    "report_file": {"type": "string"},
                    "report_file_relative": {"type": "string"},
                    "manifest_file": {"type": "string"},
                    "manifest_file_relative": {"type": "string"},
                    "example_count": {"type": "integer"},
                    "in_sample_accuracy": {"type": "number"},
                    "leave_one_out_accuracy": {"type": "number"},
                    "leave_one_out_macro_f1": {"type": "number"},
                    "bundle_invocation_command": {"type": "string"},
                },
            },
        },
    }


def _execute_scan(
    scan_path: Path,
    *,
    model_contract: Path,
    max_bytes: int,
    timeout: float,
) -> ScanExecution:
    if scan_path.is_file():
        result = scan_cli._scan_single_file(scan_path, max_bytes, timeout)
    elif scan_path.is_dir():
        result = scan_directory(scan_path, max_bytes=max_bytes, timeout_seconds=timeout)
    else:
        raise ValueError(f"scan path is not a file or directory: {scan_path}")

    if not result.java_files and not result.config_files and not result.pom_files:
        return ScanExecution(
            scan_path=scan_path,
            result=result,
            findings=(),
            scored_findings=(),
            final_report=None,
            exit_code=1,
            error_message=f"No .java/config/pom.xml files found under {scan_path}",
        )

    findings = scan_cli._run_rules(result)
    try:
        scored_findings = scan_cli._score_findings(findings)
    except ValueError as exc:
        return ScanExecution(
            scan_path=scan_path,
            result=result,
            findings=findings,
            scored_findings=(),
            final_report=None,
            exit_code=1,
            error_message=f"Scoring failed: {exc}",
        )

    try:
        model = load_trusted_model_contract(model_contract.resolve())
        final_report = build_project_risk_report(scan_path, model, scored_findings)
    except Exception as exc:
        return ScanExecution(
            scan_path=scan_path,
            result=result,
            findings=findings,
            scored_findings=scored_findings,
            final_report=None,
            exit_code=1,
            error_message=f"ML/reporting failed: {exc}",
        )

    java_ok = all(item.status == ParseStatus.OK for item in result.java_files)
    config_ok = all(item.status == ParseStatus.OK for item in result.config_files)
    pom_ok = all(item.status == ParseStatus.OK for item in result.pom_files)
    exit_code = (
        0
        if java_ok and config_ok and pom_ok and not result.rejected_paths and not scored_findings
        else 1
    )
    return ScanExecution(
        scan_path=scan_path,
        result=result,
        findings=findings,
        scored_findings=scored_findings,
        final_report=final_report,
        exit_code=exit_code,
        error_message=None,
    )


def _render_scan_execution(execution: ScanExecution) -> None:
    if execution.error_message is not None:
        print(execution.error_message, file=sys.stderr)
        return
    if execution.result.java_files:
        scan_cli._print_java_report(execution.result.java_files)
    if execution.result.config_files:
        scan_cli._print_config_report(execution.result.config_files)
    if execution.result.pom_files:
        scan_cli._print_pom_report(execution.result.pom_files)
    if execution.result.rejected_paths:
        scan_cli._print_rejected_report(execution.result.rejected_paths)
    if execution.scored_findings:
        scan_cli._print_scored_findings_report(execution.scored_findings)
    if execution.final_report is not None:
        scan_cli.render_console_report(execution.final_report)


def _scan_report_payload(execution: ScanExecution) -> dict[str, object]:
    return {
        "scan_path": str(execution.scan_path),
        "scan_root": str(execution.result.root),
        "exit_code": execution.exit_code,
        "error_message": execution.error_message,
        "java_files": [_java_file_payload(item) for item in execution.result.java_files],
        "config_files": [_config_file_payload(item) for item in execution.result.config_files],
        "pom_files": [_pom_file_payload(item) for item in execution.result.pom_files],
        "rejected_paths": [
            {"path": str(item.path), "reason": item.reason}
            for item in execution.result.rejected_paths
        ],
        "finding_count": len(execution.findings),
        "findings": [_finding_payload(item) for item in execution.findings],
        "scored_finding_count": len(execution.scored_findings),
        "scored_findings": [_scored_finding_payload(item) for item in execution.scored_findings],
        "project_risk_report": (
            _project_risk_report_payload(execution.final_report)
            if execution.final_report is not None
            else None
        ),
    }


def _java_file_payload(parsed: ParsedFile) -> dict[str, object]:
    return {
        "path": str(parsed.path),
        "status": parsed.status.value,
        "package": parsed.package,
        "class_count": len(parsed.classes),
        "class_names": [cls.name for cls in parsed.classes],
        "error_message": parsed.error_message,
    }


def _config_file_payload(parsed: ParsedConfigFile) -> dict[str, object]:
    return {
        "path": str(parsed.path),
        "status": parsed.status.value,
        "format": parsed.format.value if parsed.format is not None else None,
        "entry_count": len(parsed.entries),
        "error_message": parsed.error_message,
    }


def _pom_file_payload(parsed: ParsedPomFile) -> dict[str, object]:
    return {
        "path": str(parsed.path),
        "status": parsed.status.value,
        "dependency_count": len(parsed.dependencies),
        "error_message": parsed.error_message,
    }


def _finding_payload(item: Finding) -> dict[str, object]:
    return {
        "cwe_id": item.cwe_id,
        "file_path": str(item.file_path),
        "line": item.line,
        "identifier": item.identifier,
        "message": item.message,
        "redacted_value": item.redacted_value,
    }


def _scored_finding_payload(item: ScoredFinding) -> dict[str, object]:
    return {
        "cwe_id": item.feature.cwe_id,
        "file_path": str(item.feature.file_path),
        "line": item.feature.line,
        "identifier": item.feature.identifier,
        "message": item.feature.message,
        "redacted_value": item.feature.redacted_value,
        "score": item.score,
        "severity": item.severity.value,
        "source_type": item.feature.source_type,
        "factors": list(item.factors),
    }


def _project_risk_report_payload(report: ProjectRiskReport) -> dict[str, object]:
    return {
        "scan_path": str(report.scan_path),
        "predicted_label": report.explanation.prediction.label.value,
        "confidence": report.explanation.prediction.confidence,
        "baseline_probability": report.explanation.baseline_probability,
        "contributions": [
            {
                "feature_name": item.feature_name,
                "feature_value": item.feature_value,
                "shap_value": item.shap_value,
            }
            for item in report.explanation.contributions
        ],
    }


def _create_run_dir(output_dir: Path) -> Path:
    try:
        output_dir = output_dir.resolve()
        output_dir.mkdir(parents=True, exist_ok=True)
        run_dir = output_dir / _run_directory_name()
        run_dir.mkdir()
    except OSError as exc:
        raise ValueError(f"could not create thesis run directory: {exc}") from exc
    return run_dir


def _run_directory_name() -> str:
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return f"vibeguard-thesis-run-{timestamp}"


def _script_invocation(script_name: str, argv: list[str]) -> tuple[str, ...]:
    return (Path(sys.executable).name, script_name, *argv)


def _read_json_mapping(path: Path, context: str) -> dict[str, object]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"could not read {context}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"{context} is not valid JSON: {exc}") from exc
    return _required_mapping(raw, context)


def _required_mapping(value: object, context: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError(f"{context} must be an object")
    return value


def _required_text(value: object, context: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{context} must be a string")
    stripped = value.strip()
    if not stripped:
        raise ValueError(f"{context} must be non-empty")
    return stripped


def _required_int(value: object, context: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{context} must be an integer")
    return value


def _required_float(value: object, context: str) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise ValueError(f"{context} must be a number")
    return float(value)


if __name__ == "__main__":
    raise SystemExit(main())
