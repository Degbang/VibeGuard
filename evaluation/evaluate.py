"""Layer 4 evaluation harness for thesis-ready metric reporting.

Loads the trusted local Layer 4 contract, evaluates the committed
labelled dataset in-sample and via deterministic leave-one-out
retraining, and can render console output or write machine-readable
export artifacts.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.table import Table

from vibeguard.layer4_ml import (
    ConfusionCell,
    EvaluationResult,
    ProjectPrediction,
    evaluate_baseline_severity_model,
    evaluate_project_risk_model,
    leave_one_out_evaluate_project_risk_model,
    load_training_examples,
    load_trusted_model_contract,
)

_DEFAULT_MODEL_CONTRACT = (
    Path(__file__).resolve().parents[1] / "data" / "labeled" / "layer4_random_forest_contract.json"
)


@dataclass(frozen=True)
class EvaluationReport:
    """Final thesis-evaluation summary built from the trusted Layer 4 contract."""

    contract_path: Path
    dataset_path: Path
    random_state: int
    example_count: int
    in_sample: EvaluationResult
    leave_one_out: EvaluationResult
    baseline: EvaluationResult


def build_evaluation_report(contract_path: Path) -> EvaluationReport:
    """Build an evaluation report from one trusted Layer 4 contract."""
    resolved_contract = contract_path.resolve()
    contract_metadata = _read_contract_metadata(resolved_contract)
    dataset_path = _resolve_dataset_path(resolved_contract.parent, contract_metadata)
    random_state = _required_int(contract_metadata.get("random_state"), "random_state")
    examples = load_training_examples(dataset_path)
    model = load_trusted_model_contract(resolved_contract)
    return EvaluationReport(
        contract_path=resolved_contract,
        dataset_path=dataset_path,
        random_state=random_state,
        example_count=len(examples),
        in_sample=evaluate_project_risk_model(model, examples),
        leave_one_out=leave_one_out_evaluate_project_risk_model(
            examples, random_state=random_state
        ),
        baseline=evaluate_baseline_severity_model(examples),
    )


def render_console_report(
    report: EvaluationReport,
    *,
    console: Console | None = None,
) -> None:
    """Render the thesis-evaluation summary to the console."""
    target_console = console or Console()
    _render_overview(report, target_console)
    _render_metric_table(report, target_console)
    _render_prediction_table(report.leave_one_out, target_console)
    _render_confusion_table(report.leave_one_out.confusion, target_console)


def main(argv: list[str] | None = None) -> int:
    """Run the evaluation harness from the command line."""
    args = _parse_args(argv)
    invocation = _module_invocation("evaluation.evaluate", argv or [])
    try:
        report = build_evaluation_report(args.model_contract)
        if args.json_out is not None:
            _write_json_report(report, args.json_out)
        elif args.csv_dir is not None:
            _write_csv_reports(report, args.csv_dir)
        elif args.bundle_dir is not None:
            write_bundle_report(report, args.bundle_dir, invocation=invocation)
        else:
            render_console_report(report)
    except ValueError as exc:
        print(f"Evaluation failed: {exc}", file=sys.stderr)
        return 1
    return 0


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m evaluation.evaluate",
        description=(
            "Evaluate VibeGuard's frozen Layer 4 Random Forest against the "
            "trusted labelled dataset referenced by a model contract."
        ),
    )
    parser.add_argument(
        "--model-contract",
        type=Path,
        default=_DEFAULT_MODEL_CONTRACT,
        help=(
            "Trusted Layer 4 model contract JSON to load before running "
            "in-sample and leave-one-out evaluation."
        ),
    )
    export_group = parser.add_mutually_exclusive_group()
    export_group.add_argument(
        "--json-out",
        type=Path,
        help=(
            "Write a machine-readable JSON evaluation report to this path "
            "instead of rendering the console summary."
        ),
    )
    export_group.add_argument(
        "--csv-dir",
        type=Path,
        help=(
            "Write leave-one-out predictions and confusion-summary CSV files "
            "into this directory instead of rendering the console summary."
        ),
    )
    export_group.add_argument(
        "--bundle-dir",
        type=Path,
        help=(
            "Write a timestamped evaluation artifact bundle containing "
            "JSON plus CSV exports inside this parent directory."
        ),
    )
    return parser.parse_args(argv)


def build_json_report(report: EvaluationReport) -> dict[str, object]:
    """Convert an evaluation report into a JSON-serializable mapping."""
    return {
        "contract_path": str(report.contract_path),
        "dataset_path": str(report.dataset_path),
        "random_state": report.random_state,
        "example_count": report.example_count,
        "in_sample": _evaluation_result_payload(report.in_sample),
        "leave_one_out": _evaluation_result_payload(report.leave_one_out),
        "baseline": _evaluation_result_payload(report.baseline),
    }


def _render_overview(report: EvaluationReport, console: Console) -> None:
    table = Table(title="VibeGuard Evaluation - Layer 4 Dataset Overview")
    table.add_column("Contract", overflow="fold")
    table.add_column("Dataset", overflow="fold")
    table.add_column("Projects")
    table.add_column("Random Seed")
    table.add_row(
        str(report.contract_path),
        str(report.dataset_path),
        str(report.example_count),
        str(report.random_state),
    )
    console.print(table)


def _render_metric_table(report: EvaluationReport, console: Console) -> None:
    table = Table(title="VibeGuard Evaluation - Layer 4 Metrics")
    table.add_column("Mode")
    table.add_column("Accuracy")
    table.add_column("Macro-F1")
    table.add_row(
        "In-sample", f"{report.in_sample.accuracy:.3f}", f"{report.in_sample.macro_f1:.3f}"
    )
    table.add_row(
        "Leave-one-out",
        f"{report.leave_one_out.accuracy:.3f}",
        f"{report.leave_one_out.macro_f1:.3f}",
    )
    table.add_row(
        "Baseline (max Layer 3 severity, not learned)",
        f"{report.baseline.accuracy:.3f}",
        f"{report.baseline.macro_f1:.3f}",
    )
    console.print(table)


def _render_prediction_table(result: EvaluationResult, console: Console) -> None:
    table = Table(title="VibeGuard Evaluation - Leave-One-Out Predictions")
    table.add_column("Project Index")
    table.add_column("Actual")
    table.add_column("Predicted")
    table.add_column("Confidence")
    for prediction in result.predictions:
        table.add_row(
            str(prediction.index),
            prediction.actual.value,
            prediction.predicted.value,
            f"{prediction.confidence:.3f}",
        )
    console.print(table)


def _render_confusion_table(confusion: tuple[ConfusionCell, ...], console: Console) -> None:
    table = Table(title="VibeGuard Evaluation - Leave-One-Out Confusion Matrix")
    table.add_column("Actual")
    table.add_column("Predicted")
    table.add_column("Count")
    for cell in confusion:
        table.add_row(cell.actual.value, cell.predicted.value, str(cell.count))
    console.print(table)


def _write_json_report(report: EvaluationReport, output_path: Path) -> None:
    payload = build_json_report(report)
    try:
        output_path.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    except OSError as exc:
        raise ValueError(f"could not write JSON evaluation report: {exc}") from exc


def _write_json_report_schema(output_path: Path) -> None:
    """Write the JSON Schema contract for ``evaluation.json``."""
    try:
        output_path.write_text(
            json.dumps(_evaluation_report_schema_payload(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    except OSError as exc:
        raise ValueError(f"could not write JSON evaluation schema: {exc}") from exc


def _evaluation_report_schema_payload() -> dict[str, object]:
    """Build the machine-readable schema for evaluation JSON reports."""
    prediction_schema: dict[str, object] = {
        "type": "object",
        "additionalProperties": False,
        "required": ["index", "actual", "predicted", "confidence"],
        "properties": {
            "index": {"type": "integer"},
            "actual": {"type": "string"},
            "predicted": {"type": "string"},
            "confidence": {"type": "number"},
        },
    }
    confusion_cell_schema: dict[str, object] = {
        "type": "object",
        "additionalProperties": False,
        "required": ["actual", "predicted", "count"],
        "properties": {
            "actual": {"type": "string"},
            "predicted": {"type": "string"},
            "count": {"type": "integer"},
        },
    }
    evaluation_result_schema: dict[str, object] = {
        "type": "object",
        "additionalProperties": False,
        "required": ["accuracy", "macro_f1", "predictions", "confusion"],
        "properties": {
            "accuracy": {"type": "number"},
            "macro_f1": {"type": "number"},
            "predictions": {
                "type": "array",
                "items": prediction_schema,
            },
            "confusion": {
                "type": "array",
                "items": confusion_cell_schema,
            },
        },
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "VibeGuard Evaluation Report",
        "description": "Machine-readable Layer 4 evaluation summary for VibeGuard.",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "contract_path",
            "dataset_path",
            "random_state",
            "example_count",
            "in_sample",
            "leave_one_out",
            "baseline",
        ],
        "properties": {
            "contract_path": {"type": "string"},
            "dataset_path": {"type": "string"},
            "random_state": {"type": "integer"},
            "example_count": {"type": "integer"},
            "in_sample": evaluation_result_schema,
            "leave_one_out": evaluation_result_schema,
            "baseline": evaluation_result_schema,
        },
    }


def _write_csv_reports(report: EvaluationReport, output_dir: Path) -> None:
    predictions_path = output_dir / "leave_one_out_predictions.csv"
    confusion_path = output_dir / "leave_one_out_confusion.csv"
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        _write_csv_file(
            predictions_path,
            fieldnames=("index", "actual", "predicted", "confidence"),
            rows=tuple(
                _prediction_payload(prediction) for prediction in report.leave_one_out.predictions
            ),
        )
        _write_csv_file(
            confusion_path,
            fieldnames=("actual", "predicted", "count"),
            rows=tuple(_confusion_payload(cell) for cell in report.leave_one_out.confusion),
        )
    except OSError as exc:
        raise ValueError(f"could not write CSV evaluation report: {exc}") from exc


def write_bundle_report(
    report: EvaluationReport,
    parent_dir: Path,
    *,
    invocation: tuple[str, ...] | None = None,
) -> Path:
    """Write a bundled evaluation artifact directory and return its path."""
    try:
        parent_dir.mkdir(parents=True, exist_ok=True)
        bundle_dir = parent_dir / _bundle_directory_name()
        bundle_dir.mkdir()
    except OSError as exc:
        raise ValueError(f"could not create evaluation artifact bundle: {exc}") from exc
    json_path = bundle_dir / "evaluation.json"
    json_schema_path = bundle_dir / "evaluation.schema.json"
    predictions_path = bundle_dir / "leave_one_out_predictions.csv"
    confusion_path = bundle_dir / "leave_one_out_confusion.csv"
    manifest_path = bundle_dir / "bundle_manifest.json"
    manifest_schema_path = bundle_dir / "bundle_manifest.schema.json"
    readme_path = bundle_dir / "README.txt"
    _write_json_report(report, json_path)
    _write_json_report_schema(json_schema_path)
    _write_csv_reports(report, bundle_dir)
    _write_bundle_readme(report, readme_path)
    _write_bundle_manifest(
        report,
        manifest_path,
        emitted_files=(
            json_path.name,
            json_schema_path.name,
            predictions_path.name,
            confusion_path.name,
            readme_path.name,
            manifest_schema_path.name,
        ),
        invocation=invocation,
    )
    _write_bundle_manifest_schema(manifest_schema_path)
    return bundle_dir


def _bundle_directory_name() -> str:
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return f"vibeguard-evaluation-{timestamp}"


def _write_bundle_manifest(
    report: EvaluationReport,
    manifest_path: Path,
    *,
    emitted_files: tuple[str, ...],
    invocation: tuple[str, ...] | None,
) -> None:
    payload = {
        "export_mode": "bundle",
        "contract_path": str(report.contract_path),
        "dataset_path": str(report.dataset_path),
        "random_state": report.random_state,
        "example_count": report.example_count,
        "bundle_directory": manifest_path.parent.name,
        "emitted_files": list(emitted_files),
        "invocation_argv": list(invocation or ()),
        "invocation_command": " ".join(invocation or ()),
    }
    try:
        manifest_path.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    except OSError as exc:
        raise ValueError(f"could not write evaluation bundle manifest: {exc}") from exc


def _write_bundle_manifest_schema(schema_path: Path) -> None:
    """Write the JSON Schema contract for ``bundle_manifest.json``."""
    try:
        schema_path.write_text(
            json.dumps(_bundle_manifest_schema_payload(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    except OSError as exc:
        raise ValueError(f"could not write evaluation bundle manifest schema: {exc}") from exc


def _bundle_manifest_schema_payload() -> dict[str, object]:
    """Build the machine-readable schema for evaluation bundle manifests."""
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "VibeGuard Evaluation Bundle Manifest",
        "description": "Manifest for one VibeGuard evaluation artifact bundle.",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "export_mode",
            "contract_path",
            "dataset_path",
            "random_state",
            "example_count",
            "bundle_directory",
            "emitted_files",
            "invocation_argv",
            "invocation_command",
        ],
        "properties": {
            "export_mode": {"type": "string", "const": "bundle"},
            "contract_path": {"type": "string"},
            "dataset_path": {"type": "string"},
            "random_state": {"type": "integer"},
            "example_count": {"type": "integer"},
            "bundle_directory": {"type": "string"},
            "emitted_files": {
                "type": "array",
                "items": {"type": "string"},
            },
            "invocation_argv": {
                "type": "array",
                "items": {"type": "string"},
            },
            "invocation_command": {"type": "string"},
        },
    }


def _write_bundle_readme(report: EvaluationReport, readme_path: Path) -> None:
    text = "\n".join(
        (
            "VibeGuard Evaluation Artifact Bundle",
            "",
            "This directory was generated by the thesis evaluation harness.",
            f"Trusted model contract: {report.contract_path}",
            f"Labelled dataset: {report.dataset_path}",
            "",
            "Files:",
            "- evaluation.json: full machine-readable evaluation summary.",
            "- evaluation.schema.json: machine-readable schema for the evaluation report.",
            "- leave_one_out_predictions.csv: one row per held-out project prediction.",
            "- leave_one_out_confusion.csv: non-zero leave-one-out confusion cells.",
            "- bundle_manifest.json: provenance and expected bundle contents.",
            "- bundle_manifest.schema.json: machine-readable schema for the bundle manifest.",
            "",
            "Interpretation:",
            "- The leave-one-out metrics are the primary thesis-ready generalization check.",
            "- In-sample metrics are a sanity check, not the main claim.",
            "- 'baseline' is a fixed, non-learned rule (the severity band of a project's",
            "  single highest-scoring Layer 3 finding) evaluated on the same examples.",
            "  It is the concrete floor Layer 4 needs to beat: if leave-one-out accuracy",
            "  does not exceed the baseline, project-level ML is not demonstrating value",
            "  beyond the deterministic rule-based scorer on its own.",
        )
    )
    try:
        readme_path.write_text(text + "\n", encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"could not write evaluation bundle README: {exc}") from exc


def _module_invocation(module_name: str, argv: list[str]) -> tuple[str, ...]:
    return (Path(sys.executable).name, "-m", module_name, *argv)


def _write_csv_file(
    path: Path,
    *,
    fieldnames: tuple[str, ...],
    rows: tuple[dict[str, object], ...],
) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _evaluation_result_payload(result: EvaluationResult) -> dict[str, object]:
    return {
        "accuracy": result.accuracy,
        "macro_f1": result.macro_f1,
        "predictions": [_prediction_payload(prediction) for prediction in result.predictions],
        "confusion": [_confusion_payload(cell) for cell in result.confusion],
    }


def _prediction_payload(prediction: ProjectPrediction) -> dict[str, object]:
    return {
        "index": prediction.index,
        "actual": prediction.actual.value,
        "predicted": prediction.predicted.value,
        "confidence": prediction.confidence,
    }


def _confusion_payload(cell: ConfusionCell) -> dict[str, object]:
    return {
        "actual": cell.actual.value,
        "predicted": cell.predicted.value,
        "count": cell.count,
    }


def _read_contract_metadata(contract_path: Path) -> Mapping[str, object]:
    try:
        raw = json.loads(contract_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"could not read trusted model contract: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"trusted model contract is not valid JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise ValueError("trusted model contract must be an object")
    return raw


def _resolve_dataset_path(contract_dir: Path, metadata: Mapping[str, object]) -> Path:
    dataset_text = _required_text(metadata.get("dataset_path"), "dataset_path")
    relative_path = Path(dataset_text)
    if relative_path.is_absolute() or ".." in relative_path.parts:
        raise ValueError("trusted model contract dataset_path must be relative and contain no '..'")
    return (contract_dir / relative_path).resolve()


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


if __name__ == "__main__":
    raise SystemExit(main())
