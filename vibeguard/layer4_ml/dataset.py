"""Layer 4 labelled-dataset loading for local ML training.

This module reads explicit JSON labels for already-detected findings and
converts them into Layer 4 ``TrainingExample`` rows. It does not scan
source files, execute project code, or load serialized model artifacts.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import cast
from unicodedata import category

from vibeguard.layer1_static.rules._finding import Finding
from vibeguard.layer2_features import extract_features
from vibeguard.layer3_scoring import score_features
from vibeguard.layer4_ml.predictor import MLRiskLabel
from vibeguard.layer4_ml.trainer import TrainingExample

_REPO_ROOT = Path(__file__).resolve().parents[2]


def load_training_examples(dataset_path: Path) -> tuple[TrainingExample, ...]:
    """Load labelled project examples from a JSON dataset file.

    The expected JSON shape is:

    ```json
    {
      "projects": [
        {
          "project_id": "example-service",
          "label": "critical",
          "findings": [
            {
              "cwe_id": "CWE-798",
              "file_path": "src/main/resources/application.properties",
              "line": 4,
              "identifier": "spring.datasource.password",
              "message": "Hardcoded credential-like config value",
              "redacted_value": "h*****2"
            }
          ]
        }
      ]
    }
    ```

    Args:
        dataset_path: Path to the JSON labelled dataset.

    Returns:
        Training examples suitable for ``train_project_risk_model``.

    Raises:
        ValueError: If the dataset is malformed or contains non-portable
            finding paths. This fails loud instead of training on shifted
            or ambiguous data.
    """
    root = _load_json_mapping(dataset_path)
    project_records = _required_sequence(root.get("projects"), "projects")
    examples = tuple(
        _training_example_from_record(dataset_path.resolve().parent, index, record)
        for index, record in enumerate(project_records)
    )
    if not examples:
        raise ValueError("labelled dataset must contain at least one project")
    return examples


def _load_json_mapping(dataset_path: Path) -> Mapping[str, object]:
    try:
        raw = json.loads(dataset_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"could not read labelled dataset: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"labelled dataset is not valid JSON: {exc}") from exc
    return _required_mapping(raw, "dataset root")


def _training_example_from_record(
    dataset_root: Path, index: int, record: object
) -> TrainingExample:
    project = _required_mapping(record, f"projects[{index}]")
    project_id = _portable_project_id(project.get("project_id"), f"projects[{index}].project_id")
    project_root = _project_root(project, dataset_root, project_id, f"projects[{index}]")
    label = _risk_label(project.get("label"), f"projects[{index}].label")
    finding_records = _required_sequence(project.get("findings"), f"projects[{index}].findings")
    findings = tuple(
        _finding_from_record(project_root, finding_index, finding)
        for finding_index, finding in enumerate(finding_records)
    )
    return TrainingExample(findings=score_features(extract_features(findings)), label=label)


def _finding_from_record(project_root: Path, index: int, record: object) -> Finding:
    context = f"finding[{index}]"
    finding = _required_mapping(record, context)
    relative_path = _portable_relative_path(finding.get("file_path"), f"{context}.file_path")
    return Finding(
        cwe_id=_required_text(finding.get("cwe_id"), f"{context}.cwe_id"),
        file_path=project_root / relative_path,
        line=_optional_line(finding.get("line"), f"{context}.line"),
        identifier=_required_text(finding.get("identifier"), f"{context}.identifier"),
        message=_required_text(finding.get("message"), f"{context}.message"),
        redacted_value=_optional_text(finding.get("redacted_value"), f"{context}.redacted_value"),
    )


def _project_root(
    project: Mapping[str, object], dataset_root: Path, project_id: str, context: str
) -> Path:
    source_path = project.get("source_path")
    if source_path is None:
        return dataset_root / project_id
    relative_source = _portable_relative_path(source_path, f"{context}.source_path")
    return _REPO_ROOT / relative_source


def _required_mapping(value: object, context: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise ValueError(f"{context} must be an object")
    return cast(Mapping[str, object], value)


def _required_sequence(value: object, context: str) -> tuple[object, ...]:
    if not isinstance(value, list):
        raise ValueError(f"{context} must be a list")
    return tuple(value)


def _risk_label(value: object, context: str) -> MLRiskLabel:
    text = _required_text(value, context).lower()
    try:
        return MLRiskLabel(text)
    except ValueError as exc:
        allowed = ", ".join(label.value for label in MLRiskLabel)
        raise ValueError(f"{context} must be one of: {allowed}") from exc


def _portable_project_id(value: object, context: str) -> str:
    text = _required_text(value, context)
    path = Path(text)
    if path.is_absolute() or len(path.parts) != 1 or text in {".", ".."}:
        raise ValueError(f"{context} must be a portable single-segment project id")
    return text


def _portable_relative_path(value: object, context: str) -> Path:
    text = _required_text(value, context)
    path = Path(text)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"{context} must be a project-relative path without '..'")
    return path


def _optional_line(value: object, context: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{context} must be an integer >= 1 or null")
    if value < 1:
        raise ValueError(f"{context} must be >= 1 or null")
    return value


def _required_text(value: object, context: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{context} must be a string")
    stripped = value.strip()
    if not stripped:
        raise ValueError(f"{context} must be non-empty")
    _reject_control_text(stripped, context)
    return stripped


def _optional_text(value: object, context: str) -> str | None:
    if value is None:
        return None
    return _required_text(value, context)


def _reject_control_text(value: str, context: str) -> None:
    if any(category(character) in {"Cc", "Cf"} for character in value):
        raise ValueError(f"{context} must not contain control characters")
