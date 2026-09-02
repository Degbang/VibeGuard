"""Trusted Layer 4 model-contract persistence.

Layer 4 deliberately does not load arbitrary serialized sklearn model
artifacts. Instead, it persists a small JSON contract that points to a
trusted local labelled dataset, records the dataset hash and feature
schema, and re-trains the local Random Forest when loaded. This avoids
pickle/joblib code-execution risks while still giving the project a
repeatable model-loading contract.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import cast

from vibeguard.layer4_ml.dataset import load_training_examples
from vibeguard.layer4_ml.predictor import RiskModel
from vibeguard.layer4_ml.trainer import train_project_risk_model

_SCHEMA_VERSION = 1
_MODEL_KIND = "random_forest_retrain_v1"


@dataclass(frozen=True)
class TrustedModelContract:
    """JSON-serializable contract for trusted local Layer 4 loading."""

    schema_version: int
    model_kind: str
    dataset_path: str
    dataset_sha256: str
    random_state: int
    feature_names: tuple[str, ...]
    label_names: tuple[str, ...]
    training_example_count: int


def write_trusted_model_contract(
    contract_path: Path, dataset_path: Path, *, random_state: int = 42
) -> TrustedModelContract:
    """Validate a labelled dataset, train Layer 4, and persist a JSON contract.

    The contract stores no executable model artifact. Loading it later
    will re-load the labelled dataset, verify its content hash, and
    retrain the deterministic Random Forest with the same random seed.
    """
    resolved_contract = contract_path.resolve()
    resolved_dataset = dataset_path.resolve()
    relative_dataset_path = _relative_dataset_path(resolved_contract.parent, resolved_dataset)
    examples = load_training_examples(resolved_dataset)
    model = train_project_risk_model(examples, random_state=random_state)
    label_names = tuple(model.classifier.classes_)
    contract = TrustedModelContract(
        schema_version=_SCHEMA_VERSION,
        model_kind=_MODEL_KIND,
        dataset_path=relative_dataset_path.as_posix(),
        dataset_sha256=_sha256_file(resolved_dataset),
        random_state=random_state,
        feature_names=model.feature_names,
        label_names=label_names,
        training_example_count=len(examples),
    )
    resolved_contract.write_text(
        json.dumps(asdict(contract), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return contract


def load_trusted_model_contract(contract_path: Path) -> RiskModel:
    """Load a trusted Layer 4 model by validating and retraining from JSON contract."""
    contract = _read_contract(contract_path.resolve())
    dataset_path = _resolve_dataset_path(contract_path.resolve().parent, contract.dataset_path)
    try:
        dataset_sha256 = _sha256_file(dataset_path)
        examples = load_training_examples(dataset_path)
    except OSError as exc:
        raise ValueError(f"could not read trusted model contract dataset: {exc}") from exc
    if dataset_sha256 != contract.dataset_sha256:
        raise ValueError("trusted model contract dataset hash does not match current dataset")
    if len(examples) != contract.training_example_count:
        raise ValueError("trusted model contract example count does not match current dataset")
    model = train_project_risk_model(examples, random_state=contract.random_state)
    if model.feature_names != contract.feature_names:
        raise ValueError("trusted model contract feature schema does not match current Layer 4")
    label_names = tuple(model.classifier.classes_)
    if label_names != contract.label_names:
        raise ValueError("trusted model contract label set does not match current dataset")
    return model


def _read_contract(contract_path: Path) -> TrustedModelContract:
    try:
        raw = json.loads(contract_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"could not read trusted model contract: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"trusted model contract is not valid JSON: {exc}") from exc
    mapping = _required_mapping(raw, "trusted model contract")
    schema_version = _required_int(mapping.get("schema_version"), "schema_version")
    if schema_version != _SCHEMA_VERSION:
        raise ValueError(f"unsupported trusted model contract schema_version: {schema_version}")
    model_kind = _required_text(mapping.get("model_kind"), "model_kind")
    if model_kind != _MODEL_KIND:
        raise ValueError(f"unsupported trusted model contract model_kind: {model_kind}")
    return TrustedModelContract(
        schema_version=schema_version,
        model_kind=model_kind,
        dataset_path=_required_text(mapping.get("dataset_path"), "dataset_path"),
        dataset_sha256=_required_text(mapping.get("dataset_sha256"), "dataset_sha256"),
        random_state=_required_int(mapping.get("random_state"), "random_state"),
        feature_names=_required_text_tuple(mapping.get("feature_names"), "feature_names"),
        label_names=_required_text_tuple(mapping.get("label_names"), "label_names"),
        training_example_count=_required_int(
            mapping.get("training_example_count"), "training_example_count"
        ),
    )


def _relative_dataset_path(contract_dir: Path, dataset_path: Path) -> Path:
    try:
        relative = dataset_path.relative_to(contract_dir)
    except ValueError as exc:
        raise ValueError(
            "dataset path for trusted model contract must sit inside contract directory"
        ) from exc
    if not relative.parts:
        raise ValueError("dataset path for trusted model contract must be a file path")
    return relative


def _resolve_dataset_path(contract_dir: Path, dataset_path: str) -> Path:
    relative = Path(dataset_path)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("trusted model contract dataset_path must be a relative path without '..'")
    return (contract_dir / relative).resolve()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    digest.update(path.read_bytes())
    return digest.hexdigest()


def _required_mapping(value: object, context: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise ValueError(f"{context} must be an object")
    return cast(Mapping[str, object], value)


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


def _required_text_tuple(value: object, context: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ValueError(f"{context} must be a list of strings")
    return tuple(_required_text(item, f"{context}[]") for item in value)
