"""Layer 2 feature extraction from raw Layer 1 findings.

Layer 1 findings are candidate detections, not scored vulnerabilities.
This module converts those findings into stable, deduplicated feature
rows that later layers can score, classify, and explain while retaining
file/line traceability back to the original source location.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from unicodedata import category

from vibeguard.layer1_static.rules._finding import Finding

_CWE_INDEX = {
    "CWE-20": 0,
    "CWE-284": 1,
    "CWE-287": 2,
    "CWE-798": 3,
    "CWE-1035": 4,
}
_CWE_NAMES = {
    "CWE-20": "improper_input_validation",
    "CWE-284": "improper_access_control",
    "CWE-287": "improper_authentication",
    "CWE-798": "hardcoded_credentials",
    "CWE-1035": "known_vulnerable_component",
}
_CONFIG_EXTENSIONS = frozenset({"properties", "yml", "yaml"})


@dataclass(frozen=True)
class FindingFeature:
    """Normalized feature row derived from a single Layer 1 finding."""

    cwe_id: str
    cwe_index: int
    cwe_name: str
    file_path: Path
    line: int | None
    identifier: str
    message: str
    redacted_value: str | None
    source_extension: str
    source_type: str
    has_line: bool
    has_redacted_value: bool
    is_java_source: bool
    is_config_source: bool
    is_pom_file: bool
    identifier_length: int
    message_length: int

    @property
    def trace_key(self) -> tuple[str, str, int | None, str]:
        """Stable key used for deduplication and downstream traceability."""
        return (self.cwe_id, str(self.file_path), self.line, self.identifier)


def extract_features(findings: Iterable[Finding]) -> tuple[FindingFeature, ...]:
    """Normalize and deduplicate raw Layer 1 findings.

    Deduplication is intentionally conservative: two findings collapse
    only when they point to the same CWE, file, line, and identifier.
    The first occurrence is retained so later layers preserve the
    original rule message and redacted value.
    """
    features: list[FindingFeature] = []
    seen: set[tuple[str, str, int | None, str]] = set()
    for finding in findings:
        feature = _feature_from_finding(finding)
        if feature.trace_key in seen:
            continue
        seen.add(feature.trace_key)
        features.append(feature)
    return tuple(features)


def _feature_from_finding(finding: Finding) -> FindingFeature:
    path = finding.file_path.resolve()
    cwe_id = _normalized_cwe_id(finding.cwe_id)
    line = _normalized_line(finding.line)
    identifier = _required_text(finding.identifier, "identifier")
    message = _required_text(finding.message, "message")
    redacted_value = _optional_text(finding.redacted_value, "redacted_value")
    source_extension = _source_extension(path)
    source_type = _source_type(source_extension)
    return FindingFeature(
        cwe_id=cwe_id,
        cwe_index=_CWE_INDEX[cwe_id],
        cwe_name=_CWE_NAMES[cwe_id],
        file_path=path,
        line=line,
        identifier=identifier,
        message=message,
        redacted_value=redacted_value,
        source_extension=source_extension,
        source_type=source_type,
        has_line=line is not None,
        has_redacted_value=redacted_value is not None,
        is_java_source=source_type == "java",
        is_config_source=source_type == "config",
        is_pom_file=source_type == "pom",
        identifier_length=len(identifier),
        message_length=len(message),
    )


def _normalized_cwe_id(cwe_id: str) -> str:
    normalized = _required_text(cwe_id, "cwe_id").upper()
    if normalized not in _CWE_INDEX:
        raise ValueError(f"unsupported CWE id: {cwe_id}")
    return normalized


def _normalized_line(line: int | None) -> int | None:
    if line is None:
        return None
    if isinstance(line, bool) or not isinstance(line, int):
        raise ValueError(f"finding line must be an integer >= 1 or None, got {line!r}")
    if line < 1:
        raise ValueError(f"finding line must be >= 1 or None, got {line}")
    return line


def _required_text(value: str, field_name: str) -> str:
    stripped = value.strip()
    if not stripped:
        raise ValueError(f"finding {field_name} must be non-empty")
    _reject_invisible_text(stripped, field_name)
    return stripped


def _optional_text(value: str | None, field_name: str) -> str | None:
    if value is None:
        return None
    return _required_text(value, field_name)


def _reject_invisible_text(value: str, field_name: str) -> None:
    for character in value:
        if category(character) in {"Cc", "Cf"}:
            raise ValueError(f"finding {field_name} must not contain control characters")


def _source_extension(path: Path) -> str:
    if path.name.lower() == "pom.xml":
        return "pom.xml"
    return path.suffix.lower().lstrip(".") or "unknown"


def _source_type(source_extension: str) -> str:
    if source_extension == "java":
        return "java"
    if source_extension == "pom.xml":
        return "pom"
    if source_extension in _CONFIG_EXTENSIONS:
        return "config"
    raise ValueError(f"unsupported finding source extension: {source_extension}")
