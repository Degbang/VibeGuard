"""Tests for Layer 2 feature extraction."""

from __future__ import annotations

from pathlib import Path

import pytest

from vibeguard.layer1_static.rules._finding import Finding
from vibeguard.layer2_features import FindingFeature, extract_features


def test_extract_features_preserves_traceability_and_basic_features(tmp_path: Path) -> None:
    source = tmp_path / "Service.java"
    finding = Finding(
        cwe_id="CWE-798",
        file_path=source,
        line=12,
        identifier="password",
        message="Hardcoded credential-like value assigned to 'password'",
        redacted_value="h*****2",
    )

    features = extract_features((finding,))

    assert len(features) == 1
    feature = features[0]
    assert isinstance(feature, FindingFeature)
    assert feature.cwe_id == "CWE-798"
    assert feature.cwe_index == 3
    assert feature.cwe_name == "hardcoded_credentials"
    assert feature.file_path == source.resolve()
    assert feature.line == 12
    assert feature.identifier == "password"
    assert feature.redacted_value == "h*****2"
    assert feature.source_extension == "java"
    assert feature.source_type == "java"
    assert feature.has_line is True
    assert feature.has_redacted_value is True
    assert feature.is_java_source is True
    assert feature.is_config_source is False
    assert feature.is_pom_file is False
    assert feature.identifier_length == len("password")
    assert feature.message_length == len(finding.message)
    assert feature.trace_key == ("CWE-798", str(source.resolve()), 12, "password")


def test_extract_features_does_not_expose_absolute_path_depth(tmp_path: Path) -> None:
    finding = Finding(
        cwe_id="CWE-798",
        file_path=tmp_path / "Service.java",
        line=12,
        identifier="password",
        message="hardcoded secret",
    )

    feature = extract_features((finding,))[0]

    assert not hasattr(feature, "path_depth")


def test_extract_features_deduplicates_by_cwe_file_line_and_identifier(
    tmp_path: Path,
) -> None:
    source = tmp_path / "Service.java"
    first = Finding(
        cwe_id="CWE-798",
        file_path=source,
        line=12,
        identifier="password",
        message="first message retained",
        redacted_value="h*****2",
    )
    duplicate = Finding(
        cwe_id="CWE-798",
        file_path=source,
        line=12,
        identifier="password",
        message="duplicate message dropped",
        redacted_value="d*******e",
    )

    features = extract_features((first, duplicate))

    assert len(features) == 1
    assert features[0].message == "first message retained"
    assert features[0].redacted_value == "h*****2"


def test_extract_features_keeps_same_identifier_on_different_lines(tmp_path: Path) -> None:
    source = tmp_path / "Service.java"
    findings = (
        Finding("CWE-798", source, 12, "password", "first", "h*****2"),
        Finding("CWE-798", source, 20, "password", "second", "s****d"),
    )

    features = extract_features(findings)

    assert [(feature.identifier, feature.line) for feature in features] == [
        ("password", 12),
        ("password", 20),
    ]


def test_extract_features_marks_missing_line_and_pom_extension(tmp_path: Path) -> None:
    pom = tmp_path / "pom.xml"
    finding = Finding(
        cwe_id="CWE-1035",
        file_path=pom,
        line=None,
        identifier="org.example:vulnerable",
        message="Known vulnerable dependency",
    )

    features = extract_features((finding,))

    assert len(features) == 1
    assert features[0].source_extension == "pom.xml"
    assert features[0].source_type == "pom"
    assert features[0].has_line is False
    assert features[0].has_redacted_value is False
    assert features[0].is_java_source is False
    assert features[0].is_config_source is False
    assert features[0].is_pom_file is True


def test_extract_features_marks_config_sources(tmp_path: Path) -> None:
    config = tmp_path / "application.yml"
    finding = Finding(
        cwe_id="CWE-798",
        file_path=config,
        line=3,
        identifier="spring.datasource.password",
        message="Hardcoded credential-like config value",
        redacted_value="h*****2",
    )

    features = extract_features((finding,))

    assert len(features) == 1
    assert features[0].source_extension == "yml"
    assert features[0].source_type == "config"
    assert features[0].is_java_source is False
    assert features[0].is_config_source is True
    assert features[0].is_pom_file is False


def test_extract_features_rejects_invalid_negative_line(tmp_path: Path) -> None:
    finding = Finding(
        cwe_id="CWE-798",
        file_path=tmp_path / "Service.java",
        line=-1,
        identifier="password",
        message="invalid trace line",
        redacted_value="h*****2",
    )

    with pytest.raises(ValueError, match="line must be >= 1"):
        extract_features((finding,))


def test_extract_features_rejects_bool_line(tmp_path: Path) -> None:
    finding = Finding(
        cwe_id="CWE-798",
        file_path=tmp_path / "Service.java",
        line=True,
        identifier="password",
        message="invalid trace line",
        redacted_value="h*****2",
    )

    with pytest.raises(ValueError, match="line must be an integer"):
        extract_features((finding,))


def test_extract_features_rejects_unsupported_cwe(tmp_path: Path) -> None:
    finding = Finding(
        cwe_id="CWE-999",
        file_path=tmp_path / "Service.java",
        line=1,
        identifier="password",
        message="unsupported CWE",
    )

    with pytest.raises(ValueError, match="unsupported CWE id"):
        extract_features((finding,))


def test_extract_features_rejects_blank_identifier(tmp_path: Path) -> None:
    finding = Finding(
        cwe_id="CWE-798",
        file_path=tmp_path / "Service.java",
        line=1,
        identifier="   ",
        message="blank identifier",
    )

    with pytest.raises(ValueError, match="identifier must be non-empty"):
        extract_features((finding,))


def test_extract_features_rejects_blank_message(tmp_path: Path) -> None:
    finding = Finding(
        cwe_id="CWE-798",
        file_path=tmp_path / "Service.java",
        line=1,
        identifier="password",
        message="\t",
    )

    with pytest.raises(ValueError, match="message must be non-empty"):
        extract_features((finding,))


def test_extract_features_rejects_control_characters_in_text(tmp_path: Path) -> None:
    finding = Finding(
        cwe_id="CWE-798",
        file_path=tmp_path / "Service.java",
        line=1,
        identifier="pass\nword",
        message="hardcoded secret",
    )

    with pytest.raises(ValueError, match="identifier must not contain control"):
        extract_features((finding,))


def test_extract_features_rejects_blank_redacted_value(tmp_path: Path) -> None:
    finding = Finding(
        cwe_id="CWE-798",
        file_path=tmp_path / "Service.java",
        line=1,
        identifier="password",
        message="hardcoded secret",
        redacted_value="   ",
    )

    with pytest.raises(ValueError, match="redacted_value must be non-empty"):
        extract_features((finding,))


def test_extract_features_rejects_control_characters_in_redacted_value(
    tmp_path: Path,
) -> None:
    finding = Finding(
        cwe_id="CWE-798",
        file_path=tmp_path / "Service.java",
        line=1,
        identifier="password",
        message="hardcoded secret",
        redacted_value="h*****2\u202e",
    )

    with pytest.raises(ValueError, match="redacted_value must not contain control"):
        extract_features((finding,))


def test_extract_features_rejects_unsupported_source_extension(tmp_path: Path) -> None:
    finding = Finding(
        cwe_id="CWE-798",
        file_path=tmp_path / "README.md",
        line=1,
        identifier="password",
        message="hardcoded secret",
    )

    with pytest.raises(ValueError, match="unsupported finding source extension"):
        extract_features((finding,))


def test_extract_features_normalizes_cwe_and_trims_text(tmp_path: Path) -> None:
    source = tmp_path / "Service.java"
    finding = Finding(
        cwe_id=" cwe-798 ",
        file_path=source,
        line=1,
        identifier=" password ",
        message=" hardcoded secret ",
        redacted_value="h*****2",
    )

    features = extract_features((finding,))

    assert len(features) == 1
    assert features[0].cwe_id == "CWE-798"
    assert features[0].identifier == "password"
    assert features[0].message == "hardcoded secret"
    assert features[0].identifier_length == len("password")
    assert features[0].message_length == len("hardcoded secret")
