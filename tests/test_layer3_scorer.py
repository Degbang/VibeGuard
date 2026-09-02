"""Tests for Layer 3 deterministic rule-based scoring."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from vibeguard.layer1_static.rules._finding import Finding
from vibeguard.layer2_features import FindingFeature, extract_features
from vibeguard.layer3_scoring import RiskSeverity, ScoredFinding, score_features


def _feature(
    tmp_path: Path,
    cwe_id: str,
    filename: str,
    *,
    line: int | None = 1,
    redacted_value: str | None = None,
) -> FindingFeature:
    return extract_features(
        (
            Finding(
                cwe_id=cwe_id,
                file_path=tmp_path / filename,
                line=line,
                identifier="identifier",
                message="candidate finding",
                redacted_value=redacted_value,
            ),
        )
    )[0]


def test_score_features_preserves_order_and_traceability(tmp_path: Path) -> None:
    features = (
        _feature(tmp_path, "CWE-20", "Controller.java"),
        _feature(tmp_path, "CWE-798", "application.properties", redacted_value="h*****2"),
    )

    scored = score_features(features)

    assert len(scored) == 2
    assert all(isinstance(item, ScoredFinding) for item in scored)
    assert [item.feature for item in scored] == list(features)
    assert [item.trace_key for item in scored] == [feature.trace_key for feature in features]


def test_score_features_assigns_expected_base_scores_and_severities(
    tmp_path: Path,
) -> None:
    cases = (
        ("CWE-20", "Controller.java", 65, RiskSeverity.MEDIUM),
        ("CWE-284", "Controller.java", 80, RiskSeverity.HIGH),
        ("CWE-287", "AuthService.java", 75, RiskSeverity.HIGH),
        ("CWE-798", "Service.java", 90, RiskSeverity.CRITICAL),
        ("CWE-1035", "pom.xml", 90, RiskSeverity.CRITICAL),
    )

    for cwe_id, filename, expected_score, expected_severity in cases:
        redacted_value = "h*****2" if cwe_id == "CWE-798" else None
        feature = _feature(tmp_path, cwe_id, filename, redacted_value=redacted_value)

        scored = score_features((feature,))[0]

        assert scored.score == expected_score
        assert scored.severity is expected_severity
        assert (
            scored.factors[0]
            == f"base {cwe_id} score {expected_score if cwe_id != 'CWE-1035' else 85}"
        )


def test_score_features_boosts_config_hardcoded_credentials(tmp_path: Path) -> None:
    feature = _feature(
        tmp_path,
        "CWE-798",
        "application.yml",
        redacted_value="h*****2",
    )

    scored = score_features((feature,))[0]

    assert scored.score == 95
    assert scored.severity is RiskSeverity.CRITICAL
    assert "hardcoded credential is in deployment config" in scored.factors[1]


def test_score_features_reduces_score_when_line_is_missing(tmp_path: Path) -> None:
    feature = _feature(tmp_path, "CWE-1035", "pom.xml", line=None)

    scored = score_features((feature,))[0]

    assert scored.score == 85
    assert scored.severity is RiskSeverity.CRITICAL
    assert any("source line is unavailable" in factor for factor in scored.factors)


def test_score_features_returns_empty_tuple_for_no_features() -> None:
    assert score_features(()) == ()


def test_score_features_rejects_unknown_cwe(tmp_path: Path) -> None:
    feature = replace(_feature(tmp_path, "CWE-20", "Controller.java"), cwe_id="CWE-999")

    with pytest.raises(ValueError, match="unsupported CWE id"):
        score_features((feature,))


def test_score_features_rejects_unknown_source_type(tmp_path: Path) -> None:
    feature = replace(
        _feature(tmp_path, "CWE-20", "Controller.java"),
        source_type="unknown",
    )

    with pytest.raises(ValueError, match="unsupported source type"):
        score_features((feature,))


def test_score_features_rejects_inconsistent_source_flags(tmp_path: Path) -> None:
    feature = replace(
        _feature(tmp_path, "CWE-20", "Controller.java"),
        is_config_source=True,
    )

    with pytest.raises(ValueError, match="exactly one source-type flag"):
        score_features((feature,))


def test_score_features_rejects_source_type_flag_mismatch(tmp_path: Path) -> None:
    feature = replace(
        _feature(tmp_path, "CWE-20", "Controller.java"),
        source_type="config",
        is_java_source=False,
        is_config_source=True,
    )
    mismatched = replace(feature, source_type="java")

    with pytest.raises(ValueError, match="does not match source-type flags"):
        score_features((mismatched,))


def test_score_features_rejects_source_extension_type_mismatch(tmp_path: Path) -> None:
    feature = replace(
        _feature(tmp_path, "CWE-798", "Service.java", redacted_value="h*****2"),
        source_type="config",
        is_java_source=False,
        is_config_source=True,
    )

    with pytest.raises(ValueError, match="source_extension='java' does not match"):
        score_features((feature,))


def test_score_features_rejects_cwe_source_type_mismatch(tmp_path: Path) -> None:
    feature = _feature(tmp_path, "CWE-284", "application.yml")

    with pytest.raises(ValueError, match="CWE-284 cannot be scored"):
        score_features((feature,))


def test_score_features_rejects_cwe798_without_redacted_value(tmp_path: Path) -> None:
    feature = _feature(tmp_path, "CWE-798", "Service.java")

    with pytest.raises(ValueError, match="requires a redacted_value"):
        score_features((feature,))


def test_score_features_rejects_unexpected_redacted_value(tmp_path: Path) -> None:
    feature = replace(
        _feature(tmp_path, "CWE-284", "Controller.java"),
        redacted_value="n***a",
        has_redacted_value=True,
    )

    with pytest.raises(ValueError, match="does not accept redacted_value"):
        score_features((feature,))
