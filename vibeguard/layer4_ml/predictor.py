"""Layer 4 ML prediction over scored project findings.

Layer 4 does not re-detect vulnerabilities. It consumes Layer 3 scored
findings and turns their project-level combinations into a fixed feature
vector for a local ML classifier.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum
from statistics import mean
from typing import Any

from vibeguard.layer1_static.rules.cwe_284 import (
    CENTRALIZED_AUTH_CAVEAT,
    HAND_ROLLED_GUARD_CAVEAT,
)
from vibeguard.layer3_scoring import RiskSeverity, ScoredFinding

_CWE_IDS = ("CWE-20", "CWE-284", "CWE-287", "CWE-798", "CWE-1035")
_SOURCE_TYPES = ("java", "config", "pom")

# Whether any finding's message carries one of CWE-284's two caveat
# annotations - a project-wide centralized Spring Security rule, or a
# per-method hand-rolled header-comparison guard - that a human labeller
# can see but the rest of this feature vector cannot, since both caveats
# live only in Finding.message prose. A second, independent attempt at
# this exact signal: an earlier one (`has_unverified_guard_signal`,
# 2026-09-10) was built, measured, and reverted because it was a robust
# net *loss* on the dataset as it stood then (accuracy 0.580->0.420,
# macro-F1 0.498->0.413, "high" recall stuck at 0/10) - see
# IMPLEMENTATION_LOG.md. Re-tested here on the current, larger, keyword-
# widened 64-project dataset because the specific cluster motivating this
# retry (`unprotected-reports-service`/`ai-session-replay-service` vs.
# `ai-account-linking-service`/`ai-bulk-user-import-service`, tied 2-vs-2
# on every other feature) did not exist in that form at the time of the
# original attempt. This time it is a small, real, reproducible net gain
# (accuracy 30/64->31/64, macro-F1 0.4995->0.5156, "high" recall 6/13-
# >7/13, confirmed never worse across 6 tested random seeds) - but it is
# still not a clean signal: `ai-payment-webhooks-service` ("high")
# regresses because its one caveated finding reflects a genuinely well-
# implemented HMAC-signature guard on a *different* endpoint than the one
# actually driving its "high" label, which this project-level boolean
# cannot distinguish from "the guard covers the risk." Kept because the
# net effect across the full dataset is positive and stable, not because
# this per-project ambiguity has been resolved.
_CAVEAT_TEXTS = (CENTRALIZED_AUTH_CAVEAT, HAND_ROLLED_GUARD_CAVEAT)

# Coarse, name-based signal that a finding sits in a business-sensitive
# domain (payments, account/identity, admin) rather than general-purpose
# code - the same "match on names, not semantics" heuristic style already
# used throughout Layer 1's rules (e.g. CREDENTIAL_KEYWORDS), applied here
# at Layer 4 because none of Layer 4's other features carry any signal
# about *what* an endpoint is for. Found to matter concretely: scanning
# real AI-generated projects produced two with an identical Layer 4
# feature vector (2 CWE-284 findings, nothing else) but opposite labels -
# an unauthenticated payment-charge endpoint (critical) and a genuinely
# public product catalog (low) - because nothing in the feature vector
# encoded that distinction. See IMPLEMENTATION_LOG.md 2026-09-03.
# Matched against a finding's file path and identifier combined, case-
# insensitively, substring match - same coarse-match philosophy and same
# accepted imprecision as CREDENTIAL_KEYWORDS (e.g. "user" also matches
# an unrelated "houser"), not a semantic understanding of the endpoint.
_SENSITIVE_DOMAIN_KEYWORDS = frozenset(
    {
        "payment",
        "billing",
        "charge",
        "checkout",
        "invoice",
        "transaction",
        "wallet",
        "refund",
        "account",
        "user",
        "profile",
        "auth",
        "login",
        "signup",
        "register",
        "credential",
        "identity",
        "admin",
        "administrator",
        "staff",
        "internal",
        "management",
        # Added 2026-10-11, scanning the real dataset for high/critical
        # projects this signal was still missing entirely (zero overlap
        # with the keywords above) - see IMPLEMENTATION_LOG.md. Each one
        # is justified by at least one *pre-existing* (not newly-added)
        # high/critical project it newly catches, not reverse-engineered
        # from any one project's label: "session" (leaky-session-service,
        # critical), "subscription" (ai-billing-service, critical -
        # "billing" alone doesn't match a project literally named
        # SubscriptionController), "employee" (ai-employee-profile-service,
        # high), "consent" (ai-user-consent-service, high), "recovery"
        # (ai-account-recovery-service, critical), "report"
        # (unprotected-reports-service and ai-admin-report-export-service,
        # both high), "export" (ai-user-export-service, critical).
        # Deliberately not exhaustive: generic-sounding project names
        # like "gateway"/"intake"/"widget" that also carry a high/critical
        # label were left unmatched on purpose - those look like
        # deliberately generic placeholders testing that severity
        # detection doesn't just key off scary-sounding names, and
        # "fixing" them would defeat that test's own point.
        "session",
        "subscription",
        "employee",
        "consent",
        "recovery",
        "report",
        "export",
    }
)


class MLRiskLabel(str, Enum):
    """Risk labels predicted by Layer 4."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class ProjectFeatures:
    """Fixed project-level feature vector for Layer 4 ML."""

    names: tuple[str, ...]
    values: tuple[float, ...]


@dataclass(frozen=True)
class MLPrediction:
    """Layer 4 prediction for one scanned project."""

    label: MLRiskLabel
    confidence: float
    features: ProjectFeatures


@dataclass(frozen=True)
class RiskModel:
    """A trained local ML model plus the feature schema it expects."""

    classifier: Any
    feature_names: tuple[str, ...]


def predict_project_risk(model: RiskModel, findings: Iterable[ScoredFinding]) -> MLPrediction:
    """Predict a project-level risk label from Layer 3 scored findings.

    Args:
        model: Model returned by Layer 4 training.
        findings: Scored findings for one project.

    Returns:
        A project-level ML label and confidence.

    Raises:
        ValueError: If the model schema does not match the current
            feature extractor. This fails closed rather than making a
            prediction with shifted columns.
    """
    features = build_project_features(findings)
    if model.feature_names != features.names:
        raise ValueError("model feature schema does not match current Layer 4 schema")

    probabilities = model.classifier.predict_proba([features.values])[0]
    classes = tuple(str(label) for label in model.classifier.classes_)
    best_index = max(range(len(probabilities)), key=lambda index: probabilities[index])
    return MLPrediction(
        label=MLRiskLabel(classes[best_index]),
        confidence=float(probabilities[best_index]),
        features=features,
    )


def build_project_features(findings: Iterable[ScoredFinding]) -> ProjectFeatures:
    """Convert scored findings into a deterministic project-level vector."""
    items = tuple(findings)
    names = _feature_names()
    if not items:
        return ProjectFeatures(names=names, values=tuple(0.0 for _ in names))

    scores = tuple(float(item.score) for item in items)
    cwe_counts = _counts_by_cwe(items)
    source_counts = _counts_by_source(items)
    severity_counts = _counts_by_severity(items)
    values = (
        float(len(items)),
        max(scores),
        mean(scores),
        float(severity_counts[RiskSeverity.CRITICAL]),
        float(severity_counts[RiskSeverity.HIGH]),
        float(severity_counts[RiskSeverity.MEDIUM]),
        float(severity_counts[RiskSeverity.LOW]),
        *(float(cwe_counts[cwe_id]) for cwe_id in _CWE_IDS),
        *(float(source_counts[source_type]) for source_type in _SOURCE_TYPES),
        float(sum(1 for item in items if not item.feature.has_line)),
        _has_cwe_pair(items, "CWE-284", "CWE-20"),
        _has_cwe_pair(items, "CWE-798", "CWE-284"),
        _has_cwe_pair(items, "CWE-798", "CWE-287"),
        _has_cwe_pair(items, "CWE-798", "CWE-1035"),
        _has_same_file_pair(items, "CWE-284", "CWE-20"),
        _has_same_file_pair(items, "CWE-798", "CWE-284"),
        _has_sensitive_domain_signal(items),
        _has_guard_caveat_signal(items),
    )
    return ProjectFeatures(names=names, values=values)


def _feature_names() -> tuple[str, ...]:
    return (
        "finding_count",
        "max_rule_score",
        "mean_rule_score",
        "critical_count",
        "high_count",
        "medium_count",
        "low_count",
        *(f"{cwe_id.lower().replace('-', '_')}_count" for cwe_id in _CWE_IDS),
        *(f"{source_type}_source_count" for source_type in _SOURCE_TYPES),
        "missing_line_count",
        "has_access_control_and_input_validation",
        "has_secret_and_access_control",
        "has_secret_and_authentication",
        "has_secret_and_vulnerable_dependency",
        "same_file_access_control_and_input_validation",
        "same_file_secret_and_access_control",
        "has_sensitive_domain_signal",
        "has_guard_caveat_signal",
    )


def _counts_by_cwe(findings: tuple[ScoredFinding, ...]) -> dict[str, int]:
    return {
        cwe_id: sum(1 for item in findings if item.feature.cwe_id == cwe_id) for cwe_id in _CWE_IDS
    }


def _counts_by_source(findings: tuple[ScoredFinding, ...]) -> dict[str, int]:
    return {
        source_type: sum(1 for item in findings if item.feature.source_type == source_type)
        for source_type in _SOURCE_TYPES
    }


def _counts_by_severity(findings: tuple[ScoredFinding, ...]) -> dict[RiskSeverity, int]:
    return {
        severity: sum(1 for item in findings if item.severity is severity)
        for severity in RiskSeverity
    }


def _has_cwe_pair(findings: tuple[ScoredFinding, ...], first: str, second: str) -> float:
    cwes = {item.feature.cwe_id for item in findings}
    return 1.0 if first in cwes and second in cwes else 0.0


def _has_same_file_pair(findings: tuple[ScoredFinding, ...], first: str, second: str) -> float:
    by_file: dict[str, set[str]] = {}
    for item in findings:
        by_file.setdefault(str(item.feature.file_path), set()).add(item.feature.cwe_id)
    return 1.0 if any(first in cwes and second in cwes for cwes in by_file.values()) else 0.0


def _has_sensitive_domain_signal(findings: tuple[ScoredFinding, ...]) -> float:
    """Whether any finding's file name or identifier names a sensitive domain.

    Deliberately matches only the file's own *name* (e.g.
    "PaymentController.java"), never the full path: FindingFeature.file_path
    is a resolved absolute path, and matching against it leaks whatever
    happens to be in the local checkout location - e.g. this exact bug was
    caught in review, where "/Users/<name>/..." made every single project
    on this machine match "user" regardless of its actual code, the same
    portability failure mode that got path_depth removed from Layer 2 on
    2026-07-21. Scoped to the file name specifically for the same reason.
    """
    for item in findings:
        haystack = f"{item.feature.file_path.name} {item.feature.identifier}".lower()
        if any(keyword in haystack for keyword in _SENSITIVE_DOMAIN_KEYWORDS):
            return 1.0
    return 0.0


def _has_guard_caveat_signal(findings: tuple[ScoredFinding, ...]) -> float:
    """Whether any finding's message carries a CWE-284 caveat annotation.

    Matches on the literal caveat constants (not a guessed substring),
    the same two annotations `cwe_284.py` already appends to a finding's
    message when it detects a project-wide centralized Spring Security
    rule or a per-method hand-rolled header-comparison guard that its own
    rule logic cannot verify. See the module-level comment on
    `_CAVEAT_TEXTS` for why this signal is real but not clean.
    """
    for item in findings:
        if any(caveat in item.feature.message for caveat in _CAVEAT_TEXTS):
            return 1.0
    return 0.0
