"""Layer 3: rule-based scoring.

Combines Layer 1 findings and Layer 2 features into a deterministic,
explainable rule-based risk score per finding.
"""

from vibeguard.layer3_scoring.scorer import RiskSeverity, ScoredFinding, score_features

__all__ = ["RiskSeverity", "ScoredFinding", "score_features"]
