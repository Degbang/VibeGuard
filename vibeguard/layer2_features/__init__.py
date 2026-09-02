"""Layer 2: feature extraction.

Converts Layer 1 findings and parsed AST context into structured
numeric/categorical features consumed by Layer 3 scoring and Layer 4 ML.
"""

from vibeguard.layer2_features.extractor import FindingFeature, extract_features

__all__ = ["FindingFeature", "extract_features"]
