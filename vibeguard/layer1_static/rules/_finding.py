"""Shared detection-result shape for Layer 1 CWE rule modules.

Extracted out of ``cwe_798.py`` once a second rule module (``cwe_284.py``)
needed the same shape - see IMPLEMENTATION_LOG.md. Every rule module
returns a tuple of these, so Layer 3 (rule-based scoring) and Layer 5
(reporting) can consume any rule's output uniformly without knowing
which specific CWE produced it.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Finding:
    """A single rule-module detection, before scoring/explanation.

    A rule module only decides *candidacy* here, not severity - that's
    Layer 3's job. ``redacted_value`` is optional: it exists for rules
    like CWE-798 that revolve around a literal value (which must never
    be included verbatim - a security tool that echoes real secrets
    back into its own report output would itself become a disclosure
    risk), but doesn't apply to every CWE (e.g. a missing-annotation
    finding for CWE-284 has no "value" to redact).
    """

    cwe_id: str
    file_path: Path
    line: int | None
    identifier: str
    message: str
    redacted_value: str | None = None
