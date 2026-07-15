"""CWE-1035: Using Components with Known Vulnerabilities.

Cross-references Maven dependencies (via ``pom_parser.py``) against a
small, curated, offline snapshot of well-known, publicly-documented
Java library CVEs. Deliberately **not** a live lookup against
OSV.dev/NVD/etc.: CLAUDE.md's non-negotiable constraint is "runs
entirely locally... no external API calls for core scanning" - a
network call on every scan to check every dependency would put an
external dependency directly in the core scanning path, which is a
materially different thing from the one-off, manually-run `safety`
dependency audit this project's own tooling gets (see
IMPLEMENTATION_LOG.md). The tradeoff is real and stated plainly: this
rule can only ever be as current as `_KNOWN_VULNERABILITIES` below,
not a live feed. That is the honest, defensible scope for this rule,
not a claim of comprehensive coverage.

Each entry flags a dependency as vulnerable if its resolved version is
strictly less than the entry's ``fixed_version`` - the simplest, most
common way real advisories are phrased ("upgrade to X or later"), not
a full Maven/semver version-range engine. A dependency whose version
couldn't be resolved (``MavenDependency.version is None``, e.g. an
unresolvable property reference) is never flagged - "unknown" is not
"safe," but it is also not evidence of a vulnerability, so this rule
stays silent rather than guessing either way.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from vibeguard.layer1_static.pom_parser import MavenDependency, ParsedPomFile
from vibeguard.layer1_static.rules._finding import Finding

CWE_ID = "CWE-1035"


@dataclass(frozen=True)
class _KnownVulnerability:
    """One curated, offline CVE record for a specific Maven artifact."""

    group_id: str
    artifact_id: str
    cve_id: str
    fixed_version: str
    description: str


# A small, deliberately curated set of well-known, widely-documented
# Java library CVEs - not a comprehensive database. Each is real and
# independently verifiable (CVE IDs are public record), chosen for
# being unambiguous, high-profile, and illustrative rather than for
# breadth.
_KNOWN_VULNERABILITIES = (
    _KnownVulnerability(
        group_id="org.apache.logging.log4j",
        artifact_id="log4j-core",
        cve_id="CVE-2021-44228",
        fixed_version="2.15.0",
        description=(
            "Log4Shell: unauthenticated remote code execution via JNDI lookup in log messages"
        ),
    ),
    _KnownVulnerability(
        group_id="com.fasterxml.jackson.core",
        artifact_id="jackson-databind",
        cve_id="CVE-2019-12384",
        fixed_version="2.9.9",
        description="Polymorphic deserialization remote code execution via crafted JSON",
    ),
    _KnownVulnerability(
        group_id="commons-collections",
        artifact_id="commons-collections",
        cve_id="CVE-2015-4852",
        fixed_version="3.2.2",
        description=(
            "Unsafe deserialization enabling remote code execution "
            "(basis of widely-used gadget chains)"
        ),
    ),
    _KnownVulnerability(
        group_id="org.yaml",
        artifact_id="snakeyaml",
        cve_id="CVE-2022-1471",
        fixed_version="2.0",
        description="Unsafe deserialization of YAML input allowing remote code execution",
    ),
)

_VERSION_PREFIX_PATTERN = re.compile(r"^[\d.]+")


def detect_in_pom(parsed_pom: ParsedPomFile) -> tuple[Finding, ...]:
    """Find declared Maven dependencies matching a known-vulnerable version."""
    findings = []
    for dependency in parsed_pom.dependencies:
        finding = _check_dependency(parsed_pom.path, dependency)
        if finding is not None:
            findings.append(finding)
    return tuple(findings)


def _check_dependency(file_path: Path, dependency: MavenDependency) -> Finding | None:
    if dependency.version is None:
        return None
    vulnerability = _matching_vulnerability(dependency)
    if vulnerability is None:
        return None
    return Finding(
        cwe_id=CWE_ID,
        file_path=file_path,
        line=dependency.line,
        identifier=f"{dependency.group_id}:{dependency.artifact_id}",
        message=(
            f"{dependency.group_id}:{dependency.artifact_id}:{dependency.version} "
            f"matches {vulnerability.cve_id} ({vulnerability.description}) - "
            f"fix: upgrade to {vulnerability.fixed_version} or later"
        ),
    )


def _matching_vulnerability(dependency: MavenDependency) -> _KnownVulnerability | None:
    for vulnerability in _KNOWN_VULNERABILITIES:
        if (
            vulnerability.group_id == dependency.group_id
            and vulnerability.artifact_id == dependency.artifact_id
            and dependency.version is not None
            and _version_less_than(dependency.version, vulnerability.fixed_version)
        ):
            return vulnerability
    return None


def _parse_version(version: str) -> tuple[int, ...]:
    """Parse a version's leading dotted-numeric prefix for comparison.

    Simplified relative to a full Maven/semver version-range engine:
    "2.14.1" -> (2, 14, 1); "2.0-beta9" -> (2, 0) (the "-beta9"
    qualifier is dropped, not compared); "1.2.17.RELEASE" -> (1, 2, 17)
    (the trailing non-numeric segment is dropped). Good enough to
    compare typical Maven artifact versions against this rule's small
    curated set of fixed-version thresholds.
    """
    match = _VERSION_PREFIX_PATTERN.match(version)
    numeric_prefix = match.group(0) if match else ""
    return tuple(int(segment) for segment in numeric_prefix.split(".") if segment.isdigit())


def _version_less_than(candidate: str, threshold: str) -> bool:
    """Compare two versions, padding the shorter to equal length first.

    Plain tuple comparison would treat "2.15" as less than "2.15.0"
    (a shorter tuple that's a prefix of a longer one compares as
    "less" in Python) even though they're the same version with an
    omitted trailing zero segment - a real false-positive source,
    found by testing this specifically before shipping. Padding both
    to equal length with trailing zeros first makes them compare equal
    instead.
    """
    candidate_segments = _parse_version(candidate)
    threshold_segments = _parse_version(threshold)
    length = max(len(candidate_segments), len(threshold_segments))
    padded_candidate = candidate_segments + (0,) * (length - len(candidate_segments))
    padded_threshold = threshold_segments + (0,) * (length - len(threshold_segments))
    return padded_candidate < padded_threshold
