"""Tests for vibeguard.layer1_static.rules.cwe_1035."""

from __future__ import annotations

from pathlib import Path

from vibeguard.layer1_static.gradle_parser import parse_gradle_file
from vibeguard.layer1_static.pom_parser import parse_pom_file
from vibeguard.layer1_static.rules.cwe_1035 import CWE_ID, detect_in_gradle, detect_in_pom

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_detect_in_pom_finds_known_vulnerable_dependency() -> None:
    parsed = parse_pom_file(FIXTURES_DIR / "vulnerable-pom.xml")

    findings = detect_in_pom(parsed)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.cwe_id == CWE_ID
    assert finding.identifier == "org.apache.logging.log4j:log4j-core"
    assert finding.line == 16
    assert "CVE-2021-44228" in finding.message


def test_detect_in_pom_does_not_flag_patched_version() -> None:
    parsed = parse_pom_file(FIXTURES_DIR / "vulnerable-pom.xml")

    identifiers = {f.identifier for f in detect_in_pom(parsed)}

    assert "com.fasterxml.jackson.core:jackson-databind" not in identifiers


def test_detect_in_pom_does_not_flag_dependency_outside_the_curated_database() -> None:
    parsed = parse_pom_file(FIXTURES_DIR / "vulnerable-pom.xml")

    identifiers = {f.identifier for f in detect_in_pom(parsed)}

    assert "junit:junit" not in identifiers


def test_detect_in_pom_does_not_flag_unresolvable_version() -> None:
    """A version we couldn't resolve is "unknown," never treated as vulnerable."""
    parsed = parse_pom_file(FIXTURES_DIR / "vulnerable-pom.xml")

    identifiers = {f.identifier for f in detect_in_pom(parsed)}

    assert "org.yaml:snakeyaml" not in identifiers


def test_detect_in_pom_does_not_flag_version_missing_trailing_zero_segment(
    tmp_path: Path,
) -> None:
    """ "2.15" and "2.15.0" are the same version.

    Naive tuple comparison would treat "2.15" as less than "2.15.0"
    (a shorter tuple that's a prefix of a longer one), wrongly flagging
    the fixed version as vulnerable - found by testing this specific
    case before shipping.
    """
    pom_file = tmp_path / "pom.xml"
    pom_file.write_text(
        "<project>\n"
        "  <dependencies>\n"
        "    <dependency>\n"
        "      <groupId>com.fasterxml.jackson.core</groupId>\n"
        "      <artifactId>jackson-databind</artifactId>\n"
        "      <version>2.15</version>\n"
        "    </dependency>\n"
        "  </dependencies>\n"
        "</project>\n"
    )

    parsed = parse_pom_file(pom_file)

    assert detect_in_pom(parsed) == ()


def test_detect_in_pom_flags_the_exact_fixed_version_minus_one_patch(
    tmp_path: Path,
) -> None:
    pom_file = tmp_path / "pom.xml"
    pom_file.write_text(
        "<project>\n"
        "  <dependencies>\n"
        "    <dependency>\n"
        "      <groupId>org.yaml</groupId>\n"
        "      <artifactId>snakeyaml</artifactId>\n"
        "      <version>1.33</version>\n"
        "    </dependency>\n"
        "  </dependencies>\n"
        "</project>\n"
    )

    parsed = parse_pom_file(pom_file)

    findings = detect_in_pom(parsed)
    assert len(findings) == 1
    assert findings[0].identifier == "org.yaml:snakeyaml"


def test_detect_in_pom_finds_nothing_when_pom_has_no_dependencies(tmp_path: Path) -> None:
    pom_file = tmp_path / "pom.xml"
    pom_file.write_text("<project></project>\n")

    parsed = parse_pom_file(pom_file)

    assert detect_in_pom(parsed) == ()


def test_detect_in_pom_handles_malformed_pom_gracefully(tmp_path: Path) -> None:
    pom_file = tmp_path / "pom.xml"
    pom_file.write_text("<project><dependencies>\n")

    parsed = parse_pom_file(pom_file)

    assert parsed.dependencies == ()
    assert detect_in_pom(parsed) == ()


def test_detect_in_gradle_finds_known_vulnerable_dependency(tmp_path: Path) -> None:
    gradle_file = tmp_path / "build.gradle"
    gradle_file.write_text(
        "dependencies {\n" '    implementation "org.apache.logging.log4j:log4j-core:2.14.1"\n' "}\n"
    )
    parsed = parse_gradle_file(gradle_file)

    findings = detect_in_gradle(parsed)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.cwe_id == CWE_ID
    assert finding.identifier == "org.apache.logging.log4j:log4j-core"
    assert finding.line == 2
    assert "CVE-2021-44228" in finding.message


def test_detect_in_gradle_does_not_flag_patched_version(tmp_path: Path) -> None:
    gradle_file = tmp_path / "build.gradle"
    gradle_file.write_text(
        'dependencies {\n    implementation "org.apache.logging.log4j:log4j-core:2.17.1"\n}\n'
    )
    parsed = parse_gradle_file(gradle_file)

    assert detect_in_gradle(parsed) == ()


def test_detect_in_gradle_does_not_flag_an_unresolved_interpolated_version(
    tmp_path: Path,
) -> None:
    """A variable-interpolated version is "unknown," never treated as
    vulnerable - the same discipline as an unresolved Maven property."""
    gradle_file = tmp_path / "build.gradle"
    gradle_file.write_text(
        "dependencies {\n"
        '    implementation "org.apache.logging.log4j:log4j-core:$log4jVersion"\n'
        "}\n"
    )
    parsed = parse_gradle_file(gradle_file)

    assert detect_in_gradle(parsed) == ()


def test_detect_in_gradle_finds_nothing_when_build_file_has_no_dependencies(
    tmp_path: Path,
) -> None:
    gradle_file = tmp_path / "build.gradle"
    gradle_file.write_text("plugins {\n    id 'java'\n}\n")
    parsed = parse_gradle_file(gradle_file)

    assert detect_in_gradle(parsed) == ()
