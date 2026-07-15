"""Tests for vibeguard.layer1_static.pom_parser."""

from __future__ import annotations

import time
from pathlib import Path

from vibeguard.layer1_static._parsing_guards import ParseStatus
from vibeguard.layer1_static.pom_parser import parse_pom_file

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_parse_extracts_dependencies_with_resolved_property_version() -> None:
    result = parse_pom_file(FIXTURES_DIR / "vulnerable-pom.xml")

    assert result.status == ParseStatus.OK
    deps_by_artifact = {d.artifact_id: d for d in result.dependencies}

    log4j = deps_by_artifact["log4j-core"]
    assert log4j.group_id == "org.apache.logging.log4j"
    assert log4j.version == "2.14.1"
    assert log4j.raw_version == "${log4j.version}"
    assert log4j.line == 16


def test_parse_direct_version_is_used_as_is() -> None:
    result = parse_pom_file(FIXTURES_DIR / "vulnerable-pom.xml")
    deps_by_artifact = {d.artifact_id: d for d in result.dependencies}

    jackson = deps_by_artifact["jackson-databind"]
    assert jackson.version == "2.15.0"
    assert jackson.raw_version == "2.15.0"


def test_parse_unresolvable_property_yields_none_version_not_a_guess() -> None:
    """A property not found locally (e.g. from an inaccessible parent POM)

    must resolve to None, never a guessed or default value.
    """
    result = parse_pom_file(FIXTURES_DIR / "vulnerable-pom.xml")
    deps_by_artifact = {d.artifact_id: d for d in result.dependencies}

    snakeyaml = deps_by_artifact["snakeyaml"]
    assert snakeyaml.version is None
    assert snakeyaml.raw_version == "${snakeyaml.version}"


def test_parse_handles_pom_without_namespace_declaration(tmp_path: Path) -> None:
    """Not every real-world pom.xml declares the Maven namespace explicitly."""
    pom_file = tmp_path / "pom.xml"
    pom_file.write_text(
        "<project>\n"
        "  <dependencies>\n"
        "    <dependency>\n"
        "      <groupId>junit</groupId>\n"
        "      <artifactId>junit</artifactId>\n"
        "      <version>4.13.2</version>\n"
        "    </dependency>\n"
        "  </dependencies>\n"
        "</project>\n"
    )

    result = parse_pom_file(pom_file)

    assert result.status == ParseStatus.OK
    assert len(result.dependencies) == 1
    assert result.dependencies[0].artifact_id == "junit"


def test_parse_malformed_xml_reports_failure_not_exception(tmp_path: Path) -> None:
    pom_file = tmp_path / "pom.xml"
    pom_file.write_text("<project><dependencies><dependency>\n")

    result = parse_pom_file(pom_file)

    assert result.status == ParseStatus.PARSE_FAILED
    assert result.error_message
    assert result.dependencies == ()


def test_parse_empty_file(tmp_path: Path) -> None:
    pom_file = tmp_path / "pom.xml"
    pom_file.write_text("")

    result = parse_pom_file(pom_file)

    assert result.status == ParseStatus.EMPTY_FILE


def test_parse_missing_file_does_not_raise(tmp_path: Path) -> None:
    result = parse_pom_file(tmp_path / "does-not-exist" / "pom.xml")

    assert result.status == ParseStatus.PARSE_FAILED
    assert result.error_message


def test_parse_file_too_large_is_rejected(tmp_path: Path) -> None:
    pom_file = tmp_path / "pom.xml"
    pom_file.write_text("<project></project>\n" * 100)

    result = parse_pom_file(pom_file, max_bytes=10)

    assert result.status == ParseStatus.FILE_TOO_LARGE


def test_parse_ignores_dependency_management_entries(tmp_path: Path) -> None:
    """Only direct <dependencies>, not <dependencyManagement>, are extracted."""
    pom_file = tmp_path / "pom.xml"
    pom_file.write_text(
        "<project>\n"
        "  <dependencyManagement>\n"
        "    <dependencies>\n"
        "      <dependency>\n"
        "        <groupId>com.example</groupId>\n"
        "        <artifactId>managed-only</artifactId>\n"
        "        <version>1.0.0</version>\n"
        "      </dependency>\n"
        "    </dependencies>\n"
        "  </dependencyManagement>\n"
        "  <dependencies>\n"
        "    <dependency>\n"
        "      <groupId>com.example</groupId>\n"
        "      <artifactId>actually-used</artifactId>\n"
        "      <version>1.0.0</version>\n"
        "    </dependency>\n"
        "  </dependencies>\n"
        "</project>\n"
    )

    result = parse_pom_file(pom_file)

    artifact_ids = {d.artifact_id for d in result.dependencies}
    assert artifact_ids == {"actually-used"}


def test_parse_rejects_entity_expansion_bomb_instead_of_hanging(tmp_path: Path) -> None:
    """A 'billion laughs'-style entity expansion payload must fail closed.

    Verified empirically that CPython's bundled expat parser already
    rejects this with a ParseError rather than hanging or consuming
    excessive memory (a native protection since Python 3.7.1) - this
    test locks that behavior in as a permanent regression check.
    """
    entities = '<!ENTITY lol0 "lol">\n'
    for i in range(1, 10):
        refs = ("&lol" + str(i - 1) + ";") * 10
        entities += f'<!ENTITY lol{i} "{refs}">\n'
    payload = f"<?xml version='1.0'?>\n<!DOCTYPE lolz [\n{entities}]>\n<lolz>&lol9;</lolz>"
    pom_file = tmp_path / "pom.xml"
    pom_file.write_text(payload)

    start = time.monotonic()
    result = parse_pom_file(pom_file)
    elapsed = time.monotonic() - start

    assert result.status == ParseStatus.PARSE_FAILED
    assert elapsed < 5.0


def test_parse_does_not_resolve_external_entities(tmp_path: Path) -> None:
    """XXE (reading local files via an external entity) must not succeed."""
    pom_file = tmp_path / "pom.xml"
    pom_file.write_text(
        '<?xml version="1.0"?>\n'
        "<!DOCTYPE root [\n"
        '  <!ENTITY xxe SYSTEM "file:///etc/passwd">\n'
        "]>\n"
        "<root>&xxe;</root>\n"
    )

    result = parse_pom_file(pom_file)

    assert result.status == ParseStatus.PARSE_FAILED
