"""Tests for vibeguard.layer1_static.config_parser."""

from __future__ import annotations

import time
from pathlib import Path

from vibeguard.layer1_static.config_parser import (
    ConfigFileFormat,
    ParseStatus,
    parse_config_file,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_parse_properties_extracts_flattened_entries() -> None:
    result = parse_config_file(FIXTURES_DIR / "application.properties")

    assert result.status == ParseStatus.OK
    assert result.format == ConfigFileFormat.PROPERTIES
    entries_by_key = {entry.key: entry for entry in result.entries}
    assert entries_by_key["quarkus.datasource.password"].value == "hunter2"
    assert entries_by_key["quarkus.datasource.password"].line == 4
    assert entries_by_key["quarkus.http.port"].value == "8080"


def test_parse_yaml_extracts_same_flattened_shape_as_properties() -> None:
    yaml_result = parse_config_file(FIXTURES_DIR / "application.yml")
    properties_result = parse_config_file(FIXTURES_DIR / "application.properties")

    yaml_keys = {entry.key: entry.value for entry in yaml_result.entries}
    properties_keys = {entry.key: entry.value for entry in properties_result.entries}

    assert yaml_result.status == ParseStatus.OK
    assert yaml_result.format == ConfigFileFormat.YAML
    assert yaml_keys == properties_keys


def test_parse_yaml_line_numbers_point_at_the_value() -> None:
    result = parse_config_file(FIXTURES_DIR / "application.yml")
    entries_by_key = {entry.key: entry for entry in result.entries}

    assert entries_by_key["quarkus.datasource.password"].line == 6


def test_parse_malformed_yaml_reports_failure_not_exception() -> None:
    result = parse_config_file(FIXTURES_DIR / "malformed.yml")

    assert result.status == ParseStatus.PARSE_FAILED
    assert result.error_message
    assert result.entries == ()


def test_parse_empty_properties_file() -> None:
    result = parse_config_file(FIXTURES_DIR / "empty.properties")

    assert result.status == ParseStatus.EMPTY_FILE
    assert result.entries == ()


def test_unsupported_extension_is_reported_not_skipped_silently(tmp_path: Path) -> None:
    unsupported = tmp_path / "notes.txt"
    unsupported.write_text("hello")

    result = parse_config_file(unsupported)

    assert result.status == ParseStatus.UNSUPPORTED_FORMAT


def test_missing_file_does_not_raise(tmp_path: Path) -> None:
    result = parse_config_file(tmp_path / "does-not-exist.properties")

    assert result.status == ParseStatus.PARSE_FAILED
    assert result.error_message


def test_file_too_large_is_rejected(tmp_path: Path) -> None:
    big_file = tmp_path / "big.properties"
    big_file.write_text("key=value\n" * 100)

    result = parse_config_file(big_file, max_bytes=10)

    assert result.status == ParseStatus.FILE_TOO_LARGE


def test_properties_supports_comments_and_line_continuation(tmp_path: Path) -> None:
    props_file = tmp_path / "continuation.properties"
    props_file.write_text(
        "# a comment\n"
        "! also a comment\n"
        "\n"
        "db.url=jdbc:postgresql://localhost/db\\\n"
        "?sslmode=require\n"
    )

    result = parse_config_file(props_file)

    assert result.status == ParseStatus.OK
    entries_by_key = {entry.key: entry.value for entry in result.entries}
    assert entries_by_key["db.url"] == "jdbc:postgresql://localhost/db?sslmode=require"


def test_properties_continuation_handles_odd_backslash_runs(tmp_path: Path) -> None:
    """An odd trailing-backslash count (3, 5, ...) must still continue.

    A naive ``endswith("\\") and not endswith("\\\\")`` check only
    distinguishes 0/1/2 trailing backslashes correctly; 3 trailing
    backslashes end in "\\\\" too, so that check wrongly treats it as
    a complete line. Per the java.util.Properties spec, an odd count
    always continues (one marker backslash, the rest literal).
    """
    props_file = tmp_path / "odd_backslashes.properties"
    props_file.write_text("key=value\\\\\\\nmore\n")

    result = parse_config_file(props_file)

    assert result.status == ParseStatus.OK
    entries_by_key = {entry.key: entry.value for entry in result.entries}
    assert entries_by_key["key"] == "value\\\\more"


def test_properties_continuation_even_backslashes_do_not_continue(tmp_path: Path) -> None:
    props_file = tmp_path / "even_backslashes.properties"
    props_file.write_text("key=value\\\\\nnext=separate\n")

    result = parse_config_file(props_file)

    assert result.status == ParseStatus.OK
    entries_by_key = {entry.key: entry.value for entry in result.entries}
    assert entries_by_key["key"] == "value\\\\"
    assert entries_by_key["next"] == "separate"


def test_parse_self_referential_yaml_alias_reports_failure_not_crash(tmp_path: Path) -> None:
    """A self-referential alias must not crash the scan.

    It blows the Python recursion limit in our recursive flattener
    (PyYAML itself composes the cyclic node graph fine, since aliases
    just share object references - only our traversal recurses into
    the cycle). Must come back as PARSE_FAILED, not an escaped
    RecursionError that would abort a batch scan.
    """
    bomb_file = tmp_path / "self_referential.yml"
    bomb_file.write_text("a: &a [*a]\n")

    result = parse_config_file(bomb_file)

    assert result.status == ParseStatus.PARSE_FAILED
    assert result.error_message


def test_yaml_alias_expansion_bomb_times_out_instead_of_hanging(tmp_path: Path) -> None:
    """A known YAML DoS pattern (anchor/alias 'billion laughs' expansion).

    PyYAML's own node composition is cheap (aliases share object
    references), but naive recursive flattening of that shared graph is
    exponential. This proves the soft-timeout guard around flattening
    catches it: the caller gets control back promptly instead of hanging,
    even though the underlying background thread is left to run its
    course (documented limitation, same as ast_parser.py's timeout).
    """
    payload = 'a0: &a0 ["x","x","x","x","x","x","x","x","x"]\n'
    for i in range(1, 9):
        payload += (
            f"a{i}: &a{i} "
            f"[*a{i - 1},*a{i - 1},*a{i - 1},*a{i - 1},*a{i - 1},"
            f"*a{i - 1},*a{i - 1},*a{i - 1},*a{i - 1}]\n"
        )
    bomb_file = tmp_path / "bomb.yml"
    bomb_file.write_text(payload)

    start = time.monotonic()
    result = parse_config_file(bomb_file, timeout_seconds=1.0)
    elapsed = time.monotonic() - start

    assert result.status == ParseStatus.PARSE_TIMEOUT
    assert elapsed < 5.0
