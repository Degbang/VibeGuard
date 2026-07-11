"""Layer 1 config-file parsing: flattens .properties/.yml key-value pairs.

``javalang`` (used by ``ast_parser.py``) can only parse Java source; it
cannot parse ``application.properties``/``application.yml``. In
Quarkus/Spring projects, hardcoded credentials targeted by CWE-798 are at
least as likely to live in these config files as in ``.java`` source, so
this module gives CWE rule modules a second, format-appropriate input
alongside the Java AST. It only ever parses text into key-value pairs -
it never executes anything from the file, and YAML is parsed with
``SafeLoader`` (no arbitrary Python object construction).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path

import yaml

from vibeguard.layer1_static._parsing_guards import (
    ParsingGuardError,
    read_text_within_limit,
    run_with_timeout,
)

DEFAULT_MAX_FILE_BYTES = 2_000_000
DEFAULT_PARSE_TIMEOUT_SECONDS = 5.0

_PROPERTIES_SUFFIXES = frozenset({".properties"})
_YAML_SUFFIXES = frozenset({".yml", ".yaml"})


class ConfigParseStatus(str, Enum):
    """Outcome of attempting to parse a single config file.

    Mirrors ``ast_parser.ParseStatus`` so callers can treat both
    parsers' results uniformly: every outcome is explicit, none are
    silently dropped.
    """

    OK = "ok"
    EMPTY_FILE = "empty_file"
    FILE_TOO_LARGE = "file_too_large"
    PARSE_TIMEOUT = "parse_timeout"
    PARSE_FAILED = "parse_failed"
    UNSUPPORTED_FORMAT = "unsupported_format"


class ConfigFileFormat(str, Enum):
    """Which config syntax a file was parsed as."""

    PROPERTIES = "properties"
    YAML = "yaml"


@dataclass(frozen=True)
class ConfigEntry:
    """A single flattened key-value pair from a config file.

    ``key`` is dotted for nested YAML structures (e.g.
    ``quarkus.datasource.password``) so both formats present a uniform
    shape to CWE rule modules regardless of source syntax.
    """

    key: str
    value: str
    line: int | None


@dataclass(frozen=True)
class ParsedConfigFile:
    """Structured result of parsing one config file."""

    path: Path
    status: ConfigParseStatus
    format: ConfigFileFormat | None = None
    entries: tuple[ConfigEntry, ...] = ()
    error_message: str | None = None


def parse_config_file(
    path: Path,
    *,
    max_bytes: int = DEFAULT_MAX_FILE_BYTES,
    timeout_seconds: float = DEFAULT_PARSE_TIMEOUT_SECONDS,
) -> ParsedConfigFile:
    """Parse a single ``.properties``/``.yml``/``.yaml`` file.

    Args:
        path: Path to the config file. As with ``ast_parser.parse_file``,
            the caller is responsible for resolving and validating this
            path lies inside the expected sample-apps root.
        max_bytes: Reject files larger than this to bound memory.
        timeout_seconds: Soft wall-clock budget for YAML parsing, which
            (unlike simple key=value parsing) is vulnerable to
            anchor/alias expansion ("billion laughs") denial of service
            even from a small file.

    Returns:
        A ParsedConfigFile whose ``status`` reflects exactly what
        happened; every failure mode is a value, never an exception, so
        one bad config file can never abort a batch scan.
    """
    resolved = path.resolve()
    file_format = _detect_format(resolved)
    if file_format is None:
        return ParsedConfigFile(path=resolved, status=ConfigParseStatus.UNSUPPORTED_FORMAT)

    try:
        text = read_text_within_limit(resolved, max_bytes)
    except ParsingGuardError as exc:
        status = (
            ConfigParseStatus.FILE_TOO_LARGE if exc.too_large else ConfigParseStatus.PARSE_FAILED
        )
        return ParsedConfigFile(path=resolved, status=status, error_message=str(exc))

    if not text.strip():
        return ParsedConfigFile(
            path=resolved, status=ConfigParseStatus.EMPTY_FILE, format=file_format
        )

    if file_format is ConfigFileFormat.PROPERTIES:
        entries = _parse_properties(text)
        return ParsedConfigFile(
            path=resolved, status=ConfigParseStatus.OK, format=file_format, entries=entries
        )

    return _parse_yaml_file(resolved, text, timeout_seconds)


def _detect_format(path: Path) -> ConfigFileFormat | None:
    """Map a file's suffix to the format we know how to parse, if any."""
    suffix = path.suffix.lower()
    if suffix in _PROPERTIES_SUFFIXES:
        return ConfigFileFormat.PROPERTIES
    if suffix in _YAML_SUFFIXES:
        return ConfigFileFormat.YAML
    return None


def _parse_yaml_file(path: Path, text: str, timeout_seconds: float) -> ParsedConfigFile:
    """Run PyYAML (via a soft timeout) over ``text`` and flatten the result."""
    try:
        entries = run_with_timeout(_flatten_yaml_text, text, timeout_seconds=timeout_seconds)
    except TimeoutError:
        return ParsedConfigFile(
            path=path,
            status=ConfigParseStatus.PARSE_TIMEOUT,
            format=ConfigFileFormat.YAML,
            error_message=f"parse exceeded {timeout_seconds}s budget",
        )
    except yaml.YAMLError as exc:
        return ParsedConfigFile(
            path=path,
            status=ConfigParseStatus.PARSE_FAILED,
            format=ConfigFileFormat.YAML,
            error_message=str(exc),
        )
    return ParsedConfigFile(
        path=path, status=ConfigParseStatus.OK, format=ConfigFileFormat.YAML, entries=entries
    )


def _flatten_yaml_text(text: str) -> tuple[ConfigEntry, ...]:
    """Parse all YAML documents in ``text`` and flatten them to ConfigEntry.

    Uses ``yaml.compose_all`` (not ``safe_load_all``) so each value's
    source line number is available via its node's ``start_mark`` - the
    plain-object form ``safe_load`` returns loses that position info.
    """
    entries: list[ConfigEntry] = []
    for document in yaml.compose_all(text, Loader=yaml.SafeLoader):
        if document is not None:
            entries.extend(_flatten_yaml_node(document, prefix=""))
    return tuple(entries)


def _flatten_yaml_node(node: yaml.Node, prefix: str) -> list[ConfigEntry]:
    """Recursively flatten a YAML node into dotted-key ConfigEntry values."""
    if isinstance(node, yaml.MappingNode):
        return _flatten_yaml_mapping(node, prefix)
    if isinstance(node, yaml.SequenceNode):
        return _flatten_yaml_sequence(node, prefix)
    if isinstance(node, yaml.ScalarNode) and prefix:
        return [ConfigEntry(key=prefix, value=str(node.value), line=node.start_mark.line + 1)]
    return []


def _flatten_yaml_mapping(node: yaml.MappingNode, prefix: str) -> list[ConfigEntry]:
    entries: list[ConfigEntry] = []
    for key_node, value_node in node.value:
        key_part = str(key_node.value)
        new_prefix = f"{prefix}.{key_part}" if prefix else key_part
        entries.extend(_flatten_yaml_node(value_node, new_prefix))
    return entries


def _flatten_yaml_sequence(node: yaml.SequenceNode, prefix: str) -> list[ConfigEntry]:
    entries: list[ConfigEntry] = []
    for index, item_node in enumerate(node.value):
        entries.extend(_flatten_yaml_node(item_node, f"{prefix}[{index}]"))
    return entries


def _parse_properties(text: str) -> tuple[ConfigEntry, ...]:
    """Parse Java .properties syntax into ConfigEntry values.

    Simplified relative to the full ``java.util.Properties`` spec:
    supports comments (``#``/``!``), blank lines, ``key=value``/
    ``key:value`` pairs, and line continuation via a trailing
    unescaped backslash. Does not support whitespace-only key/value
    separators or ``\\uXXXX`` unicode escapes - real Quarkus/Spring
    config files essentially always use ``=`` and plain UTF-8 text, so
    this covers the realistic case without a full spec-compliant
    parser.
    """
    lines = text.splitlines()
    entries: list[ConfigEntry] = []
    index = 0
    while index < len(lines):
        line_number = index + 1
        stripped = lines[index].strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("!"):
            index += 1
            continue
        logical_line, lines_consumed = _join_continuation_lines(lines, index)
        parsed = _split_key_value(logical_line)
        if parsed is not None:
            key, value = parsed
            entries.append(ConfigEntry(key=key, value=value, line=line_number))
        index += lines_consumed
    return tuple(entries)


def _join_continuation_lines(lines: list[str], start_index: int) -> tuple[str, int]:
    """Join a logical .properties line that continues via trailing backslashes."""
    collected = lines[start_index]
    index = start_index
    while collected.endswith("\\") and not collected.endswith("\\\\"):
        index += 1
        if index >= len(lines):
            collected = collected[:-1]
            break
        collected = collected[:-1] + lines[index].lstrip()
    return collected, index - start_index + 1


def _split_key_value(logical_line: str) -> tuple[str, str] | None:
    """Split ``key=value`` or ``key:value`` on the first unescaped separator."""
    index = 0
    while index < len(logical_line):
        char = logical_line[index]
        if char == "\\":
            index += 2
            continue
        if char in ("=", ":"):
            key = logical_line[:index].strip()
            value = logical_line[index + 1 :].strip()
            return (key, value) if key else None
        index += 1
    return None
