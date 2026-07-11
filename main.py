"""VibeGuard CLI entry point.

Full scope: orchestrate the five-layer pipeline against a directory of
Java sample apps and produce the final explainable risk report. Current
scope: only Layer 1 (Java AST parsing + config-file parsing) exists, so
this command only parses .java/.properties/.yml/.yaml files and reports
what it found - it is not yet a vulnerability scan. Layers 2-5 will
extend this command as they land, per the build order in
CLAUDE.md/IMPLEMENTATION_LOG.md.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table

from vibeguard.layer1_static.ast_parser import (
    DEFAULT_MAX_FILE_BYTES,
    DEFAULT_PARSE_TIMEOUT_SECONDS,
    ParsedFile,
    ParseStatus,
    parse_file,
)
from vibeguard.layer1_static.config_parser import (
    ConfigParseStatus,
    ParsedConfigFile,
    parse_config_file,
)

_CONFIG_SUFFIXES = frozenset({".properties", ".yml", ".yaml"})


def main(argv: list[str] | None = None) -> int:
    """Parse Java source and config files under a path, and print a report.

    Args:
        argv: Command-line arguments, or ``None`` to read ``sys.argv``.

    Returns:
        ``0`` if every discovered file (Java or config) parsed OK,
        ``1`` otherwise (including "nothing found"), so this can be used
        as a pass/fail check in a script without parsing printed output.
    """
    args = _parse_args(argv)
    java_files = _collect_java_files(args.path)
    config_files = _collect_config_files(args.path)
    if not java_files and not config_files:
        print(f"No .java or config files found under {args.path}", file=sys.stderr)
        return 1

    java_results = [
        parse_file(java_file, max_bytes=args.max_bytes, timeout_seconds=args.timeout)
        for java_file in java_files
    ]
    config_results = [
        parse_config_file(config_file, max_bytes=args.max_bytes, timeout_seconds=args.timeout)
        for config_file in config_files
    ]

    if java_results:
        _print_java_report(java_results)
    if config_results:
        _print_config_report(config_results)

    java_ok = all(result.status == ParseStatus.OK for result in java_results)
    config_ok = all(result.status == ConfigParseStatus.OK for result in config_results)
    return 0 if java_ok and config_ok else 1


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    """Define and parse the CLI's arguments."""
    parser = argparse.ArgumentParser(
        prog="vibeguard",
        description=(
            "VibeGuard Layer 1: parse Java source (AST) and config files "
            "(.properties/.yml/.yaml, flattened key-value pairs) and report "
            "the outcome. Layers 2-5 (feature extraction, scoring, ML "
            "classification, SHAP explainability) are not implemented yet."
        ),
    )
    parser.add_argument(
        "path",
        type=Path,
        help=(
            "A single .java/.properties/.yml/.yaml file, or a directory to "
            "scan recursively for all of the above."
        ),
    )
    parser.add_argument(
        "--max-bytes",
        type=int,
        default=DEFAULT_MAX_FILE_BYTES,
        help=f"Reject files larger than this many bytes (default: {DEFAULT_MAX_FILE_BYTES}).",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_PARSE_TIMEOUT_SECONDS,
        help=f"Per-file parse timeout in seconds (default: {DEFAULT_PARSE_TIMEOUT_SECONDS}).",
    )
    return parser.parse_args(argv)


def _collect_java_files(path: Path) -> list[Path]:
    """Resolve ``path`` to a sorted list of .java files (empty if none found)."""
    resolved = path.resolve()
    if resolved.is_file():
        return [resolved] if resolved.suffix == ".java" else []
    if resolved.is_dir():
        return sorted(resolved.rglob("*.java"))
    return []


def _collect_config_files(path: Path) -> list[Path]:
    """Resolve ``path`` to a sorted list of config files (empty if none found)."""
    resolved = path.resolve()
    if resolved.is_file():
        return [resolved] if resolved.suffix.lower() in _CONFIG_SUFFIXES else []
    if resolved.is_dir():
        matches = {p for suffix in _CONFIG_SUFFIXES for p in resolved.rglob(f"*{suffix}")}
        return sorted(matches)
    return []


def _print_java_report(results: list[ParsedFile]) -> None:
    """Render a Rich table summarizing each Java file's parse outcome."""
    console = Console()
    table = Table(title="VibeGuard Layer 1 - Java AST Parse Report")
    table.add_column("File")
    table.add_column("Status")
    table.add_column("Classes")
    table.add_column("Detail")

    for result in results:
        class_names = ", ".join(cls.name for cls in result.classes) or "-"
        table.add_row(
            str(result.path), result.status.value, class_names, result.error_message or "-"
        )

    console.print(table)
    ok_count = sum(1 for result in results if result.status == ParseStatus.OK)
    console.print(f"{ok_count}/{len(results)} Java files parsed OK")


def _print_config_report(results: list[ParsedConfigFile]) -> None:
    """Render a Rich table summarizing each config file's parse outcome."""
    console = Console()
    table = Table(title="VibeGuard Layer 1 - Config File Parse Report")
    table.add_column("File")
    table.add_column("Status")
    table.add_column("Entries")
    table.add_column("Detail")

    for result in results:
        table.add_row(
            str(result.path),
            result.status.value,
            str(len(result.entries)),
            result.error_message or "-",
        )

    console.print(table)
    ok_count = sum(1 for result in results if result.status == ConfigParseStatus.OK)
    console.print(f"{ok_count}/{len(results)} config files parsed OK")


if __name__ == "__main__":
    raise SystemExit(main())
