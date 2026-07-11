"""VibeGuard CLI entry point.

Full scope: orchestrate the five-layer pipeline against a directory of
Java sample apps and produce the final explainable risk report. Current
scope: only Layer 1 (AST parsing) exists, so this command only parses
Java source and reports what ast_parser found - it is not yet a
vulnerability scan. Layers 2-5 will extend this command as they land,
per the build order in CLAUDE.md/IMPLEMENTATION_LOG.md.
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


def main(argv: list[str] | None = None) -> int:
    """Parse a .java file or directory and print a Layer 1 AST report.

    Args:
        argv: Command-line arguments, or ``None`` to read ``sys.argv``.

    Returns:
        ``0`` if every discovered file parsed with ``ParseStatus.OK``,
        ``1`` otherwise (including "no .java files found"), so this can
        be used as a pass/fail check in a script without parsing
        printed output.
    """
    args = _parse_args(argv)
    java_files = _collect_java_files(args.path)
    if not java_files:
        print(f"No .java files found under {args.path}", file=sys.stderr)
        return 1

    results = [
        parse_file(java_file, max_bytes=args.max_bytes, timeout_seconds=args.timeout)
        for java_file in java_files
    ]
    _print_report(results)

    return 0 if all(result.status == ParseStatus.OK for result in results) else 1


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    """Define and parse the CLI's arguments."""
    parser = argparse.ArgumentParser(
        prog="vibeguard",
        description=(
            "VibeGuard Layer 1: parse Java source into an AST and report the "
            "outcome. Layers 2-5 (feature extraction, scoring, ML "
            "classification, SHAP explainability) are not implemented yet."
        ),
    )
    parser.add_argument(
        "path",
        type=Path,
        help="A single .java file, or a directory to scan recursively for .java files.",
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


def _print_report(results: list[ParsedFile]) -> None:
    """Render a Rich table summarizing each file's parse outcome."""
    console = Console()
    table = Table(title="VibeGuard Layer 1 - AST Parse Report")
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
    console.print(f"{ok_count}/{len(results)} files parsed OK")


if __name__ == "__main__":
    raise SystemExit(main())
