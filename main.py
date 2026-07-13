"""VibeGuard CLI entry point.

Full scope: orchestrate the five-layer pipeline against a directory of
Java sample apps and produce the final explainable risk report. Current
scope: only Layer 1 (Java AST parsing + config-file parsing, orchestrated
by scanner.py) exists, so this command only parses .java/.properties/
.yml/.yaml files and reports what it found - it is not yet a
vulnerability scan. Layers 2-5 will extend this command as they land,
per the build order in CLAUDE.md/IMPLEMENTATION_LOG.md.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table

from vibeguard.layer1_static._parsing_guards import ParseStatus
from vibeguard.layer1_static.ast_parser import (
    DEFAULT_MAX_FILE_BYTES,
    DEFAULT_PARSE_TIMEOUT_SECONDS,
    ParsedFile,
    parse_file,
)
from vibeguard.layer1_static.config_parser import (
    CONFIG_FILE_SUFFIXES,
    ParsedConfigFile,
    parse_config_file,
)
from vibeguard.layer1_static.scanner import RejectedPath, ScanResult, scan_directory

_JAVA_SUFFIX = ".java"


def main(argv: list[str] | None = None) -> int:
    """Parse Java source and config files under a path, and print a report.

    Args:
        argv: Command-line arguments, or ``None`` to read ``sys.argv``.

    Returns:
        ``0`` if every discovered file (Java or config) parsed OK and
        none were rejected on containment grounds, ``1`` otherwise
        (including "nothing found"), so this can be used as a pass/fail
        check in a script without parsing printed output.
    """
    args = _parse_args(argv)
    resolved = args.path.resolve()

    if resolved.is_file():
        result = _scan_single_file(resolved, args.max_bytes, args.timeout)
    elif resolved.is_dir():
        result = scan_directory(resolved, max_bytes=args.max_bytes, timeout_seconds=args.timeout)
    else:
        print(f"{args.path} is not a file or directory", file=sys.stderr)
        return 1

    if not result.java_files and not result.config_files:
        print(f"No .java or config files found under {args.path}", file=sys.stderr)
        return 1

    if result.java_files:
        _print_java_report(result.java_files)
    if result.config_files:
        _print_config_report(result.config_files)
    if result.rejected_paths:
        _print_rejected_report(result.rejected_paths)

    java_ok = all(r.status == ParseStatus.OK for r in result.java_files)
    config_ok = all(r.status == ParseStatus.OK for r in result.config_files)
    return 0 if java_ok and config_ok and not result.rejected_paths else 1


def _scan_single_file(resolved: Path, max_bytes: int, timeout_seconds: float) -> ScanResult:
    """Parse exactly one explicitly-named file (no containment check needed).

    Containment checking exists to protect against files *discovered*
    while walking a directory (e.g. a symlink an operator didn't
    consciously choose). A single file named directly on the command
    line was chosen deliberately by the person running the CLI, so that
    check doesn't apply here - this mirrors scan_directory's shape
    without its directory-walking machinery.
    """
    if resolved.suffix.lower() == _JAVA_SUFFIX:
        java_result = parse_file(resolved, max_bytes=max_bytes, timeout_seconds=timeout_seconds)
        return ScanResult(
            root=resolved, java_files=(java_result,), config_files=(), rejected_paths=()
        )
    if resolved.suffix.lower() in CONFIG_FILE_SUFFIXES:
        config_result = parse_config_file(
            resolved, max_bytes=max_bytes, timeout_seconds=timeout_seconds
        )
        return ScanResult(
            root=resolved, java_files=(), config_files=(config_result,), rejected_paths=()
        )
    return ScanResult(root=resolved, java_files=(), config_files=(), rejected_paths=())


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


def _print_java_report(results: tuple[ParsedFile, ...]) -> None:
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
            str(result.path), result.status.value, class_names, _summarize(result.error_message)
        )

    console.print(table)
    ok_count = sum(1 for result in results if result.status == ParseStatus.OK)
    console.print(f"{ok_count}/{len(results)} Java files parsed OK")


def _print_config_report(results: tuple[ParsedConfigFile, ...]) -> None:
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
            _summarize(result.error_message),
        )

    console.print(table)
    ok_count = sum(1 for result in results if result.status == ParseStatus.OK)
    console.print(f"{ok_count}/{len(results)} config files parsed OK")


def _print_rejected_report(rejected: tuple[RejectedPath, ...]) -> None:
    """Render a Rich table for files excluded on containment grounds.

    Surfaced as its own table (not folded into the other reports) since
    a rejection means "this was never even parsed," which is a
    different, security-relevant kind of outcome from a parse failure.
    """
    console = Console()
    table = Table(title="VibeGuard Layer 1 - Rejected Paths (not scanned)")
    table.add_column("File")
    table.add_column("Reason")

    for entry in rejected:
        table.add_row(str(entry.path), entry.reason)

    console.print(table)


def _summarize(message: str | None, *, limit: int = 120) -> str:
    """Collapse a possibly multi-line error message to one table-friendly line."""
    if not message:
        return "-"
    collapsed = " ".join(message.split())
    return collapsed if len(collapsed) <= limit else f"{collapsed[: limit - 1]}…"


if __name__ == "__main__":
    raise SystemExit(main())
