"""VibeGuard CLI entry point.

Full scope: orchestrate the five-layer pipeline against a directory of
Java sample apps and produce the final explainable risk report. Current
scope: Layer 1 parsing/orchestration (scanner.py) plus the CWE rule
modules implemented so far (cwe_798.py, cwe_284.py) - this command
parses .java/.properties/.yml/.yaml files AND runs those rules against
every successfully-parsed file. It is not yet the full explainable risk
assessment: there is no rule-based scoring (Layer 3), no ML
classification (Layer 4), and no SHAP explanation (Layer 5) - a
finding here is a raw, unscored candidate from one rule's pattern
matching, not a final severity judgment. Layers 2-5 and the remaining
CWE rule modules will extend this command as they land, per the build
order in CLAUDE.md/IMPLEMENTATION_LOG.md.
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
from vibeguard.layer1_static.rules import cwe_284, cwe_798
from vibeguard.layer1_static.rules._finding import Finding
from vibeguard.layer1_static.scanner import RejectedPath, ScanResult, scan_directory

_JAVA_SUFFIX = ".java"


def main(argv: list[str] | None = None) -> int:
    """Parse Java source and config files under a path, run CWE rules, and report.

    Args:
        argv: Command-line arguments, or ``None`` to read ``sys.argv``.

    Returns:
        ``0`` only if every discovered file parsed OK, none were
        rejected on containment grounds, AND no CWE rule produced a
        finding; ``1`` otherwise (including "nothing found"). This
        exit-code contract is provisional: with no Layer 3 scoring yet,
        "any finding at all" is the only threshold available - it will
        become severity-based once scoring exists.
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

    findings = _run_rules(result)

    if result.java_files:
        _print_java_report(result.java_files)
    if result.config_files:
        _print_config_report(result.config_files)
    if result.rejected_paths:
        _print_rejected_report(result.rejected_paths)
    if findings:
        _print_findings_report(findings)

    java_ok = all(r.status == ParseStatus.OK for r in result.java_files)
    config_ok = all(r.status == ParseStatus.OK for r in result.config_files)
    return 0 if java_ok and config_ok and not result.rejected_paths and not findings else 1


def _run_rules(result: ScanResult) -> tuple[Finding, ...]:
    """Run every implemented CWE rule against a scan's successfully-parsed files.

    Only rules/cwe_798.py and rules/cwe_284.py exist so far; more CWE
    rule modules get added here as they land. A file that failed to
    parse is skipped - there's no AST/entries to inspect, and that
    failure is already surfaced separately via the parse report, not
    silently dropped.
    """
    findings: list[Finding] = []
    for java_file in result.java_files:
        if java_file.status != ParseStatus.OK:
            continue
        findings.extend(cwe_798.detect_in_java(java_file))
        findings.extend(cwe_284.detect_in_java(java_file))
    for config_file in result.config_files:
        if config_file.status != ParseStatus.OK:
            continue
        findings.extend(cwe_798.detect_in_config(config_file))
    return tuple(findings)


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
            "(.properties/.yml/.yaml, flattened key-value pairs), then run "
            "the CWE rules implemented so far (CWE-798 hardcoded credentials, "
            "CWE-284 improper access control) against them. Findings are "
            "unscored rule matches, not graded risk - Layers 2-5 (feature "
            "extraction, rule-based scoring, ML classification, SHAP "
            "explainability) are not implemented yet, and the remaining CWE "
            "rules (287, 20, 1035) don't exist yet either."
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


def _print_findings_report(findings: tuple[Finding, ...]) -> None:
    """Render a Rich table of every CWE finding across the scan.

    Explicitly labeled "not yet scored" in the title: without Layer 3,
    every finding here is an unranked rule match, not a graded risk -
    the table must not be read as if severity had already been judged.
    """
    console = Console()
    table = Table(title="VibeGuard Layer 1 - Findings (CWE candidates, not yet scored)")
    table.add_column("File", overflow="fold")
    table.add_column("CWE")
    table.add_column("Line")
    table.add_column("Identifier", overflow="fold")
    table.add_column("Detail", overflow="fold")

    for finding in findings:
        table.add_row(
            str(finding.file_path),
            finding.cwe_id,
            str(finding.line) if finding.line is not None else "-",
            finding.identifier,
            finding.message,
        )

    console.print(table)
    console.print(f"{len(findings)} finding(s)")


def _summarize(message: str | None, *, limit: int = 120) -> str:
    """Collapse a possibly multi-line error message to one table-friendly line."""
    if not message:
        return "-"
    collapsed = " ".join(message.split())
    return collapsed if len(collapsed) <= limit else f"{collapsed[: limit - 1]}…"


if __name__ == "__main__":
    raise SystemExit(main())
