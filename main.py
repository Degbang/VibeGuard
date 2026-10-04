"""VibeGuard CLI entry point.

Orchestrates the full five-layer pipeline against a file or directory
of Java microservice sources. The command parses .java files,
conventional application config files (``application*``,
``bootstrap*``, ``microprofile-config*``), and ``pom.xml`` files,
runs every implemented CWE rule against successfully parsed files,
normalizes/deduplicates findings via Layer 2, assigns deterministic
Layer 3 scores, predicts project-level risk through Layer 4, and
prints a Layer 5 SHAP explanation/report.

When run as a script (``python main.py ...``, not imported and called
as ``main()`` directly), the actual scan runs inside a supervised child
process - see ``process_supervisor.run_as_supervised_subprocess``'s
docstring for why: a real, reproduced native crash in the Tree-sitter
fallback parser's underlying C binding cannot be caught with a Python
``try/except``, so without this a large enough scan could die silently,
losing every result with no trace at all, which Section 4's fail-closed
requirement does not allow.
"""

from __future__ import annotations

import argparse
import dataclasses
import os
import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table

import process_supervisor
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
    is_conventional_config_path,
    parse_config_file,
)
from vibeguard.layer1_static.pom_parser import (
    ParsedPomFile,
    parse_pom_file,
    resolve_inherited_versions,
)
from vibeguard.layer1_static.rules import cwe_20, cwe_284, cwe_287, cwe_798, cwe_1035
from vibeguard.layer1_static.rules._finding import Finding
from vibeguard.layer1_static.rules._interface_annotations import (
    build_interface_hierarchy_index,
    build_interface_method_index,
    build_interface_parameter_index,
)
from vibeguard.layer1_static.scanner import RejectedPath, ScanResult, scan_directory
from vibeguard.layer2_features import extract_features
from vibeguard.layer3_scoring import ScoredFinding, score_features
from vibeguard.layer4_ml import load_trusted_model_contract
from vibeguard.layer5_report import build_project_risk_report, render_console_report

_JAVA_SUFFIX = ".java"
_POM_FILENAME = "pom.xml"
_DEFAULT_MODEL_CONTRACT = (
    Path(__file__).resolve().parent / "data" / "labeled" / "layer4_random_forest_contract.json"
)


def main(argv: list[str] | None = None) -> int:
    """Parse Java source and config files under a path, run CWE rules, and report.

    Args:
        argv: Command-line arguments, or ``None`` to read ``sys.argv``.

    Returns:
        ``0`` only if every discovered file parsed OK, none were
        rejected on containment grounds, AND no CWE rule produced a
        scored finding; ``1`` otherwise (including "nothing found").
        This exit-code contract is conservative: any scored candidate
        currently fails the scan until a later severity-threshold policy
        is deliberately added.
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

    if not result.java_files and not result.config_files and not result.pom_files:
        print(f"No .java/config/pom.xml files found under {args.path}", file=sys.stderr)
        return 1

    if result.pom_files:
        result = dataclasses.replace(result, pom_files=resolve_inherited_versions(result.pom_files))

    findings = _run_rules(result)
    try:
        scored_findings = _score_findings(findings)
    except ValueError as exc:
        print(f"Scoring failed: {exc}", file=sys.stderr)
        return 1
    try:
        model = load_trusted_model_contract(args.model_contract.resolve())
        final_report = build_project_risk_report(resolved, model, scored_findings)
    except Exception as exc:
        print(f"ML/reporting failed: {exc}", file=sys.stderr)
        return 1

    if result.java_files:
        _print_java_report(result.java_files)
    if result.config_files:
        _print_config_report(result.config_files)
    if result.pom_files:
        _print_pom_report(result.pom_files)
    if result.rejected_paths:
        _print_rejected_report(result.rejected_paths)
    if scored_findings:
        _print_scored_findings_report(scored_findings)
    render_console_report(final_report)

    java_ok = all(r.status == ParseStatus.OK for r in result.java_files)
    config_ok = all(r.status == ParseStatus.OK for r in result.config_files)
    pom_ok = all(r.status == ParseStatus.OK for r in result.pom_files)
    return (
        0
        if java_ok and config_ok and pom_ok and not result.rejected_paths and not scored_findings
        else 1
    )


def _run_rules(result: ScanResult) -> tuple[Finding, ...]:
    """Run every implemented CWE rule against a scan's successfully-parsed files.

    Every CWE rule module implemented so far runs here; more get added
    as they land. A file that failed to parse is skipped - there's no
    AST/entries to inspect, and that failure is already surfaced
    separately via the parse report, not silently dropped.
    """
    ok_java_files = tuple(jf for jf in result.java_files if jf.status == ParseStatus.OK)
    interface_annotations = build_interface_method_index(ok_java_files)
    interface_parameter_annotations = build_interface_parameter_index(ok_java_files)
    interface_hierarchy = build_interface_hierarchy_index(ok_java_files)
    findings: list[Finding] = []
    for java_file in ok_java_files:
        findings.extend(cwe_798.detect_in_java(java_file))
        findings.extend(
            cwe_284.detect_in_java(java_file, interface_annotations, interface_hierarchy)
        )
        findings.extend(cwe_287.detect_in_java(java_file))
        findings.extend(
            cwe_20.detect_in_java(
                java_file,
                interface_annotations,
                interface_parameter_annotations,
                interface_hierarchy,
            )
        )
    for config_file in result.config_files:
        if config_file.status != ParseStatus.OK:
            continue
        findings.extend(cwe_798.detect_in_config(config_file))
    for pom_file in result.pom_files:
        if pom_file.status != ParseStatus.OK:
            continue
        findings.extend(cwe_1035.detect_in_pom(pom_file))
    deduplicated_findings = cwe_284.deduplicate_interface_implementation_findings(
        tuple(findings), ok_java_files
    )
    findings_with_centralized_context = cwe_284.apply_centralized_authorization_context(
        deduplicated_findings, ok_java_files
    )
    return cwe_284.apply_hand_rolled_guard_context(findings_with_centralized_context, ok_java_files)


def _score_findings(findings: tuple[Finding, ...]) -> tuple[ScoredFinding, ...]:
    """Normalize raw findings through Layer 2 and score them through Layer 3."""
    return score_features(extract_features(findings))


def _scan_single_file(resolved: Path, max_bytes: int, timeout_seconds: float) -> ScanResult:
    """Parse exactly one explicitly-named file (no containment check needed).

    Containment checking exists to protect against files *discovered*
    while walking a directory (e.g. a symlink an operator didn't
    consciously choose). A single file named directly on the command
    line was chosen deliberately by the person running the CLI, so that
    check doesn't apply here - this mirrors scan_directory's shape
    without its directory-walking machinery.
    """
    if resolved.name.lower() == _POM_FILENAME:
        pom_result = parse_pom_file(resolved, max_bytes=max_bytes, timeout_seconds=timeout_seconds)
        return ScanResult(
            root=resolved,
            java_files=(),
            config_files=(),
            pom_files=(pom_result,),
            rejected_paths=(),
        )
    if resolved.suffix.lower() == _JAVA_SUFFIX:
        java_result = parse_file(resolved, max_bytes=max_bytes, timeout_seconds=timeout_seconds)
        return ScanResult(
            root=resolved,
            java_files=(java_result,),
            config_files=(),
            pom_files=(),
            rejected_paths=(),
        )
    if resolved.suffix.lower() in CONFIG_FILE_SUFFIXES and is_conventional_config_path(resolved):
        config_result = parse_config_file(
            resolved, max_bytes=max_bytes, timeout_seconds=timeout_seconds
        )
        return ScanResult(
            root=resolved,
            java_files=(),
            config_files=(config_result,),
            pom_files=(),
            rejected_paths=(),
        )
    return ScanResult(
        root=resolved, java_files=(), config_files=(), pom_files=(), rejected_paths=()
    )


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    """Define and parse the CLI's arguments."""
    parser = argparse.ArgumentParser(
        prog="vibeguard",
        description=(
            "VibeGuard Layer 1: parse Java source (AST), conventional "
            "application config files "
            "(application*/bootstrap*/microprofile-config* in "
            ".properties/.yml/.yaml form), and Maven pom.xml dependency "
            "declarations, then run every CWE rule implemented so far "
            "(CWE-798 hardcoded credentials, CWE-284 improper access "
            "control, CWE-287 improper authentication, CWE-20 improper "
            "input validation, CWE-1035 known-vulnerable components) "
            "against them. Findings are normalized by Layer 2, scored "
            "by Layer 3's deterministic rule-based scorer, classified "
            "by Layer 4's local Random Forest, and explained by "
            "Layer 5's SHAP attribution report."
        ),
    )
    parser.add_argument(
        "path",
        type=Path,
        help=(
            "A single .java/pom.xml/conventional application config file "
            "(application*/bootstrap*/microprofile-config*), or a "
            "directory to scan recursively for all of the above."
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
    parser.add_argument(
        "--model-contract",
        type=Path,
        default=_DEFAULT_MODEL_CONTRACT,
        help=(
            "Trusted Layer 4 model contract JSON to retrain/load before "
            "Layer 5 reporting (default: data/labeled/layer4_random_forest_contract.json)."
        ),
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


def _print_pom_report(results: tuple[ParsedPomFile, ...]) -> None:
    """Render a Rich table summarizing each pom.xml's parse outcome.

    Includes an "Unchecked" column: dependencies with no resolvable
    version (e.g. inherited from a parent BOM VibeGuard cannot read) can
    never be evaluated by CWE-1035, which would otherwise report "0
    findings" indistinguishably from "0 vulnerable dependencies, all
    checked" - a real gap found by scanning real Spring Boot/Quarkus
    projects, where the large majority of dependencies omit an explicit
    version by idiomatic convention. Surfacing the count keeps a clean
    result honest rather than silently implying full coverage.
    """
    console = Console()
    table = Table(title="VibeGuard Layer 1 - pom.xml Parse Report")
    table.add_column("File")
    table.add_column("Status")
    table.add_column("Dependencies")
    table.add_column("Unchecked (no resolvable version)")
    table.add_column("Detail")

    for result in results:
        unresolved = sum(1 for dependency in result.dependencies if dependency.version is None)
        table.add_row(
            str(result.path),
            result.status.value,
            str(len(result.dependencies)),
            str(unresolved) if result.dependencies else "-",
            _summarize(result.error_message),
        )

    console.print(table)
    ok_count = sum(1 for result in results if result.status == ParseStatus.OK)
    console.print(f"{ok_count}/{len(results)} pom.xml files parsed OK")
    total_dependencies = sum(len(result.dependencies) for result in results)
    total_unresolved = sum(
        1 for result in results for dependency in result.dependencies if dependency.version is None
    )
    if total_unresolved:
        console.print(
            f"{total_unresolved}/{total_dependencies} declared dependencies have no "
            "resolvable version (e.g. inherited from a parent BOM) and could not be "
            "checked against CWE-1035's known-vulnerability list."
        )


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


def _print_scored_findings_report(findings: tuple[ScoredFinding, ...]) -> None:
    """Render a Rich table of every scored CWE finding across the scan."""
    console = Console()
    table = Table(title="VibeGuard Layers 1-3 - Scored Findings")
    table.add_column("File", overflow="fold")
    table.add_column("CWE")
    table.add_column("Line")
    table.add_column("Score")
    table.add_column("Severity")
    table.add_column("Identifier", overflow="fold")
    table.add_column("Detail", overflow="fold")

    for scored in findings:
        feature = scored.feature
        table.add_row(
            str(feature.file_path),
            feature.cwe_id,
            str(feature.line) if feature.line is not None else "-",
            str(scored.score),
            scored.severity.value,
            feature.identifier,
            feature.message,
        )

    console.print(table)
    console.print(f"{len(findings)} scored finding(s)")


def _summarize(message: str | None, *, limit: int = 120) -> str:
    """Collapse a possibly multi-line error message to one table-friendly line."""
    if not message:
        return "-"
    collapsed = " ".join(message.split())
    return collapsed if len(collapsed) <= limit else f"{collapsed[: limit - 1]}…"


if __name__ == "__main__":
    if process_supervisor.looks_like_supervisor_worker_token(
        os.environ.get(process_supervisor.SUPERVISOR_WORKER_ENV_VAR)
    ):
        raise SystemExit(main())
    raise SystemExit(
        process_supervisor.run_as_supervised_subprocess(
            [sys.executable, str(Path(__file__).resolve()), *sys.argv[1:]]
        )
    )
