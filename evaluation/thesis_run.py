"""Top-level thesis evaluation runner for bundled artifact capture."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from evaluation.evaluate import (
    _DEFAULT_MODEL_CONTRACT,
    _module_invocation,
    build_evaluation_report,
    write_bundle_report,
)


def main(argv: list[str] | None = None) -> int:
    """Build the default thesis evaluation artifact bundle."""
    args = _parse_args(argv)
    invocation = _module_invocation("evaluation.thesis_run", argv or [])
    try:
        report = build_evaluation_report(args.model_contract)
        bundle_dir = write_bundle_report(report, args.output_dir, invocation=invocation)
    except ValueError as exc:
        print(f"Thesis run failed: {exc}", file=sys.stderr)
        return 1
    print(bundle_dir)
    return 0


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m evaluation.thesis_run",
        description=(
            "Generate the default VibeGuard thesis evaluation artifact bundle "
            "from the trusted Layer 4 contract."
        ),
    )
    parser.add_argument(
        "--model-contract",
        type=Path,
        default=_DEFAULT_MODEL_CONTRACT,
        help="Trusted Layer 4 model contract JSON to evaluate.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("evaluation_artifacts"),
        help="Parent directory where the timestamped evaluation bundle will be created.",
    )
    return parser.parse_args(argv)


if __name__ == "__main__":
    raise SystemExit(main())
