"""Shared whole-process crash/hang supervisor for VibeGuard's CLI entry points.

Extracted from ``main.py``'s original 2026-09-10 implementation once a
second and third entry point (``evaluation/human_baseline.py``,
``evaluation/thesis_orchestrator.py``) needed the identical protection -
the same "extract on the second real need" practice already used
throughout this project (see ``IMPLEMENTATION_LOG.md``). Each entry
point still owns its own ``__main__`` dispatch; this module only holds
the shared mechanism, not the wiring.

Exists for one specific, reproduced failure mode: the Tree-sitter
fallback parser's underlying native binding (``tree-sitter``/
``tree-sitter-java``) can segfault after parsing a large, varied enough
number of distinct files in one long-running process (see
``IMPLEMENTATION_LOG.md``'s 2026-09-10 entry). A segfault is a real
process-level crash that no Python ``try/except`` anywhere in this
codebase can catch, so without this wrapper an affected entry point
would simply stop, silently, with none of Section 4's "explicitly
flagged in output" guarantee - a security tool losing every result
without a trace is a correctness bug, not a cosmetic one.

This is a supervisor around the *whole* run, not per-file isolation: the
Tree-sitter ``Tree``/``Node`` objects a scan produces are not picklable,
so there is no way to isolate individual file parses in separate
processes and hand live parsed results back to a parent - the boundary
has to be the entire run, with only the child process's exit status
crossing back.
"""

from __future__ import annotations

import os
import secrets
import subprocess
import sys

# Not a fixed sentinel: a fixed value like "1" is exactly the kind of
# thing a completely unrelated environment (a copy-pasted .env file, a CI
# variable set at workflow rather than step scope, a leftover shell
# export) could plausibly already hold, which would silently disable
# crash detection with no warning - confirmed reproducible, see
# IMPLEMENTATION_LOG.md's 2026-09-10 QA entry. A fresh secrets.token_hex(16)
# per invocation (see run_as_supervised_subprocess) closes that.
SUPERVISOR_WORKER_ENV_VAR = "VIBEGUARD_SUPERVISOR_WORKER"
_WORKER_TOKEN_LENGTH = 32  # hex chars from secrets.token_hex(16)

# Distinct from any entry point's own 0 (clean)/1 (findings or error)
# exit contract - means specifically "the child process itself died
# unexpectedly," not "the run completed and found something." (argparse
# usage errors are a third, pre-existing "normal" exit code, 2, that this
# wrapper always passes through unchanged since only a negative
# returncode is treated specially.)
CRASH_EXIT_CODE = 3
# Distinct again from the above: "the child was still alive and simply
# never finished" rather than "the child died." A caller's own per-file
# parse timeout does not extend to rule execution, ML training, or
# report rendering, all of which may run afterward, unguarded, inside
# the same child process - so without a bound here a hang anywhere in
# that back half blocks the parent forever with zero signal, which is a
# worse silent failure than the crash this wrapper exists to catch.
# 300s (5 minutes) was a guess (1800s) originally, then retuned against a
# real timed reference run (main.py against four combined real-world
# repos, 898 files: 9.22s wall clock) - still a ~32x margin, not a
# per-file throttle. See IMPLEMENTATION_LOG.md's 2026-09-10 entries.
TIMEOUT_EXIT_CODE = 4
DEFAULT_TIMEOUT_SECONDS = 300.0


def looks_like_supervisor_worker_token(value: str | None) -> bool:
    """Whether ``value`` is shaped like a token this module's own
    supervisor would generate for a child - not merely "any truthy
    string set in the environment."

    A child process has no independent channel to confirm a given env
    var value actually came from its own parent (a fresh process shares
    nothing but the environment), so this can only ever be a heuristic,
    not a cryptographic guarantee - it does not, and is not meant to,
    resist a deliberate adversary who reads this source file. What it
    does close is coincidental collision: requiring a fixed-length hex
    token instead of accepting any non-empty value makes an unrelated
    environment variable happening to already satisfy this check
    astronomically unlikely, where a single-character sentinel would not.

    Args:
        value: The raw environment variable value, or ``None`` if unset.

    Returns:
        Whether ``value`` is exactly ``_WORKER_TOKEN_LENGTH`` lowercase
        hex characters.
    """
    return (
        value is not None
        and len(value) == _WORKER_TOKEN_LENGTH
        and all(char in "0123456789abcdef" for char in value)
    )


def run_as_supervised_subprocess(
    child_command: list[str],
    *,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
) -> int:
    """Re-run ``child_command`` and translate a native crash or hang into
    an explicit, fail-closed exit code instead of a silent process death.

    Args:
        child_command: The full subprocess argv to run, typically
            ``[sys.executable, "-m", "<module>", *argv]`` or
            ``[sys.executable, str(script_path), *argv]``.
        timeout_seconds: Wall-clock budget for the whole child run.

    Returns:
        The child's own exit code on a normal exit (including argparse's
        own pre-existing usage-error code, 2 - this wrapper is invisible
        on every non-crash, non-hang path). ``CRASH_EXIT_CODE`` if the
        child was killed by a signal instead of exiting normally.
        ``TIMEOUT_EXIT_CODE`` if the child was still running past
        ``timeout_seconds`` and was killed here instead.
    """
    child_env = dict(os.environ)
    child_env[SUPERVISOR_WORKER_ENV_VAR] = secrets.token_hex(16)
    try:
        completed = subprocess.run(child_command, env=child_env, timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        print(
            f"Process exceeded the {timeout_seconds:.0f}s supervisor budget and was "
            "killed before completing - this is not a normal VibeGuard error, and "
            "results are incomplete. Do not treat a missing report as a clean run. "
            "See IMPLEMENTATION_LOG.md's 2026-09-10 entry.",
            file=sys.stderr,
        )
        return TIMEOUT_EXIT_CODE
    if completed.returncode < 0:
        print(
            f"Process terminated unexpectedly (signal {-completed.returncode}) before "
            "completing - this is a native-level crash, not a normal VibeGuard error, "
            "and results are incomplete. Do not treat a missing report as a clean run. "
            "See IMPLEMENTATION_LOG.md's 2026-09-10 entry.",
            file=sys.stderr,
        )
        return CRASH_EXIT_CODE
    return completed.returncode
