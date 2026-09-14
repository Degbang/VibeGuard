"""Tests for the shared whole-process crash/hang supervisor.

Generic coverage of ``process_supervisor.py`` itself - entry-point-specific
wiring (which child command each of main.py/human_baseline.py/
thesis_orchestrator.py constructs) is covered by each of their own test
modules instead of duplicated here.
"""

from __future__ import annotations

import secrets
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import patch

import pytest

import process_supervisor


def test_supervisor_passes_through_a_normal_exit_code(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A normal exit (0 or 1, a typical entry point's own contract) must
    be unchanged - the supervisor is invisible on the success path."""
    for normal_exit_code in (0, 1):
        completed = SimpleNamespace(returncode=normal_exit_code)
        with patch("process_supervisor.subprocess.run", return_value=completed) as mock_run:
            result = process_supervisor.run_as_supervised_subprocess([sys.executable, "some/path"])

        assert result == normal_exit_code
        assert capsys.readouterr().err == ""
        (call_args,), call_kwargs = mock_run.call_args
        assert call_args == [sys.executable, "some/path"]
        assert process_supervisor.looks_like_supervisor_worker_token(
            call_kwargs["env"][process_supervisor.SUPERVISOR_WORKER_ENV_VAR]
        )
        assert call_kwargs["timeout"] == process_supervisor.DEFAULT_TIMEOUT_SECONDS


def test_supervisor_worker_token_is_fresh_per_invocation(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Two separate supervisor invocations must not hand out the same
    worker token - a fixed, reused value would be no better than the
    static "1" sentinel it replaced."""
    completed = SimpleNamespace(returncode=0)
    tokens = []
    with patch("process_supervisor.subprocess.run", return_value=completed) as mock_run:
        for _ in range(2):
            process_supervisor.run_as_supervised_subprocess([sys.executable, "some/path"])
            tokens.append(
                mock_run.call_args.kwargs["env"][process_supervisor.SUPERVISOR_WORKER_ENV_VAR]
            )
    capsys.readouterr()

    assert tokens[0] != tokens[1]


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, False),
        ("", False),
        ("1", False),  # the old sentinel value - must no longer bypass supervision
        ("true", False),
        ("0" * 32, True),
        ("a" * 31, False),  # one char short
        ("a" * 33, False),  # one char over
        ("g" * 32, False),  # not hex
        ("A" * 32, False),  # uppercase hex must not match (token_hex is lowercase)
    ],
)
def test_looks_like_supervisor_worker_token_rejects_coincidental_values(
    value: str | None, expected: bool
) -> None:
    """A value that merely happens to be set - including the exact old
    "1" sentinel, or a plausible-looking but wrong string a stray
    environment variable might carry - must not be mistaken for a
    genuine worker token, or crash/hang detection silently disables
    itself with no warning. See IMPLEMENTATION_LOG.md's 2026-09-10 QA
    entry: this was reproduced for real before being fixed."""
    assert process_supervisor.looks_like_supervisor_worker_token(value) is expected


def test_looks_like_supervisor_worker_token_accepts_a_real_generated_token() -> None:
    """Sanity check against the actual generator, not just hand-picked
    examples: a real secrets.token_hex(16) value must pass."""
    assert process_supervisor.looks_like_supervisor_worker_token(secrets.token_hex(16)) is True


def test_supervisor_detects_a_hung_child_and_fails_closed(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A child that is still alive but never finishes must not block this
    call forever. Reproduced for real (a genuinely hung child process,
    bounded by an outer test harness) before this budget was added - see
    IMPLEMENTATION_LOG.md's 2026-09-10 QA entry."""
    timeout_error = subprocess.TimeoutExpired(
        cmd=["irrelevant"], timeout=process_supervisor.DEFAULT_TIMEOUT_SECONDS
    )
    with patch("process_supervisor.subprocess.run", side_effect=timeout_error):
        result = process_supervisor.run_as_supervised_subprocess([sys.executable, "some/path"])

    assert result == process_supervisor.TIMEOUT_EXIT_CODE
    assert result not in (0, 1, process_supervisor.CRASH_EXIT_CODE)
    stderr = capsys.readouterr().err
    assert "killed" in stderr
    assert "incomplete" in stderr


def test_supervisor_detects_a_signal_death_and_fails_closed(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A negative returncode (subprocess.run's signal-death convention on
    POSIX) must never be passed through as if it were a normal exit code -
    this is the actual failure mode a real Tree-sitter native crash
    produces (SIGSEGV), confirmed by direct reproduction - see
    IMPLEMENTATION_LOG.md's 2026-09-10 entry."""
    completed = SimpleNamespace(returncode=-11)  # SIGSEGV
    with patch("process_supervisor.subprocess.run", return_value=completed):
        result = process_supervisor.run_as_supervised_subprocess([sys.executable, "some/path"])

    assert result == process_supervisor.CRASH_EXIT_CODE
    assert result not in (0, 1)
    stderr = capsys.readouterr().err
    assert "signal 11" in stderr
    assert "incomplete" in stderr


def test_run_as_supervised_subprocess_accepts_a_custom_timeout(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Callers may override the default budget - main.py and the two
    evaluation entry points all currently use the default, but the
    parameter itself must actually be honored."""
    completed = SimpleNamespace(returncode=0)
    with patch("process_supervisor.subprocess.run", return_value=completed) as mock_run:
        process_supervisor.run_as_supervised_subprocess(
            [sys.executable, "some/path"], timeout_seconds=12.5
        )
    capsys.readouterr()

    assert mock_run.call_args.kwargs["timeout"] == 12.5
