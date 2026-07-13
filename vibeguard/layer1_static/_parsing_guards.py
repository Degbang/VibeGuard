"""Shared infrastructure for Layer 1 parsers.

Both ``ast_parser.py`` (Java source) and ``config_parser.py``
(``.properties``/``.yml``) need the same two guarantees against
adversarial or oversized input — a hard file-size limit enforced before
any parsing happens, and a soft wall-clock budget around the actual
parse call — and the same vocabulary for describing what happened
(``ParseStatus``). This module centralizes all three so callers
(``main.py``, ``scanner.py``) can treat both parsers' results
uniformly, and so the guarantees can't drift apart per file format.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from enum import Enum
from pathlib import Path
from typing import TypeVar

_ParseResult = TypeVar("_ParseResult")


class ParseStatus(str, Enum):
    """Outcome of attempting to parse a single Layer 1 input file.

    Every outcome is represented explicitly so a file that can't be
    parsed is always flagged in results, never silently dropped.
    Shared between ``ast_parser.py`` and ``config_parser.py``;
    ``UNSUPPORTED_FORMAT`` only ever applies to the latter (a
    ``.java`` file is never "unsupported" to ``ast_parser.py``).
    """

    OK = "ok"
    EMPTY_FILE = "empty_file"
    FILE_TOO_LARGE = "file_too_large"
    PARSE_TIMEOUT = "parse_timeout"
    PARSE_FAILED = "parse_failed"
    UNSUPPORTED_FORMAT = "unsupported_format"


class ParsingGuardError(Exception):
    """Raised when a file fails a size or read guard.

    Callers catch this and translate it into their own format-specific
    failure result (e.g. ``ParseStatus.FILE_TOO_LARGE``); it is never
    meant to propagate out of a parser's public entry point. ``too_large``
    distinguishes the "exceeds max_bytes" case from other read failures
    without callers having to pattern-match the message text.
    """

    def __init__(self, message: str, *, too_large: bool = False) -> None:
        super().__init__(message)
        self.too_large = too_large


def read_text_within_limit(path: Path, max_bytes: int) -> str:
    """Return ``path``'s UTF-8 text, enforcing a hard size limit first.

    Args:
        path: File to read.
        max_bytes: Reject files larger than this without reading them.

    Returns:
        The file's text content.

    Raises:
        ParsingGuardError: If the file can't be stat'd, exceeds
            ``max_bytes``, or can't be read as UTF-8 text.
    """
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise ParsingGuardError(str(exc)) from exc
    if size > max_bytes:
        raise ParsingGuardError(f"{size} bytes exceeds max_bytes={max_bytes}", too_large=True)
    try:
        return path.read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeDecodeError) as exc:
        raise ParsingGuardError(str(exc)) from exc


def run_with_timeout(
    parse_func: Callable[[str], _ParseResult], source: str, *, timeout_seconds: float
) -> _ParseResult:
    """Run ``parse_func(source)`` on a daemon thread with a wall-clock budget.

    This is a soft mitigation, not true isolation: on timeout the
    background thread is abandoned (marked ``daemon=True`` so it can't
    block interpreter exit) rather than killed, since CPython has no
    supported way to forcibly stop a running thread. It bounds how long
    a caller waits on a single pathological input without hanging the
    overall scan; it does not bound the CPU the orphaned thread burns.
    True process-level isolation (subprocess per file) was considered
    unnecessary overhead for this project's scope — see
    IMPLEMENTATION_LOG.md.

    Raises:
        TimeoutError: If ``parse_func`` doesn't return within
            ``timeout_seconds``.
        Exception: Whatever ``parse_func`` itself raised, re-raised on
            the caller's thread so normal exception handling applies.
    """
    thread_result: dict[str, object] = {}

    def _invoke_parse_func_in_background() -> None:
        try:
            thread_result["return_value"] = parse_func(source)
        except Exception as exc:  # re-raised on the caller's thread below
            thread_result["exception"] = exc

    parse_thread = threading.Thread(target=_invoke_parse_func_in_background, daemon=True)
    parse_thread.start()
    parse_thread.join(timeout=timeout_seconds)
    if parse_thread.is_alive():
        raise TimeoutError(f"parse exceeded {timeout_seconds}s budget")
    if "exception" in thread_result:
        raise thread_result["exception"]  # type: ignore[misc]
    return thread_result["return_value"]  # type: ignore[return-value]
