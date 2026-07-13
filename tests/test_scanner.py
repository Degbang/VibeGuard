"""Tests for vibeguard.layer1_static.scanner."""

from __future__ import annotations

from pathlib import Path

import pytest

from vibeguard.layer1_static._parsing_guards import ParseStatus
from vibeguard.layer1_static.scanner import scan_directory


def test_scan_finds_java_and_config_files_in_nested_directories(tmp_path: Path) -> None:
    (tmp_path / "com" / "example" / "service").mkdir(parents=True)
    (tmp_path / "com" / "example" / "resources").mkdir(parents=True)
    (tmp_path / "com" / "example" / "service" / "UserService.java").write_text(
        "package com.example.service;\npublic class UserService {}\n"
    )
    (tmp_path / "com" / "example" / "resources" / "application.properties").write_text(
        "quarkus.http.port=8080\n"
    )

    result = scan_directory(tmp_path)

    assert len(result.java_files) == 1
    assert result.java_files[0].status == ParseStatus.OK
    assert result.java_files[0].classes[0].name == "UserService"

    assert len(result.config_files) == 1
    assert result.config_files[0].status == ParseStatus.OK
    assert result.rejected_paths == ()


def test_scan_ignores_irrelevant_file_types(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("# hello")
    (tmp_path / "notes.txt").write_text("hi")

    result = scan_directory(tmp_path)

    assert result.java_files == ()
    assert result.config_files == ()
    assert result.rejected_paths == ()


def test_scan_skips_git_internals(tmp_path: Path) -> None:
    git_dir = tmp_path / ".git" / "objects" / "ab"
    git_dir.mkdir(parents=True)
    (git_dir / "cd1234").write_text("not really a git object, just a probe file")
    (tmp_path / "Real.java").write_text("public class Real {}\n")

    result = scan_directory(tmp_path)

    assert len(result.java_files) == 1
    assert result.java_files[0].path.name == "Real.java"


def test_scan_raises_on_non_directory(tmp_path: Path) -> None:
    not_a_dir = tmp_path / "file.txt"
    not_a_dir.write_text("hi")

    with pytest.raises(NotADirectoryError):
        scan_directory(not_a_dir)


def test_scan_rejects_file_symlink_that_escapes_the_scan_root(tmp_path: Path) -> None:
    """Proves the path-traversal guard actually works, not just claims to.

    A sample-apps repository could contain a symlink - accidental, or
    deliberately adversarial in a public-repo dataset - whose *name*
    looks like an in-scope file but whose target lives outside the
    directory the operator intended to scan. Without an explicit
    containment check, such a file would be silently parsed as if it
    were part of the scanned project. This constructs exactly that
    scenario and confirms it's rejected, not parsed.
    """
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    secret_file = outside_dir / "Secret.java"
    secret_file.write_text('public class Secret { String key = "leaked"; }\n')

    scan_root = tmp_path / "root"
    scan_root.mkdir()
    escape_link = scan_root / "SneakyFile.java"
    escape_link.symlink_to(secret_file)

    result = scan_directory(scan_root)

    assert result.java_files == ()
    assert len(result.rejected_paths) == 1
    assert result.rejected_paths[0].path == escape_link
    assert "outside scan root" in result.rejected_paths[0].reason


def test_scan_does_not_recurse_into_symlinked_directories(tmp_path: Path) -> None:
    """A symlinked *directory* escape shouldn't even be walked into.

    Distinct from the file-symlink case above: this verifies traversal
    itself (os.walk(followlinks=False)) never descends into a linked
    directory, so files inside it never even become scan candidates.
    """
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    (outside_dir / "Hidden.java").write_text("public class Hidden {}\n")

    scan_root = tmp_path / "root"
    scan_root.mkdir()
    (scan_root / "escape_link").symlink_to(outside_dir)

    result = scan_directory(scan_root)

    assert result.java_files == ()
    assert result.rejected_paths == ()
