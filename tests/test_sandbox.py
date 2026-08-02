"""Controlled workspace boundary tests."""

from __future__ import annotations

import base64
import os
from pathlib import Path

import pytest

import openworkproof.repo_tools as repo_tools


def _decode_path(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def test_scan_workspace_manifest_includes_every_descendant_without_following(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / ".ignored").write_bytes(b"ignored\n")
    source = workspace / "src"
    source.mkdir()
    executable = source / "run.sh"
    executable.write_bytes(b"#!/bin/sh\n")
    executable.chmod(0o755)
    (workspace / "link").symlink_to("src/run.sh")
    root_fd = os.open(
        workspace,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
    )
    try:
        scanner = getattr(repo_tools, "scan_workspace_manifest", None)
        assert callable(scanner)
        manifest = scanner(root_fd, "a" * 40)
    finally:
        os.close(root_fd)

    paths = tuple(
        _decode_path(entry.path_bytes_b64url) for entry in manifest.entries
    )
    assert paths == (b".ignored", b"link", b"src", b"src/run.sh")
    entries = dict(zip(paths, manifest.entries, strict=True))
    assert entries[b".ignored"].type == "regular"
    assert entries[b".ignored"].sha256 is not None
    assert entries[b"link"].type == "symlink"
    assert _decode_path(entries[b"link"].symlink_target_b64url) == b"src/run.sh"
    assert entries[b"src"].type == "directory"
    assert entries[b"src/run.sh"].posix_mode == "100755"


def test_scan_workspace_manifest_rejects_regular_file_hardlinks(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    original = workspace / "original.txt"
    original.write_bytes(b"same inode\n")
    os.link(original, workspace / "alias.txt")
    root_fd = os.open(
        workspace,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
    )
    try:
        with pytest.raises(repo_tools.ManifestError, match="hardlink"):
            repo_tools.scan_workspace_manifest(root_fd, "a" * 40)
    finally:
        os.close(root_fd)


def test_scan_workspace_manifest_detects_file_change_during_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    target = workspace / "target.txt"
    target.write_bytes(b"before\n")
    real_read = repo_tools._read_workspace_file

    def mutate_after_read(descriptor: int, expected_size: int) -> bytes:
        payload = real_read(descriptor, expected_size)
        target.write_bytes(b"after!\n")
        return payload

    monkeypatch.setattr(
        repo_tools,
        "_read_workspace_file",
        mutate_after_read,
    )
    root_fd = os.open(
        workspace,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
    )
    try:
        with pytest.raises(
            repo_tools.ManifestError,
            match="changed during read",
        ):
            repo_tools.scan_workspace_manifest(root_fd, "a" * 40)
    finally:
        os.close(root_fd)


def test_scan_workspace_manifest_enforces_entry_and_file_bounds(
    tmp_path: Path,
) -> None:
    crowded = tmp_path / "crowded"
    crowded.mkdir()
    for index in range(513):
        (crowded / f"{index:03}.txt").write_bytes(b"x")
    crowded_fd = os.open(
        crowded,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
    )
    try:
        with pytest.raises(repo_tools.ManifestError, match="512 entries"):
            repo_tools.scan_workspace_manifest(crowded_fd, "a" * 40)
    finally:
        os.close(crowded_fd)

    oversized = tmp_path / "oversized"
    oversized.mkdir()
    (oversized / "large.bin").write_bytes(b"x" * (1_048_576 + 1))
    oversized_fd = os.open(
        oversized,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
    )
    try:
        with pytest.raises(repo_tools.ManifestError, match="exceeds 1 MiB"):
            repo_tools.scan_workspace_manifest(oversized_fd, "a" * 40)
    finally:
        os.close(oversized_fd)


def test_scan_workspace_manifest_stops_before_opening_nested_entry_513(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    root_fd = os.open(workspace, flags)
    parent_fd = os.dup(root_fd)
    try:
        for index in range(513):
            name = f"d{index:03}"
            os.mkdir(name, dir_fd=parent_fd)
            child_fd = os.open(name, flags, dir_fd=parent_fd)
            os.close(parent_fd)
            parent_fd = child_fd
    finally:
        os.close(parent_fd)

    real_open = repo_tools.os.open
    opened_children = 0

    def counted_open(path, open_flags, *args, **kwargs):
        nonlocal opened_children
        if kwargs.get("dir_fd") is not None:
            opened_children += 1
        return real_open(path, open_flags, *args, **kwargs)

    monkeypatch.setattr(repo_tools.os, "open", counted_open)
    try:
        with pytest.raises(repo_tools.ManifestError, match="512 entries"):
            repo_tools.scan_workspace_manifest(root_fd, "a" * 40)
        assert opened_children == 512
    finally:
        os.close(root_fd)


def test_scan_workspace_manifest_is_repeatable_on_the_same_root_descriptor(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "file.txt").write_bytes(b"stable\n")
    root_fd = os.open(
        workspace,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
    )
    try:
        first = repo_tools.scan_workspace_manifest(root_fd, "a" * 40)
        second = repo_tools.scan_workspace_manifest(root_fd, "a" * 40)
        assert os.fstat(root_fd)
    finally:
        os.close(root_fd)

    assert second == first


def test_scan_workspace_manifest_preserves_filesystem_path_bytes(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    root_fd = os.open(
        workspace,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
    )
    try:
        raw_name = "é".encode()
        descriptor = os.open(
            raw_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o644,
            dir_fd=root_fd,
        )
        os.write(descriptor, b"raw path\n")
        os.close(descriptor)
        manifest = repo_tools.scan_workspace_manifest(root_fd, "a" * 40)
    finally:
        os.close(root_fd)

    assert tuple(
        _decode_path(entry.path_bytes_b64url) for entry in manifest.entries
    ) == (raw_name,)


def test_scan_workspace_manifest_requires_nofollow_support(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    root_fd = os.open(
        workspace,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
    )
    monkeypatch.delattr(repo_tools.os, "O_NOFOLLOW")
    try:
        with pytest.raises(repo_tools.ManifestError, match="O_NOFOLLOW"):
            repo_tools.scan_workspace_manifest(root_fd, "a" * 40)
    finally:
        os.close(root_fd)
