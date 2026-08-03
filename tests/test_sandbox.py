"""Controlled workspace boundary tests."""

from __future__ import annotations

import base64
import os
from pathlib import Path
import stat
import subprocess

import pytest

import openworkproof.mcp_server as mcp_server
import openworkproof.repo_tools as repo_tools


def _decode_path(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _source_snapshot() -> repo_tools.ParsedSourceArchive:
    files = (repo_tools.SourceFile("README.md", "100644", b"base\n"),)
    tree_oid = repo_tools.git_tree_oid(files)
    commit_raw = (
        f"tree {tree_oid}\n"
        "author OpenWorkProof <owp@example.invalid> 0 +0000\n"
        "committer OpenWorkProof <owp@example.invalid> 0 +0000\n"
        "\n"
        "base\n"
    ).encode("ascii")
    return repo_tools.ParsedSourceArchive(
        files=files,
        commit_raw=commit_raw,
        tree_oid=tree_oid,
        source_commit=repo_tools.git_commit_oid(commit_raw),
        artifact_sha256="a" * 64,
        artifact_size_bytes=1,
        shallow_bytes=None,
    )


def _candidate_git(
    candidate: repo_tools.CandidateWorkspace,
    *arguments: str,
) -> bytes:
    environment = {
        **os.environ,
        "GIT_AUTHOR_NAME": "OpenWorkProof",
        "GIT_AUTHOR_EMAIL": "owp@example.invalid",
        "GIT_AUTHOR_DATE": "1970-01-01T00:00:01Z",
        "GIT_COMMITTER_NAME": "OpenWorkProof",
        "GIT_COMMITTER_EMAIL": "owp@example.invalid",
        "GIT_COMMITTER_DATE": "1970-01-01T00:00:01Z",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
    }
    return subprocess.run(
        [
            "/usr/bin/git",
            f"--git-dir={candidate.git_dir}",
            f"--work-tree={candidate.worktree}",
            "-c",
            "core.hooksPath=/dev/null",
            *arguments,
        ],
        check=True,
        capture_output=True,
        env=environment,
        cwd=candidate.worktree,
    ).stdout


def _candidate_manifest(
    candidate: repo_tools.CandidateWorkspace,
    head_commit: str,
) -> tuple[repo_tools.WorkspaceManifest, str]:
    root_fd = os.open(
        candidate.worktree,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
    )
    try:
        manifest = repo_tools.scan_workspace_manifest(root_fd, head_commit)
    finally:
        os.close(root_fd)
    return manifest, repo_tools.workspace_manifest_digest(manifest)


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


def test_initialize_candidate_workspace_recreates_separate_git_checkpoint(
    tmp_path: Path,
) -> None:
    runtime_root = tmp_path / "runtime"
    runtime_root.mkdir(mode=0o700)
    source = _source_snapshot()
    candidate = repo_tools.initialize_candidate_workspace(
        repo_tools.WorkspaceInitRequest(
            runtime_root=runtime_root,
            workspace_id="1" * 64,
            source=source,
        )
    )

    assert candidate.head_commit == source.source_commit
    assert candidate.worktree.parent == candidate.git_dir.parent
    assert candidate.worktree != candidate.git_dir
    assert stat.S_IMODE(os.stat(candidate.worktree).st_mode) == 0o700
    assert stat.S_IMODE(os.stat(candidate.git_dir).st_mode) == 0o700
    assert not (candidate.worktree / ".git").exists()
    assert (candidate.worktree / "README.md").read_bytes() == b"base\n"
    completed = subprocess.run(
        [
            "/usr/bin/git",
            f"--git-dir={candidate.git_dir}",
            f"--work-tree={candidate.worktree}",
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
        ],
        check=True,
        capture_output=True,
    )
    assert completed.stdout == b""
    root_fd = os.open(
        candidate.worktree,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
    )
    try:
        manifest = repo_tools.scan_workspace_manifest(
            root_fd,
            source.source_commit,
        )
    finally:
        os.close(root_fd)
    assert repo_tools.workspace_manifest_digest(manifest) == (
        candidate.workspace_manifest_digest
    )


def test_rollback_candidate_workspace_restores_exact_parent_checkpoint(
    tmp_path: Path,
) -> None:
    source, candidate, candidate_commit, candidate_manifest_digest = (
        _patched_candidate(tmp_path, "2" * 64)
    )

    result = repo_tools.rollback_candidate_workspace(
        repo_tools.RollbackRequest(
            workspace=candidate,
            target_patch_receipt_id="a" * 64,
            target_patch_receipt_digest="b" * 64,
            failure_target_patch_receipt_id="a" * 64,
            failure_target_patch_receipt_digest="b" * 64,
            before_commit=candidate_commit,
            before_manifest_digest=candidate_manifest_digest,
            parent_commit=source.source_commit,
            parent_manifest_digest=candidate.workspace_manifest_digest,
        )
    )

    assert result.execution_status == "succeeded"
    assert result.before_commit == candidate_commit
    assert result.after_commit == source.source_commit
    assert result.after_manifest_digest == candidate.workspace_manifest_digest
    assert (candidate.worktree / "README.md").read_bytes() == b"base\n"
    assert _candidate_git(candidate, "status", "--porcelain=v1") == b""


def _patched_candidate(
    tmp_path: Path,
    workspace_id: str,
) -> tuple[
    repo_tools.ParsedSourceArchive,
    repo_tools.CandidateWorkspace,
    str,
    str,
]:
    runtime_root = tmp_path / "runtime"
    runtime_root.mkdir(mode=0o700)
    source = _source_snapshot()
    candidate = repo_tools.initialize_candidate_workspace(
        repo_tools.WorkspaceInitRequest(
            runtime_root=runtime_root,
            workspace_id=workspace_id,
            source=source,
        )
    )
    (candidate.worktree / "README.md").write_bytes(b"patched\n")
    _candidate_git(candidate, "add", "--all", "--", ".")
    tree_oid = _candidate_git(candidate, "write-tree").decode().strip()
    candidate_commit = _candidate_git(
        candidate,
        "commit-tree",
        tree_oid,
        "-p",
        source.source_commit,
        "-m",
        "patch",
    ).decode().strip()
    _candidate_git(candidate, "update-ref", "HEAD", candidate_commit)
    _candidate_git(candidate, "reset", "--hard", candidate_commit)
    _, candidate_manifest_digest = _candidate_manifest(
        candidate,
        candidate_commit,
    )
    return source, candidate, candidate_commit, candidate_manifest_digest


def _rollback_request(
    *,
    source: repo_tools.ParsedSourceArchive,
    candidate: repo_tools.CandidateWorkspace,
    candidate_commit: str,
    candidate_manifest_digest: str,
    failure_target_id: str = "a" * 64,
) -> repo_tools.RollbackRequest:
    return repo_tools.RollbackRequest(
        workspace=candidate,
        target_patch_receipt_id="a" * 64,
        target_patch_receipt_digest="b" * 64,
        failure_target_patch_receipt_id=failure_target_id,
        failure_target_patch_receipt_digest="b" * 64,
        before_commit=candidate_commit,
        before_manifest_digest=candidate_manifest_digest,
        parent_commit=source.source_commit,
        parent_manifest_digest=candidate.workspace_manifest_digest,
    )


def test_rollback_candidate_workspace_rejects_wrong_failure_target_without_mutation(
    tmp_path: Path,
) -> None:
    source, candidate, candidate_commit, manifest_digest = _patched_candidate(
        tmp_path,
        "3" * 64,
    )

    with pytest.raises(repo_tools.CandidateWorkspaceError, match="target binding"):
        repo_tools.rollback_candidate_workspace(
            _rollback_request(
                source=source,
                candidate=candidate,
                candidate_commit=candidate_commit,
                candidate_manifest_digest=manifest_digest,
                failure_target_id="c" * 64,
            )
        )

    assert _candidate_git(candidate, "rev-parse", "HEAD").decode().strip() == (
        candidate_commit
    )
    assert (candidate.worktree / "README.md").read_bytes() == b"patched\n"


def test_rollback_candidate_workspace_rejects_noncanonical_control_without_mutation(
    tmp_path: Path,
) -> None:
    source, candidate, candidate_commit, manifest_digest = _patched_candidate(
        tmp_path,
        "6" * 64,
    )
    control_path = candidate.candidate_root / "control.json"
    control_path.write_bytes(b" " + control_path.read_bytes())
    control_path.chmod(0o600)

    with pytest.raises(
        repo_tools.CandidateWorkspaceError,
        match="control record",
    ):
        repo_tools.rollback_candidate_workspace(
            _rollback_request(
                source=source,
                candidate=candidate,
                candidate_commit=candidate_commit,
                candidate_manifest_digest=manifest_digest,
            )
        )

    assert _candidate_git(candidate, "rev-parse", "HEAD").decode().strip() == (
        candidate_commit
    )
    assert (candidate.worktree / "README.md").read_bytes() == b"patched\n"


def test_rollback_candidate_workspace_restores_candidate_after_postcheck_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, candidate, candidate_commit, manifest_digest = _patched_candidate(
        tmp_path,
        "4" * 64,
    )
    real_verify = repo_tools._verify_candidate_checkpoint
    calls = 0

    def fail_parent_once(*args, **kwargs) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise repo_tools.CandidateWorkspaceError("injected postcheck failure")
        real_verify(*args, **kwargs)

    monkeypatch.setattr(
        repo_tools,
        "_verify_candidate_checkpoint",
        fail_parent_once,
    )
    result = repo_tools.rollback_candidate_workspace(
        _rollback_request(
            source=source,
            candidate=candidate,
            candidate_commit=candidate_commit,
            candidate_manifest_digest=manifest_digest,
        )
    )

    assert calls == 3
    assert result.execution_status == "failed"
    assert result.after_commit == candidate_commit
    assert result.after_manifest_digest == manifest_digest
    assert (candidate.worktree / "README.md").read_bytes() == b"patched\n"
    assert _candidate_git(candidate, "status", "--porcelain=v1") == b""


def test_candidate_rollback_handler_adapts_verified_git_result(
    tmp_path: Path,
) -> None:
    source, candidate, candidate_commit, manifest_digest = _patched_candidate(
        tmp_path,
        "5" * 64,
    )
    factory = getattr(mcp_server, "make_candidate_rollback_handler", None)
    assert callable(factory)
    handler = factory(
        workspace=candidate,
        failure_target_patch_receipt_id="a" * 64,
        failure_target_patch_receipt_digest="b" * 64,
        before_commit=candidate_commit,
        before_manifest_digest=manifest_digest,
        parent_commit=source.source_commit,
        parent_manifest_digest=candidate.workspace_manifest_digest,
    )

    result = handler(
        mcp_server.RollbackCommand(
            target_patch_receipt_id="a" * 64,
            target_patch_digest="b" * 64,
            before_commit=candidate_commit,
        )
    )

    assert isinstance(result, mcp_server.RollbackHandlerResult)
    assert result.execution_status == "succeeded"
    assert result.after_commit == source.source_commit
    assert result.after_manifest_digest == candidate.workspace_manifest_digest
