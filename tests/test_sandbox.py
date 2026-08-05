"""Controlled workspace boundary tests."""

from __future__ import annotations

import base64
import copy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import time
from collections.abc import Callable

import pytest
import rfc8785

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


def _replay_profile(
    source: repo_tools.ParsedSourceArchive,
) -> tuple[repo_tools.ReplayProfile, str]:
    profile = repo_tools.ReplayProfile(
        schema_version="openworkproof-replay-profile/0.1",
        patch_profile_id="openworkproof/canonical-text-patch/0.1",
        object_format="sha1",
        source_artifact_sha256=source.artifact_sha256,
        trusted_helper_image_digest="sha256:" + "b" * 64,
        author_name="OpenWorkProof Sidecar",
        author_email="sidecar@openworkproof.invalid",
        commit_message_prefix="OpenWorkProof patch ",
        timestamp_rule="receipt-occurred-at-utc-seconds",
        worktree_profile="linux-posix-case-sensitive-v0.1",
    )
    digest = hashlib.sha256(
        rfc8785.dumps(
            {
                "domain": "openworkproof/replay-profile/v0.1",
                "profile": profile.model_dump(mode="json"),
            }
        )
    ).hexdigest()
    return profile, digest


def _bound_source(
    work_order_dict: dict,
) -> tuple[bytes, repo_tools.WorkOrder, repo_tools.ParsedSourceArchive]:
    snapshot = _source_snapshot()
    source_bytes = repo_tools.write_source_archive(
        snapshot.files,
        snapshot.commit_raw,
    )
    candidate = copy.deepcopy(work_order_dict)
    artifact_digest = hashlib.sha256(source_bytes).hexdigest()
    candidate["source_commit"] = snapshot.source_commit
    candidate["source_artifact"]["sha256"] = artifact_digest
    candidate["source_artifact"]["size_bytes"] = len(source_bytes)
    candidate["replay_profile"]["source_artifact_sha256"] = artifact_digest
    candidate["replay_profile_digest"] = hashlib.sha256(
        rfc8785.dumps(
            {
                "domain": "openworkproof/replay-profile/v0.1",
                "profile": candidate["replay_profile"],
            }
        )
    ).hexdigest()
    work_order = repo_tools.WorkOrder.model_validate(candidate)
    parsed = repo_tools.parse_source_archive(
        source_bytes,
        work_order,
        trusted_helper_image_digest=(
            work_order.replay_profile.trusted_helper_image_digest
        ),
    )
    return source_bytes, work_order, parsed


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


def _modify_readme_patch() -> bytes:
    old_oid = repo_tools.git_blob_oid(b"base\n")
    new_oid = repo_tools.git_blob_oid(b"patched\n")
    return (
        "diff --git a/README.md b/README.md\n"
        f"index {old_oid}..{new_oid} 100644\n"
        "--- a/README.md\n"
        "+++ b/README.md\n"
        "@@ -1 +1 @@\n"
        "-base\n"
        "+patched\n"
    ).encode("ascii")


def _patch_request(
    source: repo_tools.ParsedSourceArchive,
    candidate: repo_tools.CandidateWorkspace,
    *,
    patch: bytes | None = None,
    target_paths: tuple[str, ...] = ("README.md",),
) -> repo_tools.PatchRequest:
    patch_bytes = _modify_readme_patch() if patch is None else patch
    profile, profile_digest = _replay_profile(source)
    return repo_tools.PatchRequest(
        workspace=candidate,
        patch_bytes=patch_bytes,
        expected_patch_digest=hashlib.sha256(patch_bytes).hexdigest(),
        expected_patch_size_bytes=len(patch_bytes),
        declared_target_paths=target_paths,
        parent_commit=source.source_commit,
        parent_manifest_digest=candidate.workspace_manifest_digest,
        occurred_at="2026-01-01T00:00:01Z",
        replay_profile=profile,
        replay_profile_digest=profile_digest,
    )


def test_apply_patch_in_candidate_workspace_creates_exact_git_checkpoint(
    tmp_path: Path,
) -> None:
    runtime_root = tmp_path / "runtime"
    runtime_root.mkdir(mode=0o700)
    source = _source_snapshot()
    candidate = repo_tools.initialize_candidate_workspace(
        repo_tools.WorkspaceInitRequest(
            runtime_root=runtime_root,
            workspace_id="7" * 64,
            source=source,
        )
    )
    patch = _modify_readme_patch()

    result = repo_tools.apply_patch_in_candidate_workspace(
        _patch_request(source, candidate)
    )

    assert result.parent_commit == source.source_commit
    assert result.changed_paths == ("README.md",)
    assert result.patch_digest == hashlib.sha256(patch).hexdigest()
    assert result.patch_size_bytes == len(patch)
    assert (candidate.worktree / "README.md").read_bytes() == b"patched\n"
    assert _candidate_git(candidate, "rev-parse", "HEAD").decode().strip() == (
        result.candidate_commit
    )
    assert _candidate_git(candidate, "status", "--porcelain=v1") == b""
    _, manifest_digest = _candidate_manifest(
        candidate,
        result.candidate_commit,
    )
    assert result.workspace_manifest_digest == manifest_digest
    assert result.evidence.workspace_manifest_digest == manifest_digest


def test_apply_patch_in_candidate_workspace_materializes_create_and_delete(
    tmp_path: Path,
) -> None:
    runtime_root = tmp_path / "runtime"
    runtime_root.mkdir(mode=0o700)
    source = _source_snapshot()
    candidate = repo_tools.initialize_candidate_workspace(
        repo_tools.WorkspaceInitRequest(
            runtime_root=runtime_root,
            workspace_id="9" * 64,
            source=source,
        )
    )
    old_oid = repo_tools.git_blob_oid(b"base\n")
    new_oid = repo_tools.git_blob_oid(b"new\n")
    patch = (
        "diff --git a/README.md b/README.md\n"
        "deleted file mode 100644\n"
        f"index {old_oid}..{'0' * 40}\n"
        "--- a/README.md\n"
        "+++ /dev/null\n"
        "@@ -1 +0,0 @@\n"
        "-base\n"
        "diff --git a/new.txt b/new.txt\n"
        "new file mode 100644\n"
        f"index {'0' * 40}..{new_oid}\n"
        "--- /dev/null\n"
        "+++ b/new.txt\n"
        "@@ -0,0 +1 @@\n"
        "+new\n"
    ).encode("ascii")

    result = repo_tools.apply_patch_in_candidate_workspace(
        _patch_request(
            source,
            candidate,
            patch=patch,
            target_paths=("README.md", "new.txt"),
        )
    )

    assert result.changed_paths == ("README.md", "new.txt")
    assert not (candidate.worktree / "README.md").exists()
    assert (candidate.worktree / "new.txt").read_bytes() == b"new\n"
    assert _candidate_git(candidate, "status", "--porcelain=v1") == b""


def test_apply_patch_in_candidate_workspace_restores_parent_after_postcheck_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime_root = tmp_path / "runtime"
    runtime_root.mkdir(mode=0o700)
    source = _source_snapshot()
    candidate = repo_tools.initialize_candidate_workspace(
        repo_tools.WorkspaceInitRequest(
            runtime_root=runtime_root,
            workspace_id="8" * 64,
            source=source,
        )
    )
    real_verify = repo_tools._verify_candidate_checkpoint
    calls = 0

    def fail_candidate_once(*args, **kwargs) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise repo_tools.CandidateWorkspaceError("injected postcheck failure")
        real_verify(*args, **kwargs)

    monkeypatch.setattr(
        repo_tools,
        "_verify_candidate_checkpoint",
        fail_candidate_once,
    )

    with pytest.raises(
        repo_tools.CandidateWorkspaceError,
        match="injected postcheck failure",
    ):
        repo_tools.apply_patch_in_candidate_workspace(
            _patch_request(source, candidate)
        )

    assert calls == 3
    assert _candidate_git(candidate, "rev-parse", "HEAD").decode().strip() == (
        source.source_commit
    )
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
    result = repo_tools.apply_patch_in_candidate_workspace(
        _patch_request(source, candidate)
    )
    return (
        source,
        candidate,
        result.candidate_commit,
        result.workspace_manifest_digest,
    )


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


def test_rebuild_candidate_workspace_replaces_a_mismatched_checkpoint(
    tmp_path: Path,
    work_order_dict: dict,
) -> None:
    runtime_root = tmp_path / "runtime"
    runtime_root.mkdir(mode=0o700)
    source_bytes, work_order, source = _bound_source(work_order_dict)
    workspace_id = "d" * 64
    candidate = repo_tools.initialize_candidate_workspace(
        repo_tools.WorkspaceInitRequest(
            runtime_root=runtime_root,
            workspace_id=workspace_id,
            source=source,
        )
    )
    (candidate.worktree / "README.md").write_bytes(b"tampered\n")

    rebuilt = repo_tools.rebuild_candidate_workspace(
        repo_tools.WorkspaceRebuildRequest(
            runtime_root=runtime_root,
            workspace_id=workspace_id,
            source_bytes=source_bytes,
            work_order=work_order,
            trusted_helper_image_digest=(
                work_order.replay_profile.trusted_helper_image_digest
            ),
            steps=(),
        )
    )

    assert rebuilt.candidate_root == candidate.candidate_root
    assert rebuilt.head_commit == source.source_commit
    assert (rebuilt.worktree / "README.md").read_bytes() == b"base\n"
    assert _candidate_git(rebuilt, "status", "--porcelain=v1") == b""
    assert not (runtime_root / f"{workspace_id}.rebuild").exists()


def test_rebuild_candidate_workspace_replays_committed_patch_checkpoint(
    tmp_path: Path,
    work_order_dict: dict,
) -> None:
    source_bytes, work_order, source = _bound_source(work_order_dict)
    seed_root = tmp_path / "seed"
    seed_root.mkdir(mode=0o700)
    seed = repo_tools.initialize_candidate_workspace(
        repo_tools.WorkspaceInitRequest(
            runtime_root=seed_root,
            workspace_id="f" * 64,
            source=source,
        )
    )
    patch = _modify_readme_patch()
    applied = repo_tools.apply_patch_in_candidate_workspace(
        repo_tools.PatchRequest(
            workspace=seed,
            patch_bytes=patch,
            expected_patch_digest=hashlib.sha256(patch).hexdigest(),
            expected_patch_size_bytes=len(patch),
            declared_target_paths=("README.md",),
            parent_commit=source.source_commit,
            parent_manifest_digest=seed.workspace_manifest_digest,
            occurred_at="2026-01-01T00:00:01Z",
            replay_profile=work_order.replay_profile,
            replay_profile_digest=work_order.replay_profile_digest,
        )
    )
    step = repo_tools.ReplayPatchStep(
        patch_bytes=patch,
        target_paths=("README.md",),
        occurred_at="2026-01-01T00:00:01Z",
        evidence=applied.evidence,
        patch_receipt_id="1" * 64,
        patch_receipt_digest="2" * 64,
    )
    runtime_root = tmp_path / "runtime"
    runtime_root.mkdir(mode=0o700)

    rebuilt = repo_tools.rebuild_candidate_workspace(
        repo_tools.WorkspaceRebuildRequest(
            runtime_root=runtime_root,
            workspace_id="a" * 64,
            source_bytes=source_bytes,
            work_order=work_order,
            trusted_helper_image_digest=(
                work_order.replay_profile.trusted_helper_image_digest
            ),
            steps=(step,),
        )
    )

    assert _candidate_git(rebuilt, "rev-parse", "HEAD").decode().strip() == (
        applied.candidate_commit
    )
    assert (rebuilt.worktree / "README.md").read_bytes() == b"patched\n"

    rollback_root = tmp_path / "rollback"
    rollback_root.mkdir(mode=0o700)
    restored = repo_tools.rebuild_candidate_workspace(
        repo_tools.WorkspaceRebuildRequest(
            runtime_root=rollback_root,
            workspace_id="3" * 64,
            source_bytes=source_bytes,
            work_order=work_order,
            trusted_helper_image_digest=(
                work_order.replay_profile.trusted_helper_image_digest
            ),
            steps=(
                step,
                repo_tools.ReplayRollbackStep(
                    target_patch_receipt_id=step.patch_receipt_id,
                    target_patch_receipt_digest=step.patch_receipt_digest,
                    before_commit=applied.candidate_commit,
                    after_commit=source.source_commit,
                    after_manifest_digest=seed.workspace_manifest_digest,
                ),
            ),
        )
    )

    assert _candidate_git(restored, "rev-parse", "HEAD").decode().strip() == (
        source.source_commit
    )
    assert (restored.worktree / "README.md").read_bytes() == b"base\n"


def test_rebuild_candidate_workspace_restores_old_path_when_recreation_fails(
    tmp_path: Path,
    work_order_dict: dict,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime_root = tmp_path / "runtime"
    runtime_root.mkdir(mode=0o700)
    source_bytes, work_order, source = _bound_source(work_order_dict)
    workspace_id = "b" * 64
    candidate = repo_tools.initialize_candidate_workspace(
        repo_tools.WorkspaceInitRequest(
            runtime_root=runtime_root,
            workspace_id=workspace_id,
            source=source,
        )
    )
    (candidate.worktree / "README.md").write_bytes(b"tampered\n")

    def fail_recreation(*args, **kwargs):
        raise repo_tools.CandidateWorkspaceError("injected rebuild failure")

    monkeypatch.setattr(
        repo_tools,
        "initialize_candidate_workspace",
        fail_recreation,
    )
    with pytest.raises(
        repo_tools.CandidateWorkspaceError,
        match="injected rebuild failure",
    ):
        repo_tools.rebuild_candidate_workspace(
            repo_tools.WorkspaceRebuildRequest(
                runtime_root=runtime_root,
                workspace_id=workspace_id,
                source_bytes=source_bytes,
                work_order=work_order,
                trusted_helper_image_digest=(
                    work_order.replay_profile.trusted_helper_image_digest
                ),
                steps=(),
            )
        )

    assert (candidate.worktree / "README.md").read_bytes() == b"tampered\n"
    assert not (runtime_root / f"{workspace_id}.rebuild").exists()


def test_destroy_candidate_workspace_requires_and_removes_exact_checkpoint(
    tmp_path: Path,
) -> None:
    runtime_root = tmp_path / "runtime"
    runtime_root.mkdir(mode=0o700)
    source = _source_snapshot()
    candidate = repo_tools.initialize_candidate_workspace(
        repo_tools.WorkspaceInitRequest(
            runtime_root=runtime_root,
            workspace_id="e" * 64,
            source=source,
        )
    )

    result = repo_tools.destroy_candidate_workspace(
        repo_tools.WorkspaceDestroyRequest(
            workspace=candidate,
            expected_head_commit=source.source_commit,
            expected_manifest_digest=candidate.workspace_manifest_digest,
            lifecycle_state="terminal",
        )
    )

    assert result.workspace_id == candidate.workspace_id
    assert result.destroyed is True
    assert not candidate.candidate_root.exists()


def test_destroy_candidate_workspace_rejects_wrong_checkpoint_without_removal(
    tmp_path: Path,
) -> None:
    runtime_root = tmp_path / "runtime"
    runtime_root.mkdir(mode=0o700)
    source = _source_snapshot()
    candidate = repo_tools.initialize_candidate_workspace(
        repo_tools.WorkspaceInitRequest(
            runtime_root=runtime_root,
            workspace_id="c" * 64,
            source=source,
        )
    )

    with pytest.raises(
        repo_tools.CandidateWorkspaceError,
        match="checkpoint",
    ):
        repo_tools.destroy_candidate_workspace(
            repo_tools.WorkspaceDestroyRequest(
                workspace=candidate,
                expected_head_commit=source.source_commit,
                expected_manifest_digest="0" * 64,
                lifecycle_state="terminal",
            )
        )

    assert candidate.candidate_root.is_dir()
    assert (candidate.worktree / "README.md").read_bytes() == b"base\n"


def _process_request(
    tmp_path: Path,
    script: str,
) -> repo_tools.ProcessRequest:
    return repo_tools.ProcessRequest(
        argv=(sys.executable, "-c", script),
        working_directory=tmp_path,
        environment={"LC_ALL": "C", "PATH": "/usr/bin:/bin"},
    )


def test_run_bounded_process_returns_exact_small_stdout_and_stderr(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = repo_tools.SandboxPolicy()
    assert policy.max_combined_stdio_bytes == 1_048_576
    assert policy.wall_clock_timeout_seconds == 120
    assert policy.cleanup_grace_seconds == 10
    with pytest.raises(TypeError):
        repo_tools.SandboxPolicy(max_combined_stdio_bytes=1)
    tampered_policy = repo_tools.SandboxPolicy()
    object.__setattr__(tampered_policy, "max_combined_stdio_bytes", 1)
    with pytest.raises(
        repo_tools.ProcessExecutionError,
        match="binding",
    ):
        repo_tools.run_bounded_process(
            _process_request(tmp_path, "raise SystemExit(0)"),
            tampered_policy,
        )

    def forbid_unbounded_communicate(*args, **kwargs):
        raise AssertionError("bounded capture called communicate")

    monkeypatch.setattr(
        subprocess.Popen,
        "communicate",
        forbid_unbounded_communicate,
    )

    result = repo_tools.run_bounded_process(
        _process_request(
            tmp_path,
            "import os; os.write(1, b'out'); os.write(2, b'err')",
        ),
        policy,
    )

    assert result.failure_code is None
    assert result.exit_code == 0
    assert result.stdout_prefix == b"out"
    assert result.stderr_prefix == b"err"
    assert result.combined_bytes_captured == 6


def test_run_bounded_process_does_not_inherit_host_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENWORKPROOF_HOST_SECRET", "must-not-leak")

    result = repo_tools.run_bounded_process(
        _process_request(
            tmp_path,
            (
                "import os; print("
                "os.environ.get('OPENWORKPROOF_HOST_SECRET', 'missing'))"
            ),
        ),
        repo_tools.SandboxPolicy(),
    )

    assert result.exit_code == 0
    assert result.stdout_prefix == b"missing\n"


def test_run_bounded_process_returns_actual_nonzero_exit_code(
    tmp_path: Path,
) -> None:
    result = repo_tools.run_bounded_process(
        _process_request(tmp_path, "raise SystemExit(7)"),
        repo_tools.SandboxPolicy(),
    )

    assert result.failure_code is None
    assert result.exit_code == 7


def test_run_bounded_process_accepts_exact_stdio_capacity(
    tmp_path: Path,
) -> None:
    result = repo_tools.run_bounded_process(
        _process_request(
            tmp_path,
            (
                "import os\n"
                "chunk = b'x' * 65536\n"
                "for _ in range(16):\n"
                "    view = memoryview(chunk)\n"
                "    while view:\n"
                "        view = view[os.write(1, view):]\n"
            ),
        ),
        repo_tools.SandboxPolicy(),
    )

    assert result.failure_code is None
    assert result.exit_code == 0
    assert len(result.stdout_prefix) == 1_048_576
    assert result.combined_bytes_captured == 1_048_576


def test_run_bounded_process_enforces_one_shared_stdio_limit(
    tmp_path: Path,
) -> None:
    script = (
        "import os\n"
        "chunk = b'x' * 4096\n"
        "for _ in range(160):\n"
        "    os.write(1, chunk)\n"
        "    os.write(2, chunk)\n"
    )

    result = repo_tools.run_bounded_process(
        _process_request(tmp_path, script),
        repo_tools.SandboxPolicy(),
    )

    assert result.failure_code == "OUTPUT_LIMIT"
    assert result.exit_code is not None
    assert len(result.stdout_prefix) + len(result.stderr_prefix) == 1_048_576
    assert result.combined_bytes_captured == 1_048_576


def test_run_bounded_process_returns_timeout_after_frozen_deadline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_monotonic = time.monotonic
    calls = 0

    def jump_past_deadline_once() -> float:
        nonlocal calls
        calls += 1
        if calls == 2:
            return real_monotonic() + 121
        return real_monotonic()

    monkeypatch.setattr(
        repo_tools.time,
        "monotonic",
        jump_past_deadline_once,
    )

    result = repo_tools.run_bounded_process(
        _process_request(tmp_path, "import time; time.sleep(30)"),
        repo_tools.SandboxPolicy(),
    )

    assert result.failure_code == "TIMEOUT"
    assert result.exit_code is not None
    assert result.combined_bytes_captured == 0


def test_run_bounded_process_output_limit_kills_descendant_process_group(
    tmp_path: Path,
) -> None:
    marker = tmp_path / "descendant-escaped.txt"
    descendant = (
        "import time\n"
        "from pathlib import Path\n"
        "time.sleep(0.5)\n"
        f"Path({str(marker)!r}).write_text('escaped')\n"
    )
    script = (
        "import os, subprocess, sys\n"
        f"subprocess.Popen([sys.executable, '-c', {descendant!r}])\n"
        "chunk = b'x' * 65536\n"
        "while True:\n"
        "    os.write(1, chunk)\n"
    )

    result = repo_tools.run_bounded_process(
        _process_request(tmp_path, script),
        repo_tools.SandboxPolicy(),
    )
    time.sleep(0.7)

    assert result.failure_code == "OUTPUT_LIMIT"
    assert not marker.exists()


def _docker_plan(
    *,
    image_reference: str = (
        "registry.example/openworkproof/test-runner@sha256:" + "a" * 64
    ),
    container_name: str = "owp-container-01",
    workspace_volume_name: str = "owp-workspace-01",
    output_volume_name: str = "owp-output-01",
    ownership_token: str = "b" * 64,
) -> repo_tools.DockerExecutionPlan:
    return repo_tools.derive_docker_execution_plan(
        docker_binary=Path("/usr/local/bin/docker"),
        image_reference=image_reference,
        container_name=container_name,
        workspace_volume_name=workspace_volume_name,
        output_volume_name=output_volume_name,
        ownership_token=ownership_token,
        command=("/bin/sh", "-c", "printf containment-ok"),
    )


def _run_tests_container_observation(
    binding: repo_tools.RunTestsDockerBinding,
    *,
    status: str,
    ever_started: bool,
    contract_digest: str = "c" * 64,
) -> dict[str, object]:
    return {
        "name": binding.container_name,
        "ownership_token": binding.ownership_token,
        "execution_id": binding.execution_id,
        "execution_contract_digest": contract_digest,
        "status": status,
        "ever_started": ever_started,
        "immutable_image_matches": True,
        "config_matches": True,
        "mounts_match": True,
    }


def _run_tests_resource_observation(
    *,
    name: str,
    binding: repo_tools.RunTestsDockerBinding,
) -> dict[str, object]:
    return {
        "name": name,
        "ownership_token": binding.ownership_token,
        "configuration_matches": True,
    }


def _run_tests_started(
    binding: repo_tools.RunTestsDockerBinding,
    *,
    contract_digest: str = "c" * 64,
) -> repo_tools.RunTestsStartedEnvelope:
    return repo_tools.RunTestsStartedEnvelope(
        execution_id=binding.execution_id,
        execution_contract_digest=contract_digest,
    )


def _run_tests_result(
    binding: repo_tools.RunTestsDockerBinding,
    *,
    contract_digest: str = "c" * 64,
) -> repo_tools.RunTestsResultEnvelope:
    empty_digest = hashlib.sha256(b"").hexdigest()
    return repo_tools.RunTestsResultEnvelope(
        execution_id=binding.execution_id,
        execution_contract_digest=contract_digest,
        actual_exit_code=0,
        failure_code=None,
        stdout_bytes=0,
        stdout_sha256=empty_digest,
        stderr_bytes=0,
        stderr_sha256=empty_digest,
    )


def _run_tests_observation(
    binding: repo_tools.RunTestsDockerBinding,
    *,
    status: str | None = None,
    ever_started: bool = False,
    contract_digest: str = "c" * 64,
    started: repo_tools.RunTestsStartedEnvelope | None = None,
    result: repo_tools.RunTestsResultEnvelope | object | None = None,
    staging: bool = False,
    workspace: bool = False,
    output: bool = False,
) -> repo_tools.RunTestsDockerObservation:
    return repo_tools.RunTestsDockerObservation(
        staging_container=(
            _run_tests_resource_observation(
                name=binding.staging_container_name,
                binding=binding,
            )
            if staging
            else None
        ),
        container=(
            _run_tests_container_observation(
                binding,
                status=status,
                ever_started=ever_started,
                contract_digest=contract_digest,
            )
            if status is not None
            else None
        ),
        workspace_volume=(
            _run_tests_resource_observation(
                name=binding.workspace_volume_name,
                binding=binding,
            )
            if workspace
            else None
        ),
        output_volume=(
            _run_tests_resource_observation(
                name=binding.output_volume_name,
                binding=binding,
            )
            if output
            else None
        ),
        started=started,
        result=result,
    )


class _RunTestsAlwaysEqual:
    def __eq__(self, other: object) -> bool:
        return True


class _RunTestsExplodingEquality:
    def __eq__(self, other: object) -> bool:
        raise AssertionError("adversarial equality was dispatched")


class _RunTestsStrSubclass(str):
    pass


class _RunTestsEqualKey:
    def __init__(self, value: str) -> None:
        self._value = value

    def __hash__(self) -> int:
        return hash(self._value)

    def __eq__(self, other: object) -> bool:
        return other == self._value


class _RunTestsExplodingKey:
    def __init__(self, value: str) -> None:
        self._value = value

    def __hash__(self) -> int:
        return hash(self._value)

    def __eq__(self, other: object) -> bool:
        raise AssertionError("adversarial key equality was dispatched")


def test_derive_run_tests_docker_binding_is_stable_and_closed() -> None:
    binding = repo_tools.derive_run_tests_docker_binding("a" * 64)

    assert binding.execution_id == "a" * 64
    assert binding.container_name == "owp-run-" + "a" * 32
    assert binding.staging_container_name == "owp-stage-" + "a" * 32
    assert binding.workspace_volume_name == "owp-workspace-" + "a" * 32
    assert binding.output_volume_name == "owp-output-" + "a" * 32
    assert binding.ownership_token == hashlib.sha256(
        b"openworkproof/docker-run/v0.1\x00" + b"a" * 64
    ).hexdigest()
    assert max(
        len(name.encode("ascii"))
        for name in (
            binding.container_name,
            binding.staging_container_name,
            binding.workspace_volume_name,
            binding.output_volume_name,
        )
    ) < 64


@pytest.mark.parametrize("execution_id", ("", "a" * 63, "A" * 64, True))
def test_derive_run_tests_docker_binding_rejects_invalid_execution_id(
    execution_id: object,
) -> None:
    with pytest.raises(ValueError, match="execution id"):
        repo_tools.derive_run_tests_docker_binding(execution_id)


@pytest.mark.parametrize(
    ("journal_state", "observation_factory", "receipt_state", "expected"),
    (
        (
            "RESERVED",
            lambda b: _run_tests_observation(b),
            "ABSENT",
            "SAFE_TO_RETRY",
        ),
        (
            "RESERVED",
            lambda b: _run_tests_observation(b, staging=True, workspace=True),
            "ABSENT",
            "CLEAN_PRESTART",
        ),
        (
            "RESERVED",
            lambda b: _run_tests_observation(
                b, status="created", workspace=True, output=True
            ),
            "ABSENT",
            "CLEAN_PRESTART",
        ),
        (
            "STARTED_UNCONFIRMED",
            lambda b: _run_tests_observation(
                b, status="created", workspace=True, output=True
            ),
            "ABSENT",
            "CLEAN_PRESTART",
        ),
        (
            "RESERVED",
            lambda b: _run_tests_observation(
                b,
                status="running",
                ever_started=True,
                workspace=True,
                output=True,
            ),
            "ABSENT",
            "WAIT_RUNNING",
        ),
        (
            "STARTED_UNCONFIRMED",
            lambda b: _run_tests_observation(
                b,
                status="paused",
                ever_started=True,
                started=_run_tests_started(b),
                workspace=True,
                output=True,
            ),
            "ABSENT",
            "WAIT_RUNNING",
        ),
        (
            "STARTED_UNCONFIRMED",
            lambda b: _run_tests_observation(
                b,
                status="restarting",
                ever_started=True,
                started=_run_tests_started(b),
                workspace=True,
                output=True,
            ),
            "ABSENT",
            "WAIT_RUNNING",
        ),
        (
            "STARTED_UNCONFIRMED",
            lambda b: _run_tests_observation(
                b,
                status="dead",
                ever_started=True,
                started=_run_tests_started(b),
                workspace=True,
                output=True,
            ),
            "ABSENT",
            "UNRESOLVED",
        ),
        (
            "STARTED_UNCONFIRMED",
            lambda b: _run_tests_observation(
                b,
                status="exited",
                ever_started=True,
                started=_run_tests_started(b),
                result=_run_tests_result(b),
                workspace=True,
                output=True,
            ),
            "ABSENT",
            "RESUME_RESULT",
        ),
        (
            "RESERVED",
            lambda b: _run_tests_observation(
                b,
                status="exited",
                ever_started=True,
                started=_run_tests_started(b),
                result=_run_tests_result(b),
                workspace=True,
                output=True,
            ),
            "ABSENT",
            "RESUME_RESULT",
        ),
        (
            "STARTED_UNCONFIRMED",
            lambda b: _run_tests_observation(
                b,
                status="exited",
                ever_started=True,
                started=_run_tests_started(b),
                workspace=True,
                output=True,
            ),
            "ABSENT",
            "UNRESOLVED",
        ),
        (
            "STARTED_UNCONFIRMED",
            lambda b: _run_tests_observation(
                b,
                status="exited",
                ever_started=True,
                started=_run_tests_started(b),
                result={"malformed": True},
                workspace=True,
                output=True,
            ),
            "ABSENT",
            "UNRESOLVED",
        ),
        (
            "STARTED_UNCONFIRMED",
            lambda b: _run_tests_observation(
                b,
                status="exited",
                ever_started=True,
                contract_digest="d" * 64,
                started=_run_tests_started(b, contract_digest="d" * 64),
                result=_run_tests_result(b, contract_digest="d" * 64),
                workspace=True,
                output=True,
            ),
            "ABSENT",
            "UNRESOLVED",
        ),
        (
            "STARTED_UNCONFIRMED",
            lambda b: _run_tests_observation(
                b,
                status="exited",
                ever_started=True,
                started=_run_tests_started(b),
                result=_run_tests_result(b),
                workspace=True,
                output=True,
            ),
            "MATCH",
            "CLEAN_COMMITTED",
        ),
        (
            "RESERVED",
            lambda b: _run_tests_observation(b),
            "MATCH",
            "CLEAN_COMMITTED",
        ),
    ),
)
def test_reconcile_run_tests_returns_exact_pure_state_table_action(
    journal_state: str,
    observation_factory: object,
    receipt_state: str,
    expected: str,
) -> None:
    binding = repo_tools.derive_run_tests_docker_binding("a" * 64)
    observation = observation_factory(binding)

    action = repo_tools.reconcile_run_tests_docker_execution(
        journal_state,
        binding,
        observation,
        expected_execution_contract_digest="c" * 64,
        receipt_state=receipt_state,
    )

    assert action == expected
    assert action in {
        "SAFE_TO_RETRY",
        "CLEAN_PRESTART",
        "WAIT_RUNNING",
        "RESUME_RESULT",
        "CLEAN_COMMITTED",
        "UNRESOLVED",
    }
    assert not hasattr(action, "commands")


@pytest.mark.parametrize(
    "observation_factory",
    (
        lambda b: _run_tests_observation(b, staging=True),
        lambda b: _run_tests_observation(b, workspace=True),
        lambda b: _run_tests_observation(b, output=True),
        lambda b: _run_tests_observation(b, status="created"),
        lambda b: _run_tests_observation(
            b, status="created", workspace=True
        ),
        lambda b: _run_tests_observation(b, status="created", output=True),
        lambda b: _run_tests_observation(
            b,
            status="created",
            staging=True,
            workspace=True,
            output=True,
        ),
    ),
)
def test_reconcile_run_tests_cleans_every_owned_reserved_partial_position(
    observation_factory: object,
) -> None:
    binding = repo_tools.derive_run_tests_docker_binding("a" * 64)

    assert repo_tools.reconcile_run_tests_docker_execution(
        "RESERVED",
        binding,
        observation_factory(binding),
        expected_execution_contract_digest="c" * 64,
        receipt_state="ABSENT",
    ) == "CLEAN_PRESTART"


@pytest.mark.parametrize(
    ("observation_factory", "expected"),
    (
        (
            lambda b: _run_tests_observation(
                b, status="running", ever_started=True
            ),
            "UNRESOLVED",
        ),
        (
            lambda b: _run_tests_observation(
                b,
                status="exited",
                ever_started=True,
                started=_run_tests_started(b),
                result=_run_tests_result(b),
                staging=True,
            ),
            "UNRESOLVED",
        ),
        (
            lambda b: _run_tests_observation(
                b,
                status="created",
                started=_run_tests_started(b),
                staging=True,
            ),
            "UNRESOLVED",
        ),
    ),
)
def test_reconcile_run_tests_partial_started_evidence_uses_started_rules(
    observation_factory: object,
    expected: str,
) -> None:
    binding = repo_tools.derive_run_tests_docker_binding("a" * 64)

    assert repo_tools.reconcile_run_tests_docker_execution(
        "RESERVED",
        binding,
        observation_factory(binding),
        expected_execution_contract_digest="c" * 64,
        receipt_state="ABSENT",
    ) == expected


@pytest.mark.parametrize(
    ("staging", "workspace", "output"),
    (
        (False, False, False),
        (False, True, False),
        (False, False, True),
        (True, False, False),
        (True, True, False),
        (True, False, True),
        (True, True, True),
    ),
)
def test_reconcile_run_tests_exited_result_requires_complete_resources(
    staging: bool,
    workspace: bool,
    output: bool,
) -> None:
    binding = repo_tools.derive_run_tests_docker_binding("a" * 64)

    assert repo_tools.reconcile_run_tests_docker_execution(
        "STARTED_UNCONFIRMED",
        binding,
        _run_tests_observation(
            binding,
            status="exited",
            ever_started=True,
            started=_run_tests_started(binding),
            result=_run_tests_result(binding),
            staging=staging,
            workspace=workspace,
            output=output,
        ),
        expected_execution_contract_digest="c" * 64,
        receipt_state="ABSENT",
    ) == "UNRESOLVED"


def test_reconcile_run_tests_exited_result_resumes_with_complete_resources(
) -> None:
    binding = repo_tools.derive_run_tests_docker_binding("a" * 64)

    assert repo_tools.reconcile_run_tests_docker_execution(
        "STARTED_UNCONFIRMED",
        binding,
        _run_tests_observation(
            binding,
            status="exited",
            ever_started=True,
            started=_run_tests_started(binding),
            result=_run_tests_result(binding),
            workspace=True,
            output=True,
        ),
        expected_execution_contract_digest="c" * 64,
        receipt_state="ABSENT",
    ) == "RESUME_RESULT"


@pytest.mark.parametrize(
    "observation_factory",
    (
        lambda b: _run_tests_observation(b),
        lambda b: _run_tests_observation(b, staging=True),
        lambda b: _run_tests_observation(b, workspace=True),
        lambda b: _run_tests_observation(b, output=True),
        lambda b: _run_tests_observation(b, status="created"),
        lambda b: _run_tests_observation(
            b, status="running", ever_started=True
        ),
        lambda b: _run_tests_observation(
            b,
            status="paused",
            ever_started=True,
            staging=True,
            workspace=True,
        ),
        lambda b: _run_tests_observation(
            b, status="dead", ever_started=True, output=True
        ),
        lambda b: _run_tests_observation(
            b,
            status="exited",
            ever_started=True,
            started=_run_tests_started(b),
            result=_run_tests_result(b),
            staging=True,
            output=True,
        ),
    ),
)
@pytest.mark.parametrize(
    ("receipt_state", "expected"),
    (("MATCH", "CLEAN_COMMITTED"), ("MISMATCH", "UNRESOLVED")),
)
def test_reconcile_run_tests_receipt_truth_wins_after_identity_validation(
    observation_factory: object,
    receipt_state: str,
    expected: str,
) -> None:
    binding = repo_tools.derive_run_tests_docker_binding("a" * 64)

    assert repo_tools.reconcile_run_tests_docker_execution(
        "STARTED_UNCONFIRMED",
        binding,
        observation_factory(binding),
        expected_execution_contract_digest="c" * 64,
        receipt_state=receipt_state,
    ) == expected


@pytest.mark.parametrize("status", ("running", "paused", "restarting"))
def test_reconcile_run_tests_active_partial_resources_fail_closed(
    status: str,
) -> None:
    binding = repo_tools.derive_run_tests_docker_binding("a" * 64)

    assert repo_tools.reconcile_run_tests_docker_execution(
        "STARTED_UNCONFIRMED",
        binding,
        _run_tests_observation(
            binding,
            status=status,
            ever_started=True,
            workspace=True,
        ),
        expected_execution_contract_digest="c" * 64,
        receipt_state="ABSENT",
    ) == "UNRESOLVED"


@pytest.mark.parametrize(
    ("receipt_state", "expected"),
    (
        ("ABSENT", "SAFE_TO_RETRY"),
        ("MATCH", "CLEAN_COMMITTED"),
        ("MISMATCH", "UNRESOLVED"),
    ),
)
def test_reconcile_run_tests_receipt_truth_is_closed_tri_state(
    receipt_state: str,
    expected: str,
) -> None:
    binding = repo_tools.derive_run_tests_docker_binding("a" * 64)

    assert repo_tools.reconcile_run_tests_docker_execution(
        "RESERVED",
        binding,
        _run_tests_observation(binding),
        expected_execution_contract_digest="c" * 64,
        receipt_state=receipt_state,
    ) == expected


def test_reconcile_run_tests_rejects_internally_consistent_spoofed_contract(
) -> None:
    binding = repo_tools.derive_run_tests_docker_binding("a" * 64)

    assert repo_tools.reconcile_run_tests_docker_execution(
        "STARTED_UNCONFIRMED",
        binding,
        _run_tests_observation(
            binding,
            status="exited",
            ever_started=True,
            contract_digest="d" * 64,
            started=_run_tests_started(binding, contract_digest="d" * 64),
            result=_run_tests_result(binding, contract_digest="d" * 64),
        ),
        expected_execution_contract_digest="c" * 64,
        receipt_state="ABSENT",
    ) == "UNRESOLVED"


@pytest.mark.parametrize(
    ("resource", "field", "value"),
    (
        ("staging_container", "ownership_token", "d" * 64),
        ("container", "name", "owp-run-replacement"),
        ("container", "execution_id", "d" * 64),
        ("container", "immutable_image_matches", False),
        ("container", "config_matches", False),
        ("container", "mounts_match", False),
        ("workspace_volume", "configuration_matches", False),
        ("output_volume", "ownership_token", "d" * 64),
    ),
)
def test_reconcile_run_tests_rejects_unowned_or_mismatched_resources(
    resource: str,
    field: str,
    value: object,
) -> None:
    binding = repo_tools.derive_run_tests_docker_binding("a" * 64)
    observation = _run_tests_observation(
        binding,
        status="exited",
        ever_started=True,
        started=_run_tests_started(binding),
        result=_run_tests_result(binding),
        staging=True,
        workspace=True,
        output=True,
    )
    changed = dict(getattr(observation, resource))
    changed[field] = value
    observation = repo_tools.RunTestsDockerObservation(
        staging_container=changed if resource == "staging_container" else observation.staging_container,
        container=changed if resource == "container" else observation.container,
        workspace_volume=changed if resource == "workspace_volume" else observation.workspace_volume,
        output_volume=changed if resource == "output_volume" else observation.output_volume,
        started=observation.started,
        result=observation.result,
    )

    assert repo_tools.reconcile_run_tests_docker_execution(
        "STARTED_UNCONFIRMED",
        binding,
        observation,
        expected_execution_contract_digest="c" * 64,
        receipt_state="MATCH",
    ) == "UNRESOLVED"


def test_reconcile_run_tests_rejects_multiple_resource_mismatches() -> None:
    binding = repo_tools.derive_run_tests_docker_binding("a" * 64)
    observation = _run_tests_observation(
        binding,
        status="exited",
        ever_started=True,
        started=_run_tests_started(binding),
        result=_run_tests_result(binding),
        workspace=True,
        output=True,
    )
    container = dict(observation.container)
    container["config_matches"] = False
    output = dict(observation.output_volume)
    output["ownership_token"] = "d" * 64

    assert repo_tools.reconcile_run_tests_docker_execution(
        "STARTED_UNCONFIRMED",
        binding,
        repo_tools.RunTestsDockerObservation(
            staging_container=None,
            container=container,
            workspace_volume=observation.workspace_volume,
            output_volume=output,
            started=observation.started,
            result=observation.result,
        ),
        expected_execution_contract_digest="c" * 64,
        receipt_state="MATCH",
    ) == "UNRESOLVED"


@pytest.mark.parametrize(
    ("resource", "field", "value"),
    (
        ("workspace_volume", "name", _RunTestsAlwaysEqual()),
        (
            "workspace_volume",
            "name",
            _RunTestsStrSubclass("owp-workspace-" + "a" * 32),
        ),
        ("container", "name", _RunTestsAlwaysEqual()),
        (
            "container",
            "execution_id",
            _RunTestsStrSubclass("a" * 64),
        ),
    ),
)
def test_reconcile_run_tests_rejects_adversarial_observed_identity_types(
    resource: str,
    field: str,
    value: object,
) -> None:
    binding = repo_tools.derive_run_tests_docker_binding("a" * 64)
    observation = _run_tests_observation(
        binding,
        status="created",
        workspace=True,
        output=True,
    )
    changed = dict(getattr(observation, resource))
    changed[field] = value
    observation = repo_tools.RunTestsDockerObservation(
        staging_container=observation.staging_container,
        container=changed if resource == "container" else observation.container,
        workspace_volume=(
            changed
            if resource == "workspace_volume"
            else observation.workspace_volume
        ),
        output_volume=observation.output_volume,
        started=None,
        result=None,
    )

    assert repo_tools.reconcile_run_tests_docker_execution(
        "RESERVED",
        binding,
        observation,
        expected_execution_contract_digest="c" * 64,
        receipt_state="MATCH",
    ) == "UNRESOLVED"


@pytest.mark.parametrize(
    ("resource", "replacement_key"),
    (
        ("workspace_volume", _RunTestsEqualKey("name")),
        ("workspace_volume", _RunTestsStrSubclass("name")),
        ("workspace_volume", _RunTestsExplodingKey("name")),
        ("container", _RunTestsEqualKey("name")),
        ("container", _RunTestsStrSubclass("name")),
        ("container", _RunTestsExplodingKey("name")),
    ),
)
def test_reconcile_run_tests_rejects_non_exact_observation_keys_without_equality(
    resource: str,
    replacement_key: object,
) -> None:
    binding = repo_tools.derive_run_tests_docker_binding("a" * 64)
    observation = _run_tests_observation(
        binding,
        status="created",
        workspace=True,
        output=True,
    )
    changed = dict(getattr(observation, resource))
    name = changed.pop("name")
    changed[replacement_key] = name
    observation = repo_tools.RunTestsDockerObservation(
        staging_container=None,
        container=changed if resource == "container" else observation.container,
        workspace_volume=(
            changed
            if resource == "workspace_volume"
            else observation.workspace_volume
        ),
        output_volume=observation.output_volume,
        started=None,
        result=None,
    )

    assert repo_tools.reconcile_run_tests_docker_execution(
        "RESERVED",
        binding,
        observation,
        expected_execution_contract_digest="c" * 64,
        receipt_state="MATCH",
    ) == "UNRESOLVED"


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("execution_id", _RunTestsExplodingEquality()),
        ("ownership_token", _RunTestsExplodingEquality()),
        ("container_name", _RunTestsStrSubclass("owp-run-" + "a" * 32)),
    ),
)
def test_reconcile_run_tests_rejects_adversarial_binding_without_equality(
    field: str,
    value: object,
) -> None:
    valid = repo_tools.derive_run_tests_docker_binding("a" * 64)
    values = {
        "execution_id": valid.execution_id,
        "ownership_token": valid.ownership_token,
        "staging_container_name": valid.staging_container_name,
        "container_name": valid.container_name,
        "workspace_volume_name": valid.workspace_volume_name,
        "output_volume_name": valid.output_volume_name,
    }
    values[field] = value
    binding = repo_tools.RunTestsDockerBinding(**values)

    with pytest.raises(ValueError, match="binding"):
        repo_tools.reconcile_run_tests_docker_execution(
            "RESERVED",
            binding,
            _run_tests_observation(valid),
            expected_execution_contract_digest="c" * 64,
            receipt_state="ABSENT",
        )


@pytest.mark.parametrize(
    "observation_factory",
    (
        lambda b: _run_tests_observation(
            b,
            status="created",
            ever_started=True,
            workspace=True,
            output=True,
        ),
        lambda b: _run_tests_observation(
            b,
            status="exited",
            ever_started=False,
            started=_run_tests_started(b),
            result=_run_tests_result(b),
            workspace=True,
            output=True,
        ),
        lambda b: _run_tests_observation(
            b,
            status="running",
            ever_started=True,
            result=_run_tests_result(b),
            workspace=True,
            output=True,
        ),
    ),
)
def test_reconcile_run_tests_rejects_contradictory_facts(
    observation_factory: object,
) -> None:
    binding = repo_tools.derive_run_tests_docker_binding("a" * 64)

    assert repo_tools.reconcile_run_tests_docker_execution(
        "STARTED_UNCONFIRMED",
        binding,
        observation_factory(binding),
        expected_execution_contract_digest="c" * 64,
        receipt_state="ABSENT",
    ) == "UNRESOLVED"


def test_derive_docker_execution_plan_is_exact_and_deterministic() -> None:
    first = _docker_plan()
    second = _docker_plan()

    assert second == first
    assert first.workspace_volume.name == "owp-workspace-01"
    assert first.workspace_volume.mount_path == "/workspace"
    assert first.workspace_volume.read_only is True
    assert first.workspace_volume.create_argv == (
        "/usr/local/bin/docker",
        "volume",
        "create",
        "--driver",
        "local",
        "--label",
        "openworkproof.execution-owner=" + "b" * 64,
        "owp-workspace-01",
    )
    assert first.output_volume.name == "owp-output-01"
    assert first.output_volume.mount_path == "/output"
    assert first.output_volume.read_only is False
    assert first.output_volume.create_argv == (
        "/usr/local/bin/docker",
        "volume",
        "create",
        "--driver",
        "local",
        "--label",
        "openworkproof.execution-owner=" + "b" * 64,
        "owp-output-01",
    )
    # Named-volume persistence is not a filesystem quota. Candidate staging
    # and runner-envelope codecs enforce the 8 MiB / 1 MiB / 8 KiB limits.
    assert not hasattr(first.workspace_volume, "size_bytes")
    assert not hasattr(first.output_volume, "size_bytes")
    for volume in (first.workspace_volume, first.output_volume):
        joined_create = "\0".join(volume.create_argv)
        assert "--opt" not in volume.create_argv
        assert "tmpfs" not in joined_create
        assert "size=" not in joined_create
    assert first.create_container_argv == (
        "/usr/local/bin/docker",
        "create",
        "--name",
        "owp-container-01",
        "--label",
        "openworkproof.execution-owner=" + "b" * 64,
        "--pull",
        "never",
        "--network",
        "none",
        "--read-only",
        "--user",
        "65532:65532",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        "128",
        "--memory",
        "1g",
        "--cpus",
        "1",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=256m",
        "--workdir",
        "/workspace",
        "--mount",
        (
            "type=volume,source=owp-workspace-01,"
            "target=/workspace,readonly"
        ),
        "--mount",
        "type=volume,source=owp-output-01,target=/output",
        (
            "registry.example/openworkproof/test-runner@sha256:"
            + "a" * 64
        ),
        "/bin/sh",
        "-c",
        "printf containment-ok",
    )
    mount_specs = tuple(
        first.create_container_argv[index + 1]
        for index, argument in enumerate(first.create_container_argv)
        if argument == "--mount"
    )
    assert mount_specs == (
        (
            "type=volume,source=owp-workspace-01,"
            "target=/workspace,readonly"
        ),
        "type=volume,source=owp-output-01,target=/output",
    )
    assert not hasattr(first, "start_container_argv")
    assert first.preflight_absent_argv == (
        (
            "/usr/local/bin/docker",
            "container",
            "ls",
            "--all",
            "--format",
            "{{.Names}}",
        ),
        (
            "/usr/local/bin/docker",
            "volume",
            "ls",
            "--format",
            "{{.Name}}",
        ),
    )
    assert not hasattr(first, "cleanup_argv")
    joined = "\0".join(first.create_container_argv)
    for forbidden in (
        "/var/run/docker.sock",
        str(Path.home()),
        ".ssh",
        ".git",
        "credential",
        "type=bind",
    ):
        assert forbidden not in joined


@pytest.mark.parametrize(
    "image_reference",
    (
        "alpine",
        "alpine:latest",
        "namespace/repo@sha256:" + "a" * 64,
        "a/repo@sha256:" + "a" * 64,
        "sha256:" + "a" * 64,
        "registry.example/openworkproof/test-runner:latest",
        (
            "registry.example/openworkproof/test-runner:latest@sha256:"
            + "a" * 64
        ),
        "registry.example/openworkproof/test-runner@sha256:" + "A" * 64,
        "registry.example:0/openworkproof/runner@sha256:" + "a" * 64,
        "registry.example:65536/openworkproof/runner@sha256:" + "a" * 64,
        "r" * 64 + ".example/repo@sha256:" + "a" * 64,
        (
            "registry.example/" + "x" * 129 + "@sha256:" + "a" * 64
        ),
        (
            "registry.example/"
            + "x" * 100
            + "/"
            + "y" * 100
            + "@sha256:"
            + "a" * 64
        ),
    ),
)
def test_derive_docker_execution_plan_rejects_mutable_or_unqualified_image(
    image_reference: str,
) -> None:
    with pytest.raises(ValueError, match="immutable image reference"):
        _docker_plan(image_reference=image_reference)


@pytest.mark.parametrize(
    ("container_name", "workspace_name", "output_name"),
    (
        ("same", "same", "different"),
        ("same", "different", "same"),
        ("different", "same", "same"),
        ("invalid/name", "workspace", "output"),
        ("container", "UPPERCASE", "output"),
        ("container", "workspace", ""),
    ),
)
def test_derive_docker_execution_plan_rejects_invalid_or_reused_names(
    container_name: str,
    workspace_name: str,
    output_name: str,
) -> None:
    with pytest.raises(ValueError, match="identifier"):
        _docker_plan(
            container_name=container_name,
            workspace_volume_name=workspace_name,
            output_volume_name=output_name,
        )


@pytest.mark.parametrize("ownership_token", ("", "a" * 63, "A" * 64))
def test_derive_docker_execution_plan_rejects_invalid_ownership_token(
    ownership_token: str,
) -> None:
    with pytest.raises(ValueError, match="ownership token"):
        _docker_plan(ownership_token=ownership_token)


def _docker_volume_inspection(
    plan: repo_tools.DockerExecutionPlan,
    resource: str,
) -> dict:
    volume = (
        plan.workspace_volume
        if resource == "workspace_volume"
        else plan.output_volume
    )
    return {
        "Name": volume.name,
        "Driver": "local",
        "Labels": {
            "openworkproof.execution-owner": plan.ownership_token,
        },
        "Options": None,
        "Scope": "local",
    }


def _docker_container_inspection(
    plan: repo_tools.DockerExecutionPlan,
) -> dict:
    return {
        "Name": f"/{plan.container_name}",
        "State": {
            "Status": "created",
            "Running": False,
            "Paused": False,
            "Restarting": False,
            "Dead": False,
            "Pid": 0,
            "ExitCode": 0,
            "StartedAt": "0001-01-01T00:00:00Z",
            "FinishedAt": "0001-01-01T00:00:00Z",
        },
        "Config": {
            "Image": plan.image_reference,
            "User": "65532:65532",
            "Labels": {
                "openworkproof.execution-owner": plan.ownership_token,
            },
            "Volumes": None,
        },
        "HostConfig": {
            "NetworkMode": "none",
            "ReadonlyRootfs": True,
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges:true"],
            "PidsLimit": 128,
            "Memory": 1024 * 1024 * 1024,
            "NanoCpus": 1_000_000_000,
            "Tmpfs": {"/tmp": "rw,noexec,nosuid,size=256m"},
            "Mounts": [
                {
                    "Type": "volume",
                    "Source": plan.workspace_volume.name,
                    "Target": "/workspace",
                    "ReadOnly": True,
                },
                {
                    "Type": "volume",
                    "Source": plan.output_volume.name,
                    "Target": "/output",
                    "ReadOnly": False,
                },
            ],
        },
        "Mounts": [
            {
                "Destination": "/workspace",
                "Type": "volume",
                "Name": plan.workspace_volume.name,
                "RW": False,
            },
            {
                "Destination": "/output",
                "Type": "volume",
                "Name": plan.output_volume.name,
                "RW": True,
            },
        ],
    }


def _docker_image_inspection(plan: repo_tools.DockerExecutionPlan) -> dict:
    return {
        "RepoDigests": [plan.image_reference],
        "Config": {"Volumes": None},
    }


def test_docker_lifecycle_requires_absence_and_cleans_only_created_owned(
) -> None:
    plan = _docker_plan()
    state = repo_tools.validate_docker_preflight_absent(
        plan,
        repo_tools.DockerPreflightObservation(
            container_names=(),
            volume_names=(),
        ),
    )
    state = repo_tools.mark_docker_resource_created(
        plan,
        state,
        "workspace_volume",
    )
    state = repo_tools.mark_docker_resource_created(
        plan,
        state,
        "output_volume",
    )
    state = repo_tools.mark_docker_resource_created(
        plan,
        state,
        "container",
    )
    unowned_output = _docker_volume_inspection(plan, "output_volume")
    unowned_output["Labels"] = {
        "openworkproof.execution-owner": "c" * 64,
    }

    cleanup = repo_tools.derive_docker_cleanup_plan(
        plan,
        state,
        {
            "container": _docker_container_inspection(plan),
            "workspace_volume": _docker_volume_inspection(
                plan,
                "workspace_volume",
            ),
            "output_volume": unowned_output,
        },
    )

    assert cleanup.commands == (
        (
            "/usr/local/bin/docker",
            "rm",
            "--force",
            "--volumes",
            plan.container_name,
        ),
        (
            "/usr/local/bin/docker",
            "volume",
            "rm",
            plan.workspace_volume.name,
        ),
    )
    assert cleanup.retained_resources == ("output_volume",)


def test_docker_cleanup_ignores_owned_resources_not_recorded_as_created(
) -> None:
    plan = _docker_plan()
    state = repo_tools.validate_docker_preflight_absent(
        plan,
        repo_tools.DockerPreflightObservation((), ()),
    )
    state = repo_tools.mark_docker_resource_created(
        plan,
        state,
        "workspace_volume",
    )

    cleanup = repo_tools.derive_docker_cleanup_plan(
        plan,
        state,
        {
            "container": _docker_container_inspection(plan),
            "workspace_volume": _docker_volume_inspection(
                plan,
                "workspace_volume",
            ),
            "output_volume": _docker_volume_inspection(
                plan,
                "output_volume",
            ),
        },
    )

    assert cleanup.commands == (
        (
            "/usr/local/bin/docker",
            "volume",
            "rm",
            plan.workspace_volume.name,
        ),
    )
    assert cleanup.retained_resources == ()


@pytest.mark.parametrize(
    ("field", "names"),
    (
        ("container_names", ("owp-container-01",)),
        ("volume_names", ("owp-workspace-01",)),
        ("volume_names", ("owp-output-01",)),
    ),
)
def test_docker_lifecycle_rejects_preexisting_resource(
    field: str,
    names: tuple[str, ...],
) -> None:
    plan = _docker_plan()
    values = {
        "container_names": (),
        "volume_names": (),
        field: names,
    }
    with pytest.raises(ValueError, match="already exists"):
        repo_tools.validate_docker_preflight_absent(
            plan,
            repo_tools.DockerPreflightObservation(**values),
        )


def _complete_docker_lifecycle(
    plan: repo_tools.DockerExecutionPlan,
) -> repo_tools.DockerLifecycleState:
    state = repo_tools.validate_docker_preflight_absent(
        plan,
        repo_tools.DockerPreflightObservation((), ()),
    )
    for resource in ("workspace_volume", "output_volume", "container"):
        state = repo_tools.mark_docker_resource_created(
            plan,
            state,
            resource,
        )
    return state


def test_derive_ready_docker_start_requires_all_created_and_inspected() -> None:
    plan = _docker_plan()
    ready = repo_tools.derive_ready_docker_start(
        plan,
        _complete_docker_lifecycle(plan),
        _docker_image_inspection(plan),
        _docker_container_inspection(plan),
        _docker_volume_inspection(plan, "workspace_volume"),
        _docker_volume_inspection(plan, "output_volume"),
    )

    assert ready.start_argv == (
        "/usr/local/bin/docker",
        "start",
        "--attach",
        plan.container_name,
    )


def test_derive_ready_docker_start_accepts_omitted_output_readonly_default(
) -> None:
    plan = _docker_plan()
    container = _docker_container_inspection(plan)
    del container["HostConfig"]["Mounts"][1]["ReadOnly"]

    ready = repo_tools.derive_ready_docker_start(
        plan,
        _complete_docker_lifecycle(plan),
        _docker_image_inspection(plan),
        container,
        _docker_volume_inspection(plan, "workspace_volume"),
        _docker_volume_inspection(plan, "output_volume"),
    )

    assert ready.start_argv[-1] == plan.container_name


def _ready_docker_start_for_repo_digests(
    plan: repo_tools.DockerExecutionPlan,
    repo_digests: list[str],
) -> repo_tools.DockerReadyStart:
    image_inspection = _docker_image_inspection(plan)
    image_inspection["RepoDigests"] = repo_digests
    return repo_tools.derive_ready_docker_start(
        plan,
        _complete_docker_lifecycle(plan),
        image_inspection,
        _docker_container_inspection(plan),
        _docker_volume_inspection(plan, "workspace_volume"),
        _docker_volume_inspection(plan, "output_volume"),
    )


def test_derive_ready_docker_start_accepts_familiar_docker_hub_digest() -> None:
    digest = "sha256:" + "a" * 64
    plan = _docker_plan(
        image_reference=f"docker.io/library/python@{digest}",
    )
    ready = _ready_docker_start_for_repo_digests(
        plan,
        [f"python@{digest}"],
    )

    assert ready.start_argv == (
        "/usr/local/bin/docker",
        "start",
        "--attach",
        plan.container_name,
    )


def test_derive_ready_docker_start_accepts_familiar_docker_hub_namespace(
) -> None:
    digest = "sha256:" + "a" * 64
    plan = _docker_plan(
        image_reference=f"docker.io/openworkproof/runner@{digest}",
    )
    ready = _ready_docker_start_for_repo_digests(
        plan,
        [f"openworkproof/runner@{digest}"],
    )

    assert ready.start_argv[-1] == plan.container_name


@pytest.mark.parametrize(
    "observed_repository",
    (
        "other/python",
        "library/pypy",
        "docker.io/python",
        "registry.example/library/python",
        "localhost:5000/library/python",
    ),
)
def test_derive_ready_docker_start_rejects_other_repo_with_same_digest(
    observed_repository: str,
) -> None:
    digest = "sha256:" + "a" * 64
    plan = _docker_plan(
        image_reference=f"docker.io/library/python@{digest}",
    )

    with pytest.raises(ValueError, match="image inspection"):
        _ready_docker_start_for_repo_digests(
            plan,
            [f"{observed_repository}@{digest}"],
        )


def test_derive_ready_docker_start_rejects_different_digest() -> None:
    plan_digest = "sha256:" + "a" * 64
    plan = _docker_plan(
        image_reference=f"docker.io/library/python@{plan_digest}",
    )

    with pytest.raises(ValueError, match="image inspection"):
        _ready_docker_start_for_repo_digests(
            plan,
            ["python@sha256:" + "b" * 64],
        )


@pytest.mark.parametrize(
    "observed_repo_digest",
    (
        "python",
        "Python@sha256:" + "a" * 64,
        "python:3.12@sha256:" + "a" * 64,
    ),
)
def test_derive_ready_docker_start_rejects_invalid_observed_repo_digest(
    observed_repo_digest: str,
) -> None:
    digest = "sha256:" + "a" * 64
    plan = _docker_plan(
        image_reference=f"docker.io/library/python@{digest}",
    )

    with pytest.raises(ValueError, match="image inspection"):
        _ready_docker_start_for_repo_digests(
            plan,
            [observed_repo_digest],
        )


def test_docker_lifecycle_rejects_out_of_order_creation() -> None:
    plan = _docker_plan()
    state = repo_tools.validate_docker_preflight_absent(
        plan,
        repo_tools.DockerPreflightObservation((), ()),
    )
    with pytest.raises(ValueError, match="creation order"):
        repo_tools.mark_docker_resource_created(
            plan,
            state,
            "container",
        )


def test_derive_ready_docker_start_rejects_incomplete_lifecycle() -> None:
    plan = _docker_plan()
    state = repo_tools.validate_docker_preflight_absent(
        plan,
        repo_tools.DockerPreflightObservation((), ()),
    )
    state = repo_tools.mark_docker_resource_created(
        plan,
        state,
        "workspace_volume",
    )
    with pytest.raises(ValueError, match="lifecycle"):
        repo_tools.derive_ready_docker_start(
            plan,
            state,
            _docker_image_inspection(plan),
            _docker_container_inspection(plan),
            _docker_volume_inspection(plan, "workspace_volume"),
            _docker_volume_inspection(plan, "output_volume"),
        )


@pytest.mark.parametrize(
    ("status", "field", "value"),
    (
        ("running", "Running", True),
        ("exited", "ExitCode", 1),
        ("dead", "Dead", True),
        ("restarting", "Restarting", True),
        ("created", "StartedAt", "2026-08-03T00:00:00Z"),
    ),
)
def test_derive_ready_docker_start_rejects_started_or_unsafe_state(
    status: str,
    field: str,
    value: object,
) -> None:
    plan = _docker_plan()
    container = _docker_container_inspection(plan)
    container["State"]["Status"] = status
    container["State"][field] = value

    with pytest.raises(ValueError, match="ready to start"):
        repo_tools.derive_ready_docker_start(
            plan,
            _complete_docker_lifecycle(plan),
            _docker_image_inspection(plan),
            container,
            _docker_volume_inspection(plan, "workspace_volume"),
            _docker_volume_inspection(plan, "output_volume"),
        )


def test_derive_ready_docker_start_rejects_malformed_state() -> None:
    plan = _docker_plan()
    container = _docker_container_inspection(plan)
    container["State"] = {"Status": "created", "Running": False}

    with pytest.raises(ValueError, match="ready to start"):
        repo_tools.derive_ready_docker_start(
            plan,
            _complete_docker_lifecycle(plan),
            _docker_image_inspection(plan),
            container,
            _docker_volume_inspection(plan, "workspace_volume"),
            _docker_volume_inspection(plan, "output_volume"),
        )


def test_validate_docker_execution_inspections_accepts_exact_profile() -> None:
    plan = _docker_plan()
    repo_tools.validate_docker_execution_inspections(
        plan,
        _docker_container_inspection(plan),
        _docker_volume_inspection(plan, "workspace_volume"),
        _docker_volume_inspection(plan, "output_volume"),
    )


@pytest.mark.parametrize(
    ("resource", "mutation"),
    (
        ("workspace_volume", "tmpfs_options"),
        ("output_volume", "custom_options"),
        ("workspace_volume", "empty_options"),
        ("output_volume", "custom_driver"),
        ("workspace_volume", "missing_scope"),
        ("output_volume", "wrong_scope"),
        ("workspace_volume", "wrong_name"),
        ("output_volume", "wrong_label"),
    ),
)
def test_validate_docker_execution_inspections_rejects_nonpersistent_volume_profile(
    resource: str,
    mutation: str,
) -> None:
    plan = _docker_plan()
    workspace = _docker_volume_inspection(plan, "workspace_volume")
    output = _docker_volume_inspection(plan, "output_volume")
    inspected = workspace if resource == "workspace_volume" else output
    if mutation == "tmpfs_options":
        inspected["Options"] = {
            "type": "tmpfs",
            "device": "tmpfs",
            "o": "size=512m",
        }
    elif mutation == "custom_options":
        inspected["Options"] = {"o": "bind", "device": "/host/path"}
    elif mutation == "empty_options":
        inspected["Options"] = {}
    elif mutation == "custom_driver":
        inspected["Driver"] = "custom"
    elif mutation == "missing_scope":
        del inspected["Scope"]
    elif mutation == "wrong_scope":
        inspected["Scope"] = "global"
    elif mutation == "wrong_name":
        inspected["Name"] += "-other"
    else:
        inspected["Labels"] = {
            "openworkproof.execution-owner": "c" * 64,
        }

    with pytest.raises(ValueError, match="Docker inspection"):
        repo_tools.validate_docker_execution_inspections(
            plan,
            _docker_container_inspection(plan),
            workspace,
            output,
        )


@pytest.mark.parametrize("read_only", (True, None, "false", 0, 1))
def test_validate_docker_execution_inspections_rejects_explicit_invalid_output_readonly(
    read_only: object,
) -> None:
    plan = _docker_plan()
    container = _docker_container_inspection(plan)
    container["HostConfig"]["Mounts"][1]["ReadOnly"] = read_only

    with pytest.raises(ValueError, match="Docker inspection"):
        repo_tools.validate_docker_execution_inspections(
            plan,
            container,
            _docker_volume_inspection(plan, "workspace_volume"),
            _docker_volume_inspection(plan, "output_volume"),
        )


@pytest.mark.parametrize(
    "mutation",
    ("missing_mount", "malformed_mount", "missing_rw", "malformed_rw"),
)
def test_validate_docker_execution_inspections_rejects_invalid_output_runtime_mount(
    mutation: str,
) -> None:
    plan = _docker_plan()
    container = _docker_container_inspection(plan)
    if mutation == "missing_mount":
        del container["Mounts"][1]
    elif mutation == "malformed_mount":
        container["Mounts"][1] = None
    elif mutation == "missing_rw":
        del container["Mounts"][1]["RW"]
    else:
        container["Mounts"][1]["RW"] = "true"

    with pytest.raises(ValueError, match="Docker inspection"):
        repo_tools.validate_docker_execution_inspections(
            plan,
            container,
            _docker_volume_inspection(plan, "workspace_volume"),
            _docker_volume_inspection(plan, "output_volume"),
        )


@pytest.mark.parametrize(
    "mutation",
    ("missing_configured_readonly", "writable", "missing_runtime_rw"),
)
def test_validate_docker_execution_inspections_keeps_workspace_readonly_explicit(
    mutation: str,
) -> None:
    plan = _docker_plan()
    container = _docker_container_inspection(plan)
    if mutation == "missing_configured_readonly":
        del container["HostConfig"]["Mounts"][0]["ReadOnly"]
    elif mutation == "writable":
        container["HostConfig"]["Mounts"][0]["ReadOnly"] = False
    else:
        del container["Mounts"][0]["RW"]

    with pytest.raises(ValueError, match="Docker inspection"):
        repo_tools.validate_docker_execution_inspections(
            plan,
            container,
            _docker_volume_inspection(plan, "workspace_volume"),
            _docker_volume_inspection(plan, "output_volume"),
        )


@pytest.mark.parametrize(
    "mutation",
    (
        "image_volume",
        "extra_mount",
        "wrong_mount_access",
        "wrong_nocopy",
        "extra_tmpfs",
        "wrong_volume_driver",
        "wrong_volume_options",
        "wrong_owner",
    ),
)
def test_validate_docker_execution_inspections_rejects_unsafe_profile(
    mutation: str,
) -> None:
    plan = _docker_plan()
    container = _docker_container_inspection(plan)
    workspace = _docker_volume_inspection(plan, "workspace_volume")
    output = _docker_volume_inspection(plan, "output_volume")
    if mutation == "image_volume":
        container["Config"]["Volumes"] = {"/cache": {}}
    elif mutation == "extra_mount":
        container["Mounts"].append(
            {
                "Destination": "/cache",
                "Type": "volume",
                "Name": "anonymous",
                "RW": True,
            }
        )
    elif mutation == "wrong_mount_access":
        container["Mounts"][0]["RW"] = True
    elif mutation == "wrong_nocopy":
        container["HostConfig"]["Mounts"][0]["VolumeOptions"] = {
            "NoCopy": True,
        }
    elif mutation == "extra_tmpfs":
        container["HostConfig"]["Tmpfs"]["/cache"] = "rw,size=1m"
    elif mutation == "wrong_volume_driver":
        workspace["Driver"] = "other"
    elif mutation == "wrong_volume_options":
        output["Options"] = {"o": "size=65m"}
    else:
        container["Config"]["Labels"] = {}

    with pytest.raises(ValueError, match="Docker inspection"):
        repo_tools.validate_docker_execution_inspections(
            plan,
            container,
            workspace,
            output,
        )


def _run_tests_execution_contract() -> repo_tools.RunTestsExecutionContract:
    return repo_tools.RunTestsExecutionContract(
        execution_id="1" * 64,
        request_digest="2" * 64,
        arguments_digest="3" * 64,
        candidate_workspace_id="4" * 64,
        source_artifact_sha256="5" * 64,
        source_commit="6" * 40,
        candidate_commit="7" * 40,
        workspace_manifest_digest="8" * 64,
        container_image_digest="sha256:" + "9" * 64,
        command_digest="a" * 64,
        fixed_test_source_digest="b" * 64,
    )


def _run_tests_result_envelope() -> repo_tools.RunTestsResultEnvelope:
    return repo_tools.RunTestsResultEnvelope(
        execution_id="1" * 64,
        execution_contract_digest="2" * 64,
        actual_exit_code=0,
        failure_code=None,
        stdout_bytes=0,
        stdout_sha256=hashlib.sha256(b"").hexdigest(),
        stderr_bytes=0,
        stderr_sha256=hashlib.sha256(b"").hexdigest(),
    )


def _run_tests_started_envelope() -> repo_tools.RunTestsStartedEnvelope:
    return repo_tools.RunTestsStartedEnvelope(
        execution_id="1" * 64,
        execution_contract_digest="2" * 64,
    )


def test_run_tests_execution_contract_round_trips_canonical_bytes() -> None:
    contract = _run_tests_execution_contract()
    encoded = repo_tools.encode_run_tests_execution_contract(contract)

    assert encoded == rfc8785.dumps(
        {
            "arguments_digest": "3" * 64,
            "candidate_commit": "7" * 40,
            "candidate_workspace_id": "4" * 64,
            "command_digest": "a" * 64,
            "container_image_digest": "sha256:" + "9" * 64,
            "execution_id": "1" * 64,
            "fixed_test_source_digest": "b" * 64,
            "request_digest": "2" * 64,
            "schema_version": "openworkproof-run-contract/0.1",
            "source_artifact_sha256": "5" * 64,
            "source_commit": "6" * 40,
            "test_mode": "verifier",
            "tool_name": "owp.run_tests",
            "workspace_manifest_digest": "8" * 64,
        }
    )
    assert repo_tools.decode_run_tests_execution_contract(encoded) == contract


def test_run_tests_started_and_result_round_trip_canonical_bytes() -> None:
    started = _run_tests_started_envelope()
    result = _run_tests_result_envelope()

    assert repo_tools.decode_run_tests_started_envelope(
        repo_tools.encode_run_tests_started_envelope(started)
    ) == started
    assert repo_tools.decode_run_tests_result_envelope(
        repo_tools.encode_run_tests_result_envelope(result)
    ) == result


@pytest.mark.parametrize(
    ("actual_exit_code", "failure_code"),
    (
        (255, None),
        (None, "OUTPUT_LIMIT"),
        (None, "TIMEOUT"),
        (None, "DISK_LIMIT"),
    ),
)
def test_run_tests_result_round_trips_each_closed_outcome(
    actual_exit_code: int | None,
    failure_code: str | None,
) -> None:
    result = replace(
        _run_tests_result_envelope(),
        actual_exit_code=actual_exit_code,
        failure_code=failure_code,
    )

    assert repo_tools.decode_run_tests_result_envelope(
        repo_tools.encode_run_tests_result_envelope(result)
    ) == result


def test_run_tests_result_requires_one_closed_outcome() -> None:
    with pytest.raises(ValueError, match="closed outcome"):
        repo_tools.RunTestsResultEnvelope(
            execution_id="1" * 64,
            execution_contract_digest="2" * 64,
            actual_exit_code=1,
            failure_code="TIMEOUT",
            stdout_bytes=0,
            stdout_sha256=hashlib.sha256(b"").hexdigest(),
            stderr_bytes=0,
            stderr_sha256=hashlib.sha256(b"").hexdigest(),
        )


RunTestsEncoder = Callable[[object], bytes]
RunTestsDecoder = Callable[[bytes], object]


@pytest.mark.parametrize(
    ("factory", "encoder", "decoder", "field"),
    (
        (
            _run_tests_execution_contract,
            repo_tools.encode_run_tests_execution_contract,
            repo_tools.decode_run_tests_execution_contract,
            "request_digest",
        ),
        (
            _run_tests_started_envelope,
            repo_tools.encode_run_tests_started_envelope,
            repo_tools.decode_run_tests_started_envelope,
            "execution_contract_digest",
        ),
        (
            _run_tests_result_envelope,
            repo_tools.encode_run_tests_result_envelope,
            repo_tools.decode_run_tests_result_envelope,
            "stdout_sha256",
        ),
    ),
)
@pytest.mark.parametrize("invalid_digest", ("a" * 63, "A" * 64, "g" * 64))
def test_run_tests_codecs_reject_malformed_digests(
    factory: Callable[[], object],
    encoder: RunTestsEncoder,
    decoder: RunTestsDecoder,
    field: str,
    invalid_digest: str,
) -> None:
    with pytest.raises(ValueError):
        encoder(replace(factory(), **{field: invalid_digest}))

    value = json.loads(encoder(factory()))
    value[field] = invalid_digest
    with pytest.raises(ValueError):
        decoder(rfc8785.dumps(value))


@pytest.mark.parametrize("field", ("source_commit", "candidate_commit"))
@pytest.mark.parametrize("invalid_oid", ("a" * 39, "g" * 40))
def test_run_tests_contract_codec_rejects_malformed_git_oids(
    field: str,
    invalid_oid: str,
) -> None:
    contract = _run_tests_execution_contract()
    with pytest.raises(ValueError):
        repo_tools.encode_run_tests_execution_contract(
            replace(contract, **{field: invalid_oid})
        )

    value = json.loads(repo_tools.encode_run_tests_execution_contract(contract))
    value[field] = invalid_oid
    with pytest.raises(ValueError):
        repo_tools.decode_run_tests_execution_contract(rfc8785.dumps(value))


@pytest.mark.parametrize(
    "invalid_image_digest",
    (
        "a" * 64,
        "sha256:" + "a" * 63,
        "sha256:" + "A" * 64,
        "sha256:" + "g" * 64,
    ),
)
def test_run_tests_contract_codec_rejects_malformed_image_digest(
    invalid_image_digest: str,
) -> None:
    contract = _run_tests_execution_contract()
    with pytest.raises(ValueError):
        repo_tools.encode_run_tests_execution_contract(
            replace(contract, container_image_digest=invalid_image_digest)
        )

    value = json.loads(repo_tools.encode_run_tests_execution_contract(contract))
    value["container_image_digest"] = invalid_image_digest
    with pytest.raises(ValueError):
        repo_tools.decode_run_tests_execution_contract(rfc8785.dumps(value))


@pytest.mark.parametrize("field", ("stdout_bytes", "stderr_bytes"))
@pytest.mark.parametrize(
    "invalid_size",
    (-1, True, 9_007_199_254_740_992),
)
def test_run_tests_result_encoder_rejects_invalid_stream_sizes(
    field: str,
    invalid_size: int | bool,
) -> None:
    result = _run_tests_result_envelope()
    with pytest.raises(ValueError):
        repo_tools.encode_run_tests_result_envelope(
            replace(result, **{field: invalid_size})
        )


@pytest.mark.parametrize("field", ("stdout_bytes", "stderr_bytes"))
@pytest.mark.parametrize(
    "invalid_size",
    (-1, True, 9_007_199_254_740_992),
)
def test_run_tests_result_decoder_rejects_invalid_stream_sizes(
    field: str,
    invalid_size: int | bool,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _run_tests_result_envelope()
    value = json.loads(repo_tools.encode_run_tests_result_envelope(result))
    value[field] = invalid_size
    raw = (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
        if invalid_size == 9_007_199_254_740_992
        else rfc8785.dumps(value)
    )
    if invalid_size == 9_007_199_254_740_992:
        monkeypatch.setattr(
            repo_tools,
            "encode_run_tests_result_envelope",
            lambda envelope: raw,
        )
    with pytest.raises(ValueError):
        repo_tools.decode_run_tests_result_envelope(raw)


@pytest.mark.parametrize(
    ("actual_exit_code", "failure_code"),
    (
        (True, None),
        (-1, None),
        (256, None),
        ("0", None),
        (None, True),
        (None, "OTHER"),
    ),
)
def test_run_tests_result_constructor_rejects_invalid_closed_outcome_values(
    actual_exit_code: int | str | bool | None,
    failure_code: str | bool | None,
) -> None:
    with pytest.raises(ValueError, match="closed outcome"):
        repo_tools.RunTestsResultEnvelope(
            execution_id="1" * 64,
            execution_contract_digest="2" * 64,
            actual_exit_code=actual_exit_code,
            failure_code=failure_code,
            stdout_bytes=0,
            stdout_sha256=hashlib.sha256(b"").hexdigest(),
            stderr_bytes=0,
            stderr_sha256=hashlib.sha256(b"").hexdigest(),
        )


def test_frozen_verifier_command_digest_is_domain_separated() -> None:
    assert repo_tools.FROZEN_VERIFIER_ARGV == (
        "/opt/venv/bin/python",
        "-I",
        "-m",
        "pytest",
        "-q",
    )
    assert repo_tools.frozen_verifier_command_digest() == hashlib.sha256(
        rfc8785.dumps(
            {
                "domain": "openworkproof/verifier-command/v0.1",
                "argv": list(repo_tools.FROZEN_VERIFIER_ARGV),
            }
        )
    ).hexdigest()


@pytest.mark.parametrize(
    ("decoder", "encoded"),
    (
        (
            "decode_run_tests_execution_contract",
            lambda: repo_tools.encode_run_tests_execution_contract(
                _run_tests_execution_contract()
            ),
        ),
        (
            "decode_run_tests_started_envelope",
            lambda: repo_tools.encode_run_tests_started_envelope(
                repo_tools.RunTestsStartedEnvelope(
                    execution_id="1" * 64,
                    execution_contract_digest="2" * 64,
                )
            ),
        ),
        (
            "decode_run_tests_result_envelope",
            lambda: repo_tools.encode_run_tests_result_envelope(
                _run_tests_result_envelope()
            ),
        ),
    ),
)
@pytest.mark.parametrize(
    "raw",
    (
        b"",
        b" " * 8193,
        b'\xef\xbb\xbf{}',
    ),
)
def test_run_tests_decoders_reject_empty_oversize_and_bom(
    decoder: str,
    encoded: object,
    raw: bytes,
) -> None:
    assert callable(encoded)
    with pytest.raises(ValueError):
        getattr(repo_tools, decoder)(raw)


@pytest.mark.parametrize(
    ("decoder", "encoded"),
    (
        (
            "decode_run_tests_execution_contract",
            lambda: repo_tools.encode_run_tests_execution_contract(
                _run_tests_execution_contract()
            ),
        ),
        (
            "decode_run_tests_started_envelope",
            lambda: repo_tools.encode_run_tests_started_envelope(
                repo_tools.RunTestsStartedEnvelope(
                    execution_id="1" * 64,
                    execution_contract_digest="2" * 64,
                )
            ),
        ),
        (
            "decode_run_tests_result_envelope",
            lambda: repo_tools.encode_run_tests_result_envelope(
                _run_tests_result_envelope()
            ),
        ),
    ),
)
@pytest.mark.parametrize("mutation", ("duplicate", "unknown", "newline", "order"))
def test_run_tests_decoders_reject_noncanonical_json(
    decoder: str,
    encoded: object,
    mutation: str,
) -> None:
    assert callable(encoded)
    raw = encoded()
    value = json.loads(raw)
    if mutation == "duplicate":
        first_key = next(iter(value))
        malformed = b'{"' + first_key.encode("ascii") + b'":null,' + raw[1:]
    elif mutation == "unknown":
        value["unknown"] = "value"
        malformed = rfc8785.dumps(value)
    elif mutation == "newline":
        malformed = raw + b"\n"
    else:
        malformed = json.dumps(
            {key: value[key] for key in reversed(tuple(value))},
            separators=(",", ":"),
        ).encode("ascii")
        assert malformed != raw
    with pytest.raises(ValueError):
        getattr(repo_tools, decoder)(malformed)


@pytest.mark.parametrize(
    ("decoder", "encoded", "field", "value"),
    (
        (
            "decode_run_tests_execution_contract",
            lambda: repo_tools.encode_run_tests_execution_contract(
                _run_tests_execution_contract()
            ),
            "execution_id",
            1,
        ),
        (
            "decode_run_tests_started_envelope",
            lambda: repo_tools.encode_run_tests_started_envelope(
                repo_tools.RunTestsStartedEnvelope(
                    execution_id="1" * 64,
                    execution_contract_digest="2" * 64,
                )
            ),
            "execution_id",
            True,
        ),
        (
            "decode_run_tests_result_envelope",
            lambda: repo_tools.encode_run_tests_result_envelope(
                _run_tests_result_envelope()
            ),
            "stdout_bytes",
            "0",
        ),
    ),
)
def test_run_tests_decoders_reject_wrong_scalar_types(
    decoder: str,
    encoded: object,
    field: str,
    value: object,
) -> None:
    assert callable(encoded)
    decoded = json.loads(encoded())
    decoded[field] = value
    with pytest.raises(ValueError):
        getattr(repo_tools, decoder)(rfc8785.dumps(decoded))


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("test_mode", "developer"),
        ("tool_name", "owp.rollback_patch"),
    ),
)
def test_run_tests_execution_contract_decoder_rejects_other_mode_or_tool(
    field: str,
    value: str,
) -> None:
    encoded = repo_tools.encode_run_tests_execution_contract(
        _run_tests_execution_contract()
    )
    decoded = json.loads(encoded)
    decoded[field] = value

    with pytest.raises(ValueError):
        repo_tools.decode_run_tests_execution_contract(rfc8785.dumps(decoded))


@pytest.mark.parametrize("exit_code", (-1, 256, True))
def test_run_tests_result_decoder_rejects_invalid_exit_code(
    exit_code: int | bool,
) -> None:
    encoded = repo_tools.encode_run_tests_result_envelope(
        _run_tests_result_envelope()
    )
    decoded = json.loads(encoded)
    decoded["actual_exit_code"] = exit_code

    with pytest.raises(ValueError):
        repo_tools.decode_run_tests_result_envelope(rfc8785.dumps(decoded))


def test_classify_docker_execution_failure_preserves_existing_precedence(
) -> None:
    observed = repo_tools.DockerObservedResult(
        exit_code=137,
        output_limit_exceeded=True,
        timed_out=True,
        workspace_volume_exhausted=True,
        output_volume_exhausted=True,
    )
    assert repo_tools.classify_docker_execution_failure(observed) == (
        "OUTPUT_LIMIT"
    )
    assert repo_tools.classify_docker_execution_failure(
        repo_tools.DockerObservedResult(
            exit_code=137,
            output_limit_exceeded=False,
            timed_out=True,
            workspace_volume_exhausted=True,
            output_volume_exhausted=True,
        )
    ) == "TIMEOUT"


@pytest.mark.parametrize(
    ("workspace_exhausted", "output_exhausted", "expected"),
    (
        (True, False, "DISK_LIMIT"),
        (False, True, "DISK_LIMIT"),
        (False, False, None),
    ),
)
def test_classify_docker_execution_failure_uses_structured_volume_observation(
    workspace_exhausted: bool,
    output_exhausted: bool,
    expected: str | None,
) -> None:
    observed = repo_tools.DockerObservedResult(
        exit_code=1 if expected else 0,
        output_limit_exceeded=False,
        timed_out=False,
        workspace_volume_exhausted=workspace_exhausted,
        output_volume_exhausted=output_exhausted,
    )

    assert repo_tools.classify_docker_execution_failure(observed) == expected
    assert not hasattr(observed, "stderr")


def _docker_prerequisite_unavailable(message: str) -> None:
    if os.environ.get("OPENWORKPROOF_REQUIRE_LIVE_DOCKER") == "1":
        pytest.fail(message)
    pytest.skip(message)


def _real_docker_cli_and_image(*, which=shutil.which) -> tuple[Path, str]:
    explicit_docker = os.environ.get("OPENWORKPROOF_DOCKER")
    docker_location = (
        explicit_docker if explicit_docker is not None else which("docker")
    )
    if docker_location is None:
        _docker_prerequisite_unavailable(
            "Docker CLI unavailable via OPENWORKPROOF_DOCKER or PATH"
        )
    try:
        docker_binary = Path(docker_location).expanduser().resolve()
    except (OSError, RuntimeError, ValueError) as error:
        if explicit_docker is not None:
            pytest.fail(
                "Docker CLI unavailable at explicit "
                f"OPENWORKPROOF_DOCKER path: {type(error).__name__}"
            )
        _docker_prerequisite_unavailable(
            f"Docker CLI unavailable from PATH: {type(error).__name__}"
        )
    if not docker_binary.is_file() or not os.access(docker_binary, os.X_OK):
        if explicit_docker is not None:
            pytest.fail(
                "Docker CLI unavailable at explicit "
                f"OPENWORKPROOF_DOCKER path: {docker_binary}"
            )
        _docker_prerequisite_unavailable(
            f"Docker CLI unavailable at {docker_binary}"
        )
    image_reference = os.environ.get("OPENWORKPROOF_DOCKER_TEST_IMAGE")
    if image_reference is None:
        _docker_prerequisite_unavailable(
            "immutable preloaded image reference unavailable: set "
            "OPENWORKPROOF_DOCKER_TEST_IMAGE to repository@sha256:digest"
        )
    return docker_binary, image_reference


def _require_real_docker_daemon_and_image(
    docker_binary: Path,
    image_reference: str,
    *,
    run=subprocess.run,
) -> dict:
    try:
        daemon = run(
            (str(docker_binary), "info", "--format", "{{.ServerVersion}}"),
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        _docker_prerequisite_unavailable(
            f"Docker daemon unavailable: {type(error).__name__}"
        )
    if daemon.returncode != 0:
        details = daemon.stderr.strip().splitlines()
        detail = (
            details[-1]
            if details
            else f"docker info exited {daemon.returncode}"
        )
        _docker_prerequisite_unavailable(
            f"Docker daemon unavailable: {detail}"
        )

    repository, digest = image_reference.split("@", 1)
    listed = run(
        (
            str(docker_binary),
            "image",
            "ls",
            "--digests",
            "--no-trunc",
            "--format",
            "{{.Digest}}",
            repository,
        ),
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    if digest not in listed.stdout.splitlines():
        _docker_prerequisite_unavailable(
            "immutable Docker test image is not preloaded: "
            f"{image_reference}"
        )
    image = run(
        (str(docker_binary), "image", "inspect", image_reference),
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    return json.loads(image.stdout)[0]


def _cleanup_attempted_docker_resources(
    *,
    docker_binary: Path,
    ownership_token: str,
    attempted_resources: tuple[tuple[str, str], ...],
    run=subprocess.run,
) -> tuple[str, ...]:
    docker = str(docker_binary)
    failures = []
    for resource, name in reversed(attempted_resources):
        inspect_argv = (
            (docker, "inspect", name)
            if resource == "container"
            else (docker, "volume", "inspect", name)
        )
        remove_argv = (
            (docker, "rm", "--force", "--volumes", name)
            if resource == "container"
            else (docker, "volume", "rm", name)
        )
        try:
            current = run(
                inspect_argv,
                capture_output=True,
                text=True,
                timeout=10,
            )
            if current.returncode != 0:
                continue
            inspection = json.loads(current.stdout)[0]
            labels = (
                inspection["Config"]["Labels"]
                if resource == "container"
                else inspection["Labels"]
            )
            if labels.get("openworkproof.execution-owner") != ownership_token:
                failures.append(f"retained unowned {resource}: {name}")
                continue
            cleaned = run(
                remove_argv,
                capture_output=True,
                text=True,
                timeout=15,
            )
            if cleaned.returncode != 0:
                failures.append(
                    f"cleanup {resource} exited {cleaned.returncode}: {name}"
                )
        except (
            OSError,
            subprocess.SubprocessError,
            ValueError,
            IndexError,
            KeyError,
            TypeError,
            AttributeError,
        ) as error:
            failures.append(
                f"cleanup {resource} failed: {name}: {type(error).__name__}"
            )

    try:
        container_names = run(
            (
                docker,
                "container",
                "ls",
                "--all",
                "--format",
                "{{.Names}}",
            ),
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout.splitlines()
        volume_names = run(
            (docker, "volume", "ls", "--format", "{{.Name}}"),
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout.splitlines()
        remaining = [
            name
            for resource, name in attempted_resources
            if name
            in (container_names if resource == "container" else volume_names)
        ]
        if remaining:
            failures.append("resources still exist: " + ",".join(remaining))
    except (OSError, subprocess.SubprocessError) as error:
        failures.append(
            f"post-cleanup preflight failed: {type(error).__name__}"
        )
    return tuple(failures)


def _report_docker_cleanup_failures(
    active_failure: BaseException | None,
    failures: tuple[str, ...],
) -> None:
    if not failures:
        return
    message = "Docker cleanup failures: " + "; ".join(failures)
    if active_failure is not None:
        active_failure.add_note(message)
    else:
        pytest.fail(message)


def _immutable_docker_test_image() -> str:
    return "registry.example/openworkproof/test@sha256:" + "a" * 64


def test_real_docker_auto_discovery_absence_skips(monkeypatch) -> None:
    monkeypatch.delenv("OPENWORKPROOF_DOCKER", raising=False)
    monkeypatch.setenv(
        "OPENWORKPROOF_DOCKER_TEST_IMAGE",
        _immutable_docker_test_image(),
    )
    monkeypatch.delenv("OPENWORKPROOF_REQUIRE_LIVE_DOCKER", raising=False)

    with pytest.raises(pytest.skip.Exception):
        _real_docker_cli_and_image(which=lambda _: None)


def test_real_docker_explicit_invalid_cli_fails(
    monkeypatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv(
        "OPENWORKPROOF_DOCKER",
        str(tmp_path / "missing-docker"),
    )
    monkeypatch.setenv(
        "OPENWORKPROOF_DOCKER_TEST_IMAGE",
        _immutable_docker_test_image(),
    )
    monkeypatch.delenv("OPENWORKPROOF_REQUIRE_LIVE_DOCKER", raising=False)

    with pytest.raises(pytest.fail.Exception, match="Docker CLI unavailable"):
        _real_docker_cli_and_image()


def test_required_live_docker_missing_auto_discovered_cli_fails(
    monkeypatch,
) -> None:
    monkeypatch.delenv("OPENWORKPROOF_DOCKER", raising=False)
    monkeypatch.setenv(
        "OPENWORKPROOF_DOCKER_TEST_IMAGE",
        _immutable_docker_test_image(),
    )
    monkeypatch.setenv("OPENWORKPROOF_REQUIRE_LIVE_DOCKER", "1")

    with pytest.raises(pytest.fail.Exception, match="Docker CLI unavailable"):
        _real_docker_cli_and_image(which=lambda _: None)


def test_required_live_docker_missing_image_environment_fails(
    monkeypatch,
) -> None:
    monkeypatch.setenv("OPENWORKPROOF_DOCKER", sys.executable)
    monkeypatch.delenv("OPENWORKPROOF_DOCKER_TEST_IMAGE", raising=False)
    monkeypatch.setenv("OPENWORKPROOF_REQUIRE_LIVE_DOCKER", "1")

    with pytest.raises(
        pytest.fail.Exception,
        match="immutable preloaded image reference unavailable",
    ):
        _real_docker_cli_and_image()


def test_required_live_docker_unavailable_daemon_fails(monkeypatch) -> None:
    monkeypatch.setenv("OPENWORKPROOF_REQUIRE_LIVE_DOCKER", "1")

    def unavailable_daemon(command, **kwargs):
        return subprocess.CompletedProcess(
            command,
            1,
            stdout="",
            stderr="daemon unavailable",
        )

    with pytest.raises(pytest.fail.Exception, match="Docker daemon unavailable"):
        _require_real_docker_daemon_and_image(
            Path("/usr/bin/docker"),
            _immutable_docker_test_image(),
            run=unavailable_daemon,
        )


def test_required_live_docker_exact_image_absence_fails(monkeypatch) -> None:
    monkeypatch.setenv("OPENWORKPROOF_REQUIRE_LIVE_DOCKER", "1")

    def absent_image(command, **kwargs):
        if command[1] == "info":
            return subprocess.CompletedProcess(
                command,
                0,
                stdout="29.5.2\n",
                stderr="",
            )
        if command[1:3] == ("image", "ls"):
            return subprocess.CompletedProcess(
                command,
                0,
                stdout="",
                stderr="",
            )
        raise AssertionError(f"unexpected Docker command: {command}")

    with pytest.raises(
        pytest.fail.Exception,
        match="immutable Docker test image is not preloaded",
    ):
        _require_real_docker_daemon_and_image(
            Path("/usr/bin/docker"),
            _immutable_docker_test_image(),
            run=absent_image,
        )


@pytest.mark.parametrize(
    ("resource", "name"),
    (
        ("container", "owp-attempted-container"),
        ("volume", "owp-attempted-volume"),
    ),
)
def test_docker_cleanup_removes_attempted_owned_unmarked_resource(
    resource: str,
    name: str,
) -> None:
    docker_binary = Path("/usr/bin/docker")
    ownership_token = "b" * 64
    commands = []

    def fake_docker(command, **kwargs):
        command = tuple(command)
        commands.append(command)
        expected_inspect = (
            ("inspect", name)
            if resource == "container"
            else ("volume", "inspect", name)
        )
        if command[1:] == expected_inspect:
            inspection = (
                {
                    "Config": {
                        "Labels": {
                            "openworkproof.execution-owner": ownership_token,
                        }
                    }
                }
                if resource == "container"
                else {
                    "Labels": {
                        "openworkproof.execution-owner": ownership_token,
                    }
                }
            )
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=json.dumps([inspection]),
                stderr="",
            )
        if command[1:3] == ("rm", "--force"):
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")
        if command[1:3] == ("volume", "rm"):
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")
        if command[1:3] == ("container", "ls"):
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")
        if command[1:3] == ("volume", "ls"):
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")
        raise AssertionError(f"unexpected Docker command: {command}")

    failures = _cleanup_attempted_docker_resources(
        docker_binary=docker_binary,
        ownership_token=ownership_token,
        attempted_resources=((resource, name),),
        run=fake_docker,
    )

    assert failures == ()
    expected_remove = (
        (str(docker_binary), "rm", "--force", "--volumes", name)
        if resource == "container"
        else (str(docker_binary), "volume", "rm", name)
    )
    assert expected_remove in commands


def test_docker_cleanup_retains_attempted_unowned_resource() -> None:
    docker_binary = Path("/usr/bin/docker")
    container_name = "owp-unowned-container"
    commands = []

    def fake_docker(command, **kwargs):
        command = tuple(command)
        commands.append(command)
        if command[1:] == ("inspect", container_name):
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=json.dumps(
                    [
                        {
                            "Config": {
                                "Labels": {
                                    "openworkproof.execution-owner": "c" * 64,
                                }
                            }
                        }
                    ]
                ),
                stderr="",
            )
        if command[1:3] == ("container", "ls"):
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=container_name + "\n",
                stderr="",
            )
        if command[1:3] == ("volume", "ls"):
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")
        raise AssertionError(f"unexpected Docker command: {command}")

    failures = _cleanup_attempted_docker_resources(
        docker_binary=docker_binary,
        ownership_token="b" * 64,
        attempted_resources=(("container", container_name),),
        run=fake_docker,
    )

    assert failures == (
        f"retained unowned container: {container_name}",
        f"resources still exist: {container_name}",
    )
    assert not any(command[1] == "rm" for command in commands)


def _live_runner_snapshot(
    image_reference: str,
) -> tuple[bytes, bytes, bytes]:
    candidate = (
        b"import os\n"
        b"from pathlib import Path\n"
        b"import stat\n\n"
        b"def test_copy_up_and_containment():\n"
        b"    assert (os.getuid(), os.getgid()) == (65532, 65532)\n"
        b"    for root in ('/workspace', '/output'):\n"
        b"        metadata = os.stat(root)\n"
        b"        assert (metadata.st_uid, metadata.st_gid) == (65532, 65532)\n"
        b"        assert stat.S_IMODE(metadata.st_mode) == 0o755\n"
        b"    for target in ('/workspace/forbidden', '/output/forbidden', '/root-forbidden'):\n"
        b"        try:\n"
        b"            Path(target).write_text('forbidden')\n"
        b"        except OSError:\n"
        b"            pass\n"
        b"        else:\n"
        b"            raise AssertionError(f'wrote {target}')\n"
        b"    Path('/tmp/allowed').write_text('allowed')\n"
        b"    assert not Path('/var/run/docker.sock').exists()\n"
    )
    path = "test_copy_up.py"
    candidate_commit = "2" * 40
    manifest = repo_tools.WorkspaceManifest(
        schema_version="openworkproof-workspace-manifest/0.1",
        head_commit=candidate_commit,
        entries=(
            repo_tools.WorkspaceManifestEntry(
                path_bytes_b64url=base64.urlsafe_b64encode(
                    path.encode("ascii")
                ).rstrip(b"=").decode("ascii"),
                type="regular",
                posix_mode="100644",
                size_bytes=len(candidate),
                sha256=hashlib.sha256(candidate).hexdigest(),
                symlink_target_b64url=None,
            ),
        ),
    )
    contract = {
        "arguments_digest": "3" * 64,
        "candidate_commit": candidate_commit,
        "candidate_workspace_id": "4" * 64,
        "command_digest": repo_tools.frozen_verifier_command_digest(),
        "container_image_digest": image_reference.split("@", 1)[1],
        "execution_id": "6" * 64,
        "fixed_test_source_digest": "7" * 64,
        "request_digest": "8" * 64,
        "schema_version": "openworkproof-run-contract/0.1",
        "source_artifact_sha256": "9" * 64,
        "source_commit": "1" * 40,
        "test_mode": "verifier",
        "tool_name": "owp.run_tests",
        "workspace_manifest_digest": repo_tools.workspace_manifest_digest(
            manifest
        ),
    }
    contract_bytes = rfc8785.dumps(contract)
    header_bytes = rfc8785.dumps(
        {
            "contract": {
                "sha256": hashlib.sha256(contract_bytes).hexdigest(),
                "size_bytes": len(contract_bytes),
            },
            "files": [
                {
                    "mode": "100644",
                    "path": path,
                    "sha256": hashlib.sha256(candidate).hexdigest(),
                    "size_bytes": len(candidate),
                }
            ],
            "schema_version": "openworkproof-snapshot-stream/0.1",
        }
    )
    stream = (
        b"openworkproof-snapshot-stream/0.1\n"
        + len(header_bytes).to_bytes(4, "big")
        + header_bytes
        + candidate
        + contract_bytes
    )
    contract_digest = hashlib.sha256(contract_bytes).hexdigest()
    summary = rfc8785.dumps(
        {
            "execution_contract_digest": contract_digest,
            "execution_id": contract["execution_id"],
            "workspace_manifest_digest": contract[
                "workspace_manifest_digest"
            ],
        }
    ) + b"\n"
    started = rfc8785.dumps(
        {
            "execution_contract_digest": contract_digest,
            "execution_id": contract["execution_id"],
            "schema_version": "openworkproof-run-started/0.1",
        }
    )
    return stream, summary, started


@pytest.mark.docker
def test_real_docker_enforces_frozen_containment_profile() -> None:
    docker_binary, image_reference = _real_docker_cli_and_image()

    suffix = f"{os.getpid()}-{time.time_ns()}"
    ownership_token = hashlib.sha256(suffix.encode("ascii")).hexdigest()
    snapshot, expected_summary, expected_started = _live_runner_snapshot(
        image_reference
    )
    plan = repo_tools.derive_docker_execution_plan(
        docker_binary=docker_binary,
        image_reference=image_reference,
        container_name=f"owp-container-{suffix}",
        workspace_volume_name=f"owp-workspace-{suffix}",
        output_volume_name=f"owp-output-{suffix}",
        ownership_token=ownership_token,
        command=("execute",),
    )
    image_inspection = _require_real_docker_daemon_and_image(
        docker_binary,
        image_reference,
    )
    preflight_outputs = []
    for preflight_command in plan.preflight_absent_argv:
        checked = subprocess.run(
            preflight_command,
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
        preflight_outputs.append(tuple(checked.stdout.splitlines()))
    lifecycle = repo_tools.validate_docker_preflight_absent(
        plan,
        repo_tools.DockerPreflightObservation(
            container_names=preflight_outputs[0],
            volume_names=preflight_outputs[1],
        ),
    )
    attempted_resources = []
    try:
        attempted_resources.append(("volume", plan.workspace_volume.name))
        subprocess.run(
            plan.workspace_volume.create_argv,
            check=True,
            capture_output=True,
            text=True,
            timeout=15,
        )
        lifecycle = repo_tools.mark_docker_resource_created(
            plan,
            lifecycle,
            "workspace_volume",
        )
        assert subprocess.run(
            (
                str(docker_binary),
                "volume",
                "inspect",
                plan.output_volume.name,
            ),
            capture_output=True,
            text=True,
            timeout=10,
        ).returncode != 0
        staging_name = f"owp-stage-{suffix}"
        attempted_resources.append(("container", staging_name))
        subprocess.run(
            (
                str(docker_binary),
                "create",
                "--name",
                staging_name,
                "--label",
                f"openworkproof.execution-owner={ownership_token}",
                "--pull",
                "never",
                "--network",
                "none",
                "--read-only",
                "--user",
                "65532:65532",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--interactive",
                "--mount",
                (
                    f"type=volume,source={plan.workspace_volume.name},"
                    "target=/workspace"
                ),
                image_reference,
                "stage",
            ),
            check=True,
            capture_output=True,
            text=True,
            timeout=15,
        )
        staged = subprocess.run(
            (
                str(docker_binary),
                "start",
                "--attach",
                "--interactive",
                staging_name,
            ),
            input=snapshot,
            capture_output=True,
            timeout=30,
        )
        assert staged.returncode == 0, staged.stderr
        assert staged.stdout == expected_summary
        subprocess.run(
            (str(docker_binary), "rm", staging_name),
            check=True,
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert subprocess.run(
            (str(docker_binary), "inspect", staging_name),
            capture_output=True,
            text=True,
            timeout=10,
        ).returncode != 0

        attempted_resources.append(("volume", plan.output_volume.name))
        subprocess.run(
            plan.output_volume.create_argv,
            check=True,
            capture_output=True,
            text=True,
            timeout=15,
        )
        lifecycle = repo_tools.mark_docker_resource_created(
            plan,
            lifecycle,
            "output_volume",
        )
        attempted_resources.append(("container", plan.container_name))
        subprocess.run(
            plan.create_container_argv,
            check=True,
            capture_output=True,
            text=True,
            timeout=15,
        )
        lifecycle = repo_tools.mark_docker_resource_created(
            plan,
            lifecycle,
            "container",
        )
        inspection = subprocess.run(
            (str(docker_binary), "inspect", plan.container_name),
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
        inspected = json.loads(inspection.stdout)[0]
        workspace_inspection = json.loads(
            subprocess.run(
                (
                    str(docker_binary),
                    "volume",
                    "inspect",
                    plan.workspace_volume.name,
                ),
                check=True,
                capture_output=True,
                text=True,
                timeout=10,
            ).stdout
        )[0]
        output_inspection = json.loads(
            subprocess.run(
                (
                    str(docker_binary),
                    "volume",
                    "inspect",
                    plan.output_volume.name,
                ),
                check=True,
                capture_output=True,
                text=True,
                timeout=10,
            ).stdout
        )[0]
        ready = repo_tools.derive_ready_docker_start(
            plan,
            lifecycle,
            image_inspection,
            inspected,
            workspace_inspection,
            output_inspection,
        )

        executed = subprocess.run(
            ready.start_argv,
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert executed.returncode == 0, executed.stderr
        assert executed.stdout == ""
        subprocess.run(
            (str(docker_binary), "rm", plan.container_name),
            check=True,
            capture_output=True,
            text=True,
            timeout=15,
        )

        reader_name = f"owp-read-{suffix}"
        attempted_resources.append(("container", reader_name))
        subprocess.run(
            (
                str(docker_binary),
                "create",
                "--name",
                reader_name,
                "--label",
                f"openworkproof.execution-owner={ownership_token}",
                "--pull",
                "never",
                "--network",
                "none",
                "--read-only",
                "--user",
                "65532:65532",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--mount",
                (
                    f"type=volume,source={plan.output_volume.name},"
                    "target=/output,readonly"
                ),
                "--entrypoint",
                "/bin/sh",
                image_reference,
                "-c",
                "stat -c '%u:%g:%a' /output; cat /output/started.json",
            ),
            check=True,
            capture_output=True,
            text=True,
            timeout=15,
        )
        read_back = subprocess.run(
            (str(docker_binary), "start", "--attach", reader_name),
            capture_output=True,
            timeout=30,
        )
        assert read_back.returncode == 0, read_back.stderr
        assert read_back.stdout == b"65532:65532:755\n" + expected_started
        subprocess.run(
            (str(docker_binary), "rm", reader_name),
            check=True,
            capture_output=True,
            text=True,
            timeout=15,
        )
    finally:
        active_failure = sys.exc_info()[1]
        cleanup_failures = _cleanup_attempted_docker_resources(
            docker_binary=docker_binary,
            ownership_token=ownership_token,
            attempted_resources=tuple(attempted_resources),
        )
        _report_docker_cleanup_failures(active_failure, cleanup_failures)


@pytest.mark.docker
@pytest.mark.parametrize(
    ("resource", "mount_path"),
    (
        ("workspace_volume", "/workspace"),
        ("output_volume", "/output"),
    ),
)
def test_real_docker_named_volume_persists_across_short_lived_containers(
    resource: str,
    mount_path: str,
) -> None:
    docker_binary, image_reference = _real_docker_cli_and_image()

    suffix = f"persist-{resource[:3]}-{os.getpid()}-{time.time_ns()}"
    ownership_token = hashlib.sha256(suffix.encode("ascii")).hexdigest()
    marker = f"persistent-{resource}-{ownership_token[:16]}"
    writer_name = f"owp-write-{suffix}"
    reader_name = f"owp-read-{suffix}"
    plan = repo_tools.derive_docker_execution_plan(
        docker_binary=docker_binary,
        image_reference=image_reference,
        container_name=f"owp-{suffix}",
        workspace_volume_name=f"owp-workspace-{suffix}",
        output_volume_name=f"owp-output-{suffix}",
        ownership_token=ownership_token,
        command=("/bin/sh", "-c", "true"),
    )
    target_volume = (
        plan.workspace_volume
        if resource == "workspace_volume"
        else plan.output_volume
    )
    assert target_volume.mount_path == mount_path

    _require_real_docker_daemon_and_image(docker_binary, image_reference)

    preflight_outputs = []
    for preflight_command in plan.preflight_absent_argv:
        checked = subprocess.run(
            preflight_command,
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
        preflight_outputs.append(tuple(checked.stdout.splitlines()))
    repo_tools.validate_docker_preflight_absent(
        plan,
        repo_tools.DockerPreflightObservation(
            container_names=preflight_outputs[0],
            volume_names=preflight_outputs[1],
        ),
    )

    attempted_resources = []
    try:
        attempted_resources.append(("volume", target_volume.name))
        subprocess.run(
            target_volume.create_argv,
            check=True,
            capture_output=True,
            text=True,
            timeout=15,
        )
        inspected_volume = json.loads(
            subprocess.run(
                (
                    str(docker_binary),
                    "volume",
                    "inspect",
                    target_volume.name,
                ),
                check=True,
                capture_output=True,
                text=True,
                timeout=10,
            ).stdout
        )[0]
        assert inspected_volume["Name"] == target_volume.name
        assert inspected_volume["Driver"] == "local"
        assert inspected_volume["Labels"] == {
            "openworkproof.execution-owner": ownership_token,
        }
        assert inspected_volume["Options"] is None
        assert inspected_volume["Scope"] == "local"

        attempted_resources.append(("container", writer_name))
        subprocess.run(
            (
                str(docker_binary),
                "create",
                "--name",
                writer_name,
                "--label",
                f"openworkproof.execution-owner={ownership_token}",
                "--pull",
                "never",
                "--network",
                "none",
                "--read-only",
                "--user",
                "65532:65532",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,size=256m",
                "--mount",
                (
                    f"type=volume,source={target_volume.name},"
                    f"target={mount_path}"
                ),
                "--entrypoint",
                "/bin/sh",
                image_reference,
                "-c",
                f"printf %s {marker!r} > {mount_path}/marker",
            ),
            check=True,
            capture_output=True,
            text=True,
            timeout=15,
        )
        written = subprocess.run(
            (str(docker_binary), "start", "--attach", writer_name),
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert written.returncode == 0, written.stderr
        subprocess.run(
            (str(docker_binary), "rm", writer_name),
            check=True,
            capture_output=True,
            text=True,
            timeout=15,
        )

        attempted_resources.append(("container", reader_name))
        subprocess.run(
            (
                str(docker_binary),
                "create",
                "--name",
                reader_name,
                "--label",
                f"openworkproof.execution-owner={ownership_token}",
                "--pull",
                "never",
                "--network",
                "none",
                "--read-only",
                "--user",
                "65532:65532",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,size=256m",
                "--mount",
                (
                    f"type=volume,source={target_volume.name},"
                    f"target={mount_path},readonly"
                ),
                "--entrypoint",
                "/bin/sh",
                image_reference,
                "-c",
                f"cat {mount_path}/marker",
            ),
            check=True,
            capture_output=True,
            text=True,
            timeout=15,
        )
        read_back = subprocess.run(
            (str(docker_binary), "start", "--attach", reader_name),
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert read_back.returncode == 0, read_back.stderr
        assert read_back.stdout == marker
        subprocess.run(
            (str(docker_binary), "rm", reader_name),
            check=True,
            capture_output=True,
            text=True,
            timeout=15,
        )
    finally:
        active_failure = sys.exc_info()[1]
        cleanup_failures = _cleanup_attempted_docker_resources(
            docker_binary=docker_binary,
            ownership_token=ownership_token,
            attempted_resources=tuple(attempted_resources),
        )
        _report_docker_cleanup_failures(active_failure, cleanup_failures)


def test_purge_expired_evidence_leaves_nonexpired_root_untouched(
    tmp_path: Path,
) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir(mode=0o700)
    artifact = evidence_root / "result.json"
    artifact.write_bytes(b"{}")
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)

    result = repo_tools.purge_expired_evidence(
        evidence_root,
        retention_until=now + timedelta(seconds=1),
        now=now,
    )

    assert result.eligible is False
    assert result.removed_entries == 0
    assert artifact.read_bytes() == b"{}"


def test_purge_expired_evidence_removes_only_descendants_without_following_symlink(
    tmp_path: Path,
) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir(mode=0o700)
    nested = evidence_root / "nested"
    nested.mkdir()
    (nested / "result.json").write_bytes(b"{}")
    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"keep")
    (evidence_root / "outside-link").symlink_to(outside)
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)

    result = repo_tools.purge_expired_evidence(
        evidence_root,
        retention_until=now,
        now=now,
    )

    assert result.eligible is True
    assert result.removed_entries == 3
    assert evidence_root.is_dir()
    assert tuple(evidence_root.iterdir()) == ()
    assert outside.read_bytes() == b"keep"


def test_purge_expired_evidence_rejects_symlink_root_without_touching_target(
    tmp_path: Path,
) -> None:
    actual_root = tmp_path / "actual-evidence"
    actual_root.mkdir(mode=0o700)
    artifact = actual_root / "result.json"
    artifact.write_bytes(b"{}")
    linked_root = tmp_path / "linked-evidence"
    linked_root.symlink_to(actual_root, target_is_directory=True)
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)

    with pytest.raises(repo_tools.EvidencePurgeError):
        repo_tools.purge_expired_evidence(linked_root, now, now)

    assert artifact.read_bytes() == b"{}"


@pytest.mark.parametrize(
    "invalid_time",
    (
        datetime(2026, 1, 1),
        datetime(2026, 1, 1, microsecond=1, tzinfo=timezone.utc),
    ),
)
def test_purge_expired_evidence_rejects_noncanonical_time_without_deleting(
    tmp_path: Path,
    invalid_time: datetime,
) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir(mode=0o700)
    artifact = evidence_root / "result.json"
    artifact.write_bytes(b"{}")
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)

    with pytest.raises(repo_tools.EvidencePurgeError):
        repo_tools.purge_expired_evidence(
            evidence_root,
            retention_until=invalid_time,
            now=now,
        )

    assert artifact.read_bytes() == b"{}"


def test_purge_expired_evidence_rejects_oversized_tree_before_deleting(
    tmp_path: Path,
) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir(mode=0o700)
    for ordinal in range(1_025):
        (evidence_root / f"{ordinal:04d}.json").write_bytes(b"{}")
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)

    with pytest.raises(repo_tools.EvidencePurgeError):
        repo_tools.purge_expired_evidence(evidence_root, now, now)

    assert len(tuple(evidence_root.iterdir())) == 1_025
