"""Controlled workspace boundary tests."""

from __future__ import annotations

import base64
import copy
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


def test_derive_docker_execution_plan_is_exact_and_deterministic() -> None:
    first = _docker_plan()
    second = _docker_plan()

    assert second == first
    assert first.workspace_volume.name == "owp-workspace-01"
    assert first.workspace_volume.size_bytes == 512 * 1024 * 1024
    assert first.workspace_volume.mount_path == "/workspace"
    assert first.workspace_volume.read_only is True
    assert first.workspace_volume.create_argv == (
        "/usr/local/bin/docker",
        "volume",
        "create",
        "--driver",
        "local",
        "--opt",
        "type=tmpfs",
        "--opt",
        "device=tmpfs",
        "--opt",
        "o=size=512m",
        "--label",
        "openworkproof.execution-owner=" + "b" * 64,
        "owp-workspace-01",
    )
    assert first.output_volume.name == "owp-output-01"
    assert first.output_volume.size_bytes == 64 * 1024 * 1024
    assert first.output_volume.mount_path == "/output"
    assert first.output_volume.read_only is False
    assert first.output_volume.create_argv == (
        "/usr/local/bin/docker",
        "volume",
        "create",
        "--driver",
        "local",
        "--opt",
        "type=tmpfs",
        "--opt",
        "device=tmpfs",
        "--opt",
        "o=size=64m",
        "--label",
        "openworkproof.execution-owner=" + "b" * 64,
        "owp-output-01",
    )
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
            "target=/workspace,readonly,volume-nocopy"
        ),
        "--mount",
        (
            "type=volume,source=owp-output-01,"
            "target=/output,volume-nocopy"
        ),
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
            "target=/workspace,readonly,volume-nocopy"
        ),
        (
            "type=volume,source=owp-output-01,"
            "target=/output,volume-nocopy"
        ),
    )
    assert first.start_container_argv == (
        "/usr/local/bin/docker",
        "start",
        "--attach",
        "owp-container-01",
    )
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
    size = "512m" if resource == "workspace_volume" else "64m"
    return {
        "Name": volume.name,
        "Driver": "local",
        "Labels": {
            "openworkproof.execution-owner": plan.ownership_token,
        },
        "Options": {
            "type": "tmpfs",
            "device": "tmpfs",
            "o": f"size={size}",
        },
    }


def _docker_container_inspection(
    plan: repo_tools.DockerExecutionPlan,
) -> dict:
    return {
        "Name": f"/{plan.container_name}",
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
                    "VolumeOptions": {"NoCopy": True},
                },
                {
                    "Type": "volume",
                    "Source": plan.output_volume.name,
                    "Target": "/output",
                    "ReadOnly": False,
                    "VolumeOptions": {"NoCopy": True},
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


def test_docker_lifecycle_requires_absence_and_cleans_only_created_owned(
) -> None:
    plan = _docker_plan()
    state = repo_tools.validate_docker_preflight_absent(
        plan,
        repo_tools.DockerPreflightObservation(
            container_names=(),
            workspace_volume_names=(),
            output_volume_names=(),
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
        repo_tools.DockerPreflightObservation((), (), ()),
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
        ("workspace_volume_names", ("owp-workspace-01",)),
        ("output_volume_names", ("owp-output-01",)),
    ),
)
def test_docker_lifecycle_rejects_preexisting_resource(
    field: str,
    names: tuple[str, ...],
) -> None:
    plan = _docker_plan()
    values = {
        "container_names": (),
        "workspace_volume_names": (),
        "output_volume_names": (),
        field: names,
    }
    with pytest.raises(ValueError, match="already exists"):
        repo_tools.validate_docker_preflight_absent(
            plan,
            repo_tools.DockerPreflightObservation(**values),
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
            "NoCopy": False,
        }
    elif mutation == "extra_tmpfs":
        container["HostConfig"]["Tmpfs"]["/cache"] = "rw,size=1m"
    elif mutation == "wrong_volume_driver":
        workspace["Driver"] = "other"
    elif mutation == "wrong_volume_options":
        output["Options"]["o"] = "size=65m"
    else:
        container["Config"]["Labels"] = {}

    with pytest.raises(ValueError, match="Docker inspection"):
        repo_tools.validate_docker_execution_inspections(
            plan,
            container,
            workspace,
            output,
        )


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


@pytest.mark.docker
def test_real_docker_enforces_frozen_containment_profile() -> None:
    docker_location = os.environ.get("OPENWORKPROOF_DOCKER") or shutil.which(
        "docker"
    )
    if docker_location is None:
        pytest.skip("Docker CLI unavailable via OPENWORKPROOF_DOCKER or PATH")
    docker_binary = Path(docker_location).expanduser().resolve()
    if not docker_binary.is_file() or not os.access(docker_binary, os.X_OK):
        pytest.skip(f"Docker CLI unavailable at {docker_binary}")
    daemon = subprocess.run(
        (str(docker_binary), "info", "--format", "{{.ServerVersion}}"),
        capture_output=True,
        text=True,
        timeout=10,
    )
    if daemon.returncode != 0:
        details = daemon.stderr.strip().splitlines()
        detail = details[-1] if details else f"docker info exited {daemon.returncode}"
        pytest.skip(f"Docker daemon unavailable: {detail}")

    image_reference = os.environ.get("OPENWORKPROOF_DOCKER_TEST_IMAGE")
    if image_reference is None:
        pytest.skip(
            "immutable preloaded image reference unavailable: set "
            "OPENWORKPROOF_DOCKER_TEST_IMAGE to repository@sha256:digest"
        )
    image = subprocess.run(
        (str(docker_binary), "image", "inspect", image_reference),
        capture_output=True,
        text=True,
        timeout=10,
    )
    if image.returncode != 0:
        pytest.skip(
            "immutable Docker test image is not preloaded: "
            f"{image_reference}"
        )

    suffix = f"{os.getpid()}-{time.time_ns()}"
    ownership_token = hashlib.sha256(suffix.encode("ascii")).hexdigest()
    script = (
        "set -eu; "
        "test \"$(id -u):$(id -g)\" = 65532:65532; "
        "if touch /workspace/forbidden 2>/dev/null; then exit 41; fi; "
        "if touch /root-forbidden 2>/dev/null; then exit 42; fi; "
        "touch /output/allowed; touch /tmp/allowed; "
        "test ! -e /var/run/docker.sock; "
        "printf containment-ok"
    )
    plan = repo_tools.derive_docker_execution_plan(
        docker_binary=docker_binary,
        image_reference=image_reference,
        container_name=f"owp-container-{suffix}",
        workspace_volume_name=f"owp-workspace-{suffix}",
        output_volume_name=f"owp-output-{suffix}",
        ownership_token=ownership_token,
        command=("/bin/sh", "-c", script),
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
            workspace_volume_names=preflight_outputs[1],
            output_volume_names=preflight_outputs[2],
        ),
    )
    try:
        for resource, volume in (
            ("workspace_volume", plan.workspace_volume),
            ("output_volume", plan.output_volume),
        ):
            subprocess.run(
                volume.create_argv,
                check=True,
                capture_output=True,
                text=True,
                timeout=15,
            )
            lifecycle = repo_tools.mark_docker_resource_created(
                plan,
                lifecycle,
                resource,
            )
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
        repo_tools.validate_docker_execution_inspections(
            plan,
            inspected,
            workspace_inspection,
            output_inspection,
        )

        executed = subprocess.run(
            plan.start_container_argv,
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert executed.returncode == 0, executed.stderr
        assert executed.stdout == "containment-ok"
    finally:
        current_inspections = {}
        inspection_commands = {
            "container": (
                str(docker_binary),
                "inspect",
                plan.container_name,
            ),
            "workspace_volume": (
                str(docker_binary),
                "volume",
                "inspect",
                plan.workspace_volume.name,
            ),
            "output_volume": (
                str(docker_binary),
                "volume",
                "inspect",
                plan.output_volume.name,
            ),
        }
        for resource in lifecycle.created_resources:
            try:
                current = subprocess.run(
                    inspection_commands[resource],
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                current_inspections[resource] = json.loads(current.stdout)[0]
            except (OSError, subprocess.SubprocessError, ValueError, IndexError):
                continue
        cleanup = repo_tools.derive_docker_cleanup_plan(
            plan,
            lifecycle,
            current_inspections,
        )
        for cleanup_command in cleanup.commands:
            try:
                subprocess.run(
                    cleanup_command,
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
            except (OSError, subprocess.SubprocessError):
                continue


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
