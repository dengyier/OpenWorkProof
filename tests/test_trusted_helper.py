"""Trusted helper repository read boundary tests."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import socket
import stat
import subprocess
import tempfile

import pytest

from openworkproof.models import RepoReadOutput
import openworkproof.repo_tools as repo_tools


def _candidate(
    tmp_path: Path,
    content: bytes,
    *,
    source_path: str = "README.md",
) -> repo_tools.CandidateWorkspace:
    files = (repo_tools.SourceFile(source_path, "100644", content),)
    tree_oid = repo_tools.git_tree_oid(files)
    commit_raw = (
        f"tree {tree_oid}\n"
        "author OpenWorkProof <owp@example.invalid> 0 +0000\n"
        "committer OpenWorkProof <owp@example.invalid> 0 +0000\n"
        "\n"
        "base\n"
    ).encode("ascii")
    source = repo_tools.ParsedSourceArchive(
        files=files,
        commit_raw=commit_raw,
        tree_oid=tree_oid,
        source_commit=repo_tools.git_commit_oid(commit_raw),
        artifact_sha256="a" * 64,
        artifact_size_bytes=1,
        shallow_bytes=None,
    )
    runtime_root = tmp_path / "runtime"
    runtime_root.mkdir(mode=0o700)
    return repo_tools.initialize_candidate_workspace(
        repo_tools.WorkspaceInitRequest(
            runtime_root=runtime_root,
            workspace_id="b" * 64,
            source=source,
        )
    )


def _request(
    candidate: repo_tools.CandidateWorkspace,
    *,
    path: str = "README.md",
    source_artifact_sha256: str | None = None,
    expected_head_commit: str | None = None,
    expected_workspace_manifest_digest: str | None = None,
) -> repo_tools.CandidateReadRequest:
    return repo_tools.CandidateReadRequest(
        runtime_root=candidate.runtime_root,
        workspace_id=candidate.workspace_id,
        source_artifact_sha256=(
            candidate.source_artifact_sha256
            if source_artifact_sha256 is None
            else source_artifact_sha256
        ),
        expected_head_commit=(
            candidate.head_commit
            if expected_head_commit is None
            else expected_head_commit
        ),
        expected_workspace_manifest_digest=(
            candidate.workspace_manifest_digest
            if expected_workspace_manifest_digest is None
            else expected_workspace_manifest_digest
        ),
        path=path,
    )


def _manifest(
    candidate: repo_tools.CandidateWorkspace,
) -> repo_tools.WorkspaceManifest:
    descriptor = os.open(
        candidate.worktree,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
    )
    try:
        return repo_tools.scan_workspace_manifest(descriptor, candidate.head_commit)
    finally:
        os.close(descriptor)


def test_read_candidate_file_returns_exact_closed_result(tmp_path: Path) -> None:
    candidate = _candidate(tmp_path, b"base\n")
    result = repo_tools.read_candidate_file(_request(candidate))
    assert result.content == b"base\n"
    assert result.output == RepoReadOutput(
        path="README.md",
        content_sha256=hashlib.sha256(b"base\n").hexdigest(),
        size_bytes=5,
        workspace_manifest_digest=candidate.workspace_manifest_digest,
    )


def test_read_candidate_file_returns_empty_file(tmp_path: Path) -> None:
    candidate = _candidate(tmp_path, b"")

    result = repo_tools.read_candidate_file(_request(candidate))

    assert result.content == b""
    assert result.output.size_bytes == 0


def test_read_candidate_file_returns_exact_64_kib(tmp_path: Path) -> None:
    content = b"x" * 65_536
    candidate = _candidate(tmp_path, content)

    result = repo_tools.read_candidate_file(_request(candidate))

    assert result.content == content
    assert result.output.size_bytes == 65_536


def test_read_candidate_file_denies_file_larger_than_64_kib(
    tmp_path: Path,
) -> None:
    candidate = _candidate(tmp_path, b"x" * 65_537)

    with pytest.raises(repo_tools.CandidateReadError) as raised:
        repo_tools.read_candidate_file(_request(candidate))

    assert raised.value.code == "PATH_DENIED"


def test_read_candidate_file_denies_directory(tmp_path: Path) -> None:
    candidate = _candidate(tmp_path, b"base\n", source_path="src/README.md")

    with pytest.raises(repo_tools.CandidateReadError) as raised:
        repo_tools.read_candidate_file(_request(candidate, path="src"))

    assert raised.value.code == "PATH_DENIED"


def test_read_candidate_file_denies_symlink(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = _candidate(tmp_path, b"base\n")
    manifest = _manifest(candidate)
    target = candidate.worktree / "README.md"
    target.unlink()
    target.symlink_to("missing")
    monkeypatch.setattr(
        repo_tools,
        "_verify_candidate_checkpoint_read_only",
        lambda workspace: manifest,
    )

    with pytest.raises(repo_tools.CandidateReadError) as raised:
        repo_tools.read_candidate_file(_request(candidate))

    assert raised.value.code == "PATH_DENIED"


def test_read_candidate_file_denies_ancestor_symlink(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = _candidate(tmp_path, b"base\n", source_path="src/README.md")
    manifest = _manifest(candidate)
    target = candidate.worktree / "src"
    (target / "README.md").unlink()
    target.rmdir()
    target.symlink_to("missing")
    monkeypatch.setattr(
        repo_tools,
        "_verify_candidate_checkpoint_read_only",
        lambda workspace: manifest,
    )

    with pytest.raises(repo_tools.CandidateReadError) as raised:
        repo_tools.read_candidate_file(_request(candidate, path="src/README.md"))

    assert raised.value.code == "PATH_DENIED"


def test_read_candidate_file_denies_hardlink(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = _candidate(tmp_path, b"base\n")
    manifest = _manifest(candidate)
    external = tmp_path / "external"
    external.write_bytes(b"base\n")
    target = candidate.worktree / "README.md"
    target.unlink()
    os.link(external, target)
    monkeypatch.setattr(
        repo_tools,
        "_verify_candidate_checkpoint_read_only",
        lambda workspace: manifest,
    )

    with pytest.raises(repo_tools.CandidateReadError) as raised:
        repo_tools.read_candidate_file(_request(candidate))

    assert raised.value.code == "PATH_DENIED"


def test_read_candidate_file_denies_fifo(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = _candidate(tmp_path, b"base\n")
    manifest = _manifest(candidate)
    target = candidate.worktree / "README.md"
    target.unlink()
    os.mkfifo(target)
    monkeypatch.setattr(
        repo_tools,
        "_verify_candidate_checkpoint_read_only",
        lambda workspace: manifest,
    )

    with pytest.raises(repo_tools.CandidateReadError) as raised:
        repo_tools.read_candidate_file(_request(candidate))

    assert raised.value.code == "PATH_DENIED"


def test_read_candidate_file_denies_socket(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = _candidate(tmp_path, b"base\n")
    manifest = _manifest(candidate)
    target = candidate.worktree / "README.md"
    target.unlink()
    short_root = Path(tempfile.mkdtemp(prefix="owp-socket-", dir="/tmp"))
    short_worktree = short_root / "w"
    short_worktree.symlink_to(candidate.worktree)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(short_worktree / "README.md"))
    monkeypatch.setattr(
        repo_tools,
        "_verify_candidate_checkpoint_read_only",
        lambda workspace: manifest,
    )
    try:
        with pytest.raises(repo_tools.CandidateReadError) as raised:
            repo_tools.read_candidate_file(_request(candidate))
    finally:
        listener.close()
        short_worktree.unlink()
        short_root.rmdir()

    assert raised.value.code == "PATH_DENIED"


def test_read_candidate_file_denies_missing_path(tmp_path: Path) -> None:
    candidate = _candidate(tmp_path, b"base\n")

    with pytest.raises(repo_tools.CandidateReadError) as raised:
        repo_tools.read_candidate_file(_request(candidate, path="missing.txt"))

    assert raised.value.code == "PATH_DENIED"


def test_read_candidate_file_requires_source_digest_binding(tmp_path: Path) -> None:
    candidate = _candidate(tmp_path, b"base\n")

    with pytest.raises(repo_tools.CandidateReadError) as raised:
        repo_tools.read_candidate_file(
            _request(candidate, source_artifact_sha256="c" * 64)
        )

    assert raised.value.code == "RECOVERY_REQUIRED"


def test_read_candidate_file_requires_head_binding(tmp_path: Path) -> None:
    candidate = _candidate(tmp_path, b"base\n")

    with pytest.raises(repo_tools.CandidateReadError) as raised:
        repo_tools.read_candidate_file(
            _request(candidate, expected_head_commit="0" * 40)
        )

    assert raised.value.code == "RECOVERY_REQUIRED"


def test_read_candidate_file_requires_manifest_binding(tmp_path: Path) -> None:
    candidate = _candidate(tmp_path, b"base\n")

    with pytest.raises(repo_tools.CandidateReadError) as raised:
        repo_tools.read_candidate_file(
            _request(candidate, expected_workspace_manifest_digest="0" * 64)
        )

    assert raised.value.code == "RECOVERY_REQUIRED"


def test_read_candidate_file_rejects_changed_control(tmp_path: Path) -> None:
    candidate = _candidate(tmp_path, b"base\n")
    control = candidate.candidate_root / "control.json"
    control.write_bytes(b" " + control.read_bytes())
    control.chmod(0o600)

    with pytest.raises(repo_tools.CandidateReadError) as raised:
        repo_tools.read_candidate_file(_request(candidate))

    assert raised.value.code == "RECOVERY_REQUIRED"


def test_read_candidate_file_rejects_changed_index(tmp_path: Path) -> None:
    candidate = _candidate(tmp_path, b"base\n")
    subprocess.run(
        [
            "/usr/bin/git",
            f"--git-dir={candidate.git_dir}",
            f"--work-tree={candidate.worktree}",
            "update-index",
            "--chmod=+x",
            "README.md",
        ],
        check=True,
        capture_output=True,
        env={
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
            "LC_ALL": "C",
            "PATH": "/usr/bin:/bin",
        },
    )

    with pytest.raises(repo_tools.CandidateReadError) as raised:
        repo_tools.read_candidate_file(_request(candidate))

    assert raised.value.code == "RECOVERY_REQUIRED"


def test_read_candidate_file_rejects_changed_worktree_bytes(tmp_path: Path) -> None:
    candidate = _candidate(tmp_path, b"base\n")
    (candidate.worktree / "README.md").write_bytes(b"tampered\n")

    with pytest.raises(repo_tools.CandidateReadError) as raised:
        repo_tools.read_candidate_file(_request(candidate))

    assert raised.value.code == "RECOVERY_REQUIRED"


def test_read_candidate_file_rejects_changed_git_head(tmp_path: Path) -> None:
    candidate = _candidate(tmp_path, b"base\n")
    subprocess.run(
        [
            "/usr/bin/git",
            f"--git-dir={candidate.git_dir}",
            "update-ref",
            "-d",
            "refs/heads/candidate",
        ],
        check=True,
        capture_output=True,
        env={
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
            "LC_ALL": "C",
            "PATH": "/usr/bin:/bin",
        },
    )

    with pytest.raises(repo_tools.CandidateReadError) as raised:
        repo_tools.read_candidate_file(_request(candidate))

    assert raised.value.code == "RECOVERY_REQUIRED"


def test_read_candidate_file_rejects_post_read_identity_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = _candidate(tmp_path, b"base\n")
    manifest = _manifest(candidate)
    target_inode = (candidate.worktree / "README.md").stat().st_ino
    real_token = repo_tools._workspace_read_token
    target_calls = 0

    def drift_after_read(metadata: os.stat_result) -> str:
        nonlocal target_calls
        token = real_token(metadata)
        if metadata.st_ino == target_inode and stat.S_ISREG(metadata.st_mode):
            target_calls += 1
            if target_calls == 3:
                return token + ":drift"
        return token

    monkeypatch.setattr(
        repo_tools,
        "_verify_candidate_checkpoint_read_only",
        lambda workspace: manifest,
    )
    monkeypatch.setattr(repo_tools, "_workspace_read_token", drift_after_read)

    with pytest.raises(repo_tools.CandidateReadError) as raised:
        repo_tools.read_candidate_file(_request(candidate))

    assert target_calls == 3
    assert raised.value.code == "FILE_CHANGED"


def test_read_candidate_file_denies_noncanonical_path(tmp_path: Path) -> None:
    candidate = _candidate(tmp_path, b"base\n")

    with pytest.raises(repo_tools.CandidateReadError) as raised:
        repo_tools.read_candidate_file(_request(candidate, path="../README.md"))

    assert raised.value.code == "PATH_DENIED"


def test_read_candidate_file_requires_exact_request_field_types(
    tmp_path: Path,
) -> None:
    candidate = _candidate(tmp_path, b"base\n")
    request = _request(candidate)
    object.__setattr__(request, "runtime_root", str(candidate.runtime_root))

    with pytest.raises(repo_tools.CandidateReadError) as raised:
        repo_tools.read_candidate_file(request)

    assert raised.value.code == "RECOVERY_REQUIRED"


def test_read_candidate_file_uses_only_frozen_read_only_git_calls(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = _candidate(tmp_path, b"base\n")
    real_run = subprocess.run
    observed: list[tuple[list[str], dict[str, object]]] = []

    def observe(command: list[str], **kwargs):
        observed.append((command, kwargs))
        return real_run(command, **kwargs)

    monkeypatch.setattr(repo_tools.subprocess, "run", observe)

    result = repo_tools.read_candidate_file(_request(candidate))

    assert result.content == b"base\n"
    assert len(observed) == 4
    expected_environment = {
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }
    observed_arguments: list[tuple[str, ...]] = []
    for command, kwargs in observed:
        assert command[0] == "/usr/bin/git"
        config_index = command.index("-c")
        assert command[config_index : config_index + 6] == [
            "-c",
            "core.autocrlf=false",
            "-c",
            "core.filemode=true",
            "-c",
            "core.hooksPath=/dev/null",
        ]
        observed_arguments.append(tuple(command[config_index + 6 :]))
        assert kwargs["env"] == expected_environment
        assert kwargs["timeout"] == 30
        assert kwargs["check"] is False
        assert "status" not in command
        assert "write-tree" not in command
    assert observed_arguments == [
        ("rev-parse", "--is-bare-repository"),
        ("rev-parse", "HEAD"),
        ("cat-file", "-e", f"{candidate.head_commit}^{{commit}}"),
        (
            "diff-index",
            "--cached",
            "--quiet",
            candidate.head_commit,
            "--",
        ),
    ]


def test_read_candidate_file_closes_read_error_as_file_changed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = _candidate(tmp_path, b"base\n")
    manifest = _manifest(candidate)
    monkeypatch.setattr(
        repo_tools,
        "_verify_candidate_checkpoint_read_only",
        lambda workspace: manifest,
    )

    def fail_read(descriptor: int, size: int) -> bytes:
        raise OSError("injected read failure")

    monkeypatch.setattr(repo_tools.os, "read", fail_read)

    with pytest.raises(repo_tools.CandidateReadError) as raised:
        repo_tools.read_candidate_file(_request(candidate))

    assert raised.value.code == "FILE_CHANGED"
