"""Trusted helper repository read boundary tests."""

from __future__ import annotations

import base64
from dataclasses import replace
import hashlib
import inspect
import io
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import tempfile

import pytest
import rfc8785

from openworkproof.models import RepoReadOutput
import openworkproof.repo_tools as repo_tools
import openworkproof.trusted_helper as trusted_helper


def _candidate(
    tmp_path: Path,
    content: bytes,
    *,
    source_path: str = "README.md",
    additional_files: tuple[repo_tools.SourceFile, ...] = (),
) -> repo_tools.CandidateWorkspace:
    files = (
        repo_tools.SourceFile(source_path, "100644", content),
        *additional_files,
    )
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


def _rebound_snapshot_candidate(
    candidate: repo_tools.CandidateWorkspace,
    files: tuple[repo_tools.SourceFile, ...],
) -> repo_tools.CandidateWorkspace:
    (candidate.worktree / "README.md").unlink()
    for source_file in files:
        target = candidate.worktree / source_file.path
        target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        target.write_bytes(source_file.content)
        target.chmod(0o755 if source_file.mode == "100755" else 0o644)
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
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }

    def git(*arguments: str, input_bytes: bytes | None = None) -> bytes:
        return subprocess.run(
            [
                "/usr/bin/git",
                f"--git-dir={candidate.git_dir}",
                f"--work-tree={candidate.worktree}",
                "-c",
                "core.hooksPath=/dev/null",
                *arguments,
            ],
            input=input_bytes,
            check=True,
            capture_output=True,
            env=environment,
            cwd=candidate.worktree,
        ).stdout

    git("add", "-A")
    tree_oid = git("write-tree").decode("ascii").strip()
    head_commit = git(
        "commit-tree",
        tree_oid,
        "-p",
        candidate.head_commit,
        input_bytes=b"snapshot byte boundary\n",
    ).decode("ascii").strip()
    git("update-ref", "refs/heads/candidate", head_commit)
    git("reset", "--hard", head_commit)
    worktree_fd = os.open(
        candidate.worktree,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
    )
    try:
        manifest = repo_tools.scan_workspace_manifest(
            worktree_fd,
            head_commit,
        )
    finally:
        os.close(worktree_fd)
    manifest_digest = repo_tools.workspace_manifest_digest(manifest)
    control = rfc8785.dumps(
        {
            "schema_version": "openworkproof-candidate-control/0.1",
            "workspace_id": candidate.workspace_id,
            "source_artifact_sha256": candidate.source_artifact_sha256,
            "head_commit": head_commit,
            "workspace_manifest_digest": manifest_digest,
            "worktree_inode": candidate.worktree.stat().st_ino,
            "git_inode": candidate.git_dir.stat().st_ino,
        }
    )
    control_path = candidate.candidate_root / "control.json"
    control_path.write_bytes(control)
    control_path.chmod(0o600)
    return replace(
        candidate,
        head_commit=head_commit,
        workspace_manifest_digest=manifest_digest,
    )


def _snapshot_files_with_total_size(
    total_size: int,
) -> tuple[repo_tools.SourceFile, ...]:
    files: list[repo_tools.SourceFile] = []
    remaining = total_size
    index = 0
    while remaining:
        size = min(remaining, 1_048_576)
        files.append(
            repo_tools.SourceFile(
                f"file-{index:02d}.bin",
                "100644",
                bytes([index]) * size,
            )
        )
        remaining -= size
        index += 1
    return tuple(files)


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


def _snapshot_request(
    candidate: repo_tools.CandidateWorkspace,
    *,
    source_artifact_sha256: str | None = None,
    expected_head_commit: str | None = None,
    expected_workspace_manifest_digest: str | None = None,
) -> repo_tools.CandidateExecutionSnapshotRequest:
    return repo_tools.CandidateExecutionSnapshotRequest(
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
    )


def _assert_snapshot_recovery(
    candidate: repo_tools.CandidateWorkspace,
    request: object | None = None,
) -> None:
    with pytest.raises(repo_tools.CandidateReadError) as raised:
        repo_tools.prepare_candidate_execution_snapshot(
            _snapshot_request(candidate) if request is None else request
        )
    assert raised.value.code == "RECOVERY_REQUIRED"


def _install_snapshot_aba_weave(
    candidate: repo_tools.CandidateWorkspace,
    monkeypatch: pytest.MonkeyPatch,
    *,
    directory: str = "",
) -> tuple[Path, Path, dict[str, int | bool]]:
    prefix = f"{directory}/" if directory else ""
    a_path = candidate.worktree / prefix / "a.txt"
    b_path = candidate.worktree / prefix / "b.txt"
    real_scan = repo_tools.scan_workspace_manifest
    real_stat = repo_tools.os.stat
    state: dict[str, int | bool] = {
        "scan_calls": 0,
        "woven_a_stats": 0,
        "weaving": False,
    }

    def interleave_file_reads(path: str) -> None:
        if path == f"{prefix}a.txt":
            b_path.write_bytes(b"evil!\n")
        elif path == f"{prefix}b.txt":
            a_path.write_bytes(b"evil!\n")
            b_path.write_bytes(b"bravo\n")

    def weave_manifest_scan(
        root_fd: int,
        head_commit: str,
    ) -> repo_tools.WorkspaceManifest:
        state["scan_calls"] = int(state["scan_calls"]) + 1
        state["weaving"] = state["scan_calls"] == 2
        try:
            return real_scan(root_fd, head_commit)
        finally:
            state["weaving"] = False

    def weave_siblings(
        path,
        *,
        dir_fd=None,
        follow_symlinks=True,
    ) -> os.stat_result:
        if state["weaving"] and path == "a.txt":
            state["woven_a_stats"] = int(state["woven_a_stats"]) + 1
            if state["woven_a_stats"] == 1:
                a_path.write_bytes(b"alpha\n")
                return real_stat(
                    path,
                    dir_fd=dir_fd,
                    follow_symlinks=follow_symlinks,
                )
            if state["woven_a_stats"] == 2:
                metadata = real_stat(
                    path,
                    dir_fd=dir_fd,
                    follow_symlinks=follow_symlinks,
                )
                a_path.write_bytes(b"evil!\n")
                return metadata
        return real_stat(
            path,
            dir_fd=dir_fd,
            follow_symlinks=follow_symlinks,
        )

    monkeypatch.setattr(
        repo_tools,
        "_candidate_execution_snapshot_file_hook",
        interleave_file_reads,
    )
    monkeypatch.setattr(
        repo_tools,
        "scan_workspace_manifest",
        weave_manifest_scan,
    )
    monkeypatch.setattr(repo_tools.os, "stat", weave_siblings)
    return a_path, b_path, state


def _dispatcher_request(
    candidate: repo_tools.CandidateWorkspace,
    *,
    path: str = "README.md",
) -> dict[str, object]:
    return {
        "schema_version": trusted_helper.REQUEST_SCHEMA,
        "operation": "repo_read",
        "workspace_id": candidate.workspace_id,
        "source_artifact_sha256": candidate.source_artifact_sha256,
        "expected_head_commit": candidate.head_commit,
        "expected_workspace_manifest_digest": (
            candidate.workspace_manifest_digest
        ),
        "path": path,
    }


def test_dispatcher_returns_exact_canonical_success(tmp_path: Path) -> None:
    candidate = _candidate(tmp_path, b"base\n")
    stdin = io.BytesIO(rfc8785.dumps(_dispatcher_request(candidate)))
    stdout = io.BytesIO()

    exit_code = trusted_helper.main((), stdin, stdout, candidate.runtime_root)

    assert exit_code == 0
    assert stdout.getvalue() == rfc8785.dumps(
        {
            "schema_version": trusted_helper.RESPONSE_SCHEMA,
            "status": "ok",
            "result": {
                "path": "README.md",
                "content_sha256": hashlib.sha256(b"base\n").hexdigest(),
                "size_bytes": 5,
                "workspace_manifest_digest": (
                    candidate.workspace_manifest_digest
                ),
            },
            "content_b64url": base64.urlsafe_b64encode(b"base\n")
            .decode("ascii")
            .rstrip("="),
        }
    )


def test_dispatcher_rejects_argv_before_reading_stdin() -> None:
    class UnreadableInput:
        def read(self, size: int) -> bytes:
            raise AssertionError(f"stdin read unexpectedly with size {size}")

    stdout = io.BytesIO()

    exit_code = trusted_helper.main(
        ("unexpected",), UnreadableInput(), stdout, Path("/runtime")
    )

    assert exit_code == 64
    assert stdout.getvalue() == rfc8785.dumps(
        {
            "schema_version": trusted_helper.RESPONSE_SCHEMA,
            "status": "error",
            "code": "REQUEST_INVALID",
        }
    )


def _dispatcher_error(code: str) -> bytes:
    return rfc8785.dumps(
        {
            "schema_version": trusted_helper.RESPONSE_SCHEMA,
            "status": "error",
            "code": code,
        }
    )


def _dispatch_raw(
    raw: bytes,
    runtime_root: Path,
    *,
    argv: object = (),
) -> tuple[int, bytes]:
    stdout = io.BytesIO()
    exit_code = trusted_helper.main(argv, io.BytesIO(raw), stdout, runtime_root)
    return exit_code, stdout.getvalue()


def _assert_dispatch_error(
    raw: bytes,
    runtime_root: Path,
    *,
    code: str = "REQUEST_INVALID",
) -> None:
    exit_code, response = _dispatch_raw(raw, runtime_root)
    assert exit_code == trusted_helper.EXIT_BY_CODE[code]
    assert response == _dispatcher_error(code)
    assert not response.endswith(b"\n")
    if raw:
        assert raw not in response
    for secret in (b"README.md", b"private/secret.txt", b"file-secret"):
        assert secret not in response


def test_dispatcher_constants_are_frozen() -> None:
    assert trusted_helper.REQUEST_SCHEMA == (
        "openworkproof-trusted-helper-request/0.1"
    )
    assert trusted_helper.RESPONSE_SCHEMA == (
        "openworkproof-trusted-helper-response/0.1"
    )
    assert trusted_helper.MAX_REQUEST_BYTES == 8192
    assert trusted_helper.RUNTIME_ROOT == Path("/runtime")
    assert trusted_helper.EXIT_BY_CODE == {
        "REQUEST_INVALID": 64,
        "RECOVERY_REQUIRED": 65,
        "PATH_DENIED": 66,
        "FILE_CHANGED": 67,
        "INTERNAL_ERROR": 70,
    }


def test_dispatcher_reads_at_most_8193_bytes_once(tmp_path: Path) -> None:
    candidate = _candidate(tmp_path, b"base\n")
    raw = rfc8785.dumps(_dispatcher_request(candidate))

    class RecordingInput:
        def __init__(self) -> None:
            self.calls: list[int] = []

        def read(self, size: int) -> bytes:
            self.calls.append(size)
            return raw

    stdin = RecordingInput()
    stdout = io.BytesIO()

    exit_code = trusted_helper.main((), stdin, stdout, candidate.runtime_root)

    assert exit_code == 0
    assert stdin.calls == [8193]


@pytest.mark.parametrize(
    "argv",
    (("unexpected",), [""], (1,), [object()]),
)
def test_dispatcher_rejects_every_argv_element_before_stdin(argv: object) -> None:
    class UnreadableInput:
        def read(self, size: int) -> bytes:
            raise AssertionError(f"stdin read unexpectedly with size {size}")

    stdout = io.BytesIO()

    exit_code = trusted_helper.main(
        argv, UnreadableInput(), stdout, Path("/runtime")
    )

    assert exit_code == 64
    assert stdout.getvalue() == _dispatcher_error("REQUEST_INVALID")


def test_dispatcher_closes_system_exit_from_argv_length() -> None:
    class ExplodingArgv(tuple):
        def __len__(self) -> int:
            raise SystemExit("argv-system-exit-secret")

    class UnreadableInput:
        def read(self, size: int) -> bytes:
            raise AssertionError(f"stdin read unexpectedly with size {size}")

    stdout = io.BytesIO()

    exit_code = trusted_helper.main(
        ExplodingArgv(),
        UnreadableInput(),
        stdout,
        Path("/runtime"),
    )

    assert exit_code == 70
    assert stdout.getvalue() == _dispatcher_error("INTERNAL_ERROR")
    assert b"argv-system-exit-secret" not in stdout.getvalue()


def test_dispatcher_closes_keyboard_interrupt_from_stdin_read() -> None:
    class ExplodingInput:
        def read(self, unused: int) -> bytes:
            raise KeyboardInterrupt("stdin-keyboard-secret")

    stdout = io.BytesIO()

    exit_code = trusted_helper.main(
        (),
        ExplodingInput(),
        stdout,
        Path("/runtime"),
    )

    assert exit_code == 70
    assert stdout.getvalue() == _dispatcher_error("INTERNAL_ERROR")
    assert b"stdin-keyboard-secret" not in stdout.getvalue()


def test_dispatcher_closes_generator_exit_from_stdout_write() -> None:
    class ExplodingOutput:
        def __init__(self) -> None:
            self.calls = 0

        def write(self, unused: bytes) -> int:
            self.calls += 1
            raise GeneratorExit("stdout-generator-secret")

    class UnreadableInput:
        def read(self, size: int) -> bytes:
            raise AssertionError(f"stdin read unexpectedly with size {size}")

    stdout = ExplodingOutput()

    exit_code = trusted_helper.main(
        ("unexpected",),
        UnreadableInput(),
        stdout,
        Path("/runtime"),
    )

    assert exit_code == 70
    assert stdout.calls == 1


def _noncanonical_request_bytes(request: dict[str, object]) -> bytes:
    reverse_order = dict(reversed(tuple(request.items())))
    raw = json.dumps(
        reverse_order,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    assert raw != rfc8785.dumps(request)
    return raw


def _duplicate_operation_bytes(request: dict[str, object]) -> bytes:
    canonical = rfc8785.dumps(request)
    prefix = b'{"operation":"repo_read",'
    assert canonical.startswith(b"{")
    return prefix + canonical[1:]


def test_dispatcher_rejects_duplicate_keys_with_parser_hook(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = _candidate(tmp_path, b"base\n")
    raw = _duplicate_operation_bytes(_dispatcher_request(candidate))
    real_loads = json.loads
    observed_hooks: list[object] = []

    def observe_loads(payload: bytes, **kwargs):
        observed_hooks.append(kwargs.get("object_pairs_hook"))
        return real_loads(payload, **kwargs)

    monkeypatch.setattr(trusted_helper.json, "loads", observe_loads)

    _assert_dispatch_error(raw, candidate.runtime_root)

    assert len(observed_hooks) == 1
    assert observed_hooks[0] is not None


@pytest.mark.parametrize(
    "case",
    (
        "empty",
        "oversize",
        "two_frames",
        "bom",
        "trailing_newline",
        "trailing_space",
        "duplicate_key",
        "noncanonical_order",
        "nonobject",
    ),
)
def test_dispatcher_rejects_invalid_framing(
    tmp_path: Path,
    case: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = _candidate(tmp_path, b"base\n")
    request = _dispatcher_request(candidate)
    canonical = rfc8785.dumps(request)
    cases = {
        "empty": b"",
        "oversize": b"x" * 8193,
        "two_frames": canonical + canonical,
        "bom": b"\xef\xbb\xbf" + canonical,
        "trailing_newline": canonical + b"\n",
        "trailing_space": canonical + b" ",
        "duplicate_key": _duplicate_operation_bytes(request),
        "noncanonical_order": _noncanonical_request_bytes(request),
        "nonobject": b"[]",
    }
    monkeypatch.setattr(
        trusted_helper.repo_tools,
        "read_candidate_file",
        lambda unused: pytest.fail("invalid request reached repository read"),
    )

    _assert_dispatch_error(cases[case], candidate.runtime_root)


@pytest.mark.parametrize(
    ("mutation", "value"),
    (
        ("missing", "path"),
        ("extra", "runtime_root"),
        ("extra", "command"),
        ("extra", "argv"),
        ("extra", "env"),
        ("extra", "git_path"),
        ("replace", ("schema_version", None)),
        ("replace", ("operation", 1)),
        ("replace", ("workspace_id", True)),
        ("replace", ("source_artifact_sha256", [])),
        ("replace", ("expected_head_commit", 0)),
        ("replace", ("expected_workspace_manifest_digest", {})),
        ("replace", ("path", 1)),
        ("replace", ("schema_version", "wrong-schema")),
        ("replace", ("operation", "unknown")),
        ("replace", ("workspace_id", "B" * 64)),
        ("replace", ("workspace_id", "b" * 63)),
        ("replace", ("source_artifact_sha256", "A" * 64)),
        ("replace", ("source_artifact_sha256", "a" * 63)),
        ("replace", ("expected_head_commit", "A" * 40)),
        ("replace", ("expected_head_commit", "a" * 39)),
        ("replace", ("expected_workspace_manifest_digest", "A" * 64)),
        ("replace", ("expected_workspace_manifest_digest", "a" * 63)),
        ("replace", ("path", "/README.md")),
        ("replace", ("path", "../README.md")),
        ("replace", ("path", "src\\README.md")),
        ("replace", ("path", "README.md\0hidden")),
        ("replace", ("path", "x" * 513)),
        ("replace", ("path", "café.txt")),
    ),
)
def test_dispatcher_rejects_invalid_request_fields_upfront(
    tmp_path: Path,
    mutation: str,
    value: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = _candidate(tmp_path, b"base\n")
    request = _dispatcher_request(candidate)
    if mutation == "missing":
        del request[value]
    elif mutation == "extra":
        request[value] = "request-secret"
    else:
        key, replacement = value
        request[key] = replacement
    raw = rfc8785.dumps(request)
    monkeypatch.setattr(
        trusted_helper.repo_tools,
        "read_candidate_file",
        lambda unused: pytest.fail("invalid request reached repository read"),
    )

    _assert_dispatch_error(raw, candidate.runtime_root)


@pytest.mark.parametrize(
    ("code", "exit_code"),
    (
        ("RECOVERY_REQUIRED", 65),
        ("PATH_DENIED", 66),
        ("FILE_CHANGED", 67),
    ),
)
def test_dispatcher_maps_only_closed_candidate_read_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    code: str,
    exit_code: int,
) -> None:
    candidate = _candidate(
        tmp_path,
        b"file-secret",
        source_path="private/secret.txt",
    )
    raw = rfc8785.dumps(
        _dispatcher_request(candidate, path="private/secret.txt")
    )

    def reject(unused: object) -> None:
        raise repo_tools.CandidateReadError(code)

    monkeypatch.setattr(trusted_helper.repo_tools, "read_candidate_file", reject)

    actual_exit, response = _dispatch_raw(raw, candidate.runtime_root)

    assert actual_exit == exit_code
    assert response == _dispatcher_error(code)
    assert raw not in response
    assert b"private/secret.txt" not in response
    assert b"file-secret" not in response
    assert b"CandidateReadError" not in response


def test_dispatcher_closes_unhashable_candidate_error_code(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = _candidate(tmp_path, b"file-secret")
    raw = rfc8785.dumps(_dispatcher_request(candidate))

    def reject(unused: object) -> None:
        raise repo_tools.CandidateReadError([])

    monkeypatch.setattr(trusted_helper.repo_tools, "read_candidate_file", reject)

    exit_code, response = _dispatch_raw(raw, candidate.runtime_root)

    assert exit_code == 70
    assert response == _dispatcher_error("INTERNAL_ERROR")
    for secret in (raw, b"file-secret", b"CandidateReadError", b"[]"):
        assert secret not in response


def test_dispatcher_closes_candidate_error_code_property_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = _candidate(tmp_path, b"file-secret")
    raw = rfc8785.dumps(_dispatcher_request(candidate))

    class SecretCodeAccessError(Exception):
        pass

    class ExplodingCodeError(repo_tools.CandidateReadError):
        def __init__(self) -> None:
            RuntimeError.__init__(self, "constructor-secret")

        @property
        def code(self) -> str:
            raise SecretCodeAccessError("code-property-secret")

    def reject(unused: object) -> None:
        raise ExplodingCodeError

    monkeypatch.setattr(trusted_helper.repo_tools, "read_candidate_file", reject)

    exit_code, response = _dispatch_raw(raw, candidate.runtime_root)

    assert exit_code == 70
    assert response == _dispatcher_error("INTERNAL_ERROR")
    for secret in (
        raw,
        b"file-secret",
        b"ExplodingCodeError",
        b"SecretCodeAccessError",
        b"constructor-secret",
        b"code-property-secret",
    ):
        assert secret not in response


def test_dispatcher_rejects_nested_duplicate_keys(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = _candidate(tmp_path, b"base\n")
    raw = rfc8785.dumps(_dispatcher_request(candidate)).replace(
        b'"path":"README.md"',
        b'"path":{"nested":"one","nested":"two"}',
    )
    observed_nested_duplicate = False
    real_hook = trusted_helper._object_without_duplicate_keys

    def observe_hook(pairs: list[tuple[str, object]]) -> dict[str, object]:
        nonlocal observed_nested_duplicate
        if pairs == [("nested", "one"), ("nested", "two")]:
            observed_nested_duplicate = True
        return real_hook(pairs)

    monkeypatch.setattr(
        trusted_helper,
        "_object_without_duplicate_keys",
        observe_hook,
    )
    monkeypatch.setattr(
        trusted_helper.repo_tools,
        "read_candidate_file",
        lambda unused: pytest.fail("invalid request reached repository read"),
    )

    _assert_dispatch_error(raw, candidate.runtime_root)

    assert observed_nested_duplicate is True


def test_dispatcher_accepts_exact_512_byte_canonical_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = "x" * 512
    manifest_digest = "d" * 64
    request = {
        "schema_version": trusted_helper.REQUEST_SCHEMA,
        "operation": "repo_read",
        "workspace_id": "b" * 64,
        "source_artifact_sha256": "a" * 64,
        "expected_head_commit": "c" * 40,
        "expected_workspace_manifest_digest": manifest_digest,
        "path": path,
    }
    observed_paths: list[str] = []

    def read_candidate_file(
        candidate_request: repo_tools.CandidateReadRequest,
    ) -> repo_tools.CandidateReadResult:
        observed_paths.append(candidate_request.path)
        return repo_tools.CandidateReadResult(
            content=b"",
            output=RepoReadOutput(
                path=path,
                content_sha256=hashlib.sha256(b"").hexdigest(),
                size_bytes=0,
                workspace_manifest_digest=manifest_digest,
            ),
        )

    monkeypatch.setattr(
        trusted_helper.repo_tools,
        "read_candidate_file",
        read_candidate_file,
    )

    exit_code, response = _dispatch_raw(
        rfc8785.dumps(request),
        Path("/runtime"),
    )

    assert exit_code == 0
    assert observed_paths == [path]
    assert json.loads(response)["result"]["path"] == path


def test_dispatcher_rejects_513_byte_canonical_path_upfront(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = {
        "schema_version": trusted_helper.REQUEST_SCHEMA,
        "operation": "repo_read",
        "workspace_id": "b" * 64,
        "source_artifact_sha256": "a" * 64,
        "expected_head_commit": "c" * 40,
        "expected_workspace_manifest_digest": "d" * 64,
        "path": "x" * 513,
    }
    monkeypatch.setattr(
        trusted_helper.repo_tools,
        "read_candidate_file",
        lambda unused: pytest.fail("invalid request reached repository read"),
    )

    _assert_dispatch_error(rfc8785.dumps(request), Path("/runtime"))


@pytest.mark.parametrize(
    "field",
    (
        "schema_version",
        "operation",
        "workspace_id",
        "source_artifact_sha256",
        "expected_head_commit",
        "expected_workspace_manifest_digest",
        "path",
    ),
)
@pytest.mark.parametrize("wrong_value", (0, True, None))
def test_dispatcher_rejects_number_bool_and_null_for_each_request_field(
    field: str,
    wrong_value: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request: dict[str, object] = {
        "schema_version": trusted_helper.REQUEST_SCHEMA,
        "operation": "repo_read",
        "workspace_id": "b" * 64,
        "source_artifact_sha256": "a" * 64,
        "expected_head_commit": "c" * 40,
        "expected_workspace_manifest_digest": "d" * 64,
        "path": "README.md",
    }
    request[field] = wrong_value
    raw = rfc8785.dumps(request)
    monkeypatch.setattr(
        trusted_helper.repo_tools,
        "read_candidate_file",
        lambda unused: pytest.fail("invalid request reached repository read"),
    )

    _assert_dispatch_error(raw, Path("/runtime"))


@pytest.mark.parametrize("argv", ((), ("unexpected",)))
def test_trusted_helper_module_rejects_empty_stdin_with_empty_stderr(
    tmp_path: Path,
    argv: tuple[str, ...],
) -> None:
    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            "-m",
            "openworkproof.trusted_helper",
            *argv,
        ],
        input=b"",
        capture_output=True,
        check=False,
        cwd=tmp_path,
    )

    assert completed.returncode == 64
    assert completed.stdout == _dispatcher_error("REQUEST_INVALID")
    assert completed.stderr == b""


def test_dispatcher_closes_unexpected_exceptions_without_leakage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = _candidate(
        tmp_path,
        b"file-secret",
        source_path="private/secret.txt",
    )
    raw = rfc8785.dumps(
        _dispatcher_request(candidate, path="private/secret.txt")
    )

    class SecretCrash(Exception):
        pass

    def crash(unused: object) -> None:
        raise SecretCrash("exception-message-secret")

    monkeypatch.setattr(trusted_helper.repo_tools, "read_candidate_file", crash)

    exit_code, response = _dispatch_raw(raw, candidate.runtime_root)

    assert exit_code == 70
    assert response == _dispatcher_error("INTERNAL_ERROR")
    for secret in (
        raw,
        b"private/secret.txt",
        b"file-secret",
        b"SecretCrash",
        b"exception-message-secret",
    ):
        assert secret not in response


@pytest.mark.parametrize(
    "case",
    (
        "wrong_result",
        "wrong_content",
        "wrong_output",
        "path_mismatch",
        "manifest_mismatch",
        "size_mismatch",
        "hash_mismatch",
    ),
)
def test_dispatcher_rejects_unclosed_or_inconsistent_success_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
) -> None:
    content = b"file-secret"
    candidate = _candidate(tmp_path, content)
    raw = rfc8785.dumps(_dispatcher_request(candidate))
    valid_output = RepoReadOutput(
        path="README.md",
        content_sha256=hashlib.sha256(content).hexdigest(),
        size_bytes=len(content),
        workspace_manifest_digest=candidate.workspace_manifest_digest,
    )
    results = {
        "wrong_result": "internal-result-secret",
        "wrong_content": repo_tools.CandidateReadResult(
            content="content-type-secret",
            output=valid_output,
        ),
        "wrong_output": repo_tools.CandidateReadResult(
            content=content,
            output="output-type-secret",
        ),
        "path_mismatch": repo_tools.CandidateReadResult(
            content=content,
            output=RepoReadOutput(
                path="other-secret.txt",
                content_sha256=hashlib.sha256(content).hexdigest(),
                size_bytes=len(content),
                workspace_manifest_digest=candidate.workspace_manifest_digest,
            ),
        ),
        "manifest_mismatch": repo_tools.CandidateReadResult(
            content=content,
            output=RepoReadOutput(
                path="README.md",
                content_sha256=hashlib.sha256(content).hexdigest(),
                size_bytes=len(content),
                workspace_manifest_digest="e" * 64,
            ),
        ),
        "size_mismatch": repo_tools.CandidateReadResult(
            content=content,
            output=RepoReadOutput(
                path="README.md",
                content_sha256=hashlib.sha256(content).hexdigest(),
                size_bytes=len(content) - 1,
                workspace_manifest_digest=candidate.workspace_manifest_digest,
            ),
        ),
        "hash_mismatch": repo_tools.CandidateReadResult(
            content=content,
            output=RepoReadOutput(
                path="README.md",
                content_sha256="e" * 64,
                size_bytes=len(content),
                workspace_manifest_digest=candidate.workspace_manifest_digest,
            ),
        ),
    }
    monkeypatch.setattr(
        trusted_helper.repo_tools,
        "read_candidate_file",
        lambda unused: results[case],
    )

    exit_code, response = _dispatch_raw(raw, candidate.runtime_root)

    assert exit_code == 70
    assert response == _dispatcher_error("INTERNAL_ERROR")
    for secret in (
        raw,
        content,
        b"internal-result-secret",
        b"content-type-secret",
        b"output-type-secret",
        b"other-secret.txt",
    ):
        assert secret not in response


@pytest.mark.parametrize(
    ("field", "wrong_value"),
    (
        ("path", "dump-path-secret.txt"),
        ("content_sha256", "e" * 64),
        ("size_bytes", 999),
        ("workspace_manifest_digest", "e" * 64),
    ),
)
def test_dispatcher_rejects_inconsistent_success_model_dump(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    wrong_value: object,
) -> None:
    content = b"file-secret"
    candidate = _candidate(tmp_path, content)
    raw = rfc8785.dumps(_dispatcher_request(candidate))
    output = RepoReadOutput(
        path="README.md",
        content_sha256=hashlib.sha256(content).hexdigest(),
        size_bytes=len(content),
        workspace_manifest_digest=candidate.workspace_manifest_digest,
    )

    def inconsistent_dump(unused: RepoReadOutput, *, mode: str) -> dict[str, object]:
        assert mode == "json"
        dumped = {
            "path": "README.md",
            "content_sha256": hashlib.sha256(content).hexdigest(),
            "size_bytes": len(content),
            "workspace_manifest_digest": candidate.workspace_manifest_digest,
        }
        dumped[field] = wrong_value
        return dumped

    monkeypatch.setattr(RepoReadOutput, "model_dump", inconsistent_dump)
    monkeypatch.setattr(
        trusted_helper.repo_tools,
        "read_candidate_file",
        lambda unused: repo_tools.CandidateReadResult(
            content=content,
            output=output,
        ),
    )

    exit_code, response = _dispatch_raw(raw, candidate.runtime_root)

    assert exit_code == 70
    assert response == _dispatcher_error("INTERNAL_ERROR")
    assert raw not in response
    assert content not in response
    assert b"dump-path-secret.txt" not in response


def test_dispatcher_rejects_extra_success_model_dump_key(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    content = b"file-secret"
    candidate = _candidate(tmp_path, content)
    raw = rfc8785.dumps(_dispatcher_request(candidate))
    output = RepoReadOutput(
        path="README.md",
        content_sha256=hashlib.sha256(content).hexdigest(),
        size_bytes=len(content),
        workspace_manifest_digest=candidate.workspace_manifest_digest,
    )

    def extra_dump(unused: RepoReadOutput, *, mode: str) -> dict[str, object]:
        assert mode == "json"
        return {
            "path": "README.md",
            "content_sha256": hashlib.sha256(content).hexdigest(),
            "size_bytes": len(content),
            "workspace_manifest_digest": candidate.workspace_manifest_digest,
            "extra": "extra-dump-secret",
        }

    monkeypatch.setattr(RepoReadOutput, "model_dump", extra_dump)
    monkeypatch.setattr(
        trusted_helper.repo_tools,
        "read_candidate_file",
        lambda unused: repo_tools.CandidateReadResult(content, output),
    )

    exit_code, response = _dispatch_raw(raw, candidate.runtime_root)

    assert exit_code == 70
    assert response == _dispatcher_error("INTERNAL_ERROR")
    assert b"extra-dump-secret" not in response


@pytest.mark.parametrize("case", ("raises", "uncodable"))
def test_dispatcher_closes_raising_or_uncodable_success_model_dump(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
) -> None:
    content = b"file-secret"
    candidate = _candidate(tmp_path, content)
    raw = rfc8785.dumps(_dispatcher_request(candidate))
    output = RepoReadOutput(
        path="README.md",
        content_sha256=hashlib.sha256(content).hexdigest(),
        size_bytes=len(content),
        workspace_manifest_digest=candidate.workspace_manifest_digest,
    )

    def strange_dump(unused: RepoReadOutput, *, mode: str) -> dict[str, object]:
        assert mode == "json"
        if case == "raises":
            raise SystemExit("model-dump-system-secret")
        return {
            "path": object(),
            "content_sha256": hashlib.sha256(content).hexdigest(),
            "size_bytes": len(content),
            "workspace_manifest_digest": candidate.workspace_manifest_digest,
        }

    monkeypatch.setattr(RepoReadOutput, "model_dump", strange_dump)
    monkeypatch.setattr(
        trusted_helper.repo_tools,
        "read_candidate_file",
        lambda unused: repo_tools.CandidateReadResult(content, output),
    )

    exit_code, response = _dispatch_raw(raw, candidate.runtime_root)

    assert exit_code == 70
    assert response == _dispatcher_error("INTERNAL_ERROR")
    for secret in (content, b"model-dump-system-secret"):
        assert secret not in response


@pytest.mark.parametrize("failure", (RuntimeError, SystemExit, None))
def test_dispatcher_closes_internal_canonicalizer_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: type[BaseException] | None,
) -> None:
    candidate = _candidate(tmp_path, b"file-secret")
    raw = rfc8785.dumps(_dispatcher_request(candidate))
    expected = _dispatcher_error("INTERNAL_ERROR")

    def fail_canonicalization(unused: object) -> object:
        if failure is None:
            return "canonicalizer-return-secret"
        raise failure("canonicalizer-internal-secret")

    monkeypatch.setattr(trusted_helper.rfc8785, "dumps", fail_canonicalization)

    exit_code, response = _dispatch_raw(raw, candidate.runtime_root)

    assert exit_code == 70
    assert response == expected
    for secret in (
        raw,
        b"file-secret",
        b"canonicalizer-internal-secret",
        b"canonicalizer-return-secret",
    ):
        assert secret not in response


def test_internal_error_frozen_bytes_match_canonical_response() -> None:
    assert trusted_helper._INTERNAL_ERROR_BYTES == _dispatcher_error(
        "INTERNAL_ERROR"
    )


@pytest.mark.parametrize("failure_mode", ("raises", "wrong_type"))
def test_success_encoding_failure_writes_one_frozen_internal_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_mode: str,
) -> None:
    candidate = _candidate(tmp_path, b"file-secret")
    raw = rfc8785.dumps(_dispatcher_request(candidate))
    expected = _dispatcher_error("INTERNAL_ERROR")
    real_dumps = rfc8785.dumps
    writes: list[bytes] = []

    def fail_success_response(value: object) -> object:
        if type(value) is dict and value.get("status") == "ok":
            if failure_mode == "raises":
                raise RuntimeError("success-encoding-secret")
            return "success-encoding-return-secret"
        return real_dumps(value)

    class RecordingOutput:
        def write(self, payload: bytes) -> int:
            writes.append(payload)
            return len(payload)

    monkeypatch.setattr(trusted_helper.rfc8785, "dumps", fail_success_response)

    exit_code = trusted_helper.main(
        (),
        io.BytesIO(raw),
        RecordingOutput(),
        candidate.runtime_root,
    )

    assert exit_code == 70
    assert writes == [expected]
    assert b"file-secret" not in writes[0]
    assert b"success-encoding-secret" not in writes[0]
    assert b"success-encoding-return-secret" not in writes[0]


def test_dispatcher_returns_strict_unpadded_urlsafe_base64(tmp_path: Path) -> None:
    content = b"\xfb\xff"
    candidate = _candidate(tmp_path, content)
    raw = rfc8785.dumps(_dispatcher_request(candidate))

    exit_code, response_raw = _dispatch_raw(raw, candidate.runtime_root)
    response = json.loads(response_raw)
    encoded = response["content_b64url"]
    padded = encoded + "=" * (-len(encoded) % 4)
    decoded = base64.b64decode(
        padded.encode("ascii"),
        altchars=b"-_",
        validate=True,
    )

    assert exit_code == 0
    assert encoded == "-_8"
    assert "=" not in encoded
    assert decoded == content
    assert len(decoded) == response["result"]["size_bytes"]
    assert hashlib.sha256(decoded).hexdigest() == (
        response["result"]["content_sha256"]
    )


def test_dispatcher_does_not_retry_failed_stdout_write() -> None:
    class SecretWriteError(Exception):
        pass

    class BrokenOutput:
        def __init__(self) -> None:
            self.calls = 0

        def write(self, unused: bytes) -> int:
            self.calls += 1
            raise SecretWriteError("write-message-secret")

    class UnreadableInput:
        def read(self, size: int) -> bytes:
            raise AssertionError(f"stdin read unexpectedly with size {size}")

    stdout = BrokenOutput()

    exit_code = trusted_helper.main(
        ("unexpected",), UnreadableInput(), stdout, Path("/runtime")
    )

    assert exit_code == 70
    assert stdout.calls == 1


def test_dispatcher_closes_short_stdout_write_without_retry() -> None:
    class ShortOutput:
        def __init__(self) -> None:
            self.calls = 0

        def write(self, payload: bytes) -> int:
            self.calls += 1
            return len(payload) - 1

    class UnreadableInput:
        def read(self, size: int) -> bytes:
            raise AssertionError(f"stdin read unexpectedly with size {size}")

    stdout = ShortOutput()

    exit_code = trusted_helper.main(
        ("unexpected",), UnreadableInput(), stdout, Path("/runtime")
    )

    assert exit_code == 70
    assert stdout.calls == 1


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


def test_prepare_candidate_execution_snapshot_returns_exact_files(
    tmp_path: Path,
) -> None:
    candidate = _candidate(tmp_path, b"base\n")

    result = repo_tools.prepare_candidate_execution_snapshot(
        repo_tools.CandidateExecutionSnapshotRequest(
            runtime_root=candidate.runtime_root,
            workspace_id=candidate.workspace_id,
            source_artifact_sha256=candidate.source_artifact_sha256,
            expected_head_commit=candidate.head_commit,
            expected_workspace_manifest_digest=(
                candidate.workspace_manifest_digest
            ),
        )
    )

    assert result.head_commit == candidate.head_commit
    assert (
        result.workspace_manifest_digest
        == candidate.workspace_manifest_digest
    )
    assert result.plan.files == (
        repo_tools.SourceFile("README.md", "100644", b"base\n"),
    )


def test_prepare_candidate_execution_snapshot_reads_every_file_in_order(
    tmp_path: Path,
) -> None:
    candidate = _candidate(
        tmp_path,
        b"readme\n",
        additional_files=(
            repo_tools.SourceFile("z-last.txt", "100644", b"last\n"),
            repo_tools.SourceFile("bin/run", "100755", b"#!/bin/sh\n"),
            repo_tools.SourceFile("a-first.txt", "100644", b"first\n"),
        ),
    )

    result = repo_tools.prepare_candidate_execution_snapshot(
        _snapshot_request(candidate)
    )

    assert result.plan.files == (
        repo_tools.SourceFile("README.md", "100644", b"readme\n"),
        repo_tools.SourceFile("a-first.txt", "100644", b"first\n"),
        repo_tools.SourceFile("bin/run", "100755", b"#!/bin/sh\n"),
        repo_tools.SourceFile("z-last.txt", "100644", b"last\n"),
    )


def test_prepare_candidate_execution_snapshot_returns_exact_one_mib_file(
    tmp_path: Path,
) -> None:
    content = b"x" * 1_048_576
    candidate = _candidate(tmp_path, content)

    result = repo_tools.prepare_candidate_execution_snapshot(
        _snapshot_request(candidate)
    )

    assert result.plan.files == (
        repo_tools.SourceFile("README.md", "100644", content),
    )


def test_prepare_candidate_execution_snapshot_accepts_exact_eight_mib(
    tmp_path: Path,
) -> None:
    files = _snapshot_files_with_total_size(8_388_608)
    candidate = _rebound_snapshot_candidate(
        _candidate(tmp_path, b"base\n"),
        files,
    )

    result = repo_tools.prepare_candidate_execution_snapshot(
        _snapshot_request(candidate)
    )

    assert result.plan.files == files
    assert sum(len(source_file.content) for source_file in result.plan.files) == (
        8_388_608
    )


def test_prepare_candidate_execution_snapshot_rejects_eight_mib_plus_one_before_capture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = _rebound_snapshot_candidate(
        _candidate(tmp_path, b"base\n"),
        _snapshot_files_with_total_size(8_388_609),
    )
    real_capture = repo_tools._read_candidate_execution_snapshot_file
    capture_calls: list[str] = []
    hook_calls: list[str] = []

    def observe_capture(checkpoint, entry):
        capture_calls.append(entry.path_bytes_b64url)
        return real_capture(checkpoint, entry)

    monkeypatch.setattr(
        repo_tools,
        "_read_candidate_execution_snapshot_file",
        observe_capture,
    )
    monkeypatch.setattr(
        repo_tools,
        "_candidate_execution_snapshot_file_hook",
        hook_calls.append,
    )

    _assert_snapshot_recovery(candidate)

    assert capture_calls == []
    assert hook_calls == []


def test_prepare_candidate_execution_snapshot_normalizes_checkpoint_file_changed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = _candidate(tmp_path, b"base\n")
    monkeypatch.setattr(
        repo_tools,
        "_candidate_read_authority_matches",
        lambda unused: False,
    )

    _assert_snapshot_recovery(candidate)


def test_prepare_candidate_execution_snapshot_rejects_sibling_change_during_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = _candidate(
        tmp_path,
        b"base\n",
        additional_files=(
            repo_tools.SourceFile("z-last.txt", "100644", b"last\n"),
        ),
    )
    sibling = candidate.worktree / "README.md"
    sibling_inode = sibling.stat().st_ino

    def change_previously_read_sibling(path: str) -> None:
        if path == "z-last.txt":
            with sibling.open("r+b") as stream:
                stream.write(b"evil\n")
            assert sibling.stat().st_ino == sibling_inode

    monkeypatch.setattr(
        repo_tools,
        "_candidate_execution_snapshot_file_hook",
        change_previously_read_sibling,
    )

    _assert_snapshot_recovery(candidate)


def test_prepare_candidate_execution_snapshot_rejects_nested_sibling_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = _candidate(
        tmp_path,
        b"base\n",
        additional_files=(
            repo_tools.SourceFile("nested/a.txt", "100644", b"alpha\n"),
            repo_tools.SourceFile("z-last.txt", "100644", b"last\n"),
        ),
    )
    sibling = candidate.worktree / "nested" / "a.txt"
    sibling_inode = sibling.stat().st_ino

    def change_nested_sibling(path: str) -> None:
        if path == "z-last.txt":
            with sibling.open("r+b") as stream:
                stream.write(b"evil!\n")
            assert sibling.stat().st_ino == sibling_inode

    monkeypatch.setattr(
        repo_tools,
        "_candidate_execution_snapshot_file_hook",
        change_nested_sibling,
    )

    _assert_snapshot_recovery(candidate)


def test_prepare_candidate_execution_snapshot_rejects_globally_woven_aba(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = _candidate(
        tmp_path,
        b"base\n",
        additional_files=(
            repo_tools.SourceFile("a.txt", "100644", b"alpha\n"),
            repo_tools.SourceFile("b.txt", "100644", b"bravo\n"),
        ),
    )
    a_path, b_path, state = _install_snapshot_aba_weave(
        candidate,
        monkeypatch,
    )

    _assert_snapshot_recovery(candidate)

    assert state["scan_calls"] == 2
    assert state["woven_a_stats"] == 2
    assert a_path.read_bytes() == b"evil!\n"
    assert b_path.read_bytes() == b"bravo\n"


def test_prepare_candidate_execution_snapshot_rejects_nested_woven_aba(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = _candidate(
        tmp_path,
        b"base\n",
        additional_files=(
            repo_tools.SourceFile("nested/a.txt", "100644", b"alpha\n"),
            repo_tools.SourceFile("nested/b.txt", "100644", b"bravo\n"),
        ),
    )
    a_path, b_path, state = _install_snapshot_aba_weave(
        candidate,
        monkeypatch,
        directory="nested",
    )

    _assert_snapshot_recovery(candidate)

    assert state["scan_calls"] == 2
    assert state["woven_a_stats"] == 2
    assert a_path.read_bytes() == b"evil!\n"
    assert b_path.read_bytes() == b"bravo\n"


def test_prepare_candidate_execution_snapshot_rejects_513th_entry_before_io(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = _candidate(tmp_path, b"base\n")
    for index in range(512):
        (candidate.worktree / f"extra-{index:03d}.txt").write_bytes(b"")
    last_name = "extra-511.txt"
    real_stat = repo_tools.os.stat
    real_open = repo_tools.os.open
    last_entry_io: list[str] = []

    def observe_stat(path, *, dir_fd=None, follow_symlinks=True):
        if path == last_name and dir_fd is not None:
            last_entry_io.append("stat")
        return real_stat(
            path,
            dir_fd=dir_fd,
            follow_symlinks=follow_symlinks,
        )

    def observe_open(path, flags, mode=0o777, *, dir_fd=None):
        if path == last_name and dir_fd is not None:
            last_entry_io.append("open")
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(repo_tools.os, "stat", observe_stat)
    monkeypatch.setattr(repo_tools.os, "open", observe_open)

    _assert_snapshot_recovery(candidate)
    assert last_entry_io == []


def test_prepare_candidate_execution_snapshot_rejects_symlink(
    tmp_path: Path,
) -> None:
    candidate = _candidate(tmp_path, b"base\n")
    target = candidate.worktree / "README.md"
    target.unlink()
    target.symlink_to("missing")

    _assert_snapshot_recovery(candidate)


def test_prepare_candidate_execution_snapshot_rejects_hardlink(
    tmp_path: Path,
) -> None:
    candidate = _candidate(tmp_path, b"base\n")
    target = candidate.worktree / "README.md"
    target.unlink()
    external = tmp_path / "external"
    external.write_bytes(b"base\n")
    os.link(external, target)

    _assert_snapshot_recovery(candidate)


def test_prepare_candidate_execution_snapshot_rejects_fifo(
    tmp_path: Path,
) -> None:
    candidate = _candidate(tmp_path, b"base\n")
    target = candidate.worktree / "README.md"
    target.unlink()
    os.mkfifo(target)

    _assert_snapshot_recovery(candidate)


def test_prepare_candidate_execution_snapshot_rejects_oversize_regular_file(
    tmp_path: Path,
) -> None:
    candidate = _candidate(tmp_path, b"base\n")
    (candidate.worktree / "README.md").write_bytes(
        b"x" * (1_048_576 + 1)
    )

    _assert_snapshot_recovery(candidate)


def test_prepare_candidate_execution_snapshot_rejects_wrong_source_digest(
    tmp_path: Path,
) -> None:
    candidate = _candidate(tmp_path, b"base\n")

    _assert_snapshot_recovery(
        candidate,
        _snapshot_request(candidate, source_artifact_sha256="c" * 64),
    )


def test_prepare_candidate_execution_snapshot_rejects_wrong_head(
    tmp_path: Path,
) -> None:
    candidate = _candidate(tmp_path, b"base\n")

    _assert_snapshot_recovery(
        candidate,
        _snapshot_request(candidate, expected_head_commit="0" * 40),
    )


def test_prepare_candidate_execution_snapshot_rejects_wrong_manifest_digest(
    tmp_path: Path,
) -> None:
    candidate = _candidate(tmp_path, b"base\n")

    _assert_snapshot_recovery(
        candidate,
        _snapshot_request(
            candidate,
            expected_workspace_manifest_digest="0" * 64,
        ),
    )


@pytest.mark.parametrize("mutation", ("replace", "drift"))
def test_prepare_candidate_execution_snapshot_rejects_control_replacement_or_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    candidate = _candidate(tmp_path, b"base\n")
    control = candidate.candidate_root / "control.json"
    original = control.read_bytes()

    def mutate_control() -> None:
        if mutation == "replace":
            replacement = candidate.candidate_root / "replacement"
            replacement.write_bytes(original)
            replacement.chmod(0o600)
            replacement.replace(control)
        else:
            with control.open("r+b") as stream:
                stream.write(b" " + original[1:])

    monkeypatch.setattr(
        repo_tools,
        "_candidate_execution_snapshot_after_files_hook",
        mutate_control,
    )

    _assert_snapshot_recovery(candidate)


@pytest.mark.parametrize("mutation", ("index", "authority"))
def test_prepare_candidate_execution_snapshot_rejects_git_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    candidate = _candidate(tmp_path, b"base\n")

    def mutate_git() -> None:
        if mutation == "index":
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
        else:
            head = candidate.git_dir / "HEAD"
            original = head.read_bytes()
            head.write_bytes(b"x" * len(original))

    monkeypatch.setattr(
        repo_tools,
        "_candidate_execution_snapshot_after_files_hook",
        mutate_git,
    )

    _assert_snapshot_recovery(candidate)


def test_prepare_candidate_execution_snapshot_rejects_external_git_alternates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = _candidate(tmp_path, b"base\n")
    external_objects = tmp_path / "external-objects"
    (candidate.git_dir / "objects").rename(external_objects)
    internal_objects = candidate.git_dir / "objects"
    (internal_objects / "info").mkdir(parents=True)
    (internal_objects / "pack").mkdir()
    (internal_objects / "info" / "alternates").write_text(
        f"{external_objects}\n",
        encoding="ascii",
    )
    git_environment = {
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }
    resolved = subprocess.run(
        [
            "/usr/bin/git",
            f"--git-dir={candidate.git_dir}",
            f"--work-tree={candidate.worktree}",
            "cat-file",
            "-e",
            "HEAD^{commit}",
        ],
        check=False,
        capture_output=True,
        env=git_environment,
        cwd=candidate.worktree,
    )
    assert resolved.returncode == 0
    hook_calls: list[str] = []
    monkeypatch.setattr(
        repo_tools,
        "_candidate_execution_snapshot_file_hook",
        hook_calls.append,
    )

    _assert_snapshot_recovery(candidate)

    assert hook_calls == []


def test_prepare_candidate_execution_snapshot_reruns_git_semantics_after_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = _candidate(tmp_path, b"base\n")
    real_git_read_only = repo_tools._run_git_read_only
    after_files = False
    final_git_calls: list[tuple[str, ...]] = []

    def change_cached_index() -> None:
        nonlocal after_files
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
        after_files = True

    def observe_git_read_only(*args, **kwargs):
        if after_files:
            final_git_calls.append(kwargs["arguments"])
        return real_git_read_only(*args, **kwargs)

    monkeypatch.setattr(
        repo_tools,
        "_candidate_execution_snapshot_after_files_hook",
        change_cached_index,
    )
    monkeypatch.setattr(
        repo_tools,
        "_candidate_read_authority_matches",
        lambda unused: True,
    )
    monkeypatch.setattr(
        repo_tools,
        "_run_git_read_only",
        observe_git_read_only,
    )

    _assert_snapshot_recovery(candidate)

    assert final_git_calls == [
        ("rev-parse", "HEAD"),
        ("cat-file", "-e", "HEAD^{commit}"),
        ("diff-index", "--cached", "--quiet", "HEAD", "--"),
    ]


def test_prepare_candidate_execution_snapshot_disables_candidate_fsmonitor(
    tmp_path: Path,
) -> None:
    content = b"base\n"
    candidate = _candidate(tmp_path, content)
    fsmonitor = tmp_path / "candidate-fsmonitor"
    marker = tmp_path / "fsmonitor-marker"
    fsmonitor.write_bytes(
        b'#!/bin/sh\n: > "${0%/*}/fsmonitor-marker"\n'
    )
    fsmonitor.chmod(0o700)
    subprocess.run(
        [
            "/usr/bin/git",
            f"--git-dir={candidate.git_dir}",
            "config",
            "core.fsmonitor",
            str(fsmonitor),
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

    result = repo_tools.prepare_candidate_execution_snapshot(
        _snapshot_request(candidate)
    )

    assert result.plan.files == (
        repo_tools.SourceFile("README.md", "100644", content),
    )
    assert not marker.exists()


def test_prepare_candidate_execution_snapshot_disables_candidate_external_diff(
    tmp_path: Path,
) -> None:
    candidate = _candidate(tmp_path, b"base\n")
    external_diff = tmp_path / "candidate-external-diff"
    marker = tmp_path / "external-diff-marker"
    external_diff.write_bytes(
        b'#!/bin/sh\n: > "${0%/*}/external-diff-marker"\nexit 0\n'
    )
    external_diff.chmod(0o700)
    git_environment = {
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }
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
        env=git_environment,
    )
    for key, value in (
        ("diff.external", str(external_diff)),
        ("diff.trustExitCode", "true"),
    ):
        subprocess.run(
            [
                "/usr/bin/git",
                f"--git-dir={candidate.git_dir}",
                "config",
                key,
                value,
            ],
            check=True,
            capture_output=True,
            env=git_environment,
        )

    error_code = None
    try:
        repo_tools.prepare_candidate_execution_snapshot(
            _snapshot_request(candidate)
        )
    except repo_tools.CandidateReadError as error:
        error_code = error.code

    assert (error_code, marker.exists()) == ("RECOVERY_REQUIRED", False)


def test_prepare_candidate_execution_snapshot_closes_every_fd_on_file_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = _candidate(
        tmp_path,
        b"base\n",
        source_path="nested/README.md",
    )
    real_anchor = repo_tools._candidate_read_anchor
    real_open = repo_tools.os.open
    real_read_workspace_file = repo_tools._read_workspace_file
    checkpoint_descriptors: list[int] = []
    file_descriptors: list[int] = []
    file_read_armed = False

    def capture_anchor(*args, **kwargs):
        anchor = real_anchor(*args, **kwargs)
        checkpoint_descriptors.append(anchor.descriptor)
        return anchor

    def arm_file_failure(path: str) -> None:
        nonlocal file_read_armed
        assert path == "nested/README.md"
        file_read_armed = True

    def capture_open(path, flags, mode=0o777, *, dir_fd=None):
        descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
        if file_read_armed:
            file_descriptors.append(descriptor)
        return descriptor

    def fail_file_read(descriptor: int, size_bytes: int) -> bytes:
        if file_read_armed:
            raise OSError("injected snapshot read failure")
        return real_read_workspace_file(descriptor, size_bytes)

    monkeypatch.setattr(
        repo_tools,
        "_candidate_read_anchor",
        capture_anchor,
    )
    monkeypatch.setattr(
        repo_tools,
        "_candidate_execution_snapshot_file_hook",
        arm_file_failure,
    )
    monkeypatch.setattr(repo_tools.os, "open", capture_open)
    monkeypatch.setattr(repo_tools, "_read_workspace_file", fail_file_read)

    _assert_snapshot_recovery(candidate)
    assert len(checkpoint_descriptors) == 5
    assert len(file_descriptors) == 2
    for descriptor in (*checkpoint_descriptors, *file_descriptors):
        with pytest.raises(OSError):
            os.fstat(descriptor)


def test_prepare_candidate_execution_snapshot_closes_checkpoint_fds_on_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = _candidate(tmp_path, b"base\n")
    real_anchor = repo_tools._candidate_read_anchor
    captured_descriptors: list[int] = []

    def capture_anchor(*args, **kwargs):
        anchor = real_anchor(*args, **kwargs)
        captured_descriptors.append(anchor.descriptor)
        return anchor

    def fail_scan(
        unused_root_fd: int,
        unused_head_commit: str,
    ) -> repo_tools.WorkspaceManifest:
        raise repo_tools.ManifestError("injected checkpoint failure")

    monkeypatch.setattr(repo_tools, "_candidate_read_anchor", capture_anchor)
    monkeypatch.setattr(repo_tools, "scan_workspace_manifest", fail_scan)

    _assert_snapshot_recovery(candidate)
    assert len(captured_descriptors) == 5
    for descriptor in captured_descriptors:
        with pytest.raises(OSError):
            os.fstat(descriptor)


@pytest.mark.parametrize("failure_type", (KeyboardInterrupt, SystemExit))
def test_prepare_candidate_execution_snapshot_closes_checkpoint_fds_on_base_exception(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_type: type[BaseException],
) -> None:
    candidate = _candidate(tmp_path, b"base\n")
    real_anchor = repo_tools._candidate_read_anchor
    captured_descriptors: list[int] = []

    def capture_anchor(*args, **kwargs):
        anchor = real_anchor(*args, **kwargs)
        captured_descriptors.append(anchor.descriptor)
        return anchor

    def interrupt_scan(
        unused_root_fd: int,
        unused_head_commit: str,
    ) -> repo_tools.WorkspaceManifest:
        raise failure_type("injected base exception")

    monkeypatch.setattr(repo_tools, "_candidate_read_anchor", capture_anchor)
    monkeypatch.setattr(repo_tools, "scan_workspace_manifest", interrupt_scan)

    leaked_descriptors: list[int] = []
    with pytest.raises(failure_type) as raised:
        try:
            repo_tools.prepare_candidate_execution_snapshot(
                _snapshot_request(candidate)
            )
        finally:
            for descriptor in captured_descriptors:
                try:
                    os.fstat(descriptor)
                except OSError:
                    continue
                leaked_descriptors.append(descriptor)
                os.close(descriptor)

    assert raised.value.args == ("injected base exception",)
    assert len(captured_descriptors) == 5
    assert leaked_descriptors == []


@pytest.mark.parametrize("failure_type", (KeyboardInterrupt, SystemExit))
def test_snapshot_closes_checkpoint_fds_when_owner_return_is_interrupted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_type: type[BaseException],
) -> None:
    candidate = _candidate(tmp_path, b"base\n")
    real_anchor = repo_tools._candidate_read_anchor
    captured_descriptors: list[int] = []
    owner = repo_tools._with_verified_candidate_checkpoint_read_only
    source_lines, first_line = inspect.getsourcelines(owner)
    return_line = next(
        first_line + offset
        for offset, source_line in enumerate(source_lines)
        if source_line.strip() == "return operation_result"
    )
    failure = failure_type("injected owner return interruption")

    def capture_anchor(*args, **kwargs):
        anchor = real_anchor(*args, **kwargs)
        captured_descriptors.append(anchor.descriptor)
        return anchor

    def interrupt_owner_return(frame, event, unused_argument):
        if (
            event == "line"
            and frame.f_code is owner.__code__
            and frame.f_lineno == return_line
        ):
            raise failure
        return interrupt_owner_return

    monkeypatch.setattr(repo_tools, "_candidate_read_anchor", capture_anchor)

    leaked_descriptors: list[int] = []
    with pytest.raises(failure_type) as raised:
        try:
            sys.settrace(interrupt_owner_return)
            repo_tools.prepare_candidate_execution_snapshot(
                _snapshot_request(candidate)
            )
        finally:
            sys.settrace(None)
            for descriptor in captured_descriptors:
                try:
                    os.fstat(descriptor)
                except OSError:
                    continue
                leaked_descriptors.append(descriptor)
                os.close(descriptor)

    assert len(captured_descriptors) == 5
    assert leaked_descriptors == []
    assert raised.value is failure


@pytest.mark.parametrize("failure_type", (KeyboardInterrupt, SystemExit))
@pytest.mark.parametrize("site", ("checkpoint_root", "snapshot_file"))
def test_snapshot_closes_fd_when_open_registration_is_interrupted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_type: type[BaseException],
    site: str,
) -> None:
    candidate = _candidate(tmp_path, b"base\n")
    real_open = repo_tools.os.open
    real_close = repo_tools.os.close
    opened_descriptors: list[int] = []
    close_calls: list[int] = []
    snapshot_file_armed = False
    if site == "checkpoint_root":
        target_path = candidate.runtime_root
    else:
        target_path = "README.md"
    target = repo_tools._CandidateReadDescriptorOwner.open
    source_lines, first_line = inspect.getsourcelines(target)
    boundary_line = next(
        first_line + offset
        for offset, source_line in enumerate(source_lines)
        if source_line.strip() == "self._descriptors.append(descriptor)"
    )
    failure = failure_type(f"injected {site} registration interruption")

    def arm_snapshot_file(unused_path: str) -> None:
        nonlocal snapshot_file_armed
        close_calls.clear()
        snapshot_file_armed = True

    def observe_open(path, flags, mode=0o777, *, dir_fd=None):
        descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
        if (
            (site == "checkpoint_root" and path == target_path)
            or (
                site == "snapshot_file"
                and snapshot_file_armed
                and path == target_path
            )
        ):
            if site == "checkpoint_root":
                close_calls.clear()
            opened_descriptors.append(descriptor)
        return descriptor

    def observe_close(descriptor: int) -> None:
        close_calls.append(descriptor)
        real_close(descriptor)

    def interrupt_registration(frame, event, unused_argument):
        if (
            event == "line"
            and frame.f_code is target.__code__
            and frame.f_lineno == boundary_line
            and frame.f_locals["path"] == target_path
            and (site == "checkpoint_root" or snapshot_file_armed)
        ):
            raise failure
        return interrupt_registration

    monkeypatch.setattr(repo_tools.os, "open", observe_open)
    monkeypatch.setattr(repo_tools.os, "close", observe_close)
    if site == "snapshot_file":
        monkeypatch.setattr(
            repo_tools,
            "_candidate_execution_snapshot_file_hook",
            arm_snapshot_file,
        )

    leaked_descriptors: list[int] = []
    with pytest.raises(failure_type) as raised:
        try:
            sys.settrace(interrupt_registration)
            repo_tools.prepare_candidate_execution_snapshot(
                _snapshot_request(candidate)
            )
        finally:
            sys.settrace(None)
            for descriptor in opened_descriptors:
                try:
                    os.fstat(descriptor)
                except OSError:
                    continue
                leaked_descriptors.append(descriptor)
                real_close(descriptor)

    assert len(opened_descriptors) == 1
    assert leaked_descriptors == []
    assert close_calls.count(opened_descriptors[0]) == 1
    assert raised.value is failure


@pytest.mark.parametrize("failure_type", (KeyboardInterrupt, SystemExit))
def test_snapshot_closes_duplicate_when_dup_registration_is_interrupted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_type: type[BaseException],
) -> None:
    candidate = _candidate(tmp_path, b"base\n")
    real_dup = repo_tools.os.dup
    real_close = repo_tools.os.close
    duplicated_descriptors: list[int] = []
    close_calls: list[int] = []
    target = repo_tools._CandidateReadDescriptorOwner.dup
    source_lines, first_line = inspect.getsourcelines(target)
    boundary_line = next(
        first_line + offset
        for offset, source_line in enumerate(source_lines)
        if source_line.strip() == "self._descriptors.append(duplicate)"
    )
    failure = failure_type("injected duplicate registration interruption")

    def observe_dup(descriptor: int) -> int:
        duplicate = real_dup(descriptor)
        close_calls.clear()
        duplicated_descriptors.append(duplicate)
        return duplicate

    def observe_close(descriptor: int) -> None:
        close_calls.append(descriptor)
        real_close(descriptor)

    def interrupt_registration(frame, event, unused_argument):
        if (
            event == "line"
            and frame.f_code is target.__code__
            and frame.f_lineno == boundary_line
        ):
            raise failure
        return interrupt_registration

    monkeypatch.setattr(repo_tools.os, "dup", observe_dup)
    monkeypatch.setattr(repo_tools.os, "close", observe_close)

    leaked_descriptors: list[int] = []
    with pytest.raises(failure_type) as raised:
        try:
            sys.settrace(interrupt_registration)
            repo_tools.prepare_candidate_execution_snapshot(
                _snapshot_request(candidate)
            )
        finally:
            sys.settrace(None)
            for descriptor in duplicated_descriptors:
                try:
                    os.fstat(descriptor)
                except OSError:
                    continue
                leaked_descriptors.append(descriptor)
                real_close(descriptor)

    assert len(duplicated_descriptors) == 1
    assert leaked_descriptors == []
    assert close_calls.count(duplicated_descriptors[0]) == 1
    assert raised.value is failure


def test_candidate_descriptor_owner_does_not_close_recycled_duplicate() -> None:
    source = os.open("/dev/null", os.O_RDONLY)
    owner = repo_tools._CandidateReadDescriptorOwner()
    recycled: int | None = None
    try:
        duplicate = owner.dup(source)
        owner.close()
        recycled = os.dup(source)
        assert recycled == duplicate

        owner.close()

        os.fstat(recycled)
    finally:
        if recycled is not None:
            os.close(recycled)
        os.close(source)


def test_candidate_snapshot_and_read_route_all_descriptor_acquisitions_through_owner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    content = b"base\n"
    candidate = _candidate(
        tmp_path,
        content,
        source_path="nested/README.md",
    )
    real_open = repo_tools.os.open
    real_dup = repo_tools.os.dup
    owner_open_code = repo_tools._CandidateReadDescriptorOwner.open.__code__
    owner_dup_code = repo_tools._CandidateReadDescriptorOwner.dup.__code__
    direct_acquisition_callers: list[tuple[str, str]] = []

    def observe_open(path, flags, mode=0o777, *, dir_fd=None):
        caller = sys._getframe(1)
        if (
            caller.f_globals.get("__name__") == repo_tools.__name__
            and caller.f_code is not owner_open_code
        ):
            direct_acquisition_callers.append(("open", caller.f_code.co_name))
        return real_open(path, flags, mode, dir_fd=dir_fd)

    def observe_dup(descriptor: int) -> int:
        caller = sys._getframe(1)
        if (
            caller.f_globals.get("__name__") == repo_tools.__name__
            and caller.f_code is not owner_dup_code
        ):
            direct_acquisition_callers.append(("dup", caller.f_code.co_name))
        return real_dup(descriptor)

    monkeypatch.setattr(repo_tools.os, "open", observe_open)
    monkeypatch.setattr(repo_tools.os, "dup", observe_dup)

    snapshot = repo_tools.prepare_candidate_execution_snapshot(
        _snapshot_request(candidate)
    )
    read = repo_tools.read_candidate_file(
        _request(candidate, path="nested/README.md")
    )

    assert snapshot.plan.files == (
        repo_tools.SourceFile("nested/README.md", "100644", content),
    )
    assert read.content == content
    assert direct_acquisition_callers == []


@pytest.mark.parametrize(
    ("field", "wrong_value"),
    (
        ("runtime_root", Path("relative-runtime")),
        ("workspace_id", "B" * 64),
        ("source_artifact_sha256", "A" * 64),
        ("expected_head_commit", "A" * 40),
        ("expected_workspace_manifest_digest", "A" * 64),
    ),
)
def test_prepare_candidate_execution_snapshot_requires_canonical_request_fields(
    tmp_path: Path,
    field: str,
    wrong_value: object,
) -> None:
    candidate = _candidate(tmp_path, b"base\n")
    values = {
        "runtime_root": candidate.runtime_root,
        "workspace_id": candidate.workspace_id,
        "source_artifact_sha256": candidate.source_artifact_sha256,
        "expected_head_commit": candidate.head_commit,
        "expected_workspace_manifest_digest": (
            candidate.workspace_manifest_digest
        ),
    }
    values[field] = wrong_value
    request = repo_tools.CandidateExecutionSnapshotRequest(**values)

    _assert_snapshot_recovery(candidate, request)


def test_prepare_candidate_execution_snapshot_requires_exact_request_type(
    tmp_path: Path,
) -> None:
    candidate = _candidate(tmp_path, b"base\n")
    request = _snapshot_request(candidate)

    _assert_snapshot_recovery(
        candidate,
        {
            "runtime_root": request.runtime_root,
            "workspace_id": request.workspace_id,
        },
    )


def test_prepare_candidate_execution_snapshot_requires_private_owned_runtime(
    tmp_path: Path,
) -> None:
    candidate = _candidate(tmp_path, b"base\n")
    candidate.runtime_root.chmod(0o755)

    _assert_snapshot_recovery(candidate)


@pytest.mark.parametrize(
    "mutation",
    (
        "missing_file",
        "missing_directory",
        "extra_file",
        "extra_directory",
        "reserved_path",
        "invalid_path",
    ),
)
def test_prepare_candidate_execution_snapshot_rejects_workspace_shape_changes(
    tmp_path: Path,
    mutation: str,
) -> None:
    source_path = (
        "nested/README.md" if mutation == "missing_directory" else "README.md"
    )
    candidate = _candidate(tmp_path, b"base\n", source_path=source_path)
    if mutation == "missing_file":
        (candidate.worktree / "README.md").unlink()
    elif mutation == "missing_directory":
        (candidate.worktree / "nested" / "README.md").unlink()
        (candidate.worktree / "nested").rmdir()
    elif mutation == "extra_file":
        (candidate.worktree / "extra.txt").write_bytes(b"extra\n")
    elif mutation == "extra_directory":
        (candidate.worktree / "extra").mkdir()
    elif mutation == "reserved_path":
        (candidate.worktree / ".git").mkdir()
    else:
        (candidate.worktree / "invalid name.txt").write_bytes(b"invalid\n")

    _assert_snapshot_recovery(candidate)


@pytest.mark.parametrize("mode", (0o600, 0o777))
def test_prepare_candidate_execution_snapshot_rejects_noncanonical_file_mode(
    tmp_path: Path,
    mode: int,
) -> None:
    candidate = _candidate(tmp_path, b"base\n")
    (candidate.worktree / "README.md").chmod(mode)

    _assert_snapshot_recovery(candidate)


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
) -> None:
    candidate = _candidate(tmp_path, b"base\n")
    target = candidate.worktree / "README.md"
    target.unlink()
    target.symlink_to("missing")

    with pytest.raises(repo_tools.CandidateReadError) as raised:
        repo_tools.read_candidate_file(_request(candidate))

    assert raised.value.code == "PATH_DENIED"


def test_read_candidate_file_denies_ancestor_symlink(
    tmp_path: Path,
) -> None:
    candidate = _candidate(tmp_path, b"base\n", source_path="src/README.md")
    target = candidate.worktree / "src"
    (target / "README.md").unlink()
    target.rmdir()
    target.symlink_to("missing")
    with pytest.raises(repo_tools.CandidateReadError) as raised:
        repo_tools.read_candidate_file(_request(candidate, path="src/README.md"))

    assert raised.value.code == "PATH_DENIED"


def test_read_candidate_file_denies_hardlink(
    tmp_path: Path,
) -> None:
    candidate = _candidate(tmp_path, b"base\n")
    external = tmp_path / "external"
    external.write_bytes(b"base\n")
    target = candidate.worktree / "README.md"
    target.unlink()
    os.link(external, target)
    with pytest.raises(repo_tools.CandidateReadError) as raised:
        repo_tools.read_candidate_file(_request(candidate))

    assert raised.value.code == "PATH_DENIED"


def test_read_candidate_file_denies_fifo(
    tmp_path: Path,
) -> None:
    candidate = _candidate(tmp_path, b"base\n")
    target = candidate.worktree / "README.md"
    target.unlink()
    os.mkfifo(target)
    with pytest.raises(repo_tools.CandidateReadError) as raised:
        repo_tools.read_candidate_file(_request(candidate))

    assert raised.value.code == "PATH_DENIED"


def test_read_candidate_file_denies_socket(
    tmp_path: Path,
) -> None:
    candidate = _candidate(tmp_path, b"base\n")
    target = candidate.worktree / "README.md"
    target.unlink()
    short_root = Path(tempfile.mkdtemp(prefix="owp-socket-", dir="/tmp"))
    short_worktree = short_root / "w"
    short_worktree.symlink_to(candidate.worktree)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(short_worktree / "README.md"))
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


def test_read_candidate_file_rejects_initial_metadata_mismatch_as_recovery(
    tmp_path: Path,
) -> None:
    candidate = _candidate(tmp_path, b"base\n")
    (candidate.worktree / "README.md").chmod(0o000)

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
    target_inode = (candidate.worktree / "README.md").stat().st_ino
    real_token = repo_tools._workspace_read_token
    target_calls = 0
    drift_observed = False
    checkpoint_complete = False

    def drift_after_read(metadata: os.stat_result) -> str:
        nonlocal drift_observed, target_calls
        token = real_token(metadata)
        if (
            checkpoint_complete
            and metadata.st_ino == target_inode
            and stat.S_ISREG(metadata.st_mode)
        ):
            target_calls += 1
            if target_calls == 3:
                drift_observed = True
                return token + ":drift"
        return token

    def mark_checkpoint_complete() -> None:
        nonlocal checkpoint_complete
        checkpoint_complete = True

    monkeypatch.setattr(
        repo_tools,
        "_candidate_read_checkpoint_hook",
        mark_checkpoint_complete,
    )
    monkeypatch.setattr(repo_tools, "_workspace_read_token", drift_after_read)

    with pytest.raises(repo_tools.CandidateReadError) as raised:
        repo_tools.read_candidate_file(_request(candidate))

    assert drift_observed is True
    assert raised.value.code == "FILE_CHANGED"


def test_read_candidate_file_rejects_leaf_replaced_after_checkpoint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = _candidate(tmp_path, b"base\n")
    target = candidate.worktree / "README.md"
    original_inode = target.stat().st_ino

    def replace_leaf() -> None:
        replacement = candidate.worktree / "replacement"
        replacement.write_bytes(b"base\n")
        replacement.chmod(0o644)
        replacement.replace(target)
        assert target.stat().st_ino != original_inode

    monkeypatch.setattr(
        repo_tools,
        "_candidate_read_checkpoint_hook",
        replace_leaf,
        raising=False,
    )

    with pytest.raises(repo_tools.CandidateReadError) as raised:
        repo_tools.read_candidate_file(_request(candidate))

    assert raised.value.code == "FILE_CHANGED"


def test_read_candidate_file_rejects_ancestor_replaced_after_checkpoint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = _candidate(tmp_path, b"base\n", source_path="src/README.md")
    ancestor = candidate.worktree / "src"
    original_inode = ancestor.stat().st_ino

    def replace_ancestor() -> None:
        ancestor.rename(candidate.worktree / "old-src")
        ancestor.mkdir(mode=0o755)
        replacement = ancestor / "README.md"
        replacement.write_bytes(b"base\n")
        replacement.chmod(0o644)
        assert ancestor.stat().st_ino != original_inode

    monkeypatch.setattr(
        repo_tools,
        "_candidate_read_checkpoint_hook",
        replace_ancestor,
    )

    with pytest.raises(repo_tools.CandidateReadError) as raised:
        repo_tools.read_candidate_file(_request(candidate, path="src/README.md"))

    assert raised.value.code == "FILE_CHANGED"


def test_read_candidate_file_rejects_worktree_replaced_after_checkpoint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = _candidate(tmp_path, b"base\n")
    original_inode = candidate.worktree.stat().st_ino

    def replace_worktree() -> None:
        candidate.worktree.rename(candidate.candidate_root / "old-worktree")
        candidate.worktree.mkdir(mode=0o700)
        replacement = candidate.worktree / "README.md"
        replacement.write_bytes(b"base\n")
        replacement.chmod(0o644)
        assert candidate.worktree.stat().st_ino != original_inode

    monkeypatch.setattr(
        repo_tools,
        "_candidate_read_checkpoint_hook",
        replace_worktree,
    )

    with pytest.raises(repo_tools.CandidateReadError) as raised:
        repo_tools.read_candidate_file(_request(candidate))

    assert raised.value.code == "FILE_CHANGED"


def test_read_candidate_file_rejects_metadata_change_after_checkpoint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = _candidate(tmp_path, b"base\n")

    def change_metadata() -> None:
        (candidate.worktree / "README.md").chmod(0o600)

    monkeypatch.setattr(
        repo_tools,
        "_candidate_read_checkpoint_hook",
        change_metadata,
    )

    with pytest.raises(repo_tools.CandidateReadError) as raised:
        repo_tools.read_candidate_file(_request(candidate))

    assert raised.value.code == "FILE_CHANGED"


def test_read_candidate_file_rejects_in_place_sibling_content_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = _candidate(
        tmp_path,
        b"base\n",
        additional_files=(
            repo_tools.SourceFile("other.txt", "100644", b"other\n"),
        ),
    )
    sibling = candidate.worktree / "other.txt"
    sibling_inode = sibling.stat().st_ino
    parent_token = repo_tools._workspace_read_token(candidate.worktree.stat())

    def change_sibling() -> None:
        with sibling.open("r+b") as stream:
            stream.write(b"evil!\n")
        assert sibling.stat().st_ino == sibling_inode
        assert (
            repo_tools._workspace_read_token(candidate.worktree.stat())
            == parent_token
        )

    monkeypatch.setattr(
        repo_tools,
        "_candidate_read_checkpoint_hook",
        change_sibling,
    )

    with pytest.raises(repo_tools.CandidateReadError) as raised:
        repo_tools.read_candidate_file(_request(candidate))

    assert raised.value.code == "FILE_CHANGED"


def test_read_candidate_file_rejects_sibling_metadata_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = _candidate(
        tmp_path,
        b"base\n",
        additional_files=(
            repo_tools.SourceFile("other.txt", "100644", b"other\n"),
        ),
    )
    sibling = candidate.worktree / "other.txt"
    sibling_inode = sibling.stat().st_ino
    parent_token = repo_tools._workspace_read_token(candidate.worktree.stat())

    def change_sibling_metadata() -> None:
        sibling.chmod(0o755)
        assert sibling.stat().st_ino == sibling_inode
        assert (
            repo_tools._workspace_read_token(candidate.worktree.stat())
            == parent_token
        )

    monkeypatch.setattr(
        repo_tools,
        "_candidate_read_checkpoint_hook",
        change_sibling_metadata,
    )

    with pytest.raises(repo_tools.CandidateReadError) as raised:
        repo_tools.read_candidate_file(_request(candidate))

    assert raised.value.code == "FILE_CHANGED"


def test_read_candidate_file_rejects_nested_sibling_content_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = _candidate(
        tmp_path,
        b"base\n",
        additional_files=(
            repo_tools.SourceFile("nested/other.txt", "100644", b"other\n"),
        ),
    )
    sibling = candidate.worktree / "nested" / "other.txt"
    sibling_inode = sibling.stat().st_ino
    parent_token = repo_tools._workspace_read_token(sibling.parent.stat())

    def change_nested_sibling() -> None:
        with sibling.open("r+b") as stream:
            stream.write(b"evil!\n")
        assert sibling.stat().st_ino == sibling_inode
        assert repo_tools._workspace_read_token(sibling.parent.stat()) == parent_token

    monkeypatch.setattr(
        repo_tools,
        "_candidate_read_checkpoint_hook",
        change_nested_sibling,
    )

    with pytest.raises(repo_tools.CandidateReadError) as raised:
        repo_tools.read_candidate_file(_request(candidate))

    assert raised.value.code == "FILE_CHANGED"


def test_read_candidate_file_rejects_globally_woven_sibling_aba(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = _candidate(
        tmp_path,
        b"base\n",
        additional_files=(
            repo_tools.SourceFile("a.txt", "100644", b"alpha\n"),
            repo_tools.SourceFile("b.txt", "100644", b"bravo\n"),
        ),
    )
    a_path = candidate.worktree / "a.txt"
    b_path = candidate.worktree / "b.txt"
    a_inode = a_path.stat().st_ino
    b_inode = b_path.stat().st_ino
    real_scan = repo_tools.scan_workspace_manifest
    real_stat = repo_tools.os.stat
    scan_calls = 0
    woven_a_stats = 0
    weaving = False

    def weave_manifest_scan(
        root_fd: int,
        head_commit: str,
    ) -> repo_tools.WorkspaceManifest:
        nonlocal scan_calls, weaving
        scan_calls += 1
        weaving = scan_calls == 2
        try:
            return real_scan(root_fd, head_commit)
        finally:
            weaving = False

    def weave_siblings(
        path,
        *,
        dir_fd=None,
        follow_symlinks=True,
    ) -> os.stat_result:
        nonlocal woven_a_stats
        if weaving and path == "a.txt":
            woven_a_stats += 1
            if woven_a_stats == 1:
                a_path.write_bytes(b"alpha\n")
                return real_stat(
                    path,
                    dir_fd=dir_fd,
                    follow_symlinks=follow_symlinks,
                )
            if woven_a_stats == 2:
                metadata = real_stat(
                    path,
                    dir_fd=dir_fd,
                    follow_symlinks=follow_symlinks,
                )
                a_path.write_bytes(b"evil!\n")
                b_path.write_bytes(b"bravo\n")
                return metadata
        return real_stat(
            path,
            dir_fd=dir_fd,
            follow_symlinks=follow_symlinks,
        )

    def start_with_both_siblings_changed() -> None:
        a_path.write_bytes(b"evil!\n")
        b_path.write_bytes(b"evil!\n")
        assert a_path.stat().st_ino == a_inode
        assert b_path.stat().st_ino == b_inode

    monkeypatch.setattr(
        repo_tools,
        "_candidate_read_checkpoint_hook",
        start_with_both_siblings_changed,
    )
    monkeypatch.setattr(
        repo_tools,
        "scan_workspace_manifest",
        weave_manifest_scan,
    )
    monkeypatch.setattr(repo_tools.os, "stat", weave_siblings)

    with pytest.raises(repo_tools.CandidateReadError) as raised:
        repo_tools.read_candidate_file(_request(candidate))

    assert scan_calls == 2
    assert woven_a_stats == 2
    assert a_path.read_bytes() == b"evil!\n"
    assert b_path.read_bytes() == b"bravo\n"
    assert raised.value.code == "FILE_CHANGED"


def test_read_candidate_file_rejects_initial_manifest_metadata_aba(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = _candidate(tmp_path, b"base\n")
    target = candidate.worktree / "README.md"
    target_inode = target.stat().st_ino
    initial_token = repo_tools._workspace_read_token(target.stat())
    real_scan = repo_tools.scan_workspace_manifest
    scan_calls = 0

    def restore_metadata_before_initial_scan(
        root_fd: int,
        head_commit: str,
    ) -> repo_tools.WorkspaceManifest:
        nonlocal scan_calls
        scan_calls += 1
        if scan_calls == 1:
            target.chmod(0o755)
            target.chmod(0o644)
            assert target.stat().st_ino == target_inode
            assert stat.S_IMODE(target.stat().st_mode) == 0o644
            assert repo_tools._workspace_read_token(target.stat()) != initial_token
        return real_scan(root_fd, head_commit)

    monkeypatch.setattr(
        repo_tools,
        "scan_workspace_manifest",
        restore_metadata_before_initial_scan,
    )

    with pytest.raises(repo_tools.CandidateReadError) as raised:
        repo_tools.read_candidate_file(_request(candidate))

    assert scan_calls == 1
    assert raised.value.code == "RECOVERY_REQUIRED"


def test_read_candidate_file_maps_post_read_manifest_scan_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = _candidate(tmp_path, b"base\n")
    real_scan = repo_tools.scan_workspace_manifest
    real_anchor = repo_tools._candidate_read_anchor
    closed_descriptors: list[int] = []
    scan_calls = 0

    def fail_post_read_scan(
        root_fd: int,
        head_commit: str,
    ) -> repo_tools.WorkspaceManifest:
        nonlocal scan_calls
        scan_calls += 1
        if scan_calls == 2:
            raise repo_tools.ManifestError("post-read scan failed")
        return real_scan(root_fd, head_commit)

    def capture_anchor(*args, **kwargs):
        anchor = real_anchor(*args, **kwargs)
        closed_descriptors.append(anchor.descriptor)
        return anchor

    monkeypatch.setattr(
        repo_tools,
        "scan_workspace_manifest",
        fail_post_read_scan,
    )
    monkeypatch.setattr(
        repo_tools,
        "_candidate_read_anchor",
        capture_anchor,
    )

    with pytest.raises(repo_tools.CandidateReadError) as raised:
        repo_tools.read_candidate_file(_request(candidate))

    assert scan_calls == 2
    assert raised.value.code == "FILE_CHANGED"
    assert closed_descriptors
    for descriptor in closed_descriptors:
        with pytest.raises(OSError):
            os.fstat(descriptor)


def test_read_candidate_file_rejects_control_corruption_after_checkpoint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = _candidate(tmp_path, b"base\n")
    control = candidate.candidate_root / "control.json"

    def corrupt_control() -> None:
        control.write_bytes(b"corrupt")
        control.chmod(0o600)

    monkeypatch.setattr(
        repo_tools,
        "_candidate_read_checkpoint_hook",
        corrupt_control,
    )

    with pytest.raises(repo_tools.CandidateReadError) as raised:
        repo_tools.read_candidate_file(_request(candidate))

    assert raised.value.code == "FILE_CHANGED"


@pytest.mark.parametrize(
    "authority_name",
    ("index", "ref", "head", "object"),
)
def test_read_candidate_file_rejects_git_authority_corruption_after_checkpoint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    authority_name: str,
) -> None:
    candidate = _candidate(tmp_path, b"base\n")
    authority_paths = {
        "index": candidate.git_dir / "index",
        "ref": candidate.git_dir / "refs" / "heads" / "candidate",
        "head": candidate.git_dir / "HEAD",
        "object": (
            candidate.git_dir
            / "objects"
            / candidate.head_commit[:2]
            / candidate.head_commit[2:]
        ),
    }
    authority_path = authority_paths[authority_name]

    def corrupt_authority() -> None:
        content = bytearray(authority_path.read_bytes())
        content[0] ^= 1
        authority_path.chmod(0o600)
        authority_path.write_bytes(content)

    monkeypatch.setattr(
        repo_tools,
        "_candidate_read_checkpoint_hook",
        corrupt_authority,
    )

    with pytest.raises(repo_tools.CandidateReadError) as raised:
        repo_tools.read_candidate_file(_request(candidate))

    assert raised.value.code == "FILE_CHANGED"


def test_read_candidate_file_rejects_ephemeral_ref_during_git_calls(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = _candidate(tmp_path, b"base\n")
    ref_path = candidate.git_dir / "refs" / "heads" / "candidate"
    ref_raw = ref_path.read_bytes()
    ref_path.unlink()
    real_run = repo_tools._run_git_read_only
    restored_calls = 0

    def run_with_ephemeral_ref(*, git_dir, worktree, arguments):
        nonlocal restored_calls
        if arguments in {
            ("rev-parse", "HEAD"),
            ("cat-file", "-e", "HEAD^{commit}"),
            ("diff-index", "--cached", "--quiet", "HEAD", "--"),
        }:
            restored_calls += 1
            ref_path.write_bytes(ref_raw)
            try:
                return real_run(
                    git_dir=git_dir,
                    worktree=worktree,
                    arguments=arguments,
                )
            finally:
                ref_path.unlink()
        return real_run(
            git_dir=git_dir,
            worktree=worktree,
            arguments=arguments,
        )

    monkeypatch.setattr(repo_tools, "_run_git_read_only", run_with_ephemeral_ref)

    with pytest.raises(repo_tools.CandidateReadError) as raised:
        repo_tools.read_candidate_file(_request(candidate))

    assert restored_calls == 3
    assert not ref_path.exists()
    assert raised.value.code == "RECOVERY_REQUIRED"


@pytest.mark.parametrize(
    ("limit_name", "limit_value"),
    (
        ("_MAX_GIT_AUTHORITY_ENTRIES", 1),
        ("_MAX_GIT_AUTHORITY_TOTAL_BYTES", 1),
    ),
)
def test_read_candidate_file_rejects_git_authority_snapshot_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    limit_name: str,
    limit_value: int,
) -> None:
    candidate = _candidate(tmp_path, b"base\n")
    monkeypatch.setattr(repo_tools, limit_name, limit_value)

    with pytest.raises(repo_tools.CandidateReadError) as raised:
        repo_tools.read_candidate_file(_request(candidate))

    assert raised.value.code == "RECOVERY_REQUIRED"


@pytest.mark.parametrize("entry_kind", ("symlink", "fifo"))
def test_workspace_identity_snapshot_rejects_unsupported_entry(
    tmp_path: Path,
    entry_kind: str,
) -> None:
    candidate = _candidate(tmp_path, b"base\n")
    unexpected = candidate.worktree / "unexpected"
    if entry_kind == "symlink":
        unexpected.symlink_to("README.md")
    else:
        os.mkfifo(unexpected, mode=0o600)
    descriptor = os.open(
        candidate.worktree,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
    )

    try:
        with pytest.raises(repo_tools.CandidateWorkspaceError):
            repo_tools._scan_candidate_workspace_identity(descriptor)
    finally:
        os.close(descriptor)


def test_workspace_identity_snapshot_closes_child_fd_on_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = _candidate(
        tmp_path,
        b"base\n",
        additional_files=(
            repo_tools.SourceFile("nested/other.txt", "100644", b"other\n"),
        ),
    )
    descriptor = os.open(
        candidate.worktree,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
    )
    real_open = repo_tools.os.open
    real_stat = repo_tools.os.stat
    child_descriptors: list[int] = []

    def observe_open(path, flags, mode=0o777, *, dir_fd=None):
        opened = real_open(path, flags, mode, dir_fd=dir_fd)
        if path == "nested":
            child_descriptors.append(opened)
        return opened

    def fail_nested_stat(path, *, dir_fd=None, follow_symlinks=True):
        if path == "other.txt":
            raise OSError("injected identity stat failure")
        return real_stat(
            path,
            dir_fd=dir_fd,
            follow_symlinks=follow_symlinks,
        )

    monkeypatch.setattr(repo_tools.os, "open", observe_open)
    monkeypatch.setattr(repo_tools.os, "stat", fail_nested_stat)

    try:
        with pytest.raises(repo_tools.CandidateWorkspaceError):
            repo_tools._scan_candidate_workspace_identity(descriptor)
    finally:
        os.close(descriptor)

    assert child_descriptors
    for child_descriptor in child_descriptors:
        with pytest.raises(OSError):
            os.fstat(child_descriptor)


@pytest.mark.parametrize(
    ("limit_name", "limit_value", "additional_files"),
    (
        (
            "_MAX_WORKSPACE_MANIFEST_ENTRIES",
            1,
            (repo_tools.SourceFile("other.txt", "100644", b"other\n"),),
        ),
        (
            "_MAX_WORKSPACE_IDENTITY_DEPTH",
            0,
            (repo_tools.SourceFile("nested/other.txt", "100644", b"other\n"),),
        ),
        (
            "_MAX_WORKSPACE_IDENTITY_PATH_BYTES",
            3,
            (),
        ),
    ),
)
def test_workspace_identity_snapshot_rejects_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    limit_name: str,
    limit_value: int,
    additional_files: tuple[repo_tools.SourceFile, ...],
) -> None:
    candidate = _candidate(
        tmp_path,
        b"base\n",
        additional_files=additional_files,
    )
    descriptor = os.open(
        candidate.worktree,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
    )
    monkeypatch.setattr(repo_tools, limit_name, limit_value)

    try:
        with pytest.raises(repo_tools.CandidateWorkspaceError):
            repo_tools._scan_candidate_workspace_identity(descriptor)
    finally:
        os.close(descriptor)


def test_workspace_identity_snapshot_enforces_global_limit_after_recursion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = _candidate(
        tmp_path,
        b"base\n",
        additional_files=(
            repo_tools.SourceFile("a/x", "100644", b"x\n"),
            repo_tools.SourceFile("z", "100644", b"z\n"),
        ),
    )
    descriptors_before = len(os.listdir("/dev/fd"))
    descriptor = os.open(
        candidate.worktree,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
    )
    monkeypatch.setattr(repo_tools, "_MAX_WORKSPACE_MANIFEST_ENTRIES", 3)

    try:
        with pytest.raises(repo_tools.CandidateWorkspaceError):
            repo_tools._scan_candidate_workspace_identity(descriptor)
    finally:
        os.close(descriptor)

    assert len(os.listdir("/dev/fd")) == descriptors_before


def test_workspace_identity_snapshot_rejects_513th_before_stat_or_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = _candidate(tmp_path, b"base\n")
    (candidate.worktree / "README.md").unlink()
    nested = candidate.worktree / "0"
    nested.mkdir()
    (nested / "x").write_bytes(b"x\n")
    for index in range(511):
        (candidate.worktree / f"s{index:03d}").write_bytes(b"s\n")
    real_open = repo_tools.os.open
    real_stat = repo_tools.os.stat
    observed_513th = False

    def observe_open(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal observed_513th
        if path == "s510":
            observed_513th = True
        return real_open(path, flags, mode, dir_fd=dir_fd)

    def observe_stat(path, *, dir_fd=None, follow_symlinks=True):
        nonlocal observed_513th
        if path == "s510":
            observed_513th = True
        return real_stat(
            path,
            dir_fd=dir_fd,
            follow_symlinks=follow_symlinks,
        )

    descriptors_before = len(os.listdir("/dev/fd"))
    descriptor = os.open(
        candidate.worktree,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
    )
    monkeypatch.setattr(repo_tools.os, "open", observe_open)
    monkeypatch.setattr(repo_tools.os, "stat", observe_stat)

    try:
        with pytest.raises(repo_tools.CandidateWorkspaceError):
            repo_tools._scan_candidate_workspace_identity(descriptor)
    finally:
        os.close(descriptor)

    assert observed_513th is False
    assert len(os.listdir("/dev/fd")) == descriptors_before


def test_read_candidate_file_never_returns_prefix_during_truncation_race(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = _candidate(tmp_path, b"base\n")
    target = candidate.worktree / "README.md"
    real_read = repo_tools.os.read
    checkpoint_complete = False
    raced = False

    def mark_checkpoint_complete() -> None:
        nonlocal checkpoint_complete
        checkpoint_complete = True

    def truncate_during_read(descriptor: int, size: int) -> bytes:
        nonlocal raced
        if checkpoint_complete and not raced:
            raced = True
            target.write_bytes(b"x")
        return real_read(descriptor, size)

    monkeypatch.setattr(
        repo_tools,
        "_candidate_read_checkpoint_hook",
        mark_checkpoint_complete,
    )
    monkeypatch.setattr(repo_tools.os, "read", truncate_during_read)

    with pytest.raises(repo_tools.CandidateReadError) as raised:
        repo_tools.read_candidate_file(_request(candidate))

    assert raced is True
    assert raised.value.code == "FILE_CHANGED"


def test_read_candidate_file_rejects_content_change_during_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = _candidate(tmp_path, b"base\n")
    target = candidate.worktree / "README.md"
    real_read = repo_tools.os.read
    checkpoint_complete = False
    raced = False

    def mark_checkpoint_complete() -> None:
        nonlocal checkpoint_complete
        checkpoint_complete = True

    def change_content_during_read(descriptor: int, size: int) -> bytes:
        nonlocal raced
        if checkpoint_complete and not raced:
            raced = True
            target.write_bytes(b"evil\n")
        return real_read(descriptor, size)

    monkeypatch.setattr(
        repo_tools,
        "_candidate_read_checkpoint_hook",
        mark_checkpoint_complete,
    )
    monkeypatch.setattr(repo_tools.os, "read", change_content_during_read)

    with pytest.raises(repo_tools.CandidateReadError) as raised:
        repo_tools.read_candidate_file(_request(candidate))

    assert raced is True
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
        assert command[config_index : config_index + 8] == [
            "-c",
            "core.autocrlf=false",
            "-c",
            "core.filemode=true",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
        ]
        observed_arguments.append(tuple(command[config_index + 8 :]))
        assert kwargs["env"] == expected_environment
        assert kwargs["timeout"] == 30
        assert kwargs["check"] is False
        assert "status" not in command
        assert "write-tree" not in command
        assert candidate.head_commit not in command
    assert observed_arguments == [
        ("rev-parse", "--is-bare-repository"),
        ("rev-parse", "HEAD"),
        ("cat-file", "-e", "HEAD^{commit}"),
        (
            "diff-index",
            "--cached",
            "--quiet",
            "HEAD",
            "--",
        ),
    ]


def test_read_candidate_file_closes_read_error_as_file_changed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = _candidate(tmp_path, b"base\n")
    checkpoint_complete = False

    def mark_checkpoint_complete() -> None:
        nonlocal checkpoint_complete
        checkpoint_complete = True

    monkeypatch.setattr(
        repo_tools,
        "_candidate_read_checkpoint_hook",
        mark_checkpoint_complete,
    )

    def fail_read(descriptor: int, size: int) -> bytes:
        if checkpoint_complete:
            raise OSError("injected read failure")
        return real_read(descriptor, size)

    real_read = repo_tools.os.read
    monkeypatch.setattr(repo_tools.os, "read", fail_read)

    with pytest.raises(repo_tools.CandidateReadError) as raised:
        repo_tools.read_candidate_file(_request(candidate))

    assert raised.value.code == "FILE_CHANGED"


def test_read_candidate_file_closes_every_checkpoint_descriptor_on_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = _candidate(tmp_path, b"base\n", source_path="src/README.md")
    captured_descriptors: tuple[int, ...] = ()

    def fail_after_checkpoint(checkpoint, path: str) -> bytes:
        nonlocal captured_descriptors
        captured_descriptors = tuple(
            anchor.descriptor for anchor in checkpoint.anchors
        )
        raise repo_tools.CandidateReadError("FILE_CHANGED")

    monkeypatch.setattr(
        repo_tools,
        "_read_verified_candidate_path",
        fail_after_checkpoint,
    )

    with pytest.raises(repo_tools.CandidateReadError) as raised:
        repo_tools.read_candidate_file(_request(candidate, path="src/README.md"))

    assert raised.value.code == "FILE_CHANGED"
    assert len(captured_descriptors) == 7
    for descriptor in captured_descriptors:
        with pytest.raises(OSError):
            os.fstat(descriptor)


def test_read_candidate_file_closes_descriptors_when_checkpoint_scan_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = _candidate(tmp_path, b"base\n")
    real_anchor = repo_tools._candidate_read_anchor
    captured_descriptors: list[int] = []

    def observe_anchor(*args, **kwargs):
        anchor = real_anchor(*args, **kwargs)
        captured_descriptors.append(anchor.descriptor)
        return anchor

    def fail_scan(root_fd: int, head_commit: str):
        raise repo_tools.ManifestError("injected scan failure")

    monkeypatch.setattr(repo_tools, "_candidate_read_anchor", observe_anchor)
    monkeypatch.setattr(repo_tools, "scan_workspace_manifest", fail_scan)

    with pytest.raises(repo_tools.CandidateReadError) as raised:
        repo_tools.read_candidate_file(_request(candidate))

    assert raised.value.code == "RECOVERY_REQUIRED"
    assert len(captured_descriptors) == 6
    for descriptor in captured_descriptors:
        with pytest.raises(OSError):
            os.fstat(descriptor)
