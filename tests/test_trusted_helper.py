"""Trusted helper repository read boundary tests."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
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


def test_dispatcher_returns_strict_unpadded_urlsafe_base64(tmp_path: Path) -> None:
    candidate = _candidate(tmp_path, b"\xfb\xff")
    raw = rfc8785.dumps(_dispatcher_request(candidate))

    exit_code, response_raw = _dispatch_raw(raw, candidate.runtime_root)
    response = json.loads(response_raw)

    assert exit_code == 0
    assert response["content_b64url"] == "-_8"
    assert "=" not in response["content_b64url"]


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
    checkpoint_complete = False

    def drift_after_read(metadata: os.stat_result) -> str:
        nonlocal target_calls
        token = real_token(metadata)
        if (
            checkpoint_complete
            and metadata.st_ino == target_inode
            and stat.S_ISREG(metadata.st_mode)
        ):
            target_calls += 1
            if target_calls == 3:
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

    assert target_calls == 3
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
