#!/usr/bin/env python3
"""Stage and execute one frozen verifier snapshot inside the execution image."""

from __future__ import annotations

import base64
from dataclasses import dataclass
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time
from typing import BinaryIO, Callable


FROZEN_VERIFIER_ARGV = (
    "/opt/venv/bin/python",
    "-I",
    "-m",
    "pytest",
    "-q",
)
MAX_CONTRACT_BYTES = 8192
MAX_RESULT_BYTES = 8192
MAX_COMBINED_STDIO_BYTES = 1048576
WALL_CLOCK_TIMEOUT_SECONDS = 120

_MAGIC = b"openworkproof-snapshot-stream/0.1\n"
_MAX_HEADER_BYTES = 65_536
_MAX_STREAM_BYTES = 8_527_872
_MAX_FILES = 126
_MAX_PATH_BYTES = 512
_MAX_FILE_BYTES = 1_048_576
_MAX_CANDIDATE_BYTES = 8_388_608
_MAX_SUMMARY_BYTES = 512
_ALLOWED_MODES = frozenset({"100644", "100755"})
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_OID = re.compile(r"^[0-9a-f]{40}$")
_IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_CONTRACT_KEYS = frozenset(
    {
        "arguments_digest",
        "candidate_commit",
        "candidate_workspace_id",
        "command_digest",
        "container_image_digest",
        "execution_id",
        "fixed_test_source_digest",
        "request_digest",
        "schema_version",
        "source_artifact_sha256",
        "source_commit",
        "test_mode",
        "tool_name",
        "workspace_manifest_digest",
    }
)


class RunnerError(RuntimeError):
    """The staged snapshot or execution boundary is not closed."""


@dataclass(frozen=True, slots=True)
class ProcessOutcome:
    exit_code: int | None
    failure_code: str | None
    stdout: bytes
    stderr: bytes


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")


def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise RunnerError("JSON contains a duplicate key")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise RunnerError(f"invalid JSON constant: {value}")


def _parse_canonical_json(raw: bytes) -> object:
    try:
        value = json.loads(
            raw.decode("ascii"),
            object_pairs_hook=_reject_duplicates,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RunnerError) as error:
        raise RunnerError("JSON is not strict canonical ASCII") from error
    try:
        canonical = _canonical(value)
    except (UnicodeEncodeError, TypeError, ValueError) as error:
        raise RunnerError("JSON cannot be canonically encoded") from error
    if canonical != raw:
        raise RunnerError("JSON bytes are not canonical")
    return value


def _frozen_command_digest() -> str:
    return hashlib.sha256(
        _canonical(
            {
                "domain": "openworkproof/verifier-command/v0.1",
                "argv": list(FROZEN_VERIFIER_ARGV),
            }
        )
    ).hexdigest()


def _validated_contract(raw: bytes) -> dict[str, str]:
    if not 1 <= len(raw) <= MAX_CONTRACT_BYTES:
        raise RunnerError("run contract size is invalid")
    value = _parse_canonical_json(raw)
    if type(value) is not dict or frozenset(value) != _CONTRACT_KEYS:
        raise RunnerError("run contract keys are invalid")
    if not all(type(item) is str for item in value.values()):
        raise RunnerError("run contract values must be strings")
    contract = value
    if (
        contract["schema_version"] != "openworkproof-run-contract/0.1"
        or contract["tool_name"] != "owp.run_tests"
        or contract["test_mode"] != "verifier"
    ):
        raise RunnerError("run contract constants are invalid")
    for key in (
        "arguments_digest",
        "candidate_workspace_id",
        "execution_id",
        "fixed_test_source_digest",
        "request_digest",
        "source_artifact_sha256",
        "workspace_manifest_digest",
    ):
        if _DIGEST.fullmatch(contract[key]) is None:
            raise RunnerError(f"run contract digest is invalid: {key}")
    for key in ("candidate_commit", "source_commit"):
        if _OID.fullmatch(contract[key]) is None:
            raise RunnerError(f"run contract object id is invalid: {key}")
    if _IMAGE_DIGEST.fullmatch(contract["container_image_digest"]) is None:
        raise RunnerError("run contract image digest is invalid")
    if contract["command_digest"] != _frozen_command_digest():
        raise RunnerError("run contract command digest is not frozen")
    return contract


def _validated_root(path: Path, label: str) -> Path:
    if type(path) is not type(Path()) or not path.is_absolute():
        raise RunnerError(f"{label} root is not an absolute path")
    try:
        metadata = path.lstat()
    except OSError as error:
        raise RunnerError(f"{label} root is unavailable") from error
    if path.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
        raise RunnerError(f"{label} root is not a regular directory")
    return path


def _validated_path(value: object) -> str:
    if type(value) is not str or not value:
        raise RunnerError("snapshot path is invalid")
    try:
        raw = value.encode("ascii")
    except UnicodeEncodeError as error:
        raise RunnerError("snapshot path is not ASCII") from error
    parts = value.split("/")
    if (
        not 1 <= len(raw) <= _MAX_PATH_BYTES
        or value.startswith("/")
        or value.endswith("/")
        or "\0" in value
        or any(part in {"", ".", ".."} for part in parts)
        or value == "run-contract.json"
    ):
        raise RunnerError("snapshot path is not canonical")
    return value


def _read_exact(stream: BinaryIO, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = stream.read(min(remaining, 65_536))
        if not isinstance(chunk, bytes) or not chunk:
            raise RunnerError("snapshot stream ended early")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _write_new_regular(path: Path, content: bytes, mode: int) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags | nofollow, mode)
    try:
        view = memoryview(content)
        written = 0
        while written < len(view):
            count = os.write(descriptor, view[written:])
            if count <= 0:
                raise RunnerError("snapshot write made no progress")
            written += count
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.utime(path, ns=(0, 0), follow_symlinks=False)


def _read_regular(path: Path, maximum: int) -> tuple[bytes, os.stat_result]:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, os.O_RDONLY | nofollow)
    except OSError as error:
        raise RunnerError(f"regular file cannot be opened: {path.name}") from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or not 0 <= before.st_size <= maximum
        ):
            raise RunnerError(f"file metadata is invalid: {path.name}")
        content = _read_exact(os.fdopen(os.dup(descriptor), "rb", closefd=True), before.st_size)
        if os.read(descriptor, 1):
            raise RunnerError(f"file grew during read: {path.name}")
        after = os.fstat(descriptor)
        named = path.lstat()
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if identity_before != identity_after or not os.path.samestat(after, named):
            raise RunnerError(f"file changed during read: {path.name}")
        return content, after
    finally:
        os.close(descriptor)


def _manifest_digest(
    files: dict[str, tuple[str, bytes]],
    head_commit: str,
) -> str:
    directories = {
        "/".join(path.split("/")[:index])
        for path in files
        for index in range(1, len(path.split("/")))
    }
    entries: list[dict[str, object]] = []
    for path in directories:
        entries.append(
            {
                "path_bytes_b64url": base64.urlsafe_b64encode(path.encode("ascii"))
                .rstrip(b"=")
                .decode("ascii"),
                "type": "directory",
                "posix_mode": "040755",
                "size_bytes": None,
                "sha256": None,
                "symlink_target_b64url": None,
            }
        )
    for path, (mode, content) in files.items():
        entries.append(
            {
                "path_bytes_b64url": base64.urlsafe_b64encode(path.encode("ascii"))
                .rstrip(b"=")
                .decode("ascii"),
                "type": "regular",
                "posix_mode": mode,
                "size_bytes": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
                "symlink_target_b64url": None,
            }
        )
    entries.sort(
        key=lambda entry: base64.urlsafe_b64decode(
            str(entry["path_bytes_b64url"]) + "=="
        )
    )
    manifest = {
        "schema_version": "openworkproof-workspace-manifest/0.1",
        "head_commit": head_commit,
        "entries": entries,
    }
    return hashlib.sha256(
        _canonical(
            {
                "domain": "openworkproof/workspace-manifest/v0.1",
                "manifest": manifest,
            }
        )
    ).hexdigest()


def _scan_workspace(root: Path) -> dict[str, tuple[str, bytes]]:
    files: dict[str, tuple[str, bytes]] = {}
    directories: set[str] = set()
    total = 0

    def scan(directory: Path, prefix: str) -> None:
        nonlocal total
        try:
            entries = sorted(os.scandir(directory), key=lambda item: os.fsencode(item.name))
        except OSError as error:
            raise RunnerError("workspace cannot be scanned") from error
        for entry in entries:
            path = f"{prefix}/{entry.name}" if prefix else entry.name
            if path == "run-contract.json":
                if prefix or entry.is_symlink() or not entry.is_file(follow_symlinks=False):
                    raise RunnerError("reserved control file is invalid")
                continue
            canonical = _validated_path(path)
            try:
                metadata = entry.stat(follow_symlinks=False)
            except OSError as error:
                raise RunnerError("workspace entry cannot be inspected") from error
            if entry.is_symlink():
                raise RunnerError("workspace contains a symlink")
            if stat.S_ISDIR(metadata.st_mode):
                if stat.S_IMODE(metadata.st_mode) != 0o755:
                    raise RunnerError("workspace directory mode is not normalized")
                directories.add(canonical)
                scan(Path(entry.path), canonical)
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise RunnerError("workspace contains a special file")
            if len(files) >= _MAX_FILES:
                raise RunnerError("workspace has too many files")
            mode = f"{metadata.st_mode:06o}"
            if mode not in _ALLOWED_MODES:
                raise RunnerError("workspace file mode is not normalized")
            content, fresh = _read_regular(Path(entry.path), _MAX_FILE_BYTES)
            if f"{fresh.st_mode:06o}" != mode:
                raise RunnerError("workspace file mode changed")
            total += len(content)
            if total > _MAX_CANDIDATE_BYTES:
                raise RunnerError("workspace content exceeds its limit")
            files[canonical] = (mode, content)

    scan(root, "")
    if not files:
        raise RunnerError("workspace has no candidate files")
    derived = {
        "/".join(path.split("/")[:index])
        for path in files
        for index in range(1, len(path.split("/")))
    }
    if directories != derived:
        raise RunnerError("workspace directories are not exactly derived")
    return files


def _stage(root: Path, input_stream: BinaryIO, output_stream: BinaryIO) -> int:
    root = _validated_root(root, "workspace")
    if any(os.scandir(root)):
        raise RunnerError("staging workspace is not empty")
    if _read_exact(input_stream, len(_MAGIC)) != _MAGIC:
        raise RunnerError("snapshot stream magic is invalid")
    header_size = int.from_bytes(_read_exact(input_stream, 4), "big")
    if not 1 <= header_size <= _MAX_HEADER_BYTES:
        raise RunnerError("snapshot header size is invalid")
    header_raw = _read_exact(input_stream, header_size)
    header = _parse_canonical_json(header_raw)
    if type(header) is not dict or set(header) != {
        "schema_version",
        "files",
        "contract",
    }:
        raise RunnerError("snapshot header keys are invalid")
    if header["schema_version"] != "openworkproof-snapshot-stream/0.1":
        raise RunnerError("snapshot schema is invalid")
    rows = header["files"]
    if type(rows) is not list or not 1 <= len(rows) <= _MAX_FILES:
        raise RunnerError("snapshot file count is invalid")
    validated_rows: list[tuple[str, str, int, str]] = []
    previous: bytes | None = None
    total = 0
    for row in rows:
        if type(row) is not dict or set(row) != {"path", "mode", "size_bytes", "sha256"}:
            raise RunnerError("snapshot file keys are invalid")
        path = _validated_path(row["path"])
        raw_path = path.encode("ascii")
        if previous is not None and raw_path <= previous:
            raise RunnerError("snapshot paths are not strictly ordered")
        previous = raw_path
        mode = row["mode"]
        size = row["size_bytes"]
        digest = row["sha256"]
        if (
            type(mode) is not str
            or mode not in _ALLOWED_MODES
            or type(size) is not int
            or not 0 <= size <= _MAX_FILE_BYTES
            or type(digest) is not str
            or _DIGEST.fullmatch(digest) is None
        ):
            raise RunnerError("snapshot file metadata is invalid")
        total += size
        if total > _MAX_CANDIDATE_BYTES:
            raise RunnerError("snapshot candidate content is too large")
        validated_rows.append((path, mode, size, digest))
    contract_record = header["contract"]
    if type(contract_record) is not dict or set(contract_record) != {"size_bytes", "sha256"}:
        raise RunnerError("snapshot contract metadata keys are invalid")
    contract_size = contract_record["size_bytes"]
    contract_digest = contract_record["sha256"]
    if (
        type(contract_size) is not int
        or not 1 <= contract_size <= MAX_CONTRACT_BYTES
        or type(contract_digest) is not str
        or _DIGEST.fullmatch(contract_digest) is None
    ):
        raise RunnerError("snapshot contract metadata is invalid")
    expected_stream_size = len(_MAGIC) + 4 + header_size + total + contract_size
    if expected_stream_size > _MAX_STREAM_BYTES:
        raise RunnerError("snapshot stream exceeds its limit")

    payloads: list[tuple[str, str, bytes]] = []
    for path, mode, size, digest in validated_rows:
        content = _read_exact(input_stream, size)
        if hashlib.sha256(content).hexdigest() != digest:
            raise RunnerError("snapshot file digest does not match")
        payloads.append((path, mode, content))
    contract_raw = _read_exact(input_stream, contract_size)
    if hashlib.sha256(contract_raw).hexdigest() != contract_digest:
        raise RunnerError("snapshot contract digest does not match")
    contract = _validated_contract(contract_raw)
    trailing = input_stream.read(1)
    if not isinstance(trailing, bytes) or trailing:
        raise RunnerError("snapshot stream has trailing bytes")

    created_files: list[Path] = []
    created_directories: list[Path] = []
    try:
        for path, mode, content in payloads:
            destination = root / path
            current = root
            for part in path.split("/")[:-1]:
                current = current / part
                if not current.exists():
                    current.mkdir(mode=0o755)
                    os.chmod(current, 0o755)
                    os.utime(current, ns=(0, 0), follow_symlinks=False)
                    created_directories.append(current)
                else:
                    metadata = current.lstat()
                    if current.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
                        raise RunnerError("snapshot parent is not a directory")
            _write_new_regular(destination, content, int(mode[-3:], 8))
            created_files.append(destination)
        control = root / "run-contract.json"
        _write_new_regular(control, contract_raw, 0o644)
        created_files.append(control)
        staged = _scan_workspace(root)
        expected = {path: (mode, content) for path, mode, content in payloads}
        if staged != expected:
            raise RunnerError("staged candidate bytes drifted")
        reread_contract, _ = _read_regular(control, MAX_CONTRACT_BYTES)
        if reread_contract != contract_raw:
            raise RunnerError("staged contract bytes drifted")
        manifest_digest = _manifest_digest(staged, contract["candidate_commit"])
        if manifest_digest != contract["workspace_manifest_digest"]:
            raise RunnerError("staged workspace manifest does not match contract")
        for directory in sorted({root, *created_directories}, key=lambda item: len(item.parts), reverse=True):
            descriptor = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        summary = _canonical(
            {
                "execution_contract_digest": hashlib.sha256(contract_raw).hexdigest(),
                "execution_id": contract["execution_id"],
                "workspace_manifest_digest": manifest_digest,
            }
        ) + b"\n"
        if len(summary) > _MAX_SUMMARY_BYTES:
            raise RunnerError("staging summary exceeds its limit")
        output_stream.write(summary)
        output_stream.flush()
        return 0
    except BaseException:
        for path in reversed(created_files):
            try:
                path.unlink()
            except OSError:
                pass
        for path in reversed(created_directories):
            try:
                path.rmdir()
            except OSError:
                pass
        raise


def _terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=1.0)
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=9.0)
    except subprocess.TimeoutExpired as error:
        raise RunnerError("verifier process group could not be stopped") from error


def _run_process(argv: tuple[str, ...], cwd: Path) -> ProcessOutcome:
    try:
        process = subprocess.Popen(
            argv,
            cwd=cwd,
            env={
                "HOME": "/nonexistent",
                "LC_ALL": "C.UTF-8",
                "PATH": "/opt/venv/bin:/usr/bin:/bin",
                "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
                "TZ": "UTC",
            },
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            start_new_session=True,
        )
    except OSError as error:
        if error.errno == errno.ENOSPC:
            return ProcessOutcome(None, "DISK_LIMIT", b"", b"")
        raise RunnerError("verifier process could not start") from error
    if process.stdout is None or process.stderr is None:
        _terminate_process_group(process)
        raise RunnerError("verifier process pipes are unavailable")
    selector = selectors.DefaultSelector()
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    captured = 0
    failure: str | None = None
    deadline = time.monotonic() + WALL_CLOCK_TIMEOUT_SECONDS
    try:
        for name, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        while selector.get_map() or process.poll() is None:
            remaining_time = deadline - time.monotonic()
            if remaining_time <= 0:
                failure = "TIMEOUT"
                break
            try:
                events = selector.select(timeout=min(remaining_time, 0.1))
            except InterruptedError:
                continue
            for key, _ in events:
                remaining_bytes = MAX_COMBINED_STDIO_BYTES - captured
                try:
                    data = os.read(key.fd, min(65_536, remaining_bytes + 1))
                except BlockingIOError:
                    continue
                except OSError as error:
                    if error.errno == errno.ENOSPC:
                        failure = "DISK_LIMIT"
                        break
                    raise
                if not data:
                    selector.unregister(key.fileobj)
                    continue
                retained = data[:remaining_bytes]
                buffers[key.data].extend(retained)
                captured += len(retained)
                if len(data) > remaining_bytes:
                    failure = "OUTPUT_LIMIT"
                    break
            if failure is not None:
                break
        if failure is not None:
            _terminate_process_group(process)
        elif process.poll() is None:
            _terminate_process_group(process)
            raise RunnerError("verifier process ended without status")
    except RunnerError:
        raise
    except Exception as error:
        _terminate_process_group(process)
        raise RunnerError("verifier output capture failed") from error
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()
    if failure is not None:
        return ProcessOutcome(None, failure, bytes(buffers["stdout"]), bytes(buffers["stderr"]))
    if type(process.returncode) is not int or not 0 <= process.returncode <= 255:
        raise RunnerError("verifier exit status is not encodable")
    return ProcessOutcome(
        process.returncode,
        None,
        bytes(buffers["stdout"]),
        bytes(buffers["stderr"]),
    )


def _atomic_write(path: Path, content: bytes) -> None:
    if path.exists() or path.is_symlink():
        raise RunnerError(f"output marker already exists: {path.name}")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.tmp-",
        dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o644)
        view = memoryview(content)
        written = 0
        while written < len(view):
            count = os.write(descriptor, view[written:])
            if count <= 0:
                raise RunnerError("atomic output write made no progress")
            written += count
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.link(temporary, path, follow_symlinks=False)
        temporary.unlink()
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except FileExistsError as error:
        raise RunnerError(f"output marker already exists: {path.name}") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary.exists():
            temporary.unlink()


def _execute(
    workspace: Path,
    output: Path,
    process_runner: Callable[[tuple[str, ...], Path], ProcessOutcome],
) -> int:
    workspace = _validated_root(workspace, "workspace")
    output = _validated_root(output, "output")
    if any(os.scandir(output)):
        raise RunnerError("output directory is not empty")
    contract_path = workspace / "run-contract.json"
    contract_raw, contract_metadata = _read_regular(contract_path, MAX_CONTRACT_BYTES)
    if f"{contract_metadata.st_mode:06o}" != "100644":
        raise RunnerError("run contract mode is not normalized")
    contract = _validated_contract(contract_raw)
    files = _scan_workspace(workspace)
    manifest_digest = _manifest_digest(files, contract["candidate_commit"])
    if manifest_digest != contract["workspace_manifest_digest"]:
        raise RunnerError("candidate workspace manifest does not match contract")
    contract_digest = hashlib.sha256(contract_raw).hexdigest()
    started = _canonical(
        {
            "execution_contract_digest": contract_digest,
            "execution_id": contract["execution_id"],
            "schema_version": "openworkproof-run-started/0.1",
        }
    )
    _atomic_write(output / "started.json", started)
    outcome = process_runner(FROZEN_VERIFIER_ARGV, workspace)
    if type(outcome) is not ProcessOutcome:
        raise RunnerError("process runner returned an invalid outcome")
    if type(outcome.stdout) is not bytes or type(outcome.stderr) is not bytes:
        raise RunnerError("process runner returned invalid streams")
    if len(outcome.stdout) + len(outcome.stderr) > MAX_COMBINED_STDIO_BYTES:
        raise RunnerError("process runner exceeded the diagnostic stream limit")
    completed = (
        type(outcome.exit_code) is int
        and 0 <= outcome.exit_code <= 255
        and outcome.failure_code is None
    )
    failed = (
        outcome.exit_code is None
        and outcome.failure_code in {"OUTPUT_LIMIT", "TIMEOUT", "DISK_LIMIT"}
    )
    if not completed and not failed:
        raise RunnerError("process runner returned an open outcome")
    result = _canonical(
        {
            "actual_exit_code": outcome.exit_code,
            "execution_contract_digest": contract_digest,
            "execution_id": contract["execution_id"],
            "failure_code": outcome.failure_code,
            "schema_version": "openworkproof-run-result/0.1",
            "stderr_bytes": len(outcome.stderr),
            "stderr_sha256": hashlib.sha256(outcome.stderr).hexdigest(),
            "stdout_bytes": len(outcome.stdout),
            "stdout_sha256": hashlib.sha256(outcome.stdout).hexdigest(),
        }
    )
    if len(result) > MAX_RESULT_BYTES:
        raise RunnerError("result envelope exceeds its limit")
    _atomic_write(output / "result.json", result)
    if outcome.failure_code is not None:
        return 1
    return outcome.exit_code


def main(
    argv: tuple[str, ...] | None = None,
    *,
    workspace_root: Path = Path("/workspace"),
    output_root: Path = Path("/output"),
    input_stream: BinaryIO | None = None,
    output_stream: BinaryIO | None = None,
    process_runner: Callable[[tuple[str, ...], Path], ProcessOutcome] | None = None,
) -> int:
    arguments = tuple(sys.argv[1:]) if argv is None else argv
    if arguments not in {("stage",), ("execute",)}:
        return 2
    try:
        if arguments == ("stage",):
            return _stage(
                workspace_root,
                sys.stdin.buffer if input_stream is None else input_stream,
                sys.stdout.buffer if output_stream is None else output_stream,
            )
        return _execute(
            workspace_root,
            output_root,
            _run_process if process_runner is None else process_runner,
        )
    except (RunnerError, OSError, ValueError, TypeError) as error:
        print(f"run_tests_runner: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
