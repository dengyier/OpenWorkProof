#!/usr/bin/env python3
"""Stage and execute one frozen verifier snapshot inside the execution image."""

from __future__ import annotations

import base64
import ctypes
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
    "-c",
    "/dev/null",
    "--rootdir=/fixed-tests",
    "--confcutdir=/fixed-tests",
    "/fixed-tests/verifier_test.py",
)
FROZEN_VERIFIER_COMMAND = {
    "argv": list(FROZEN_VERIFIER_ARGV),
    "working_directory": "/workspace",
    "env": {
        "HOME": "/nonexistent",
        "LC_ALL": "C.UTF-8",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
        "TZ": "UTC",
    },
}
FIXED_TEST_ROOT = Path("/fixed-tests")
FIXED_TEST_PATH = FIXED_TEST_ROOT / "verifier_test.py"
MAX_FIXED_TEST_BYTES = 65_536
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
_MAX_MANIFEST_ENTRIES = 512
_MAX_SUMMARY_BYTES = 512
_ALLOWED_MODES = frozenset({"100644", "100755"})
_PATH_PATTERN = re.compile(r"^[A-Za-z0-9._/-]+$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_OID = re.compile(r"^[0-9a-f]{40}$")
_IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_SYS_LANDLOCK_CREATE_RULESET = 444
_SYS_LANDLOCK_ADD_RULE = 445
_SYS_LANDLOCK_RESTRICT_SELF = 446
_LANDLOCK_CREATE_RULESET_VERSION = 1
_LANDLOCK_RULE_PATH_BENEATH = 1
_LANDLOCK_MAX_KNOWN_ABI = 10
_PR_SET_DUMPABLE = 4
_PR_SET_NO_NEW_PRIVS = 38
_LANDLOCK_ACCESS_FS_WRITE_FILE = 1 << 1
_LANDLOCK_ACCESS_FS_REMOVE_DIR = 1 << 4
_LANDLOCK_ACCESS_FS_REMOVE_FILE = 1 << 5
_LANDLOCK_ACCESS_FS_MAKE_CHAR = 1 << 6
_LANDLOCK_ACCESS_FS_MAKE_DIR = 1 << 7
_LANDLOCK_ACCESS_FS_MAKE_REG = 1 << 8
_LANDLOCK_ACCESS_FS_MAKE_SOCK = 1 << 9
_LANDLOCK_ACCESS_FS_MAKE_FIFO = 1 << 10
_LANDLOCK_ACCESS_FS_MAKE_BLOCK = 1 << 11
_LANDLOCK_ACCESS_FS_MAKE_SYM = 1 << 12
_LANDLOCK_ACCESS_FS_REFER = 1 << 13
_LANDLOCK_ACCESS_FS_TRUNCATE = 1 << 14
_LANDLOCK_ACCESS_FS_IOCTL_DEV = 1 << 15
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


class _LandlockRulesetAttr(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64)]


class _LandlockPathBeneathAttr(ctypes.Structure):
    _fields_ = [
        ("allowed_access", ctypes.c_uint64),
        ("parent_fd", ctypes.c_int32),
        ("reserved", ctypes.c_uint32),
    ]


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
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
        RunnerError,
    ) as error:
        raise RunnerError("JSON is not strict canonical ASCII") from error
    try:
        canonical = _canonical(value)
    except (UnicodeEncodeError, TypeError, ValueError, RecursionError) as error:
        raise RunnerError("JSON cannot be canonically encoded") from error
    if canonical != raw:
        raise RunnerError("JSON bytes are not canonical")
    return value


def _frozen_command_digest() -> str:
    return hashlib.sha256(
        _canonical(
            {
                "domain": "openworkproof/test-command/v0.1",
                "command": FROZEN_VERIFIER_COMMAND,
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


def _validated_fixed_test(
    root: Path,
    path: Path,
    expected_digest: str,
) -> bytes:
    if (
        type(root) is not type(Path())
        or type(path) is not type(Path())
        or not root.is_absolute()
        or not path.is_absolute()
        or path.parent != root
        or path.name != "verifier_test.py"
    ):
        raise RunnerError("fixed test path is not canonical")
    root = _validated_root(root, "fixed test")
    root_metadata = root.lstat()
    if stat.S_IMODE(root_metadata.st_mode) & 0o222:
        raise RunnerError("fixed test root is writable")
    production_root = root == Path("/fixed-tests")
    expected_owner_uid = 0 if production_root else root_metadata.st_uid
    if production_root and root_metadata.st_uid != 0:
        raise RunnerError("fixed test root is not root-owned")
    content, metadata = _read_regular(path, MAX_FIXED_TEST_BYTES)
    if (
        metadata.st_uid != expected_owner_uid
        or (production_root and metadata.st_gid != 0)
        or stat.S_IMODE(metadata.st_mode) != 0o444
    ):
        raise RunnerError("fixed test ownership or mode is invalid")
    if hashlib.sha256(content).hexdigest() != expected_digest:
        raise RunnerError("fixed test digest does not match contract")
    try:
        content.decode("utf-8")
    except UnicodeDecodeError as error:
        raise RunnerError("fixed test is not canonical UTF-8") from error
    if (
        not content
        or content.startswith(b"\xef\xbb\xbf")
        or b"\x00" in content
        or b"\r" in content
        or not content.endswith(b"\n")
    ):
        raise RunnerError("fixed test text is not canonical")
    return content


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
        or _PATH_PATTERN.fullmatch(value) is None
        or any(part in {"", ".", ".."} for part in parts)
        or parts[0] == ".git"
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


def _write_new_regular(
    path: Path,
    content: bytes,
    mode: int,
    created_files: list[Path],
) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags | nofollow, mode)
    created_files.append(path)
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


def _file_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


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
        identity_before = _file_identity(before)
        identity_after = _file_identity(after)
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
    if len(files) + len(directories) > _MAX_MANIFEST_ENTRIES:
        raise RunnerError("workspace manifest exceeds 512 entries")
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
                    created_directories.append(current)
                    os.chmod(current, 0o755)
                else:
                    metadata = current.lstat()
                    if current.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
                        raise RunnerError("snapshot parent is not a directory")
            _write_new_regular(
                destination,
                content,
                int(mode[-3:], 8),
                created_files,
            )
        control = root / "run-contract.json"
        _write_new_regular(control, contract_raw, 0o644, created_files)
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
        for path in created_files:
            os.utime(path, ns=(0, 0), follow_symlinks=False)
        for directory in sorted(
            created_directories,
            key=lambda item: len(item.parts),
            reverse=True,
        ):
            os.utime(directory, ns=(0, 0), follow_symlinks=False)
            descriptor = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        descriptor = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
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


def _pid_namespace_members() -> tuple[int, ...]:
    try:
        entries = os.listdir("/proc")
    except OSError as error:
        raise RunnerError("Linux PID namespace cannot be enumerated") from error
    own_pid = os.getpid()
    return tuple(
        sorted(
            int(entry)
            for entry in entries
            if entry.isascii()
            and entry.isdigit()
            and int(entry) > 0
            and int(entry) != own_pid
        )
    )


def _reap_pid1_children() -> None:
    while True:
        try:
            pid, _ = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return
        except OSError as error:
            raise RunnerError("PID 1 could not reap verifier descendants") from error
        if pid == 0:
            return


def _signal_pid_namespace(pids: tuple[int, ...], requested_signal: int) -> None:
    for pid in pids:
        try:
            os.kill(pid, requested_signal)
        except ProcessLookupError:
            continue
        except OSError as error:
            raise RunnerError("verifier descendant could not be signalled") from error


def _close_pid_namespace() -> None:
    term_deadline = time.monotonic() + 1.0
    kill_deadline = term_deadline + 9.0
    stable_zero_scans = 0
    while time.monotonic() < kill_deadline:
        _reap_pid1_children()
        pids = _pid_namespace_members()
        if not pids:
            stable_zero_scans += 1
            if stable_zero_scans == 3:
                return
        else:
            stable_zero_scans = 0
            requested_signal = (
                signal.SIGTERM
                if time.monotonic() < term_deadline
                else signal.SIGKILL
            )
            _signal_pid_namespace(pids, requested_signal)
        time.sleep(0.01)
    raise RunnerError("verifier descendants did not reach stable zero")


def _production_descendant_cleaner() -> Callable[[], None]:
    if not sys.platform.startswith("linux"):
        raise RunnerError("verifier descendant supervision requires Linux")
    if os.getpid() != 1:
        raise RunnerError("verifier runner must be PID 1")
    if _pid_namespace_members():
        raise RunnerError("verifier PID namespace is not initially empty")
    return _close_pid_namespace


def _linux_syscall(number: int, *args: object) -> int:
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    return int(libc.syscall(ctypes.c_long(number), *args))


def _linux_prctl(option: int, argument: int, *remaining: int) -> int:
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.restype = ctypes.c_int
    return int(libc.prctl(option, argument, *remaining))


def _query_landlock_abi(
    syscall: Callable[..., int] = _linux_syscall,
) -> int:
    if not sys.platform.startswith("linux"):
        raise RunnerError("verifier output authority requires Linux Landlock")
    abi = syscall(
        _SYS_LANDLOCK_CREATE_RULESET,
        None,
        0,
        _LANDLOCK_CREATE_RULESET_VERSION,
    )
    if not 3 <= abi <= _LANDLOCK_MAX_KNOWN_ABI:
        raise RunnerError("verifier output authority has an unsupported Landlock ABI")
    return abi


def _landlock_write_access(abi: int) -> int:
    if not 3 <= abi <= _LANDLOCK_MAX_KNOWN_ABI:
        raise RunnerError("verifier output authority has an unsupported Landlock ABI")
    access = (
        _LANDLOCK_ACCESS_FS_WRITE_FILE
        | _LANDLOCK_ACCESS_FS_REMOVE_DIR
        | _LANDLOCK_ACCESS_FS_REMOVE_FILE
        | _LANDLOCK_ACCESS_FS_MAKE_CHAR
        | _LANDLOCK_ACCESS_FS_MAKE_DIR
        | _LANDLOCK_ACCESS_FS_MAKE_REG
        | _LANDLOCK_ACCESS_FS_MAKE_SOCK
        | _LANDLOCK_ACCESS_FS_MAKE_FIFO
        | _LANDLOCK_ACCESS_FS_MAKE_BLOCK
        | _LANDLOCK_ACCESS_FS_MAKE_SYM
        | _LANDLOCK_ACCESS_FS_REFER
        | _LANDLOCK_ACCESS_FS_TRUNCATE
    )
    if abi >= 5:
        access |= _LANDLOCK_ACCESS_FS_IOCTL_DEV
    return access


def _landlock_dev_null_access(abi: int) -> int:
    _landlock_write_access(abi)
    access = _LANDLOCK_ACCESS_FS_WRITE_FILE
    if abi >= 5:
        access |= _LANDLOCK_ACCESS_FS_IOCTL_DEV
    return access


def _validate_dev_null(
    path: Path,
    statter: Callable[[Path], os.stat_result],
) -> None:
    if path != Path("/dev/null"):
        raise RunnerError("Landlock /dev/null rule path is not exact")
    metadata = statter(path)
    if (
        not stat.S_ISCHR(metadata.st_mode)
        or os.major(metadata.st_rdev) != 1
        or os.minor(metadata.st_rdev) != 3
    ):
        raise RunnerError("Landlock /dev/null is not the expected character device")


def _build_landlock_preexec(
    abi: int,
    writable_root: Path,
    *,
    device_null: Path = Path("/dev/null"),
    syscall: Callable[..., int] = _linux_syscall,
    prctl: Callable[..., int] = _linux_prctl,
    opener: Callable[..., int] = os.open,
    closer: Callable[[int], None] = os.close,
    statter: Callable[[Path], os.stat_result] = os.lstat,
) -> Callable[[], None]:
    access = _landlock_write_access(abi)
    dev_null_access = _landlock_dev_null_access(abi)
    writable_root = writable_root.absolute()
    metadata = writable_root.lstat()
    if writable_root.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
        raise RunnerError("Landlock writable root is not a regular directory")
    _validate_dev_null(device_null, statter)

    def restrict_child() -> None:
        if prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
            raise RunnerError("Landlock no_new_privs failed")
        ruleset = _LandlockRulesetAttr(handled_access_fs=access)
        ruleset_fd = syscall(
            _SYS_LANDLOCK_CREATE_RULESET,
            ctypes.byref(ruleset),
            ctypes.sizeof(ruleset),
            0,
        )
        if ruleset_fd < 0:
            raise RunnerError("Landlock ruleset creation failed")
        try:
            for path, allowed_access, directory_flags in (
                (writable_root, access, getattr(os, "O_DIRECTORY", 0)),
                (device_null, dev_null_access, getattr(os, "O_NOFOLLOW", 0)),
            ):
                path_fd = opener(
                    path,
                    getattr(os, "O_PATH", 0) | os.O_CLOEXEC | directory_flags,
                )
                try:
                    path_rule = _LandlockPathBeneathAttr(
                        allowed_access=allowed_access,
                        parent_fd=path_fd,
                        reserved=0,
                    )
                    if syscall(
                        _SYS_LANDLOCK_ADD_RULE,
                        ruleset_fd,
                        _LANDLOCK_RULE_PATH_BENEATH,
                        ctypes.byref(path_rule),
                        0,
                    ) != 0:
                        raise RunnerError("Landlock path rule failed")
                finally:
                    closer(path_fd)
            if syscall(_SYS_LANDLOCK_RESTRICT_SELF, ruleset_fd, 0) != 0:
                raise RunnerError("Landlock restrict_self failed")
        finally:
            closer(ruleset_fd)

    return restrict_child


def _production_child_preexec(
    writable_root: Path = Path("/tmp"),
    *,
    device_null: Path = Path("/dev/null"),
    syscall: Callable[..., int] = _linux_syscall,
    prctl: Callable[..., int] = _linux_prctl,
    opener: Callable[..., int] = os.open,
    closer: Callable[[int], None] = os.close,
    statter: Callable[[Path], os.stat_result] = os.lstat,
) -> Callable[[], None]:
    abi = _query_landlock_abi(syscall)
    if prctl(_PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
        raise RunnerError("verifier PID 1 could not disable dumpability")
    return _build_landlock_preexec(
        abi,
        writable_root,
        device_null=device_null,
        syscall=syscall,
        prctl=prctl,
        opener=opener,
        closer=closer,
        statter=statter,
    )


def _run_process(
    argv: tuple[str, ...],
    cwd: Path,
    *,
    descendant_cleaner: Callable[[], None] | None = None,
    child_preexec: Callable[[], None] | None = None,
) -> ProcessOutcome:
    cleaner = (
        _production_descendant_cleaner()
        if descendant_cleaner is None
        else descendant_cleaner
    )
    preexec = (
        _production_child_preexec()
        if child_preexec is None
        else child_preexec
    )
    try:
        process = subprocess.Popen(
            argv,
            cwd=cwd,
            env={
                "HOME": "/nonexistent",
                "LC_ALL": "C.UTF-8",
                "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
                "TZ": "UTC",
            },
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            start_new_session=True,
            preexec_fn=preexec,
        )
    except (OSError, subprocess.SubprocessError) as error:
        if isinstance(error, OSError) and error.errno == errno.ENOSPC:
            cleaner()
            return ProcessOutcome(None, "DISK_LIMIT", b"", b"")
        cleaner()
        raise RunnerError("verifier process could not start") from error
    if process.stdout is None or process.stderr is None:
        _terminate_process_group(process)
        cleaner()
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
        cleaner()
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


def _validated_marker_identity(
    path: Path,
    expected: bytes,
    prior_identity: tuple[int, ...] | None = None,
) -> tuple[int, ...]:
    content, metadata = _read_regular(path, MAX_RESULT_BYTES)
    identity = _file_identity(metadata)
    if (
        content != expected
        or f"{metadata.st_mode:06o}" != "100644"
        or metadata.st_uid != os.geteuid()
        or metadata.st_gid != os.getegid()
        or (prior_identity is not None and identity != prior_identity)
    ):
        raise RunnerError(f"output marker changed: {path.name}")
    return identity


def _execute(
    workspace: Path,
    output: Path,
    process_runner: Callable[[tuple[str, ...], Path], ProcessOutcome],
    *,
    fixed_test_root: Path | None = None,
    fixed_test_path: Path | None = None,
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
    _validated_fixed_test(
        FIXED_TEST_ROOT if fixed_test_root is None else fixed_test_root,
        FIXED_TEST_PATH if fixed_test_path is None else fixed_test_path,
        contract["fixed_test_source_digest"],
    )
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
    started_path = output / "started.json"
    _atomic_write(started_path, started)
    started_identity = _validated_marker_identity(started_path, started)
    outcome = process_runner(FROZEN_VERIFIER_ARGV, workspace)
    _validated_marker_identity(started_path, started, started_identity)
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
    fixed_test_root: Path | None = None,
    fixed_test_path: Path | None = None,
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
            fixed_test_root=fixed_test_root,
            fixed_test_path=fixed_test_path,
        )
    except (RunnerError, OSError, ValueError, TypeError) as error:
        print(f"run_tests_runner: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
