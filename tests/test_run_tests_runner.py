"""Contracts for the standalone verifier execution-image runner."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

import pytest

from openworkproof import repo_tools


ROOT = Path(__file__).resolve().parents[1]
RUNNER_PATH = (
    ROOT / "supply-chain" / "images" / "execution" / "run_tests_runner.py"
)


def _load_runner():
    spec = importlib.util.spec_from_file_location(
        "openworkproof_standalone_run_tests_runner",
        RUNNER_PATH,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


runner = _load_runner()


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")


def _command_digest() -> str:
    return hashlib.sha256(
        _canonical(
            {
                "domain": "openworkproof/verifier-command/v0.1",
                "argv": list(runner.FROZEN_VERIFIER_ARGV),
            }
        )
    ).hexdigest()


def _manifest_digest(files: dict[str, tuple[str, bytes]], head: str) -> str:
    directories = {
        "/".join(path.split("/")[:index])
        for path in files
        for index in range(1, len(path.split("/")))
    }
    entries = [
        {
            "path_bytes_b64url": __import__("base64")
            .urlsafe_b64encode(path.encode("ascii"))
            .rstrip(b"=")
            .decode("ascii"),
            "type": "directory",
            "posix_mode": "040755",
            "size_bytes": None,
            "sha256": None,
            "symlink_target_b64url": None,
        }
        for path in directories
    ]
    entries.extend(
        {
            "path_bytes_b64url": __import__("base64")
            .urlsafe_b64encode(path.encode("ascii"))
            .rstrip(b"=")
            .decode("ascii"),
            "type": "regular",
            "posix_mode": mode,
            "size_bytes": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
            "symlink_target_b64url": None,
        }
        for path, (mode, content) in files.items()
    )
    entries.sort(
        key=lambda item: __import__("base64").urlsafe_b64decode(
            item["path_bytes_b64url"] + "=="
        )
    )
    manifest = {
        "schema_version": "openworkproof-workspace-manifest/0.1",
        "head_commit": head,
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


def _contract(files: dict[str, tuple[str, bytes]]) -> dict[str, object]:
    candidate_commit = "2" * 40
    return {
        "arguments_digest": "3" * 64,
        "candidate_commit": candidate_commit,
        "candidate_workspace_id": "4" * 64,
        "command_digest": _command_digest(),
        "container_image_digest": "sha256:" + "5" * 64,
        "execution_id": "6" * 64,
        "fixed_test_source_digest": "7" * 64,
        "request_digest": "8" * 64,
        "schema_version": "openworkproof-run-contract/0.1",
        "source_artifact_sha256": "9" * 64,
        "source_commit": "1" * 40,
        "test_mode": "verifier",
        "tool_name": "owp.run_tests",
        "workspace_manifest_digest": _manifest_digest(files, candidate_commit),
    }


def _nested_files(depth: int, branches: str) -> dict[str, tuple[str, bytes]]:
    return {
        "/".join([branch] * depth + ["f"]): ("100644", branch.encode("ascii"))
        for branch in branches
    }


def _write_workspace(
    tmp_path: Path,
) -> tuple[Path, Path, dict[str, tuple[str, bytes]], dict[str, object]]:
    workspace = tmp_path / "workspace"
    output = tmp_path / "output"
    workspace.mkdir()
    output.mkdir()
    files = {
        "README.md": ("100644", b"candidate\n"),
        "src/test_sample.py": ("100755", b"def test_ok():\n    assert True\n"),
    }
    for path, (mode, content) in files.items():
        destination = workspace / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content)
        destination.chmod(int(mode[-3:], 8))
    contract = _contract(files)
    (workspace / "run-contract.json").write_bytes(_canonical(contract))
    return workspace, output, files, contract


def _stream(
    files: dict[str, tuple[str, bytes]],
    contract: dict[str, object],
    *,
    header_mutator=None,
    trailing: bytes = b"",
) -> bytes:
    rows = [
        {
            "path": path,
            "mode": mode,
            "size_bytes": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
        }
        for path, (mode, content) in sorted(files.items())
    ]
    contract_bytes = _canonical(contract)
    header = {
        "schema_version": "openworkproof-snapshot-stream/0.1",
        "files": rows,
        "contract": {
            "size_bytes": len(contract_bytes),
            "sha256": hashlib.sha256(contract_bytes).hexdigest(),
        },
    }
    if header_mutator is not None:
        header_mutator(header)
    header_bytes = _canonical(header)
    payload = b"".join(content for _, content in files.values()) + contract_bytes
    return (
        b"openworkproof-snapshot-stream/0.1\n"
        + len(header_bytes).to_bytes(4, "big")
        + header_bytes
        + payload
        + trailing
    )


def test_runner_constants_and_import_surface_are_frozen() -> None:
    assert runner.FROZEN_VERIFIER_ARGV == (
        "/opt/venv/bin/python",
        "-I",
        "-m",
        "pytest",
        "-q",
    )
    assert runner.MAX_CONTRACT_BYTES == 8192
    assert runner.MAX_RESULT_BYTES == 8192
    assert runner.MAX_COMBINED_STDIO_BYTES == 1048576
    assert runner.WALL_CLOCK_TIMEOUT_SECONDS == 120
    source = RUNNER_PATH.read_text(encoding="utf-8")
    assert "openworkproof" not in "\n".join(
        line for line in source.splitlines() if line.lstrip().startswith(("import ", "from "))
    ).casefold()
    assert ".communicate(" not in source
    assert "shell=True" not in source


def test_stage_writes_snapshot_and_exact_canonical_summary(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    files = {
        "README.md": ("100644", b"candidate\n"),
        "src/test_sample.py": ("100755", b"def test_ok():\n    assert True\n"),
    }
    contract = _contract(files)
    stdout = io.BytesIO()

    result = runner.main(
        ("stage",),
        workspace_root=workspace,
        input_stream=io.BytesIO(_stream(files, contract)),
        output_stream=stdout,
    )

    assert result == 0
    normalized_paths = (
        workspace,
        workspace / "README.md",
        workspace / "src",
        workspace / "src/test_sample.py",
        workspace / "run-contract.json",
    )
    for path in normalized_paths:
        metadata = path.lstat()
        assert metadata.st_atime_ns == 0
        assert metadata.st_mtime_ns == 0
    assert (workspace / "README.md").read_bytes() == files["README.md"][1]
    assert (workspace / "src/test_sample.py").read_bytes() == files["src/test_sample.py"][1]
    assert (workspace / "run-contract.json").read_bytes() == _canonical(contract)
    assert stdout.getvalue() == _canonical(
        {
            "execution_id": contract["execution_id"],
            "execution_contract_digest": hashlib.sha256(
                _canonical(contract)
            ).hexdigest(),
            "workspace_manifest_digest": contract["workspace_manifest_digest"],
        }
    ) + b"\n"


def test_manifest_entry_limit_accepts_512_and_rejects_513() -> None:
    boundary = _nested_files(255, "ab")
    assert len(boundary) + 510 == 512

    assert len(runner._manifest_digest(boundary, "2" * 40)) == 64

    above = {**boundary, "root-file": ("100644", b"c")}
    assert len(above) + 510 == 513
    with pytest.raises(runner.RunnerError, match="512"):
        runner._manifest_digest(above, "2" * 40)


@pytest.mark.parametrize("mode", ["stage", "execute"])
def test_runner_rejects_528_entry_manifest_before_success_or_marker(
    tmp_path: Path, mode: str
) -> None:
    files = _nested_files(175, "abc")
    assert len(files) + 525 == 528
    contract = _contract(files)
    workspace = tmp_path / "workspace"
    output = tmp_path / "output"
    workspace.mkdir()
    output.mkdir()
    stdout = io.BytesIO()
    if mode == "stage":
        result = runner.main(
            ("stage",),
            workspace_root=workspace,
            input_stream=io.BytesIO(_stream(files, contract)),
            output_stream=stdout,
        )
        assert not list(workspace.iterdir())
    else:
        for path, (file_mode, content) in files.items():
            destination = workspace / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(content)
            destination.chmod(int(file_mode[-3:], 8))
        (workspace / "run-contract.json").write_bytes(_canonical(contract))
        result = runner.main(
            ("execute",),
            workspace_root=workspace,
            output_root=output,
            process_runner=lambda argv, cwd: runner.ProcessOutcome(
                exit_code=0,
                failure_code=None,
                stdout=b"",
                stderr=b"",
            ),
        )

    assert result != 0
    assert stdout.getvalue() == b""
    assert not list(output.iterdir())


@pytest.mark.parametrize(
    "path",
    (
        "a",
        "a" * 512,
        "src/main.py",
        ".gitignore",
        ".Git/config",
        "src/.git/config",
    ),
)
def test_runner_path_acceptance_matches_authoritative_validator(path: str) -> None:
    assert repo_tools.validate_canonical_relative_path(path) == path
    assert runner._validated_path(path) == path


@pytest.mark.parametrize(
    "path",
    (
        "",
        "a" * 513,
        "/absolute",
        "trailing/",
        "empty//segment",
        ".",
        "..",
        "a/./b",
        "a/../b",
        "a\\b",
        "has space",
        "line\nbreak",
        "control\x01byte",
        "glob*",
        "question?",
        "class[ab]",
        ".git",
        ".git/config",
    ),
)
def test_runner_path_rejection_matches_authoritative_validator(path: str) -> None:
    with pytest.raises(repo_tools.PathError):
        repo_tools.validate_canonical_relative_path(path)
    with pytest.raises(runner.RunnerError):
        runner._validated_path(path)


def test_runner_manifest_digest_matches_authoritative_repo_tools() -> None:
    files = {
        ".Git/config": ("100644", b"case-sensitive\n"),
        "README.md": ("100644", b"readme\n"),
        "src/app.py": ("100755", b"app\n"),
    }
    directories = {
        "/".join(path.split("/")[:index])
        for path in files
        for index in range(1, len(path.split("/")))
    }
    records = [
        repo_tools.WorkspaceScanRecord(
            path.encode("ascii"),
            "directory",
            0o040755,
            None,
            None,
            None,
            1,
            "stable",
            "stable",
        )
        for path in directories
    ]
    records.extend(
        repo_tools.WorkspaceScanRecord(
            path.encode("ascii"),
            "regular",
            int(mode, 8),
            len(content),
            content,
            None,
            1,
            "stable",
            "stable",
        )
        for path, (mode, content) in files.items()
    )
    authoritative = repo_tools.workspace_manifest_digest(
        repo_tools.build_workspace_manifest("2" * 40, records)
    )

    assert runner._manifest_digest(files, "2" * 40) == authoritative


@pytest.mark.parametrize(
    "failure_point",
    ("partial_enospc", "fsync", "file_utime", "mkdir_followup"),
)
def test_stage_failure_cleans_every_new_file_and_directory_immediately(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_point: str,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    files = {"nested/candidate.py": ("100644", b"candidate bytes")}
    contract = _contract(files)
    if failure_point == "partial_enospc":
        real_write = runner.os.write
        calls = 0

        def partial_then_enospc(descriptor: int, content) -> int:
            nonlocal calls
            calls += 1
            if calls == 1:
                return real_write(descriptor, content[:1])
            raise OSError(28, os.strerror(28))

        monkeypatch.setattr(runner.os, "write", partial_then_enospc)
    elif failure_point == "fsync":
        monkeypatch.setattr(
            runner.os,
            "fsync",
            lambda descriptor: (_ for _ in ()).throw(OSError("fsync failed")),
        )
    elif failure_point == "file_utime":
        monkeypatch.setattr(
            runner.os,
            "utime",
            lambda *args, **kwargs: (_ for _ in ()).throw(OSError("utime failed")),
        )
    else:
        monkeypatch.setattr(
            runner.os,
            "chmod",
            lambda *args, **kwargs: (_ for _ in ()).throw(OSError("chmod failed")),
        )

    result = runner.main(
        ("stage",),
        workspace_root=workspace,
        input_stream=io.BytesIO(_stream(files, contract)),
        output_stream=io.BytesIO(),
    )

    assert result != 0
    assert not list(workspace.iterdir())


def _no_descendant_cleanup() -> None:
    return None


@pytest.mark.parametrize("escape", ["setsid", "double_fork"])
def test_detached_survivor_is_closed_before_exact_result_publication(
    tmp_path: Path, escape: str
) -> None:
    workspace, output, _, contract = _write_workspace(tmp_path)
    pidfile = tmp_path / "survivor.pid"
    forged = output / "result.json"
    payload = (
        "import os,time\n"
        "from pathlib import Path\n"
        f"Path({str(pidfile)!r}).write_text(str(os.getpid()))\n"
        "time.sleep(0.2)\n"
        f"Path({str(forged)!r}).write_text('forged')\n"
        "time.sleep(30)\n"
    )
    if escape == "setsid":
        descendant = payload
    else:
        descendant = (
            "import os\n"
            "if os.fork(): os._exit(0)\n"
            "os.setsid()\n"
            "if os.fork(): os._exit(0)\n"
            + payload
        )
    parent = (
        "import subprocess,sys\n"
        f"subprocess.Popen([sys.executable,'-c',{descendant!r}], "
        "stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, "
        "stderr=subprocess.DEVNULL, start_new_session=True)\n"
    )
    survivor_pid: int | None = None

    def cleanup_survivor() -> None:
        nonlocal survivor_pid
        for _ in range(100):
            if pidfile.exists():
                break
            time.sleep(0.01)
        survivor_pid = int(pidfile.read_text())
        os.kill(survivor_pid, signal.SIGKILL)

    def supervised_process(argv, cwd):
        return runner._run_process(
            (sys.executable, "-c", parent),
            cwd,
            descendant_cleaner=cleanup_survivor,
        )

    try:
        result = runner.main(
            ("execute",),
            workspace_root=workspace,
            output_root=output,
            process_runner=supervised_process,
        )
        exact = (output / "result.json").read_bytes()
        time.sleep(0.4)

        assert result == 0
        assert (output / "result.json").read_bytes() == exact
        assert json.loads(exact)["execution_id"] == contract["execution_id"]
        assert exact != b"forged"
    finally:
        if survivor_pid is not None:
            try:
                os.kill(survivor_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


@pytest.mark.parametrize("tamper", ["bytes", "same_bytes_new_inode"])
def test_started_marker_tamper_after_child_cleanup_prevents_result(
    tmp_path: Path, tamper: str
) -> None:
    workspace, output, _, _ = _write_workspace(tmp_path)

    def tampering_process(argv, cwd):
        started = output / "started.json"
        original = started.read_bytes()
        if tamper == "bytes":
            started.write_bytes(b"tampered")
        else:
            replacement = output / "replacement"
            replacement.write_bytes(original)
            os.replace(replacement, started)
        return runner.ProcessOutcome(0, None, b"", b"")

    result = runner.main(
        ("execute",),
        workspace_root=workspace,
        output_root=output,
        process_runner=tampering_process,
    )

    assert result != 0
    assert not (output / "result.json").exists()


def test_production_descendant_supervision_requires_linux_pid1(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(runner.sys, "platform", "darwin")
    with pytest.raises(runner.RunnerError, match="Linux"):
        runner._production_descendant_cleaner()

    monkeypatch.setattr(runner.sys, "platform", "linux")
    monkeypatch.setattr(runner.os, "getpid", lambda: 2)
    with pytest.raises(runner.RunnerError, match="PID 1"):
        runner._production_descendant_cleaner()


def test_production_descendant_supervision_requires_readable_empty_proc(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(runner.sys, "platform", "linux")
    monkeypatch.setattr(runner.os, "getpid", lambda: 1)
    monkeypatch.setattr(
        runner.os,
        "listdir",
        lambda path: (_ for _ in ()).throw(OSError("proc unavailable")),
    )
    with pytest.raises(runner.RunnerError, match="cannot be enumerated"):
        runner._production_descendant_cleaner()

    monkeypatch.setattr(runner, "_pid_namespace_members", lambda: (2,))
    with pytest.raises(runner.RunnerError, match="not initially empty"):
        runner._production_descendant_cleaner()


def test_pid_namespace_cleanup_uses_term_kill_and_stable_zero(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observations = iter(((41, 42), (42,), (42,), (), (), ()))
    signals: list[tuple[tuple[int, ...], int]] = []
    clock = 0.0

    def monotonic() -> float:
        return clock

    def advance(seconds: float) -> None:
        nonlocal clock
        clock += 0.6

    monkeypatch.setattr(runner, "_reap_pid1_children", lambda: None)
    monkeypatch.setattr(runner, "_pid_namespace_members", lambda: next(observations))
    monkeypatch.setattr(
        runner,
        "_signal_pid_namespace",
        lambda pids, requested_signal: signals.append((pids, requested_signal)),
    )
    monkeypatch.setattr(runner.time, "monotonic", monotonic)
    monkeypatch.setattr(runner.time, "sleep", advance)

    runner._close_pid_namespace()

    assert signals == [
        ((41, 42), signal.SIGTERM),
        ((42,), signal.SIGTERM),
        ((42,), signal.SIGKILL),
    ]


def test_pid_namespace_cleanup_fails_when_descendant_never_resolves(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    signals: list[int] = []
    clock = 0.0

    def advance(seconds: float) -> None:
        nonlocal clock
        clock += 5.5

    monkeypatch.setattr(runner, "_reap_pid1_children", lambda: None)
    monkeypatch.setattr(runner, "_pid_namespace_members", lambda: (42,))
    monkeypatch.setattr(
        runner,
        "_signal_pid_namespace",
        lambda pids, requested_signal: signals.append(requested_signal),
    )
    monkeypatch.setattr(runner.time, "monotonic", lambda: clock)
    monkeypatch.setattr(runner.time, "sleep", advance)

    with pytest.raises(runner.RunnerError, match="stable zero"):
        runner._close_pid_namespace()

    assert signals == [signal.SIGTERM, signal.SIGKILL]


def test_pid_namespace_enumeration_excludes_only_pid1(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        runner.os,
        "listdir",
        lambda path: ["self", "1", "12", "3", "not-a-pid"],
    )
    monkeypatch.setattr(runner.os, "getpid", lambda: 1)

    assert runner._pid_namespace_members() == (3, 12)


def test_descendant_supervision_failure_is_fail_closed_without_result(
    tmp_path: Path,
) -> None:
    workspace, output, _, _ = _write_workspace(tmp_path)

    def fail_cleanup() -> None:
        raise runner.RunnerError("descendant supervision unavailable")

    def process(argv, cwd):
        return runner._run_process(
            (sys.executable, "-c", "pass"),
            cwd,
            descendant_cleaner=fail_cleanup,
        )

    result = runner.main(
        ("execute",),
        workspace_root=workspace,
        output_root=output,
        process_runner=process,
    )

    assert result != 0
    assert (output / "started.json").is_file()
    assert not (output / "result.json").exists()


@pytest.mark.parametrize("mode", ["stage", "execute"])
def test_deep_json_is_a_controlled_nonzero_failure(
    tmp_path: Path, mode: str
) -> None:
    workspace = tmp_path / "workspace"
    output = tmp_path / "output"
    workspace.mkdir()
    output.mkdir()
    depth = 16_000 if mode == "stage" else 4_000
    deep = b"[" * depth + b"0" + b"]" * depth
    if mode == "stage":
        stream = (
            b"openworkproof-snapshot-stream/0.1\n"
            + len(deep).to_bytes(4, "big")
            + deep
        )
        result = runner.main(
            ("stage",),
            workspace_root=workspace,
            input_stream=io.BytesIO(stream),
            output_stream=io.BytesIO(),
        )
    else:
        (workspace / "candidate").write_bytes(b"x")
        (workspace / "run-contract.json").write_bytes(deep)
        result = runner.main(
            ("execute",),
            workspace_root=workspace,
            output_root=output,
        )

    assert result != 0
    assert not list(output.iterdir())


def test_json_recursionerror_is_a_controlled_runner_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace, output, _, _ = _write_workspace(tmp_path)
    monkeypatch.setattr(
        runner.json,
        "loads",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            RecursionError("injected JSON recursion")
        ),
    )

    result = runner.main(
        ("execute",),
        workspace_root=workspace,
        output_root=output,
    )

    assert result != 0
    assert not list(output.iterdir())


@pytest.mark.parametrize("bad_argv", [(), ("unknown",), ("execute", "extra")])
def test_runner_rejects_all_nonfixed_argv(bad_argv: tuple[str, ...], tmp_path: Path) -> None:
    assert runner.main(bad_argv, workspace_root=tmp_path, output_root=tmp_path) != 0


def test_execute_writes_exact_started_and_completed_result(tmp_path: Path) -> None:
    workspace, output, _, contract = _write_workspace(tmp_path)

    result = runner.main(
        ("execute",),
        workspace_root=workspace,
        output_root=output,
        process_runner=lambda argv, cwd: runner.ProcessOutcome(
            exit_code=0,
            failure_code=None,
            stdout=b"ok",
            stderr=b"warning",
        ),
    )

    assert result == 0
    contract_digest = hashlib.sha256(_canonical(contract)).hexdigest()
    assert (output / "started.json").read_bytes() == _canonical(
        {
            "execution_contract_digest": contract_digest,
            "execution_id": contract["execution_id"],
            "schema_version": "openworkproof-run-started/0.1",
        }
    )
    assert (output / "result.json").read_bytes() == _canonical(
        {
            "actual_exit_code": 0,
            "execution_contract_digest": contract_digest,
            "execution_id": contract["execution_id"],
            "failure_code": None,
            "schema_version": "openworkproof-run-result/0.1",
            "stderr_bytes": 7,
            "stderr_sha256": hashlib.sha256(b"warning").hexdigest(),
            "stdout_bytes": 2,
            "stdout_sha256": hashlib.sha256(b"ok").hexdigest(),
        }
    )


@pytest.mark.parametrize("failure_code", ["OUTPUT_LIMIT", "TIMEOUT", "DISK_LIMIT"])
def test_execute_writes_exact_closed_infrastructure_failure(
    tmp_path: Path, failure_code: str
) -> None:
    workspace, output, _, contract = _write_workspace(tmp_path)

    result = runner.main(
        ("execute",),
        workspace_root=workspace,
        output_root=output,
        process_runner=lambda argv, cwd: runner.ProcessOutcome(
            exit_code=None,
            failure_code=failure_code,
            stdout=b"partial",
            stderr=b"diagnostic",
        ),
    )

    assert result != 0
    envelope = json.loads((output / "result.json").read_bytes())
    assert envelope["actual_exit_code"] is None
    assert envelope["failure_code"] == failure_code
    assert envelope["execution_id"] == contract["execution_id"]


def test_execute_rejects_duplicate_contract_keys(tmp_path: Path) -> None:
    workspace, output, _, contract = _write_workspace(tmp_path)
    raw = _canonical(contract).replace(b"{", b'{"execution_id":"shadow",', 1)
    (workspace / "run-contract.json").write_bytes(raw)

    assert runner.main(("execute",), workspace_root=workspace, output_root=output) != 0
    assert not list(output.iterdir())


def test_execute_rejects_noncanonical_contract(tmp_path: Path) -> None:
    workspace, output, _, contract = _write_workspace(tmp_path)
    (workspace / "run-contract.json").write_bytes(
        json.dumps(contract, sort_keys=False, indent=2).encode("ascii")
    )

    assert runner.main(("execute",), workspace_root=workspace, output_root=output) != 0
    assert not list(output.iterdir())


def test_execute_rejects_wrong_frozen_command_digest(tmp_path: Path) -> None:
    workspace, output, _, contract = _write_workspace(tmp_path)
    contract["command_digest"] = "f" * 64
    (workspace / "run-contract.json").write_bytes(_canonical(contract))

    assert runner.main(("execute",), workspace_root=workspace, output_root=output) != 0
    assert not list(output.iterdir())


def test_execute_rejects_candidate_file_drift_before_started(tmp_path: Path) -> None:
    workspace, output, _, _ = _write_workspace(tmp_path)
    (workspace / "README.md").write_bytes(b"drift\n")

    assert runner.main(("execute",), workspace_root=workspace, output_root=output) != 0
    assert not list(output.iterdir())


def test_execute_rejects_symlink_before_started(tmp_path: Path) -> None:
    workspace, output, _, _ = _write_workspace(tmp_path)
    (workspace / "linked").symlink_to("README.md")

    assert runner.main(("execute",), workspace_root=workspace, output_root=output) != 0
    assert not list(output.iterdir())


@pytest.mark.parametrize("marker", ["started.json", "result.json"])
def test_execute_rejects_preexisting_output_marker(
    tmp_path: Path, marker: str
) -> None:
    workspace, output, _, _ = _write_workspace(tmp_path)
    (output / marker).write_bytes(b"preexisting")

    assert runner.main(("execute",), workspace_root=workspace, output_root=output) != 0
    assert sorted(path.name for path in output.iterdir()) == [marker]


def test_atomic_started_write_failure_creates_no_marker_or_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace, output, _, _ = _write_workspace(tmp_path)

    def fail_link(*args, **kwargs):
        raise OSError("injected atomic publication failure")

    monkeypatch.setattr(runner.os, "link", fail_link)

    assert runner.main(("execute",), workspace_root=workspace, output_root=output) != 0
    assert not list(output.iterdir())


def test_atomic_started_write_race_never_deletes_the_winning_marker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace, output, _, _ = _write_workspace(tmp_path)

    def lose_publication_race(source, target, **kwargs):
        Path(target).write_bytes(b"winning marker")
        raise FileExistsError("injected no-replace race")

    monkeypatch.setattr(runner.os, "link", lose_publication_race)

    assert runner.main(("execute",), workspace_root=workspace, output_root=output) != 0
    assert (output / "started.json").read_bytes() == b"winning marker"
    assert not (output / "result.json").exists()


@pytest.mark.parametrize("bad_path", ["../escape", "run-contract.json", "a/../b"])
def test_stage_rejects_reserved_or_traversing_path(
    tmp_path: Path, bad_path: str
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    files = {"safe": ("100644", b"x")}
    contract = _contract(files)

    def mutate(header: dict[str, object]) -> None:
        header["files"][0]["path"] = bad_path

    result = runner.main(
        ("stage",),
        workspace_root=workspace,
        input_stream=io.BytesIO(_stream(files, contract, header_mutator=mutate)),
        output_stream=io.BytesIO(),
    )

    assert result != 0
    assert not list(workspace.iterdir())


def test_stage_rejects_duplicate_file_paths(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    files = {"safe": ("100644", b"x")}
    contract = _contract(files)

    def mutate(header: dict[str, object]) -> None:
        header["files"].append(dict(header["files"][0]))

    result = runner.main(
        ("stage",),
        workspace_root=workspace,
        input_stream=io.BytesIO(_stream(files, contract, header_mutator=mutate)),
        output_stream=io.BytesIO(),
    )

    assert result != 0
    assert not list(workspace.iterdir())


def test_stage_rejects_trailing_stream_bytes(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    files = {"safe": ("100644", b"x")}
    contract = _contract(files)

    result = runner.main(
        ("stage",),
        workspace_root=workspace,
        input_stream=io.BytesIO(_stream(files, contract, trailing=b"x")),
        output_stream=io.BytesIO(),
    )

    assert result != 0
    assert not list(workspace.iterdir())


def test_stage_rejects_preexisting_symlink(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    outside = tmp_path / "outside"
    workspace.mkdir()
    outside.mkdir()
    (workspace / "src").symlink_to(outside, target_is_directory=True)
    files = {"src/test.py": ("100644", b"x")}
    contract = _contract(files)

    result = runner.main(
        ("stage",),
        workspace_root=workspace,
        input_stream=io.BytesIO(_stream(files, contract)),
        output_stream=io.BytesIO(),
    )

    assert result != 0
    assert not (outside / "test.py").exists()


def test_real_process_capture_enforces_output_limit_and_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(runner, "MAX_COMBINED_STDIO_BYTES", 1024)
    output = runner._run_process(
        (
            sys.executable,
            "-c",
            "import os; os.write(1, b'x' * 2048)",
        ),
        tmp_path,
        descendant_cleaner=_no_descendant_cleanup,
    )
    assert output.failure_code == "OUTPUT_LIMIT"
    assert len(output.stdout) + len(output.stderr) == 1024

    monkeypatch.setattr(runner, "WALL_CLOCK_TIMEOUT_SECONDS", 0.01)
    timeout = runner._run_process(
        (sys.executable, "-c", "import time; time.sleep(30)"),
        tmp_path,
        descendant_cleaner=_no_descendant_cleanup,
    )
    assert timeout.failure_code == "TIMEOUT"


def test_real_process_capture_maps_enospc_to_disk_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def raise_enospc(*args, **kwargs):
        raise OSError(28, os.strerror(28))

    monkeypatch.setattr(runner.subprocess, "Popen", raise_enospc)

    outcome = runner._run_process(
        (sys.executable, "-c", "pass"),
        tmp_path,
        descendant_cleaner=_no_descendant_cleanup,
    )

    assert outcome == runner.ProcessOutcome(
        exit_code=None,
        failure_code="DISK_LIMIT",
        stdout=b"",
        stderr=b"",
    )
