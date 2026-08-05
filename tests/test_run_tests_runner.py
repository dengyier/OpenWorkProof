"""Contracts for the standalone verifier execution-image runner."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys

import pytest


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
    )
    assert output.failure_code == "OUTPUT_LIMIT"
    assert len(output.stdout) + len(output.stderr) == 1024

    monkeypatch.setattr(runner, "WALL_CLOCK_TIMEOUT_SECONDS", 0.01)
    timeout = runner._run_process(
        (sys.executable, "-c", "import time; time.sleep(30)"),
        tmp_path,
    )
    assert timeout.failure_code == "TIMEOUT"


def test_real_process_capture_maps_enospc_to_disk_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def raise_enospc(*args, **kwargs):
        raise OSError(28, os.strerror(28))

    monkeypatch.setattr(runner.subprocess, "Popen", raise_enospc)

    outcome = runner._run_process((sys.executable, "-c", "pass"), tmp_path)

    assert outcome == runner.ProcessOutcome(
        exit_code=None,
        failure_code="DISK_LIMIT",
        stdout=b"",
        stderr=b"",
    )
