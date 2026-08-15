"""Contracts for the standalone verifier execution-image runner."""

from __future__ import annotations

import errno
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import runpy
import shutil
import signal
import stat
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest

from openworkproof import repo_tools


ROOT = Path(__file__).resolve().parents[1]
RUNNER_PATH = (
    ROOT / "supply-chain" / "images" / "execution" / "run_tests_runner.py"
)
VERIFIER_TEST_PATH = (
    ROOT / "supply-chain" / "images" / "execution" / "verifier_test.py"
)
FIXED_TEST_BYTES = VERIFIER_TEST_PATH.read_bytes()


@pytest.fixture(autouse=True)
def _fixed_test_seam(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, request: pytest.FixtureRequest
) -> None:
    fixed_root = tmp_path / "fixed-tests"
    fixed_root.mkdir()
    fixed_path = fixed_root / "verifier_test.py"
    fixed_path.write_bytes(FIXED_TEST_BYTES)
    fixed_path.chmod(0o444)
    fixed_root.chmod(0o555)

    def restore_permissions() -> None:
        try:
            if fixed_path.is_symlink():
                fixed_path.unlink()
            if fixed_root.exists():
                fixed_root.chmod(0o755)
            if fixed_path.exists():
                fixed_path.chmod(0o644)
        except OSError:
            pass  # the test may already have removed the fixed-tests tree

    request.addfinalizer(restore_permissions)
    monkeypatch.setattr(runner, "FIXED_TEST_ROOT", fixed_root, raising=False)
    monkeypatch.setattr(runner, "FIXED_TEST_PATH", fixed_path, raising=False)


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
                "domain": "openworkproof/test-command/v0.1",
                "command": runner.FROZEN_VERIFIER_COMMAND,
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
        "fixed_test_source_digest": hashlib.sha256(FIXED_TEST_BYTES).hexdigest(),
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


def test_signed_profile_repo_tools_and_runner_share_one_frozen_command(
    signed_work_order,
) -> None:
    verifier = next(
        profile
        for profile in signed_work_order.test_profiles
        if profile.test_mode == "verifier"
    )
    expected = verifier.command.model_dump(mode="json")

    assert expected == repo_tools.FROZEN_VERIFIER_COMMAND
    assert expected == runner.FROZEN_VERIFIER_COMMAND
    assert verifier.command.argv == repo_tools.FROZEN_VERIFIER_ARGV
    assert verifier.command.argv == runner.FROZEN_VERIFIER_ARGV
    assert verifier.command_digest == repo_tools.frozen_verifier_command_digest()
    assert verifier.command_digest == runner._frozen_command_digest()
    assert verifier.command_digest == (
        "ffff970faa57adccdf3bf9df83e4dd4bab330036123f2d1747c4328d24091589"
    )


def test_runner_constants_and_import_surface_are_frozen() -> None:
    assert runner.FROZEN_VERIFIER_ARGV == (
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
    assert "close_fds=True" in source
    assert "pass_fds" not in source
    assert "preexec_fn=preexec" in source


def test_tracked_verifier_test_has_closed_provenance_and_workspace_import() -> None:
    source = VERIFIER_TEST_PATH.read_text(encoding="utf-8")

    assert "https://github.com/Textualize/rich/issues/4196" in source
    assert "9d8f9a372cc5916fd4781fec207ced7ddac2f08f" in source
    assert 'sys.path.insert(0, "/workspace")' in source
    assert "from rich._wrap import divide_line, words" in source
    assert "NO-BREAK SPACE" in source


def test_tracked_verifier_test_rejects_frozen_regex_and_accepts_nbsp_fix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import rich._wrap as rich_wrap

    assert rich_wrap.re_word.pattern == r"\s*\S+\s*"
    namespace = runpy.run_path(str(VERIFIER_TEST_PATH))
    probe = namespace["test_non_breaking_space_stays_inside_one_wrapping_token"]

    with pytest.raises(AssertionError):
        probe()

    monkeypatch.setattr(
        rich_wrap,
        "re_word",
        re.compile(r"[^\S\u00a0]*(?:[^\s\u00a0]|\u00a0)+[^\S\u00a0]*"),
    )
    probe()


def test_process_environment_is_exactly_the_signed_four_variables(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    observed: dict[str, object] = {}

    def reject_start(argv, **kwargs):
        observed["argv"] = argv
        observed.update(kwargs)
        raise OSError(errno.EACCES, "injected")

    monkeypatch.setattr(runner.subprocess, "Popen", reject_start)

    with pytest.raises(runner.RunnerError, match="could not start"):
        runner._run_process(
            ("/bin/true",),
            tmp_path,
            descendant_cleaner=_no_descendant_cleanup,
            child_preexec=_no_child_preexec,
        )

    assert observed["argv"] == ("/bin/true",)
    assert observed["cwd"] == tmp_path
    assert observed["env"] == {
        "HOME": "/nonexistent",
        "LC_ALL": "C.UTF-8",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
        "TZ": "UTC",
    }


def test_stage_writes_snapshot_and_exact_canonical_summary(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    os.utime(workspace, ns=(1_000_000_000, 2_000_000_000))
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
        workspace / "README.md",
        workspace / "src",
        workspace / "src/test_sample.py",
        workspace / "run-contract.json",
    )
    for path in normalized_paths:
        metadata = path.lstat()
        assert metadata.st_atime_ns == 0
        assert metadata.st_mtime_ns == 0
    root_metadata = workspace.lstat()
    assert root_metadata.st_atime_ns != 0
    assert root_metadata.st_mtime_ns != 0
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


def test_stage_never_normalizes_mount_root_timestamp(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    files = {"nested/candidate.py": ("100644", b"candidate bytes")}
    contract = _contract(files)
    real_utime = runner.os.utime

    def reject_mount_root(path, *args, **kwargs) -> None:
        if Path(path) == workspace:
            raise PermissionError(errno.EPERM, "root-owned mount")
        real_utime(path, *args, **kwargs)

    monkeypatch.setattr(runner.os, "utime", reject_mount_root)

    result = runner.main(
        ("stage",),
        workspace_root=workspace,
        input_stream=io.BytesIO(_stream(files, contract)),
        output_stream=io.BytesIO(),
    )

    assert result == 0
    for path in (
        workspace / "nested",
        workspace / "nested/candidate.py",
        workspace / "run-contract.json",
    ):
        metadata = path.lstat()
        assert metadata.st_atime_ns == 0
        assert metadata.st_mtime_ns == 0


def _no_descendant_cleanup() -> None:
    return None


def _no_child_preexec() -> None:
    return None


_LINUX_PROBE_OK = "OPENWORKPROOF_LINUX_PROBE_OK\n"
_LINUX_PROBE_PREAMBLE = r'''
import hashlib
import importlib.util
from pathlib import Path
import sys

spec = importlib.util.spec_from_file_location(
    "openworkproof_live_run_tests_runner",
    "/opt/openworkproof/run_tests_runner.py",
)
assert spec is not None and spec.loader is not None
runner = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = runner
spec.loader.exec_module(runner)

workspace = Path("/workspace")
output = Path("/output")
scratch = Path("/tmp/openworkproof-landlock-scratch")
for root in (workspace, output):
    root.mkdir(mode=0o755, exist_ok=True)
    assert not any(root.iterdir())
scratch.mkdir(mode=0o700)

def identity(path):
    metadata = path.lstat()
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
        path.read_bytes(),
    )

def prepare(files):
    for relative, (mode, content) in files.items():
        path = workspace / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        path.chmod(int(mode[-3:], 8))
    candidate_commit = "2" * 40
    contract = {
        "arguments_digest": "3" * 64,
        "candidate_commit": candidate_commit,
        "candidate_workspace_id": "4" * 64,
        "command_digest": runner._frozen_command_digest(),
        "container_image_digest": "sha256:" + "5" * 64,
        "execution_id": "6" * 64,
        "fixed_test_source_digest": hashlib.sha256(
            Path("/fixed-tests/verifier_test.py").read_bytes()
        ).hexdigest(),
        "request_digest": "8" * 64,
        "schema_version": "openworkproof-run-contract/0.1",
        "source_artifact_sha256": "9" * 64,
        "source_commit": "1" * 40,
        "test_mode": "verifier",
        "tool_name": "owp.run_tests",
        "workspace_manifest_digest": runner._manifest_digest(
            files, candidate_commit
        ),
    }
    (workspace / "run-contract.json").write_bytes(runner._canonical(contract))
    return contract

abi = runner._query_landlock_abi()
preexec = runner._build_landlock_preexec(abi, scratch)
'''

_FORGED_MARKER_LINUX_PROBE = _LINUX_PROBE_PREAMBLE + r'''
files = {"README.md": ("100644", b"candidate\n")}
contract = prepare(files)
workspace_before = {
    str(path.relative_to(workspace)): identity(path)
    for path in sorted(workspace.rglob("*"))
    if path.is_file()
}
workspace_paths = tuple(
    str(path.relative_to(workspace)) for path in sorted(workspace.rglob("*"))
)
forged = runner._canonical(
    {
        "actual_exit_code": 0,
        "execution_contract_digest": "0" * 64,
        "execution_id": contract["execution_id"],
        "failure_code": None,
        "schema_version": "openworkproof-run-result/0.1",
        "stderr_bytes": 0,
        "stderr_sha256": hashlib.sha256(b"").hexdigest(),
        "stdout_bytes": 0,
        "stdout_sha256": hashlib.sha256(b"").hexdigest(),
    }
)
attack = (
    "import os\n"
    "from pathlib import Path\n"
    "workspace=Path('/workspace')\n"
    "output=Path('/output')\n"
    "scratch=Path('/tmp/openworkproof-landlock-scratch')\n"
    f"forged={forged!r}\n"
    "source=scratch/'forged'\n"
    "source.write_bytes(forged)\n"
    "attempts=[\n"
    " lambda: (output/'result.json').write_bytes(forged),\n"
    " lambda: os.replace(source, output/'started.json'),\n"
    " lambda: os.link(output/'started.json', scratch/'started-alias'),\n"
    " lambda: os.link(source, output/'result.json'),\n"
    " lambda: (workspace/'README.md').write_bytes(b'changed'),\n"
    " lambda: (workspace/'candidate').write_bytes(b'changed'),\n"
    "]\n"
    "for attempt in attempts:\n"
    " try: attempt()\n"
    " except OSError: pass\n"
    " else: raise SystemExit(73)\n"
)
marker_before = None

def process(argv, cwd):
    global marker_before
    assert argv == runner.FROZEN_VERIFIER_ARGV
    started = output / "started.json"
    marker_before = identity(started)
    outcome = runner._run_process(
        (sys.executable, "-I", "-c", attack),
        cwd,
        descendant_cleaner=lambda: None,
        child_preexec=preexec,
    )
    assert outcome.exit_code == 0
    assert outcome.failure_code is None
    assert outcome.stdout == b"" and outcome.stderr == b""
    assert identity(started) == marker_before
    return outcome

assert runner.main(
    ("execute",),
    workspace_root=workspace,
    output_root=output,
    process_runner=process,
) == 0
assert marker_before is not None
assert identity(output / "started.json") == marker_before
published = (output / "result.json").read_bytes()
published_identity = identity(output / "result.json")
assert identity(output / "result.json") == published_identity
assert published != forged
result = runner._parse_canonical_json(published)
assert result["execution_id"] == contract["execution_id"]
assert tuple(
    str(path.relative_to(workspace)) for path in sorted(workspace.rglob("*"))
) == workspace_paths
assert {
    str(path.relative_to(workspace)): identity(path)
    for path in sorted(workspace.rglob("*"))
    if path.is_file()
} == workspace_before
assert not (scratch / "started-alias").exists()
print("OPENWORKPROOF_LINUX_PROBE_OK")
'''

_EXACT_COMMAND_LINUX_PROBE = _LINUX_PROBE_PREAMBLE + r'''
preexec = runner._build_landlock_preexec(abi, Path("/tmp"))
files = {
    "rich/__init__.py": ("100644", b""),
    "rich/_wrap.py": (
        "100644",
        b"def words(text):\n"
        b"    yield 0, len(text), text\n\n"
        b"def divide_line(text, width, fold=False):\n"
        b"    return [2]\n",
    ),
}
prepare(files)
workspace_before = {
    str(path.relative_to(workspace)): identity(path)
    for path in sorted(workspace.rglob("*"))
    if path.is_file()
}
workspace_paths = tuple(
    str(path.relative_to(workspace)) for path in sorted(workspace.rglob("*"))
)

def process(argv, cwd):
    assert argv == runner.FROZEN_VERIFIER_ARGV
    outcome = runner._run_process(
        argv,
        cwd,
        descendant_cleaner=lambda: None,
        child_preexec=preexec,
    )
    assert outcome.exit_code == 0
    assert outcome.failure_code is None
    return outcome

assert runner.FROZEN_VERIFIER_ARGV == (
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
assert runner.main(
    ("execute",),
    workspace_root=workspace,
    output_root=output,
    process_runner=process,
) == 0
result = runner._parse_canonical_json((output / "result.json").read_bytes())
assert result["actual_exit_code"] == 0
assert result["failure_code"] is None
assert tuple(
    str(path.relative_to(workspace)) for path in sorted(workspace.rglob("*"))
) == workspace_paths
assert {
    str(path.relative_to(workspace)): identity(path)
    for path in sorted(workspace.rglob("*"))
    if path.is_file()
} == workspace_before
print("OPENWORKPROOF_LINUX_PROBE_OK")
'''


def _run_required_live_linux_probe(
    probe: str,
    *,
    run=subprocess.run,
) -> None:
    if os.environ.get("OPENWORKPROOF_REQUIRE_LIVE_DOCKER") != "1":
        pytest.skip(
            "real Landlock enforcement requires Linux; "
            "set OPENWORKPROOF_REQUIRE_LIVE_DOCKER=1 for the immutable-image probe"
        )
    docker = os.environ.get("OPENWORKPROOF_DOCKER") or shutil.which("docker")
    if docker is None:
        pytest.fail("required live Docker CLI is unavailable")
    docker_path = Path(docker).expanduser()
    if not docker_path.is_file() or not os.access(docker_path, os.X_OK):
        pytest.fail(f"required live Docker CLI is unavailable: {docker_path}")
    image = os.environ.get("OPENWORKPROOF_DOCKER_TEST_IMAGE")
    if image is None or re.fullmatch(r"[^@\s]+@sha256:[0-9a-f]{64}", image) is None:
        pytest.fail(
            "required immutable Docker test image is unavailable: set "
            "OPENWORKPROOF_DOCKER_TEST_IMAGE to repository@sha256:digest"
        )
    try:
        daemon = run(
            (str(docker_path), "info"),
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as error:
        pytest.fail(f"required live Docker daemon is unavailable: {type(error).__name__}")
    if daemon.returncode != 0:
        pytest.fail(
            "required live Docker daemon is unavailable: "
            f"rc={daemon.returncode} stderr={daemon.stderr!r}"
        )
    inspected = run(
        (str(docker_path), "image", "inspect", image),
        capture_output=True,
        text=True,
        timeout=10,
    )
    if inspected.returncode != 0:
        pytest.fail(
            "required immutable Docker test image is not preloaded: "
            f"{image}; rc={inspected.returncode} stderr={inspected.stderr!r}"
        )
    completed = run(
        (
            str(docker_path),
            "run",
            "--rm",
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
            "/tmp:rw,noexec,nosuid,size=256m,uid=65532,gid=65532,mode=0755",
            "--tmpfs",
            "/workspace:rw,noexec,nosuid,size=16m,uid=65532,gid=65532,mode=0755",
            "--tmpfs",
            "/output:rw,noexec,nosuid,size=2m,uid=65532,gid=65532,mode=0755",
            "--entrypoint",
            "/opt/venv/bin/python",
            image,
            "-I",
            "-c",
            probe,
        ),
        capture_output=True,
        text=True,
        timeout=180,
    )
    if completed.returncode != 0:
        pytest.fail(
            f"required Linux probe exited {completed.returncode}: "
            f"stdout={completed.stdout!r}; stderr={completed.stderr!r}"
        )
    if completed.stdout != _LINUX_PROBE_OK or completed.stderr != "":
        pytest.fail(
            "required Linux probe returned unexpected streams: "
            f"stdout={completed.stdout!r}; stderr={completed.stderr!r}"
        )


def test_required_live_linux_probe_uses_exact_containment_argv(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    image = "openworkproof/execution-test@sha256:" + "a" * 64
    probe = "print('OPENWORKPROOF_LINUX_PROBE_OK')"
    commands: list[tuple[str, ...]] = []

    def fake_run(command, **kwargs):
        command = tuple(command)
        commands.append(command)
        if command[1] == "info":
            return subprocess.CompletedProcess(command, 0, "29.5.2\n", "")
        if command[1:3] == ("image", "inspect"):
            return subprocess.CompletedProcess(command, 0, "[]\n", "")
        return subprocess.CompletedProcess(
            command,
            0,
            "OPENWORKPROOF_LINUX_PROBE_OK\n",
            "",
        )

    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setenv("OPENWORKPROOF_REQUIRE_LIVE_DOCKER", "1")
    monkeypatch.setenv("OPENWORKPROOF_DOCKER", sys.executable)
    monkeypatch.setenv("OPENWORKPROOF_DOCKER_TEST_IMAGE", image)

    _run_required_live_linux_probe(probe, run=fake_run)

    assert commands == [
        (sys.executable, "info"),
        (sys.executable, "image", "inspect", image),
        (
            sys.executable,
            "run",
            "--rm",
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
            "/tmp:rw,noexec,nosuid,size=256m,uid=65532,gid=65532,mode=0755",
            "--tmpfs",
            "/workspace:rw,noexec,nosuid,size=16m,uid=65532,gid=65532,mode=0755",
            "--tmpfs",
            "/output:rw,noexec,nosuid,size=2m,uid=65532,gid=65532,mode=0755",
            "--entrypoint",
            "/opt/venv/bin/python",
            image,
            "-I",
            "-c",
            probe,
        ),
    ]


def test_required_live_linux_probe_propagates_probe_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    image = "openworkproof/execution-test@sha256:" + "a" * 64

    def fake_run(command, **kwargs):
        command = tuple(command)
        if command[1] in {"info", "image"}:
            return subprocess.CompletedProcess(command, 0, "", "")
        return subprocess.CompletedProcess(command, 73, "partial\n", "denied\n")

    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setenv("OPENWORKPROOF_REQUIRE_LIVE_DOCKER", "1")
    monkeypatch.setenv("OPENWORKPROOF_DOCKER", sys.executable)
    monkeypatch.setenv("OPENWORKPROOF_DOCKER_TEST_IMAGE", image)

    with pytest.raises(pytest.fail.Exception, match="exited 73.*denied"):
        _run_required_live_linux_probe("raise SystemExit(73)", run=fake_run)


def _linux_dev_null_stat(path: Path) -> SimpleNamespace:
    assert path == Path("/dev/null")
    return SimpleNamespace(
        st_mode=stat.S_IFCHR | 0o666,
        st_rdev=os.makedev(1, 3),
    )


def test_landlock_policy_requires_linux_and_supported_abi(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(runner.sys, "platform", "darwin")
    with pytest.raises(runner.RunnerError, match="Linux"):
        runner._production_child_preexec()

    monkeypatch.setattr(runner.sys, "platform", "linux")
    for abi in (2, runner._LANDLOCK_MAX_KNOWN_ABI + 1):
        with pytest.raises(runner.RunnerError, match="ABI"):
            runner._production_child_preexec(
                syscall=lambda number, *args, abi=abi: abi,
                prctl=lambda *args: 0,
            )


@pytest.mark.parametrize("failure_stage", ["query", "create", "add", "restrict"])
def test_landlock_syscall_failures_are_controlled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure_stage: str
) -> None:
    calls: list[int] = []

    def syscall(number: int, *args) -> int:
        calls.append(number)
        stage_by_call = {
            runner._SYS_LANDLOCK_CREATE_RULESET: (
                "query" if len(calls) == 1 else "create"
            ),
            runner._SYS_LANDLOCK_ADD_RULE: "add",
            runner._SYS_LANDLOCK_RESTRICT_SELF: "restrict",
        }
        if stage_by_call[number] == failure_stage:
            return -1
        if number == runner._SYS_LANDLOCK_CREATE_RULESET:
            return 5 if len(calls) == 1 else 71
        return 0

    monkeypatch.setattr(runner.sys, "platform", "linux")
    if failure_stage == "query":
        with pytest.raises(runner.RunnerError, match="ABI"):
            runner._production_child_preexec(
                writable_root=tmp_path,
                syscall=syscall,
                prctl=lambda *args: 0,
            )
        return

    preexec = runner._production_child_preexec(
        writable_root=tmp_path,
        syscall=syscall,
        prctl=lambda *args: 0,
        opener=lambda *args: 72,
        closer=lambda descriptor: None,
        statter=_linux_dev_null_stat,
    )
    with pytest.raises(runner.RunnerError, match="Landlock"):
        preexec()


def test_landlock_policy_handles_every_supported_write_right(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    masks: list[int] = []
    rules: list[tuple[int, int]] = []
    opened_paths: list[Path] = []
    prctls: list[tuple[int, ...]] = []

    def syscall(number: int, *args) -> int:
        if number == runner._SYS_LANDLOCK_CREATE_RULESET:
            if not args[0]:
                return 5
            masks.append(args[0]._obj.handled_access_fs)
            return 71
        if number == runner._SYS_LANDLOCK_ADD_RULE:
            masks.append(args[2]._obj.allowed_access)
            rules.append((args[2]._obj.parent_fd, args[2]._obj.allowed_access))
        return 0

    def opener(path: Path, flags: int) -> int:
        opened_paths.append(Path(path))
        return 71 + len(opened_paths)

    monkeypatch.setattr(runner.sys, "platform", "linux")
    preexec = runner._production_child_preexec(
        writable_root=tmp_path,
        syscall=syscall,
        prctl=lambda *args: prctls.append(args) or 0,
        opener=opener,
        closer=lambda descriptor: None,
        statter=_linux_dev_null_stat,
    )
    preexec()

    expected = runner._landlock_write_access(5)
    dev_null_access = (
        runner._LANDLOCK_ACCESS_FS_WRITE_FILE
        | runner._LANDLOCK_ACCESS_FS_IOCTL_DEV
    )
    assert runner._landlock_dev_null_access(3) == (
        runner._LANDLOCK_ACCESS_FS_WRITE_FILE
    )
    assert runner._landlock_dev_null_access(5) == dev_null_access
    assert masks == [expected, expected, dev_null_access]
    assert rules == [(72, expected), (73, dev_null_access)]
    assert opened_paths == [tmp_path, Path("/dev/null")]
    assert Path("/dev") not in opened_paths
    assert tmp_path / "output" not in opened_paths
    assert prctls == [
        (runner._PR_SET_DUMPABLE, 0, 0, 0, 0),
        (runner._PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0),
    ]


@pytest.mark.parametrize(
    ("mode", "device"),
    (
        (stat.S_IFLNK | 0o777, os.makedev(1, 3)),
        (stat.S_IFREG | 0o666, 0),
        (stat.S_IFCHR | 0o666, os.makedev(1, 5)),
    ),
)
def test_landlock_rejects_noncanonical_dev_null(
    tmp_path: Path, mode: int, device: int
) -> None:
    metadata = SimpleNamespace(st_mode=mode, st_rdev=device)

    with pytest.raises(runner.RunnerError, match="/dev/null"):
        runner._build_landlock_preexec(
            5,
            tmp_path,
            device_null=Path("/dev/null"),
            statter=lambda path: metadata,
        )


@pytest.mark.parametrize("failure_stage", ["dumpable", "no_new_privs"])
def test_landlock_prctl_failures_are_controlled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure_stage: str
) -> None:
    calls = 0

    def prctl(*args) -> int:
        nonlocal calls
        calls += 1
        expected_call = 1 if failure_stage == "dumpable" else 2
        return -1 if calls == expected_call else 0

    monkeypatch.setattr(runner.sys, "platform", "linux")
    if failure_stage == "dumpable":
        with pytest.raises(runner.RunnerError, match="dumpability"):
            runner._production_child_preexec(
                writable_root=tmp_path,
                syscall=lambda number, *args: 5,
                prctl=prctl,
            )
        return

    preexec = runner._production_child_preexec(
        writable_root=tmp_path,
        syscall=lambda number, *args: 5 if calls == 0 else 0,
        prctl=prctl,
        opener=lambda *args: 72,
        closer=lambda descriptor: None,
        statter=_linux_dev_null_stat,
    )
    with pytest.raises(runner.RunnerError, match="no_new_privs"):
        preexec()


def test_landlock_preflight_failure_never_starts_candidate_or_publishes_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace, output, _, _ = _write_workspace(tmp_path)
    started_candidate = False

    monkeypatch.setattr(runner, "_production_descendant_cleaner", lambda: lambda: None)
    monkeypatch.setattr(
        runner,
        "_production_child_preexec",
        lambda: (_ for _ in ()).throw(runner.RunnerError("Landlock unavailable")),
    )

    def unexpected_popen(*args, **kwargs):
        nonlocal started_candidate
        started_candidate = True
        raise AssertionError("candidate must not start")

    monkeypatch.setattr(runner.subprocess, "Popen", unexpected_popen)

    result = runner.main(
        ("execute",),
        workspace_root=workspace,
        output_root=output,
    )

    assert result != 0
    assert not started_candidate
    assert (output / "started.json").is_file()
    assert not (output / "result.json").exists()


def test_landlock_child_setup_failure_never_executes_candidate_or_publishes_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace, output, _, _ = _write_workspace(tmp_path)

    monkeypatch.setattr(runner, "_production_descendant_cleaner", lambda: lambda: None)
    monkeypatch.setattr(
        runner,
        "_production_child_preexec",
        lambda: lambda: (_ for _ in ()).throw(
            runner.RunnerError("Landlock restrict_self failed")
        ),
    )
    result = runner.main(
        ("execute",),
        workspace_root=workspace,
        output_root=output,
    )

    assert result != 0
    assert (output / "started.json").is_file()
    assert not (output / "result.json").exists()


def test_landlock_blocks_forged_markers_aliases_and_workspace_writes(
    tmp_path: Path,
) -> None:
    if not sys.platform.startswith("linux"):
        _run_required_live_linux_probe(_FORGED_MARKER_LINUX_PROBE)
        return
    workspace, output, _, contract = _write_workspace(tmp_path)
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    forged = _canonical(
        {
            "actual_exit_code": 0,
            "execution_contract_digest": "0" * 64,
            "execution_id": contract["execution_id"],
            "failure_code": None,
            "schema_version": "openworkproof-run-result/0.1",
            "stderr_bytes": 0,
            "stderr_sha256": hashlib.sha256(b"").hexdigest(),
            "stdout_bytes": 0,
            "stdout_sha256": hashlib.sha256(b"").hexdigest(),
        }
    )
    attack = (
        "import os\n"
        "from pathlib import Path\n"
        f"workspace=Path({str(workspace)!r})\n"
        f"output=Path({str(output)!r})\n"
        f"scratch=Path({str(scratch)!r})\n"
        f"forged={forged!r}\n"
        "source=scratch/'forged'\n"
        "source.write_bytes(forged)\n"
        "attempts=[\n"
        " lambda: (output/'result.json').write_bytes(forged),\n"
        " lambda: os.replace(source, output/'started.json'),\n"
        " lambda: os.link(output/'started.json', scratch/'started-alias'),\n"
        " lambda: os.link(source, output/'result.json'),\n"
        " lambda: (workspace/'candidate').write_bytes(b'changed'),\n"
        "]\n"
        "for attempt in attempts:\n"
        " try: attempt()\n"
        " except OSError: pass\n"
        " else: raise SystemExit(73)\n"
    )

    try:
        abi = runner._query_landlock_abi()
        preexec = runner._build_landlock_preexec(abi, scratch)
    except runner.RunnerError as error:
        pytest.skip(f"Landlock unavailable: {error}")

    def process(argv, cwd):
        return runner._run_process(
            (sys.executable, "-c", attack),
            cwd,
            descendant_cleaner=_no_descendant_cleanup,
            child_preexec=preexec,
        )

    result = runner.main(
        ("execute",),
        workspace_root=workspace,
        output_root=output,
        process_runner=process,
    )

    published = (output / "result.json").read_bytes()
    assert result == 0
    assert published != forged
    assert json.loads(published)["execution_id"] == contract["execution_id"]
    assert not (scratch / "started-alias").exists()


def test_exact_frozen_verifier_argv_runs_under_landlock(tmp_path: Path) -> None:
    if not sys.platform.startswith("linux"):
        _run_required_live_linux_probe(_EXACT_COMMAND_LINUX_PROBE)
        return
    if not Path(runner.FROZEN_VERIFIER_ARGV[0]).is_file():
        pytest.skip(
            "exact frozen verifier Landlock regression requires the Linux execution image"
        )
    workspace, output, _, _ = _write_workspace(tmp_path)
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    try:
        abi = runner._query_landlock_abi()
        preexec = runner._build_landlock_preexec(abi, scratch)
    except runner.RunnerError as error:
        pytest.skip(f"Landlock unavailable: {error}")

    def process(argv, cwd):
        assert argv == runner.FROZEN_VERIFIER_ARGV
        return runner._run_process(
            argv,
            cwd,
            descendant_cleaner=_no_descendant_cleanup,
            child_preexec=preexec,
        )

    result = runner.main(
        ("execute",),
        workspace_root=workspace,
        output_root=output,
        process_runner=process,
    )

    assert result == 0
    assert json.loads((output / "result.json").read_bytes())["actual_exit_code"] == 0


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
            child_preexec=_no_child_preexec,
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
            child_preexec=_no_child_preexec,
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
    observed: list[tuple[tuple[str, ...], Path]] = []

    def process(argv, cwd):
        observed.append((argv, cwd))
        return runner.ProcessOutcome(
            exit_code=0,
            failure_code=None,
            stdout=b"ok",
            stderr=b"warning",
        )

    result = runner.main(
        ("execute",),
        workspace_root=workspace,
        output_root=output,
        process_runner=process,
    )

    assert result == 0
    assert observed == [(runner.FROZEN_VERIFIER_ARGV, workspace)]
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


def _rewrite_fixed_test_digest(workspace: Path, digest: str) -> None:
    contract_path = workspace / "run-contract.json"
    contract = json.loads(contract_path.read_bytes())
    contract["fixed_test_source_digest"] = digest
    contract_path.write_bytes(_canonical(contract))


@pytest.mark.parametrize(
    ("failure", "content"),
    (
        ("missing", None),
        ("symlink", None),
        ("writable-mode", None),
        ("oversized", b"x" * 65_537),
        ("utf8-bom", b"\xef\xbb\xbfprint('x')\n"),
        ("nul", b"print('x')\x00\n"),
        ("cr", b"print('x')\r\n"),
        ("missing-final-lf", b"print('x')"),
        ("invalid-utf8", b"# \xff\n"),
        ("digest-mismatch", b"print('different')\n"),
    ),
)
def test_execute_rejects_invalid_fixed_test_before_started_or_process(
    tmp_path: Path,
    failure: str,
    content: bytes | None,
) -> None:
    workspace, output, _, _ = _write_workspace(tmp_path)
    fixed_root = tmp_path / "fixed-tests"
    fixed_path = fixed_root / "verifier_test.py"
    process_called = False

    fixed_root.chmod(0o755)
    if failure == "missing":
        fixed_path.unlink()
    elif failure == "symlink":
        fixed_path.unlink()
        fixed_path.symlink_to(VERIFIER_TEST_PATH)
    elif failure == "writable-mode":
        fixed_path.chmod(0o644)
    else:
        assert content is not None
        fixed_path.chmod(0o644)
        fixed_path.write_bytes(content)
        fixed_path.chmod(0o444)
        if failure != "digest-mismatch":
            _rewrite_fixed_test_digest(workspace, hashlib.sha256(content).hexdigest())
    fixed_root.chmod(0o555)

    def unexpected_process(argv, cwd):
        nonlocal process_called
        process_called = True
        raise AssertionError("fixed-test rejection must precede process execution")

    try:
        result = runner.main(
            ("execute",),
            workspace_root=workspace,
            output_root=output,
            process_runner=unexpected_process,
        )
    finally:
        # Restore write access so pytest's tmp cleanup can remove the
        # read-only fixed-tests tree (avoids the known rm_rf warnings).
        fixed_root.chmod(0o755)

    assert result != 0
    assert not process_called
    assert not list(output.iterdir())


def test_execute_rejects_wrong_fixed_test_owner_before_started(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace, output, _, _ = _write_workspace(tmp_path)
    fixed_root = tmp_path / "fixed-tests"
    original_lstat = Path.lstat

    def wrong_root_owner(path: Path):
        metadata = original_lstat(path)
        if path == fixed_root:
            values = list(metadata)
            values[4] = metadata.st_uid + 1
            return os.stat_result(values)
        return metadata

    monkeypatch.setattr(Path, "lstat", wrong_root_owner)

    assert runner.main(
        ("execute",),
        workspace_root=workspace,
        output_root=output,
        process_runner=lambda argv, cwd: (_ for _ in ()).throw(
            AssertionError("process must not run")
        ),
    ) != 0
    assert not list(output.iterdir())


@pytest.mark.parametrize(
    ("fixed_root", "fixed_path"),
    (
        (Path("fixed-tests"), Path("fixed-tests/verifier_test.py")),
        (Path("/fixed-tests"), Path("/other/verifier_test.py")),
        (Path("/fixed-tests"), Path("/fixed-tests/other.py")),
    ),
)
def test_execute_rejects_noncanonical_fixed_test_seam(
    tmp_path: Path, fixed_root: Path, fixed_path: Path
) -> None:
    workspace, output, _, _ = _write_workspace(tmp_path)

    with pytest.raises(runner.RunnerError):
        runner._execute(
            workspace,
            output,
            lambda argv, cwd: (_ for _ in ()).throw(
                AssertionError("process must not run")
            ),
            fixed_test_root=fixed_root,
            fixed_test_path=fixed_path,
        )
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
        child_preexec=_no_child_preexec,
    )
    assert output.failure_code == "OUTPUT_LIMIT"
    assert len(output.stdout) + len(output.stderr) == 1024

    monkeypatch.setattr(runner, "WALL_CLOCK_TIMEOUT_SECONDS", 0.01)
    timeout = runner._run_process(
        (sys.executable, "-c", "import time; time.sleep(30)"),
        tmp_path,
        descendant_cleaner=_no_descendant_cleanup,
        child_preexec=_no_child_preexec,
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
        child_preexec=_no_child_preexec,
    )

    assert outcome == runner.ProcessOutcome(
        exit_code=None,
        failure_code="DISK_LIMIT",
        stdout=b"",
        stderr=b"",
    )
