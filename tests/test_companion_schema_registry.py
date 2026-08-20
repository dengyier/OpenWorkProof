"""Independent companion (0.1) schema registry tests.

The companion registry packages closed companion evidence-document schemas
(execution environment fingerprint) *beside* the frozen v0.1-v0.5 protocol
registry.  Every digest, path and seed below is deterministic and test-only; it
must not be mistaken for a production key, signature or contract identifier.
"""

from __future__ import annotations

import hashlib
import importlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import zipfile

import pytest
import rfc8785

from openworkproof.environment_fingerprint import SignedEnvironmentFingerprintV01
from openworkproof.verification_report import VerificationReportV01


PROJECT_ROOT = Path(__file__).resolve().parents[1]
COMPANION_VERSION = "0.1"
COMPANION_REGISTRY_SCHEMA_VERSION = "openworkproof-companion-schema-registry/0.1"
COMPANION_FILENAMES = frozenset(
    {
        "schema-registry.json",
        "execution-environment.schema.json",
        "verification-report.schema.json",
    }
)
COMPANION_OBJECT_PATHS = {
    "execution-environment": "execution-environment.schema.json",
    "verification-report": "verification-report.schema.json",
}
COMPANION_TRANSACTION_PREFIXES = (
    ".openworkproof-companion-backup-",
    ".openworkproof-companion-stage-",
)
COMPANION_LOCK_PREFIX = ".openworkproof-companion-lock-"


def _api():
    return importlib.import_module("openworkproof.companion_schema_registry")


def _runtime_directory() -> Path:
    return PROJECT_ROOT / "src/openworkproof/schemas/companion-v0.1"


def _spec_directory() -> Path:
    return PROJECT_ROOT / "specs/companion-v0.1"


def _builtin_bytes() -> dict[str, bytes]:
    directory = _runtime_directory()
    return {name: directory.joinpath(name).read_bytes() for name in COMPANION_FILENAMES}


def _snapshot(directory: Path) -> dict[str, bytes]:
    return {
        path.name: path.read_bytes()
        for path in directory.iterdir()
        if path.is_file()
    }


def _write_old_set(directory: Path) -> dict[str, bytes]:
    directory.mkdir()
    for name in COMPANION_FILENAMES:
        directory.joinpath(name).write_bytes(f"old:{name}".encode())
    return _snapshot(directory)


def _companion_artifacts(parent: Path) -> set[str]:
    return {
        path.name
        for path in parent.iterdir()
        if path.name.startswith(COMPANION_TRANSACTION_PREFIXES)
    }


def _remove_generated_directory(directory: Path) -> None:
    if not directory.exists():
        return
    for name in COMPANION_FILENAMES:
        path = directory / name
        if path.is_file() and not path.is_symlink():
            path.unlink()
    directory.rmdir()


@pytest.fixture(scope="module")
def built_companion_wheel(
    tmp_path_factory: pytest.TempPathFactory,
) -> Path:
    workspace = tmp_path_factory.mktemp("companion-wheel")
    project = workspace / "project"
    project.mkdir()
    shutil.copy2(PROJECT_ROOT / "pyproject.toml", project / "pyproject.toml")
    shutil.copytree(PROJECT_ROOT / "src", project / "src")
    wheelhouse = workspace / "wheelhouse"
    wheelhouse.mkdir()
    subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "wheel",
            "--no-build-isolation",
            "--no-deps",
            "--wheel-dir",
            str(wheelhouse),
            ".",
        ],
        cwd=project,
        check=True,
        capture_output=True,
        text=True,
    )
    wheels = tuple(wheelhouse.glob("*.whl"))
    assert len(wheels) == 1
    return wheels[0]


# --------------------------------------------------------------------------- #
# 1. deterministic, canonical generation and mirror parity
# --------------------------------------------------------------------------- #


def test_companion_generation_is_deterministic(tmp_path: Path) -> None:
    api = _api()
    first = tmp_path / "first"
    second = tmp_path / "second"

    api.generate_companion_schemas(first)
    api.generate_companion_schemas(second)

    assert _snapshot(first) == _snapshot(second)


def test_runtime_and_spec_mirror_are_byte_identical(tmp_path: Path) -> None:
    api = _api()
    runtime = tmp_path / "runtime"
    spec = tmp_path / "spec"

    api.generate_companion_schemas(runtime, mirror=spec)

    assert _snapshot(runtime) == _snapshot(spec)
    assert set(_snapshot(runtime)) == COMPANION_FILENAMES


def test_exact_complete_file_set(tmp_path: Path) -> None:
    api = _api()
    destination = tmp_path / "destination"

    api.generate_companion_schemas(destination)

    assert {path.name for path in destination.iterdir()} == COMPANION_FILENAMES
    assert set(api.generated_companion_files()) == COMPANION_FILENAMES
    assert set(api.OBJECT_PATHS) == set(COMPANION_OBJECT_PATHS)
    assert api.COMPANION_VERSION == COMPANION_VERSION


def test_registry_entries_are_sorted_with_exact_sha256() -> None:
    api = _api()
    files = api.generated_companion_files()

    assert files["schema-registry.json"] == rfc8785.dumps(
        json.loads(files["schema-registry.json"])
    )
    for name in COMPANION_OBJECT_PATHS.values():
        assert files[name] == rfc8785.dumps(json.loads(files[name]))

    assert files["execution-environment.schema.json"] == rfc8785.dumps(
        SignedEnvironmentFingerprintV01.model_json_schema()
    )
    assert files["verification-report.schema.json"] == rfc8785.dumps(
        VerificationReportV01.model_json_schema()
    )

    registry = json.loads(files["schema-registry.json"])
    assert registry == {
        "schema_version": COMPANION_REGISTRY_SCHEMA_VERSION,
        "document_version": COMPANION_VERSION,
        "schemas": [
            {
                "object_type": "execution-environment",
                "path": "execution-environment.schema.json",
                "sha256": hashlib.sha256(
                    files["execution-environment.schema.json"]
                ).hexdigest(),
            },
            {
                "object_type": "verification-report",
                "path": "verification-report.schema.json",
                "sha256": hashlib.sha256(
                    files["verification-report.schema.json"]
                ).hexdigest(),
            },
        ],
    }
    assert [entry["object_type"] for entry in registry["schemas"]] == sorted(
        COMPANION_OBJECT_PATHS
    )
    assert "schema-registry.json" not in {
        entry["path"] for entry in registry["schemas"]
    }


# --------------------------------------------------------------------------- #
# 2. frozen protocol boundary
# --------------------------------------------------------------------------- #


def test_protocol_v01_to_v05_anchors_are_unchanged() -> None:
    schema_api = importlib.import_module("openworkproof.schema_registry")

    for version in ("0.1", "0.2", "0.3", "0.4", "0.5"):
        directory = PROJECT_ROOT / "src/openworkproof/schemas" / f"v{version}"
        runtime = {
            path.name: path.read_bytes()
            for path in directory.iterdir()
            if path.is_file()
        }
        assert schema_api._generated_files(version=version) == runtime


def test_companion_objects_are_not_added_to_protocol_registry() -> None:
    schema_api = importlib.import_module("openworkproof.schema_registry")

    for version, object_paths in schema_api._OBJECT_PATHS_BY_VERSION.items():
        assert "execution-environment" not in object_paths
        assert "execution-environment.schema.json" not in object_paths.values()
    assert "0.1" in schema_api._OBJECT_PATHS_BY_VERSION


def test_committed_runtime_and_spec_directories_match_generator() -> None:
    api = _api()
    generated = api.generated_companion_files()
    runtime = _runtime_directory()
    spec = _spec_directory()

    assert {path.name for path in runtime.iterdir()} == COMPANION_FILENAMES
    assert {path.name for path in spec.iterdir()} == COMPANION_FILENAMES
    for name in COMPANION_FILENAMES:
        runtime_bytes = runtime.joinpath(name).read_bytes()
        spec_bytes = spec.joinpath(name).read_bytes()
        assert runtime_bytes == generated[name]
        assert spec_bytes == generated[name]
        assert runtime_bytes == spec_bytes
        assert runtime_bytes == rfc8785.dumps(json.loads(runtime_bytes))


# --------------------------------------------------------------------------- #
# 3. target resolution and distinctness
# --------------------------------------------------------------------------- #


def test_same_destination_and_mirror_is_rejected(tmp_path: Path) -> None:
    api = _api()
    destination = tmp_path / "schemas"
    before = _write_old_set(destination)

    with pytest.raises(ValueError, match="conflict"):
        api.generate_companion_schemas(destination, mirror=destination)

    assert _snapshot(destination) == before


def test_nested_destination_and_mirror_is_rejected(tmp_path: Path) -> None:
    api = _api()
    destination = tmp_path / "schemas"

    with pytest.raises(ValueError, match="conflict"):
        api.generate_companion_schemas(
            destination,
            mirror=destination / "inner",
        )

    assert destination.exists() is False


def test_resolved_destination_and_mirror_alias_is_rejected() -> None:
    api = _api()
    completed = subprocess.run(
        ["mktemp", "-d"],
        check=True,
        capture_output=True,
        text=True,
    )
    root = Path(completed.stdout.strip())
    canonical_root = root.resolve()
    if canonical_root == root:
        root.rmdir()
        pytest.skip("mktemp path has no canonical ancestor alias")
    destination = root / "schemas"
    mirror = canonical_root / "schemas"

    try:
        with pytest.raises(ValueError, match="conflict"):
            api.generate_companion_schemas(destination, mirror=mirror)
        assert destination.exists() is False
    finally:
        root.rmdir()


# --------------------------------------------------------------------------- #
# 4. transaction failure injection
# --------------------------------------------------------------------------- #


def test_pre_commit_failure_leaves_both_targets_unchanged(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = _api()
    destination = tmp_path / "destination"
    mirror = tmp_path / "mirror"
    destination_before = _write_old_set(destination)
    mirror_before = _write_old_set(mirror)
    original_write_bytes = Path.write_bytes

    def fail_stage_write(path: Path, content: bytes) -> int:
        if path.parent.name.startswith(".openworkproof-companion-stage-"):
            raise OSError("simulated pre-commit stage write failure")
        return original_write_bytes(path, content)

    monkeypatch.setattr(Path, "write_bytes", fail_stage_write)

    with pytest.raises(OSError, match="pre-commit"):
        api.generate_companion_schemas(destination, mirror=mirror)

    assert _snapshot(destination) == destination_before
    assert _snapshot(mirror) == mirror_before
    assert _companion_artifacts(tmp_path) == set()


def test_second_target_commit_failure_rolls_back_both_targets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = _api()
    destination = tmp_path / "destination"
    mirror = tmp_path / "mirror"
    destination_before = _write_old_set(destination)
    mirror_before = _write_old_set(mirror)
    original_replace = Path.replace
    failed = False

    def fail_first_replace_to_mirror(source: Path, target: Path) -> Path:
        nonlocal failed
        if Path(target) == mirror and not failed:
            failed = True
            raise OSError("simulated mirror commit failure")
        return original_replace(source, target)

    monkeypatch.setattr(Path, "replace", fail_first_replace_to_mirror)

    with pytest.raises(OSError, match="simulated mirror commit failure"):
        api.generate_companion_schemas(destination, mirror=mirror)

    assert _snapshot(destination) == destination_before
    assert _snapshot(mirror) == mirror_before
    assert _companion_artifacts(tmp_path) == set()


def test_commit_ack_loss_is_resolved_by_exact_readback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = _api()
    destination = tmp_path / "destination"
    mirror = tmp_path / "mirror"
    _write_old_set(destination)
    _write_old_set(mirror)
    original_replace = Path.replace
    acked = False

    def replace_but_lose_ack(source: Path, target: Path) -> Path:
        nonlocal acked
        result = original_replace(source, target)
        if Path(target) == mirror and not acked:
            acked = True
            raise OSError("simulated COMMIT ACK loss")
        return result

    monkeypatch.setattr(Path, "replace", replace_but_lose_ack)

    # The mirror replace actually landed but reported an error; the exact
    # readback must recognise the commit and finish cleanly, leaving both
    # targets in the new state.
    api.generate_companion_schemas(destination, mirror=mirror)

    assert acked is True
    assert _snapshot(destination) == _builtin_bytes()
    assert _snapshot(mirror) == _builtin_bytes()
    assert _companion_artifacts(tmp_path) == set()


def test_persistent_backup_cleanup_failure_reports_committed_and_recovers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = _api()
    destination = tmp_path / "destination"
    mirror = tmp_path / "mirror"
    _write_old_set(destination)
    _write_old_set(mirror)
    original_unlink = Path.unlink

    def fail_backup_unlink(path: Path, *args, **kwargs) -> None:
        if path.parent.name.startswith(".openworkproof-companion-backup-"):
            raise OSError("simulated persistent backup cleanup failure")
        original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", fail_backup_unlink)

    with pytest.raises(api.CompanionSchemaCleanupError) as captured:
        api.generate_companion_schemas(destination, mirror=mirror)

    error = captured.value
    assert error.committed is True
    assert error.backup_paths
    assert not error.stage_paths
    assert _snapshot(destination) == _builtin_bytes()
    assert _snapshot(mirror) == _builtin_bytes()
    assert not any(
        name.startswith(".openworkproof-companion-stage-")
        for name in _companion_artifacts(tmp_path)
    )

    monkeypatch.setattr(Path, "unlink", original_unlink)
    api.generate_companion_schemas(destination, mirror=mirror)

    assert _snapshot(destination) == _builtin_bytes()
    assert _snapshot(mirror) == _builtin_bytes()
    assert _companion_artifacts(tmp_path) == set()


def test_rollback_truth_is_all_old_or_all_new(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = _api()
    destination = tmp_path / "destination"
    mirror = tmp_path / "mirror"
    destination_before = _write_old_set(destination)
    mirror_before = _write_old_set(mirror)
    original_replace = Path.replace
    failed = False

    def fail_second_commit(source: Path, target: Path) -> Path:
        nonlocal failed
        if Path(target) == mirror and not failed:
            failed = True
            raise OSError("simulated second commit failure")
        return original_replace(source, target)

    monkeypatch.setattr(Path, "replace", fail_second_commit)

    with pytest.raises(OSError):
        api.generate_companion_schemas(destination, mirror=mirror)

    # Rollback truth: after any failure, each target is either entirely old or
    # entirely new, never a mixed or partial state.
    for directory, before in (
        (destination, destination_before),
        (mirror, mirror_before),
    ):
        snapshot = _snapshot(directory)
        assert snapshot in (before, _builtin_bytes())
        assert snapshot == before

    assert _companion_artifacts(tmp_path) == set()


def test_silent_stage_corruption_is_rejected_before_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = _api()
    destination = tmp_path / "destination"
    mirror = tmp_path / "mirror"
    destination_before = _write_old_set(destination)
    mirror_before = _write_old_set(mirror)
    original_write_bytes = Path.write_bytes

    def corrupt_stage_write(path: Path, content: bytes) -> int:
        if path.parent.name.startswith(".openworkproof-companion-stage-"):
            return original_write_bytes(path, b"{}")
        return original_write_bytes(path, content)

    monkeypatch.setattr(Path, "write_bytes", corrupt_stage_write)

    with pytest.raises(RuntimeError, match="staging verification"):
        api.generate_companion_schemas(destination, mirror=mirror)

    assert _snapshot(destination) == destination_before
    assert _snapshot(mirror) == mirror_before
    assert _companion_artifacts(tmp_path) == set()


def test_final_readback_tamper_rolls_back_both_targets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = _api()
    destination = tmp_path / "destination"
    mirror = tmp_path / "mirror"
    destination_before = _write_old_set(destination)
    mirror_before = _write_old_set(mirror)
    original_read_bytes = Path.read_bytes

    def tamper_target_readback(path: Path) -> bytes:
        if path.parent.name in {"destination", "mirror"}:
            return b"tampered"
        return original_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", tamper_target_readback)

    with pytest.raises(RuntimeError, match="commit readback"):
        api.generate_companion_schemas(destination, mirror=mirror)

    monkeypatch.setattr(Path, "read_bytes", original_read_bytes)

    assert _snapshot(destination) == destination_before
    assert _snapshot(mirror) == mirror_before
    assert _companion_artifacts(tmp_path) == set()


def test_no_leftover_stage_or_backup_artifacts(tmp_path: Path) -> None:
    api = _api()
    destination = tmp_path / "destination"
    mirror = tmp_path / "mirror"

    api.generate_companion_schemas(destination, mirror=mirror)

    assert _companion_artifacts(tmp_path) == set()
    locks = tuple(
        path
        for path in tmp_path.iterdir()
        if path.name.startswith(COMPANION_LOCK_PREFIX)
    )
    assert len(locks) == 2
    assert all(
        path.is_file()
        and not path.is_symlink()
        and path.stat().st_size == 0
        for path in locks
    )


# --------------------------------------------------------------------------- #
# 5. CLI and packaging
# --------------------------------------------------------------------------- #


def test_cli_invocation_generates_both_directories(tmp_path: Path) -> None:
    api = _api()
    destination = tmp_path / "src/openworkproof/schemas/companion-v0.1"
    mirror = tmp_path / "specs/companion-v0.1"

    assert api.main(
        ["--destination", str(destination), "--mirror", str(mirror)]
    ) == 0

    assert {path.name for path in destination.iterdir()} == COMPANION_FILENAMES
    assert _snapshot(destination) == _snapshot(mirror)


def test_built_wheel_contains_exactly_companion_schema_resources(
    built_companion_wheel: Path,
) -> None:
    api = _api()
    with zipfile.ZipFile(built_companion_wheel) as archive:
        prefix = "openworkproof/schemas/companion-v0.1/"
        members = {
            name.removeprefix(prefix)
            for name in archive.namelist()
            if name.startswith(prefix) and not name.endswith("/")
        }
        assert members == COMPANION_FILENAMES
        for name, expected_digest in (
            (
                "schema-registry.json",
                hashlib.sha256(
                    api.generated_companion_files()["schema-registry.json"]
                ).hexdigest(),
            ),
            (
                "execution-environment.schema.json",
                hashlib.sha256(
                    api.generated_companion_files()[
                        "execution-environment.schema.json"
                    ]
                ).hexdigest(),
            ),
            (
                "verification-report.schema.json",
                hashlib.sha256(
                    api.generated_companion_files()[
                        "verification-report.schema.json"
                    ]
                ).hexdigest(),
            ),
        ):
            content = archive.read(f"{prefix}{name}")
            assert hashlib.sha256(content).hexdigest() == expected_digest
