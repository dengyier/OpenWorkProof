"""Authoritative, packaged, deterministic v0.1 schema registry tests."""

from __future__ import annotations

import hashlib
import importlib
import json
import os
from importlib import resources
from pathlib import Path
import shutil
import subprocess
import sys
import zipfile

import pytest
import rfc8785

from openworkproof.models import (
    ACTION_RECEIPT_ADAPTER,
    AcceptanceReceipt,
    CapabilityGrant,
    WorkOrder,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_FILENAMES = frozenset(
    {
        "schema-registry.json",
        "work-order.schema.json",
        "capability-grant.schema.json",
        "action-receipt.schema.json",
        "acceptance-receipt.schema.json",
        "acceptance-rejection-receipt.schema.json",
    }
)
OBJECT_PATHS = {
    "acceptance-receipt": "acceptance-receipt.schema.json",
    "acceptance-rejection-receipt": (
        "acceptance-rejection-receipt.schema.json"
    ),
    "action-receipt": "action-receipt.schema.json",
    "capability-grant": "capability-grant.schema.json",
    "work-order": "work-order.schema.json",
}
FROZEN_V01_DIGESTS = {
    "acceptance-receipt.schema.json": (
        "5436e77e03d64cf131f2273b7527e63aa854f9c3de7b60aeae8751024267ff0e"
    ),
    "acceptance-rejection-receipt.schema.json": (
        "cab320167c5af36afcc06506d13cbaa85c3dd9f6b470c4db12d127726fa86ae8"
    ),
    "action-receipt.schema.json": (
        "1aba0e2a9cf3b55478d5def0ef7f89d84976fc22798bb6d709d21afb31cedde8"
    ),
    "capability-grant.schema.json": (
        "f7c01f4ed227954f6310fd03ab5cbf52916510971c01c7f22ff9115e358cd17e"
    ),
    "schema-registry.json": (
        "b543abb2d972a84d3fffe97e6f9381f33b5cfe40fe0c8c7c046f91354f849000"
    ),
    "work-order.schema.json": (
        "171b59390c66d586d7ee387d783ca8bc759779a08c36d31c85cf232998568013"
    ),
}
TRANSACTION_PREFIXES = (
    ".openworkproof-schema-backup-",
    ".openworkproof-schema-stage-",
)
LOCK_PREFIX = ".openworkproof-schema-lock-"


def _api():
    return importlib.import_module("openworkproof.schema_registry")


def _builtin_directory():
    return resources.files("openworkproof").joinpath("schemas", "v0.1")


def _builtin_bytes() -> dict[str, bytes]:
    directory = _builtin_directory()
    return {name: directory.joinpath(name).read_bytes() for name in SCHEMA_FILENAMES}


def _copy_builtin_schemas(destination: Path) -> Path:
    destination.mkdir()
    for name, content in _builtin_bytes().items():
        destination.joinpath(name).write_bytes(content)
    return destination


def _snapshot(directory: Path) -> dict[str, bytes]:
    return {
        path.name: path.read_bytes()
        for path in directory.iterdir()
        if path.is_file()
    }


def _write_old_schema_set(directory: Path) -> dict[str, bytes]:
    directory.mkdir()
    for name in SCHEMA_FILENAMES:
        directory.joinpath(name).write_bytes(f"old:{name}".encode())
    return _snapshot(directory)


def _schema_transaction_artifacts(parent: Path) -> set[str]:
    return {
        path.name
        for path in parent.iterdir()
        if path.name.startswith(TRANSACTION_PREFIXES)
    }


def _remove_generated_directory(directory: Path) -> None:
    if not directory.exists():
        return
    for name in SCHEMA_FILENAMES:
        path = directory / name
        if path.is_file() and not path.is_symlink():
            path.unlink()
    directory.rmdir()


def _use_fake_runtime_authority(
    api,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Path:
    root = tmp_path / "fake-package"
    directory = root / "schemas" / "v0.1"
    directory.mkdir(parents=True)
    for name, content in _builtin_bytes().items():
        directory.joinpath(name).write_bytes(content)
    monkeypatch.setattr(api.resources, "files", lambda package: root)
    return directory


@pytest.fixture(scope="module")
def built_wheel(tmp_path_factory: pytest.TempPathFactory) -> Path:
    workspace = tmp_path_factory.mktemp("schema-wheel")
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


def test_package_and_published_mirror_match_frozen_v01_anchors() -> None:
    package = _builtin_directory()
    mirror = PROJECT_ROOT / "specs" / "v0.1"

    assert {item.name for item in package.iterdir()} == SCHEMA_FILENAMES
    assert {item.name for item in mirror.iterdir()} == SCHEMA_FILENAMES
    for filename, expected_digest in FROZEN_V01_DIGESTS.items():
        package_bytes = package.joinpath(filename).read_bytes()
        mirror_bytes = mirror.joinpath(filename).read_bytes()
        assert package_bytes == mirror_bytes
        assert hashlib.sha256(package_bytes).hexdigest() == expected_digest
        assert package_bytes == rfc8785.dumps(json.loads(package_bytes))


def test_current_generators_match_frozen_v01_schema_anchors() -> None:
    api = _api()
    generated = {
        "acceptance-receipt": AcceptanceReceipt.model_json_schema(),
        "action-receipt": ACTION_RECEIPT_ADAPTER.json_schema(),
        "capability-grant": CapabilityGrant.model_json_schema(),
        "work-order": WorkOrder.model_json_schema(),
    }

    for object_type, schema in generated.items():
        filename = OBJECT_PATHS[object_type]
        generated_bytes = rfc8785.dumps(schema)
        assert hashlib.sha256(generated_bytes).hexdigest() == (
            FROZEN_V01_DIGESTS[filename]
        )
        assert api.authoritative_schema(object_type) == schema
        assert api.authoritative_digest(object_type) == (
            FROZEN_V01_DIGESTS[filename]
        )


def test_registry_has_a_closed_non_recursive_digest_manifest() -> None:
    registry_bytes = _builtin_directory().joinpath(
        "schema-registry.json"
    ).read_bytes()
    registry = json.loads(registry_bytes)
    expected_entries = [
        {
            "object_type": object_type,
            "path": path,
            "sha256": FROZEN_V01_DIGESTS[path],
        }
        for object_type, path in OBJECT_PATHS.items()
    ]

    assert registry_bytes == rfc8785.dumps(registry)
    assert registry == {
        "schema_version": "openworkproof-schema-registry/0.1",
        "protocol_version": "0.1",
        "schemas": expected_entries,
    }
    assert "schema-registry.json" not in {
        entry["path"] for entry in registry["schemas"]
    }
    assert hashlib.sha256(registry_bytes).hexdigest() == (
        FROZEN_V01_DIGESTS["schema-registry.json"]
    )


@pytest.mark.parametrize(
    "mutation",
    ("extra", "missing", "noncanonical", "joint_drift"),
)
def test_runtime_authority_validates_entire_frozen_resource_set_before_parse(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    api = _api()
    directory = _use_fake_runtime_authority(api, tmp_path, monkeypatch)

    if mutation == "extra":
        directory.joinpath("extra.schema.json").write_bytes(b"{}")
    elif mutation == "missing":
        directory.joinpath("acceptance-receipt.schema.json").unlink()
    elif mutation == "noncanonical":
        path = directory / "acceptance-receipt.schema.json"
        path.write_bytes(path.read_bytes() + b"\n")
    else:
        path = directory / "work-order.schema.json"
        schema = json.loads(path.read_bytes())
        schema["required"].remove("objective")
        loosened = rfc8785.dumps(schema)
        path.write_bytes(loosened)
        registry_path = directory / "schema-registry.json"
        registry = json.loads(registry_path.read_bytes())
        entry = next(
            item
            for item in registry["schemas"]
            if item["object_type"] == "work-order"
        )
        entry["sha256"] = hashlib.sha256(loosened).hexdigest()
        registry_path.write_bytes(rfc8785.dumps(registry))

    with pytest.raises(RuntimeError, match="authoritative schema"):
        api.authoritative_schema("work-order")


def test_unknown_version_and_object_type_fail_closed(tmp_path: Path) -> None:
    api = _api()

    for function in (api.authoritative_schema, api.authoritative_digest):
        with pytest.raises(ValueError, match="unknown protocol version"):
            function("work-order", version="0.2")
        with pytest.raises(ValueError, match="unknown object type"):
            function("arbitrary-object")

    result = api.compare_bundle_schemas_to_builtin(tmp_path, version="0.2")
    assert result.valid is False
    assert result.error_code == "UNKNOWN_PROTOCOL_VERSION"


def test_v01_registry_routing_is_closed_and_explicit() -> None:
    api = _api()

    assert api._OBJECT_PATHS_BY_VERSION == {"0.1": OBJECT_PATHS}
    assert set(api._SCHEMA_FACTORIES_BY_VERSION) == {"0.1"}
    assert set(api._SCHEMA_FACTORIES_BY_VERSION["0.1"]) == set(OBJECT_PATHS)
    assert set(api._generated_files(version="0.1")) == SCHEMA_FILENAMES


def test_v02_is_unregistered_before_complete_schema_freeze(tmp_path: Path) -> None:
    api = _api()
    destination = tmp_path / "v02"

    with pytest.raises(ValueError, match="unknown protocol version"):
        api.write_authoritative_schemas(
            destination,
            version="0.2",
        )

    assert destination.exists() is False


def test_cli_requires_explicit_registered_version_and_destination(
    tmp_path: Path,
) -> None:
    api = _api()
    destination = tmp_path / "v01"

    assert api.main(
        [
            "--version",
            "0.1",
            "--destination",
            str(destination),
        ]
    ) == 0
    assert set(_snapshot(destination)) == SCHEMA_FILENAMES

    missing_version = tmp_path / "missing-version"
    with pytest.raises(SystemExit):
        api.main(["--destination", str(missing_version)])
    assert missing_version.exists() is False

    unknown_version = tmp_path / "unknown-version"
    with pytest.raises(SystemExit):
        api.main(
            [
                "--version",
                "0.2",
                "--destination",
                str(unknown_version),
            ]
        )
    assert unknown_version.exists() is False


def test_runtime_authority_is_independent_of_current_working_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = _api()
    expected = api.authoritative_schema("work-order")
    elsewhere = tmp_path / "unrelated"
    elsewhere.mkdir()

    monkeypatch.chdir(elsewhere)

    assert api.authoritative_schema("work-order") == expected
    assert api.authoritative_digest("work-order") == (
        FROZEN_V01_DIGESTS["work-order.schema.json"]
    )


def test_wider_bundle_schema_cannot_override_builtin_authority(
    tmp_path: Path,
) -> None:
    api = _api()
    copied = _copy_builtin_schemas(tmp_path / "schemas")
    path = copied / "work-order.schema.json"
    schema = json.loads(path.read_bytes())
    schema["required"].remove("objective")
    path.write_bytes(rfc8785.dumps(schema))

    result = api.compare_bundle_schemas_to_builtin(copied, version="0.1")

    assert result.valid is False
    assert result.error_code == "AUTHORITATIVE_SCHEMA_MISMATCH"


@pytest.mark.parametrize(
    "mutation",
    ("extra", "missing", "directory", "symlink"),
)
def test_bundle_schema_set_must_be_exact_regular_files(
    tmp_path: Path,
    mutation: str,
) -> None:
    api = _api()
    copied = _copy_builtin_schemas(tmp_path / "schemas")
    target = copied / "work-order.schema.json"

    if mutation == "extra":
        (copied / "extra.schema.json").write_bytes(b"{}")
    elif mutation == "missing":
        target.unlink()
    elif mutation == "directory":
        target.unlink()
        target.mkdir()
    else:
        content = target.read_bytes()
        target.unlink()
        external = tmp_path / "external.schema.json"
        external.write_bytes(content)
        target.symlink_to(external)

    result = api.compare_bundle_schemas_to_builtin(copied, version="0.1")

    assert result.valid is False
    assert result.error_code == "AUTHORITATIVE_SCHEMA_MISMATCH"


def test_writer_and_cli_emit_exact_repeatable_package_and_mirror_bytes(
    tmp_path: Path,
) -> None:
    api = _api()
    package = tmp_path / "package"
    mirror = tmp_path / "mirror"

    assert api.main(
        [
            "--version",
            "0.1",
            "--destination",
            str(package),
            "--mirror",
            str(mirror),
        ]
    ) == 0
    first_package = {
        path.name: path.read_bytes() for path in package.iterdir()
    }
    first_mirror = {path.name: path.read_bytes() for path in mirror.iterdir()}
    assert set(first_package) == SCHEMA_FILENAMES
    assert first_mirror == first_package

    api.write_authoritative_schemas(package, mirror=mirror)

    assert {path.name: path.read_bytes() for path in package.iterdir()} == (
        first_package
    )
    assert {path.name: path.read_bytes() for path in mirror.iterdir()} == (
        first_mirror
    )


def test_cli_accepts_real_macos_mktemp_parent() -> None:
    api = _api()
    completed = subprocess.run(
        ["mktemp", "-d"],
        check=True,
        capture_output=True,
        text=True,
    )
    root = Path(completed.stdout.strip())
    package = root / "package"
    mirror = root / "mirror"

    try:
        assert api.main(
            [
                "--version",
                "0.1",
                "--destination",
                str(package),
                "--mirror",
                str(mirror),
            ]
        ) == 0
        assert set(_snapshot(package)) == SCHEMA_FILENAMES
        assert _snapshot(mirror) == _snapshot(package)
    finally:
        _remove_generated_directory(package)
        _remove_generated_directory(mirror)
        for artifact in tuple(root.iterdir()):
            if artifact.name.startswith(TRANSACTION_PREFIXES):
                _remove_generated_directory(artifact)
            elif (
                artifact.name.startswith(LOCK_PREFIX)
                and artifact.is_file()
                and not artifact.is_symlink()
            ):
                artifact.unlink()
        root.rmdir()


def test_resolved_destination_and_mirror_conflict_is_rejected() -> None:
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
            api.write_authoritative_schemas(destination, mirror=mirror)
        assert destination.exists() is False
    finally:
        root.rmdir()


def test_generator_drift_is_rejected_before_creating_either_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = _api()
    loosened = WorkOrder.model_json_schema()
    loosened["required"].remove("objective")
    monkeypatch.setitem(
        api._SCHEMA_FACTORIES,
        "work-order",
        lambda: loosened,
    )
    destination = tmp_path / "destination"
    mirror = tmp_path / "mirror"

    with pytest.raises(RuntimeError, match="frozen v0.1 schema drift"):
        api.write_authoritative_schemas(destination, mirror=mirror)

    assert destination.exists() is False
    assert mirror.exists() is False


@pytest.mark.parametrize(
    "invalid_mirror",
    ("file", "symlink", "parent_file", "parent_symlink"),
)
def test_invalid_mirror_preflight_leaves_destination_byte_for_byte_unchanged(
    tmp_path: Path,
    invalid_mirror: str,
) -> None:
    api = _api()
    destination = tmp_path / "destination"
    before = _write_old_schema_set(destination)
    mirror = tmp_path / "mirror"
    if invalid_mirror == "file":
        mirror.write_bytes(b"not a directory")
    elif invalid_mirror == "symlink":
        target = tmp_path / "mirror-target"
        target.mkdir()
        mirror.symlink_to(target, target_is_directory=True)
    elif invalid_mirror == "parent_file":
        parent = tmp_path / "mirror-parent"
        parent.write_bytes(b"not a directory")
        mirror = parent / "mirror"
    else:
        parent_target = tmp_path / "mirror-parent-target"
        parent_target.mkdir()
        parent = tmp_path / "mirror-parent"
        parent.symlink_to(parent_target, target_is_directory=True)
        mirror = parent / "mirror"

    with pytest.raises((OSError, ValueError)):
        api.write_authoritative_schemas(destination, mirror=mirror)

    assert _snapshot(destination) == before


def test_writer_rejects_conflicting_targets_without_mutation(
    tmp_path: Path,
) -> None:
    api = _api()
    destination = tmp_path / "schemas"
    before = _write_old_schema_set(destination)

    with pytest.raises(ValueError, match="conflict"):
        api.write_authoritative_schemas(destination, mirror=destination)

    assert _snapshot(destination) == before


def test_second_target_commit_failure_rolls_back_both_targets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = _api()
    destination = tmp_path / "destination"
    mirror = tmp_path / "mirror"
    destination_before = _write_old_schema_set(destination)
    mirror_before = _write_old_schema_set(mirror)
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
        api.write_authoritative_schemas(destination, mirror=mirror)

    assert _snapshot(destination) == destination_before
    assert _snapshot(mirror) == mirror_before


def test_second_stage_write_failure_cleans_unreturned_stage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = _api()
    destination = tmp_path / "destination"
    mirror = tmp_path / "mirror"
    original_write_bytes = Path.write_bytes
    stage_writes = 0

    def fail_second_stage_write(path: Path, content: bytes) -> int:
        nonlocal stage_writes
        if path.parent.name.startswith(".openworkproof-schema-stage-"):
            stage_writes += 1
            if stage_writes == 2:
                raise OSError("simulated second stage write failure")
        return original_write_bytes(path, content)

    monkeypatch.setattr(Path, "write_bytes", fail_second_stage_write)

    with pytest.raises(OSError, match="simulated second stage write failure"):
        api.write_authoritative_schemas(destination, mirror=mirror)

    assert stage_writes == 2
    assert destination.exists() is False
    assert mirror.exists() is False
    assert _schema_transaction_artifacts(tmp_path) == set()


def test_one_shot_backup_cleanup_failure_is_retried_after_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = _api()
    destination = tmp_path / "destination"
    mirror = tmp_path / "mirror"
    _write_old_schema_set(destination)
    _write_old_schema_set(mirror)
    original_unlink = Path.unlink
    failed = False

    def fail_one_backup_unlink(
        path: Path,
        *args,
        **kwargs,
    ) -> None:
        nonlocal failed
        if (
            path.parent.name.startswith(".openworkproof-schema-backup-")
            and not failed
        ):
            failed = True
            raise OSError("simulated one-shot backup cleanup failure")
        original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", fail_one_backup_unlink)

    api.write_authoritative_schemas(destination, mirror=mirror)

    assert failed is True
    assert _snapshot(destination) == _builtin_bytes()
    assert _snapshot(mirror) == _builtin_bytes()
    assert _schema_transaction_artifacts(tmp_path) == set()


def test_persistent_backup_cleanup_failure_reports_committed_and_recovers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = _api()
    destination = tmp_path / "destination"
    mirror = tmp_path / "mirror"
    _write_old_schema_set(destination)
    _write_old_schema_set(mirror)
    original_unlink = Path.unlink

    def fail_backup_unlink(
        path: Path,
        *args,
        **kwargs,
    ) -> None:
        if path.parent.name.startswith(
            ".openworkproof-schema-backup-"
        ):
            raise OSError("simulated persistent backup cleanup failure")
        original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", fail_backup_unlink)

    with pytest.raises(api.SchemaCleanupError) as captured:
        api.write_authoritative_schemas(destination, mirror=mirror)

    error = captured.value
    assert error.committed is True
    assert set(error.backup_paths) == {
        tmp_path / name
        for name in _schema_transaction_artifacts(tmp_path)
        if name.startswith(".openworkproof-schema-backup-")
    }
    assert error.backup_paths
    assert _snapshot(destination) == _builtin_bytes()
    assert _snapshot(mirror) == _builtin_bytes()
    assert not any(
        name.startswith(".openworkproof-schema-stage-")
        for name in _schema_transaction_artifacts(tmp_path)
    )

    monkeypatch.setattr(Path, "unlink", original_unlink)
    api.write_authoritative_schemas(destination, mirror=mirror)

    assert _snapshot(destination) == _builtin_bytes()
    assert _snapshot(mirror) == _builtin_bytes()
    assert _schema_transaction_artifacts(tmp_path) == set()


def test_concurrent_cross_process_writers_serialize_by_resolved_targets(
    tmp_path: Path,
) -> None:
    destination = tmp_path / "destination"
    mirror = tmp_path / "mirror"
    start = tmp_path / "start"
    process_count = 12
    script = """
import pathlib
import sys
import time

start = pathlib.Path(sys.argv[1])
while not start.exists():
    time.sleep(0.001)

import openworkproof.schema_registry as api

original_stage = api._stage_schema_directory
def delayed_stage(target, files):
    stage = original_stage(target, files)
    time.sleep(0.03)
    return stage

api._stage_schema_directory = delayed_stage
raise SystemExit(api.main([
    "--version", "0.1",
    "--destination", sys.argv[2],
    "--mirror", sys.argv[3],
]))
"""
    environment = {
        **os.environ,
        "PYTHONPATH": str(PROJECT_ROOT / "src"),
    }
    processes = []
    for index in range(process_count):
        first, second = (
            (destination, mirror)
            if index % 2 == 0
            else (mirror, destination)
        )
        processes.append(
            subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    script,
                    str(start),
                    str(first),
                    str(second),
                ],
                cwd=PROJECT_ROOT,
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        )
    start.write_bytes(b"go")

    results = []
    try:
        for process in processes:
            stdout, stderr = process.communicate(timeout=30)
            results.append((process.returncode, stdout, stderr))
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
                process.wait()

    failures = [
        f"returncode={returncode}\nstdout={stdout}\nstderr={stderr}"
        for returncode, stdout, stderr in results
        if returncode != 0
    ]
    assert failures == []
    assert _snapshot(destination) == _builtin_bytes()
    assert _snapshot(mirror) == _builtin_bytes()
    assert _schema_transaction_artifacts(tmp_path) == set()
    locks = tuple(
        path
        for path in tmp_path.iterdir()
        if path.name.startswith(LOCK_PREFIX)
    )
    assert len(locks) == 2
    assert all(
        path.is_file()
        and not path.is_symlink()
        and path.stat().st_size == 0
        for path in locks
    )


def test_symlink_lock_file_is_rejected_without_touching_its_target(
    tmp_path: Path,
) -> None:
    api = _api()
    destination = tmp_path / "destination"
    lock_path = api._lock_path(destination)
    attacker_target = tmp_path / "attacker-target"
    attacker_target.write_bytes(b"must remain unchanged")
    lock_path.symlink_to(attacker_target)

    with pytest.raises(ValueError, match="lock"):
        api.write_authoritative_schemas(destination)

    assert destination.exists() is False
    assert attacker_target.read_bytes() == b"must remain unchanged"
    assert lock_path.is_symlink()


def test_built_wheel_contains_all_authoritative_schema_resources(
    built_wheel: Path,
) -> None:
    with zipfile.ZipFile(built_wheel) as archive:
        members = {
            name.removeprefix("openworkproof/schemas/v0.1/")
            for name in archive.namelist()
            if name.startswith("openworkproof/schemas/v0.1/")
            and not name.endswith("/")
        }
        assert members == SCHEMA_FILENAMES
        for name, expected_digest in FROZEN_V01_DIGESTS.items():
            content = archive.read(f"openworkproof/schemas/v0.1/{name}")
            assert hashlib.sha256(content).hexdigest() == expected_digest


def test_registry_loads_from_an_installed_wheel_outside_project_cwd(
    built_wheel: Path,
    tmp_path: Path,
) -> None:
    installed = tmp_path / "installed"
    subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--no-deps",
            "--target",
            str(installed),
            str(built_wheel),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    script = """
import pathlib
import sys
sys.path.insert(0, sys.argv[1])
import openworkproof
from openworkproof.schema_registry import authoritative_schema
package = pathlib.Path(openworkproof.__file__).resolve()
assert package.is_relative_to(pathlib.Path(sys.argv[1]).resolve())
assert authoritative_schema("work-order")["type"] == "object"
"""
    subprocess.run(
        [sys.executable, "-c", script, str(installed)],
        cwd=cwd,
        env={**os.environ, "PYTHONPATH": ""},
        check=True,
        capture_output=True,
        text=True,
    )
