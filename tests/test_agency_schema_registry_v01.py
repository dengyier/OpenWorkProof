"""Independent human agency (0.1) schema registry tests.

The agency registry packages the three closed, Acceptor-signed protocol object
schemas (human-agency-profile, agency-profile-transition, agency-appeal)
*beside* the frozen v0.1-v0.5 protocol registry and the companion registry. It
must never mutate any frozen protocol anchor: every existing v0.1-v0.5 digest
and the main ``schema-registry.json`` stay byte-for-byte identical.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import zipfile

import pytest
import rfc8785

from openworkproof.agency import (
    AgencyAppealV01,
    AgencyProfileTransitionV01,
    HumanAgencyProfileV01,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
AGENCY_VERSION = "0.1"
AGENCY_REGISTRY_SCHEMA_VERSION = "openworkproof-agency-schema-registry/0.1"
AGENCY_FILENAMES = frozenset(
    {
        "schema-registry.json",
        "human-agency-profile.schema.json",
        "agency-profile-transition.schema.json",
        "agency-appeal.schema.json",
    }
)
AGENCY_OBJECT_PATHS = {
    "human-agency-profile": "human-agency-profile.schema.json",
    "agency-profile-transition": "agency-profile-transition.schema.json",
    "agency-appeal": "agency-appeal.schema.json",
}
AGENCY_SCHEMA_FACTORIES = {
    "human-agency-profile": HumanAgencyProfileV01.model_json_schema,
    "agency-profile-transition": (
        AgencyProfileTransitionV01.model_json_schema
    ),
    "agency-appeal": AgencyAppealV01.model_json_schema,
}
AGENCY_TRANSACTION_PREFIXES = (
    ".openworkproof-agency-backup-",
    ".openworkproof-agency-stage-",
)
AGENCY_LOCK_PREFIX = ".openworkproof-agency-lock-"


def _api():
    return importlib.import_module("openworkproof.agency_schema_registry")


def _runtime_directory() -> Path:
    return PROJECT_ROOT / "src/openworkproof/schemas/agency-v0.1"


def _builtin_bytes() -> dict[str, bytes]:
    directory = _runtime_directory()
    return {
        name: directory.joinpath(name).read_bytes()
        for name in AGENCY_FILENAMES
    }


def _snapshot(directory: Path) -> dict[str, bytes]:
    return {
        path.name: path.read_bytes()
        for path in directory.iterdir()
        if path.is_file()
    }


def _write_old_set(directory: Path) -> dict[str, bytes]:
    directory.mkdir()
    for name in AGENCY_FILENAMES:
        directory.joinpath(name).write_bytes(f"old:{name}".encode())
    return _snapshot(directory)


def _agency_artifacts(parent: Path) -> set[str]:
    return {
        path.name
        for path in parent.iterdir()
        if path.name.startswith(AGENCY_TRANSACTION_PREFIXES)
    }


def _remove_generated_directory(directory: Path) -> None:
    if not directory.exists():
        return
    for name in AGENCY_FILENAMES:
        path = directory / name
        if path.is_file() and not path.is_symlink():
            path.unlink()
    directory.rmdir()


@pytest.fixture(scope="module")
def built_agency_wheel(tmp_path_factory: pytest.TempPathFactory) -> Path:
    workspace = tmp_path_factory.mktemp("agency-wheel")
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
# 1. deterministic, canonical generation and packaged-byte parity
# --------------------------------------------------------------------------- #


def test_agency_generation_is_deterministic(tmp_path: Path) -> None:
    api = _api()
    first = tmp_path / "first"
    second = tmp_path / "second"

    api.generate_agency_schemas(first)
    api.generate_agency_schemas(second)

    assert _snapshot(first) == _snapshot(second)


def test_generated_bytes_match_packaged_bytes_exactly(tmp_path: Path) -> None:
    api = _api()
    destination = tmp_path / "destination"

    api.generate_agency_schemas(destination)

    assert _snapshot(destination) == _builtin_bytes()


def test_exact_complete_file_set(tmp_path: Path) -> None:
    api = _api()
    destination = tmp_path / "destination"

    api.generate_agency_schemas(destination)

    assert {path.name for path in destination.iterdir()} == AGENCY_FILENAMES
    assert set(api.generated_agency_files()) == AGENCY_FILENAMES
    assert set(api.OBJECT_PATHS) == set(AGENCY_OBJECT_PATHS)
    assert api.AGENCY_VERSION == AGENCY_VERSION


def test_registry_entries_are_utf8_sorted_with_exact_sha256() -> None:
    api = _api()
    files = api.generated_agency_files()

    assert files["schema-registry.json"] == rfc8785.dumps(
        json.loads(files["schema-registry.json"])
    )
    for name in AGENCY_OBJECT_PATHS.values():
        assert files[name] == rfc8785.dumps(json.loads(files[name]))

    for object_type, factory in AGENCY_SCHEMA_FACTORIES.items():
        path = AGENCY_OBJECT_PATHS[object_type]
        assert files[path] == rfc8785.dumps(
            api._harden_agency_schema(factory(), object_type=object_type)
        )

    registry = json.loads(files["schema-registry.json"])
    assert registry == {
        "schema_version": AGENCY_REGISTRY_SCHEMA_VERSION,
        "protocol_version": AGENCY_VERSION,
        "schemas": [
            {
                "object_type": object_type,
                "path": AGENCY_OBJECT_PATHS[object_type],
                "sha256": hashlib.sha256(
                    files[AGENCY_OBJECT_PATHS[object_type]]
                ).hexdigest(),
            }
            for object_type in sorted(AGENCY_OBJECT_PATHS)
        ],
    }
    assert [entry["object_type"] for entry in registry["schemas"]] == sorted(
        AGENCY_OBJECT_PATHS
    )
    assert "schema-registry.json" not in {
        entry["path"] for entry in registry["schemas"]
    }


def test_authoritative_agency_schema_returns_canonical_bytes() -> None:
    api = _api()

    for object_type, factory in AGENCY_SCHEMA_FACTORIES.items():
        assert api.authoritative_agency_schema(object_type) == rfc8785.dumps(
            api._harden_agency_schema(factory(), object_type=object_type)
        )
        assert api.authoritative_agency_schema(object_type) == (
            _runtime_directory() / AGENCY_OBJECT_PATHS[object_type]
        ).read_bytes()


def test_unknown_object_type_fails_closed() -> None:
    api = _api()

    for unknown in (
        "agency-bundle",
        "work-order",
        "human-agency-profile-extra",
        "",
    ):
        with pytest.raises(ValueError, match="unknown object type"):
            api.authoritative_agency_schema(unknown)


def test_verify_packaged_agency_schemas_succeeds() -> None:
    api = _api()

    assert api.verify_packaged_agency_schemas() is None


def test_verify_packaged_agency_schemas_rejects_corruption(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = _api()
    root = tmp_path / "fake-package"
    directory = root / "schemas" / "agency-v0.1"
    directory.mkdir(parents=True)
    for name, content in _builtin_bytes().items():
        directory.joinpath(name).write_bytes(content)
    monkeypatch.setattr(api.resources, "files", lambda package: root)

    assert api.verify_packaged_agency_schemas() is None

    # Tamper one packaged object byte without touching the registry: the
    # verifier must detect the drift against the generated anchors.
    profile = directory / "human-agency-profile.schema.json"
    schema = json.loads(profile.read_bytes())
    schema["required"].remove("work_order_digest")
    profile.write_bytes(rfc8785.dumps(schema))

    with pytest.raises(RuntimeError, match="agency"):
        api.verify_packaged_agency_schemas()


def test_verify_packaged_agency_schemas_rejects_missing_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = _api()
    root = tmp_path / "fake-package"
    directory = root / "schemas" / "agency-v0.1"
    directory.mkdir(parents=True)
    for name, content in _builtin_bytes().items():
        directory.joinpath(name).write_bytes(content)
    (directory / "agency-appeal.schema.json").unlink()
    monkeypatch.setattr(api.resources, "files", lambda package: root)

    with pytest.raises(RuntimeError, match="agency"):
        api.verify_packaged_agency_schemas()


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


def test_agency_objects_are_not_added_to_protocol_registry() -> None:
    schema_api = importlib.import_module("openworkproof.schema_registry")

    for version, object_paths in schema_api._OBJECT_PATHS_BY_VERSION.items():
        assert "human-agency-profile" not in object_paths
        assert "agency-profile-transition" not in object_paths
        assert "agency-appeal" not in object_paths
        assert "human-agency-profile.schema.json" not in object_paths.values()
        assert "agency-profile-transition.schema.json" not in object_paths.values()
        assert "agency-appeal.schema.json" not in object_paths.values()
    assert "0.1" in schema_api._OBJECT_PATHS_BY_VERSION


def test_main_v01_registry_digest_is_unchanged() -> None:
    schema_api = importlib.import_module("openworkproof.schema_registry")

    # The frozen v0.1 digest table must contain exactly the six original
    # protocol objects; the agency registry never touches this table.
    assert set(schema_api._FROZEN_V01_DIGESTS) == {
        "acceptance-receipt.schema.json",
        "acceptance-rejection-receipt.schema.json",
        "action-receipt.schema.json",
        "capability-grant.schema.json",
        "schema-registry.json",
        "work-order.schema.json",
    }
    assert schema_api._FROZEN_V01_DIGESTS["schema-registry.json"] == (
        "b543abb2d972a84d3fffe97e6f9381f33b5cfe40fe0c8c7c046f91354f849000"
    )
    assert schema_api._FROZEN_V01_DIGESTS["work-order.schema.json"] == (
        "171b59390c66d586d7ee387d783ca8bc759779a08c36d31c85cf232998568013"
    )


# --------------------------------------------------------------------------- #
# 3. transaction safety
# --------------------------------------------------------------------------- #


def test_writer_replaces_an_existing_agency_set_atomically(tmp_path: Path) -> None:
    api = _api()
    destination = tmp_path / "destination"
    before = _write_old_set(destination)

    api.generate_agency_schemas(destination)

    assert _snapshot(destination) == _builtin_bytes()
    assert _snapshot(destination) != before
    assert _agency_artifacts(tmp_path) == set()


def test_writer_rejects_unexpected_existing_entries(tmp_path: Path) -> None:
    api = _api()
    destination = tmp_path / "destination"
    _write_old_set(destination)
    (destination / "unexpected.schema.json").write_bytes(b"{}")

    with pytest.raises(ValueError, match="unexpected"):
        api.generate_agency_schemas(destination)

    assert (destination / "unexpected.schema.json").read_bytes() == b"{}"


def test_no_leftover_stage_or_backup_artifacts(tmp_path: Path) -> None:
    api = _api()
    destination = tmp_path / "destination"

    api.generate_agency_schemas(destination)

    assert _agency_artifacts(tmp_path) == set()
    locks = tuple(
        path
        for path in tmp_path.iterdir()
        if path.name.startswith(AGENCY_LOCK_PREFIX)
    )
    assert len(locks) == 1
    assert all(
        path.is_file()
        and not path.is_symlink()
        and path.stat().st_size == 0
        for path in locks
    )


def test_backup_rename_ack_loss_records_backup_and_completes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = _api()
    destination = tmp_path / "destination"
    _write_old_set(destination)
    original_replace = Path.replace
    lost_ack = False

    def replace_then_lose_ack(source: Path, target: Path) -> Path:
        nonlocal lost_ack
        result = original_replace(source, target)
        if (
            Path(target).name.startswith(".openworkproof-agency-backup-")
            and not lost_ack
        ):
            lost_ack = True
            raise OSError("simulated backup rename ACK loss")
        return result

    monkeypatch.setattr(Path, "replace", replace_then_lose_ack)

    # The old-target -> backup rename actually landed but reported an error.
    # The committed-truth readback must record the backup and finish the
    # transaction so the new target is complete and nothing is left behind.
    api.generate_agency_schemas(destination)

    assert lost_ack is True
    assert _snapshot(destination) == _builtin_bytes()
    assert _agency_artifacts(tmp_path) == set()


def test_backup_rename_failure_preserves_old_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = _api()
    destination = tmp_path / "destination"
    before = _write_old_set(destination)
    original_replace = Path.replace
    failed = False

    def fail_backup_rename(source: Path, target: Path) -> Path:
        nonlocal failed
        if (
            Path(target).name.startswith(".openworkproof-agency-backup-")
            and not failed
        ):
            failed = True
            raise OSError("simulated backup rename failure")
        return original_replace(source, target)

    monkeypatch.setattr(Path, "replace", fail_backup_rename)

    # A genuine backup rename failure never lands: the old target must stay
    # exactly in place and no stage/backup artifacts may remain.
    with pytest.raises(OSError, match="backup rename failure"):
        api.generate_agency_schemas(destination)

    assert failed is True
    assert _snapshot(destination) == before
    assert _agency_artifacts(tmp_path) == set()


# --------------------------------------------------------------------------- #
# 4. packaging and installed-wheel readability
# --------------------------------------------------------------------------- #


def test_built_wheel_contains_exactly_agency_schema_resources(
    built_agency_wheel: Path,
) -> None:
    api = _api()
    with zipfile.ZipFile(built_agency_wheel) as archive:
        prefix = "openworkproof/schemas/agency-v0.1/"
        members = {
            name.removeprefix(prefix)
            for name in archive.namelist()
            if name.startswith(prefix) and not name.endswith("/")
        }
        assert members == AGENCY_FILENAMES
        generated = api.generated_agency_files()
        for name in sorted(AGENCY_FILENAMES):
            expected_digest = hashlib.sha256(generated[name]).hexdigest()
            content = archive.read(f"{prefix}{name}")
            assert hashlib.sha256(content).hexdigest() == expected_digest


def test_registry_loads_from_an_installed_wheel_outside_project_cwd(
    built_agency_wheel: Path,
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
            str(built_agency_wheel),
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
from importlib import resources
import openworkproof
from openworkproof.agency_schema_registry import (
    authoritative_agency_schema,
    verify_packaged_agency_schemas,
)
package = pathlib.Path(openworkproof.__file__).resolve()
assert package.is_relative_to(pathlib.Path(sys.argv[1]).resolve())
resources.files("openworkproof").joinpath(
    "schemas", "agency-v0.1", "human-agency-profile.schema.json"
).read_bytes()
assert authoritative_agency_schema("human-agency-profile").startswith(b"{")
verify_packaged_agency_schemas()
"""
    subprocess.run(
        [sys.executable, "-c", script, str(installed)],
        cwd=cwd,
        env={**os.environ, "PYTHONPATH": ""},
        check=True,
        capture_output=True,
        text=True,
    )


def test_installed_wheel_dir_exposes_all_public_names(
    built_agency_wheel: Path,
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
            str(built_agency_wheel),
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
package = pathlib.Path(openworkproof.__file__).resolve()
assert package.is_relative_to(pathlib.Path(sys.argv[1]).resolve())
names = set(dir(openworkproof))
missing = sorted(set(openworkproof.__all__) - names)
assert not missing, f"missing from dir(openworkproof): {missing}"
agency_exports = {
    "HumanAgencyProfileV01",
    "AgencyProfileTransitionV01",
    "AgencyAppealV01",
    "commit_human_agency_profile",
    "commit_agency_profile_transition",
    "commit_agency_appeal",
    "load_agency_history",
    "load_current_human_agency_profile",
    "load_agency_appeals",
    "authorize_tool_call_with_agency_profile",
    "dispatch_protected_agent_action",
    "export_agency_bundle",
    "verify_agency_bundle_directory",
    "AgencyBundleManifestV01",
    "AgencyBundleVerificationResultV01",
}
assert agency_exports <= names, sorted(agency_exports - names)
lazy_names = set(openworkproof._LAZY_EXPORTS)
assert not (lazy_names & set(openworkproof.__dict__)), "dir() triggered __getattr__"
lazy_modules = {module for module, _ in openworkproof._LAZY_EXPORTS.values()}
assert not (lazy_modules & set(sys.modules)), "dir() triggered lazy import"
"""
    subprocess.run(
        [sys.executable, "-c", script, str(installed)],
        cwd=cwd,
        env={**os.environ, "PYTHONPATH": ""},
        check=True,
        capture_output=True,
        text=True,
    )
