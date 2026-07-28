"""Generate and load the authoritative OpenWorkProof v0.1 JSON Schemas."""

from __future__ import annotations

import argparse
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import hashlib
from importlib import resources
import json
import os
from pathlib import Path
import stat
import tempfile
from typing import Any

import rfc8785

from openworkproof.models import (
    ACTION_RECEIPT_ADAPTER,
    AcceptanceReceipt,
    CapabilityGrant,
    WorkOrder,
)


_VERSION = "0.1"
_REGISTRY_FILENAME = "schema-registry.json"
_REGISTRY_SCHEMA_VERSION = "openworkproof-schema-registry/0.1"
_OBJECT_PATHS = {
    "acceptance-receipt": "acceptance-receipt.schema.json",
    "action-receipt": "action-receipt.schema.json",
    "capability-grant": "capability-grant.schema.json",
    "work-order": "work-order.schema.json",
}
# These are protocol-review anchors, not generated cache values. Changing one
# requires an explicit v0.1 compatibility decision or a protocol version bump.
_FROZEN_V01_DIGESTS = {
    "acceptance-receipt.schema.json": (
        "5436e77e03d64cf131f2273b7527e63aa854f9c3de7b60aeae8751024267ff0e"
    ),
    "action-receipt.schema.json": (
        "fac732ff13f30ccbd95aefdf6d92b7084c336d498e0845e020893dc6cf319ebe"
    ),
    "capability-grant.schema.json": (
        "f7c01f4ed227954f6310fd03ab5cbf52916510971c01c7f22ff9115e358cd17e"
    ),
    "schema-registry.json": (
        "20b3114531176064a059253d94694067d7fb2c43d7c161698564293efe442260"
    ),
    "work-order.schema.json": (
        "1f20662f25f1e11df2c407b924b76cffb8f863e6717939b499326c227cef94d0"
    ),
}
_FROZEN_V01_REGISTRY = {
    "schema_version": _REGISTRY_SCHEMA_VERSION,
    "protocol_version": _VERSION,
    "schemas": [
        {
            "object_type": object_type,
            "path": path,
            "sha256": _FROZEN_V01_DIGESTS[path],
        }
        for object_type, path in _OBJECT_PATHS.items()
    ],
}
_SCHEMA_FACTORIES: dict[str, Callable[[], dict[str, Any]]] = {
    "acceptance-receipt": AcceptanceReceipt.model_json_schema,
    "action-receipt": ACTION_RECEIPT_ADAPTER.json_schema,
    "capability-grant": CapabilityGrant.model_json_schema,
    "work-order": WorkOrder.model_json_schema,
}
_FILENAMES = frozenset({_REGISTRY_FILENAME, *_OBJECT_PATHS.values()})
_LOCK_PREFIX = ".openworkproof-schema-lock-"
_STAGE_PREFIX = ".openworkproof-schema-stage-"
_BACKUP_PREFIX = ".openworkproof-schema-backup-"


@dataclass(frozen=True, slots=True)
class SchemaComparisonResult:
    valid: bool
    error_code: str | None


class SchemaCleanupError(RuntimeError):
    """Report cleanup failure without obscuring whether commit completed."""

    def __init__(
        self,
        message: str,
        *,
        committed: bool,
        backup_paths: Sequence[Path] = (),
        stage_paths: Sequence[Path] = (),
    ) -> None:
        super().__init__(message)
        self.committed = committed
        self.backup_paths = tuple(backup_paths)
        self.stage_paths = tuple(stage_paths)


def _require_version(version: str) -> None:
    if version != _VERSION:
        raise ValueError(f"unknown protocol version: {version}")


def _require_object_type(object_type: str) -> str:
    try:
        return _OBJECT_PATHS[object_type]
    except KeyError as error:
        raise ValueError(f"unknown object type: {object_type}") from error


def _runtime_directory(version: str):
    _require_version(version)
    return resources.files("openworkproof").joinpath("schemas", "v0.1")


def _parse_canonical_json(raw: bytes, *, error_message: str) -> dict:
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError(error_message) from error
    if not isinstance(value, dict) or rfc8785.dumps(value) != raw:
        raise RuntimeError(error_message)
    return value


def _validated_runtime_files(version: str) -> dict[str, bytes]:
    directory = _runtime_directory(version)
    try:
        entries = tuple(directory.iterdir())
        if {entry.name for entry in entries} != _FILENAMES:
            raise RuntimeError("authoritative schema resource set is invalid")
        files: dict[str, bytes] = {}
        for entry in entries:
            is_symlink = getattr(entry, "is_symlink", lambda: False)
            if is_symlink() or not entry.is_file():
                raise RuntimeError("authoritative schema resource set is invalid")
            files[entry.name] = entry.read_bytes()
    except (FileNotFoundError, IsADirectoryError, OSError) as error:
        raise RuntimeError("authoritative schema resource set is invalid") from error

    for filename, expected_digest in _FROZEN_V01_DIGESTS.items():
        if hashlib.sha256(files[filename]).hexdigest() != expected_digest:
            raise RuntimeError("authoritative schema anchor mismatch")
    for raw in files.values():
        _parse_canonical_json(
            raw,
            error_message="authoritative schema is not canonical",
        )
    registry = _parse_canonical_json(
        files[_REGISTRY_FILENAME],
        error_message="authoritative schema registry is not canonical",
    )
    if registry != _FROZEN_V01_REGISTRY:
        raise RuntimeError("authoritative schema registry is not frozen")
    return files


def authoritative_schema(
    object_type: str,
    version: str = _VERSION,
) -> dict:
    """Load one schema from installed package authority."""

    filename = _require_object_type(object_type)
    files = _validated_runtime_files(version)
    return _parse_canonical_json(
        files[filename],
        error_message="authoritative schema is invalid",
    )


def authoritative_digest(
    object_type: str,
    version: str = _VERSION,
) -> str:
    """Return the verified SHA-256 from the installed schema registry."""

    filename = _require_object_type(object_type)
    _validated_runtime_files(version)
    return _FROZEN_V01_DIGESTS[filename]


def _generated_files() -> dict[str, bytes]:
    files = {
        _OBJECT_PATHS[object_type]: rfc8785.dumps(factory())
        for object_type, factory in _SCHEMA_FACTORIES.items()
    }
    for filename, content in files.items():
        if (
            hashlib.sha256(content).hexdigest()
            != _FROZEN_V01_DIGESTS[filename]
        ):
            raise RuntimeError(
                f"frozen v0.1 schema drift: {filename}; "
                "anchor changes require protocol review"
            )
    generated = {
        _REGISTRY_FILENAME: rfc8785.dumps(_FROZEN_V01_REGISTRY),
        **files,
    }
    for filename, content in generated.items():
        if (
            hashlib.sha256(content).hexdigest()
            != _FROZEN_V01_DIGESTS[filename]
        ):
            raise RuntimeError(
                f"frozen v0.1 schema drift: {filename}; "
                "anchor changes require protocol review"
            )
    return generated


def _preflight_target(directory: Path) -> tuple[Path, tuple[Path, ...]]:
    requested_target = Path(os.path.abspath(directory))
    if requested_target.is_symlink():
        raise ValueError("schema destination must be a real directory")

    requested_parent = requested_target.parent
    if requested_parent.is_symlink():
        raise ValueError("schema destination parent is a symlink")

    missing_names: list[str] = []
    parent = requested_parent
    while not parent.exists():
        if parent.is_symlink() or parent == parent.parent:
            raise ValueError("schema destination parent is invalid")
        missing_names.append(parent.name)
        parent = parent.parent
    if parent.is_symlink() or not parent.is_dir():
        raise ValueError("schema destination parent is invalid")

    canonical_parent = parent.resolve(strict=True)
    missing: list[Path] = []
    for name in reversed(missing_names):
        canonical_parent /= name
        missing.append(canonical_parent)
    target = canonical_parent / requested_target.name

    if target.exists() and not target.is_dir():
        raise ValueError("schema destination must be a real directory")
    existing = tuple(target.iterdir()) if target.exists() else ()
    if any(
        path.name not in _FILENAMES
        or path.is_symlink()
        or not path.is_file()
        for path in existing
    ):
        raise ValueError("schema destination contains unexpected entries")
    return target, tuple(missing)


def _create_missing_parents(
    plans: Sequence[tuple[Path, tuple[Path, ...]]],
) -> list[Path]:
    candidates = {
        directory
        for _, missing in plans
        for directory in missing
    }
    created: list[Path] = []
    for directory in sorted(candidates, key=lambda value: len(value.parts)):
        if directory.exists():
            if directory.is_symlink() or not directory.is_dir():
                raise ValueError("schema destination parent changed")
            continue
        try:
            directory.mkdir()
        except FileExistsError:
            if directory.is_symlink() or not directory.is_dir():
                raise ValueError("schema destination parent changed") from None
        else:
            created.append(directory)
    return created


def _target_key(target: Path) -> str:
    return hashlib.sha256(os.fsencode(str(target))).hexdigest()[:16]


def _stage_prefix(target: Path) -> str:
    return f"{_STAGE_PREFIX}{_target_key(target)}-"


def _backup_prefix(target: Path) -> str:
    return f"{_BACKUP_PREFIX}{_target_key(target)}-"


def _lock_path(target: Path) -> Path:
    return target.parent / f"{_LOCK_PREFIX}{_target_key(target)}"


def _validate_open_lock(lock_path: Path, descriptor: int) -> None:
    opened = os.fstat(descriptor)
    try:
        linked = os.stat(lock_path, follow_symlinks=False)
    except OSError as error:
        raise ValueError("schema transaction lock is invalid") from error
    if (
        not stat.S_ISREG(opened.st_mode)
        or not stat.S_ISREG(linked.st_mode)
        or (opened.st_dev, opened.st_ino) != (linked.st_dev, linked.st_ino)
    ):
        raise ValueError("schema transaction lock is invalid")


@contextmanager
def _locked_targets(targets: Sequence[Path]) -> Iterator[None]:
    descriptors: list[int] = []
    ordered = sorted(set(targets), key=lambda target: os.fsencode(str(target)))
    try:
        for target in ordered:
            lock_path = _lock_path(target)
            flags = os.O_RDWR | os.O_CREAT
            flags |= getattr(os, "O_CLOEXEC", 0)
            flags |= getattr(os, "O_NOFOLLOW", 0)
            try:
                descriptor = os.open(lock_path, flags, 0o600)
            except OSError as error:
                raise ValueError(
                    "schema transaction lock is invalid"
                ) from error
            try:
                _validate_open_lock(lock_path, descriptor)
                fcntl.flock(descriptor, fcntl.LOCK_EX)
                _validate_open_lock(lock_path, descriptor)
            except Exception:
                os.close(descriptor)
                raise
            descriptors.append(descriptor)
        yield
    finally:
        for descriptor in reversed(descriptors):
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)


def _stage_schema_directory(
    target: Path,
    files: dict[str, bytes],
) -> Path:
    stage = Path(
        tempfile.mkdtemp(
            prefix=_stage_prefix(target),
            dir=target.parent,
        )
    )
    try:
        for filename, content in files.items():
            stage.joinpath(filename).write_bytes(content)
    except Exception:
        try:
            _remove_schema_directory(stage)
        except (OSError, RuntimeError) as cleanup_error:
            raise SchemaCleanupError(
                "schema staging failed and its directory could not be cleaned",
                committed=False,
                stage_paths=(stage,),
            ) from cleanup_error
        raise
    return stage


def _remove_schema_directory(directory: Path) -> None:
    last_error: OSError | None = None
    for _ in range(3):
        try:
            if directory.is_symlink():
                raise RuntimeError(
                    "schema transaction cleanup target is invalid"
                )
            if not directory.exists():
                return
            if not directory.is_dir():
                raise RuntimeError(
                    "schema transaction cleanup target is invalid"
                )
            entries = tuple(directory.iterdir())
            if any(
                entry.name not in _FILENAMES
                or entry.is_symlink()
                or not entry.is_file()
                for entry in entries
            ):
                raise RuntimeError(
                    "schema transaction cleanup set is invalid"
                )
            for entry in entries:
                entry.unlink()
            directory.rmdir()
            return
        except OSError as error:
            last_error = error
    assert last_error is not None
    raise last_error


def _unused_backup_path(target: Path) -> Path:
    backup = Path(
        tempfile.mkdtemp(
            prefix=_backup_prefix(target),
            dir=target.parent,
        )
    )
    backup.rmdir()
    return backup


def _transaction_artifacts(target: Path, prefix: str) -> tuple[Path, ...]:
    return tuple(
        sorted(
            (
                path
                for path in target.parent.iterdir()
                if path.name.startswith(prefix)
            ),
            key=lambda path: os.fsencode(path.name),
        )
    )


def _recover_target(target: Path) -> None:
    backups = _transaction_artifacts(target, _backup_prefix(target))
    stages = _transaction_artifacts(target, _stage_prefix(target))
    if not target.exists() and backups:
        if len(backups) != 1:
            raise SchemaCleanupError(
                "schema recovery found ambiguous backups",
                committed=False,
                backup_paths=backups,
                stage_paths=stages,
            )
        backups[0].replace(target)
        backups = ()

    failed_backups: list[Path] = []
    failed_stages: list[Path] = []
    first_error: Exception | None = None
    for backup in backups:
        try:
            _remove_schema_directory(backup)
        except (OSError, RuntimeError) as error:
            failed_backups.append(backup)
            first_error = first_error or error
    for stage in stages:
        try:
            _remove_schema_directory(stage)
        except (OSError, RuntimeError) as error:
            failed_stages.append(stage)
            first_error = first_error or error
    if failed_backups or failed_stages:
        raise SchemaCleanupError(
            "schema recovery cleanup failed",
            committed=bool(failed_backups and target.exists()),
            backup_paths=failed_backups,
            stage_paths=failed_stages,
        ) from first_error


def _commit_staged_directories(
    targets: Sequence[tuple[Path, Path]],
) -> None:
    backups: dict[Path, Path] = {}
    installed: set[Path] = set()
    try:
        for target, stage in targets:
            if target.exists():
                backup = _unused_backup_path(target)
                target.replace(backup)
                backups[target] = backup
            stage.replace(target)
            installed.add(target)
    except Exception:
        rollback_error: Exception | None = None
        for target, _ in reversed(targets):
            try:
                if target in installed:
                    _remove_schema_directory(target)
                backup = backups.get(target)
                if backup is not None and backup.exists():
                    backup.replace(target)
            except Exception as error:
                rollback_error = rollback_error or error
        if rollback_error is not None:
            raise RuntimeError("schema transaction rollback failed") from rollback_error
        raise
    failed_backups: list[Path] = []
    first_error: Exception | None = None
    for backup in backups.values():
        try:
            _remove_schema_directory(backup)
        except (OSError, RuntimeError) as error:
            failed_backups.append(backup)
            first_error = first_error or error
    if failed_backups:
        raise SchemaCleanupError(
            "schema commit completed but backup cleanup failed",
            committed=True,
            backup_paths=failed_backups,
        ) from first_error


def write_authoritative_schemas(
    destination: Path,
    mirror: Path | None = None,
) -> None:
    """Generate the frozen package schemas and optional published mirror."""

    files = _generated_files()
    requested = [destination] + ([mirror] if mirror is not None else [])
    plans = [_preflight_target(path) for path in requested]
    targets = [target for target, _ in plans]
    if len(targets) == 2 and (
        targets[0] == targets[1]
        or targets[0] in targets[1].parents
        or targets[1] in targets[0].parents
    ):
        raise ValueError("schema destination and mirror conflict")

    created_parents: list[Path] = []
    try:
        created_parents = _create_missing_parents(plans)
        with _locked_targets(targets):
            locked_plans = [_preflight_target(path) for path in requested]
            locked_targets = [target for target, _ in locked_plans]
            if locked_targets != targets:
                raise ValueError("schema destination changed before locking")
            for target in targets:
                _recover_target(target)

            stages: list[Path] = []
            try:
                for target in targets:
                    stages.append(_stage_schema_directory(target, files))
                _commit_staged_directories(
                    tuple(zip(targets, stages, strict=True))
                )
            finally:
                failed_stages: list[Path] = []
                first_error: Exception | None = None
                for stage in stages:
                    try:
                        _remove_schema_directory(stage)
                    except (OSError, RuntimeError) as error:
                        failed_stages.append(stage)
                        first_error = first_error or error
                if failed_stages:
                    raise SchemaCleanupError(
                        "schema transaction stage cleanup failed",
                        committed=False,
                        stage_paths=failed_stages,
                    ) from first_error
    finally:
        for parent in reversed(created_parents):
            try:
                parent.rmdir()
            except OSError:
                pass


def compare_bundle_schemas_to_builtin(
    directory: Path,
    version: str,
) -> SchemaComparisonResult:
    """Compare a bundle schema directory byte-for-byte with installed authority."""

    if version != _VERSION:
        return SchemaComparisonResult(False, "UNKNOWN_PROTOCOL_VERSION")
    try:
        builtin_files = _validated_runtime_files(version)
        if (
            directory.is_symlink()
            or not directory.is_dir()
            or {path.name for path in directory.iterdir()} != _FILENAMES
        ):
            return SchemaComparisonResult(
                False,
                "AUTHORITATIVE_SCHEMA_MISMATCH",
            )
        for filename in _FILENAMES:
            candidate = directory / filename
            if candidate.is_symlink() or not candidate.is_file():
                return SchemaComparisonResult(
                    False,
                    "AUTHORITATIVE_SCHEMA_MISMATCH",
                )
            if candidate.read_bytes() != builtin_files[filename]:
                return SchemaComparisonResult(
                    False,
                    "AUTHORITATIVE_SCHEMA_MISMATCH",
                )
    except (OSError, RuntimeError, ValueError):
        return SchemaComparisonResult(False, "AUTHORITATIVE_SCHEMA_MISMATCH")
    return SchemaComparisonResult(True, None)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate authoritative OpenWorkProof v0.1 schemas."
    )
    parser.add_argument("destination", type=Path)
    parser.add_argument("--mirror", type=Path)
    arguments = parser.parse_args(argv)
    write_authoritative_schemas(arguments.destination, mirror=arguments.mirror)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
