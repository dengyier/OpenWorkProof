"""Generate the independent human agency (0.1) schema registry.

The agency registry sits *beside* the frozen v0.1-v0.5 protocol registry and the
companion registry: it packages the three closed, Acceptor-signed protocol
object schemas (human-agency-profile, agency-profile-transition, agency-appeal)
without mutating any frozen protocol bytes, hashes or object routing.  It never
touches ``schema_registry._FROZEN_V01_DIGESTS`` or the main v0.1
``schema-registry.json`` digest.

The writer follows the same safe single-target transaction shape as the sibling
registries -- resolved-target checks, a sibling stage, complete-file
verification, backup/commit/rollback, exact byte readback after an uncertain
COMMIT acknowledgement, and cleanup -- and it never removes a target with
``rmtree`` before replacing it.
"""

from __future__ import annotations

import argparse
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
import fcntl
import hashlib
from importlib import resources
import json
import os
from pathlib import Path
import stat
import tempfile

import rfc8785

from openworkproof.agency import (
    AgencyAppealV01,
    AgencyProfileTransitionV01,
    HumanAgencyProfileV01,
)


__all__ = [
    "AGENCY_VERSION",
    "OBJECT_PATHS",
    "SCHEMA_FACTORIES",
    "authoritative_agency_schema",
    "generate_agency_schemas",
    "generated_agency_files",
    "verify_packaged_agency_schemas",
]


AGENCY_VERSION = "0.1"
_REGISTRY_FILENAME = "schema-registry.json"
_REGISTRY_SCHEMA_VERSION = "openworkproof-agency-schema-registry/0.1"
OBJECT_PATHS = {
    "human-agency-profile": "human-agency-profile.schema.json",
    "agency-profile-transition": "agency-profile-transition.schema.json",
    "agency-appeal": "agency-appeal.schema.json",
}
SCHEMA_FACTORIES = {
    "human-agency-profile": HumanAgencyProfileV01.model_json_schema,
    "agency-profile-transition": (
        AgencyProfileTransitionV01.model_json_schema
    ),
    "agency-appeal": AgencyAppealV01.model_json_schema,
}
_FILENAMES = frozenset({_REGISTRY_FILENAME, *OBJECT_PATHS.values()})
_LOCK_PREFIX = ".openworkproof-agency-lock-"
_STAGE_PREFIX = ".openworkproof-agency-stage-"
_BACKUP_PREFIX = ".openworkproof-agency-backup-"


class AgencySchemaCleanupError(RuntimeError):
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


def _require_object_type(object_type: str) -> str:
    try:
        return OBJECT_PATHS[object_type]
    except KeyError as error:
        raise ValueError(f"unknown object type: {object_type}") from error


def _parse_canonical_json(raw: bytes, *, error_message: str) -> dict:
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError(error_message) from error
    if not isinstance(value, dict) or rfc8785.dumps(value) != raw:
        raise RuntimeError(error_message)
    return value


def generated_agency_files() -> dict[str, bytes]:
    """Return the canonical registry and every agency schema, deterministically."""

    schemas = {
        OBJECT_PATHS[name]: rfc8785.dumps(factory())
        for name, factory in SCHEMA_FACTORIES.items()
    }
    registry = {
        "schema_version": _REGISTRY_SCHEMA_VERSION,
        "protocol_version": AGENCY_VERSION,
        "schemas": [
            {
                "object_type": name,
                "path": OBJECT_PATHS[name],
                "sha256": hashlib.sha256(
                    schemas[OBJECT_PATHS[name]]
                ).hexdigest(),
            }
            for name in sorted(OBJECT_PATHS)
        ],
    }
    return {_REGISTRY_FILENAME: rfc8785.dumps(registry), **schemas}


def _verify_generated_files(files: dict[str, bytes]) -> None:
    if set(files) != _FILENAMES:
        raise RuntimeError("agency generated file set is invalid")
    for filename, content in files.items():
        _parse_canonical_json(
            content,
            error_message="agency schema is not canonical",
        )
    registry = _parse_canonical_json(
        files[_REGISTRY_FILENAME],
        error_message="agency registry is not canonical",
    )
    expected = {
        "schema_version": _REGISTRY_SCHEMA_VERSION,
        "protocol_version": AGENCY_VERSION,
        "schemas": [
            {
                "object_type": name,
                "path": OBJECT_PATHS[name],
                "sha256": hashlib.sha256(
                    files[OBJECT_PATHS[name]]
                ).hexdigest(),
            }
            for name in sorted(OBJECT_PATHS)
        ],
    }
    if registry != expected:
        raise RuntimeError("agency registry is inconsistent")


def _packaged_agency_files() -> dict[str, bytes]:
    """Load and verify the installed agency schema resource set.

    The packaged directory must be byte-for-byte identical to the deterministic
    generated anchors, so packaged and generated authority can never diverge.
    """

    directory = resources.files("openworkproof").joinpath(
        "schemas", "agency-v0.1"
    )
    try:
        entries = tuple(directory.iterdir())
        if {entry.name for entry in entries} != _FILENAMES:
            raise RuntimeError("agency packaged schema set is invalid")
        files: dict[str, bytes] = {}
        for entry in entries:
            is_symlink = getattr(entry, "is_symlink", lambda: False)
            if is_symlink() or not entry.is_file():
                raise RuntimeError("agency packaged schema set is invalid")
            files[entry.name] = entry.read_bytes()
    except (FileNotFoundError, IsADirectoryError, OSError) as error:
        raise RuntimeError("agency packaged schema set is invalid") from error

    for filename in _FILENAMES:
        _parse_canonical_json(
            files[filename],
            error_message="agency packaged schema is not canonical",
        )
    if files != generated_agency_files():
        raise RuntimeError("agency packaged schemas drifted from generated anchors")
    return files


def verify_packaged_agency_schemas() -> None:
    """Verify the installed agency-v0.1 resources match the frozen anchors."""

    _packaged_agency_files()


def authoritative_agency_schema(object_type: str) -> bytes:
    """Load one agency schema as canonical bytes from installed authority."""

    filename = _require_object_type(object_type)
    return _packaged_agency_files()[filename]


# --------------------------------------------------------------------------- #
# transaction helpers (local, agency-specific prefixes and file set)
# --------------------------------------------------------------------------- #


def _preflight_target(directory: Path) -> tuple[Path, tuple[Path, ...]]:
    requested_target = Path(os.path.abspath(directory))
    if requested_target.is_symlink():
        raise ValueError("agency schema destination must be a real directory")

    requested_parent = requested_target.parent
    if requested_parent.is_symlink():
        raise ValueError("agency schema destination parent is a symlink")

    missing_names: list[str] = []
    parent = requested_parent
    while not parent.exists():
        if parent.is_symlink() or parent == parent.parent:
            raise ValueError("agency schema destination parent is invalid")
        missing_names.append(parent.name)
        parent = parent.parent
    if parent.is_symlink() or not parent.is_dir():
        raise ValueError("agency schema destination parent is invalid")

    canonical_parent = parent.resolve(strict=True)
    missing: list[Path] = []
    for name in reversed(missing_names):
        canonical_parent /= name
        missing.append(canonical_parent)
    target = canonical_parent / requested_target.name

    if target.exists() and not target.is_dir():
        raise ValueError("agency schema destination must be a real directory")
    existing = tuple(target.iterdir()) if target.exists() else ()
    if any(
        path.name not in _FILENAMES
        or path.is_symlink()
        or not path.is_file()
        for path in existing
    ):
        raise ValueError("agency schema destination contains unexpected entries")
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
                raise ValueError("agency schema destination parent changed")
            continue
        try:
            directory.mkdir()
        except FileExistsError:
            if directory.is_symlink() or not directory.is_dir():
                raise ValueError(
                    "agency schema destination parent changed"
                ) from None
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
        raise ValueError("agency schema transaction lock is invalid") from error
    if (
        not stat.S_ISREG(opened.st_mode)
        or not stat.S_ISREG(linked.st_mode)
        or (opened.st_dev, opened.st_ino) != (linked.st_dev, linked.st_ino)
    ):
        raise ValueError("agency schema transaction lock is invalid")


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
                    "agency schema transaction lock is invalid"
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


def _stage_directory(target: Path, files: dict[str, bytes]) -> Path:
    stage = Path(
        tempfile.mkdtemp(
            prefix=_stage_prefix(target),
            dir=target.parent,
        )
    )
    try:
        for filename, content in files.items():
            stage.joinpath(filename).write_bytes(content)
        if not _readback_matches(stage, files):
            raise RuntimeError("agency schema staging verification failed")
    except Exception:
        try:
            _remove_schema_directory(stage, frozenset(files))
        except (OSError, RuntimeError) as cleanup_error:
            raise AgencySchemaCleanupError(
                "agency schema staging failed and its directory could not "
                "be cleaned",
                committed=False,
                stage_paths=(stage,),
            ) from cleanup_error
        raise
    return stage


def _remove_schema_directory(
    directory: Path,
    filenames: frozenset[str] = _FILENAMES,
) -> None:
    last_error: OSError | None = None
    for _ in range(3):
        try:
            if directory.is_symlink():
                raise RuntimeError(
                    "agency schema transaction cleanup target is invalid"
                )
            if not directory.exists():
                return
            if not directory.is_dir():
                raise RuntimeError(
                    "agency schema transaction cleanup target is invalid"
                )
            entries = tuple(directory.iterdir())
            if any(
                entry.name not in filenames
                or entry.is_symlink()
                or not entry.is_file()
                for entry in entries
            ):
                raise RuntimeError(
                    "agency schema transaction cleanup set is invalid"
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


def _readback_matches(target: Path, files: dict[str, bytes]) -> bool:
    """Return True when ``target`` is byte-for-byte the expected file set."""

    try:
        if target.is_symlink() or not target.is_dir():
            return False
        entries = tuple(target.iterdir())
        if {entry.name for entry in entries} != set(files):
            return False
        for filename, content in files.items():
            path = target / filename
            if path.is_symlink() or not path.is_file():
                return False
            if path.read_bytes() != content:
                return False
    except OSError:
        return False
    return True


def _recover_target(target: Path) -> None:
    backups = _transaction_artifacts(target, _backup_prefix(target))
    stages = _transaction_artifacts(target, _stage_prefix(target))
    if not target.exists() and backups:
        if len(backups) != 1:
            raise AgencySchemaCleanupError(
                "agency schema recovery found ambiguous backups",
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
            _remove_schema_directory(backup, _FILENAMES)
        except (OSError, RuntimeError) as error:
            failed_backups.append(backup)
            first_error = first_error or error
    for stage in stages:
        try:
            _remove_schema_directory(stage, _FILENAMES)
        except (OSError, RuntimeError) as error:
            failed_stages.append(stage)
            first_error = first_error or error
    if failed_backups or failed_stages:
        raise AgencySchemaCleanupError(
            "agency schema recovery cleanup failed",
            committed=bool(failed_backups and target.exists()),
            backup_paths=failed_backups,
            stage_paths=failed_stages,
        ) from first_error


def _commit_staged_directories(
    targets: Sequence[tuple[Path, Path]],
    files: dict[str, bytes],
) -> None:
    filenames = frozenset(files)
    backups: dict[Path, Path] = {}
    installed: set[Path] = set()
    try:
        for target, stage in targets:
            if target.exists():
                backup = _unused_backup_path(target)
                try:
                    target.replace(backup)
                except Exception:
                    # Uncertain COMMIT acknowledgement: a filesystem may move
                    # the old target to its backup yet still report an error.
                    # Read the committed truth back instead of trusting the
                    # syscall result -- only a clean "old target no longer
                    # present and its backup now exists" outcome counts as
                    # landed. Anything else is ambiguous and fails closed.
                    if target.exists() or not backup.is_dir():
                        raise
                backups[target] = backup
            try:
                stage.replace(target)
            except Exception:
                if not _readback_matches(target, files):
                    raise
            installed.add(target)

        for target, _ in targets:
            if not _readback_matches(target, files):
                raise RuntimeError("agency schema commit readback failed")
    except Exception:
        rollback_error: Exception | None = None
        for target, _ in reversed(targets):
            try:
                if target in installed:
                    _remove_schema_directory(target, filenames)
                backup = backups.get(target)
                if backup is not None and backup.exists():
                    backup.replace(target)
            except Exception as error:
                rollback_error = rollback_error or error
        if rollback_error is not None:
            leftover_backups = tuple(
                backup for backup in backups.values() if backup.exists()
            )
            leftover_stages = tuple(
                stage for _, stage in targets if stage.exists()
            )
            raise AgencySchemaCleanupError(
                "agency schema transaction rollback failed",
                committed=False,
                backup_paths=leftover_backups,
                stage_paths=leftover_stages,
            ) from rollback_error
        raise

    failed_backups: list[Path] = []
    first_error: Exception | None = None
    for backup in backups.values():
        try:
            _remove_schema_directory(backup, filenames)
        except (OSError, RuntimeError) as error:
            failed_backups.append(backup)
            first_error = first_error or error
    if failed_backups:
        raise AgencySchemaCleanupError(
            "agency schema commit completed but backup cleanup failed",
            committed=True,
            backup_paths=failed_backups,
        ) from first_error


def _write_agency_transaction(
    targets: Sequence[Path],
    files: dict[str, bytes],
) -> None:
    filenames = frozenset(files)
    plans = [_preflight_target(target) for target in targets]
    resolved = [target for target, _ in plans]

    created_parents: list[Path] = []
    try:
        created_parents = _create_missing_parents(plans)
        with _locked_targets(resolved):
            locked_plans = [_preflight_target(target) for target in targets]
            locked_targets = [target for target, _ in locked_plans]
            if locked_targets != resolved:
                raise ValueError(
                    "agency schema destination changed before locking"
                )
            for target in resolved:
                _recover_target(target)

            stages: list[Path] = []
            try:
                for target in resolved:
                    stages.append(_stage_directory(target, files))
                _commit_staged_directories(
                    tuple(zip(resolved, stages, strict=True)),
                    files,
                )
            finally:
                failed_stages: list[Path] = []
                first_error: Exception | None = None
                for stage in stages:
                    try:
                        _remove_schema_directory(stage, filenames)
                    except (OSError, RuntimeError) as error:
                        failed_stages.append(stage)
                        first_error = first_error or error
                if failed_stages:
                    raise AgencySchemaCleanupError(
                        "agency schema transaction stage cleanup failed",
                        committed=False,
                        stage_paths=failed_stages,
                    ) from first_error
    finally:
        for parent in reversed(created_parents):
            try:
                parent.rmdir()
            except OSError:
                pass


def generate_agency_schemas(destination: Path) -> None:
    """Generate the frozen agency schemas into ``destination``, safely."""

    files = generated_agency_files()
    _verify_generated_files(files)
    _write_agency_transaction([Path(destination)], files)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate authoritative human agency schemas."
    )
    parser.add_argument("--destination", required=True, type=Path)
    arguments = parser.parse_args(argv)
    generate_agency_schemas(arguments.destination)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
