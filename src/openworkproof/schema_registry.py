"""Generate and load frozen OpenWorkProof protocol JSON Schemas."""

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
    ActionBindingManifest,
    AcceptanceReceipt,
    AcceptanceRejectionReceipt,
    AcceptanceTransitionReceipt,
    AuthorityCheckpoint,
    BindingDecision,
    CapabilityGrant,
    CommitmentAnchor,
    EvaluationScopeManifest,
    JudgmentCommitment,
    PolicyAnchor,
    SubjectClaim,
    VerificationArmResult,
    VerificationArmResultV03,
    VerificationDecision,
    VerificationDecisionV03,
    VerificationProfileV02,
    VerificationProfileV03,
    WorkOrder,
)


_DEFAULT_VERSION = "0.1"
_REGISTRY_FILENAME = "schema-registry.json"
_REGISTRY_SCHEMA_VERSION = "openworkproof-schema-registry/0.1"
V01_OBJECT_PATHS = {
    "acceptance-receipt": "acceptance-receipt.schema.json",
    "acceptance-rejection-receipt": (
        "acceptance-rejection-receipt.schema.json"
    ),
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
_FROZEN_V01_REGISTRY = {
    "schema_version": _REGISTRY_SCHEMA_VERSION,
    "protocol_version": _DEFAULT_VERSION,
    "schemas": [
        {
            "object_type": object_type,
            "path": path,
            "sha256": _FROZEN_V01_DIGESTS[path],
        }
        for object_type, path in V01_OBJECT_PATHS.items()
    ],
}
V01_SCHEMA_FACTORIES: dict[str, Callable[[], dict[str, Any]]] = {
    "acceptance-receipt": AcceptanceReceipt.model_json_schema,
    "acceptance-rejection-receipt": (
        AcceptanceRejectionReceipt.model_json_schema
    ),
    "action-receipt": ACTION_RECEIPT_ADAPTER.json_schema,
    "capability-grant": CapabilityGrant.model_json_schema,
    "work-order": WorkOrder.model_json_schema,
}
V02_OBJECT_PATHS = {
    "acceptance-transition": "acceptance-transition.schema.json",
    "commitment-anchor": "commitment-anchor.schema.json",
    "policy-anchor": "policy-anchor.schema.json",
    "subject-claim": "subject-claim.schema.json",
    "verification-arm-result": "verification-arm-result.schema.json",
    "verification-decision": "verification-decision.schema.json",
    "verification-profile": "verification-profile.schema.json",
}
V02_SCHEMA_FACTORIES: dict[str, Callable[[], dict[str, Any]]] = {
    "acceptance-transition": AcceptanceTransitionReceipt.model_json_schema,
    "commitment-anchor": CommitmentAnchor.model_json_schema,
    "policy-anchor": PolicyAnchor.model_json_schema,
    "subject-claim": SubjectClaim.model_json_schema,
    "verification-arm-result": VerificationArmResult.model_json_schema,
    "verification-decision": VerificationDecision.model_json_schema,
    "verification-profile": VerificationProfileV02.model_json_schema,
}
_FROZEN_V02_DIGESTS = {
    "acceptance-transition.schema.json": (
        "504a06d4748b0ea045f40c2182ee85e2b59cea8793d6c9259f695dc6c764e1a0"
    ),
    "commitment-anchor.schema.json": (
        "ccd6116e57589a12e6a6015c39205f47731bf4fc011d719469f9a944d10cf61f"
    ),
    "policy-anchor.schema.json": (
        "7423e5f09f6f22d8785daa7e9dd7c79489b494f63ad12b28a74e480967127d0b"
    ),
    "schema-registry.json": (
        "ba555173e56743920b136b131505489f0e8765ea21433c96db7dcc3c354141ae"
    ),
    "subject-claim.schema.json": (
        "ec9cd237217dc96a376ce1e67349414abcaa9369a9d4de8d1f85c17e635d1bfe"
    ),
    "verification-arm-result.schema.json": (
        "c65913e8dc1f42d0f295be3d136b0566d2e0b7b2ae12b4e1b74634d010750310"
    ),
    "verification-decision.schema.json": (
        "d4f15b2aabcf7eadfdf703d37ae7164de9c9d3a3ef0b2a6648a18094e6e7fec1"
    ),
    "verification-profile.schema.json": (
        "22df63576418905c68d910f573a7f444700f9b3f7098590dca1876618d70b32c"
    ),
}
_FROZEN_V02_REGISTRY = {
    "schema_version": _REGISTRY_SCHEMA_VERSION,
    "protocol_version": "0.2",
    "schemas": [
        {
            "object_type": object_type,
            "path": path,
            "sha256": _FROZEN_V02_DIGESTS[path],
        }
        for object_type, path in V02_OBJECT_PATHS.items()
    ],
}
V03_OBJECT_PATHS = {
    "evaluation-scope": "evaluation-scope.schema.json",
    "verification-arm-result": "verification-arm-result.schema.json",
    "verification-decision": "verification-decision.schema.json",
    "verification-profile": "verification-profile.schema.json",
}
V03_SCHEMA_FACTORIES: dict[str, Callable[[], dict[str, Any]]] = {
    "evaluation-scope": EvaluationScopeManifest.model_json_schema,
    "verification-arm-result": VerificationArmResultV03.model_json_schema,
    "verification-decision": VerificationDecisionV03.model_json_schema,
    "verification-profile": VerificationProfileV03.model_json_schema,
}
_FROZEN_V03_DIGESTS = {
    "evaluation-scope.schema.json": (
        "dd63163297871008cd18b2de54fc6d22fedf71009bfbd7c849b632a02783d330"
    ),
    "schema-registry.json": (
        "e934f2295ae36901b9d8430d184549eb367dca4cecd86f30ed625502f072e1b1"
    ),
    "verification-arm-result.schema.json": (
        "73d16598938c5e17d073ab75c779816d5ad4b8a4cfc14f18fed3c8370ca2309b"
    ),
    "verification-decision.schema.json": (
        "e1ec873558bba467f22923d79e7b0592df4910aee32047b5037da99701c08408"
    ),
    "verification-profile.schema.json": (
        "ac6cb592983cfdda7132ff7c636106e70f5e5b8ccf0f35b9689ff82ae487dd96"
    ),
}
_FROZEN_V03_REGISTRY = {
    "schema_version": _REGISTRY_SCHEMA_VERSION,
    "protocol_version": "0.3",
    "schemas": [
        {
            "object_type": object_type,
            "path": path,
            "sha256": _FROZEN_V03_DIGESTS[path],
        }
        for object_type, path in V03_OBJECT_PATHS.items()
    ],
}
V04_OBJECT_PATHS = {
    "action-binding-manifest": "action-binding-manifest.schema.json",
    "authority-checkpoint": "authority-checkpoint.schema.json",
    "binding-decision": "binding-decision.schema.json",
    "judgment-commitment": "judgment-commitment.schema.json",
}
V04_SCHEMA_FACTORIES: dict[str, Callable[[], dict[str, Any]]] = {
    "action-binding-manifest": ActionBindingManifest.model_json_schema,
    "authority-checkpoint": AuthorityCheckpoint.model_json_schema,
    "binding-decision": BindingDecision.model_json_schema,
    "judgment-commitment": JudgmentCommitment.model_json_schema,
}
_FROZEN_V04_DIGESTS = {
    "action-binding-manifest.schema.json": (
        "6e4dc37a733345ea2e74188a38cea4527e2fcfb5bf1cd487bcfc2bbc6f2f59b2"
    ),
    "authority-checkpoint.schema.json": (
        "deb518fb233088e69ba203df98c896d60a4e902e1484b1e05673cc55a60ead55"
    ),
    "binding-decision.schema.json": (
        "4a120533fdd611bf1f1f4aa292289e70658e5f59eecefc07c9bc513abce8acbe"
    ),
    "judgment-commitment.schema.json": (
        "29a2fbca6bdd5dc6aaf2c023e6a0fd0361531a30ae7486cdc5f1023e2542ecd2"
    ),
    "schema-registry.json": (
        "b347c54f523d2994142770191a467bd6e796dc4094fda1ac7da07d78729f8f30"
    ),
}
_FROZEN_V04_REGISTRY = {
    "schema_version": _REGISTRY_SCHEMA_VERSION,
    "protocol_version": "0.4",
    "schemas": [
        {
            "object_type": object_type,
            "path": path,
            "sha256": _FROZEN_V04_DIGESTS[path],
        }
        for object_type, path in V04_OBJECT_PATHS.items()
    ],
}
_OBJECT_PATHS_BY_VERSION = {
    "0.1": V01_OBJECT_PATHS,
    "0.2": V02_OBJECT_PATHS,
    "0.3": V03_OBJECT_PATHS,
    "0.4": V04_OBJECT_PATHS,
}
_SCHEMA_FACTORIES_BY_VERSION = {
    "0.1": V01_SCHEMA_FACTORIES,
    "0.2": V02_SCHEMA_FACTORIES,
    "0.3": V03_SCHEMA_FACTORIES,
    "0.4": V04_SCHEMA_FACTORIES,
}
_FROZEN_DIGESTS_BY_VERSION = {
    "0.1": _FROZEN_V01_DIGESTS,
    "0.2": _FROZEN_V02_DIGESTS,
    "0.3": _FROZEN_V03_DIGESTS,
    "0.4": _FROZEN_V04_DIGESTS,
}
_FROZEN_REGISTRIES_BY_VERSION = {
    "0.1": _FROZEN_V01_REGISTRY,
    "0.2": _FROZEN_V02_REGISTRY,
    "0.3": _FROZEN_V03_REGISTRY,
    "0.4": _FROZEN_V04_REGISTRY,
}
_FILENAMES_BY_VERSION = {
    version: frozenset({_REGISTRY_FILENAME, *object_paths.values()})
    for version, object_paths in _OBJECT_PATHS_BY_VERSION.items()
}
# Backward-compatible private aliases retained for focused v0.1 tamper tests.
_VERSION = _DEFAULT_VERSION
_OBJECT_PATHS = V01_OBJECT_PATHS
_SCHEMA_FACTORIES = V01_SCHEMA_FACTORIES
_FILENAMES = _FILENAMES_BY_VERSION[_DEFAULT_VERSION]
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
    if version not in _OBJECT_PATHS_BY_VERSION:
        raise ValueError(f"unknown protocol version: {version}")


def _require_object_type(object_type: str, version: str) -> str:
    _require_version(version)
    try:
        return _OBJECT_PATHS_BY_VERSION[version][object_type]
    except KeyError as error:
        raise ValueError(f"unknown object type: {object_type}") from error


def _runtime_directory(version: str):
    _require_version(version)
    return resources.files("openworkproof").joinpath("schemas", f"v{version}")


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
    filenames = _FILENAMES_BY_VERSION[version]
    try:
        entries = tuple(directory.iterdir())
        if {entry.name for entry in entries} != filenames:
            raise RuntimeError("authoritative schema resource set is invalid")
        files: dict[str, bytes] = {}
        for entry in entries:
            is_symlink = getattr(entry, "is_symlink", lambda: False)
            if is_symlink() or not entry.is_file():
                raise RuntimeError("authoritative schema resource set is invalid")
            files[entry.name] = entry.read_bytes()
    except (FileNotFoundError, IsADirectoryError, OSError) as error:
        raise RuntimeError("authoritative schema resource set is invalid") from error

    frozen_digests = _FROZEN_DIGESTS_BY_VERSION[version]
    for filename, expected_digest in frozen_digests.items():
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
    if registry != _FROZEN_REGISTRIES_BY_VERSION[version]:
        raise RuntimeError("authoritative schema registry is not frozen")
    return files


def authoritative_schema(
    object_type: str,
    version: str = _DEFAULT_VERSION,
) -> dict:
    """Load one schema from installed package authority."""

    filename = _require_object_type(object_type, version)
    files = _validated_runtime_files(version)
    return _parse_canonical_json(
        files[filename],
        error_message="authoritative schema is invalid",
    )


def authoritative_digest(
    object_type: str,
    version: str = _DEFAULT_VERSION,
) -> str:
    """Return the verified SHA-256 from the installed schema registry."""

    filename = _require_object_type(object_type, version)
    _validated_runtime_files(version)
    return _FROZEN_DIGESTS_BY_VERSION[version][filename]


def _generated_files(
    *, version: str = _DEFAULT_VERSION,
) -> dict[str, bytes]:
    _require_version(version)
    object_paths = _OBJECT_PATHS_BY_VERSION[version]
    factories = _SCHEMA_FACTORIES_BY_VERSION[version]
    files = {
        object_paths[object_type]: rfc8785.dumps(factory())
        for object_type, factory in factories.items()
    }
    frozen_digests = _FROZEN_DIGESTS_BY_VERSION[version]
    for filename, content in files.items():
        if (
            hashlib.sha256(content).hexdigest()
            != frozen_digests[filename]
        ):
            raise RuntimeError(
                f"frozen v{version} schema drift: {filename}; "
                "anchor changes require protocol review"
            )
    generated = {
        _REGISTRY_FILENAME: rfc8785.dumps(
            _FROZEN_REGISTRIES_BY_VERSION[version]
        ),
        **files,
    }
    for filename, content in generated.items():
        if (
            hashlib.sha256(content).hexdigest()
            != frozen_digests[filename]
        ):
            raise RuntimeError(
                f"frozen v{version} schema drift: {filename}; "
                "anchor changes require protocol review"
            )
    return generated


def _preflight_target(
    directory: Path,
    filenames: frozenset[str] = _FILENAMES,
) -> tuple[Path, tuple[Path, ...]]:
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
        path.name not in filenames
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
            _remove_schema_directory(stage, frozenset(files))
        except (OSError, RuntimeError) as cleanup_error:
            raise SchemaCleanupError(
                "schema staging failed and its directory could not be cleaned",
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
                entry.name not in filenames
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


def _recover_target(
    target: Path,
    filenames: frozenset[str] = _FILENAMES,
) -> None:
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
            _remove_schema_directory(backup, filenames)
        except (OSError, RuntimeError) as error:
            failed_backups.append(backup)
            first_error = first_error or error
    for stage in stages:
        try:
            _remove_schema_directory(stage, filenames)
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
    filenames: frozenset[str] = _FILENAMES,
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
                    _remove_schema_directory(target, filenames)
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
            _remove_schema_directory(backup, filenames)
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
    *,
    version: str = _DEFAULT_VERSION,
) -> None:
    """Generate the frozen package schemas and optional published mirror."""

    files = _generated_files(version=version)
    filenames = _FILENAMES_BY_VERSION[version]
    requested = [destination] + ([mirror] if mirror is not None else [])
    plans = [_preflight_target(path, filenames) for path in requested]
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
            locked_plans = [
                _preflight_target(path, filenames) for path in requested
            ]
            locked_targets = [target for target, _ in locked_plans]
            if locked_targets != targets:
                raise ValueError("schema destination changed before locking")
            for target in targets:
                _recover_target(target, filenames)

            stages: list[Path] = []
            try:
                for target in targets:
                    stages.append(_stage_schema_directory(target, files))
                _commit_staged_directories(
                    tuple(zip(targets, stages, strict=True)),
                    filenames,
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

    if version not in _OBJECT_PATHS_BY_VERSION:
        return SchemaComparisonResult(False, "UNKNOWN_PROTOCOL_VERSION")
    try:
        builtin_files = _validated_runtime_files(version)
        filenames = _FILENAMES_BY_VERSION[version]
        if (
            directory.is_symlink()
            or not directory.is_dir()
            or {path.name for path in directory.iterdir()} != filenames
        ):
            return SchemaComparisonResult(
                False,
                "AUTHORITATIVE_SCHEMA_MISMATCH",
            )
        for filename in filenames:
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
        description="Generate authoritative OpenWorkProof protocol schemas."
    )
    parser.add_argument(
        "--version",
        required=True,
        choices=tuple(_OBJECT_PATHS_BY_VERSION),
    )
    parser.add_argument(
        "--destination",
        "--output",
        dest="destination",
        required=True,
        type=Path,
    )
    parser.add_argument("--mirror", type=Path)
    arguments = parser.parse_args(argv)
    write_authoritative_schemas(
        arguments.destination,
        mirror=arguments.mirror,
        version=arguments.version,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
