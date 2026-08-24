"""Offline-verifiable OpenWorkProof human agency boundary bundles (0.1).

This module exports a minimal, offline-verifiable snapshot of one WorkOrder's
human agency boundary: the signed WorkOrder (whose key bindings are the
public-key authority), every profile and transition, and every appeal. The
exporter freezes one canonical UTC second ``evaluated_at`` from a trusted clock
inside the ledger target lock and re-resolves the signed history into an
``active``, ``revoked``, or ``expired`` boundary.

The closed outer manifest is a self-contained snapshot attestation signed by
the WorkOrder Sidecar key (``_signed_domain="manifest"`` v0.1). Its signature
covers ``work_order_digest``, ``evaluated_at``, ``current_status``,
``current_profile_id``, ``boundary`` and every entry, so an unauthenticated
keyless rewrite — deleting the revoke/supersede suffix or rewriting
``evaluated_at``/status — fails closed. The signature fixes the claimed
``evaluated_at`` but does not prove real-world time: it is not a timestamp
authority endorsement.

The verifier re-derives the boundary from the manifest and the file bytes
only; it never reads the ledger, the network, environment private keys, or the
system clock, and it never accepts a caller-supplied ``now``.
"""

from __future__ import annotations

import ctypes
from dataclasses import dataclass
import errno
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import uuid
from datetime import datetime, timezone
from typing import Annotated, Any, Callable, Literal

import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import BeforeValidator, ConfigDict, model_validator

from openworkproof.agency import (
    AgencyAppealV01,
    AgencyProfileHistoryError,
    AgencyProfileTransitionV01,
    HumanAgencyProfileV01,
    resolve_human_agency_profile_structure,
    verify_agency_appeal,
    verify_agency_profile_transition,
    verify_human_agency_profile,
)
from openworkproof.agency_ledger import (
    load_agency_appeals,
    load_agency_history,
)
from openworkproof.models import (
    CanonicalUTCTime,
    Digest64,
    KeyBinding,
    ProtocolModel,
    SafeNonNegativeInt,
    SignedProtocolModel,
    WorkOrder,
)
from openworkproof.signing import (
    decode_and_verify_key_binding,
    key_id,
    sign_payload,
    verify_payload,
    verify_work_order_identity_bindings,
)


__all__ = [
    "AGENCY_BUNDLE_BOUNDARY",
    "AGENCY_VERIFY_SCRIPT",
    "MAX_AGENCY_FILES",
    "MAX_AGENCY_FILE_BYTES",
    "MAX_AGENCY_TOTAL_BYTES",
    "AgencyBundleError",
    "AgencyBundleManifestEntryV01",
    "AgencyBundleManifestV01",
    "AgencyBundleVerificationResultV01",
    "compose_agency_manifest",
    "export_agency_bundle",
    "validate_agency_bundle_manifest",
    "verify_agency_bundle_directory",
]

MAX_AGENCY_FILES = 4096
MAX_AGENCY_FILE_BYTES = 64 * 1024 * 1024
MAX_AGENCY_TOTAL_BYTES = 512 * 1024 * 1024

AGENCY_BUNDLE_BOUNDARY = (
    "authorization evidence, not legal or employment judgment"
)

AGENCY_VERIFY_SCRIPT = (
    b"#!/bin/sh\n"
    b"set -eu\n"
    b'exec python -m openworkproof.agency_bundle "${1:-.}"\n'
)


class AgencyBundleError(RuntimeError):
    """An agency boundary bundle cannot be read or validated safely."""


def _agency_relative_path(value: Any) -> str:
    if type(value) is not str:
        raise ValueError("agency bundle path must be a strict string")
    if not value or len(value.encode("utf-8")) > 512:
        raise ValueError("agency bundle path length is invalid")
    if value.startswith("/") or "\\" in value or "\x00" in value or "//" in value:
        raise ValueError("agency bundle path is not canonical relative POSIX")
    if any(part in {"", ".", ".."} for part in value.split("/")):
        raise ValueError("agency bundle path contains an unsafe segment")
    return value


AgencyRelativePath = Annotated[str, BeforeValidator(_agency_relative_path)]

_AGENCY_BUNDLE_CONFIG = ConfigDict(
    extra="forbid",
    frozen=True,
    strict=True,
    validate_assignment=True,
    revalidate_instances="subclass-instances",
)


class AgencyBundleManifestEntryV01(ProtocolModel):
    model_config = _AGENCY_BUNDLE_CONFIG

    path: AgencyRelativePath
    sha256: Digest64
    size_bytes: SafeNonNegativeInt


class AgencyBundleManifestV01(SignedProtocolModel):
    model_config = _AGENCY_BUNDLE_CONFIG
    _signed_domain = "manifest"

    schema_version: Literal["openworkproof-agency-bundle/0.1"]
    work_order_digest: Digest64
    evaluated_at: CanonicalUTCTime
    current_status: Literal["active", "revoked", "expired"]
    current_profile_id: Digest64 | None
    boundary: Literal[AGENCY_BUNDLE_BOUNDARY]
    entries: tuple[AgencyBundleManifestEntryV01, ...]

    @model_validator(mode="after")
    def _closed_manifest(self) -> AgencyBundleManifestV01:
        paths = tuple(entry.path for entry in self.entries)
        if not paths or paths != tuple(
            sorted(set(paths), key=lambda item: item.encode("utf-8"))
        ):
            raise ValueError(
                "agency bundle entries must be non-empty, sorted, and unique"
            )
        if self.current_status == "active" and self.current_profile_id is None:
            raise ValueError("active agency bundle must name a current profile")
        if self.current_status == "revoked" and self.current_profile_id is not None:
            raise ValueError(
                "revoked agency bundle must not name a current profile"
            )
        if self.current_status == "expired" and self.current_profile_id is None:
            raise ValueError(
                "expired agency bundle must name the terminal profile"
            )
        return self


class AgencyBundleVerificationResultV01(ProtocolModel):
    model_config = _AGENCY_BUNDLE_CONFIG

    schema_version: Literal["openworkproof-agency-bundle-result/0.1"]
    work_order_digest: Digest64
    evaluated_at: CanonicalUTCTime
    current_status: Literal["active", "revoked", "expired"]
    current_profile_id: Digest64 | None
    appeal_count: SafeNonNegativeInt
    boundary: Literal[AGENCY_BUNDLE_BOUNDARY]


@dataclass(frozen=True, slots=True)
class _ScannedFile:
    payload: bytes
    mode: int


@dataclass(frozen=True, slots=True)
class _AgencyExportSnapshot:
    work_order: WorkOrder
    profiles: tuple[HumanAgencyProfileV01, ...]
    transitions: tuple[AgencyProfileTransitionV01, ...]
    appeals: tuple[AgencyAppealV01, ...]
    evaluated_at: datetime
    current_status: Literal["active", "revoked", "expired"]
    current_profile_id: str | None


def _canonical(value: object) -> bytes:
    return rfc8785.dumps(value)


def _read_regular(path: Path) -> _ScannedFile:
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise AgencyBundleError(
                "agency bundles contain stable single-link regular files only"
            )
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
        )
    except AgencyBundleError:
        raise
    except OSError as error:
        raise AgencyBundleError(
            "agency bundle file cannot be opened safely"
        ) from error
    try:
        opened = os.fstat(descriptor)
        identity = (
            opened.st_dev,
            opened.st_ino,
            opened.st_mode,
            opened.st_nlink,
            opened.st_size,
            opened.st_mtime_ns,
        )
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or (
                before.st_dev,
                before.st_ino,
                before.st_mode,
                before.st_nlink,
                before.st_size,
                before.st_mtime_ns,
            )
            != identity
        ):
            raise AgencyBundleError(
                "agency bundles contain stable single-link regular files only"
            )
        if opened.st_size > MAX_AGENCY_FILE_BYTES:
            raise AgencyBundleError("agency bundle file exceeds the size limit")
        chunks: list[bytes] = []
        remaining = MAX_AGENCY_FILE_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
        if (
            len(payload) != opened.st_size
            or (
                after.st_dev,
                after.st_ino,
                after.st_mode,
                after.st_nlink,
                after.st_size,
                after.st_mtime_ns,
            )
            != identity
        ):
            raise AgencyBundleError(
                "agency bundle file changed while being read"
            )
    finally:
        os.close(descriptor)
    try:
        final = path.lstat()
    except OSError as error:
        raise AgencyBundleError(
            "agency bundle file changed after read"
        ) from error
    if (
        final.st_dev,
        final.st_ino,
        final.st_mode,
        final.st_nlink,
        final.st_size,
        final.st_mtime_ns,
    ) != identity:
        raise AgencyBundleError("agency bundle file changed after read")
    return _ScannedFile(payload=payload, mode=stat.S_IMODE(opened.st_mode))


def _scan_tree(root: Path) -> dict[str, _ScannedFile]:
    if root.is_symlink() or not root.is_dir():
        raise AgencyBundleError("agency bundle root must be a real directory")
    files: dict[str, _ScannedFile] = {}
    directories: set[str] = set()
    total = 0
    try:
        for directory, names, filenames in os.walk(root, followlinks=False):
            directory_path = Path(directory)
            for name in names:
                child = directory_path / name
                metadata = child.lstat()
                if child.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
                    raise AgencyBundleError(
                        "agency bundle tree contains a non-directory"
                    )
                directories.add(child.relative_to(root).as_posix())
            for name in filenames:
                path = directory_path / name
                relative = _agency_relative_path(
                    path.relative_to(root).as_posix()
                )
                if relative in files:
                    raise AgencyBundleError("agency bundle path is duplicated")
                if len(files) >= MAX_AGENCY_FILES:
                    raise AgencyBundleError(
                        "agency bundle file count exceeds the limit"
                    )
                scanned = _read_regular(path)
                files[relative] = scanned
                total += len(scanned.payload)
                if total > MAX_AGENCY_TOTAL_BYTES:
                    raise AgencyBundleError(
                        "agency bundle total size exceeds the limit"
                    )
        expected_directories = {
            parent.as_posix()
            for relative in files
            for parent in Path(relative).parents
            if parent.as_posix() != "."
        }
        if directories != expected_directories:
            raise AgencyBundleError(
                "agency bundle directory set is not exact"
            )
    except AgencyBundleError:
        raise
    except (OSError, UnicodeError, ValueError) as error:
        raise AgencyBundleError("agency bundle tree scan failed") from error
    return files


def _canonical_root(path: Path) -> Path:
    absolute = Path(os.path.abspath(path))
    if absolute.is_symlink():
        raise AgencyBundleError("agency bundle path must not be a symlink")
    try:
        resolved = absolute.resolve(strict=True)
    except OSError as error:
        raise AgencyBundleError(
            "agency bundle path cannot be resolved"
        ) from error
    if resolved != absolute:
        raise AgencyBundleError(
            "agency bundle path must not traverse symlinks"
        )
    return resolved


def _canonical_json(payload: bytes, label: str) -> object:
    try:
        value = json.loads(payload)
    except Exception as error:
        raise AgencyBundleError(f"{label} is invalid") from error
    if _canonical(value) != payload:
        raise AgencyBundleError(f"{label} is not canonical")
    return value


def _parse_agency_manifest(payload: bytes) -> AgencyBundleManifestV01:
    try:
        manifest = AgencyBundleManifestV01.model_validate(json.loads(payload))
    except Exception as error:
        raise AgencyBundleError("agency manifest is invalid") from error
    if _canonical(manifest.model_dump(mode="json")) != payload:
        raise AgencyBundleError("agency manifest is not canonical")
    return manifest


def _write_new(
    root: Path,
    relative: str,
    payload: bytes,
    *,
    mode: int = 0o600,
) -> None:
    relative = _agency_relative_path(relative)
    target = root.joinpath(*relative.split("/"))
    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(
        target,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0),
        mode,
    )
    try:
        os.fchmod(descriptor, mode)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise AgencyBundleError(
                    "agency bundle snapshot write made no progress"
                )
            view = view[written:]
    finally:
        os.close(descriptor)


_REQUIRED_AGENCY_FILES = frozenset(
    {
        "agency/work-order.json",
        "verify.sh",
    }
)


def _path_is_allowed(path: str) -> bool:
    return (
        path == "verify.sh"
        or path == "agency/work-order.json"
        or path.startswith("agency/profiles/")
        or path.startswith("agency/transitions/")
        or path.startswith("agency/appeals/")
    )


def _derive_bundle_status(
    work_order: WorkOrder,
    profiles: tuple[HumanAgencyProfileV01, ...],
    transitions: tuple[AgencyProfileTransitionV01, ...],
    evaluated_at: datetime,
) -> tuple[str, str | None]:
    """Re-resolve the signed history into (status, current_profile_id)."""

    structure = resolve_human_agency_profile_structure(
        work_order, profiles, transitions
    )
    if structure.status == "revoked":
        return "revoked", None
    current = structure.current_profile
    if current is None:
        raise AgencyBundleError("agency profile history resolved without a profile")
    if current.valid_from <= evaluated_at <= current.expires_at:
        return "active", current.profile_id
    return "expired", current.profile_id


def compose_agency_manifest(
    files: dict[str, bytes],
    *,
    work_order_digest: str,
    evaluated_at: str,
    current_status: Literal["active", "revoked", "expired"],
    current_profile_id: str | None,
    sidecar_private_key: Ed25519PrivateKey,
) -> AgencyBundleManifestV01:
    """Compose and Sidecar-sign the deterministic outer manifest.

    The manifest is a self-contained snapshot attestation signed by the
    WorkOrder Sidecar key. Its signature covers ``work_order_digest``,
    ``evaluated_at``, ``current_status``, ``current_profile_id``,
    ``boundary`` and every ``entries`` element (path/SHA-256/size), so any
    keyless rewrite of the closed snapshot fails closed on verification. The
    manifest is never listed in its own ``entries`` (no self-hash).
    """

    if type(files) is not dict or any(
        type(path) is not str or type(payload) is not bytes
        for path, payload in files.items()
    ):
        raise AgencyBundleError(
            "agency manifest files must be an exact byte map"
        )
    if not isinstance(sidecar_private_key, Ed25519PrivateKey):
        raise AgencyBundleError("sidecar private key must be Ed25519")
    if "agency-manifest.json" in files:
        raise AgencyBundleError("agency manifest must not include itself")
    try:
        normalized = {
            _agency_relative_path(path): payload
            for path, payload in files.items()
        }
    except ValueError as error:
        raise AgencyBundleError(
            "agency manifest file path is invalid"
        ) from error
    if len(normalized) > MAX_AGENCY_FILES:
        raise AgencyBundleError("agency bundle file count exceeds the limit")
    if any(
        len(payload) > MAX_AGENCY_FILE_BYTES
        for payload in normalized.values()
    ):
        raise AgencyBundleError("agency bundle file exceeds the size limit")
    if sum(len(payload) for payload in normalized.values()) > (
        MAX_AGENCY_TOTAL_BYTES
    ):
        raise AgencyBundleError("agency bundle total size exceeds the limit")
    actual = set(normalized)
    if not _REQUIRED_AGENCY_FILES <= actual:
        raise AgencyBundleError("agency bundle required files are missing")
    if any(not _path_is_allowed(path) for path in actual):
        raise AgencyBundleError("agency bundle path allowlist is invalid")
    if normalized["verify.sh"] != AGENCY_VERIFY_SCRIPT:
        raise AgencyBundleError("agency bundle required files are invalid")
    entries = tuple(
        AgencyBundleManifestEntryV01(
            path=path,
            sha256=hashlib.sha256(payload).hexdigest(),
            size_bytes=len(payload),
        )
        for path, payload in sorted(
            normalized.items(), key=lambda item: item[0].encode("utf-8")
        )
    )
    try:
        payload = {
            "schema_version": "openworkproof-agency-bundle/0.1",
            "work_order_digest": work_order_digest,
            "evaluated_at": evaluated_at,
            "current_status": current_status,
            "current_profile_id": current_profile_id,
            "boundary": AGENCY_BUNDLE_BOUNDARY,
            "entries": [entry.model_dump(mode="json") for entry in entries],
        }
        return AgencyBundleManifestV01.model_validate(
            sign_payload("manifest", payload, sidecar_private_key)
        )
    except AgencyBundleError:
        raise
    except Exception as error:
        raise AgencyBundleError("agency manifest summary is invalid") from error


def validate_agency_bundle_manifest(
    bundle_root: Path,
) -> AgencyBundleManifestV01:
    """Validate only the stable outer snapshot and closed file manifest.

    This checks the canonical manifest bytes, the digest self-consistency, and
    the exact file set/entry integrity; it does not verify the Sidecar
    signature. Full attestation (Sidecar role binding + signature) is enforced
    by :func:`verify_agency_bundle_directory`.
    """

    try:
        manifest, _scanned = _load_agency_manifest_snapshot(bundle_root)
        return manifest
    except AgencyBundleError:
        raise
    except Exception as error:
        raise AgencyBundleError(
            "agency bundle manifest validation failed"
        ) from error


def _load_agency_manifest_snapshot(
    bundle_root: Path,
) -> tuple[AgencyBundleManifestV01, dict[str, _ScannedFile]]:
    root = _canonical_root(Path(bundle_root))
    scanned = _scan_tree(root)
    try:
        manifest_file = scanned.get("agency-manifest.json")
        if manifest_file is None:
            raise AgencyBundleError("agency manifest is missing")
        manifest = _parse_agency_manifest(manifest_file.payload)
        actual = set(scanned) - {"agency-manifest.json"}
        expected = {entry.path for entry in manifest.entries}
        if actual != expected:
            raise AgencyBundleError("agency manifest file set is not exact")
        for entry in manifest.entries:
            payload = scanned[entry.path].payload
            if (
                len(payload) != entry.size_bytes
                or hashlib.sha256(payload).hexdigest() != entry.sha256
            ):
                raise AgencyBundleError(
                    "agency manifest entry integrity failed"
                )
        if not _REQUIRED_AGENCY_FILES <= actual:
            raise AgencyBundleError("agency bundle required files are missing")
        if any(not _path_is_allowed(path) for path in actual):
            raise AgencyBundleError("agency bundle path allowlist is invalid")
        verify_file = scanned["verify.sh"]
        if (
            verify_file.payload != AGENCY_VERIFY_SCRIPT
            or not verify_file.mode & 0o111
        ):
            raise AgencyBundleError("agency bundle required files are invalid")
        return manifest, scanned
    except AgencyBundleError:
        raise
    except Exception as error:
        raise AgencyBundleError(
            "agency bundle manifest snapshot is invalid"
        ) from error


def _load_work_order(scanned: dict[str, _ScannedFile]) -> WorkOrder:
    item = scanned.get("agency/work-order.json")
    if item is None:
        raise AgencyBundleError("agency work order is missing")
    raw = _canonical_json(item.payload, "agency work order")
    try:
        work_order = WorkOrder.model_validate(raw)
    except Exception as error:
        raise AgencyBundleError("agency work order is malformed") from error
    if not verify_work_order_identity_bindings(work_order):
        raise AgencyBundleError("agency work order authority is invalid")
    return work_order


def _sidecar_binding(work_order: WorkOrder) -> KeyBinding | None:
    matches = [
        binding
        for binding in work_order.key_bindings
        if binding.role == "Sidecar"
    ]
    if len(matches) != 1:
        return None
    return matches[0]


def _verify_manifest_signature(
    manifest: AgencyBundleManifestV01,
    work_order: WorkOrder,
) -> None:
    """Accept only the WorkOrder Sidecar binding as the snapshot attestor.

    The manifest is the closed outer snapshot; its signature must be produced
    by the Sidecar role key bound in the WorkOrder identity bindings. Any other
    role, a forged signature, or a keyless rewrite of the closed snapshot fails
    closed here.
    """

    sidecar_binding = _sidecar_binding(work_order)
    if sidecar_binding is None:
        raise AgencyBundleError("agency work order lacks a Sidecar binding")
    try:
        sidecar_public_key = decode_and_verify_key_binding(sidecar_binding)
    except (ValueError, TypeError) as error:
        raise AgencyBundleError("agency Sidecar binding is invalid") from error
    if not verify_payload(
        "manifest",
        manifest.model_dump(mode="json"),
        sidecar_public_key,
    ):
        raise AgencyBundleError("agency manifest signature is invalid")


def _load_agency_objects(
    scanned: dict[str, _ScannedFile],
    *,
    kind: str,
    model: type[Any],
    verify: Callable[[Any, WorkOrder], bool],
    work_order: WorkOrder,
    id_field: str,
) -> tuple:
    prefix = f"agency/{kind}/"
    result: dict[str, Any] = {}
    for relative, item in scanned.items():
        if not relative.startswith(prefix):
            continue
        if not relative.endswith(".json"):
            raise AgencyBundleError(
                "agency bundle contains a non-JSON object file"
            )
        name = relative[len(prefix) : -len(".json")]
        raw = _canonical_json(item.payload, f"agency {kind} object")
        try:
            obj = model.model_validate(raw)
        except Exception as error:
            raise AgencyBundleError(f"agency {kind} object is malformed") from error
        if getattr(obj, id_field) != name:
            raise AgencyBundleError(
                f"agency {kind} filename does not match its id"
            )
        if not verify(obj, work_order):
            raise AgencyBundleError(
                f"agency {kind} signature or binding is invalid"
            )
        if getattr(obj, id_field) in result:
            raise AgencyBundleError(f"agency {kind} id is duplicated")
        result[getattr(obj, id_field)] = obj
    return tuple(result.values())


def verify_agency_bundle_directory(
    bundle_root: Path,
) -> AgencyBundleVerificationResultV01:
    """Replay one agency boundary bundle from copied bytes without a ledger."""

    try:
        manifest, scanned = _load_agency_manifest_snapshot(bundle_root)
        work_order = _load_work_order(scanned)
        if manifest.work_order_digest != work_order.digest:
            raise AgencyBundleError(
                "agency manifest work_order_digest diverges from replay"
            )
        _verify_manifest_signature(manifest, work_order)
        profiles = _load_agency_objects(
            scanned,
            kind="profiles",
            model=HumanAgencyProfileV01,
            verify=verify_human_agency_profile,
            work_order=work_order,
            id_field="profile_id",
        )
        transitions = _load_agency_objects(
            scanned,
            kind="transitions",
            model=AgencyProfileTransitionV01,
            verify=verify_agency_profile_transition,
            work_order=work_order,
            id_field="transition_id",
        )
        appeals = _load_agency_objects(
            scanned,
            kind="appeals",
            model=AgencyAppealV01,
            verify=verify_agency_appeal,
            work_order=work_order,
            id_field="appeal_id",
        )
        profiles_by_id = {profile.profile_id: profile for profile in profiles}
        for appeal in appeals:
            target = profiles_by_id.get(appeal.profile_id)
            if target is None or target.digest != appeal.profile_digest:
                raise AgencyBundleError(
                    "agency appeal target is inconsistent"
                )
        status, current_profile_id = _derive_bundle_status(
            work_order,
            tuple(profiles),
            tuple(transitions),
            manifest.evaluated_at,
        )
        if (
            manifest.current_status,
            manifest.current_profile_id,
        ) != (status, current_profile_id):
            raise AgencyBundleError(
                "agency manifest status diverges from replay"
            )
        return AgencyBundleVerificationResultV01(
            schema_version="openworkproof-agency-bundle-result/0.1",
            work_order_digest=work_order.digest,
            evaluated_at=manifest.evaluated_at.strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            current_status=status,
            current_profile_id=current_profile_id,
            appeal_count=len(appeals),
            boundary=AGENCY_BUNDLE_BOUNDARY,
        )
    except AgencyBundleError:
        raise
    except Exception as error:
        raise AgencyBundleError("agency bundle verification failed") from error


def _fsync_agency_tree(root: Path) -> None:
    files = sorted(
        (path for path in root.rglob("*") if path.is_file()),
        key=lambda path: path.as_posix().encode("utf-8"),
    )
    directories = sorted(
        (path for path in root.rglob("*") if path.is_dir()),
        key=lambda path: len(path.parts),
        reverse=True,
    )
    for path in files:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    for path in (*directories, root):
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _rename_no_replace(source: Path, destination: Path) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    source_bytes = os.fsencode(source)
    destination_bytes = os.fsencode(destination)
    if sys.platform == "darwin":
        rename = libc.renameatx_np
        rename.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        rename.restype = ctypes.c_int
        result = rename(-2, source_bytes, -2, destination_bytes, 0x00000004)
    elif sys.platform.startswith("linux") and hasattr(libc, "renameat2"):
        rename = libc.renameat2
        rename.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        rename.restype = ctypes.c_int
        result = rename(-100, source_bytes, -100, destination_bytes, 1)
    else:
        raise AgencyBundleError(
            "atomic no-replace directory rename is unavailable"
        )
    if result != 0:
        error_number = ctypes.get_errno()
        if error_number in {errno.EEXIST, errno.ENOTEMPTY}:
            raise FileExistsError(
                error_number,
                os.strerror(error_number),
                destination,
            )
        raise OSError(
            error_number,
            os.strerror(error_number),
            destination,
        )


def _read_agency_export_snapshot(
    ledger: Path,
    clock: Callable[[], datetime],
) -> _AgencyExportSnapshot:
    from openworkproof.evidence import (  # noqa: PLC0415
        _best_effort_close,
        _best_effort_rollback,
        _borrow_or_acquire_target_lock,
        _freeze_trusted_utc_second,
        _release_target_lock,
        connect_ledger,
        load_authoritative_work_order,
    )

    path = Path(ledger)
    if not path.is_file():
        raise AgencyBundleError("agency export ledger is unavailable")
    lock_descriptor: int | None = None
    connection = None
    try:
        lock_descriptor, _ = _borrow_or_acquire_target_lock(path, None)
        evaluated_at = _freeze_trusted_utc_second(clock())
        connection = connect_ledger(path)
        try:
            work_order = load_authoritative_work_order(connection)
        finally:
            _best_effort_close(connection)
            connection = None
        history = load_agency_history(path, work_order.digest)
        appeals = load_agency_appeals(path, work_order.digest)
        status, current_profile_id = _derive_bundle_status(
            work_order,
            history.profiles,
            history.transitions,
            evaluated_at,
        )
        return _AgencyExportSnapshot(
            work_order=work_order,
            profiles=history.profiles,
            transitions=history.transitions,
            appeals=appeals,
            evaluated_at=evaluated_at,
            current_status=status,
            current_profile_id=current_profile_id,
        )
    except AgencyBundleError:
        raise
    except AgencyProfileHistoryError as error:
        raise AgencyBundleError(
            "agency export history is invalid"
        ) from error
    except Exception as error:
        _best_effort_rollback(connection)
        raise AgencyBundleError("agency export snapshot is invalid") from error
    finally:
        close_error = _best_effort_close(connection)
        _, release_errors = _release_target_lock(lock_descriptor)
        cleanup_errors = tuple(
            item
            for item in (close_error, *release_errors)
            if item is not None
        )
        if cleanup_errors:
            raise AgencyBundleError(
                "agency export snapshot cleanup failed"
            ) from cleanup_errors[0]


def _write_agency_export_snapshot(
    stage: Path,
    snapshot: _AgencyExportSnapshot,
    sidecar_private_key: Ed25519PrivateKey,
) -> None:
    _write_new(
        stage,
        "agency/work-order.json",
        _canonical(snapshot.work_order.model_dump(mode="json")),
    )
    for profile in snapshot.profiles:
        _write_new(
            stage,
            f"agency/profiles/{profile.profile_id}.json",
            _canonical(profile.model_dump(mode="json")),
        )
    for transition in snapshot.transitions:
        _write_new(
            stage,
            f"agency/transitions/{transition.transition_id}.json",
            _canonical(transition.model_dump(mode="json")),
        )
    for appeal in snapshot.appeals:
        _write_new(
            stage,
            f"agency/appeals/{appeal.appeal_id}.json",
            _canonical(appeal.model_dump(mode="json")),
        )
    _write_new(stage, "verify.sh", AGENCY_VERIFY_SCRIPT, mode=0o700)

    files = {
        path.relative_to(stage).as_posix(): path.read_bytes()
        for path in stage.rglob("*")
        if path.is_file() and path.name != "agency-manifest.json"
    }
    manifest = compose_agency_manifest(
        files,
        work_order_digest=snapshot.work_order.digest,
        evaluated_at=snapshot.evaluated_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        current_status=snapshot.current_status,
        current_profile_id=snapshot.current_profile_id,
        sidecar_private_key=sidecar_private_key,
    )
    _write_new(
        stage,
        "agency-manifest.json",
        _canonical(manifest.model_dump(mode="json")),
    )


def _exact_agency_export_readback(
    destination: Path,
    expected: AgencyBundleManifestV01,
) -> bool:
    try:
        actual = validate_agency_bundle_manifest(destination)
        verified = verify_agency_bundle_directory(destination)
    except Exception:
        return False
    return (
        actual == expected
        and verified.work_order_digest == expected.work_order_digest
        and verified.current_status == expected.current_status
        and verified.current_profile_id == expected.current_profile_id
    )


def export_agency_bundle(
    ledger: Path,
    output: Path,
    *,
    sidecar_private_key: Ed25519PrivateKey,
    clock: Callable[[], datetime] | None = None,
) -> AgencyBundleManifestV01:
    """Export one current human agency boundary as an atomic offline bundle.

    ``sidecar_private_key`` is mandatory: the exporter signs the closed
    manifest snapshot with the WorkOrder Sidecar key. It is never read from
    the environment or a default, and it never enters the bundle. The key must
    match the Sidecar role binding of the authoritative WorkOrder, otherwise
    the export rejects before any stage is written.
    """

    if not isinstance(sidecar_private_key, Ed25519PrivateKey):
        raise AgencyBundleError("sidecar private key must be Ed25519")
    if clock is None:
        clock = lambda: datetime.now(timezone.utc)
    output = Path(output)
    parent = _canonical_root(output.parent)
    destination = parent / output.name
    if destination.exists() or destination.is_symlink():
        raise AgencyBundleError("agency bundle target already exists")
    ledger_resolved = Path(ledger).resolve()
    if destination == ledger_resolved or destination.is_relative_to(
        ledger_resolved
    ):
        raise AgencyBundleError("agency bundle output overlaps the ledger")
    stage = parent / f".{output.name}.openworkproof-agency-{uuid.uuid4().hex}.tmp"
    committed = False
    try:
        stage.mkdir(mode=0o700)
        snapshot = _read_agency_export_snapshot(ledger, clock)
        sidecar_binding = _sidecar_binding(snapshot.work_order)
        if sidecar_binding is None:
            raise AgencyBundleError("agency work order lacks a Sidecar binding")
        try:
            decode_and_verify_key_binding(sidecar_binding)
        except (ValueError, TypeError) as error:
            raise AgencyBundleError("agency Sidecar binding is invalid") from error
        if key_id(sidecar_private_key.public_key()) != sidecar_binding.key_id:
            raise AgencyBundleError(
                "sidecar private key does not match the WorkOrder Sidecar binding"
            )
        _write_agency_export_snapshot(stage, snapshot, sidecar_private_key)
        expected = validate_agency_bundle_manifest(stage)
        verified = verify_agency_bundle_directory(stage)
        if (
            verified.work_order_digest != snapshot.work_order.digest
            or verified.current_status != snapshot.current_status
            or verified.current_profile_id != snapshot.current_profile_id
        ):
            raise AgencyBundleError("agency export self-verification diverged")
        _fsync_agency_tree(stage)
        if destination.exists() or destination.is_symlink():
            raise AgencyBundleError(
                "agency bundle target appeared during export"
            )
        try:
            _rename_no_replace(stage, destination)
            parent_descriptor = os.open(parent, os.O_RDONLY)
            try:
                os.fsync(parent_descriptor)
            finally:
                os.close(parent_descriptor)
        except FileExistsError as error:
            raise AgencyBundleError(
                "agency bundle target appeared during export"
            ) from error
        except Exception as error:
            if _exact_agency_export_readback(destination, expected):
                committed = True
                return expected
            raise AgencyBundleError(
                "agency bundle commit outcome is indeterminate"
            ) from error
        committed = True
        return expected
    except AgencyBundleError:
        raise
    except Exception as error:
        raise AgencyBundleError("agency bundle export failed") from error
    finally:
        if not committed and stage.exists():
            try:
                shutil.rmtree(stage)
            except OSError as error:
                raise AgencyBundleError(
                    "agency bundle export cleanup failed"
                ) from error


def _main(arguments: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if arguments is None else arguments
    if len(arguments) > 1:
        print(
            json.dumps(
                {"error": "usage: python -m openworkproof.agency_bundle [DIR]"},
                ensure_ascii=False,
            ),
            file=sys.stderr,
        )
        return 4
    root = Path(arguments[0] if arguments else ".")
    try:
        result = verify_agency_bundle_directory(root)
    except AgencyBundleError as error:
        print(
            json.dumps(
                {
                    "schema_version": (
                        "openworkproof-agency-bundle-result/0.1"
                    ),
                    "work_order_digest": None,
                    "evaluated_at": None,
                    "current_status": None,
                    "current_profile_id": None,
                    "appeal_count": None,
                    "boundary": AGENCY_BUNDLE_BOUNDARY,
                },
                ensure_ascii=False,
                sort_keys=True,
            )
        )
        print(
            json.dumps({"error": str(error)}, ensure_ascii=False),
            file=sys.stderr,
        )
        return 4
    print(
        json.dumps(
            result.model_dump(mode="json"),
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
