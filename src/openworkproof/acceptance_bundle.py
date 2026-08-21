"""Offline-verifiable OpenWorkProof acceptance bundles (0.1)."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
from typing import Annotated, Any, Literal

import rfc8785
from pydantic import BeforeValidator, ConfigDict, model_validator

from openworkproof.models import Digest64, ProtocolModel, SafeNonNegativeInt


__all__ = [
    "ACCEPTANCE_VERIFY_SCRIPT",
    "MAX_ACCEPTANCE_FILES",
    "MAX_ACCEPTANCE_FILE_BYTES",
    "MAX_ACCEPTANCE_TOTAL_BYTES",
    "AcceptanceBundleError",
    "AcceptanceBundleVerificationResult",
    "AcceptanceManifestEntry",
    "AcceptanceManifestV01",
    "compose_acceptance_manifest",
    "validate_acceptance_bundle_manifest",
    "verify_acceptance_bundle_directory",
]

MAX_ACCEPTANCE_FILES = 4096
MAX_ACCEPTANCE_FILE_BYTES = 64 * 1024 * 1024
MAX_ACCEPTANCE_TOTAL_BYTES = 512 * 1024 * 1024

ACCEPTANCE_VERIFY_SCRIPT = (
    b"#!/bin/sh\n"
    b"set -eu\n"
    b'exec python -m openworkproof.acceptance_bundle "${1:-.}"\n'
)


class AcceptanceBundleError(RuntimeError):
    """An acceptance bundle cannot be read or validated safely."""


def _acceptance_relative_path(value: Any) -> str:
    if type(value) is not str:
        raise ValueError("acceptance bundle path must be a strict string")
    if not value or len(value.encode("utf-8")) > 512:
        raise ValueError("acceptance bundle path length is invalid")
    if (
        value.startswith("/")
        or "\\" in value
        or "\x00" in value
        or "//" in value
    ):
        raise ValueError("acceptance bundle path is not canonical relative POSIX")
    if any(part in {"", ".", ".."} for part in value.split("/")):
        raise ValueError("acceptance bundle path contains an unsafe segment")
    return value


AcceptanceRelativePath = Annotated[
    str,
    BeforeValidator(_acceptance_relative_path),
]

_ACCEPTANCE_BUNDLE_CONFIG = ConfigDict(
    extra="forbid",
    frozen=True,
    strict=True,
    validate_assignment=True,
    revalidate_instances="subclass-instances",
)


class AcceptanceManifestEntry(ProtocolModel):
    model_config = _ACCEPTANCE_BUNDLE_CONFIG

    path: AcceptanceRelativePath
    sha256: Digest64
    size_bytes: SafeNonNegativeInt


class AcceptanceManifestV01(ProtocolModel):
    model_config = _ACCEPTANCE_BUNDLE_CONFIG

    schema_version: Literal["openworkproof-acceptance-bundle/0.1"]
    surface_manifest_digest: Digest64
    delivery_manifest_digest: Digest64
    work_order_digest: Digest64
    verification_decision_digest: Digest64
    composition_report_digest: Digest64
    terminal_decision: Literal["accepted", "rejected"]
    terminal_receipt_digest: Digest64
    acceptance_decision_binding_digest: Digest64
    entries: tuple[AcceptanceManifestEntry, ...]

    @model_validator(mode="after")
    def _closed_manifest(self) -> AcceptanceManifestV01:
        paths = tuple(entry.path for entry in self.entries)
        if not paths or paths != tuple(
            sorted(set(paths), key=lambda item: item.encode("utf-8"))
        ):
            raise ValueError(
                "acceptance bundle entries must be non-empty, sorted, and unique"
            )
        by_path = {entry.path: entry for entry in self.entries}
        surface = by_path.get("surface/surface-manifest.json")
        delivery = by_path.get("surface/delivery-package/manifest.json")
        if (
            surface is None
            or delivery is None
            or surface.sha256 != self.surface_manifest_digest
            or delivery.sha256 != self.delivery_manifest_digest
        ):
            raise ValueError("acceptance manifest summary digests are inconsistent")
        return self


class AcceptanceBundleVerificationResult(ProtocolModel):
    model_config = _ACCEPTANCE_BUNDLE_CONFIG

    schema_version: Literal["openworkproof-acceptance-bundle-result/0.1"]
    terminal_decision: Literal["ACCEPTED", "REJECTED"]
    work_order_digest: Digest64
    surface_manifest_digest: Digest64
    verification_decision_digest: Digest64
    terminal_receipt_digest: Digest64
    acceptance_decision_binding_digest: Digest64
    boundary: Literal[
        "not payment, settlement, legal audit, or adoption"
    ]


@dataclass(frozen=True, slots=True)
class _ScannedFile:
    payload: bytes
    mode: int


def _canonical(value: object) -> bytes:
    return rfc8785.dumps(value)


def _read_regular(path: Path) -> _ScannedFile:
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise AcceptanceBundleError(
                "acceptance bundles contain stable single-link regular files only"
            )
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
        )
    except AcceptanceBundleError:
        raise
    except OSError as error:
        raise AcceptanceBundleError(
            "acceptance bundle file cannot be opened safely"
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
            raise AcceptanceBundleError(
                "acceptance bundles contain stable single-link regular files only"
            )
        if opened.st_size > MAX_ACCEPTANCE_FILE_BYTES:
            raise AcceptanceBundleError(
                "acceptance bundle file exceeds the size limit"
            )
        chunks: list[bytes] = []
        remaining = MAX_ACCEPTANCE_FILE_BYTES + 1
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
            raise AcceptanceBundleError(
                "acceptance bundle file changed while being read"
            )
    finally:
        os.close(descriptor)
    try:
        final = path.lstat()
    except OSError as error:
        raise AcceptanceBundleError(
            "acceptance bundle file changed after read"
        ) from error
    if (
        final.st_dev,
        final.st_ino,
        final.st_mode,
        final.st_nlink,
        final.st_size,
        final.st_mtime_ns,
    ) != identity:
        raise AcceptanceBundleError(
            "acceptance bundle file changed after read"
        )
    return _ScannedFile(payload=payload, mode=stat.S_IMODE(opened.st_mode))


def _scan_tree(root: Path) -> dict[str, _ScannedFile]:
    if root.is_symlink() or not root.is_dir():
        raise AcceptanceBundleError(
            "acceptance bundle root must be a real directory"
        )
    files: dict[str, _ScannedFile] = {}
    total = 0
    try:
        for directory, names, filenames in os.walk(root, followlinks=False):
            directory_path = Path(directory)
            for name in names:
                child = directory_path / name
                metadata = child.lstat()
                if child.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
                    raise AcceptanceBundleError(
                        "acceptance bundle tree contains a non-directory"
                    )
            for name in filenames:
                path = directory_path / name
                relative = _acceptance_relative_path(
                    path.relative_to(root).as_posix()
                )
                if relative in files:
                    raise AcceptanceBundleError(
                        "acceptance bundle path is duplicated"
                    )
                if len(files) >= MAX_ACCEPTANCE_FILES:
                    raise AcceptanceBundleError(
                        "acceptance bundle file count exceeds the limit"
                    )
                scanned = _read_regular(path)
                files[relative] = scanned
                total += len(scanned.payload)
                if total > MAX_ACCEPTANCE_TOTAL_BYTES:
                    raise AcceptanceBundleError(
                        "acceptance bundle total size exceeds the limit"
                    )
    except AcceptanceBundleError:
        raise
    except (OSError, UnicodeError, ValueError) as error:
        raise AcceptanceBundleError(
            "acceptance bundle tree scan failed"
        ) from error
    return files


def _canonical_root(path: Path) -> Path:
    absolute = Path(os.path.abspath(path))
    if absolute.is_symlink():
        raise AcceptanceBundleError(
            "acceptance bundle path must not be a symlink"
        )
    try:
        resolved = absolute.resolve(strict=True)
    except OSError as error:
        raise AcceptanceBundleError(
            "acceptance bundle path cannot be resolved"
        ) from error
    if resolved != absolute:
        raise AcceptanceBundleError(
            "acceptance bundle path must not traverse symlinks"
        )
    return resolved


def _parse_acceptance_manifest(payload: bytes) -> AcceptanceManifestV01:
    try:
        manifest = AcceptanceManifestV01.model_validate(json.loads(payload))
    except Exception as error:
        raise AcceptanceBundleError(
            "acceptance manifest is invalid"
        ) from error
    if _canonical(manifest.model_dump(mode="json")) != payload:
        raise AcceptanceBundleError(
            "acceptance manifest is not canonical"
        )
    return manifest


def _write_new(
    root: Path,
    relative: str,
    payload: bytes,
    *,
    mode: int = 0o600,
) -> None:
    relative = _acceptance_relative_path(relative)
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
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise AcceptanceBundleError(
                    "acceptance bundle snapshot write made no progress"
                )
            view = view[written:]
    finally:
        os.close(descriptor)


_REQUIRED_ACCEPTANCE_FILES = frozenset(
    {
        "acceptance/committed-evidence-index.json",
        "acceptance/composition-reports.json",
        "acceptance/decision-binding.json",
        "acceptance/effective-grants.json",
        "acceptance/grant-attempts.json",
        "acceptance/terminal-receipt.json",
        "surface/delivery-package/manifest.json",
        "surface/surface-manifest.json",
        "verify.sh",
    }
)


def _path_is_allowed(path: str) -> bool:
    return (
        path in _REQUIRED_ACCEPTANCE_FILES
        or path.startswith("surface/")
        or path.startswith("acceptance/evidence/")
    )


def compose_acceptance_manifest(
    files: dict[str, bytes],
    *,
    surface_manifest_digest: str,
    delivery_manifest_digest: str,
    work_order_digest: str,
    verification_decision_digest: str,
    composition_report_digest: str,
    terminal_decision: Literal["accepted", "rejected"],
    terminal_receipt_digest: str,
    acceptance_decision_binding_digest: str,
) -> AcceptanceManifestV01:
    """Compose deterministic outer metadata from an already frozen file map."""

    if type(files) is not dict or any(
        type(path) is not str or type(payload) is not bytes
        for path, payload in files.items()
    ):
        raise AcceptanceBundleError(
            "acceptance manifest files must be an exact byte map"
        )
    if "acceptance-manifest.json" in files:
        raise AcceptanceBundleError(
            "acceptance manifest must not include itself"
        )
    try:
        normalized = {
            _acceptance_relative_path(path): payload
            for path, payload in files.items()
        }
    except ValueError as error:
        raise AcceptanceBundleError(
            "acceptance manifest file path is invalid"
        ) from error
    if len(normalized) > MAX_ACCEPTANCE_FILES:
        raise AcceptanceBundleError(
            "acceptance bundle file count exceeds the limit"
        )
    if any(
        len(payload) > MAX_ACCEPTANCE_FILE_BYTES
        for payload in normalized.values()
    ):
        raise AcceptanceBundleError(
            "acceptance bundle file exceeds the size limit"
        )
    if sum(len(payload) for payload in normalized.values()) > (
        MAX_ACCEPTANCE_TOTAL_BYTES
    ):
        raise AcceptanceBundleError(
            "acceptance bundle total size exceeds the limit"
        )
    actual = set(normalized)
    if not _REQUIRED_ACCEPTANCE_FILES <= actual:
        raise AcceptanceBundleError(
            "acceptance bundle required files are missing"
        )
    if any(not _path_is_allowed(path) for path in actual):
        raise AcceptanceBundleError(
            "acceptance bundle path allowlist is invalid"
        )
    if normalized["verify.sh"] != ACCEPTANCE_VERIFY_SCRIPT:
        raise AcceptanceBundleError(
            "acceptance bundle required files are invalid"
        )
    entries = tuple(
        AcceptanceManifestEntry(
            path=path,
            sha256=hashlib.sha256(payload).hexdigest(),
            size_bytes=len(payload),
        )
        for path, payload in sorted(
            normalized.items(), key=lambda item: item[0].encode("utf-8")
        )
    )
    try:
        return AcceptanceManifestV01(
            schema_version="openworkproof-acceptance-bundle/0.1",
            surface_manifest_digest=surface_manifest_digest,
            delivery_manifest_digest=delivery_manifest_digest,
            work_order_digest=work_order_digest,
            verification_decision_digest=verification_decision_digest,
            composition_report_digest=composition_report_digest,
            terminal_decision=terminal_decision,
            terminal_receipt_digest=terminal_receipt_digest,
            acceptance_decision_binding_digest=(
                acceptance_decision_binding_digest
            ),
            entries=[entry.model_dump(mode="json") for entry in entries],
        )
    except Exception as error:
        raise AcceptanceBundleError(
            "acceptance manifest summary is invalid"
        ) from error


def validate_acceptance_bundle_manifest(
    bundle_root: Path,
) -> AcceptanceManifestV01:
    """Validate only the stable outer snapshot and closed file manifest."""

    try:
        manifest, _scanned = _load_acceptance_manifest_snapshot(bundle_root)
        return manifest
    except AcceptanceBundleError:
        raise
    except Exception as error:
        raise AcceptanceBundleError(
            "acceptance bundle manifest validation failed"
        ) from error


def _load_acceptance_manifest_snapshot(
    bundle_root: Path,
) -> tuple[AcceptanceManifestV01, dict[str, _ScannedFile]]:
    root = _canonical_root(Path(bundle_root))
    scanned = _scan_tree(root)
    try:
        manifest_file = scanned.get("acceptance-manifest.json")
        if manifest_file is None:
            raise AcceptanceBundleError(
                "acceptance manifest is missing"
            )
        manifest = _parse_acceptance_manifest(manifest_file.payload)
        actual = set(scanned) - {"acceptance-manifest.json"}
        expected = {entry.path for entry in manifest.entries}
        if actual != expected:
            raise AcceptanceBundleError(
                "acceptance manifest file set is not exact"
            )
        for entry in manifest.entries:
            payload = scanned[entry.path].payload
            if (
                len(payload) != entry.size_bytes
                or hashlib.sha256(payload).hexdigest() != entry.sha256
            ):
                raise AcceptanceBundleError(
                    "acceptance manifest entry integrity failed"
                )
        if not _REQUIRED_ACCEPTANCE_FILES <= actual:
            raise AcceptanceBundleError(
                "acceptance bundle required files are missing"
            )
        if any(not _path_is_allowed(path) for path in actual):
            raise AcceptanceBundleError(
                "acceptance bundle path allowlist is invalid"
            )
        verify_file = scanned["verify.sh"]
        if (
            verify_file.payload != ACCEPTANCE_VERIFY_SCRIPT
            or not verify_file.mode & 0o111
        ):
            raise AcceptanceBundleError(
                "acceptance bundle required files are invalid"
            )
        return manifest, scanned
    except AcceptanceBundleError:
        raise
    except Exception as error:
        raise AcceptanceBundleError(
            "acceptance bundle manifest snapshot is invalid"
        ) from error


def _canonical_json(payload: bytes, label: str) -> object:
    try:
        value = json.loads(payload)
    except Exception as error:
        raise AcceptanceBundleError(f"{label} is invalid") from error
    if _canonical(value) != payload:
        raise AcceptanceBundleError(f"{label} is not canonical")
    return value


def _load_companion_objects(
    scanned: dict[str, _ScannedFile],
    *,
    terminal_decision: Literal["accepted", "rejected"],
):
    from openworkproof.models import (  # noqa: PLC0415
        AcceptanceDecisionBindingV01,
        AcceptanceReceipt,
        AcceptanceRejectionReceipt,
        CapabilityGrant,
        CompositionReport,
        EvidenceRef,
    )
    from openworkproof.policy import CommittedEvidence  # noqa: PLC0415

    def load_array(relative: str, model, label: str) -> tuple:
        raw = _canonical_json(scanned[relative].payload, label)
        if type(raw) is not list:
            raise AcceptanceBundleError(f"{label} must be an array")
        try:
            return tuple(model.model_validate(item) for item in raw)
        except Exception as error:
            raise AcceptanceBundleError(f"{label} is malformed") from error

    grants = load_array(
        "acceptance/effective-grants.json",
        CapabilityGrant,
        "acceptance effective grants",
    )
    attempts = load_array(
        "acceptance/grant-attempts.json",
        CapabilityGrant,
        "acceptance grant attempts",
    )
    reports = load_array(
        "acceptance/composition-reports.json",
        CompositionReport,
        "acceptance composition reports",
    )
    if not reports:
        raise AcceptanceBundleError(
            "acceptance composition reports are empty"
        )
    terminal_raw = _canonical_json(
        scanned["acceptance/terminal-receipt.json"].payload,
        "acceptance terminal receipt",
    )
    terminal_type = (
        AcceptanceReceipt
        if terminal_decision == "accepted"
        else AcceptanceRejectionReceipt
    )
    try:
        terminal = terminal_type.model_validate(terminal_raw)
        binding = AcceptanceDecisionBindingV01.model_validate(
            _canonical_json(
                scanned["acceptance/decision-binding.json"].payload,
                "acceptance decision binding",
            )
        )
    except Exception as error:
        raise AcceptanceBundleError(
            "acceptance terminal or binding is malformed"
        ) from error

    index = _canonical_json(
        scanned["acceptance/committed-evidence-index.json"].payload,
        "acceptance committed evidence index",
    )
    if (
        type(index) is not dict
        or set(index) != {"schema_version", "entries"}
        or index["schema_version"]
        != "openworkproof-committed-evidence-index/0.1"
        or type(index["entries"]) is not list
    ):
        raise AcceptanceBundleError(
            "acceptance committed evidence index is malformed"
        )
    committed = []
    indexed_paths = []
    for raw_entry in index["entries"]:
        if type(raw_entry) is not dict or set(raw_entry) != {
            "bundle_path",
            "reference",
        }:
            raise AcceptanceBundleError(
                "acceptance committed evidence entry is malformed"
            )
        try:
            reference = EvidenceRef.model_validate(raw_entry["reference"])
            bundle_path = _acceptance_relative_path(raw_entry["bundle_path"])
        except Exception as error:
            raise AcceptanceBundleError(
                "acceptance committed evidence entry is malformed"
            ) from error
        expected_path = f"acceptance/evidence/{reference.path}"
        if bundle_path != expected_path or bundle_path not in scanned:
            raise AcceptanceBundleError(
                "acceptance committed evidence path is not bound"
            )
        payload = scanned[bundle_path].payload
        if (
            len(payload) != reference.size_bytes
            or hashlib.sha256(payload).hexdigest() != reference.sha256
        ):
            raise AcceptanceBundleError(
                "acceptance committed evidence integrity failed"
            )
        indexed_paths.append(bundle_path)
        committed.append(CommittedEvidence(reference=reference, payload=payload))
    if indexed_paths != sorted(
        set(indexed_paths), key=lambda value: value.encode("utf-8")
    ) or set(indexed_paths) != {
        path for path in scanned if path.startswith("acceptance/evidence/")
    }:
        raise AcceptanceBundleError(
            "acceptance committed evidence index is not exact"
        )
    return grants, attempts, reports, tuple(committed), terminal, binding


def verify_acceptance_bundle_directory(
    bundle_root: Path,
) -> AcceptanceBundleVerificationResult:
    """Replay one Acceptance Bundle from copied bytes without a live ledger."""

    try:
        from openworkproof import acceptance, delivery_package  # noqa: PLC0415
        from openworkproof.models import ApprovalRequestedReceipt  # noqa: PLC0415
        from openworkproof.signing import (  # noqa: PLC0415
            decode_and_verify_key_binding,
            verify_payload,
        )
        from openworkproof.surface_bundle import verify_surface_bundle  # noqa: PLC0415

        manifest, scanned = _load_acceptance_manifest_snapshot(bundle_root)
        with tempfile.TemporaryDirectory(
            prefix="openworkproof-acceptance-verify-",
            dir=_canonical_root(Path(bundle_root)).parent,
        ) as raw_snapshot:
            snapshot = Path(raw_snapshot)
            for relative, item in scanned.items():
                _write_new(
                    snapshot,
                    relative,
                    item.payload,
                    mode=item.mode,
                )
            surface_root = snapshot / "surface"
            surface = verify_surface_bundle(surface_root)
            if surface.report.decision_status != "VERIFIED":
                raise AcceptanceBundleError(
                    "acceptance bundle requires a VERIFIED surface"
                )
            delivery_root = surface_root / "delivery-package"
            delivery_result = delivery_package.verify_delivery_package(
                delivery_root
            )
            delivery_manifest = delivery_package.load_and_verify_manifest(
                delivery_root
            )
            if (
                delivery_manifest.verification_protocol_version != "0.5"
                or delivery_manifest.privacy_view != "customer_private"
                or delivery_result.full_offline_replay is not True
                or delivery_result.current_decision != "VERIFIED"
            ):
                raise AcceptanceBundleError(
                    "acceptance bundle requires a private replayable v0.5 delivery"
                )
            (
                work_order,
                _claim,
                _scope,
                _profile,
                decision,
                _results,
                _inventory,
            ) = delivery_package._load_v05_objects_and_evidence(
                delivery_root,
                delivery_manifest,
            )
            receipts = delivery_package._load_receipts(
                delivery_root,
                delivery_manifest,
                work_order,
            )
            history = delivery_package._load_acceptance_history(
                delivery_root,
                delivery_manifest,
                work_order,
                decision,
                receipts,
            )
            if history.withdrawal is not None or history.supersession is not None:
                raise AcceptanceBundleError(
                    "acceptance bundle forbids terminal transitions"
                )
            (
                grants,
                attempts,
                reports,
                committed,
                terminal,
                binding,
            ) = _load_companion_objects(
                scanned,
                terminal_decision=manifest.terminal_decision,
            )
            package_terminal = (
                history.acceptance
                if manifest.terminal_decision == "accepted"
                else history.rejection
            )
            other_terminal = (
                history.rejection
                if manifest.terminal_decision == "accepted"
                else history.acceptance
            )
            if package_terminal is None or other_terminal is not None:
                raise AcceptanceBundleError(
                    "acceptance bundle terminal is not unique"
                )
            if terminal != package_terminal:
                raise AcceptanceBundleError(
                    "acceptance bundle terminal diverges from the delivery"
                )
            public_keys = {
                item.key_id: decode_and_verify_key_binding(item)
                for item in work_order.key_bindings
            }
            verified_terminal = acceptance.verify_acceptance_bundle(
                work_order=work_order,
                report=reports[-1],
                effective_grants=grants,
                grant_attempts=attempts,
                receipts=receipts,
                committed_evidence=committed,
                acceptance_receipt=(
                    terminal if manifest.terminal_decision == "accepted" else None
                ),
                rejection=(
                    terminal if manifest.terminal_decision == "rejected" else None
                ),
                public_keys=public_keys,
                reports=reports,
            )
            acceptors = tuple(
                item for item in work_order.key_bindings if item.role == "Acceptor"
            )
            if (
                len(acceptors) != 1
                or binding.signer_key_id != acceptors[0].key_id
                or not verify_payload(
                    "acceptance-decision-binding",
                    binding.model_dump(mode="json"),
                    decode_and_verify_key_binding(acceptors[0]),
                )
            ):
                raise AcceptanceBundleError(
                    "acceptance decision binding authority is invalid"
                )
            request = receipts[-1] if receipts else None
            terminal_id = (
                verified_terminal.acceptance_id
                if manifest.terminal_decision == "accepted"
                else verified_terminal.rejection_id
            )
            if not isinstance(request, ApprovalRequestedReceipt) or any(
                (
                    binding.work_order_digest != work_order.digest,
                    binding.verification_decision_id != decision.decision_id,
                    binding.verification_decision_digest != decision.digest,
                    binding.composition_report_digest
                    != acceptance.composition_report_digest(reports[-1]),
                    binding.acceptance_request_receipt_id != request.receipt_id,
                    binding.acceptance_request_receipt_digest != request.digest,
                    binding.terminal_kind != manifest.terminal_decision,
                    binding.terminal_receipt_id != terminal_id,
                    binding.terminal_receipt_digest != verified_terminal.digest,
                )
            ):
                raise AcceptanceBundleError(
                    "acceptance decision binding does not match one delivery"
                )
            if any(
                (
                    manifest.surface_manifest_digest != surface.manifest_digest,
                    manifest.delivery_manifest_digest
                    != delivery_result.manifest_digest,
                    manifest.work_order_digest != work_order.digest,
                    manifest.verification_decision_digest != decision.digest,
                    manifest.composition_report_digest
                    != acceptance.composition_report_digest(reports[-1]),
                    manifest.terminal_receipt_digest != verified_terminal.digest,
                    manifest.acceptance_decision_binding_digest != binding.digest,
                    surface.report.work_order_digest != work_order.digest,
                    surface.report.verification_decision_digests
                    != (decision.digest,),
                )
            ):
                raise AcceptanceBundleError(
                    "acceptance manifest summary diverges from replay"
                )
            return AcceptanceBundleVerificationResult(
                schema_version="openworkproof-acceptance-bundle-result/0.1",
                terminal_decision=(
                    "ACCEPTED"
                    if manifest.terminal_decision == "accepted"
                    else "REJECTED"
                ),
                work_order_digest=work_order.digest,
                surface_manifest_digest=surface.manifest_digest,
                verification_decision_digest=decision.digest,
                terminal_receipt_digest=verified_terminal.digest,
                acceptance_decision_binding_digest=binding.digest,
                boundary="not payment, settlement, legal audit, or adoption",
            )
    except AcceptanceBundleError:
        raise
    except Exception as error:
        raise AcceptanceBundleError(
            "acceptance bundle verification failed"
        ) from error
