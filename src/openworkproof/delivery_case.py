"""Verified Agent Delivery — one closed, offline delivery-case orchestrator.

This module is a thin orchestration layer over the existing Surface Bundle,
Acceptance Bundle and settlement-readiness verifiers. It never re-implements
protocol logic, never signs on behalf of an authority, never reads payment
accounts and never fabricates a second source of truth: the delivery-case
status is always derived from the existing verifiable bundles at read time.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import stat
import tempfile
from typing import Any, Literal

from pydantic import ConfigDict, model_validator
import rfc8785

from openworkproof.acceptance_bundle import verify_acceptance_bundle_directory
from openworkproof.models import (
    AcceptanceDecisionBindingV01,
    CanonicalUTCTime,
    Digest64,
    ProtocolModel,
)
from openworkproof.settlement import (
    SettlementReadiness,
    SettlementSnapshot,
)
from openworkproof.surface_bundle import verify_surface_bundle


__all__ = [
    "DeliveryCaseError",
    "DeliveryCaseManifestV01",
    "DeliveryCaseResultV01",
    "DeliveryCaseStage",
    "ExternalEvidenceReferenceV01",
    "initialize_delivery_case",
    "inspect_delivery_case",
    "export_delivery_case",
    "verify_exported_delivery_case",
]


class DeliveryCaseError(RuntimeError):
    """A delivery case cannot be built, inspected or exported safely."""


_CONFIG = ConfigDict(
    extra="forbid",
    frozen=True,
    strict=True,
    revalidate_instances="subclass-instances",
)


class DeliveryCaseStage(str, Enum):
    SCOPE_DRAFTED = "SCOPE_DRAFTED"
    SOW_REFERENCED = "SOW_REFERENCED"
    READY_FOR_VERIFICATION = "READY_FOR_VERIFICATION"
    VERIFIED = "VERIFIED"
    REFUTED = "REFUTED"
    UNKNOWN = "UNKNOWN"
    READY_FOR_ACCEPTANCE = "READY_FOR_ACCEPTANCE"
    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"
    READY_FOR_SETTLEMENT_REVIEW = "READY_FOR_SETTLEMENT_REVIEW"
    EXTERNAL_PAYMENT_EVIDENCED = "EXTERNAL_PAYMENT_EVIDENCED"


class DeliveryCaseManifestV01(ProtocolModel):
    model_config = _CONFIG

    schema_version: Literal["openworkproof-delivery-case/0.1"]
    case_id: Digest64
    profile: Literal["coding-agent"]
    buyer_alias: str
    delivery_provider_alias: str
    created_at: CanonicalUTCTime


class ExternalEvidenceReferenceV01(ProtocolModel):
    model_config = _CONFIG

    schema_version: Literal["openworkproof-external-evidence/0.1"]
    status: Literal["not_evidenced", "external_reference_present"]
    reference_digest: Digest64 | None
    observed_at: CanonicalUTCTime | None

    @model_validator(mode="after")
    def _closed_reference(self) -> ExternalEvidenceReferenceV01:
        present = self.status == "external_reference_present"
        has_digest = self.reference_digest is not None
        has_observed = self.observed_at is not None
        if (has_digest != has_observed) or (present != has_digest):
            raise ValueError("external evidence status and reference must agree")
        return self


_DELIVERY_CASE_REASON_CODES = frozenset(
    {
        "SOW_NOT_EVIDENCED",
        "SURFACE_MISSING",
        "SURFACE_UNKNOWN",
        "SURFACE_REFUTED",
        "ACCEPTANCE_MISSING",
        "CUSTOMER_REJECTED",
        "SETTLEMENT_STATUS_MISSING",
        "PAYMENT_NOT_EVIDENCED",
        "OPERATIONAL_ERROR",
    }
)

DeliveryCaseReasonCode = Literal[
    "SOW_NOT_EVIDENCED",
    "SURFACE_MISSING",
    "SURFACE_UNKNOWN",
    "SURFACE_REFUTED",
    "ACCEPTANCE_MISSING",
    "CUSTOMER_REJECTED",
    "SETTLEMENT_STATUS_MISSING",
    "PAYMENT_NOT_EVIDENCED",
    "OPERATIONAL_ERROR",
]


class DeliveryCaseResultV01(ProtocolModel):
    model_config = _CONFIG

    schema_version: Literal["openworkproof-delivery-case-result/0.1"]
    case_id: Digest64
    case_stage: Literal[
        "SCOPE_DRAFTED",
        "SOW_REFERENCED",
        "READY_FOR_VERIFICATION",
        "VERIFIED",
        "REFUTED",
        "UNKNOWN",
        "READY_FOR_ACCEPTANCE",
        "ACCEPTED",
        "REJECTED",
        "READY_FOR_SETTLEMENT_REVIEW",
        "EXTERNAL_PAYMENT_EVIDENCED",
    ]
    verification_decision: Literal["VERIFIED", "REFUTED", "UNKNOWN"] | None
    acceptance_decision: Literal["ACCEPTED", "REJECTED"] | None
    settlement_readiness: Literal[
        "NOT_READY",
        "READY_FOR_ACCEPTANCE",
        "ACCEPTED_FOR_SETTLEMENT",
        "READY_FOR_SETTLEMENT_REVIEW",
        "SUSPENDED",
        "WITHDRAWN",
        "SUPERSEDED",
    ] | None
    sow_evidence: Literal["not_evidenced", "external_reference_present"]
    payment_evidence: Literal["not_evidenced", "external_reference_present"]
    surface_manifest_digest: Digest64 | None
    acceptance_binding_digest: Digest64 | None
    reason_codes: tuple[DeliveryCaseReasonCode, ...]
    boundary: Literal[
        "not payment, completed settlement, legal audit, or customer adoption"
    ]

    @model_validator(mode="after")
    def _closed_reason_codes(self) -> DeliveryCaseResultV01:
        codes = self.reason_codes
        if list(codes) != sorted(set(codes), key=lambda value: value.encode("utf-8")):
            raise ValueError("reason codes must be UTF-8 sorted and unique")
        return self


_SCORECARD_SCHEMA_VERSION = "openworkproof-commercial-scorecard/0.1"
_SCORECARD_KEYS = (
    "outreach_sent",
    "buyer_interviewed",
    "sow_signed",
    "deposit_evidenced",
    "delivery_verified",
    "customer_accepted",
    "external_payment_evidenced",
    "repeat_order_evidenced",
)
_EMPTY_CASE_DIRECTORIES = ("protocol", "surface", "acceptance", "settlement")


def _canonical_bytes(model: ProtocolModel) -> bytes:
    return rfc8785.dumps(model.model_dump(mode="json"))


def _utc_second(value: datetime | None) -> datetime:
    if value is None:
        value = datetime.now(timezone.utc)
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).replace(microsecond=0)


def _canonical_parent(case_root: Path) -> Path:
    absolute = Path(os.path.abspath(case_root))
    parent = absolute.parent
    if parent.is_symlink():
        raise DeliveryCaseError("delivery case parent must not be a symlink")
    try:
        resolved = parent.resolve(strict=True)
    except OSError as error:
        raise DeliveryCaseError("delivery case parent cannot be resolved") from error
    if resolved != parent:
        raise DeliveryCaseError("delivery case parent must not traverse symlinks")
    return parent


def _write_new(root: Path, relative: str, payload: bytes, *, mode: int) -> None:
    target = root.joinpath(*relative.split("/"))
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(target.parent, 0o700)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(target, flags, mode)
    try:
        os.fchmod(descriptor, mode)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise DeliveryCaseError("delivery case write made no progress")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _scorecard_bytes() -> bytes:
    document = {
        "schema_version": _SCORECARD_SCHEMA_VERSION,
        **{key: "not_evidenced" for key in _SCORECARD_KEYS},
    }
    return rfc8785.dumps(document)


def _not_evidenced_reference() -> ExternalEvidenceReferenceV01:
    return ExternalEvidenceReferenceV01.model_validate(
        {
            "schema_version": "openworkproof-external-evidence/0.1",
            "status": "not_evidenced",
            "reference_digest": None,
            "observed_at": None,
        }
    )


def initialize_delivery_case(
    case_root: Path,
    *,
    case_id: str | None = None,
    now: datetime | None = None,
) -> DeliveryCaseManifestV01:
    """Create one closed case directory without overwriting any target."""

    target = Path(case_root)
    if target.exists() or target.is_symlink():
        raise DeliveryCaseError("delivery case target already exists")
    parent = _canonical_parent(target)
    if case_id is None:
        case_id = secrets.token_hex(32)
    created_at = _utc_second(now)
    manifest = DeliveryCaseManifestV01.model_validate(
        {
            "schema_version": "openworkproof-delivery-case/0.1",
            "case_id": case_id,
            "profile": "coding-agent",
            "buyer_alias": "buyer",
            "delivery_provider_alias": "delivery-provider",
            "created_at": created_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
    )
    stage = Path(tempfile.mkdtemp(prefix=".owp-delivery-case-", dir=parent))
    try:
        _write_new(stage, "case.json", _canonical_bytes(manifest), mode=0o600)
        _write_new(
            stage,
            "commercial/sow-reference.json",
            _canonical_bytes(_not_evidenced_reference()),
            mode=0o600,
        )
        _write_new(
            stage,
            "commercial/payer-status.json",
            _canonical_bytes(_not_evidenced_reference()),
            mode=0o600,
        )
        _write_new(
            stage,
            "commercial/scorecard.json",
            _scorecard_bytes(),
            mode=0o600,
        )
        for name in _EMPTY_CASE_DIRECTORIES:
            directory = stage / name
            directory.mkdir(mode=0o700)
            os.chmod(directory, 0o700)
        if target.exists() or target.is_symlink():
            raise DeliveryCaseError("delivery case target already exists")
        try:
            os.rename(stage, target)
        except FileExistsError as error:
            raise DeliveryCaseError(
                "delivery case target already exists"
            ) from error
        return manifest
    except DeliveryCaseError:
        try:
            shutil.rmtree(stage)
        except OSError as error:
            raise DeliveryCaseError("delivery case cleanup failed") from error
        raise
    except OSError as error:
        try:
            shutil.rmtree(stage)
        except OSError as cleanup_error:
            raise DeliveryCaseError("delivery case cleanup failed") from cleanup_error
        raise DeliveryCaseError("delivery case initialization failed") from error


MAX_CASE_FILES = 4096
MAX_CASE_FILE_BYTES = 64 * 1024 * 1024
MAX_CASE_TOTAL_BYTES = 2 * 1024 * 1024 * 1024

_ALLOWED_CASE_PATHS = frozenset(
    {
        "case.json",
        "commercial/sow-reference.json",
        "commercial/payer-status.json",
        "commercial/scorecard.json",
        "settlement/settlement-status.json",
    }
)


def _safe_relative(value: Any) -> str:
    if type(value) is not str:
        raise DeliveryCaseError("delivery case path must be a strict string")
    if not value or len(value.encode("utf-8")) > 512:
        raise DeliveryCaseError("delivery case path length is invalid")
    if (
        value.startswith("/")
        or "\\" in value
        or "\x00" in value
        or "//" in value
    ):
        raise DeliveryCaseError("delivery case path is not canonical relative POSIX")
    if any(part in {"", ".", ".."} for part in value.split("/")):
        raise DeliveryCaseError("delivery case path contains an unsafe segment")
    return value


def _path_is_allowed(path: str) -> bool:
    if path in _ALLOWED_CASE_PATHS:
        return True
    return (
        path.startswith("protocol/")
        or path.startswith("surface/")
        or path.startswith("acceptance/")
    )


def _read_regular(path: Path) -> tuple[bytes, int]:
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise DeliveryCaseError(
                "delivery case contains unstable single-link regular files only"
            )
        descriptor = os.open(
            path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        )
    except DeliveryCaseError:
        raise
    except OSError as error:
        raise DeliveryCaseError("delivery case file cannot be opened safely") from error
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
            raise DeliveryCaseError(
                "delivery case contains unstable single-link regular files only"
            )
        if opened.st_size > MAX_CASE_FILE_BYTES:
            raise DeliveryCaseError("delivery case file exceeds the size limit")
        chunks: list[bytes] = []
        remaining = MAX_CASE_FILE_BYTES + 1
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
            raise DeliveryCaseError("delivery case file changed while being read")
    finally:
        os.close(descriptor)
    final = path.lstat()
    if (
        final.st_dev,
        final.st_ino,
        final.st_mode,
        final.st_nlink,
        final.st_size,
        final.st_mtime_ns,
    ) != identity:
        raise DeliveryCaseError("delivery case file changed after read")
    return payload, stat.S_IMODE(opened.st_mode)


def _scan_tree(root: Path, allowed) -> dict[str, tuple[bytes, int]]:
    if root.is_symlink() or not root.is_dir():
        raise DeliveryCaseError("delivery case root must be a real directory")
    files: dict[str, tuple[bytes, int]] = {}
    total = 0
    try:
        for directory, names, filenames in os.walk(root, followlinks=False):
            directory_path = Path(directory)
            for name in names:
                child = directory_path / name
                metadata = child.lstat()
                if child.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
                    raise DeliveryCaseError(
                        "delivery case tree contains a non-directory"
                    )
            for name in filenames:
                path = directory_path / name
                relative = _safe_relative(path.relative_to(root).as_posix())
                if relative in files:
                    raise DeliveryCaseError("delivery case path is duplicated")
                if len(files) >= MAX_CASE_FILES:
                    raise DeliveryCaseError("delivery case file count exceeds the limit")
                payload, mode = _read_regular(path)
                if not allowed(relative):
                    raise DeliveryCaseError(
                        f"delivery case contains an unknown file: {relative}"
                    )
                files[relative] = (payload, mode)
                total += len(payload)
                if total > MAX_CASE_TOTAL_BYTES:
                    raise DeliveryCaseError("delivery case total size exceeds the limit")
    except DeliveryCaseError:
        raise
    except (OSError, UnicodeError, ValueError) as error:
        raise DeliveryCaseError("delivery case tree scan failed") from error
    return files


def _scan_case_tree(root: Path) -> dict[str, tuple[bytes, int]]:
    return _scan_tree(root, _path_is_allowed)


_EXPORT_PATHS = frozenset(
    {
        "delivery-case-manifest.json",
        "delivery-result.json",
        "delivery-summary.md",
    }
)


def _export_path_is_allowed(path: str) -> bool:
    if path in _EXPORT_PATHS:
        return True
    if path.startswith("case/"):
        return _path_is_allowed(path[len("case/") :])
    return False


def _scan_export_tree(root: Path) -> dict[str, tuple[bytes, int]]:
    return _scan_tree(root, _export_path_is_allowed)


def _canonical_case_root(case_root: Path) -> Path:
    absolute = Path(os.path.abspath(case_root))
    if absolute.is_symlink():
        raise DeliveryCaseError("delivery case path must not be a symlink")
    try:
        resolved = absolute.resolve(strict=True)
    except OSError as error:
        raise DeliveryCaseError("delivery case path cannot be resolved") from error
    if resolved != absolute:
        raise DeliveryCaseError("delivery case path must not traverse symlinks")
    return resolved


def _load_strict_model(payload: bytes, model, label: str):
    try:
        raw = json.loads(payload)
        instance = model.model_validate(raw)
    except Exception as error:
        raise DeliveryCaseError(f"{label} is invalid") from error
    if rfc8785.dumps(instance.model_dump(mode="json")) != payload:
        raise DeliveryCaseError(f"{label} is not canonical")
    return instance


def _load_case(payload: bytes) -> DeliveryCaseManifestV01:
    return _load_strict_model(payload, DeliveryCaseManifestV01, "case.json")


def _load_external_reference(payload: bytes) -> ExternalEvidenceReferenceV01:
    return _load_strict_model(
        payload, ExternalEvidenceReferenceV01, "external evidence reference"
    )


def _result(
    case: DeliveryCaseManifestV01,
    stage: DeliveryCaseStage,
    *,
    sow: ExternalEvidenceReferenceV01,
    payment: ExternalEvidenceReferenceV01,
    verification_decision: Literal["VERIFIED", "REFUTED", "UNKNOWN"] | None = None,
    acceptance_decision: Literal["ACCEPTED", "REJECTED"] | None = None,
    settlement_readiness: SettlementReadiness | None = None,
    surface_manifest_digest: str | None = None,
    acceptance_binding_digest: str | None = None,
    reasons: tuple[str, ...] = (),
) -> DeliveryCaseResultV01:
    return DeliveryCaseResultV01.model_validate(
        {
            "schema_version": "openworkproof-delivery-case-result/0.1",
            "case_id": case.case_id,
            "case_stage": stage.value,
            "verification_decision": verification_decision,
            "acceptance_decision": acceptance_decision,
            "settlement_readiness": (
                None if settlement_readiness is None else settlement_readiness.value
            ),
            "sow_evidence": sow.status,
            "payment_evidence": payment.status,
            "surface_manifest_digest": surface_manifest_digest,
            "acceptance_binding_digest": acceptance_binding_digest,
            "reason_codes": tuple(sorted(set(reasons), key=lambda item: item.encode("utf-8"))),
            "boundary": (
                "not payment, completed settlement, legal audit, or customer adoption"
            ),
        }
    )


def _verified_settlement_result(
    root: Path,
    snapshot: dict[str, tuple[bytes, int]],
    case: DeliveryCaseManifestV01,
    sow: ExternalEvidenceReferenceV01,
    payment: ExternalEvidenceReferenceV01,
    surface,
    acceptance,
) -> DeliveryCaseResultV01:
    binding = _load_strict_model(
        snapshot["acceptance/acceptance/decision-binding.json"][0],
        AcceptanceDecisionBindingV01,
        "acceptance decision binding",
    )
    settlement = _load_strict_model(
        snapshot["settlement/settlement-status.json"][0],
        SettlementSnapshot,
        "settlement status",
    )
    if settlement.current_decision_id != binding.verification_decision_id:
        raise DeliveryCaseError(
            "settlement and acceptance do not describe one delivery"
        )
    if settlement.settlement_readiness not in {
        SettlementReadiness.ACCEPTED_FOR_SETTLEMENT,
        SettlementReadiness.READY_FOR_SETTLEMENT_REVIEW,
    }:
        raise DeliveryCaseError(
            "settlement snapshot is not ready for settlement review"
        )
    evidenced = payment.status == "external_reference_present"
    return _result(
        case,
        (
            DeliveryCaseStage.EXTERNAL_PAYMENT_EVIDENCED
            if evidenced
            else DeliveryCaseStage.READY_FOR_SETTLEMENT_REVIEW
        ),
        sow=sow,
        payment=payment,
        verification_decision="VERIFIED",
        acceptance_decision="ACCEPTED",
        settlement_readiness=settlement.settlement_readiness,
        surface_manifest_digest=surface.manifest_digest,
        acceptance_binding_digest=binding.digest,
        reasons=() if evidenced else ("PAYMENT_NOT_EVIDENCED",),
    )


def inspect_delivery_case(case_root: Path) -> DeliveryCaseResultV01:
    """Re-derive one delivery case status from its existing verified bundles."""

    root = _canonical_case_root(case_root)
    snapshot = _scan_case_tree(root)
    if "case.json" not in snapshot:
        raise DeliveryCaseError("delivery case manifest is missing")
    if "commercial/sow-reference.json" not in snapshot:
        raise DeliveryCaseError("delivery case SOW reference is missing")
    if "commercial/payer-status.json" not in snapshot:
        raise DeliveryCaseError("delivery case payer status is missing")
    case = _load_case(snapshot["case.json"][0])
    sow = _load_external_reference(snapshot["commercial/sow-reference.json"][0])
    payment = _load_external_reference(snapshot["commercial/payer-status.json"][0])
    if sow.status == "not_evidenced":
        return _result(
            case, DeliveryCaseStage.SCOPE_DRAFTED, sow=sow, payment=payment,
            reasons=("SOW_NOT_EVIDENCED",),
        )
    if "surface/surface-manifest.json" not in snapshot:
        return _result(
            case, DeliveryCaseStage.SOW_REFERENCED, sow=sow, payment=payment,
            reasons=("SURFACE_MISSING",),
        )
    surface = verify_surface_bundle(root / "surface")
    if surface.report.decision_status != "VERIFIED":
        status = surface.report.decision_status
        stage = (
            DeliveryCaseStage.REFUTED
            if status == "REFUTED"
            else DeliveryCaseStage.UNKNOWN
        )
        return _result(
            case, stage, sow=sow, payment=payment,
            verification_decision=status,
            surface_manifest_digest=surface.manifest_digest,
            reasons=(f"SURFACE_{status}",),
        )
    if "acceptance/acceptance-manifest.json" not in snapshot:
        return _result(
            case, DeliveryCaseStage.READY_FOR_ACCEPTANCE, sow=sow, payment=payment,
            verification_decision="VERIFIED",
            surface_manifest_digest=surface.manifest_digest,
            reasons=("ACCEPTANCE_MISSING",),
        )
    acceptance = verify_acceptance_bundle_directory(root / "acceptance")
    if acceptance.surface_manifest_digest != surface.manifest_digest:
        raise DeliveryCaseError(
            "surface and acceptance do not describe one delivery"
        )
    if acceptance.terminal_decision == "REJECTED":
        return _result(
            case, DeliveryCaseStage.REJECTED, sow=sow, payment=payment,
            verification_decision="VERIFIED",
            acceptance_decision="REJECTED",
            surface_manifest_digest=surface.manifest_digest,
            acceptance_binding_digest=acceptance.acceptance_decision_binding_digest,
            reasons=("CUSTOMER_REJECTED",),
        )
    if "settlement/settlement-status.json" not in snapshot:
        return _result(
            case, DeliveryCaseStage.ACCEPTED, sow=sow, payment=payment,
            verification_decision="VERIFIED",
            acceptance_decision="ACCEPTED",
            surface_manifest_digest=surface.manifest_digest,
            acceptance_binding_digest=acceptance.acceptance_decision_binding_digest,
            reasons=("SETTLEMENT_STATUS_MISSING",),
        )
    return _verified_settlement_result(
        root, snapshot, case, sow, payment, surface, acceptance
    )


_EXPORT_MANIFEST_BOUNDARY = (
    "integrity only; not an authorization, acceptance, payment, or legal trust root"
)


def _compose_export_manifest(
    case_snapshot: dict[str, tuple[bytes, int]],
    *,
    case_id: str,
    result_bytes: bytes,
    summary_bytes: bytes,
) -> bytes:
    entries: list[dict[str, object]] = []
    for relative, (payload, _mode) in case_snapshot.items():
        entries.append(
            {
                "path": f"case/{relative}",
                "sha256": hashlib.sha256(payload).hexdigest(),
                "size_bytes": len(payload),
            }
        )
    for relative, payload in (
        ("delivery-result.json", result_bytes),
        ("delivery-summary.md", summary_bytes),
    ):
        entries.append(
            {
                "path": relative,
                "sha256": hashlib.sha256(payload).hexdigest(),
                "size_bytes": len(payload),
            }
        )
    entries.sort(key=lambda entry: str(entry["path"]).encode("utf-8"))
    return rfc8785.dumps(
        {
            "schema_version": "openworkproof-delivery-case-manifest/0.1",
            "case_id": case_id,
            "boundary": _EXPORT_MANIFEST_BOUNDARY,
            "entries": entries,
        }
    )


def _load_export_manifest(payload: bytes) -> dict[str, object]:
    try:
        raw = json.loads(payload)
    except Exception as error:
        raise DeliveryCaseError("export manifest is invalid") from error
    if rfc8785.dumps(raw) != payload:
        raise DeliveryCaseError("export manifest is not canonical")
    if type(raw) is not dict or set(raw) != {
        "schema_version",
        "case_id",
        "boundary",
        "entries",
    }:
        raise DeliveryCaseError("export manifest envelope is not closed")
    if raw["schema_version"] != "openworkproof-delivery-case-manifest/0.1":
        raise DeliveryCaseError("export manifest schema is invalid")
    if raw["boundary"] != _EXPORT_MANIFEST_BOUNDARY:
        raise DeliveryCaseError("export manifest boundary is invalid")
    if type(raw["case_id"]) is not str or len(raw["case_id"]) != 64:
        raise DeliveryCaseError("export manifest case id is invalid")
    entries = raw["entries"]
    if type(entries) is not list or not entries:
        raise DeliveryCaseError("export manifest entries are invalid")
    paths: list[str] = []
    for entry in entries:
        if type(entry) is not dict or set(entry) != {
            "path",
            "sha256",
            "size_bytes",
        }:
            raise DeliveryCaseError("export manifest entry is invalid")
        try:
            _safe_relative(entry["path"])
        except DeliveryCaseError as error:
            raise DeliveryCaseError("export manifest path is invalid") from error
        if (
            type(entry["sha256"]) is not str
            or len(entry["sha256"]) != 64
            or type(entry["size_bytes"]) is not int
            or not 0 <= entry["size_bytes"] <= 2 * 1024 * 1024 * 1024
        ):
            raise DeliveryCaseError("export manifest entry is invalid")
        paths.append(entry["path"])
    if list(paths) != sorted(set(paths), key=lambda value: value.encode("utf-8")):
        raise DeliveryCaseError("export manifest entries are not sorted or unique")
    return raw


def _rename_no_replace(source: Path, destination: Path) -> None:
    import ctypes
    import errno
    import sys

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
        raise DeliveryCaseError("atomic no-replace directory rename is unavailable")
    if result != 0:
        error_number = ctypes.get_errno()
        if error_number in {errno.EEXIST, errno.ENOTEMPTY}:
            raise FileExistsError(
                error_number, os.strerror(error_number), destination
            )
        raise OSError(error_number, os.strerror(error_number), destination)


def export_delivery_case(
    case_root: Path,
    output: Path,
) -> DeliveryCaseResultV01:
    """Export one delivery case as a self-verifying, no-replace directory."""

    from openworkproof.delivery_case_render import (  # noqa: PLC0415
        render_delivery_result,
        render_delivery_summary,
    )

    source = _canonical_case_root(case_root)
    output_path = Path(output)
    if output_path.exists() or output_path.is_symlink():
        raise DeliveryCaseError("delivery case export target already exists")
    parent = _canonical_parent(output_path)
    result = inspect_delivery_case(source)
    case_snapshot = _scan_case_tree(source)
    result_bytes = render_delivery_result(result)
    summary_bytes = render_delivery_summary(result).encode("utf-8")
    manifest_bytes = _compose_export_manifest(
        case_snapshot,
        case_id=result.case_id,
        result_bytes=result_bytes,
        summary_bytes=summary_bytes,
    )
    stage = Path(tempfile.mkdtemp(prefix=".owp-delivery-case-export-", dir=parent))
    try:
        for relative, (payload, mode) in case_snapshot.items():
            _write_new(stage, f"case/{relative}", payload, mode=mode)
        _write_new(stage, "delivery-result.json", result_bytes, mode=0o600)
        _write_new(stage, "delivery-summary.md", summary_bytes, mode=0o600)
        _write_new(stage, "delivery-case-manifest.json", manifest_bytes, mode=0o600)
        verify_exported_delivery_case(stage)
        if output_path.exists() or output_path.is_symlink():
            raise DeliveryCaseError("delivery case export target already exists")
        try:
            _rename_no_replace(stage, output_path)
        except FileExistsError as error:
            raise DeliveryCaseError(
                "delivery case export target already exists"
            ) from error
        return result
    except DeliveryCaseError:
        try:
            shutil.rmtree(stage)
        except OSError as error:
            raise DeliveryCaseError("delivery case export cleanup failed") from error
        raise
    except Exception as error:
        try:
            shutil.rmtree(stage)
        except OSError as cleanup_error:
            raise DeliveryCaseError("delivery case export cleanup failed") from cleanup_error
        raise DeliveryCaseError("delivery case export failed") from error


def verify_exported_delivery_case(
    export_dir: Path,
) -> DeliveryCaseResultV01:
    """Verify one exported delivery case and re-derive its status from evidence."""

    root = _canonical_case_root(export_dir)
    snapshot = _scan_export_tree(root)
    if "delivery-case-manifest.json" not in snapshot:
        raise DeliveryCaseError("delivery case export manifest is missing")
    if "delivery-result.json" not in snapshot:
        raise DeliveryCaseError("delivery case export result is missing")
    manifest = _load_export_manifest(snapshot["delivery-case-manifest.json"][0])
    actual = set(snapshot) - {"delivery-case-manifest.json"}
    expected = {str(entry["path"]) for entry in manifest["entries"]}
    if actual != expected:
        raise DeliveryCaseError("delivery case export manifest file set is not exact")
    for entry in manifest["entries"]:
        relative = str(entry["path"])
        payload = snapshot[relative][0]
        if (
            len(payload) != entry["size_bytes"]
            or hashlib.sha256(payload).hexdigest() != entry["sha256"]
        ):
            raise DeliveryCaseError("delivery case export integrity failed")
    stored = _load_strict_model(
        snapshot["delivery-result.json"][0],
        DeliveryCaseResultV01,
        "delivery result",
    )
    derived = inspect_delivery_case(root / "case")
    if derived != stored:
        raise DeliveryCaseError("delivery result does not match the replayed case")
    return derived
