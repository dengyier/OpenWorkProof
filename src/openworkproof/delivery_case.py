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
import os
from pathlib import Path
import secrets
import shutil
import stat
import tempfile
from typing import Literal

from pydantic import ConfigDict, model_validator
import rfc8785

from openworkproof.models import (
    CanonicalUTCTime,
    Digest64,
    ProtocolModel,
)
from openworkproof.settlement import SettlementReadiness


__all__ = [
    "DeliveryCaseError",
    "DeliveryCaseManifestV01",
    "DeliveryCaseResultV01",
    "DeliveryCaseStage",
    "ExternalEvidenceReferenceV01",
    "initialize_delivery_case",
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
    case_stage: DeliveryCaseStage
    verification_decision: Literal["VERIFIED", "REFUTED", "UNKNOWN"] | None
    acceptance_decision: Literal["ACCEPTED", "REJECTED"] | None
    settlement_readiness: SettlementReadiness | None
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
