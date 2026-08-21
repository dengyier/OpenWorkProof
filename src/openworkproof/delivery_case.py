"""Verified Agent Delivery — one closed, offline delivery-case orchestrator.

This module is a thin orchestration layer over the existing Surface Bundle,
Acceptance Bundle and settlement-readiness verifiers. It never re-implements
protocol logic, never signs on behalf of an authority, never reads payment
accounts and never fabricates a second source of truth: the delivery-case
status is always derived from the existing verifiable bundles at read time.
"""

from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import ConfigDict, model_validator

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
