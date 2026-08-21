"""Verified Delivery Case 0.1 — model, initialization, status, export gates."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from openworkproof.delivery_case import (
    DeliveryCaseManifestV01,
    ExternalEvidenceReferenceV01,
)


def test_case_manifest_is_closed_and_contains_no_runtime_status() -> None:
    payload = {
        "schema_version": "openworkproof-delivery-case/0.1",
        "case_id": "1" * 64,
        "profile": "coding-agent",
        "buyer_alias": "buyer",
        "delivery_provider_alias": "provider",
        "created_at": "2026-08-22T00:00:00Z",
    }
    case = DeliveryCaseManifestV01.model_validate(payload)
    assert "case_stage" not in DeliveryCaseManifestV01.model_fields
    with pytest.raises(ValidationError):
        DeliveryCaseManifestV01.model_validate({**payload, "case_stage": "ACCEPTED"})


@pytest.mark.parametrize("field", ("reference_digest", "observed_at"))
def test_not_evidenced_reference_cannot_carry_evidence(field: str) -> None:
    payload = {
        "schema_version": "openworkproof-external-evidence/0.1",
        "status": "not_evidenced",
        "reference_digest": None,
        "observed_at": None,
    }
    payload[field] = "2" * 64 if field == "reference_digest" else "2026-08-22T00:00:00Z"
    with pytest.raises(ValidationError):
        ExternalEvidenceReferenceV01.model_validate(payload)
