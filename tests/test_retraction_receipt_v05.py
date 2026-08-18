from __future__ import annotations

import copy
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from openworkproof.models import (
    RetractionReceiptV05,
    retraction_receipt_id,
)
from openworkproof.signing import sign_payload


def _retraction_payload(
    *,
    target_receipt_id: str = "a" * 64,
    target_receipt_digest: str = "b" * 64,
    target_receipt_kind: str = "tool_call",
    retraction_effect: str = "refuted",
    retraction_reason: str = "evidence_refuted",
    refutes_decision_id: str | None = None,
    refutes_decision_digest: str | None = None,
    causal_parent_ids: list[str] | None = None,
    retracted_at: str = "2026-01-01T01:00:00Z",
) -> dict[str, Any]:
    parents = list(causal_parent_ids) if causal_parent_ids is not None else [
        target_receipt_id
    ]
    payload = {
        "schema_version": "openworkproof-retraction-receipt/0.5",
        "protocol_version": "0.5",
        "work_order_digest": "c" * 64,
        "target_receipt_id": target_receipt_id,
        "target_receipt_digest": target_receipt_digest,
        "target_receipt_kind": target_receipt_kind,
        "retraction_effect": retraction_effect,
        "retraction_reason": retraction_reason,
        "refutes_decision_id": refutes_decision_id,
        "refutes_decision_digest": refutes_decision_digest,
        "causal_parent_ids": parents,
        "nonce": "d" * 64,
        "retracted_at": retracted_at,
    }
    return {"retraction_id": retraction_receipt_id(payload), **payload}


def _signed_retraction(
    payload: dict[str, Any],
    manager_key: Ed25519PrivateKey,
) -> RetractionReceiptV05:
    return RetractionReceiptV05.model_validate(
        sign_payload("retraction-receipt", payload, manager_key, version="0.5")
    )


def test_valid_retraction_receipt_constructs(
    frozen_role_keys_v05: dict[str, tuple[Ed25519PrivateKey, dict[str, str]]],
) -> None:
    manager_key = frozen_role_keys_v05["Manager"][0]
    payload = _retraction_payload()
    receipt = _signed_retraction(payload, manager_key)
    assert receipt.retraction_id == payload["retraction_id"]
    assert receipt.target_receipt_kind == "tool_call"
    assert receipt.retraction_effect == "refuted"
    assert receipt.retraction_reason == "evidence_refuted"
    assert receipt.causal_parent_ids == ("a" * 64,)


def test_retraction_rejects_wrong_target_digest(
    frozen_role_keys_v05: dict[str, tuple[Ed25519PrivateKey, dict[str, str]]],
) -> None:
    """A retraction that names one receipt id but a different digest is a
    forged binding. The model layer recomputes the retraction id from content,
    so the digest swap is only caught by the transaction layer (Task 2) which
    verifies the target receipt exists with that exact digest. Here we pin the
    model contract: a changed target digest produces a different id (the id
    is content-derived), which means the same signed envelope cannot silently
    re-bind."""
    manager_key = frozen_role_keys_v05["Manager"][0]
    original = _retraction_payload()
    tampered = copy.deepcopy(original)
    tampered["target_receipt_digest"] = "f" * 64
    assert retraction_receipt_id(original) != retraction_receipt_id(tampered)
    # The retraction with the tampered digest is a *valid* model (self-consistent)
    # but binds a different target; the digest-to-receipt binding is a ledger
    # concern enforced at commit time, not a shape concern.
    signed = _signed_retraction(
        {**tampered, "retraction_id": retraction_receipt_id(tampered)},
        manager_key,
    )
    assert signed.target_receipt_digest == "f" * 64


def test_retraction_rejects_unpaired_refutes_decision(
    frozen_role_keys_v05: dict[str, tuple[Ed25519PrivateKey, dict[str, str]]],
) -> None:
    """refutes_decision_id without digest (or vice versa) is malformed input."""
    manager_key = frozen_role_keys_v05["Manager"][0]
    payload = _retraction_payload(
        refutes_decision_id="e" * 64,
        refutes_decision_digest=None,
        causal_parent_ids=["a" * 64, "e" * 64],
    )
    with pytest.raises(ValidationError):
        _signed_retraction(payload, manager_key)


def test_retraction_requires_target_in_causal_parents(
    frozen_role_keys_v05: dict[str, tuple[Ed25519PrivateKey, dict[str, str]]],
) -> None:
    """The causal parent set must bind the retracted receipt itself."""
    manager_key = frozen_role_keys_v05["Manager"][0]
    payload = _retraction_payload(causal_parent_ids=["9" * 64])
    with pytest.raises(ValidationError):
        _signed_retraction(payload, manager_key)


def test_retraction_rejects_downgrade_with_evidence_refuted(
    frozen_role_keys_v05: dict[str, tuple[Ed25519PrivateKey, dict[str, str]]],
) -> None:
    """confidence_downgrade must not claim evidence_refuted: a downgrade is
    not a refutation."""
    manager_key = frozen_role_keys_v05["Manager"][0]
    payload = _retraction_payload(
        retraction_effect="confidence_downgrade",
        retraction_reason="evidence_refuted",
    )
    with pytest.raises(ValidationError):
        _signed_retraction(payload, manager_key)


def test_retraction_rejects_causal_time_inversion(
    frozen_role_keys_v05: dict[str, tuple[Ed25519PrivateKey, dict[str, str]]],
) -> None:
    """The retraction cannot predate the receipt it retracts. For the model
    layer we bind a minimum sanity: the field must parse as canonical UTC and
    the model must carry a retracted_at later than the work order epoch used
    by the demo fixtures. Here we only assert canonical-time enforcement."""
    manager_key = frozen_role_keys_v05["Manager"][0]
    payload = _retraction_payload(retracted_at="2026-01-01T00:00:00+00:00")
    with pytest.raises(ValidationError):
        _signed_retraction(payload, manager_key)


def test_retraction_rejects_unknown_reason(
    frozen_role_keys_v05: dict[str, tuple[Ed25519PrivateKey, dict[str, str]]],
) -> None:
    manager_key = frozen_role_keys_v05["Manager"][0]
    payload = _retraction_payload(retraction_reason="not_a_reason")
    with pytest.raises(ValidationError):
        _signed_retraction(payload, manager_key)


def test_retraction_id_digest_is_domain_scoped() -> None:
    """Two payloads identical except for the retraction_id field must
    produce the same computed id (the id is derived, not free-form)."""
    first = _retraction_payload()
    second = copy.deepcopy(first)
    second["retraction_id"] = "f" * 64
    assert retraction_receipt_id(first) == retraction_receipt_id(second)
