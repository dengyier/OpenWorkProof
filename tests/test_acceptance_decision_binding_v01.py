"""Acceptance-to-v0.5-decision companion binding tests."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from pydantic import ValidationError

from openworkproof.signing import key_id, sign_payload, verify_payload


PROJECT_ROOT = Path(__file__).resolve().parents[1]
FROZEN_PROTOCOL_FILES = {
    "src/openworkproof/schemas/v0.1/acceptance-receipt.schema.json": (
        "5436e77e03d64cf131f2273b7527e63aa854f9c3de7b60aeae8751024267ff0e"
    ),
    "src/openworkproof/schemas/v0.1/acceptance-rejection-receipt.schema.json": (
        "cab320167c5af36afcc06506d13cbaa85c3dd9f6b470c4db12d127726fa86ae8"
    ),
    "src/openworkproof/schemas/v0.1/schema-registry.json": (
        "b543abb2d972a84d3fffe97e6f9381f33b5cfe40fe0c8c7c046f91354f849000"
    ),
    "src/openworkproof/schemas/v0.5/verification-decision.schema.json": (
        "682dc06cb5034bc55f93378d5b887e6ef46522ef289ab1aec54debda880128d3"
    ),
    "src/openworkproof/schemas/v0.5/schema-registry.json": (
        "bc3e702340b538529b2d5faff5227991e05c08643d5ebc7af5a5a059c85049e8"
    ),
}


def test_frozen_acceptance_and_v05_schema_bytes_are_unchanged() -> None:
    for relative, expected in FROZEN_PROTOCOL_FILES.items():
        payload = PROJECT_ROOT.joinpath(relative).read_bytes()
        assert hashlib.sha256(payload).hexdigest() == expected


def test_unbound_cross_version_pair_requires_signed_companion() -> None:
    """Two independently valid proofs must not become one delivery by packaging."""

    from openworkproof.models import AcceptanceDecisionBindingV01

    assert AcceptanceDecisionBindingV01 is not None


def _binding_payload() -> dict[str, object]:
    from openworkproof.models import acceptance_decision_binding_id

    raw: dict[str, object] = {
        "schema_version": "openworkproof-acceptance-decision-binding/0.1",
        "protocol_version": "0.1",
        "work_order_digest": "1" * 64,
        "verification_decision_id": "2" * 64,
        "verification_decision_digest": "3" * 64,
        "composition_report_digest": "4" * 64,
        "acceptance_request_receipt_id": "5" * 64,
        "acceptance_request_receipt_digest": "6" * 64,
        "terminal_kind": "accepted",
        "terminal_receipt_id": "7" * 64,
        "terminal_receipt_digest": "8" * 64,
        "bound_at": "2026-08-21T12:00:00Z",
        "nonce": "9" * 64,
    }
    raw["binding_id"] = acceptance_decision_binding_id(raw)
    return raw


def _signed_binding(ephemeral_role_keys, *, role: str = "Acceptor"):
    from openworkproof.models import AcceptanceDecisionBindingV01

    private_key = ephemeral_role_keys[role][0]
    return AcceptanceDecisionBindingV01.model_validate(
        sign_payload(
            "acceptance-decision-binding",
            _binding_payload(),
            private_key,
        )
    )


def test_binding_id_and_signature_are_deterministic(ephemeral_role_keys) -> None:
    from openworkproof.models import acceptance_decision_binding_id

    first = _signed_binding(ephemeral_role_keys)
    second = _signed_binding(ephemeral_role_keys)
    assert first == second
    assert first.binding_id == acceptance_decision_binding_id(
        first.model_dump(mode="json")
    )
    assert verify_payload(
        "acceptance-decision-binding",
        first.model_dump(mode="json"),
        ephemeral_role_keys["Acceptor"][0].public_key(),
    )


def test_binding_signature_does_not_verify_under_another_role(
    ephemeral_role_keys,
) -> None:
    binding = _signed_binding(ephemeral_role_keys)
    assert binding.signer_key_id == key_id(
        ephemeral_role_keys["Acceptor"][0].public_key()
    )
    assert not verify_payload(
        "acceptance-decision-binding",
        binding.model_dump(mode="json"),
        ephemeral_role_keys["Maintainer"][0].public_key(),
    )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("schema_version", "openworkproof-acceptance-decision-binding/9.9"),
        ("protocol_version", "0.2"),
        ("verification_decision_digest", "a" * 63),
        ("terminal_kind", "withdrawn"),
        ("bound_at", "2026-08-21T12:00:00+00:00"),
        ("nonce", "A" * 64),
    ),
)
def test_binding_rejects_invalid_closed_fields(
    ephemeral_role_keys,
    field: str,
    value: object,
) -> None:
    from openworkproof.models import AcceptanceDecisionBindingV01

    raw = _binding_payload()
    raw[field] = value
    signed = sign_payload(
        "acceptance-decision-binding",
        raw,
        ephemeral_role_keys["Acceptor"][0],
    )
    with pytest.raises(ValidationError):
        AcceptanceDecisionBindingV01.model_validate(signed)


def test_binding_rejects_unknown_fields(ephemeral_role_keys) -> None:
    from openworkproof.models import AcceptanceDecisionBindingV01

    raw = _binding_payload()
    raw["customer_note"] = "unsigned interpretation"
    signed = sign_payload(
        "acceptance-decision-binding",
        raw,
        ephemeral_role_keys["Acceptor"][0],
    )
    with pytest.raises(ValidationError):
        AcceptanceDecisionBindingV01.model_validate(signed)


def test_binding_rejects_semantic_change_with_stale_id(
    ephemeral_role_keys,
) -> None:
    from openworkproof.models import AcceptanceDecisionBindingV01

    raw = _binding_payload()
    raw["verification_decision_digest"] = "a" * 64
    signed = sign_payload(
        "acceptance-decision-binding",
        raw,
        ephemeral_role_keys["Acceptor"][0],
    )
    with pytest.raises(ValidationError, match="binding ID"):
        AcceptanceDecisionBindingV01.model_validate(signed)


def test_binding_revalidates_malicious_subclass(ephemeral_role_keys) -> None:
    from openworkproof.models import AcceptanceDecisionBindingV01

    binding = _signed_binding(ephemeral_role_keys)

    class Child(AcceptanceDecisionBindingV01):
        pass

    malicious = Child.model_construct(
        **{
            **binding.__dict__,
            "terminal_kind": "withdrawn",
        }
    )
    with pytest.raises(ValidationError):
        AcceptanceDecisionBindingV01.model_validate(malicious)
