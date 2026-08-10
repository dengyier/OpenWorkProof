from __future__ import annotations

import base64
import copy

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from openworkproof.models import (
    CommitmentAnchor,
    PolicyAnchor,
    SubjectClaim,
    VerificationProfileV02,
)
from openworkproof.signing import key_id, sign_payload, verify_payload


def test_subject_claim_binds_customer_acceptor_and_signature(
    signed_subject_claim: SubjectClaim,
    signed_work_order,
    ephemeral_role_keys,
) -> None:
    assert signed_subject_claim.work_order_digest == signed_work_order.digest
    assert (
        signed_subject_claim.customer_acceptor_key_id
        == signed_work_order.acceptor_key_ids[0]
    )
    assert signed_subject_claim.signer_key_id == signed_work_order.key_bindings[1].key_id
    assert verify_payload(
        "subject-claim",
        signed_subject_claim.model_dump(mode="json"),
        ephemeral_role_keys["Manager"][0].public_key(),
    )


def test_subject_claim_binds_customer_acceptor_and_changes_digest(
    signed_subject_claim: SubjectClaim,
) -> None:
    changed = signed_subject_claim.model_dump(mode="json")
    changed["claim_statement"] = "different delivery claim"

    with pytest.raises(ValueError, match="digest"):
        SubjectClaim.model_validate(changed)


@pytest.mark.parametrize(
    "field",
    ["acceptance_conditions", "excluded_scope", "required_artifacts"],
)
def test_subject_claim_arrays_are_non_empty_sorted_and_unique(
    signed_subject_claim: SubjectClaim,
    ephemeral_role_keys,
    field: str,
) -> None:
    candidate = signed_subject_claim.model_dump(mode="json")
    candidate[field] = []
    with pytest.raises(ValidationError, match=field):
        SubjectClaim.model_validate(
            sign_payload(
                "subject-claim", candidate, ephemeral_role_keys["Manager"][0]
            )
        )

    candidate = signed_subject_claim.model_dump(mode="json")
    candidate[field] = list(reversed(candidate[field])) + [candidate[field][0]]
    with pytest.raises(ValidationError, match=field):
        SubjectClaim.model_validate(
            sign_payload(
                "subject-claim", candidate, ephemeral_role_keys["Manager"][0]
            )
        )


def test_external_anchors_are_closed_and_reverse_bound(
    policy_anchor: PolicyAnchor,
    commitment_anchor: CommitmentAnchor,
    signed_subject_claim: SubjectClaim,
    signed_work_order,
) -> None:
    assert policy_anchor.policy_digest == "9" * 64
    assert commitment_anchor.work_order_digest == signed_work_order.digest
    assert commitment_anchor.subject_claim_digest == signed_subject_claim.digest
    with pytest.raises(ValidationError, match="extra"):
        CommitmentAnchor.model_validate(
            {**commitment_anchor.model_dump(mode="json"), "payment_status": "paid"}
        )


def test_standard_profile_binds_claim_and_closed_arms(
    signed_verification_profile: VerificationProfileV02,
    signed_subject_claim: SubjectClaim,
    signed_work_order,
    ephemeral_role_keys,
) -> None:
    profile = signed_verification_profile
    assert profile.work_order_digest == signed_work_order.digest
    assert profile.subject_claim_digest == signed_subject_claim.digest
    assert profile.positive_arm.arm_kind == "positive"
    assert profile.positive_arm.mutant_patch_digest is None
    assert len(profile.negative_arms) == 1
    assert profile.negative_arms[0].mutant_patch_digest is not None
    assert len(profile.verifier_bindings) == 1
    assert verify_payload(
        "verification-profile",
        profile.model_dump(mode="json"),
        ephemeral_role_keys["Manager"][0].public_key(),
    )


def test_profile_change_invalidates_canonical_digest(
    signed_verification_profile: VerificationProfileV02,
) -> None:
    changed = signed_verification_profile.model_dump(mode="json")
    changed["max_output_bytes"] += 1
    with pytest.raises(ValidationError, match="digest"):
        VerificationProfileV02.model_validate(changed)


@pytest.mark.parametrize("level", [2, 3])
def test_level_two_and_three_require_commitment_anchor(
    verification_profile_dict,
    ephemeral_role_keys,
    level: int,
) -> None:
    candidate = copy.deepcopy(verification_profile_dict)
    candidate["delivery_trust_level"] = level
    if level == 3:
        candidate["assurance_level"] = "high_risk"
    signed = sign_payload(
        "verification-profile", candidate, ephemeral_role_keys["Manager"][0]
    )
    with pytest.raises(ValidationError, match="commitment_anchor"):
        VerificationProfileV02.model_validate(signed)


def test_level_three_requires_high_risk_assurance(
    verification_profile_dict,
    ephemeral_role_keys,
) -> None:
    candidate = copy.deepcopy(verification_profile_dict)
    candidate["delivery_trust_level"] = 3
    candidate["commitment_anchor_digest"] = "c" * 64
    signed = sign_payload(
        "verification-profile", candidate, ephemeral_role_keys["Manager"][0]
    )
    with pytest.raises(ValidationError, match="high_risk"):
        VerificationProfileV02.model_validate(signed)


def test_profile_requires_negative_arm_and_ordered_time(
    verification_profile_dict,
    ephemeral_role_keys,
) -> None:
    no_negative = copy.deepcopy(verification_profile_dict)
    no_negative["negative_arms"] = []
    with pytest.raises(ValidationError, match="negative"):
        VerificationProfileV02.model_validate(
            sign_payload(
                "verification-profile", no_negative, ephemeral_role_keys["Manager"][0]
            )
        )

    reversed_time = copy.deepcopy(verification_profile_dict)
    reversed_time["expires_at"] = reversed_time["created_at"]
    with pytest.raises(ValidationError, match="time"):
        VerificationProfileV02.model_validate(
            sign_payload(
                "verification-profile", reversed_time, ephemeral_role_keys["Manager"][0]
            )
        )


def test_high_risk_profile_requires_two_distinct_verifier_bindings(
    verification_profile_dict,
    ephemeral_role_keys,
) -> None:
    candidate = copy.deepcopy(verification_profile_dict)
    candidate["delivery_trust_level"] = 3
    candidate["commitment_anchor_digest"] = "c" * 64
    candidate["assurance_level"] = "high_risk"
    signed = sign_payload(
        "verification-profile", candidate, ephemeral_role_keys["Manager"][0]
    )
    with pytest.raises(ValidationError, match="two distinct"):
        VerificationProfileV02.model_validate(signed)


def test_high_risk_profile_accepts_two_distinct_verifier_bindings(
    verification_profile_dict,
    ephemeral_role_keys,
) -> None:
    candidate = copy.deepcopy(verification_profile_dict)
    candidate["delivery_trust_level"] = 3
    candidate["commitment_anchor_digest"] = "c" * 64
    candidate["assurance_level"] = "high_risk"
    independent_private_key = Ed25519PrivateKey.generate()
    independent_public_key = independent_private_key.public_key()
    independent_raw = independent_public_key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    candidate["verifier_bindings"].append(
        {
            "binding_id": "d" * 64,
            "verifier_subject_id": "independent-verifier",
            "verifier_key_id": key_id(independent_public_key),
            "verifier_public_key_b64url": base64.urlsafe_b64encode(
                independent_raw
            ).decode("ascii").rstrip("="),
            "controller_factors": ["independent-auditor"],
            "execution_context_factors": ["isolated-container-b"],
            "valid_from": "2026-01-01T00:00:04Z",
            "expires_at": "2026-01-01T01:00:00Z",
        }
    )
    parsed = VerificationProfileV02.model_validate(
        sign_payload(
            "verification-profile", candidate, ephemeral_role_keys["Manager"][0]
        )
    )
    assert len(parsed.verifier_bindings) == 2


def test_profile_rejects_bool_limits(
    verification_profile_dict,
    ephemeral_role_keys,
) -> None:
    candidate = copy.deepcopy(verification_profile_dict)
    candidate["max_evidence_bytes"] = True
    with pytest.raises(ValidationError, match="strict JSON integer"):
        VerificationProfileV02.model_validate(
            sign_payload(
                "verification-profile", candidate, ephemeral_role_keys["Manager"][0]
            )
        )
