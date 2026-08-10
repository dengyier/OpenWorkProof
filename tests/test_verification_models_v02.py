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
    VerificationArmResult,
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


@pytest.fixture
def arm_result_dict(signed_verification_profile, ephemeral_role_keys):
    verifier = ephemeral_role_keys["Verifier"][1]
    return {
        "schema_version": "openworkproof-verification-arm-result/0.2",
        "arm_result_id": "0" * 64,
        "profile_digest": signed_verification_profile.digest,
        "arm_id": signed_verification_profile.negative_arms[0].arm_id,
        "arm_kind": "negative",
        "mutation_status": "applied",
        "execution_status": "completed",
        "expectation_status": "satisfied",
        "reason_codes": ["MUTATION_APPLIED", "MUTATION_CAUGHT"],
        "action_receipt_ids": ["1" * 64, "2" * 64],
        "evidence_refs": [
            {
                "path": "results/negative.json",
                "sha256": "3" * 64,
                "media_type": "application/json",
                "size_bytes": 128,
            }
        ],
        "verifier_subject_id": verifier["subject_id"],
        "verifier_key_id": verifier["key_id"],
        "verifier_build_digest": "4" * 64,
        "dependency_lock_digest": "5" * 64,
        "controller_factors": ["customer-independent-verifier"],
        "execution_context_factors": ["isolated-container-a"],
        "created_at": "2026-01-01T00:10:00Z",
    }


def _signed_arm_result(candidate, ephemeral_role_keys) -> VerificationArmResult:
    return VerificationArmResult.model_validate(
        sign_payload(
            "verification-arm-result",
            candidate,
            ephemeral_role_keys["Verifier"][0],
        )
    )


@pytest.mark.parametrize(
    ("mutation", "execution", "expectation", "reason_codes"),
    [
        ("applied", "completed", "satisfied", ["MUTATION_APPLIED", "MUTATION_CAUGHT"]),
        (
            "applied",
            "completed",
            "contradicted",
            ["MUTATION_APPLIED", "MUTATION_SURVIVED"],
        ),
        ("not_applied", "completed", "indeterminate", ["MUTATION_NOT_APPLIED"]),
        (
            "applied",
            "timed_out",
            "indeterminate",
            ["EXEC_TIMEOUT", "MUTATION_APPLIED"],
        ),
        (
            "applied",
            "crashed",
            "indeterminate",
            ["EXEC_CRASHED", "MUTATION_APPLIED"],
        ),
        (
            "applied",
            "resource_exhausted",
            "indeterminate",
            ["EXEC_RESOURCE_EXHAUSTED", "MUTATION_APPLIED"],
        ),
        (
            "applied",
            "evidence_unavailable",
            "indeterminate",
            ["EVIDENCE_MISSING", "MUTATION_APPLIED"],
        ),
    ],
)
def test_negative_arm_result_axes_are_orthogonal(
    mutation,
    execution,
    expectation,
    reason_codes,
    arm_result_dict,
    ephemeral_role_keys,
) -> None:
    value = {
        **arm_result_dict,
        "mutation_status": mutation,
        "execution_status": execution,
        "expectation_status": expectation,
        "reason_codes": reason_codes,
    }
    assert _signed_arm_result(value, ephemeral_role_keys)


def test_positive_arm_success_uses_no_mutation(
    arm_result_dict,
    signed_verification_profile,
    ephemeral_role_keys,
) -> None:
    value = {
        **arm_result_dict,
        "arm_id": signed_verification_profile.positive_arm.arm_id,
        "arm_kind": "positive",
        "mutation_status": "not_applicable",
        "reason_codes": [],
        "evidence_refs": [
            {
                **arm_result_dict["evidence_refs"][0],
                "path": "results/positive.json",
            }
        ],
    }
    assert _signed_arm_result(value, ephemeral_role_keys).expectation_status == "satisfied"


@pytest.mark.parametrize(
    ("arm_kind", "mutation", "execution", "expectation"),
    [
        ("positive", "applied", "completed", "satisfied"),
        ("negative", "not_applicable", "completed", "satisfied"),
        ("negative", "not_applied", "completed", "satisfied"),
        ("negative", "applied", "crashed", "satisfied"),
    ],
)
def test_illegal_arm_result_axis_combinations_fail_model_validation(
    arm_kind,
    mutation,
    execution,
    expectation,
    arm_result_dict,
    signed_verification_profile,
    ephemeral_role_keys,
) -> None:
    value = {
        **arm_result_dict,
        "arm_kind": arm_kind,
        "mutation_status": mutation,
        "execution_status": execution,
        "expectation_status": expectation,
    }
    if arm_kind == "positive":
        value["arm_id"] = signed_verification_profile.positive_arm.arm_id
    with pytest.raises(ValidationError):
        _signed_arm_result(value, ephemeral_role_keys)


@pytest.mark.parametrize(
    ("field", "value", "match"),
    [
        ("reason_codes", ["MUTATION_APPLIED", "MUTATION_APPLIED"], "reason"),
        ("action_receipt_ids", ["2" * 64, "1" * 64], "receipt"),
        ("evidence_refs", [], "evidence"),
    ],
)
def test_arm_result_rejects_non_canonical_or_missing_evidence(
    field,
    value,
    match,
    arm_result_dict,
    ephemeral_role_keys,
) -> None:
    candidate = {**arm_result_dict, field: value}
    with pytest.raises(ValidationError, match=match):
        _signed_arm_result(candidate, ephemeral_role_keys)


def test_arm_result_rejects_bool_evidence_size(
    arm_result_dict,
    ephemeral_role_keys,
) -> None:
    candidate = copy.deepcopy(arm_result_dict)
    signed = sign_payload(
        "verification-arm-result",
        candidate,
        ephemeral_role_keys["Verifier"][0],
    )
    signed["evidence_refs"][0]["size_bytes"] = True
    with pytest.raises(ValidationError, match="strict JSON integer"):
        VerificationArmResult.model_validate(signed)


def test_arm_result_change_invalidates_digest(
    arm_result_dict,
    ephemeral_role_keys,
) -> None:
    result = _signed_arm_result(arm_result_dict, ephemeral_role_keys)
    changed = result.model_dump(mode="json")
    changed["verifier_build_digest"] = "f" * 64
    with pytest.raises(ValidationError, match="digest"):
        VerificationArmResult.model_validate(changed)
