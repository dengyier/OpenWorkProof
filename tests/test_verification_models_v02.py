from __future__ import annotations

import base64
import copy
import hashlib
from datetime import datetime, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from openworkproof.models import (
    CommitmentAnchor,
    PolicyAnchor,
    SubjectClaim,
    VerificationArmResult,
    VerificationDecision,
    VerificationProfileV02,
)
from openworkproof.signing import canonical_bytes, key_id, sign_payload, verify_payload
from openworkproof.verification import (
    VerificationInputError,
    compose_verification_decision,
    validate_verification_decision,
    verification_decision_signing_bytes,
)


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


def _decision_arm_result(
    *,
    profile: VerificationProfileV02,
    arm_kind: str,
    result_id: str,
    expectation_status: str,
    private_key: Ed25519PrivateKey,
    verifier_binding,
    execution_status: str = "completed",
) -> VerificationArmResult:
    arm = (
        profile.positive_arm
        if arm_kind == "positive"
        else profile.negative_arms[0]
    )
    mutation_status = "not_applicable" if arm_kind == "positive" else "applied"
    if expectation_status == "indeterminate":
        execution_status = "evidence_unavailable"
        reason_codes = ["EVIDENCE_MISSING"]
        if arm_kind == "negative":
            reason_codes.append("MUTATION_APPLIED")
        evidence_refs = []
    elif arm_kind == "negative":
        reason_codes = [
            "MUTATION_APPLIED",
            "MUTATION_CAUGHT"
            if expectation_status == "satisfied"
            else "MUTATION_SURVIVED",
        ]
        evidence_refs = [
            {
                "path": f"results/{arm_kind}-{result_id[:4]}.json",
                "sha256": "d" * 64,
                "media_type": "application/json",
                "size_bytes": 128,
            }
        ]
    else:
        reason_codes = []
        evidence_refs = [
            {
                "path": f"results/{arm_kind}-{result_id[:4]}.json",
                "sha256": "e" * 64,
                "media_type": "application/json",
                "size_bytes": 128,
            }
        ]
    candidate = {
        "schema_version": "openworkproof-verification-arm-result/0.2",
        "arm_result_id": result_id,
        "profile_digest": profile.digest,
        "arm_id": arm.arm_id,
        "arm_kind": arm_kind,
        "mutation_status": mutation_status,
        "execution_status": execution_status,
        "expectation_status": expectation_status,
        "reason_codes": sorted(reason_codes),
        "action_receipt_ids": [result_id],
        "evidence_refs": evidence_refs,
        "verifier_subject_id": verifier_binding.verifier_subject_id,
        "verifier_key_id": verifier_binding.verifier_key_id,
        "verifier_build_digest": "4" * 64,
        "dependency_lock_digest": "5" * 64,
        "controller_factors": list(verifier_binding.controller_factors),
        "execution_context_factors": list(
            verifier_binding.execution_context_factors
        ),
        "created_at": "2026-01-01T00:10:00Z",
    }
    return VerificationArmResult.model_validate(
        sign_payload("verification-arm-result", candidate, private_key)
    )


def _decision_results(
    profile: VerificationProfileV02,
    ephemeral_role_keys,
    *,
    positive: str = "satisfied",
    negative: str = "satisfied",
) -> tuple[VerificationArmResult, ...]:
    binding = profile.verifier_bindings[0]
    private_key = ephemeral_role_keys["Verifier"][0]
    return (
        _decision_arm_result(
            profile=profile,
            arm_kind="positive",
            result_id="8" * 64,
            expectation_status=positive,
            private_key=private_key,
            verifier_binding=binding,
        ),
        _decision_arm_result(
            profile=profile,
            arm_kind="negative",
            result_id="9" * 64,
            expectation_status=negative,
            private_key=private_key,
            verifier_binding=binding,
        ),
    )


def _compose_decision_draft(
    profile: VerificationProfileV02,
    claim: SubjectClaim,
    results: tuple[VerificationArmResult, ...],
    previous_decision: VerificationDecision | None = None,
):
    return compose_verification_decision(
        profile=profile,
        subject_claim=claim,
        arm_results=results,
        previous_decision=previous_decision,
        decision_id="a" * 64,
        decided_at=datetime(2026, 1, 1, 0, 20, tzinfo=timezone.utc),
        nonce="b" * 64,
    )


def _signed_decision(
    draft,
    *,
    profile: VerificationProfileV02,
    private_keys: tuple[Ed25519PrivateKey, ...],
) -> VerificationDecision:
    encoded = verification_decision_signing_bytes(draft)
    binding_by_key = {
        binding.verifier_key_id: binding for binding in profile.verifier_bindings
    }
    signatures = []
    for private_key in private_keys:
        signer_key_id = key_id(private_key.public_key())
        binding = binding_by_key[signer_key_id]
        signatures.append(
            {
                "verifier_subject_id": binding.verifier_subject_id,
                "verifier_key_id": signer_key_id,
                "signature_alg": "Ed25519",
                "signature": base64.urlsafe_b64encode(
                    private_key.sign(encoded)
                ).decode("ascii").rstrip("="),
            }
        )
    signatures.sort(key=lambda item: item["verifier_key_id"].encode("utf-8"))
    return VerificationDecision.model_validate(
        {
            "schema_version": "openworkproof-verification-decision/0.2",
            **draft.model_dump(mode="json"),
            "digest": hashlib.sha256(encoded).hexdigest(),
            "verifier_signatures": signatures,
        }
    )


@pytest.mark.parametrize(
    ("positive", "negative", "expected"),
    [
        ("satisfied", "satisfied", "VERIFIED"),
        ("contradicted", "satisfied", "REFUTED"),
        ("satisfied", "contradicted", "REFUTED"),
        ("satisfied", "indeterminate", "UNKNOWN"),
    ],
)
def test_compose_verification_decision_matrix(
    positive,
    negative,
    expected,
    signed_verification_profile,
    signed_subject_claim,
    ephemeral_role_keys,
) -> None:
    results = _decision_results(
        signed_verification_profile,
        ephemeral_role_keys,
        positive=positive,
        negative=negative,
    )
    assert (
        _compose_decision_draft(
            signed_verification_profile,
            signed_subject_claim,
            results,
        ).decision
        == expected
    )


def test_decision_requires_complete_sorted_unique_arm_result_set(
    signed_verification_profile,
    signed_subject_claim,
    ephemeral_role_keys,
) -> None:
    results = _decision_results(signed_verification_profile, ephemeral_role_keys)
    with pytest.raises(VerificationInputError, match="sorted and unique"):
        _compose_decision_draft(
            signed_verification_profile,
            signed_subject_claim,
            tuple(reversed(results)),
        )
    with pytest.raises(VerificationInputError, match="incomplete"):
        _compose_decision_draft(
            signed_verification_profile,
            signed_subject_claim,
            results[:1],
        )
    with pytest.raises(VerificationInputError, match="sorted and unique"):
        _compose_decision_draft(
            signed_verification_profile,
            signed_subject_claim,
            (results[0], results[0]),
        )


def test_missing_evidence_is_signed_unknown_not_invalid_input(
    signed_verification_profile,
    signed_subject_claim,
    ephemeral_role_keys,
) -> None:
    results = _decision_results(
        signed_verification_profile,
        ephemeral_role_keys,
        negative="indeterminate",
    )
    draft = _compose_decision_draft(
        signed_verification_profile,
        signed_subject_claim,
        results,
    )
    assert draft.decision == "UNKNOWN"
    assert "EVIDENCE_MISSING" in draft.reason_codes


def test_decision_rejects_wrong_claim_and_profile_result(
    signed_verification_profile,
    signed_subject_claim,
    ephemeral_role_keys,
) -> None:
    results = _decision_results(signed_verification_profile, ephemeral_role_keys)
    wrong_claim = signed_subject_claim.model_copy(
        update={"digest": "f" * 64}
    )
    with pytest.raises(VerificationInputError, match="claim"):
        _compose_decision_draft(
            signed_verification_profile,
            wrong_claim,
            results,
        )
    wrong_result = results[0].model_copy(update={"profile_digest": "f" * 64})
    with pytest.raises(VerificationInputError, match="profile"):
        _compose_decision_draft(
            signed_verification_profile,
            signed_subject_claim,
            (wrong_result, results[1]),
        )

    missing_parent = results[0].model_copy(update={"action_receipt_ids": ()})
    with pytest.raises(VerificationInputError, match="causal parents"):
        _compose_decision_draft(
            signed_verification_profile,
            signed_subject_claim,
            (missing_parent, results[1]),
        )


def test_decision_rejects_bad_arm_result_signature(
    signed_verification_profile,
    signed_subject_claim,
    ephemeral_role_keys,
) -> None:
    results = _decision_results(signed_verification_profile, ephemeral_role_keys)
    bad = results[0].model_copy(
        update={"signature": base64.urlsafe_b64encode(b"x" * 64).decode("ascii").rstrip("=")}
    )
    with pytest.raises(VerificationInputError, match="signature"):
        _compose_decision_draft(
            signed_verification_profile,
            signed_subject_claim,
            (bad, results[1]),
        )


def test_decision_signature_set_is_exact_and_profile_bound(
    signed_verification_profile,
    signed_subject_claim,
    ephemeral_role_keys,
) -> None:
    results = _decision_results(signed_verification_profile, ephemeral_role_keys)
    draft = _compose_decision_draft(
        signed_verification_profile,
        signed_subject_claim,
        results,
    )
    decision = _signed_decision(
        draft,
        profile=signed_verification_profile,
        private_keys=(ephemeral_role_keys["Verifier"][0],),
    )
    assert validate_verification_decision(
        profile=signed_verification_profile,
        decision=decision,
    ) is decision

    extra = decision.model_dump(mode="json")
    extra["verifier_signatures"].append(extra["verifier_signatures"][0])
    with pytest.raises(ValidationError, match="signature"):
        VerificationDecision.model_validate(extra)

    wrong = decision.model_dump(mode="json")
    wrong["verifier_signatures"][0]["signature"] = base64.urlsafe_b64encode(
        ephemeral_role_keys["Manager"][0].sign(
            verification_decision_signing_bytes(decision)
        )
    ).decode("ascii").rstrip("=")
    wrong_decision = VerificationDecision.model_validate(wrong)
    with pytest.raises(VerificationInputError, match="signature"):
        validate_verification_decision(
            profile=signed_verification_profile,
            decision=wrong_decision,
        )

    divergent = decision.model_dump(mode="json")
    divergent["nonce"] = "c" * 64
    divergent_payload = {
        key: value
        for key, value in divergent.items()
        if key not in {"digest", "verifier_signatures"}
    }
    divergent["digest"] = hashlib.sha256(
        canonical_bytes("verification-decision", divergent_payload)
    ).hexdigest()
    divergent_decision = VerificationDecision.model_validate(divergent)
    with pytest.raises(VerificationInputError, match="signature"):
        validate_verification_decision(
            profile=signed_verification_profile,
            decision=divergent_decision,
        )


def test_decision_supersedes_current_decision_exactly(
    signed_verification_profile,
    signed_subject_claim,
    ephemeral_role_keys,
) -> None:
    results = _decision_results(signed_verification_profile, ephemeral_role_keys)
    first_draft = _compose_decision_draft(
        signed_verification_profile,
        signed_subject_claim,
        results,
    )
    first = _signed_decision(
        first_draft,
        profile=signed_verification_profile,
        private_keys=(ephemeral_role_keys["Verifier"][0],),
    )
    next_draft = compose_verification_decision(
        profile=signed_verification_profile,
        subject_claim=signed_subject_claim,
        arm_results=results,
        previous_decision=first,
        decision_id="c" * 64,
        decided_at=datetime(2026, 1, 1, 0, 30, tzinfo=timezone.utc),
        nonce="d" * 64,
    )
    assert next_draft.supersedes_decision_id == first.decision_id
    assert next_draft.supersedes_decision_digest == first.digest
    assert next_draft.causal_parent_decision_ids == (first.decision_id,)

    with pytest.raises(VerificationInputError, match="time is stale"):
        compose_verification_decision(
            profile=signed_verification_profile,
            subject_claim=signed_subject_claim,
            arm_results=results,
            previous_decision=first,
            decision_id="e" * 64,
            decided_at=datetime(2026, 1, 1, 0, 19, tzinfo=timezone.utc),
            nonce="f" * 64,
        )


def test_high_risk_decision_requires_independent_results_and_two_signatures(
    verification_profile_dict,
    signed_subject_claim,
    ephemeral_role_keys,
) -> None:
    independent_key = Ed25519PrivateKey.generate()
    independent_public = independent_key.public_key()
    independent_raw = independent_public.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    candidate = copy.deepcopy(verification_profile_dict)
    candidate["delivery_trust_level"] = 3
    candidate["commitment_anchor_digest"] = "c" * 64
    candidate["assurance_level"] = "high_risk"
    candidate["verifier_bindings"].append(
        {
            "binding_id": "d" * 64,
            "verifier_subject_id": "independent-verifier",
            "verifier_key_id": key_id(independent_public),
            "verifier_public_key_b64url": base64.urlsafe_b64encode(
                independent_raw
            ).decode("ascii").rstrip("="),
            "controller_factors": ["independent-auditor"],
            "execution_context_factors": ["isolated-container-b"],
            "valid_from": "2026-01-01T00:00:04Z",
            "expires_at": "2026-01-01T01:00:00Z",
        }
    )
    profile = VerificationProfileV02.model_validate(
        sign_payload(
            "verification-profile",
            candidate,
            ephemeral_role_keys["Manager"][0],
        )
    )
    primary_binding, independent_binding = profile.verifier_bindings
    results = (
        _decision_arm_result(
            profile=profile,
            arm_kind="positive",
            result_id="8" * 64,
            expectation_status="satisfied",
            private_key=ephemeral_role_keys["Verifier"][0],
            verifier_binding=primary_binding,
        ),
        _decision_arm_result(
            profile=profile,
            arm_kind="negative",
            result_id="9" * 64,
            expectation_status="satisfied",
            private_key=independent_key,
            verifier_binding=independent_binding,
        ),
    )
    draft = _compose_decision_draft(profile, signed_subject_claim, results)
    assert draft.decision == "VERIFIED"
    assert draft.independence.is_sufficient
    decision = _signed_decision(
        draft,
        profile=profile,
        private_keys=(ephemeral_role_keys["Verifier"][0], independent_key),
    )
    assert validate_verification_decision(profile=profile, decision=decision)

    one_signature = decision.model_dump(mode="json")
    one_signature["verifier_signatures"] = one_signature[
        "verifier_signatures"
    ][:1]
    with pytest.raises(ValidationError, match="signature set"):
        VerificationDecision.model_validate(one_signature)

    reused_results = (
        results[0],
        _decision_arm_result(
            profile=profile,
            arm_kind="negative",
            result_id="9" * 64,
            expectation_status="satisfied",
            private_key=ephemeral_role_keys["Verifier"][0],
            verifier_binding=primary_binding,
        ),
    )
    unknown = _compose_decision_draft(profile, signed_subject_claim, reused_results)
    assert unknown.decision == "UNKNOWN"
    assert "INDEPENDENCE_INSUFFICIENT" in unknown.reason_codes
