from __future__ import annotations

from typing import Literal

import pytest

from openworkproof.models import (
    DecisionDraftRequest,
    EvaluationScopeManifest,
    VerificationArmResultV03,
    VerificationProfileV02,
    VerificationProfileV03,
)
from openworkproof.signing import sign_payload
from openworkproof.verification import (
    VerificationInputError,
    compose_verification_decision_v03,
    validate_verification_profile_v03,
)


@pytest.fixture
def verification_profile_v03(
    evaluation_scope_v03: EvaluationScopeManifest,
    ephemeral_role_keys,
) -> VerificationProfileV03:
    verifier = ephemeral_role_keys["Verifier"][1]
    common_arm = {
        "source_commit": evaluation_scope_v03.source_revision,
        "candidate_commit": evaluation_scope_v03.candidate_commit,
        "workspace_manifest_digest": evaluation_scope_v03.workspace_manifest_digest,
        "command_digest": "4" * 64,
        "container_image_digest": "sha256:" + "a" * 64,
        "fixed_test_source_digest": "b" * 64,
        "required_evidence_purposes": ["verifier_result"],
    }
    payload = {
        "schema_version": "openworkproof-verification-profile/0.3",
        "profile_id": "6" * 64,
        "work_order_digest": evaluation_scope_v03.work_order_digest,
        "subject_claim_digest": evaluation_scope_v03.subject_claim_digest,
        "evaluation_scope_id": evaluation_scope_v03.scope_id,
        "evaluation_scope_digest": evaluation_scope_v03.digest,
        "scope_requirement": "exact_match",
        "delivery_trust_level": 1,
        "policy_anchor_digest": None,
        "commitment_anchor_digest": None,
        "subject_kind": "tests_passed",
        "assurance_level": "standard",
        "verifier_bindings": [
            {
                "binding_id": "a" * 64,
                "verifier_subject_id": verifier["subject_id"],
                "verifier_key_id": verifier["key_id"],
                "verifier_public_key_b64url": verifier["public_key_b64url"],
                "controller_factors": ["customer-independent-verifier"],
                "execution_context_factors": ["isolated-container-a"],
                "valid_from": "2026-01-01T00:00:04Z",
                "expires_at": "2026-01-01T01:00:00Z",
            }
        ],
        "positive_arm": {
            **common_arm,
            "arm_id": "1" * 64,
            "arm_kind": "positive",
            "mutant_patch_digest": None,
            "expected_exit_codes": [0],
            "expected_outcome": "pass",
            "result_artifact_paths": ["results/positive.json"],
        },
        "negative_arms": [
            {
                **common_arm,
                "arm_id": "2" * 64,
                "arm_kind": "negative",
                "mutant_patch_digest": "5" * 64,
                "expected_exit_codes": [1],
                "expected_outcome": "fail",
                "result_artifact_paths": ["results/negative.json"],
            }
        ],
        "max_evidence_bytes": 1048576,
        "max_output_bytes": 65536,
        "created_at": "2026-01-01T00:00:05Z",
        "expires_at": "2026-01-01T01:00:00Z",
        "nonce": "b" * 64,
    }
    return VerificationProfileV03.model_validate(
        sign_payload(
            "verification-profile",
            payload,
            ephemeral_role_keys["Manager"][0],
            version="0.3",
        )
    )


def _arm_result(
    *,
    profile: VerificationProfileV03,
    manifest: EvaluationScopeManifest,
    ephemeral_role_keys,
    arm_kind: Literal["positive", "negative"],
    scope_status: Literal["satisfied", "contradicted", "indeterminate"],
    negative_survived: bool = False,
    observed_count: int | None = None,
    observed_population_digest: str | None = None,
    observed_required_target_ids: tuple[str, ...] | None = None,
) -> VerificationArmResultV03:
    arm = profile.positive_arm if arm_kind == "positive" else profile.negative_arms[0]
    result_id = "8" * 64 if arm_kind == "positive" else "9" * 64
    expectation = (
        "contradicted" if arm_kind == "negative" and negative_survived else "satisfied"
    )
    reasons: list[str] = []
    if arm_kind == "negative":
        reasons.extend(
            [
                "MUTATION_APPLIED",
                "MUTATION_SURVIVED" if negative_survived else "MUTATION_CAUGHT",
            ]
        )
    if scope_status == "indeterminate":
        reasons.append("SCOPE_EVIDENCE_MISSING")
    elif scope_status == "contradicted":
        reasons.append("SCOPE_POPULATION_DRIFT")
    verifier = profile.verifier_bindings[0]
    payload = {
        "schema_version": "openworkproof-verification-arm-result/0.3",
        "arm_result_id": result_id,
        "profile_digest": profile.digest,
        "arm_id": arm.arm_id,
        "arm_kind": arm_kind,
        "mutation_status": "not_applicable" if arm_kind == "positive" else "applied",
        "execution_status": "completed",
        "expectation_status": expectation,
        "reason_codes": sorted(reasons),
        "action_receipt_ids": [result_id],
        "evidence_refs": [
            {
                "path": f"results/{arm_kind}.json",
                "sha256": "d" * 64,
                "media_type": "application/json",
                "size_bytes": 128,
            }
        ],
        "scope_manifest_digest": manifest.digest,
        "observed_member_count": (
            manifest.member_count if observed_count is None else observed_count
        ),
        "observed_population_digest": (
            manifest.population_digest
            if observed_population_digest is None
            else observed_population_digest
        ),
        "observed_required_target_ids": list(
            manifest.required_target_ids
            if observed_required_target_ids is None
            else observed_required_target_ids
        ),
        "scope_expectation_status": scope_status,
        "scope_evidence_refs": [
            {
                "path": f"scope/{arm_kind}.json",
                "sha256": "e" * 64,
                "media_type": "application/json",
                "size_bytes": 128,
            }
        ],
        "verifier_subject_id": verifier.verifier_subject_id,
        "verifier_key_id": verifier.verifier_key_id,
        "verifier_build_digest": "4" * 64,
        "dependency_lock_digest": "5" * 64,
        "controller_factors": list(verifier.controller_factors),
        "execution_context_factors": list(verifier.execution_context_factors),
        "created_at": "2026-01-01T00:10:00Z",
    }
    return VerificationArmResultV03.model_validate(
        sign_payload(
            "verification-arm-result",
            payload,
            ephemeral_role_keys["Verifier"][0],
            version="0.3",
        )
    )


def _compose(
    profile,
    manifest,
    results,
):
    return compose_verification_decision_v03(
        profile=profile,
        manifest=manifest,
        arm_results=results,
        request=DecisionDraftRequest(
            decision_id="c" * 64,
            decided_at="2026-01-01T00:20:00Z",
            nonce="d" * 64,
        ),
    )


def test_v03_profile_binds_exact_manifest(
    verification_profile_v03,
    evaluation_scope_v03,
) -> None:
    validate_verification_profile_v03(
        verification_profile_v03, evaluation_scope_v03
    )
    wrong = verification_profile_v03.model_copy(
        update={"evaluation_scope_id": "f" * 64}
    )
    with pytest.raises(VerificationInputError, match="scope"):
        validate_verification_profile_v03(wrong, evaluation_scope_v03)


@pytest.mark.parametrize(
    ("scope_status", "negative_survived", "expected"),
    (
        ("satisfied", False, "VERIFIED"),
        ("satisfied", True, "REFUTED"),
        ("indeterminate", False, "UNKNOWN"),
        ("contradicted", False, "UNKNOWN"),
    ),
)
def test_v03_compose_decision_table(
    verification_profile_v03,
    evaluation_scope_v03,
    ephemeral_role_keys,
    scope_status,
    negative_survived,
    expected,
) -> None:
    results = tuple(
        _arm_result(
            profile=verification_profile_v03,
            manifest=evaluation_scope_v03,
            ephemeral_role_keys=ephemeral_role_keys,
            arm_kind=kind,
            scope_status=scope_status,
            negative_survived=negative_survived,
        )
        for kind in ("positive", "negative")
    )
    draft = _compose(verification_profile_v03, evaluation_scope_v03, results)
    assert draft.decision == expected
    assert draft.scope_assessment.scope_status == scope_status


def test_v03_cross_arm_mismatch_is_unknown(
    verification_profile_v03,
    evaluation_scope_v03,
    ephemeral_role_keys,
) -> None:
    results = (
        _arm_result(
            profile=verification_profile_v03,
            manifest=evaluation_scope_v03,
            ephemeral_role_keys=ephemeral_role_keys,
            arm_kind="positive",
            scope_status="satisfied",
        ),
        _arm_result(
            profile=verification_profile_v03,
            manifest=evaluation_scope_v03,
            ephemeral_role_keys=ephemeral_role_keys,
            arm_kind="negative",
            scope_status="satisfied",
            observed_population_digest="f" * 64,
        ),
    )
    draft = _compose(verification_profile_v03, evaluation_scope_v03, results)
    assert draft.decision == "UNKNOWN"
    assert "SCOPE_CROSS_ARM_MISMATCH" in draft.reason_codes


def test_v03_validly_resigned_wrong_count_is_unknown(
    verification_profile_v03,
    evaluation_scope_v03,
    ephemeral_role_keys,
) -> None:
    results = tuple(
        _arm_result(
            profile=verification_profile_v03,
            manifest=evaluation_scope_v03,
            ephemeral_role_keys=ephemeral_role_keys,
            arm_kind=kind,
            scope_status="satisfied",
            observed_count=evaluation_scope_v03.member_count - 1,
        )
        for kind in ("positive", "negative")
    )
    draft = _compose(verification_profile_v03, evaluation_scope_v03, results)
    assert draft.decision == "UNKNOWN"
    assert "SCOPE_POPULATION_DRIFT" in draft.reason_codes


def test_v03_missing_required_target_is_unknown(
    verification_profile_v03,
    evaluation_scope_v03,
    ephemeral_role_keys,
) -> None:
    observed_targets = evaluation_scope_v03.required_target_ids[:-1]
    results = tuple(
        _arm_result(
            profile=verification_profile_v03,
            manifest=evaluation_scope_v03,
            ephemeral_role_keys=ephemeral_role_keys,
            arm_kind=kind,
            scope_status="satisfied",
            observed_required_target_ids=observed_targets,
        )
        for kind in ("positive", "negative")
    )
    draft = _compose(verification_profile_v03, evaluation_scope_v03, results)
    assert draft.decision == "UNKNOWN"
    assert draft.scope_assessment.missing_required_target_ids
    assert "SCOPE_REQUIRED_TARGET_MISSING" in draft.reason_codes


def test_v03_draft_rejects_caller_forged_scope_assessment(
    verification_profile_v03,
    evaluation_scope_v03,
    ephemeral_role_keys,
) -> None:
    results = tuple(
        _arm_result(
            profile=verification_profile_v03,
            manifest=evaluation_scope_v03,
            ephemeral_role_keys=ephemeral_role_keys,
            arm_kind=kind,
            scope_status="satisfied",
            observed_count=evaluation_scope_v03.member_count - 1,
        )
        for kind in ("positive", "negative")
    )
    draft = _compose(verification_profile_v03, evaluation_scope_v03, results)
    forged = draft.model_dump(mode="json")
    forged["scope_assessment"]["scope_status"] = "satisfied"
    with pytest.raises(ValueError, match="internally inconsistent"):
        type(draft).model_validate(forged)


def test_v03_composer_rejects_v02_profile(
    signed_verification_profile: VerificationProfileV02,
    evaluation_scope_v03,
) -> None:
    with pytest.raises(VerificationInputError, match="v0.3"):
        _compose(signed_verification_profile, evaluation_scope_v03, ())
