"""Deterministic Evidence Lifecycle v0.2 verification composition."""

from __future__ import annotations

import base64
import hashlib
from datetime import datetime

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from openworkproof.acceptance import (
    AcceptanceTransactionError,
    evidence_snapshot_digest,
)
from openworkproof.models import (
    DecisionDraftRequest,
    SubjectClaim,
    VerificationArmResult,
    VerificationArmResultReference,
    VerificationDecision,
    VerificationDecisionDraft,
    VerificationIndependenceAssessment,
    VerificationProfileV02,
    VerificationReasonCode,
)
from openworkproof.signing import canonical_bytes, verify_payload


class VerificationInputError(ValueError):
    """Authenticated protocol input is invalid; no decision may be created."""


def _decode_public_key(value: str) -> Ed25519PublicKey:
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        return Ed25519PublicKey.from_public_bytes(raw)
    except (TypeError, ValueError) as error:
        raise VerificationInputError("verifier public key is invalid") from error


def _decode_signature(value: str) -> bytes:
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (TypeError, ValueError) as error:
        raise VerificationInputError("verification decision signature is invalid") from error
    if len(raw) != 64:
        raise VerificationInputError("verification decision signature is invalid")
    return raw


def verification_decision_signing_bytes(
    value: VerificationDecisionDraft | VerificationDecision,
) -> bytes:
    """Return the common canonical bytes signed by every decision verifier."""

    if isinstance(value, VerificationDecisionDraft):
        payload = {
            "schema_version": "openworkproof-verification-decision/0.2",
            **value.model_dump(mode="json"),
        }
    elif isinstance(value, VerificationDecision):
        payload = value.model_dump(
            mode="json", exclude={"digest", "verifier_signatures"}
        )
    else:
        raise VerificationInputError("verification decision payload type is invalid")
    return canonical_bytes("verification-decision", payload)


def assess_independence(
    profile: VerificationProfileV02,
    arm_results: tuple[VerificationArmResult, ...],
) -> VerificationIndependenceAssessment:
    required = 2 if profile.assurance_level == "high_risk" else 1
    subjects = {result.verifier_subject_id for result in arm_results}
    keys = {result.verifier_key_id for result in arm_results}
    controllers = {result.controller_factors for result in arm_results}
    contexts = {result.execution_context_factors for result in arm_results}
    checks = {
        "distinct_subjects": len(subjects) >= required,
        "distinct_keys": len(keys) >= required,
        "distinct_controllers": len(controllers) >= required,
        "distinct_execution_contexts": len(contexts) >= required,
    }
    codes = tuple(
        sorted(
            code
            for field, code in (
                ("distinct_subjects", "INDEPENDENCE_INSUFFICIENT"),
                ("distinct_keys", "INDEPENDENCE_KEY_REUSED"),
                ("distinct_controllers", "INDEPENDENCE_DOMAIN_OVERLAP"),
                (
                    "distinct_execution_contexts",
                    "INDEPENDENCE_CONTEXT_REUSED",
                ),
            )
            if not checks[field]
        )
    )
    return VerificationIndependenceAssessment(**checks, reason_codes=codes)


def decision_reason_codes(
    arm_results: tuple[VerificationArmResult, ...],
    independence: VerificationIndependenceAssessment,
) -> tuple[VerificationReasonCode, ...]:
    return tuple(
        sorted(
            {
                *independence.reason_codes,
                *(code for result in arm_results for code in result.reason_codes),
            }
        )
    )


def _validate_arm_results(
    *,
    profile: VerificationProfileV02,
    arm_results: tuple[VerificationArmResult, ...],
) -> None:
    ordered_ids = tuple(result.arm_result_id for result in arm_results)
    if ordered_ids != tuple(sorted(set(ordered_ids))):
        raise VerificationInputError("arm results must be sorted and unique")
    if any(result.profile_digest != profile.digest for result in arm_results):
        raise VerificationInputError("arm result profile mismatch")
    if any(not result.action_receipt_ids for result in arm_results):
        raise VerificationInputError("arm result causal parents are missing")

    expected_arms = {
        arm.arm_id: arm for arm in (profile.positive_arm, *profile.negative_arms)
    }
    if {result.arm_id for result in arm_results} != set(expected_arms) or len(
        arm_results
    ) != len(expected_arms):
        raise VerificationInputError("arm result set is incomplete")

    bindings = {
        binding.verifier_key_id: binding for binding in profile.verifier_bindings
    }
    for result in arm_results:
        arm = expected_arms[result.arm_id]
        if result.arm_kind != arm.arm_kind:
            raise VerificationInputError("arm result kind mismatch")
        binding = bindings.get(result.verifier_key_id)
        if binding is None or binding.verifier_subject_id != result.verifier_subject_id:
            raise VerificationInputError("arm result verifier is not profile-bound")
        if (
            result.controller_factors != binding.controller_factors
            or result.execution_context_factors
            != binding.execution_context_factors
        ):
            raise VerificationInputError("arm result independence factors mismatch")
        if not (
            binding.valid_from <= result.created_at < binding.expires_at
            and profile.created_at <= result.created_at < profile.expires_at
        ):
            raise VerificationInputError("arm result verifier binding is not current")
        public_key = _decode_public_key(binding.verifier_public_key_b64url)
        if not verify_payload(
            "verification-arm-result",
            result.model_dump(mode="json"),
            public_key,
        ):
            raise VerificationInputError("arm result signature is invalid")


def validate_verification_decision(
    *,
    profile: VerificationProfileV02,
    decision: VerificationDecision,
) -> VerificationDecision:
    """Validate the exact Profile-bound multi-signature set on a decision."""

    if (
        decision.work_order_digest != profile.work_order_digest
        or decision.subject_claim_digest != profile.subject_claim_digest
        or decision.profile_id != profile.profile_id
        or decision.profile_digest != profile.digest
        or decision.assurance_level != profile.assurance_level
    ):
        raise VerificationInputError("verification decision profile mismatch")
    if not profile.created_at <= decision.decided_at < profile.expires_at:
        raise VerificationInputError("verification decision is outside profile validity")

    binding_by_key = {
        binding.verifier_key_id: binding for binding in profile.verifier_bindings
    }
    expected_keys = tuple(
        sorted(binding_by_key, key=lambda value: value.encode("utf-8"))
    )
    actual_keys = tuple(
        signature.verifier_key_id for signature in decision.verifier_signatures
    )
    if actual_keys != expected_keys:
        raise VerificationInputError("verification decision signature set is not profile-bound")

    encoded = verification_decision_signing_bytes(decision)
    for signature in decision.verifier_signatures:
        binding = binding_by_key[signature.verifier_key_id]
        if signature.verifier_subject_id != binding.verifier_subject_id:
            raise VerificationInputError(
                "verification decision signature subject is not profile-bound"
            )
        public_key = _decode_public_key(binding.verifier_public_key_b64url)
        try:
            public_key.verify(_decode_signature(signature.signature), encoded)
        except InvalidSignature as error:
            raise VerificationInputError(
                "verification decision signature is invalid"
            ) from error
    return decision


def compose_verification_decision(
    *,
    profile: VerificationProfileV02,
    subject_claim: SubjectClaim,
    arm_results: tuple[VerificationArmResult, ...],
    previous_decision: VerificationDecision | None,
    decision_id: str,
    decided_at: datetime,
    nonce: str,
) -> VerificationDecisionDraft:
    """Compose a deterministic draft from authenticated, frozen inputs."""

    if (
        type(decided_at) is not datetime
        or decided_at.tzinfo is None
        or decided_at.utcoffset() is None
        or decided_at.utcoffset().total_seconds() != 0
        or decided_at.microsecond != 0
    ):
        raise VerificationInputError("decided_at must be a canonical UTC second")
    try:
        request = DecisionDraftRequest.model_validate(
            {
                "decision_id": decision_id,
                "decided_at": decided_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "nonce": nonce,
            }
        )
    except ValueError as error:
        raise VerificationInputError("decision draft request is invalid") from error

    if profile.subject_claim_digest != subject_claim.digest:
        raise VerificationInputError("subject claim does not match profile")
    if profile.work_order_digest != subject_claim.work_order_digest:
        raise VerificationInputError("subject claim work order does not match profile")
    _validate_arm_results(profile=profile, arm_results=arm_results)

    if previous_decision is not None:
        validate_verification_decision(profile=profile, decision=previous_decision)
        if not previous_decision.decided_at < request.decided_at:
            raise VerificationInputError("superseding decision time is stale")

    positive = tuple(
        result for result in arm_results if result.arm_kind == "positive"
    )
    negative = tuple(
        result for result in arm_results if result.arm_kind == "negative"
    )
    if len(positive) != 1 or len(negative) != len(profile.negative_arms):
        raise VerificationInputError("arm result set is incomplete")

    independence = assess_independence(profile, arm_results)
    if positive[0].expectation_status == "contradicted" or any(
        result.expectation_status == "contradicted" for result in negative
    ):
        decision = "REFUTED"
    elif positive[0].expectation_status != "satisfied" or any(
        result.expectation_status != "satisfied" for result in negative
    ) or not independence.is_sufficient:
        decision = "UNKNOWN"
    else:
        decision = "VERIFIED"

    references = []
    for result in arm_results:
        try:
            snapshot = evidence_snapshot_digest(result.evidence_refs)
        except AcceptanceTransactionError as error:
            raise VerificationInputError("arm result evidence is not canonical") from error
        references.append(
            VerificationArmResultReference(
                arm_id=result.arm_id,
                arm_result_id=result.arm_result_id,
                arm_result_digest=result.digest,
                evidence_snapshot_digest=snapshot,
            )
        )

    return VerificationDecisionDraft(
        decision_id=request.decision_id,
        work_order_digest=profile.work_order_digest,
        subject_claim_digest=profile.subject_claim_digest,
        profile_id=profile.profile_id,
        profile_digest=profile.digest,
        arm_results=tuple(reference.model_dump(mode="json") for reference in references),
        assurance_level=profile.assurance_level,
        decision=decision,
        independence=independence.model_dump(mode="json"),
        reason_codes=decision_reason_codes(arm_results, independence),
        supersedes_decision_id=(
            None if previous_decision is None else previous_decision.decision_id
        ),
        supersedes_decision_digest=(
            None if previous_decision is None else previous_decision.digest
        ),
        causal_parent_receipt_ids=tuple(
            sorted(
                {
                    receipt_id
                    for result in arm_results
                    for receipt_id in result.action_receipt_ids
                }
            )
        ),
        causal_parent_decision_ids=(
            () if previous_decision is None else (previous_decision.decision_id,)
        ),
        decided_at=request.model_dump(mode="json")["decided_at"],
        nonce=request.nonce,
    )
