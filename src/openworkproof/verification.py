"""Deterministic Evidence Lifecycle v0.2 verification composition."""

from __future__ import annotations

import base64
import hashlib
import json
import sqlite3
from datetime import datetime
from pathlib import Path
from collections.abc import Sequence
from typing import Callable, Literal, TypeVar

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from openworkproof.acceptance import (
    AcceptanceTransactionError,
    evidence_snapshot_digest,
)
from openworkproof.models import (
    CommitmentAnchor,
    DecisionDraftRequest,
    EvaluationScopeManifest,
    PolicyAnchor,
    SubjectClaim,
    VerificationArmResult,
    VerificationArmResultV03,
    VerificationArmResultReference,
    VerificationDecision,
    VerificationDecisionDraft,
    VerificationDecisionDraftV03,
    VerificationIndependenceAssessment,
    VerificationProfileV02,
    VerificationProfileV03,
    VerificationReasonCode,
    ScopeAssessment,
    WorkOrder,
)
from openworkproof.signing import (
    canonical_bytes,
    decode_and_verify_key_binding,
    verify_payload,
    verify_work_order_identity_bindings,
)
import openworkproof.evidence as evidence


class VerificationInputError(ValueError):
    """Authenticated protocol input is invalid; no decision may be created."""


class VerificationTransactionError(RuntimeError):
    """A verification ledger transaction did not commit."""


class VerificationCommittedError(VerificationTransactionError):
    """The exact result committed although acknowledgement or cleanup failed."""

    def __init__(self, message: str, committed: object) -> None:
        super().__init__(message)
        self.committed = committed


class VerificationCommitIndeterminateError(VerificationTransactionError):
    """The transaction outcome cannot be proven and blind retry is unsafe."""


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
        _validate_single_arm_result(
            profile=profile,
            result=result,
            expected_arm=expected_arms[result.arm_id],
            bindings=bindings,
        )


def _validate_single_arm_result(
    *,
    profile: VerificationProfileV02,
    result: VerificationArmResult,
    expected_arm=None,
    bindings=None,
) -> None:
    expected_arms = {
        arm.arm_id: arm for arm in (profile.positive_arm, *profile.negative_arms)
    }
    arm = expected_arm if expected_arm is not None else expected_arms.get(result.arm_id)
    if arm is None or result.arm_kind != arm.arm_kind:
        raise VerificationInputError("arm result kind or id mismatch")
    profile_bindings = bindings or {
        binding.verifier_key_id: binding for binding in profile.verifier_bindings
    }
    binding = profile_bindings.get(result.verifier_key_id)
    if binding is None or binding.verifier_subject_id != result.verifier_subject_id:
        raise VerificationInputError("arm result verifier is not profile-bound")
    if (
        result.controller_factors != binding.controller_factors
        or result.execution_context_factors != binding.execution_context_factors
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


def validate_verification_profile_v03(
    profile: VerificationProfileV03,
    manifest: EvaluationScopeManifest,
) -> None:
    if not isinstance(profile, VerificationProfileV03):
        raise VerificationInputError("profile must be a v0.3 verification profile")
    if not isinstance(manifest, EvaluationScopeManifest):
        raise VerificationInputError("manifest must be a v0.3 evaluation scope")
    if (
        profile.evaluation_scope_id != manifest.scope_id
        or profile.evaluation_scope_digest != manifest.digest
        or profile.work_order_digest != manifest.work_order_digest
        or profile.subject_claim_digest != manifest.subject_claim_digest
    ):
        raise VerificationInputError("profile scope binding mismatch")
    for arm in (profile.positive_arm, *profile.negative_arms):
        if (
            arm.source_commit != manifest.source_revision
            or arm.candidate_commit != manifest.candidate_commit
            or arm.workspace_manifest_digest != manifest.workspace_manifest_digest
        ):
            raise VerificationInputError("profile arm scope binding mismatch")


def _validate_arm_results_v03(
    *,
    profile: VerificationProfileV03,
    manifest: EvaluationScopeManifest,
    arm_results: tuple[VerificationArmResultV03, ...],
) -> None:
    ordered_ids = tuple(result.arm_result_id for result in arm_results)
    if ordered_ids != tuple(sorted(set(ordered_ids))):
        raise VerificationInputError("arm results must be sorted and unique")
    expected_arms = {
        arm.arm_id: arm for arm in (profile.positive_arm, *profile.negative_arms)
    }
    if (
        len(arm_results) != len(expected_arms)
        or {result.arm_id for result in arm_results} != set(expected_arms)
    ):
        raise VerificationInputError("arm result set is incomplete")
    bindings = {
        binding.verifier_key_id: binding for binding in profile.verifier_bindings
    }
    for result in arm_results:
        if result.profile_digest != profile.digest:
            raise VerificationInputError("arm result profile mismatch")
        if result.scope_manifest_digest != manifest.digest:
            raise VerificationInputError("arm result scope manifest mismatch")
        arm = expected_arms[result.arm_id]
        if result.arm_kind != arm.arm_kind:
            raise VerificationInputError("arm result kind or id mismatch")
        binding = bindings.get(result.verifier_key_id)
        if (
            binding is None
            or binding.verifier_subject_id != result.verifier_subject_id
            or binding.controller_factors != result.controller_factors
            or binding.execution_context_factors
            != result.execution_context_factors
        ):
            raise VerificationInputError("arm result verifier is not profile-bound")
        if not (
            binding.valid_from <= result.created_at < binding.expires_at
            and profile.created_at <= result.created_at < profile.expires_at
        ):
            raise VerificationInputError("arm result verifier binding is not current")
        if not verify_payload(
            "verification-arm-result",
            result.model_dump(mode="json"),
            _decode_public_key(binding.verifier_public_key_b64url),
            version="0.3",
        ):
            raise VerificationInputError("arm result signature is invalid")


def compose_verification_decision_v03(
    *,
    profile: VerificationProfileV03,
    manifest: EvaluationScopeManifest,
    arm_results: Sequence[VerificationArmResultV03],
    request: DecisionDraftRequest,
) -> VerificationDecisionDraftV03:
    if not isinstance(profile, VerificationProfileV03):
        raise VerificationInputError("profile must be a v0.3 verification profile")
    if not isinstance(request, DecisionDraftRequest):
        raise VerificationInputError("request must be a DecisionDraftRequest")
    validate_verification_profile_v03(profile, manifest)
    results = tuple(arm_results)
    _validate_arm_results_v03(
        profile=profile,
        manifest=manifest,
        arm_results=results,
    )
    if not profile.created_at <= request.decided_at < profile.expires_at:
        raise VerificationInputError("verification decision is outside profile validity")

    positive = tuple(result for result in results if result.arm_kind == "positive")
    negative = tuple(result for result in results if result.arm_kind == "negative")
    if len(positive) != 1 or len(negative) != len(profile.negative_arms):
        raise VerificationInputError("arm result set is incomplete")

    missing_required = tuple(
        sorted(
            {
                target
                for result in results
                for target in (
                    set(manifest.required_target_ids)
                    - set(result.observed_required_target_ids)
                )
            }
        )
    )
    counts = tuple(result.observed_member_count for result in results)
    population_digests = {
        result.observed_population_digest for result in results
    }
    scope_reasons = {
        code
        for result in results
        for code in result.reason_codes
        if code.startswith("SCOPE_")
    }
    cross_arm_mismatch = len(set(counts)) != 1 or len(population_digests) != 1
    if cross_arm_mismatch:
        scope_reasons.add("SCOPE_CROSS_ARM_MISMATCH")
    if missing_required:
        scope_reasons.add("SCOPE_REQUIRED_TARGET_MISSING")
    population_mismatch = any(
        result.observed_member_count != manifest.member_count
        or result.observed_population_digest != manifest.population_digest
        for result in results
    )
    if population_mismatch:
        scope_reasons.add("SCOPE_POPULATION_DRIFT")
    if any(not result.scope_evidence_refs for result in results):
        scope_reasons.add("SCOPE_EVIDENCE_MISSING")

    reported_statuses = {result.scope_expectation_status for result in results}
    if (
        cross_arm_mismatch
        or missing_required
        or "indeterminate" in reported_statuses
        or "SCOPE_EVIDENCE_MISSING" in scope_reasons
    ):
        scope_status = "indeterminate"
    elif population_mismatch or "contradicted" in reported_statuses:
        scope_status = "contradicted"
    else:
        scope_status = "satisfied"

    independence = assess_independence(profile, results)
    if scope_status != "satisfied":
        decision = "UNKNOWN"
    elif positive[0].expectation_status == "contradicted" or any(
        result.expectation_status == "contradicted" for result in negative
    ):
        decision = "REFUTED"
    elif positive[0].expectation_status != "satisfied" or any(
        result.expectation_status != "satisfied" for result in negative
    ) or not independence.is_sufficient:
        decision = "UNKNOWN"
    else:
        decision = "VERIFIED"

    references: list[VerificationArmResultReference] = []
    for result in results:
        try:
            snapshot = evidence_snapshot_digest(
                tuple(
                    sorted(
                        (*result.evidence_refs, *result.scope_evidence_refs),
                        key=lambda ref: ref.path,
                    )
                )
            )
        except AcceptanceTransactionError as error:
            raise VerificationInputError(
                "arm result evidence is not canonical"
            ) from error
        references.append(
            VerificationArmResultReference(
                arm_id=result.arm_id,
                arm_result_id=result.arm_result_id,
                arm_result_digest=result.digest,
                evidence_snapshot_digest=snapshot,
            )
        )

    reason_codes = tuple(
        sorted(
            {
                *scope_reasons,
                *independence.reason_codes,
                *(code for result in results for code in result.reason_codes),
            }
        )
    )
    assessment = ScopeAssessment(
        declared_member_count=manifest.member_count,
        observed_member_counts=counts,
        population_digest=manifest.population_digest,
        required_target_count=len(manifest.required_target_ids),
        missing_required_target_ids=missing_required,
        scope_status=scope_status,
    )
    return VerificationDecisionDraftV03(
        decision_id=request.decision_id,
        work_order_digest=profile.work_order_digest,
        subject_claim_digest=profile.subject_claim_digest,
        profile_id=profile.profile_id,
        profile_digest=profile.digest,
        arm_results=tuple(
            reference.model_dump(mode="json") for reference in references
        ),
        assurance_level=profile.assurance_level,
        decision=decision,
        independence=independence.model_dump(mode="json"),
        reason_codes=reason_codes,
        supersedes_decision_id=None,
        supersedes_decision_digest=None,
        causal_parent_receipt_ids=tuple(
            sorted(
                {
                    receipt_id
                    for result in results
                    for receipt_id in result.action_receipt_ids
                }
            )
        ),
        causal_parent_decision_ids=(),
        decided_at=request.model_dump(mode="json")["decided_at"],
        nonce=request.nonce,
        scope_manifest_digest=manifest.digest,
        scope_assessment=assessment.model_dump(mode="json"),
    )


_T = TypeVar("_T")
_Fault = Literal[
    "before_commit",
    "commit_ack_loss",
    "readback_failure",
    "cleanup_failure",
]


def _canonical_model_blob(value) -> bytes:
    return rfc8785.dumps(value.model_dump(mode="json"))


def _load_canonical_model(model_type: type[_T], raw: object, label: str) -> _T:
    if not isinstance(raw, (bytes, str)):
        raise VerificationTransactionError(f"{label} canonical row has the wrong type")
    try:
        parsed = model_type.model_validate_json(raw)
    except Exception as error:
        raise VerificationTransactionError(f"{label} canonical row is invalid") from error
    encoded = raw.encode("utf-8") if isinstance(raw, str) else raw
    if _canonical_model_blob(parsed) != encoded:
        raise VerificationTransactionError(f"{label} canonical row is not canonical")
    return parsed


def external_anchor_digest(anchor: PolicyAnchor | CommitmentAnchor) -> str:
    kind = "policy" if isinstance(anchor, PolicyAnchor) else "commitment"
    if not isinstance(anchor, (PolicyAnchor, CommitmentAnchor)):
        raise VerificationInputError("external anchor type is invalid")
    return hashlib.sha256(
        rfc8785.dumps(
            {
                "domain": f"openworkproof/external-anchor/{kind}/v0.2",
                "anchor": anchor.model_dump(mode="json"),
            }
        )
    ).hexdigest()


def _manager_binding(work_order: WorkOrder):
    if not verify_work_order_identity_bindings(work_order):
        raise VerificationTransactionError("WorkOrder authority is invalid")
    try:
        return next(
            binding for binding in work_order.key_bindings if binding.role == "Manager"
        )
    except StopIteration as error:
        raise VerificationTransactionError("WorkOrder Manager binding is missing") from error


def _validate_profile_authority(
    *,
    work_order: WorkOrder,
    claim: SubjectClaim,
    profile: VerificationProfileV02,
) -> None:
    manager = _manager_binding(work_order)
    manager_key = decode_and_verify_key_binding(manager)
    if (
        claim.work_order_digest != work_order.digest
        or profile.work_order_digest != work_order.digest
        or profile.subject_claim_digest != claim.digest
    ):
        raise VerificationTransactionError("profile authority digests do not match")
    if claim.customer_acceptor_key_id not in work_order.acceptor_key_ids:
        raise VerificationTransactionError("claim Acceptor is not WorkOrder-bound")
    if claim.signer_key_id != manager.key_id or not verify_payload(
        "subject-claim", claim.model_dump(mode="json"), manager_key
    ):
        raise VerificationTransactionError("subject claim Manager signature is invalid")
    if profile.signer_key_id != manager.key_id or not verify_payload(
        "verification-profile", profile.model_dump(mode="json"), manager_key
    ):
        raise VerificationTransactionError("profile Manager signature is invalid")
    if not (
        claim.created_at <= profile.created_at < profile.expires_at
        and profile.expires_at <= work_order.deadline
    ):
        raise VerificationTransactionError("profile validity is outside the WorkOrder")


def _cleanup_transaction(
    connection: sqlite3.Connection | None,
    lock_descriptor: int | None,
) -> tuple[Exception, ...]:
    errors: list[Exception] = []
    close_error = evidence._best_effort_close(connection)
    if close_error is not None:
        errors.append(close_error)
    _, release_errors = evidence._release_target_lock(lock_descriptor)
    errors.extend(release_errors)
    return tuple(errors)


def _commit_with_readback(
    path: Path,
    *,
    stage: Callable[[sqlite3.Connection], _T],
    readback: Callable[[_T], bool],
    fault: _Fault | None,
) -> _T:
    if fault not in {None, "before_commit", "commit_ack_loss", "readback_failure", "cleanup_failure"}:
        raise VerificationTransactionError("unknown transaction fault")
    if not path.is_file():
        raise VerificationTransactionError("verification ledger is unavailable")
    lock_descriptor: int | None = None
    connection: sqlite3.Connection | None = None
    committed = False
    result: _T | None = None
    try:
        lock_descriptor, _ = evidence._borrow_or_acquire_target_lock(path, None)
        connection = evidence.connect_ledger(path)
        connection.execute("BEGIN IMMEDIATE")
        result = stage(connection)
        if fault == "before_commit":
            raise VerificationTransactionError("injected fault before commit")
        connection.execute("COMMIT")
        committed = True
        if fault == "commit_ack_loss":
            raise OSError("injected commit acknowledgement loss")
        if fault == "readback_failure":
            raise VerificationCommitIndeterminateError(
                "verification readback was deliberately unavailable"
            )
        if not readback(result):
            raise VerificationCommitIndeterminateError(
                "verification readback could not confirm the exact commit"
            )
    except Exception as error:
        evidence._best_effort_rollback(connection)
        cleanup_errors = _cleanup_transaction(connection, lock_descriptor)
        if isinstance(error, VerificationCommittedError):
            raise error
        if isinstance(error, VerificationCommitIndeterminateError):
            raise error
        if committed and result is not None:
            try:
                confirmed = readback(result)
            except Exception as readback_error:
                raise VerificationCommitIndeterminateError(
                    "verification commit outcome is indeterminate"
                ) from readback_error
            if confirmed:
                raise VerificationCommittedError(
                    "verification committed but acknowledgement was lost",
                    result,
                ) from error
            raise VerificationCommitIndeterminateError(
                "verification commit outcome is indeterminate"
            ) from error
        if isinstance(error, VerificationTransactionError) and not cleanup_errors:
            raise error
        raise VerificationTransactionError("verification transaction failed") from error
    assert result is not None
    cleanup_errors = list(_cleanup_transaction(connection, lock_descriptor))
    if fault == "cleanup_failure":
        cleanup_errors.append(OSError("injected cleanup failure"))
    if cleanup_errors:
        raise VerificationCommittedError(
            "verification committed but cleanup failed", result
        ) from cleanup_errors[0]
    return result


def _exact_profile_readback(
    path: Path,
    *,
    claim: SubjectClaim,
    profile: VerificationProfileV02,
    anchors: tuple[PolicyAnchor | CommitmentAnchor, ...],
) -> bool:
    connection = evidence.connect_ledger(path)
    try:
        claim_row = connection.execute(
            "SELECT claim_json FROM subject_claims WHERE claim_id = ?",
            (claim.claim_id,),
        ).fetchone()
        profile_row = connection.execute(
            "SELECT subject_claim_id, profile_json FROM verification_profiles_v02 WHERE profile_id = ?",
            (profile.profile_id,),
        ).fetchone()
        if claim_row != (_canonical_model_blob(claim),) or profile_row != (
            claim.claim_id,
            _canonical_model_blob(profile),
        ):
            return False
        for anchor in anchors:
            kind = "policy" if isinstance(anchor, PolicyAnchor) else "commitment"
            row = connection.execute(
                "SELECT anchor_kind, anchor_json FROM external_anchors WHERE anchor_digest = ?",
                (external_anchor_digest(anchor),),
            ).fetchone()
            if row != (kind, _canonical_model_blob(anchor)):
                return False
        return True
    finally:
        connection.close()


def _assert_nonce_unused(
    connection: sqlite3.Connection,
    nonce: str,
    *,
    allowed: tuple[tuple[str, str], ...] = (),
) -> None:
    allowed_set = set(allowed)
    for table, identifier_column, json_column in (
        ("receipts", "receipt_id", "receipt_json"),
        ("subject_claims", "claim_id", "claim_json"),
        ("verification_profiles_v02", "profile_id", "profile_json"),
        ("verification_decisions", "decision_id", "decision_json"),
        ("acceptance_transitions", "transition_id", "transition_json"),
    ):
        for identifier, raw in connection.execute(
            f"SELECT {identifier_column}, {json_column} FROM {table}"
        ):
            try:
                payload = json.loads(raw)
            except (TypeError, ValueError) as error:
                raise VerificationTransactionError(
                    "protocol nonce source row is invalid"
                ) from error
            if payload.get("nonce") == nonce and (table, identifier) not in allowed_set:
                raise VerificationTransactionError("protocol nonce is already used")


def commit_verification_profile(
    ledger_path: Path,
    claim: SubjectClaim,
    profile: VerificationProfileV02,
    *,
    policy_anchor: PolicyAnchor | None = None,
    commitment_anchor: CommitmentAnchor | None = None,
    fault: _Fault | None = None,
) -> VerificationProfileV02:
    path = Path(ledger_path)
    try:
        parsed_claim = SubjectClaim.model_validate(claim.model_dump(mode="json"))
        parsed_profile = VerificationProfileV02.model_validate(
            profile.model_dump(mode="json")
        )
    except Exception as error:
        raise VerificationTransactionError("profile inputs are malformed") from error
    anchors = tuple(
        anchor for anchor in (policy_anchor, commitment_anchor) if anchor is not None
    )

    def stage(connection: sqlite3.Connection) -> VerificationProfileV02:
        work_order = evidence.load_authoritative_work_order(connection)
        _validate_profile_authority(
            work_order=work_order, claim=parsed_claim, profile=parsed_profile
        )
        if (parsed_profile.policy_anchor_digest is None) != (policy_anchor is None):
            raise VerificationTransactionError("policy anchor binding is incomplete")
        if policy_anchor is not None and parsed_profile.policy_anchor_digest != external_anchor_digest(policy_anchor):
            raise VerificationTransactionError("policy anchor digest mismatch")
        if (parsed_profile.commitment_anchor_digest is None) != (commitment_anchor is None):
            raise VerificationTransactionError("commitment anchor binding is incomplete")
        if commitment_anchor is not None:
            if (
                parsed_profile.commitment_anchor_digest
                != external_anchor_digest(commitment_anchor)
                or commitment_anchor.work_order_digest != work_order.digest
                or commitment_anchor.subject_claim_digest != parsed_claim.digest
            ):
                raise VerificationTransactionError("commitment anchor binding mismatch")
            if (
                parsed_profile.delivery_trust_level in {2, 3}
                and (
                    commitment_anchor.anchor_provider != "customer_signed_document"
                    or not commitment_anchor.anchor_reference.startswith("customer://")
                )
            ):
                raise VerificationTransactionError(
                    "level 2/3 requires a customer-domain commitment"
                )
        existing = connection.execute(
            "SELECT subject_claim_id, profile_json FROM verification_profiles_v02 WHERE profile_id = ?",
            (parsed_profile.profile_id,),
        ).fetchone()
        if existing is not None:
            if existing == (parsed_claim.claim_id, _canonical_model_blob(parsed_profile)):
                raise VerificationCommittedError(
                    "the exact verification profile is already committed",
                    parsed_profile,
                )
            raise VerificationTransactionError("verification profile id is already used")
        claim_row = connection.execute(
            "SELECT claim_json FROM subject_claims WHERE claim_id = ?",
            (parsed_claim.claim_id,),
        ).fetchone()
        if claim_row is not None and claim_row != (_canonical_model_blob(parsed_claim),):
            raise VerificationTransactionError("subject claim id is already used")
        if parsed_claim.nonce == parsed_profile.nonce:
            raise VerificationTransactionError(
                "claim and profile must use distinct protocol nonces"
            )
        allowed_claim = (
            ()
            if claim_row is None
            else (("subject_claims", parsed_claim.claim_id),)
        )
        _assert_nonce_unused(
            connection,
            parsed_claim.nonce,
            allowed=allowed_claim,
        )
        _assert_nonce_unused(connection, parsed_profile.nonce)
        if claim_row is None:
            connection.execute(
                "INSERT INTO subject_claims (claim_id, claim_json) VALUES (?, ?)",
                (parsed_claim.claim_id, _canonical_model_blob(parsed_claim)),
            )
        for anchor in anchors:
            kind = "policy" if isinstance(anchor, PolicyAnchor) else "commitment"
            connection.execute(
                "INSERT OR IGNORE INTO external_anchors (anchor_digest, anchor_kind, anchor_json) VALUES (?, ?, ?)",
                (external_anchor_digest(anchor), kind, _canonical_model_blob(anchor)),
            )
            stored = connection.execute(
                "SELECT anchor_kind, anchor_json FROM external_anchors WHERE anchor_digest = ?",
                (external_anchor_digest(anchor),),
            ).fetchone()
            if stored != (kind, _canonical_model_blob(anchor)):
                raise VerificationTransactionError("external anchor digest is already used")
        connection.execute(
            "INSERT INTO verification_profiles_v02 (profile_id, subject_claim_id, profile_json) VALUES (?, ?, ?)",
            (
                parsed_profile.profile_id,
                parsed_claim.claim_id,
                _canonical_model_blob(parsed_profile),
            ),
        )
        return parsed_profile

    return _commit_with_readback(
        path,
        stage=stage,
        readback=lambda _: _exact_profile_readback(
            path, claim=parsed_claim, profile=parsed_profile, anchors=anchors
        ),
        fault=fault,
    )


def _load_profile_context(
    connection: sqlite3.Connection,
    *,
    profile_digest: str,
) -> tuple[WorkOrder, SubjectClaim, VerificationProfileV02]:
    work_order = evidence.load_authoritative_work_order(connection)
    matches = []
    for profile_id, claim_id, raw in connection.execute(
        "SELECT profile_id, subject_claim_id, profile_json FROM verification_profiles_v02 ORDER BY profile_id"
    ):
        profile = _load_canonical_model(
            VerificationProfileV02, raw, "verification profile"
        )
        if profile.profile_id != profile_id:
            raise VerificationTransactionError("profile index does not match canonical row")
        if profile.digest == profile_digest:
            matches.append((claim_id, profile))
    if len(matches) != 1:
        raise VerificationTransactionError("verification profile is unavailable")
    claim_id, profile = matches[0]
    row = connection.execute(
        "SELECT claim_json FROM subject_claims WHERE claim_id = ?", (claim_id,)
    ).fetchone()
    if row is None:
        raise VerificationTransactionError("subject claim row is unavailable")
    claim = _load_canonical_model(SubjectClaim, row[0], "subject claim")
    if claim.claim_id != claim_id:
        raise VerificationTransactionError("claim index does not match canonical row")
    _validate_profile_authority(work_order=work_order, claim=claim, profile=profile)
    return work_order, claim, profile


def _validate_causal_receipts(
    connection: sqlite3.Connection,
    *,
    work_order: WorkOrder,
    receipt_ids: tuple[str, ...],
) -> None:
    sidecar = next(
        binding for binding in work_order.key_bindings if binding.role == "Sidecar"
    )
    sidecar_key = decode_and_verify_key_binding(sidecar)
    for receipt_id in receipt_ids:
        row = connection.execute(
            "SELECT receipt_json FROM receipts WHERE receipt_id = ?", (receipt_id,)
        ).fetchone()
        if row is None:
            raise VerificationTransactionError("arm result causal parent is missing")
        try:
            receipt = evidence.ACTION_RECEIPT_ADAPTER.validate_json(row[0])
        except Exception as error:
            raise VerificationTransactionError("causal receipt canonical row is invalid") from error
        encoded = row[0].encode("utf-8") if isinstance(row[0], str) else row[0]
        if (
            receipt.receipt_id != receipt_id
            or receipt.work_order_digest != work_order.digest
            or rfc8785.dumps(receipt.model_dump(mode="json")) != encoded
            or not verify_payload(
                "action-receipt", receipt.model_dump(mode="json"), sidecar_key
            )
        ):
            raise VerificationTransactionError("causal receipt validation failed")


def _exact_arm_result_readback(path: Path, result: VerificationArmResult) -> bool:
    connection = evidence.connect_ledger(path)
    try:
        row = connection.execute(
            "SELECT arm_result_json FROM verification_arm_results WHERE arm_result_id = ?",
            (result.arm_result_id,),
        ).fetchone()
        return row == (_canonical_model_blob(result),)
    finally:
        connection.close()


def commit_verification_arm_result(
    ledger_path: Path,
    result: VerificationArmResult,
    *,
    fault: _Fault | None = None,
) -> VerificationArmResult:
    path = Path(ledger_path)
    try:
        parsed = VerificationArmResult.model_validate(result.model_dump(mode="json"))
    except Exception as error:
        raise VerificationTransactionError("arm result input is malformed") from error

    def stage(connection: sqlite3.Connection) -> VerificationArmResult:
        work_order, _, profile = _load_profile_context(
            connection, profile_digest=parsed.profile_digest
        )
        try:
            _validate_single_arm_result(profile=profile, result=parsed)
        except VerificationInputError as error:
            raise VerificationTransactionError(str(error)) from error
        _validate_causal_receipts(
            connection,
            work_order=work_order,
            receipt_ids=parsed.action_receipt_ids,
        )
        if sum(ref.size_bytes for ref in parsed.evidence_refs) > profile.max_evidence_bytes:
            raise VerificationTransactionError("arm result evidence limit exceeded")
        arm = (
            profile.positive_arm
            if parsed.arm_id == profile.positive_arm.arm_id
            else next(item for item in profile.negative_arms if item.arm_id == parsed.arm_id)
        )
        allowed_paths = set(arm.result_artifact_paths)
        if any(ref.path not in allowed_paths for ref in parsed.evidence_refs):
            raise VerificationTransactionError("arm result evidence path is outside profile")
        existing = connection.execute(
            "SELECT profile_id, arm_id, arm_result_json FROM verification_arm_results WHERE arm_result_id = ?",
            (parsed.arm_result_id,),
        ).fetchone()
        expected = (profile.profile_id, parsed.arm_id, _canonical_model_blob(parsed))
        if existing is not None:
            if existing == expected:
                raise VerificationCommittedError(
                    "the exact arm result is already committed", parsed
                )
            raise VerificationTransactionError("arm result id is already used")
        connection.execute(
            "INSERT INTO verification_arm_results (arm_result_id, profile_id, arm_id, arm_result_json) VALUES (?, ?, ?, ?)",
            (parsed.arm_result_id, *expected),
        )
        return parsed

    return _commit_with_readback(
        path,
        stage=stage,
        readback=lambda _: _exact_arm_result_readback(path, parsed),
        fault=fault,
    )


def _load_arm_results(
    connection: sqlite3.Connection,
    *,
    profile: VerificationProfileV02,
    selected_ids: tuple[str, ...] | None = None,
) -> tuple[VerificationArmResult, ...]:
    values = []
    for result_id, profile_id, arm_id, raw in connection.execute(
        "SELECT arm_result_id, profile_id, arm_id, arm_result_json FROM verification_arm_results WHERE profile_id = ? ORDER BY arm_result_id",
        (profile.profile_id,),
    ):
        result = _load_canonical_model(
            VerificationArmResult, raw, "verification arm result"
        )
        if (
            result.arm_result_id != result_id
            or result.arm_id != arm_id
            or profile_id != profile.profile_id
        ):
            raise VerificationTransactionError("arm result index does not match canonical row")
        try:
            _validate_single_arm_result(profile=profile, result=result)
        except VerificationInputError as error:
            raise VerificationTransactionError(str(error)) from error
        values.append(result)
    if selected_ids is not None:
        selected = [item for item in values if item.arm_result_id in set(selected_ids)]
        if len(selected) != len(selected_ids):
            raise VerificationTransactionError("decision arm result is unavailable")
        return tuple(sorted(selected, key=lambda item: item.arm_result_id))
    latest = {}
    for result in values:
        key = (result.created_at, result.arm_result_id)
        current = latest.get(result.arm_id)
        if current is None or key > (current.created_at, current.arm_result_id):
            latest[result.arm_id] = result
    return tuple(sorted(latest.values(), key=lambda item: item.arm_result_id))


def _load_current_decision(
    connection: sqlite3.Connection,
    *,
    profile: VerificationProfileV02,
) -> VerificationDecision | None:
    previous = None
    for decision_id, predecessor_id, raw in connection.execute(
        "SELECT decision_id, predecessor_id, decision_json FROM verification_decisions ORDER BY rowid"
    ):
        decision = _load_canonical_model(
            VerificationDecision, raw, "verification decision"
        )
        if decision.decision_id != decision_id or predecessor_id != (
            None if previous is None else previous.decision_id
        ):
            raise VerificationTransactionError("verification decision chain is invalid")
        try:
            validate_verification_decision(profile=profile, decision=decision)
        except VerificationInputError as error:
            raise VerificationTransactionError(str(error)) from error
        parents = tuple(
            row[0]
            for row in connection.execute(
                "SELECT arm_result_id FROM verification_decision_parents WHERE decision_id = ? ORDER BY ordinal",
                (decision_id,),
            )
        )
        if parents != tuple(item.arm_result_id for item in decision.arm_results):
            raise VerificationTransactionError("verification decision parents are invalid")
        previous = decision
    return previous


def _load_single_profile(
    connection: sqlite3.Connection,
) -> tuple[WorkOrder, SubjectClaim, VerificationProfileV02]:
    rows = tuple(connection.execute("SELECT profile_json FROM verification_profiles_v02"))
    if len(rows) != 1:
        raise VerificationTransactionError("exactly one verification profile is required")
    profile = _load_canonical_model(
        VerificationProfileV02, rows[0][0], "verification profile"
    )
    return _load_profile_context(connection, profile_digest=profile.digest)


def prepare_verification_decision(
    ledger_path: Path,
    request: DecisionDraftRequest,
) -> VerificationDecisionDraft:
    path = Path(ledger_path)
    if not path.is_file():
        raise VerificationTransactionError("verification ledger is unavailable")
    lock_descriptor: int | None = None
    connection: sqlite3.Connection | None = None
    try:
        parsed_request = DecisionDraftRequest.model_validate(
            request.model_dump(mode="json")
        )
        lock_descriptor, _ = evidence._borrow_or_acquire_target_lock(path, None)
        connection = evidence.connect_ledger(path)
        connection.execute("BEGIN")
        _, claim, profile = _load_single_profile(connection)
        results = _load_arm_results(connection, profile=profile)
        previous = _load_current_decision(connection, profile=profile)
        draft = compose_verification_decision(
            profile=profile,
            subject_claim=claim,
            arm_results=results,
            previous_decision=previous,
            decision_id=parsed_request.decision_id,
            decided_at=parsed_request.decided_at,
            nonce=parsed_request.nonce,
        )
        connection.execute("ROLLBACK")
        return draft
    except VerificationTransactionError:
        evidence._best_effort_rollback(connection)
        raise
    except Exception as error:
        evidence._best_effort_rollback(connection)
        raise VerificationTransactionError(
            "verification decision preparation failed"
        ) from error
    finally:
        cleanup = _cleanup_transaction(connection, lock_descriptor)
        if cleanup:
            raise VerificationCommitIndeterminateError(
                "verification decision preparation cleanup failed"
            ) from cleanup[0]


def _exact_decision_readback(path: Path, decision: VerificationDecision) -> bool:
    connection = evidence.connect_ledger(path)
    try:
        row = connection.execute(
            "SELECT predecessor_id, decision_json FROM verification_decisions WHERE decision_id = ?",
            (decision.decision_id,),
        ).fetchone()
        expected = (
            decision.supersedes_decision_id,
            _canonical_model_blob(decision),
        )
        if row != expected:
            return False
        parents = tuple(
            connection.execute(
                "SELECT ordinal, arm_result_id FROM verification_decision_parents WHERE decision_id = ? ORDER BY ordinal",
                (decision.decision_id,),
            )
        )
        return parents == tuple(
            (ordinal, reference.arm_result_id)
            for ordinal, reference in enumerate(decision.arm_results)
        )
    finally:
        connection.close()


def commit_verification_decision(
    ledger_path: Path,
    decision: VerificationDecision,
    *,
    fault: _Fault | None = None,
) -> VerificationDecision:
    path = Path(ledger_path)
    try:
        parsed = VerificationDecision.model_validate(decision.model_dump(mode="json"))
    except Exception as error:
        raise VerificationTransactionError("verification decision is malformed") from error

    def stage(connection: sqlite3.Connection) -> VerificationDecision:
        _, claim, profile = _load_profile_context(
            connection, profile_digest=parsed.profile_digest
        )
        current = _load_current_decision(connection, profile=profile)
        if current is not None and current.decision_id == parsed.decision_id:
            if current == parsed and _exact_decision_readback(path, parsed):
                raise VerificationCommittedError(
                    "the exact verification decision is already committed", parsed
                )
            raise VerificationTransactionError(
                "verification decision id is already used"
            )
        _assert_nonce_unused(connection, parsed.nonce)
        selected_ids = tuple(item.arm_result_id for item in parsed.arm_results)
        results = _load_arm_results(
            connection, profile=profile, selected_ids=selected_ids
        )
        latest = _load_arm_results(connection, profile=profile)
        if tuple(item.arm_result_id for item in results) != tuple(
            item.arm_result_id for item in latest
        ):
            raise VerificationTransactionError("verification decision uses stale arm results")
        try:
            draft = compose_verification_decision(
                profile=profile,
                subject_claim=claim,
                arm_results=results,
                previous_decision=current,
                decision_id=parsed.decision_id,
                decided_at=parsed.decided_at,
                nonce=parsed.nonce,
            )
            validate_verification_decision(profile=profile, decision=parsed)
        except VerificationInputError as error:
            raise VerificationTransactionError(str(error)) from error
        if verification_decision_signing_bytes(draft) != verification_decision_signing_bytes(parsed):
            raise VerificationTransactionError("verification decision draft mismatch")
        existing = connection.execute(
            "SELECT predecessor_id, decision_json FROM verification_decisions WHERE decision_id = ?",
            (parsed.decision_id,),
        ).fetchone()
        expected = (parsed.supersedes_decision_id, _canonical_model_blob(parsed))
        if existing is not None:
            if existing == expected and _exact_decision_readback(path, parsed):
                raise VerificationCommittedError(
                    "the exact verification decision is already committed", parsed
                )
            raise VerificationTransactionError("verification decision id is already used")
        connection.execute(
            "INSERT INTO verification_decisions (decision_id, predecessor_id, decision_json) VALUES (?, ?, ?)",
            (parsed.decision_id, parsed.supersedes_decision_id, _canonical_model_blob(parsed)),
        )
        for ordinal, reference in enumerate(parsed.arm_results):
            connection.execute(
                "INSERT INTO verification_decision_parents (decision_id, ordinal, arm_result_id) VALUES (?, ?, ?)",
                (parsed.decision_id, ordinal, reference.arm_result_id),
            )
        return parsed

    return _commit_with_readback(
        path,
        stage=stage,
        readback=lambda _: _exact_decision_readback(path, parsed),
        fault=fault,
    )
