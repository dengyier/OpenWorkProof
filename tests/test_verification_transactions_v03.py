from __future__ import annotations

import base64
import copy
import hashlib
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Literal

import pytest
import rfc8785

import openworkproof.evidence as evidence
from openworkproof.models import (
    DecisionDraftRequest,
    EvaluationScopeManifest,
    VerificationArmResultV03,
    VerificationDecisionV03,
    VerificationProfileV02,
    VerificationProfileV03,
)
from openworkproof.scope import ObservedScope, requirement_digest
from openworkproof.signing import key_id, sign_payload
from openworkproof.verification import (
    VerificationCommittedError,
    VerificationInputError,
    VerificationTransactionError,
    commit_evaluation_scope,
    commit_verification_arm_result_v03,
    commit_verification_decision_v03,
    commit_verification_profile_v03,
    compose_verification_decision_v03,
    prepare_verification_decision_v03,
    validate_verification_profile_v03,
    verification_decision_signing_bytes_v03,
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
    action_receipt_id: str | None = None,
    evidence_ref: dict[str, object] | None = None,
    scope_evidence_ref: dict[str, object] | None = None,
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
        "action_receipt_ids": [action_receipt_id or result_id],
        "evidence_refs": [
            evidence_ref
            or {
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
            scope_evidence_ref
            or {
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


def _transaction_digest(domain: str, payload: object) -> str:
    return hashlib.sha256(
        rfc8785.dumps(
            {"domain": f"openworkproof/{domain}/v0.3", "payload": payload}
        )
    ).hexdigest()


def _transaction_manifest(
    payload,
    *,
    work_order,
    claim,
    manager_key,
) -> EvaluationScopeManifest:
    raw = copy.deepcopy(payload)
    raw.update(
        {
            "work_order_digest": work_order.digest,
            "subject_claim_digest": claim.digest,
            "source_revision": claim.source_revision,
        }
    )
    for member in raw["members"]:
        member["source_revision"] = claim.source_revision
    source_id = next(
        item["member_id"]
        for item in raw["members"]
        if item["member_kind"] == "source_file"
    )
    test_id = next(
        item["member_id"]
        for item in raw["members"]
        if item["member_kind"] == "test_case"
    )
    raw["requirement_bindings"] = sorted(
        [
            *(
                {
                    "requirement_kind": "acceptance_condition",
                    "requirement_digest": requirement_digest(
                        "acceptance_condition", value
                    ),
                    "member_ids": [test_id],
                }
                for value in claim.acceptance_conditions
            ),
            *(
                {
                    "requirement_kind": "required_artifact",
                    "requirement_digest": requirement_digest(
                        "required_artifact", value
                    ),
                    "member_ids": [source_id],
                }
                for value in claim.required_artifacts
            ),
        ],
        key=lambda item: (
            item["requirement_kind"].encode("utf-8"),
            item["requirement_digest"],
        ),
    )
    raw["required_target_ids"] = sorted(
        {
            member_id
            for binding in raw["requirement_bindings"]
            for member_id in binding["member_ids"]
        }
    )
    raw["scope_id"] = "0" * 64
    raw["scope_id"] = _transaction_digest(
        "evaluation-scope",
        {key: value for key, value in raw.items() if key != "scope_id"},
    )
    return EvaluationScopeManifest.model_validate(
        sign_payload(
            "evaluation-scope", raw, manager_key, version="0.3"
        )
    )


def _transaction_profile(
    profile,
    *,
    manifest,
    manager_key,
) -> VerificationProfileV03:
    raw = profile.model_dump(
        mode="json",
        exclude={"digest", "signature_alg", "signer_key_id", "signature"},
    )
    raw.update(
        {
            "work_order_digest": manifest.work_order_digest,
            "subject_claim_digest": manifest.subject_claim_digest,
            "evaluation_scope_id": manifest.scope_id,
            "evaluation_scope_digest": manifest.digest,
        }
    )
    for arm in (raw["positive_arm"], *raw["negative_arms"]):
        arm.update(
            {
                "source_commit": manifest.source_revision,
                "candidate_commit": manifest.candidate_commit,
                "workspace_manifest_digest": manifest.workspace_manifest_digest,
            }
        )
    return VerificationProfileV03.model_validate(
        sign_payload(
            "verification-profile", raw, manager_key, version="0.3"
        )
    )


def _insert_transaction_receipt(path: Path, receipt) -> None:
    connection = evidence.connect_ledger(path)
    try:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            """
            INSERT INTO receipts (
                receipt_id, work_order_digest, nonce, sequence,
                previous_digest, receipt_json
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                receipt.receipt_id,
                receipt.work_order_digest,
                receipt.nonce,
                receipt.sequence,
                receipt.previous_receipt_digest,
                evidence._canonical_json(receipt.model_dump(mode="json")),
            ),
        )
        connection.execute("COMMIT")
    finally:
        connection.close()


def _write_json_evidence(root: Path, relative: str, value: object) -> dict[str, object]:
    raw = rfc8785.dumps(value)
    target = root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(raw)
    return {
        "path": relative,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "media_type": "application/json",
        "size_bytes": len(raw),
    }


@pytest.fixture
def v03_transaction_case(
    tmp_path,
    signed_work_order,
    signed_subject_claim,
    evaluation_scope_payload_v03,
    verification_profile_v03,
    ephemeral_role_keys,
    sidecar_receipt_factory,
):
    ledger = tmp_path / "verification-v03.sqlite3"
    evidence.initialize_ledger(ledger, signed_work_order)
    manifest = _transaction_manifest(
        evaluation_scope_payload_v03,
        work_order=signed_work_order,
        claim=signed_subject_claim,
        manager_key=ephemeral_role_keys["Manager"][0],
    )
    profile = _transaction_profile(
        verification_profile_v03,
        manifest=manifest,
        manager_key=ephemeral_role_keys["Manager"][0],
    )
    commit_evaluation_scope(ledger, signed_subject_claim, manifest)
    commit_verification_profile_v03(ledger, profile)
    receipt = sidecar_receipt_factory(
        state_before="locally_verified",
        state_after="evidence_incomplete",
        event_type="system_event",
        event_name="proof_composed",
        sequence=1,
    )
    _insert_transaction_receipt(ledger, receipt)
    observed = ObservedScope(
        member_ids=tuple(member.member_id for member in manifest.members),
        member_count=manifest.member_count,
        population_digest=manifest.population_digest,
        required_target_ids=manifest.required_target_ids,
        source_revision=manifest.source_revision,
        workspace_manifest_digest=manifest.workspace_manifest_digest,
        selector_engine_digests=tuple(
            sorted(rule.selector_engine_digest for rule in manifest.selector_rules)
        ),
        evidence_complete=True,
    )
    results = []
    for kind in ("positive", "negative"):
        result_ref = _write_json_evidence(
            tmp_path, f"results/{kind}.json", {"arm": kind, "passed": True}
        )
        scope_ref = _write_json_evidence(
            tmp_path,
            f"scope/{kind}.json",
            observed.model_dump(mode="json"),
        )
        result = _arm_result(
            profile=profile,
            manifest=manifest,
            ephemeral_role_keys=ephemeral_role_keys,
            arm_kind=kind,
            scope_status="satisfied",
            action_receipt_id=receipt.receipt_id,
            evidence_ref=result_ref,
            scope_evidence_ref=scope_ref,
        )
        results.append(result)
    return {
        "ledger": ledger,
        "manifest": manifest,
        "profile": profile,
        "results": tuple(results),
        "keys": ephemeral_role_keys,
        "tmp_path": tmp_path,
    }


def _sign_decision_draft_v03(case, draft) -> VerificationDecisionV03:
    encoded = verification_decision_signing_bytes_v03(draft)
    binding = case["profile"].verifier_bindings[0]
    private_key = case["keys"]["Verifier"][0]
    return VerificationDecisionV03.model_validate(
        {
            "schema_version": "openworkproof-verification-decision/0.3",
            **draft.model_dump(mode="json"),
            "digest": hashlib.sha256(encoded).hexdigest(),
            "verifier_signatures": [
                {
                    "verifier_subject_id": binding.verifier_subject_id,
                    "verifier_key_id": key_id(private_key.public_key()),
                    "signature_alg": "Ed25519",
                    "signature": base64.urlsafe_b64encode(
                        private_key.sign(encoded)
                    ).decode("ascii").rstrip("="),
                }
            ],
        }
    )


def _signed_decision_v03(case, request) -> VerificationDecisionV03:
    return _sign_decision_draft_v03(
        case, prepare_verification_decision_v03(case["ledger"], request)
    )


def _resign_arm_result_v03(case, result, **changes) -> VerificationArmResultV03:
    raw = result.model_dump(
        mode="json",
        exclude={"digest", "signature_alg", "signer_key_id", "signature"},
    )
    raw.update(changes)
    return VerificationArmResultV03.model_validate(
        sign_payload(
            "verification-arm-result",
            raw,
            case["keys"]["Verifier"][0],
            version="0.3",
        )
    )


def test_v03_transactions_commit_scope_bound_verified_chain(
    v03_transaction_case,
) -> None:
    case = v03_transaction_case
    for result in case["results"]:
        assert commit_verification_arm_result_v03(case["ledger"], result) == result
    request = DecisionDraftRequest(
        decision_id="c" * 64,
        decided_at="2026-01-01T00:20:00Z",
        nonce="d" * 64,
    )
    decision = _signed_decision_v03(case, request)
    assert decision.decision == "VERIFIED"
    assert commit_verification_decision_v03(case["ledger"], decision) == decision


def test_v03_arm_recomputes_scope_evidence_and_fails_closed(
    v03_transaction_case,
) -> None:
    case = v03_transaction_case
    result = case["results"][0]
    (case["tmp_path"] / result.scope_evidence_refs[0].path).write_text(
        "{}", encoding="utf-8"
    )
    with pytest.raises(VerificationTransactionError, match="evidence"):
        commit_verification_arm_result_v03(case["ledger"], result)


def test_v03_arm_rejects_resigned_wrong_manifest_and_n_minus_one(
    v03_transaction_case,
) -> None:
    case = v03_transaction_case
    result = case["results"][0]
    wrong_manifest = _resign_arm_result_v03(
        case, result, scope_manifest_digest="f" * 64
    )
    with pytest.raises(VerificationTransactionError, match="binding"):
        commit_verification_arm_result_v03(case["ledger"], wrong_manifest)

    manifest = case["manifest"]
    retained = manifest.members[:-1]
    observed = ObservedScope(
        member_ids=tuple(member.member_id for member in retained),
        member_count=len(retained),
        population_digest=manifest.population_digest,
        required_target_ids=tuple(
            target
            for target in manifest.required_target_ids
            if target in {member.member_id for member in retained}
        ),
        source_revision=manifest.source_revision,
        workspace_manifest_digest=manifest.workspace_manifest_digest,
        selector_engine_digests=tuple(
            sorted(rule.selector_engine_digest for rule in manifest.selector_rules)
        ),
        evidence_complete=True,
    )
    scope_ref = _write_json_evidence(
        case["tmp_path"],
        result.scope_evidence_refs[0].path,
        observed.model_dump(mode="json"),
    )
    n_minus_one = _resign_arm_result_v03(
        case,
        result,
        observed_member_count=observed.member_count,
        observed_population_digest=observed.population_digest,
        observed_required_target_ids=list(observed.required_target_ids),
        scope_expectation_status="indeterminate",
        scope_evidence_refs=[scope_ref],
        reason_codes=["SCOPE_REQUIRED_TARGET_MISSING"],
    )
    assert commit_verification_arm_result_v03(case["ledger"], n_minus_one) == n_minus_one


def test_v03_arm_precommit_fault_is_zero_write_and_ack_loss_is_committed(
    v03_transaction_case,
) -> None:
    case = v03_transaction_case
    result = case["results"][0]
    with pytest.raises(VerificationTransactionError):
        commit_verification_arm_result_v03(
            case["ledger"], result, fault="commit_failure"
        )
    connection = evidence.connect_ledger(case["ledger"])
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM verification_arm_results_v03"
        ).fetchone() == (0,)
    finally:
        connection.close()
    with pytest.raises(VerificationCommittedError) as raised:
        commit_verification_arm_result_v03(
            case["ledger"], result, fault="commit_ack_loss"
        )
    assert raised.value.committed == result


def test_v03_decision_concurrency_has_one_exact_truth(
    v03_transaction_case,
) -> None:
    case = v03_transaction_case
    for result in case["results"]:
        commit_verification_arm_result_v03(case["ledger"], result)
    decision = _signed_decision_v03(
        case,
        DecisionDraftRequest(
            decision_id="c" * 64,
            decided_at="2026-01-01T00:20:00Z",
            nonce="d" * 64,
        ),
    )

    def commit_once():
        try:
            return commit_verification_decision_v03(case["ledger"], decision)
        except VerificationCommittedError as error:
            return error.committed

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = tuple(pool.map(lambda _: commit_once(), range(2)))
    assert outcomes == (decision, decision)
    connection = evidence.connect_ledger(case["ledger"])
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM verification_decisions_v03"
        ).fetchone() == (1,)
    finally:
        connection.close()


def test_v03_decision_rejects_bad_signature_and_preserves_ack_truth(
    v03_transaction_case,
) -> None:
    case = v03_transaction_case
    for result in case["results"]:
        commit_verification_arm_result_v03(case["ledger"], result)
    decision = _signed_decision_v03(
        case,
        DecisionDraftRequest(
            decision_id="c" * 64,
            decided_at="2026-01-01T00:20:00Z",
            nonce="d" * 64,
        ),
    )
    signature = decision.verifier_signatures[0].model_copy(
        update={"signature": "A" * 86}
    )
    tampered = decision.model_copy(update={"verifier_signatures": (signature,)})
    with pytest.raises(VerificationTransactionError, match="signature"):
        commit_verification_decision_v03(case["ledger"], tampered)
    with pytest.raises(VerificationCommittedError) as raised:
        commit_verification_decision_v03(
            case["ledger"], decision, fault="commit_ack_loss"
        )
    assert raised.value.committed == decision


def test_v03_stale_unsigned_parent_is_rejected_after_competing_commit(
    v03_transaction_case,
) -> None:
    case = v03_transaction_case
    for result in case["results"]:
        commit_verification_arm_result_v03(case["ledger"], result)
    first_request = DecisionDraftRequest(
        decision_id="c" * 64,
        decided_at="2026-01-01T00:20:00Z",
        nonce="d" * 64,
    )
    stale_request = DecisionDraftRequest(
        decision_id="e" * 64,
        decided_at="2026-01-01T00:21:00Z",
        nonce="f" * 64,
    )
    first = _signed_decision_v03(case, first_request)
    stale = _signed_decision_v03(case, stale_request)
    commit_verification_decision_v03(case["ledger"], first)
    with pytest.raises(VerificationTransactionError, match="draft mismatch"):
        commit_verification_decision_v03(case["ledger"], stale)


def test_v03_superseding_decision_binds_current_parent(
    v03_transaction_case,
) -> None:
    case = v03_transaction_case
    for result in case["results"]:
        commit_verification_arm_result_v03(case["ledger"], result)
    first = _signed_decision_v03(
        case,
        DecisionDraftRequest(
            decision_id="c" * 64,
            decided_at="2026-01-01T00:20:00Z",
            nonce="d" * 64,
        ),
    )
    commit_verification_decision_v03(case["ledger"], first)
    second = _signed_decision_v03(
        case,
        DecisionDraftRequest(
            decision_id="e" * 64,
            decided_at="2026-01-01T00:21:00Z",
            nonce="f" * 64,
        ),
    )
    assert second.supersedes_decision_id == first.decision_id
    assert commit_verification_decision_v03(case["ledger"], second) == second
