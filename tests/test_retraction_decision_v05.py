from __future__ import annotations

from typing import Any

import pytest

import openworkproof.evidence as evidence
from openworkproof.models import (
    EvaluationScopeManifest,
    VerificationProfileV03,
    RetractionReceiptV05,
    retraction_receipt_id,
)
from openworkproof.retraction import commit_retraction_receipt
from openworkproof.signing import sign_payload
from openworkproof.verification import (
    commit_verification_arm_result_v05,
    commit_verification_profile_v05,
    prepare_verification_decision_v05,
)

from test_retraction_receipt_v05 import _retraction_payload
from test_verification_integrity_transactions_v05 import (
    _compose_v05,
    _resign_arm_result_v05,
    v05_transaction_case,
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


def _retract_receipt(case: dict[str, Any], receipt_id: str, receipt_digest: str) -> RetractionReceiptV05:
    payload = _retraction_payload(
        target_receipt_id=receipt_id,
        target_receipt_digest=receipt_digest,
        retraction_reason="evidence_refuted",
        retraction_effect="refuted",
    )
    payload["work_order_digest"] = case["profile"].work_order_digest
    payload["retraction_id"] = retraction_receipt_id(payload)
    return RetractionReceiptV05.model_validate(
        sign_payload(
            "retraction-receipt",
            payload,
            case["keys"]["Manager"][0],
            version="0.5",
        )
    )


def test_decision_unknown_when_causal_receipt_refuted(
    v05_transaction_case,
) -> None:
    """A decision whose causal receipt was retracted with evidence_refuted must
    not derive VERIFIED: the conclusion rests on refuted evidence. The current
    implementation ignores retractions, so this test drives RED."""
    case = v05_transaction_case
    commit_verification_profile_v05(case["ledger"], case["profile"])
    results = []
    for result in case["results"]:
        committed = _resign_arm_result_v05(case, result)
        commit_verification_arm_result_v05(case["ledger"], committed)
        results.append(committed)

    # Baseline: without a retraction the full chain composes VERIFIED.
    baseline = _compose_v05(case, results=tuple(results))
    assert baseline.decision == "VERIFIED"

    # Retract every causal receipt with evidence_refuted, then recompose.
    retracted_ids = {
        receipt_id
        for result in results
        for receipt_id in result.action_receipt_ids
    }
    for receipt_id in retracted_ids:
        row = evidence.connect_ledger(case["ledger"]).execute(
            "SELECT receipt_json FROM receipts WHERE receipt_id = ?",
            (receipt_id,),
        ).fetchone()
        from openworkproof.models import parse_action_receipt_json

        parsed = parse_action_receipt_json(row[0])
        commit_retraction_receipt(
            case["ledger"],
            _retract_receipt(case, receipt_id, parsed.digest),
        )

    draft = prepare_verification_decision_v05(
        case["ledger"], _decision_request(case, "refuted-causal")
    )
    assert draft.decision == "UNKNOWN"
    assert "RECEIPT_RETRACTED" in draft.reason_codes


def test_decision_refuted_priority_over_retraction(
    v05_transaction_case,
) -> None:
    """A contradicted positive arm must derive REFUTED even when a causal
    receipt was also retracted: the direct refutation is stronger."""
    case = v05_transaction_case
    commit_verification_profile_v05(case["ledger"], case["profile"])
    results = []
    for kind, result in zip(("positive", "negative"), case["results"], strict=True):
        if kind == "positive":
            result = _resign_arm_result_v05(
                case,
                result,
                expectation_status="contradicted",
                reason_codes=["MUTATION_SURVIVED"],
            )
        else:
            result = _resign_arm_result_v05(case, result)
        commit_verification_arm_result_v05(case["ledger"], result)
        results.append(result)
    retracted_ids = {
        receipt_id
        for result in results
        for receipt_id in result.action_receipt_ids
    }
    for receipt_id in retracted_ids:
        row = evidence.connect_ledger(case["ledger"]).execute(
            "SELECT receipt_json FROM receipts WHERE receipt_id = ?",
            (receipt_id,),
        ).fetchone()
        from openworkproof.models import parse_action_receipt_json

        parsed = parse_action_receipt_json(row[0])
        commit_retraction_receipt(
            case["ledger"],
            _retract_receipt(case, receipt_id, parsed.digest),
        )
    draft = prepare_verification_decision_v05(
        case["ledger"], _decision_request(case, "refuted-arm")
    )
    assert draft.decision == "REFUTED"


def _decision_request(case: dict[str, Any], suffix: str) -> Any:
    from openworkproof.models import DecisionDraftRequest

    return DecisionDraftRequest(
        decision_id="d" * 64,
        decided_at="2026-01-01T00:30:00Z",
        nonce="f" * 64,
    )
