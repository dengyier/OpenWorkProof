from __future__ import annotations

import base64
import hashlib
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

import openworkproof.evidence as evidence
from openworkproof.models import (
    DecisionDraftRequest,
    VerificationArmResult,
    VerificationDecision,
    VerificationProfileV02,
)
from openworkproof.signing import key_id, sign_payload
from openworkproof.verification import (
    VerificationCommitIndeterminateError,
    VerificationCommittedError,
    VerificationTransactionError,
    commit_verification_arm_result,
    commit_verification_decision,
    commit_verification_profile,
    external_anchor_digest,
    prepare_verification_decision,
    verification_decision_signing_bytes,
)


V02_TABLES = {
    "subject_claims",
    "verification_profiles_v02",
    "external_anchors",
    "verification_arm_results",
    "verification_decisions",
    "verification_decision_parents",
}


def _all_table_snapshot(path: Path) -> dict[str, tuple[tuple[object, ...], ...]]:
    connection = sqlite3.connect(path)
    try:
        names = tuple(
            row[0]
            for row in connection.execute(
                """
                SELECT name FROM sqlite_master
                WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
                ORDER BY name
                """
            )
        )
        return {
            name: tuple(connection.execute(f'SELECT * FROM "{name}"'))
            for name in names
        }
    finally:
        connection.close()


@pytest.fixture
def v02_ledger(tmp_path, signed_work_order) -> Path:
    path = tmp_path / "verification-ledger.sqlite3"
    evidence.initialize_ledger(path, signed_work_order)
    return path


def _insert_causal_receipt(path, receipt) -> None:
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


def _arm_result(
    *,
    profile,
    arm_kind: str,
    result_id: str,
    receipt_id: str,
    private_key,
) -> VerificationArmResult:
    binding = profile.verifier_bindings[0]
    arm = profile.positive_arm if arm_kind == "positive" else profile.negative_arms[0]
    reasons = [] if arm_kind == "positive" else ["MUTATION_APPLIED", "MUTATION_CAUGHT"]
    candidate = {
        "schema_version": "openworkproof-verification-arm-result/0.2",
        "arm_result_id": result_id,
        "profile_digest": profile.digest,
        "arm_id": arm.arm_id,
        "arm_kind": arm_kind,
        "mutation_status": "not_applicable" if arm_kind == "positive" else "applied",
        "execution_status": "completed",
        "expectation_status": "satisfied",
        "reason_codes": reasons,
        "action_receipt_ids": [receipt_id],
        "evidence_refs": [
            {
                "path": arm.result_artifact_paths[0],
                "sha256": ("d" if arm_kind == "positive" else "e") * 64,
                "media_type": "application/json",
                "size_bytes": 128,
            }
        ],
        "verifier_subject_id": binding.verifier_subject_id,
        "verifier_key_id": binding.verifier_key_id,
        "verifier_build_digest": "4" * 64,
        "dependency_lock_digest": "5" * 64,
        "controller_factors": list(binding.controller_factors),
        "execution_context_factors": list(binding.execution_context_factors),
        "created_at": "2026-01-01T00:10:00Z",
    }
    return VerificationArmResult.model_validate(
        sign_payload("verification-arm-result", candidate, private_key)
    )


@pytest.fixture
def committed_v02_case(
    v02_ledger,
    signed_work_order,
    signed_subject_claim,
    signed_verification_profile,
    ephemeral_role_keys,
    sidecar_receipt_factory,
):
    commit_verification_profile(
        v02_ledger,
        signed_subject_claim,
        signed_verification_profile,
    )
    receipt = sidecar_receipt_factory(
        state_before="locally_verified",
        state_after="evidence_incomplete",
        event_type="system_event",
        event_name="proof_composed",
        sequence=1,
    )
    _insert_causal_receipt(v02_ledger, receipt)
    results = (
        _arm_result(
            profile=signed_verification_profile,
            arm_kind="positive",
            result_id="8" * 64,
            receipt_id=receipt.receipt_id,
            private_key=ephemeral_role_keys["Verifier"][0],
        ),
        _arm_result(
            profile=signed_verification_profile,
            arm_kind="negative",
            result_id="9" * 64,
            receipt_id=receipt.receipt_id,
            private_key=ephemeral_role_keys["Verifier"][0],
        ),
    )
    for result in results:
        commit_verification_arm_result(v02_ledger, result)
    return {
        "ledger": v02_ledger,
        "profile": signed_verification_profile,
        "claim": signed_subject_claim,
        "results": results,
        "verifier_key": ephemeral_role_keys["Verifier"][0],
    }


def _signed_decision(case, request) -> VerificationDecision:
    draft = prepare_verification_decision(case["ledger"], request)
    encoded = verification_decision_signing_bytes(draft)
    private_key = case["verifier_key"]
    binding = case["profile"].verifier_bindings[0]
    return VerificationDecision.model_validate(
        {
            "schema_version": "openworkproof-verification-decision/0.2",
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


def _request(
    *,
    decision_id: str = "a" * 64,
    decided_at: str = "2026-01-01T00:20:00Z",
    nonce: str = "1" * 64,
) -> DecisionDraftRequest:
    return DecisionDraftRequest.model_validate(
        {
            "decision_id": decision_id,
            "decided_at": decided_at,
            "nonce": nonce,
        }
    )


def test_ledger_schema_includes_exact_v02_transaction_tables(v02_ledger) -> None:
    connection = sqlite3.connect(v02_ledger)
    try:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
    finally:
        connection.close()
    assert V02_TABLES <= tables


def test_profile_precommit_failure_has_zero_protocol_writes(
    v02_ledger,
    signed_subject_claim,
    signed_verification_profile,
) -> None:
    before = _all_table_snapshot(v02_ledger)
    with pytest.raises(VerificationTransactionError, match="fault"):
        commit_verification_profile(
            v02_ledger,
            signed_subject_claim,
            signed_verification_profile,
            fault="before_commit",
        )
    assert _all_table_snapshot(v02_ledger) == before


def test_t1_t2_t3_commit_exact_canonical_rows(committed_v02_case) -> None:
    case = committed_v02_case
    decision = _signed_decision(case, _request())
    assert commit_verification_decision(case["ledger"], decision) == decision
    connection = sqlite3.connect(case["ledger"])
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM subject_claims"
        ).fetchone() == (1,)
        assert connection.execute(
            "SELECT COUNT(*) FROM verification_profiles_v02"
        ).fetchone() == (1,)
        assert connection.execute(
            "SELECT COUNT(*) FROM verification_arm_results"
        ).fetchone() == (2,)
        assert connection.execute(
            "SELECT COUNT(*) FROM verification_decision_parents"
        ).fetchone() == (2,)
    finally:
        connection.close()


def test_level_two_profile_commits_exact_customer_commitment(
    v02_ledger,
    verification_profile_dict,
    signed_subject_claim,
    commitment_anchor,
    ephemeral_role_keys,
) -> None:
    candidate = dict(verification_profile_dict)
    candidate["delivery_trust_level"] = 2
    candidate["commitment_anchor_digest"] = external_anchor_digest(
        commitment_anchor
    )
    profile = VerificationProfileV02.model_validate(
        sign_payload(
            "verification-profile",
            candidate,
            ephemeral_role_keys["Manager"][0],
        )
    )
    assert commit_verification_profile(
        v02_ledger,
        signed_subject_claim,
        profile,
        commitment_anchor=commitment_anchor,
    ) == profile


def test_decision_commit_ack_loss_is_recoverable(committed_v02_case) -> None:
    decision = _signed_decision(committed_v02_case, _request())
    with pytest.raises(VerificationCommittedError) as raised:
        commit_verification_decision(
            committed_v02_case["ledger"],
            decision,
            fault="commit_ack_loss",
        )
    assert raised.value.committed == decision


def test_decision_failed_readback_is_indeterminate(committed_v02_case) -> None:
    decision = _signed_decision(committed_v02_case, _request())
    with pytest.raises(VerificationCommitIndeterminateError):
        commit_verification_decision(
            committed_v02_case["ledger"],
            decision,
            fault="readback_failure",
        )


def test_committed_cleanup_failure_returns_committed_truth(
    committed_v02_case,
) -> None:
    decision = _signed_decision(committed_v02_case, _request())
    with pytest.raises(VerificationCommittedError) as raised:
        commit_verification_decision(
            committed_v02_case["ledger"],
            decision,
            fault="cleanup_failure",
        )
    assert raised.value.committed == decision


def test_arm_result_precommit_failure_is_zero_write_and_duplicate_is_recovered(
    committed_v02_case,
) -> None:
    case = committed_v02_case
    with pytest.raises(VerificationCommittedError) as duplicate:
        commit_verification_arm_result(case["ledger"], case["results"][0])
    assert duplicate.value.committed == case["results"][0]

    replacement = _arm_result(
        profile=case["profile"],
        arm_kind="positive",
        result_id="f" * 64,
        receipt_id=case["results"][0].action_receipt_ids[0],
        private_key=case["verifier_key"],
    )
    before = _all_table_snapshot(case["ledger"])
    with pytest.raises(VerificationTransactionError, match="fault"):
        commit_verification_arm_result(
            case["ledger"], replacement, fault="before_commit"
        )
    assert _all_table_snapshot(case["ledger"]) == before


def test_concurrent_same_decision_has_one_commit_winner(committed_v02_case) -> None:
    decision = _signed_decision(committed_v02_case, _request())

    def commit_once():
        try:
            return commit_verification_decision(
                committed_v02_case["ledger"], decision
            )
        except VerificationCommittedError as error:
            return error

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = tuple(executor.map(lambda _: commit_once(), range(2)))
    assert sum(isinstance(item, VerificationDecision) for item in outcomes) == 1
    assert sum(isinstance(item, VerificationCommittedError) for item in outcomes) == 1


def test_decision_nonce_cannot_be_reused_across_commits(
    committed_v02_case,
) -> None:
    first = _signed_decision(committed_v02_case, _request())
    assert commit_verification_decision(committed_v02_case["ledger"], first) == first

    reused_nonce = _request(
        decision_id="d" * 64,
        decided_at="2026-01-01T00:21:00Z",
        nonce=first.nonce,
    )
    second = _signed_decision(committed_v02_case, reused_nonce)
    before = _all_table_snapshot(committed_v02_case["ledger"])
    with pytest.raises(VerificationTransactionError, match="nonce"):
        commit_verification_decision(committed_v02_case["ledger"], second)
    assert _all_table_snapshot(committed_v02_case["ledger"]) == before


def test_decision_nonce_cannot_reuse_profile_nonce(committed_v02_case) -> None:
    decision = _signed_decision(
        committed_v02_case,
        _request(nonce=committed_v02_case["profile"].nonce),
    )
    before = _all_table_snapshot(committed_v02_case["ledger"])
    with pytest.raises(VerificationTransactionError, match="nonce"):
        commit_verification_decision(committed_v02_case["ledger"], decision)
    assert _all_table_snapshot(committed_v02_case["ledger"]) == before


def test_competing_decisions_from_same_predecessor_have_one_winner(
    committed_v02_case,
) -> None:
    first = _signed_decision(committed_v02_case, _request())
    assert commit_verification_decision(committed_v02_case["ledger"], first) == first

    candidate_one = _signed_decision(
        committed_v02_case,
        _request(
            decision_id="d" * 64,
            decided_at="2026-01-01T00:21:00Z",
            nonce="e" * 64,
        ),
    )
    candidate_two = _signed_decision(
        committed_v02_case,
        _request(
            decision_id="f" * 64,
            decided_at="2026-01-01T00:21:01Z",
            nonce="2" * 64,
        ),
    )
    assert (
        commit_verification_decision(
            committed_v02_case["ledger"], candidate_one
        )
        == candidate_one
    )
    before = _all_table_snapshot(committed_v02_case["ledger"])
    with pytest.raises(VerificationTransactionError):
        commit_verification_decision(
            committed_v02_case["ledger"], candidate_two
        )
    assert _all_table_snapshot(committed_v02_case["ledger"]) == before


def test_tampered_arm_canonical_json_fails_closed(committed_v02_case) -> None:
    connection = sqlite3.connect(committed_v02_case["ledger"])
    try:
        connection.execute(
            """
            UPDATE verification_arm_results
            SET arm_result_json = ?
            WHERE arm_result_id = ?
            """,
            (b'{}', committed_v02_case["results"][0].arm_result_id),
        )
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(VerificationTransactionError, match="canonical"):
        prepare_verification_decision(committed_v02_case["ledger"], _request())
