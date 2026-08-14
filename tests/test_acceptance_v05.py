from __future__ import annotations

import hashlib
from typing import Any

import pytest
import rfc8785

import openworkproof.evidence as evidence
from openworkproof import acceptance, verification
from openworkproof.models import (
    AcceptanceTransitionReceipt,
    DecisionDraftRequest,
    VerificationDecisionV05,
)
from openworkproof.settlement import (
    SettlementReadiness,
    read_settlement_snapshot,
)
from openworkproof.signing import key_id, sign_payload

from test_verification_integrity_transactions_v05 import (
    _signed_decision_v05,
    commit_verification_arm_result_v05,
    commit_verification_decision_v05,
    commit_verification_profile_v05,
    v05_transaction_case,
    verification_profile_v03,
)


def _commit_v05_decision(case) -> VerificationDecisionV05:
    commit_verification_profile_v05(case["ledger"], case["profile"])
    for result in case["results"]:
        commit_verification_arm_result_v05(case["ledger"], result)
    decision = _signed_decision_v05(
        case,
        DecisionDraftRequest(
            decision_id="c" * 64,
            decided_at="2026-01-01T00:20:00Z",
            nonce="d" * 64,
        ),
    )
    commit_verification_decision_v05(case["ledger"], decision)
    return decision


def _resign_decision_v05(case, base_decision, **changes) -> VerificationDecisionV05:
    raw = base_decision.model_dump(
        mode="json", exclude={"digest", "verifier_signatures"}
    )
    raw.update(changes)
    encoded = verification.canonical_bytes(
        "verification-decision", raw, version="0.5"
    )
    binding = case["profile"].verifier_bindings[0]
    private_key = case["keys"]["Verifier"][0]
    return VerificationDecisionV05.model_validate(
        {
            **raw,
            "digest": hashlib.sha256(encoded).hexdigest(),
            "verifier_signatures": [
                {
                    "verifier_subject_id": binding.verifier_subject_id,
                    "verifier_key_id": key_id(private_key.public_key()),
                    "signature_alg": "Ed25519",
                    "signature": __import__("base64")
                    .urlsafe_b64encode(private_key.sign(encoded))
                    .decode("ascii")
                    .rstrip("="),
                }
            ],
        }
    )


def _insert_decision_row(case, decision) -> None:
    connection = evidence.connect_ledger(case["ledger"])
    try:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            """
            INSERT INTO verification_decisions_v05 (
                decision_id, decision_digest, profile_id, scope_id,
                predecessor_id, decision_json, committed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                decision.decision_id,
                decision.digest,
                case["profile"].profile_id,
                case["manifest"].scope_id,
                decision.supersedes_decision_id,
                rfc8785.dumps(decision.model_dump(mode="json")),
                "2026-01-01T00:20:00Z",
            ),
        )
        for ordinal, reference in enumerate(decision.arm_results):
            connection.execute(
                """
                INSERT INTO verification_decision_parents_v05 (
                    decision_id, ordinal, arm_result_id
                ) VALUES (?, ?, ?)
                """,
                (decision.decision_id, ordinal, reference.arm_result_id),
            )
        connection.execute("COMMIT")
    finally:
        connection.close()


def _commit_acceptance_fixture(ledger, signed_acceptance_receipt) -> None:
    connection = evidence.connect_ledger(ledger)
    try:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            """
            INSERT INTO acceptance_receipts (
                acceptance_id, work_order_digest, acceptance_json
            ) VALUES (?, ?, ?)
            """,
            (
                signed_acceptance_receipt.acceptance_id,
                signed_acceptance_receipt.work_order_digest,
                evidence._canonical_json(
                    signed_acceptance_receipt.model_dump(mode="json")
                ),
            ),
        )
        connection.execute("COMMIT")
    finally:
        connection.close()


def _transition_for_v05(
    *,
    case,
    decision,
    signed_acceptance_receipt,
    transition: str,
    decision_digest: str | None = None,
) -> AcceptanceTransitionReceipt:
    replacement_id = "e" * 64 if transition == "superseded" else None
    payload = {
        "schema_version": "openworkproof-acceptance-transition/0.2",
        "protocol_version": "0.2",
        "transition_id": "f" * 64,
        "work_order_digest": signed_acceptance_receipt.work_order_digest,
        "target_acceptance_id": signed_acceptance_receipt.acceptance_id,
        "target_acceptance_digest": signed_acceptance_receipt.digest,
        "verification_decision_id": decision.decision_id,
        "verification_decision_digest": (
            decision.digest if decision_digest is None else decision_digest
        ),
        "transition": transition,
        "replacement_acceptance_id": replacement_id,
        "replacement_acceptance_digest": (
            "1" * 64 if replacement_id is not None else None
        ),
        "reason_code": (
            "REPLACED_DELIVERY"
            if replacement_id is not None
            else "MANUAL_WITHDRAWAL"
        ),
        "causal_parent_ids": sorted(
            {
                signed_acceptance_receipt.acceptance_id,
                decision.decision_id,
                *(() if replacement_id is None else (replacement_id,)),
            }
        ),
        "decided_at": "2026-01-01T00:30:00Z",
        "nonce": "2" * 64,
    }
    return AcceptanceTransitionReceipt.model_validate(
        sign_payload(
            "acceptance-transition",
            payload,
            case["keys"]["Acceptor"][0],
        )
    )


def test_v05_verified_decision_is_the_closed_acceptance_authority(
    v05_transaction_case,
) -> None:
    case = v05_transaction_case
    decision = _commit_v05_decision(case)
    connection = evidence.connect_ledger(case["ledger"])
    try:
        record = acceptance._resolve_current_verification_record(connection)
        gated = acceptance._require_current_verified_decision_if_v02(connection)
    finally:
        connection.close()
    assert record == acceptance.CurrentVerificationRecord(
        protocol_version="0.5",
        decision_id=decision.decision_id,
        decision_digest=decision.digest,
        decision="VERIFIED",
    )
    assert gated == record


def test_v05_verified_decision_is_ready_for_acceptance_not_settlement(
    v05_transaction_case,
) -> None:
    case = v05_transaction_case
    decision = _commit_v05_decision(case)
    snapshot = read_settlement_snapshot(case["ledger"])
    assert snapshot.current_decision_id == decision.decision_id
    assert snapshot.settlement_readiness is SettlementReadiness.READY_FOR_ACCEPTANCE


@pytest.mark.parametrize(
    ("transition", "expected_readiness"),
    (
        ("withdrawn", SettlementReadiness.WITHDRAWN),
        ("superseded", SettlementReadiness.SUPERSEDED),
    ),
)
def test_v05_acceptance_transition_routes_to_v05_family(
    v05_transaction_case,
    signed_acceptance_receipt,
    transition,
    expected_readiness,
) -> None:
    case = v05_transaction_case
    decision = _commit_v05_decision(case)
    _commit_acceptance_fixture(case["ledger"], signed_acceptance_receipt)
    receipt = _transition_for_v05(
        case=case,
        decision=decision,
        signed_acceptance_receipt=signed_acceptance_receipt,
        transition=transition,
    )
    assert acceptance.commit_acceptance_transition(case["ledger"], receipt) == receipt
    connection = evidence.connect_ledger(case["ledger"])
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM acceptance_transitions"
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT COUNT(*) FROM acceptance_transitions_v03"
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT COUNT(*) FROM acceptance_transitions_v05"
        ).fetchone() == (1,)
        assert connection.execute(
            "SELECT COUNT(*) FROM acceptance_transition_parents_v05"
        ).fetchone() == (len(receipt.causal_parent_ids),)
    finally:
        connection.close()
    snapshot = read_settlement_snapshot(case["ledger"])
    assert snapshot.settlement_readiness is expected_readiness


def test_v05_transition_rejects_fabricated_cross_version_decision_digest(
    v05_transaction_case,
    signed_acceptance_receipt,
) -> None:
    case = v05_transaction_case
    decision = _commit_v05_decision(case)
    _commit_acceptance_fixture(case["ledger"], signed_acceptance_receipt)
    receipt = _transition_for_v05(
        case=case,
        decision=decision,
        signed_acceptance_receipt=signed_acceptance_receipt,
        transition="withdrawn",
        decision_digest="f" * 64,
    )
    with pytest.raises(acceptance.AcceptanceTransactionError, match="not current"):
        acceptance.commit_acceptance_transition(case["ledger"], receipt)


@pytest.mark.parametrize("outcome", ("UNKNOWN", "REFUTED"))
def test_v05_non_verified_decision_cannot_open_acceptance_gate(
    v05_transaction_case,
    outcome,
) -> None:
    case = v05_transaction_case
    decision = _commit_v05_decision(case)
    mutated = _resign_decision_v05(
        case,
        decision,
        decision_id="e" * 64,
        decision=outcome,
        supersedes_decision_id=decision.decision_id,
        supersedes_decision_digest=decision.digest,
        causal_parent_decision_ids=(decision.decision_id,),
        decided_at="2026-01-01T00:21:00Z",
    )
    _insert_decision_row(case, mutated)
    connection = evidence.connect_ledger(case["ledger"])
    try:
        with pytest.raises(
            acceptance.AcceptanceTransactionError, match="VERIFIED"
        ):
            acceptance._require_current_verified_decision_if_v02(connection)
    finally:
        connection.close()


def test_v05_missing_decision_cannot_open_acceptance_gate(
    v05_transaction_case,
) -> None:
    case = v05_transaction_case
    commit_verification_profile_v05(case["ledger"], case["profile"])
    connection = evidence.connect_ledger(case["ledger"])
    try:
        with pytest.raises(
            acceptance.AcceptanceTransactionError, match="VERIFIED"
        ):
            acceptance._require_current_verified_decision_if_v02(connection)
    finally:
        connection.close()


def test_v05_dual_profile_families_are_rejected_as_ambiguous(
    v05_transaction_case,
) -> None:
    case = v05_transaction_case
    decision = _commit_v05_decision(case)
    connection = evidence.connect_ledger(case["ledger"])
    try:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            """
            INSERT INTO verification_profiles_v03 (
                profile_id, profile_digest, scope_id, scope_digest,
                subject_claim_id, profile_json
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                "ab" * 32,
                "c" * 64,
                case["manifest"].scope_id,
                case["manifest"].digest,
                "d" * 64,
                rfc8785.dumps({"nonce": "x"}),
            ),
        )
        connection.execute("COMMIT")
        with pytest.raises(
            acceptance.AcceptanceTransactionError, match="ambiguous"
        ):
            acceptance._resolve_current_verification_record(connection)
    finally:
        connection.close()


def test_v05_fabricated_decision_row_in_foreign_family_is_ambiguous(
    v05_transaction_case,
) -> None:
    case = v05_transaction_case
    decision = _commit_v05_decision(case)
    connection = evidence.connect_ledger(case["ledger"])
    try:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            """
            INSERT INTO verification_profiles_v03 (
                profile_id, profile_digest, scope_id, scope_digest,
                subject_claim_id, profile_json
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                "ab" * 32,
                "c" * 64,
                case["manifest"].scope_id,
                case["manifest"].digest,
                "d" * 64,
                rfc8785.dumps({"nonce": "x"}),
            ),
        )
        connection.execute(
            """
            INSERT INTO verification_decisions_v03 (
                decision_id, decision_digest, profile_id, scope_id,
                predecessor_id, decision_json
            ) VALUES (?, ?, ?, ?, NULL, ?)
            """,
            (
                decision.decision_id,
                decision.digest,
                "ab" * 32,
                case["manifest"].scope_id,
                rfc8785.dumps({"nonce": "x"}),
            ),
        )
        connection.execute("COMMIT")
        with pytest.raises(
            acceptance.AcceptanceTransactionError, match="ambiguous"
        ):
            acceptance._resolve_current_verification_record(connection)
    finally:
        connection.close()


def test_v05_decision_chain_without_parents_rows_closes_the_gate(
    v05_transaction_case,
) -> None:
    case = v05_transaction_case
    decision = _commit_v05_decision(case)
    connection = evidence.connect_ledger(case["ledger"])
    try:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            "DROP TRIGGER verification_decision_parents_v05_are_immutable_delete"
        )
        connection.execute(
            "DELETE FROM verification_decision_parents_v05 WHERE decision_id = ?",
            (decision.decision_id,),
        )
        connection.execute("COMMIT")
    finally:
        connection.close()
    connection = evidence.connect_ledger(case["ledger"])
    try:
        with pytest.raises(acceptance.AcceptanceTransactionError):
            acceptance._require_current_verified_decision_if_v02(connection)
    finally:
        connection.close()


def test_v05_tampered_decision_signature_raises_closed_exception(
    v05_transaction_case,
) -> None:
    case = v05_transaction_case
    decision = _commit_v05_decision(case)
    connection = evidence.connect_ledger(case["ledger"])
    try:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            "DROP TRIGGER verification_decisions_v05_are_immutable_update"
        )
        tampered = decision.model_copy(
            update={
                "verifier_signatures": (
                    decision.verifier_signatures[0].model_copy(
                        update={"signature": "A" * 86}
                    ),
                )
            }
        )
        connection.execute(
            "UPDATE verification_decisions_v05 SET decision_json = ? "
            "WHERE decision_id = ?",
            (
                rfc8785.dumps(tampered.model_dump(mode="json")),
                decision.decision_id,
            ),
        )
        connection.execute("COMMIT")
    finally:
        connection.close()
    connection = evidence.connect_ledger(case["ledger"])
    try:
        with pytest.raises(acceptance.AcceptanceTransactionError):
            acceptance._require_current_verified_decision_if_v02(connection)
    finally:
        connection.close()


def test_v05_transition_rejects_cross_family_terminal_row(
    v05_transaction_case,
    signed_acceptance_receipt,
) -> None:
    case = v05_transaction_case
    decision = _commit_v05_decision(case)
    _commit_acceptance_fixture(case["ledger"], signed_acceptance_receipt)
    connection = evidence.connect_ledger(case["ledger"])
    try:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            """
            INSERT INTO verification_decisions (
                decision_id, predecessor_id, decision_json
            ) VALUES (?, NULL, ?)
            """,
            ("bb" * 32, rfc8785.dumps({"nonce": "x"})),
        )
        connection.execute(
            """
            INSERT INTO acceptance_transitions (
                transition_id, target_acceptance_id,
                verification_decision_id, transition_json
            ) VALUES (?, ?, ?, ?)
            """,
            (
                "aa" * 32,
                signed_acceptance_receipt.acceptance_id,
                "bb" * 32,
                rfc8785.dumps({"nonce": "x"}),
            ),
        )
        connection.execute("COMMIT")
    finally:
        connection.close()
    receipt = _transition_for_v05(
        case=case,
        decision=decision,
        signed_acceptance_receipt=signed_acceptance_receipt,
        transition="withdrawn",
    )
    with pytest.raises(
        acceptance.AcceptanceTransactionError, match="protocol families"
    ):
        acceptance.commit_acceptance_transition(case["ledger"], receipt)


def test_v05_settlement_rejects_cross_family_decision_ambiguity(
    v05_transaction_case,
) -> None:
    case = v05_transaction_case
    decision = _commit_v05_decision(case)
    connection = evidence.connect_ledger(case["ledger"])
    try:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            """
            INSERT INTO verification_decisions (
                decision_id, predecessor_id, decision_json
            ) VALUES (?, NULL, ?)
            """,
            (
                decision.decision_id,
                rfc8785.dumps({"nonce": "x"}),
            ),
        )
        connection.execute("COMMIT")
    finally:
        connection.close()
    with pytest.raises(Exception, match="invalid"):
        read_settlement_snapshot(case["ledger"])
