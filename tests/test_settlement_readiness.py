from __future__ import annotations

import pytest
import sqlite3
from concurrent.futures import ThreadPoolExecutor

from openworkproof.models import (
    AcceptanceReceipt,
    AcceptanceRejectionReceipt,
    AcceptanceTransitionReceipt,
    VerificationDecision,
)
from openworkproof import evidence
from openworkproof.acceptance import (
    AcceptanceCommitIndeterminateError,
    AcceptanceCommittedError,
    AcceptanceTransactionError,
    commit_acceptance_transition,
)
from openworkproof.settlement import (
    AcceptanceHistory,
    EffectiveAcceptance,
    SettlementReadiness,
    effective_acceptance,
    read_settlement_snapshot,
    settlement_readiness,
)
from openworkproof.signing import sign_payload
from openworkproof.verification import (
    commit_verification_arm_result,
    commit_verification_decision,
    commit_verification_profile,
)
from test_verification_transactions_v02 import (
    _arm_result,
    _insert_causal_receipt,
    _request,
    _signed_decision,
)


@pytest.fixture
def acceptance_transition_dict() -> dict:
    return {
        "schema_version": "openworkproof-acceptance-transition/0.2",
        "protocol_version": "0.2",
        "transition_id": "4" * 64,
        "work_order_digest": "7" * 64,
        "target_acceptance_id": "1" * 64,
        "target_acceptance_digest": "2" * 64,
        "verification_decision_id": "3" * 64,
        "verification_decision_digest": "4" * 64,
        "transition": "withdrawn",
        "replacement_acceptance_id": None,
        "replacement_acceptance_digest": None,
        "reason_code": "MANUAL_WITHDRAWAL",
        "causal_parent_ids": ["1" * 64, "3" * 64],
        "decided_at": "2026-01-01T00:30:00Z",
        "nonce": "5" * 64,
    }


def _acceptance() -> AcceptanceReceipt:
    return AcceptanceReceipt.model_construct(acceptance_id="1" * 64)


def _rejection() -> AcceptanceRejectionReceipt:
    return AcceptanceRejectionReceipt.model_construct(rejection_id="2" * 64)


def _decision(value: str) -> VerificationDecision:
    return VerificationDecision.model_construct(
        decision_id="3" * 64,
        decision=value,
    )


def _transition(value: str) -> AcceptanceTransitionReceipt:
    return AcceptanceTransitionReceipt.model_construct(
        transition_id="4" * 64,
        transition=value,
    )


def _table_snapshot(path) -> dict[str, tuple[tuple[object, ...], ...]]:
    connection = sqlite3.connect(path)
    try:
        tables = tuple(
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
            table: tuple(connection.execute(f'SELECT * FROM "{table}"'))
            for table in tables
        }
    finally:
        connection.close()


@pytest.fixture
def transition_case(
    tmp_path,
    signed_work_order,
    signed_subject_claim,
    signed_verification_profile,
    signed_acceptance_receipt,
    ephemeral_role_keys,
    sidecar_receipt_factory,
):
    ledger = tmp_path / "settlement-ledger.sqlite3"
    evidence.initialize_ledger(ledger, signed_work_order)
    commit_verification_profile(
        ledger,
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
    _insert_causal_receipt(ledger, receipt)
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
        commit_verification_arm_result(ledger, result)
    decision_case = {
        "ledger": ledger,
        "profile": signed_verification_profile,
        "claim": signed_subject_claim,
        "results": results,
        "verifier_key": ephemeral_role_keys["Verifier"][0],
    }
    decision = _signed_decision(
        decision_case,
        _request(decision_id="d" * 64),
    )
    commit_verification_decision(ledger, decision)
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
                signed_work_order.digest,
                evidence._canonical_json(
                    signed_acceptance_receipt.model_dump(mode="json")
                ),
            ),
        )
        connection.execute("COMMIT")
    finally:
        connection.close()
    raw = {
        "schema_version": "openworkproof-acceptance-transition/0.2",
        "protocol_version": "0.2",
        "transition_id": "4" * 64,
        "work_order_digest": signed_work_order.digest,
        "target_acceptance_id": signed_acceptance_receipt.acceptance_id,
        "target_acceptance_digest": signed_acceptance_receipt.digest,
        "verification_decision_id": decision.decision_id,
        "verification_decision_digest": decision.digest,
        "transition": "withdrawn",
        "replacement_acceptance_id": None,
        "replacement_acceptance_digest": None,
        "reason_code": "MANUAL_WITHDRAWAL",
        "causal_parent_ids": sorted(
            [signed_acceptance_receipt.acceptance_id, decision.decision_id]
        ),
        "decided_at": "2026-01-01T00:30:00Z",
        "nonce": "5" * 64,
    }
    transition = AcceptanceTransitionReceipt.model_validate(
        sign_payload(
            "acceptance-transition",
            raw,
            ephemeral_role_keys["Acceptor"][0],
        )
    )
    return {
        "ledger": ledger,
        "acceptance": signed_acceptance_receipt,
        "decision": decision,
        "transition": transition,
    }


@pytest.mark.parametrize(
    ("history", "expected"),
    (
        (
            AcceptanceHistory.model_construct(
                acceptance=_acceptance(),
                rejection=None,
                withdrawal=_transition("withdrawn"),
                supersession=_transition("superseded"),
                current_decision=_decision("VERIFIED"),
            ),
            EffectiveAcceptance.WITHDRAWN,
        ),
        (
            AcceptanceHistory.model_construct(
                acceptance=_acceptance(),
                rejection=None,
                withdrawal=None,
                supersession=_transition("superseded"),
                current_decision=_decision("VERIFIED"),
            ),
            EffectiveAcceptance.SUPERSEDED,
        ),
        (
            AcceptanceHistory.model_construct(
                acceptance=_acceptance(),
                rejection=None,
                withdrawal=None,
                supersession=None,
                current_decision=_decision("UNKNOWN"),
            ),
            EffectiveAcceptance.SUSPENDED,
        ),
        (
            AcceptanceHistory.model_construct(
                acceptance=_acceptance(),
                rejection=None,
                withdrawal=None,
                supersession=None,
                current_decision=_decision("VERIFIED"),
            ),
            EffectiveAcceptance.ACTIVE,
        ),
        (
            AcceptanceHistory.model_construct(
                acceptance=None,
                rejection=None,
                withdrawal=None,
                supersession=None,
                current_decision=_decision("VERIFIED"),
            ),
            EffectiveAcceptance.NONE,
        ),
    ),
)
def test_effective_acceptance_priority(history, expected) -> None:
    assert effective_acceptance(history) is expected


@pytest.mark.parametrize(
    ("decision", "acceptance", "rejection", "expected"),
    (
        (
            _decision("VERIFIED"),
            EffectiveAcceptance.WITHDRAWN,
            None,
            SettlementReadiness.WITHDRAWN,
        ),
        (
            _decision("VERIFIED"),
            EffectiveAcceptance.SUPERSEDED,
            None,
            SettlementReadiness.SUPERSEDED,
        ),
        (
            _decision("REFUTED"),
            EffectiveAcceptance.SUSPENDED,
            None,
            SettlementReadiness.SUSPENDED,
        ),
        (
            _decision("VERIFIED"),
            EffectiveAcceptance.ACTIVE,
            None,
            SettlementReadiness.ACCEPTED_FOR_SETTLEMENT,
        ),
        (
            _decision("VERIFIED"),
            EffectiveAcceptance.NONE,
            None,
            SettlementReadiness.READY_FOR_ACCEPTANCE,
        ),
        (
            _decision("VERIFIED"),
            EffectiveAcceptance.NONE,
            _rejection(),
            SettlementReadiness.NOT_READY,
        ),
        (None, EffectiveAcceptance.NONE, None, SettlementReadiness.NOT_READY),
    ),
)
def test_settlement_readiness_priority(
    decision,
    acceptance,
    rejection,
    expected,
) -> None:
    assert (
        settlement_readiness(
            decision=decision,
            acceptance=acceptance,
            rejection=rejection,
        )
        is expected
    )


def test_transition_model_closes_replacement_semantics(
    acceptance_transition_dict,
    ephemeral_role_keys,
) -> None:
    withdrawn = dict(acceptance_transition_dict)
    withdrawn["transition"] = "withdrawn"
    withdrawn["replacement_acceptance_id"] = None
    withdrawn["replacement_acceptance_digest"] = None
    withdrawn = sign_payload(
        "acceptance-transition",
        withdrawn,
        ephemeral_role_keys["Acceptor"][0],
    )
    assert AcceptanceTransitionReceipt.model_validate(withdrawn).transition == "withdrawn"

    superseded = dict(acceptance_transition_dict)
    superseded["transition"] = "superseded"
    superseded["replacement_acceptance_id"] = "5" * 64
    superseded["replacement_acceptance_digest"] = "6" * 64
    superseded["causal_parent_ids"] = ["1" * 64, "3" * 64, "5" * 64]
    signed_superseded = sign_payload(
        "acceptance-transition",
        superseded,
        ephemeral_role_keys["Acceptor"][0],
    )
    assert (
        AcceptanceTransitionReceipt.model_validate(signed_superseded).transition
        == "superseded"
    )

    superseded["replacement_acceptance_id"] = superseded["target_acceptance_id"]
    superseded["causal_parent_ids"] = ["1" * 64, "3" * 64]
    signed_invalid = sign_payload(
        "acceptance-transition",
        superseded,
        ephemeral_role_keys["Acceptor"][0],
    )
    with pytest.raises(ValueError, match="replacement"):
        AcceptanceTransitionReceipt.model_validate(signed_invalid)


def test_transition_commit_is_exact_and_append_only(transition_case) -> None:
    before = read_settlement_snapshot(transition_case["ledger"])
    assert type(before).model_validate_json(before.model_dump_json()) == before
    assert before.effective_acceptance is EffectiveAcceptance.ACTIVE
    assert (
        before.settlement_readiness
        is SettlementReadiness.ACCEPTED_FOR_SETTLEMENT
    )
    transition = transition_case["transition"]
    assert (
        commit_acceptance_transition(transition_case["ledger"], transition)
        == transition
    )
    connection = sqlite3.connect(transition_case["ledger"])
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM acceptance_transitions"
        ).fetchone() == (1,)
        assert connection.execute(
            "SELECT COUNT(*) FROM acceptance_transition_parents"
        ).fetchone() == (2,)
    finally:
        connection.close()
    after = read_settlement_snapshot(transition_case["ledger"])
    assert after.effective_acceptance is EffectiveAcceptance.WITHDRAWN
    assert after.settlement_readiness is SettlementReadiness.WITHDRAWN


def test_transition_precommit_failure_has_zero_writes(transition_case) -> None:
    before = _table_snapshot(transition_case["ledger"])
    with pytest.raises(AcceptanceTransactionError, match="fault"):
        commit_acceptance_transition(
            transition_case["ledger"],
            transition_case["transition"],
            fault="before_commit",
        )
    assert _table_snapshot(transition_case["ledger"]) == before


def test_transition_commit_ack_loss_returns_committed_truth(
    transition_case,
) -> None:
    with pytest.raises(AcceptanceCommittedError) as raised:
        commit_acceptance_transition(
            transition_case["ledger"],
            transition_case["transition"],
            fault="commit_ack_loss",
        )
    assert raised.value.committed == transition_case["transition"]


def test_transition_failed_readback_is_indeterminate(transition_case) -> None:
    with pytest.raises(AcceptanceCommitIndeterminateError):
        commit_acceptance_transition(
            transition_case["ledger"],
            transition_case["transition"],
            fault="readback_failure",
        )


def test_transition_cleanup_failure_preserves_committed_truth(
    transition_case,
) -> None:
    with pytest.raises(AcceptanceCommittedError) as raised:
        commit_acceptance_transition(
            transition_case["ledger"],
            transition_case["transition"],
            fault="cleanup_failure",
        )
    assert raised.value.committed == transition_case["transition"]


def test_concurrent_transition_has_one_commit_winner(transition_case) -> None:
    def commit_once():
        try:
            return commit_acceptance_transition(
                transition_case["ledger"],
                transition_case["transition"],
            )
        except AcceptanceCommittedError as error:
            return error

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = tuple(executor.map(lambda _: commit_once(), range(2)))
    assert sum(
        isinstance(item, AcceptanceTransitionReceipt) for item in outcomes
    ) == 1
    assert sum(isinstance(item, AcceptanceCommittedError) for item in outcomes) == 1


def test_supersession_derives_superseded_readiness(
    transition_case,
    ephemeral_role_keys,
) -> None:
    raw = transition_case["transition"].model_dump(
        mode="json",
        exclude={"digest", "signature_alg", "signer_key_id", "signature"},
    )
    replacement_id = "6" * 64
    raw.update(
        transition_id="7" * 64,
        transition="superseded",
        replacement_acceptance_id=replacement_id,
        replacement_acceptance_digest="8" * 64,
        reason_code="REPLACED_DELIVERY",
        causal_parent_ids=sorted(
            [
                raw["target_acceptance_id"],
                raw["verification_decision_id"],
                replacement_id,
            ]
        ),
        nonce="6" * 64,
    )
    supersession = AcceptanceTransitionReceipt.model_validate(
        sign_payload(
            "acceptance-transition",
            raw,
            ephemeral_role_keys["Acceptor"][0],
        )
    )
    assert (
        commit_acceptance_transition(transition_case["ledger"], supersession)
        == supersession
    )
    snapshot = read_settlement_snapshot(transition_case["ledger"])
    assert snapshot.effective_acceptance is EffectiveAcceptance.SUPERSEDED
    assert snapshot.settlement_readiness is SettlementReadiness.SUPERSEDED


def test_transition_wrong_signer_is_zero_write(
    transition_case,
    ephemeral_role_keys,
) -> None:
    raw = transition_case["transition"].model_dump(
        mode="json",
        exclude={"digest", "signature_alg", "signer_key_id", "signature"},
    )
    invalid = AcceptanceTransitionReceipt.model_validate(
        sign_payload(
            "acceptance-transition",
            raw,
            ephemeral_role_keys["Manager"][0],
        )
    )
    before = _table_snapshot(transition_case["ledger"])
    with pytest.raises(AcceptanceTransactionError, match="WorkOrder"):
        commit_acceptance_transition(transition_case["ledger"], invalid)
    assert _table_snapshot(transition_case["ledger"]) == before


def test_settlement_snapshot_rejects_tampered_transition(transition_case) -> None:
    commit_acceptance_transition(
        transition_case["ledger"],
        transition_case["transition"],
    )
    connection = sqlite3.connect(transition_case["ledger"])
    try:
        connection.execute(
            "UPDATE acceptance_transitions SET transition_json = ?",
            (b"{}",),
        )
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(RuntimeError, match="transition"):
        read_settlement_snapshot(transition_case["ledger"])
