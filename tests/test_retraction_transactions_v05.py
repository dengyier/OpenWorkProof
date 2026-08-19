from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest

import openworkproof.evidence as evidence
import rfc8785
from openworkproof.models import RetractionReceiptV05, retraction_receipt_id
from openworkproof.retraction import (
    RetractionCommittedError,
    RetractionCommitIndeterminateError,
    RetractionTransactionError,
    commit_retraction_receipt,
    receipt_retraction_status,
    retraction_chain,
)
from openworkproof.signing import sign_payload

from test_retraction_receipt_v05 import _retraction_payload


@pytest.fixture
def retraction_case(
    tmp_path,
    signed_work_order,
    sidecar_receipt_factory,
    ephemeral_role_keys,
) -> dict[str, Any]:
    ledger = tmp_path / "retraction.sqlite3"
    evidence.initialize_ledger(ledger, signed_work_order)
    receipt = sidecar_receipt_factory(
        state_before="locally_verified",
        state_after="evidence_incomplete",
        event_type="system_event",
        event_name="proof_composed",
        sequence=1,
    )
    connection = evidence.connect_ledger(ledger)
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
    return {
        "ledger": ledger,
        "work_order": signed_work_order,
        "receipt": receipt,
        "keys": ephemeral_role_keys,
    }


def _signed_retraction_for(
    case: dict[str, Any],
    *,
    target_receipt_id: str,
    target_receipt_digest: str,
    reason: str = "evidence_refuted",
    effect: str = "refuted",
    retracted_at: str = "2026-01-01T01:00:00Z",
) -> RetractionReceiptV05:
    payload = _retraction_payload(
        target_receipt_id=target_receipt_id,
        target_receipt_digest=target_receipt_digest,
        retraction_reason=reason,
        retraction_effect=effect,
        retracted_at=retracted_at,
    )
    payload["work_order_digest"] = case["work_order"].digest
    payload["retraction_id"] = retraction_receipt_id(payload)
    return RetractionReceiptV05.model_validate(
        sign_payload(
            "retraction-receipt",
            payload,
            case["keys"]["Manager"][0],
            version="0.5",
        )
    )


def test_commit_retraction_receipt_roundtrip(retraction_case) -> None:
    case = retraction_case
    receipt = case["receipt"]
    retraction = _signed_retraction_for(
        case,
        target_receipt_id=receipt.receipt_id,
        target_receipt_digest=receipt.digest,
    )
    committed = commit_retraction_receipt(case["ledger"], retraction)
    assert committed.retraction_id == retraction.retraction_id
    assert receipt_retraction_status(case["ledger"], receipt.receipt_id) == "refuted"
    chain = retraction_chain(case["ledger"], receipt.receipt_id)
    assert tuple(item.retraction_id for item in chain) == (retraction.retraction_id,)


def test_commit_retraction_rejects_missing_target(retraction_case) -> None:
    case = retraction_case
    retraction = _signed_retraction_for(
        case,
        target_receipt_id="f" * 64,
        target_receipt_digest="e" * 64,
    )
    with pytest.raises(RetractionTransactionError):
        commit_retraction_receipt(case["ledger"], retraction)


def test_commit_retraction_rejects_digest_mismatch(retraction_case) -> None:
    case = retraction_case
    receipt = case["receipt"]
    retraction = _signed_retraction_for(
        case,
        target_receipt_id=receipt.receipt_id,
        target_receipt_digest="e" * 64,
    )
    with pytest.raises(RetractionTransactionError):
        commit_retraction_receipt(case["ledger"], retraction)


def test_commit_retraction_rejects_wrong_signer(retraction_case) -> None:
    case = retraction_case
    receipt = case["receipt"]
    payload = _retraction_payload(
        target_receipt_id=receipt.receipt_id,
        target_receipt_digest=receipt.digest,
    )
    payload["work_order_digest"] = case["work_order"].digest
    payload["retraction_id"] = retraction_receipt_id(payload)
    retraction = RetractionReceiptV05.model_validate(
        sign_payload(
            "retraction-receipt",
            payload,
            case["keys"]["Acceptor"][0],
            version="0.5",
        )
    )
    with pytest.raises(RetractionTransactionError):
        commit_retraction_receipt(case["ledger"], retraction)


def test_commit_retraction_rejects_time_inversion(retraction_case) -> None:
    case = retraction_case
    receipt = case["receipt"]
    retraction = _signed_retraction_for(
        case,
        target_receipt_id=receipt.receipt_id,
        target_receipt_digest=receipt.digest,
        retracted_at="2020-01-01T00:00:00Z",
    )
    with pytest.raises(RetractionTransactionError):
        commit_retraction_receipt(case["ledger"], retraction)


def test_commit_retraction_rejects_duplicate(retraction_case) -> None:
    case = retraction_case
    receipt = case["receipt"]
    retraction = _signed_retraction_for(
        case,
        target_receipt_id=receipt.receipt_id,
        target_receipt_digest=receipt.digest,
    )
    commit_retraction_receipt(case["ledger"], retraction)
    with pytest.raises(RetractionTransactionError):
        commit_retraction_receipt(case["ledger"], retraction)


def test_commit_retraction_before_commit_fault_is_zero_write(retraction_case) -> None:
    case = retraction_case
    receipt = case["receipt"]
    retraction = _signed_retraction_for(
        case,
        target_receipt_id=receipt.receipt_id,
        target_receipt_digest=receipt.digest,
    )
    with pytest.raises(RetractionTransactionError):
        commit_retraction_receipt(
            case["ledger"], retraction, fault="before_commit"
        )
    assert receipt_retraction_status(case["ledger"], receipt.receipt_id) == "standing"


def test_retraction_rows_are_immutable(retraction_case) -> None:
    case = retraction_case
    receipt = case["receipt"]
    retraction = _signed_retraction_for(
        case,
        target_receipt_id=receipt.receipt_id,
        target_receipt_digest=receipt.digest,
    )
    commit_retraction_receipt(case["ledger"], retraction)
    connection = evidence.connect_ledger(case["ledger"])
    try:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE retraction_receipts_v05 SET target_receipt_digest = ? "
                "WHERE retraction_id = ?",
                ("f" * 64, retraction.retraction_id),
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "DELETE FROM retraction_receipts_v05 "
                "WHERE retraction_id = ?",
                (retraction.retraction_id,),
            )
    finally:
        connection.close()


def test_commit_retraction_concurrent_single_winner(retraction_case) -> None:
    case = retraction_case
    receipt = case["receipt"]
    retraction = _signed_retraction_for(
        case,
        target_receipt_id=receipt.receipt_id,
        target_receipt_digest=receipt.digest,
    )

    def attempt() -> str:
        try:
            commit_retraction_receipt(case["ledger"], retraction)
            return "committed"
        except RetractionCommittedError:
            return "already"
        except RetractionTransactionError:
            return "rejected"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(lambda _: attempt(), range(2)))
    assert outcomes.count("committed") + outcomes.count("already") == 2
    assert receipt_retraction_status(case["ledger"], receipt.receipt_id) == "refuted"


def test_retraction_nonce_cannot_be_reused_across_targets(
    retraction_case,
) -> None:
    """Two retractions with different targets must not share a nonce: the
    nonce is a global single-use protocol value."""
    case = retraction_case
    receipt = case["receipt"]
    first = _signed_retraction_for(
        case,
        target_receipt_id=receipt.receipt_id,
        target_receipt_digest=receipt.digest,
    )
    commit_retraction_receipt(case["ledger"], first)
    # Second target: craft another committed receipt then retract with the
    # same nonce.
    second_receipt = case["receipt"]
    same_nonce = _signed_retraction_for(
        case,
        target_receipt_id=second_receipt.receipt_id,
        target_receipt_digest=second_receipt.digest,
    )
    # Force the same nonce by rebuilding the payload with first.nonce.
    payload = _retraction_payload(
        target_receipt_id=second_receipt.receipt_id,
        target_receipt_digest=second_receipt.digest,
    )
    payload["work_order_digest"] = case["work_order"].digest
    payload["nonce"] = first.nonce
    payload["retraction_id"] = retraction_receipt_id(payload)
    duplicate = RetractionReceiptV05.model_validate(
        sign_payload(
            "retraction-receipt",
            payload,
            case["keys"]["Manager"][0],
            version="0.5",
        )
    )
    with pytest.raises(RetractionTransactionError):
        commit_retraction_receipt(case["ledger"], duplicate)


def test_retraction_nonce_conflicts_with_committed_decision(
    retraction_case,
    sidecar_receipt_factory,
) -> None:
    """A retraction nonce must not collide with a nonce already used by any
    other protocol object (here: another committed receipt)."""
    case = retraction_case
    # A second committed receipt that consumed a nonce.
    second = sidecar_receipt_factory(
        state_before="locally_verified",
        state_after="evidence_incomplete",
        event_type="system_event",
        event_name="proof_composed",
        sequence=2,
    )
    # Give the second receipt a distinct id so both rows coexist.
    second = second.model_copy(
        update={"receipt_id": "7" * 64, "nonce": "5" * 64}
    )
    connection = evidence.connect_ledger(case["ledger"])
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
                second.receipt_id,
                second.work_order_digest,
                "5" * 64,
                second.sequence,
                second.previous_receipt_digest,
                evidence._canonical_json(second.model_dump(mode="json")),
            ),
        )
        connection.execute("COMMIT")
    finally:
        connection.close()
    receipt = case["receipt"]
    payload = _retraction_payload(
        target_receipt_id=receipt.receipt_id,
        target_receipt_digest=receipt.digest,
    )
    payload["work_order_digest"] = case["work_order"].digest
    payload["nonce"] = "5" * 64
    payload["retraction_id"] = retraction_receipt_id(payload)
    retraction = RetractionReceiptV05.model_validate(
        sign_payload(
            "retraction-receipt",
            payload,
            case["keys"]["Manager"][0],
            version="0.5",
        )
    )
    with pytest.raises(RetractionTransactionError):
        commit_retraction_receipt(case["ledger"], retraction)
