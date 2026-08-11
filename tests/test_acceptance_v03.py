from __future__ import annotations

import sqlite3

import pytest

import openworkproof.acceptance as acceptance
import openworkproof.evidence as evidence
from openworkproof.models import (
    AcceptanceTransitionReceipt,
    DecisionDraftRequest,
    VerificationProfileV02,
)
from openworkproof.scope import ObservedScope
from openworkproof.signing import sign_payload
from openworkproof.settlement import (
    SettlementReadiness,
    read_settlement_snapshot,
)
from openworkproof.verification import (
    commit_verification_arm_result_v03,
    commit_verification_decision_v03,
    commit_verification_profile,
)
from openworkproof.acceptance import commit_acceptance_transition
from test_verification_transactions_v03 import (
    _resign_arm_result_v03,
    _signed_decision_v03,
    _write_json_evidence,
    v03_transaction_case,
    verification_profile_v03,
)


def _commit_v03_decision(case):
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
    commit_verification_decision_v03(case["ledger"], decision)
    return decision


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


def _transition_for_v03(
    *,
    case,
    decision,
    signed_acceptance_receipt,
    transition: str,
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
        "verification_decision_digest": decision.digest,
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


def test_v03_verified_decision_is_the_closed_acceptance_authority(
    v03_transaction_case,
) -> None:
    case = v03_transaction_case
    decision = _commit_v03_decision(case)
    connection = evidence.connect_ledger(case["ledger"])
    try:
        record = acceptance._resolve_current_verification_record(connection)
        gated = acceptance._require_current_verified_decision_if_v02(connection)
    finally:
        connection.close()
    assert record == acceptance.CurrentVerificationRecord(
        protocol_version="0.3",
        decision_id=decision.decision_id,
        decision_digest=decision.digest,
        decision="VERIFIED",
    )
    assert gated == record


def test_v03_verified_decision_is_ready_for_acceptance_not_settlement(
    v03_transaction_case,
) -> None:
    case = v03_transaction_case
    decision = _commit_v03_decision(case)
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
def test_v03_acceptance_transition_routes_to_matching_protocol_family(
    v03_transaction_case,
    signed_acceptance_receipt,
    transition,
    expected_readiness,
) -> None:
    case = v03_transaction_case
    decision = _commit_v03_decision(case)
    _commit_acceptance_fixture(case["ledger"], signed_acceptance_receipt)
    receipt = _transition_for_v03(
        case=case,
        decision=decision,
        signed_acceptance_receipt=signed_acceptance_receipt,
        transition=transition,
    )
    assert commit_acceptance_transition(case["ledger"], receipt) == receipt
    connection = evidence.connect_ledger(case["ledger"])
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM acceptance_transitions"
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT COUNT(*) FROM acceptance_transitions_v03"
        ).fetchone() == (1,)
    finally:
        connection.close()
    snapshot = read_settlement_snapshot(case["ledger"])
    assert snapshot.settlement_readiness is expected_readiness


def test_v03_transition_rejects_fabricated_cross_version_decision_digest(
    v03_transaction_case,
    signed_acceptance_receipt,
) -> None:
    case = v03_transaction_case
    decision = _commit_v03_decision(case)
    _commit_acceptance_fixture(case["ledger"], signed_acceptance_receipt)
    valid = _transition_for_v03(
        case=case,
        decision=decision,
        signed_acceptance_receipt=signed_acceptance_receipt,
        transition="withdrawn",
    )
    payload = valid.model_dump(
        mode="json",
        exclude={"digest", "signature_alg", "signer_key_id", "signature"},
    )
    payload["verification_decision_digest"] = "3" * 64
    forged = AcceptanceTransitionReceipt.model_validate(
        sign_payload(
            "acceptance-transition",
            payload,
            case["keys"]["Acceptor"][0],
        )
    )
    with pytest.raises(
        acceptance.AcceptanceTransactionError, match="decision is not current"
    ):
        commit_acceptance_transition(case["ledger"], forged)
    connection = evidence.connect_ledger(case["ledger"])
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM acceptance_transitions_v03"
        ).fetchone() == (0,)
    finally:
        connection.close()


def test_same_decision_id_in_both_protocol_tables_is_ambiguous(
    v03_transaction_case,
) -> None:
    case = v03_transaction_case
    decision = _commit_v03_decision(case)
    connection = sqlite3.connect(case["ledger"])
    try:
        connection.execute(
            """
            INSERT INTO verification_decisions (
                decision_id, predecessor_id, decision_json
            ) VALUES (?, NULL, ?)
            """,
            (decision.decision_id, b'{"fabricated":"v0.2-row"}'),
        )
        connection.commit()
    finally:
        connection.close()
    connection = evidence.connect_ledger(case["ledger"])
    try:
        with pytest.raises(
            acceptance.AcceptanceTransactionError, match="ambiguous"
        ):
            acceptance._resolve_current_verification_record(connection)
    finally:
        connection.close()


def test_dual_profile_families_are_rejected_as_ambiguous(
    v03_transaction_case,
    signed_subject_claim,
    signed_verification_profile,
    ephemeral_role_keys,
) -> None:
    case = v03_transaction_case
    _commit_v03_decision(case)
    profile_payload = signed_verification_profile.model_dump(
        mode="json",
        exclude={"digest", "signature_alg", "signer_key_id", "signature"},
    )
    profile_payload["nonce"] = "a" * 64
    v02_profile = VerificationProfileV02.model_validate(
        sign_payload(
            "verification-profile",
            profile_payload,
            ephemeral_role_keys["Manager"][0],
        )
    )
    commit_verification_profile(
        case["ledger"], signed_subject_claim, v02_profile
    )
    connection = evidence.connect_ledger(case["ledger"])
    try:
        with pytest.raises(
            acceptance.AcceptanceTransactionError, match="ambiguous"
        ):
            acceptance._resolve_current_verification_record(connection)
    finally:
        connection.close()
    with pytest.raises(Exception, match="profile history"):
        read_settlement_snapshot(case["ledger"])


def test_missing_v03_decision_cannot_open_acceptance_gate(
    v03_transaction_case,
) -> None:
    connection = evidence.connect_ledger(v03_transaction_case["ledger"])
    try:
        with pytest.raises(
            acceptance.AcceptanceTransactionError, match="current VERIFIED"
        ):
            acceptance._require_current_verified_decision_if_v02(connection)
    finally:
        connection.close()


def test_v03_unknown_decision_cannot_open_acceptance_gate(
    v03_transaction_case,
) -> None:
    case = v03_transaction_case
    original = case["results"][1]
    manifest = case["manifest"]
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
        evidence_complete=False,
    )
    scope_ref = _write_json_evidence(
        case["tmp_path"],
        original.scope_evidence_refs[0].path,
        observed.model_dump(mode="json"),
    )
    unknown = _resign_arm_result_v03(
        case,
        original,
        scope_expectation_status="indeterminate",
        scope_evidence_refs=[scope_ref],
        reason_codes=[
            "MUTATION_APPLIED",
            "MUTATION_CAUGHT",
            "SCOPE_EVIDENCE_MISSING",
        ],
    )
    case["results"] = (case["results"][0], unknown)
    decision = _commit_v03_decision(case)
    assert decision.decision == "UNKNOWN"
    connection = evidence.connect_ledger(case["ledger"])
    try:
        with pytest.raises(
            acceptance.AcceptanceTransactionError, match="current VERIFIED"
        ):
            acceptance._require_current_verified_decision_if_v02(connection)
    finally:
        connection.close()


def test_v03_refuted_decision_cannot_open_acceptance_gate(
    v03_transaction_case,
) -> None:
    case = v03_transaction_case
    refuted = _resign_arm_result_v03(
        case,
        case["results"][1],
        expectation_status="contradicted",
        reason_codes=["MUTATION_APPLIED", "MUTATION_SURVIVED"],
    )
    case["results"] = (case["results"][0], refuted)
    decision = _commit_v03_decision(case)
    assert decision.decision == "REFUTED"
    connection = evidence.connect_ledger(case["ledger"])
    try:
        with pytest.raises(
            acceptance.AcceptanceTransactionError, match="current VERIFIED"
        ):
            acceptance._require_current_verified_decision_if_v02(connection)
    finally:
        connection.close()
