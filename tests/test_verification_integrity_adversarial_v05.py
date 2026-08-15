from __future__ import annotations

import hashlib
import json
import sqlite3
from typing import Any

import pytest
import rfc8785

from openworkproof import evidence
from openworkproof.delivery_package import export_delivery_package
from openworkproof.models import (
    DecisionDraftRequest,
    VerificationArmResultV05,
    VerificationProfileV05,
)
from openworkproof.signing import sign_payload
from openworkproof.verification import (
    VerificationCommittedError,
    VerificationTransactionError,
    commit_verification_arm_result_v05,
    commit_verification_decision_v05,
    commit_verification_profile_v05,
    load_verification_profile_v05,
    prepare_verification_decision_v05,
)

from test_control_integrity_v05 import (
    _assess_control,
    _control_observation_payload,
    _negative_results,
    control_case,
)
from test_verification_integrity_transactions_v05 import (
    _compose_v05,
    _resign_arm_result_v05,
    _signed_decision_v05,
    _v05_control_observation,
    _v05_population_observation,
    v05_transaction_case,
    verification_profile_v03,
)

# ---------------------------------------------------------------------------
# Task 12: the specification section 12 fifteen-class adversarial matrix.
# Every signed semantic tamper is rebuilt and re-signed with the authorized
# test key so the semantic failure cannot be conflated with a bad signature;
# a companion bad-signature test pins the two error classes apart.
# ---------------------------------------------------------------------------


def _resigned_tamper(case, result, mutate) -> VerificationArmResultV05:
    raw = result.model_dump(
        mode="json",
        exclude={"digest", "signature_alg", "signer_key_id", "signature"},
    )
    mutate(raw)
    return VerificationArmResultV05.model_validate(
        sign_payload(
            "verification-arm-result",
            raw,
            case["keys"]["Verifier"][0],
            version="0.5",
        )
    )


def _repaired_profile(case) -> VerificationProfileV05:
    raw = case["profile"].model_dump(
        mode="json",
        exclude={"digest", "signature_alg", "signer_key_id", "signature"},
    )
    raw["profile_id"] = "7" * 64
    raw["nonce"] = "e" * 64
    return VerificationProfileV05.model_validate(
        sign_payload(
            "verification-profile",
            raw,
            case["keys"]["Manager"][0],
            version="0.5",
        )
    )


def _commit_full_chain(case) -> VerificationProfileV05:
    commit_verification_profile_v05(case["ledger"], case["profile"])
    for result in case["results"]:
        commit_verification_arm_result_v05(case["ledger"], result)
    return case["profile"]


# ---------------------------------------------------------------------------
# Attack 7: same fixture failure with a changed error or predicate signature.
# ---------------------------------------------------------------------------


def test_control_true_failure_with_changed_error_or_predicate_is_mismatched(
    control_case: dict[str, Any],
) -> None:
    """Spec section 12 attack 7: fixture still fails, signature differs.

    The failure is reported through a closed execution-failure reason code
    with a zero exit code, so the derivation must classify the observation
    as a target failure whose signature drifted from the registered
    expectation: ``mismatched`` with ``CONTROL_FAILURE_SIGNATURE_MISMATCH``.
    Deriving ``survived`` here would mask a real failure as a green control.
    """
    case = control_case
    contract = case["profile"].control_contracts[0]
    drifted = _control_observation_payload(
        contract,
        control_status="mismatched",
        exit_codes=[0],
        signature={
            "execution_status": "completed",
            "exit_codes": [0],
            "reason_codes": ["EXEC_COMMAND_FAILED"],
            "predicate_ids": ["tests_passed"],
            "required_evidence_purposes": ["test-result"],
        },
    )
    assessment = _assess_control(
        case,
        _negative_results(case, control_observation=drifted),
    )
    assert assessment.status == "mismatched"
    assert "CONTROL_FAILURE_SIGNATURE_MISMATCH" in assessment.reason_codes

    # Companion guard: claiming survived for the same drifted failure is a
    # contradiction between claimed and derived status and must be rejected.
    lying = _control_observation_payload(
        contract,
        control_status="survived",
        exit_codes=[0],
        signature={
            "execution_status": "completed",
            "exit_codes": [0],
            "reason_codes": ["EXEC_COMMAND_FAILED"],
            "predicate_ids": ["tests_passed"],
            "required_evidence_purposes": ["test-result"],
        },
    )
    with pytest.raises(ValueError, match="claims survived but derives mismatched"):
        _assess_control(
            case,
            _negative_results(case, control_observation=lying),
        )


# ---------------------------------------------------------------------------
# Attack 1-5: population tamper matrix at the end-to-end decision layer.
# ---------------------------------------------------------------------------


def test_attack_1_eligible_400_selected_zero_cannot_report_verified(
    v05_transaction_case,
) -> None:
    """eligible=400 / selected=0 must derive capture_failed -> UNKNOWN."""
    case = v05_transaction_case
    commit_verification_profile_v05(case["ledger"], case["profile"])
    results = []
    for kind, result in zip(("positive", "negative"), case["results"], strict=True):
        observations = [
            _v05_population_observation(
                case["tmp_path"],
                contract,
                suffix=f"attack1-{kind}-{contract.member_kind}",
                eligible_seen=400,
                selected_count=0,
            )
            for contract in case["profile"].population_contracts
        ]
        tampered = _resign_arm_result_v05(
            case, result, population_observations=observations
        )
        commit_verification_arm_result_v05(case["ledger"], tampered)
        results.append(tampered)
    draft = _compose_v05(case, results=tuple(results))
    assert draft.decision == "UNKNOWN"
    assert draft.integrity_assessment.population_status == "capture_failed"
    assert "POPULATION_CAPTURE_FAILED" in draft.integrity_assessment.reason_codes


def test_attack_2_zero_eligible_with_nonempty_selected_is_rejected(
    v05_transaction_case,
) -> None:
    """A fabricated non-empty selected set with zero eligible cannot validate."""
    case = v05_transaction_case
    observations = [
        _v05_population_observation(
            case["tmp_path"],
            contract,
            suffix=f"attack2-{contract.member_kind}",
            eligible_seen=0,
            selected_count=0,
        )
        for contract in case["profile"].population_contracts
    ]
    observations[0]["selected_count"] = 1
    observations[0]["selected_population_digest"] = "1" * 64
    with pytest.raises(ValueError, match="selected_count must not exceed"):
        _resign_arm_result_v05(
            case,
            case["results"][0],
            population_observations=observations,
        )


def test_attack_3_same_counts_changed_rule_digest_fails_closed(
    v05_transaction_case,
) -> None:
    """Same counts with a swapped selector engine digest cannot commit."""
    case = v05_transaction_case
    commit_verification_profile_v05(case["ledger"], case["profile"])
    tampered = _resigned_tamper(
        case,
        case["results"][0],
        lambda raw: raw["population_observations"][0].update(
            {"selector_engine_digest": "f" * 64}
        ),
    )
    with pytest.raises(VerificationTransactionError, match="do not replay"):
        commit_verification_arm_result_v05(case["ledger"], tampered)


def test_attack_3_bad_signature_class_is_distinct_from_semantic_drift(
    v05_transaction_case,
) -> None:
    """The same drift signed by the wrong role must fail as a signature error."""
    case = v05_transaction_case
    commit_verification_profile_v05(case["ledger"], case["profile"])
    raw = case["results"][0].model_dump(
        mode="json",
        exclude={"digest", "signature_alg", "signer_key_id", "signature"},
    )
    raw["population_observations"][0]["selector_engine_digest"] = "f" * 64
    with pytest.raises(ValueError, match="signer must equal verifier key"):
        VerificationArmResultV05.model_validate(
            sign_payload(
                "verification-arm-result",
                raw,
                case["keys"]["Manager"][0],
                version="0.5",
            )
        )


def test_attack_4_same_counts_changed_member_digest_fails_closed(
    v05_transaction_case,
) -> None:
    """Same counts with a changed eligible member digest cannot commit."""
    case = v05_transaction_case
    commit_verification_profile_v05(case["ledger"], case["profile"])
    tampered = _resigned_tamper(
        case,
        case["results"][0],
        lambda raw: raw["population_observations"][0].update(
            {"eligible_population_digest": "a" * 64}
        ),
    )
    with pytest.raises(VerificationTransactionError, match="do not replay"):
        commit_verification_arm_result_v05(case["ledger"], tampered)


def test_attack_5_cross_arm_population_mismatch_is_unknown(
    v05_transaction_case,
) -> None:
    """Positive/negative arms reporting different eligible sets -> UNKNOWN."""
    case = v05_transaction_case
    commit_verification_profile_v05(case["ledger"], case["profile"])
    inflated = [
        _v05_population_observation(
            case["tmp_path"],
            contract,
            suffix=f"attack5-{contract.member_kind}",
            eligible_seen=len(contract.declared_selected_member_ids) + 1,
            selected_count=len(contract.declared_selected_member_ids),
        )
        for contract in case["profile"].population_contracts
    ]
    positive = _resign_arm_result_v05(
        case, case["results"][0], population_observations=inflated
    )
    commit_verification_arm_result_v05(case["ledger"], positive)
    commit_verification_arm_result_v05(case["ledger"], case["results"][1])
    draft = _compose_v05(case, results=(positive, case["results"][1]))
    assert draft.decision == "UNKNOWN"
    assert draft.integrity_assessment.population_status == "drifted"
    assert "POPULATION_CROSS_ARM_MISMATCH" in draft.integrity_assessment.reason_codes


# ---------------------------------------------------------------------------
# Attack 6, 8, 9: control tamper matrix.
# ---------------------------------------------------------------------------


def test_attack_6_replaced_fixture_with_reused_control_id_is_unknown(
    v05_transaction_case,
) -> None:
    """A swapped fixture under a reused control id derives mismatched."""
    case = v05_transaction_case
    commit_verification_profile_v05(case["ledger"], case["profile"])
    commit_verification_arm_result_v05(case["ledger"], case["results"][0])
    contract = case["profile"].control_contracts[0]
    control = _v05_control_observation(
        case["tmp_path"],
        contract,
        arm_kind="negative",
        control_status="mismatched",
        fixture_digest="d" * 64,
    )
    negative = _resign_arm_result_v05(
        case, case["results"][1], control_observation=control
    )
    commit_verification_arm_result_v05(case["ledger"], negative)
    draft = _compose_v05(case, results=(case["results"][0], negative))
    assert draft.decision == "UNKNOWN"
    assert draft.integrity_assessment.control_status == "mismatched"
    assert "CONTROL_FIXTURE_DRIFT" in draft.integrity_assessment.reason_codes


def test_attack_8_unapplied_provocation_is_unknown(
    v05_transaction_case,
) -> None:
    """A provocation that was never applied cannot reach VERIFIED."""
    case = v05_transaction_case
    commit_verification_profile_v05(case["ledger"], case["profile"])
    commit_verification_arm_result_v05(case["ledger"], case["results"][0])
    contract = case["profile"].control_contracts[0]
    control = _v05_control_observation(
        case["tmp_path"],
        contract,
        arm_kind="negative",
        control_status="unavailable",
        execution_status="evidence_unavailable",
    )
    negative = _resign_arm_result_v05(
        case,
        case["results"][1],
        mutation_status="not_applied",
        expectation_status="indeterminate",
        reason_codes=["MUTATION_NOT_APPLIED"],
        control_observation=control,
    )
    commit_verification_arm_result_v05(case["ledger"], negative)
    draft = _compose_v05(case, results=(case["results"][0], negative))
    assert draft.decision == "UNKNOWN"
    assert draft.integrity_assessment.control_status == "unavailable"
    assert "CONTROL_EVIDENCE_MISSING" in draft.integrity_assessment.reason_codes


def test_attack_9_infrastructure_only_failure_cannot_commit_as_proven(
    v05_transaction_case,
) -> None:
    """A dependency-only failure claimed proven is an inconsistent status."""
    case = v05_transaction_case
    commit_verification_profile_v05(case["ledger"], case["profile"])
    commit_verification_arm_result_v05(case["ledger"], case["results"][0])
    contract = case["profile"].control_contracts[0]
    control = _v05_control_observation(
        case["tmp_path"],
        contract,
        arm_kind="negative",
        control_status="proven",
        signature={
            **contract.expected_failure_signature.model_dump(mode="json"),
            "reason_codes": ["EXEC_DEPENDENCY_DRIFT"],
        },
    )
    negative = _resign_arm_result_v05(
        case, case["results"][1], control_observation=control
    )
    with pytest.raises(
        VerificationTransactionError, match="claims an inconsistent status"
    ):
        commit_verification_arm_result_v05(case["ledger"], negative)


# ---------------------------------------------------------------------------
# Attack 10-12: lifecycle reuse matrix.
# ---------------------------------------------------------------------------


def test_attack_10_result_after_profile_expiry_is_rejected(
    v05_transaction_case,
) -> None:
    case = v05_transaction_case
    commit_verification_profile_v05(case["ledger"], case["profile"])
    stale = _resign_arm_result_v05(
        case, case["results"][0], created_at="2026-01-01T01:30:00Z"
    )
    with pytest.raises(VerificationTransactionError, match="signature is invalid"):
        commit_verification_arm_result_v05(case["ledger"], stale)


def test_attack_10_decision_after_profile_expiry_is_rejected(
    v05_transaction_case,
) -> None:
    case = v05_transaction_case
    _commit_full_chain(case)
    with pytest.raises(VerificationTransactionError, match="preparation failed"):
        _signed_decision_v05(
            case,
            DecisionDraftRequest(
                decision_id="c" * 64,
                decided_at="2026-01-01T01:30:00Z",
                nonce="d" * 64,
            ),
        )


def test_attack_11_result_referencing_unknown_profile_is_rejected(
    v05_transaction_case,
) -> None:
    case = v05_transaction_case
    commit_verification_profile_v05(case["ledger"], case["profile"])
    orphan = _resign_arm_result_v05(case, case["results"][0], profile_digest="f" * 64)
    with pytest.raises(VerificationTransactionError):
        commit_verification_arm_result_v05(case["ledger"], orphan)


def test_attack_11_profile_signed_by_wrong_role_is_rejected(
    v05_transaction_case,
) -> None:
    case = v05_transaction_case
    raw = case["profile"].model_dump(
        mode="json",
        exclude={"digest", "signature_alg", "signer_key_id", "signature"},
    )
    raw["nonce"] = "c" * 64
    forged = VerificationProfileV05.model_validate(
        sign_payload(
            "verification-profile",
            raw,
            case["keys"]["Verifier"][0],
            version="0.5",
        )
    )
    with pytest.raises(VerificationTransactionError, match="Manager signature"):
        commit_verification_profile_v05(case["ledger"], forged)


def test_attack_11_expired_profile_is_rejected(v05_transaction_case) -> None:
    case = v05_transaction_case
    raw = case["profile"].model_dump(
        mode="json",
        exclude={"digest", "signature_alg", "signer_key_id", "signature"},
    )
    raw["created_at"] = "2025-01-01T00:00:00Z"
    expired = VerificationProfileV05.model_validate(
        sign_payload(
            "verification-profile",
            raw,
            case["keys"]["Manager"][0],
            version="0.5",
        )
    )
    with pytest.raises(VerificationTransactionError, match="validity"):
        commit_verification_profile_v05(case["ledger"], expired)


def test_attack_12_reuse_after_repair_fails_closed(v05_transaction_case) -> None:
    """Repairs supersede by decision; stale bytes and profile duplication fail closed."""
    case = v05_transaction_case
    _commit_full_chain(case)
    first = _signed_decision_v05(
        case,
        DecisionDraftRequest(
            decision_id="c" * 64,
            decided_at="2026-01-01T00:20:00Z",
            nonce="d" * 64,
        ),
    )
    commit_verification_decision_v05(case["ledger"], first)
    second = _signed_decision_v05(
        case,
        DecisionDraftRequest(
            decision_id="e" * 64,
            decided_at="2026-01-01T00:21:00Z",
            nonce="f" * 64,
        ),
    )
    assert second.supersedes_decision_id == first.decision_id
    commit_verification_decision_v05(case["ledger"], second)

    # (a) After the repair decision exists, the old decision bytes cannot be
    #     committed again: its nonce is spent and it is no longer the truth.
    with pytest.raises(VerificationTransactionError):
        commit_verification_decision_v05(case["ledger"], first)

    # (b) The storage boundary allows exactly one profile per subject claim:
    #     a second "repaired" profile row is physically rejected.
    repaired = _repaired_profile(case)
    with pytest.raises(VerificationTransactionError, match="transaction failed"):
        commit_verification_profile_v05(case["ledger"], repaired)


# ---------------------------------------------------------------------------
# Attack 13: physical corruption probes over every v0.5 row family.
# ---------------------------------------------------------------------------


def _corrupt_row(case, table: str, column: str, value, *, where: str, who: str) -> None:
    connection = evidence.connect_ledger(case["ledger"])
    try:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(f"DROP TRIGGER {table}_are_immutable_update")
        connection.execute(
            f"UPDATE {table} SET {column} = ? WHERE {where} = ?", (value, who)
        )
        connection.execute("COMMIT")
    finally:
        connection.close()


def test_attack_13_corrupted_profile_json_fails_closed(v05_transaction_case) -> None:
    case = v05_transaction_case
    commit_verification_profile_v05(case["ledger"], case["profile"])
    _corrupt_row(
        case,
        "verification_profiles_v05",
        "profile_json",
        sqlite3.Binary(b"\x00"),
        where="profile_id",
        who=case["profile"].profile_id,
    )
    with pytest.raises(VerificationTransactionError, match="canonical"):
        load_verification_profile_v05(case["ledger"], case["profile"].profile_id)


def test_attack_13_corrupted_arm_result_json_fails_closed(
    v05_transaction_case,
) -> None:
    case = v05_transaction_case
    _commit_full_chain(case)
    _corrupt_row(
        case,
        "verification_arm_results_v05",
        "arm_result_json",
        sqlite3.Binary(b"\x00"),
        where="arm_result_id",
        who=case["results"][0].arm_result_id,
    )
    with pytest.raises(VerificationTransactionError):
        prepare_verification_decision_v05(
            case["ledger"],
            DecisionDraftRequest(
                decision_id="c" * 64,
                decided_at="2026-01-01T00:20:00Z",
                nonce="d" * 64,
            ),
        )


def test_attack_13_corrupted_decision_json_fails_closed(v05_transaction_case) -> None:
    case = v05_transaction_case
    _commit_full_chain(case)
    decision = _signed_decision_v05(
        case,
        DecisionDraftRequest(
            decision_id="c" * 64,
            decided_at="2026-01-01T00:20:00Z",
            nonce="d" * 64,
        ),
    )
    commit_verification_decision_v05(case["ledger"], decision)
    _corrupt_row(
        case,
        "verification_decisions_v05",
        "decision_json",
        sqlite3.Binary(b"\x00"),
        where="decision_id",
        who=decision.decision_id,
    )
    with pytest.raises(VerificationTransactionError):
        prepare_verification_decision_v05(
            case["ledger"],
            DecisionDraftRequest(
                decision_id="c" * 64,
                decided_at="2026-01-01T00:20:00Z",
                nonce="d" * 64,
            ),
        )


def test_attack_13_dangling_decision_parent_relation_fails_closed(
    v05_transaction_case,
) -> None:
    case = v05_transaction_case
    _commit_full_chain(case)
    decision = _signed_decision_v05(
        case,
        DecisionDraftRequest(
            decision_id="c" * 64,
            decided_at="2026-01-01T00:20:00Z",
            nonce="d" * 64,
        ),
    )
    commit_verification_decision_v05(case["ledger"], decision)
    connection = evidence.connect_ledger(case["ledger"])
    try:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            "DROP TRIGGER verification_decision_parents_v05_are_immutable_delete"
        )
        connection.execute(
            "DELETE FROM verification_decision_parents_v05 "
            "WHERE decision_id = ?",
            (decision.decision_id,),
        )
        connection.execute("COMMIT")
    finally:
        connection.close()
    with pytest.raises(VerificationTransactionError):
        prepare_verification_decision_v05(
            case["ledger"],
            DecisionDraftRequest(
                decision_id="c" * 64,
                decided_at="2026-01-01T00:20:00Z",
                nonce="d" * 64,
            ),
        )


# ---------------------------------------------------------------------------
# Attack 14: COMMIT happened but the ACK disappeared.
# ---------------------------------------------------------------------------


def test_attack_14_ack_loss_is_committed_truth_for_arm_and_decision(
    v05_transaction_case,
) -> None:
    case = v05_transaction_case
    commit_verification_profile_v05(case["ledger"], case["profile"])
    with pytest.raises(VerificationCommittedError) as raised:
        commit_verification_arm_result_v05(
            case["ledger"], case["results"][0], fault="commit_ack_loss"
        )
    assert raised.value.committed == case["results"][0]
    commit_verification_arm_result_v05(case["ledger"], case["results"][1])
    decision = _signed_decision_v05(
        case,
        DecisionDraftRequest(
            decision_id="c" * 64,
            decided_at="2026-01-01T00:20:00Z",
            nonce="d" * 64,
        ),
    )
    with pytest.raises(VerificationCommittedError) as raised:
        commit_verification_decision_v05(
            case["ledger"], decision, fault="commit_ack_loss"
        )
    assert raised.value.committed == decision
    draft = _compose_v05(case)
    assert draft.decision == "VERIFIED"


# ---------------------------------------------------------------------------
# Attack 15: public package leakage probe.
# ---------------------------------------------------------------------------


def test_attack_15_public_package_leaks_no_locator_fixture_or_absolute_path(
    v05_transaction_case,
) -> None:
    case = v05_transaction_case
    _commit_full_chain(case)
    decision = _signed_decision_v05(
        case,
        DecisionDraftRequest(
            decision_id="c" * 64,
            decided_at="2026-01-01T00:20:00Z",
            nonce="d" * 64,
        ),
    )
    commit_verification_decision_v05(case["ledger"], decision)
    output = case["tmp_path"] / "public-package"
    export_delivery_package(case["ledger"], output, privacy_view="public")
    fixture_bytes = (case["tmp_path"] / "control/negative.json").read_bytes()
    absolute = str(case["tmp_path"]).encode("utf-8")
    for package_file in output.rglob("*"):
        if not package_file.is_file():
            continue
        content = package_file.read_bytes()
        assert b"results/" not in content
        assert b"evidence/" not in content
        assert b"scope/" not in content
        assert absolute not in content
        assert fixture_bytes not in content


def _row_committed_at(case, table: str, column: str, *, where: str, who: str) -> str:
    connection = evidence.connect_ledger(case["ledger"])
    try:
        return connection.execute(
            f"SELECT {column} FROM {table} WHERE {where} = ?", (who,)
        ).fetchone()[0]
    finally:
        connection.close()


@pytest.mark.parametrize("family", ("profile", "arm_result", "decision"))
def test_attack_13_tampered_committed_at_breaks_exact_truth_readback(
    v05_transaction_case, family: str
) -> None:
    """Spec attack 13: an inverted committed_at must break exact-truth replay.

    The committed_at column is the append-only ordering witness consulted by
    every v0.5 readback; tampering it must make the exact-truth readback for
    the affected row fail, never silently accept the row as committed truth.
    """
    case = v05_transaction_case
    from openworkproof.verification import (
        _exact_arm_result_v05_readback,
        _exact_decision_v05_readback,
        _exact_profile_v05_readback,
    )

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

    if family == "profile":
        table, column, who = (
            "verification_profiles_v05",
            "committed_at",
            case["profile"].profile_id,
        )
        original = _row_committed_at(
            case, table, column, where="profile_id", who=who
        )
        _corrupt_row(
            case, table, column, "2020-01-01T00:00:00Z",
            where="profile_id", who=who,
        )
        assert (
            _exact_profile_v05_readback(
                case["ledger"], profile=case["profile"], committed_at=original
            )
            is False
        )
    elif family == "arm_result":
        table, column, who = (
            "verification_arm_results_v05",
            "committed_at",
            case["results"][0].arm_result_id,
        )
        original = _row_committed_at(
            case, table, column, where="arm_result_id", who=who
        )
        _corrupt_row(
            case, table, column, "2020-01-01T00:00:00Z",
            where="arm_result_id", who=who,
        )
        assert (
            _exact_arm_result_v05_readback(
                case["ledger"], case["results"][0], original
            )
            is False
        )
    else:
        table, column, who = (
            "verification_decisions_v05",
            "committed_at",
            decision.decision_id,
        )
        original = _row_committed_at(
            case, table, column, where="decision_id", who=who
        )
        _corrupt_row(
            case, table, column, "2020-01-01T00:00:00Z",
            where="decision_id", who=who,
        )
        assert (
            _exact_decision_v05_readback(case["ledger"], decision, original)
            is False
        )


def test_hardening_boundary_infra_drift_with_zero_exit_still_derives_survived(
    control_case,
) -> None:
    """Guard: infra-only failure codes are NOT target failures.

    EXEC_DEPENDENCY_DRIFT with a zero exit code derives survived (the fixture
    did not fail; the run drifted for infrastructure reasons), so the
    hardening must never classify it as mismatched. Pinned for regression.
    """
    case = control_case
    contract = case["profile"].control_contracts[0]
    expected = contract.expected_failure_signature.model_dump(mode="json")
    drifted = _control_observation_payload(
        contract,
        control_status="survived",
        exit_codes=[0],
        signature={
            **expected,
            "exit_codes": [0],
            "reason_codes": ["EXEC_DEPENDENCY_DRIFT"],
        },
    )
    assessment = _assess_control(
        case,
        _negative_results(case, control_observation=drifted),
    )
    assert assessment.status == "survived"
    assert "CONTROL_SURVIVED" in assessment.reason_codes


def _full_chain_with_decision(case):
    _commit_full_chain(case)
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


def test_audit_i1_decision_load_rejects_missing_arm_rows(v05_transaction_case) -> None:
    """Audit I1: the current decision must not survive deletion of its arm
    result rows — the loader must fail closed."""
    case = v05_transaction_case
    _full_chain_with_decision(case)
    connection = evidence.connect_ledger(case["ledger"])
    try:
        connection.execute("PRAGMA foreign_keys = OFF")
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            "DROP TRIGGER verification_arm_results_v05_are_immutable_delete"
        )
        connection.execute("DELETE FROM verification_arm_results_v05")
        connection.execute("COMMIT")
    finally:
        connection.close()
    with pytest.raises(VerificationTransactionError, match="unavailable"):
        prepare_verification_decision_v05(
            case["ledger"],
            DecisionDraftRequest(
                decision_id="e" * 64,
                decided_at="2026-01-01T00:21:00Z",
                nonce="f" * 64,
            ),
        )


def test_audit_i1_decision_load_rejects_noncanonical_committed_at(
    v05_transaction_case,
) -> None:
    """Audit I1: a non-canonical committed_at on the decision row must be
    rejected by the current-decision loader."""
    case = v05_transaction_case
    decision = _full_chain_with_decision(case)
    _corrupt_row(
        case,
        "verification_decisions_v05",
        "committed_at",
        "2026-01-01",
        where="decision_id",
        who=decision.decision_id,
    )
    with pytest.raises(VerificationTransactionError, match="committed_at"):
        prepare_verification_decision_v05(
            case["ledger"],
            DecisionDraftRequest(
                decision_id="e" * 64,
                decided_at="2026-01-01T00:21:00Z",
                nonce="f" * 64,
            ),
        )


def test_audit_i1_decision_load_rejects_inverted_committed_at(
    v05_transaction_case,
) -> None:
    """Audit I1: a decision committed before its arm results violates the
    causal order and must be rejected."""
    case = v05_transaction_case
    decision = _full_chain_with_decision(case)
    _corrupt_row(
        case,
        "verification_decisions_v05",
        "committed_at",
        "2020-01-01T00:00:00Z",
        where="decision_id",
        who=decision.decision_id,
    )
    with pytest.raises(VerificationTransactionError, match="causal order"):
        prepare_verification_decision_v05(
            case["ledger"],
            DecisionDraftRequest(
                decision_id="e" * 64,
                decided_at="2026-01-01T00:21:00Z",
                nonce="f" * 64,
            ),
        )


def test_audit_i1_decision_load_rejects_swapped_arm_rows(v05_transaction_case) -> None:
    """Audit I1: swapping arm result row contents between ids is physically
    blocked by the storage layer (UNIQUE arm_result_json), and any content
    tamper that does land fails the current-decision loader."""
    case = v05_transaction_case
    _full_chain_with_decision(case)
    connection = evidence.connect_ledger(case["ledger"])
    try:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            "DROP TRIGGER verification_arm_results_v05_are_immutable_update"
        )
        rows = connection.execute(
            "SELECT arm_result_id, arm_result_json "
            "FROM verification_arm_results_v05 ORDER BY arm_result_id"
        ).fetchall()
        assert len(rows) == 2
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE verification_arm_results_v05 SET arm_result_json = ? "
                "WHERE arm_result_id = ?",
                (rows[1][1], rows[0][0]),
            )
        connection.execute("ROLLBACK")
    finally:
        connection.close()
    _corrupt_row(
        case,
        "verification_arm_results_v05",
        "arm_result_json",
        sqlite3.Binary(b"\x00"),
        where="arm_result_id",
        who=case["results"][0].arm_result_id,
    )
    with pytest.raises(VerificationTransactionError):
        prepare_verification_decision_v05(
            case["ledger"],
            DecisionDraftRequest(
                decision_id="e" * 64,
                decided_at="2026-01-01T00:21:00Z",
                nonce="f" * 64,
            ),
        )


def _control_observation_with_evidence(
    case,
    *,
    evidence_document,
    control_status="proven",
) -> VerificationArmResultV05:
    from openworkproof.verification import VerificationTransactionError

    contract = case["profile"].control_contracts[0]
    payload = _v05_control_observation(
        case["tmp_path"], contract, arm_kind="negative"
    )
    ref_path = payload["evidence_refs"][0]["path"]
    raw = rfc8785.dumps(evidence_document)
    (case["tmp_path"] / ref_path).write_bytes(raw)
    payload["evidence_refs"] = [
        {
            "path": ref_path,
            "sha256": hashlib.sha256(raw).hexdigest(),
            "media_type": "application/json",
            "size_bytes": len(raw),
        }
    ]
    return _resign_arm_result_v05(
        case, case["results"][1], control_observation=payload
    )


def test_audit_i2_noncanonical_control_evidence_cannot_be_proven(
    v05_transaction_case,
) -> None:
    """Audit I2: a bare ``{"arm": "negative"}`` control-evidence blob must
    never resolve to proven — the closed evidence resolver rejects it."""
    case = v05_transaction_case
    commit_verification_profile_v05(case["ledger"], case["profile"])
    negative = _control_observation_with_evidence(
        case, evidence_document={"arm": "negative"}
    )
    with pytest.raises(VerificationTransactionError, match="unprovable"):
        commit_verification_arm_result_v05(case["ledger"], negative)


def test_audit_i2_control_evidence_contradiction_is_rejected(
    v05_transaction_case,
) -> None:
    """Audit I2: canonical evidence whose failure facts diverge from the
    signed observation must be rejected as a contradiction."""
    case = v05_transaction_case
    commit_verification_profile_v05(case["ledger"], case["profile"])
    contract = case["profile"].control_contracts[0]
    observed = contract.expected_failure_signature.model_dump(mode="json")
    evidence_document = {
        "schema_version": "openworkproof-control-evidence/0.5",
        "control_id": contract.control_id,
        "fixture_digest": contract.fixture_digest,
        "provocation_digest": contract.provocation_digest,
        "execution_status": "completed",
        "exit_codes": [2],
        "reason_codes": observed["reason_codes"],
        "predicate_ids": observed["predicate_ids"],
        "required_evidence_purposes": observed["required_evidence_purposes"],
    }
    negative = _control_observation_with_evidence(
        case, evidence_document=evidence_document
    )
    with pytest.raises(
        VerificationTransactionError, match="contradicts the signed observation"
    ):
        commit_verification_arm_result_v05(case["ledger"], negative)


def test_audit_i2_missing_control_evidence_is_rejected(
    v05_transaction_case,
) -> None:
    """Audit I2: a signed observation whose control evidence file is missing
    must fail closed at commit."""
    case = v05_transaction_case
    commit_verification_profile_v05(case["ledger"], case["profile"])
    contract = case["profile"].control_contracts[0]
    payload = _v05_control_observation(
        case["tmp_path"], contract, arm_kind="negative"
    )
    ref_path = payload["evidence_refs"][0]["path"]
    (case["tmp_path"] / ref_path).unlink()
    negative = _resign_arm_result_v05(
        case, case["results"][1], control_observation=payload
    )
    with pytest.raises(VerificationTransactionError, match="unavailable"):
        commit_verification_arm_result_v05(case["ledger"], negative)


def _committed_v05_transition(case, signed_acceptance_receipt):
    from openworkproof import acceptance as acceptance_module
    from openworkproof.settlement import read_settlement_snapshot

    from test_acceptance_v05 import _commit_acceptance_fixture, _transition_for_v05

    decision = _full_chain_with_decision(case)
    _commit_acceptance_fixture(case["ledger"], signed_acceptance_receipt)
    receipt = _transition_for_v05(
        case=case,
        decision=decision,
        signed_acceptance_receipt=signed_acceptance_receipt,
        transition="withdrawn",
    )
    acceptance_module.commit_acceptance_transition(case["ledger"], receipt)
    return read_settlement_snapshot, receipt


def test_audit_i5_transition_row_tamper_fails_closed(
    v05_transaction_case, signed_acceptance_receipt
) -> None:
    """Audit I5: tampering a v0.5 acceptance transition row must fail the
    settlement/acceptance load path."""
    from openworkproof.settlement import SettlementReadError

    case = v05_transaction_case
    read_settlement_snapshot, receipt = _committed_v05_transition(
        case, signed_acceptance_receipt
    )
    _corrupt_row(
        case,
        "acceptance_transitions_v05",
        "transition_json",
        sqlite3.Binary(b"\x00"),
        where="transition_id",
        who=receipt.transition_id,
    )
    with pytest.raises(SettlementReadError):
        read_settlement_snapshot(case["ledger"])


def test_audit_i5_transition_parent_row_delete_fails_closed(
    v05_transaction_case, signed_acceptance_receipt
) -> None:
    """Audit I5: deleting a v0.5 acceptance transition parent row must fail
    the settlement/acceptance load path."""
    from openworkproof.settlement import SettlementReadError

    case = v05_transaction_case
    read_settlement_snapshot, receipt = _committed_v05_transition(
        case, signed_acceptance_receipt
    )
    connection = evidence.connect_ledger(case["ledger"])
    try:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            "DROP TRIGGER acceptance_transition_parents_v05_are_immutable_delete"
        )
        connection.execute(
            "DELETE FROM acceptance_transition_parents_v05 "
            "WHERE transition_id = ?",
            (receipt.transition_id,),
        )
        connection.execute("COMMIT")
    finally:
        connection.close()
    with pytest.raises(SettlementReadError):
        read_settlement_snapshot(case["ledger"])


def test_audit_i1_decision_load_rejects_leap_second_committed_at(
    v05_transaction_case,
) -> None:
    """A leap-second committed_at is not a canonical UTC second."""
    case = v05_transaction_case
    decision = _full_chain_with_decision(case)
    _corrupt_row(
        case,
        "verification_decisions_v05",
        "committed_at",
        "2026-01-01T00:00:60Z",
        where="decision_id",
        who=decision.decision_id,
    )
    with pytest.raises(VerificationTransactionError, match="committed_at"):
        prepare_verification_decision_v05(
            case["ledger"],
            DecisionDraftRequest(
                decision_id="e" * 64,
                decided_at="2026-01-01T00:21:00Z",
                nonce="f" * 64,
            ),
        )


# ---------------------------------------------------------------------------
# Third-round audit B/C: per-rule output witness and canonical RFC 8785
# population evidence. Every test is attack-shaped and must be RED against
# the audited baseline.
# ---------------------------------------------------------------------------


def _population_observation_with_evidence(
    case,
    *,
    observation_index: int,
    ref_index: int,
    evidence_bytes: bytes,
) -> VerificationArmResultV05:
    """Re-sign an arm result whose target population observation points at
    attacker-supplied evidence bytes (sha256/size recomputed)."""
    result = case["results"][0]
    observations = [
        observation.model_dump(mode="json")
        for observation in result.population_observations
    ]
    target = observations[observation_index]
    ref = target["evidence_refs"][ref_index]
    (case["tmp_path"] / ref["path"]).write_bytes(evidence_bytes)
    target["evidence_refs"] = [
        (
            {
                **item,
                "sha256": hashlib.sha256(evidence_bytes).hexdigest(),
                "size_bytes": len(evidence_bytes),
            }
            if index == ref_index
            else item
        )
        for index, item in enumerate(target["evidence_refs"])
    ]
    observations[observation_index] = target
    return _resign_arm_result_v05(
        case,
        result,
        population_observations=observations,
    )


def _eligible_evidence_bytes(case, observation_index: int = 0) -> bytes:
    from openworkproof.models import PopulationObservationV05

    result = case["results"][0]
    observation = result.population_observations[observation_index]
    ref = observation.evidence_refs[0]
    return (case["tmp_path"] / ref.path).read_bytes()


def _assert_population_evidence_rejected(case, evidence_bytes: bytes) -> None:
    from openworkproof.verification import VerificationTransactionError

    commit_verification_profile_v05(case["ledger"], case["profile"])
    tampered = _population_observation_with_evidence(
        case,
        observation_index=0,
        ref_index=0,
        evidence_bytes=evidence_bytes,
    )
    with pytest.raises(VerificationTransactionError):
        commit_verification_arm_result_v05(case["ledger"], tampered)


def test_audit_c_whitespace_padded_population_evidence_is_rejected(
    v05_transaction_case,
) -> None:
    """Audit C: population evidence must be canonical RFC 8785 bytes;
    whitespace-padded JSON that parses to the closed schema is not
    canonical and must fail closed."""
    import json as _json

    case = v05_transaction_case
    canonical = _eligible_evidence_bytes(case)
    document = _json.loads(canonical)
    padded = _json.dumps(document, indent=2, sort_keys=True).encode("utf-8")
    _assert_population_evidence_rejected(case, padded)


def test_audit_c_key_reordered_population_evidence_is_rejected(
    v05_transaction_case,
) -> None:
    """Audit C: evidence with the same keys in non-canonical order must
    fail closed."""
    case = v05_transaction_case
    canonical = _eligible_evidence_bytes(case)
    document = json.loads(canonical)
    reordered = json.dumps(
        {
            "purpose": document["purpose"],
            "member_ids": document["member_ids"],
            "schema_version": document["schema_version"],
        },
        sort_keys=False,
        separators=(",", ":"),
    ).encode("utf-8")
    _assert_population_evidence_rejected(case, reordered)


def test_audit_c_duplicate_key_population_evidence_is_rejected(
    v05_transaction_case,
) -> None:
    """Audit C: a document with a duplicated key parses last-wins but is
    not canonical bytes and must fail closed."""
    case = v05_transaction_case
    canonical = _eligible_evidence_bytes(case)
    document = json.loads(canonical)
    serialized = json.dumps(
        document, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    marker = b'"purpose":"' + document["purpose"].encode("utf-8") + b'"'
    duplicated = serialized.replace(
        marker,
        marker + b',' + marker,
        1,
    )
    _assert_population_evidence_rejected(case, duplicated)


def test_audit_c_escape_equivalent_population_evidence_is_rejected(
    v05_transaction_case,
) -> None:
    """Audit C: escape-equivalent JSON (e.g. \\u escapes) parses to the
    same value but is not canonical bytes and must fail closed."""
    case = v05_transaction_case
    canonical = _eligible_evidence_bytes(case)
    escaped = canonical.replace(b"-population", b"-\\u0070opulation", 1)
    _assert_population_evidence_rejected(case, escaped)


def _two_pytest_rule_case(
    tmp_path,
    signed_work_order,
    signed_subject_claim,
    evaluation_scope_payload_v03,
    scope_members_v03,
    verification_profile_v03,
    ephemeral_role_keys,
    sidecar_receipt_factory,
):
    """Build a fresh v0.5 case whose manifest has TWO same-kind
    (pytest_collection) selector rules with disjoint declared selections
    over two test_case members."""
    import copy as _copy

    from openworkproof.models import ScopeMember, VerificationProfileV05
    from openworkproof.scope import (
        ObservedScope,
        population_digest,
        scope_member_id as _smid,
    )
    from openworkproof.signing import sign_payload as _sign_payload
    from openworkproof.verification import commit_evaluation_scope
    from test_control_integrity_v05 import _control_contract
    from test_population_integrity_v05 import _contract
    from test_verification_integrity_transactions_v05 import (
        _insert_transaction_receipt,
        _transaction_manifest,
        _v05_arm_result,
        _v05_control_observation,
        _write_json_evidence,
    )

    ledger = tmp_path / "audit-b.sqlite3"
    evidence.initialize_ledger(ledger, signed_work_order)
    selector_parent = tmp_path / "scope/selectors"
    selector_parent.mkdir(parents=True, exist_ok=True)
    source_revision = scope_members_v03[0].source_revision
    extra_member = ScopeMember.model_validate(
        {
            "member_id": _smid(
                "test_case", "tests/test_widget.py::test_widget_extra"
            ),
            "member_kind": "test_case",
            "locator": "tests/test_widget.py::test_widget_extra",
            "locator_digest": hashlib.sha256(
                b"tests/test_widget.py::test_widget_extra"
            ).hexdigest(),
            "content_digest": hashlib.sha256(b"test").hexdigest(),
            "source_revision": source_revision,
        }
    )
    members = sorted(
        [
            member.model_dump(mode="json") for member in scope_members_v03
        ]
        + [extra_member.model_dump(mode="json")],
        key=lambda member: (
            member["member_kind"].encode("utf-8"),
            member["locator_digest"],
            member["member_id"],
        ),
    )
    spec_source = rfc8785.dumps(
        {
            "schema_version": "openworkproof-scope-selector/0.3",
            "selector_kind": "explicit",
            "locators": ["src/widget.py"],
        }
    )
    spec_a = rfc8785.dumps(
        {
            "schema_version": "openworkproof-scope-selector/0.3",
            "selector_kind": "pytest_collection",
            "selector_args": ["tests/test_a.py"],
        }
    )
    spec_b = rfc8785.dumps(
        {
            "schema_version": "openworkproof-scope-selector/0.3",
            "selector_kind": "pytest_collection",
            "selector_args": ["tests/test_b.py"],
        }
    )
    (selector_parent / "source.json").write_bytes(spec_source)
    (selector_parent / "a.json").write_bytes(spec_a)
    (selector_parent / "b.json").write_bytes(spec_b)
    scope_payload = _copy.deepcopy(evaluation_scope_payload_v03)
    scope_payload["selector_rules"] = [
        {
            "rule_id": "0" * 64,
            "selector_kind": "explicit",
            "selector_spec_digest": hashlib.sha256(spec_source).hexdigest(),
            "selector_engine_digest": "4" * 64,
            "required_evidence_paths": ["scope/selectors/source.json"],
        },
        {
            "rule_id": "1" * 64,
            "selector_kind": "pytest_collection",
            "selector_spec_digest": hashlib.sha256(spec_a).hexdigest(),
            "selector_engine_digest": "5" * 64,
            "required_evidence_paths": ["scope/selectors/a.json"],
        },
        {
            "rule_id": "2" * 64,
            "selector_kind": "pytest_collection",
            "selector_spec_digest": hashlib.sha256(spec_b).hexdigest(),
            "selector_engine_digest": "6" * 64,
            "required_evidence_paths": ["scope/selectors/b.json"],
        },
    ]
    scope_payload["members"] = members
    scope_payload["member_count"] = len(members)
    scope_payload["population_digest"] = population_digest(
        tuple(ScopeMember.model_validate(member) for member in members)
    )
    manifest = _transaction_manifest(
        scope_payload,
        work_order=signed_work_order,
        claim=signed_subject_claim,
        manager_key=ephemeral_role_keys["Manager"][0],
    )
    raw = verification_profile_v03.model_dump(
        mode="json",
        exclude={"digest", "signature_alg", "signer_key_id", "signature"},
    )
    raw["schema_version"] = "openworkproof-verification-profile/0.5"
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
    source_id = next(
        member["member_id"]
        for member in members
        if member["member_kind"] == "source_file"
    )
    test_ids = sorted(
        member["member_id"]
        for member in members
        if member["member_kind"] == "test_case"
    )
    raw["population_contracts"] = sorted(
        [
            _contract(
                manifest.selector_rules[0].model_dump(mode="json"),
                [source_id],
                "source_file",
            ),
            _contract(
                manifest.selector_rules[1].model_dump(mode="json"),
                [test_ids[0]],
                "test_case",
            ),
            _contract(
                manifest.selector_rules[2].model_dump(mode="json"),
                [test_ids[1]],
                "test_case",
            ),
        ],
        key=lambda item: item["contract_id"],
    )
    negative_arm = raw["negative_arms"][0]
    control = _control_contract(
        negative_arm["arm_id"], negative_arm["mutant_patch_digest"]
    )
    raw["control_contracts"] = [control]
    profile = VerificationProfileV05.model_validate(
        _sign_payload(
            "verification-profile", raw, ephemeral_role_keys["Manager"][0], version="0.5"
        )
    )
    commit_evaluation_scope(ledger, signed_subject_claim, manifest)
    receipt = sidecar_receipt_factory(
        state_before="locally_verified",
        state_after="evidence_incomplete",
        event_type="system_event",
        event_name="proof_composed",
        sequence=1,
    )
    _insert_transaction_receipt(ledger, receipt)
    observed = ObservedScope(
        member_ids=tuple(member["member_id"] for member in members),
        member_count=len(members),
        population_digest=scope_payload["population_digest"],
        required_target_ids=tuple(manifest.required_target_ids),
        source_revision=manifest.source_revision,
        workspace_manifest_digest=manifest.workspace_manifest_digest,
        selector_engine_digests=tuple(
            sorted(
                rule.selector_engine_digest for rule in manifest.selector_rules
            )
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
        control_observation = (
            _v05_control_observation(
                tmp_path,
                profile.control_contracts[0],
                arm_kind=kind,
            )
            if kind == "negative"
            else None
        )
        placeholder = [
            _v05_population_observation(
                tmp_path,
                contract,
                suffix=f"{kind}-init-{index}",
            )
            for index, contract in enumerate(profile.population_contracts)
        ]
        results.append(
            _v05_arm_result(
                profile=profile,
                manifest=manifest,
                keys=ephemeral_role_keys,
                arm_kind=kind,
                observations=placeholder,
                control_observation=control_observation,
                action_receipt_id=receipt.receipt_id,
                evidence_ref=result_ref,
                scope_evidence_ref=scope_ref,
            )
        )
    return {
        "ledger": ledger,
        "manifest": manifest,
        "profile": profile,
        "results": tuple(results),
        "keys": ephemeral_role_keys,
        "tmp_path": tmp_path,
    }


def _observation_with_eligible(
    tmp_path: Path,
    contract,
    *,
    suffix: str,
    eligible_ids: list[str],
    selected_ids: list[str],
) -> dict[str, Any]:
    from openworkproof.integrity import population_observation_payload

    payload, inventory = population_observation_payload(
        contract=contract,
        eligible_member_ids=eligible_ids,
        selected_member_ids=selected_ids,
        observed_at="2026-01-01T00:10:00Z",
        eligible_path=f"evidence/{suffix}/eligible-population.json",
        selected_path=f"evidence/{suffix}/selected-population.json",
    )
    for ref in payload["evidence_refs"]:
        content = inventory[ref["sha256"]]
        target = tmp_path / ref["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    return payload


def _fill_observations(case, *, eligible_b_extra: bool) -> list:
    from openworkproof.models import PopulationObservationV05

    contracts = case["profile"].population_contracts
    source_contract = next(
        contract
        for contract in contracts
        if contract.member_kind == "source_file"
    )
    pytest_contracts = sorted(
        (
            contract
            for contract in contracts
            if contract.member_kind == "test_case"
        ),
        key=lambda contract: contract.selector_rule_id,
    )
    source_id = source_contract.declared_selected_member_ids[0]
    test_ids = [
        contract.declared_selected_member_ids[0]
        for contract in pytest_contracts
    ]
    eligible_all = sorted(set(test_ids))
    extra = f"e{0:063x}" if eligible_b_extra else None
    eligible_b = sorted(set(test_ids) | {extra}) if extra else eligible_all
    results = []
    for result in case["results"]:
        observations = [
            _observation_with_eligible(
                case["tmp_path"],
                source_contract,
                suffix=f"{result.arm_kind}-source",
                eligible_ids=[source_id],
                selected_ids=[source_id],
            ),
            _observation_with_eligible(
                case["tmp_path"],
                pytest_contracts[0],
                suffix=f"{result.arm_kind}-a",
                eligible_ids=eligible_all,
                selected_ids=[test_ids[0]],
            ),
            _observation_with_eligible(
                case["tmp_path"],
                pytest_contracts[1],
                suffix=f"{result.arm_kind}-b",
                eligible_ids=eligible_b,
                selected_ids=[test_ids[1]],
            ),
        ]
        raw = result.model_dump(
            mode="json",
            exclude={"digest", "signature_alg", "signer_key_id", "signature"},
        )
        raw["population_observations"] = sorted(
            [
                PopulationObservationV05.model_validate(item).model_dump(mode="json")
                for item in observations
            ],
            key=lambda item: item["contract_id"],
        )
        results.append(
            VerificationArmResultV05.model_validate(
                sign_payload(
                    "verification-arm-result",
                    raw,
                    case["keys"]["Verifier"][0],
                    version="0.5",
                )
            )
        )
    return results


def _commit_two_rule_chain(case, results) -> None:
    commit_verification_profile_v05(case["ledger"], case["profile"])
    for result in results:
        commit_verification_arm_result_v05(case["ledger"], result)


def test_audit_b_same_kind_different_eligible_sets_fail_closed(
    tmp_path,
    signed_work_order,
    signed_subject_claim,
    evaluation_scope_payload_v03,
    scope_members_v03,
    verification_profile_v03,
    ephemeral_role_keys,
    sidecar_receipt_factory,
) -> None:
    """Audit B: two same-kind selector rules in one arm must witness the
    SAME eligible population; differing eligible evidence (both containing
    the kind partition) must fail closed instead of interchanging."""
    from openworkproof.verification import (
        VerificationTransactionError,
        prepare_verification_decision_v05,
    )

    case = _two_pytest_rule_case(
        tmp_path,
        signed_work_order,
        signed_subject_claim,
        evaluation_scope_payload_v03,
        scope_members_v03,
        verification_profile_v03,
        ephemeral_role_keys,
        sidecar_receipt_factory,
    )
    results = _fill_observations(case, eligible_b_extra=True)
    with pytest.raises(VerificationTransactionError):
        _commit_two_rule_chain(case, results)
        prepare_verification_decision_v05(
            case["ledger"],
            DecisionDraftRequest(
                decision_id="e" * 64,
                decided_at="2026-01-01T00:21:00Z",
                nonce="f" * 64,
            ),
        )


def test_audit_b_same_kind_consistent_eligible_is_accepted(
    tmp_path,
    signed_work_order,
    signed_subject_claim,
    evaluation_scope_payload_v03,
    scope_members_v03,
    verification_profile_v03,
    ephemeral_role_keys,
    sidecar_receipt_factory,
) -> None:
    """Audit B: same-kind rules whose eligible evidence is identical still
    verify — the consistency check must not over-reject."""
    from openworkproof.verification import prepare_verification_decision_v05

    case = _two_pytest_rule_case(
        tmp_path,
        signed_work_order,
        signed_subject_claim,
        evaluation_scope_payload_v03,
        scope_members_v03,
        verification_profile_v03,
        ephemeral_role_keys,
        sidecar_receipt_factory,
    )
    results = _fill_observations(case, eligible_b_extra=False)
    _commit_two_rule_chain(case, results)
    decision = prepare_verification_decision_v05(
        case["ledger"],
        DecisionDraftRequest(
            decision_id="e" * 64,
            decided_at="2026-01-01T00:21:00Z",
            nonce="f" * 64,
        ),
    )
    assert decision is not None
