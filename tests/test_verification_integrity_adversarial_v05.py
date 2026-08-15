from __future__ import annotations

import sqlite3
from typing import Any

import pytest

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
