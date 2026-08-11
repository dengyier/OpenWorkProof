from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

import openworkproof.evidence as evidence
from openworkproof.acceptance import commit_acceptance_transition
from openworkproof.delivery_package import (
    DeliveryPackageError,
    export_delivery_package,
    verify_delivery_package,
)
from openworkproof.models import (
    DecisionDraftRequest,
    EvaluationScopeManifest,
    VerificationProfileV03,
)
from openworkproof.scope import ObservedScope, compare_observed_scope
from openworkproof.settlement import SettlementReadError, read_settlement_snapshot
from openworkproof.signing import sign_payload
from openworkproof.verification import (
    VerificationCommitIndeterminateError,
    VerificationCommittedError,
    VerificationInputError,
    VerificationTransactionError,
    commit_evaluation_scope,
    commit_verification_arm_result_v03,
    commit_verification_decision_v03,
    commit_verification_profile_v03,
    load_evaluation_scope,
    prepare_verification_decision_v03,
    validate_verification_profile_v03,
)
from test_acceptance_v03 import (
    _commit_acceptance_fixture,
    _commit_v03_decision,
    _transition_for_v03,
)
from test_scope_transactions_v03 import (
    bound_profile_v03,
    bound_scope_v03,
    v03_ledger,
)
from test_verification_transactions_v03 import (
    _arm_result,
    _compose,
    _signed_decision_v03,
    v03_transaction_case,
    verification_profile_v03,
)


def _snapshot(path: Path) -> dict[str, tuple[tuple[object, ...], ...]]:
    connection = sqlite3.connect(path)
    try:
        names = tuple(
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type = 'table' AND name NOT LIKE 'sqlite_%' "
                "ORDER BY name"
            )
        )
        return {
            name: tuple(connection.execute(f'SELECT * FROM "{name}"'))
            for name in names
        }
    finally:
        connection.close()


def _observed(manifest: EvaluationScopeManifest, **changes) -> ObservedScope:
    payload = {
        "member_ids": [member.member_id for member in manifest.members],
        "member_count": manifest.member_count,
        "population_digest": manifest.population_digest,
        "required_target_ids": list(manifest.required_target_ids),
        "source_revision": manifest.source_revision,
        "workspace_manifest_digest": manifest.workspace_manifest_digest,
        "selector_engine_digests": sorted(
            rule.selector_engine_digest for rule in manifest.selector_rules
        ),
        "evidence_complete": True,
    }
    payload.update(changes)
    return ObservedScope.model_validate(payload)


@pytest.mark.parametrize(
    ("changes", "status", "reason"),
    (
        (
            {
                "member_ids": [],
                "member_count": 0,
                "evidence_complete": False,
            },
            "indeterminate",
            "SCOPE_EMPTY",
        ),
        (
            {"source_revision": "f" * 40},
            "indeterminate",
            "SCOPE_WORKSPACE_DRIFT",
        ),
        (
            {"workspace_manifest_digest": "f" * 64},
            "indeterminate",
            "SCOPE_WORKSPACE_DRIFT",
        ),
        (
            {"selector_engine_digests": ["f" * 64]},
            "indeterminate",
            "SCOPE_SELECTOR_MISMATCH",
        ),
    ),
)
def test_observation_omission_and_drift_matrix(
    evaluation_scope_v03,
    changes,
    status,
    reason,
) -> None:
    result = compare_observed_scope(
        evaluation_scope_v03,
        _observed(evaluation_scope_v03, **changes),
    )
    assert result.scope_status == status
    assert reason in result.reason_codes


@pytest.mark.parametrize("kind", ("source_file", "test_case"))
def test_each_required_member_omission_is_indeterminate(
    evaluation_scope_v03,
    kind,
) -> None:
    omitted = next(
        member for member in evaluation_scope_v03.members
        if member.member_kind == kind
    )
    retained = tuple(
        member.member_id
        for member in evaluation_scope_v03.members
        if member.member_id != omitted.member_id
    )
    observed = _observed(
        evaluation_scope_v03,
        member_ids=retained,
        member_count=len(retained),
        evidence_complete=False,
    )
    result = compare_observed_scope(evaluation_scope_v03, observed)
    assert result.scope_status == "indeterminate"
    assert omitted.member_id in result.missing_required_target_ids
    assert "SCOPE_REQUIRED_TARGET_MISSING" in result.reason_codes


def test_declared_n_but_observed_n_minus_one_is_indeterminate(
    evaluation_scope_v03,
) -> None:
    observed = _observed(evaluation_scope_v03)
    payload = observed.model_dump(mode="json")
    payload["member_ids"] = payload["member_ids"][:-1]
    payload["member_count"] -= 1
    payload["evidence_complete"] = False
    result = compare_observed_scope(
        evaluation_scope_v03,
        ObservedScope.model_validate(payload),
    )
    assert result.scope_status == "indeterminate"
    assert "SCOPE_EVIDENCE_MISSING" in result.reason_codes


def test_profile_rejects_validly_resigned_candidate_drift(
    verification_profile_v03,
    evaluation_scope_v03,
    ephemeral_role_keys,
) -> None:
    raw = verification_profile_v03.model_dump(
        mode="json",
        exclude={"digest", "signature_alg", "signer_key_id", "signature"},
    )
    raw["positive_arm"]["candidate_commit"] = "f" * 40
    for arm in raw["negative_arms"]:
        arm["candidate_commit"] = "f" * 40
    changed = VerificationProfileV03.model_validate(
        sign_payload(
            "verification-profile",
            raw,
            ephemeral_role_keys["Manager"][0],
            version="0.3",
        )
    )
    with pytest.raises(VerificationInputError, match="scope binding"):
        validate_verification_profile_v03(changed, evaluation_scope_v03)


@pytest.mark.parametrize(
    ("negative_changes", "expected_reason"),
    (
        ({"observed_count_delta": -1}, "SCOPE_POPULATION_DRIFT"),
        ({"observed_population_digest": "f" * 64}, "SCOPE_CROSS_ARM_MISMATCH"),
    ),
)
def test_positive_full_negative_reduced_or_cross_arm_mismatch_is_unknown(
    verification_profile_v03,
    evaluation_scope_v03,
    ephemeral_role_keys,
    negative_changes,
    expected_reason,
) -> None:
    count = evaluation_scope_v03.member_count
    negative = dict(negative_changes)
    delta = negative.pop("observed_count_delta", 0)
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
            observed_count=count + delta,
            **negative,
        ),
    )
    decision = _compose(
        verification_profile_v03,
        evaluation_scope_v03,
        results,
    )
    assert decision.decision == "UNKNOWN"
    assert expected_reason in decision.reason_codes


@pytest.mark.parametrize(
    "fault",
    ("insert_failure", "before_commit", "commit_failure"),
)
def test_scope_precommit_faults_are_full_snapshot_zero_write(
    v03_ledger,
    signed_subject_claim,
    bound_scope_v03,
    fault,
) -> None:
    before = _snapshot(v03_ledger)
    with pytest.raises(VerificationTransactionError):
        commit_evaluation_scope(
            v03_ledger,
            signed_subject_claim,
            bound_scope_v03,
            fault=fault,
        )
    assert _snapshot(v03_ledger) == before


@pytest.mark.parametrize(
    ("fault", "error"),
    (
        ("commit_ack_loss", VerificationCommittedError),
        ("cleanup_failure", VerificationCommittedError),
        ("readback_failure", VerificationCommitIndeterminateError),
    ),
)
def test_scope_postcommit_faults_preserve_exact_committed_truth(
    v03_ledger,
    signed_subject_claim,
    bound_scope_v03,
    fault,
    error,
) -> None:
    with pytest.raises(error):
        commit_evaluation_scope(
            v03_ledger,
            signed_subject_claim,
            bound_scope_v03,
            fault=fault,
        )
    assert load_evaluation_scope(v03_ledger, bound_scope_v03.scope_id) == (
        bound_scope_v03
    )


@pytest.mark.parametrize(
    "fault",
    ("insert_failure", "before_commit", "commit_failure"),
)
def test_profile_precommit_faults_are_full_snapshot_zero_write(
    v03_ledger,
    signed_subject_claim,
    bound_scope_v03,
    bound_profile_v03,
    fault,
) -> None:
    commit_evaluation_scope(v03_ledger, signed_subject_claim, bound_scope_v03)
    before = _snapshot(v03_ledger)
    with pytest.raises(VerificationTransactionError):
        commit_verification_profile_v03(
            v03_ledger,
            bound_profile_v03,
            fault=fault,
        )
    assert _snapshot(v03_ledger) == before


@pytest.mark.parametrize(
    ("fault", "error"),
    (
        ("commit_ack_loss", VerificationCommittedError),
        ("cleanup_failure", VerificationCommittedError),
        ("readback_failure", VerificationCommitIndeterminateError),
    ),
)
def test_profile_postcommit_faults_preserve_exact_committed_truth(
    v03_ledger,
    signed_subject_claim,
    bound_scope_v03,
    bound_profile_v03,
    fault,
    error,
) -> None:
    commit_evaluation_scope(v03_ledger, signed_subject_claim, bound_scope_v03)
    with pytest.raises(error):
        commit_verification_profile_v03(
            v03_ledger,
            bound_profile_v03,
            fault=fault,
        )
    connection = evidence.connect_ledger(v03_ledger)
    try:
        row = connection.execute(
            "SELECT profile_digest FROM verification_profiles_v03"
        ).fetchone()
    finally:
        connection.close()
    assert row == (bound_profile_v03.digest,)


@pytest.mark.parametrize(
    "fault",
    ("insert_failure", "before_commit", "commit_failure"),
)
def test_arm_precommit_faults_are_full_snapshot_zero_write(
    v03_transaction_case,
    fault,
) -> None:
    case = v03_transaction_case
    before = _snapshot(case["ledger"])
    with pytest.raises(VerificationTransactionError):
        commit_verification_arm_result_v03(
            case["ledger"], case["results"][0], fault=fault
        )
    assert _snapshot(case["ledger"]) == before


@pytest.mark.parametrize(
    ("fault", "error"),
    (
        ("commit_ack_loss", VerificationCommittedError),
        ("cleanup_failure", VerificationCommittedError),
        ("readback_failure", VerificationCommitIndeterminateError),
    ),
)
def test_arm_postcommit_faults_preserve_exact_committed_truth(
    v03_transaction_case,
    fault,
    error,
) -> None:
    case = v03_transaction_case
    result = case["results"][0]
    with pytest.raises(error):
        commit_verification_arm_result_v03(
            case["ledger"], result, fault=fault
        )
    connection = evidence.connect_ledger(case["ledger"])
    try:
        row = connection.execute(
            "SELECT arm_result_digest FROM verification_arm_results_v03"
        ).fetchone()
    finally:
        connection.close()
    assert row == (result.digest,)


def _prepare_decision_case(case):
    for result in case["results"]:
        commit_verification_arm_result_v03(case["ledger"], result)
    return _signed_decision_v03(
        case,
        DecisionDraftRequest(
            decision_id="c" * 64,
            decided_at="2026-01-01T00:20:00Z",
            nonce="d" * 64,
        ),
    )


@pytest.mark.parametrize(
    "fault",
    ("insert_failure", "before_commit", "commit_failure"),
)
def test_decision_precommit_faults_are_full_snapshot_zero_write(
    v03_transaction_case,
    fault,
) -> None:
    case = v03_transaction_case
    decision = _prepare_decision_case(case)
    before = _snapshot(case["ledger"])
    with pytest.raises(VerificationTransactionError):
        commit_verification_decision_v03(
            case["ledger"], decision, fault=fault
        )
    assert _snapshot(case["ledger"]) == before


@pytest.mark.parametrize(
    ("fault", "error"),
    (
        ("commit_ack_loss", VerificationCommittedError),
        ("cleanup_failure", VerificationCommittedError),
        ("readback_failure", VerificationCommitIndeterminateError),
    ),
)
def test_decision_postcommit_faults_preserve_exact_committed_truth(
    v03_transaction_case,
    fault,
    error,
) -> None:
    case = v03_transaction_case
    decision = _prepare_decision_case(case)
    with pytest.raises(error):
        commit_verification_decision_v03(
            case["ledger"], decision, fault=fault
        )
    connection = evidence.connect_ledger(case["ledger"])
    try:
        row = connection.execute(
            "SELECT decision_digest FROM verification_decisions_v03"
        ).fetchone()
    finally:
        connection.close()
    assert row == (decision.digest,)


@pytest.mark.parametrize(
    ("table", "column"),
    (
        ("evaluation_scopes_v03", "scope_json"),
        ("verification_profiles_v03", "profile_json"),
        ("verification_arm_results_v03", "arm_result_json"),
        ("verification_decisions_v03", "decision_json"),
    ),
)
def test_canonical_ledger_row_tamper_fails_closed(
    v03_transaction_case,
    table,
    column,
) -> None:
    case = v03_transaction_case
    decision = _prepare_decision_case(case)
    commit_verification_decision_v03(case["ledger"], decision)
    connection = sqlite3.connect(case["ledger"])
    try:
        connection.execute(
            f'UPDATE "{table}" SET "{column}" = ? '
            f'WHERE rowid = (SELECT MIN(rowid) FROM "{table}")',
            (b"{}",),
        )
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(VerificationTransactionError):
        prepare_verification_decision_v03(
            case["ledger"],
            DecisionDraftRequest(
                decision_id="e" * 64,
                decided_at="2026-01-01T00:21:00Z",
                nonce="f" * 64,
            ),
        )


def test_decision_parent_row_tamper_fails_closed(v03_transaction_case) -> None:
    case = v03_transaction_case
    decision = _prepare_decision_case(case)
    commit_verification_decision_v03(case["ledger"], decision)
    connection = sqlite3.connect(case["ledger"])
    try:
        connection.execute(
            "UPDATE verification_decision_parents_v03 "
            "SET arm_result_id = ? WHERE ordinal = 0",
            ("f" * 64,),
        )
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(VerificationTransactionError, match="parents"):
        prepare_verification_decision_v03(
            case["ledger"],
            DecisionDraftRequest(
                decision_id="e" * 64,
                decided_at="2026-01-01T00:21:00Z",
                nonce="f" * 64,
            ),
        )


def test_selector_and_scope_evidence_byte_tamper_fail_closed(
    v03_transaction_case,
) -> None:
    case = v03_transaction_case
    selector = case["tmp_path"] / "scope/selectors/explicit.json"
    selector.write_bytes(selector.read_bytes() + b" ")
    with pytest.raises(VerificationTransactionError, match="selector"):
        commit_verification_arm_result_v03(
            case["ledger"], case["results"][0]
        )

    selector.write_bytes(selector.read_bytes()[:-1])
    scope_ref = case["results"][0].scope_evidence_refs[0]
    scope_path = case["tmp_path"] / scope_ref.path
    scope_path.write_bytes(scope_path.read_bytes() + b" ")
    with pytest.raises(VerificationTransactionError, match="evidence"):
        commit_verification_arm_result_v03(
            case["ledger"], case["results"][0]
        )


def test_acceptance_row_tamper_fails_closed(
    v03_transaction_case,
    signed_acceptance_receipt,
) -> None:
    case = v03_transaction_case
    decision = _commit_v03_decision(case)
    _commit_acceptance_fixture(case["ledger"], signed_acceptance_receipt)
    transition = _transition_for_v03(
        case=case,
        decision=decision,
        signed_acceptance_receipt=signed_acceptance_receipt,
        transition="withdrawn",
    )
    commit_acceptance_transition(case["ledger"], transition)
    connection = sqlite3.connect(case["ledger"])
    try:
        connection.execute(
            "UPDATE acceptance_transitions_v03 SET transition_json = ?",
            (b"{}",),
        )
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(SettlementReadError):
        read_settlement_snapshot(case["ledger"])


def test_package_manifest_and_member_evidence_tamper_fail_closed(
    v03_transaction_case,
) -> None:
    case = v03_transaction_case
    _commit_v03_decision(case)
    output = case["tmp_path"] / "customer-package"
    export_delivery_package(
        case["ledger"], output, privacy_view="customer_private"
    )
    manifest = output / "manifest.json"
    raw = json.loads(manifest.read_text(encoding="utf-8"))
    raw["privacy_view"] = "public"
    manifest.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(DeliveryPackageError):
        verify_delivery_package(output)

    output = case["tmp_path"] / "customer-package-member-tamper"
    export_delivery_package(
        case["ledger"], output, privacy_view="customer_private"
    )
    members = output / "scope/members.json"
    members.write_bytes(members.read_bytes() + b" ")
    with pytest.raises(DeliveryPackageError, match="integrity"):
        verify_delivery_package(output)


def test_bad_signature_is_not_reported_as_semantic_scope_failure(
    v03_ledger,
    signed_subject_claim,
    bound_scope_v03,
) -> None:
    raw = bound_scope_v03.model_dump(mode="json")
    raw["signature"] = "A" * 86
    malformed = EvaluationScopeManifest.model_validate(raw)
    with pytest.raises(VerificationTransactionError, match="signature") as raised:
        commit_evaluation_scope(v03_ledger, signed_subject_claim, malformed)
    assert "does not match SubjectClaim" not in str(raised.value)
