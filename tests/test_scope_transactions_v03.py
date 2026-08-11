from __future__ import annotations

import copy
import hashlib
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
import rfc8785

import openworkproof.evidence as evidence
from openworkproof.models import (
    EvaluationScopeManifest,
    VerificationProfileV03,
)
from openworkproof.scope import requirement_digest
from openworkproof.signing import sign_payload
from openworkproof.verification import (
    VerificationCommitIndeterminateError,
    VerificationCommittedError,
    VerificationTransactionError,
    commit_evaluation_scope,
    commit_verification_profile_v03,
    load_evaluation_scope,
)


V03_TABLES = {
    "evaluation_scopes_v03",
    "verification_profiles_v03",
    "verification_arm_results_v03",
    "verification_decisions_v03",
    "verification_decision_parents_v03",
    "acceptance_transitions_v03",
    "acceptance_transition_parents_v03",
}


def _v03_digest(domain: str, payload: object) -> str:
    return hashlib.sha256(
        rfc8785.dumps(
            {"domain": f"openworkproof/{domain}/v0.3", "payload": payload}
        )
    ).hexdigest()


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
def v03_ledger(tmp_path, signed_work_order) -> Path:
    path = tmp_path / "scope-ledger.sqlite3"
    evidence.initialize_ledger(path, signed_work_order)
    return path


@pytest.fixture
def bound_scope_v03(
    evaluation_scope_payload_v03,
    signed_work_order,
    signed_subject_claim,
    ephemeral_role_keys,
) -> EvaluationScopeManifest:
    payload = copy.deepcopy(evaluation_scope_payload_v03)
    payload.update(
        {
            "work_order_digest": signed_work_order.digest,
            "subject_claim_digest": signed_subject_claim.digest,
            "source_revision": signed_subject_claim.source_revision,
        }
    )
    for member in payload["members"]:
        member["source_revision"] = signed_subject_claim.source_revision
    source_member = next(
        item for item in payload["members"] if item["member_kind"] == "source_file"
    )
    test_member = next(
        item for item in payload["members"] if item["member_kind"] == "test_case"
    )
    bindings = []
    for value in signed_subject_claim.acceptance_conditions:
        bindings.append(
            {
                "requirement_kind": "acceptance_condition",
                "requirement_digest": requirement_digest(
                    "acceptance_condition", value
                ),
                "member_ids": [test_member["member_id"]],
            }
        )
    for value in signed_subject_claim.required_artifacts:
        bindings.append(
            {
                "requirement_kind": "required_artifact",
                "requirement_digest": requirement_digest("required_artifact", value),
                "member_ids": [source_member["member_id"]],
            }
        )
    payload["requirement_bindings"] = sorted(
        bindings,
        key=lambda item: (
            item["requirement_kind"].encode("utf-8"),
            item["requirement_digest"],
        ),
    )
    payload["required_target_ids"] = sorted(
        {
            member_id
            for binding in payload["requirement_bindings"]
            for member_id in binding["member_ids"]
        }
    )
    payload["scope_id"] = "0" * 64
    payload["scope_id"] = _v03_digest(
        "evaluation-scope",
        {key: value for key, value in payload.items() if key != "scope_id"},
    )
    return EvaluationScopeManifest.model_validate(
        sign_payload(
            "evaluation-scope",
            payload,
            ephemeral_role_keys["Manager"][0],
            version="0.3",
        )
    )


@pytest.fixture
def bound_profile_v03(
    signed_verification_profile,
    bound_scope_v03,
    ephemeral_role_keys,
) -> VerificationProfileV03:
    payload = signed_verification_profile.model_dump(
        mode="json",
        exclude={"digest", "signature_alg", "signer_key_id", "signature"},
    )
    payload.update(
        {
            "schema_version": "openworkproof-verification-profile/0.3",
            "work_order_digest": bound_scope_v03.work_order_digest,
            "subject_claim_digest": bound_scope_v03.subject_claim_digest,
            "evaluation_scope_id": bound_scope_v03.scope_id,
            "evaluation_scope_digest": bound_scope_v03.digest,
            "scope_requirement": "exact_match",
        }
    )
    for arm in (payload["positive_arm"], *payload["negative_arms"]):
        arm.update(
            {
                "source_commit": bound_scope_v03.source_revision,
                "candidate_commit": bound_scope_v03.candidate_commit,
                "workspace_manifest_digest": bound_scope_v03.workspace_manifest_digest,
            }
        )
    return VerificationProfileV03.model_validate(
        sign_payload(
            "verification-profile",
            payload,
            ephemeral_role_keys["Manager"][0],
            version="0.3",
        )
    )


def test_v03_parallel_tables_are_initialized(v03_ledger) -> None:
    connection = evidence.connect_ledger(v03_ledger)
    try:
        names = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
    finally:
        connection.close()
    assert V03_TABLES <= names


def test_scope_commit_and_load_are_canonical(
    v03_ledger, signed_subject_claim, bound_scope_v03
) -> None:
    committed = commit_evaluation_scope(
        v03_ledger, signed_subject_claim, bound_scope_v03
    )
    assert committed == bound_scope_v03
    assert load_evaluation_scope(v03_ledger, bound_scope_v03.scope_id) == committed

    connection = evidence.connect_ledger(v03_ledger)
    try:
        row = connection.execute(
            "SELECT claim_id, scope_digest, scope_json FROM evaluation_scopes_v03"
        ).fetchone()
    finally:
        connection.close()
    assert row == (
        signed_subject_claim.claim_id,
        bound_scope_v03.digest,
        evidence._canonical_json(bound_scope_v03.model_dump(mode="json")).encode(),
    )


def test_exact_scope_recommit_reports_committed_truth(
    v03_ledger, signed_subject_claim, bound_scope_v03
) -> None:
    commit_evaluation_scope(v03_ledger, signed_subject_claim, bound_scope_v03)
    with pytest.raises(VerificationCommittedError) as raised:
        commit_evaluation_scope(v03_ledger, signed_subject_claim, bound_scope_v03)
    assert raised.value.committed == bound_scope_v03


@pytest.mark.parametrize(
    "fault",
    ("insert_failure", "before_commit", "commit_failure", "readback_failure"),
)
def test_scope_precommit_or_indeterminate_fault_has_expected_truth(
    v03_ledger, signed_subject_claim, bound_scope_v03, fault
) -> None:
    before = _all_table_snapshot(v03_ledger)
    error = (
        VerificationTransactionError
        if fault != "readback_failure"
        else VerificationCommitIndeterminateError
    )
    with pytest.raises(error):
        commit_evaluation_scope(
            v03_ledger,
            signed_subject_claim,
            bound_scope_v03,
            fault=fault,
        )
    if fault != "readback_failure":
        assert _all_table_snapshot(v03_ledger) == before
    else:
        assert load_evaluation_scope(v03_ledger, bound_scope_v03.scope_id) == bound_scope_v03


@pytest.mark.parametrize("fault", ("commit_ack_loss", "cleanup_failure"))
def test_scope_postcommit_fault_preserves_exact_truth(
    v03_ledger, signed_subject_claim, bound_scope_v03, fault
) -> None:
    with pytest.raises(VerificationCommittedError) as raised:
        commit_evaluation_scope(
            v03_ledger,
            signed_subject_claim,
            bound_scope_v03,
            fault=fault,
        )
    assert raised.value.committed == bound_scope_v03
    assert load_evaluation_scope(v03_ledger, bound_scope_v03.scope_id) == bound_scope_v03


def test_scope_rejects_wrong_authority_without_writes(
    v03_ledger,
    signed_subject_claim,
    bound_scope_v03,
    ephemeral_role_keys,
) -> None:
    payload = bound_scope_v03.model_dump(mode="json")
    payload["signature"] = sign_payload(
        "evaluation-scope",
        {
            key: value
            for key, value in payload.items()
            if key not in {"digest", "signature_alg", "signer_key_id", "signature"}
        },
        ephemeral_role_keys["Verifier"][0],
        version="0.3",
    )["signature"]
    malformed = bound_scope_v03.model_copy(update={"signature": payload["signature"]})
    before = _all_table_snapshot(v03_ledger)
    with pytest.raises(VerificationTransactionError, match="signature"):
        commit_evaluation_scope(v03_ledger, signed_subject_claim, malformed)
    assert _all_table_snapshot(v03_ledger) == before


def test_scope_nonce_reuse_and_conflicting_bytes_fail_closed(
    v03_ledger, signed_subject_claim, bound_scope_v03, ephemeral_role_keys
) -> None:
    commit_evaluation_scope(v03_ledger, signed_subject_claim, bound_scope_v03)
    changed_payload = bound_scope_v03.model_dump(
        mode="json",
        exclude={"digest", "signature_alg", "signer_key_id", "signature"},
    )
    changed_payload["candidate_commit"] = "3" * 40
    changed_payload["scope_id"] = "0" * 64
    changed_payload["scope_id"] = _v03_digest(
        "evaluation-scope",
        {
            key: value
            for key, value in changed_payload.items()
            if key != "scope_id"
        },
    )
    changed = EvaluationScopeManifest.model_validate(
        sign_payload(
            "evaluation-scope",
            changed_payload,
            ephemeral_role_keys["Manager"][0],
            version="0.3",
        )
    )
    with pytest.raises(VerificationTransactionError, match="nonce"):
        commit_evaluation_scope(v03_ledger, signed_subject_claim, changed)


def test_scope_rejects_expiry_beyond_manager_grant(
    v03_ledger,
    signed_subject_claim,
    bound_scope_v03,
    ephemeral_role_keys,
) -> None:
    payload = bound_scope_v03.model_dump(
        mode="json",
        exclude={"digest", "signature_alg", "signer_key_id", "signature"},
    )
    payload["expires_at"] = "2026-01-02T00:00:01Z"
    payload["scope_id"] = "0" * 64
    payload["scope_id"] = _v03_digest(
        "evaluation-scope",
        {key: value for key, value in payload.items() if key != "scope_id"},
    )
    expired = EvaluationScopeManifest.model_validate(
        sign_payload(
            "evaluation-scope",
            payload,
            ephemeral_role_keys["Manager"][0],
            version="0.3",
        )
    )
    before = _all_table_snapshot(v03_ledger)
    with pytest.raises(VerificationTransactionError, match="grant"):
        commit_evaluation_scope(v03_ledger, signed_subject_claim, expired)
    assert _all_table_snapshot(v03_ledger) == before


def test_scope_commit_has_one_truth_under_concurrency(
    v03_ledger, signed_subject_claim, bound_scope_v03
) -> None:
    def commit_once():
        try:
            return commit_evaluation_scope(
                v03_ledger, signed_subject_claim, bound_scope_v03
            )
        except VerificationCommittedError as error:
            return error.committed

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = tuple(pool.map(lambda _: commit_once(), range(2)))
    assert results == (bound_scope_v03, bound_scope_v03)
    connection = evidence.connect_ledger(v03_ledger)
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM evaluation_scopes_v03"
        ).fetchone() == (1,)
    finally:
        connection.close()


def test_v03_profile_requires_committed_exact_scope(
    v03_ledger,
    signed_subject_claim,
    bound_scope_v03,
    bound_profile_v03,
) -> None:
    with pytest.raises(VerificationTransactionError, match="scope"):
        commit_verification_profile_v03(v03_ledger, bound_profile_v03)
    commit_evaluation_scope(v03_ledger, signed_subject_claim, bound_scope_v03)
    assert (
        commit_verification_profile_v03(v03_ledger, bound_profile_v03)
        == bound_profile_v03
    )


def test_v03_profile_exact_recommit_and_fault_semantics(
    v03_ledger,
    signed_subject_claim,
    bound_scope_v03,
    bound_profile_v03,
) -> None:
    commit_evaluation_scope(v03_ledger, signed_subject_claim, bound_scope_v03)
    before = _all_table_snapshot(v03_ledger)
    with pytest.raises(VerificationTransactionError):
        commit_verification_profile_v03(
            v03_ledger, bound_profile_v03, fault="commit_failure"
        )
    assert _all_table_snapshot(v03_ledger) == before
    commit_verification_profile_v03(v03_ledger, bound_profile_v03)
    with pytest.raises(VerificationCommittedError) as raised:
        commit_verification_profile_v03(v03_ledger, bound_profile_v03)
    assert raised.value.committed == bound_profile_v03
