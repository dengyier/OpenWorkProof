from __future__ import annotations

import copy
import hashlib
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest
import rfc8785

import openworkproof.evidence as evidence
from openworkproof.models import (
    EvaluationScopeManifest,
    VerificationArmResultV05,
    VerificationProfileV03,
    VerificationProfileV05,
    population_member_digest,
)
from openworkproof.scope import ObservedScope
from openworkproof.signing import sign_payload
from openworkproof.verification import (
    VerificationCommitIndeterminateError,
    VerificationCommittedError,
    VerificationTransactionError,
    commit_evaluation_scope,
    commit_verification_arm_result_v05,
    commit_verification_profile_v05,
    load_verification_profile_v05,
)

from test_control_integrity_v05 import _control_observation_payload
from test_population_integrity_v05 import _contract, _control_contract


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


def _transaction_digest(domain: str, payload: object) -> str:
    return hashlib.sha256(
        rfc8785.dumps(
            {"domain": f"openworkproof/{domain}/v0.3", "payload": payload}
        )
    ).hexdigest()


def _transaction_manifest(
    payload,
    *,
    work_order,
    claim,
    manager_key,
) -> EvaluationScopeManifest:
    raw = copy.deepcopy(payload)
    raw.update(
        {
            "work_order_digest": work_order.digest,
            "subject_claim_digest": claim.digest,
            "source_revision": claim.source_revision,
        }
    )
    for member in raw["members"]:
        member["source_revision"] = claim.source_revision
    source_id = next(
        item["member_id"]
        for item in raw["members"]
        if item["member_kind"] == "source_file"
    )
    test_id = next(
        item["member_id"]
        for item in raw["members"]
        if item["member_kind"] == "test_case"
    )
    from openworkproof.scope import requirement_digest

    raw["requirement_bindings"] = sorted(
        [
            *(
                {
                    "requirement_kind": "acceptance_condition",
                    "requirement_digest": requirement_digest(
                        "acceptance_condition", value
                    ),
                    "member_ids": [test_id],
                }
                for value in claim.acceptance_conditions
            ),
            *(
                {
                    "requirement_kind": "required_artifact",
                    "requirement_digest": requirement_digest(
                        "required_artifact", value
                    ),
                    "member_ids": [source_id],
                }
                for value in claim.required_artifacts
            ),
        ],
        key=lambda item: (
            item["requirement_kind"].encode("utf-8"),
            item["requirement_digest"],
        ),
    )
    raw["required_target_ids"] = sorted(
        {
            member_id
            for binding in raw["requirement_bindings"]
            for member_id in binding["member_ids"]
        }
    )
    raw["scope_id"] = "0" * 64
    raw["scope_id"] = _transaction_digest(
        "evaluation-scope",
        {key: value for key, value in raw.items() if key != "scope_id"},
    )
    return EvaluationScopeManifest.model_validate(
        sign_payload(
            "evaluation-scope", raw, manager_key, version="0.3"
        )
    )


def _transaction_profile_v05(
    profile: VerificationProfileV03,
    *,
    manifest: EvaluationScopeManifest,
    manager_key,
    control_changes: dict[str, Any] | None = None,
) -> VerificationProfileV05:
    raw = profile.model_dump(
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
    members_by_kind = {
        kind: sorted(
            member.member_id
            for member in manifest.members
            if member.member_kind == kind
        )
        for kind in ("source_file", "test_case")
    }
    raw["population_contracts"] = sorted(
        [
            _contract(rule.model_dump(mode="json"), members_by_kind[kind], kind)
            for rule, kind in zip(
                manifest.selector_rules,
                ("source_file", "test_case"),
                strict=True,
            )
        ],
        key=lambda item: item["contract_id"],
    )
    negative_arm = raw["negative_arms"][0]
    control = _control_contract(
        negative_arm["arm_id"], negative_arm["mutant_patch_digest"]
    )
    if control_changes:
        control.update(copy.deepcopy(control_changes))
        from openworkproof.models import control_contract_id

        control["control_id"] = control_contract_id(control)
    raw["control_contracts"] = [control]
    return VerificationProfileV05.model_validate(
        sign_payload(
            "verification-profile", raw, manager_key, version="0.5"
        )
    )


def _insert_transaction_receipt(path: Path, receipt) -> None:
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


def _write_json_evidence(root: Path, relative: str, value: object) -> dict[str, object]:
    raw = rfc8785.dumps(value)
    target = root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(raw)
    return {
        "path": relative,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "media_type": "application/json",
        "size_bytes": len(raw),
    }


def _population_evidence_file(
    root: Path,
    purpose: str,
    member_ids: list[str],
    *,
    relative: str,
) -> dict[str, Any]:
    document = {
        "schema_version": "openworkproof-population-evidence/0.5",
        "purpose": purpose,
        "member_ids": sorted(set(member_ids)),
    }
    raw = rfc8785.dumps(document)
    target = root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(raw)
    return {
        "path": relative,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "media_type": "application/json",
        "size_bytes": len(raw),
    }


def _v05_population_observation(
    root: Path,
    contract,
    *,
    suffix: str,
    eligible_seen: int | None = None,
    selected_count: int | None = None,
) -> dict[str, Any]:
    declared = list(contract.declared_selected_member_ids)
    eligible_seen = len(declared) if eligible_seen is None else eligible_seen
    selected_count = len(declared) if selected_count is None else selected_count
    if eligible_seen == 0:
        eligible_members: list[str] = []
        selected_members: list[str] = []
        numerator, denominator = 0, 1
    else:
        extras: list[str] = []
        index = 0
        while len(extras) < max(0, eligible_seen - len(declared)):
            candidate = f"e{index:063x}"
            index += 1
            if candidate not in declared:
                extras.append(candidate)
        eligible_members = sorted(set(declared) | set(extras))
        selected_members = [] if selected_count == 0 else declared
        numerator, denominator = (
            (0, 1) if selected_count == 0 else (selected_count, eligible_seen)
        )
    eligible_ref = _population_evidence_file(
        root,
        "eligible-population",
        eligible_members,
        relative=f"evidence/{suffix}/eligible-population.json",
    )
    selected_ref = _population_evidence_file(
        root,
        "selected-population",
        selected_members,
        relative=f"evidence/{suffix}/selected-population.json",
    )
    return {
        "contract_id": contract.contract_id,
        "selector_rule_id": contract.selector_rule_id,
        "selector_spec_digest": contract.selector_spec_digest,
        "selector_engine_digest": contract.selector_engine_digest,
        "eligible_seen": eligible_seen,
        "eligible_population_digest": population_member_digest(
            tuple(eligible_members)
        ),
        "selected_count": selected_count,
        "selected_population_digest": population_member_digest(
            tuple(selected_members)
        ),
        "capture_numerator": numerator,
        "capture_denominator": denominator,
        "observed_at": "2026-01-01T00:10:00Z",
        "evidence_refs": [eligible_ref, selected_ref],
    }


def _v05_control_observation(
    root: Path,
    contract,
    *,
    arm_kind: str,
    **overrides: Any,
) -> dict[str, Any]:
    payload = _control_observation_payload(contract, **overrides)
    payload["evidence_refs"] = [
        _write_json_evidence(
            root, f"control/{arm_kind}.json", {"arm": arm_kind}
        )
    ]
    return payload


def _v05_arm_result(
    *,
    profile: VerificationProfileV05,
    manifest: EvaluationScopeManifest,
    keys,
    arm_kind: str,
    observations: list[dict[str, Any]],
    control_observation: dict[str, Any] | None,
    action_receipt_id: str | None = None,
    evidence_ref: dict[str, object] | None = None,
    scope_evidence_ref: dict[str, object] | None = None,
    created_at: str = "2026-01-01T00:10:00Z",
    mutation_status: str = "applied",
) -> VerificationArmResultV05:
    arm = profile.positive_arm if arm_kind == "positive" else profile.negative_arms[0]
    result_id = "8" * 64 if arm_kind == "positive" else "9" * 64
    if arm_kind == "negative" and mutation_status == "not_applied":
        expectation = "indeterminate"
        reasons = ["MUTATION_NOT_APPLIED"]
    else:
        expectation = "satisfied"
        reasons = (
            ["MUTATION_APPLIED", "MUTATION_CAUGHT"]
            if arm_kind == "negative"
            else []
        )
    verifier = profile.verifier_bindings[0]
    payload = {
        "schema_version": "openworkproof-verification-arm-result/0.5",
        "arm_result_id": result_id,
        "profile_digest": profile.digest,
        "arm_id": arm.arm_id,
        "arm_kind": arm_kind,
        "mutation_status": (
            "not_applicable" if arm_kind == "positive" else mutation_status
        ),
        "execution_status": "completed",
        "expectation_status": expectation,
        "reason_codes": sorted(reasons),
        "action_receipt_ids": [action_receipt_id or result_id],
        "evidence_refs": [
            evidence_ref
            or {
                "path": f"results/{arm_kind}.json",
                "sha256": "d" * 64,
                "media_type": "application/json",
                "size_bytes": 128,
            }
        ],
        "scope_manifest_digest": manifest.digest,
        "observed_member_count": manifest.member_count,
        "observed_population_digest": manifest.population_digest,
        "observed_required_target_ids": list(manifest.required_target_ids),
        "scope_expectation_status": "satisfied",
        "scope_evidence_refs": [
            scope_evidence_ref
            or {
                "path": f"scope/{arm_kind}.json",
                "sha256": "e" * 64,
                "media_type": "application/json",
                "size_bytes": 128,
            }
        ],
        "verifier_subject_id": verifier.verifier_subject_id,
        "verifier_key_id": verifier.verifier_key_id,
        "verifier_build_digest": "4" * 64,
        "dependency_lock_digest": "5" * 64,
        "controller_factors": list(verifier.controller_factors),
        "execution_context_factors": list(verifier.execution_context_factors),
        "created_at": created_at,
        "population_observations": observations,
        "control_observation": control_observation,
    }
    return VerificationArmResultV05.model_validate(
        sign_payload(
            "verification-arm-result",
            payload,
            keys["Verifier"][0],
            version="0.5",
        )
    )


def _resign_arm_result_v05(case, result, **changes) -> VerificationArmResultV05:
    raw = result.model_dump(
        mode="json",
        exclude={"digest", "signature_alg", "signer_key_id", "signature"},
    )
    raw.update(changes)
    return VerificationArmResultV05.model_validate(
        sign_payload(
            "verification-arm-result",
            raw,
            case["keys"]["Verifier"][0],
            version="0.5",
        )
    )


@pytest.fixture
def v05_transaction_case(
    tmp_path,
    signed_work_order,
    signed_subject_claim,
    evaluation_scope_payload_v03,
    verification_profile_v03,
    ephemeral_role_keys,
    sidecar_receipt_factory,
):
    ledger = tmp_path / "verification-v05.sqlite3"
    evidence.initialize_ledger(ledger, signed_work_order)
    selector_parent = tmp_path / "scope/selectors"
    selector_parent.mkdir(parents=True, exist_ok=True)
    source_spec = {
        "schema_version": "openworkproof-selector-spec/0.3",
        "selector_kind": "explicit",
        "locators": ["src/widget.py"],
    }
    test_spec = {
        "schema_version": "openworkproof-selector-spec/0.3",
        "selector_kind": "explicit",
        "locators": ["tests/test_widget.py::test_widget[param-\u4e00]"],
    }
    source_raw = rfc8785.dumps(source_spec)
    test_raw = rfc8785.dumps(test_spec)
    (selector_parent / "source.json").write_bytes(source_raw)
    (selector_parent / "tests.json").write_bytes(test_raw)
    scope_payload = copy.deepcopy(evaluation_scope_payload_v03)
    original = scope_payload["selector_rules"][0]
    scope_payload["selector_rules"] = [
        {
            **original,
            "rule_id": "3" * 64,
            "selector_spec_digest": hashlib.sha256(source_raw).hexdigest(),
            "selector_engine_digest": "5" * 64,
            "required_evidence_paths": ["scope/selectors/source.json"],
        },
        {
            **original,
            "rule_id": "6" * 64,
            "selector_spec_digest": hashlib.sha256(test_raw).hexdigest(),
            "selector_engine_digest": "8" * 64,
            "required_evidence_paths": ["scope/selectors/tests.json"],
        },
    ]
    manifest = _transaction_manifest(
        scope_payload,
        work_order=signed_work_order,
        claim=signed_subject_claim,
        manager_key=ephemeral_role_keys["Manager"][0],
    )
    profile = _transaction_profile_v05(
        verification_profile_v03,
        manifest=manifest,
        manager_key=ephemeral_role_keys["Manager"][0],
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
        member_ids=tuple(member.member_id for member in manifest.members),
        member_count=manifest.member_count,
        population_digest=manifest.population_digest,
        required_target_ids=manifest.required_target_ids,
        source_revision=manifest.source_revision,
        workspace_manifest_digest=manifest.workspace_manifest_digest,
        selector_engine_digests=tuple(
            sorted(rule.selector_engine_digest for rule in manifest.selector_rules)
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
        observations = [
            _v05_population_observation(
                tmp_path,
                contract,
                suffix=f"{kind}-{contract.member_kind}",
            )
            for contract in profile.population_contracts
        ]
        control = (
            _v05_control_observation(
                tmp_path,
                profile.control_contracts[0],
                arm_kind=kind,
            )
            if kind == "negative"
            else None
        )
        results.append(
            _v05_arm_result(
                profile=profile,
                manifest=manifest,
                keys=ephemeral_role_keys,
                arm_kind=kind,
                observations=observations,
                control_observation=control,
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


def test_v05_tables_and_triggers_are_immutable(v05_transaction_case) -> None:
    case = v05_transaction_case
    commit_verification_profile_v05(case["ledger"], case["profile"])
    connection = evidence.connect_ledger(case["ledger"])
    try:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        assert {
            "verification_profiles_v05",
            "verification_arm_results_v05",
            "verification_decisions_v05",
            "verification_decision_parents_v05",
            "acceptance_transitions_v05",
            "acceptance_transition_parents_v05",
        } <= tables
        triggers = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'trigger'"
            )
        }
        for table in (
            "verification_profiles_v05",
            "verification_arm_results_v05",
            "verification_decisions_v05",
            "verification_decision_parents_v05",
            "acceptance_transitions_v05",
            "acceptance_transition_parents_v05",
        ):
            assert f"{table}_are_immutable_update" in triggers
            assert f"{table}_are_immutable_delete" in triggers
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute(
                "UPDATE verification_profiles_v05 SET scope_digest = '0' * 64"
            )
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute(
                "DELETE FROM verification_profiles_v05"
            )
    finally:
        connection.close()


def test_v05_profile_loads_with_recomputed_bindings(v05_transaction_case) -> None:
    case = v05_transaction_case
    commit_verification_profile_v05(case["ledger"], case["profile"])
    loaded = load_verification_profile_v05(
        case["ledger"], case["profile"].profile_id
    )
    assert loaded == case["profile"]
    with pytest.raises(VerificationCommittedError):
        commit_verification_profile_v05(case["ledger"], case["profile"])


def test_v05_profile_load_rejects_corrupted_row(v05_transaction_case) -> None:
    case = v05_transaction_case
    commit_verification_profile_v05(case["ledger"], case["profile"])
    connection = evidence.connect_ledger(case["ledger"])
    try:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            "DROP TRIGGER verification_profiles_v05_are_immutable_update"
        )
        connection.execute(
            "UPDATE verification_profiles_v05 SET profile_json = X'00' "
            "WHERE profile_id = ?",
            (case["profile"].profile_id,),
        )
        connection.execute("COMMIT")
    finally:
        connection.close()
    with pytest.raises(VerificationTransactionError, match="canonical"):
        load_verification_profile_v05(
            case["ledger"], case["profile"].profile_id
        )


def test_v05_profile_rejects_swapped_contracts(v05_transaction_case) -> None:
    case = v05_transaction_case
    commit_verification_profile_v05(case["ledger"], case["profile"])
    contracts = [
        contract.model_dump(mode="json")
        for contract in case["profile"].population_contracts
    ]
    source = next(item for item in contracts if item["member_kind"] == "source_file")
    test = next(item for item in contracts if item["member_kind"] == "test_case")
    source["member_kind"], test["member_kind"] = (
        test["member_kind"],
        source["member_kind"],
    )
    (
        source["declared_selected_member_ids"],
        test["declared_selected_member_ids"],
    ) = (
        list(test["declared_selected_member_ids"]),
        list(source["declared_selected_member_ids"]),
    )
    from openworkproof.models import population_contract_id

    source["contract_id"] = population_contract_id(source)
    test["contract_id"] = population_contract_id(test)
    raw = case["profile"].model_dump(
        mode="json",
        exclude={"digest", "signature_alg", "signer_key_id", "signature"},
    )
    raw["population_contracts"] = sorted(
        [source, test], key=lambda item: item["contract_id"]
    )
    malformed = VerificationProfileV05.model_validate(
        sign_payload(
            "verification-profile",
            raw,
            case["keys"]["Manager"][0],
            version="0.5",
        )
    )
    with pytest.raises(VerificationTransactionError, match="contracts"):
        commit_verification_profile_v05(case["ledger"], malformed)


def test_v05_profile_rejects_wrong_manager_signature(
    v05_transaction_case,
) -> None:
    case = v05_transaction_case
    commit_verification_profile_v05(case["ledger"], case["profile"])
    raw = case["profile"].model_dump(
        mode="json",
        exclude={"digest", "signature_alg", "signer_key_id", "signature"},
    )
    malformed = VerificationProfileV05.model_validate(
        sign_payload(
            "verification-profile",
            raw,
            case["keys"]["Verifier"][0],
            version="0.5",
        )
    )
    with pytest.raises(VerificationTransactionError, match="Manager"):
        commit_verification_profile_v05(case["ledger"], malformed)


def test_v05_profile_id_conflict_and_precommit_zero_write(
    v05_transaction_case,
) -> None:
    case = v05_transaction_case
    commit_verification_profile_v05(case["ledger"], case["profile"])
    raw = case["profile"].model_dump(
        mode="json",
        exclude={"digest", "signature_alg", "signer_key_id", "signature"},
    )
    raw["nonce"] = "1e" * 32
    conflicting = VerificationProfileV05.model_validate(
        sign_payload(
            "verification-profile",
            raw,
            case["keys"]["Manager"][0],
            version="0.5",
        )
    )
    with pytest.raises(VerificationTransactionError, match="already used"):
        commit_verification_profile_v05(
            case["ledger"], conflicting, fault="commit_failure"
        )
    connection = evidence.connect_ledger(case["ledger"])
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM verification_profiles_v05"
        ).fetchone() == (1,)
    finally:
        connection.close()


def test_v05_profile_ack_loss_is_committed(v05_transaction_case) -> None:
    case = v05_transaction_case
    commit_verification_profile_v05(case["ledger"], case["profile"])
    with pytest.raises(VerificationCommittedError) as raised:
        commit_verification_profile_v05(
            case["ledger"], case["profile"], fault="commit_ack_loss"
        )
    assert raised.value.committed == case["profile"]


def test_v05_profile_concurrency_has_one_exact_truth(v05_transaction_case) -> None:
    case = v05_transaction_case

    def commit_once():
        try:
            return commit_verification_profile_v05(case["ledger"], case["profile"])
        except VerificationCommittedError as error:
            return error.committed

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = tuple(pool.map(lambda _: commit_once(), range(2)))
    assert outcomes == (case["profile"], case["profile"])
    connection = evidence.connect_ledger(case["ledger"])
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM verification_profiles_v05"
        ).fetchone() == (1,)
    finally:
        connection.close()


def test_v05_arm_commits_replayed_population_and_control(
    v05_transaction_case,
) -> None:
    case = v05_transaction_case
    commit_verification_profile_v05(case["ledger"], case["profile"])
    for result in case["results"]:
        assert commit_verification_arm_result_v05(case["ledger"], result) == result
    connection = evidence.connect_ledger(case["ledger"])
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM verification_arm_results_v05"
        ).fetchone() == (2,)
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute(
                "UPDATE verification_arm_results_v05 SET arm_id = '0' * 64"
            )
    finally:
        connection.close()
    with pytest.raises(VerificationCommittedError):
        commit_verification_arm_result_v05(case["ledger"], case["results"][0])


def test_v05_arm_rejects_tampered_population_evidence(
    v05_transaction_case,
) -> None:
    case = v05_transaction_case
    commit_verification_profile_v05(case["ledger"], case["profile"])
    result = case["results"][0]
    observation = result.population_observations[0]
    ref = observation.evidence_refs[0]
    (case["tmp_path"] / ref.path).write_text(
        '{"tampered": true}', encoding="utf-8"
    )
    with pytest.raises(VerificationTransactionError, match="digest"):
        commit_verification_arm_result_v05(case["ledger"], result)


def test_v05_arm_rejects_missing_population_evidence(
    v05_transaction_case,
) -> None:
    case = v05_transaction_case
    commit_verification_profile_v05(case["ledger"], case["profile"])
    result = case["results"][0]
    ref = result.population_observations[0].evidence_refs[0]
    (case["tmp_path"] / ref.path).unlink()
    with pytest.raises(VerificationTransactionError, match="unavailable"):
        commit_verification_arm_result_v05(case["ledger"], result)


def test_v05_arm_rejects_unreplayable_population_digests(
    v05_transaction_case,
) -> None:
    case = v05_transaction_case
    commit_verification_profile_v05(case["ledger"], case["profile"])
    result = case["results"][0]
    observations = [
        observation.model_dump(mode="json")
        for observation in result.population_observations
    ]
    observations[0]["eligible_population_digest"] = "f" * 64
    malformed = _resign_arm_result_v05(
        case, result, population_observations=observations
    )
    with pytest.raises(VerificationTransactionError, match="do not replay"):
        commit_verification_arm_result_v05(case["ledger"], malformed)


def test_v05_arm_rejects_control_status_contradiction(
    v05_transaction_case,
) -> None:
    case = v05_transaction_case
    commit_verification_profile_v05(case["ledger"], case["profile"])
    result = case["results"][1]
    contract = case["profile"].control_contracts[0]
    control = _v05_control_observation(
        case["tmp_path"],
        contract,
        arm_kind="negative",
        control_status="proven",
        fixture_digest="d" * 64,
    )
    malformed = _resign_arm_result_v05(
        case, result, control_observation=control
    )
    with pytest.raises(VerificationTransactionError, match="inconsistent"):
        commit_verification_arm_result_v05(case["ledger"], malformed)


def test_v05_arm_rejects_control_observation_outside_window(
    tmp_path,
    signed_work_order,
    signed_subject_claim,
    evaluation_scope_payload_v03,
    verification_profile_v03,
    ephemeral_role_keys,
    sidecar_receipt_factory,
) -> None:
    ledger = tmp_path / "verification-v05-window.sqlite3"
    evidence.initialize_ledger(ledger, signed_work_order)
    selector_parent = tmp_path / "scope/selectors"
    selector_parent.mkdir(parents=True, exist_ok=True)
    source_spec = {
        "schema_version": "openworkproof-selector-spec/0.3",
        "selector_kind": "explicit",
        "locators": ["src/widget.py"],
    }
    test_spec = {
        "schema_version": "openworkproof-selector-spec/0.3",
        "selector_kind": "explicit",
        "locators": ["tests/test_widget.py::test_widget[param-\u4e00]"],
    }
    source_raw = rfc8785.dumps(source_spec)
    test_raw = rfc8785.dumps(test_spec)
    (selector_parent / "source.json").write_bytes(source_raw)
    (selector_parent / "tests.json").write_bytes(test_raw)
    scope_payload = copy.deepcopy(evaluation_scope_payload_v03)
    original = scope_payload["selector_rules"][0]
    scope_payload["selector_rules"] = [
        {
            **original,
            "rule_id": "3" * 64,
            "selector_spec_digest": hashlib.sha256(source_raw).hexdigest(),
            "selector_engine_digest": "5" * 64,
            "required_evidence_paths": ["scope/selectors/source.json"],
        },
        {
            **original,
            "rule_id": "6" * 64,
            "selector_spec_digest": hashlib.sha256(test_raw).hexdigest(),
            "selector_engine_digest": "8" * 64,
            "required_evidence_paths": ["scope/selectors/tests.json"],
        },
    ]
    manifest = _transaction_manifest(
        scope_payload,
        work_order=signed_work_order,
        claim=signed_subject_claim,
        manager_key=ephemeral_role_keys["Manager"][0],
    )
    profile = _transaction_profile_v05(
        verification_profile_v03,
        manifest=manifest,
        manager_key=ephemeral_role_keys["Manager"][0],
        control_changes={
            "valid_from": "2026-01-01T00:00:00Z",
            "expires_at": "2026-01-01T00:05:00Z",
        },
    )
    commit_evaluation_scope(ledger, signed_subject_claim, manifest)
    commit_verification_profile_v05(ledger, profile)
    receipt = sidecar_receipt_factory(
        state_before="locally_verified",
        state_after="evidence_incomplete",
        event_type="system_event",
        event_name="proof_composed",
        sequence=1,
    )
    _insert_transaction_receipt(ledger, receipt)
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
        evidence_complete=True,
    )
    kind = "negative"
    result_ref = _write_json_evidence(
        tmp_path, f"results/{kind}.json", {"arm": kind, "passed": True}
    )
    scope_ref = _write_json_evidence(
        tmp_path, f"scope/{kind}.json", observed.model_dump(mode="json")
    )
    observations = [
        _v05_population_observation(
            tmp_path, contract, suffix=f"{kind}-{contract.member_kind}"
        )
        for contract in profile.population_contracts
    ]
    control = _v05_control_observation(
        tmp_path, profile.control_contracts[0], arm_kind=kind
    )
    result = _v05_arm_result(
        profile=profile,
        manifest=manifest,
        keys=ephemeral_role_keys,
        arm_kind=kind,
        observations=observations,
        control_observation=control,
        action_receipt_id=receipt.receipt_id,
        evidence_ref=result_ref,
        scope_evidence_ref=scope_ref,
    )
    with pytest.raises(VerificationTransactionError, match="window"):
        commit_verification_arm_result_v05(ledger, result)


def test_v05_arm_precommit_fault_zero_write_and_ack_loss_committed(
    v05_transaction_case,
) -> None:
    case = v05_transaction_case
    commit_verification_profile_v05(case["ledger"], case["profile"])
    result = case["results"][0]
    with pytest.raises(VerificationTransactionError):
        commit_verification_arm_result_v05(
            case["ledger"], result, fault="commit_failure"
        )
    connection = evidence.connect_ledger(case["ledger"])
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM verification_arm_results_v05"
        ).fetchone() == (0,)
    finally:
        connection.close()
    with pytest.raises(VerificationCommittedError) as raised:
        commit_verification_arm_result_v05(
            case["ledger"], result, fault="commit_ack_loss"
        )
    assert raised.value.committed == result


def test_v05_arm_concurrency_has_one_exact_truth(v05_transaction_case) -> None:
    case = v05_transaction_case
    commit_verification_profile_v05(case["ledger"], case["profile"])
    result = case["results"][0]

    def commit_once():
        try:
            return commit_verification_arm_result_v05(case["ledger"], result)
        except VerificationCommittedError as error:
            return error.committed

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = tuple(pool.map(lambda _: commit_once(), range(2)))
    assert outcomes == (result, result)
    connection = evidence.connect_ledger(case["ledger"])
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM verification_arm_results_v05"
        ).fetchone() == (1,)
    finally:
        connection.close()


def test_v05_profile_rejects_reused_nonce(v05_transaction_case) -> None:
    case = v05_transaction_case
    commit_verification_profile_v05(case["ledger"], case["profile"])
    raw = case["profile"].model_dump(
        mode="json",
        exclude={"digest", "signature_alg", "signer_key_id", "signature"},
    )
    raw["profile_id"] = "7" * 64
    conflicting = VerificationProfileV05.model_validate(
        sign_payload(
            "verification-profile",
            raw,
            case["keys"]["Manager"][0],
            version="0.5",
        )
    )
    with pytest.raises(VerificationTransactionError, match="nonce"):
        commit_verification_profile_v05(case["ledger"], conflicting)


def test_v05_profile_rejects_outside_scope_window(v05_transaction_case) -> None:
    case = v05_transaction_case
    raw = case["profile"].model_dump(
        mode="json",
        exclude={"digest", "signature_alg", "signer_key_id", "signature"},
    )
    raw["created_at"] = "2025-01-01T00:00:00Z"
    stale = VerificationProfileV05.model_validate(
        sign_payload(
            "verification-profile",
            raw,
            case["keys"]["Manager"][0],
            version="0.5",
        )
    )
    with pytest.raises(VerificationTransactionError, match="validity"):
        commit_verification_profile_v05(case["ledger"], stale)


def test_v05_arm_rejects_stale_profile_result(v05_transaction_case) -> None:
    case = v05_transaction_case
    commit_verification_profile_v05(case["ledger"], case["profile"])
    result = _resign_arm_result_v05(
        case, case["results"][0], created_at="2026-01-01T02:00:00Z"
    )
    with pytest.raises(VerificationTransactionError, match="signature"):
        commit_verification_arm_result_v05(case["ledger"], result)


@pytest.mark.parametrize(
    ("fault", "expected", "rows"),
    (
        ("insert_failure", (VerificationTransactionError,), 0),
        ("before_commit", (VerificationTransactionError,), 0),
        ("readback_failure", (VerificationCommitIndeterminateError,), 1),
        ("cleanup_failure", (VerificationCommittedError,), 1),
    ),
)
def test_v05_arm_remaining_faults_are_closed(
    v05_transaction_case, fault: str, expected, rows: int
) -> None:
    case = v05_transaction_case
    commit_verification_profile_v05(case["ledger"], case["profile"])
    result = case["results"][0]
    with pytest.raises(expected):
        commit_verification_arm_result_v05(case["ledger"], result, fault=fault)
    connection = evidence.connect_ledger(case["ledger"])
    try:
        count = connection.execute(
            "SELECT COUNT(*) FROM verification_arm_results_v05"
        ).fetchone()[0]
    finally:
        connection.close()
    assert count == rows


@pytest.mark.parametrize(
    ("fault", "expected", "rows"),
    (
        ("readback_failure", (VerificationCommitIndeterminateError,), 1),
        ("cleanup_failure", (VerificationCommittedError,), 1),
    ),
)
def test_v05_profile_remaining_faults_are_closed(
    v05_transaction_case, fault: str, expected, rows: int
) -> None:
    case = v05_transaction_case
    raw = case["profile"].model_dump(
        mode="json",
        exclude={"digest", "signature_alg", "signer_key_id", "signature"},
    )
    raw["profile_id"] = "7" * 64
    fresh = VerificationProfileV05.model_validate(
        sign_payload(
            "verification-profile",
            raw,
            case["keys"]["Manager"][0],
            version="0.5",
        )
    )
    with pytest.raises(expected):
        commit_verification_profile_v05(case["ledger"], fresh, fault=fault)
    connection = evidence.connect_ledger(case["ledger"])
    try:
        count = connection.execute(
            "SELECT COUNT(*) FROM verification_profiles_v05 "
            "WHERE profile_id = ?",
            (fresh.profile_id,),
        ).fetchone()[0]
    finally:
        connection.close()
    assert count == rows
