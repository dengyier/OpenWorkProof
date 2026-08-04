"""Trusted handler coordination tests."""

from __future__ import annotations

from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import sqlite3

import pytest
import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

import openworkproof.evidence as evidence
import openworkproof.mcp_server as mcp_server
import openworkproof.repo_tools as repo_tools
from openworkproof.mcp_server import (
    HandlerCoordinationError,
    ToolCallDenied,
    execute_run_tests,
)
from openworkproof.models import (
    AgentRequest,
    CapabilityGrant,
    RollbackReceipt,
    RunTestsArguments,
    TestResultEvidence as ResultEvidence,
    ToolCallReceipt,
    WorkOrder,
    request_arguments_digest,
)
from openworkproof.policy import (
    AuthorizationLedgerPrefix,
    CommittedEvidence,
    ProspectiveExecutionFacts,
    derive_authorization_context,
)
from openworkproof.repo_tools import (
    ReplayCheckpoint,
    ResolutionManifest,
    ResolutionManifestEntry,
    build_workspace_manifest,
    resolution_manifest_digest,
    workspace_manifest_digest,
)
from openworkproof.signing import sign_payload

from test_receipt_chain import (
    _activate_ledger_root,
    _append_action_receipt,
    _child_grant,
    _delegation_request,
    _grant_id,
    _grant_replay_inputs,
    _issue_child,
    _jcs_digest,
    _linked_tool_receipt,
    _resigned_work_order,
    _work_order_with_pr_chain_predicates,
)


def _resigned_root(
    work_order: WorkOrder,
    maintainer_key: Ed25519PrivateKey,
) -> CapabilityGrant:
    raw = work_order.root_grant_template.model_dump(mode="json")
    raw["work_order_digest"] = work_order.digest
    return CapabilityGrant.model_validate(
        sign_payload("capability-grant", raw, maintainer_key)
    )


def _append_active_patch(
    *,
    ledger_path: Path,
    evidence_root: Path,
    work_order: WorkOrder,
    developer: CapabilityGrant,
    developer_issuance,
    role_keys,
    sidecar_receipt_factory,
    now: datetime,
) -> tuple[ToolCallReceipt, ReplayCheckpoint, tuple[CommittedEvidence, ...]]:
    patch_bytes = b"0123456789"
    patch_digest = hashlib.sha256(patch_bytes).hexdigest()
    candidate_commit = "2" * 40
    source_manifest = build_workspace_manifest(work_order.source_commit, ())
    candidate_manifest = build_workspace_manifest(candidate_commit, ())
    candidate_manifest_digest = workspace_manifest_digest(candidate_manifest)
    result = {
        "schema_version": "openworkproof-patch-result/0.1",
        "parent_commit": work_order.source_commit,
        "parent_manifest_digest": workspace_manifest_digest(source_manifest),
        "candidate_commit": candidate_commit,
        "workspace_manifest_digest": candidate_manifest_digest,
        "patch_digest": patch_digest,
        "patch_size_bytes": len(patch_bytes),
        "replay_profile_digest": work_order.replay_profile_digest,
    }
    result_bytes = rfc8785.dumps(result)
    result_digest = hashlib.sha256(result_bytes).hexdigest()
    receipt = _linked_tool_receipt(
        tool_name="owp.apply_patch",
        state_before="running",
        state_after="running",
        sequence=developer_issuance.sequence + 1,
        previous_receipt=developer_issuance,
        root=developer,
        signed_work_order=work_order,
        sidecar_receipt_factory=sidecar_receipt_factory,
        role_keys=role_keys,
        label="handler-loop:patch",
        actor_role="Developer",
        remaining_after=1,
        occurred_at="2026-01-01T00:00:05Z",
    )
    raw = receipt.model_dump(mode="json")
    arguments = {
        "target_paths": ["src/x"],
        "patch_digest": patch_digest,
        "patch_size_bytes": len(patch_bytes),
    }
    manifest = ResolutionManifest(
        schema_version="openworkproof-resolution-manifest/0.1",
        workspace_manifest_digest=result["parent_manifest_digest"],
        requested_paths=("src/x",),
        resolved_entries=(
            ResolutionManifestEntry(
                requested_path="src/x",
                resolved_relative_path="src/x",
            ),
        ),
    )
    raw.update(
        {
            "request_arguments": arguments,
            "arguments_digest": request_arguments_digest(
                "owp.apply_patch", arguments
            ),
            "output_digest": result_digest,
            "evidence_refs": [
                {
                    "path": "evidence/patch-input/01.diff",
                    "sha256": patch_digest,
                    "media_type": "text/x-diff",
                    "size_bytes": len(patch_bytes),
                },
                {
                    "path": "evidence/patch-result/01.json",
                    "sha256": result_digest,
                    "media_type": "application/json",
                    "size_bytes": len(result_bytes),
                },
            ],
        }
    )
    for predicate in raw["predicate_results"]:
        if predicate["name"] == "path_allowed":
            predicate["input"]["resolution_manifest_digest"] = (
                resolution_manifest_digest(manifest)
            )
        elif predicate["name"] == "quota_remaining":
            predicate["input"].update(
                {
                    "grant_id": developer.grant_id,
                    "grant_remaining_before": 2,
                    "ledger_prefix_digest": developer_issuance.digest,
                }
            )
        else:
            continue
        predicate["input_digest"] = _jcs_digest(
            {
                "domain": "openworkproof/predicate-input/v0.1",
                "predicate_id": predicate["predicate_id"],
                "input": predicate["input"],
            }
        )
    claim = raw["nested_claim"]
    claim["arguments_digest"] = raw["arguments_digest"]
    claim = sign_payload("agent-request", claim, role_keys["Developer"][0])
    raw["nested_claim"] = claim
    raw["nested_claim_digest"] = claim["digest"]
    receipt = evidence.ACTION_RECEIPT_ADAPTER.validate_python(
        sign_payload("action-receipt", raw, role_keys["Sidecar"][0])
    )
    payloads = {
        receipt.evidence_refs[0].path: patch_bytes,
        receipt.evidence_refs[1].path: result_bytes,
    }
    evidence.complete_receipt_publication(
        ledger_path,
        evidence_root=evidence_root,
        receipt=receipt,
        payloads=payloads,
        clock=lambda: now,
        trusted_resolution_manifest=manifest,
    )
    checkpoint = ReplayCheckpoint(
        files=(),
        head_commit=candidate_commit,
        workspace_manifest=candidate_manifest,
        workspace_manifest_digest=candidate_manifest_digest,
        verified_test_results=(),
    )
    committed = tuple(
        CommittedEvidence(
            reference=reference,
            payload=payloads[reference.path],
        )
        for reference in receipt.evidence_refs
    )
    return receipt, checkpoint, committed


def _run_tests_case(
    *,
    tmp_path: Path,
    signed_work_order: WorkOrder,
    role_keys,
    sidecar_receipt_factory,
    now: datetime,
):
    work_order = _work_order_with_pr_chain_predicates(
        signed_work_order,
        role_keys["Maintainer"][0],
    )
    root = _resigned_root(work_order, role_keys["Maintainer"][0])
    ledger_path = tmp_path / "handler-loop.sqlite3"
    evidence_root = tmp_path / "handler-loop-evidence"
    evidence_root.mkdir()
    _activate_ledger_root(ledger_path, work_order, root, role_keys, now)
    verifier = _child_grant(
        work_order,
        root,
        role_keys,
        label="handler-loop:verifier",
        subject_role="Verifier",
        updates={"quota": {"tool_calls": 1, "repair_rounds": 0}},
    )
    verifier_issuance = _issue_child(
        ledger_path,
        verifier,
        _delegation_request(
            work_order,
            root,
            verifier,
            role_keys,
            actor_role="Manager",
            nonce=_grant_id("handler-loop:verifier-request"),
        ),
        role_keys,
        now,
    )
    developer = _child_grant(
        work_order,
        root,
        role_keys,
        label="handler-loop:developer",
        updates={
            "allowed_tools": ["owp.apply_patch", "owp.rollback_patch"],
            "quota": {"tool_calls": 2, "repair_rounds": 0},
        },
    )
    developer_issuance = _issue_child(
        ledger_path,
        developer,
        _delegation_request(
            work_order,
            root,
            developer,
            role_keys,
            actor_role="Manager",
            nonce=_grant_id("handler-loop:developer-request"),
        ),
        role_keys,
        now,
    )
    patch, checkpoint, committed = _append_active_patch(
        ledger_path=ledger_path,
        evidence_root=evidence_root,
        work_order=work_order,
        developer=developer,
        developer_issuance=developer_issuance,
        role_keys=role_keys,
        sidecar_receipt_factory=sidecar_receipt_factory,
        now=now,
    )
    receipts, grants, attempts = _grant_replay_inputs(
        ledger_path, work_order
    )
    context = derive_authorization_context(
        work_order,
        AuthorizationLedgerPrefix(
            effective_grants=tuple(
                sorted(grants.values(), key=lambda item: item.grant_id)
            ),
            grant_attempts=tuple(
                sorted(attempts.values(), key=lambda item: item.digest)
            ),
            receipts=receipts,
        ),
        committed,
        checkpoint,
        now,
    )
    profile = next(
        item for item in work_order.test_profiles if item.test_mode == "verifier"
    )
    arguments = RunTestsArguments(
        test_mode="verifier",
        command_digest=profile.command_digest,
        source_commit=work_order.source_commit,
        candidate_commit=checkpoint.head_commit,
        workspace_manifest_digest=checkpoint.workspace_manifest_digest,
        container_image_digest=profile.container_image_digest,
        fixed_test_source_digest=profile.fixed_test_source_digest,
    )
    binding = role_keys["Verifier"][1]
    request = AgentRequest.model_validate(
        sign_payload(
            "agent-request",
            {
                "claim_type": "agent-request",
                "work_order_digest": work_order.digest,
                "grant_id": verifier.grant_id,
                "actor_id": binding["subject_id"],
                "actor_key_id": binding["key_id"],
                "tool_name": "owp.run_tests",
                "arguments_digest": request_arguments_digest(
                    "owp.run_tests", arguments
                ),
                "nonce": _grant_id("handler-loop:test-request"),
                "requested_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "authentication_method": "agent_signature",
                "model_id": "model",
                "model_version": "1",
                "prompt_template_digest": "a" * 64,
                "context_source_digest": "b" * 64,
            },
            role_keys["Verifier"][0],
        )
    )
    facts = ProspectiveExecutionFacts(
        execution_context_id="1" * 64,
        container_instance_id_digest="2" * 64,
        controller_id=role_keys["Sidecar"][1]["key_id"],
    )
    return {
        "ledger_path": ledger_path,
        "evidence_root": evidence_root,
        "work_order": work_order,
        "context": context,
        "request": request,
        "arguments": arguments,
        "facts": facts,
        "verifier": verifier,
        "developer": developer,
        "verifier_issuance": verifier_issuance,
        "patch": patch,
    }


def _run_tests_contract(case) -> repo_tools.RunTestsExecutionContract:
    arguments = case["arguments"]
    return repo_tools.RunTestsExecutionContract(
        execution_id=mcp_server._handler_execution_id(
            case["request"], case["facts"]
        ),
        request_digest=case["request"].digest,
        arguments_digest=case["request"].arguments_digest,
        candidate_workspace_id="c" * 64,
        source_artifact_sha256=(
            case["work_order"].replay_profile.source_artifact_sha256
        ),
        source_commit=arguments.source_commit,
        candidate_commit=arguments.candidate_commit,
        workspace_manifest_digest=arguments.workspace_manifest_digest,
        container_image_digest=arguments.container_image_digest,
        command_digest=arguments.command_digest,
        fixed_test_source_digest=arguments.fixed_test_source_digest,
    )


def _request_for_grant(case, grant, role_keys) -> AgentRequest:
    binding = next(
        item
        for item in case["work_order"].key_bindings
        if item.key_id == grant.subject_key_id
    )
    role = next(
        name
        for name, (_, raw) in role_keys.items()
        if raw["key_id"] == binding.key_id
    )
    return AgentRequest.model_validate(
        sign_payload(
            "agent-request",
            {
                **case["request"].model_dump(
                    mode="json",
                    exclude={
                        "digest",
                        "signature_alg",
                        "signer_key_id",
                        "signature",
                    },
                ),
                "grant_id": grant.grant_id,
                "actor_id": binding.subject_id,
                "actor_key_id": binding.key_id,
                "nonce": _grant_id(f"handler-loop:{role}:denied"),
            },
            role_keys[role][0],
        )
    )


def test_handler_journal_schema_includes_run_tests_recovery_fields(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now: datetime,
) -> None:
    case = _run_tests_case(
        tmp_path=tmp_path,
        signed_work_order=signed_work_order,
        role_keys=ephemeral_role_keys,
        sidecar_receipt_factory=sidecar_receipt_factory,
        now=fixed_now,
    )
    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        columns = connection.execute(
            "PRAGMA table_info(handler_executions)"
        ).fetchall()
    finally:
        connection.close()
    assert {row[1] for row in columns} >= {
        "request_json",
        "execution_contract_json",
        "execution_contract_digest",
    }


def test_handler_journal_recovery_fields_are_closed_by_tool(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now: datetime,
) -> None:
    case = _run_tests_case(
        tmp_path=tmp_path,
        signed_work_order=signed_work_order,
        role_keys=ephemeral_role_keys,
        sidecar_receipt_factory=sidecar_receipt_factory,
        now=fixed_now,
    )
    connection = evidence.connect_ledger(case["ledger_path"])
    insert = """
        INSERT INTO handler_executions (
            execution_id, work_order_digest, request_digest, nonce,
            grant_id, tool_name, arguments_digest, execution_context_id,
            container_instance_id_digest, controller_id, reserved_at, state,
            request_json, execution_contract_json,
            execution_contract_digest
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'RESERVED', ?, ?, ?)
    """
    common = (
        "0" * 64,
        case["work_order"].digest,
        "1" * 64,
        "2" * 64,
        case["verifier"].grant_id,
        "owp.run_tests",
        "3" * 64,
        "4" * 64,
        "5" * 64,
        case["facts"].controller_id,
        fixed_now.strftime("%Y-%m-%dT%H:%M:%SZ"),
    )
    try:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(insert, (*common, None, None, None))
        rollback = (
            "6" * 64,
            case["work_order"].digest,
            "7" * 64,
            "8" * 64,
            case["developer"].grant_id,
            "owp.rollback_patch",
            "9" * 64,
            "a" * 64,
            "b" * 64,
            case["facts"].controller_id,
            fixed_now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(insert, (*rollback, "{}", "{}", "c" * 64))
    finally:
        connection.close()


@pytest.mark.parametrize(
    "predecessor",
    (
        evidence._HANDLER_EXECUTION_SCHEMA_V1,
        evidence._LEGACY_HANDLER_EXECUTION_SCHEMA,
    ),
)
def test_handler_journal_schema_migrates_empty_predecessors(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now: datetime,
    predecessor: str,
) -> None:
    case = _run_tests_case(
        tmp_path=tmp_path,
        signed_work_order=signed_work_order,
        role_keys=ephemeral_role_keys,
        sidecar_receipt_factory=sidecar_receipt_factory,
        now=fixed_now,
    )
    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        connection.execute("DROP TABLE handler_executions")
        connection.execute(predecessor)
    finally:
        connection.close()
    lock_descriptor = evidence._acquire_target_lock(case["ledger_path"])
    try:
        mcp_server._ensure_handler_execution_schema(
            case["ledger_path"], lock_descriptor
        )
    finally:
        evidence._release_target_lock(lock_descriptor)
    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        stored = connection.execute(
            """
            SELECT sql FROM sqlite_master
            WHERE type = 'table' AND name = 'handler_executions'
            """
        ).fetchone()
    finally:
        connection.close()
    assert stored is not None
    assert mcp_server._normalized_sql(stored[0]) == mcp_server._normalized_sql(
        evidence._HANDLER_EXECUTION_SCHEMA
    )


@pytest.mark.parametrize(
    "predecessor",
    (
        evidence._HANDLER_EXECUTION_SCHEMA_V1,
        evidence._LEGACY_HANDLER_EXECUTION_SCHEMA,
    ),
)
def test_handler_journal_schema_rejects_nonempty_predecessors(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now: datetime,
    predecessor: str,
) -> None:
    case = _run_tests_case(
        tmp_path=tmp_path,
        signed_work_order=signed_work_order,
        role_keys=ephemeral_role_keys,
        sidecar_receipt_factory=sidecar_receipt_factory,
        now=fixed_now,
    )
    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        connection.execute("DROP TABLE handler_executions")
        connection.execute(predecessor)
        connection.execute(
            """
            INSERT INTO handler_executions (
                execution_id, work_order_digest, request_digest, nonce,
                grant_id, tool_name, arguments_digest,
                execution_context_id, container_instance_id_digest,
                controller_id, reserved_at, state
            ) VALUES (?, ?, ?, ?, ?, 'owp.run_tests', ?, ?, ?, ?, ?, 'RESERVED')
            """,
            (
                "0" * 64,
                case["work_order"].digest,
                case["request"].digest,
                case["request"].nonce,
                case["verifier"].grant_id,
                case["request"].arguments_digest,
                case["facts"].execution_context_id,
                case["facts"].container_instance_id_digest,
                case["facts"].controller_id,
                fixed_now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            ),
        )
    finally:
        connection.close()
    lock_descriptor = evidence._acquire_target_lock(case["ledger_path"])
    try:
        with pytest.raises(
            HandlerCoordinationError, match="RECOVERY_REQUIRED"
        ):
            mcp_server._ensure_handler_execution_schema(
                case["ledger_path"], lock_descriptor
            )
    finally:
        evidence._release_target_lock(lock_descriptor)


def test_handler_journal_persists_and_loads_exact_recovery_fields(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now: datetime,
) -> None:
    case = _run_tests_case(
        tmp_path=tmp_path,
        signed_work_order=signed_work_order,
        role_keys=ephemeral_role_keys,
        sidecar_receipt_factory=sidecar_receipt_factory,
        now=fixed_now,
    )
    contract = _run_tests_contract(case)
    lock_descriptor = evidence._acquire_target_lock(case["ledger_path"])
    try:
        execution_id = mcp_server._reserve_handler_execution(
            case["ledger_path"],
            lock_descriptor,
            case["context"],
            case["request"],
            case["facts"],
            contract,
        )
        stored = mcp_server._load_stored_run_tests_execution(
            case["ledger_path"], lock_descriptor
        )
    finally:
        evidence._release_target_lock(lock_descriptor)
    assert stored == mcp_server._StoredRunTestsExecution(
        execution_id=execution_id,
        request=case["request"],
        contract=contract,
        reserved_at=fixed_now,
        state="RESERVED",
    )
    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        row = connection.execute(
            """
            SELECT request_json, execution_contract_json,
                   execution_contract_digest
            FROM handler_executions
            """
        ).fetchone()
    finally:
        connection.close()
    request_bytes = rfc8785.dumps(case["request"].model_dump(mode="json"))
    contract_bytes = repo_tools.encode_run_tests_execution_contract(contract)
    assert row == (
        request_bytes.decode("utf-8"),
        contract_bytes.decode("utf-8"),
        hashlib.sha256(contract_bytes).hexdigest(),
    )


def test_handler_journal_recovery_fields_reject_mixed_tool_rows(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now: datetime,
) -> None:
    case = _run_tests_case(
        tmp_path=tmp_path,
        signed_work_order=signed_work_order,
        role_keys=ephemeral_role_keys,
        sidecar_receipt_factory=sidecar_receipt_factory,
        now=fixed_now,
    )
    lock_descriptor = evidence._acquire_target_lock(case["ledger_path"])
    try:
        mcp_server._reserve_handler_execution(
            case["ledger_path"],
            lock_descriptor,
            case["context"],
            case["request"],
            case["facts"],
            _run_tests_contract(case),
        )
        connection = evidence.connect_ledger(case["ledger_path"])
        try:
            connection.execute(
                """
                INSERT INTO handler_executions (
                    execution_id, work_order_digest, request_digest, nonce,
                    grant_id, tool_name, arguments_digest,
                    execution_context_id, container_instance_id_digest,
                    controller_id, reserved_at, state,
                    request_json, execution_contract_json,
                    execution_contract_digest
                ) VALUES (
                    ?, ?, ?, ?, ?, 'owp.rollback_patch', ?, ?, ?, ?, ?,
                    'RESERVED', NULL, NULL, NULL
                )
                """,
                (
                    "d" * 64,
                    case["work_order"].digest,
                    "e" * 64,
                    "f" * 64,
                    case["developer"].grant_id,
                    "0" * 64,
                    "3" * 64,
                    "4" * 64,
                    case["facts"].controller_id,
                    fixed_now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                ),
            )
        finally:
            connection.close()
        with pytest.raises(
            HandlerCoordinationError, match="RECOVERY_REQUIRED"
        ):
            mcp_server._load_stored_run_tests_execution(
                case["ledger_path"], lock_descriptor
            )
    finally:
        evidence._release_target_lock(lock_descriptor)


@pytest.mark.parametrize(
    "tamper",
    (
        "duplicate_request_key",
        "noncanonical_request",
        "request_signature",
        "contract_digest",
        "contract_arguments",
        "journal_arguments_digest",
        "developer_contract",
        "reserved_at",
    ),
)
def test_handler_journal_recovery_fields_reject_tampering(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now: datetime,
    tamper: str,
) -> None:
    case = _run_tests_case(
        tmp_path=tmp_path,
        signed_work_order=signed_work_order,
        role_keys=ephemeral_role_keys,
        sidecar_receipt_factory=sidecar_receipt_factory,
        now=fixed_now,
    )
    contract = _run_tests_contract(case)
    lock_descriptor = evidence._acquire_target_lock(case["ledger_path"])
    try:
        mcp_server._reserve_handler_execution(
            case["ledger_path"],
            lock_descriptor,
            case["context"],
            case["request"],
            case["facts"],
            contract,
        )
        connection = evidence.connect_ledger(case["ledger_path"])
        try:
            if tamper == "duplicate_request_key":
                original = connection.execute(
                    "SELECT request_json FROM handler_executions"
                ).fetchone()[0]
                value = '{"actor_id":"duplicate",' + original[1:]
                connection.execute(
                    "UPDATE handler_executions SET request_json = ?", (value,)
                )
            elif tamper == "noncanonical_request":
                connection.execute(
                    "UPDATE handler_executions SET request_json = request_json || ' '"
                )
            elif tamper == "request_signature":
                raw = connection.execute(
                    "SELECT request_json FROM handler_executions"
                ).fetchone()[0]
                value = json.loads(raw)
                value["model_id"] = "tampered"
                connection.execute(
                    "UPDATE handler_executions SET request_json = ?",
                    (rfc8785.dumps(value).decode("utf-8"),),
                )
            elif tamper == "contract_digest":
                connection.execute(
                    "UPDATE handler_executions SET execution_contract_digest = ?",
                    ("0" * 64,),
                )
            elif tamper == "contract_arguments":
                raw = connection.execute(
                    "SELECT execution_contract_json FROM handler_executions"
                ).fetchone()[0]
                value = json.loads(raw)
                value["candidate_commit"] = "0" * 40
                changed = rfc8785.dumps(value)
                connection.execute(
                    """
                    UPDATE handler_executions
                    SET execution_contract_json = ?, execution_contract_digest = ?
                    """,
                    (
                        changed.decode("utf-8"),
                        hashlib.sha256(changed).hexdigest(),
                    ),
                )
            elif tamper == "journal_arguments_digest":
                connection.execute(
                    "UPDATE handler_executions SET arguments_digest = ?",
                    ("0" * 64,),
                )
            elif tamper == "developer_contract":
                raw = connection.execute(
                    "SELECT execution_contract_json FROM handler_executions"
                ).fetchone()[0].replace(
                    '"test_mode":"verifier"', '"test_mode":"developer"'
                )
                connection.execute(
                    """
                    UPDATE handler_executions
                    SET execution_contract_json = ?, execution_contract_digest = ?
                    """,
                    (raw, hashlib.sha256(raw.encode("utf-8")).hexdigest()),
                )
            else:
                connection.execute(
                    "UPDATE handler_executions SET reserved_at = ?",
                    ("2026-01-01T00:00:05.1Z",),
                )
        finally:
            connection.close()
        with pytest.raises(
            HandlerCoordinationError, match="RECOVERY_REQUIRED"
        ):
            mcp_server._load_stored_run_tests_execution(
                case["ledger_path"], lock_descriptor
            )
    finally:
        evidence._release_target_lock(lock_descriptor)


def test_execute_run_tests_completes_authorize_handler_publish_loop(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now: datetime,
) -> None:
    case = _run_tests_case(
        tmp_path=tmp_path,
        signed_work_order=signed_work_order,
        role_keys=ephemeral_role_keys,
        sidecar_receipt_factory=sidecar_receipt_factory,
        now=fixed_now,
    )
    calls = []

    def handler(arguments: RunTestsArguments) -> int:
        calls.append(arguments)
        return 0

    receipt = execute_run_tests(
        case["ledger_path"],
        evidence_root=case["evidence_root"],
        context=case["context"],
        request=case["request"],
        request_arguments=case["arguments"],
        execution_contract=_run_tests_contract(case),
        execution_facts=case["facts"],
        sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
        handler=handler,
        clock=lambda: fixed_now,
    )

    assert calls == [case["arguments"]]
    assert receipt.policy_decision == "allow"
    assert receipt.execution_status == "succeeded"
    assert receipt.state_before == "running"
    assert receipt.state_after == "locally_verified"
    assert receipt.parent_receipt_ids == (
        case["verifier_issuance"].receipt_id,
        case["patch"].receipt_id,
    )
    assert receipt.quota_charge.remaining_after == 0
    assert len(receipt.evidence_refs) == 1
    final = (
        case["evidence_root"]
        / receipt.evidence_refs[0].path.removeprefix("evidence/")
    )
    result = json.loads(final.read_bytes())
    assert result["actual_exit_code"] == 0
    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        assert connection.execute(
            "SELECT current_state, version FROM work_order_state"
        ).fetchone() == ("locally_verified", receipt.sequence)
        assert connection.execute(
            "SELECT state FROM evidence_publications WHERE receipt_id = ?",
            (receipt.receipt_id,),
        ).fetchone() == ("COMMITTED",)
    finally:
        connection.close()


def test_execute_run_tests_commits_started_handler_failure_without_evidence(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now: datetime,
) -> None:
    case = _run_tests_case(
        tmp_path=tmp_path,
        signed_work_order=signed_work_order,
        role_keys=ephemeral_role_keys,
        sidecar_receipt_factory=sidecar_receipt_factory,
        now=fixed_now,
    )

    def handler(arguments: RunTestsArguments) -> int:
        del arguments
        raise RuntimeError("secret infrastructure detail")

    receipt = execute_run_tests(
        case["ledger_path"],
        evidence_root=case["evidence_root"],
        context=case["context"],
        request=case["request"],
        request_arguments=case["arguments"],
        execution_contract=_run_tests_contract(case),
        execution_facts=case["facts"],
        sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
        handler=handler,
        clock=lambda: fixed_now,
    )

    assert receipt.execution_status == "failed"
    assert receipt.execution_error_code == "HANDLER_ERROR"
    assert receipt.state_before == receipt.state_after == "running"
    assert receipt.evidence_refs == ()
    assert receipt.quota_charge.remaining_after == 0
    assert "secret" not in receipt.model_dump_json()
    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM evidence_publications WHERE receipt_id = ?",
            (receipt.receipt_id,),
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT COUNT(*) FROM grant_events WHERE receipt_id = ?",
            (receipt.receipt_id,),
        ).fetchone() == (1,)
    finally:
        connection.close()


def test_execute_run_tests_denial_never_starts_handler_or_writes(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now: datetime,
) -> None:
    case = _run_tests_case(
        tmp_path=tmp_path,
        signed_work_order=signed_work_order,
        role_keys=ephemeral_role_keys,
        sidecar_receipt_factory=sidecar_receipt_factory,
        now=fixed_now,
    )
    request = _request_for_grant(
        case,
        case["developer"],
        ephemeral_role_keys,
    )
    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        before = connection.execute(
            "SELECT COUNT(*), MAX(sequence) FROM receipts"
        ).fetchone()
    finally:
        connection.close()

    with pytest.raises(ToolCallDenied) as captured:
        execute_run_tests(
            case["ledger_path"],
            evidence_root=case["evidence_root"],
            context=case["context"],
            request=request,
            request_arguments=case["arguments"],
            execution_contract=_run_tests_contract(case),
            execution_facts=case["facts"],
            sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
            handler=lambda _: pytest.fail("denied handler started"),
            clock=lambda: fixed_now,
        )

    assert captured.value.decision.error_code == "ROLE_DENIED"
    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        assert connection.execute(
            "SELECT COUNT(*), MAX(sequence) FROM receipts"
        ).fetchone() == before
    finally:
        connection.close()


def test_execute_run_tests_rejects_stale_context_before_second_handler(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now: datetime,
) -> None:
    case = _run_tests_case(
        tmp_path=tmp_path,
        signed_work_order=signed_work_order,
        role_keys=ephemeral_role_keys,
        sidecar_receipt_factory=sidecar_receipt_factory,
        now=fixed_now,
    )
    execute_run_tests(
        case["ledger_path"],
        evidence_root=case["evidence_root"],
        context=case["context"],
        request=case["request"],
        request_arguments=case["arguments"],
        execution_contract=_run_tests_contract(case),
        execution_facts=case["facts"],
        sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
        handler=lambda _: 0,
        clock=lambda: fixed_now,
    )

    with pytest.raises(
        HandlerCoordinationError,
        match="current ledger snapshot",
    ):
        execute_run_tests(
            case["ledger_path"],
            evidence_root=case["evidence_root"],
            context=case["context"],
            request=case["request"],
            request_arguments=case["arguments"],
            execution_contract=_run_tests_contract(case),
            execution_facts=case["facts"],
            sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
            handler=lambda _: pytest.fail("stale handler started"),
            clock=lambda: fixed_now,
        )


def test_execute_run_tests_rejects_missing_evidence_capacity_before_handler(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now: datetime,
) -> None:
    artifacts = tuple(
        artifact.model_copy(update={"max_size_bytes": 1})
        if artifact.purpose == "verifier_result"
        else artifact
        for artifact in signed_work_order.evidence_policy.artifacts
    )
    policy = signed_work_order.evidence_policy.model_copy(
        update={"artifacts": artifacts}
    )
    constrained = _resigned_work_order(
        signed_work_order,
        ephemeral_role_keys["Maintainer"][0],
        json_updates={
            "evidence_policy": policy.model_dump(mode="json"),
        },
        model_updates={"evidence_policy": policy},
    )
    case = _run_tests_case(
        tmp_path=tmp_path,
        signed_work_order=constrained,
        role_keys=ephemeral_role_keys,
        sidecar_receipt_factory=sidecar_receipt_factory,
        now=fixed_now,
    )

    with pytest.raises(
        HandlerCoordinationError,
        match="EVIDENCE_SLOT_UNAVAILABLE",
    ):
        execute_run_tests(
            case["ledger_path"],
            evidence_root=case["evidence_root"],
            context=case["context"],
            request=case["request"],
            request_arguments=case["arguments"],
            execution_contract=_run_tests_contract(case),
            execution_facts=case["facts"],
            sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
            handler=lambda _: pytest.fail("unreserved handler started"),
            clock=lambda: fixed_now,
        )


def test_execute_run_tests_blocks_after_started_handler_process_crash(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now: datetime,
) -> None:
    case = _run_tests_case(
        tmp_path=tmp_path,
        signed_work_order=signed_work_order,
        role_keys=ephemeral_role_keys,
        sidecar_receipt_factory=sidecar_receipt_factory,
        now=fixed_now,
    )
    child = os.fork()
    if child == 0:
        execute_run_tests(
            case["ledger_path"],
            evidence_root=case["evidence_root"],
            context=case["context"],
            request=case["request"],
            request_arguments=case["arguments"],
            execution_contract=_run_tests_contract(case),
            execution_facts=case["facts"],
            sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
            handler=lambda _: os._exit(73),
            clock=lambda: fixed_now,
        )
        os._exit(74)

    _, status = os.waitpid(child, 0)
    assert os.WIFEXITED(status)
    assert os.WEXITSTATUS(status) == 73
    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        before = connection.execute(
            "SELECT COUNT(*), MAX(sequence) FROM receipts"
        ).fetchone()
        assert connection.execute(
            """
            SELECT request_digest, nonce, state
            FROM handler_executions
            """
        ).fetchone() == (
            case["request"].digest,
            case["request"].nonce,
            "STARTED_UNCONFIRMED",
        )
    finally:
        connection.close()

    with pytest.raises(HandlerCoordinationError, match="RECOVERY_REQUIRED"):
        execute_run_tests(
            case["ledger_path"],
            evidence_root=case["evidence_root"],
            context=case["context"],
            request=case["request"],
            request_arguments=case["arguments"],
            execution_contract=_run_tests_contract(case),
            execution_facts=case["facts"],
            sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
            handler=lambda _: pytest.fail("uncertain handler restarted"),
            clock=lambda: fixed_now,
        )

    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        assert connection.execute(
            "SELECT COUNT(*), MAX(sequence) FROM receipts"
        ).fetchone() == before
        assert connection.execute(
            "SELECT state FROM handler_executions"
        ).fetchone() == ("STARTED_UNCONFIRMED",)
    finally:
        connection.close()


def test_execute_run_tests_retries_after_reserved_only_process_crash(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now: datetime,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = _run_tests_case(
        tmp_path=tmp_path,
        signed_work_order=signed_work_order,
        role_keys=ephemeral_role_keys,
        sidecar_receipt_factory=sidecar_receipt_factory,
        now=fixed_now,
    )
    real_mark_started = mcp_server._mark_handler_started
    monkeypatch.setattr(
        mcp_server,
        "_mark_handler_started",
        lambda *_: os._exit(75),
    )
    child = os.fork()
    if child == 0:
        execute_run_tests(
            case["ledger_path"],
            evidence_root=case["evidence_root"],
            context=case["context"],
            request=case["request"],
            request_arguments=case["arguments"],
            execution_contract=_run_tests_contract(case),
            execution_facts=case["facts"],
            sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
            handler=lambda _: os._exit(76),
            clock=lambda: fixed_now,
        )
        os._exit(77)

    _, status = os.waitpid(child, 0)
    assert os.WIFEXITED(status)
    assert os.WEXITSTATUS(status) == 75
    monkeypatch.setattr(
        mcp_server,
        "_mark_handler_started",
        real_mark_started,
    )
    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        before = connection.execute(
            "SELECT COUNT(*), MAX(sequence) FROM receipts"
        ).fetchone()
        assert connection.execute(
            "SELECT state FROM handler_executions"
        ).fetchone() == ("RESERVED",)
    finally:
        connection.close()

    receipt = execute_run_tests(
        case["ledger_path"],
        evidence_root=case["evidence_root"],
        context=case["context"],
        request=case["request"],
        request_arguments=case["arguments"],
        execution_contract=_run_tests_contract(case),
        execution_facts=case["facts"],
        sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
        handler=lambda _: 0,
        clock=lambda: fixed_now,
    )

    assert receipt.execution_status == "succeeded"
    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM handler_executions"
        ).fetchone() == (0,)
        after = connection.execute(
            "SELECT COUNT(*), MAX(sequence) FROM receipts"
        ).fetchone()
        assert after == (before[0] + 1, before[1] + 1)
    finally:
        connection.close()


def test_execute_run_tests_recovers_committed_receipt_after_cleanup_crash(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now: datetime,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = _run_tests_case(
        tmp_path=tmp_path,
        signed_work_order=signed_work_order,
        role_keys=ephemeral_role_keys,
        sidecar_receipt_factory=sidecar_receipt_factory,
        now=fixed_now,
    )
    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        before = connection.execute(
            "SELECT COUNT(*), MAX(sequence) FROM receipts"
        ).fetchone()
    finally:
        connection.close()
    real_finalize = mcp_server._finalize_handler_execution
    monkeypatch.setattr(
        mcp_server,
        "_finalize_handler_execution",
        lambda *_: os._exit(78),
    )
    child = os.fork()
    if child == 0:
        execute_run_tests(
            case["ledger_path"],
            evidence_root=case["evidence_root"],
            context=case["context"],
            request=case["request"],
            request_arguments=case["arguments"],
            execution_contract=_run_tests_contract(case),
            execution_facts=case["facts"],
            sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
            handler=lambda _: 0,
            clock=lambda: fixed_now,
        )
        os._exit(79)

    _, status = os.waitpid(child, 0)
    assert os.WIFEXITED(status)
    assert os.WEXITSTATUS(status) == 78
    monkeypatch.setattr(
        mcp_server,
        "_finalize_handler_execution",
        real_finalize,
    )
    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        committed = connection.execute(
            "SELECT COUNT(*), MAX(sequence) FROM receipts"
        ).fetchone()
        assert committed == (before[0] + 1, before[1] + 1)
        assert connection.execute(
            "SELECT state FROM handler_executions"
        ).fetchone() == ("STARTED_UNCONFIRMED",)
        assert connection.execute(
            """
            SELECT state
            FROM evidence_publications
            WHERE receipt_id = (
                SELECT receipt_id FROM receipts WHERE nonce = ?
            )
            """,
            (case["request"].nonce,),
        ).fetchone() == ("COMMITTED",)
    finally:
        connection.close()

    with pytest.raises(
        HandlerCoordinationError,
        match="current ledger snapshot",
    ):
        execute_run_tests(
            case["ledger_path"],
            evidence_root=case["evidence_root"],
            context=case["context"],
            request=case["request"],
            request_arguments=case["arguments"],
            execution_contract=_run_tests_contract(case),
            execution_facts=case["facts"],
            sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
            handler=lambda _: pytest.fail("committed handler restarted"),
            clock=lambda: fixed_now,
        )

    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM handler_executions"
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT COUNT(*), MAX(sequence) FROM receipts"
        ).fetchone() == committed
    finally:
        connection.close()


def test_execute_run_tests_migrates_ledger_without_handler_journal(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now: datetime,
) -> None:
    case = _run_tests_case(
        tmp_path=tmp_path,
        signed_work_order=signed_work_order,
        role_keys=ephemeral_role_keys,
        sidecar_receipt_factory=sidecar_receipt_factory,
        now=fixed_now,
    )
    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        connection.execute("DROP TABLE handler_executions")
    finally:
        connection.close()

    receipt = execute_run_tests(
        case["ledger_path"],
        evidence_root=case["evidence_root"],
        context=case["context"],
        request=case["request"],
        request_arguments=case["arguments"],
        execution_contract=_run_tests_contract(case),
        execution_facts=case["facts"],
        sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
        handler=lambda _: 0,
        clock=lambda: fixed_now,
    )

    assert receipt.execution_status == "succeeded"
    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        assert connection.execute(
            """
            SELECT COUNT(*)
            FROM sqlite_master
            WHERE type = 'table' AND name = 'handler_executions'
            """
        ).fetchone() == (1,)
        assert connection.execute(
            "SELECT COUNT(*) FROM handler_executions"
        ).fetchone() == (0,)
    finally:
        connection.close()


def _rollback_case(
    *,
    tmp_path: Path,
    signed_work_order: WorkOrder,
    role_keys,
    sidecar_receipt_factory,
    now: datetime,
):
    case = _run_tests_case(
        tmp_path=tmp_path,
        signed_work_order=signed_work_order,
        role_keys=role_keys,
        sidecar_receipt_factory=sidecar_receipt_factory,
        now=now,
    )
    failure = execute_run_tests(
        case["ledger_path"],
        evidence_root=case["evidence_root"],
        context=case["context"],
        request=case["request"],
        request_arguments=case["arguments"],
        execution_contract=_run_tests_contract(case),
        execution_facts=case["facts"],
        sidecar_private_key=role_keys["Sidecar"][0],
        handler=lambda _: 1,
        clock=lambda: now,
    )
    receipts, grants, attempts = _grant_replay_inputs(
        case["ledger_path"],
        case["work_order"],
    )
    committed = []
    for receipt in receipts:
        for reference in receipt.evidence_refs:
            path = (
                case["evidence_root"]
                / reference.path.removeprefix("evidence/")
            )
            committed.append(
                CommittedEvidence(
                    reference=reference,
                    payload=path.read_bytes(),
                )
            )
    failure_payload = next(
        item.payload
        for item in committed
        if item.reference in failure.evidence_refs
    )
    checkpoint = ReplayCheckpoint(
        files=case["context"].replay_checkpoint.files,
        head_commit=case["context"].replay_checkpoint.head_commit,
        workspace_manifest=(
            case["context"].replay_checkpoint.workspace_manifest
        ),
        workspace_manifest_digest=(
            case["context"].replay_checkpoint.workspace_manifest_digest
        ),
        verified_test_results=(
            ResultEvidence.model_validate_json(failure_payload),
        ),
    )
    context = derive_authorization_context(
        case["work_order"],
        AuthorizationLedgerPrefix(
            effective_grants=tuple(
                sorted(grants.values(), key=lambda item: item.grant_id)
            ),
            grant_attempts=tuple(
                sorted(attempts.values(), key=lambda item: item.digest)
            ),
            receipts=receipts,
        ),
        tuple(committed),
        checkpoint,
        now,
    )
    arguments = {
        "target_patch_receipt_id": case["patch"].receipt_id,
        "target_patch_digest": case["patch"].digest,
        "before_commit": checkpoint.head_commit,
    }
    binding = role_keys["Developer"][1]
    request = AgentRequest.model_validate(
        sign_payload(
            "agent-request",
            {
                "claim_type": "agent-request",
                "work_order_digest": case["work_order"].digest,
                "grant_id": case["developer"].grant_id,
                "actor_id": binding["subject_id"],
                "actor_key_id": binding["key_id"],
                "tool_name": "owp.rollback_patch",
                "arguments_digest": request_arguments_digest(
                    "owp.rollback_patch",
                    arguments,
                ),
                "nonce": _grant_id("handler-loop:rollback-request"),
                "requested_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "authentication_method": "agent_signature",
                "model_id": "model",
                "model_version": "1",
                "prompt_template_digest": "a" * 64,
                "context_source_digest": "b" * 64,
            },
            role_keys["Developer"][0],
        )
    )
    case.update(
        {
            "context": context,
            "request": request,
            "rollback_arguments": arguments,
            "failure": failure,
            "facts": ProspectiveExecutionFacts(
                execution_context_id="3" * 64,
                container_instance_id_digest="4" * 64,
                controller_id=role_keys["Sidecar"][1]["key_id"],
            ),
        }
    )
    return case


def test_execute_rollback_commits_success_and_clears_handler_journal(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now: datetime,
) -> None:
    execute_rollback = getattr(mcp_server, "execute_rollback", None)
    result_type = getattr(mcp_server, "RollbackHandlerResult", None)
    assert callable(execute_rollback)
    assert result_type is not None
    case = _rollback_case(
        tmp_path=tmp_path,
        signed_work_order=signed_work_order,
        role_keys=ephemeral_role_keys,
        sidecar_receipt_factory=sidecar_receipt_factory,
        now=fixed_now,
    )
    parent_manifest = build_workspace_manifest(
        case["work_order"].source_commit,
        (),
    )
    calls = []

    def handler(arguments):
        calls.append(arguments)
        return result_type(
            execution_status="succeeded",
            before_commit=case["context"].replay_checkpoint.head_commit,
            after_commit=case["work_order"].source_commit,
            after_manifest_digest=workspace_manifest_digest(parent_manifest),
        )

    receipt = execute_rollback(
        case["ledger_path"],
        evidence_root=case["evidence_root"],
        context=case["context"],
        request=case["request"],
        execution_facts=case["facts"],
        sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
        handler=handler,
        clock=lambda: fixed_now,
    )

    assert len(calls) == 1
    assert calls[0].target_patch_receipt_id == case["patch"].receipt_id
    assert isinstance(receipt, RollbackReceipt)
    assert receipt.execution_status == "succeeded"
    assert receipt.after_commit == case["work_order"].source_commit
    assert receipt.state_before == receipt.state_after == "needs_rework"
    assert receipt.quota_charge.remaining_after == 0
    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM handler_executions"
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT current_state, version FROM work_order_state"
        ).fetchone() == ("needs_rework", receipt.sequence)
    finally:
        connection.close()


def test_execute_rollback_commits_verified_failed_result(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now: datetime,
) -> None:
    case = _rollback_case(
        tmp_path=tmp_path,
        signed_work_order=signed_work_order,
        role_keys=ephemeral_role_keys,
        sidecar_receipt_factory=sidecar_receipt_factory,
        now=fixed_now,
    )
    before = case["context"].replay_checkpoint.head_commit
    manifest = case["context"].replay_checkpoint.workspace_manifest_digest

    receipt = mcp_server.execute_rollback(
        case["ledger_path"],
        evidence_root=case["evidence_root"],
        context=case["context"],
        request=case["request"],
        execution_facts=case["facts"],
        sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
        handler=lambda _: mcp_server.RollbackHandlerResult(
            execution_status="failed",
            before_commit=before,
            after_commit=before,
            after_manifest_digest=manifest,
        ),
        clock=lambda: fixed_now,
    )

    assert receipt.execution_status == "failed"
    assert receipt.execution_error_code == "HANDLER_ERROR"
    assert receipt.after_commit == before
    assert receipt.after_manifest_digest == manifest
    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM handler_executions"
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT COUNT(*) FROM grant_events WHERE receipt_id = ?",
            (receipt.receipt_id,),
        ).fetchone() == (1,)
    finally:
        connection.close()


def test_execute_rollback_handler_exception_requires_recovery(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now: datetime,
) -> None:
    case = _rollback_case(
        tmp_path=tmp_path,
        signed_work_order=signed_work_order,
        role_keys=ephemeral_role_keys,
        sidecar_receipt_factory=sidecar_receipt_factory,
        now=fixed_now,
    )
    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        before = connection.execute(
            "SELECT COUNT(*), MAX(sequence) FROM receipts"
        ).fetchone()
    finally:
        connection.close()

    def handler(_):
        raise RuntimeError("unknown workspace state")

    with pytest.raises(HandlerCoordinationError, match="RECOVERY_REQUIRED"):
        mcp_server.execute_rollback(
            case["ledger_path"],
            evidence_root=case["evidence_root"],
            context=case["context"],
            request=case["request"],
            execution_facts=case["facts"],
            sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
            handler=handler,
            clock=lambda: fixed_now,
        )

    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        assert connection.execute(
            "SELECT COUNT(*), MAX(sequence) FROM receipts"
        ).fetchone() == before
        assert connection.execute(
            """
            SELECT tool_name, state, request_json,
                   execution_contract_json, execution_contract_digest
            FROM handler_executions
            """
        ).fetchone() == (
            "owp.rollback_patch",
            "STARTED_UNCONFIRMED",
            None,
            None,
            None,
        )
    finally:
        connection.close()


def test_execute_rollback_denial_never_starts_handler(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now: datetime,
) -> None:
    case = _rollback_case(
        tmp_path=tmp_path,
        signed_work_order=signed_work_order,
        role_keys=ephemeral_role_keys,
        sidecar_receipt_factory=sidecar_receipt_factory,
        now=fixed_now,
    )
    denied_request = _request_for_grant(
        case,
        case["verifier"],
        ephemeral_role_keys,
    )
    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        before = connection.execute(
            "SELECT COUNT(*), MAX(sequence) FROM receipts"
        ).fetchone()
    finally:
        connection.close()

    with pytest.raises(ToolCallDenied) as captured:
        mcp_server.execute_rollback(
            case["ledger_path"],
            evidence_root=case["evidence_root"],
            context=case["context"],
            request=denied_request,
            execution_facts=case["facts"],
            sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
            handler=lambda _: pytest.fail("denied rollback handler started"),
            clock=lambda: fixed_now,
        )

    assert captured.value.decision.error_code == "ROLE_DENIED"
    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        assert connection.execute(
            "SELECT COUNT(*), MAX(sequence) FROM receipts"
        ).fetchone() == before
        assert connection.execute(
            "SELECT COUNT(*) FROM handler_executions"
        ).fetchone() == (0,)
    finally:
        connection.close()


def test_execute_rollback_migrates_empty_legacy_handler_journal(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now: datetime,
) -> None:
    case = _rollback_case(
        tmp_path=tmp_path,
        signed_work_order=signed_work_order,
        role_keys=ephemeral_role_keys,
        sidecar_receipt_factory=sidecar_receipt_factory,
        now=fixed_now,
    )
    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        connection.execute("DROP TABLE handler_executions")
        connection.execute(evidence._LEGACY_HANDLER_EXECUTION_SCHEMA)
    finally:
        connection.close()
    before = case["context"].replay_checkpoint.head_commit

    receipt = mcp_server.execute_rollback(
        case["ledger_path"],
        evidence_root=case["evidence_root"],
        context=case["context"],
        request=case["request"],
        execution_facts=case["facts"],
        sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
        handler=lambda _: mcp_server.RollbackHandlerResult(
            execution_status="failed",
            before_commit=before,
            after_commit=before,
            after_manifest_digest=(
                case["context"].replay_checkpoint.workspace_manifest_digest
            ),
        ),
        clock=lambda: fixed_now,
    )

    assert receipt.execution_status == "failed"
    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        schema = connection.execute(
            """
            SELECT sql FROM sqlite_master
            WHERE type = 'table' AND name = 'handler_executions'
            """
        ).fetchone()
        assert schema is not None
        assert mcp_server._normalized_sql(schema[0]) == (
            mcp_server._normalized_sql(evidence._HANDLER_EXECUTION_SCHEMA)
        )
    finally:
        connection.close()


def test_execute_rollback_recovers_committed_receipt_after_cleanup_failure(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now: datetime,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = _rollback_case(
        tmp_path=tmp_path,
        signed_work_order=signed_work_order,
        role_keys=ephemeral_role_keys,
        sidecar_receipt_factory=sidecar_receipt_factory,
        now=fixed_now,
    )
    parent_manifest = build_workspace_manifest(
        case["work_order"].source_commit,
        (),
    )
    result = mcp_server.RollbackHandlerResult(
        execution_status="succeeded",
        before_commit=case["context"].replay_checkpoint.head_commit,
        after_commit=case["work_order"].source_commit,
        after_manifest_digest=workspace_manifest_digest(parent_manifest),
    )
    real_finalize = mcp_server._finalize_handler_execution

    def fail_cleanup(*_) -> None:
        raise HandlerCoordinationError("injected cleanup failure")

    monkeypatch.setattr(
        mcp_server,
        "_finalize_handler_execution",
        fail_cleanup,
    )
    with pytest.raises(
        HandlerCoordinationError,
        match="injected cleanup failure",
    ):
        mcp_server.execute_rollback(
            case["ledger_path"],
            evidence_root=case["evidence_root"],
            context=case["context"],
            request=case["request"],
            execution_facts=case["facts"],
            sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
            handler=lambda _: result,
            clock=lambda: fixed_now,
        )
    monkeypatch.setattr(
        mcp_server,
        "_finalize_handler_execution",
        real_finalize,
    )
    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        committed = connection.execute(
            "SELECT COUNT(*), MAX(sequence) FROM receipts"
        ).fetchone()
        assert connection.execute(
            "SELECT tool_name, state FROM handler_executions"
        ).fetchone() == (
            "owp.rollback_patch",
            "STARTED_UNCONFIRMED",
        )
    finally:
        connection.close()

    with pytest.raises(
        HandlerCoordinationError,
        match="current ledger snapshot",
    ):
        mcp_server.execute_rollback(
            case["ledger_path"],
            evidence_root=case["evidence_root"],
            context=case["context"],
            request=case["request"],
            execution_facts=case["facts"],
            sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
            handler=lambda _: pytest.fail("committed rollback restarted"),
            clock=lambda: fixed_now,
        )

    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM handler_executions"
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT COUNT(*), MAX(sequence) FROM receipts"
        ).fetchone() == committed
    finally:
        connection.close()
