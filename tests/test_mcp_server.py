"""Trusted handler coordination tests."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime
import dataclasses
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess

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
    verifier_tool_calls: int = 1,
    developer_tools: tuple[str, ...] | None = None,
    repo_read_path: str | None = None,
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
        updates={"quota": {"tool_calls": verifier_tool_calls, "repair_rounds": 0}},
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
            "allowed_tools": list(
                developer_tools
                if developer_tools is not None
                else ("owp.apply_patch", "owp.rollback_patch")
            ),
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
    import stat  # noqa: PLC0415

    if repo_read_path is not None:
        # Repo-read-only case: no active patch, a non-empty workspace manifest
        # that declares the readable path, and a fresh candidate commit.
        patch = None
        candidate_commit = work_order.source_commit
        manifest = build_workspace_manifest(
            candidate_commit,
            (
                repo_tools.WorkspaceScanRecord(
                    path_bytes=repo_read_path.encode("ascii"),
                    entry_type="regular",
                    posix_mode=stat.S_IFREG | 0o644,
                    size_bytes=4,
                    content=b"test",
                    symlink_target=None,
                    link_count=1,
                    read_token_before="stable",
                    read_token_after="stable",
                ),
            ),
        )
        checkpoint = ReplayCheckpoint(
            files=(),
            head_commit=candidate_commit,
            workspace_manifest=manifest,
            workspace_manifest_digest=workspace_manifest_digest(manifest),
            verified_test_results=(),
        )
        committed: tuple[CommittedEvidence, ...] = ()
    else:
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
        "root": root,
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


def _run_tests_snapshot_request(
    case,
    runtime_root: Path,
) -> repo_tools.CandidateExecutionSnapshotRequest:
    return repo_tools.CandidateExecutionSnapshotRequest(
        runtime_root=runtime_root,
        workspace_id="c" * 64,
        source_artifact_sha256=(
            case["work_order"].replay_profile.source_artifact_sha256
        ),
        expected_head_commit=case["arguments"].candidate_commit,
        expected_workspace_manifest_digest=(
            case["arguments"].workspace_manifest_digest
        ),
    )


def _run_tests_snapshot(case) -> repo_tools.CandidateExecutionSnapshot:
    return repo_tools.CandidateExecutionSnapshot(
        head_commit=case["arguments"].candidate_commit,
        workspace_manifest_digest=case["arguments"].workspace_manifest_digest,
        plan=repo_tools.ExecutionSnapshotPlan(
            files=(),
            read_only=True,
            owner_uid=65532,
            owner_gid=65532,
            atime_unix_seconds=0,
            mtime_unix_seconds=0,
            clear_extended_attributes=True,
            clear_posix_acls=True,
            clear_file_capabilities=True,
        ),
    )


def _closed_run_tests_outcome(
    contract: repo_tools.RunTestsExecutionContract,
    *,
    actual_exit_code: int | None = 0,
    failure_code: repo_tools.RunTestsFailureCode | None = None,
) -> repo_tools.RunTestsExecutionOutcome:
    contract_digest = hashlib.sha256(
        repo_tools.encode_run_tests_execution_contract(contract)
    ).hexdigest()
    empty_digest = hashlib.sha256(b"").hexdigest()
    return repo_tools.RunTestsExecutionOutcome(
        "CLOSED_RESULT",
        repo_tools.RunTestsResultEnvelope(
            execution_id=contract.execution_id,
            execution_contract_digest=contract_digest,
            actual_exit_code=actual_exit_code,
            failure_code=failure_code,
            stdout_bytes=0,
            stdout_sha256=empty_digest,
            stderr_bytes=0,
            stderr_sha256=empty_digest,
        ),
    )


class _FakeRunTestsExecutionDriver:
    def __init__(
        self,
        *,
        actual_exit_code: int | None = 0,
        failure_code: repo_tools.RunTestsFailureCode | None = None,
        preparation_action: str = "READY_TO_START",
        reconciliation_outcomes: tuple[
            repo_tools.RunTestsExecutionOutcome, ...
        ] = (),
        cleanup_error: Exception | None = None,
        reconciliation_error: Exception | None = None,
        start_error: Exception | None = None,
        start_outcome: repo_tools.RunTestsExecutionOutcome | None = None,
        prepare_exit_code: int | None = None,
        start_exit_code: int | None = None,
    ) -> None:
        self.actual_exit_code = actual_exit_code
        self.failure_code = failure_code
        self.preparation_action = preparation_action
        self.reconciliation_outcomes = list(reconciliation_outcomes)
        self.cleanup_error = cleanup_error
        self.reconciliation_error = reconciliation_error
        self.start_error = start_error
        self.start_outcome = start_outcome
        self.prepare_exit_code = prepare_exit_code
        self.start_exit_code = start_exit_code
        self.calls: list[tuple[object, ...]] = []

    def prepare(self, contract, snapshot):
        self.calls.append(("prepare", contract, snapshot))
        if self.prepare_exit_code is not None:
            os._exit(self.prepare_exit_code)
        return repo_tools.RunTestsPreparationOutcome(self.preparation_action)

    def start_and_wait(self, contract):
        self.calls.append(("start_and_wait", contract))
        if self.start_error is not None:
            raise self.start_error
        if self.start_exit_code is not None:
            os._exit(self.start_exit_code)
        if self.start_outcome is not None:
            return self.start_outcome
        return _closed_run_tests_outcome(
            contract,
            actual_exit_code=self.actual_exit_code,
            failure_code=self.failure_code,
        )

    def reconcile(self, contract, journal_state, receipt_state):
        self.calls.append(
            ("reconcile", contract, journal_state, receipt_state)
        )
        if self.reconciliation_error is not None:
            raise self.reconciliation_error
        if self.reconciliation_outcomes:
            return self.reconciliation_outcomes.pop(0)
        return repo_tools.RunTestsExecutionOutcome("UNRESOLVED")

    def cleanup(self, contract):
        self.calls.append(("cleanup", contract))
        if self.cleanup_error is not None:
            raise self.cleanup_error


class _PersistentRunTestsExecutionDriver:
    _PREPARATION_RESOURCES = {
        "workspace_volume": ("workspace_volume_name",),
        "staging_create": (
            "workspace_volume_name",
            "staging_container_name",
        ),
        "staging_removal": ("workspace_volume_name",),
        "output_volume": (
            "workspace_volume_name",
            "output_volume_name",
        ),
        "execution_container": (
            "workspace_volume_name",
            "output_volume_name",
            "container_name",
        ),
    }

    def __init__(
        self,
        state_path: Path,
        *,
        prepare_crash_position: str | None = None,
        start_crash_position: str | None = None,
    ) -> None:
        self.state_path = state_path
        self.prepare_crash_position = prepare_crash_position
        self.start_crash_position = start_crash_position
        self.calls: list[tuple[object, ...]] = []
        self.reconciled_resources: dict[str, str] | None = None

    def _read(self) -> dict[str, object]:
        if not self.state_path.exists():
            return {"phase": "empty", "resources": {}, "start_count": 0}
        value = json.loads(self.state_path.read_text(encoding="utf-8"))
        assert type(value) is dict
        return value

    def _write(self, value: dict[str, object]) -> None:
        self.state_path.write_text(
            json.dumps(value, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )

    @classmethod
    def resources_for(
        cls,
        contract: repo_tools.RunTestsExecutionContract,
        position: str,
    ) -> dict[str, str]:
        binding = repo_tools.derive_run_tests_docker_binding(
            contract.execution_id
        )
        return {
            attribute: getattr(binding, attribute)
            for attribute in cls._PREPARATION_RESOURCES[position]
        }

    def prepare(self, contract, snapshot):
        self.calls.append(("prepare", contract, snapshot))
        start_count = self._read()["start_count"]
        for position in self._PREPARATION_RESOURCES:
            self._write(
                {
                    "execution_id": contract.execution_id,
                    "phase": position,
                    "resources": self.resources_for(contract, position),
                    "start_count": start_count,
                }
            )
            if position == self.prepare_crash_position:
                os._exit(71)
        return repo_tools.RunTestsPreparationOutcome("READY_TO_START")

    def start_and_wait(self, contract):
        self.calls.append(("start_and_wait", contract))
        state = self._read()
        state.update(
            {
                "execution_id": contract.execution_id,
                "phase": self.start_crash_position or "closed_result",
                "start_count": int(state["start_count"]) + 1,
            }
        )
        self._write(state)
        if self.start_crash_position is not None:
            os._exit(73)
        return _closed_run_tests_outcome(contract)

    def reconcile(self, contract, journal_state, receipt_state):
        self.calls.append(
            ("reconcile", contract, journal_state, receipt_state)
        )
        state = self._read()
        assert state["execution_id"] == contract.execution_id
        self.reconciled_resources = dict(state["resources"])
        if state["phase"] in self._PREPARATION_RESOURCES:
            state.update({"phase": "reconciled", "resources": {}})
            self._write(state)
            return repo_tools.RunTestsExecutionOutcome("SAFE_TO_RETRY")
        if state["phase"] in {"docker_start_accepted", "result_renamed"}:
            return _closed_run_tests_outcome(contract)
        return repo_tools.RunTestsExecutionOutcome("UNRESOLVED")

    def cleanup(self, contract):
        self.calls.append(("cleanup", contract))
        state = self._read()
        state.update({"phase": "cleaned", "resources": {}})
        self._write(state)


@pytest.fixture(autouse=True)
def _stub_candidate_execution_snapshot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def prepare(
        request: repo_tools.CandidateExecutionSnapshotRequest,
    ) -> repo_tools.CandidateExecutionSnapshot:
        return repo_tools.CandidateExecutionSnapshot(
            head_commit=request.expected_head_commit,
            workspace_manifest_digest=(
                request.expected_workspace_manifest_digest
            ),
            plan=repo_tools.ExecutionSnapshotPlan(
                files=(),
                read_only=True,
                owner_uid=65532,
                owner_gid=65532,
                atime_unix_seconds=0,
                mtime_unix_seconds=0,
                clear_extended_attributes=True,
                clear_posix_acls=True,
                clear_file_capabilities=True,
            ),
        )

    monkeypatch.setattr(
        repo_tools,
        "prepare_candidate_execution_snapshot",
        prepare,
    )


def _reserve_run_tests_execution(case, *, started: bool) -> None:
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
        if started:
            mcp_server._mark_handler_started(
                case["ledger_path"],
                lock_descriptor,
                contract.execution_id,
            )
    finally:
        evidence._release_target_lock(lock_descriptor)


def _run_tests_persistence_counts(case) -> tuple[int, int, int, int]:
    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        return connection.execute(
            """
            SELECT
                (SELECT COUNT(*) FROM receipts WHERE nonce = ?),
                (SELECT COUNT(*) FROM grant_events AS event
                 JOIN receipts AS receipt
                   ON receipt.receipt_id = event.receipt_id
                 WHERE receipt.nonce = ?),
                (SELECT COUNT(*) FROM evidence_publications AS publication
                 JOIN receipts AS receipt
                   ON receipt.receipt_id = publication.receipt_id
                 WHERE receipt.nonce = ?),
                (SELECT version FROM work_order_state WHERE singleton = 1)
            """,
            (case["request"].nonce,) * 3,
        ).fetchone()
    finally:
        connection.close()


def _current_run_tests_context(case, now: datetime):
    receipts, grants, attempts = _grant_replay_inputs(
        case["ledger_path"], case["work_order"]
    )
    committed = []
    verified = []
    verifier_paths = {
        f"evidence/{artifact.path}"
        for artifact in case["work_order"].evidence_policy.artifacts
        if artifact.purpose in {
            "verifier_result",
            "verifier_independent_result",
        }
    }
    for receipt in receipts:
        for reference in receipt.evidence_refs:
            path = (
                case["evidence_root"]
                / reference.path.removeprefix("evidence/")
            )
            payload = path.read_bytes()
            committed.append(
                CommittedEvidence(reference=reference, payload=payload)
            )
            if reference.path in verifier_paths:
                verified.append(ResultEvidence.model_validate_json(payload))
    committed.sort(key=lambda item: item.reference.path.encode())
    checkpoint = case["context"].replay_checkpoint
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
        ReplayCheckpoint(
            files=checkpoint.files,
            head_commit=checkpoint.head_commit,
            workspace_manifest=checkpoint.workspace_manifest,
            workspace_manifest_digest=checkpoint.workspace_manifest_digest,
            verified_test_results=tuple(verified),
        ),
        now,
    )
    # Terminal states live in the authoritative state row, not in the
    # action-receipt prefix (acceptance/rejection are separate tables).
    import sqlite3 as _sql  # noqa: PLC0415

    connection = _sql.connect(case["ledger_path"])
    try:
        state_row = connection.execute(
            "SELECT current_state FROM work_order_state WHERE singleton = 1"
        ).fetchone()
    finally:
        connection.close()
    if state_row is not None and state_row[0] in {
        "accepted",
        "rejected",
        "frozen",
    }:
        context = dataclasses.replace(context, current_state=state_row[0])
    return context


def _execute_run_tests_case(
    case,
    tmp_path: Path,
    role_keys,
    execution_driver: _FakeRunTestsExecutionDriver,
    *,
    context=None,
    request=None,
    request_arguments=None,
    execution_facts=None,
    candidate_snapshot_request=None,
    sidecar_private_key=None,
    now: datetime | None = None,
):
    selected_context = case["context"] if context is None else context
    return execute_run_tests(
        case["ledger_path"],
        evidence_root=case["evidence_root"],
        context=selected_context,
        request=case["request"] if request is None else request,
        request_arguments=(
            case["arguments"]
            if request_arguments is None
            else request_arguments
        ),
        execution_facts=(
            case["facts"] if execution_facts is None else execution_facts
        ),
        candidate_snapshot_request=(
            _run_tests_snapshot_request(case, tmp_path.resolve())
            if candidate_snapshot_request is None
            else candidate_snapshot_request
        ),
        sidecar_private_key=(
            role_keys["Sidecar"][0]
            if sidecar_private_key is None
            else sidecar_private_key
        ),
        execution_driver=execution_driver,
        clock=lambda: (
            selected_context.transaction_time if now is None else now
        ),
    )


def _append_same_second_grant(
    case,
    role_keys,
    now: datetime,
):
    child = _child_grant(
        case["work_order"],
        case["root"],
        role_keys,
        label="handler-loop:same-second-child",
        updates={
            "allowed_tools": ["owp.repo_read"],
            "quota": {"tool_calls": 1, "repair_rounds": 0},
        },
    )
    return _issue_child(
        case["ledger_path"],
        child,
        _delegation_request(
            case["work_order"],
            case["root"],
            child,
            role_keys,
            actor_role="Manager",
            nonce=_grant_id("handler-loop:same-second-child-request"),
        ),
        role_keys,
        now,
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


def _replacement_run_tests_request(case, role_keys) -> AgentRequest:
    raw = case["request"].model_dump(
        mode="json",
        exclude={"digest", "signature_alg", "signer_key_id", "signature"},
    )
    raw.update(
        {
            "nonce": _grant_id("handler-loop:replacement-test-request"),
            "model_id": "replacement-model",
            "model_version": "2",
            "prompt_template_digest": "d" * 64,
            "context_source_digest": "e" * 64,
        }
    )
    return AgentRequest.model_validate(
        sign_payload("agent-request", raw, role_keys["Verifier"][0])
    )


def _run_tests_request_for_arguments(
    case,
    arguments: RunTestsArguments,
    role_keys,
) -> AgentRequest:
    raw = case["request"].model_dump(
        mode="json",
        exclude={"digest", "signature_alg", "signer_key_id", "signature"},
    )
    raw.update(
        {
            "arguments_digest": request_arguments_digest(
                "owp.run_tests", arguments
            ),
            "nonce": _grant_id("handler-loop:changed-test-request"),
        }
    )
    return AgentRequest.model_validate(
        sign_payload("agent-request", raw, role_keys["Verifier"][0])
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
        "authorization_prefix_digest",
        "request_json",
        "execution_contract_json",
        "execution_contract_digest",
    }


def test_authorization_prefix_digest_binds_all_canonical_components(
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
    prefix = case["context"].ledger_prefix
    stable = AuthorizationLedgerPrefix(
        effective_grants=tuple(prefix.effective_grants),
        grant_attempts=tuple(prefix.grant_attempts),
        receipts=tuple(prefix.receipts),
    )
    assert mcp_server._authorization_prefix_digest(prefix) == (
        mcp_server._authorization_prefix_digest(stable)
    )

    changed_grant = prefix.effective_grants[0].model_copy(
        update={"subject_agent_id": "changed-subject"}
    )
    changed_grants = AuthorizationLedgerPrefix(
        effective_grants=(changed_grant, *prefix.effective_grants[1:]),
        grant_attempts=prefix.grant_attempts,
        receipts=prefix.receipts,
    )
    assert mcp_server._authorization_prefix_digest(changed_grants) != (
        mcp_server._authorization_prefix_digest(prefix)
    )

    changed_attempts = AuthorizationLedgerPrefix(
        effective_grants=prefix.effective_grants,
        grant_attempts=(changed_grant,),
        receipts=prefix.receipts,
    )
    assert mcp_server._authorization_prefix_digest(changed_attempts) != (
        mcp_server._authorization_prefix_digest(prefix)
    )

    changed_receipt = prefix.receipts[-1].model_copy(
        update={"sequence": prefix.receipts[-1].sequence + 1}
    )
    changed_receipts = AuthorizationLedgerPrefix(
        effective_grants=prefix.effective_grants,
        grant_attempts=prefix.grant_attempts,
        receipts=(*prefix.receipts[:-1], changed_receipt),
    )
    assert mcp_server._authorization_prefix_digest(changed_receipts) != (
        mcp_server._authorization_prefix_digest(prefix)
    )


def test_current_handler_schema_has_a_named_prefix_predecessor() -> None:
    assert hasattr(evidence, "_HANDLER_EXECUTION_SCHEMA_V2")


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
            authorization_prefix_digest,
            request_json, execution_contract_json,
            execution_contract_digest
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'RESERVED', ?, ?, ?, ?)
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
            connection.execute(insert, (*common, None, None, None, None))
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(insert, (*common, "d" * 64, None, None, None))
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
            connection.execute(
                insert,
                (*rollback, "d" * 64, None, None, None),
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                insert,
                (*rollback, None, "{}", "{}", "c" * 64),
            )
    finally:
        connection.close()


@pytest.mark.parametrize(
    "predecessor",
    (
        evidence._HANDLER_EXECUTION_SCHEMA_V2,
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
        evidence._HANDLER_EXECUTION_SCHEMA_V2,
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
        tool_name = (
            "owp.rollback_patch"
            if predecessor == evidence._HANDLER_EXECUTION_SCHEMA_V2
            else "owp.run_tests"
        )
        grant_id = (
            case["developer"].grant_id
            if tool_name == "owp.rollback_patch"
            else case["verifier"].grant_id
        )
        connection.execute(
            """
            INSERT INTO handler_executions (
                execution_id, work_order_digest, request_digest, nonce,
                grant_id, tool_name, arguments_digest,
                execution_context_id, container_instance_id_digest,
                controller_id, reserved_at, state
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'RESERVED')
            """,
            (
                "0" * 64,
                case["work_order"].digest,
                case["request"].digest,
                case["request"].nonce,
                grant_id,
                tool_name,
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
        execution_facts=case["facts"],
        authorization_prefix_digest=(
            mcp_server._authorization_prefix_digest(
                case["context"].ledger_prefix
            )
        ),
        reserved_at=fixed_now,
        state="RESERVED",
    )
    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        row = connection.execute(
            """
            SELECT authorization_prefix_digest,
                   request_json, execution_contract_json,
                   execution_contract_digest
            FROM handler_executions
            """
        ).fetchone()
    finally:
        connection.close()
    request_bytes = rfc8785.dumps(case["request"].model_dump(mode="json"))
    contract_bytes = repo_tools.encode_run_tests_execution_contract(contract)
    assert row == (
        mcp_server._authorization_prefix_digest(
            case["context"].ledger_prefix
        ),
        request_bytes.decode("utf-8"),
        contract_bytes.decode("utf-8"),
        hashlib.sha256(contract_bytes).hexdigest(),
    )


def test_generic_journal_recovery_never_discards_reserved_run_tests(
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
    _reserve_run_tests_execution(case, started=False)
    lock_descriptor = evidence._acquire_target_lock(case["ledger_path"])
    try:
        with pytest.raises(
            HandlerCoordinationError, match="RECOVERY_REQUIRED"
        ):
            mcp_server._recover_handler_executions(
                case["ledger_path"], lock_descriptor
            )
    finally:
        evidence._release_target_lock(lock_descriptor)
    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        assert connection.execute(
            "SELECT state FROM handler_executions"
        ).fetchone() == ("RESERVED",)
    finally:
        connection.close()


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
        "authorization_prefix_digest",
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
            elif tamper == "authorization_prefix_digest":
                connection.execute(
                    "UPDATE handler_executions "
                    "SET authorization_prefix_digest = ?",
                    ("not-a-digest",),
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


def test_execute_run_tests_completes_authorize_driver_publish_loop(
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
    snapshot_request = _run_tests_snapshot_request(case, tmp_path.resolve())
    snapshot = _run_tests_snapshot(case)
    monkeypatch.setattr(
        repo_tools,
        "prepare_candidate_execution_snapshot",
        lambda request: snapshot
        if request == snapshot_request
        else pytest.fail("unexpected candidate snapshot request"),
    )
    driver = _FakeRunTestsExecutionDriver()

    receipt = _execute_run_tests_case(
        case,
        tmp_path,
        ephemeral_role_keys,
        driver,
        candidate_snapshot_request=snapshot_request,
    )

    assert [call[0] for call in driver.calls] == [
        "prepare",
        "start_and_wait",
        "cleanup",
    ]
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


def test_execute_run_tests_recovers_old_closed_result_without_reauthorization(
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
        mcp_server._reserve_handler_execution(
            case["ledger_path"],
            lock_descriptor,
            case["context"],
            case["request"],
            case["facts"],
            contract,
        )
        mcp_server._mark_handler_started(
            case["ledger_path"], lock_descriptor, contract.execution_id
        )
    finally:
        evidence._release_target_lock(lock_descriptor)
    driver = _FakeRunTestsExecutionDriver(
        reconciliation_outcomes=(_closed_run_tests_outcome(contract),)
    )
    replacement_request = _replacement_run_tests_request(
        case, ephemeral_role_keys
    )

    receipt = _execute_run_tests_case(
        case,
        tmp_path,
        ephemeral_role_keys,
        driver,
        request=replacement_request,
    )

    assert receipt.nested_claim == case["request"]
    assert receipt.nonce == case["request"].nonce
    assert receipt.nonce != replacement_request.nonce
    assert [call[0] for call in driver.calls] == ["reconcile", "cleanup"]
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


def test_execute_run_tests_receipt_mismatch_remains_unresolved(
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
    committed = _execute_run_tests_case(
        case,
        tmp_path,
        ephemeral_role_keys,
        _FakeRunTestsExecutionDriver(),
    )
    current_context = _current_run_tests_context(case, fixed_now)
    stored_facts = ProspectiveExecutionFacts(
        execution_context_id="9" * 64,
        container_instance_id_digest="8" * 64,
        controller_id=case["facts"].controller_id,
    )
    contract = replace(
        _run_tests_contract(case),
        execution_id=mcp_server._handler_execution_id(
            case["request"], stored_facts
        ),
    )
    lock_descriptor = evidence._acquire_target_lock(case["ledger_path"])
    try:
        mcp_server._reserve_handler_execution(
            case["ledger_path"],
            lock_descriptor,
            current_context,
            case["request"],
            stored_facts,
            contract,
        )
        mcp_server._mark_handler_started(
            case["ledger_path"], lock_descriptor, contract.execution_id
        )
    finally:
        evidence._release_target_lock(lock_descriptor)
    driver = _FakeRunTestsExecutionDriver(
        reconciliation_outcomes=(
            repo_tools.RunTestsExecutionOutcome("UNRESOLVED"),
        )
    )

    with pytest.raises(HandlerCoordinationError, match="RECOVERY_REQUIRED"):
        _execute_run_tests_case(
            case,
            tmp_path,
            ephemeral_role_keys,
            driver,
            context=current_context,
            request=_replacement_run_tests_request(case, ephemeral_role_keys),
        )

    assert driver.calls[0][2:] == ("STARTED_UNCONFIRMED", "MISMATCH")
    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        assert connection.execute(
            "SELECT execution_id, state FROM handler_executions"
        ).fetchone() == (contract.execution_id, "STARTED_UNCONFIRMED")
        assert connection.execute(
            "SELECT COUNT(*) FROM receipts WHERE nonce = ?",
            (case["request"].nonce,),
        ).fetchone() == (1,)
        assert connection.execute(
            "SELECT receipt_id FROM receipts WHERE nonce = ?",
            (case["request"].nonce,),
        ).fetchone() == (committed.receipt_id,)
    finally:
        connection.close()


def test_execute_run_tests_wrong_recovery_sidecar_never_calls_driver(
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
    _reserve_run_tests_execution(case, started=True)
    driver = _FakeRunTestsExecutionDriver()

    with pytest.raises(HandlerCoordinationError, match="RECOVERY_REQUIRED"):
        _execute_run_tests_case(
            case,
            tmp_path,
            ephemeral_role_keys,
            driver,
            sidecar_private_key=ephemeral_role_keys["Maintainer"][0],
        )
    assert driver.calls == []
    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        assert connection.execute(
            "SELECT state FROM handler_executions"
        ).fetchone() == ("STARTED_UNCONFIRMED",)
    finally:
        connection.close()


def test_execute_run_tests_commits_unexpected_exit_as_needs_rework(
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

    receipt = _execute_run_tests_case(
        case,
        tmp_path,
        ephemeral_role_keys,
        _FakeRunTestsExecutionDriver(actual_exit_code=1),
    )

    assert receipt.execution_status == "succeeded"
    assert receipt.execution_error_code is None
    assert receipt.state_before == "running"
    assert receipt.state_after == "needs_rework"
    assert len(receipt.evidence_refs) == 1
    payload = (
        case["evidence_root"]
        / receipt.evidence_refs[0].path.removeprefix("evidence/")
    ).read_bytes()
    assert ResultEvidence.model_validate_json(payload).actual_exit_code == 1


@pytest.mark.parametrize("failure_code", ("OUTPUT_LIMIT", "TIMEOUT", "DISK_LIMIT"))
def test_execute_run_tests_commits_each_closed_infrastructure_failure(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now: datetime,
    failure_code: repo_tools.RunTestsFailureCode,
) -> None:
    case = _run_tests_case(
        tmp_path=tmp_path,
        signed_work_order=signed_work_order,
        role_keys=ephemeral_role_keys,
        sidecar_receipt_factory=sidecar_receipt_factory,
        now=fixed_now,
    )
    receipt = _execute_run_tests_case(
        case,
        tmp_path,
        ephemeral_role_keys,
        _FakeRunTestsExecutionDriver(
            actual_exit_code=None,
            failure_code=failure_code,
        ),
    )
    assert receipt.execution_status == "failed"
    assert receipt.execution_error_code == failure_code
    assert receipt.evidence_refs == ()
    assert receipt.state_before == receipt.state_after == "running"
    assert receipt.quota_charge.remaining_after == 0
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


@pytest.mark.parametrize("action", ("WAIT_RUNNING", "UNRESOLVED"))
def test_execute_run_tests_retains_started_journal_for_unclosed_outcome(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now: datetime,
    action: str,
) -> None:
    case = _run_tests_case(
        tmp_path=tmp_path,
        signed_work_order=signed_work_order,
        role_keys=ephemeral_role_keys,
        sidecar_receipt_factory=sidecar_receipt_factory,
        now=fixed_now,
    )
    driver = _FakeRunTestsExecutionDriver(
        start_outcome=repo_tools.RunTestsExecutionOutcome(action)
    )
    with pytest.raises(HandlerCoordinationError, match="RECOVERY_REQUIRED"):
        _execute_run_tests_case(
            case,
            tmp_path,
            ephemeral_role_keys,
            driver,
        )
    assert [call[0] for call in driver.calls] == ["prepare", "start_and_wait"]
    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        assert connection.execute(
            "SELECT state FROM handler_executions"
        ).fetchone() == ("STARTED_UNCONFIRMED",)
        assert connection.execute(
            "SELECT COUNT(*) FROM receipts WHERE nonce = ?",
            (case["request"].nonce,),
        ).fetchone() == (0,)
    finally:
        connection.close()


@pytest.mark.parametrize("recovery_action", ("SAFE_TO_RETRY", "UNRESOLVED"))
def test_execute_run_tests_reconciles_uncertain_preparation_without_start(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now: datetime,
    recovery_action: str,
) -> None:
    case = _run_tests_case(
        tmp_path=tmp_path,
        signed_work_order=signed_work_order,
        role_keys=ephemeral_role_keys,
        sidecar_receipt_factory=sidecar_receipt_factory,
        now=fixed_now,
    )
    driver = _FakeRunTestsExecutionDriver(
        preparation_action="UNRESOLVED",
        reconciliation_outcomes=(
            repo_tools.RunTestsExecutionOutcome(recovery_action),
        ),
    )
    with pytest.raises(HandlerCoordinationError, match="RECOVERY_REQUIRED"):
        _execute_run_tests_case(
            case,
            tmp_path,
            ephemeral_role_keys,
            driver,
        )
    assert [call[0] for call in driver.calls] == ["prepare", "reconcile"]
    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        expected_rows = 0 if recovery_action == "SAFE_TO_RETRY" else 1
        assert connection.execute(
            "SELECT COUNT(*) FROM handler_executions"
        ).fetchone() == (expected_rows,)
        assert connection.execute(
            "SELECT COUNT(*) FROM receipts WHERE nonce = ?",
            (case["request"].nonce,),
        ).fetchone() == (0,)
    finally:
        connection.close()


@pytest.mark.parametrize("failure_at", ("reconcile", "start"))
def test_execute_run_tests_maps_driver_uncertainty_to_recovery_required(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now: datetime,
    failure_at: str,
) -> None:
    case = _run_tests_case(
        tmp_path=tmp_path,
        signed_work_order=signed_work_order,
        role_keys=ephemeral_role_keys,
        sidecar_receipt_factory=sidecar_receipt_factory,
        now=fixed_now,
    )
    driver = _FakeRunTestsExecutionDriver(
        preparation_action=(
            "UNRESOLVED" if failure_at == "reconcile" else "READY_TO_START"
        ),
        reconciliation_error=(
            RuntimeError("uncertain reconcile")
            if failure_at == "reconcile"
            else None
        ),
        start_error=(
            RuntimeError("uncertain start") if failure_at == "start" else None
        ),
    )

    with pytest.raises(HandlerCoordinationError, match="RECOVERY_REQUIRED"):
        _execute_run_tests_case(
            case,
            tmp_path,
            ephemeral_role_keys,
            driver,
        )

    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        assert connection.execute(
            "SELECT state FROM handler_executions"
        ).fetchone() == (
            "RESERVED" if failure_at == "reconcile" else "STARTED_UNCONFIRMED",
        )
        assert connection.execute(
            "SELECT COUNT(*) FROM receipts WHERE nonce = ?",
            (case["request"].nonce,),
        ).fetchone() == (0,)
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
        _execute_run_tests_case(
            case,
            tmp_path,
            ephemeral_role_keys,
            _FakeRunTestsExecutionDriver(),
            request=request,
        )

    assert captured.value.decision.error_code == "ROLE_DENIED"
    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        assert connection.execute(
            "SELECT COUNT(*), MAX(sequence) FROM receipts"
        ).fetchone() == before
    finally:
        connection.close()


def test_execute_run_tests_wrong_frozen_command_never_calls_driver(
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
    arguments = case["arguments"].model_copy(
        update={"command_digest": "0" * 64}
    )
    request = _run_tests_request_for_arguments(
        case, arguments, ephemeral_role_keys
    )
    driver = _FakeRunTestsExecutionDriver()

    with pytest.raises(ToolCallDenied):
        _execute_run_tests_case(
            case,
            tmp_path,
            ephemeral_role_keys,
            driver,
            request=request,
            request_arguments=arguments,
        )

    assert driver.calls == []
    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM handler_executions"
        ).fetchone() == (0,)
    finally:
        connection.close()


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("source_artifact_sha256", "0" * 64),
        ("expected_head_commit", "0" * 40),
        ("expected_workspace_manifest_digest", "0" * 64),
    ),
)
def test_execute_run_tests_rejects_snapshot_binding_before_driver(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now: datetime,
    field: str,
    value: str,
) -> None:
    case = _run_tests_case(
        tmp_path=tmp_path,
        signed_work_order=signed_work_order,
        role_keys=ephemeral_role_keys,
        sidecar_receipt_factory=sidecar_receipt_factory,
        now=fixed_now,
    )
    request = _run_tests_snapshot_request(case, tmp_path.resolve())
    request = replace(request, **{field: value})
    driver = _FakeRunTestsExecutionDriver()

    with pytest.raises(
        HandlerCoordinationError, match="execution binding is invalid"
    ):
        _execute_run_tests_case(
            case,
            tmp_path,
            ephemeral_role_keys,
            driver,
            candidate_snapshot_request=request,
        )
    assert driver.calls == []
    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM handler_executions"
        ).fetchone() == (0,)
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
    _execute_run_tests_case(
        case,
        tmp_path,
        ephemeral_role_keys,
        _FakeRunTestsExecutionDriver(),
    )

    with pytest.raises(
        HandlerCoordinationError,
        match="current ledger snapshot",
    ):
        _execute_run_tests_case(
            case,
            tmp_path,
            ephemeral_role_keys,
            _FakeRunTestsExecutionDriver(),
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
        _execute_run_tests_case(
            case,
            tmp_path,
            ephemeral_role_keys,
            _FakeRunTestsExecutionDriver(),
        )


def test_run_tests_capacity_preflight_builds_every_closed_receipt_shape(
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
    calls = []
    real_build = mcp_server._build_run_tests_receipt

    def record(*args, **kwargs):
        calls.append(
            (
                kwargs["execution_status"],
                kwargs["actual_exit_code"],
                kwargs["execution_error_code"],
            )
        )
        return real_build(*args, **kwargs)

    monkeypatch.setattr(mcp_server, "_build_run_tests_receipt", record)
    monkeypatch.setattr(mcp_server, "_MAX_RECEIPT_BYTES", 0)
    driver = _FakeRunTestsExecutionDriver()

    with pytest.raises(
        HandlerCoordinationError, match="BUNDLE_CAPACITY_EXCEEDED"
    ):
        _execute_run_tests_case(
            case,
            tmp_path,
            ephemeral_role_keys,
            driver,
        )

    assert calls == [
        ("succeeded", 0, None),
        ("succeeded", 1, None),
        ("failed", None, "OUTPUT_LIMIT"),
        ("failed", None, "TIMEOUT"),
        ("failed", None, "DISK_LIMIT"),
    ]
    assert driver.calls == []


def test_execute_run_tests_retains_started_execution_while_driver_waits(
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
    _reserve_run_tests_execution(case, started=True)
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

    driver = _FakeRunTestsExecutionDriver(
        reconciliation_outcomes=(
            repo_tools.RunTestsExecutionOutcome("WAIT_RUNNING"),
        )
    )
    with pytest.raises(HandlerCoordinationError, match="RECOVERY_REQUIRED"):
        _execute_run_tests_case(
            case,
            tmp_path,
            ephemeral_role_keys,
            driver,
        )

    assert [call[0] for call in driver.calls] == ["reconcile"]
    assert driver.calls[0][2:] == ("STARTED_UNCONFIRMED", "ABSENT")
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


def test_execute_run_tests_retries_after_safe_reserved_recovery(
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
    _reserve_run_tests_execution(case, started=False)
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

    driver = _FakeRunTestsExecutionDriver(
        reconciliation_outcomes=(
            repo_tools.RunTestsExecutionOutcome("SAFE_TO_RETRY"),
        )
    )
    receipt = _execute_run_tests_case(
        case,
        tmp_path,
        ephemeral_role_keys,
        driver,
    )

    assert receipt.execution_status == "succeeded"
    assert [call[0] for call in driver.calls] == [
        "reconcile",
        "prepare",
        "start_and_wait",
        "cleanup",
    ]
    assert driver.calls[0][2:] == ("RESERVED", "ABSENT")
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


def test_execute_run_tests_absent_receipt_rejects_same_second_prefix_advance(
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
    _reserve_run_tests_execution(case, started=False)
    later = _append_same_second_grant(
        case,
        ephemeral_role_keys,
        fixed_now,
    )
    current_context = _current_run_tests_context(case, fixed_now)
    driver = _FakeRunTestsExecutionDriver(
        reconciliation_outcomes=(
            repo_tools.RunTestsExecutionOutcome("SAFE_TO_RETRY"),
        )
    )

    with pytest.raises(HandlerCoordinationError, match="RECOVERY_REQUIRED"):
        _execute_run_tests_case(
            case,
            tmp_path,
            ephemeral_role_keys,
            driver,
            context=current_context,
        )

    assert driver.calls == []
    assert current_context.ledger_prefix.receipts[-1].receipt_id == (
        later.receipt_id
    )
    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        assert connection.execute(
            "SELECT request_digest, state FROM handler_executions"
        ).fetchone() == (case["request"].digest, "RESERVED")
        assert connection.execute(
            "SELECT COUNT(*) FROM receipts WHERE nonce = ?",
            (case["request"].nonce,),
        ).fetchone() == (0,)
    finally:
        connection.close()


@pytest.mark.parametrize(
    ("crash_step", "expected_state", "exit_code"),
    (
        ("reservation", "RESERVED", 75),
        ("started_mark", "STARTED_UNCONFIRMED", 76),
    ),
)
def test_execute_run_tests_recovers_journal_transition_crashes(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now: datetime,
    monkeypatch: pytest.MonkeyPatch,
    crash_step: str,
    expected_state: str,
    exit_code: int,
) -> None:
    case = _run_tests_case(
        tmp_path=tmp_path,
        signed_work_order=signed_work_order,
        role_keys=ephemeral_role_keys,
        sidecar_receipt_factory=sidecar_receipt_factory,
        now=fixed_now,
    )
    before = _run_tests_persistence_counts(case)
    target_name = (
        "_reserve_handler_execution"
        if crash_step == "reservation"
        else "_mark_handler_started"
    )
    real_target = getattr(mcp_server, target_name)

    def crash_after(*args, **kwargs):
        result = real_target(*args, **kwargs)
        os._exit(exit_code)

    monkeypatch.setattr(mcp_server, target_name, crash_after)
    child = os.fork()
    if child == 0:
        _execute_run_tests_case(
            case,
            tmp_path,
            ephemeral_role_keys,
            _FakeRunTestsExecutionDriver(),
        )
        os._exit(77)
    _, status = os.waitpid(child, 0)
    assert os.WIFEXITED(status)
    assert os.WEXITSTATUS(status) == exit_code
    monkeypatch.setattr(mcp_server, target_name, real_target)
    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        assert connection.execute(
            "SELECT state FROM handler_executions"
        ).fetchone() == (expected_state,)
        assert connection.execute(
            "SELECT COUNT(*) FROM receipts WHERE nonce = ?",
            (case["request"].nonce,),
        ).fetchone() == (0,)
    finally:
        connection.close()

    recovery_driver = _FakeRunTestsExecutionDriver(
        reconciliation_outcomes=(
            repo_tools.RunTestsExecutionOutcome("SAFE_TO_RETRY"),
        )
    )
    receipt = _execute_run_tests_case(
        case,
        tmp_path,
        ephemeral_role_keys,
        recovery_driver,
    )
    assert receipt.execution_status == "succeeded"
    assert sum(
        call[0] == "start_and_wait" for call in recovery_driver.calls
    ) == 1
    after = _run_tests_persistence_counts(case)
    assert after[:3] == (1, 1, 1)
    assert after[3] == before[3] + 1


@pytest.mark.parametrize(
    "position",
    (
        "workspace_volume",
        "staging_create",
        "staging_removal",
        "output_volume",
        "execution_container",
    ),
)
def test_execute_run_tests_recovers_each_preparation_crash_position(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now: datetime,
    position: str,
) -> None:
    case = _run_tests_case(
        tmp_path=tmp_path,
        signed_work_order=signed_work_order,
        role_keys=ephemeral_role_keys,
        sidecar_receipt_factory=sidecar_receipt_factory,
        now=fixed_now,
    )
    contract = _run_tests_contract(case)
    state_path = tmp_path / f"persistent-preparation-{position}.json"
    before = _run_tests_persistence_counts(case)
    child = os.fork()
    if child == 0:
        _execute_run_tests_case(
            case,
            tmp_path,
            ephemeral_role_keys,
            _PersistentRunTestsExecutionDriver(
                state_path,
                prepare_crash_position=position,
            ),
        )
        os._exit(72)
    _, status = os.waitpid(child, 0)
    assert os.WIFEXITED(status)
    assert os.WEXITSTATUS(status) == 71
    persisted = json.loads(state_path.read_text(encoding="utf-8"))
    assert persisted == {
        "execution_id": contract.execution_id,
        "phase": position,
        "resources": (
            _PersistentRunTestsExecutionDriver.resources_for(
                contract, position
            )
        ),
        "start_count": 0,
    }
    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        assert connection.execute(
            "SELECT state FROM handler_executions"
        ).fetchone() == ("RESERVED",)
        assert connection.execute(
            "SELECT COUNT(*) FROM receipts WHERE nonce = ?",
            (case["request"].nonce,),
        ).fetchone() == (0,)
    finally:
        connection.close()

    recovery_driver = _PersistentRunTestsExecutionDriver(
        state_path,
    )
    receipt = _execute_run_tests_case(
        case,
        tmp_path,
        ephemeral_role_keys,
        recovery_driver,
    )
    assert receipt.execution_status == "succeeded"
    assert sum(
        call[0] == "start_and_wait" for call in recovery_driver.calls
    ) == 1
    assert recovery_driver.reconciled_resources == persisted["resources"]
    final_state = json.loads(state_path.read_text(encoding="utf-8"))
    assert final_state["resources"] == {}
    assert final_state["phase"] == "cleaned"
    assert final_state["start_count"] == 1
    after = _run_tests_persistence_counts(case)
    assert after[:3] == (1, 1, 1)
    assert after[3] == before[3] + 1


@pytest.mark.parametrize(
    "position", ("docker_start_accepted", "result_renamed")
)
def test_execute_run_tests_recovers_lost_start_ack_without_second_start(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now: datetime,
    position: str,
) -> None:
    case = _run_tests_case(
        tmp_path=tmp_path,
        signed_work_order=signed_work_order,
        role_keys=ephemeral_role_keys,
        sidecar_receipt_factory=sidecar_receipt_factory,
        now=fixed_now,
    )
    state_path = tmp_path / f"persistent-start-{position}.json"
    before = _run_tests_persistence_counts(case)
    child = os.fork()
    if child == 0:
        _execute_run_tests_case(
            case,
            tmp_path,
            ephemeral_role_keys,
            _PersistentRunTestsExecutionDriver(
                state_path,
                start_crash_position=position,
            ),
        )
        os._exit(74)
    _, status = os.waitpid(child, 0)
    assert os.WIFEXITED(status)
    assert os.WEXITSTATUS(status) == 73
    contract = _run_tests_contract(case)
    persisted = json.loads(state_path.read_text(encoding="utf-8"))
    assert persisted["execution_id"] == contract.execution_id
    assert persisted["phase"] == position
    assert persisted["start_count"] == 1
    recovery_driver = _PersistentRunTestsExecutionDriver(
        state_path,
    )
    receipt = _execute_run_tests_case(
        case,
        tmp_path,
        ephemeral_role_keys,
        recovery_driver,
        request=_replacement_run_tests_request(case, ephemeral_role_keys),
    )
    assert receipt.nonce == case["request"].nonce
    assert sum(
        call[0] == "start_and_wait" for call in recovery_driver.calls
    ) == 0
    assert json.loads(state_path.read_text(encoding="utf-8"))[
        "start_count"
    ] == 1
    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM receipts WHERE nonce = ?",
            (case["request"].nonce,),
        ).fetchone() == (1,)
        assert connection.execute(
            "SELECT COUNT(*) FROM grant_events WHERE receipt_id = ?",
            (receipt.receipt_id,),
        ).fetchone() == (1,)
    finally:
        connection.close()
    after = _run_tests_persistence_counts(case)
    assert after[:3] == (1, 1, 1)
    assert after[3] == before[3] + 1


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
    before_counts = _run_tests_persistence_counts(case)
    first_driver = _FakeRunTestsExecutionDriver(
        actual_exit_code=None,
        failure_code="TIMEOUT",
        cleanup_error=RuntimeError("injected cleanup failure"),
    )
    with pytest.raises(
        HandlerCoordinationError, match="RECOVERY_REQUIRED"
    ) as captured:
        _execute_run_tests_case(
            case,
            tmp_path,
            ephemeral_role_keys,
            first_driver,
        )
    assert isinstance(captured.value.__cause__, RuntimeError)
    assert str(captured.value.__cause__) == "injected cleanup failure"
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
            "SELECT COUNT(*) FROM evidence_publications "
            "WHERE receipt_id = ("
            "SELECT receipt_id FROM receipts WHERE nonce = ?)",
            (case["request"].nonce,),
        ).fetchone() == (0,)
    finally:
        connection.close()
    committed_counts = _run_tests_persistence_counts(case)
    assert committed_counts[:3] == (1, 1, 0)
    assert committed_counts[3] == before_counts[3] + 1

    later = _append_same_second_grant(
        case,
        ephemeral_role_keys,
        fixed_now,
    )
    current_context = _current_run_tests_context(case, fixed_now)
    assert current_context.ledger_prefix.receipts[-1].receipt_id == (
        later.receipt_id
    )
    recovery_driver = _FakeRunTestsExecutionDriver(
        reconciliation_outcomes=(
            repo_tools.RunTestsExecutionOutcome("CLOSED_RESULT", None),
        )
    )
    with pytest.raises(ToolCallDenied):
        _execute_run_tests_case(
            case,
            tmp_path,
            ephemeral_role_keys,
            recovery_driver,
            context=current_context,
        )

    assert [call[0] for call in recovery_driver.calls] == ["reconcile"]
    assert recovery_driver.calls[0][2:] == (
        "STARTED_UNCONFIRMED",
        "MATCH",
    )
    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM handler_executions"
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT COUNT(*), MAX(sequence) FROM receipts"
        ).fetchone() == (committed[0] + 1, committed[1] + 1)
    finally:
        connection.close()


def test_execute_run_tests_crash_after_journal_cleanup_does_not_republish(
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
    before_counts = _run_tests_persistence_counts(case)
    real_delete = mcp_server._delete_handler_execution

    def crash_after_delete(*args, **kwargs):
        real_delete(*args, **kwargs)
        os._exit(78)

    monkeypatch.setattr(
        mcp_server, "_delete_handler_execution", crash_after_delete
    )
    child = os.fork()
    if child == 0:
        _execute_run_tests_case(
            case,
            tmp_path,
            ephemeral_role_keys,
            _FakeRunTestsExecutionDriver(),
        )
        os._exit(79)
    _, status = os.waitpid(child, 0)
    assert os.WIFEXITED(status)
    assert os.WEXITSTATUS(status) == 78
    monkeypatch.setattr(
        mcp_server, "_delete_handler_execution", real_delete
    )
    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        committed = connection.execute(
            "SELECT COUNT(*), MAX(sequence) FROM receipts"
        ).fetchone()
        assert connection.execute(
            "SELECT COUNT(*) FROM handler_executions"
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT COUNT(*) FROM grant_events WHERE receipt_id = ("
            "SELECT receipt_id FROM receipts WHERE nonce = ?) ",
            (case["request"].nonce,),
        ).fetchone() == (1,)
    finally:
        connection.close()
    committed_counts = _run_tests_persistence_counts(case)
    assert committed_counts[:3] == (1, 1, 1)
    assert committed_counts[3] == before_counts[3] + 1

    driver = _FakeRunTestsExecutionDriver()
    with pytest.raises(ToolCallDenied):
        _execute_run_tests_case(
            case,
            tmp_path,
            ephemeral_role_keys,
            driver,
            context=_current_run_tests_context(case, fixed_now),
            request=_replacement_run_tests_request(case, ephemeral_role_keys),
        )
    assert driver.calls == []
    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        assert connection.execute(
            "SELECT COUNT(*), MAX(sequence) FROM receipts"
        ).fetchone() == committed
    finally:
        connection.close()
    assert _run_tests_persistence_counts(case) == committed_counts


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

    receipt = _execute_run_tests_case(
        case,
        tmp_path,
        ephemeral_role_keys,
        _FakeRunTestsExecutionDriver(),
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
    failure = _execute_run_tests_case(
        case,
        tmp_path,
        role_keys,
        _FakeRunTestsExecutionDriver(actual_exit_code=1),
        now=now,
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
            SELECT tool_name, state, authorization_prefix_digest,
                   request_json,
                   execution_contract_json, execution_contract_digest
            FROM handler_executions
            """
        ).fetchone() == (
            "owp.rollback_patch",
            "STARTED_UNCONFIRMED",
            None,
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


def test_mcp_server_type_hints_resolve() -> None:
    """Every annotated function in mcp_server resolves without NameError."""
    import inspect  # noqa: PLC0415
    import typing  # noqa: PLC0415

    from openworkproof import mcp_server as mod  # noqa: PLC0415

    unresolved = []
    for name, member in vars(mod).items():
        if (
            inspect.isfunction(member)
            and getattr(member, "__annotations__", None)
        ):
            try:
                typing.get_type_hints(member)
            except Exception as error:  # noqa: BLE001
                unresolved.append((name, repr(error)))
    assert not unresolved, unresolved


def test_build_docker_run_tests_driver_fails_closed_on_invalid_config() -> None:
    from openworkproof import repo_tools  # noqa: PLC0415

    with pytest.raises(mcp_server.HandlerCoordinationError):
        mcp_server.build_docker_run_tests_driver(
            docker_binary=Path("relative-docker"),
            image_reference="not-immutable",
            candidate_runtime_root=Path("/tmp"),
        )
    with pytest.raises(mcp_server.HandlerCoordinationError):
        mcp_server.build_docker_run_tests_driver(
            docker_binary=Path("/usr/local/bin/docker"),
            image_reference="not-immutable",
            candidate_runtime_root=Path("/tmp"),
        )
    driver = mcp_server.build_docker_run_tests_driver(
        docker_binary=Path("/usr/local/bin/docker"),
        image_reference="docker.io/library/python@sha256:" + "0" * 64,
        candidate_runtime_root=Path("/tmp"),
    )
    assert isinstance(driver, repo_tools.DockerRunTestsExecutor)


def test_execute_run_tests_production_delegates_with_docker_driver(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now: datetime,
    monkeypatch,
) -> None:
    from openworkproof import repo_tools  # noqa: PLC0415

    case = _run_tests_case(
        tmp_path=tmp_path,
        signed_work_order=signed_work_order,
        role_keys=ephemeral_role_keys,
        sidecar_receipt_factory=sidecar_receipt_factory,
        now=fixed_now,
    )
    captured = {}

    def fake_execute(ledger_path, **kwargs):
        captured["ledger_path"] = ledger_path
        captured.update(kwargs)
        return None

    monkeypatch.setattr(mcp_server, "execute_run_tests", fake_execute)
    mcp_server.execute_run_tests_production(
        case["ledger_path"],
        evidence_root=case["evidence_root"],
        context=case["context"],
        request=case["request"],
        request_arguments=case["arguments"],
        execution_facts=case["facts"],
        sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
        docker_binary=Path("/usr/local/bin/docker"),
        image_reference="docker.io/library/python@sha256:" + "0" * 64,
        candidate_runtime_root=tmp_path,
        clock=lambda: fixed_now,
    )
    assert isinstance(
        captured["execution_driver"], repo_tools.DockerRunTestsExecutor
    )
    snapshot_request = captured["candidate_snapshot_request"]
    assert snapshot_request.expected_head_commit == (
        case["arguments"].candidate_commit
    )
    assert snapshot_request.expected_workspace_manifest_digest == (
        case["arguments"].workspace_manifest_digest
    )
    assert snapshot_request.source_artifact_sha256 == (
        case["work_order"].replay_profile.source_artifact_sha256
    )
