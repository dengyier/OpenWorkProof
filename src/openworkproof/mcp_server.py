"""Trusted MCP handler coordination primitives.

The transport server is intentionally deferred.  This module closes trusted
handler paths so an adapter cannot return before its receipt and evidence are
committed.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat
from typing import Literal

import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

import openworkproof.evidence as evidence
import openworkproof.repo_tools as repo_tools
from openworkproof.models import (
    ACTION_RECEIPT_ADAPTER,
    AgentRequest,
    EvidenceRef,
    GrantIssuedReceipt,
    PolicyDecision,
    RollbackReceipt,
    RunTestsArguments,
    TestResultEvidence,
    ToolCallReceipt,
    request_arguments_digest,
)
from openworkproof.policy import (
    AuthorizationContext,
    AuthorizationLedgerPrefix,
    ProspectiveExecutionFacts,
    authorize_tool_call,
    derive_authorization_context,
    validate_rollback,
)
from openworkproof.predicates import (
    EvaluationContext,
    evaluate_required_predicates,
    select_required_predicates,
)
from openworkproof.repo_tools import (
    CandidateWorkspace,
    RollbackRequest as WorkspaceRollbackRequest,
    rollback_candidate_workspace,
)
from openworkproof.signing import key_id, sign_payload, verify_nested_claim


class ToolCallDenied(RuntimeError):
    """The authenticated request reached policy and was denied."""

    def __init__(self, decision: PolicyDecision) -> None:
        super().__init__(decision.error_code or "tool call denied")
        self.decision = decision


class HandlerCoordinationError(RuntimeError):
    """The trusted handler coordinator could not preserve its boundary."""


@dataclass(frozen=True, slots=True)
class RollbackCommand:
    target_patch_receipt_id: str
    target_patch_digest: str
    before_commit: str

    def __post_init__(self) -> None:
        digest = re.compile(r"^[0-9a-f]{64}$")
        commit = re.compile(r"^[0-9a-f]{40}$")
        if (
            type(self.target_patch_receipt_id) is not str
            or digest.fullmatch(self.target_patch_receipt_id) is None
            or type(self.target_patch_digest) is not str
            or digest.fullmatch(self.target_patch_digest) is None
            or type(self.before_commit) is not str
            or commit.fullmatch(self.before_commit) is None
        ):
            raise HandlerCoordinationError("rollback command is malformed")


@dataclass(frozen=True, slots=True)
class RollbackHandlerResult:
    execution_status: Literal["succeeded", "failed"]
    before_commit: str
    after_commit: str
    after_manifest_digest: str

    def __post_init__(self) -> None:
        commit = re.compile(r"^[0-9a-f]{40}$")
        digest = re.compile(r"^[0-9a-f]{64}$")
        if (
            self.execution_status not in {"succeeded", "failed"}
            or type(self.before_commit) is not str
            or commit.fullmatch(self.before_commit) is None
            or type(self.after_commit) is not str
            or commit.fullmatch(self.after_commit) is None
            or type(self.after_manifest_digest) is not str
            or digest.fullmatch(self.after_manifest_digest) is None
            or (
                self.execution_status == "succeeded"
                and self.after_commit == self.before_commit
            )
            or (
                self.execution_status == "failed"
                and self.after_commit != self.before_commit
            )
        ):
            raise HandlerCoordinationError("rollback handler result is malformed")


def make_candidate_rollback_handler(
    *,
    workspace: CandidateWorkspace,
    failure_target_patch_receipt_id: str,
    failure_target_patch_receipt_digest: str,
    before_commit: str,
    before_manifest_digest: str,
    parent_commit: str,
    parent_manifest_digest: str,
) -> Callable[[RollbackCommand], RollbackHandlerResult]:
    """Bind one trusted candidate checkpoint to the rollback coordinator."""

    frozen_command = RollbackCommand(
        target_patch_receipt_id=failure_target_patch_receipt_id,
        target_patch_digest=failure_target_patch_receipt_digest,
        before_commit=before_commit,
    )
    if (
        type(workspace) is not CandidateWorkspace
        or type(before_manifest_digest) is not str
        or re.fullmatch(r"[0-9a-f]{64}", before_manifest_digest) is None
    ):
        raise HandlerCoordinationError(
            "candidate rollback binding is malformed"
        )
    RollbackHandlerResult(
        execution_status="succeeded",
        before_commit=before_commit,
        after_commit=parent_commit,
        after_manifest_digest=parent_manifest_digest,
    )

    def handler(command: RollbackCommand) -> RollbackHandlerResult:
        if type(command) is not RollbackCommand or command != frozen_command:
            raise HandlerCoordinationError(
                "rollback command does not match frozen workspace target"
            )
        result = rollback_candidate_workspace(
            WorkspaceRollbackRequest(
                workspace=workspace,
                target_patch_receipt_id=command.target_patch_receipt_id,
                target_patch_receipt_digest=command.target_patch_digest,
                failure_target_patch_receipt_id=(
                    failure_target_patch_receipt_id
                ),
                failure_target_patch_receipt_digest=(
                    failure_target_patch_receipt_digest
                ),
                before_commit=command.before_commit,
                before_manifest_digest=before_manifest_digest,
                parent_commit=parent_commit,
                parent_manifest_digest=parent_manifest_digest,
            )
        )
        return RollbackHandlerResult(
            execution_status=result.execution_status,
            before_commit=result.before_commit,
            after_commit=result.after_commit,
            after_manifest_digest=result.after_manifest_digest,
        )

    return handler


_MAX_RECEIPT_BYTES = 64 * 1024
_MAX_AGENT_REQUEST_BYTES = 8_192
_MAX_AUTHORIZATION_PREFIX_BYTES = 8 * 1024 * 1024


def _digest(value: object) -> str:
    return hashlib.sha256(rfc8785.dumps(value)).hexdigest()


def _journal_transaction(
    ledger_path: Path,
    lock_descriptor: int,
    operation: Callable[[sqlite3.Connection], object],
) -> object:
    evidence._borrow_or_acquire_target_lock(
        ledger_path,
        lock_descriptor,
    )
    connection = evidence.connect_ledger(ledger_path)
    try:
        connection.execute("BEGIN IMMEDIATE")
        result = operation(connection)
        connection.execute("COMMIT")
    except Exception as error:
        rollback_error = evidence._best_effort_rollback(connection)
        close_error = evidence._best_effort_close(connection)
        causes = [error]
        if rollback_error is not None:
            causes.append(rollback_error)
        if close_error is not None:
            causes.append(close_error)
        raise HandlerCoordinationError("RECOVERY_REQUIRED") from (
            evidence._error_cause(
                "handler execution journal transaction failed",
                causes,
            )
        )
    close_error = evidence._best_effort_close(connection)
    if close_error is not None:
        raise HandlerCoordinationError("RECOVERY_REQUIRED") from close_error
    return result


def _handler_execution_id(
    request: AgentRequest,
    execution_facts: ProspectiveExecutionFacts,
) -> str:
    return _digest(
        {
            "domain": "openworkproof/handler-execution/v0.1",
            "request_digest": request.digest,
            "execution_context_id": execution_facts.execution_context_id,
            "container_instance_id_digest": (
                execution_facts.container_instance_id_digest
            ),
            "controller_id": execution_facts.controller_id,
        }
    )


@dataclass(frozen=True, slots=True)
class _StoredRunTestsExecution:
    execution_id: str
    request: AgentRequest
    contract: repo_tools.RunTestsExecutionContract
    execution_facts: ProspectiveExecutionFacts
    authorization_prefix_digest: str
    reserved_at: datetime
    state: Literal["RESERVED", "STARTED_UNCONFIRMED"]


def _canonical_agent_request(request: AgentRequest) -> bytes:
    if type(request) is not AgentRequest:
        raise ValueError("stored AgentRequest is invalid")
    encoded = rfc8785.dumps(request.model_dump(mode="json"))
    if not 1 <= len(encoded) <= _MAX_AGENT_REQUEST_BYTES:
        raise ValueError("stored AgentRequest exceeds its byte limit")
    return encoded


def _authorization_prefix_digest(
    prefix: AuthorizationLedgerPrefix,
) -> str:
    if type(prefix) is not AuthorizationLedgerPrefix:
        raise ValueError("authorization prefix is invalid")
    encoded = rfc8785.dumps(
        {
            "domain": "openworkproof/authorization-ledger-prefix/v0.1",
            "effective_grants": [
                grant.model_dump(mode="json")
                for grant in prefix.effective_grants
            ],
            "grant_attempts": [
                grant.model_dump(mode="json")
                for grant in prefix.grant_attempts
            ],
            "receipts": [
                receipt.model_dump(mode="json")
                for receipt in prefix.receipts
            ],
        }
    )
    if not 1 <= len(encoded) <= _MAX_AUTHORIZATION_PREFIX_BYTES:
        raise ValueError("authorization prefix exceeds its byte limit")
    return hashlib.sha256(encoded).hexdigest()


def _decode_canonical_agent_request(raw: object) -> AgentRequest:
    if type(raw) is not str:
        raise ValueError("stored AgentRequest JSON is invalid")
    encoded = raw.encode("utf-8")
    if not 1 <= len(encoded) <= _MAX_AGENT_REQUEST_BYTES:
        raise ValueError("stored AgentRequest exceeds its byte limit")

    def reject_duplicates(
        pairs: list[tuple[str, object]],
    ) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("stored AgentRequest has duplicate keys")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise ValueError(f"invalid JSON constant: {value}")

    value = json.loads(
        raw,
        object_pairs_hook=reject_duplicates,
        parse_constant=reject_constant,
    )
    if rfc8785.dumps(value) != encoded:
        raise ValueError("stored AgentRequest is not canonical")
    request = AgentRequest.model_validate(value)
    if _canonical_agent_request(request) != encoded:
        raise ValueError("stored AgentRequest does not round trip")
    return request


def _contract_arguments_digest(
    contract: repo_tools.RunTestsExecutionContract,
) -> str:
    arguments = RunTestsArguments(
        test_mode="verifier",
        command_digest=contract.command_digest,
        source_commit=contract.source_commit,
        candidate_commit=contract.candidate_commit,
        workspace_manifest_digest=contract.workspace_manifest_digest,
        container_image_digest=contract.container_image_digest,
        fixed_test_source_digest=contract.fixed_test_source_digest,
    )
    return request_arguments_digest("owp.run_tests", arguments)


def _normalized_sql(value: str) -> str:
    return " ".join(value.split()).casefold()


def _ensure_handler_execution_schema(
    ledger_path: Path,
    lock_descriptor: int,
) -> None:
    expected = evidence._HANDLER_EXECUTION_SCHEMA

    def ensure(connection: sqlite3.Connection) -> None:
        row = connection.execute(
            """
            SELECT sql
            FROM sqlite_master
            WHERE type = 'table' AND name = 'handler_executions'
            """
        ).fetchone()
        if row is None:
            connection.execute(expected)
            return
        if len(row) != 1 or type(row[0]) is not str:
            raise ValueError("handler execution journal schema is invalid")
        actual = _normalized_sql(row[0])
        if actual == _normalized_sql(expected):
            return
        predecessors = (
            evidence._LEGACY_HANDLER_EXECUTION_SCHEMA,
            evidence._HANDLER_EXECUTION_SCHEMA_V1,
            evidence._HANDLER_EXECUTION_SCHEMA_V2,
        )
        if actual in {
            _normalized_sql(predecessor) for predecessor in predecessors
        }:
            if connection.execute(
                "SELECT COUNT(*) FROM handler_executions"
            ).fetchone() != (0,):
                raise ValueError(
                    "legacy handler execution journal is unresolved"
                )
            connection.execute("DROP TABLE handler_executions")
            connection.execute(expected)
            return
        raise ValueError("handler execution journal schema is invalid")

    _journal_transaction(ledger_path, lock_descriptor, ensure)


def _receipt_matches_handler_execution(
    stored_json: str,
    row: tuple[object, ...],
) -> bool:
    try:
        receipt = ACTION_RECEIPT_ADAPTER.validate_json(stored_json)
    except Exception:
        return False
    (
        _,
        work_order_digest,
        request_digest,
        nonce,
        grant_id,
        tool_name,
        arguments_digest,
        execution_context_id,
        container_instance_id_digest,
        controller_id,
        _,
        _,
    ) = row
    common = (
        receipt.work_order_digest == work_order_digest
        and receipt.nested_claim_digest == request_digest
        and receipt.nonce == nonce
        and getattr(receipt, "grant_id", None) == grant_id
        and receipt.nested_claim.tool_name == tool_name
        and receipt.nested_claim.arguments_digest == arguments_digest
        and receipt.policy_decision == "allow"
        and receipt.execution_status in {"succeeded", "failed"}
    )
    if not common:
        return False
    if isinstance(receipt, RollbackReceipt):
        return (
            tool_name == "owp.rollback_patch"
            and receipt.gateway_signer_key_id == controller_id
        )
    factors = receipt.correlation_factors
    return (
        isinstance(receipt, ToolCallReceipt)
        and receipt.tool_name == tool_name
        and receipt.arguments_digest == arguments_digest
        and factors is not None
        and factors.execution_context_id == execution_context_id
        and factors.container_instance_id_digest
        == container_instance_id_digest
        and factors.controller_id == controller_id
    )


def _recover_handler_executions(
    ledger_path: Path,
    lock_descriptor: int,
) -> None:
    def recover(connection: sqlite3.Connection) -> None:
        rows = tuple(
            connection.execute(
                """
                SELECT
                    execution_id,
                    work_order_digest,
                    request_digest,
                    nonce,
                    grant_id,
                    tool_name,
                    arguments_digest,
                    execution_context_id,
                    container_instance_id_digest,
                    controller_id,
                    reserved_at,
                    state
                FROM handler_executions
                ORDER BY execution_id
                """
            ).fetchall()
        )
        if len(rows) > 1:
            raise ValueError("multiple handler executions are unresolved")
        if not rows:
            return
        row = tuple(rows[0])
        if row[5] == "owp.run_tests":
            raise ValueError(
                "run-tests execution requires typed driver reconciliation"
            )
        state = row[-1]
        stored = connection.execute(
            "SELECT receipt_json FROM receipts WHERE nonce = ?",
            (row[3],),
        ).fetchone()
        if state == "RESERVED" and stored is None:
            connection.execute(
                "DELETE FROM handler_executions WHERE execution_id = ?",
                (row[0],),
            )
            return
        if (
            state == "STARTED_UNCONFIRMED"
            and stored is not None
            and _receipt_matches_handler_execution(stored[0], row)
        ):
            connection.execute(
                "DELETE FROM handler_executions WHERE execution_id = ?",
                (row[0],),
            )
            return
        raise ValueError("handler execution truth is unresolved")

    _journal_transaction(ledger_path, lock_descriptor, recover)


def _reserve_handler_execution(
    ledger_path: Path,
    lock_descriptor: int,
    context: AuthorizationContext,
    request: AgentRequest,
    execution_facts: ProspectiveExecutionFacts,
    execution_contract: repo_tools.RunTestsExecutionContract | None,
) -> str:
    execution_id = _handler_execution_id(request, execution_facts)
    request_json: str | None = None
    contract_json: str | None = None
    contract_digest: str | None = None
    authorization_prefix_digest: str | None = None
    if request.tool_name == "owp.run_tests":
        if type(execution_contract) is not repo_tools.RunTestsExecutionContract:
            raise HandlerCoordinationError("RECOVERY_REQUIRED")
        if (
            execution_contract.execution_id != execution_id
            or execution_contract.request_digest != request.digest
            or execution_contract.arguments_digest != request.arguments_digest
            or _contract_arguments_digest(execution_contract)
            != request.arguments_digest
        ):
            raise HandlerCoordinationError("RECOVERY_REQUIRED")
        try:
            request_bytes = _canonical_agent_request(request)
            contract_bytes = repo_tools.encode_run_tests_execution_contract(
                execution_contract
            )
        except (TypeError, ValueError) as error:
            raise HandlerCoordinationError("RECOVERY_REQUIRED") from error
        if not 1 <= len(contract_bytes) <= 8_192:
            raise HandlerCoordinationError("RECOVERY_REQUIRED")
        request_json = request_bytes.decode("utf-8")
        contract_json = contract_bytes.decode("utf-8")
        contract_digest = hashlib.sha256(contract_bytes).hexdigest()
        try:
            authorization_prefix_digest = _authorization_prefix_digest(
                context.ledger_prefix
            )
        except (TypeError, ValueError) as error:
            raise HandlerCoordinationError("RECOVERY_REQUIRED") from error
    elif request.tool_name == "owp.rollback_patch":
        if execution_contract is not None:
            raise HandlerCoordinationError("RECOVERY_REQUIRED")
    else:
        raise HandlerCoordinationError("RECOVERY_REQUIRED")

    def reserve(connection: sqlite3.Connection) -> None:
        if connection.execute(
            "SELECT COUNT(*) FROM handler_executions"
        ).fetchone() != (0,):
            raise ValueError("a handler execution is already unresolved")
        connection.execute(
            """
            INSERT INTO handler_executions (
                execution_id,
                work_order_digest,
                request_digest,
                nonce,
                grant_id,
                tool_name,
                arguments_digest,
                execution_context_id,
                container_instance_id_digest,
                controller_id,
                reserved_at,
                state,
                authorization_prefix_digest,
                request_json,
                execution_contract_json,
                execution_contract_digest
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'RESERVED', ?, ?, ?, ?
            )
            """,
            (
                execution_id,
                context.work_order.digest,
                request.digest,
                request.nonce,
                request.grant_id,
                request.tool_name,
                request.arguments_digest,
                execution_facts.execution_context_id,
                execution_facts.container_instance_id_digest,
                execution_facts.controller_id,
                context.transaction_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                authorization_prefix_digest,
                request_json,
                contract_json,
                contract_digest,
            ),
        )

    _journal_transaction(ledger_path, lock_descriptor, reserve)
    return execution_id


def _load_stored_run_tests_execution(
    ledger_path: Path,
    lock_descriptor: int,
) -> _StoredRunTestsExecution | None:
    def load(
        connection: sqlite3.Connection,
    ) -> _StoredRunTestsExecution | None:
        rows = connection.execute(
            """
            SELECT
                execution_id,
                work_order_digest,
                request_digest,
                nonce,
                grant_id,
                tool_name,
                arguments_digest,
                execution_context_id,
                container_instance_id_digest,
                controller_id,
                reserved_at,
                state,
                authorization_prefix_digest,
                request_json,
                execution_contract_json,
                execution_contract_digest
            FROM handler_executions
            ORDER BY execution_id
            LIMIT 2
            """
        ).fetchall()
        if not rows:
            return None
        if len(rows) != 1:
            raise ValueError("multiple handler executions are unresolved")
        if rows[0][5] == "owp.rollback_patch":
            return None
        (
            execution_id,
            work_order_digest,
            request_digest,
            nonce,
            grant_id,
            tool_name,
            arguments_digest,
            execution_context_id,
            container_instance_id_digest,
            controller_id,
            reserved_at_raw,
            state,
            authorization_prefix_digest,
            request_json,
            contract_json,
            contract_digest,
        ) = rows[0]
        request = _decode_canonical_agent_request(request_json)
        work_order = evidence.load_authoritative_work_order(connection)
        if type(contract_json) is not str:
            raise ValueError("stored execution contract JSON is invalid")
        contract_bytes = contract_json.encode("utf-8")
        if not 1 <= len(contract_bytes) <= 8_192:
            raise ValueError("stored execution contract exceeds its byte limit")
        contract = repo_tools.decode_run_tests_execution_contract(
            contract_bytes
        )
        if (
            type(contract_digest) is not str
            or hashlib.sha256(contract_bytes).hexdigest() != contract_digest
        ):
            raise ValueError("stored execution contract digest is invalid")
        if type(reserved_at_raw) is not str:
            raise ValueError("stored reservation time is invalid")
        reserved_at = datetime.strptime(
            reserved_at_raw, "%Y-%m-%dT%H:%M:%SZ"
        ).replace(tzinfo=timezone.utc)
        if reserved_at.strftime("%Y-%m-%dT%H:%M:%SZ") != reserved_at_raw:
            raise ValueError("stored reservation time is not a UTC second")
        if state not in {"RESERVED", "STARTED_UNCONFIRMED"}:
            raise ValueError("stored execution state is invalid")
        if (
            type(authorization_prefix_digest) is not str
            or re.fullmatch(r"[0-9a-f]{64}", authorization_prefix_digest)
            is None
        ):
            raise ValueError("stored authorization prefix digest is invalid")
        facts = ProspectiveExecutionFacts(
            execution_context_id=execution_context_id,
            container_instance_id_digest=container_instance_id_digest,
            controller_id=controller_id,
        )
        if (
            tool_name != "owp.run_tests"
            or not verify_nested_claim(request, work_order)
            or request.work_order_digest != work_order_digest
            or request.digest != request_digest
            or request.nonce != nonce
            or request.grant_id != grant_id
            or request.tool_name != tool_name
            or request.arguments_digest != arguments_digest
            or _handler_execution_id(request, facts) != execution_id
            or contract.execution_id != execution_id
            or contract.request_digest != request_digest
            or contract.arguments_digest != arguments_digest
            or _contract_arguments_digest(contract) != arguments_digest
        ):
            raise ValueError("stored run-tests execution fields disagree")
        return _StoredRunTestsExecution(
            execution_id=execution_id,
            request=request,
            contract=contract,
            execution_facts=facts,
            authorization_prefix_digest=authorization_prefix_digest,
            reserved_at=reserved_at,
            state=state,
        )

    result = _journal_transaction(ledger_path, lock_descriptor, load)
    if result is None or type(result) is _StoredRunTestsExecution:
        return result
    raise HandlerCoordinationError("RECOVERY_REQUIRED")


def _mark_handler_started(
    ledger_path: Path,
    lock_descriptor: int,
    execution_id: str,
) -> None:
    def mark(connection: sqlite3.Connection) -> None:
        cursor = connection.execute(
            """
            UPDATE handler_executions
            SET state = 'STARTED_UNCONFIRMED'
            WHERE execution_id = ? AND state = 'RESERVED'
            """,
            (execution_id,),
        )
        if cursor.rowcount != 1:
            raise ValueError("handler execution reservation is unavailable")

    _journal_transaction(ledger_path, lock_descriptor, mark)


def _finalize_handler_execution(
    ledger_path: Path,
    lock_descriptor: int,
) -> None:
    _recover_handler_executions(ledger_path, lock_descriptor)


def _delete_handler_execution(
    ledger_path: Path,
    lock_descriptor: int,
    execution_id: str,
) -> None:
    def delete(connection: sqlite3.Connection) -> None:
        cursor = connection.execute(
            "DELETE FROM handler_executions WHERE execution_id = ?",
            (execution_id,),
        )
        if cursor.rowcount != 1:
            raise ValueError("handler execution journal is unavailable")

    _journal_transaction(ledger_path, lock_descriptor, delete)


def _run_tests_receipt_state(
    ledger_path: Path,
    lock_descriptor: int,
    stored: _StoredRunTestsExecution,
) -> repo_tools.RunTestsReceiptState:
    def observe(connection: sqlite3.Connection) -> str:
        row = connection.execute(
            "SELECT receipt_json FROM receipts WHERE nonce = ?",
            (stored.request.nonce,),
        ).fetchone()
        if row is None:
            return "ABSENT"
        journal_row = connection.execute(
            """
            SELECT
                execution_id, work_order_digest, request_digest, nonce,
                grant_id, tool_name, arguments_digest,
                execution_context_id, container_instance_id_digest,
                controller_id, reserved_at, state
            FROM handler_executions
            WHERE execution_id = ?
            """,
            (stored.execution_id,),
        ).fetchone()
        if journal_row is None or type(row[0]) is not str:
            raise ValueError("stored run-tests Receipt observation is invalid")
        return (
            "MATCH"
            if _receipt_matches_handler_execution(row[0], tuple(journal_row))
            else "MISMATCH"
        )

    result = _journal_transaction(ledger_path, lock_descriptor, observe)
    if result in {"ABSENT", "MATCH", "MISMATCH"}:
        return result
    raise HandlerCoordinationError("RECOVERY_REQUIRED")


def _recovery_authorization_context(
    ledger_path: Path,
    evidence_root: Path,
    context: AuthorizationContext,
    stored: _StoredRunTestsExecution,
    receipt_state: repo_tools.RunTestsReceiptState,
    now: datetime,
    lock_descriptor: int,
) -> AuthorizationContext:
    _require_current_context(
        ledger_path,
        evidence_root,
        context,
        now,
        lock_descriptor,
    )
    if stored.request.work_order_digest != context.work_order.digest:
        raise HandlerCoordinationError("RECOVERY_REQUIRED")
    if receipt_state != "ABSENT":
        return context
    try:
        current_prefix_digest = _authorization_prefix_digest(
            context.ledger_prefix
        )
    except (TypeError, ValueError) as error:
        raise HandlerCoordinationError("RECOVERY_REQUIRED") from error
    if current_prefix_digest != stored.authorization_prefix_digest:
        raise HandlerCoordinationError("RECOVERY_REQUIRED")
    return derive_authorization_context(
        context.work_order,
        context.ledger_prefix,
        context.committed_evidence,
        context.replay_checkpoint,
        stored.reserved_at,
    )


def _remaining_tool_calls(context: AuthorizationContext, grant_id: str) -> int:
    balances = {
        (candidate_id, metric): remaining
        for candidate_id, metric, remaining in context.replay_state.balances
    }
    try:
        return balances[(grant_id, "tool_calls")]
    except KeyError as error:
        raise HandlerCoordinationError(
            "authorized Grant balance is unavailable"
        ) from error


def _committed_evidence_matches_context(
    root: Path,
    context: AuthorizationContext,
) -> None:
    expected = {
        item.reference.path: item
        for item in context.committed_evidence
    }
    actual_paths = {
        reference.path
        for receipt in context.ledger_prefix.receipts
        for reference in receipt.evidence_refs
    }
    if set(expected) != actual_paths:
        raise HandlerCoordinationError(
            "authorization evidence coverage is stale"
        )
    root_metadata = os.stat(root, follow_symlinks=False)
    if not stat.S_ISDIR(root_metadata.st_mode):
        raise HandlerCoordinationError(
            "authorization evidence root is unavailable"
        )
    for path, item in expected.items():
        relative = path.removeprefix("evidence/")
        parts = Path(relative).parts
        if (
            relative == path
            or not parts
            or Path(relative).is_absolute()
            or any(part in {"", ".", ".."} for part in parts)
        ):
            raise HandlerCoordinationError(
                "authorization evidence path is outside the root"
            )
        descriptors: list[int] = []
        recheck_descriptors: list[int] = []
        try:
            descriptors, identities = evidence._open_evidence_chain(
                root,
                parts,
                expected_size=item.reference.size_bytes,
            )
            payload, metadata = evidence._read_exact_descriptor(
                descriptors[-1],
                digest=item.reference.sha256,
                size_bytes=item.reference.size_bytes,
                allowed_links=(1,),
            )
            metadata_identity = (
                metadata.st_dev,
                metadata.st_ino,
                metadata.st_mode,
                metadata.st_nlink,
                metadata.st_size,
            )
            recheck_descriptors, recheck_identities = (
                evidence._open_evidence_chain(
                    root,
                    parts,
                    expected_size=item.reference.size_bytes,
                )
            )
            if (
                payload != item.payload
                or metadata_identity != identities[-1]
                or recheck_identities != identities
            ):
                raise OSError("authorization evidence changed")
        except OSError as error:
            raise HandlerCoordinationError(
                "authorization evidence bytes are stale"
            ) from error
        finally:
            evidence._close_evidence_descriptors(recheck_descriptors)
            evidence._close_evidence_descriptors(descriptors)
    root_after = os.stat(root, follow_symlinks=False)
    if (root_metadata.st_dev, root_metadata.st_ino) != (
        root_after.st_dev,
        root_after.st_ino,
    ):
        raise HandlerCoordinationError(
            "authorization evidence root changed during validation"
        )


def _require_current_context(
    ledger_path: Path,
    evidence_root: Path,
    context: AuthorizationContext,
    now: datetime,
    lock_descriptor: int,
) -> None:
    evidence.require_all_publications_committed(
        ledger_path,
        evidence_root=evidence_root,
        _borrowed_lock_descriptor=lock_descriptor,
    )
    connection = evidence.connect_ledger(ledger_path)
    try:
        work_order, receipts, grants, groups = (
            evidence._replay_receipt_publication_ledger(connection)
        )
        attempts = evidence._validated_grant_attempts(
            connection,
            work_order,
            receipts,
        )
        state_row = connection.execute(
            """
            SELECT current_state, version
            FROM work_order_state
            WHERE singleton = 1
            """
        ).fetchone()
    finally:
        connection.close()
    current_prefix = AuthorizationLedgerPrefix(
        effective_grants=tuple(
            sorted(grants.values(), key=lambda item: item.grant_id)
        ),
        grant_attempts=tuple(
            sorted(attempts.values(), key=lambda item: item.digest)
        ),
        receipts=receipts,
    )
    if (
        work_order != context.work_order
        or current_prefix != context.ledger_prefix
        or context.transaction_time != now
        or state_row
        != (
            context.current_state,
            evidence._derive_protocol_transaction_version(
                action_receipts=receipts,
                acceptance_receipts=(),
            ),
        )
        or any(state_value != "COMMITTED" for _, state_value in groups)
    ):
        raise HandlerCoordinationError(
            "authorization context is not the current ledger snapshot"
        )
    _committed_evidence_matches_context(evidence_root, context)
    rebuilt = derive_authorization_context(
        work_order,
        current_prefix,
        context.committed_evidence,
        context.replay_checkpoint,
        now,
    )
    if rebuilt != context:
        raise HandlerCoordinationError(
            "authorization context does not reproduce exactly"
        )


def _test_result_payload(
    arguments: RunTestsArguments,
    actual_exit_code: int,
) -> bytes:
    result = TestResultEvidence(
        schema_version="openworkproof-test-result/0.1",
        **arguments.model_dump(mode="python"),
        actual_exit_code=actual_exit_code,
    )
    return rfc8785.dumps(result.model_dump(mode="json"))


def _run_tests_arguments_from_contract(
    contract: repo_tools.RunTestsExecutionContract,
) -> RunTestsArguments:
    return RunTestsArguments(
        test_mode="verifier",
        command_digest=contract.command_digest,
        source_commit=contract.source_commit,
        candidate_commit=contract.candidate_commit,
        workspace_manifest_digest=contract.workspace_manifest_digest,
        container_image_digest=contract.container_image_digest,
        fixed_test_source_digest=contract.fixed_test_source_digest,
    )


def _next_test_reference(
    context: AuthorizationContext,
    arguments: RunTestsArguments,
    payload: bytes,
) -> EvidenceRef:
    purpose = (
        "verifier_result"
        if arguments.test_mode == "verifier"
        else "developer_test_result"
    )
    used_paths = {
        reference.path
        for receipt in context.ledger_prefix.receipts
        for reference in receipt.evidence_refs
    }
    slot = next(
        (
            artifact
            for artifact in context.work_order.evidence_policy.artifacts
            if artifact.purpose == purpose
            and f"evidence/{artifact.path}" not in used_paths
        ),
        None,
    )
    if slot is None or len(payload) > slot.max_size_bytes:
        raise HandlerCoordinationError(
            "EVIDENCE_SLOT_UNAVAILABLE"
        )
    return EvidenceRef(
        path=f"evidence/{slot.path}",
        sha256=hashlib.sha256(payload).hexdigest(),
        media_type=slot.media_type,
        size_bytes=len(payload),
    )


def _predicate_results(
    context: AuthorizationContext,
    request: AgentRequest,
    arguments: RunTestsArguments,
    *,
    execution_status: str,
    actual_exit_code: int | None,
    evidence_digest: str | None,
):
    selected = select_required_predicates(
        work_order=context.work_order,
        tool_name="owp.run_tests",
        policy_decision="allow",
        execution_status=execution_status,
        test_mode=arguments.test_mode,
    )
    remaining_before = _remaining_tool_calls(context, request.grant_id)
    tip = context.ledger_prefix.receipts[-1]
    profile = next(
        candidate
        for candidate in context.work_order.test_profiles
        if candidate.test_mode == arguments.test_mode
    )
    inputs: dict[str, object] = {}
    for spec in selected:
        if spec.name == "tool_allowed":
            value = {"actual_tool_name": "owp.run_tests"}
        elif spec.name == "quota_remaining":
            value = {
                "grant_id": request.grant_id,
                "metric": "tool_calls",
                "amount": 1,
                "grant_remaining_before": remaining_before,
                "ledger_prefix_digest": tip.digest,
            }
        elif spec.name == "tests_passed":
            value = {
                "test_mode": "verifier",
                "command_digest": arguments.command_digest,
                "expected_exit_code": profile.expected_exit_code,
                "actual_exit_code": actual_exit_code,
                "test_evidence_digest": evidence_digest,
                "source_commit": arguments.source_commit,
                "candidate_commit": arguments.candidate_commit,
                "workspace_manifest_digest": (
                    arguments.workspace_manifest_digest
                ),
                "container_image_digest": arguments.container_image_digest,
                "fixed_test_source_digest": (
                    arguments.fixed_test_source_digest
                ),
            }
        else:
            raise HandlerCoordinationError(
                "run-tests predicate authority is incomplete"
            )
        inputs[spec.predicate_id] = value
    return evaluate_required_predicates(
        selected,
        EvaluationContext(
            inputs=inputs,
            authoritative_inputs=inputs,
            authoritative_ledger_prefix_digests={
                request.grant_id: tip.digest,
            },
        ),
    )


def _causal_parents(
    context: AuthorizationContext,
    request: AgentRequest,
):
    receipts = context.ledger_prefix.receipts
    issuance = next(
        (
            receipt
            for receipt in receipts
            if isinstance(receipt, GrantIssuedReceipt)
            and receipt.policy_decision == "allow"
            and receipt.issued_grant_id == request.grant_id
        ),
        None,
    )
    active_patch = next(
        (
            receipt
            for receipt in receipts
            if receipt.receipt_id == context.active_patch_receipt_id
        ),
        None,
    )
    if issuance is None or active_patch is None:
        raise HandlerCoordinationError(
            "run-tests causal parents are unavailable"
        )
    return tuple(
        receipt.receipt_id
        for receipt in sorted(
            {issuance.receipt_id: issuance, active_patch.receipt_id: active_patch}.values(),
            key=lambda item: item.sequence,
        )
    )


def _build_run_tests_receipt(
    context: AuthorizationContext,
    request: AgentRequest,
    arguments: RunTestsArguments,
    execution_facts: ProspectiveExecutionFacts,
    sidecar_private_key: Ed25519PrivateKey,
    *,
    execution_status: str,
    execution_error_code: Literal[
        "OUTPUT_LIMIT", "TIMEOUT", "DISK_LIMIT"
    ] | None,
    actual_exit_code: int | None,
    payload: bytes | None,
) -> ToolCallReceipt:
    if execution_status == "succeeded":
        if execution_error_code is not None:
            raise HandlerCoordinationError("run-tests outcome is malformed")
        assert payload is not None and actual_exit_code is not None
        reference = _next_test_reference(context, arguments, payload)
        evidence_refs = (reference,)
        output_digest = reference.sha256
        state_after = (
            "locally_verified"
            if arguments.test_mode == "verifier"
            and actual_exit_code
            == next(
                profile.expected_exit_code
                for profile in context.work_order.test_profiles
                if profile.test_mode == arguments.test_mode
            )
            else "needs_rework"
            if arguments.test_mode == "verifier"
            else context.current_state
        )
    else:
        if execution_error_code not in {
            "OUTPUT_LIMIT",
            "TIMEOUT",
            "DISK_LIMIT",
        }:
            raise HandlerCoordinationError("run-tests outcome is malformed")
        if payload is not None or actual_exit_code is not None:
            raise HandlerCoordinationError("run-tests outcome is malformed")
        evidence_refs = ()
        output_digest = _digest(
            {"status": "failed", "error_code": execution_error_code}
        )
        state_after = context.current_state
    results = _predicate_results(
        context,
        request,
        arguments,
        execution_status=execution_status,
        actual_exit_code=actual_exit_code,
        evidence_digest=(
            None if payload is None else hashlib.sha256(payload).hexdigest()
        ),
    )
    remaining_before = _remaining_tool_calls(context, request.grant_id)
    sidecar_key_id = key_id(sidecar_private_key.public_key())
    toolchain_id = _digest(
        {
            "domain": "openworkproof/toolchain/v0.1",
            "tool_name": "owp.run_tests",
            "tool_version": "0.1",
            "container_image_digest": arguments.container_image_digest,
            "command_digest": arguments.command_digest,
        }
    )
    receipt_id = _digest(
        {
            "domain": "openworkproof/receipt-id/v0.1",
            "request_digest": request.digest,
            "entropy": secrets.token_hex(32),
        }
    )
    raw = {
        "protocol_version": "0.1",
        "receipt_id": receipt_id,
        "work_order_digest": context.work_order.digest,
        "actor_type": "agent",
        "actor_id": request.actor_id,
        "actor_key_id": request.actor_key_id,
        "nested_claim_type": "agent-request",
        "nested_claim_digest": request.digest,
        "nested_claim": request.model_dump(mode="json"),
        "gateway_signer_key_id": sidecar_key_id,
        "event_type": "tool_call",
        "policy_decision": "allow",
        "policy_error_code": None,
        "execution_status": execution_status,
        "execution_error_code": execution_error_code,
        "quota_charge": {
            "grant_id": request.grant_id,
            "metric": "tool_calls",
            "amount": 1,
            "remaining_after": remaining_before - 1,
        },
        "state_before": context.current_state,
        "state_after": state_after,
        "parent_receipt_ids": _causal_parents(context, request),
        "correlation_factors": {
            "model_id": request.model_id,
            "model_version": request.model_version,
            "prompt_template_digest": request.prompt_template_digest,
            "context_source_digest": request.context_source_digest,
            "toolchain_id": toolchain_id,
            "execution_context_id": execution_facts.execution_context_id,
            "container_instance_id_digest": (
                execution_facts.container_instance_id_digest
            ),
            "controller_id": execution_facts.controller_id,
            "fixed_test_source_digest": arguments.fixed_test_source_digest,
        },
        "evidence_refs": [
            item.model_dump(mode="json") for item in evidence_refs
        ],
        "occurred_at": context.transaction_time.strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
        "sequence": len(context.ledger_prefix.receipts) + 1,
        "nonce": request.nonce,
        "previous_receipt_digest": (
            context.ledger_prefix.receipts[-1].digest
        ),
        "grant_id": request.grant_id,
        "tool_name": "owp.run_tests",
        "tool_version": "0.1",
        "request_arguments": arguments.model_dump(mode="json"),
        "arguments_digest": request.arguments_digest,
        "output_digest": output_digest,
        "predicate_results": [
            result.model_dump(mode="json") for result in results
        ],
    }
    return ACTION_RECEIPT_ADAPTER.validate_python(
        sign_payload("action-receipt", raw, sidecar_private_key)
    )


def _preflight_run_tests_receipts(
    context: AuthorizationContext,
    request: AgentRequest,
    arguments: RunTestsArguments,
    execution_facts: ProspectiveExecutionFacts,
    sidecar_private_key: Ed25519PrivateKey,
) -> None:
    representative_receipts = []
    expected_exit_code = next(
        profile.expected_exit_code
        for profile in context.work_order.test_profiles
        if profile.test_mode == "verifier"
    )
    unexpected_exit_code = 0 if expected_exit_code != 0 else 1
    for exit_code in (expected_exit_code, unexpected_exit_code):
        payload = _test_result_payload(arguments, exit_code)
        representative_receipts.append(
            _build_run_tests_receipt(
                context,
                request,
                arguments,
                execution_facts,
                sidecar_private_key,
                execution_status="succeeded",
                execution_error_code=None,
                actual_exit_code=exit_code,
                payload=payload,
            )
        )
    for failure_code in ("OUTPUT_LIMIT", "TIMEOUT", "DISK_LIMIT"):
        representative_receipts.append(
            _build_run_tests_receipt(
                context,
                request,
                arguments,
                execution_facts,
                sidecar_private_key,
                execution_status="failed",
                execution_error_code=failure_code,
                actual_exit_code=None,
                payload=None,
            )
        )
    if any(
        len(rfc8785.dumps(receipt.model_dump(mode="json")))
        > _MAX_RECEIPT_BYTES
        for receipt in representative_receipts
    ):
        raise HandlerCoordinationError("BUNDLE_CAPACITY_EXCEEDED")


def _recover_run_tests_execution(
    ledger_path: Path,
    evidence_root: Path,
    lock_descriptor: int,
    context: AuthorizationContext,
    stored: _StoredRunTestsExecution,
    sidecar_private_key: Ed25519PrivateKey,
    execution_driver: repo_tools.RunTestsExecutionDriver,
    now: datetime,
) -> ToolCallReceipt | None:
    if (
        key_id(sidecar_private_key.public_key())
        != stored.execution_facts.controller_id
    ):
        raise HandlerCoordinationError("RECOVERY_REQUIRED")
    receipt_state = _run_tests_receipt_state(
        ledger_path, lock_descriptor, stored
    )
    old_context = _recovery_authorization_context(
        ledger_path,
        evidence_root,
        context,
        stored,
        receipt_state,
        now,
        lock_descriptor,
    )
    try:
        outcome = execution_driver.reconcile(
            stored.contract,
            stored.state,
            receipt_state,
        )
    except Exception as error:
        raise HandlerCoordinationError("RECOVERY_REQUIRED") from error
    if outcome.action in {"WAIT_RUNNING", "UNRESOLVED"}:
        raise HandlerCoordinationError("RECOVERY_REQUIRED")
    if outcome.action == "SAFE_TO_RETRY":
        if receipt_state != "ABSENT":
            raise HandlerCoordinationError("RECOVERY_REQUIRED")
        _delete_handler_execution(
            ledger_path, lock_descriptor, stored.execution_id
        )
        return None
    if outcome.action != "CLOSED_RESULT":
        raise HandlerCoordinationError("RECOVERY_REQUIRED")
    if receipt_state == "MISMATCH":
        raise HandlerCoordinationError("RECOVERY_REQUIRED")
    if receipt_state == "MATCH":
        if outcome.result is not None:
            raise HandlerCoordinationError("RECOVERY_REQUIRED")
        _delete_handler_execution(
            ledger_path, lock_descriptor, stored.execution_id
        )
        return None
    result = outcome.result
    if result is not None:
        try:
            repo_tools.encode_run_tests_result_envelope(result)
        except (TypeError, ValueError) as error:
            raise HandlerCoordinationError("RECOVERY_REQUIRED") from error
    contract_digest = hashlib.sha256(
        repo_tools.encode_run_tests_execution_contract(stored.contract)
    ).hexdigest()
    if (
        result is None
        or result.execution_id != stored.execution_id
        or result.execution_contract_digest != contract_digest
    ):
        raise HandlerCoordinationError("RECOVERY_REQUIRED")
    arguments = _run_tests_arguments_from_contract(stored.contract)
    if result.failure_code is not None:
        receipt = _build_run_tests_receipt(
            old_context,
            stored.request,
            arguments,
            stored.execution_facts,
            sidecar_private_key,
            execution_status="failed",
            execution_error_code=result.failure_code,
            actual_exit_code=None,
            payload=None,
        )
        payloads: dict[str, bytes] = {}
    else:
        if result.actual_exit_code is None:
            raise HandlerCoordinationError("RECOVERY_REQUIRED")
        payload = _test_result_payload(arguments, result.actual_exit_code)
        receipt = _build_run_tests_receipt(
            old_context,
            stored.request,
            arguments,
            stored.execution_facts,
            sidecar_private_key,
            execution_status="succeeded",
            execution_error_code=None,
            actual_exit_code=result.actual_exit_code,
            payload=payload,
        )
        payloads = {receipt.evidence_refs[0].path: payload}
    evidence.complete_receipt_publication(
        ledger_path,
        evidence_root=evidence_root,
        receipt=receipt,
        payloads=payloads,
        clock=lambda: stored.reserved_at,
        _borrowed_lock_descriptor=lock_descriptor,
    )
    try:
        execution_driver.cleanup(stored.contract)
    except Exception as error:
        raise HandlerCoordinationError("RECOVERY_REQUIRED") from error
    _delete_handler_execution(
        ledger_path, lock_descriptor, stored.execution_id
    )
    return receipt


def execute_run_tests(
    ledger_path: Path,
    *,
    evidence_root: Path,
    context: AuthorizationContext,
    request: AgentRequest,
    request_arguments: RunTestsArguments,
    execution_facts: ProspectiveExecutionFacts,
    candidate_snapshot_request: repo_tools.CandidateExecutionSnapshotRequest,
    sidecar_private_key: Ed25519PrivateKey,
    execution_driver: repo_tools.RunTestsExecutionDriver,
    clock: Callable[[], datetime],
) -> ToolCallReceipt:
    """Authorize, execute, sign, publish, and commit one test call."""

    path = Path(ledger_path)
    root = Path(evidence_root)
    if (
        type(candidate_snapshot_request)
        is not repo_tools.CandidateExecutionSnapshotRequest
        or not callable(getattr(execution_driver, "prepare", None))
        or not callable(getattr(execution_driver, "start_and_wait", None))
        or not callable(getattr(execution_driver, "reconcile", None))
        or not callable(getattr(execution_driver, "cleanup", None))
    ):
        raise HandlerCoordinationError("HANDLER_UNAVAILABLE")
    evidence.recover_evidence_publications(path, evidence_root=root)
    lock_descriptor = evidence._acquire_target_lock(path)
    primary_error: Exception | None = None
    receipt: ToolCallReceipt | None = None
    try:
        _ensure_handler_execution_schema(path, lock_descriptor)
        now = evidence._freeze_trusted_utc_second(clock())
        stored = _load_stored_run_tests_execution(path, lock_descriptor)
        if stored is not None:
            receipt = _recover_run_tests_execution(
                path,
                root,
                lock_descriptor,
                context,
                stored,
                sidecar_private_key,
                execution_driver,
                now,
            )
            if receipt is not None:
                _, release_errors = evidence._release_target_lock(
                    lock_descriptor
                )
                lock_descriptor = -1
                if release_errors:
                    raise HandlerCoordinationError(
                        "handler coordination lock release failed"
                    ) from release_errors[0]
                return receipt
        if (
            key_id(sidecar_private_key.public_key())
            != execution_facts.controller_id
        ):
            raise HandlerCoordinationError(
                "Sidecar signing key does not match execution controller"
            )
        _require_current_context(
            path,
            root,
            context,
            now,
            lock_descriptor,
        )
        decision = authorize_tool_call(
            context,
            request,
            request_arguments,
            execution_facts,
        )
        if not decision.allowed:
            raise ToolCallDenied(decision)
        if (
            request_arguments.test_mode != "verifier"
            or request_arguments.command_digest
            != repo_tools.frozen_verifier_command_digest()
            or candidate_snapshot_request.source_artifact_sha256
            != context.work_order.replay_profile.source_artifact_sha256
            or candidate_snapshot_request.expected_head_commit
            != request_arguments.candidate_commit
            or candidate_snapshot_request.expected_workspace_manifest_digest
            != request_arguments.workspace_manifest_digest
        ):
            raise HandlerCoordinationError(
                "run-tests execution binding is invalid"
            )
        _preflight_run_tests_receipts(
            context,
            request,
            request_arguments,
            execution_facts,
            sidecar_private_key,
        )
        execution_id = _handler_execution_id(request, execution_facts)
        execution_contract = repo_tools.RunTestsExecutionContract(
            execution_id=execution_id,
            request_digest=request.digest,
            arguments_digest=request.arguments_digest,
            candidate_workspace_id=candidate_snapshot_request.workspace_id,
            source_artifact_sha256=(
                candidate_snapshot_request.source_artifact_sha256
            ),
            source_commit=request_arguments.source_commit,
            candidate_commit=request_arguments.candidate_commit,
            workspace_manifest_digest=(
                request_arguments.workspace_manifest_digest
            ),
            container_image_digest=(
                request_arguments.container_image_digest
            ),
            command_digest=request_arguments.command_digest,
            fixed_test_source_digest=(
                request_arguments.fixed_test_source_digest
            ),
        )
        _reserve_handler_execution(
            path,
            lock_descriptor,
            context,
            request,
            execution_facts,
            execution_contract,
        )
        try:
            snapshot = repo_tools.prepare_candidate_execution_snapshot(
                candidate_snapshot_request
            )
            if (
                snapshot.head_commit
                != candidate_snapshot_request.expected_head_commit
                or snapshot.workspace_manifest_digest
                != candidate_snapshot_request.expected_workspace_manifest_digest
            ):
                raise ValueError("candidate execution snapshot is mismatched")
            preparation = execution_driver.prepare(
                execution_contract,
                snapshot,
            )
        except Exception:
            preparation = repo_tools.RunTestsPreparationOutcome("UNRESOLVED")
        if preparation.action != "READY_TO_START":
            try:
                recovered = execution_driver.reconcile(
                    execution_contract,
                    "RESERVED",
                    "ABSENT",
                )
            except Exception as error:
                raise HandlerCoordinationError(
                    "RECOVERY_REQUIRED"
                ) from error
            if recovered.action == "SAFE_TO_RETRY":
                _delete_handler_execution(
                    path, lock_descriptor, execution_id
                )
            raise HandlerCoordinationError("RECOVERY_REQUIRED")
        _mark_handler_started(
            path,
            lock_descriptor,
            execution_id,
        )
        try:
            outcome = execution_driver.start_and_wait(execution_contract)
        except Exception as error:
            raise HandlerCoordinationError("RECOVERY_REQUIRED") from error
        if outcome.action != "CLOSED_RESULT" or outcome.result is None:
            raise HandlerCoordinationError("RECOVERY_REQUIRED")
        result = outcome.result
        try:
            repo_tools.encode_run_tests_result_envelope(result)
        except (TypeError, ValueError) as error:
            raise HandlerCoordinationError("RECOVERY_REQUIRED") from error
        contract_digest = hashlib.sha256(
            repo_tools.encode_run_tests_execution_contract(execution_contract)
        ).hexdigest()
        if (
            result.execution_id != execution_id
            or result.execution_contract_digest != contract_digest
        ):
            raise HandlerCoordinationError("RECOVERY_REQUIRED")
        if result.failure_code is not None:
            receipt = _build_run_tests_receipt(
                context,
                request,
                request_arguments,
                execution_facts,
                sidecar_private_key,
                execution_status="failed",
                execution_error_code=result.failure_code,
                actual_exit_code=None,
                payload=None,
            )
            payloads = {}
        else:
            actual_exit_code = result.actual_exit_code
            if actual_exit_code is None:
                raise HandlerCoordinationError("RECOVERY_REQUIRED")
            payload = _test_result_payload(
                request_arguments,
                actual_exit_code,
            )
            receipt = _build_run_tests_receipt(
                context,
                request,
                request_arguments,
                execution_facts,
                sidecar_private_key,
                execution_status="succeeded",
                execution_error_code=None,
                actual_exit_code=actual_exit_code,
                payload=payload,
            )
            payloads = {receipt.evidence_refs[0].path: payload}
        evidence.complete_receipt_publication(
            path,
            evidence_root=root,
            receipt=receipt,
            payloads=payloads,
            clock=lambda: now,
            _borrowed_lock_descriptor=lock_descriptor,
        )
        try:
            execution_driver.cleanup(execution_contract)
        except Exception as error:
            raise HandlerCoordinationError("RECOVERY_REQUIRED") from error
        _delete_handler_execution(path, lock_descriptor, execution_id)
    except Exception as error:
        primary_error = error
    if lock_descriptor < 0:
        release_errors = ()
    else:
        _, release_errors = evidence._release_target_lock(lock_descriptor)
    if primary_error is not None:
        if release_errors:
            raise HandlerCoordinationError(
                "handler coordination and lock release both failed"
            ) from primary_error
        raise primary_error
    if release_errors:
        raise HandlerCoordinationError(
            "handler coordination lock release failed"
        ) from release_errors[0]
    assert receipt is not None
    return receipt


def _rollback_parents(
    context: AuthorizationContext,
    request: AgentRequest,
) -> tuple[GrantIssuedReceipt, ToolCallReceipt, ToolCallReceipt]:
    receipts = context.ledger_prefix.receipts
    issuance = next(
        (
            receipt
            for receipt in receipts
            if isinstance(receipt, GrantIssuedReceipt)
            and receipt.policy_decision == "allow"
            and receipt.issued_grant_id == request.grant_id
        ),
        None,
    )
    target = next(
        (
            receipt
            for receipt in receipts
            if receipt.receipt_id == context.active_patch_receipt_id
        ),
        None,
    )
    failure = next(
        (
            receipt
            for receipt in receipts
            if receipt.receipt_id == context.causal_state.failure_receipt_id
        ),
        None,
    )
    if (
        not isinstance(issuance, GrantIssuedReceipt)
        or not isinstance(target, ToolCallReceipt)
        or not isinstance(failure, ToolCallReceipt)
    ):
        raise HandlerCoordinationError(
            "rollback causal parents are unavailable"
        )
    return issuance, target, failure


def _rollback_command(
    context: AuthorizationContext,
    request: AgentRequest,
) -> RollbackCommand:
    _, target, _ = _rollback_parents(context, request)
    return RollbackCommand(
        target_patch_receipt_id=target.receipt_id,
        target_patch_digest=target.digest,
        before_commit=context.replay_checkpoint.head_commit,
    )


def _build_rollback_receipt(
    context: AuthorizationContext,
    request: AgentRequest,
    sidecar_private_key: Ed25519PrivateKey,
    result: RollbackHandlerResult,
) -> RollbackReceipt:
    issuance, target, failure = _rollback_parents(context, request)
    remaining_before = _remaining_tool_calls(context, request.grant_id)
    sidecar_key_id = key_id(sidecar_private_key.public_key())
    raw = {
        "protocol_version": "0.1",
        "receipt_id": _digest(
            {
                "domain": "openworkproof/receipt-id/v0.1",
                "request_digest": request.digest,
                "entropy": secrets.token_hex(32),
            }
        ),
        "work_order_digest": context.work_order.digest,
        "actor_type": "agent",
        "actor_id": request.actor_id,
        "actor_key_id": request.actor_key_id,
        "nested_claim_type": "agent-request",
        "nested_claim_digest": request.digest,
        "nested_claim": request.model_dump(mode="json"),
        "gateway_signer_key_id": sidecar_key_id,
        "event_type": "rollback",
        "policy_decision": "allow",
        "policy_error_code": None,
        "execution_status": result.execution_status,
        "execution_error_code": (
            None
            if result.execution_status == "succeeded"
            else "HANDLER_ERROR"
        ),
        "quota_charge": {
            "grant_id": request.grant_id,
            "metric": "tool_calls",
            "amount": 1,
            "remaining_after": remaining_before - 1,
        },
        "state_before": "needs_rework",
        "state_after": "needs_rework",
        "parent_receipt_ids": [
            issuance.receipt_id,
            target.receipt_id,
            failure.receipt_id,
        ],
        "correlation_factors": None,
        "evidence_refs": [],
        "occurred_at": context.transaction_time.strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
        "sequence": len(context.ledger_prefix.receipts) + 1,
        "nonce": request.nonce,
        "previous_receipt_digest": (
            context.ledger_prefix.receipts[-1].digest
        ),
        "grant_id": request.grant_id,
        "target_patch_receipt_id": target.receipt_id,
        "target_patch_digest": target.digest,
        "before_commit": result.before_commit,
        "after_commit": result.after_commit,
        "after_manifest_digest": result.after_manifest_digest,
        "rollback_result": result.execution_status,
    }
    return ACTION_RECEIPT_ADAPTER.validate_python(
        sign_payload("action-receipt", raw, sidecar_private_key)
    )


def _preflight_rollback_receipts(
    context: AuthorizationContext,
    request: AgentRequest,
    sidecar_private_key: Ed25519PrivateKey,
) -> None:
    before = context.replay_checkpoint.head_commit
    alternate = context.work_order.source_commit
    if alternate == before:
        alternate = "0" * 40 if before != "0" * 40 else "1" * 40
    representatives = (
        RollbackHandlerResult(
            execution_status="succeeded",
            before_commit=before,
            after_commit=alternate,
            after_manifest_digest="0" * 64,
        ),
        RollbackHandlerResult(
            execution_status="failed",
            before_commit=before,
            after_commit=before,
            after_manifest_digest=(
                context.replay_checkpoint.workspace_manifest_digest
            ),
        ),
    )
    if any(
        len(
            rfc8785.dumps(
                _build_rollback_receipt(
                    context,
                    request,
                    sidecar_private_key,
                    result,
                ).model_dump(mode="json")
            )
        )
        > _MAX_RECEIPT_BYTES
        for result in representatives
    ):
        raise HandlerCoordinationError("BUNDLE_CAPACITY_EXCEEDED")


def execute_rollback(
    ledger_path: Path,
    *,
    evidence_root: Path,
    context: AuthorizationContext,
    request: AgentRequest,
    execution_facts: ProspectiveExecutionFacts,
    sidecar_private_key: Ed25519PrivateKey,
    handler: Callable[[RollbackCommand], RollbackHandlerResult],
    clock: Callable[[], datetime],
) -> RollbackReceipt:
    """Authorize, execute, sign, and commit one rollback attempt."""

    path = Path(ledger_path)
    root = Path(evidence_root)
    if not callable(handler):
        raise HandlerCoordinationError("HANDLER_UNAVAILABLE")
    evidence.recover_evidence_publications(path, evidence_root=root)
    lock_descriptor = evidence._acquire_target_lock(path)
    primary_error: Exception | None = None
    receipt: RollbackReceipt | None = None
    try:
        _ensure_handler_execution_schema(path, lock_descriptor)
        _recover_handler_executions(path, lock_descriptor)
        now = evidence._freeze_trusted_utc_second(clock())
        if (
            key_id(sidecar_private_key.public_key())
            != execution_facts.controller_id
        ):
            raise HandlerCoordinationError(
                "Sidecar signing key does not match execution controller"
            )
        _require_current_context(
            path,
            root,
            context,
            now,
            lock_descriptor,
        )
        decision = validate_rollback(context, request)
        if not decision.allowed:
            raise ToolCallDenied(decision)
        _preflight_rollback_receipts(
            context,
            request,
            sidecar_private_key,
        )
        command = _rollback_command(context, request)
        execution_id = _reserve_handler_execution(
            path,
            lock_descriptor,
            context,
            request,
            execution_facts,
            None,
        )
        _mark_handler_started(path, lock_descriptor, execution_id)
        try:
            result = handler(command)
        except Exception as error:
            raise HandlerCoordinationError("RECOVERY_REQUIRED") from error
        if type(result) is not RollbackHandlerResult:
            raise HandlerCoordinationError("RECOVERY_REQUIRED")
        receipt = _build_rollback_receipt(
            context,
            request,
            sidecar_private_key,
            result,
        )
        evidence.complete_receipt_publication(
            path,
            evidence_root=root,
            receipt=receipt,
            payloads={},
            clock=lambda: now,
            _borrowed_lock_descriptor=lock_descriptor,
        )
        _finalize_handler_execution(path, lock_descriptor)
    except Exception as error:
        primary_error = error
    _, release_errors = evidence._release_target_lock(lock_descriptor)
    if primary_error is not None:
        if release_errors:
            raise HandlerCoordinationError(
                "handler coordination and lock release both failed"
            ) from primary_error
        raise primary_error
    if release_errors:
        raise HandlerCoordinationError(
            "handler coordination lock release failed"
        ) from release_errors[0]
    assert receipt is not None
    return receipt


__all__ = [
    "HandlerCoordinationError",
    "RollbackCommand",
    "RollbackHandlerResult",
    "ToolCallDenied",
    "execute_rollback",
    "execute_run_tests",
    "make_candidate_rollback_handler",
]
