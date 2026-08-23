"""Trusted MCP handler coordination primitives.

The transport server is intentionally deferred.  This module closes trusted
handler paths so an adapter cannot return before its receipt and evidence are
committed.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import secrets
import sqlite3
from typing import Literal

import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

import openworkproof.evidence as evidence
import openworkproof.repo_tools as repo_tools
import openworkproof.runtime_context as runtime_context
from openworkproof.binding_transactions import (
    load_historical_action_binding_manifest,
)
from openworkproof.models import (
    ActionReceiptEnvelope,
    AgentRequest,
    AgentRequestV04,
    EvidenceRef,
    GrantIssuedReceipt,
    POLICY_ERROR_CODES,
    POLICY_ERROR_CODES_V04,
    PolicyDecision,
    RepoReadArguments,
    RollbackReceipt,
    RollbackReceiptV04,
    RunTestsArguments,
    SystemEventReceipt,
    TestResultEvidence,
    ToolCallReceipt,
    ToolCallReceiptV04,
    ToolRequestArguments,
    WorkOrder,
    parse_agent_request,
    parse_action_receipt_json,
    request_arguments_digest,
)
from openworkproof.policy import (
    AuthorizationContext,
    AuthorizationLedgerPrefix,
    ProspectiveExecutionFacts,
    _authorize_bound_action_with_manifest,
    authorize_bound_action,
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


def _require_current_context(
    ledger_path: Path,
    evidence_root: Path,
    context: AuthorizationContext,
    now: datetime,
    lock_descriptor: int,
) -> None:
    try:
        runtime_context.require_current_context(
            ledger_path,
            evidence_root,
            context,
            now,
            lock_descriptor,
        )
    except runtime_context.RuntimeContextError as error:
        raise HandlerCoordinationError(str(error)) from error


def _require_bound_action(
    ledger_path: Path,
    context: AuthorizationContext,
    request: AgentRequest,
    request_arguments: object | None,
    execution_facts: ProspectiveExecutionFacts | None = None,
) -> PolicyDecision:
    decision = authorize_bound_action(
        ledger_path,
        context,
        request,
        request_arguments,
        execution_facts,
    )
    if not decision.allowed:
        raise ToolCallDenied(decision)
    return decision


def _enforce_agency_authorization(
    agency_authorize: Callable[[], PolicyDecision] | None,
) -> None:
    """Enforce the opt-in agency boundary for a brand-new action (A).

    This runs inside the already-held target lock, on the new-action path
    only: after the existing context and the complete base authorization have
    allowed the call, and before any preflight, reservation, handler, or
    receipt write. Reconciliation/finalization of a previously RESERVED or
    STARTED_UNCONFIRMED action (B) is not re-authorized against the current
    profile — recovery replays the stored request truth, so a later
    revocation is not retroactive. Idempotent bookkeeping/schema/evidence
    recovery (C) runs before this gate and is therefore excluded from the
    denied new-action no-business-write invariant. The callback is invoked
    exactly once; a malformed return value fails closed and a deny raises the
    normal ToolCallDenied.
    """

    if agency_authorize is None:
        return
    decision = agency_authorize()
    if type(decision) is not PolicyDecision:
        raise HandlerCoordinationError(
            "agency authorization returned a malformed decision"
        )
    if not decision.allowed:
        raise ToolCallDenied(decision)


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
    agency_binding: str | None = None


def _canonical_agent_request(request: AgentRequest) -> bytes:
    if type(request) not in {AgentRequest, AgentRequestV04}:
        raise ValueError("stored AgentRequest is invalid")
    encoded = rfc8785.dumps(request.model_dump(mode="json"))
    if not 1 <= len(encoded) <= _MAX_AGENT_REQUEST_BYTES:
        raise ValueError("stored AgentRequest exceeds its byte limit")
    return encoded


_LEGACY_AUTHORIZATION_PREFIX_DOMAIN = (
    "openworkproof/authorization-ledger-prefix/v0.1"
)
_AGENCY_AUTHORIZATION_PREFIX_DOMAIN = (
    "openworkproof/authorization-ledger-prefix-agency/v0.1"
)


def _authorization_prefix_digest(
    prefix: AuthorizationLedgerPrefix,
    *,
    domain: str = _LEGACY_AUTHORIZATION_PREFIX_DOMAIN,
) -> str:
    if type(prefix) is not AuthorizationLedgerPrefix:
        raise ValueError("authorization prefix is invalid")
    if domain not in {
        _LEGACY_AUTHORIZATION_PREFIX_DOMAIN,
        _AGENCY_AUTHORIZATION_PREFIX_DOMAIN,
    }:
        raise ValueError("authorization prefix domain is invalid")
    encoded = rfc8785.dumps(
        {
            "domain": domain,
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


def _agency_binding_prefix_domain(agency_binding: str | None) -> str:
    """Map a stored journal agency binding to its authorization domain.

    NULL maps to the legacy domain; the fixed exact marker maps to the
    domain-separated agency domain. Any other value fails closed so a marker
    flip without a matching domain digest cannot be laundered as bound.
    """

    if agency_binding is None:
        return _LEGACY_AUTHORIZATION_PREFIX_DOMAIN
    if agency_binding == evidence._HANDLER_AGENCY_BINDING_MARKER:
        return _AGENCY_AUTHORIZATION_PREFIX_DOMAIN
    raise HandlerCoordinationError("RECOVERY_REQUIRED")


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
    request = parse_agent_request(value)
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
    """Idempotently ensure the handler execution journal schema (C).

    This bookkeeping step runs inside the target lock before the incoming
    request's base/agency authorization gate. It creates the current journal
    table, drops an empty predecessor, or atomically rebuilds the immediately
    previous schema while preserving any nonempty row with a NULL agency
    binding; it never executes a handler, writes a receipt, or changes
    business state, so it is excluded from the denied new-action
    no-business-write invariant.
    """

    expected = evidence._HANDLER_EXECUTION_SCHEMA
    previous = evidence._HANDLER_EXECUTION_SCHEMA_V3

    def _rebuild_with_agency_binding(connection: sqlite3.Connection) -> None:
        connection.execute(
            "ALTER TABLE handler_executions "
            "RENAME TO handler_executions_agency_migrate"
        )
        connection.execute(expected)
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
                agency_binding,
                request_json,
                execution_contract_json,
                execution_contract_digest
            )
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
                NULL,
                request_json,
                execution_contract_json,
                execution_contract_digest
            FROM handler_executions_agency_migrate
            """
        )
        connection.execute("DROP TABLE handler_executions_agency_migrate")

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
        if actual == _normalized_sql(previous):
            if connection.execute(
                "SELECT COUNT(*) FROM handler_executions"
            ).fetchone() == (0,):
                connection.execute("DROP TABLE handler_executions")
                connection.execute(expected)
                return
            _rebuild_with_agency_binding(connection)
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
        receipt = parse_action_receipt_json(stored_json)
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
    """Reconcile a previously reserved generic action before the agency gate.

    This is the (B)/(C) recovery boundary for repo-read and rollback: a
    RESERVED row with no matching receipt is a provably stale reservation and
    is cleaned up (C); a STARTED_UNCONFIRMED row whose receipt already
    committed is finalized (B). Neither path re-authorizes the stored request
    against the current profile — a later revocation is not retroactive — and
    neither runs a handler or writes a new receipt. run-tests rows are refused
    here because they require the typed driver reconciliation.
    """

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
    *,
    agency_bound: bool = False,
) -> str:
    execution_id = _handler_execution_id(request, execution_facts)
    request_json: str | None = None
    contract_json: str | None = None
    contract_digest: str | None = None
    authorization_prefix_digest: str | None = None
    agency_binding: str | None = None
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
        agency_binding = (
            evidence._HANDLER_AGENCY_BINDING_MARKER if agency_bound else None
        )
        try:
            authorization_prefix_digest = _authorization_prefix_digest(
                context.ledger_prefix,
                domain=_agency_binding_prefix_domain(agency_binding),
            )
        except (TypeError, ValueError) as error:
            raise HandlerCoordinationError("RECOVERY_REQUIRED") from error
    elif request.tool_name in {"owp.rollback_patch", "owp.repo_read"}:
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
                agency_binding,
                request_json,
                execution_contract_json,
                execution_contract_digest
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'RESERVED', ?, ?, ?, ?, ?
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
                agency_binding,
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
    """Load a prior run-tests reservation for reconciliation (B).

    The stored request, contract, and authorization prefix are replayed
    verbatim; the loaded row is not re-authorized against the current profile.
    """

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
                agency_binding,
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
            agency_binding,
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
        if agency_binding is not None and agency_binding != (
            evidence._HANDLER_AGENCY_BINDING_MARKER
        ):
            raise ValueError("stored agency binding marker is invalid")
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
            agency_binding=agency_binding,
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
    """Rebuild the historical authorization context for a stored action (B).

    The prefix is reconstructed so its digest matches the reservation-time
    authorization prefix digest; the stored request is never re-authorized
    against the current profile.
    """

    _require_current_context(
        ledger_path,
        evidence_root,
        context,
        now,
        lock_descriptor,
    )
    if stored.request.work_order_digest != context.work_order.digest:
        raise HandlerCoordinationError("RECOVERY_REQUIRED")
    domain = _agency_binding_prefix_domain(stored.agency_binding)
    if receipt_state == "ABSENT":
        try:
            current_prefix_digest = _authorization_prefix_digest(
                context.ledger_prefix,
                domain=domain,
            )
        except (TypeError, ValueError) as error:
            raise HandlerCoordinationError("RECOVERY_REQUIRED") from error
        if current_prefix_digest != stored.authorization_prefix_digest:
            raise HandlerCoordinationError("RECOVERY_REQUIRED")
        historical_prefix = context.ledger_prefix
    else:
        candidates: list[AuthorizationLedgerPrefix] = []
        receipts = context.ledger_prefix.receipts
        for count in range(len(receipts) + 1):
            historical_receipts = receipts[:count]
            issued_grant_ids = {
                receipt.issued_grant_id
                for receipt in historical_receipts
                if isinstance(receipt, GrantIssuedReceipt)
                and receipt.policy_decision == "allow"
                and receipt.issued_grant_id is not None
            }
            denied_grant_digests = {
                receipt.candidate_grant_digest
                for receipt in historical_receipts
                if isinstance(receipt, GrantIssuedReceipt)
                and receipt.policy_decision == "deny"
                and receipt.candidate_grant_digest is not None
            }
            candidate = AuthorizationLedgerPrefix(
                effective_grants=tuple(
                    grant
                    for grant in context.ledger_prefix.effective_grants
                    if grant.grant_id in issued_grant_ids
                ),
                grant_attempts=tuple(
                    grant
                    for grant in context.ledger_prefix.grant_attempts
                    if grant.digest in denied_grant_digests
                ),
                receipts=historical_receipts,
            )
            try:
                digest = _authorization_prefix_digest(candidate, domain=domain)
            except (TypeError, ValueError) as error:
                raise HandlerCoordinationError(
                    "RECOVERY_REQUIRED"
                ) from error
            if digest == stored.authorization_prefix_digest:
                candidates.append(candidate)
        if len(candidates) != 1:
            raise HandlerCoordinationError("RECOVERY_REQUIRED")
        historical_prefix = candidates[0]
    historical_evidence_paths = {
        reference.path
        for receipt in historical_prefix.receipts
        for reference in receipt.evidence_refs
    }
    historical_evidence = tuple(
        item
        for item in context.committed_evidence
        if item.reference.path in historical_evidence_paths
    )
    return derive_authorization_context(
        context.work_order,
        historical_prefix,
        historical_evidence,
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


def _run_tests_episode(
    context: AuthorizationContext,
    request: AgentRequest,
    arguments: RunTestsArguments,
) -> Literal["primary_verifier", "independent_verifier"]:
    """Derive the closed run-tests episode from current authority.

    The episode is derived from the signed context and the agent request;
    callers do not supply it. A second Verifier run after the first composition
    is the independent_verifier episode; all other Verifier runs are the
    primary_verifier episode. Developer mode and any non-Verifier caller are
    not handled by this helper.
    """
    binding = next(
        (
            item
            for item in context.work_order.key_bindings
            if item.subject_id == request.actor_id
            and item.key_id == request.actor_key_id
        ),
        None,
    )
    if binding is None or binding.role != "Verifier":
        raise HandlerCoordinationError("run-tests actor is not the Verifier")
    if arguments.test_mode != "verifier":
        raise HandlerCoordinationError("run-tests mode is not verifier")
    if context.current_state in {"running", "retrying"}:
        return "primary_verifier"
    if context.current_state == "evidence_incomplete":
        return "independent_verifier"
    raise HandlerCoordinationError("run-tests state is not executable")


def _next_test_reference(
    context: AuthorizationContext,
    arguments: RunTestsArguments,
    payload: bytes,
    *,
    purpose: Literal["verifier_result", "verifier_independent_result", "developer_test_result"] | None = None,
) -> EvidenceRef:
    if purpose is None:
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
    *,
    extra_parents: tuple[ActionReceiptEnvelope, ...] = (),
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
    parents: dict[str, ActionReceiptEnvelope] = {
        issuance.receipt_id: issuance,
        active_patch.receipt_id: active_patch,
    }
    for parent in extra_parents:
        parents[parent.receipt_id] = parent
    return tuple(
        receipt.receipt_id
        for receipt in sorted(
            parents.values(),
            key=lambda item: item.sequence,
        )
    )


def _latest_proof_composed_trigger(
    receipts: tuple[ActionReceiptEnvelope, ...],
) -> SystemEventReceipt | None:
    for receipt in reversed(receipts):
        if (
            isinstance(receipt, SystemEventReceipt)
            and receipt.system_event_name == "proof_composed"
        ):
            return receipt
    return None


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
    episode = _run_tests_episode(context, request, arguments)
    if episode == "independent_verifier":
        trigger = _latest_proof_composed_trigger(context.ledger_prefix.receipts)
        # A retry after an infrastructure failure causally links to the
        # previous closed failure receipt of the same episode, so the exact
        # publication-tip parent requirement is satisfied on retry.
        prior_independent = next(
            (
                receipt
                for receipt in reversed(context.ledger_prefix.receipts)
                if isinstance(receipt, ToolCallReceipt)
                and receipt.tool_name == "owp.run_tests"
                and receipt.state_before == "evidence_incomplete"
                and receipt.state_after == "evidence_incomplete"
            ),
            None,
        )
        extra_parents: tuple[ActionReceiptEnvelope, ...] = tuple(
            parent
            for parent in (trigger, prior_independent)
            if parent is not None
        )
        purpose: Literal[
            "verifier_result",
            "verifier_independent_result",
            "developer_test_result",
        ] = "verifier_independent_result"
    else:
        extra_parents = ()
        purpose = (
            "verifier_result"
            if arguments.test_mode == "verifier"
            else "developer_test_result"
        )
    if execution_status == "succeeded":
        if execution_error_code is not None:
            raise HandlerCoordinationError("run-tests outcome is malformed")
        assert payload is not None and actual_exit_code is not None
        reference = _next_test_reference(
            context, arguments, payload, purpose=purpose
        )
        evidence_refs = (reference,)
        output_digest = reference.sha256
        if episode == "independent_verifier":
            state_after = "evidence_incomplete"
        else:
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
        state_after = (
            "evidence_incomplete"
            if episode == "independent_verifier"
            else context.current_state
        )
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
        "protocol_version": (
            "0.4" if type(request) is AgentRequestV04 else "0.1"
        ),
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
        "parent_receipt_ids": _causal_parents(
            context, request, extra_parents=extra_parents
        ),
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
    receipt_type = (
        ToolCallReceiptV04
        if type(request) is AgentRequestV04
        else ToolCallReceipt
    )
    return receipt_type.model_validate(
        sign_payload(
            "action-receipt",
            raw,
            sidecar_private_key,
            version=("0.4" if type(request) is AgentRequestV04 else "0.1"),
        )
    )


def _preflight_run_tests_receipts(
    context: AuthorizationContext,
    request: AgentRequest,
    arguments: RunTestsArguments,
    execution_facts: ProspectiveExecutionFacts,
    sidecar_private_key: Ed25519PrivateKey,
) -> None:
    episode = _run_tests_episode(context, request, arguments)
    if episode == "independent_verifier":
        if context.causal_state.latest_composition_trigger_id is None:
            raise HandlerCoordinationError(
                "independent verifier trigger is unavailable"
            )
        if (
            context.independent_failure_terminal
            or context.causal_state.independent_result_receipt_id is not None
        ):
            raise HandlerCoordinationError(
                "independent verifier episode is sealed"
            )
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
    agency_authorize: Callable[[], PolicyDecision] | None = None,
) -> ToolCallReceipt | None:
    """Finalize a previously RESERVED/STARTED_UNCONFIRMED run-tests (B).

    Reconciliation reconstructs the historical authorization prefix from the
    stored request truth instead of re-authorizing against the current
    profile, so a later revocation is not retroactive. On success it either
    publishes the stored receipt and clears the journal row, or clears an
    already-committed receipt and returns None. A protected caller recovering
    a legacy-unbound stored action still finalizes the truth but must not
    receive it as a protected result.
    """

    protected = agency_authorize is not None
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
    if type(stored.request) is AgentRequestV04:
        try:
            historical_manifest = load_historical_action_binding_manifest(
                ledger_path,
                work_order_digest=stored.request.work_order_digest,
                binding_manifest_id=(
                    stored.request.action_binding_manifest_id
                ),
                binding_manifest_digest=(
                    stored.request.action_binding_manifest_digest
                ),
                judgment_commitment_id=(
                    stored.request.judgment_commitment_id
                ),
                judgment_commitment_digest=(
                    stored.request.judgment_commitment_digest
                ),
                transaction_time=stored.reserved_at,
            )
            historical_decision = _authorize_bound_action_with_manifest(
                old_context,
                stored.request,
                _run_tests_arguments_from_contract(stored.contract),
                stored.execution_facts,
                historical_manifest,
            )
        except Exception as error:
            raise HandlerCoordinationError("RECOVERY_REQUIRED") from error
        if not historical_decision.allowed:
            raise HandlerCoordinationError("RECOVERY_REQUIRED")
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
    if protected and stored.agency_binding is None:
        raise HandlerCoordinationError("AGENCY_UNBOUND_RECOVERY")
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
    agency_authorize: Callable[[], PolicyDecision] | None = None,
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
                agency_authorize,
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
        if type(request) is AgentRequestV04:
            decision = _require_bound_action(
                path,
                context,
                request,
                request_arguments,
                execution_facts,
            )
        else:
            _require_bound_action(path, context, request, request_arguments)
            decision = authorize_tool_call(
                context,
                request,
                request_arguments,
                execution_facts,
            )
        if not decision.allowed:
            raise ToolCallDenied(decision)
        _enforce_agency_authorization(agency_authorize)
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
            agency_bound=(agency_authorize is not None),
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
        "protocol_version": (
            "0.4" if type(request) is AgentRequestV04 else "0.1"
        ),
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
    receipt_type = (
        RollbackReceiptV04
        if type(request) is AgentRequestV04
        else RollbackReceipt
    )
    return receipt_type.model_validate(
        sign_payload(
            "action-receipt",
            raw,
            sidecar_private_key,
            version=("0.4" if type(request) is AgentRequestV04 else "0.1"),
        )
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
    agency_authorize: Callable[[], PolicyDecision] | None = None,
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
        if type(request) is AgentRequestV04:
            decision = _require_bound_action(path, context, request, None)
        else:
            _require_bound_action(path, context, request, None)
            decision = validate_rollback(context, request)
        if not decision.allowed:
            raise ToolCallDenied(decision)
        _enforce_agency_authorization(agency_authorize)
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
    "produce_deny_receipt",
]


def build_docker_run_tests_driver(
    *,
    docker_binary: Path,
    image_reference: str,
    candidate_runtime_root: Path,
) -> repo_tools.DockerRunTestsExecutor:
    """Construct the production Docker run-tests executor (fail closed)."""
    if (
        not isinstance(docker_binary, Path)
        or not docker_binary.is_absolute()
        or not isinstance(candidate_runtime_root, Path)
        or not candidate_runtime_root.is_absolute()
        or type(image_reference) is not str
    ):
        raise HandlerCoordinationError("HANDLER_UNAVAILABLE")
    try:
        return repo_tools.DockerRunTestsExecutor(
            docker_binary=docker_binary,
            candidate_runtime_root=candidate_runtime_root,
            image_reference=image_reference,
        )
    except ValueError as error:
        raise HandlerCoordinationError("HANDLER_UNAVAILABLE") from error


def execute_run_tests_production(
    ledger_path: Path,
    *,
    evidence_root: Path,
    context: AuthorizationContext,
    request: AgentRequest,
    request_arguments: RunTestsArguments,
    execution_facts: ProspectiveExecutionFacts,
    sidecar_private_key: Ed25519PrivateKey,
    docker_binary: Path,
    image_reference: str,
    candidate_runtime_root: Path,
    clock: Callable[[], datetime],
) -> ToolCallReceipt:
    """Run one production test call with the real Docker executor."""
    if (
        not isinstance(docker_binary, Path)
        or not isinstance(candidate_runtime_root, Path)
        or type(image_reference) is not str
    ):
        raise HandlerCoordinationError("HANDLER_UNAVAILABLE")
    snapshot_request = repo_tools.CandidateExecutionSnapshotRequest(
        runtime_root=Path(candidate_runtime_root),
        workspace_id="c" * 64,
        source_artifact_sha256=(
            context.work_order.replay_profile.source_artifact_sha256
        ),
        expected_head_commit=request_arguments.candidate_commit,
        expected_workspace_manifest_digest=(
            request_arguments.workspace_manifest_digest
        ),
    )
    driver = build_docker_run_tests_driver(
        docker_binary=docker_binary,
        image_reference=image_reference,
        candidate_runtime_root=Path(candidate_runtime_root),
    )
    return execute_run_tests(
        ledger_path,
        evidence_root=evidence_root,
        context=context,
        request=request,
        request_arguments=request_arguments,
        execution_facts=execution_facts,
        candidate_snapshot_request=snapshot_request,
        sidecar_private_key=sidecar_private_key,
        execution_driver=driver,
        clock=clock,
    )


def make_repo_pipeline_read_handler(
    *,
    max_bytes: int = 1_048_576,
) -> Callable[
    [repo_tools.CandidateReadRequest], repo_tools.CandidateReadResult
]:
    """Build a production repo-read handler backed by the repo pipeline.

    The handler reads ``CandidateReadRequest.path`` under the candidate
    runtime root through the repo_pipeline reader (UTF-8 decode, size cap,
    permission guards) and constructs the exact ``RepoReadOutput`` with its
    content digest and the expected workspace-manifest binding.
    """

    def handler(
        command: repo_tools.CandidateReadRequest,
    ) -> repo_tools.CandidateReadResult:
        from openworkproof.repo_pipeline.errors import RepoPipelineError
        from openworkproof.repo_pipeline.reader import (
            read_text_file,
            sha256_bytes,
        )

        root = Path(command.runtime_root)
        path = root / command.path
        if not path.is_file():
            raise HandlerCoordinationError("REPO_READ_PATH_MISSING")
        try:
            content = read_text_file(path, max_bytes=max_bytes)
        except RepoPipelineError as error:
            raise HandlerCoordinationError("REPO_READ_READ_FAILED") from error
        raw = content.encode("utf-8")
        return repo_tools.CandidateReadResult(
            content=raw,
            output=repo_tools.RepoReadOutput(
                path=command.path,
                content_sha256=sha256_bytes(raw),
                size_bytes=len(raw),
                workspace_manifest_digest=(
                    command.expected_workspace_manifest_digest
                ),
            ),
        )

    return handler


def _repo_read_predicate_results(
    context: AuthorizationContext,
    request: AgentRequest,
    arguments: RepoReadArguments,
    output_digest: str,
) -> tuple:
    """Construct the exact predicate results for a repo-read receipt."""
    from openworkproof.predicates import (  # noqa: PLC0415
        EvaluationContext,
        evaluate_required_predicates,
    )
    from openworkproof.repo_tools import (  # noqa: PLC0415
        ResolutionManifest,
        ResolutionManifestEntry,
        resolution_manifest_digest,
    )

    selected = tuple(
        spec
        for spec in (
            context.work_order.preconditions
            + context.work_order.invariants
        )
        if "owp.repo_read" in spec.applies_to_tools
    )
    inputs: dict[str, object] = {}
    for spec in selected:
        if spec.name == "tool_allowed":
            inputs[spec.predicate_id] = {
                "actual_tool_name": "owp.repo_read"
            }
        elif spec.name == "quota_remaining":
            inputs[spec.predicate_id] = {
                "grant_id": request.grant_id,
                "metric": "tool_calls",
                "amount": 1,
                "grant_remaining_before": _remaining_tool_calls(
                    context, request.grant_id
                ),
                "ledger_prefix_digest": (
                    context.ledger_prefix.receipts[-1].digest
                ),
            }
        elif spec.name == "path_allowed":
            manifest = ResolutionManifest(
                schema_version="openworkproof-resolution-manifest/0.1",
                workspace_manifest_digest=(
                    context.replay_checkpoint.workspace_manifest_digest
                ),
                requested_paths=(arguments.path,),
                resolved_entries=(
                    ResolutionManifestEntry(
                        requested_path=arguments.path,
                        resolved_relative_path=arguments.path,
                    ),
                ),
            )
            inputs[spec.predicate_id] = {
                "requested_paths": [arguments.path],
                "resolved_entries": [
                    {
                        "requested_path": arguments.path,
                        "resolved_relative_path": arguments.path,
                    }
                ],
                "resolution_manifest_digest": resolution_manifest_digest(
                    manifest
                ),
            }
        else:
            raise HandlerCoordinationError(
                "repo-read predicate has no offline authority rule"
            )
    results = evaluate_required_predicates(
        selected,
        EvaluationContext(
            inputs=inputs,
            authoritative_inputs=inputs,
            authoritative_ledger_prefix_digests={
                request.grant_id: context.ledger_prefix.receipts[-1].digest,
            },
        ),
    )
    return tuple(
        result.model_dump(mode="json") for result in results
    )


def _repo_read_parents(
    context: AuthorizationContext,
    request: AgentRequest,
) -> tuple[str, ...]:
    """Causal parents for a repo-read receipt: grant issuance plus the active
    patch when one exists (mirrors the frozen causal replay rule)."""
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
    if issuance is None:
        raise HandlerCoordinationError("repo-read causal parents are unavailable")
    parents: dict[str, ActionReceiptEnvelope] = {
        issuance.receipt_id: issuance
    }
    active_patch = next(
        (
            receipt
            for receipt in receipts
            if receipt.receipt_id == context.active_patch_receipt_id
        ),
        None,
    )
    if active_patch is not None:
        parents[active_patch.receipt_id] = active_patch
    return tuple(
        receipt.receipt_id
        for receipt in sorted(
            parents.values(), key=lambda item: item.sequence
        )
    )


def _repo_read_command(
    context: AuthorizationContext,
    arguments: RepoReadArguments,
    candidate_runtime_root: Path,
) -> repo_tools.CandidateReadRequest:
    return repo_tools.CandidateReadRequest(
        runtime_root=Path(candidate_runtime_root),
        workspace_id="c" * 64,
        source_artifact_sha256=(
            context.work_order.replay_profile.source_artifact_sha256
        ),
        expected_head_commit=context.replay_checkpoint.head_commit,
        expected_workspace_manifest_digest=(
            context.replay_checkpoint.workspace_manifest_digest
        ),
        path=arguments.path,
    )


def _build_repo_read_receipt(
    context: AuthorizationContext,
    request: AgentRequest,
    arguments: RepoReadArguments,
    result: repo_tools.CandidateReadResult,
    sidecar_private_key: Ed25519PrivateKey,
    execution_facts: ProspectiveExecutionFacts,
) -> ToolCallReceipt:
    remaining_before = _remaining_tool_calls(context, request.grant_id)
    sidecar_key_id = key_id(sidecar_private_key.public_key())
    output_digest = _digest(result.output.model_dump(mode="json"))
    raw = {
        "protocol_version": (
            "0.4" if type(request) is AgentRequestV04 else "0.1"
        ),
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
        "event_type": "tool_call",
        "policy_decision": "allow",
        "policy_error_code": None,
        "execution_status": "succeeded",
        "execution_error_code": None,
        "quota_charge": {
            "grant_id": request.grant_id,
            "metric": "tool_calls",
            "amount": 1,
            "remaining_after": remaining_before - 1,
        },
        "state_before": context.current_state,
        "state_after": context.current_state,
        "parent_receipt_ids": list(_repo_read_parents(context, request)),
        "correlation_factors": {
            "model_id": request.model_id,
            "model_version": request.model_version,
            "prompt_template_digest": request.prompt_template_digest,
            "context_source_digest": request.context_source_digest,
            "toolchain_id": _digest(
                {
                    "domain": "openworkproof/toolchain/v0.1",
                    "tool_name": "owp.repo_read",
                    "tool_version": "0.1",
                }
            ),
            "execution_context_id": execution_facts.execution_context_id,
            "container_instance_id_digest": (
                execution_facts.container_instance_id_digest
            ),
            "controller_id": execution_facts.controller_id,
            "fixed_test_source_digest": None,
        },
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
        "tool_name": "owp.repo_read",
        "tool_version": "0.1",
        "request_arguments": arguments.model_dump(mode="json"),
        "arguments_digest": request.arguments_digest,
        "output_digest": output_digest,
        "predicate_results": list(
            _repo_read_predicate_results(
                context,
                request,
                arguments,
                output_digest,
            )
        ),
    }
    receipt_type = (
        ToolCallReceiptV04
        if type(request) is AgentRequestV04
        else ToolCallReceipt
    )
    return receipt_type.model_validate(
        sign_payload(
            "action-receipt",
            raw,
            sidecar_private_key,
            version=("0.4" if type(request) is AgentRequestV04 else "0.1"),
        )
    )


def _preflight_repo_read_receipts(
    context: AuthorizationContext,
    request: AgentRequest,
    arguments: RepoReadArguments,
    sidecar_private_key: Ed25519PrivateKey,
    execution_facts: ProspectiveExecutionFacts,
) -> None:
    import base64  # noqa: PLC0415

    entries = context.replay_checkpoint.workspace_manifest.entries
    decoded_paths = {
        base64.urlsafe_b64decode(
            (entry.path_bytes_b64url + "==").encode("ascii")
        ).decode("utf-8")
        for entry in entries
    }
    if arguments.path not in decoded_paths:
        raise HandlerCoordinationError("REPO_READ_PATH_DENIED")
    representative = repo_tools.CandidateReadResult(
        content=b"x" * 65_536,
        output=repo_tools.RepoReadOutput(
            path=arguments.path,
            content_sha256="0" * 64,
            size_bytes=65_536,
            workspace_manifest_digest=(
                context.replay_checkpoint.workspace_manifest_digest
            ),
        ),
    )
    if (
        len(
            rfc8785.dumps(
                _build_repo_read_receipt(
                    context,
                    request,
                    arguments,
                    representative,
                    sidecar_private_key,
                    execution_facts,
                ).model_dump(mode="json")
            )
        )
        > _MAX_RECEIPT_BYTES
    ):
        raise HandlerCoordinationError("BUNDLE_CAPACITY_EXCEEDED")


def _readback_repo_read_committed(
    ledger_path: Path,
    *,
    work_order,
    receipt: ToolCallReceipt,
) -> bool:
    try:
        connection = evidence.connect_ledger(ledger_path)
        try:
            current_work_order, receipts, _, _ = (
                evidence._replay_receipt_publication_ledger(connection)
            )
        finally:
            connection.close()
    except Exception:
        return False
    return (
        current_work_order == work_order
        and bool(receipts)
        and receipts[-1].receipt_id == receipt.receipt_id
        and receipts[-1] == receipt
    )


def execute_repo_read(
    ledger_path: Path,
    *,
    evidence_root: Path,
    context: AuthorizationContext,
    request: AgentRequest,
    request_arguments: RepoReadArguments,
    execution_facts: ProspectiveExecutionFacts,
    sidecar_private_key: Ed25519PrivateKey,
    candidate_runtime_root: Path,
    handler: Callable[[repo_tools.CandidateReadRequest], repo_tools.CandidateReadResult],
    clock: Callable[[], datetime],
    agency_authorize: Callable[[], PolicyDecision] | None = None,
) -> ToolCallReceipt:
    """Authorize, execute, sign, and commit one repo-read attempt."""
    if (
        not callable(handler)
        or not isinstance(candidate_runtime_root, Path)
        or not isinstance(request_arguments, RepoReadArguments)
    ):
        raise HandlerCoordinationError("HANDLER_UNAVAILABLE")
    arguments = request_arguments
    path = Path(ledger_path)
    root = Path(evidence_root)
    evidence.recover_evidence_publications(path, evidence_root=root)
    lock_descriptor = evidence._acquire_target_lock(path)
    primary_error: Exception | None = None
    receipt: ToolCallReceipt | None = None
    try:
        _ensure_handler_execution_schema(path, lock_descriptor)
        _recover_handler_executions(path, lock_descriptor)
        now = evidence._freeze_trusted_utc_second(clock())
        _require_current_context(
            path,
            root,
            context,
            now,
            lock_descriptor,
        )
        if type(request) is AgentRequestV04:
            decision = _require_bound_action(path, context, request, arguments)
        else:
            _require_bound_action(path, context, request, arguments)
            decision = authorize_tool_call(
                context,
                request,
                arguments,
                None,
            )
        if not decision.allowed:
            raise ToolCallDenied(decision)
        _enforce_agency_authorization(agency_authorize)
        _preflight_repo_read_receipts(
            context,
            request,
            arguments,
            sidecar_private_key,
            execution_facts,
        )
        command = _repo_read_command(context, arguments, candidate_runtime_root)
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
        if type(result) is not repo_tools.CandidateReadResult:
            raise HandlerCoordinationError("RECOVERY_REQUIRED")
        receipt = _build_repo_read_receipt(
            context,
            request,
            arguments,
            result,
            sidecar_private_key,
            execution_facts,
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


def produce_deny_receipt(
    ledger_path: Path,
    *,
    evidence_root: Path,
    context: AuthorizationContext,
    request: AgentRequest,
    arguments: object,
    execution_facts: ProspectiveExecutionFacts,
    sidecar_private_key: Ed25519PrivateKey,
    decision: PolicyDecision,
    clock: Callable[[], datetime],
) -> ToolCallReceipt:
    """Atomically record an authenticated same-state denial receipt.

    The policy layer already denied the tool call (for example
    ROLE_DENIED / CAPABILITY_DENIED / QUOTA_EXHAUSTED). This entry point
    records an immutable, zero-charge denial receipt so the rejection
    itself becomes auditable — without starting a handler, charging
    quota, or changing task state. The nonce is derived from a dedicated
    domain so it is globally unique and independent of the request nonce.

    It is an optional audit entry: callers that only need the denial
    error keep raising ToolCallDenied; callers that need a denial audit
    trail call this function before surfacing the error.
    """
    path = Path(ledger_path)
    root = Path(evidence_root)
    try:
        ToolRequestArguments.__class_getitem__  # noqa: B018 - type-alias marker
    except (AttributeError, TypeError):
        pass
    if not _is_tool_request_arguments(arguments):
        raise ValueError("deny receipt arguments must be a ToolRequestArguments")
    if not isinstance(decision, PolicyDecision) or decision.allowed:
        raise ValueError("deny receipt requires a non-allowed PolicyDecision")
    if (
        key_id(sidecar_private_key.public_key())
        != execution_facts.controller_id
    ):
        raise HandlerCoordinationError(
            "Sidecar signing key does not match execution controller"
        )
    evidence.recover_evidence_publications(path, evidence_root=root)
    lock_descriptor = evidence._acquire_target_lock(path)
    primary_error: Exception | None = None
    receipt: ToolCallReceipt | None = None
    try:
        _ensure_handler_execution_schema(path, lock_descriptor)
        now = evidence._freeze_trusted_utc_second(clock())
        _require_current_context(
            path,
            root,
            context,
            now,
            lock_descriptor,
        )
        state = context.current_state
        receipt_id = hashlib.sha256(
            rfc8785.dumps(
                {
                    "domain": "openworkproof/deny-receipt/v0.1",
                    "work_order_digest": context.work_order.digest,
                    "tool_name": request.tool_name,
                    "arguments_digest": request.arguments_digest,
                    "policy_error_code": decision.error_code,
                    "sequence_hint": len(context.ledger_prefix.receipts) + 1,
                }
            )
        ).hexdigest()
        raw = {
            "protocol_version": (
                "0.4" if type(request) is AgentRequestV04 else "0.1"
            ),
            "receipt_id": receipt_id,
            "work_order_digest": context.work_order.digest,
            "actor_type": "agent",
            "actor_id": request.actor_id,
            "actor_key_id": request.actor_key_id,
            "nested_claim_type": "agent-request",
            "nested_claim_digest": request.digest,
            "nested_claim": request.model_dump(mode="json"),
            "gateway_signer_key_id": key_id(sidecar_private_key.public_key()),
            "event_type": "tool_call",
            "policy_decision": "deny",
            "policy_error_code": decision.error_code,
            "execution_status": "denied",
            "execution_error_code": None,
            "quota_charge": None,
            "state_before": state,
            "state_after": state,
            "parent_receipt_ids": _causal_parents(context, request),
            "correlation_factors": {
                "model_id": request.model_id,
                "model_version": request.model_version,
                "prompt_template_digest": request.prompt_template_digest,
                "context_source_digest": request.context_source_digest,
                "toolchain_id": None,
                "execution_context_id": None,
                "container_instance_id_digest": None,
                "controller_id": execution_facts.controller_id,
                "fixed_test_source_digest": None,
            },
            "evidence_refs": [],
            "occurred_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "sequence": len(context.ledger_prefix.receipts) + 1,
            "nonce": request.nonce,
            "previous_receipt_digest": (
                context.ledger_prefix.receipts[-1].receipt_id
                if context.ledger_prefix.receipts
                else context.work_order.digest
            ),
            "grant_id": request.grant_id,
            "tool_name": request.tool_name,
            "tool_version": "0.1",
            "request_arguments": arguments.model_dump(mode="json"),
            "arguments_digest": request.arguments_digest,
            "output_digest": None,
            "predicate_results": [],
        }
        allowed_error_codes = (
            POLICY_ERROR_CODES_V04
            if type(request) is AgentRequestV04
            else POLICY_ERROR_CODES
        )
        if decision.error_code not in allowed_error_codes:
            # The binding gate can deny a legacy request with a v0.4-only
            # code (e.g. UNSIGNED_METADATA_REFERENCE) that the v0.1 receipt
            # Literal cannot carry. Fail loudly as a denial; never leak a
            # pydantic ValidationError or write a mis-typed receipt.
            raise ToolCallDenied(decision)
        receipt_type = (
            ToolCallReceiptV04
            if type(request) is AgentRequestV04
            else ToolCallReceipt
        )
        receipt = receipt_type.model_validate(
            sign_payload(
                "action-receipt",
                raw,
                sidecar_private_key,
                version=(
                    "0.4" if type(request) is AgentRequestV04 else "0.1"
                ),
            )
        )
        receipt.validate_against_work_order(context.work_order)
        connection = evidence.connect_ledger(path)
        try:
            connection.execute("BEGIN IMMEDIATE")
            try:
                connection.execute(
                    """
                    INSERT INTO receipts (
                        receipt_id,
                        work_order_digest,
                        nonce,
                        sequence,
                        previous_digest,
                        receipt_json
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        receipt.receipt_id,
                        context.work_order.digest,
                        request.nonce,
                        len(context.ledger_prefix.receipts) + 1,
                        (
                            context.ledger_prefix.receipts[-1].receipt_id
                            if context.ledger_prefix.receipts
                            else context.work_order.digest
                        ),
                        evidence._canonical_json(
                            receipt.model_dump(mode="json")
                        ),
                    ),
                )
                for parent_receipt_id in _causal_parents(
                    context, request
                ):
                    connection.execute(
                        """
                        INSERT INTO receipt_parents (
                            child_receipt_id,
                            parent_receipt_id
                        )
                        VALUES (?, ?)
                        """,
                        (receipt.receipt_id, parent_receipt_id),
                    )
                connection.execute("COMMIT")
            except Exception:
                connection.execute("ROLLBACK")
                raise
        finally:
            connection.close()
    except Exception as error:
        primary_error = error
    _, release_errors = evidence._release_target_lock(lock_descriptor)
    if primary_error is not None:
        if release_errors:
            raise HandlerCoordinationError(
                "deny receipt and lock release both failed"
            ) from primary_error
        raise primary_error
    if release_errors:
        raise HandlerCoordinationError(
            "deny receipt lock release failed"
        ) from release_errors[0]
    assert receipt is not None
    return receipt


def _is_tool_request_arguments(value: object) -> bool:
    """True when value is one of the registered ToolRequestArguments variants.

    ToolRequestArguments is a pydantic Union alias, so isinstance is not
    reliable; validate against the union adapter instead.
    """
    from pydantic import TypeAdapter  # noqa: PLC0415

    adapter = TypeAdapter(ToolRequestArguments)
    try:
        adapter.validate_python(value)
    except Exception:  # noqa: BLE001 - validation failure
        return False
    return True


def _committed_evidence_from_ledger(
    ledger_path: Path,
    evidence_root: Path,
    work_order: WorkOrder,
    receipts,
) -> tuple:
    """Rebuild the committed evidence tuple from the evidence root."""
    from openworkproof.policy import CommittedEvidence  # noqa: PLC0415

    connection = evidence.connect_ledger(ledger_path)
    try:
        groups = evidence._journal_publication_groups(connection)
    finally:
        connection.close()
    committed: list[CommittedEvidence] = []
    for group in groups:
        for publication in group.publications:
            if publication.state != "COMMITTED":
                continue
            artifact_path = Path(evidence_root) / publication.final_path
            try:
                payload = artifact_path.read_bytes()
            except OSError:
                continue
            committed.append(
                CommittedEvidence(
                    reference=publication.reference,
                    payload=payload,
                )
            )
    committed.sort(key=lambda item: item.reference.path.encode())
    return tuple(committed)


def _context_from_payload(
    ledger_path: Path,
    evidence_root: Path,
    payload: Mapping[str, object],
    now: datetime,
) -> AuthorizationContext:
    """Reconstruct an AuthorizationContext from a transport payload."""
    from openworkproof.policy import (
        AuthorizationLedgerPrefix,
        derive_authorization_context,
    )
    from openworkproof.repo_tools import (
        ReplayCheckpoint,
        WorkspaceManifest,
    )

    checkpoint_data = payload["checkpoint"]
    if type(checkpoint_data) is not dict:
        raise KeyError("checkpoint")
    manifest_data = checkpoint_data.get("workspace_manifest")
    from openworkproof.repo_tools import WorkspaceManifestEntry  # noqa: PLC0415

    manifest = WorkspaceManifest(
        schema_version=manifest_data["schema_version"],
        head_commit=manifest_data["head_commit"],
        entries=tuple(
            WorkspaceManifestEntry(
                path_bytes_b64url=entry["path_bytes_b64url"],
                type=entry["type"],
                posix_mode=entry["posix_mode"],
                size_bytes=entry["size_bytes"],
                sha256=entry["sha256"],
                symlink_target_b64url=entry["symlink_target_b64url"],
            )
            for entry in manifest_data["entries"]
        ),
    )
    checkpoint = ReplayCheckpoint(
        files=(),
        head_commit=checkpoint_data["head_commit"],
        workspace_manifest=manifest,
        workspace_manifest_digest=checkpoint_data[
            "workspace_manifest_digest"
        ],
        verified_test_results=(),
    )
    connection = evidence.connect_ledger(ledger_path)
    try:
        work_order, receipts, grants, _ = (
            evidence._replay_receipt_publication_ledger(connection)
        )
        attempts = evidence._validated_grant_attempts(
            connection, work_order, receipts
        )
    finally:
        connection.close()
    prefix = AuthorizationLedgerPrefix(
        effective_grants=tuple(
            sorted(grants.values(), key=lambda item: item.grant_id)
        ),
        grant_attempts=tuple(
            sorted(attempts.values(), key=lambda item: item.digest)
        ),
        receipts=receipts,
    )
    committed = _committed_evidence_from_ledger(
        ledger_path, evidence_root, work_order, receipts
    )
    return derive_authorization_context(
        work_order,
        prefix,
        committed,
        checkpoint,
        now,
    )


def _load_sidecar_key(key_hex: str) -> Ed25519PrivateKey:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )

    raw = bytes.fromhex(key_hex)
    if len(raw) != 32:
        raise HandlerCoordinationError("SIDECAR_KEY_INVALID")
    return Ed25519PrivateKey.from_private_bytes(raw)


def _run_tests_from_payload(
    ledger_path: str | Path,
    payload: Mapping[str, object],
) -> ToolCallReceipt:
    """Forward one run-tests execution from a transport payload."""
    from openworkproof.models import RunTestsArguments, parse_agent_request
    from openworkproof.policy import ProspectiveExecutionFacts

    path = Path(ledger_path)
    now = evidence._freeze_trusted_utc_second(
        datetime.fromisoformat(str(payload["now"]))
    )
    context = _context_from_payload(
        path,
        Path(str(payload["evidence_root"])),
        payload,
        now,
    )
    request = parse_agent_request(payload["request"])
    arguments = RunTestsArguments.model_validate(payload["arguments"])
    facts = ProspectiveExecutionFacts(
        execution_context_id=payload["facts"]["execution_context_id"],
        container_instance_id_digest=payload["facts"][
            "container_instance_id_digest"
        ],
        controller_id=payload["facts"]["controller_id"],
    )
    sidecar_key = _load_sidecar_key(str(payload["sidecar_key_hex"]))
    return execute_run_tests_production(
        path,
        evidence_root=Path(str(payload["evidence_root"])),
        context=context,
        request=request,
        request_arguments=arguments,
        execution_facts=facts,
        sidecar_private_key=sidecar_key,
        docker_binary=Path(str(payload["docker_binary"])),
        image_reference=str(payload["image_reference"]),
        candidate_runtime_root=Path(str(payload["candidate_runtime_root"])),
        clock=lambda: now,
    )


def _repo_read_from_payload(
    ledger_path: str | Path,
    payload: Mapping[str, object],
) -> ToolCallReceipt:
    """Forward one repo-read execution from a transport payload."""
    from openworkproof.models import RepoReadArguments, parse_agent_request

    path = Path(ledger_path)
    now = evidence._freeze_trusted_utc_second(
        datetime.fromisoformat(str(payload["now"]))
    )
    context = _context_from_payload(
        path,
        Path(str(payload["evidence_root"])),
        payload,
        now,
    )
    request = parse_agent_request(payload["request"])
    arguments = RepoReadArguments.model_validate(payload["arguments"])
    facts = ProspectiveExecutionFacts(
        execution_context_id=payload["facts"]["execution_context_id"],
        container_instance_id_digest=payload["facts"][
            "container_instance_id_digest"
        ],
        controller_id=payload["facts"]["controller_id"],
    )
    sidecar_key = _load_sidecar_key(str(payload["sidecar_key_hex"]))
    return execute_repo_read(
        path,
        evidence_root=Path(str(payload["evidence_root"])),
        context=context,
        request=request,
        request_arguments=arguments,
        execution_facts=facts,
        sidecar_private_key=sidecar_key,
        candidate_runtime_root=Path(str(payload["candidate_runtime_root"])),
        handler=make_repo_pipeline_read_handler(),
        clock=lambda: now,
    )
