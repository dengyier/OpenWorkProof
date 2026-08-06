"""Deterministic proof composition and independent acceptance authority.

Package-internal module implementing the closed aggregate digests, the
CompositionReport construction authority, and the compose/request/prepare/
commit acceptance transactions from the design at
docs/superpowers/specs/2026-08-06-openworkproof-acceptance-transaction-design.md.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import secrets
import sqlite3
from typing import Literal

import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import openworkproof.evidence as evidence
from openworkproof.composition import replay_authorization_causality
from openworkproof.models import (
    AcceptanceReceipt,
    ActionReceiptEnvelope,
    AgentRequest,
    ApprovalRequestedReceipt,
    ComposeProofArguments,
    CompositionReport,
    CorrelationReference,
    EvidenceRef,
    FinalArtifact,
    FrozenDict,
    GrantIssuedReceipt,
    IndependenceAssessment,
    PredicateResult,
    SystemEventReceipt,
    ToolCallReceipt,
)
from openworkproof.policy import AuthorizationContext
from openworkproof.runtime_context import RuntimeContextError, require_current_context
from openworkproof.signing import key_id, sign_payload


class AcceptanceTransactionError(RuntimeError):
    """Composition or acceptance failed before proven commit."""


class AcceptanceCommittedError(AcceptanceTransactionError):
    """The exact result committed but a later operation failed."""

    def __init__(self, message: str, committed: object) -> None:
        super().__init__(message)
        self.committed = committed


class AcceptanceCommitIndeterminateError(AcceptanceTransactionError):
    """Readback could prove neither rollback nor the exact commit."""


def causal_graph_root(
    receipts: tuple[ActionReceiptEnvelope, ...],
) -> str:
    ordered = tuple(sorted(receipts, key=lambda item: item.sequence))
    if (
        ordered != receipts
        or len({item.receipt_id for item in ordered}) != len(ordered)
    ):
        raise AcceptanceTransactionError("receipt prefix is not canonical")
    nodes = [
        {
            "receipt_id": item.receipt_id,
            "receipt_digest": item.digest,
            "parent_receipt_ids": list(item.parent_receipt_ids),
        }
        for item in ordered
    ]
    return hashlib.sha256(
        rfc8785.dumps(
            {
                "domain": "openworkproof/causal-graph-root/0.1",
                "nodes": nodes,
            }
        )
    ).hexdigest()


def evidence_snapshot_digest(
    refs: tuple[EvidenceRef, ...],
) -> str:
    ordered = tuple(sorted(refs, key=lambda item: item.path.encode("utf-8")))
    if ordered != refs or len({item.path for item in ordered}) != len(ordered):
        raise AcceptanceTransactionError("evidence snapshot is not canonical")
    return hashlib.sha256(
        rfc8785.dumps(
            {
                "domain": "openworkproof/evidence-snapshot/0.1",
                "refs": [item.model_dump(mode="json") for item in ordered],
            }
        )
    ).hexdigest()


def composition_report_digest(report: CompositionReport) -> str:
    return hashlib.sha256(
        rfc8785.dumps(report.model_dump(mode="json"))
    ).hexdigest()


def acceptance_id(
    *,
    work_order_digest: str,
    request_receipt_id: str,
    request_receipt_digest: str,
    report_digest: str,
    evidence_snapshot: str,
) -> str:
    return hashlib.sha256(
        rfc8785.dumps(
            {
                "domain": "openworkproof/acceptance-id/0.1",
                "work_order_digest": work_order_digest,
                "request_receipt_id": request_receipt_id,
                "request_receipt_digest": request_receipt_digest,
                "composition_report_digest": report_digest,
                "evidence_snapshot_digest": evidence_snapshot,
            }
        )
    ).hexdigest()


@dataclass(frozen=True, slots=True)
class CompositionTransactionResult:
    initiator_receipt: ToolCallReceipt
    report: CompositionReport
    trigger_receipt: SystemEventReceipt


@dataclass(frozen=True, slots=True)
class AcceptanceSigningDraft:
    signing_domain: Literal["acceptance-receipt"]
    acceptance_id: str
    payload: FrozenDict
    canonical_payload: bytes


def _freeze_second(clock_value: datetime) -> datetime:
    return evidence._freeze_trusted_utc_second(clock_value)


def _role_for(
    receipt: ActionReceiptEnvelope,
    work_order,
) -> str | None:
    for binding in work_order.key_bindings:
        if (
            binding.subject_id == receipt.actor_id
            and binding.key_id == receipt.actor_key_id
        ):
            return binding.role
    return None


def _derive_composition_report(
    context: AuthorizationContext,
    initiator: ToolCallReceipt,
    prefix: tuple[ActionReceiptEnvelope, ...],
    now: datetime,
) -> CompositionReport:
    """Derive the canonical report over the prefix ending at initiator."""
    work_order = context.work_order
    replay_authorization_causality(work_order, prefix)
    coverage: dict[str, bool] = {}
    for dimension in work_order.required_evidence_dimensions:
        coverage[dimension] = False
    # The authority dimension is proven by the successful causal replay of
    # the signed authorization history itself; it needs no artifact file.
    coverage["authority"] = True
    for receipt in prefix:
        for reference in receipt.evidence_refs:
            relative = reference.path.removeprefix("evidence/")
            for artifact in work_order.evidence_policy.artifacts:
                if artifact.path != relative:
                    continue
                coverage[artifact.evidence_dimension] = True
    missing_dimensions = [
        dimension
        for dimension in work_order.required_evidence_dimensions
        if not coverage[dimension]
    ]
    complete = (
        not missing_dimensions
        and context.current_state in {"locally_verified", "proof_ready"}
    )
    unresolved_failures = (
        ()
        if complete
        else (
            {
                "code": "MISSING_EVIDENCE_DIMENSION",
                "subject_ref": context.work_order.digest,
            },
        )
    )
    developer_ref: CorrelationReference | None = None
    verifier_ref: CorrelationReference | None = None
    test_refs: list[EvidenceRef] = []
    for receipt in prefix:
        if not isinstance(receipt, ToolCallReceipt) or receipt.correlation_factors is None:
            continue
        role = _role_for(receipt, work_order)
        if role == "Developer" and developer_ref is None:
            developer_ref = CorrelationReference(
                receipt_digest=receipt.digest,
                factors=receipt.correlation_factors.model_dump(mode="json"),
            )
        elif role == "Verifier" and verifier_ref is None:
            verifier_ref = CorrelationReference(
                receipt_digest=receipt.digest,
                factors=receipt.correlation_factors.model_dump(mode="json"),
            )
            test_refs.extend(receipt.evidence_refs)
    if developer_ref is None:
        raise AcceptanceTransactionError(
            "composition requires a developer execution reference"
        )
    if verifier_ref is None:
        raise AcceptanceTransactionError(
            "composition requires a verifier execution reference"
        )
    shared = _shared_factor_codes(developer_ref.factors, verifier_ref.factors)
    independence = IndependenceAssessment(
        policy=work_order.independence_policy,
        developer_reference=developer_ref.model_dump(mode="json"),
        verifier_reference=verifier_ref.model_dump(mode="json"),
        shared_factors=shared,
        satisfied=complete,
    )
    warnings = _shared_factor_warnings(
        developer_ref.factors,
        verifier_ref.factors,
        shared,
    )
    artifact_digests = _sorted_unique_evidence_refs(prefix)
    checkpoint = context.replay_checkpoint
    active_patch_id = context.active_patch_receipt_id
    if active_patch_id is None:
        raise AcceptanceTransactionError(
            "composition requires a committed active patch"
        )
    receipt_digests = tuple(receipt.digest for receipt in prefix)
    postconditions = _evaluate_postconditions(context)
    all_passed = bool(postconditions) and all(
        result.passed for result in postconditions
    )
    complete = complete and all_passed
    verifier_conclusion = "proof_ready" if complete else "evidence_incomplete"
    unresolved = unresolved_failures
    if not complete and not unresolved:
        unresolved = (
            {
                "code": "GLOBAL_POSTCONDITION_FAILED",
                "subject_ref": work_order.digest,
            },
        )
    return CompositionReport(
        schema_version="openworkproof-composition-report/0.1",
        work_order_digest=work_order.digest,
        initiator_receipt_id=initiator.receipt_id,
        initiator_receipt_digest=initiator.digest,
        final_artifact=FinalArtifact(
            active_patch_receipt_digest=active_patch_id,
            candidate_commit=checkpoint.head_commit,
            workspace_manifest_digest=checkpoint.workspace_manifest_digest,
        ).model_dump(mode="json"),
        artifact_digests=tuple(
            item.model_dump(mode="json") for item in artifact_digests
        ),
        evidence_snapshot_digest=evidence_snapshot_digest(artifact_digests),
        receipt_digests=receipt_digests,
        causal_graph_root=causal_graph_root(prefix),
        causal_complete=complete,
        evidence_coverage=FrozenDict(coverage),
        independence_assessment=independence.model_dump(mode="json"),
        test_evidence_refs=tuple(
            item.model_dump(mode="json")
            for item in _sorted_unique_evidence_refs_for_test(prefix)
        ),
        unresolved_failures=unresolved,
        warnings=warnings,
        global_postconditions=tuple(
            item.model_dump(mode="json") for item in postconditions
        ),
        global_postconditions_satisfied=all_passed,
        verifier_conclusion=verifier_conclusion,
        composed_at=now.strftime("%Y-%m-%dT%H:%M:%SZ"),
    )


def _shared_factor_codes(developer, verifier) -> tuple[str, ...]:
    shared = []
    comparisons = (
        (
            "model",
            (developer.model_id, developer.model_version)
            == (verifier.model_id, verifier.model_version),
        ),
        (
            "prompt_template",
            developer.prompt_template_digest == verifier.prompt_template_digest,
        ),
        (
            "context_source",
            developer.context_source_digest == verifier.context_source_digest,
        ),
        (
            "toolchain",
            developer.toolchain_id is not None
            and developer.toolchain_id == verifier.toolchain_id,
        ),
        (
            "execution_context",
            developer.execution_context_id is not None
            and developer.container_instance_id_digest is not None
            and (developer.execution_context_id, developer.container_instance_id_digest)
            == (
                verifier.execution_context_id,
                verifier.container_instance_id_digest,
            ),
        ),
        (
            "controller",
            developer.controller_id == verifier.controller_id,
        ),
        (
            "test_source",
            developer.fixed_test_source_digest is not None
            and developer.fixed_test_source_digest == verifier.fixed_test_source_digest,
        ),
    )
    for name, shared_value in comparisons:
        if shared_value:
            shared.append(name)
    return tuple(shared)


_WARNING_CODE_BY_FACTOR = {
    "model": "SHARED_MODEL",
    "prompt_template": "SHARED_PROMPT_TEMPLATE",
    "context_source": "SHARED_CONTEXT_SOURCE",
    "toolchain": "SHARED_TOOLCHAIN",
    "execution_context": "SHARED_EXECUTION_CONTEXT",
    "controller": "SHARED_CONTROLLER",
    "test_source": "SHARED_TEST_SOURCE",
}


def _shared_factor_value(developer, verifier, factor: str) -> object:
    if factor == "model":
        return {
            "model_id": developer.model_id,
            "model_version": developer.model_version,
        }
    if factor == "execution_context":
        return {
            "execution_context_id": developer.execution_context_id,
            "container_instance_id_digest": (
                developer.container_instance_id_digest
            ),
        }
    if factor == "prompt_template":
        return developer.prompt_template_digest
    if factor == "context_source":
        return developer.context_source_digest
    if factor == "toolchain":
        return developer.toolchain_id
    if factor == "controller":
        return developer.controller_id
    if factor == "test_source":
        return developer.fixed_test_source_digest
    raise AssertionError(f"unknown shared factor: {factor}")


def _shared_factor_warnings(
    developer,
    verifier,
    shared: tuple[str, ...],
) -> tuple[dict, ...]:
    return tuple(
        sorted(
            (
                {
                    "code": _WARNING_CODE_BY_FACTOR[factor],
                    "subject_ref": hashlib.sha256(
                        rfc8785.dumps(
                            {
                                "domain": "openworkproof/shared-factor-ref/v0.1",
                                "factor": factor,
                                "value": _shared_factor_value(
                                    developer, verifier, factor
                                ),
                            }
                        )
                    ).hexdigest(),
                }
                for factor in shared
            ),
            key=lambda item: (
                item["code"].encode("utf-8"),
                item["subject_ref"].encode("utf-8"),
            ),
        )
    )


def _sorted_unique_evidence_refs(
    prefix: tuple[ActionReceiptEnvelope, ...],
) -> tuple[EvidenceRef, ...]:
    by_path: dict[str, EvidenceRef] = {}
    for receipt in prefix:
        for reference in receipt.evidence_refs:
            by_path[reference.path] = reference
    return tuple(
        sorted(by_path.values(), key=lambda item: item.path.encode("utf-8"))
    )


def _sorted_unique_evidence_refs_for_test(
    prefix: tuple[ActionReceiptEnvelope, ...],
) -> tuple[EvidenceRef, ...]:
    refs = [
        reference
        for receipt in prefix
        for reference in receipt.evidence_refs
        if reference.path.startswith("evidence/verifier-result/")
    ]
    return tuple(sorted(refs, key=lambda item: item.path.encode("utf-8")))


def _evaluate_postconditions(
    context: AuthorizationContext,
) -> tuple[PredicateResult, ...]:
    from openworkproof.models import TestsPassedPredicateInput  # noqa: PLC0415
    from openworkproof.predicates import EvaluationContext, evaluate_required_predicates  # noqa: PLC0415

    inputs: dict[str, dict] = {}
    results = context.replay_checkpoint.verified_test_results
    for spec in context.work_order.postconditions:
        if spec.name != "tests_passed":
            continue
        verifier_results = tuple(
            result for result in results if result.test_mode == "verifier"
        )
        latest = verifier_results[-1] if verifier_results else None
        arguments = spec.arguments
        evidence_digest = None
        if latest is not None:
            evidence_digest = hashlib.sha256(
                rfc8785.dumps(latest.model_dump(mode="json"))
            ).hexdigest()
        inputs[spec.predicate_id] = TestsPassedPredicateInput(
            test_mode=arguments["test_mode"],
            command_digest=arguments["command_digest"],
            expected_exit_code=arguments["expected_exit_code"],
            actual_exit_code=(
                latest.actual_exit_code if latest is not None else None
            ),
            test_evidence_digest=evidence_digest,
            source_commit=(
                latest.source_commit
                if latest is not None
                else context.work_order.source_commit
            ),
            candidate_commit=(
                latest.candidate_commit
                if latest is not None
                else context.replay_checkpoint.head_commit
            ),
            workspace_manifest_digest=(
                latest.workspace_manifest_digest
                if latest is not None
                else context.replay_checkpoint.workspace_manifest_digest
            ),
            container_image_digest=(
                latest.container_image_digest
                if latest is not None
                else context.work_order.test_profiles[-1].container_image_digest
            ),
            fixed_test_source_digest=arguments["fixed_test_source_digest"],
        ).model_dump(mode="json")
    evaluation = EvaluationContext(inputs=inputs)
    return evaluate_required_predicates(
        context.work_order.postconditions,
        evaluation,
    )


def _compose_causal_parents(
    context: AuthorizationContext,
    prefix: tuple[ActionReceiptEnvelope, ...],
    grant_id: str,
) -> tuple[str, ...]:
    by_id = {receipt.receipt_id: receipt for receipt in prefix}
    parents: dict[str, ActionReceiptEnvelope] = {}
    issuance = next(
        (
            receipt
            for receipt in prefix
            if isinstance(receipt, GrantIssuedReceipt)
            and receipt.policy_decision == "allow"
            and receipt.issued_grant_id == grant_id
        ),
        None,
    )
    if issuance is None:
        raise AcceptanceTransactionError(
            "compose grant issuance is unavailable"
        )
    parents[issuance.receipt_id] = issuance
    active_patch_id = context.active_patch_receipt_id
    if active_patch_id is not None and active_patch_id in by_id:
        parents[active_patch_id] = by_id[active_patch_id]
    passing = [
        receipt
        for receipt in prefix
        if isinstance(receipt, ToolCallReceipt)
        and receipt.tool_name == "owp.run_tests"
        and receipt.policy_decision == "allow"
        and receipt.execution_status == "succeeded"
    ]
    if passing:
        latest = passing[-1]
        parents[latest.receipt_id] = latest
    return tuple(
        receipt.receipt_id
        for receipt in sorted(
            parents.values(),
            key=lambda item: item.sequence,
        )
    )


def _build_compose_receipt(
    context: AuthorizationContext,
    request: AgentRequest,
    arguments: ComposeProofArguments,
    sidecar_private_key: Ed25519PrivateKey,
    *,
    sequence: int,
    previous_digest: str,
) -> ToolCallReceipt:
    from openworkproof.policy import authorize_tool_call  # noqa: PLC0415

    decision = authorize_tool_call(
        context,
        request,
        arguments,
    )
    if not decision.allowed:
        raise AcceptanceTransactionError(
            decision.error_code or "compose proof was denied"
        )

    sidecar_key_id = key_id(sidecar_private_key.public_key())
    remaining_before = _remaining_tool_calls(context, request.grant_id)
    receipt_id = hashlib.sha256(
        rfc8785.dumps(
            {
                "domain": "openworkproof/receipt-id/v0.1",
                "request_digest": request.digest,
                "entropy": secrets.token_hex(32),
            }
        )
    ).hexdigest()
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
        "parent_receipt_ids": list(
            _compose_causal_parents(
                context,
                context.ledger_prefix.receipts,
                request.grant_id,
            )
        ),
        "correlation_factors": {
            "model_id": request.model_id,
            "model_version": request.model_version,
            "prompt_template_digest": request.prompt_template_digest,
            "context_source_digest": request.context_source_digest,
            "toolchain_id": None,
            "execution_context_id": None,
            "container_instance_id_digest": None,
            "controller_id": sidecar_key_id,
            "fixed_test_source_digest": None,
        },
        "evidence_refs": [],
        "occurred_at": context.transaction_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "sequence": sequence,
        "nonce": request.nonce,
        "previous_receipt_digest": previous_digest,
        "grant_id": request.grant_id,
        "tool_name": "owp.compose_proof",
        "tool_version": "0.1",
        "request_arguments": arguments.model_dump(mode="json"),
        "arguments_digest": request.arguments_digest,
        "output_digest": hashlib.sha256(
            rfc8785.dumps({"status": "composition_request_accepted"})
        ).hexdigest(),
        "predicate_results": [],
    }
    return evidence.ACTION_RECEIPT_ADAPTER.validate_python(
        sign_payload("action-receipt", raw, sidecar_private_key)
    )


def _remaining_tool_calls(context: AuthorizationContext, grant_id: str) -> int:
    for candidate_grant_id, metric, remaining in context.replay_state.balances:
        if candidate_grant_id == grant_id and metric == "tool_calls":
            return remaining
    raise AcceptanceTransactionError("grant quota is unavailable")


def _build_proof_composed_receipt(
    context: AuthorizationContext,
    initiator: ToolCallReceipt,
    report: CompositionReport,
    sidecar_private_key: Ed25519PrivateKey,
    *,
    sequence: int,
    previous_digest: str,
) -> SystemEventReceipt:
    sidecar_key_id = key_id(sidecar_private_key.public_key())
    arguments = initiator.request_arguments
    if not isinstance(arguments, ComposeProofArguments):
        raise AcceptanceTransactionError(
            "compose initiator arguments are unavailable"
        )
    cause = {
        "initiator_receipt_digest": initiator.digest,
        "composition_report_digest": composition_report_digest(report),
        "state_version_before": arguments.expected_state_version,
    }
    input_digest = hashlib.sha256(
        rfc8785.dumps(
            {
                "domain": "openworkproof/system-event-input/v0.1",
                "event_name": "proof_composed",
                "work_order_digest": context.work_order.digest,
                "cause": cause,
            }
        )
    ).hexdigest()
    receipt_id = hashlib.sha256(
        rfc8785.dumps(
            {
                "domain": "openworkproof/receipt-id/v0.1",
                "request_digest": initiator.digest,
                "entropy": secrets.token_hex(32),
            }
        )
    ).hexdigest()
    raw = {
        "protocol_version": "0.1",
        "receipt_id": receipt_id,
        "work_order_digest": context.work_order.digest,
        "gateway_signer_key_id": sidecar_key_id,
        "event_type": "system_event",
        "policy_decision": "not_applicable",
        "policy_error_code": None,
        "execution_status": "succeeded",
        "execution_error_code": None,
        "state_before": initiator.state_after,
        "state_after": (
            "proof_ready"
            if report.verifier_conclusion == "proof_ready"
            else "evidence_incomplete"
        ),
        "parent_receipt_ids": [initiator.receipt_id],
        "correlation_factors": None,
        "evidence_refs": [],
        "occurred_at": context.transaction_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "sequence": sequence,
        "nonce": hashlib.sha256(
            rfc8785.dumps(
                {
                    "domain": "openworkproof/system-event-nonce/v0.1",
                    "receipt_id": receipt_id,
                }
            )
        ).hexdigest(),
        "previous_receipt_digest": previous_digest,
        "actor_type": "sidecar",
        "actor_id": "sidecar",
        "actor_key_id": sidecar_key_id,
        "nested_claim_type": "sidecar-event",
        "nested_claim_digest": input_digest,
        "nested_claim": {
            "claim_type": "sidecar-event",
            "work_order_digest": context.work_order.digest,
            "event_name": "proof_composed",
            "cause": cause,
            "input_digest": input_digest,
            "occurred_at": context.transaction_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        },
        "system_event_name": "proof_composed",
        "cause": cause,
        "input_digest": input_digest,
        "error_code": None,
        "quota_charge": None,
    }
    return evidence.ACTION_RECEIPT_ADAPTER.validate_python(
        sign_payload("action-receipt", raw, sidecar_private_key)
    )


def _insert_compose_rows(
    connection: sqlite3.Connection,
    *,
    work_order,
    initiator: ToolCallReceipt,
    trigger: SystemEventReceipt,
    report: CompositionReport,
    current_state: str,
    current_version: int,
) -> None:
    for receipt in (initiator, trigger):
        connection.execute(
            """
            INSERT INTO receipts (
                receipt_id, work_order_digest, nonce, sequence,
                previous_digest, receipt_json
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                receipt.receipt_id,
                work_order.digest,
                receipt.nonce,
                receipt.sequence,
                receipt.previous_receipt_digest,
                evidence._canonical_json(receipt.model_dump(mode="json")),
            ),
        )
        for parent_id in receipt.parent_receipt_ids:
            connection.execute(
                """
                INSERT INTO receipt_parents (child_receipt_id, parent_receipt_id)
                VALUES (?, ?)
                """,
                (receipt.receipt_id, parent_id),
            )
    charge = initiator.quota_charge
    if charge is None:
        raise AcceptanceTransactionError("compose initiator must charge quota")
    connection.execute(
        """
        INSERT INTO grant_events (
            event_id, receipt_id, grant_id, event_type, metric, amount
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            hashlib.sha256(
                f"grant-event:{initiator.receipt_id}".encode("ascii")
            ).hexdigest(),
            initiator.receipt_id,
            charge.grant_id,
            initiator.event_type,
            charge.metric,
            charge.amount,
        ),
    )
    connection.execute(
        """
        INSERT INTO composition_reports (
            report_digest, work_order_digest, initiator_receipt_id,
            initiator_receipt_digest, source_state_version, report_json
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            composition_report_digest(report),
            work_order.digest,
            initiator.receipt_id,
            initiator.digest,
            current_version,
            evidence._canonical_json(report.model_dump(mode="json")),
        ),
    )
    state_update = connection.execute(
        """
        UPDATE work_order_state
        SET current_state = ?, version = version + 1
        WHERE singleton = 1
          AND work_order_digest = ?
          AND current_state = ?
          AND version = ?
        """,
        (
            trigger.state_after,
            work_order.digest,
            current_state,
            current_version,
        ),
    )
    sequence_update = connection.execute(
        """
        UPDATE sequence_counter
        SET next_sequence = next_sequence + 1
        WHERE singleton = 1 AND next_sequence = ?
        """,
        (initiator.sequence,),
    )
    trigger_sequence_update = connection.execute(
        """
        UPDATE sequence_counter
        SET next_sequence = next_sequence + 1
        WHERE singleton = 1 AND next_sequence = ?
        """,
        (trigger.sequence,),
    )
    if (
        state_update.rowcount != 1
        or sequence_update.rowcount != 1
        or trigger_sequence_update.rowcount != 1
    ):
        raise AcceptanceTransactionError(
            "composition counters could not be advanced"
        )


def compose_proof_transaction(
    ledger_path: Path,
    *,
    evidence_root: Path,
    context: AuthorizationContext,
    request: AgentRequest,
    sidecar_private_key: Ed25519PrivateKey,
    clock: Callable[[], datetime],
) -> CompositionTransactionResult:
    """Atomically commit one Manager compose proof and its report."""
    from openworkproof.models import request_arguments_digest  # noqa: PLC0415

    path = Path(ledger_path)
    if not path.is_file():
        raise AcceptanceTransactionError("composition ledger is unavailable")
    lock_descriptor: int | None = None
    owns_lock = False
    connection: sqlite3.Connection | None = None
    try:
        lock_descriptor, owns_lock = evidence._borrow_or_acquire_target_lock(
            path, None
        )
        now = _freeze_second(clock())
        if context.transaction_time != now:
            raise AcceptanceTransactionError(
                "authorization context time is stale"
            )
        require_current_context(
            path,
            evidence_root,
            context,
            now,
            lock_descriptor,
        )
        if request.tool_name != "owp.compose_proof":
            raise AcceptanceTransactionError("compose request tool is invalid")
        expected = ComposeProofArguments(
            expected_state_version=len(context.ledger_prefix.receipts),
            previous_report_digest=(
                None if context.current_state == "locally_verified" else None
            ),
        )
        if request.arguments_digest != request_arguments_digest(
            "owp.compose_proof", expected
        ):
            raise AcceptanceTransactionError(
                "compose request arguments do not match current context"
            )
        prefix_len = len(context.ledger_prefix.receipts)
        initiator = _build_compose_receipt(
            context,
            request,
            expected,
            sidecar_private_key,
            sequence=prefix_len + 1,
            previous_digest=(
                context.ledger_prefix.receipts[-1].digest
                if context.ledger_prefix.receipts
                else None
            ),
        )
        prefix = tuple(context.ledger_prefix.receipts) + (initiator,)
        report = _derive_composition_report(context, initiator, prefix, now)
        trigger = _build_proof_composed_receipt(
            context,
            initiator,
            report,
            sidecar_private_key,
            sequence=prefix_len + 2,
            previous_digest=initiator.digest,
        )
        connection = evidence.connect_ledger(path)
        connection.execute("BEGIN IMMEDIATE")
        work_order, receipts, _, _ = (
            evidence._replay_receipt_publication_ledger(connection)
        )
        state_row = connection.execute(
            "SELECT current_state, version FROM work_order_state WHERE singleton = 1"
        ).fetchone()
        expected_version = evidence._derive_protocol_transaction_version(
            action_receipts=receipts,
            acceptance_receipts=(),
        )
        if (
            work_order != context.work_order
            or len(receipts) != prefix_len
            or state_row != (context.current_state, expected_version)
        ):
            raise AcceptanceTransactionError(
                "composition ledger changed under the target lock"
            )
        _insert_compose_rows(
            connection,
            work_order=work_order,
            initiator=initiator,
            trigger=trigger,
            report=report,
            current_state=context.current_state,
            current_version=state_row[1],
        )
        connection.execute("COMMIT")
        return CompositionTransactionResult(
            initiator_receipt=initiator,
            report=report,
            trigger_receipt=trigger,
        )
    except (RuntimeContextError, AcceptanceTransactionError) as error:
        rollback_error = evidence._best_effort_rollback(connection)
        if rollback_error is not None:
            raise AcceptanceTransactionError(
                "composition rollback failed"
            ) from rollback_error
        raise
    except Exception as error:
        rollback_error = evidence._best_effort_rollback(connection)
        if rollback_error is not None:
            raise AcceptanceCommitIndeterminateError(
                "composition rollback failed"
            ) from rollback_error
        raise
    finally:
        close_error = evidence._best_effort_close(connection)
        if close_error is not None:
            raise AcceptanceCommitIndeterminateError(
                "composition connection close failed"
            ) from close_error
        if owns_lock:
            _, release_errors = evidence._release_target_lock(lock_descriptor)
            if release_errors:
                raise AcceptanceCommitIndeterminateError(
                    "composition target lock release failed"
                ) from release_errors[0]
