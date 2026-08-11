"""Deterministic proof composition and independent acceptance authority.

Package-internal module implementing the closed aggregate digests, the
CompositionReport construction authority, and the compose/request/prepare/
commit acceptance transactions from the design at
docs/superpowers/specs/2026-08-06-openworkproof-acceptance-transaction-design.md.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
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
    AcceptanceRejectionReceipt,
    AcceptanceTransitionReceipt,
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
    request_arguments_digest,
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
    complete = not missing_dimensions
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
    verifier_receipts: list[ToolCallReceipt] = []
    for receipt in prefix:
        if not isinstance(receipt, ToolCallReceipt) or receipt.correlation_factors is None:
            continue
        role = _role_for(receipt, work_order)
        if role == "Developer" and developer_ref is None:
            developer_ref = CorrelationReference(
                receipt_digest=receipt.digest,
                factors=receipt.correlation_factors.model_dump(mode="json"),
            )
        elif role == "Verifier":
            verifier_receipts.append(receipt)
            test_refs.extend(receipt.evidence_refs)
    # The verifier reference is the independent result receipt when the
    # five-dimension recomposition chain is present; otherwise the first
    # primary Verifier execution remains authoritative.
    if verifier_receipts:
        independent = next(
            (
                receipt
                for receipt in reversed(verifier_receipts)
                if any(
                    reference.path
                    in {
                        f"evidence/{artifact.path}"
                        for artifact in work_order.evidence_policy.artifacts
                        if artifact.purpose == "verifier_independent_result"
                    }
                    for reference in receipt.evidence_refs
                )
            ),
            None,
        )
        selected_verifier = independent or verifier_receipts[0]
        verifier_ref = CorrelationReference(
            receipt_digest=selected_verifier.digest,
            factors=selected_verifier.correlation_factors.model_dump(mode="json"),
        )
    test_refs = tuple(
        sorted(
            set(test_refs),
            key=lambda item: item.path.encode(),
        )
    )
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
            item.model_dump(mode="json") for item in test_refs
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
    evaluation = EvaluationContext(
        inputs=inputs,
        authoritative_inputs=inputs,
    )
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
    if context.current_state == "evidence_incomplete":
        trigger = by_id.get(
            context.causal_state.latest_composition_trigger_id
        )
        independent = by_id.get(
            context.causal_state.independent_result_receipt_id
        )
        if (
            trigger is None
            or independent is None
            or not isinstance(trigger, SystemEventReceipt)
            or trigger.system_event_name != "proof_composed"
        ):
            raise AcceptanceTransactionError(
                "recomposition causal inputs are unavailable"
            )
        parents[trigger.receipt_id] = trigger
        parents[independent.receipt_id] = independent
    else:
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
    committed_result: CompositionTransactionResult | None = None
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
        if context.current_state == "locally_verified":
            expected_previous_report_digest = None
        elif context.current_state == "evidence_incomplete":
            current_report = _current_report(path, context.work_order)
            trigger = _latest_proof_composed_trigger(context)
            expected_previous_report_digest = composition_report_digest(
                current_report
            )
            if (
                getattr(trigger.cause, "composition_report_digest", None)
                != expected_previous_report_digest
            ):
                raise AcceptanceTransactionError(
                    "current report does not match its proof-composed trigger"
                )
        else:
            raise AcceptanceTransactionError(
                "composition state is invalid"
            )
        expected = ComposeProofArguments(
            expected_state_version=evidence._derive_protocol_transaction_version(
                action_receipts=context.ledger_prefix.receipts,
                acceptance_receipts=(),
            ),
            previous_report_digest=expected_previous_report_digest,
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
        if (
            context.current_state == "evidence_incomplete"
            and report.verifier_conclusion != "proof_ready"
        ):
            raise AcceptanceTransactionError(
                "recomposition remains evidence-incomplete"
            )
        trigger = _build_proof_composed_receipt(
            context,
            initiator,
            report,
            sidecar_private_key,
            sequence=prefix_len + 2,
            previous_digest=initiator.digest,
        )
        result = CompositionTransactionResult(
            initiator_receipt=initiator,
            report=report,
            trigger_receipt=trigger,
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
        try:
            connection.execute("COMMIT")
        except Exception as error:
            if _readback_compose_committed(
                path,
                work_order=work_order,
                initiator=initiator,
                trigger=trigger,
                report=report,
                expected_state=trigger.state_after,
                expected_version=state_row[1] + 1,
            ):
                committed_result = result
                raise AcceptanceCommittedError(
                    "composition committed but its acknowledgement was lost",
                    result,
                ) from error
            raise AcceptanceCommitIndeterminateError(
                "composition commit outcome is indeterminate"
            ) from error
        if not _readback_compose_committed(
            path,
            work_order=work_order,
            initiator=initiator,
            trigger=trigger,
            report=report,
            expected_state=trigger.state_after,
            expected_version=state_row[1] + 1,
        ):
            raise AcceptanceCommitIndeterminateError(
                "composition readback could not confirm the exact commit"
            )
        committed_result = result
        return result
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
        cleanup_errors: list[Exception] = []
        close_error = evidence._best_effort_close(connection)
        if close_error is not None:
            cleanup_errors.append(close_error)
        if owns_lock:
            _, release_errors = evidence._release_target_lock(lock_descriptor)
            cleanup_errors.extend(release_errors)
        if cleanup_errors:
            if committed_result is not None:
                raise AcceptanceCommittedError(
                    "composition committed but cleanup failed",
                    committed_result,
                ) from cleanup_errors[0]
            else:
                raise AcceptanceCommitIndeterminateError(
                    "composition cleanup failed"
                ) from cleanup_errors[0]


def _current_report(
    ledger_path: Path,
    work_order,
) -> CompositionReport:
    connection = evidence.connect_ledger(ledger_path)
    try:
        reports = evidence._validated_composition_reports(
            connection,
            work_order,
        )
    finally:
        connection.close()
    if not reports:
        raise AcceptanceTransactionError(
            "final acceptance requires a current composition report"
        )
    return reports[-1]


def _build_acceptance_request_receipt(
    context: AuthorizationContext,
    request: AgentRequest,
    report: CompositionReport,
    *,
    expires_at: datetime,
    sidecar_private_key: Ed25519PrivateKey,
    sequence: int,
    previous_digest: str,
) -> ApprovalRequestedReceipt:
    scope = {
        "work_order_digest": context.work_order.digest,
        "operation": "submit_final_acceptance",
        "composition_report_digest": composition_report_digest(report),
    }
    target_action_digest = hashlib.sha256(
        rfc8785.dumps(
            {
                "domain": "openworkproof/final-acceptance-action/v0.1",
                "requested_scope": scope,
            }
        )
    ).hexdigest()
    arguments = {
        "request_kind": "final_acceptance",
        "target_action_digest": target_action_digest,
        "required_role": "Acceptor",
        "requested_scope": scope,
        "expires_at": expires_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    if request.arguments_digest != request_arguments_digest(
        "owp.request_acceptance", arguments
    ):
        raise AcceptanceTransactionError(
            "acceptance request arguments do not match current report"
        )
    remaining_before = _remaining_tool_calls(context, request.grant_id)
    sidecar_key_id = key_id(sidecar_private_key.public_key())
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
        "event_type": "approval_requested",
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
        "state_after": "awaiting_human",
        "parent_receipt_ids": list(
            _request_parents(context, report, request.grant_id)
        ),
        "correlation_factors": None,
        "evidence_refs": [],
        "occurred_at": context.transaction_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "sequence": sequence,
        "nonce": request.nonce,
        "previous_receipt_digest": previous_digest,
        "grant_id": request.grant_id,
        "request_kind": "final_acceptance",
        "target_action_digest": target_action_digest,
        "required_role": "Acceptor",
        "requested_scope": scope,
        "expires_at": expires_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    return evidence.ACTION_RECEIPT_ADAPTER.validate_python(
        sign_payload("action-receipt", raw, sidecar_private_key)
    )


def _request_parents(
    context: AuthorizationContext,
    report: CompositionReport,
    grant_id: str,
) -> tuple[ActionReceiptEnvelope, ...]:
    """Final-request causal parents: grant issuance + proof_composed trigger."""
    receipts = context.ledger_prefix.receipts
    parents: dict[str, ActionReceiptEnvelope] = {}
    issuance = next(
        (
            receipt
            for receipt in receipts
            if isinstance(receipt, GrantIssuedReceipt)
            and receipt.policy_decision == "allow"
            and receipt.issued_grant_id == grant_id
        ),
        None,
    )
    if issuance is None:
        raise AcceptanceTransactionError(
            "acceptance request grant issuance is unavailable"
        )
    parents[issuance.receipt_id] = issuance
    # The trigger is the proof_composed SystemEventReceipt that bound the
    # current report digest.
    trigger = next(
        (
            receipt
            for receipt in receipts
            if isinstance(receipt, SystemEventReceipt)
            and receipt.system_event_name == "proof_composed"
            and getattr(receipt.cause, "composition_report_digest", None)
            == composition_report_digest(report)
        ),
        None,
    )
    if trigger is not None:
        parents[trigger.receipt_id] = trigger
    return tuple(
        receipt.receipt_id
        for receipt in sorted(
            parents.values(),
            key=lambda item: item.sequence,
        )
    )


def _authorize_acceptance_request(
    context: AuthorizationContext,
    request: AgentRequest,
) -> None:
    """Prospective authorization for the final-acceptance request.

    Mirrors the tool-call gate: verified signature, freshness, Manager
    role, Grant subject binding, capability, revocation, validity and
    quota must all hold before any allow receipt is constructed.
    """
    from openworkproof.signing import (
        decode_and_verify_key_binding,
        verify_payload,
    )  # noqa: PLC0415

    work_order = context.work_order
    if (
        request.work_order_digest != work_order.digest
        or request.tool_name != "owp.request_acceptance"
    ):
        raise AcceptanceTransactionError(
            "acceptance request work_order binding is invalid"
        )
    grants = {
        grant.grant_id: grant
        for grant in context.ledger_prefix.effective_grants
    }
    grant = grants.get(request.grant_id)
    bindings = {
        binding.key_id: binding
        for binding in work_order.key_bindings
    }
    binding = bindings.get(request.actor_key_id)
    if (
        grant is None
        or binding is None
        or request.actor_id != binding.subject_id
        or grant.subject_key_id != binding.key_id
        or grant.subject_agent_id != binding.subject_id
    ):
        raise AcceptanceTransactionError(
            "acceptance request Grant or actor binding is invalid"
        )
    if binding.role != "Manager":
        raise AcceptanceTransactionError(
            "final acceptance must be requested by the Manager"
        )
    try:
        public_key = decode_and_verify_key_binding(binding)
    except Exception as error:
        raise AcceptanceTransactionError(
            "acceptance request key binding is invalid"
        ) from error
    if not verify_payload(
        "agent-request",
        request.model_dump(mode="json"),
        public_key,
    ):
        raise AcceptanceTransactionError(
            "acceptance request signature is invalid"
        )
    request_age = context.transaction_time - request.requested_at
    if request_age < timedelta(0) or request_age > timedelta(seconds=300):
        raise AcceptanceTransactionError(
            "acceptance request is outside the freshness window"
        )
    if context.transaction_time > work_order.deadline:
        raise AcceptanceTransactionError(
            "contract expired before the acceptance request"
        )
    if request.grant_id in context.replay_state.revoked_grant_ids:
        raise AcceptanceTransactionError(
            "acceptance request Grant is revoked"
        )
    if (
        request.tool_name not in work_order.allowed_tools
        or request.tool_name not in grant.allowed_tools
    ):
        raise AcceptanceTransactionError(
            "acceptance request capability is denied"
        )
    if not (
        grant.valid_from
        <= context.transaction_time
        <= min(grant.expires_at, work_order.deadline)
    ):
        raise AcceptanceTransactionError(
            "acceptance request Grant is outside its validity"
        )
    if _remaining_tool_calls(context, request.grant_id) <= 0:
        raise AcceptanceTransactionError(
            "acceptance request Grant quota is exhausted"
        )
    if any(
        receipt.nonce == request.nonce
        for receipt in context.ledger_prefix.receipts
    ):
        raise AcceptanceTransactionError(
            "acceptance request nonce is already used"
        )


def _latest_proof_composed_trigger(
    context: AuthorizationContext,
) -> SystemEventReceipt:
    trigger_id = context.causal_state.latest_composition_trigger_id
    matches = tuple(
        receipt
        for receipt in context.ledger_prefix.receipts
        if isinstance(receipt, SystemEventReceipt)
        and receipt.receipt_id == trigger_id
        and receipt.system_event_name == "proof_composed"
    )
    if len(matches) != 1:
        raise AcceptanceTransactionError(
            "current composition trigger is unavailable"
        )
    return matches[0]


@dataclass(frozen=True, slots=True)
class CurrentVerificationRecord:
    protocol_version: Literal["0.2", "0.3"]
    decision_id: str
    decision_digest: str
    decision: Literal["VERIFIED", "REFUTED", "UNKNOWN"]


def _load_current_verification_decision(
    connection: sqlite3.Connection,
):
    from openworkproof import verification  # noqa: PLC0415

    v02_count = connection.execute(
        "SELECT COUNT(*) FROM verification_profiles_v02"
    ).fetchone()
    v03_count = connection.execute(
        "SELECT COUNT(*) FROM verification_profiles_v03"
    ).fetchone()
    if v02_count == (0,) and v03_count == (0,):
        return None
    if v02_count not in {(0,), (1,)} or v03_count not in {(0,), (1,)}:
        raise AcceptanceTransactionError(
            "acceptance requires exactly one verification profile"
        )
    if v02_count == (1,) and v03_count == (1,):
        raise AcceptanceTransactionError(
            "acceptance verification protocol is ambiguous"
        )
    if v02_count == (1,):
        _, _, profile = verification._load_single_profile(connection)
        decision = verification._load_current_decision(
            connection, profile=profile
        )
        version: Literal["0.2", "0.3"] = "0.2"
    else:
        _, _, manifest, profile = verification._load_single_profile_v03(
            connection
        )
        decision = verification._load_current_decision_v03(
            connection, profile=profile, manifest=manifest
        )
        version = "0.3"
    if decision is None:
        raise AcceptanceTransactionError(
            "acceptance requires a current verification decision"
        )
    return version, decision


def _resolve_current_verification_record(
    connection: sqlite3.Connection,
) -> CurrentVerificationRecord:
    current = _load_current_verification_decision(connection)
    if current is None:
        raise AcceptanceTransactionError(
            "acceptance requires a current verification decision"
        )
    version, decision = current
    matches = 0
    for table in ("verification_decisions", "verification_decisions_v03"):
        matches += connection.execute(
            f"SELECT COUNT(*) FROM {table} WHERE decision_id = ?",
            (decision.decision_id,),
        ).fetchone()[0]
    if matches != 1:
        raise AcceptanceTransactionError(
            "acceptance verification decision is ambiguous"
        )
    return CurrentVerificationRecord(
        protocol_version=version,
        decision_id=decision.decision_id,
        decision_digest=decision.digest,
        decision=decision.decision,
    )


def _require_current_verified_decision_if_v02(
    connection: sqlite3.Connection,
):
    """Compatibility gate for no-profile, v0.2, and v0.3 ledgers."""

    counts = (
        connection.execute(
            "SELECT COUNT(*) FROM verification_profiles_v02"
        ).fetchone(),
        connection.execute(
            "SELECT COUNT(*) FROM verification_profiles_v03"
        ).fetchone(),
    )
    if counts == ((0,), (0,)):
        return None
    try:
        current = _resolve_current_verification_record(connection)
    except AcceptanceTransactionError as error:
        if "current verification decision" not in str(error):
            raise
        raise AcceptanceTransactionError(
            "acceptance requires the current VERIFIED decision"
        ) from error
    if current.decision != "VERIFIED":
        raise AcceptanceTransactionError(
            "acceptance requires the current VERIFIED decision"
        )
    return current


def request_acceptance_transaction(
    ledger_path: Path,
    *,
    evidence_root: Path,
    context: AuthorizationContext,
    request: AgentRequest,
    sidecar_private_key: Ed25519PrivateKey,
    expires_at: datetime,
    clock: Callable[[], datetime],
) -> ApprovalRequestedReceipt:
    """Atomically request final acceptance from proof_ready."""
    path = Path(ledger_path)
    if not path.is_file():
        raise AcceptanceTransactionError("acceptance request ledger is unavailable")
    lock_descriptor: int | None = None
    owns_lock = False
    connection: sqlite3.Connection | None = None
    committed_result: ApprovalRequestedReceipt | None = None
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
        if context.current_state != "proof_ready":
            raise AcceptanceTransactionError(
                "final acceptance requires proof_ready"
            )
        if request.tool_name != "owp.request_acceptance":
            raise AcceptanceTransactionError(
                "acceptance request tool is invalid"
            )
        _authorize_acceptance_request(context, request)
        if expires_at.tzinfo is None or expires_at.utcoffset() is None:
            raise AcceptanceTransactionError("request expiry must be UTC")
        expiry = expires_at.astimezone(timezone.utc)
        validity = (expiry - now).total_seconds()
        if not 0 <= validity <= 3600:
            raise AcceptanceTransactionError(
                "request expiry must be within one hour"
            )
        if expiry > context.work_order.deadline:
            raise AcceptanceTransactionError(
                "request expiry exceeds the WorkOrder deadline"
            )
        work_order, receipts, _, _ = evidence._replay_receipt_publication_ledger(
            evidence.connect_ledger(path)
        )
        report = _current_report(path, work_order)
        prefix_len = len(context.ledger_prefix.receipts)
        request_receipt = _build_acceptance_request_receipt(
            context,
            request,
            report,
            expires_at=expiry,
            sidecar_private_key=sidecar_private_key,
            sequence=prefix_len + 1,
            previous_digest=(
                context.ledger_prefix.receipts[-1].digest
                if context.ledger_prefix.receipts
                else None
            ),
        )
        connection = evidence.connect_ledger(path)
        connection.execute("BEGIN IMMEDIATE")
        work_order, receipts, _, _ = (
            evidence._replay_receipt_publication_ledger(connection)
        )
        _require_current_verified_decision_if_v02(connection)
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
                "acceptance request ledger changed under the target lock"
            )
        _insert_request_rows(
            connection,
            work_order=work_order,
            request_receipt=request_receipt,
            current_state=context.current_state,
            current_version=state_row[1],
        )
        try:
            connection.execute("COMMIT")
        except Exception as error:
            if _readback_request_committed(
                path,
                work_order=work_order,
                request_receipt=request_receipt,
            ):
                committed_result = request_receipt
                raise AcceptanceCommittedError(
                    "acceptance request committed but its acknowledgement "
                    "was lost",
                    request_receipt,
                ) from error
            raise AcceptanceCommitIndeterminateError(
                "acceptance request commit outcome is indeterminate"
            ) from error
        if not _readback_request_committed(
            path,
            work_order=work_order,
            request_receipt=request_receipt,
        ):
            raise AcceptanceCommitIndeterminateError(
                "acceptance request readback could not confirm the exact commit"
            )
        committed_result = request_receipt
        return request_receipt
    except (RuntimeContextError, AcceptanceTransactionError):
        rollback_error = evidence._best_effort_rollback(connection)
        if rollback_error is not None:
            raise AcceptanceTransactionError(
                "acceptance request rollback failed"
            ) from rollback_error
        raise
    finally:
        cleanup_errors: list[Exception] = []
        close_error = evidence._best_effort_close(connection)
        if close_error is not None:
            cleanup_errors.append(close_error)
        if owns_lock:
            _, release_errors = evidence._release_target_lock(lock_descriptor)
            cleanup_errors.extend(release_errors)
        if cleanup_errors:
            if committed_result is not None:
                raise AcceptanceCommittedError(
                    "acceptance request committed but cleanup failed",
                    committed_result,
                ) from cleanup_errors[0]
            else:
                raise AcceptanceCommitIndeterminateError(
                    "acceptance request cleanup failed"
                ) from cleanup_errors[0]


def _insert_request_rows(
    connection: sqlite3.Connection,
    *,
    work_order,
    request_receipt: ApprovalRequestedReceipt,
    current_state: str,
    current_version: int,
) -> None:
    connection.execute(
        """
        INSERT INTO receipts (
            receipt_id, work_order_digest, nonce, sequence,
            previous_digest, receipt_json
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            request_receipt.receipt_id,
            work_order.digest,
            request_receipt.nonce,
            request_receipt.sequence,
            request_receipt.previous_receipt_digest,
            evidence._canonical_json(request_receipt.model_dump(mode="json")),
        ),
    )
    for parent_id in request_receipt.parent_receipt_ids:
        connection.execute(
            """
            INSERT INTO receipt_parents (child_receipt_id, parent_receipt_id)
            VALUES (?, ?)
            """,
            (request_receipt.receipt_id, parent_id),
        )
    charge = request_receipt.quota_charge
    if charge is None:
        raise AcceptanceTransactionError(
            "acceptance request must charge quota"
        )
    connection.execute(
        """
        INSERT INTO grant_events (
            event_id, receipt_id, grant_id, event_type, metric, amount
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            hashlib.sha256(
                f"grant-event:{request_receipt.receipt_id}".encode("ascii")
            ).hexdigest(),
            request_receipt.receipt_id,
            charge.grant_id,
            request_receipt.event_type,
            charge.metric,
            charge.amount,
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
            request_receipt.state_after,
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
        (request_receipt.sequence,),
    )
    if state_update.rowcount != 1 or sequence_update.rowcount != 1:
        raise AcceptanceTransactionError(
            "acceptance request counters could not be advanced"
        )


def _current_acceptance_request(
    ledger_path: Path,
    work_order,
) -> ApprovalRequestedReceipt:
    connection = evidence.connect_ledger(ledger_path)
    try:
        _, receipts, _, _ = evidence._replay_receipt_publication_ledger(connection)
    finally:
        connection.close()
    requests = [
        receipt
        for receipt in receipts
        if isinstance(receipt, ApprovalRequestedReceipt)
        and receipt.request_kind == "final_acceptance"
        and receipt.policy_decision == "allow"
        and receipt.execution_status == "succeeded"
    ]
    if not requests:
        raise AcceptanceTransactionError(
            "acceptance requires a current final-acceptance request"
        )
    return requests[-1]


def prepare_acceptance(
    ledger_path: Path,
    *,
    evidence_root: Path,
    context: AuthorizationContext,
    clock: Callable[[], datetime],
) -> AcceptanceSigningDraft:
    """Return the exact externally signable AcceptanceReceipt draft."""
    path = Path(ledger_path)
    if not path.is_file():
        raise AcceptanceTransactionError("acceptance ledger is unavailable")
    lock_descriptor: int | None = None
    owns_lock = False
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
        if context.current_state != "awaiting_human":
            raise AcceptanceTransactionError(
                "acceptance preparation requires awaiting_human"
            )
        verification_connection = evidence.connect_ledger(path)
        try:
            _require_current_verified_decision_if_v02(verification_connection)
        finally:
            verification_connection.close()
        work_order, receipts, _, _ = evidence._replay_receipt_publication_ledger(
            evidence.connect_ledger(path)
        )
        report = _current_report(path, work_order)
        request = _current_acceptance_request(path, work_order)
        if request.expires_at < now:
            raise AcceptanceTransactionError(
                "acceptance request has expired"
            )
        if context.ledger_prefix.receipts[-1].digest != request.digest:
            raise AcceptanceTransactionError(
                "acceptance request is not the current ledger tip"
            )
        prefix = context.ledger_prefix.receipts
        refs = _sorted_unique_evidence_refs(prefix)
        snapshot = evidence_snapshot_digest(refs)
        acceptance_id_value = acceptance_id(
            work_order_digest=work_order.digest,
            request_receipt_id=request.receipt_id,
            request_receipt_digest=request.digest,
            report_digest=composition_report_digest(report),
            evidence_snapshot=snapshot,
        )
        payload = {
            "protocol_version": "0.1",
            "acceptance_id": acceptance_id_value,
            "work_order_digest": work_order.digest,
            "acceptance_request_receipt_id": request.receipt_id,
            "acceptance_request_receipt_digest": request.digest,
            "composition_report_digest": composition_report_digest(report),
            "final_artifact": report.final_artifact.model_dump(mode="json"),
            "artifact_digests": [
                item.model_dump(mode="json") for item in report.artifact_digests
            ],
            "evidence_snapshot_digest": snapshot,
            "receipt_digests": [item.digest for item in prefix],
            "causal_graph_root": report.causal_graph_root,
            "causal_complete": True,
            "evidence_coverage": dict(report.evidence_coverage),
            "independence_assessment": (
                report.independence_assessment.model_dump(mode="json")
            ),
            "test_evidence_refs": [
                item.model_dump(mode="json") for item in report.test_evidence_refs
            ],
            "decision": "accepted",
            "unresolved_failures": [],
            "warnings": [item.model_dump(mode="json") for item in report.warnings],
            "global_postconditions": [
                item.model_dump(mode="json")
                for item in report.global_postconditions
            ],
            "global_postconditions_satisfied": True,
            "verifier_conclusion": "proof_ready",
            "accepted_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        canonical = rfc8785.dumps(payload)
        return AcceptanceSigningDraft(
            signing_domain="acceptance-receipt",
            acceptance_id=acceptance_id_value,
            payload=FrozenDict(payload),
            canonical_payload=canonical,
        )
    except (RuntimeContextError, AcceptanceTransactionError):
        raise
    finally:
        if owns_lock:
            _, release_errors = evidence._release_target_lock(lock_descriptor)
            if release_errors:
                raise AcceptanceCommitIndeterminateError(
                    "acceptance preparation target lock release failed"
                ) from release_errors[0]


def commit_acceptance(
    ledger_path: Path,
    *,
    evidence_root: Path,
    context: AuthorizationContext,
    acceptance: AcceptanceReceipt,
    public_keys,
    clock: Callable[[], datetime],
) -> AcceptanceReceipt:
    """Atomically commit the Acceptor-signed AcceptanceReceipt."""
    from openworkproof.signing import decode_and_verify_key_binding, verify_payload  # noqa: PLC0415

    path = Path(ledger_path)
    if not path.is_file():
        raise AcceptanceTransactionError("acceptance ledger is unavailable")
    lock_descriptor: int | None = None
    owns_lock = False
    connection: sqlite3.Connection | None = None
    committed_result: AcceptanceReceipt | None = None
    try:
        lock_descriptor, owns_lock = evidence._borrow_or_acquire_target_lock(
            path, None
        )
        now = _freeze_second(clock())
        if context.transaction_time != now:
            raise AcceptanceTransactionError(
                "authorization context time is stale"
            )
        try:
            require_current_context(
                path,
                evidence_root,
                context,
                now,
                lock_descriptor,
            )
        except RuntimeContextError as error:
            if _readback_acceptance_committed(
                path,
                work_order=context.work_order,
                acceptance=acceptance,
            ):
                committed_result = acceptance
                raise AcceptanceCommittedError(
                    "the exact acceptance is already committed",
                    acceptance,
                ) from error
            raise
        if context.current_state != "awaiting_human":
            raise AcceptanceTransactionError(
                "acceptance requires awaiting_human"
            )
        work_order, receipts, _, _ = evidence._replay_receipt_publication_ledger(
            evidence.connect_ledger(path)
        )
        report = _current_report(path, work_order)
        request = _current_acceptance_request(path, work_order)
        if request.expires_at < now:
            raise AcceptanceTransactionError(
                "acceptance request has expired"
            )
        if context.ledger_prefix.receipts[-1].digest != request.digest:
            raise AcceptanceTransactionError(
                "acceptance request is not the current ledger tip"
            )
        acceptor = work_order.key_bindings[5]
        if acceptance.signer_key_id != acceptor.key_id:
            raise AcceptanceTransactionError(
                "acceptance must be signed by the bound Acceptor"
            )
        parsed = AcceptanceReceipt.model_validate(
            acceptance.model_dump(mode="json")
        )
        parsed.validate_against_work_order(work_order)
        accepted_at = parsed.accepted_at
        if accepted_at < request.occurred_at:
            raise AcceptanceTransactionError(
                "accepted_at precedes the acceptance request"
            )
        if accepted_at > now:
            raise AcceptanceTransactionError(
                "accepted_at is in the future"
            )
        if (now - accepted_at).total_seconds() > 300:
            raise AcceptanceTransactionError(
                "acceptance signature is stale"
            )
        if accepted_at > request.expires_at:
            raise AcceptanceTransactionError(
                "acceptance signature exceeds request expiry"
            )
        if accepted_at > work_order.deadline:
            raise AcceptanceTransactionError(
                "acceptance signature exceeds the WorkOrder deadline"
            )
        prefix = context.ledger_prefix.receipts
        refs = _sorted_unique_evidence_refs(prefix)
        snapshot = evidence_snapshot_digest(refs)
        expected_id = acceptance_id(
            work_order_digest=work_order.digest,
            request_receipt_id=request.receipt_id,
            request_receipt_digest=request.digest,
            report_digest=composition_report_digest(report),
            evidence_snapshot=snapshot,
        )
        if parsed.acceptance_id != expected_id:
            raise AcceptanceTransactionError(
                "acceptance ID does not match the authoritative snapshot"
            )
        expected_payload = _expected_acceptance_payload(
            work_order,
            report,
            request,
            snapshot,
            expected_id,
            accepted_at,
            prefix,
        )
        actual_payload = {
            key: value
            for key, value in parsed.model_dump(mode="json").items()
            if key not in {"digest", "signature_alg", "signer_key_id", "signature"}
        }
        if actual_payload != expected_payload:
            raise AcceptanceTransactionError(
                "acceptance payload does not match the authoritative snapshot"
            )
        acceptor_key = decode_and_verify_key_binding(acceptor)
        if not verify_payload(
            "acceptance-receipt",
            parsed.model_dump(mode="json"),
            acceptor_key,
        ):
            raise AcceptanceTransactionError(
                "acceptance signature verification failed"
            )
        connection = evidence.connect_ledger(path)
        connection.execute("BEGIN IMMEDIATE")
        _require_current_verified_decision_if_v02(connection)
        existing = connection.execute(
            "SELECT COUNT(*) FROM acceptance_receipts"
        ).fetchone()
        if existing is not None and existing[0] != 0:
            raise AcceptanceTransactionError(
                "WorkOrder already has an acceptance"
            )
        state_row = connection.execute(
            "SELECT current_state, version FROM work_order_state WHERE singleton = 1"
        ).fetchone()
        if state_row != ("awaiting_human", _derive_version(connection, work_order)):
            raise AcceptanceTransactionError(
                "acceptance ledger changed under the target lock"
            )
        _insert_acceptance_rows(
            connection,
            work_order=work_order,
            acceptance=parsed,
            current_state=state_row[0],
            current_version=state_row[1],
        )
        try:
            connection.execute("COMMIT")
        except Exception as error:
            if _readback_acceptance_committed(
                path,
                work_order=work_order,
                acceptance=parsed,
            ):
                committed_result = parsed
                raise AcceptanceCommittedError(
                    "acceptance committed but its acknowledgement was lost",
                    parsed,
                ) from error
            raise AcceptanceCommitIndeterminateError(
                "acceptance commit outcome is indeterminate"
            ) from error
        if not _readback_acceptance_committed(
            path,
            work_order=work_order,
            acceptance=parsed,
        ):
            raise AcceptanceCommitIndeterminateError(
                "acceptance readback could not confirm the exact commit"
            )
        committed_result = parsed
        return parsed
    except (RuntimeContextError, AcceptanceTransactionError):
        rollback_error = evidence._best_effort_rollback(connection)
        if rollback_error is not None:
            raise AcceptanceTransactionError(
                "acceptance rollback failed"
            ) from rollback_error
        raise
    finally:
        cleanup_errors: list[Exception] = []
        close_error = evidence._best_effort_close(connection)
        if close_error is not None:
            cleanup_errors.append(close_error)
        if owns_lock:
            _, release_errors = evidence._release_target_lock(lock_descriptor)
            cleanup_errors.extend(release_errors)
        if cleanup_errors:
            if committed_result is not None:
                raise AcceptanceCommittedError(
                    "acceptance committed but cleanup failed",
                    committed_result,
                ) from cleanup_errors[0]
            else:
                raise AcceptanceCommitIndeterminateError(
                    "acceptance cleanup failed"
                ) from cleanup_errors[0]


def _derive_version(connection, work_order) -> int:
    _, receipts, _, _ = evidence._replay_receipt_publication_ledger(connection)
    return evidence._derive_protocol_transaction_version(
        action_receipts=receipts,
        acceptance_receipts=(),
    )


def _expected_acceptance_payload(
    work_order,
    report: CompositionReport,
    request: ApprovalRequestedReceipt,
    snapshot: str,
    expected_id: str,
    accepted_at: datetime,
    prefix: tuple[ActionReceiptEnvelope, ...],
) -> dict:
    return {
        "protocol_version": "0.1",
        "acceptance_id": expected_id,
        "work_order_digest": work_order.digest,
        "acceptance_request_receipt_id": request.receipt_id,
        "acceptance_request_receipt_digest": request.digest,
        "composition_report_digest": composition_report_digest(report),
        "final_artifact": report.final_artifact.model_dump(mode="json"),
        "artifact_digests": [
            item.model_dump(mode="json") for item in report.artifact_digests
        ],
        "evidence_snapshot_digest": snapshot,
        "receipt_digests": [item.digest for item in prefix],
        "causal_graph_root": report.causal_graph_root,
        "causal_complete": True,
        "evidence_coverage": dict(report.evidence_coverage),
        "independence_assessment": (
            report.independence_assessment.model_dump(mode="json")
        ),
        "test_evidence_refs": [
            item.model_dump(mode="json") for item in report.test_evidence_refs
        ],
        "decision": "accepted",
        "unresolved_failures": [],
        "warnings": [item.model_dump(mode="json") for item in report.warnings],
        "global_postconditions": [
            item.model_dump(mode="json")
            for item in report.global_postconditions
        ],
        "global_postconditions_satisfied": True,
        "verifier_conclusion": "proof_ready",
        "accepted_at": accepted_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def validate_acceptance_bindings(
    *,
    work_order,
    report: CompositionReport,
    receipts: tuple[ActionReceiptEnvelope, ...],
    acceptance_receipt: AcceptanceReceipt,
) -> AcceptanceReceipt:
    """Verify one AcceptanceReceipt against its exact signed history."""
    if (
        not isinstance(report, CompositionReport)
        or type(receipts) is not tuple
        or not receipts
        or any(
            not isinstance(receipt, ActionReceiptEnvelope)
            for receipt in receipts
        )
        or not isinstance(acceptance_receipt, AcceptanceReceipt)
    ):
        raise AcceptanceTransactionError(
            "acceptance binding inputs are unavailable"
        )
    request = receipts[-1]
    if (
        not isinstance(request, ApprovalRequestedReceipt)
        or request.request_kind != "final_acceptance"
        or request.required_role != "Acceptor"
        or request.policy_decision != "allow"
        or request.execution_status != "succeeded"
        or request.state_after != "awaiting_human"
    ):
        raise AcceptanceTransactionError(
            "acceptance has no current final-acceptance request"
        )
    report_digest = composition_report_digest(report)
    expected_scope = {
        "work_order_digest": work_order.digest,
        "operation": "submit_final_acceptance",
        "composition_report_digest": report_digest,
    }
    trigger = receipts[-2] if len(receipts) >= 2 else None
    if (
        report.work_order_digest != work_order.digest
        or report.verifier_conclusion != "proof_ready"
        or request.requested_scope != expected_scope
        or request.target_action_digest
        != hashlib.sha256(
            rfc8785.dumps(
                {
                    "domain": "openworkproof/final-acceptance-action/v0.1",
                    "requested_scope": expected_scope,
                }
            )
        ).hexdigest()
        or not isinstance(trigger, SystemEventReceipt)
        or trigger.system_event_name != "proof_composed"
        or getattr(trigger.cause, "composition_report_digest", None)
        != report_digest
    ):
        raise AcceptanceTransactionError(
            "acceptance report or request binding is invalid"
        )
    initiator_indexes = tuple(
        index
        for index, receipt in enumerate(receipts)
        if receipt.receipt_id == report.initiator_receipt_id
        and receipt.digest == report.initiator_receipt_digest
    )
    if len(initiator_indexes) != 1:
        raise AcceptanceTransactionError(
            "acceptance report initiator is not unique"
        )
    report_prefix = receipts[: initiator_indexes[0] + 1]
    report_refs = _sorted_unique_evidence_refs(report_prefix)
    if (
        report.receipt_digests
        != tuple(receipt.digest for receipt in report_prefix)
        or report.causal_graph_root != causal_graph_root(report_prefix)
        or report.evidence_snapshot_digest
        != evidence_snapshot_digest(report_refs)
    ):
        raise AcceptanceTransactionError(
            "composition report does not match its authoritative prefix"
        )
    full_refs = _sorted_unique_evidence_refs(receipts)
    snapshot = evidence_snapshot_digest(full_refs)
    expected_id = acceptance_id(
        work_order_digest=work_order.digest,
        request_receipt_id=request.receipt_id,
        request_receipt_digest=request.digest,
        report_digest=report_digest,
        evidence_snapshot=snapshot,
    )
    accepted_at = acceptance_receipt.accepted_at
    if (
        accepted_at < request.occurred_at
        or accepted_at > request.expires_at
        or accepted_at > work_order.deadline
        or acceptance_receipt.acceptance_id != expected_id
    ):
        raise AcceptanceTransactionError(
            "acceptance time or identifier binding is invalid"
        )
    expected_payload = _expected_acceptance_payload(
        work_order,
        report,
        request,
        snapshot,
        expected_id,
        accepted_at,
        receipts,
    )
    actual_payload = {
        key: value
        for key, value in acceptance_receipt.model_dump(mode="json").items()
        if key not in {"digest", "signature_alg", "signer_key_id", "signature"}
    }
    if actual_payload != expected_payload:
        raise AcceptanceTransactionError(
            "acceptance payload does not match its authoritative prefix"
        )
    from openworkproof.signing import (  # noqa: PLC0415
        decode_and_verify_key_binding,
        verify_payload,
    )

    acceptance_receipt.validate_against_work_order(work_order)
    acceptor = work_order.key_bindings[5]
    if (
        acceptance_receipt.signer_key_id != acceptor.key_id
        or not verify_payload(
            "acceptance-receipt",
            acceptance_receipt.model_dump(mode="json"),
            decode_and_verify_key_binding(acceptor),
        )
    ):
        raise AcceptanceTransactionError(
            "acceptance signature does not match the bound Acceptor"
        )
    return acceptance_receipt


def rejection_id(
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
                "domain": "openworkproof/rejection-id/0.1",
                "work_order_digest": work_order_digest,
                "request_receipt_id": request_receipt_id,
                "request_receipt_digest": request_receipt_digest,
                "composition_report_digest": report_digest,
                "evidence_snapshot_digest": evidence_snapshot,
            }
        )
    ).hexdigest()


def _expected_rejection_payload(
    work_order,
    report: CompositionReport,
    request: ApprovalRequestedReceipt,
    snapshot: str,
    expected_id: str,
    rejected_at: datetime,
    prefix: tuple[ActionReceiptEnvelope, ...],
    reason_code: str,
    reason_detail: str,
) -> dict:
    return {
        "protocol_version": "0.1",
        "rejection_id": expected_id,
        "work_order_digest": work_order.digest,
        "acceptance_request_receipt_id": request.receipt_id,
        "acceptance_request_receipt_digest": request.digest,
        "composition_report_digest": composition_report_digest(report),
        "evidence_snapshot_digest": snapshot,
        "receipt_digests": [item.digest for item in prefix],
        "causal_graph_root": report.causal_graph_root,
        "reason_code": reason_code,
        "reason_detail": reason_detail,
        "decision": "rejected",
        "rejected_at": rejected_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def validate_rejection_bindings(
    *,
    work_order,
    report: CompositionReport,
    receipts: tuple[ActionReceiptEnvelope, ...],
    rejection: AcceptanceRejectionReceipt,
) -> AcceptanceRejectionReceipt:
    """Verify one AcceptanceRejectionReceipt against its exact history."""
    if (
        not isinstance(report, CompositionReport)
        or type(receipts) is not tuple
        or not receipts
        or any(
            not isinstance(receipt, ActionReceiptEnvelope)
            for receipt in receipts
        )
        or not isinstance(rejection, AcceptanceRejectionReceipt)
    ):
        raise AcceptanceTransactionError(
            "rejection binding inputs are unavailable"
        )
    request = receipts[-1]
    if (
        not isinstance(request, ApprovalRequestedReceipt)
        or request.request_kind != "final_acceptance"
        or request.required_role != "Acceptor"
        or request.policy_decision != "allow"
        or request.execution_status != "succeeded"
        or request.state_after != "awaiting_human"
    ):
        raise AcceptanceTransactionError(
            "rejection has no current final-acceptance request"
        )
    report_digest = composition_report_digest(report)
    expected_scope = {
        "work_order_digest": work_order.digest,
        "operation": "submit_final_acceptance",
        "composition_report_digest": report_digest,
    }
    trigger = receipts[-2] if len(receipts) >= 2 else None
    if (
        report.work_order_digest != work_order.digest
        or report.verifier_conclusion != "proof_ready"
        or request.requested_scope != expected_scope
        or request.target_action_digest
        != hashlib.sha256(
            rfc8785.dumps(
                {
                    "domain": "openworkproof/final-acceptance-action/v0.1",
                    "requested_scope": expected_scope,
                }
            )
        ).hexdigest()
        or not isinstance(trigger, SystemEventReceipt)
        or trigger.system_event_name != "proof_composed"
        or getattr(trigger.cause, "composition_report_digest", None)
        != report_digest
    ):
        raise AcceptanceTransactionError(
            "rejection report or request binding is invalid"
        )
    initiator_indexes = tuple(
        index
        for index, receipt in enumerate(receipts)
        if receipt.receipt_id == report.initiator_receipt_id
        and receipt.digest == report.initiator_receipt_digest
    )
    if len(initiator_indexes) != 1:
        raise AcceptanceTransactionError(
            "rejection report initiator is not unique"
        )
    report_prefix = receipts[: initiator_indexes[0] + 1]
    report_refs = _sorted_unique_evidence_refs(report_prefix)
    if (
        report.receipt_digests
        != tuple(receipt.digest for receipt in report_prefix)
        or report.causal_graph_root != causal_graph_root(report_prefix)
        or report.evidence_snapshot_digest
        != evidence_snapshot_digest(report_refs)
    ):
        raise AcceptanceTransactionError(
            "composition report does not match its authoritative prefix"
        )
    full_refs = _sorted_unique_evidence_refs(receipts)
    snapshot = evidence_snapshot_digest(full_refs)
    expected_id = rejection_id(
        work_order_digest=work_order.digest,
        request_receipt_id=request.receipt_id,
        request_receipt_digest=request.digest,
        report_digest=report_digest,
        evidence_snapshot=snapshot,
    )
    rejected_at = rejection.rejected_at
    if (
        rejected_at < request.occurred_at
        or rejected_at > request.expires_at
        or rejected_at > work_order.deadline
        or rejection.rejection_id != expected_id
    ):
        raise AcceptanceTransactionError(
            "rejection time or identifier binding is invalid"
        )
    expected_payload = _expected_rejection_payload(
        work_order,
        report,
        request,
        snapshot,
        expected_id,
        rejected_at,
        receipts,
        rejection.reason_code,
        rejection.reason_detail,
    )
    actual_payload = {
        key: value
        for key, value in rejection.model_dump(mode="json").items()
        if key not in {"digest", "signature_alg", "signer_key_id", "signature"}
    }
    if actual_payload != expected_payload:
        raise AcceptanceTransactionError(
            "rejection payload does not match its authoritative prefix"
        )
    from openworkproof.signing import (  # noqa: PLC0415
        decode_and_verify_key_binding,
        verify_payload,
    )

    rejection.validate_against_work_order(work_order)
    acceptor = work_order.key_bindings[5]
    if (
        rejection.signer_key_id != acceptor.key_id
        or not verify_payload(
            "acceptance-rejection-receipt",
            rejection.model_dump(mode="json"),
            decode_and_verify_key_binding(acceptor),
        )
    ):
        raise AcceptanceTransactionError(
            "rejection signature does not match the bound Acceptor"
        )
    return rejection


def verify_acceptance_bundle(
    *,
    work_order,
    report: CompositionReport,
    effective_grants: tuple,
    grant_attempts: tuple,
    receipts: tuple[ActionReceiptEnvelope, ...],
    committed_evidence: tuple,
    acceptance_receipt: AcceptanceReceipt | None = None,
    public_keys: Mapping,
    reports: tuple[CompositionReport, ...] | None = None,
    rejection: AcceptanceRejectionReceipt | None = None,
) -> AcceptanceReceipt | AcceptanceRejectionReceipt:
    """Verify a copied acceptance bundle without a live ledger.

    Exactly one terminal decision (acceptance or rejection) must be bound
    to the request tip.
    """
    from openworkproof.policy import (  # noqa: PLC0415
        AuthorizationLedgerPrefix,
        CommittedEvidence,
        _validate_committed_evidence,
    )

    if (
        type(effective_grants) is not tuple
        or type(grant_attempts) is not tuple
        or type(committed_evidence) is not tuple
        or any(
            not isinstance(item, CommittedEvidence)
            for item in committed_evidence
        )
        or (acceptance_receipt is None) == (rejection is None)
    ):
        raise AcceptanceTransactionError(
            "offline acceptance bundle is malformed"
        )
    selected_reports = reports if reports is not None else (report,)
    try:
        final_report = verify_composition_bundle(
            work_order=work_order,
            effective_grants=effective_grants,
            grant_attempts=grant_attempts,
            receipts=receipts,
            committed_evidence=committed_evidence,
            reports=selected_reports,
            public_keys=public_keys,
        )
        if final_report != report:
            raise AcceptanceTransactionError(
                "offline bundle final report does not match the acceptance report"
            )
        if rejection is not None:
            return validate_rejection_bindings(
                work_order=work_order,
                report=report,
                receipts=receipts,
                rejection=rejection,
            )
        assert acceptance_receipt is not None
        return validate_acceptance_bindings(
            work_order=work_order,
            report=report,
            receipts=receipts,
            acceptance_receipt=acceptance_receipt,
        )
    except AcceptanceTransactionError:
        raise
    except Exception as error:
        raise AcceptanceTransactionError(
            "offline acceptance bundle failed verification"
        ) from error


def _insert_acceptance_rows(
    connection: sqlite3.Connection,
    *,
    work_order,
    acceptance: AcceptanceReceipt,
    current_state: str,
    current_version: int,
) -> None:
    connection.execute(
        """
        INSERT INTO acceptance_receipts (
            acceptance_id, work_order_digest, acceptance_json
        )
        VALUES (?, ?, ?)
        """,
        (
            acceptance.acceptance_id,
            work_order.digest,
            evidence._canonical_json(acceptance.model_dump(mode="json")),
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
            "accepted",
            work_order.digest,
            current_state,
            current_version,
        ),
    )
    if state_update.rowcount != 1:
        raise AcceptanceTransactionError(
            "acceptance state could not be advanced"
        )


def _readback_compose_committed(
    ledger_path: Path,
    *,
    work_order,
    initiator: ToolCallReceipt,
    trigger: SystemEventReceipt,
    report: CompositionReport,
    expected_state: str,
    expected_version: int,
) -> bool:
    """Prove the exact composition committed by reopening the ledger."""
    try:
        connection = evidence.connect_ledger(ledger_path)
        try:
            current_work_order, receipts, _, _ = (
                evidence._replay_receipt_publication_ledger(connection)
            )
            reports = evidence._validated_composition_reports(
                connection,
                current_work_order,
            )
            state_row = connection.execute(
                "SELECT current_state, version FROM work_order_state "
                "WHERE singleton = 1"
            ).fetchone()
        finally:
            connection.close()
    except Exception:
        return False
    return (
        current_work_order == work_order
        and len(receipts) >= 2
        and receipts[-2:] == (initiator, trigger)
        and any(candidate == report for candidate in reports)
        and state_row == (expected_state, expected_version)
    )


def _readback_request_committed(
    ledger_path: Path,
    *,
    work_order,
    request_receipt: ApprovalRequestedReceipt,
) -> bool:
    try:
        connection = evidence.connect_ledger(ledger_path)
        try:
            current_work_order, receipts, _, _ = (
                evidence._replay_receipt_publication_ledger(connection)
            )
            state = connection.execute(
                "SELECT current_state FROM work_order_state WHERE singleton = 1"
            ).fetchone()
        finally:
            connection.close()
    except Exception:
        return False
    return (
        current_work_order == work_order
        and bool(receipts)
        and receipts[-1] == request_receipt
        and state is not None
        and state[0] == request_receipt.state_after
    )


def _readback_acceptance_committed(
    ledger_path: Path,
    *,
    work_order,
    acceptance: AcceptanceReceipt,
) -> bool:
    try:
        connection = evidence.connect_ledger(ledger_path)
        try:
            current_work_order, _, _, _ = (
                evidence._replay_receipt_publication_ledger(connection)
            )
            acceptances = evidence._validated_acceptance_receipts(
                connection,
                current_work_order,
            )
        finally:
            connection.close()
    except Exception:
        return False
    return (
        current_work_order == work_order
        and acceptances == (acceptance,)
    )


def _validate_composition_report_binding(
    *,
    work_order,
    report: CompositionReport,
    receipts: tuple[ActionReceiptEnvelope, ...],
) -> CompositionReport:
    """Validate one CompositionReport against its exact signed prefix."""
    initiator_indexes = tuple(
        index
        for index, receipt in enumerate(receipts)
        if receipt.receipt_id == report.initiator_receipt_id
        and receipt.digest == report.initiator_receipt_digest
    )
    if len(initiator_indexes) != 1:
        raise AcceptanceTransactionError(
            "composition report initiator is not unique"
        )
    initiator_index = initiator_indexes[0]
    trigger = (
        receipts[initiator_index + 1]
        if initiator_index + 1 < len(receipts)
        else None
    )
    report_digest = composition_report_digest(report)
    report_prefix = receipts[: initiator_index + 1]
    report_refs = _sorted_unique_evidence_refs(report_prefix)
    if (
        report.work_order_digest != work_order.digest
        or not isinstance(trigger, SystemEventReceipt)
        or trigger.system_event_name != "proof_composed"
        or getattr(trigger.cause, "composition_report_digest", None)
        != report_digest
        or report.receipt_digests
        != tuple(receipt.digest for receipt in report_prefix)
        or report.causal_graph_root != causal_graph_root(report_prefix)
        or report.evidence_snapshot_digest
        != evidence_snapshot_digest(report_refs)
    ):
        raise AcceptanceTransactionError(
            "composition report does not match its authoritative prefix"
        )
    return report


def verify_composition_bundle(
    *,
    work_order,
    effective_grants: tuple,
    grant_attempts: tuple,
    receipts: tuple[ActionReceiptEnvelope, ...],
    committed_evidence: tuple,
    reports: tuple[CompositionReport, ...],
    public_keys: Mapping,
) -> CompositionReport:
    """Verify a copied multi-report bundle without a live ledger."""
    from openworkproof.evidence import validate_grant_chain  # noqa: PLC0415
    from openworkproof.policy import (  # noqa: PLC0415
        AuthorizationLedgerPrefix,
        CommittedEvidence,
        _validate_committed_evidence,
    )
    from openworkproof.composition import replay_authorization_causality  # noqa: PLC0415

    if (
        type(effective_grants) is not tuple
        or type(grant_attempts) is not tuple
        or type(committed_evidence) is not tuple
        or type(reports) is not tuple
        or not reports
        or any(
            not isinstance(item, CommittedEvidence)
            for item in committed_evidence
        )
        or any(
            not isinstance(item, CompositionReport) for item in reports
        )
    ):
        raise AcceptanceTransactionError(
            "offline composition bundle is malformed"
        )
    try:
        validate_grant_chain(
            work_order,
            effective_grants,
            grant_attempts,
            receipts,
            public_keys,
        )
        prefix = AuthorizationLedgerPrefix(
            effective_grants=effective_grants,
            grant_attempts=grant_attempts,
            receipts=receipts,
        )
        _validate_committed_evidence(
            work_order,
            prefix,
            committed_evidence,
        )
        replay_authorization_causality(work_order, receipts)
        triggers = tuple(
            receipt
            for receipt in receipts
            if isinstance(receipt, SystemEventReceipt)
            and receipt.system_event_name == "proof_composed"
        )
        if len(triggers) != len(reports):
            raise AcceptanceTransactionError(
                "composition report count does not match the trigger count"
            )
        # Reports must map one-to-one, in order, onto the proof_composed
        # triggers: duplicates and reordering are rejected so that a tuple
        # containing the final report twice cannot skip validating an earlier
        # report.
        initiator_indexes = tuple(
            tuple(
                index
                for index, receipt in enumerate(receipts)
                if receipt.receipt_id == report.initiator_receipt_id
                and receipt.digest == report.initiator_receipt_digest
            )
            for report in reports
        )
        if any(len(indexes) != 1 for indexes in initiator_indexes):
            raise AcceptanceTransactionError(
                "composition report initiator is not unique"
            )
        flattened = tuple(indexes[0] for indexes in initiator_indexes)
        if any(
            left >= right
            for left, right in zip(flattened, flattened[1:])
        ):
            raise AcceptanceTransactionError(
                "composition reports are duplicated or out of order"
            )
        bound_triggers = {
            receipts[index + 1].receipt_id for index in flattened
        }
        if bound_triggers != {trigger.receipt_id for trigger in triggers}:
            raise AcceptanceTransactionError(
                "composition reports do not map one-to-one onto triggers"
            )
        for report in reports:
            _validate_composition_report_binding(
                work_order=work_order,
                report=report,
                receipts=receipts,
            )
        return reports[-1]
    except AcceptanceTransactionError:
        raise
    except Exception as error:
        raise AcceptanceTransactionError(
            "offline composition bundle failed verification"
        ) from error


def _insert_rejection_rows(
    connection: sqlite3.Connection,
    *,
    work_order,
    rejection: AcceptanceRejectionReceipt,
    current_state: str,
    current_version: int,
) -> None:
    connection.execute(
        """
        INSERT INTO acceptance_rejection_receipts (
            rejection_id, work_order_digest,
            acceptance_request_receipt_id, rejection_json
        )
        VALUES (?, ?, ?, ?)
        """,
        (
            rejection.rejection_id,
            work_order.digest,
            rejection.acceptance_request_receipt_id,
            evidence._canonical_json(rejection.model_dump(mode="json")),
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
            "rejected",
            work_order.digest,
            current_state,
            current_version,
        ),
    )
    if state_update.rowcount != 1:
        raise AcceptanceTransactionError(
            "rejection state could not be advanced"
        )


def _readback_rejection_committed(
    ledger_path: Path,
    *,
    work_order,
    rejection: AcceptanceRejectionReceipt,
) -> bool:
    """Prove the exact rejection committed by reopening the ledger."""
    try:
        connection = evidence.connect_ledger(ledger_path)
        try:
            current_work_order, _, _, _ = (
                evidence._replay_receipt_publication_ledger(connection)
            )
            rejections = evidence._validated_acceptance_rejections(
                connection,
                current_work_order,
            )
            state = connection.execute(
                "SELECT current_state FROM work_order_state "
                "WHERE singleton = 1"
            ).fetchone()
        finally:
            connection.close()
    except Exception:
        return False
    return (
        current_work_order == work_order
        and len(rejections) == 1
        and rejections[0].rejection_id == rejection.rejection_id
        and state is not None
        and state[0] == "rejected"
    )


def reject_acceptance_transaction(
    ledger_path: Path,
    *,
    evidence_root: Path,
    context: AuthorizationContext,
    rejection: AcceptanceRejectionReceipt,
    public_keys=None,
    clock: Callable[[], datetime],
) -> AcceptanceRejectionReceipt:
    """Atomically commit the Acceptor-signed AcceptanceRejectionReceipt."""
    from openworkproof.signing import (  # noqa: PLC0415
        decode_and_verify_key_binding,
        verify_payload,
    )

    path = Path(ledger_path)
    if not path.is_file():
        raise AcceptanceTransactionError("acceptance ledger is unavailable")
    lock_descriptor: int | None = None
    owns_lock = False
    connection: sqlite3.Connection | None = None
    committed_result: AcceptanceRejectionReceipt | None = None
    try:
        lock_descriptor, owns_lock = evidence._borrow_or_acquire_target_lock(
            path, None
        )
        now = _freeze_second(clock())
        if context.transaction_time != now:
            raise AcceptanceTransactionError(
                "authorization context time is stale"
            )
        try:
            require_current_context(
                path,
                evidence_root,
                context,
                now,
                lock_descriptor,
            )
        except RuntimeContextError as error:
            if _readback_rejection_committed(
                path,
                work_order=context.work_order,
                rejection=rejection,
            ):
                committed_result = rejection
                raise AcceptanceCommittedError(
                    "the exact rejection is already committed",
                    rejection,
                ) from error
            raise
        if context.current_state != "awaiting_human":
            raise AcceptanceTransactionError(
                "rejection requires awaiting_human"
            )
        work_order, receipts, _, _ = evidence._replay_receipt_publication_ledger(
            evidence.connect_ledger(path)
        )
        report = _current_report(path, work_order)
        request = _current_acceptance_request(path, work_order)
        if request.expires_at < now:
            raise AcceptanceTransactionError(
                "acceptance request has expired"
            )
        if context.ledger_prefix.receipts[-1].digest != request.digest:
            raise AcceptanceTransactionError(
                "acceptance request is not the current ledger tip"
            )
        acceptor = work_order.key_bindings[5]
        if rejection.signer_key_id != acceptor.key_id:
            raise AcceptanceTransactionError(
                "rejection must be signed by the bound Acceptor"
            )
        parsed = AcceptanceRejectionReceipt.model_validate(
            rejection.model_dump(mode="json")
        )
        parsed.validate_against_work_order(work_order)
        rejected_at = parsed.rejected_at
        if rejected_at < request.occurred_at:
            raise AcceptanceTransactionError(
                "rejected_at precedes the acceptance request"
            )
        if rejected_at > now:
            raise AcceptanceTransactionError(
                "rejected_at is in the future"
            )
        if (now - rejected_at).total_seconds() > 300:
            raise AcceptanceTransactionError(
                "rejection signature is stale"
            )
        if rejected_at > request.expires_at:
            raise AcceptanceTransactionError(
                "rejection signature exceeds request expiry"
            )
        if rejected_at > work_order.deadline:
            raise AcceptanceTransactionError(
                "rejection signature exceeds the WorkOrder deadline"
            )
        prefix = context.ledger_prefix.receipts
        refs = _sorted_unique_evidence_refs(prefix)
        snapshot = evidence_snapshot_digest(refs)
        expected_id = rejection_id(
            work_order_digest=work_order.digest,
            request_receipt_id=request.receipt_id,
            request_receipt_digest=request.digest,
            report_digest=composition_report_digest(report),
            evidence_snapshot=snapshot,
        )
        if parsed.rejection_id != expected_id:
            raise AcceptanceTransactionError(
                "rejection ID does not match the authoritative snapshot"
            )
        expected_payload = _expected_rejection_payload(
            work_order,
            report,
            request,
            snapshot,
            expected_id,
            rejected_at,
            prefix,
            parsed.reason_code,
            parsed.reason_detail,
        )
        actual_payload = {
            key: value
            for key, value in parsed.model_dump(mode="json").items()
            if key not in {"digest", "signature_alg", "signer_key_id", "signature"}
        }
        if actual_payload != expected_payload:
            raise AcceptanceTransactionError(
                "rejection payload does not match the authoritative snapshot"
            )
        acceptor_key = decode_and_verify_key_binding(acceptor)
        if not verify_payload(
            "acceptance-rejection-receipt",
            parsed.model_dump(mode="json"),
            acceptor_key,
        ):
            raise AcceptanceTransactionError(
                "rejection signature verification failed"
            )
        connection = evidence.connect_ledger(path)
        connection.execute("BEGIN IMMEDIATE")
        existing_acceptance = connection.execute(
            "SELECT COUNT(*) FROM acceptance_receipts"
        ).fetchone()
        if existing_acceptance is not None and existing_acceptance[0] != 0:
            raise AcceptanceTransactionError(
                "WorkOrder already has an acceptance"
            )
        existing_rejection = connection.execute(
            "SELECT COUNT(*) FROM acceptance_rejection_receipts"
        ).fetchone()
        if existing_rejection is not None and existing_rejection[0] != 0:
            raise AcceptanceTransactionError(
                "WorkOrder already has a rejection"
            )
        state_row = connection.execute(
            "SELECT current_state, version FROM work_order_state WHERE singleton = 1"
        ).fetchone()
        if state_row != ("awaiting_human", _derive_version(connection, work_order)):
            raise AcceptanceTransactionError(
                "rejection ledger changed under the target lock"
            )
        _insert_rejection_rows(
            connection,
            work_order=work_order,
            rejection=parsed,
            current_state=state_row[0],
            current_version=state_row[1],
        )
        try:
            connection.execute("COMMIT")
        except Exception as error:
            if _readback_rejection_committed(
                path,
                work_order=work_order,
                rejection=parsed,
            ):
                committed_result = parsed
                raise AcceptanceCommittedError(
                    "rejection committed but its acknowledgement was lost",
                    parsed,
                ) from error
            raise AcceptanceCommitIndeterminateError(
                "rejection commit outcome is indeterminate"
            ) from error
        if not _readback_rejection_committed(
            path,
            work_order=work_order,
            rejection=parsed,
        ):
            raise AcceptanceCommitIndeterminateError(
                "rejection readback could not confirm the exact commit"
            )
        committed_result = parsed
        return parsed
    except Exception as error:
        if committed_result is not None and isinstance(
            error, AcceptanceCommittedError
        ):
            raise
        raise
    finally:
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass
        if owns_lock and lock_descriptor is not None:
            evidence._release_target_lock(lock_descriptor)


def _exact_acceptance_transition_readback(
    ledger_path: Path,
    transition: AcceptanceTransitionReceipt,
) -> bool:
    try:
        connection = evidence.connect_ledger(ledger_path)
        try:
            current = _resolve_current_verification_record(connection)
            if (
                current.decision_id != transition.verification_decision_id
                or current.decision_digest
                != transition.verification_decision_digest
            ):
                return False
            if current.protocol_version == "0.2":
                transition_table = "acceptance_transitions"
                parent_table = "acceptance_transition_parents"
                row = connection.execute(
                    f"""
                    SELECT target_acceptance_id, verification_decision_id,
                           transition_json
                    FROM {transition_table}
                    WHERE transition_id = ?
                    """,
                    (transition.transition_id,),
                ).fetchone()
                expected_row = (
                    transition.target_acceptance_id,
                    transition.verification_decision_id,
                    rfc8785.dumps(transition.model_dump(mode="json")),
                )
            else:
                transition_table = "acceptance_transitions_v03"
                parent_table = "acceptance_transition_parents_v03"
                row = connection.execute(
                    f"""
                    SELECT transition_digest, target_acceptance_id,
                           verification_decision_id, transition_json
                    FROM {transition_table}
                    WHERE transition_id = ?
                    """,
                    (transition.transition_id,),
                ).fetchone()
                expected_row = (
                    transition.digest,
                    transition.target_acceptance_id,
                    transition.verification_decision_id,
                    rfc8785.dumps(transition.model_dump(mode="json")),
                )
            parents = tuple(
                connection.execute(
                    f"""
                    SELECT ordinal, parent_id
                    FROM {parent_table}
                    WHERE transition_id = ?
                    ORDER BY ordinal
                    """,
                    (transition.transition_id,),
                )
            )
        finally:
            connection.close()
    except Exception:
        return False
    return row == expected_row and parents == tuple(
        (ordinal, parent_id)
        for ordinal, parent_id in enumerate(transition.causal_parent_ids)
    )


def commit_acceptance_transition(
    ledger_path: Path,
    transition: AcceptanceTransitionReceipt,
    *,
    fault: Literal[
        "before_commit",
        "commit_ack_loss",
        "readback_failure",
        "cleanup_failure",
    ]
    | None = None,
) -> AcceptanceTransitionReceipt:
    """Append an Acceptor-signed withdrawal or supersession receipt."""
    from openworkproof import verification  # noqa: PLC0415
    from openworkproof.signing import (  # noqa: PLC0415
        decode_and_verify_key_binding,
        verify_payload,
    )

    if fault not in {
        None,
        "before_commit",
        "commit_ack_loss",
        "readback_failure",
        "cleanup_failure",
    }:
        raise AcceptanceTransactionError("unknown transition fault")
    path = Path(ledger_path)
    if not path.is_file():
        raise AcceptanceTransactionError("acceptance ledger is unavailable")
    try:
        parsed = AcceptanceTransitionReceipt.model_validate(
            transition.model_dump(mode="json")
        )
    except Exception as error:
        raise AcceptanceTransactionError(
            "acceptance transition is malformed"
        ) from error

    lock_descriptor: int | None = None
    connection: sqlite3.Connection | None = None
    committed = False
    try:
        lock_descriptor, _ = evidence._borrow_or_acquire_target_lock(path, None)
        connection = evidence.connect_ledger(path)
        connection.execute("BEGIN IMMEDIATE")
        work_order = evidence.load_authoritative_work_order(connection)
        try:
            parsed.validate_against_work_order(work_order)
        except ValueError as error:
            raise AcceptanceTransactionError(str(error)) from error
        acceptor = next(
            binding
            for binding in work_order.key_bindings
            if binding.role == "Acceptor"
        )
        acceptor_key = decode_and_verify_key_binding(acceptor)
        if not verify_payload(
            "acceptance-transition",
            parsed.model_dump(mode="json"),
            acceptor_key,
        ):
            raise AcceptanceTransactionError(
                "acceptance transition signature is invalid"
            )
        acceptances = evidence._validated_acceptance_receipts(
            connection,
            work_order,
        )
        if len(acceptances) != 1:
            raise AcceptanceTransactionError(
                "transition requires one exact acceptance"
            )
        acceptance = acceptances[0]
        if (
            parsed.target_acceptance_id != acceptance.acceptance_id
            or parsed.target_acceptance_digest != acceptance.digest
        ):
            raise AcceptanceTransactionError(
                "transition target acceptance is not current"
            )
        current = _load_current_verification_decision(connection)
        if current is None:
            raise AcceptanceTransactionError(
                "transition verification decision is unavailable"
            )
        protocol_version, decision = current
        if (
            decision is None
            or parsed.verification_decision_id != decision.decision_id
            or parsed.verification_decision_digest != decision.digest
        ):
            raise AcceptanceTransactionError(
                "transition verification decision is not current"
            )
        if not (
            acceptance.accepted_at <= parsed.decided_at <= work_order.deadline
            and decision.decided_at <= parsed.decided_at
        ):
            raise AcceptanceTransactionError(
                "transition time is outside its authoritative history"
            )
        if (
            parsed.reason_code == "EVIDENCE_REFUTED"
            and decision.decision != "REFUTED"
        ) or (
            parsed.reason_code == "EVIDENCE_UNKNOWN"
            and decision.decision != "UNKNOWN"
        ):
            raise AcceptanceTransactionError(
                "transition reason does not match the current decision"
            )
        if protocol_version == "0.2":
            transition_table = "acceptance_transitions"
            parent_table = "acceptance_transition_parents"
            existing = connection.execute(
                f"""
                SELECT target_acceptance_id, verification_decision_id,
                       transition_json
                FROM {transition_table}
                WHERE transition_id = ?
                """,
                (parsed.transition_id,),
            ).fetchone()
            expected = (
                parsed.target_acceptance_id,
                parsed.verification_decision_id,
                rfc8785.dumps(parsed.model_dump(mode="json")),
            )
        else:
            transition_table = "acceptance_transitions_v03"
            parent_table = "acceptance_transition_parents_v03"
            existing = connection.execute(
                f"""
                SELECT transition_digest, target_acceptance_id,
                       verification_decision_id, transition_json
                FROM {transition_table}
                WHERE transition_id = ?
                """,
                (parsed.transition_id,),
            ).fetchone()
            expected = (
                parsed.digest,
                parsed.target_acceptance_id,
                parsed.verification_decision_id,
                rfc8785.dumps(parsed.model_dump(mode="json")),
            )
        if existing is not None:
            if existing == expected and _exact_acceptance_transition_readback(
                path,
                parsed,
            ):
                raise AcceptanceCommittedError(
                    "the exact acceptance transition is already committed",
                    parsed,
                )
            raise AcceptanceTransactionError(
                "acceptance transition id is already used"
            )
        if connection.execute(
            f"SELECT 1 FROM {transition_table} WHERE target_acceptance_id = ?",
            (parsed.target_acceptance_id,),
        ).fetchone() is not None:
            raise AcceptanceTransactionError(
                "acceptance already has a terminal transition"
            )
        verification._assert_nonce_unused(connection, parsed.nonce)
        if protocol_version == "0.2":
            connection.execute(
                f"""
                INSERT INTO {transition_table} (
                    transition_id, target_acceptance_id,
                    verification_decision_id, transition_json
                ) VALUES (?, ?, ?, ?)
                """,
                (parsed.transition_id, *expected),
            )
        else:
            connection.execute(
                f"""
                INSERT INTO {transition_table} (
                    transition_id, transition_digest, target_acceptance_id,
                    verification_decision_id, transition_json
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (parsed.transition_id, *expected),
            )
        for ordinal, parent_id in enumerate(parsed.causal_parent_ids):
            connection.execute(
                """
                INSERT INTO {parent_table} (
                    transition_id, ordinal, parent_id
                ) VALUES (?, ?, ?)
                """.format(parent_table=parent_table),
                (parsed.transition_id, ordinal, parent_id),
            )
        if fault == "before_commit":
            raise AcceptanceTransactionError("injected fault before commit")
        connection.execute("COMMIT")
        committed = True
        if fault == "commit_ack_loss":
            raise OSError("injected commit acknowledgement loss")
        if fault == "readback_failure":
            raise AcceptanceCommitIndeterminateError(
                "acceptance transition readback was unavailable"
            )
        if not _exact_acceptance_transition_readback(path, parsed):
            raise AcceptanceCommitIndeterminateError(
                "acceptance transition readback did not confirm commit"
            )
    except Exception as error:
        evidence._best_effort_rollback(connection)
        if isinstance(error, AcceptanceCommittedError):
            raise
        if isinstance(error, AcceptanceCommitIndeterminateError):
            raise
        if committed:
            if _exact_acceptance_transition_readback(path, parsed):
                raise AcceptanceCommittedError(
                    "acceptance transition committed but acknowledgement was lost",
                    parsed,
                ) from error
            raise AcceptanceCommitIndeterminateError(
                "acceptance transition commit outcome is indeterminate"
            ) from error
        if isinstance(error, AcceptanceTransactionError):
            raise
        raise AcceptanceTransactionError(
            "acceptance transition transaction failed"
        ) from error
    finally:
        close_error = evidence._best_effort_close(connection)
        _, release_errors = evidence._release_target_lock(lock_descriptor)
        cleanup_errors = tuple(
            item
            for item in (close_error, *release_errors)
            if item is not None
        )
    if fault == "cleanup_failure":
        cleanup_errors += (OSError("injected cleanup failure"),)
    if cleanup_errors:
        raise AcceptanceCommittedError(
            "acceptance transition committed but cleanup failed",
            parsed,
        ) from cleanup_errors[0]
    return parsed
