"""Evidence-gated task state transitions for protocol v0.1."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
from enum import StrEnum

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import ValidationError

from openworkproof.models import (
    ACTION_RECEIPT_ADAPTER,
    AcceptanceReceipt,
    ActionReceipt,
    ActionReceiptEnvelope,
    ApprovalDecisionReceipt,
    ApprovalRequestedReceipt,
    GrantConsumedReceipt,
    GrantIssuedReceipt,
    GrantRevokedReceipt,
    RollbackReceipt,
    RunTestsArguments,
    SystemEventReceipt,
    TerminationDecisionReceipt,
    TestsPassedPredicateInput,
    ToolCallReceipt,
    TransitionDecision,
    WorkOrder,
)
from openworkproof.signing import (
    verify_nested_claim,
    verify_payload,
    verify_work_order_identity_bindings,
)


class TaskState(StrEnum):
    ISSUED = "issued"
    RUNNING = "running"
    NEEDS_REWORK = "needs_rework"
    RETRYING = "retrying"
    LOCALLY_VERIFIED = "locally_verified"
    EVIDENCE_INCOMPLETE = "evidence_incomplete"
    PROOF_READY = "proof_ready"
    AWAITING_HUMAN = "awaiting_human"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    FROZEN = "frozen"


ALLOWED_TRANSITIONS: dict[TaskState, frozenset[TaskState]] = {
    TaskState.ISSUED: frozenset(
        {TaskState.RUNNING, TaskState.FROZEN, TaskState.REJECTED}
    ),
    TaskState.RUNNING: frozenset(
        {
            TaskState.NEEDS_REWORK,
            TaskState.LOCALLY_VERIFIED,
            TaskState.FROZEN,
            TaskState.REJECTED,
        }
    ),
    TaskState.NEEDS_REWORK: frozenset(
        {TaskState.RETRYING, TaskState.FROZEN, TaskState.REJECTED}
    ),
    TaskState.RETRYING: frozenset(
        {
            TaskState.NEEDS_REWORK,
            TaskState.LOCALLY_VERIFIED,
            TaskState.FROZEN,
            TaskState.REJECTED,
        }
    ),
    TaskState.LOCALLY_VERIFIED: frozenset(
        {
            TaskState.EVIDENCE_INCOMPLETE,
            TaskState.PROOF_READY,
            TaskState.FROZEN,
            TaskState.REJECTED,
        }
    ),
    TaskState.EVIDENCE_INCOMPLETE: frozenset(
        {TaskState.PROOF_READY, TaskState.FROZEN, TaskState.REJECTED}
    ),
    TaskState.PROOF_READY: frozenset(
        {TaskState.AWAITING_HUMAN, TaskState.FROZEN, TaskState.REJECTED}
    ),
    TaskState.AWAITING_HUMAN: frozenset(
        {TaskState.ACCEPTED, TaskState.FROZEN, TaskState.REJECTED}
    ),
    TaskState.ACCEPTED: frozenset(),
    TaskState.REJECTED: frozenset(),
    TaskState.FROZEN: frozenset({TaskState.REJECTED}),
}

_EXPIRABLE_STATES = frozenset(
    {
        TaskState.ISSUED,
        TaskState.RUNNING,
        TaskState.NEEDS_REWORK,
        TaskState.RETRYING,
        TaskState.LOCALLY_VERIFIED,
        TaskState.EVIDENCE_INCOMPLETE,
        TaskState.PROOF_READY,
        TaskState.AWAITING_HUMAN,
    }
)


def _allowed(reason: str) -> TransitionDecision:
    return TransitionDecision(allowed=True, error_code=None, reason=reason)


def _denied(code: str, reason: str) -> TransitionDecision:
    return TransitionDecision(allowed=False, error_code=code, reason=reason)


def _public_key(
    public_keys: Mapping[str, Ed25519PublicKey],
    key_id: str,
) -> Ed25519PublicKey | None:
    value = public_keys.get(key_id)
    return value if isinstance(value, Ed25519PublicKey) else None


def _work_order_is_trusted(
    work_order: WorkOrder,
    public_keys: Mapping[str, Ed25519PublicKey],
) -> bool:
    if not verify_work_order_identity_bindings(work_order):
        return False
    maintainer = work_order.key_bindings[0]
    public_key = _public_key(public_keys, maintainer.key_id)
    return public_key is not None and verify_payload(
        "work-order",
        work_order.model_dump(mode="json"),
        public_key,
    )


def _validate_action_receipt(
    receipt: ActionReceipt,
    work_order: WorkOrder,
    public_keys: Mapping[str, Ed25519PublicKey],
    now: datetime,
) -> ActionReceipt | None:
    try:
        parsed = ACTION_RECEIPT_ADAPTER.validate_python(
            receipt.model_dump(mode="json")
        )
        parsed.validate_against_work_order(work_order)
        if isinstance(parsed, ToolCallReceipt):
            parsed.validate_predicates_against(work_order)

        gateway_key = _public_key(public_keys, parsed.gateway_signer_key_id)
        if gateway_key is None or not verify_payload(
            "action-receipt",
            parsed.model_dump(mode="json"),
            gateway_key,
        ):
            return None
        if parsed.actor_type in {"agent", "human"}:
            actor_key = _public_key(public_keys, parsed.actor_key_id)
            domain = (
                "agent-request"
                if parsed.actor_type == "agent"
                else "human-decision"
            )
            if (
                actor_key is None
                or not verify_nested_claim(parsed.nested_claim, work_order)
                or not verify_payload(
                    domain,
                    parsed.nested_claim.model_dump(mode="json"),
                    actor_key,
                )
            ):
                return None

        if now.tzinfo is None or now.utcoffset() is None:
            return None
        normalized_now = now.astimezone(timezone.utc)
        if parsed.occurred_at > normalized_now:
            return None
        if parsed.sequence == 1 and (
            parsed.previous_receipt_digest is not None
            or parsed.parent_receipt_ids
        ):
            return None
        if parsed.sequence > 1 and parsed.previous_receipt_digest is None:
            return None
        return parsed
    except (AttributeError, TypeError, ValidationError, ValueError):
        return None


def _actor_role(receipt: ActionReceiptEnvelope, work_order: WorkOrder) -> str | None:
    for binding in work_order.key_bindings:
        if (
            binding.subject_id == receipt.actor_id
            and binding.key_id == receipt.actor_key_id
        ):
            return binding.role
    return None


def _agent_direct_call_is_authorized(
    receipt: ActionReceipt,
    work_order: WorkOrder,
) -> bool:
    role = _actor_role(receipt, work_order)
    tool_name = receipt.nested_claim.tool_name
    if role == "Manager":
        if isinstance(receipt, GrantIssuedReceipt):
            expected = (
                "owp.activate_root_grant"
                if receipt.parent_grant_id is None
                else "owp.delegate_grant"
            )
            return tool_name == expected
        if isinstance(receipt, GrantRevokedReceipt):
            return tool_name == "owp.revoke_grant"
        if isinstance(receipt, GrantConsumedReceipt):
            return tool_name == "owp.start_retry"
        if isinstance(receipt, ApprovalRequestedReceipt):
            expected = (
                "owp.request_acceptance"
                if receipt.request_kind == "final_acceptance"
                else "owp.request_pr_proposal"
            )
            return tool_name == expected
        return isinstance(receipt, ToolCallReceipt) and tool_name in {
            "owp.create_pr_proposal",
            "owp.compose_proof",
        }
    if role == "Developer":
        if isinstance(receipt, RollbackReceipt):
            return tool_name == "owp.rollback_patch"
        if not isinstance(receipt, ToolCallReceipt):
            return False
        if tool_name in {"owp.repo_read", "owp.apply_patch"}:
            return True
        return (
            tool_name == "owp.run_tests"
            and isinstance(receipt.request_arguments, RunTestsArguments)
            and receipt.request_arguments.test_mode == "developer"
        )
    if role == "Verifier":
        return (
            isinstance(receipt, ToolCallReceipt)
            and tool_name == "owp.run_tests"
            and isinstance(receipt.request_arguments, RunTestsArguments)
            and receipt.request_arguments.test_mode == "verifier"
        )
    return False


def _validate_acceptance(
    acceptance: AcceptanceReceipt,
    work_order: WorkOrder,
    public_keys: Mapping[str, Ed25519PublicKey],
    now: datetime,
) -> bool:
    try:
        parsed = AcceptanceReceipt.model_validate(
            acceptance.model_dump(mode="json")
        )
        parsed.validate_against_work_order(work_order)
        acceptor = work_order.key_bindings[5]
        public_key = _public_key(public_keys, acceptor.key_id)
        return (
            public_key is not None
            and verify_payload(
                "acceptance-receipt",
                parsed.model_dump(mode="json"),
                public_key,
            )
            and parsed.accepted_at <= now.astimezone(timezone.utc)
            and parsed.accepted_at <= work_order.deadline
        )
    except (AttributeError, TypeError, ValidationError, ValueError):
        return False


def _validate_verifier_transition(
    receipt: ToolCallReceipt,
    work_order: WorkOrder,
    state_after: TaskState,
) -> bool:
    if (
        not _agent_direct_call_is_authorized(receipt, work_order)
        or receipt.policy_decision != "allow"
        or receipt.execution_status != "succeeded"
    ):
        return False
    arguments = receipt.request_arguments
    profile = next(
        (
            profile
            for profile in work_order.test_profiles
            if profile.test_mode == "verifier"
        ),
        None,
    )
    if profile is None or (
        getattr(arguments, "test_mode", None),
        getattr(arguments, "command_digest", None),
        getattr(arguments, "source_commit", None),
        getattr(arguments, "container_image_digest", None),
        getattr(arguments, "fixed_test_source_digest", None),
    ) != (
        "verifier",
        profile.command_digest,
        work_order.source_commit,
        profile.container_image_digest,
        profile.fixed_test_source_digest,
    ):
        return False

    post_ids = {spec.predicate_id for spec in work_order.postconditions}
    post_results = [
        result
        for result in receipt.predicate_results
        if result.predicate_id in post_ids
    ]
    if len(post_results) != len(work_order.postconditions):
        return False
    tests_results = [
        result for result in post_results if result.name == "tests_passed"
    ]
    if len(tests_results) != 1 or not isinstance(
        tests_results[0].input,
        TestsPassedPredicateInput,
    ):
        return False
    test_result = tests_results[0]
    if state_after is TaskState.LOCALLY_VERIFIED:
        return all(result.passed for result in post_results) and (
            test_result.input.actual_exit_code
            == test_result.input.expected_exit_code
        )
    if state_after is TaskState.NEEDS_REWORK:
        return any(
            not result.passed and result.error_code == "PREDICATE_FALSE"
            for result in post_results
        )
    return False


def _validate_final_request(
    receipt: ApprovalRequestedReceipt,
    work_order: WorkOrder,
    now: datetime,
) -> bool:
    validity_seconds = (receipt.expires_at - receipt.occurred_at).total_seconds()
    return (
        _agent_direct_call_is_authorized(receipt, work_order)
        and receipt.request_kind == "final_acceptance"
        and receipt.nested_claim.tool_name == "owp.request_acceptance"
        and receipt.policy_decision == "allow"
        and receipt.execution_status == "succeeded"
        and 0 <= validity_seconds <= 3600
        and receipt.occurred_at <= now.astimezone(timezone.utc)
        and now.astimezone(timezone.utc) <= receipt.expires_at
        and receipt.expires_at <= work_order.deadline
    )


def _validate_termination(
    receipt: TerminationDecisionReceipt,
    work_order: WorkOrder,
    state_before: TaskState,
    now: datetime,
) -> bool:
    if now.tzinfo is None or now.utcoffset() is None:
        return False
    skew = abs((receipt.occurred_at - receipt.decided_at).total_seconds())
    deadline_valid = state_before is TaskState.FROZEN or (
        state_before in _EXPIRABLE_STATES
        and receipt.decided_at <= work_order.deadline
        and receipt.occurred_at <= work_order.deadline
    )
    return (
        _actor_role(receipt, work_order) == "Maintainer"
        and receipt.policy_decision == "allow"
        and receipt.execution_status == "succeeded"
        and receipt.target_work_order_digest == work_order.digest
        and receipt.decision == "rejected"
        and receipt.termination_reason == "MAINTAINER_REJECTED"
        and receipt.decided_at >= work_order.issued_at
        and receipt.occurred_at <= now.astimezone(timezone.utc)
        and skew <= 300
        and deadline_valid
    )


def _validate_contract_expiry(
    receipt: SystemEventReceipt,
    work_order: WorkOrder,
    now: datetime,
) -> bool:
    cause = receipt.cause
    return (
        receipt.system_event_name == "contract_expired"
        and receipt.error_code == "CONTRACT_EXPIRED"
        and getattr(cause, "deadline", None) == work_order.deadline
        and getattr(cause, "observed_at", None) == receipt.occurred_at
        and getattr(cause, "tip_receipt_digest", None)
        == receipt.previous_receipt_digest
        and receipt.occurred_at > work_order.deadline
        and now.astimezone(timezone.utc) > work_order.deadline
    )


def validate_transition_evidence(
    work_order: WorkOrder,
    state_before: TaskState,
    state_after: TaskState,
    trigger_receipt: ActionReceipt | None,
    acceptance_receipt: AcceptanceReceipt | None,
    public_keys: Mapping[str, Ed25519PublicKey],
    now: datetime,
) -> TransitionDecision:
    if (
        not isinstance(work_order, WorkOrder)
        or not isinstance(state_before, TaskState)
        or not isinstance(state_after, TaskState)
        or state_after not in ALLOWED_TRANSITIONS[state_before]
    ):
        return _denied("INVALID_TRANSITION", "transition is not adjacent")
    if (
        not isinstance(now, datetime)
        or now.tzinfo is None
        or now.utcoffset() is None
    ):
        return _denied("INVALID_EVIDENCE", "now must be timezone-aware")
    if not _work_order_is_trusted(work_order, public_keys):
        return _denied("INVALID_EVIDENCE", "WorkOrder trust failed")

    if state_after is TaskState.ACCEPTED:
        if (
            trigger_receipt is not None
            or not isinstance(acceptance_receipt, AcceptanceReceipt)
            or not _validate_acceptance(
                acceptance_receipt,
                work_order,
                public_keys,
                now,
            )
        ):
            return _denied("INVALID_EVIDENCE", "acceptance evidence is invalid")
        return _denied(
            "TRANSITION_CONTEXT_UNAVAILABLE",
            "acceptance ledger suffix is not available in Task 5",
        )

    if acceptance_receipt is not None or trigger_receipt is None:
        return _denied("INVALID_EVIDENCE", "action transition evidence is missing")
    receipt = _validate_action_receipt(
        trigger_receipt,
        work_order,
        public_keys,
        now,
    )
    if receipt is None or (
        receipt.state_before != state_before.value
        or receipt.state_after != state_after.value
    ):
        return _denied("INVALID_EVIDENCE", "receipt binding is invalid")

    if isinstance(receipt, SystemEventReceipt) and receipt.system_event_name in {
        "proof_composed",
        "security_violation",
    }:
        return _denied(
            "COMPOSITION_VALIDATOR_UNAVAILABLE",
            "composition recomputation is not available in Task 5",
        )

    if (
        isinstance(receipt, TerminationDecisionReceipt)
        and (
            state_before is TaskState.FROZEN
            or receipt.sequence > 1
        )
    ) or (
        receipt.sequence > 1
        and (
            isinstance(receipt, SystemEventReceipt)
            and receipt.system_event_name == "contract_expired"
        )
    ):
        return _denied(
            "TRANSITION_CONTEXT_UNAVAILABLE",
            "trusted chain tip is not available in Task 5",
        )

    if (
        state_before is TaskState.NEEDS_REWORK
        and state_after is TaskState.RETRYING
    ):
        if (
            not isinstance(receipt, GrantConsumedReceipt)
            or not _agent_direct_call_is_authorized(receipt, work_order)
            or receipt.metric != "repair_rounds"
            or receipt.amount != 1
        ):
            return _denied("INVALID_EVIDENCE", "retry charge is invalid")
        return _denied(
            "TRANSITION_CONTEXT_UNAVAILABLE",
            "failure episode and rollback history are unavailable in Task 5",
        )

    if state_before is TaskState.ISSUED and state_after is TaskState.RUNNING:
        root = work_order.root_grant_template
        if (
            isinstance(receipt, GrantIssuedReceipt)
            and _agent_direct_call_is_authorized(receipt, work_order)
            and receipt.parent_grant_id is None
            and receipt.authorizing_grant_id == root.grant_id
            and receipt.issued_grant_id == root.grant_id
            and receipt.nested_claim.tool_name == "owp.activate_root_grant"
        ):
            return _allowed("root Grant activated")
        return _denied("INVALID_EVIDENCE", "root activation evidence is invalid")

    if state_before in {TaskState.RUNNING, TaskState.RETRYING} and state_after in {
        TaskState.NEEDS_REWORK,
        TaskState.LOCALLY_VERIFIED,
    }:
        if isinstance(receipt, ToolCallReceipt) and _validate_verifier_transition(
            receipt,
            work_order,
            state_after,
        ):
            return _allowed("Verifier outcome authorizes transition")
        return _denied("INVALID_EVIDENCE", "Verifier evidence is invalid")

    if (
        state_before is TaskState.PROOF_READY
        and state_after is TaskState.AWAITING_HUMAN
    ):
        if isinstance(receipt, ApprovalRequestedReceipt) and _validate_final_request(
            receipt,
            work_order,
            now,
        ):
            return _denied(
                "TRANSITION_CONTEXT_UNAVAILABLE",
                "composition report and request history are unavailable in Task 5",
            )
        return _denied("INVALID_EVIDENCE", "final request evidence is invalid")

    if state_after is TaskState.REJECTED:
        if isinstance(receipt, TerminationDecisionReceipt) and _validate_termination(
            receipt,
            work_order,
            state_before,
            now,
        ):
            return _allowed("Maintainer terminated WorkOrder")
        return _denied("INVALID_EVIDENCE", "termination evidence is invalid")

    if state_after is TaskState.FROZEN:
        if isinstance(receipt, SystemEventReceipt) and _validate_contract_expiry(
            receipt,
            work_order,
            now,
        ):
            return _allowed("contract expiry observed")
        return _denied("INVALID_EVIDENCE", "freeze evidence is invalid")

    return _denied("INVALID_EVIDENCE", "transition evidence is unsupported")


def apply_state_transition(
    *,
    work_order: WorkOrder,
    state_before: TaskState,
    state_after: TaskState,
    trigger_receipt: ActionReceipt | None,
    acceptance_receipt: AcceptanceReceipt | None,
    public_keys: Mapping[str, Ed25519PublicKey],
    now: datetime,
) -> TransitionDecision:
    if state_before is state_after:
        return _denied(
            "STATE_CHANGE_REQUIRED",
            "same-state receipts use append_receipt",
        )
    return validate_transition_evidence(
        work_order,
        state_before,
        state_after,
        trigger_receipt,
        acceptance_receipt,
        public_keys,
        now,
    )


def append_receipt(
    *,
    work_order: WorkOrder,
    state: TaskState,
    receipt: ActionReceipt,
    public_keys: Mapping[str, Ed25519PublicKey],
    now: datetime,
) -> TransitionDecision:
    if not _work_order_is_trusted(work_order, public_keys):
        return _denied("INVALID_EVIDENCE", "WorkOrder trust failed")
    parsed = _validate_action_receipt(receipt, work_order, public_keys, now)
    if parsed is None:
        return _denied("INVALID_EVIDENCE", "receipt integrity failed")
    if parsed.state_before != state.value or parsed.state_after != state.value:
        return _denied(
            "TRANSITION_REQUIRED",
            "state-changing receipts use apply_state_transition",
        )
    if state in {TaskState.ACCEPTED, TaskState.REJECTED, TaskState.FROZEN}:
        return _denied("STATE_DENIED", "state does not accept same-state receipts")
    if parsed.policy_decision == "deny":
        return _allowed("authenticated same-state denial appended")
    role = _actor_role(parsed, work_order)
    if isinstance(
        parsed,
        (
            GrantIssuedReceipt,
            GrantConsumedReceipt,
            GrantRevokedReceipt,
            ToolCallReceipt,
            ApprovalRequestedReceipt,
            RollbackReceipt,
        ),
    ) and not _agent_direct_call_is_authorized(parsed, work_order):
        return _denied(
            "STATE_DENIED",
            "Agent direct call is outside the frozen role matrix",
        )
    if (
        isinstance(parsed, ToolCallReceipt)
        and parsed.tool_name == "owp.compose_proof"
        and role == "Manager"
        and state
        in {TaskState.LOCALLY_VERIFIED, TaskState.EVIDENCE_INCOMPLETE}
    ):
        return _denied(
            "COMPOSITION_VALIDATOR_UNAVAILABLE",
            "same-state composition requires canonical receipt history",
        )
    if state is TaskState.EVIDENCE_INCOMPLETE:
        if (
            isinstance(parsed, ToolCallReceipt)
            and parsed.tool_name == "owp.run_tests"
            and role == "Verifier"
        ):
            return _denied(
                "TRANSITION_CONTEXT_UNAVAILABLE",
                "same-state evidence requires unavailable episode history",
            )
        return _denied(
            "STATE_DENIED",
            "evidence-incomplete only accepts an independent Verifier rerun",
        )
    if state is TaskState.NEEDS_REWORK and isinstance(parsed, RollbackReceipt):
        return _denied(
            "TRANSITION_CONTEXT_UNAVAILABLE",
            "same-state evidence requires unavailable episode history",
        )
    if state in {TaskState.PROOF_READY, TaskState.AWAITING_HUMAN}:
        return _denied("STATE_DENIED", "human-gate tail forbids successful append")
    if isinstance(parsed, GrantConsumedReceipt):
        if state is TaskState.NEEDS_REWORK and role == "Manager":
            return _denied(
                "TRANSITION_REQUIRED",
                "retry charge must select the retrying state transition",
            )
        return _denied(
            "STATE_DENIED",
            "retry charge is not a same-state audit event",
        )
    grant_audit_states = {
        TaskState.RUNNING,
        TaskState.RETRYING,
        TaskState.NEEDS_REWORK,
    }
    if isinstance(parsed, GrantIssuedReceipt):
        if (
            parsed.parent_grant_id is not None
            and role == "Manager"
            and state in grant_audit_states
        ):
            return _allowed("child Grant issuance appended")
        return _denied(
            "STATE_DENIED",
            "child Grant issuance is outside its role or state window",
        )
    if isinstance(parsed, GrantRevokedReceipt):
        if role == "Manager" and state in grant_audit_states:
            return _allowed("Grant revocation appended")
        return _denied(
            "STATE_DENIED",
            "Grant revocation is outside its role or state window",
        )
    if isinstance(parsed, ToolCallReceipt):
        if state not in {TaskState.RUNNING, TaskState.RETRYING}:
            return _denied(
                "STATE_DENIED",
                "tool results are outside their state window",
            )
        if (
            parsed.tool_name == "owp.run_tests"
            and role == "Verifier"
            and parsed.execution_status == "succeeded"
        ):
            return _denied(
                "TRANSITION_REQUIRED",
                "normal Verifier result must select a state transition",
            )
        if parsed.tool_name in {
            "owp.repo_read",
            "owp.apply_patch",
            "owp.run_tests",
            "owp.create_pr_proposal",
        }:
            return _allowed("ordinary tool result appended")
        return _denied(
            "STATE_DENIED",
            "tool result is outside its role or tool window",
        )
    if (
        isinstance(parsed, ApprovalRequestedReceipt)
        and parsed.request_kind == "high_risk_action"
    ):
        if (
            state in {TaskState.RUNNING, TaskState.RETRYING}
            and role == "Manager"
        ):
            return _allowed("high-risk approval request appended")
        return _denied(
            "STATE_DENIED",
            "approval request is outside its role or state window",
        )
    if isinstance(parsed, ApprovalDecisionReceipt):
        if (
            state in {TaskState.RUNNING, TaskState.RETRYING}
            and role == "Maintainer"
        ):
            return _allowed("approval decision appended")
        return _denied(
            "STATE_DENIED",
            "approval decision is outside its role or state window",
        )
    return _denied("STATE_DENIED", "event is not a valid same-state append")


__all__ = [
    "ALLOWED_TRANSITIONS",
    "TaskState",
    "append_receipt",
    "apply_state_transition",
    "validate_transition_evidence",
]
