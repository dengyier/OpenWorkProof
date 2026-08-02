"""Immutable authorization policy replay for bounded signed histories."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
from itertools import islice
import json
import re

import rfc8785

from openworkproof.composition import (
    AuthorizationCausalSnapshot,
    AuthorizationCausalState,
    AuthorizationCausalityError,
    replay_authorization_causality,
    validate_authorization_causal_bindings,
)
from openworkproof.models import (
    ActionReceiptEnvelope,
    AgentRequest,
    ApplyPatchArguments,
    ApprovalHumanDecision,
    ApprovalDecisionReceipt,
    ApprovalRequestedReceipt,
    CapabilityGrant,
    EvidenceRef,
    GrantConsumedReceipt,
    GrantIssuedReceipt,
    GrantRevokedReceipt,
    KeyBinding,
    PatchResultEvidence,
    PolicyDecision,
    RepoReadArguments,
    RollbackReceipt,
    RunTestsArguments,
    SystemEventReceipt,
    TerminationHumanDecision,
    TerminationDecisionReceipt,
    ToolCallReceipt,
    ToolRequestArguments,
    WorkOrder,
    ComposeProofArguments,
    CreatePrProposalArguments,
    request_arguments_digest,
)
from openworkproof.repo_tools import (
    ReplayCheckpoint,
    workspace_manifest_digest,
)
from openworkproof.predicates import (
    EvaluationContext,
    evaluate_required_predicates,
    select_required_predicates,
)
from openworkproof.signing import (
    decode_and_verify_key_binding,
    verify_payload,
)
from openworkproof.state import (
    TaskState,
    _agent_direct_call_is_authorized,
    _validate_termination,
    append_receipt,
    apply_state_transition,
)


MAX_EFFECTIVE_GRANTS = 8
MAX_GRANT_ATTEMPTS = 8
MAX_AUTHORIZATION_RECEIPTS = 64
DENIAL_PRECEDENCE = (
    "STATE_DENIED",
    "ROLE_DENIED",
    "CAPABILITY_DENIED",
    "APPROVAL_DENIED",
    "PREDICATE_DENIED",
    "QUOTA_EXHAUSTED",
)


class AuthorizationPolicyError(RuntimeError):
    """The signed history cannot satisfy the frozen authorization policy."""


@dataclass(frozen=True, slots=True)
class AuthorizationLedgerPrefix:
    """Canonical bounded inputs for one live authorization transaction."""

    effective_grants: tuple[CapabilityGrant, ...]
    grant_attempts: tuple[CapabilityGrant, ...]
    receipts: tuple[ActionReceiptEnvelope, ...]

    def __post_init__(self) -> None:
        if any(
            type(value) is not tuple
            for value in (
                self.effective_grants,
                self.grant_attempts,
                self.receipts,
            )
        ):
            raise AuthorizationPolicyError(
                "live policy collections must be exact tuples"
            )
        if (
            len(self.effective_grants) > MAX_EFFECTIVE_GRANTS
            or len(self.grant_attempts) > MAX_GRANT_ATTEMPTS
            or len(self.receipts) > MAX_AUTHORIZATION_RECEIPTS
        ):
            raise AuthorizationPolicyError(
                "live policy collection exceeds its bounded capacity"
            )
        if any(
            not isinstance(grant, CapabilityGrant)
            for grant in self.effective_grants + self.grant_attempts
        ) or any(
            not isinstance(receipt, ActionReceiptEnvelope)
            for receipt in self.receipts
        ):
            raise AuthorizationPolicyError(
                "live policy collection contains a malformed entry"
            )
        grant_ids = tuple(
            grant.grant_id for grant in self.effective_grants
        )
        attempt_digests = tuple(
            grant.digest for grant in self.grant_attempts
        )
        if (
            grant_ids != tuple(sorted(grant_ids))
            or len(set(grant_ids)) != len(grant_ids)
            or attempt_digests != tuple(sorted(attempt_digests))
            or len(set(attempt_digests)) != len(attempt_digests)
        ):
            raise AuthorizationPolicyError(
                "live policy Grants are not canonical and unique"
            )


@dataclass(frozen=True, slots=True)
class CommittedEvidence:
    """Exact committed bytes paired with their signed evidence reference."""

    reference: EvidenceRef
    payload: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.reference, EvidenceRef) or type(
            self.payload
        ) is not bytes:
            raise AuthorizationPolicyError(
                "committed evidence entry is malformed"
            )


@dataclass(frozen=True)
class AuthorizationReplayState:
    """Immutable policy facts reconstructed from the signed receipt history."""

    active_patch_receipt_id: str | None
    balances: tuple[tuple[str, str, int], ...]
    revoked_grant_ids: tuple[str, ...]
    used_single_use_grant_ids: tuple[str, ...]
    approval_decision_by_request: tuple[tuple[str, str], ...]


@dataclass(frozen=True, slots=True)
class AuthorizationContext:
    """Verified immutable facts used by one live authorization decision."""

    work_order: WorkOrder
    ledger_prefix: AuthorizationLedgerPrefix
    committed_evidence: tuple[CommittedEvidence, ...]
    replay_checkpoint: ReplayCheckpoint
    transaction_time: datetime
    causal_state: AuthorizationCausalState
    replay_state: AuthorizationReplayState
    current_state: str
    routine_capacity_remaining: int
    denial_count: int
    independent_failure_terminal: bool

    @property
    def active_patch_receipt_id(self) -> str | None:
        return self.causal_state.active_patch_receipt_id


@dataclass(frozen=True, slots=True)
class ProspectiveExecutionFacts:
    """Sidecar-observed execution identity for a prospective test call."""

    execution_context_id: str
    container_instance_id_digest: str
    controller_id: str

    def __post_init__(self) -> None:
        digest = re.compile(r"^[0-9a-f]{64}$")
        key = re.compile(r"^ed25519:[0-9a-f]{64}$")
        if (
            type(self.execution_context_id) is not str
            or digest.fullmatch(self.execution_context_id) is None
            or type(self.container_instance_id_digest) is not str
            or digest.fullmatch(self.container_instance_id_digest) is None
            or type(self.controller_id) is not str
            or key.fullmatch(self.controller_id) is None
        ):
            raise AuthorizationPolicyError(
                "prospective execution facts are malformed"
            )


@dataclass(frozen=True)
class _GrantReplayState:
    remaining_tool_calls: int
    remaining_repair_rounds: int
    use_count: int
    revoked: bool


@dataclass(frozen=True)
class _GrantReplayContext:
    states_before_receipt: tuple[
        tuple[str, tuple[tuple[str, _GrantReplayState], ...]],
        ...,
    ]
    final_states: tuple[tuple[str, _GrantReplayState], ...]

    def state_before(
        self,
        receipt_id: str,
        grant_id: str,
    ) -> _GrantReplayState | None:
        for candidate_id, states in self.states_before_receipt:
            if candidate_id != receipt_id:
                continue
            return dict(states).get(grant_id)
        return None

    def final_by_grant(self) -> dict[str, _GrantReplayState]:
        return dict(self.final_states)


def _fail(message: str) -> AuthorizationPolicyError:
    return AuthorizationPolicyError(message)


def _validate_tool_authorization_inputs(
    context: AuthorizationContext,
    request: AgentRequest,
    request_arguments: ToolRequestArguments,
    execution_facts: ProspectiveExecutionFacts | None,
) -> tuple[CapabilityGrant, KeyBinding]:
    """Verify signed prospective inputs before any policy decision."""

    argument_tools = {
        RepoReadArguments: "owp.repo_read",
        ApplyPatchArguments: "owp.apply_patch",
        RunTestsArguments: "owp.run_tests",
        CreatePrProposalArguments: "owp.create_pr_proposal",
        ComposeProofArguments: "owp.compose_proof",
    }
    if type(context) is not AuthorizationContext:
        raise _fail("authorization context is malformed")
    if type(request) is not AgentRequest:
        raise _fail("Agent request is malformed")
    tool_name = argument_tools.get(type(request_arguments))
    if tool_name is None:
        raise _fail("tool request arguments are malformed")
    if execution_facts is not None and type(
        execution_facts
    ) is not ProspectiveExecutionFacts:
        raise _fail("prospective execution facts are malformed")
    if isinstance(request_arguments, RunTestsArguments):
        if execution_facts is None:
            raise _fail("test execution facts are required")
    elif execution_facts is not None:
        raise _fail("execution facts are forbidden for this tool")
    if (
        request.work_order_digest != context.work_order.digest
        or request.tool_name != tool_name
        or request.arguments_digest
        != request_arguments_digest(tool_name, request_arguments)
    ):
        raise _fail("Agent request integrity binding is invalid")

    grants = {
        grant.grant_id: grant
        for grant in context.ledger_prefix.effective_grants
    }
    grant = grants.get(request.grant_id)
    bindings = {
        binding.key_id: binding
        for binding in context.work_order.key_bindings
    }
    binding = bindings.get(request.actor_key_id)
    if (
        grant is None
        or binding is None
        or request.actor_id != binding.subject_id
        or grant.subject_key_id != binding.key_id
        or grant.subject_agent_id != binding.subject_id
    ):
        raise _fail("Agent request Grant or actor binding is invalid")
    try:
        public_key = decode_and_verify_key_binding(binding)
    except Exception as error:
        raise _fail("Agent request key binding is invalid") from error
    if not verify_payload(
        "agent-request",
        request.model_dump(mode="json"),
        public_key,
    ):
        raise _fail("Agent request signature is invalid")

    request_age = context.transaction_time - request.requested_at
    if request_age < timedelta(0) or request_age > timedelta(seconds=300):
        raise _fail("Agent request is outside the freshness window")

    if execution_facts is not None:
        sidecar_key_ids = {
            candidate.key_id
            for candidate in context.work_order.key_bindings
            if candidate.role == "Sidecar"
        }
        if execution_facts.controller_id not in sidecar_key_ids:
            raise _fail("prospective execution controller is not the Sidecar")
    return grant, binding


def _denial_code(
    *,
    state_allowed: bool,
    role_allowed: bool,
    capability_allowed: bool,
    approval_allowed: bool = True,
    predicate_allowed: bool = True,
    quota_allowed: bool = True,
) -> str | None:
    allowed = (
        state_allowed,
        role_allowed,
        capability_allowed,
        approval_allowed,
        predicate_allowed,
        quota_allowed,
    )
    return next(
        (
            error_code
            for error_code, condition in zip(
                DENIAL_PRECEDENCE,
                allowed,
                strict=True,
            )
            if not condition
        ),
        None,
    )


def _remaining_tool_calls(
    context: AuthorizationContext,
    grant_id: str,
) -> int:
    balances = {
        (candidate_id, metric): remaining
        for candidate_id, metric, remaining in context.replay_state.balances
    }
    try:
        return balances[(grant_id, "tool_calls")]
    except KeyError as error:
        raise _fail("effective Grant balance is unavailable") from error


def _policy_decision(error_code: str | None) -> PolicyDecision:
    return PolicyDecision(
        allowed=error_code is None,
        decision="allow" if error_code is None else "deny",
        error_code=error_code,
        reason=(
            "TOOL_CALL_AUTHORIZED"
            if error_code is None
            else "TOOL_CALL_DENIED"
        ),
    )


def _prospective_state_allowed(
    context: AuthorizationContext,
    tool_name: str,
    arguments: ToolRequestArguments,
) -> bool:
    if tool_name == "owp.repo_read":
        return context.current_state in {"running", "retrying"}
    if tool_name == "owp.apply_patch":
        return (
            context.current_state in {"running", "retrying"}
            and context.active_patch_receipt_id is None
        )
    if tool_name == "owp.run_tests":
        return context.current_state in {"running", "retrying"} or (
            context.current_state == "evidence_incomplete"
            and isinstance(arguments, RunTestsArguments)
            and arguments.test_mode == "verifier"
        )
    if tool_name == "owp.create_pr_proposal":
        return (
            context.current_state in {"running", "retrying"}
            and context.active_patch_receipt_id is not None
        )
    if tool_name == "owp.compose_proof":
        return (
            context.current_state
            in {"locally_verified", "evidence_incomplete"}
            and context.active_patch_receipt_id is not None
        )
    return False


def _prospective_role_allowed(
    role: str,
    tool_name: str,
    arguments: ToolRequestArguments,
) -> bool:
    if role == "Manager":
        return tool_name in {
            "owp.compose_proof",
            "owp.create_pr_proposal",
        }
    if role == "Developer":
        return tool_name in {"owp.apply_patch", "owp.repo_read"} or (
            tool_name == "owp.run_tests"
            and isinstance(arguments, RunTestsArguments)
            and arguments.test_mode == "developer"
        )
    if role == "Verifier":
        return (
            tool_name == "owp.run_tests"
            and isinstance(arguments, RunTestsArguments)
            and arguments.test_mode == "verifier"
        )
    return False


def _static_predicates_allowed(
    context: AuthorizationContext,
    grant: CapabilityGrant,
    arguments: ToolRequestArguments,
    execution_facts: ProspectiveExecutionFacts | None,
) -> bool:
    if isinstance(arguments, RepoReadArguments):
        return _roots_within((arguments.path,), grant.allowed_read_roots)
    if isinstance(arguments, ApplyPatchArguments):
        return _roots_within(
            arguments.target_paths,
            grant.allowed_write_roots,
        )
    if not isinstance(arguments, RunTestsArguments):
        return True
    if execution_facts is None or context.active_patch_receipt_id is None:
        return False
    profiles = tuple(
        profile
        for profile in context.work_order.test_profiles
        if profile.test_mode == arguments.test_mode
    )
    if len(profiles) != 1:
        return False
    profile = profiles[0]
    if (
        arguments.command_digest != profile.command_digest
        or arguments.source_commit != context.work_order.source_commit
        or arguments.candidate_commit
        != context.replay_checkpoint.head_commit
        or arguments.workspace_manifest_digest
        != context.replay_checkpoint.workspace_manifest_digest
        or arguments.container_image_digest
        != profile.container_image_digest
        or arguments.fixed_test_source_digest
        != profile.fixed_test_source_digest
    ):
        return False
    used_execution_contexts: set[str] = set()
    used_container_instances: set[str] = set()
    for receipt in context.ledger_prefix.receipts:
        if not isinstance(receipt, ToolCallReceipt):
            continue
        if receipt.tool_name != "owp.run_tests":
            continue
        factors = receipt.correlation_factors
        if factors.execution_context_id is not None:
            used_execution_contexts.add(factors.execution_context_id)
        if factors.container_instance_id_digest is not None:
            used_container_instances.add(
                factors.container_instance_id_digest
            )
    if (
        execution_facts.execution_context_id in used_execution_contexts
        or execution_facts.container_instance_id_digest
        in used_container_instances
    ):
        return False
    return not (
        arguments.test_mode == "verifier"
        and context.causal_state.independent_result_receipt_id is not None
    )


def _prospective_approval_allowed(
    context: AuthorizationContext,
    tool_name: str,
    arguments: ToolRequestArguments,
) -> bool:
    if tool_name != "owp.create_pr_proposal":
        return True
    if not isinstance(arguments, CreatePrProposalArguments):
        return False
    by_id = {
        receipt.receipt_id: receipt
        for receipt in context.ledger_prefix.receipts
    }
    patch = by_id.get(context.active_patch_receipt_id)
    decision = by_id.get(arguments.approval_receipt_id)
    request = (
        by_id.get(decision.request_receipt_id)
        if isinstance(decision, ApprovalDecisionReceipt)
        else None
    )
    decisions = dict(context.replay_state.approval_decision_by_request)
    return (
        isinstance(patch, ToolCallReceipt)
        and patch.tool_name == "owp.apply_patch"
        and isinstance(decision, ApprovalDecisionReceipt)
        and isinstance(request, ApprovalRequestedReceipt)
        and decisions.get(request.receipt_id) == decision.receipt_id
        and arguments.target_patch_digest == patch.digest
        and arguments.approval_receipt_digest == decision.digest
        and decision.request_receipt_digest == request.digest
        and decision.decision == "approved"
        and decision.policy_decision == "allow"
        and decision.execution_status == "succeeded"
        and request.request_kind == "high_risk_action"
        and request.requested_scope["work_order_digest"]
        == context.work_order.digest
        and request.requested_scope["target_patch_digest"]
        == patch.digest
        and decision.approved_scope == request.requested_scope
        and context.transaction_time <= request.expires_at
        and context.transaction_time <= decision.expires_at
    )


def _compose_arguments_allowed(
    context: AuthorizationContext,
    tool_name: str,
    arguments: ToolRequestArguments,
) -> bool:
    if tool_name != "owp.compose_proof":
        return True
    if not isinstance(arguments, ComposeProofArguments) or (
        arguments.expected_state_version
        != len(context.ledger_prefix.receipts)
    ):
        return False
    if context.current_state == "locally_verified":
        return arguments.previous_report_digest is None
    if context.current_state != "evidence_incomplete":
        return False
    by_id = {
        receipt.receipt_id: receipt
        for receipt in context.ledger_prefix.receipts
    }
    trigger = by_id.get(
        context.causal_state.latest_composition_trigger_id
    )
    independent = by_id.get(
        context.causal_state.independent_result_receipt_id
    )
    return (
        isinstance(trigger, SystemEventReceipt)
        and trigger.system_event_name == "proof_composed"
        and isinstance(independent, ToolCallReceipt)
        and independent.tool_name == "owp.run_tests"
        and arguments.previous_report_digest
        == trigger.cause.composition_report_digest
    )


def authorize_tool_call(
    context: AuthorizationContext,
    request: AgentRequest,
    request_arguments: ToolRequestArguments,
    execution_facts: ProspectiveExecutionFacts | None = None,
) -> PolicyDecision:
    """Decide prospective handler eligibility without mutating authority."""

    grant, binding = _validate_tool_authorization_inputs(
        context,
        request,
        request_arguments,
        execution_facts,
    )
    if context.transaction_time > context.work_order.deadline:
        raise _fail("contract expired before tool authorization")
    if context.routine_capacity_remaining <= 0:
        raise _fail("routine Receipt capacity is exhausted")
    if context.independent_failure_terminal:
        raise _fail("EVIDENCE_FAILURE_SEALED")

    capability_allowed = (
        request.tool_name in context.work_order.allowed_tools
        and request.tool_name in grant.allowed_tools
        and grant.grant_id not in context.replay_state.revoked_grant_ids
        and grant.valid_from
        <= context.transaction_time
        <= min(grant.expires_at, context.work_order.deadline)
    )
    error_code = _denial_code(
        state_allowed=_prospective_state_allowed(
            context,
            request.tool_name,
            request_arguments,
        ),
        role_allowed=_prospective_role_allowed(
            binding.role,
            request.tool_name,
            request_arguments,
        ),
        capability_allowed=capability_allowed,
        approval_allowed=_prospective_approval_allowed(
            context,
            request.tool_name,
            request_arguments,
        ),
        predicate_allowed=(
            _static_predicates_allowed(
                context,
                grant,
                request_arguments,
                execution_facts,
            )
            and _compose_arguments_allowed(
                context,
                request.tool_name,
                request_arguments,
            )
        ),
        quota_allowed=_remaining_tool_calls(context, grant.grant_id) > 0,
    )
    return _policy_decision(error_code)


def validate_human_decision(
    context: AuthorizationContext,
    claim: ApprovalHumanDecision | TerminationHumanDecision,
) -> PolicyDecision:
    """Decide a signed human claim without mutating authority."""

    if type(context) is not AuthorizationContext or type(claim) not in {
        ApprovalHumanDecision,
        TerminationHumanDecision,
    }:
        raise _fail("human decision inputs are malformed")
    if claim.work_order_digest != context.work_order.digest:
        raise _fail("human decision WorkOrder binding is invalid")

    bindings = tuple(
        binding
        for binding in context.work_order.key_bindings
        if binding.key_id == claim.actor_key_id
    )
    if (
        len(bindings) != 1
        or claim.actor_id != bindings[0].subject_id
        or claim.signer_key_id != bindings[0].key_id
    ):
        raise _fail("human decision actor binding is invalid")
    binding = bindings[0]
    try:
        public_key = decode_and_verify_key_binding(binding)
    except Exception as error:
        raise _fail("human decision key binding is invalid") from error
    if not verify_payload(
        "human-decision",
        claim.model_dump(mode="json"),
        public_key,
    ):
        raise _fail("human decision signature is invalid")

    ingestion_age = context.transaction_time - claim.decided_at
    if ingestion_age < timedelta(0) or ingestion_age > timedelta(seconds=300):
        raise _fail("human decision freshness window is invalid")

    if isinstance(claim, TerminationHumanDecision):
        if (
            claim.target_work_order_digest != context.work_order.digest
            or claim.decided_at < context.work_order.issued_at
        ):
            raise _fail("human termination binding is invalid")
        error_code = _denial_code(
            state_allowed=context.current_state
            not in {"accepted", "rejected"},
            role_allowed=binding.role == "Maintainer",
            capability_allowed=True,
        )
        return _policy_decision(error_code)

    request = next(
        (
            receipt
            for receipt in context.ledger_prefix.receipts
            if receipt.receipt_id == claim.request_receipt_id
        ),
        None,
    )
    if (
        not isinstance(request, ApprovalRequestedReceipt)
        or request.policy_decision != "allow"
        or request.execution_status != "succeeded"
        or request.request_kind != "high_risk_action"
        or request.digest != claim.request_receipt_digest
        or request.requested_scope != claim.approved_scope
        or request.expires_at != claim.expires_at
        or claim.decided_at < request.occurred_at
        or claim.decided_at > request.expires_at
    ):
        raise _fail("human approval binding is invalid")
    if claim.request_receipt_id in dict(
        context.replay_state.approval_decision_by_request
    ):
        raise _fail("human approval request already has a decision")

    error_code = _denial_code(
        state_allowed=context.current_state in {"running", "retrying"},
        role_allowed=binding.role == request.required_role,
        capability_allowed=True,
        approval_allowed=(
            claim.decision == "approved"
            and context.transaction_time <= claim.expires_at
        ),
    )
    return _policy_decision(error_code)


def _bounded_mapping(
    value: Mapping[str, CapabilityGrant],
    *,
    cap: int,
    label: str,
) -> dict[str, CapabilityGrant]:
    if not isinstance(value, Mapping):
        raise _fail(f"{label} must be a mapping")
    try:
        items = tuple(islice(value.items(), cap + 1))
    except AuthorizationPolicyError:
        raise
    except Exception as error:
        raise _fail(f"{label} input is unavailable") from error
    if len(items) > cap:
        raise _fail(f"{label} exceeds its bounded capacity")
    snapshot: dict[str, CapabilityGrant] = {}
    for key, grant in items:
        if (
            type(key) is not str
            or not isinstance(grant, CapabilityGrant)
            or key in snapshot
        ):
            raise _fail(f"{label} contains a malformed entry")
        snapshot[key] = grant
    return snapshot


def _bounded_receipts(
    receipts: Iterable[ActionReceiptEnvelope],
) -> tuple[ActionReceiptEnvelope, ...]:
    try:
        bounded = tuple(
            islice(receipts, MAX_AUTHORIZATION_RECEIPTS + 1)
        )
    except AuthorizationPolicyError:
        raise
    except Exception as error:
        raise _fail("receipt history input is unavailable") from error
    if len(bounded) > MAX_AUTHORIZATION_RECEIPTS:
        raise _fail("receipt history exceeds its bounded capacity")
    if any(
        not isinstance(receipt, ActionReceiptEnvelope)
        for receipt in bounded
    ):
        raise _fail("receipt history contains a malformed receipt")
    return bounded


def _validate_grant_signatures(
    work_order: WorkOrder,
    grants: Mapping[str, CapabilityGrant],
    attempts: Mapping[str, CapabilityGrant],
) -> None:
    try:
        bindings_by_key = {
            binding.key_id: (
                binding,
                decode_and_verify_key_binding(binding),
            )
            for binding in work_order.key_bindings
        }
    except Exception as error:
        raise _fail("Grant signature key bindings are unavailable") from error
    if len(bindings_by_key) != len(work_order.key_bindings):
        raise _fail("Grant signature key bindings are not unique")

    def validate_grant(
        grant: CapabilityGrant,
        *,
        issuer_roles: set[str],
        subject_roles: set[str],
    ) -> None:
        issuer_entry = bindings_by_key.get(grant.issuer_key_id)
        subject_entry = bindings_by_key.get(grant.subject_key_id)
        if (
            grant.work_order_digest != work_order.digest
            or issuer_entry is None
            or issuer_entry[0].role not in issuer_roles
            or grant.signer_key_id != grant.issuer_key_id
            or subject_entry is None
            or subject_entry[0].subject_id
            != grant.subject_agent_id
            or subject_entry[0].role not in subject_roles
            or not verify_payload(
                "capability-grant",
                grant.model_dump(mode="json"),
                issuer_entry[1],
            )
        ):
            raise _fail("Grant signature or role binding is invalid")

    for grant in grants.values():
        validate_grant(
            grant,
            issuer_roles={
                "Maintainer"
                if grant.parent_grant_id is None
                else "Manager"
            },
            subject_roles=(
                {"Manager"}
                if grant.parent_grant_id is None
                else {"Developer", "Verifier"}
            ),
        )
    for grant in attempts.values():
        validate_grant(
            grant,
            issuer_roles=(
                {"Maintainer"}
                if grant.parent_grant_id is None
                else {"Manager", "Developer", "Verifier"}
            ),
            subject_roles=(
                {"Manager"}
                if grant.parent_grant_id is None
                else {"Developer", "Verifier"}
            ),
        )


def _root_contains(root: str, candidate: str) -> bool:
    return candidate == root or candidate.startswith(f"{root}/")


def _roots_within(
    candidates: tuple[str, ...],
    allowed: tuple[str, ...],
) -> bool:
    return all(
        any(_root_contains(root, candidate) for root in allowed)
        for candidate in candidates
    )


def _child_signing_binding(
    work_order: WorkOrder,
    candidate: CapabilityGrant,
):
    matches = tuple(
        binding
        for binding in work_order.key_bindings
        if binding.key_id == candidate.signer_key_id
    )
    if len(matches) != 1:
        raise _fail("child Grant signer binding is unavailable")
    return matches[0]


def _request_matches_candidate_issuer(request, binding) -> bool:
    return (
        request.actor_id == binding.subject_id
        and request.actor_key_id == binding.key_id
        and request.signer_key_id == binding.key_id
    )


def _child_policy_decision(
    work_order: WorkOrder,
    parent: CapabilityGrant,
    parent_state: _GrantReplayState | None,
    candidate: CapabilityGrant,
    request,
    signing_binding,
    bindings: Mapping[str, object],
    now,
    *,
    state_allowed: bool,
) -> tuple[bool, str | None]:
    manager = bindings["Manager"]
    developer = bindings["Developer"]
    verifier = bindings["Verifier"]
    matching_subjects = tuple(
        binding
        for binding in (developer, verifier)
        if (
            candidate.subject_agent_id == binding.subject_id
            and candidate.subject_key_id == binding.key_id
        )
    )
    authority_valid = (
        signing_binding.role == "Manager"
        and signing_binding.key_id == manager.key_id
        and parent.subject_agent_id == manager.subject_id
        and parent.subject_key_id == manager.key_id
        and request.actor_id == manager.subject_id
        and request.actor_key_id == manager.key_id
    )
    role_allowed = authority_valid and len(matching_subjects) == 1
    tools_valid = (
        set(candidate.allowed_tools) <= set(parent.allowed_tools)
        and set(candidate.allowed_tools) <= set(work_order.allowed_tools)
    )
    roots_valid = (
        _roots_within(
            candidate.allowed_read_roots,
            parent.allowed_read_roots,
        )
        and _roots_within(
            candidate.allowed_read_roots,
            work_order.allowed_read_roots,
        )
        and _roots_within(
            candidate.allowed_write_roots,
            parent.allowed_write_roots,
        )
        and _roots_within(
            candidate.allowed_write_roots,
            work_order.allowed_write_roots,
        )
    )
    subject = matching_subjects[0] if len(matching_subjects) == 1 else None
    role_tools = (
        {"owp.run_tests"}
        if subject is not None and subject.role == "Verifier"
        else {
            "owp.apply_patch",
            "owp.repo_read",
            "owp.rollback_patch",
            *(
                ("owp.run_tests",)
                if any(
                    profile.test_mode == "developer"
                    for profile in work_order.test_profiles
                )
                else ()
            ),
        }
    )
    time_valid = (
        work_order.issued_at
        <= candidate.issued_at
        <= candidate.valid_from
        < candidate.expires_at
        == work_order.deadline
        and parent.valid_from
        <= candidate.issued_at
        <= candidate.valid_from
        < candidate.expires_at
        <= parent.expires_at
        and parent.valid_from <= now <= parent.expires_at
        and 0 <= (now - candidate.issued_at).total_seconds() <= 300
    )
    rights_valid = (
        candidate.may_delegate is False
        and candidate.usage_mode in {"single_use", "metered"}
    )
    quota_valid = (
        parent_state is not None
        and candidate.quota.tool_calls
        <= parent_state.remaining_tool_calls
        and candidate.quota.repair_rounds
        <= parent_state.remaining_repair_rounds
    )
    capability_valid = (
        parent_state is not None
        and not parent_state.revoked
        and subject is not None
        and tools_valid
        and set(candidate.allowed_tools) <= role_tools
        and roots_valid
        and not (
            subject is not None
            and subject.role == "Verifier"
            and candidate.allowed_write_roots
        )
        and time_valid
        and rights_valid
    )
    error_code = _denial_code(
        state_allowed=state_allowed,
        role_allowed=role_allowed,
        capability_allowed=capability_valid,
        quota_allowed=quota_valid,
    )
    return error_code is None, error_code


def _replay_grant_context(
    work_order: WorkOrder,
    receipts: Iterable[ActionReceiptEnvelope],
    grants: Mapping[str, CapabilityGrant],
) -> _GrantReplayContext:
    mutable: dict[str, dict[str, int | bool]] = {}
    states_before_receipt: list[
        tuple[str, tuple[tuple[str, _GrantReplayState], ...]]
    ] = []

    def frozen_states() -> tuple[tuple[str, _GrantReplayState], ...]:
        return tuple(
            (
                grant_id,
                _GrantReplayState(
                    remaining_tool_calls=int(state["tool_calls"]),
                    remaining_repair_rounds=int(
                        state["repair_rounds"]
                    ),
                    use_count=int(state["use_count"]),
                    revoked=bool(state["revoked"]),
                ),
            )
            for grant_id, state in sorted(mutable.items())
        )

    def add_grant(grant: CapabilityGrant) -> None:
        if grant.grant_id in mutable:
            raise _fail("Grant quota replay encountered duplicate authority")
        mutable[grant.grant_id] = {
            "tool_calls": grant.quota.tool_calls,
            "repair_rounds": grant.quota.repair_rounds,
            "use_count": 0,
            "revoked": False,
        }

    def consume_authority(grant: CapabilityGrant) -> None:
        state = mutable.get(grant.grant_id)
        if state is None or state["revoked"] is True:
            raise _fail("Grant quota replay references inactive authority")
        if grant.usage_mode == "single_use" and state["use_count"] != 0:
            raise _fail("single-use Grant was consumed more than once")
        state["use_count"] = int(state["use_count"]) + 1

    def validate_direct_call(receipt, *, require_active: bool):
        grant = grants.get(receipt.grant_id)
        state = mutable.get(receipt.grant_id)
        request = receipt.nested_claim
        elapsed = (
            receipt.occurred_at - request.requested_at
        ).total_seconds()
        if (
            grant is None
            or state is None
            or receipt.actor_id != grant.subject_agent_id
            or receipt.actor_key_id != grant.subject_key_id
            or request.actor_id != grant.subject_agent_id
            or request.actor_key_id != grant.subject_key_id
            or request.signer_key_id != grant.subject_key_id
            or request.grant_id != grant.grant_id
            or request.work_order_digest != work_order.digest
            or request.requested_at < work_order.issued_at
            or request.requested_at > work_order.deadline
            or receipt.occurred_at < work_order.issued_at
            or receipt.occurred_at > work_order.deadline
            or elapsed < 0
            or elapsed > 300
        ):
            raise _fail("Grant call binding failed semantic replay")
        role_authorized = _agent_direct_call_is_authorized(
            receipt,
            work_order,
        )
        if require_active and not role_authorized:
            raise _fail("Grant direct-call role failed semantic replay")
        if require_active and (
            state["revoked"] is True
            or request.tool_name not in grant.allowed_tools
            or request.requested_at < grant.valid_from
            or request.requested_at > grant.expires_at
            or receipt.occurred_at < grant.valid_from
            or receipt.occurred_at > grant.expires_at
        ):
            raise _fail("Grant charge authority failed semantic replay")
        return grant, state, role_authorized

    charge_types = (
        GrantConsumedReceipt,
        ToolCallReceipt,
        ApprovalRequestedReceipt,
        RollbackReceipt,
    )
    for receipt in receipts:
        states_before_receipt.append(
            (receipt.receipt_id, frozen_states())
        )
        if isinstance(receipt, GrantIssuedReceipt):
            if (
                receipt.policy_decision != "allow"
                or receipt.execution_status != "succeeded"
            ):
                continue
            grant = grants.get(receipt.issued_grant_id)
            if grant is None:
                raise _fail("Grant quota replay cannot resolve issuance")
            if grant.parent_grant_id is None:
                add_grant(grant)
                continue
            parent = grants.get(grant.parent_grant_id)
            parent_state = mutable.get(grant.parent_grant_id)
            if parent is None or parent_state is None:
                raise _fail(
                    "Grant quota replay references non-prior parent"
                )
            consume_authority(parent)
            for metric in ("tool_calls", "repair_rounds"):
                remaining = int(parent_state[metric]) - getattr(
                    grant.quota,
                    metric,
                )
                if remaining < 0:
                    raise _fail("Grant quota replay over-allocates parent")
                parent_state[metric] = remaining
            add_grant(grant)
            continue
        if isinstance(receipt, GrantRevokedReceipt):
            if (
                receipt.policy_decision != "allow"
                or receipt.execution_status != "succeeded"
            ):
                if receipt.quota_charge is not None:
                    raise _fail("denied Grant receipt cannot charge quota")
                continue
            authorizer = grants.get(receipt.authorizing_grant_id)
            target_state = mutable.get(receipt.revoked_grant_id)
            if authorizer is None or target_state is None:
                raise _fail(
                    "Grant quota replay cannot resolve revocation"
                )
            consume_authority(authorizer)
            target_state["revoked"] = True
            continue
        if not isinstance(receipt, charge_types):
            if (
                receipt.policy_decision == "deny"
                and receipt.quota_charge is not None
            ):
                raise _fail("denied Grant receipt cannot charge quota")
            continue
        if receipt.policy_decision == "deny":
            if receipt.quota_charge is not None:
                raise _fail("denied Grant receipt cannot charge quota")
            if (
                isinstance(receipt, GrantConsumedReceipt)
                and receipt.amount != 1
            ):
                raise _fail(
                    "start_retry must consume exactly one repair round"
                )
            validate_direct_call(
                receipt,
                require_active=False,
            )
            continue
        charge = receipt.quota_charge
        if charge is None:
            raise _fail("started Grant receipt must charge quota")
        if (
            isinstance(receipt, GrantConsumedReceipt)
            and receipt.amount != 1
        ):
            raise _fail("start_retry must consume exactly one repair round")
        grant, state, _ = validate_direct_call(
            receipt,
            require_active=True,
        )
        if charge.grant_id != grant.grant_id:
            raise _fail("Grant charge does not match direct call")
        remaining = int(state[charge.metric])
        if charge.amount > remaining:
            raise _fail("Grant quota is exhausted")
        expected_after = remaining - charge.amount
        if charge.remaining_after != expected_after:
            raise _fail(
                "Grant quota remaining_after failed semantic replay"
            )
        consume_authority(grant)
        state[charge.metric] = expected_after
    if set(mutable) != set(grants):
        raise _fail("Grant quota replay is incomplete")
    return _GrantReplayContext(
        states_before_receipt=tuple(states_before_receipt),
        final_states=frozen_states(),
    )


def _replay_grant_quota_history(
    work_order: WorkOrder,
    receipts: Iterable[ActionReceiptEnvelope],
    grants: Mapping[str, CapabilityGrant],
) -> dict[str, _GrantReplayState]:
    return _replay_grant_context(
        work_order,
        receipts,
        grants,
    ).final_by_grant()


def _grant_history_replay_context(
    work_order: WorkOrder,
    receipts: Iterable[ActionReceiptEnvelope],
    grants: Mapping[str, CapabilityGrant],
    attempts: Mapping[str, CapabilityGrant],
) -> _GrantReplayContext:
    history = tuple(receipts)
    replay_context = _replay_grant_context(
        work_order,
        history,
        grants,
    )
    bindings = {
        binding.role: binding for binding in work_order.key_bindings
    }
    manager = bindings["Manager"]
    prior_effective: dict[str, CapabilityGrant] = {}
    seen_attempts: set[str] = set()
    revoked_grants: set[str] = set()
    root_seen = False
    for receipt in history:
        if isinstance(receipt, GrantRevokedReceipt):
            authorizer = prior_effective.get(
                receipt.authorizing_grant_id
            )
            target = prior_effective.get(receipt.revoked_grant_id)
            request = receipt.nested_claim
            binding_invalid = (
                authorizer is None
                or authorizer.parent_grant_id is not None
                or target is None
                or target.parent_grant_id != authorizer.grant_id
                or target.grant_id in revoked_grants
                or receipt.state_before != receipt.state_after
                or receipt.actor_id != manager.subject_id
                or receipt.actor_key_id != manager.key_id
                or request.actor_id != manager.subject_id
                or request.actor_key_id != manager.key_id
                or request.signer_key_id != manager.key_id
                or request.work_order_digest != work_order.digest
                or request.grant_id != authorizer.grant_id
                or request.tool_name != "owp.revoke_grant"
                or request.requested_at < work_order.issued_at
                or request.requested_at > work_order.deadline
                or receipt.occurred_at < request.requested_at
                or (
                    receipt.occurred_at - request.requested_at
                ).total_seconds()
                > 300
                or receipt.occurred_at > work_order.deadline
            )
            allowed_invalid = (
                receipt.policy_decision == "allow"
                and (
                    receipt.policy_error_code is not None
                    or receipt.execution_status != "succeeded"
                    or receipt.execution_error_code is not None
                    or request.requested_at < authorizer.valid_from
                    or request.requested_at > authorizer.expires_at
                    or receipt.occurred_at < authorizer.valid_from
                    or receipt.occurred_at > authorizer.expires_at
                )
            )
            denied_invalid = (
                receipt.policy_decision == "deny"
                and (
                    receipt.policy_error_code is None
                    or receipt.execution_status != "denied"
                    or receipt.execution_error_code is not None
                    or receipt.quota_charge is not None
                )
            )
            if (
                binding_invalid
                or allowed_invalid
                or denied_invalid
                or receipt.policy_decision not in {"allow", "deny"}
            ):
                raise _fail(
                    "Grant revocation history failed semantic replay"
                )
            if receipt.policy_decision == "allow":
                revoked_grants.add(target.grant_id)
            continue
        if not isinstance(receipt, GrantIssuedReceipt):
            continue
        if receipt.parent_grant_id is None:
            root = grants.get(receipt.issued_grant_id)
            request = receipt.nested_claim
            if (
                root_seen
                or receipt.sequence != 1
                or root is None
                or root.parent_grant_id is not None
                or receipt.candidate_grant_digest != root.digest
                or receipt.actor_id != manager.subject_id
                or receipt.actor_key_id != manager.key_id
                or not _request_matches_candidate_issuer(
                    request,
                    manager,
                )
                or request.work_order_digest != work_order.digest
                or request.grant_id != root.grant_id
                or request.tool_name != "owp.activate_root_grant"
                or request.requested_at < work_order.issued_at
                or request.requested_at > work_order.deadline
                or request.requested_at < root.valid_from
                or request.requested_at > root.expires_at
                or receipt.occurred_at < request.requested_at
                or (
                    receipt.occurred_at - request.requested_at
                ).total_seconds()
                > 300
                or receipt.occurred_at < root.valid_from
                or receipt.occurred_at > root.expires_at
            ):
                raise _fail(
                    "root activation history failed semantic replay"
                )
            root_seen = True
            prior_effective[root.grant_id] = root
            continue
        parent = prior_effective.get(receipt.parent_grant_id)
        candidate = (
            grants.get(receipt.issued_grant_id)
            if receipt.policy_decision == "allow"
            else attempts.get(receipt.candidate_grant_digest)
        )
        if parent is None or candidate is None:
            raise _fail("Grant history references non-prior authority")
        signing_binding = _child_signing_binding(
            work_order,
            candidate,
        )
        request = receipt.nested_claim
        if (
            receipt.actor_id != signing_binding.subject_id
            or receipt.actor_key_id != signing_binding.key_id
            or not _request_matches_candidate_issuer(
                request,
                signing_binding,
            )
            or candidate.parent_grant_id != parent.grant_id
            or request.work_order_digest != work_order.digest
            or request.grant_id != parent.grant_id
            or request.tool_name != "owp.delegate_grant"
            or request.requested_at < work_order.issued_at
            or request.requested_at > work_order.deadline
            or receipt.occurred_at < request.requested_at
            or (
                receipt.occurred_at - request.requested_at
            ).total_seconds()
            > 300
        ):
            raise _fail(
                "Grant history request binding failed semantic replay"
            )
        allowed, error_code = _child_policy_decision(
            work_order,
            parent,
            replay_context.state_before(
                receipt.receipt_id,
                parent.grant_id,
            ),
            candidate,
            request,
            signing_binding,
            bindings,
            receipt.occurred_at,
            state_allowed=(
                receipt.state_before == receipt.state_after
                and receipt.state_before
                in {"running", "retrying", "needs_rework"}
            ),
        )
        if receipt.policy_decision == "allow":
            if (
                not allowed
                or error_code is not None
                or receipt.policy_error_code is not None
                or receipt.execution_status != "succeeded"
                or receipt.issued_grant_id != candidate.grant_id
            ):
                raise _fail(
                    "allowed Grant history fails policy replay"
                )
            prior_effective[candidate.grant_id] = candidate
        else:
            if (
                allowed
                or error_code is None
                or receipt.policy_error_code != error_code
                or receipt.execution_status != "denied"
            ):
                raise _fail(
                    "denied Grant history fails policy replay"
                )
            seen_attempts.add(candidate.digest)
    if (
        not root_seen
        or set(prior_effective) != set(grants)
        or seen_attempts != set(attempts)
    ):
        raise _fail("Grant history replay is incomplete")
    return replay_context


def _validate_grant_history_semantics(
    work_order: WorkOrder,
    receipts: Iterable[ActionReceiptEnvelope],
    grants: Mapping[str, CapabilityGrant],
    attempts: Mapping[str, CapabilityGrant],
) -> dict[str, _GrantReplayState]:
    return _grant_history_replay_context(
        work_order,
        receipts,
        grants,
        attempts,
    ).final_by_grant()


def _validate_state_history(
    work_order: WorkOrder,
    receipts: tuple[ActionReceiptEnvelope, ...],
    causal_state: AuthorizationCausalState,
) -> None:
    try:
        public_keys = {
            binding.key_id: decode_and_verify_key_binding(binding)
            for binding in work_order.key_bindings
        }
    except Exception as error:
        raise _fail(
            "WorkOrder key bindings are unavailable for state replay"
        ) from error
    for receipt in receipts:
        receipt_causal_state = causal_state.snapshot_for(
            receipt.receipt_id
        )
        state_before = TaskState(receipt.state_before)
        state_after = TaskState(receipt.state_after)
        decision = (
            append_receipt(
                work_order=work_order,
                state=state_before,
                receipt=receipt,
                public_keys=public_keys,
                now=receipt.occurred_at,
            )
            if state_before is state_after
            else apply_state_transition(
                work_order=work_order,
                state_before=state_before,
                state_after=state_after,
                trigger_receipt=receipt,
                acceptance_receipt=None,
                public_keys=public_keys,
                now=receipt.occurred_at,
            )
        )
        if decision.allowed:
            continue
        if decision.error_code in {
            "COMPOSITION_VALIDATOR_UNAVAILABLE",
            "TRANSITION_CONTEXT_UNAVAILABLE",
        }:
            if (
                isinstance(receipt, ToolCallReceipt)
                and _tool_state_context_exception(
                    work_order,
                    receipt,
                    receipt_causal_state,
                )
            ):
                continue
            if isinstance(
                receipt,
                (
                    GrantConsumedReceipt,
                    RollbackReceipt,
                    SystemEventReceipt,
                ),
            ):
                continue
        if (
            isinstance(receipt, TerminationDecisionReceipt)
            and _validate_termination(
                receipt,
                work_order,
                state_before,
                receipt.occurred_at,
            )
        ):
            continue
        raise _fail("receipt is denied by the frozen state machine")


def _tool_predicates(
    work_order: WorkOrder,
    receipt: ToolCallReceipt,
    grant: CapabilityGrant,
    state: _GrantReplayState,
) -> tuple[tuple, bool]:
    test_mode = (
        receipt.request_arguments.test_mode
        if isinstance(receipt.request_arguments, RunTestsArguments)
        else "developer"
    )
    selected = select_required_predicates(
        work_order=work_order,
        tool_name=receipt.tool_name,
        policy_decision=receipt.policy_decision,
        execution_status=receipt.execution_status,
        test_mode=test_mode,
    )
    supplied = {
        result.predicate_id: result
        for result in receipt.predicate_results
    }
    authoritative: dict[str, object] = {}
    child_scope_allowed = True
    for spec in selected:
        result = supplied.get(spec.predicate_id)
        if result is None:
            raise _fail("tool predicate set is incomplete")
        if spec.name == "tool_allowed":
            value: object = {"actual_tool_name": receipt.tool_name}
        elif spec.name == "quota_remaining":
            value = {
                "grant_id": grant.grant_id,
                "metric": "tool_calls",
                "amount": 1,
                "grant_remaining_before": state.remaining_tool_calls,
                "ledger_prefix_digest": receipt.previous_receipt_digest,
            }
        elif spec.name == "path_allowed":
            path_input = result.input
            if isinstance(receipt.request_arguments, ApplyPatchArguments):
                requested = receipt.request_arguments.target_paths
                child_roots = grant.allowed_write_roots
            elif isinstance(receipt.request_arguments, RepoReadArguments):
                requested = (receipt.request_arguments.path,)
                child_roots = grant.allowed_read_roots
            else:
                raise _fail("path predicate request type is unavailable")
            resolved = tuple(
                item.resolved_relative_path
                for item in path_input.resolved_entries
            )
            child_scope_allowed = (
                path_input.requested_paths == tuple(requested)
                and tuple(
                    item.requested_path
                    for item in path_input.resolved_entries
                )
                == tuple(requested)
                and path_input.resolution_manifest_digest is not None
                and all(
                    any(_root_contains(root, path) for root in child_roots)
                    for path in requested
                )
                and all(
                    path is not None
                    and any(
                        _root_contains(root, path)
                        for root in child_roots
                    )
                    for path in resolved
                )
            )
            value = {
                "requested_paths": list(requested),
                "resolved_entries": [
                    item.model_dump(mode="json")
                    for item in path_input.resolved_entries
                ],
                "resolution_manifest_digest": (
                    path_input.resolution_manifest_digest
                ),
            }
        elif spec.name == "tests_passed":
            arguments = receipt.request_arguments
            profile = next(
                (
                    item
                    for item in work_order.test_profiles
                    if item.test_mode == "verifier"
                ),
                None,
            )
            if (
                not isinstance(arguments, RunTestsArguments)
                or profile is None
            ):
                raise _fail(
                    "Verifier predicate authority is unavailable"
                )
            value = {
                **result.input.model_dump(mode="json"),
                "command_digest": profile.command_digest,
                "expected_exit_code": profile.expected_exit_code,
                "source_commit": arguments.source_commit,
                "candidate_commit": arguments.candidate_commit,
                "workspace_manifest_digest": (
                    arguments.workspace_manifest_digest
                ),
                "container_image_digest": profile.container_image_digest,
                "fixed_test_source_digest": (
                    profile.fixed_test_source_digest
                ),
            }
        else:
            raise _fail("tool predicate has no offline authority rule")
        authoritative[spec.predicate_id] = value
    evaluated = evaluate_required_predicates(
        selected,
        EvaluationContext(
            inputs={
                result.predicate_id: result.input
                for result in receipt.predicate_results
            },
            authoritative_inputs=authoritative,
            authoritative_ledger_prefix_digests={
                grant.grant_id: receipt.previous_receipt_digest,
            },
        ),
    )
    if evaluated != receipt.predicate_results:
        raise _fail(
            "tool PredicateResults failed exact historical replay"
        )
    return evaluated, child_scope_allowed


def _approval_allowed(
    receipt: ToolCallReceipt,
    prior: Mapping[str, ActionReceiptEnvelope],
    decisions: Mapping[str, str],
) -> bool:
    if receipt.tool_name != "owp.create_pr_proposal":
        return True
    decision = prior.get(receipt.approval_receipt_id)
    request = (
        prior.get(decision.request_receipt_id)
        if isinstance(decision, ApprovalDecisionReceipt)
        else None
    )
    requested_at = receipt.nested_claim.requested_at
    return (
        isinstance(decision, ApprovalDecisionReceipt)
        and isinstance(request, ApprovalRequestedReceipt)
        and decisions.get(request.receipt_id) == decision.receipt_id
        and receipt.approval_receipt_digest == decision.digest
        and decision.request_receipt_digest == request.digest
        and decision.decision == "approved"
        and decision.policy_decision == "allow"
        and decision.execution_status == "succeeded"
        and request.request_kind == "high_risk_action"
        and request.requested_scope["work_order_digest"]
        == receipt.work_order_digest
        and request.requested_scope["target_patch_digest"]
        == receipt.request_arguments.target_patch_digest
        and decision.approved_scope == request.requested_scope
        and requested_at <= decision.expires_at
        and requested_at <= request.expires_at
        and receipt.occurred_at <= decision.expires_at
        and receipt.occurred_at <= request.expires_at
    )


def _tool_state_allowed(
    work_order: WorkOrder,
    receipt: ToolCallReceipt,
    causal_state: AuthorizationCausalSnapshot,
) -> bool:
    state_before = receipt.state_before
    if receipt.tool_name == "owp.compose_proof":
        if receipt.state_after != state_before:
            return False
        if state_before == "locally_verified":
            return (
                causal_state.active_patch_receipt_id
                in receipt.parent_receipt_ids
            )
        if state_before != "evidence_incomplete":
            return False
        return (
            causal_state.latest_composition_trigger_id
            in receipt.parent_receipt_ids
            and causal_state.independent_result_receipt_id
            in receipt.parent_receipt_ids
        )
    if (
        receipt.tool_name == "owp.run_tests"
        and state_before == "evidence_incomplete"
    ):
        if receipt.state_after != state_before:
            return False
        role = next(
            (
                binding.role
                for binding in work_order.key_bindings
                if (
                    binding.subject_id == receipt.actor_id
                    and binding.key_id == receipt.actor_key_id
                )
            ),
            None,
        )
        test_results = tuple(
            result
            for result in receipt.predicate_results
            if result.name == "tests_passed"
        )
        tests_passed = bool(test_results) and all(
            result.passed for result in test_results
        )
        result_binding_valid = (
            causal_state.independent_result_receipt_id
            == receipt.receipt_id
            if tests_passed
            else causal_state.independent_result_receipt_id is None
        )
        return (
            role == "Verifier"
            and causal_state.active_patch_receipt_id
            in receipt.parent_receipt_ids
            and causal_state.latest_composition_trigger_id
            in receipt.parent_receipt_ids
            and result_binding_valid
        )
    return state_before in {"running", "retrying"}


def _tool_state_context_exception(
    work_order: WorkOrder,
    receipt: ToolCallReceipt,
    causal_state: AuthorizationCausalSnapshot,
) -> bool:
    is_context_dependent = (
        receipt.tool_name == "owp.compose_proof"
        and receipt.state_before
        in {"locally_verified", "evidence_incomplete"}
    ) or (
        receipt.tool_name == "owp.run_tests"
        and receipt.state_before == "evidence_incomplete"
    )
    return (
        is_context_dependent
        and receipt.state_after == receipt.state_before
        and _tool_state_allowed(work_order, receipt, causal_state)
    )


def _validate_policy_history(
    work_order: WorkOrder,
    receipts: tuple[ActionReceiptEnvelope, ...],
    grants: Mapping[str, CapabilityGrant],
    replay_context: _GrantReplayContext,
    causal_state: AuthorizationCausalState,
) -> None:
    prior: dict[str, ActionReceiptEnvelope] = {}

    for receipt in receipts:
        receipt_causal_state = causal_state.snapshot_for(
            receipt.receipt_id
        )
        decisions = dict(
            receipt_causal_state.approval_decision_by_request
        )
        if isinstance(receipt, GrantIssuedReceipt):
            prior[receipt.receipt_id] = receipt
            continue
        if isinstance(receipt, GrantRevokedReceipt):
            grant = grants.get(receipt.authorizing_grant_id)
            state = replay_context.state_before(
                receipt.receipt_id,
                receipt.authorizing_grant_id,
            )
            target = replay_context.state_before(
                receipt.receipt_id,
                receipt.revoked_grant_id,
            )
            request = receipt.nested_claim
            expected = _denial_code(
                state_allowed=receipt.state_before
                in {"running", "retrying", "needs_rework"},
                role_allowed=(
                    grant is not None
                    and state is not None
                    and receipt.actor_id == grant.subject_agent_id
                    and receipt.actor_key_id == grant.subject_key_id
                    and _agent_direct_call_is_authorized(
                        receipt,
                        work_order,
                    )
                ),
                capability_allowed=(
                    grant is not None
                    and state is not None
                    and target is not None
                    and state.revoked is False
                    and request.tool_name in grant.allowed_tools
                    and grant.valid_from
                    <= request.requested_at
                    <= receipt.occurred_at
                    <= grant.expires_at
                ),
            )
            if receipt.policy_decision == "deny":
                if receipt.policy_error_code != expected:
                    raise _fail(
                        "revocation denial failed historical policy replay"
                    )
            else:
                if expected is not None:
                    raise _fail(
                        "allowed revocation failed historical policy replay"
                    )
            prior[receipt.receipt_id] = receipt
            continue
        if isinstance(
            receipt,
            (GrantConsumedReceipt, ApprovalRequestedReceipt, RollbackReceipt),
        ):
            grant = grants.get(receipt.grant_id)
            state = replay_context.state_before(
                receipt.receipt_id,
                receipt.grant_id,
            )
            request = receipt.nested_claim
            if (
                isinstance(receipt, ApprovalRequestedReceipt)
                and receipt.request_kind == "high_risk_action"
                and grant is not None
            ):
                gate = work_order.approval_gates[0]
                maximum_expiry = min(
                    receipt.occurred_at
                    + timedelta(seconds=gate.max_validity_seconds),
                    grant.expires_at,
                    work_order.deadline,
                )
                if receipt.expires_at > maximum_expiry:
                    raise _fail(
                        "approval request validity exceeds protocol cap"
                    )
            if isinstance(receipt, GrantConsumedReceipt):
                state_allowed = receipt.state_before == "needs_rework"
                quota_metric = "repair_rounds"
            elif isinstance(receipt, ApprovalRequestedReceipt):
                state_allowed = (
                    receipt.state_before in {"running", "retrying"}
                    if receipt.request_kind == "high_risk_action"
                    else receipt.state_before == "proof_ready"
                )
                quota_metric = "tool_calls"
            else:
                state_allowed = receipt.state_before == "needs_rework"
                quota_metric = "tool_calls"
            expected = _denial_code(
                state_allowed=state_allowed,
                role_allowed=(
                    grant is not None
                    and state is not None
                    and receipt.actor_id == grant.subject_agent_id
                    and receipt.actor_key_id == grant.subject_key_id
                    and _agent_direct_call_is_authorized(
                        receipt,
                        work_order,
                    )
                ),
                capability_allowed=(
                    grant is not None
                    and state is not None
                    and state.revoked is False
                    and request.tool_name in grant.allowed_tools
                    and grant.valid_from
                    <= request.requested_at
                    <= receipt.occurred_at
                    <= grant.expires_at
                ),
                quota_allowed=(
                    state is not None
                    and (
                        state.remaining_repair_rounds
                        if quota_metric == "repair_rounds"
                        else state.remaining_tool_calls
                    )
                    > 0
                ),
            )
            if receipt.policy_decision == "deny":
                if receipt.policy_error_code != expected:
                    raise _fail(
                        "non-tool denial failed historical policy replay"
                    )
            else:
                if expected is not None:
                    raise _fail(
                        "allowed non-tool action failed policy replay"
                    )
            prior[receipt.receipt_id] = receipt
            continue
        if isinstance(receipt, ToolCallReceipt):
            grant = grants.get(receipt.grant_id)
            state = replay_context.state_before(
                receipt.receipt_id,
                receipt.grant_id,
            )
            if grant is None or state is None:
                raise _fail(
                    "tool receipt references a never-effective Grant"
                )
            evaluated, child_scope_allowed = _tool_predicates(
                work_order,
                receipt,
                grant,
                state,
            )
            request = receipt.nested_claim
            role_allowed = (
                receipt.actor_id == grant.subject_agent_id
                and receipt.actor_key_id == grant.subject_key_id
                and _agent_direct_call_is_authorized(
                    receipt,
                    work_order,
                )
            )
            capability_allowed = (
                state.revoked is False
                and receipt.tool_name in grant.allowed_tools
                and child_scope_allowed
                and grant.valid_from
                <= request.requested_at
                <= receipt.occurred_at
                <= grant.expires_at
            )
            expected = _denial_code(
                state_allowed=_tool_state_allowed(
                    work_order,
                    receipt,
                    receipt_causal_state,
                ),
                role_allowed=role_allowed,
                capability_allowed=capability_allowed,
                approval_allowed=_approval_allowed(
                    receipt,
                    prior,
                    decisions,
                ),
                predicate_allowed=all(
                    item.passed
                    for item in evaluated
                    if item.name != "tests_passed"
                ),
                quota_allowed=state.remaining_tool_calls > 0,
            )
            if receipt.policy_decision == "deny":
                if receipt.policy_error_code != expected:
                    raise _fail(
                        "tool denial failed historical policy replay"
                    )
            else:
                if expected is not None:
                    raise _fail(
                        "allowed tool failed historical policy replay"
                    )
            prior[receipt.receipt_id] = receipt
            continue
        if isinstance(receipt, ApprovalDecisionReceipt):
            request = prior.get(receipt.request_receipt_id)
            approved = receipt.decision == "approved"
            expected_decision_id = (
                decisions.get(request.receipt_id)
                if isinstance(request, ApprovalRequestedReceipt)
                else None
            )
            if (
                not isinstance(request, ApprovalRequestedReceipt)
                or expected_decision_id != receipt.receipt_id
                or request.digest != receipt.request_receipt_digest
                or request.requested_scope != receipt.approved_scope
                or request.expires_at != receipt.expires_at
                or approved
                != (
                    receipt.policy_decision == "allow"
                    and receipt.execution_status == "succeeded"
                )
                or (
                    not approved
                    and (
                        receipt.policy_decision != "deny"
                        or receipt.execution_status != "denied"
                    )
                )
                or receipt.decided_at < request.occurred_at
                or receipt.decided_at > request.expires_at
                or receipt.occurred_at < receipt.decided_at
                or (
                    receipt.occurred_at - receipt.decided_at
                ).total_seconds()
                > 300
            ):
                raise _fail("Human approval failed historical replay")
        elif isinstance(receipt, TerminationDecisionReceipt):
            if (
                receipt.target_work_order_digest != work_order.digest
                or receipt.decided_at < work_order.issued_at
                or receipt.occurred_at < receipt.decided_at
                or (
                    receipt.occurred_at - receipt.decided_at
                ).total_seconds()
                > 300
            ):
                raise _fail("Human termination failed historical replay")
        prior[receipt.receipt_id] = receipt


def replay_authorization_policy(
    work_order: WorkOrder,
    grants: Mapping[str, CapabilityGrant],
    attempts: Mapping[str, CapabilityGrant],
    receipts: Iterable[ActionReceiptEnvelope],
    causal_state: AuthorizationCausalState,
) -> AuthorizationReplayState:
    """Replay the bounded authorization policy without external state."""

    if (
        not isinstance(work_order, WorkOrder)
        or not isinstance(causal_state, AuthorizationCausalState)
    ):
        raise _fail("authorization policy inputs are unavailable")
    effective = _bounded_mapping(
        grants,
        cap=MAX_EFFECTIVE_GRANTS,
        label="effective Grants",
    )
    denied = _bounded_mapping(
        attempts,
        cap=MAX_GRANT_ATTEMPTS,
        label="Grant attempts",
    )
    bounded = _bounded_receipts(receipts)
    _validate_grant_signatures(work_order, effective, denied)
    try:
        validate_authorization_causal_bindings(
            work_order,
            bounded,
            causal_state,
        )
    except AuthorizationCausalityError as error:
        raise _fail(str(error)) from error
    decision_pairs = causal_state.approval_decision_by_request
    replay_context = _grant_history_replay_context(
        work_order,
        bounded,
        effective,
        denied,
    )
    quota_states = replay_context.final_by_grant()
    _validate_policy_history(
        work_order,
        bounded,
        effective,
        replay_context,
        causal_state,
    )
    _validate_state_history(work_order, bounded, causal_state)
    balances = tuple(
        entry
        for grant_id, state in sorted(quota_states.items())
        for entry in (
            (grant_id, "repair_rounds", state.remaining_repair_rounds),
            (grant_id, "tool_calls", state.remaining_tool_calls),
        )
    )
    return AuthorizationReplayState(
        active_patch_receipt_id=causal_state.active_patch_receipt_id,
        balances=balances,
        revoked_grant_ids=tuple(
            sorted(
                grant_id
                for grant_id, state in quota_states.items()
                if state.revoked
            )
        ),
        used_single_use_grant_ids=tuple(
            sorted(
                grant_id
                for grant_id, state in quota_states.items()
                if effective[grant_id].usage_mode == "single_use"
                and state.use_count > 0
            )
        ),
        approval_decision_by_request=decision_pairs,
    )


def _validate_committed_evidence(
    work_order: WorkOrder,
    ledger_prefix: AuthorizationLedgerPrefix,
    committed_evidence: tuple[CommittedEvidence, ...],
) -> dict[str, CommittedEvidence]:
    committed_paths = tuple(
        item.reference.path for item in committed_evidence
    )
    if (
        committed_paths
        != tuple(sorted(committed_paths, key=lambda value: value.encode()))
        or len(set(committed_paths)) != len(committed_paths)
    ):
        raise _fail("committed evidence is not canonical and unique")

    expected_by_path: dict[str, EvidenceRef] = {}
    for receipt in ledger_prefix.receipts:
        for reference in receipt.evidence_refs:
            if reference.path in expected_by_path:
                raise _fail("receipt evidence coverage is not one-to-one")
            expected_by_path[reference.path] = reference
    committed_by_path = {
        item.reference.path: item for item in committed_evidence
    }
    if set(committed_by_path) != set(expected_by_path):
        raise _fail("committed evidence coverage is not exact")

    artifacts = {
        f"{work_order.evidence_policy.evidence_root}/{artifact.path}": artifact
        for artifact in work_order.evidence_policy.artifacts
    }
    for path, expected_reference in expected_by_path.items():
        item = committed_by_path[path]
        artifact = artifacts.get(path)
        if artifact is None:
            raise _fail("committed evidence path is outside the allowlist")
        if item.reference != expected_reference:
            raise _fail("committed evidence reference does not match receipt")
        if item.reference.media_type != artifact.media_type:
            raise _fail("committed evidence media type is invalid")
        if item.reference.size_bytes > artifact.max_size_bytes:
            raise _fail("committed evidence exceeds its artifact limit")
        if len(item.payload) != item.reference.size_bytes:
            raise _fail("committed evidence size does not match reference")
        if (
            hashlib.sha256(item.payload).hexdigest()
            != item.reference.sha256
        ):
            raise _fail("committed evidence digest does not match bytes")
        if item.reference.media_type == "application/json":
            try:
                decoded = json.loads(item.payload)
                canonical = rfc8785.dumps(decoded)
            except (TypeError, ValueError, UnicodeDecodeError) as error:
                raise _fail("committed JSON evidence is invalid") from error
            if canonical != item.payload:
                raise _fail("committed JSON evidence is not RFC 8785 canonical")
    return committed_by_path


def _validate_replay_checkpoint(
    work_order: WorkOrder,
    ledger_prefix: AuthorizationLedgerPrefix,
    committed_by_path: Mapping[str, CommittedEvidence],
    replay_checkpoint: ReplayCheckpoint,
    active_patch_receipt_id: str | None,
) -> None:
    try:
        actual_manifest_digest = workspace_manifest_digest(
            replay_checkpoint.workspace_manifest
        )
    except Exception as error:
        raise _fail("replay checkpoint manifest is invalid") from error
    if (
        replay_checkpoint.workspace_manifest.head_commit
        != replay_checkpoint.head_commit
        or replay_checkpoint.workspace_manifest_digest
        != actual_manifest_digest
    ):
        raise _fail("replay checkpoint manifest binding is invalid")
    if active_patch_receipt_id is None:
        if replay_checkpoint.head_commit != work_order.source_commit:
            raise _fail("source replay checkpoint head is invalid")
        return

    active_patch = next(
        (
            receipt
            for receipt in ledger_prefix.receipts
            if receipt.receipt_id == active_patch_receipt_id
        ),
        None,
    )
    if (
        not isinstance(active_patch, ToolCallReceipt)
        or active_patch.tool_name != "owp.apply_patch"
        or active_patch.policy_decision != "allow"
        or active_patch.execution_status != "succeeded"
        or not isinstance(active_patch.request_arguments, ApplyPatchArguments)
    ):
        raise _fail("active patch checkpoint origin is invalid")
    artifacts = {
        f"{work_order.evidence_policy.evidence_root}/{artifact.path}": artifact
        for artifact in work_order.evidence_policy.artifacts
    }
    result_refs = tuple(
        reference
        for reference in active_patch.evidence_refs
        if artifacts.get(reference.path) is not None
        and artifacts[reference.path].purpose == "patch_result"
    )
    if len(result_refs) != 1:
        raise _fail("active patch evidence has no unique result")
    result_ref = result_refs[0]
    committed_result = committed_by_path.get(result_ref.path)
    if committed_result is None:
        raise _fail("active patch result evidence is unavailable")
    try:
        patch_result = PatchResultEvidence.model_validate_json(
            committed_result.payload
        )
    except (TypeError, ValueError) as error:
        raise _fail("active patch result evidence is invalid") from error
    if (
        active_patch.output_digest != result_ref.sha256
        or patch_result.patch_digest
        != active_patch.request_arguments.patch_digest
        or patch_result.patch_size_bytes
        != active_patch.request_arguments.patch_size_bytes
        or patch_result.replay_profile_digest
        != work_order.replay_profile_digest
        or patch_result.candidate_commit != replay_checkpoint.head_commit
        or patch_result.workspace_manifest_digest
        != replay_checkpoint.workspace_manifest_digest
    ):
        raise _fail("active patch checkpoint binding is invalid")


def derive_authorization_context(
    work_order: WorkOrder,
    ledger_prefix: AuthorizationLedgerPrefix,
    committed_evidence: tuple[CommittedEvidence, ...],
    replay_checkpoint: ReplayCheckpoint,
    transaction_time: datetime,
) -> AuthorizationContext:
    """Derive live policy facts from one closed, signed ledger snapshot."""

    if (
        not isinstance(work_order, WorkOrder)
        or not isinstance(ledger_prefix, AuthorizationLedgerPrefix)
        or type(committed_evidence) is not tuple
        or any(
            not isinstance(item, CommittedEvidence)
            for item in committed_evidence
        )
        or not isinstance(replay_checkpoint, ReplayCheckpoint)
    ):
        raise _fail("live authorization context inputs are unavailable")
    if (
        not isinstance(transaction_time, datetime)
        or transaction_time.tzinfo is None
        or transaction_time.utcoffset() != timedelta(0)
        or transaction_time.microsecond != 0
    ):
        raise _fail("transaction time must be a trusted UTC second")
    canonical_time = transaction_time.astimezone(timezone.utc)
    earliest_time = (
        ledger_prefix.receipts[-1].occurred_at
        if ledger_prefix.receipts
        else work_order.issued_at
    )
    if canonical_time < earliest_time:
        raise _fail("transaction time precedes the signed ledger prefix")

    effective_grants = {
        grant.grant_id: grant
        for grant in ledger_prefix.effective_grants
    }
    grant_attempts = {
        grant.digest: grant
        for grant in ledger_prefix.grant_attempts
    }
    try:
        causal_state = replay_authorization_causality(
            work_order,
            ledger_prefix.receipts,
        )
    except AuthorizationCausalityError as error:
        raise _fail(str(error)) from error
    replay_state = replay_authorization_policy(
        work_order,
        effective_grants,
        grant_attempts,
        ledger_prefix.receipts,
        causal_state,
    )
    committed_by_path = _validate_committed_evidence(
        work_order,
        ledger_prefix,
        committed_evidence,
    )
    _validate_replay_checkpoint(
        work_order,
        ledger_prefix,
        committed_by_path,
        replay_checkpoint,
        causal_state.active_patch_receipt_id,
    )
    current_state = (
        ledger_prefix.receipts[-1].state_after
        if ledger_prefix.receipts
        else "issued"
    )
    return AuthorizationContext(
        work_order=work_order,
        ledger_prefix=ledger_prefix,
        committed_evidence=committed_evidence,
        replay_checkpoint=replay_checkpoint,
        transaction_time=canonical_time,
        causal_state=causal_state,
        replay_state=replay_state,
        current_state=current_state,
        routine_capacity_remaining=max(
            0,
            61 - len(ledger_prefix.receipts),
        ),
        denial_count=sum(
            receipt.policy_decision == "deny"
            for receipt in ledger_prefix.receipts
        ),
        independent_failure_terminal=(
            causal_state.independent_failure_terminal
        ),
    )


__all__ = [
    "AuthorizationContext",
    "AuthorizationLedgerPrefix",
    "AuthorizationPolicyError",
    "AuthorizationReplayState",
    "CommittedEvidence",
    "ProspectiveExecutionFacts",
    "authorize_tool_call",
    "derive_authorization_context",
    "replay_authorization_policy",
    "validate_human_decision",
]
