"""Direct tests for the immutable authorization policy replay."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, is_dataclass, replace
from datetime import datetime, timedelta
import hashlib
import inspect
import json

import pytest
import rfc8785

import openworkproof.evidence as evidence
import openworkproof.policy as policy_module
from openworkproof.composition import (
    AuthorizationCausalityError,
    replay_authorization_causality,
)
from openworkproof.models import (
    ACTION_RECEIPT_ADAPTER,
    AgentRequest,
    ApplyPatchArguments,
    CapabilityGrant,
    ComposeProofArguments,
    CreatePrProposalArguments,
    RepoReadArguments,
    RunTestsArguments,
    TerminationHumanDecision,
    WorkOrder,
    request_arguments_digest,
)
from openworkproof.policy import (
    AuthorizationContext,
    AuthorizationLedgerPrefix,
    AuthorizationPolicyError,
    CommittedEvidence,
    ProspectiveExecutionFacts,
    _GrantReplayState,
    _denial_code,
    _grant_history_replay_context,
    _tool_predicates,
    _validate_tool_authorization_inputs,
    _validate_grant_history_semantics,
    _validate_policy_history,
    authorize_tool_call,
    derive_authorization_context,
    replay_authorization_policy,
)
from openworkproof.predicates import (
    EvaluationContext,
    evaluate_required_predicates,
    select_required_predicates,
)
from openworkproof.signing import sign_payload
from openworkproof.repo_tools import (
    ReplayCheckpoint,
    build_workspace_manifest,
    workspace_manifest_digest,
)

from test_receipt_chain import (
    _activate_ledger_root,
    _approval_decision_for_request,
    _approval_request_for_patch,
    _child_grant,
    _delegation_request,
    _full_pr_authorization_history,
    _grant_id,
    _grant_replay_context,
    _grant_replay_inputs,
    _issue_child,
    _jcs_digest,
    _linked_failed_rollback_receipt,
    _linked_denied_revocation_receipt,
    _linked_grant_consumed_receipt,
    _linked_tool_receipt,
    _pr_proposal_call,
    _resign_linked_agent_receipt,
    _retry_episode,
    _revocation_request,
    _revoke_child,
    _work_order_with_pr_chain_predicates,
)
from test_proof_composition import (
    _linked_run_tests,
    _proof_composed,
    _with_compose_previous_report,
    _with_correlation_factors,
    _with_parents,
)


def _source_checkpoint(work_order: WorkOrder) -> ReplayCheckpoint:
    manifest = build_workspace_manifest(work_order.source_commit, ())
    return ReplayCheckpoint(
        files=(),
        head_commit=work_order.source_commit,
        workspace_manifest=manifest,
        workspace_manifest_digest=workspace_manifest_digest(manifest),
        verified_test_results=(),
    )


def _live_policy_prefix(grants, attempts, receipts):
    return AuthorizationLedgerPrefix(
        effective_grants=tuple(
            sorted(grants.values(), key=lambda item: item.grant_id)
        ),
        grant_attempts=tuple(
            sorted(attempts.values(), key=lambda item: item.digest)
        ),
        receipts=receipts,
    )


def _signed_tool_request(
    work_order,
    grant,
    arguments,
    role_keys,
    now,
):
    binding = next(
        item
        for item in work_order.key_bindings
        if item.key_id == grant.subject_key_id
    )
    tool_name = {
        RepoReadArguments: "owp.repo_read",
        ApplyPatchArguments: "owp.apply_patch",
        RunTestsArguments: "owp.run_tests",
        CreatePrProposalArguments: "owp.create_pr_proposal",
        ComposeProofArguments: "owp.compose_proof",
    }[type(arguments)]
    return AgentRequest.model_validate(
        sign_payload(
            "agent-request",
            {
                "claim_type": "agent-request",
                "work_order_digest": work_order.digest,
                "grant_id": grant.grant_id,
                "actor_id": binding.subject_id,
                "actor_key_id": binding.key_id,
                "tool_name": tool_name,
                "arguments_digest": request_arguments_digest(
                    tool_name,
                    arguments,
                ),
                "nonce": _grant_id(
                    f"live:{tool_name}:{grant.grant_id}:{now.isoformat()}"
                ),
                "requested_at": now.isoformat().replace("+00:00", "Z"),
                "authentication_method": "agent_signature",
                "model_id": "model",
                "model_version": "1",
                "prompt_template_digest": "a" * 64,
                "context_source_digest": "b" * 64,
            },
            role_keys[binding.role][0],
        )
    )


def _prospective_context(
    *,
    tmp_path,
    label,
    signed_work_order,
    signed_root_grant,
    ephemeral_role_keys,
    fixed_now,
    child_subject_role="Developer",
    child_updates=None,
):
    _, child, receipts, grants, attempts = _grant_replay_context(
        tmp_path=tmp_path,
        label=label,
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
        with_child=True,
        child_subject_role=child_subject_role,
        child_updates=child_updates,
    )
    context = derive_authorization_context(
        signed_work_order,
        _live_policy_prefix(grants, attempts, receipts),
        (),
        _source_checkpoint(signed_work_order),
        fixed_now,
    )
    assert child is not None
    return context, child


def test_prospective_execution_facts_are_frozen_and_canonical(
    ephemeral_role_keys,
) -> None:
    sidecar = ephemeral_role_keys["Sidecar"][1]
    facts = ProspectiveExecutionFacts(
        execution_context_id="1" * 64,
        container_instance_id_digest="2" * 64,
        controller_id=sidecar["key_id"],
    )

    with pytest.raises(FrozenInstanceError):
        facts.execution_context_id = "3" * 64
    for updates in (
        {"execution_context_id": "A" * 64},
        {"container_instance_id_digest": "2" * 63},
        {"controller_id": "sidecar"},
    ):
        with pytest.raises(
            AuthorizationPolicyError,
            match="prospective execution facts",
        ):
            ProspectiveExecutionFacts(
                execution_context_id=updates.get(
                    "execution_context_id",
                    "1" * 64,
                ),
                container_instance_id_digest=updates.get(
                    "container_instance_id_digest",
                    "2" * 64,
                ),
                controller_id=updates.get(
                    "controller_id",
                    sidecar["key_id"],
                ),
            )


def test_tool_authorization_integrity_accepts_exact_signed_inputs(
    tmp_path,
    signed_work_order,
    signed_root_grant,
    ephemeral_role_keys,
    fixed_now,
) -> None:
    context, grant = _prospective_context(
        tmp_path=tmp_path,
        label="prospective-integrity-allowed",
        signed_work_order=signed_work_order,
        signed_root_grant=signed_root_grant,
        ephemeral_role_keys=ephemeral_role_keys,
        fixed_now=fixed_now,
    )
    arguments = RepoReadArguments(path="src")
    request = _signed_tool_request(
        signed_work_order,
        grant,
        arguments,
        ephemeral_role_keys,
        fixed_now,
    )

    assert list(
        inspect.signature(_validate_tool_authorization_inputs).parameters
    ) == ["context", "request", "request_arguments", "execution_facts"]
    assert _validate_tool_authorization_inputs(
        context,
        request,
        arguments,
        None,
    ) == (
        grant,
        next(
            binding
            for binding in signed_work_order.key_bindings
            if binding.key_id == grant.subject_key_id
        ),
    )


def test_tool_authorization_integrity_rejects_untrusted_inputs(
    tmp_path,
    signed_work_order,
    signed_root_grant,
    ephemeral_role_keys,
    fixed_now,
) -> None:
    context, grant = _prospective_context(
        tmp_path=tmp_path,
        label="prospective-integrity-denied",
        signed_work_order=signed_work_order,
        signed_root_grant=signed_root_grant,
        ephemeral_role_keys=ephemeral_role_keys,
        fixed_now=fixed_now,
    )
    arguments = RepoReadArguments(path="src")
    request = _signed_tool_request(
        signed_work_order,
        grant,
        arguments,
        ephemeral_role_keys,
        fixed_now,
    )
    sidecar = ephemeral_role_keys["Sidecar"][1]
    facts = ProspectiveExecutionFacts(
        execution_context_id="1" * 64,
        container_instance_id_digest="2" * 64,
        controller_id=sidecar["key_id"],
    )
    other_arguments = RepoReadArguments(path="tests")
    invalid_cases = (
        (object(), request, arguments, None),
        (context, object(), arguments, None),
        (context, request, object(), None),
        (context, request, arguments, facts),
        (
            context,
            request.model_copy(update={"work_order_digest": "f" * 64}),
            arguments,
            None,
        ),
        (
            context,
            request.model_copy(update={"grant_id": "f" * 64}),
            arguments,
            None,
        ),
        (
            context,
            request.model_copy(update={"arguments_digest": "f" * 64}),
            arguments,
            None,
        ),
        (context, request, other_arguments, None),
        (
            context,
            request.model_copy(
                update={
                    "requested_at": fixed_now - timedelta(seconds=301),
                }
            ),
            arguments,
            None,
        ),
        (
            context,
            request.model_copy(
                update={
                    "requested_at": fixed_now + timedelta(seconds=1),
                }
            ),
            arguments,
            None,
        ),
    )
    for candidate in invalid_cases:
        with pytest.raises(AuthorizationPolicyError):
            _validate_tool_authorization_inputs(*candidate)


def test_tool_authorization_integrity_requires_test_execution_facts(
    tmp_path,
    signed_work_order,
    signed_root_grant,
    ephemeral_role_keys,
    fixed_now,
) -> None:
    context, grant = _prospective_context(
        tmp_path=tmp_path,
        label="prospective-test-facts",
        signed_work_order=signed_work_order,
        signed_root_grant=signed_root_grant,
        ephemeral_role_keys=ephemeral_role_keys,
        fixed_now=fixed_now,
    )
    verifier = _child_grant(
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        label="prospective-test-facts:verifier",
        subject_role="Verifier",
    )
    arguments = RunTestsArguments(
        test_mode="verifier",
        command_digest=signed_work_order.test_profiles[-1].command_digest,
        source_commit=signed_work_order.source_commit,
        candidate_commit=signed_work_order.source_commit,
        workspace_manifest_digest=context.replay_checkpoint.workspace_manifest_digest,
        container_image_digest=signed_work_order.test_profiles[-1].container_image_digest,
        fixed_test_source_digest=signed_work_order.test_profiles[-1].fixed_test_source_digest,
    )
    request = _signed_tool_request(
        signed_work_order,
        verifier,
        arguments,
        ephemeral_role_keys,
        fixed_now,
    )

    with pytest.raises(AuthorizationPolicyError):
        _validate_tool_authorization_inputs(
            context,
            request,
            arguments,
            None,
        )


def _decision_request(
    *,
    context,
    grant,
    arguments,
    role_keys,
    facts=None,
):
    request = _signed_tool_request(
        context.work_order,
        grant,
        arguments,
        role_keys,
        context.transaction_time,
    )
    return authorize_tool_call(context, request, arguments, facts)


def test_tool_authorization_role_matrix_and_state_denial(
    tmp_path,
    signed_work_order,
    signed_root_grant,
    ephemeral_role_keys,
    fixed_now,
) -> None:
    context, developer = _prospective_context(
        tmp_path=tmp_path,
        label="prospective-role-state",
        signed_work_order=signed_work_order,
        signed_root_grant=signed_root_grant,
        ephemeral_role_keys=ephemeral_role_keys,
        fixed_now=fixed_now,
    )
    read_arguments = RepoReadArguments(path="src")
    assert _decision_request(
        context=context,
        grant=developer,
        arguments=read_arguments,
        role_keys=ephemeral_role_keys,
    ).allowed

    closed = replace(context, current_state="accepted")
    assert _decision_request(
        context=closed,
        grant=developer,
        arguments=read_arguments,
        role_keys=ephemeral_role_keys,
    ).error_code == "STATE_DENIED"

    compose_context = replace(
        context,
        current_state="locally_verified",
        causal_state=replace(
            context.causal_state,
            active_patch_receipt_id="f" * 64,
        ),
    )
    compose_arguments = ComposeProofArguments(
        expected_state_version=len(context.ledger_prefix.receipts),
        previous_report_digest=None,
    )
    assert _decision_request(
        context=compose_context,
        grant=developer,
        arguments=compose_arguments,
        role_keys=ephemeral_role_keys,
    ).error_code == "ROLE_DENIED"


def test_tool_authorization_capability_quota_and_precedence(
    tmp_path,
    signed_work_order,
    signed_root_grant,
    ephemeral_role_keys,
    fixed_now,
) -> None:
    capability_context, capability_grant = _prospective_context(
        tmp_path=tmp_path,
        label="prospective-capability",
        signed_work_order=signed_work_order,
        signed_root_grant=signed_root_grant,
        ephemeral_role_keys=ephemeral_role_keys,
        fixed_now=fixed_now,
        child_updates={"allowed_tools": ["owp.apply_patch"]},
    )
    read_arguments = RepoReadArguments(path="src")
    assert _decision_request(
        context=capability_context,
        grant=capability_grant,
        arguments=read_arguments,
        role_keys=ephemeral_role_keys,
    ).error_code == "CAPABILITY_DENIED"

    quota_context, quota_grant = _prospective_context(
        tmp_path=tmp_path,
        label="prospective-quota",
        signed_work_order=signed_work_order,
        signed_root_grant=signed_root_grant,
        ephemeral_role_keys=ephemeral_role_keys,
        fixed_now=fixed_now,
    )
    quota_context = replace(
        quota_context,
        replay_state=replace(
            quota_context.replay_state,
            balances=tuple(
                (
                    grant_id,
                    metric,
                    0
                    if grant_id == quota_grant.grant_id
                    and metric == "tool_calls"
                    else remaining,
                )
                for grant_id, metric, remaining
                in quota_context.replay_state.balances
            ),
        ),
    )
    assert _decision_request(
        context=quota_context,
        grant=quota_grant,
        arguments=read_arguments,
        role_keys=ephemeral_role_keys,
    ).error_code == "QUOTA_EXHAUSTED"

    assert _decision_request(
        context=replace(quota_context, current_state="frozen"),
        grant=quota_grant,
        arguments=read_arguments,
        role_keys=ephemeral_role_keys,
    ).error_code == "STATE_DENIED"


def test_tool_authorization_prepolicy_capacity_and_terminal_guards(
    tmp_path,
    signed_work_order,
    signed_root_grant,
    ephemeral_role_keys,
    fixed_now,
) -> None:
    context, grant = _prospective_context(
        tmp_path=tmp_path,
        label="prospective-prepolicy",
        signed_work_order=signed_work_order,
        signed_root_grant=signed_root_grant,
        ephemeral_role_keys=ephemeral_role_keys,
        fixed_now=fixed_now,
    )
    arguments = RepoReadArguments(path="src")
    for candidate, message in (
        (replace(context, routine_capacity_remaining=0), "capacity"),
        (
            replace(context, independent_failure_terminal=True),
            "EVIDENCE_FAILURE_SEALED",
        ),
        (
            replace(
                context,
                transaction_time=signed_work_order.deadline
                + timedelta(seconds=1),
            ),
            "expired",
        ),
    ):
        with pytest.raises(AuthorizationPolicyError, match=message):
            _decision_request(
                context=candidate,
                grant=grant,
                arguments=arguments,
                role_keys=ephemeral_role_keys,
            )


def _approved_pr_context(
    *,
    tmp_path,
    signed_work_order,
    signed_root_grant,
    ephemeral_role_keys,
    fixed_now,
    sidecar_receipt_factory,
):
    work_order, prefix, committed, checkpoint = _active_patch_context_inputs(
        tmp_path=tmp_path,
        signed_work_order=signed_work_order,
        signed_root_grant=signed_root_grant,
        ephemeral_role_keys=ephemeral_role_keys,
        fixed_now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
    )
    root = next(
        grant
        for grant in prefix.effective_grants
        if grant.parent_grant_id is None
    )
    patch = prefix.receipts[-1]
    request = _approval_request_for_patch(
        root=root,
        root_issuance=prefix.receipts[0],
        patch=patch,
        signed_work_order=work_order,
        sidecar_receipt_factory=sidecar_receipt_factory,
        role_keys=ephemeral_role_keys,
        label="prospective-pr:request",
        remaining_after=47,
    )
    decision = _approval_decision_for_request(
        request=request,
        previous_receipt=request,
        sequence=request.sequence + 1,
        approved=True,
        parent_receipt_ids=(request.receipt_id,),
        signed_work_order=work_order,
        sidecar_receipt_factory=sidecar_receipt_factory,
        role_keys=ephemeral_role_keys,
        label="prospective-pr:decision",
    )
    approved_prefix = replace(
        prefix,
        receipts=(*prefix.receipts, request, decision),
    )
    context = derive_authorization_context(
        work_order,
        approved_prefix,
        committed,
        checkpoint,
        datetime.fromisoformat("2026-01-01T00:00:10+00:00"),
    )
    return context, root, patch, request, decision


def _pending_approval_context(
    *,
    tmp_path,
    signed_work_order,
    signed_root_grant,
    ephemeral_role_keys,
    fixed_now,
    sidecar_receipt_factory,
    approved=True,
):
    work_order, prefix, committed, checkpoint = _active_patch_context_inputs(
        tmp_path=tmp_path,
        signed_work_order=signed_work_order,
        signed_root_grant=signed_root_grant,
        ephemeral_role_keys=ephemeral_role_keys,
        fixed_now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
    )
    root = next(
        grant
        for grant in prefix.effective_grants
        if grant.parent_grant_id is None
    )
    patch = prefix.receipts[-1]
    request = _approval_request_for_patch(
        root=root,
        root_issuance=prefix.receipts[0],
        patch=patch,
        signed_work_order=work_order,
        sidecar_receipt_factory=sidecar_receipt_factory,
        role_keys=ephemeral_role_keys,
        label="pending-approval:request",
        remaining_after=47,
    )
    decision = _approval_decision_for_request(
        request=request,
        previous_receipt=request,
        sequence=request.sequence + 1,
        approved=approved,
        parent_receipt_ids=(request.receipt_id,),
        signed_work_order=work_order,
        sidecar_receipt_factory=sidecar_receipt_factory,
        role_keys=ephemeral_role_keys,
        label=f"pending-approval:decision:{approved}",
    )
    context = derive_authorization_context(
        work_order,
        replace(prefix, receipts=(*prefix.receipts, request)),
        committed,
        checkpoint,
        datetime.fromisoformat("2026-01-01T00:00:10+00:00"),
    )
    return context, request, decision.nested_claim


def test_human_decision_policy_allows_bound_maintainer_approval(
    tmp_path,
    signed_work_order,
    signed_root_grant,
    ephemeral_role_keys,
    fixed_now,
    sidecar_receipt_factory,
) -> None:
    context, _, claim = _pending_approval_context(
        tmp_path=tmp_path,
        signed_work_order=signed_work_order,
        signed_root_grant=signed_root_grant,
        ephemeral_role_keys=ephemeral_role_keys,
        fixed_now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
    )

    decision = policy_module.validate_human_decision(context, claim)

    assert decision.allowed
    assert decision.error_code is None


def _resign_human_decision(
    claim,
    role_keys,
    *,
    role="Maintainer",
    updates=None,
):
    raw = claim.model_dump(mode="json")
    binding = role_keys[role][1]
    raw.update(
        {
            "actor_id": binding["subject_id"],
            "actor_key_id": binding["key_id"],
            **(updates or {}),
        }
    )
    return type(claim).model_validate(
        sign_payload("human-decision", raw, role_keys[role][0])
    )


def _termination_claim(work_order, role_keys, *, role="Maintainer", decided_at):
    binding = role_keys[role][1]
    return TerminationHumanDecision.model_validate(
        sign_payload(
            "human-decision",
            {
                "claim_type": "human-decision",
                "decision_type": "termination_decision",
                "work_order_digest": work_order.digest,
                "decision": "rejected",
                "reason": "MAINTAINER_REJECTED",
                "decided_at": decided_at,
                "actor_id": binding["subject_id"],
                "actor_key_id": binding["key_id"],
                "target_work_order_digest": work_order.digest,
            },
            role_keys[role][0],
        )
    )


def test_human_decision_policy_preserves_explicit_approval_denial(
    tmp_path,
    signed_work_order,
    signed_root_grant,
    ephemeral_role_keys,
    fixed_now,
    sidecar_receipt_factory,
) -> None:
    context, _, claim = _pending_approval_context(
        tmp_path=tmp_path,
        signed_work_order=signed_work_order,
        signed_root_grant=signed_root_grant,
        ephemeral_role_keys=ephemeral_role_keys,
        fixed_now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
        approved=False,
    )

    decision = policy_module.validate_human_decision(context, claim)

    assert decision.allowed is False
    assert decision.error_code == "APPROVAL_DENIED"


def test_human_decision_policy_denies_non_maintainer_role(
    tmp_path,
    signed_work_order,
    signed_root_grant,
    ephemeral_role_keys,
    fixed_now,
    sidecar_receipt_factory,
) -> None:
    context, _, claim = _pending_approval_context(
        tmp_path=tmp_path,
        signed_work_order=signed_work_order,
        signed_root_grant=signed_root_grant,
        ephemeral_role_keys=ephemeral_role_keys,
        fixed_now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
    )
    wrong_role = _resign_human_decision(
        claim,
        ephemeral_role_keys,
        role="Developer",
    )

    decision = policy_module.validate_human_decision(context, wrong_role)

    assert decision.allowed is False
    assert decision.error_code == "ROLE_DENIED"


@pytest.mark.parametrize(
    "updates",
    (
        {"request_receipt_digest": "f" * 64},
        {"approved_scope": {"operation": "different_action"}},
        {"expires_at": "2026-01-01T00:04:59Z"},
        {"decided_at": "2026-01-01T00:00:05Z"},
    ),
)
def test_human_decision_policy_rejects_approval_binding_mismatch(
    tmp_path,
    signed_work_order,
    signed_root_grant,
    ephemeral_role_keys,
    fixed_now,
    sidecar_receipt_factory,
    updates,
) -> None:
    context, _, claim = _pending_approval_context(
        tmp_path=tmp_path,
        signed_work_order=signed_work_order,
        signed_root_grant=signed_root_grant,
        ephemeral_role_keys=ephemeral_role_keys,
        fixed_now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
    )
    mismatched = _resign_human_decision(
        claim,
        ephemeral_role_keys,
        updates=updates,
    )

    with pytest.raises(AuthorizationPolicyError, match="approval"):
        policy_module.validate_human_decision(context, mismatched)


def test_human_decision_policy_rejects_bad_signature_and_duplicate_decision(
    tmp_path,
    signed_work_order,
    signed_root_grant,
    ephemeral_role_keys,
    fixed_now,
    sidecar_receipt_factory,
) -> None:
    context, request, claim = _pending_approval_context(
        tmp_path=tmp_path,
        signed_work_order=signed_work_order,
        signed_root_grant=signed_root_grant,
        ephemeral_role_keys=ephemeral_role_keys,
        fixed_now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
    )
    bad_signature = claim.model_copy(update={"signature": "A" * 86})
    duplicate_context = replace(
        context,
        replay_state=replace(
            context.replay_state,
            approval_decision_by_request=((request.receipt_id, "d" * 64),),
        ),
    )

    with pytest.raises(AuthorizationPolicyError, match="signature"):
        policy_module.validate_human_decision(context, bad_signature)
    with pytest.raises(AuthorizationPolicyError, match="already"):
        policy_module.validate_human_decision(duplicate_context, claim)


def test_human_decision_policy_rejects_stale_ingestion(
    tmp_path,
    signed_work_order,
    signed_root_grant,
    ephemeral_role_keys,
    fixed_now,
    sidecar_receipt_factory,
) -> None:
    context, _, claim = _pending_approval_context(
        tmp_path=tmp_path,
        signed_work_order=signed_work_order,
        signed_root_grant=signed_root_grant,
        ephemeral_role_keys=ephemeral_role_keys,
        fixed_now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
    )
    stale = replace(
        context,
        transaction_time=claim.decided_at + timedelta(seconds=301),
    )

    with pytest.raises(AuthorizationPolicyError, match="freshness"):
        policy_module.validate_human_decision(stale, claim)


def test_human_decision_policy_denies_expired_approval_at_ingestion(
    tmp_path,
    signed_work_order,
    signed_root_grant,
    ephemeral_role_keys,
    fixed_now,
    sidecar_receipt_factory,
) -> None:
    context, _, claim = _pending_approval_context(
        tmp_path=tmp_path,
        signed_work_order=signed_work_order,
        signed_root_grant=signed_root_grant,
        ephemeral_role_keys=ephemeral_role_keys,
        fixed_now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
    )

    decision = policy_module.validate_human_decision(
        replace(
            context,
            transaction_time=claim.expires_at + timedelta(seconds=1),
        ),
        claim,
    )

    assert decision.allowed is False
    assert decision.error_code == "APPROVAL_DENIED"


def test_human_decision_policy_allows_maintainer_termination_without_request(
    tmp_path,
    signed_work_order,
    signed_root_grant,
    ephemeral_role_keys,
    fixed_now,
) -> None:
    context, _ = _prospective_context(
        tmp_path=tmp_path,
        label="human-termination",
        signed_work_order=signed_work_order,
        signed_root_grant=signed_root_grant,
        ephemeral_role_keys=ephemeral_role_keys,
        fixed_now=fixed_now,
    )
    claim = _termination_claim(
        signed_work_order,
        ephemeral_role_keys,
        decided_at="2026-01-01T00:00:05Z",
    )

    decision = policy_module.validate_human_decision(
        replace(context, independent_failure_terminal=True),
        claim,
    )

    assert decision.allowed
    assert decision.error_code is None


def test_human_decision_policy_enforces_termination_state_and_role(
    tmp_path,
    signed_work_order,
    signed_root_grant,
    ephemeral_role_keys,
    fixed_now,
) -> None:
    context, _ = _prospective_context(
        tmp_path=tmp_path,
        label="human-termination-denied",
        signed_work_order=signed_work_order,
        signed_root_grant=signed_root_grant,
        ephemeral_role_keys=ephemeral_role_keys,
        fixed_now=fixed_now,
    )
    maintainer = _termination_claim(
        signed_work_order,
        ephemeral_role_keys,
        decided_at="2026-01-01T00:00:05Z",
    )
    developer = _termination_claim(
        signed_work_order,
        ephemeral_role_keys,
        role="Developer",
        decided_at="2026-01-01T00:00:05Z",
    )

    assert policy_module.validate_human_decision(
        replace(context, current_state="accepted"),
        maintainer,
    ).error_code == "STATE_DENIED"
    assert policy_module.validate_human_decision(
        context,
        developer,
    ).error_code == "ROLE_DENIED"


def test_tool_authorization_arguments_enforce_grant_roots(
    tmp_path,
    signed_work_order,
    signed_root_grant,
    ephemeral_role_keys,
    fixed_now,
) -> None:
    context, developer = _prospective_context(
        tmp_path=tmp_path,
        label="prospective-arguments-roots",
        signed_work_order=signed_work_order,
        signed_root_grant=signed_root_grant,
        ephemeral_role_keys=ephemeral_role_keys,
        fixed_now=fixed_now,
    )

    assert _decision_request(
        context=context,
        grant=developer,
        arguments=RepoReadArguments(path="src/openworkproof"),
        role_keys=ephemeral_role_keys,
    ).allowed
    assert _decision_request(
        context=context,
        grant=developer,
        arguments=RepoReadArguments(path="docs"),
        role_keys=ephemeral_role_keys,
    ).error_code == "PREDICATE_DENIED"


def test_tool_authorization_approval_binds_current_patch(
    tmp_path,
    signed_work_order,
    signed_root_grant,
    ephemeral_role_keys,
    fixed_now,
    sidecar_receipt_factory,
) -> None:
    context, root, patch, _, decision = _approved_pr_context(
        tmp_path=tmp_path,
        signed_work_order=signed_work_order,
        signed_root_grant=signed_root_grant,
        ephemeral_role_keys=ephemeral_role_keys,
        fixed_now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
    )
    allowed = CreatePrProposalArguments(
        target_patch_digest=patch.digest,
        approval_receipt_id=decision.receipt_id,
        approval_receipt_digest=decision.digest,
    )
    assert _decision_request(
        context=context,
        grant=root,
        arguments=allowed,
        role_keys=ephemeral_role_keys,
    ).allowed

    wrong_approval = allowed.model_copy(
        update={"approval_receipt_id": "f" * 64}
    )
    assert _decision_request(
        context=context,
        grant=root,
        arguments=wrong_approval,
        role_keys=ephemeral_role_keys,
    ).error_code == "APPROVAL_DENIED"


def test_tool_authorization_compose_binds_ledger_version(
    tmp_path,
    signed_work_order,
    signed_root_grant,
    ephemeral_role_keys,
    fixed_now,
    sidecar_receipt_factory,
) -> None:
    work_order, prefix, committed, checkpoint = _active_patch_context_inputs(
        tmp_path=tmp_path,
        signed_work_order=signed_work_order,
        signed_root_grant=signed_root_grant,
        ephemeral_role_keys=ephemeral_role_keys,
        fixed_now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
    )
    context = replace(
        derive_authorization_context(
            work_order,
            prefix,
            committed,
            checkpoint,
            datetime.fromisoformat("2026-01-01T00:00:10+00:00"),
        ),
        current_state="locally_verified",
    )
    root = next(
        grant
        for grant in prefix.effective_grants
        if grant.parent_grant_id is None
    )
    allowed = ComposeProofArguments(
        expected_state_version=len(prefix.receipts),
        previous_report_digest=None,
    )
    assert _decision_request(
        context=context,
        grant=root,
        arguments=allowed,
        role_keys=ephemeral_role_keys,
    ).allowed
    assert _decision_request(
        context=context,
        grant=root,
        arguments=allowed.model_copy(
            update={"expected_state_version": len(prefix.receipts) + 1}
        ),
        role_keys=ephemeral_role_keys,
    ).error_code == "PREDICATE_DENIED"


def test_tool_authorization_execution_binds_profile_and_closed_branch(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    fixed_now,
    sidecar_receipt_factory,
) -> None:
    context, developer = _developer_test_context(
        tmp_path=tmp_path,
        signed_work_order=signed_work_order,
        ephemeral_role_keys=ephemeral_role_keys,
        fixed_now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
    )
    profile = next(
        item
        for item in context.work_order.test_profiles
        if item.test_mode == "developer"
    )
    arguments = RunTestsArguments(
        test_mode="developer",
        command_digest=profile.command_digest,
        source_commit=context.work_order.source_commit,
        candidate_commit=context.replay_checkpoint.head_commit,
        workspace_manifest_digest=(
            context.replay_checkpoint.workspace_manifest_digest
        ),
        container_image_digest=profile.container_image_digest,
        fixed_test_source_digest=None,
    )
    facts = ProspectiveExecutionFacts(
        execution_context_id="1" * 64,
        container_instance_id_digest="2" * 64,
        controller_id=ephemeral_role_keys["Sidecar"][1]["key_id"],
    )
    assert _decision_request(
        context=context,
        grant=developer,
        arguments=arguments,
        role_keys=ephemeral_role_keys,
        facts=facts,
    ).allowed
    assert _decision_request(
        context=context,
        grant=developer,
        arguments=arguments.model_copy(
            update={"command_digest": "f" * 64}
        ),
        role_keys=ephemeral_role_keys,
        facts=facts,
    ).error_code == "PREDICATE_DENIED"
    assert _decision_request(
        context=replace(context, current_state="evidence_incomplete"),
        grant=developer,
        arguments=arguments,
        role_keys=ephemeral_role_keys,
        facts=facts,
    ).error_code == "STATE_DENIED"


def _active_patch_context_inputs(
    *,
    tmp_path,
    signed_work_order,
    signed_root_grant,
    ephemeral_role_keys,
    fixed_now,
    sidecar_receipt_factory,
    canonical_result=True,
):
    work_order, history, grants, attempts = _full_pr_authorization_history(
        case="allowed",
        tmp_path=tmp_path,
        signed_work_order=signed_work_order,
        ephemeral_role_keys=ephemeral_role_keys,
        fixed_now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
    )
    patch = history[2]
    grant = grants[patch.grant_id]
    patch_bytes = b"0123456789"
    patch_digest = hashlib.sha256(patch_bytes).hexdigest()
    candidate_commit = "2" * 40
    manifest = build_workspace_manifest(candidate_commit, ())
    manifest_digest = workspace_manifest_digest(manifest)
    source_manifest = build_workspace_manifest(work_order.source_commit, ())
    patch_result = {
        "schema_version": "openworkproof-patch-result/0.1",
        "parent_commit": work_order.source_commit,
        "parent_manifest_digest": workspace_manifest_digest(source_manifest),
        "candidate_commit": candidate_commit,
        "workspace_manifest_digest": manifest_digest,
        "patch_digest": patch_digest,
        "patch_size_bytes": len(patch_bytes),
        "replay_profile_digest": work_order.replay_profile_digest,
    }
    result_bytes = (
        rfc8785.dumps(patch_result)
        if canonical_result
        else json.dumps(
            patch_result,
            indent=2,
            sort_keys=True,
        ).encode("utf-8")
    )
    result_digest = hashlib.sha256(result_bytes).hexdigest()
    patch_raw = patch.model_dump(mode="json")
    patch_raw["request_arguments"].update(
        {
            "patch_digest": patch_digest,
            "patch_size_bytes": len(patch_bytes),
        }
    )
    patch_raw["arguments_digest"] = evidence.request_arguments_digest(
        "owp.apply_patch",
        patch_raw["request_arguments"],
    )
    patch_raw["output_digest"] = result_digest
    patch_raw["evidence_refs"] = [
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
    ]
    patch_claim = patch_raw["nested_claim"]
    patch_claim["arguments_digest"] = patch_raw["arguments_digest"]
    patch_claim = sign_payload(
        "agent-request",
        patch_claim,
        ephemeral_role_keys["Developer"][0],
    )
    patch_raw["nested_claim"] = patch_claim
    patch_raw["nested_claim_digest"] = patch_claim["digest"]
    patch = ACTION_RECEIPT_ADAPTER.validate_python(
        sign_payload(
            "action-receipt",
            patch_raw,
            ephemeral_role_keys["Sidecar"][0],
        )
    )
    patch = _rebind_tool_predicates(
        patch,
        work_order,
        grant,
        ephemeral_role_keys,
        remaining_before=2,
    )
    receipts = (*history[:2], patch)
    payload_by_path = {
        "evidence/patch-input/01.diff": patch_bytes,
        "evidence/patch-result/01.json": result_bytes,
    }
    committed = tuple(
        CommittedEvidence(
            reference=reference,
            payload=payload_by_path[reference.path],
        )
        for reference in patch.evidence_refs
    )
    checkpoint = ReplayCheckpoint(
        files=(),
        head_commit=candidate_commit,
        workspace_manifest=manifest,
        workspace_manifest_digest=manifest_digest,
        verified_test_results=(),
    )
    return (
        work_order,
        _live_policy_prefix(grants, attempts, receipts),
        committed,
        checkpoint,
    )


def _developer_test_context(
    *,
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    fixed_now,
    sidecar_receipt_factory,
):
    work_order = _work_order_with_pr_chain_predicates(
        signed_work_order,
        ephemeral_role_keys["Maintainer"][0],
    )
    root_raw = work_order.root_grant_template.model_dump(mode="json")
    root_raw["work_order_digest"] = work_order.digest
    root = CapabilityGrant.model_validate(
        sign_payload(
            "capability-grant",
            root_raw,
            ephemeral_role_keys["Maintainer"][0],
        )
    )
    _, child, history, grants, attempts = _grant_replay_context(
        tmp_path=tmp_path,
        label="prospective-developer-test",
        work_order=work_order,
        root=root,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
        with_child=True,
        child_updates={
            "allowed_tools": [
                "owp.apply_patch",
                "owp.repo_read",
                "owp.run_tests",
            ],
            "quota": {"tool_calls": 4, "repair_rounds": 0},
        },
    )
    assert child is not None
    patch = _linked_tool_receipt(
        tool_name="owp.apply_patch",
        state_before="running",
        state_after="running",
        sequence=3,
        previous_receipt=history[-1],
        root=child,
        signed_work_order=work_order,
        sidecar_receipt_factory=sidecar_receipt_factory,
        role_keys=ephemeral_role_keys,
        label="prospective-developer-test:patch",
        actor_role="Developer",
        remaining_after=3,
        occurred_at="2026-01-01T00:00:06Z",
    )
    patch_bytes = b"0123456789"
    patch_digest = hashlib.sha256(patch_bytes).hexdigest()
    candidate_commit = "2" * 40
    manifest = build_workspace_manifest(candidate_commit, ())
    manifest_digest = workspace_manifest_digest(manifest)
    source_manifest = build_workspace_manifest(work_order.source_commit, ())
    result_bytes = rfc8785.dumps(
        {
            "schema_version": "openworkproof-patch-result/0.1",
            "parent_commit": work_order.source_commit,
            "parent_manifest_digest": workspace_manifest_digest(
                source_manifest
            ),
            "candidate_commit": candidate_commit,
            "workspace_manifest_digest": manifest_digest,
            "patch_digest": patch_digest,
            "patch_size_bytes": len(patch_bytes),
            "replay_profile_digest": work_order.replay_profile_digest,
        }
    )
    result_digest = hashlib.sha256(result_bytes).hexdigest()
    raw = patch.model_dump(mode="json")
    raw["request_arguments"].update(
        {
            "patch_digest": patch_digest,
            "patch_size_bytes": len(patch_bytes),
        }
    )
    raw["arguments_digest"] = request_arguments_digest(
        "owp.apply_patch",
        raw["request_arguments"],
    )
    raw["output_digest"] = result_digest
    raw["evidence_refs"] = [
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
    ]
    claim = raw["nested_claim"]
    claim["arguments_digest"] = raw["arguments_digest"]
    claim = sign_payload(
        "agent-request",
        claim,
        ephemeral_role_keys["Developer"][0],
    )
    raw["nested_claim"] = claim
    raw["nested_claim_digest"] = claim["digest"]
    patch = ACTION_RECEIPT_ADAPTER.validate_python(
        sign_payload(
            "action-receipt",
            raw,
            ephemeral_role_keys["Sidecar"][0],
        )
    )
    patch = _rebind_tool_predicates(
        patch,
        work_order,
        child,
        ephemeral_role_keys,
        remaining_before=4,
    )
    receipts = (*history, patch)
    references = {
        "evidence/patch-input/01.diff": patch_bytes,
        "evidence/patch-result/01.json": result_bytes,
    }
    committed = tuple(
        CommittedEvidence(
            reference=reference,
            payload=references[reference.path],
        )
        for reference in patch.evidence_refs
    )
    checkpoint = ReplayCheckpoint(
        files=(),
        head_commit=candidate_commit,
        workspace_manifest=manifest,
        workspace_manifest_digest=manifest_digest,
        verified_test_results=(),
    )
    context = derive_authorization_context(
        work_order,
        _live_policy_prefix(grants, attempts, receipts),
        committed,
        checkpoint,
        datetime.fromisoformat("2026-01-01T00:00:10+00:00"),
    )
    return context, child


def test_derive_authorization_context_uses_verified_signed_prefix(
    tmp_path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys,
    fixed_now: datetime,
) -> None:
    _, _, receipts, grants, attempts = _grant_replay_context(
        tmp_path=tmp_path,
        label="live-policy-context",
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
    )
    prefix = _live_policy_prefix(grants, attempts, receipts)

    context = derive_authorization_context(
        signed_work_order,
        prefix,
        (),
        _source_checkpoint(signed_work_order),
        fixed_now,
    )

    assert is_dataclass(AuthorizationContext)
    assert is_dataclass(AuthorizationLedgerPrefix)
    assert is_dataclass(CommittedEvidence)
    assert context.current_state == "running"
    assert context.active_patch_receipt_id is None
    assert context.routine_capacity_remaining == 60
    assert context.denial_count == 0
    assert context.independent_failure_terminal is False
    with pytest.raises(FrozenInstanceError):
        context.current_state = "frozen"


def test_authorization_context_binds_active_patch_evidence_and_checkpoint(
    tmp_path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys,
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    work_order, prefix, committed, checkpoint = _active_patch_context_inputs(
        tmp_path=tmp_path,
        signed_work_order=signed_work_order,
        signed_root_grant=signed_root_grant,
        ephemeral_role_keys=ephemeral_role_keys,
        fixed_now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
    )
    transaction_time = datetime.fromisoformat(
        "2026-01-01T00:00:10+00:00"
    )

    context = derive_authorization_context(
        work_order,
        prefix,
        committed,
        checkpoint,
        transaction_time,
    )

    assert context.active_patch_receipt_id == prefix.receipts[-1].receipt_id
    assert context.replay_checkpoint.head_commit == "2" * 40

    wrong_reference = committed[0].reference.model_copy(
        update={"sha256": "f" * 64}
    )
    wrong_path = committed[0].reference.model_copy(
        update={"path": "evidence/not-allowed/01.diff"}
    )
    wrong_media = committed[0].reference.model_copy(
        update={"media_type": "application/json"}
    )
    wrong_size = committed[0].reference.model_copy(
        update={"size_bytes": committed[0].reference.size_bytes + 1}
    )
    invalid_evidence = (
        committed[:-1],
        committed + (committed[0],),
        (
            replace(committed[0], payload=b"tampered"),
            committed[1],
        ),
        (
            replace(committed[0], reference=wrong_reference),
            committed[1],
        ),
        (
            replace(committed[0], reference=wrong_path),
            committed[1],
        ),
        (
            replace(committed[0], reference=wrong_media),
            committed[1],
        ),
        (
            replace(committed[0], reference=wrong_size),
            committed[1],
        ),
    )
    for candidate in invalid_evidence:
        with pytest.raises(AuthorizationPolicyError, match="evidence"):
            derive_authorization_context(
                work_order,
                prefix,
                candidate,
                checkpoint,
                transaction_time,
            )

    with pytest.raises(AuthorizationPolicyError, match="checkpoint"):
        derive_authorization_context(
            work_order,
            prefix,
            committed,
            replace(
                checkpoint,
                head_commit=work_order.source_commit,
            ),
            transaction_time,
        )


def test_authorization_context_rejects_noncanonical_json_evidence(
    tmp_path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys,
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    work_order, prefix, committed, checkpoint = _active_patch_context_inputs(
        tmp_path=tmp_path,
        signed_work_order=signed_work_order,
        signed_root_grant=signed_root_grant,
        ephemeral_role_keys=ephemeral_role_keys,
        fixed_now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
        canonical_result=False,
    )

    with pytest.raises(AuthorizationPolicyError, match="RFC 8785"):
        derive_authorization_context(
            work_order,
            prefix,
            committed,
            checkpoint,
            datetime.fromisoformat("2026-01-01T00:00:10+00:00"),
        )


def test_authorization_context_binds_source_checkpoint_without_patch(
    tmp_path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys,
    fixed_now: datetime,
) -> None:
    _, _, receipts, grants, attempts = _grant_replay_context(
        tmp_path=tmp_path,
        label="live-policy-source-checkpoint",
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
    )
    checkpoint = _source_checkpoint(signed_work_order)
    wrong_manifest = build_workspace_manifest("f" * 40, ())

    with pytest.raises(AuthorizationPolicyError, match="checkpoint"):
        derive_authorization_context(
            signed_work_order,
            _live_policy_prefix(grants, attempts, receipts),
            (),
            replace(
                checkpoint,
                workspace_manifest=wrong_manifest,
            ),
            fixed_now,
        )


@pytest.mark.parametrize(
    "transaction_time",
    (
        datetime(2026, 1, 1, 0, 0, 1),
        datetime.fromisoformat("2026-01-01T00:00:01.000001+00:00"),
        datetime.fromisoformat("1970-01-01T00:00:00+00:00"),
    ),
)
def test_authorization_context_rejects_invalid_transaction_time(
    transaction_time,
    tmp_path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys,
    fixed_now: datetime,
) -> None:
    _, _, receipts, grants, attempts = _grant_replay_context(
        tmp_path=tmp_path,
        label=f"live-policy-time-{transaction_time.microsecond}",
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
    )

    with pytest.raises(
        AuthorizationPolicyError,
        match="transaction time",
    ):
        derive_authorization_context(
            signed_work_order,
            _live_policy_prefix(grants, attempts, receipts),
            (),
            _source_checkpoint(signed_work_order),
            transaction_time,
        )


def test_live_policy_prefix_rejects_noncanonical_collections(
    tmp_path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys,
    fixed_now: datetime,
) -> None:
    _, _, receipts, grants, attempts = _grant_replay_context(
        tmp_path=tmp_path,
        label="live-policy-bounds",
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
    )
    root = tuple(grants.values())[0]
    later_root = root.model_copy(update={"grant_id": "f" * 64})

    invalid_values = (
        {
            "effective_grants": [root],
            "grant_attempts": (),
            "receipts": receipts,
        },
        {
            "effective_grants": tuple(
                sorted(
                    (root, later_root),
                    key=lambda item: item.grant_id,
                    reverse=True,
                )
            ),
            "grant_attempts": (),
            "receipts": receipts,
        },
        {
            "effective_grants": (root,) * 9,
            "grant_attempts": (),
            "receipts": receipts,
        },
        {
            "effective_grants": (root,),
            "grant_attempts": (root,) * 9,
            "receipts": receipts,
        },
        {
            "effective_grants": (root,),
            "grant_attempts": (),
            "receipts": receipts * 65,
        },
    )
    for value in invalid_values:
        with pytest.raises(AuthorizationPolicyError):
            AuthorizationLedgerPrefix(**value)


def test_authorization_context_rejects_work_order_mismatch(
    tmp_path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys,
    fixed_now: datetime,
) -> None:
    _, _, receipts, grants, attempts = _grant_replay_context(
        tmp_path=tmp_path,
        label="live-policy-work-order-mismatch",
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
    )
    other_work_order = signed_work_order.model_copy(
        update={"work_order_id": "f" * 64}
    )

    with pytest.raises(AuthorizationPolicyError):
        derive_authorization_context(
            other_work_order,
            _live_policy_prefix(grants, attempts, receipts),
            (),
            _source_checkpoint(other_work_order),
            fixed_now,
        )


def _denied_pr_call(call, work_order, grant, role_keys):
    raw = call.model_dump(mode="json")
    raw.update(
        {
            "policy_decision": "deny",
            "policy_error_code": "APPROVAL_DENIED",
            "execution_status": "denied",
            "execution_error_code": None,
            "output_digest": None,
            "quota_charge": None,
        }
    )
    for field_name in (
        "toolchain_id",
        "execution_context_id",
        "container_instance_id_digest",
        "fixed_test_source_digest",
    ):
        raw["correlation_factors"][field_name] = None
    selected = select_required_predicates(
        work_order=work_order,
        tool_name=call.tool_name,
        policy_decision="deny",
        execution_status="denied",
        test_mode="developer",
    )
    prior = {
        result.predicate_id: result.input
        for result in call.predicate_results
    }
    raw["predicate_results"] = [
        result.model_dump(mode="json")
        for result in evaluate_required_predicates(
            selected,
            EvaluationContext(
                inputs=prior,
                authoritative_inputs=prior,
                authoritative_ledger_prefix_digests={
                    grant.grant_id: call.previous_receipt_digest,
                },
            ),
        )
    ]
    return ACTION_RECEIPT_ADAPTER.validate_python(
        sign_payload(
            "action-receipt",
            raw,
            role_keys["Sidecar"][0],
        )
    )


def _rebind_tool_predicates(
    receipt,
    work_order,
    grant,
    role_keys,
    *,
    remaining_before: int,
):
    raw = receipt.model_dump(mode="json")
    selected = select_required_predicates(
        work_order=work_order,
        tool_name=receipt.tool_name,
        policy_decision=receipt.policy_decision,
        execution_status=receipt.execution_status,
        test_mode=getattr(
            receipt.request_arguments,
            "test_mode",
            "developer",
        ),
    )
    supplied = {
        result.predicate_id: result.input
        for result in receipt.predicate_results
    }
    authoritative = {}
    inputs = {}
    for spec in selected:
        if spec.name == "tool_allowed":
            value = {"actual_tool_name": receipt.tool_name}
        elif spec.name == "quota_remaining":
            value = {
                "grant_id": grant.grant_id,
                "metric": "tool_calls",
                "amount": 1,
                "grant_remaining_before": remaining_before,
                "ledger_prefix_digest": receipt.previous_receipt_digest,
            }
        elif spec.name == "path_allowed":
            value = supplied[spec.predicate_id].model_dump(mode="json")
        elif spec.name == "tests_passed":
            value = supplied[spec.predicate_id].model_dump(mode="json")
        else:
            raise AssertionError("unexpected policy test predicate")
        authoritative[spec.predicate_id] = value
        inputs[spec.predicate_id] = value
    raw["predicate_results"] = [
        result.model_dump(mode="json")
        for result in evaluate_required_predicates(
            selected,
            EvaluationContext(
                inputs=inputs,
                authoritative_inputs=authoritative,
                authoritative_ledger_prefix_digests={
                    grant.grant_id: receipt.previous_receipt_digest,
                },
            ),
        )
    ]
    return ACTION_RECEIPT_ADAPTER.validate_python(
        sign_payload(
            "action-receipt",
            raw,
            role_keys["Sidecar"][0],
        )
    )


def _resign_receipt_state_after(receipt, state_after, role_keys):
    raw = receipt.model_dump(mode="json")
    raw["state_after"] = state_after
    return ACTION_RECEIPT_ADAPTER.validate_python(
        sign_payload(
            "action-receipt",
            raw,
            role_keys["Sidecar"][0],
        )
    )


def _policy_recomposition_history(
    *,
    tmp_path,
    label: str,
    signed_work_order: WorkOrder,
    ephemeral_role_keys,
    fixed_now: datetime,
    sidecar_receipt_factory,
    independent_passed: bool = True,
):
    work_order = _work_order_with_pr_chain_predicates(
        signed_work_order,
        ephemeral_role_keys["Maintainer"][0],
    )
    root_raw = work_order.root_grant_template.model_dump(mode="json")
    root_raw["work_order_digest"] = work_order.digest
    root = CapabilityGrant.model_validate(
        sign_payload(
            "capability-grant",
            root_raw,
            ephemeral_role_keys["Maintainer"][0],
        )
    )
    ledger_path = tmp_path / f"{label}.sqlite3"
    _activate_ledger_root(
        ledger_path,
        work_order,
        root,
        ephemeral_role_keys,
        fixed_now,
    )
    developer = _child_grant(
        work_order,
        root,
        ephemeral_role_keys,
        label=f"{label}:developer",
        updates={"quota": {"tool_calls": 4, "repair_rounds": 0}},
    )
    verifier = _child_grant(
        work_order,
        root,
        ephemeral_role_keys,
        label=f"{label}:verifier",
        subject_role="Verifier",
        updates={"quota": {"tool_calls": 4, "repair_rounds": 0}},
    )
    for candidate in (developer, verifier):
        _issue_child(
            ledger_path,
            candidate,
            _delegation_request(
                work_order,
                root,
                candidate,
                ephemeral_role_keys,
                actor_role="Manager",
                nonce=_grant_id(f"{label}:{candidate.grant_id}:request"),
            ),
            ephemeral_role_keys,
            fixed_now,
        )
    receipts, grants, attempts = _grant_replay_inputs(
        ledger_path,
        work_order,
    )
    root_issuance, developer_issuance, verifier_issuance = receipts
    patch = _linked_tool_receipt(
        tool_name="owp.apply_patch",
        state_before="running",
        state_after="running",
        sequence=4,
        previous_receipt=verifier_issuance,
        root=developer,
        signed_work_order=work_order,
        sidecar_receipt_factory=sidecar_receipt_factory,
        role_keys=ephemeral_role_keys,
        label=f"{label}:patch",
        actor_role="Developer",
        remaining_after=3,
    )
    patch = _rebind_tool_predicates(
        _with_parents(
            patch,
            (developer_issuance.receipt_id,),
            ephemeral_role_keys,
        ),
        work_order,
        developer,
        ephemeral_role_keys,
        remaining_before=4,
    )
    passing = _linked_run_tests(
        state_before="running",
        state_after="locally_verified",
        sequence=5,
        previous_receipt=patch,
        parent_receipt_ids=(
            verifier_issuance.receipt_id,
            patch.receipt_id,
        ),
        grant=verifier,
        signed_work_order=work_order,
        sidecar_receipt_factory=sidecar_receipt_factory,
        role_keys=ephemeral_role_keys,
        label=f"{label}:passing",
        remaining_after=3,
    )
    passing = _rebind_tool_predicates(
        passing,
        work_order,
        verifier,
        ephemeral_role_keys,
        remaining_before=4,
    )
    root_remaining = root.quota.tool_calls - 8
    first_compose = _linked_tool_receipt(
        tool_name="owp.compose_proof",
        state_before="locally_verified",
        state_after="locally_verified",
        sequence=6,
        previous_receipt=passing,
        root=root,
        signed_work_order=work_order,
        sidecar_receipt_factory=sidecar_receipt_factory,
        role_keys=ephemeral_role_keys,
        label=f"{label}:first-compose",
        remaining_after=root_remaining - 1,
        expected_state_version=5,
        occurred_at="2026-01-01T00:00:07Z",
    )
    first_compose = _rebind_tool_predicates(
        _with_parents(
            first_compose,
            (
                root_issuance.receipt_id,
                patch.receipt_id,
                passing.receipt_id,
            ),
            ephemeral_role_keys,
        ),
        work_order,
        root,
        ephemeral_role_keys,
        remaining_before=root_remaining,
    )
    trigger = _proof_composed(
        initiator=first_compose,
        sequence=7,
        state_before="locally_verified",
        state_after="evidence_incomplete",
        signed_work_order=work_order,
        sidecar_receipt_factory=sidecar_receipt_factory,
        role_keys=ephemeral_role_keys,
        label=f"{label}:trigger",
        state_version_before=5,
    )
    independent = _linked_run_tests(
        state_before="evidence_incomplete",
        state_after="evidence_incomplete",
        sequence=8,
        previous_receipt=trigger,
        parent_receipt_ids=(
            verifier_issuance.receipt_id,
            patch.receipt_id,
            trigger.receipt_id,
        ),
        grant=verifier,
        signed_work_order=work_order,
        sidecar_receipt_factory=sidecar_receipt_factory,
        role_keys=ephemeral_role_keys,
        label=f"{label}:independent",
        remaining_after=2,
        test_passed=independent_passed,
    )
    independent = _rebind_tool_predicates(
        independent,
        work_order,
        verifier,
        ephemeral_role_keys,
        remaining_before=3,
    )
    independent = _with_correlation_factors(
        independent,
        {
            "execution_context_id": _grant_id(
                f"{label}:independent:execution-context"
            ),
            "container_instance_id_digest": _grant_id(
                f"{label}:independent:container-instance"
            ),
        },
        ephemeral_role_keys,
    )
    recomposition = _linked_tool_receipt(
        tool_name="owp.compose_proof",
        state_before="evidence_incomplete",
        state_after="evidence_incomplete",
        sequence=9,
        previous_receipt=independent,
        root=root,
        signed_work_order=work_order,
        sidecar_receipt_factory=sidecar_receipt_factory,
        role_keys=ephemeral_role_keys,
        label=f"{label}:recomposition",
        remaining_after=root_remaining - 2,
        expected_state_version=7,
        occurred_at="2026-01-01T00:00:10Z",
    )
    recomposition = _rebind_tool_predicates(
        _with_parents(
            recomposition,
            (
                root_issuance.receipt_id,
                trigger.receipt_id,
                independent.receipt_id,
            ),
            ephemeral_role_keys,
        ),
        work_order,
        root,
        ephemeral_role_keys,
        remaining_before=root_remaining - 1,
    )
    recomposition = _with_compose_previous_report(
        recomposition,
        trigger.cause.composition_report_digest,
        ephemeral_role_keys,
    )
    return (
        work_order,
        (
            *receipts,
            patch,
            passing,
            first_compose,
            trigger,
            independent,
            recomposition,
        ),
        grants,
        attempts,
    )


def test_policy_replay_accepts_approved_pr(
    tmp_path,
    signed_work_order: WorkOrder,
    ephemeral_role_keys,
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    work_order, receipts, grants, attempts = (
        _full_pr_authorization_history(
            case="approved",
            tmp_path=tmp_path,
            signed_work_order=signed_work_order,
            ephemeral_role_keys=ephemeral_role_keys,
            fixed_now=fixed_now,
            sidecar_receipt_factory=sidecar_receipt_factory,
        )
    )
    causal_state = replay_authorization_causality(
        work_order,
        receipts,
    )

    replay = replay_authorization_policy(
        work_order,
        grants,
        attempts,
        receipts,
        causal_state,
    )

    assert replay.active_patch_receipt_id == receipts[2].receipt_id
    assert replay.approval_decision_by_request == (
        (receipts[3].receipt_id, receipts[4].receipt_id),
    )


@pytest.mark.parametrize(
    "case",
    (
        "independent_false",
        "independent_true",
        "first_compose",
        "recomposition",
    ),
)
def test_policy_replay_accepts_frozen_tool_state_matrix(
    case: str,
    tmp_path,
    signed_work_order: WorkOrder,
    ephemeral_role_keys,
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    work_order, receipts, grants, attempts = (
        _policy_recomposition_history(
            tmp_path=tmp_path,
            label=f"policy-state-matrix:{case}",
            signed_work_order=signed_work_order,
            ephemeral_role_keys=ephemeral_role_keys,
            fixed_now=fixed_now,
            sidecar_receipt_factory=sidecar_receipt_factory,
            independent_passed=case != "independent_false",
        )
    )
    if case == "first_compose":
        history = receipts[:6]
    elif case.startswith("independent"):
        history = receipts[:8]
    else:
        history = receipts
    causal_state = replay_authorization_causality(
        work_order,
        history,
    )

    replay_authorization_policy(
        work_order,
        grants,
        attempts,
        history,
        causal_state,
    )


@pytest.mark.parametrize(
    "field_name",
    ("execution_context_id", "container_instance_id_digest"),
)
def test_independent_context_rejects_reuse_from_prior_failed_tool(
    field_name: str,
    tmp_path,
    signed_work_order: WorkOrder,
    ephemeral_role_keys,
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    work_order, original, grants, _ = _policy_recomposition_history(
        tmp_path=tmp_path,
        label=f"failed-context:{field_name}",
        signed_work_order=signed_work_order,
        ephemeral_role_keys=ephemeral_role_keys,
        fixed_now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
    )
    root_issuance, developer_issuance, verifier_issuance, patch = (
        original[:4]
    )
    root = grants[work_order.root_grant_template.grant_id]
    developer = grants[developer_issuance.issued_grant_id]
    verifier = grants[verifier_issuance.issued_grant_id]
    failed = _linked_tool_receipt(
        tool_name="owp.repo_read",
        state_before="running",
        state_after="running",
        sequence=5,
        previous_receipt=patch,
        root=developer,
        signed_work_order=work_order,
        sidecar_receipt_factory=sidecar_receipt_factory,
        role_keys=ephemeral_role_keys,
        label=f"failed-context:{field_name}:failed",
        actor_role="Developer",
        execution_status="failed",
        remaining_after=2,
    )
    failed = _rebind_tool_predicates(
        _with_parents(
            failed,
            (
                developer_issuance.receipt_id,
                patch.receipt_id,
            ),
            ephemeral_role_keys,
        ),
        work_order,
        developer,
        ephemeral_role_keys,
        remaining_before=3,
    )
    failed = _with_correlation_factors(
        failed,
        {
            "execution_context_id": _grant_id(
                f"failed-context:{field_name}:execution"
            ),
            "container_instance_id_digest": _grant_id(
                f"failed-context:{field_name}:container"
            ),
        },
        ephemeral_role_keys,
    )
    passing = _linked_run_tests(
        state_before="running",
        state_after="locally_verified",
        sequence=6,
        previous_receipt=failed,
        parent_receipt_ids=(
            verifier_issuance.receipt_id,
            patch.receipt_id,
        ),
        grant=verifier,
        signed_work_order=work_order,
        sidecar_receipt_factory=sidecar_receipt_factory,
        role_keys=ephemeral_role_keys,
        label=f"failed-context:{field_name}:passing",
        remaining_after=3,
    )
    passing = _rebind_tool_predicates(
        passing,
        work_order,
        verifier,
        ephemeral_role_keys,
        remaining_before=4,
    )
    root_remaining = root.quota.tool_calls - 8
    first_compose = _linked_tool_receipt(
        tool_name="owp.compose_proof",
        state_before="locally_verified",
        state_after="locally_verified",
        sequence=7,
        previous_receipt=passing,
        root=root,
        signed_work_order=work_order,
        sidecar_receipt_factory=sidecar_receipt_factory,
        role_keys=ephemeral_role_keys,
        label=f"failed-context:{field_name}:compose",
        remaining_after=root_remaining - 1,
    )
    first_compose = _rebind_tool_predicates(
        _with_parents(
            first_compose,
            (
                root_issuance.receipt_id,
                patch.receipt_id,
                passing.receipt_id,
            ),
            ephemeral_role_keys,
        ),
        work_order,
        root,
        ephemeral_role_keys,
        remaining_before=root_remaining,
    )
    trigger = _proof_composed(
        initiator=first_compose,
        sequence=8,
        state_before="locally_verified",
        state_after="evidence_incomplete",
        signed_work_order=work_order,
        sidecar_receipt_factory=sidecar_receipt_factory,
        role_keys=ephemeral_role_keys,
        label=f"failed-context:{field_name}:trigger",
    )
    independent = _linked_run_tests(
        state_before="evidence_incomplete",
        state_after="evidence_incomplete",
        sequence=9,
        previous_receipt=trigger,
        parent_receipt_ids=(
            verifier_issuance.receipt_id,
            patch.receipt_id,
            trigger.receipt_id,
        ),
        grant=verifier,
        signed_work_order=work_order,
        sidecar_receipt_factory=sidecar_receipt_factory,
        role_keys=ephemeral_role_keys,
        label=f"failed-context:{field_name}:independent",
        remaining_after=2,
    )
    independent = _rebind_tool_predicates(
        independent,
        work_order,
        verifier,
        ephemeral_role_keys,
        remaining_before=3,
    )
    independent = _with_correlation_factors(
        independent,
        {
            "execution_context_id": _grant_id(
                f"failed-context:{field_name}:independent-execution"
            ),
            "container_instance_id_digest": _grant_id(
                f"failed-context:{field_name}:independent-container"
            ),
            field_name: getattr(failed.correlation_factors, field_name),
        },
        ephemeral_role_keys,
    )
    history = (
        root_issuance,
        developer_issuance,
        verifier_issuance,
        patch,
        failed,
        passing,
        first_compose,
        trigger,
        independent,
    )

    with pytest.raises(
        AuthorizationCausalityError,
        match="fresh",
    ):
        replay_authorization_causality(
            work_order,
            history,
        )


def test_grant_context_tracks_sibling_and_parent_charge_prefix(
    tmp_path,
    signed_work_order: WorkOrder,
    ephemeral_role_keys,
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    work_order, receipts, grants, attempts = (
        _policy_recomposition_history(
            tmp_path=tmp_path,
            label="policy-grant-prefix",
            signed_work_order=signed_work_order,
            ephemeral_role_keys=ephemeral_role_keys,
            fixed_now=fixed_now,
            sidecar_receipt_factory=sidecar_receipt_factory,
        )
    )
    context = _grant_history_replay_context(
        work_order,
        receipts,
        grants,
        attempts,
    )
    root = grants[work_order.root_grant_template.grant_id]
    developer = grants[receipts[1].issued_grant_id]
    verifier = grants[receipts[2].issued_grant_id]
    after_first_sibling = context.state_before(
        receipts[2].receipt_id,
        root.grant_id,
    )
    after_first_parent_charge = context.state_before(
        receipts[8].receipt_id,
        root.grant_id,
    )

    assert after_first_sibling is not None
    assert (
        after_first_sibling.remaining_tool_calls
        == root.quota.tool_calls - developer.quota.tool_calls
    )
    assert after_first_parent_charge is not None
    assert (
        after_first_parent_charge.remaining_tool_calls
        == root.quota.tool_calls
        - developer.quota.tool_calls
        - verifier.quota.tool_calls
        - 1
    )


@pytest.mark.parametrize(
    ("case", "state_after"),
    (
        ("first_compose", "proof_ready"),
        ("recomposition", "proof_ready"),
        ("independent", "proof_ready"),
    ),
)
def test_public_policy_rejects_state_changing_context_exceptions(
    case: str,
    state_after: str,
    tmp_path,
    signed_work_order: WorkOrder,
    ephemeral_role_keys,
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    work_order, receipts, grants, attempts = (
        _policy_recomposition_history(
            tmp_path=tmp_path,
            label=f"policy-invalid-state:{case}",
            signed_work_order=signed_work_order,
            ephemeral_role_keys=ephemeral_role_keys,
            fixed_now=fixed_now,
            sidecar_receipt_factory=sidecar_receipt_factory,
            independent_passed=case != "independent",
        )
    )
    tip_index = {
        "first_compose": 5,
        "independent": 7,
        "recomposition": 8,
    }[case]
    forged_tip = _resign_receipt_state_after(
        receipts[tip_index],
        state_after,
        ephemeral_role_keys,
    )
    if case == "independent":
        forged_tip = _with_parents(
            forged_tip,
            (
                receipts[2].receipt_id,
                receipts[3].receipt_id,
            ),
            ephemeral_role_keys,
        )
    history = (*receipts[:tip_index], forged_tip)
    causal_state = replay_authorization_causality(
        work_order,
        history,
    )

    with pytest.raises(AuthorizationPolicyError):
        replay_authorization_policy(
            work_order,
            grants,
            attempts,
            history,
            causal_state,
        )


def test_public_policy_rejects_stale_same_type_causal_state(
    tmp_path,
    signed_work_order: WorkOrder,
    ephemeral_role_keys,
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    work_order, receipts, grants, attempts = (
        _policy_recomposition_history(
            tmp_path=tmp_path,
            label="policy-stale-causal-state",
            signed_work_order=signed_work_order,
            ephemeral_role_keys=ephemeral_role_keys,
            fixed_now=fixed_now,
            sidecar_receipt_factory=sidecar_receipt_factory,
        )
    )
    second_trigger = _proof_composed(
        initiator=receipts[-1],
        sequence=10,
        state_before="evidence_incomplete",
        state_after="proof_ready",
        signed_work_order=work_order,
        sidecar_receipt_factory=sidecar_receipt_factory,
        role_keys=ephemeral_role_keys,
        label="policy-stale-causal-state:second-trigger",
    )
    history = (*receipts, second_trigger)
    canonical = replay_authorization_causality(work_order, history)
    stale = replace(
        canonical,
        latest_composition_trigger_id=receipts[6].receipt_id,
        independent_result_receipt_id=receipts[7].receipt_id,
    )

    with pytest.raises(
        AuthorizationPolicyError,
        match="canonical causal state",
    ):
        replay_authorization_policy(
            work_order,
            grants,
            attempts,
            history,
            stale,
        )


def test_full_recomposition_replays_policy_and_aggregate_after_proof_ready(
    tmp_path,
    signed_work_order: WorkOrder,
    ephemeral_role_keys,
    public_keys,
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    work_order, receipts, grants, attempts = (
        _policy_recomposition_history(
            tmp_path=tmp_path,
            label="policy-full-recomposition",
            signed_work_order=signed_work_order,
            ephemeral_role_keys=ephemeral_role_keys,
            fixed_now=fixed_now,
            sidecar_receipt_factory=sidecar_receipt_factory,
        )
    )
    proof_ready = _proof_composed(
        initiator=receipts[-1],
        sequence=10,
        state_before="evidence_incomplete",
        state_after="proof_ready",
        signed_work_order=work_order,
        sidecar_receipt_factory=sidecar_receipt_factory,
        role_keys=ephemeral_role_keys,
        label="policy-full-recomposition:proof-ready",
        state_version_before=7,
    )
    history = (*receipts, proof_ready)
    causal_state = replay_authorization_causality(
        work_order,
        history,
    )

    replay_authorization_policy(
        work_order,
        grants,
        attempts,
        history,
        causal_state,
    )
    evidence.validate_grant_chain(
        work_order,
        tuple(grants.values()),
        tuple(attempts.values()),
        history,
        public_keys,
    )


@pytest.mark.parametrize(
    "case",
    (
        "active_patch",
        "failure",
        "rollback",
        "composition",
        "independent",
        "approval_pair",
    ),
)
def test_public_policy_rejects_forged_causal_bindings(
    case: str,
    tmp_path,
    signed_work_order: WorkOrder,
    ephemeral_role_keys,
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    work_order, receipts, grants, attempts = (
        _full_pr_authorization_history(
            case="approved",
            tmp_path=tmp_path,
            signed_work_order=signed_work_order,
            ephemeral_role_keys=ephemeral_role_keys,
            fixed_now=fixed_now,
            sidecar_receipt_factory=sidecar_receipt_factory,
        )
    )
    causal_state = replay_authorization_causality(
        work_order,
        receipts,
    )
    root, _, patch, request, decision, proposal = receipts
    if case == "approval_pair":
        forged = replace(
            causal_state,
            approval_decision_by_request=(
                (request.receipt_id, patch.receipt_id),
            ),
        )
    else:
        wrong_ids = {
            "active_patch": proposal.receipt_id,
            "failure": patch.receipt_id,
            "rollback": root.receipt_id,
            "composition": decision.receipt_id,
            "independent": patch.receipt_id,
        }
        if case == "composition":
            forged = replace(
                causal_state,
                latest_composition_trigger_id=wrong_ids[case],
            )
        elif case == "independent":
            forged = replace(
                causal_state,
                independent_result_receipt_id=wrong_ids[case],
            )
        else:
            forged = replace(
                causal_state,
                **{f"{case}_receipt_id": wrong_ids[case]},
            )

    with pytest.raises(
        AuthorizationPolicyError,
        match="causal binding",
    ):
        replay_authorization_policy(
            work_order,
            grants,
            attempts,
            receipts,
            forged,
        )


def test_signed_overlapping_child_denial_prefers_capability(
    tmp_path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys,
    fixed_now: datetime,
) -> None:
    _, child, receipts, grants, attempts = _grant_replay_context(
        tmp_path=tmp_path,
        label="policy-child-overlap",
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
        with_child=True,
        child_updates={
            "allowed_tools": ["owp.compose_proof"],
            "quota": {"tool_calls": 51, "repair_rounds": 0},
        },
    )
    assert child is not None
    assert receipts[-1].policy_decision == "deny"
    assert receipts[-1].policy_error_code == "CAPABILITY_DENIED"
    assert child.digest in attempts
    causal_state = replay_authorization_causality(
        signed_work_order,
        receipts,
    )

    replay_authorization_policy(
        signed_work_order,
        grants,
        attempts,
        receipts,
        causal_state,
    )


@pytest.mark.parametrize(
    "wrong_error_code",
    ("CAPABILITY_DENIED", "QUOTA_EXHAUSTED"),
)
def test_public_child_denial_prefers_state_over_other_failures(
    wrong_error_code: str,
    tmp_path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys,
    fixed_now: datetime,
) -> None:
    _, _, receipts, grants, attempts = _grant_replay_context(
        tmp_path=tmp_path,
        label=f"policy-child-state:{wrong_error_code}",
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
        with_child=True,
        child_updates={
            "allowed_tools": ["owp.compose_proof"],
            "quota": {"tool_calls": 51, "repair_rounds": 0},
        },
    )
    raw = receipts[-1].model_dump(mode="json")
    raw.update(
        {
            "state_before": "proof_ready",
            "state_after": "proof_ready",
            "policy_error_code": "STATE_DENIED",
        }
    )
    denied = ACTION_RECEIPT_ADAPTER.validate_python(
        sign_payload(
            "action-receipt",
            raw,
            ephemeral_role_keys["Sidecar"][0],
        )
    )
    history = (*receipts[:-1], denied)
    causal_state = replay_authorization_causality(
        signed_work_order,
        history,
    )

    replay_authorization_policy(
        signed_work_order,
        grants,
        attempts,
        history,
        causal_state,
    )

    raw["policy_error_code"] = wrong_error_code
    wrong = ACTION_RECEIPT_ADAPTER.validate_python(
        sign_payload(
            "action-receipt",
            raw,
            ephemeral_role_keys["Sidecar"][0],
        )
    )
    with pytest.raises(
        AuthorizationPolicyError,
        match="denied Grant history",
    ):
        replay_authorization_policy(
            signed_work_order,
            grants,
            attempts,
            (*receipts[:-1], wrong),
            causal_state,
        )


@pytest.mark.parametrize("case", ("root", "child", "attempt"))
@pytest.mark.parametrize("corruption", ("signature", "issuer_role"))
def test_public_policy_rejects_invalid_grant_authenticity(
    case: str,
    corruption: str,
    tmp_path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys,
    fixed_now: datetime,
) -> None:
    invalid_child = case == "attempt"
    _, child, receipts, grants, attempts = _grant_replay_context(
        tmp_path=tmp_path,
        label=f"policy-signature:{case}",
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
        with_child=case != "root",
        child_updates=(
            {"allowed_tools": ["owp.compose_proof"]}
            if invalid_child
            else None
        ),
    )
    selected = (
        grants[signed_root_grant.grant_id]
        if case == "root"
        else child
    )
    assert selected is not None
    if corruption == "signature":
        signature = selected.signature
        tampered = selected.model_copy(
            update={
                "signature": (
                    ("A" if signature[0] != "A" else "B")
                    + signature[1:]
                )
            }
        )
    else:
        signer_role = (
            "Developer"
            if selected.parent_grant_id is None
            else "Verifier"
        )
        raw = selected.model_dump(mode="json")
        raw["issuer_key_id"] = ephemeral_role_keys[signer_role][1][
            "key_id"
        ]
        tampered = CapabilityGrant.model_validate(
            sign_payload(
                "capability-grant",
                raw,
                ephemeral_role_keys[signer_role][0],
            )
        )
    if case == "attempt":
        attempts = {tampered.digest: tampered}
    else:
        grants = {**grants, tampered.grant_id: tampered}
    causal_state = replay_authorization_causality(
        signed_work_order,
        receipts,
    )

    with pytest.raises(
        AuthorizationPolicyError,
        match=(
            "history"
            if case == "attempt" and corruption == "issuer_role"
            else "Grant signature"
        ),
    ):
        replay_authorization_policy(
            signed_work_order,
            grants,
            attempts,
            receipts,
            causal_state,
        )


@pytest.mark.parametrize("actor_role", ("Developer", "Verifier"))
def test_bound_cross_role_child_attempt_replays_as_role_denied(
    actor_role: str,
    tmp_path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys,
    fixed_now: datetime,
) -> None:
    ledger_path = tmp_path / f"cross-role-{actor_role}.sqlite3"
    _activate_ledger_root(
        ledger_path,
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        fixed_now,
    )
    candidate = _child_grant(
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        label=f"cross-role:{actor_role}",
        subject_role=actor_role,
        signer_role=actor_role,
    )
    _issue_child(
        ledger_path,
        candidate,
        _delegation_request(
            signed_work_order,
            signed_root_grant,
            candidate,
            ephemeral_role_keys,
            actor_role=actor_role,
            nonce=_grant_id(f"cross-role:{actor_role}:request"),
        ),
        ephemeral_role_keys,
        fixed_now,
    )
    receipts, grants, attempts = _grant_replay_inputs(
        ledger_path,
        signed_work_order,
    )
    assert receipts[-1].policy_error_code == "ROLE_DENIED"
    assert attempts == {candidate.digest: candidate}
    causal_state = replay_authorization_causality(
        signed_work_order,
        receipts,
    )

    replay_authorization_policy(
        signed_work_order,
        grants,
        attempts,
        receipts,
        causal_state,
    )


def test_policy_replay_accepts_valid_approval_denial(
    tmp_path,
    signed_work_order: WorkOrder,
    ephemeral_role_keys,
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    work_order, receipts, grants, attempts = (
        _full_pr_authorization_history(
            case="denied",
            tmp_path=tmp_path,
            signed_work_order=signed_work_order,
            ephemeral_role_keys=ephemeral_role_keys,
            fixed_now=fixed_now,
            sidecar_receipt_factory=sidecar_receipt_factory,
        )
    )
    denied = _denied_pr_call(
        receipts[-1],
        work_order,
        grants[work_order.root_grant_template.grant_id],
        ephemeral_role_keys,
    )
    history = (*receipts[:-1], denied)
    causal_state = replay_authorization_causality(
        work_order,
        history,
    )

    replay = replay_authorization_policy(
        work_order,
        grants,
        attempts,
        history,
        causal_state,
    )

    assert replay.active_patch_receipt_id == receipts[2].receipt_id


@pytest.mark.parametrize("decision", ("allow", "deny"))
def test_policy_replay_rejects_overlong_high_risk_approval_request(
    decision: str,
    tmp_path,
    signed_work_order: WorkOrder,
    ephemeral_role_keys,
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    work_order, receipts, grants, attempts = (
        _full_pr_authorization_history(
            case="approved",
            tmp_path=tmp_path,
            signed_work_order=signed_work_order,
            ephemeral_role_keys=ephemeral_role_keys,
            fixed_now=fixed_now,
            sidecar_receipt_factory=sidecar_receipt_factory,
        )
    )
    request = receipts[3]
    expires_at = "2026-01-01T01:00:07Z"
    arguments = {
        "request_kind": request.request_kind,
        "target_action_digest": request.target_action_digest,
        "required_role": request.required_role,
        "requested_scope": request.requested_scope,
        "expires_at": expires_at,
    }
    updates = {"expires_at": expires_at}
    if decision == "deny":
        updates.update(
            {
                "policy_decision": "deny",
                "policy_error_code": "STATE_DENIED",
                "execution_status": "denied",
                "quota_charge": None,
            }
        )
    overlong = _resign_linked_agent_receipt(
        request,
        grant_id=request.grant_id,
        tool_name="owp.request_pr_proposal",
        arguments=arguments,
        actor_role="Manager",
        label=f"overlong-approval:{decision}",
        role_keys=ephemeral_role_keys,
        updates=updates,
    )
    history = (*receipts[:3], overlong)
    causal_state = replay_authorization_causality(
        work_order,
        history,
    )

    with pytest.raises(
        AuthorizationPolicyError,
        match="approval request validity exceeds",
    ):
        replay_authorization_policy(
            work_order,
            grants,
            attempts,
            history,
            causal_state,
        )


@pytest.mark.parametrize("case", ("denied", "expired"))
def test_policy_replay_rejects_allowed_pr_with_unusable_approval(
    case: str,
    tmp_path,
    signed_work_order: WorkOrder,
    ephemeral_role_keys,
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    work_order, receipts, grants, attempts = (
        _full_pr_authorization_history(
            case=case,
            tmp_path=tmp_path,
            signed_work_order=signed_work_order,
            ephemeral_role_keys=ephemeral_role_keys,
            fixed_now=fixed_now,
            sidecar_receipt_factory=sidecar_receipt_factory,
        )
    )
    causal_state = replay_authorization_causality(
        work_order,
        receipts,
    )

    with pytest.raises(
        AuthorizationPolicyError,
        match="allowed tool",
    ):
        replay_authorization_policy(
            work_order,
            grants,
            attempts,
            receipts,
            causal_state,
        )


@pytest.mark.parametrize(
    "case",
    ("missing_decision", "wrong_scope", "cross_request"),
)
def test_policy_replay_rejects_unbound_pr_approval(
    case: str,
    tmp_path,
    signed_work_order: WorkOrder,
    ephemeral_role_keys,
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    work_order, receipts, grants, attempts = (
        _full_pr_authorization_history(
            case="approved",
            tmp_path=tmp_path,
            signed_work_order=signed_work_order,
            ephemeral_role_keys=ephemeral_role_keys,
            fixed_now=fixed_now,
            sidecar_receipt_factory=sidecar_receipt_factory,
        )
    )
    root_issuance, _, patch, request, decision, original = receipts
    root = grants[work_order.root_grant_template.grant_id]
    call = _pr_proposal_call(
        root=root,
        approval_id=(
            request.receipt_id
            if case == "missing_decision"
            else decision.receipt_id
        ),
        approval_digest=(
            request.digest
            if case == "missing_decision"
            else decision.digest
        ),
        previous_receipt=decision,
        parent_receipt_ids=(
            root_issuance.receipt_id,
            patch.receipt_id,
            decision.receipt_id,
        ),
        target_patch_digest=(
            root.digest if case == "wrong_scope" else patch.digest
        ),
        occurred_at="2026-01-01T00:00:10Z",
        signed_work_order=work_order,
        sidecar_receipt_factory=sidecar_receipt_factory,
        role_keys=ephemeral_role_keys,
        label=f"policy-unbound-approval:{case}",
        remaining_before=47,
        remaining_after=46,
    )
    history = (*receipts[:-1], call)
    causal_state = replay_authorization_causality(
        work_order,
        receipts[:-1],
    )
    if case == "cross_request":
        causal_state = replace(
            causal_state,
            approval_decision_by_request=(
                (request.receipt_id, patch.receipt_id),
            ),
        )

    with pytest.raises(AuthorizationPolicyError):
        replay_authorization_policy(
            work_order,
            grants,
            attempts,
            history,
            causal_state,
        )

    assert original.approval_receipt_id == decision.receipt_id


def _proactive_rollback_history(
    *,
    tmp_path,
    signed_work_order: WorkOrder,
    ephemeral_role_keys,
    fixed_now: datetime,
    sidecar_receipt_factory,
    target_receipt_id: str | None = None,
    target_digest: str | None = None,
    include_patch_parent: bool = True,
):
    work_order = _work_order_with_pr_chain_predicates(
        signed_work_order,
        ephemeral_role_keys["Maintainer"][0],
    )
    root_raw = work_order.root_grant_template.model_dump(mode="json")
    root_raw["work_order_digest"] = work_order.digest
    root = CapabilityGrant.model_validate(
        sign_payload(
            "capability-grant",
            root_raw,
            ephemeral_role_keys["Maintainer"][0],
        )
    )
    _, child, receipts, grants, attempts = _grant_replay_context(
        tmp_path=tmp_path,
        label="proactive-rollback",
        work_order=work_order,
        root=root,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
        with_child=True,
        child_updates={
            "allowed_tools": [
                "owp.apply_patch",
                "owp.repo_read",
                "owp.rollback_patch",
            ]
        },
    )
    assert child is not None
    root_issuance, child_issuance = receipts
    patch = _linked_tool_receipt(
        tool_name="owp.apply_patch",
        state_before="running",
        state_after="running",
        sequence=3,
        previous_receipt=child_issuance,
        root=child,
        signed_work_order=work_order,
        sidecar_receipt_factory=sidecar_receipt_factory,
        role_keys=ephemeral_role_keys,
        label="proactive-rollback:patch",
        actor_role="Developer",
        remaining_after=1,
    )
    patch = _rebind_tool_predicates(
        _with_parents(
            patch,
            (child_issuance.receipt_id,),
            ephemeral_role_keys,
        ),
        work_order,
        child,
        ephemeral_role_keys,
        remaining_before=2,
    )
    tip = _linked_tool_receipt(
        tool_name="owp.repo_read",
        state_before="running",
        state_after="running",
        sequence=4,
        previous_receipt=patch,
        root=child,
        signed_work_order=work_order,
        sidecar_receipt_factory=sidecar_receipt_factory,
        role_keys=ephemeral_role_keys,
        label="proactive-rollback:tip",
        actor_role="Developer",
        remaining_after=0,
    )
    tip = _rebind_tool_predicates(
        _with_parents(
            tip,
            (
                child_issuance.receipt_id,
                patch.receipt_id,
            ),
            ephemeral_role_keys,
        ),
        work_order,
        child,
        ephemeral_role_keys,
        remaining_before=1,
    )
    resolved_target_id = target_receipt_id or patch.receipt_id
    resolved_target_digest = target_digest or patch.digest
    rollback_parents = [
        child_issuance.receipt_id,
        *(
            (patch.receipt_id,)
            if include_patch_parent
            else ()
        ),
        tip.receipt_id,
    ]
    base = sidecar_receipt_factory(
        state_before="running",
        state_after="running",
        event_type="rollback",
        actor_role="Developer",
        policy_decision="deny",
        execution_status="denied",
        sequence=5,
        previous_receipt_digest=tip.digest,
        parent_receipt_ids=tuple(rollback_parents),
        occurred_at="2026-01-01T00:00:06Z",
    )
    before_commit = "1" * 40
    arguments = {
        "target_patch_receipt_id": resolved_target_id,
        "target_patch_digest": resolved_target_digest,
        "before_commit": before_commit,
    }
    rollback = _resign_linked_agent_receipt(
        base,
        grant_id=child.grant_id,
        tool_name="owp.rollback_patch",
        arguments=arguments,
        actor_role="Developer",
        label="proactive-rollback:denial",
        role_keys=ephemeral_role_keys,
        work_order_digest=work_order.digest,
        updates={
            "target_patch_receipt_id": resolved_target_id,
            "target_patch_digest": resolved_target_digest,
            "before_commit": before_commit,
            "after_commit": before_commit,
            "after_manifest_digest": None,
            "rollback_result": "denied",
            "policy_decision": "deny",
            "policy_error_code": "STATE_DENIED",
            "execution_status": "denied",
            "quota_charge": None,
            "sequence": 5,
            "previous_receipt_digest": tip.digest,
            "parent_receipt_ids": rollback_parents,
        },
    )
    return (
        work_order,
        (
            root_issuance,
            child_issuance,
            patch,
            tip,
            rollback,
        ),
        grants,
        attempts,
    )


def test_policy_replay_accepts_proactive_rollback_state_denial(
    tmp_path,
    signed_work_order: WorkOrder,
    ephemeral_role_keys,
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    work_order, history, grants, attempts = (
        _proactive_rollback_history(
            tmp_path=tmp_path,
            signed_work_order=signed_work_order,
            ephemeral_role_keys=ephemeral_role_keys,
            fixed_now=fixed_now,
            sidecar_receipt_factory=sidecar_receipt_factory,
        )
    )
    assert history[-1].parent_receipt_ids == (
        history[1].receipt_id,
        history[2].receipt_id,
        history[3].receipt_id,
    )
    causal_state = replay_authorization_causality(
        work_order,
        history,
    )

    replay_authorization_policy(
        work_order,
        grants,
        attempts,
        history,
        causal_state,
    )


@pytest.mark.parametrize(
    "target_tamper",
    ("receipt_id", "digest"),
)
def test_proactive_rollback_denial_rejects_unresolved_target(
    target_tamper: str,
    tmp_path,
    signed_work_order: WorkOrder,
    ephemeral_role_keys,
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    updates = {
        (
            "target_receipt_id"
            if target_tamper == "receipt_id"
            else "target_digest"
        ): _grant_id(f"proactive-rollback:wrong-{target_tamper}")
    }
    work_order, history, _, _ = _proactive_rollback_history(
        tmp_path=tmp_path,
        signed_work_order=signed_work_order,
        ephemeral_role_keys=ephemeral_role_keys,
        fixed_now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
        include_patch_parent=False,
        **updates,
    )

    with pytest.raises(
        AuthorizationCausalityError,
        match="receipt causal reference is unavailable",
    ):
        replay_authorization_causality(
            work_order,
            history,
        )


def test_policy_replay_rejects_false_allow_precondition(
    tmp_path,
    signed_work_order: WorkOrder,
    signed_root_grant,
    ephemeral_role_keys,
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    _, child, receipts, grants, attempts = _grant_replay_context(
        tmp_path=tmp_path,
        label="policy-false-precondition",
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
        with_child=True,
    )
    assert child is not None
    receipt = _linked_tool_receipt(
        tool_name="owp.repo_read",
        state_before="running",
        state_after="running",
        sequence=3,
        previous_receipt=receipts[-1],
        root=child,
        signed_work_order=signed_work_order,
        sidecar_receipt_factory=sidecar_receipt_factory,
        role_keys=ephemeral_role_keys,
        label="policy-false-precondition:call",
        actor_role="Developer",
        remaining_after=1,
    )
    raw = receipt.model_dump(mode="json")
    result = next(
        item
        for item in raw["predicate_results"]
        if item["name"] == "tool_allowed"
    )
    result["passed"] = False
    result["error_code"] = "PREDICATE_FALSE"
    forged = ACTION_RECEIPT_ADAPTER.validate_python(
        sign_payload(
            "action-receipt",
            raw,
            ephemeral_role_keys["Sidecar"][0],
        )
    )
    history = (*receipts, forged)
    causal_state = replay_authorization_causality(
        signed_work_order,
        history,
    )
    with pytest.raises(
        AuthorizationPolicyError,
        match="allowed tool",
    ):
        replay_authorization_policy(
            signed_work_order,
            grants,
            attempts,
            history,
            causal_state,
        )


def test_policy_replay_accepts_false_verifier_postcondition(
    tmp_path,
    signed_work_order: WorkOrder,
    signed_root_grant,
    ephemeral_role_keys,
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    episode = _retry_episode(
        tmp_path=tmp_path,
        label="policy-false-postcondition",
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
    )
    receipts, grants, attempts = _grant_replay_inputs(
        episode["ledger_path"],
        signed_work_order,
    )
    failure = episode["failure"]
    raw = failure.model_dump(mode="json")
    result = next(
        item
        for item in raw["predicate_results"]
        if item["name"] == "quota_remaining"
    )
    result["input"].update(
        {
            "grant_id": failure.grant_id,
            "grant_remaining_before": 2,
            "ledger_prefix_digest": failure.previous_receipt_digest,
        }
    )
    result["input_digest"] = _jcs_digest(
        {
            "domain": "openworkproof/predicate-input/v0.1",
            "predicate_id": result["predicate_id"],
            "input": result["input"],
        }
    )
    rebound = ACTION_RECEIPT_ADAPTER.validate_python(
        sign_payload(
            "action-receipt",
            raw,
            ephemeral_role_keys["Sidecar"][0],
        )
    )
    evaluated, child_scope_allowed = _tool_predicates(
        signed_work_order,
        rebound,
        grants[failure.grant_id],
        _GrantReplayState(2, 0, 0, False),
    )

    assert child_scope_allowed is True
    assert any(
        result.name == "tests_passed"
        and result.passed is False
        and result.error_code == "PREDICATE_FALSE"
        for result in evaluated
    )


def test_policy_replay_tracks_delegation_and_single_use(
    tmp_path,
    signed_work_order: WorkOrder,
    signed_root_grant,
    ephemeral_role_keys,
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    _, child, receipts, grants, attempts = _grant_replay_context(
        tmp_path=tmp_path,
        label="policy-single-use",
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
        with_child=True,
        child_updates={
            "usage_mode": "single_use",
            "quota": {"tool_calls": 1, "repair_rounds": 0},
        },
    )
    assert child is not None
    call = _linked_tool_receipt(
        tool_name="owp.repo_read",
        state_before="running",
        state_after="running",
        sequence=3,
        previous_receipt=receipts[-1],
        root=child,
        signed_work_order=signed_work_order,
        sidecar_receipt_factory=sidecar_receipt_factory,
        role_keys=ephemeral_role_keys,
        label="policy-single-use:call",
        actor_role="Developer",
        remaining_after=0,
    )
    history = (*receipts, call)
    replay = _validate_grant_history_semantics(
        signed_work_order,
        history,
        grants,
        attempts,
    )

    assert replay[child.grant_id].use_count == 1
    assert replay[child.grant_id].remaining_tool_calls == 0
    assert (
        replay[signed_root_grant.grant_id].remaining_tool_calls
        == signed_root_grant.quota.tool_calls - child.quota.tool_calls
    )


def test_policy_replay_tracks_revocation(
    tmp_path,
    signed_work_order: WorkOrder,
    signed_root_grant,
    ephemeral_role_keys,
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    ledger_path, child, _, _, _ = _grant_replay_context(
        tmp_path=tmp_path,
        label="policy-revocation",
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
        with_child=True,
    )
    assert child is not None
    _revoke_child(
        ledger_path,
        signed_root_grant,
        child,
        _revocation_request(
            signed_work_order,
            signed_root_grant,
            child,
            ephemeral_role_keys,
            actor_role="Manager",
            nonce=_grant_id("policy-revocation"),
        ),
        ephemeral_role_keys,
        fixed_now,
    )
    receipts, grants, attempts = _grant_replay_inputs(
        ledger_path,
        signed_work_order,
    )
    causal_state = replay_authorization_causality(
        signed_work_order,
        receipts,
    )

    replay = replay_authorization_policy(
        signed_work_order,
        grants,
        attempts,
        receipts,
        causal_state,
    )

    assert replay.revoked_grant_ids == (child.grant_id,)


@pytest.mark.parametrize(
    ("conditions", "expected"),
    (
        ((False, False, False, False, False, False), "STATE_DENIED"),
        ((True, False, False, False, False, False), "ROLE_DENIED"),
        ((True, True, False, False, False, False), "CAPABILITY_DENIED"),
        ((True, True, True, False, False, False), "APPROVAL_DENIED"),
        ((True, True, True, True, False, False), "PREDICATE_DENIED"),
        ((True, True, True, True, True, False), "QUOTA_EXHAUSTED"),
        ((True, True, True, True, True, True), None),
    ),
)
def test_policy_denial_precedence_is_exact(
    conditions: tuple[bool, ...],
    expected: str | None,
) -> None:
    assert _denial_code(
        state_allowed=conditions[0],
        role_allowed=conditions[1],
        capability_allowed=conditions[2],
        approval_allowed=conditions[3],
        predicate_allowed=conditions[4],
        quota_allowed=conditions[5],
    ) == expected


def test_policy_replay_tracks_repair_round_charge(
    tmp_path,
    signed_work_order: WorkOrder,
    signed_root_grant,
    ephemeral_role_keys,
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    _, child, receipts, grants, attempts = _grant_replay_context(
        tmp_path=tmp_path,
        label="policy-repair-round",
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
        with_child=True,
        child_updates={
            "allowed_tools": [
                "owp.repo_read",
                "owp.rollback_patch",
            ],
        },
    )
    assert child is not None
    failed_tool = _linked_tool_receipt(
        tool_name="owp.repo_read",
        state_before="running",
        state_after="running",
        sequence=3,
        previous_receipt=receipts[-1],
        root=child,
        signed_work_order=signed_work_order,
        sidecar_receipt_factory=sidecar_receipt_factory,
        role_keys=ephemeral_role_keys,
        label="policy-repair-round:tool",
        actor_role="Developer",
        execution_status="failed",
        remaining_after=child.quota.tool_calls - 1,
    )
    rollback = _linked_failed_rollback_receipt(
        grant=child,
        sequence=4,
        previous_receipt=failed_tool,
        remaining_after=child.quota.tool_calls - 2,
        signed_work_order=signed_work_order,
        sidecar_receipt_factory=sidecar_receipt_factory,
        role_keys=ephemeral_role_keys,
        label="policy-repair-round:rollback",
    )
    repair = _linked_grant_consumed_receipt(
        grant=signed_root_grant,
        sequence=5,
        previous_receipt=rollback,
        remaining_after=0,
        signed_work_order=signed_work_order,
        sidecar_receipt_factory=sidecar_receipt_factory,
        role_keys=ephemeral_role_keys,
        label="policy-repair-round:retry",
    )

    replay = _validate_grant_history_semantics(
        signed_work_order,
        (*receipts, failed_tool, rollback, repair),
        grants,
        attempts,
    )

    assert (
        replay[signed_root_grant.grant_id].remaining_repair_rounds
        == 0
    )


def test_policy_replay_enforces_tool_state_before_role_precedence(
    tmp_path,
    signed_work_order: WorkOrder,
    signed_root_grant,
    ephemeral_role_keys,
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    _, _, receipts, grants, attempts = _grant_replay_context(
        tmp_path=tmp_path,
        label="policy-tool-precedence",
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
    )
    denied = _linked_tool_receipt(
        tool_name="owp.repo_read",
        state_before="needs_rework",
        state_after="needs_rework",
        sequence=2,
        previous_receipt=receipts[-1],
        root=signed_root_grant,
        signed_work_order=signed_work_order,
        sidecar_receipt_factory=sidecar_receipt_factory,
        role_keys=ephemeral_role_keys,
        label="policy-tool-precedence:denied",
        policy_decision="deny",
        policy_error_code="STATE_DENIED",
        actor_role="Manager",
    )
    denied = _rebind_tool_predicates(
        denied,
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        remaining_before=signed_root_grant.quota.tool_calls,
    )
    history = (*receipts, denied)
    causal_state = replay_authorization_causality(
        signed_work_order,
        history,
    )

    replay_authorization_policy(
        signed_work_order,
        grants,
        attempts,
        history,
        causal_state,
    )

    raw = denied.model_dump(mode="json")
    raw["policy_error_code"] = "ROLE_DENIED"
    wrong = ACTION_RECEIPT_ADAPTER.validate_python(
        sign_payload(
            "action-receipt",
            raw,
            ephemeral_role_keys["Sidecar"][0],
        )
    )
    with pytest.raises(
        AuthorizationPolicyError,
        match="tool denial",
    ):
        replay_authorization_policy(
            signed_work_order,
            grants,
            attempts,
            (*receipts, wrong),
            causal_state,
        )


def test_policy_replay_enforces_retry_state_before_capability(
    tmp_path,
    signed_work_order: WorkOrder,
    signed_root_grant,
    ephemeral_role_keys,
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    _, _, receipts, grants, attempts = _grant_replay_context(
        tmp_path=tmp_path,
        label="policy-retry-precedence",
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
    )
    denied = _linked_grant_consumed_receipt(
        grant=signed_root_grant,
        sequence=2,
        previous_receipt=receipts[-1],
        remaining_after=None,
        signed_work_order=signed_work_order,
        sidecar_receipt_factory=sidecar_receipt_factory,
        role_keys=ephemeral_role_keys,
        label="policy-retry-precedence:denied",
        policy_decision="deny",
        policy_error_code="STATE_DENIED",
        state_before="running",
        occurred_at="2026-01-01T00:00:06Z",
    )
    history = (*receipts, denied)
    causal_state = replay_authorization_causality(
        signed_work_order,
        history,
    )

    replay_authorization_policy(
        signed_work_order,
        grants,
        attempts,
        history,
        causal_state,
    )

    raw = denied.model_dump(mode="json")
    raw["policy_error_code"] = "CAPABILITY_DENIED"
    wrong = ACTION_RECEIPT_ADAPTER.validate_python(
        sign_payload(
            "action-receipt",
            raw,
            ephemeral_role_keys["Sidecar"][0],
        )
    )
    with pytest.raises(
        AuthorizationPolicyError,
        match="non-tool denial",
    ):
        replay_authorization_policy(
            signed_work_order,
            grants,
            attempts,
            (*receipts, wrong),
            causal_state,
        )


def test_policy_replay_enforces_approval_request_denial(
    tmp_path,
    signed_work_order: WorkOrder,
    ephemeral_role_keys,
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    work_order, receipts, grants, attempts = (
        _full_pr_authorization_history(
            case="approved",
            tmp_path=tmp_path,
            signed_work_order=signed_work_order,
            ephemeral_role_keys=ephemeral_role_keys,
            fixed_now=fixed_now,
            sidecar_receipt_factory=sidecar_receipt_factory,
        )
    )
    request = receipts[3]
    raw = request.model_dump(mode="json")
    raw.update(
        {
            "policy_decision": "deny",
            "policy_error_code": "STATE_DENIED",
            "execution_status": "denied",
            "quota_charge": None,
            "state_before": "needs_rework",
            "state_after": "needs_rework",
        }
    )
    denied = ACTION_RECEIPT_ADAPTER.validate_python(
        sign_payload(
            "action-receipt",
            raw,
            ephemeral_role_keys["Sidecar"][0],
        )
    )
    history = (*receipts[:3], denied)
    causal_state = replay_authorization_causality(
        work_order,
        history,
    )

    replay_authorization_policy(
        work_order,
        grants,
        attempts,
        history,
        causal_state,
    )

    raw["policy_error_code"] = "CAPABILITY_DENIED"
    wrong = ACTION_RECEIPT_ADAPTER.validate_python(
        sign_payload(
            "action-receipt",
            raw,
            ephemeral_role_keys["Sidecar"][0],
        )
    )
    with pytest.raises(AuthorizationPolicyError):
        replay_authorization_policy(
            work_order,
            grants,
            attempts,
            (*receipts[:3], wrong),
            causal_state,
        )


def test_policy_replay_enforces_rollback_denial(
    tmp_path,
    signed_work_order: WorkOrder,
    ephemeral_role_keys,
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    work_order, history, grants, attempts = (
        _proactive_rollback_history(
            tmp_path=tmp_path,
            signed_work_order=signed_work_order,
            ephemeral_role_keys=ephemeral_role_keys,
            fixed_now=fixed_now,
            sidecar_receipt_factory=sidecar_receipt_factory,
        )
    )
    causal_state = replay_authorization_causality(
        work_order,
        history,
    )
    replay_context = _grant_history_replay_context(
        work_order,
        history,
        grants,
        attempts,
    )

    _validate_policy_history(
        work_order,
        history,
        grants,
        replay_context,
        causal_state,
    )

    raw = history[-1].model_dump(mode="json")
    raw["policy_error_code"] = "CAPABILITY_DENIED"
    wrong = ACTION_RECEIPT_ADAPTER.validate_python(
        sign_payload(
            "action-receipt",
            raw,
            ephemeral_role_keys["Sidecar"][0],
        )
    )
    with pytest.raises(AuthorizationPolicyError):
        _validate_policy_history(
            work_order,
            (*history[:-1], wrong),
            grants,
            replay_context,
            causal_state,
        )


def test_policy_replay_enforces_revocation_denial(
    tmp_path,
    signed_work_order: WorkOrder,
    signed_root_grant,
    ephemeral_role_keys,
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    _, child, receipts, grants, attempts = _grant_replay_context(
        tmp_path=tmp_path,
        label="policy-revocation-denial",
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
        with_child=True,
    )
    assert child is not None
    denied = _linked_denied_revocation_receipt(
        authorizer=signed_root_grant,
        target=child,
        sequence=3,
        previous_receipt=receipts[-1],
        signed_work_order=signed_work_order,
        sidecar_receipt_factory=sidecar_receipt_factory,
        role_keys=ephemeral_role_keys,
        label="policy-revocation-denial:call",
        policy_error_code="STATE_DENIED",
    )
    raw = denied.model_dump(mode="json")
    raw.update(
        {
            "state_before": "proof_ready",
            "state_after": "proof_ready",
        }
    )
    denied = ACTION_RECEIPT_ADAPTER.validate_python(
        sign_payload(
            "action-receipt",
            raw,
            ephemeral_role_keys["Sidecar"][0],
        )
    )
    denied = _with_parents(
        denied,
        (receipts[0].receipt_id, receipts[1].receipt_id),
        ephemeral_role_keys,
    )
    history = (*receipts, denied)
    causal_state = replay_authorization_causality(
        signed_work_order,
        history,
    )

    replay_authorization_policy(
        signed_work_order,
        grants,
        attempts,
        history,
        causal_state,
    )

    raw = denied.model_dump(mode="json")
    raw["policy_error_code"] = "CAPABILITY_DENIED"
    wrong = ACTION_RECEIPT_ADAPTER.validate_python(
        sign_payload(
            "action-receipt",
            raw,
            ephemeral_role_keys["Sidecar"][0],
        )
    )
    with pytest.raises(AuthorizationPolicyError):
        replay_authorization_policy(
            signed_work_order,
            grants,
            attempts,
            (*receipts, wrong),
            causal_state,
        )
