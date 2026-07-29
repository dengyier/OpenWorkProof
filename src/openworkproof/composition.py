"""Bounded causal replay for authorization receipt histories."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from itertools import islice

from openworkproof.models import (
    ActionReceiptEnvelope,
    ApprovalDecisionReceipt,
    ApprovalRequestedReceipt,
    ComposeProofArguments,
    CreatePrProposalArguments,
    GrantConsumedReceipt,
    GrantIssuedReceipt,
    GrantRevokedReceipt,
    RollbackReceipt,
    SystemEventReceipt,
    TerminationDecisionReceipt,
    ToolCallReceipt,
    WorkOrder,
)


MAX_AUTHORIZATION_RECEIPTS = 64


class AuthorizationCausalityError(RuntimeError):
    """Authorization receipt causality could not be replayed exactly."""


@dataclass(frozen=True)
class AuthorizationCausalSnapshot:
    """Immutable causal facts visible at one signed receipt."""

    active_patch_receipt_id: str | None
    failure_receipt_id: str | None
    rollback_receipt_id: str | None
    latest_composition_trigger_id: str | None
    independent_result_receipt_id: str | None
    approval_decision_by_request: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class AuthorizationCausalState(AuthorizationCausalSnapshot):
    """Immutable final facts and bounded per-receipt causal snapshots."""

    snapshots_by_receipt: tuple[
        tuple[str, AuthorizationCausalSnapshot],
        ...,
    ]

    def snapshot_for(self, receipt_id: str) -> AuthorizationCausalSnapshot:
        for candidate_id, snapshot in self.snapshots_by_receipt:
            if candidate_id == receipt_id:
                return snapshot
        raise _fail("receipt causal snapshot is unavailable")


@dataclass(frozen=True)
class _CausalIndex:
    by_id: dict[str, ActionReceiptEnvelope]
    by_digest: dict[str, ActionReceiptEnvelope]
    by_sequence: dict[int, ActionReceiptEnvelope]
    issuance_by_grant: dict[str, GrantIssuedReceipt]


def _fail(message: str) -> AuthorizationCausalityError:
    return AuthorizationCausalityError(message)


def _bounded_receipts(
    receipts: Iterable[ActionReceiptEnvelope],
) -> tuple[ActionReceiptEnvelope, ...]:
    try:
        bounded = tuple(
            islice(receipts, MAX_AUTHORIZATION_RECEIPTS + 1)
        )
    except AuthorizationCausalityError:
        raise
    except Exception as error:
        raise _fail(
            "receipt history input is unavailable"
        ) from error
    if len(bounded) > MAX_AUTHORIZATION_RECEIPTS:
        raise _fail("receipt history exceeds its bounded input capacity")
    return bounded


def _build_index(
    receipts: tuple[ActionReceiptEnvelope, ...],
) -> _CausalIndex:
    by_id: dict[str, ActionReceiptEnvelope] = {}
    by_digest: dict[str, ActionReceiptEnvelope] = {}
    by_sequence: dict[int, ActionReceiptEnvelope] = {}
    issuance_by_grant: dict[str, GrantIssuedReceipt] = {}
    for receipt in receipts:
        if (
            receipt.receipt_id in by_id
            or receipt.digest in by_digest
            or receipt.sequence in by_sequence
        ):
            raise _fail("receipt history index is not unique")
        by_id[receipt.receipt_id] = receipt
        by_digest[receipt.digest] = receipt
        by_sequence[receipt.sequence] = receipt
        if (
            isinstance(receipt, GrantIssuedReceipt)
            and receipt.policy_decision == "allow"
            and receipt.execution_status == "succeeded"
            and receipt.issued_grant_id is not None
        ):
            if receipt.issued_grant_id in issuance_by_grant:
                raise _fail("Grant issuance index is not unique")
            issuance_by_grant[receipt.issued_grant_id] = receipt
    return _CausalIndex(
        by_id=by_id,
        by_digest=by_digest,
        by_sequence=by_sequence,
        issuance_by_grant=issuance_by_grant,
    )


def validate_authorization_causal_bindings(
    work_order: WorkOrder,
    receipts: tuple[ActionReceiptEnvelope, ...],
    causal_state: AuthorizationCausalState,
) -> None:
    """Compare caller state with canonical replay of its bounded snapshot."""

    canonical = replay_authorization_causality(work_order, receipts)
    if canonical != causal_state:
        raise _fail(
            "canonical causal state rejects the supplied causal binding"
        )


def replay_authorization_causality(
    work_order: WorkOrder,
    receipts: Iterable[ActionReceiptEnvelope],
) -> AuthorizationCausalState:
    """Replay exact semantic parents and return the frozen causal state."""

    if not isinstance(work_order, WorkOrder):
        raise _fail("WorkOrder is unavailable for causal replay")
    bounded = _bounded_receipts(receipts)
    if any(
        not isinstance(receipt, ActionReceiptEnvelope)
        for receipt in bounded
    ):
        raise _fail("receipt history contains a malformed receipt")
    index = _build_index(bounded)
    ordered = bounded
    roles_by_key = {
        binding.key_id: binding.role
        for binding in work_order.key_bindings
    }
    roles_by_actor = {
        (binding.subject_id, binding.key_id): binding.role
        for binding in work_order.key_bindings
    }
    previous: ActionReceiptEnvelope | None = None
    for expected_sequence, receipt in enumerate(ordered, start=1):
        if (
            receipt.work_order_digest != work_order.digest
            or receipt.sequence != expected_sequence
            or receipt.previous_receipt_digest
            != (previous.digest if previous is not None else None)
        ):
            raise _fail(
                "receipt chain origin or adjacency is invalid"
            )
        previous = receipt
    if ordered:
        first = ordered[0]
        root_grant_id = work_order.root_grant_template.grant_id
        root_activation = (
            isinstance(first, GrantIssuedReceipt)
            and first.parent_grant_id is None
            and first.authorizing_grant_id == root_grant_id
            and first.issued_grant_id == root_grant_id
            and first.policy_decision == "allow"
            and first.execution_status == "succeeded"
            and first.state_before == "issued"
            and first.state_after == "running"
            and first.parent_receipt_ids == ()
            and roles_by_actor.get(
                (first.actor_id, first.actor_key_id)
            )
            == "Manager"
        )
        cause = (
            first.cause
            if isinstance(first, SystemEventReceipt)
            else None
        )
        contract_expiry = (
            isinstance(first, SystemEventReceipt)
            and first.system_event_name == "contract_expired"
            and first.error_code == "CONTRACT_EXPIRED"
            and first.policy_decision == "not_applicable"
            and first.execution_status == "succeeded"
            and first.state_before == "issued"
            and first.state_after == "frozen"
            and first.parent_receipt_ids == ()
            and roles_by_actor.get(
                (first.actor_id, first.actor_key_id)
            )
            == "Sidecar"
            and getattr(cause, "deadline", None)
            == work_order.deadline
            and getattr(cause, "observed_at", None)
            == first.occurred_at
            and getattr(cause, "tip_receipt_digest", None) is None
            and first.occurred_at > work_order.deadline
        )
        maintainer_termination = (
            isinstance(first, TerminationDecisionReceipt)
            and first.policy_decision == "allow"
            and first.execution_status == "succeeded"
            and first.state_before == "issued"
            and first.state_after == "rejected"
            and first.parent_receipt_ids == ()
            and first.target_work_order_digest == work_order.digest
            and roles_by_actor.get(
                (first.actor_id, first.actor_key_id)
            )
            == "Maintainer"
            and first.decided_at >= work_order.issued_at
            and first.occurred_at >= first.decided_at
            and (
                first.occurred_at - first.decided_at
            ).total_seconds()
            <= 300
            and first.occurred_at <= work_order.deadline
        )
        if sum(
            (root_activation, contract_expiry, maintainer_termination)
        ) != 1:
            raise _fail("receipt chain has no valid genesis event")
    prior: list[ActionReceiptEnvelope] = []
    active_patch: ToolCallReceipt | None = None
    current_failure: ToolCallReceipt | None = None
    current_rollback: RollbackReceipt | None = None
    latest_passing_result: ToolCallReceipt | None = None
    latest_composition_trigger: SystemEventReceipt | None = None
    independent_result: ToolCallReceipt | None = None
    independent_failure_terminal = False
    sealed_tail_appended = False
    started_execution_context_ids: set[str] = set()
    started_container_instance_digests: set[str] = set()
    latest_revocation: dict[str, GrantRevokedReceipt] = {}
    decision_by_request: dict[str, ApprovalDecisionReceipt] = {}
    snapshots_by_receipt: list[
        tuple[str, AuthorizationCausalSnapshot]
    ] = []

    def verifier_result_passed(receipt: ToolCallReceipt) -> bool:
        results = tuple(
            result
            for result in receipt.predicate_results
            if result.name == "tests_passed"
        )
        return bool(results) and all(
            result.passed for result in results
        )

    def prior_receipt(
        current: ActionReceiptEnvelope,
        receipt_id: str,
        *,
        digest: str | None = None,
        expected_type=None,
    ) -> ActionReceiptEnvelope:
        candidate = index.by_id.get(receipt_id)
        if (
            candidate is None
            or candidate.sequence >= current.sequence
            or (digest is not None and candidate.digest != digest)
            or (
                expected_type is not None
                and not isinstance(candidate, expected_type)
            )
        ):
            raise _fail("receipt causal reference is unavailable")
        return candidate

    def prior_digest(
        current: ActionReceiptEnvelope,
        digest: str,
        *,
        expected_type=None,
    ) -> ActionReceiptEnvelope:
        candidate = index.by_digest.get(digest)
        if candidate is None:
            raise _fail("receipt causal digest is unavailable")
        return prior_receipt(
            current,
            candidate.receipt_id,
            digest=digest,
            expected_type=expected_type,
        )

    def grant_issuance(
        current: ActionReceiptEnvelope,
        grant_id: str,
    ) -> GrantIssuedReceipt:
        issuance = index.issuance_by_grant.get(grant_id)
        if issuance is None:
            raise _fail("receipt authorizing Grant issuance is unavailable")
        candidate = prior_receipt(
            current,
            issuance.receipt_id,
            expected_type=GrantIssuedReceipt,
        )
        assert isinstance(candidate, GrantIssuedReceipt)
        return candidate

    for receipt in ordered:
        if independent_failure_terminal:
            termination = (
                isinstance(receipt, TerminationDecisionReceipt)
                and receipt.state_before == "evidence_incomplete"
                and receipt.state_after == "rejected"
                and receipt.policy_decision == "allow"
                and receipt.execution_status == "succeeded"
            )
            contract_expiry = (
                isinstance(receipt, SystemEventReceipt)
                and receipt.system_event_name == "contract_expired"
                and receipt.error_code == "CONTRACT_EXPIRED"
                and receipt.state_before == "evidence_incomplete"
                and receipt.state_after == "frozen"
            )
            if sealed_tail_appended or not (termination or contract_expiry):
                raise _fail(
                    "independent evidence failure sealed the episode"
                )
            sealed_tail_appended = True
        root_activation = (
            isinstance(receipt, GrantIssuedReceipt)
            and receipt.parent_grant_id is None
            and receipt.policy_decision == "allow"
            and receipt.execution_status == "succeeded"
        )
        parents: dict[str, ActionReceiptEnvelope] = {}

        def add_parent(parent: ActionReceiptEnvelope) -> None:
            parents[parent.receipt_id] = parent

        if root_activation:
            if receipt.sequence != 1:
                raise _fail("root activation is not the genesis receipt")
        elif receipt.actor_type == "agent":
            grant_id_value = (
                receipt.authorizing_grant_id
                if isinstance(
                    receipt,
                    (GrantIssuedReceipt, GrantRevokedReceipt),
                )
                else receipt.grant_id
            )
            add_parent(grant_issuance(receipt, grant_id_value))
            if receipt.policy_decision == "deny":
                revocation = latest_revocation.get(grant_id_value)
                if revocation is not None:
                    add_parent(revocation)
                if receipt.policy_error_code == "STATE_DENIED" and prior:
                    add_parent(prior[-1])

        if isinstance(receipt, GrantConsumedReceipt):
            if current_failure is not None and current_rollback is not None:
                add_parent(current_failure)
                add_parent(current_rollback)
            if (
                receipt.policy_decision == "allow"
                and (
                    current_failure is None
                    or current_rollback is None
                    or current_rollback.sequence
                    <= current_failure.sequence
                )
            ):
                raise _fail("retry causal episode is unavailable")
        elif isinstance(receipt, GrantRevokedReceipt):
            add_parent(
                grant_issuance(receipt, receipt.revoked_grant_id)
            )
        elif isinstance(receipt, ToolCallReceipt):
            if receipt.tool_name == "owp.repo_read":
                if active_patch is not None:
                    add_parent(active_patch)
            elif receipt.tool_name == "owp.run_tests":
                is_independent_attempt = (
                    receipt.state_before == "evidence_incomplete"
                    and receipt.state_after == "evidence_incomplete"
                    and receipt.policy_decision == "allow"
                    and receipt.execution_status == "succeeded"
                    and roles_by_key.get(receipt.actor_key_id)
                    == "Verifier"
                )
                if active_patch is not None:
                    add_parent(active_patch)
                elif receipt.policy_decision == "allow":
                    raise _fail("tested patch receipt is unavailable")
                if is_independent_attempt:
                    if latest_composition_trigger is None:
                        raise _fail(
                            "independent result episode is unavailable"
                        )
                    add_parent(latest_composition_trigger)
                    factors = receipt.correlation_factors
                    if (
                        factors.execution_context_id is None
                        or factors.container_instance_id_digest is None
                        or factors.execution_context_id
                        in started_execution_context_ids
                        or factors.container_instance_id_digest
                        in started_container_instance_digests
                    ):
                        raise _fail(
                            "independent result requires fresh execution context"
                        )
                    if (
                        verifier_result_passed(receipt)
                        and independent_result is not None
                    ):
                        raise _fail(
                            "independent result episode is unavailable"
                        )
            elif receipt.tool_name == "owp.create_pr_proposal":
                arguments = receipt.request_arguments
                if not isinstance(arguments, CreatePrProposalArguments):
                    raise _fail("PR proposal arguments are unavailable")
                patch = prior_digest(
                    receipt,
                    arguments.target_patch_digest,
                    expected_type=ToolCallReceipt,
                )
                if (
                    patch.tool_name != "owp.apply_patch"
                    or patch is not active_patch
                ):
                    raise _fail("PR proposal target patch is not active")
                decision = prior_receipt(
                    receipt,
                    receipt.approval_receipt_id,
                    digest=receipt.approval_receipt_digest,
                    expected_type=ApprovalDecisionReceipt,
                )
                assert isinstance(decision, ApprovalDecisionReceipt)
                request = prior_receipt(
                    receipt,
                    decision.request_receipt_id,
                    digest=decision.request_receipt_digest,
                    expected_type=ApprovalRequestedReceipt,
                )
                assert isinstance(request, ApprovalRequestedReceipt)
                scope = {
                    "work_order_digest": work_order.digest,
                    "operation": "create_local_pr_proposal",
                    "target_patch_digest": patch.digest,
                }
                if (
                    request.request_kind != "high_risk_action"
                    or dict(request.requested_scope) != scope
                    or dict(decision.approved_scope) != scope
                    or request.expires_at != decision.expires_at
                    or decision_by_request.get(request.receipt_id)
                    is not decision
                ):
                    raise _fail("PR proposal approval binding is invalid")
                add_parent(patch)
                add_parent(decision)
            elif receipt.tool_name == "owp.compose_proof":
                arguments = receipt.request_arguments
                if not isinstance(arguments, ComposeProofArguments):
                    raise _fail("composition arguments are unavailable")
                if receipt.state_before == "evidence_incomplete":
                    if (
                        latest_composition_trigger is None
                        or independent_result is None
                    ):
                        raise _fail(
                            "recomposition causal inputs are unavailable"
                        )
                    add_parent(latest_composition_trigger)
                    add_parent(independent_result)
                    if (
                        arguments.previous_report_digest
                        != latest_composition_trigger.cause.composition_report_digest
                    ):
                        raise _fail(
                            "composition previous report digest is invalid"
                        )
                else:
                    if (
                        receipt.state_before == "locally_verified"
                        and arguments.previous_report_digest is not None
                    ):
                        raise _fail(
                            "composition previous report digest is invalid"
                        )
                    if active_patch is not None:
                        add_parent(active_patch)
                    if latest_passing_result is not None:
                        add_parent(latest_passing_result)
                    if (
                        receipt.policy_decision == "allow"
                        and (
                            active_patch is None
                            or latest_passing_result is None
                        )
                    ):
                        raise _fail(
                            "composition causal inputs are unavailable"
                        )
        elif isinstance(receipt, ApprovalRequestedReceipt):
            scope = dict(receipt.requested_scope)
            if receipt.request_kind == "high_risk_action":
                patch = prior_digest(
                    receipt,
                    scope["target_patch_digest"],
                    expected_type=ToolCallReceipt,
                )
                if (
                    patch.tool_name != "owp.apply_patch"
                    or patch is not active_patch
                ):
                    raise _fail("approval target patch is not active")
                add_parent(patch)
            else:
                report_digest = scope["composition_report_digest"]
                trigger = next(
                    (
                        item
                        for item in reversed(prior)
                        if (
                            isinstance(item, SystemEventReceipt)
                            and item.system_event_name
                            == "proof_composed"
                            and getattr(
                                item.cause,
                                "composition_report_digest",
                                None,
                            )
                            == report_digest
                        )
                    ),
                    None,
                )
                if trigger is None:
                    raise _fail(
                        "final approval trigger is unavailable"
                    )
                add_parent(trigger)
        elif isinstance(receipt, ApprovalDecisionReceipt):
            request = prior_receipt(
                receipt,
                receipt.request_receipt_id,
                digest=receipt.request_receipt_digest,
                expected_type=ApprovalRequestedReceipt,
            )
            assert isinstance(request, ApprovalRequestedReceipt)
            if receipt.request_receipt_id in decision_by_request:
                raise _fail(
                    "approval request has more than one decision"
                )
            if (
                receipt.approved_scope != request.requested_scope
                or receipt.expires_at != request.expires_at
                or receipt.decided_at < request.occurred_at
                or receipt.decided_at > request.expires_at
                or receipt.occurred_at < receipt.decided_at
                or (
                    receipt.occurred_at - receipt.decided_at
                ).total_seconds()
                > 300
            ):
                raise _fail("approval decision is stale or mismatched")
            decision_by_request[receipt.request_receipt_id] = receipt
            add_parent(request)
        elif isinstance(receipt, RollbackReceipt):
            patch = prior_receipt(
                receipt,
                receipt.target_patch_receipt_id,
                digest=receipt.target_patch_digest,
                expected_type=ToolCallReceipt,
            )
            if (
                patch.tool_name != "owp.apply_patch"
                or patch is not active_patch
            ):
                raise _fail("rollback target is not the active patch")
            add_parent(patch)
            proactive_denial = (
                receipt.policy_decision == "deny"
                and receipt.policy_error_code == "STATE_DENIED"
                and receipt.execution_status == "denied"
                and receipt.state_before == receipt.state_after
                and receipt.state_before in {"running", "retrying"}
            )
            if not proactive_denial:
                failure = current_failure
                if (
                    failure is None
                    or failure.sequence <= patch.sequence
                    or patch.receipt_id not in failure.parent_receipt_ids
                ):
                    raise _fail(
                        "rollback failure receipt is unavailable"
                    )
                add_parent(failure)
        elif isinstance(receipt, SystemEventReceipt):
            if receipt.system_event_name in {
                "proof_composed",
                "security_violation",
            }:
                initiator = prior_digest(
                    receipt,
                    receipt.cause.initiator_receipt_digest,
                    expected_type=ToolCallReceipt,
                )
                parents = {initiator.receipt_id: initiator}
            elif prior:
                parents = {prior[-1].receipt_id: prior[-1]}
        elif isinstance(receipt, TerminationDecisionReceipt):
            parents = (
                {prior[-1].receipt_id: prior[-1]} if prior else {}
            )

        expected = tuple(
            parent.receipt_id
            for parent in sorted(
                parents.values(),
                key=lambda item: item.sequence,
            )
        )
        if receipt.parent_receipt_ids != expected:
            raise _fail(
                "receipt causal parents failed exact historical replay"
            )

        if (
            isinstance(receipt, ToolCallReceipt)
            and receipt.tool_name == "owp.apply_patch"
            and receipt.policy_decision == "allow"
            and receipt.execution_status == "succeeded"
        ):
            if active_patch is not None:
                raise _fail("a second active patch is not allowed")
            active_patch = receipt
            current_failure = None
            current_rollback = None
            latest_passing_result = None
        elif (
            isinstance(receipt, RollbackReceipt)
            and receipt.policy_decision == "allow"
            and receipt.execution_status == "succeeded"
        ):
            active_patch = None
            current_rollback = receipt
        if (
            isinstance(receipt, ToolCallReceipt)
            and receipt.tool_name == "owp.run_tests"
            and receipt.policy_decision == "allow"
            and receipt.execution_status == "succeeded"
        ):
            if receipt.state_after == "needs_rework":
                current_failure = receipt
                current_rollback = None
            elif (
                receipt.state_before == "evidence_incomplete"
                and receipt.state_after == "evidence_incomplete"
                and roles_by_key.get(receipt.actor_key_id)
                == "Verifier"
                and verifier_result_passed(receipt)
            ):
                independent_result = receipt
            elif (
                receipt.state_before == "evidence_incomplete"
                and receipt.state_after == "evidence_incomplete"
                and roles_by_key.get(receipt.actor_key_id)
                == "Verifier"
            ):
                independent_failure_terminal = True
            elif receipt.state_after == "locally_verified":
                latest_passing_result = receipt
        if (
            isinstance(receipt, ToolCallReceipt)
            and receipt.quota_charge is not None
            and roles_by_key.get(receipt.actor_key_id)
            in {"Developer", "Verifier"}
        ):
            factors = receipt.correlation_factors
            if factors.execution_context_id is not None:
                started_execution_context_ids.add(
                    factors.execution_context_id
                )
            if factors.container_instance_id_digest is not None:
                started_container_instance_digests.add(
                    factors.container_instance_id_digest
                )
        if (
            isinstance(receipt, SystemEventReceipt)
            and receipt.system_event_name == "proof_composed"
        ):
            latest_composition_trigger = receipt
            independent_result = None
        if (
            isinstance(receipt, GrantRevokedReceipt)
            and receipt.policy_decision == "allow"
            and receipt.execution_status == "succeeded"
        ):
            latest_revocation[receipt.revoked_grant_id] = receipt
        snapshots_by_receipt.append(
            (
                receipt.receipt_id,
                AuthorizationCausalSnapshot(
                    active_patch_receipt_id=(
                        active_patch.receipt_id
                        if active_patch is not None
                        else None
                    ),
                    failure_receipt_id=(
                        current_failure.receipt_id
                        if current_failure is not None
                        else None
                    ),
                    rollback_receipt_id=(
                        current_rollback.receipt_id
                        if current_rollback is not None
                        else None
                    ),
                    latest_composition_trigger_id=(
                        latest_composition_trigger.receipt_id
                        if latest_composition_trigger is not None
                        else None
                    ),
                    independent_result_receipt_id=(
                        independent_result.receipt_id
                        if independent_result is not None
                        else None
                    ),
                    approval_decision_by_request=tuple(
                        (request_id, decision.receipt_id)
                        for request_id, decision
                        in decision_by_request.items()
                    ),
                ),
            )
        )
        prior.append(receipt)

    return AuthorizationCausalState(
        active_patch_receipt_id=(
            active_patch.receipt_id
            if active_patch is not None
            else None
        ),
        failure_receipt_id=(
            current_failure.receipt_id
            if current_failure is not None
            else None
        ),
        rollback_receipt_id=(
            current_rollback.receipt_id
            if current_rollback is not None
            else None
        ),
        latest_composition_trigger_id=(
            latest_composition_trigger.receipt_id
            if latest_composition_trigger is not None
            else None
        ),
        independent_result_receipt_id=(
            independent_result.receipt_id
            if independent_result is not None
            else None
        ),
        approval_decision_by_request=tuple(
            (request_id, decision.receipt_id)
            for request_id, decision in decision_by_request.items()
        ),
        snapshots_by_receipt=tuple(snapshots_by_receipt),
    )


__all__ = [
    "AuthorizationCausalState",
    "AuthorizationCausalSnapshot",
    "AuthorizationCausalityError",
    "replay_authorization_causality",
    "validate_authorization_causal_bindings",
]
