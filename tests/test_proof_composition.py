"""Authorization causality replay tests."""

from __future__ import annotations

import copy

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

import openworkproof.evidence as evidence
from openworkproof.composition import (
    MAX_AUTHORIZATION_RECEIPTS,
    AuthorizationCausalityError,
    _bounded_receipts,
    replay_authorization_causality,
)
from openworkproof.models import CapabilityGrant, WorkOrder
from openworkproof.signing import sign_payload
from test_contract import system_input_digest
from test_receipt_chain import (
    _approval_decision_for_request,
    _approval_request_for_patch,
    _grant_id,
    _linked_tool_receipt,
    _pr_proposal_call,
    _resign_linked_agent_receipt,
)


class _CountingSinglePass:
    def __init__(self, count: int) -> None:
        self._values = iter(range(count))
        self.iter_calls = 0
        self.yielded = 0

    def __iter__(self):
        if self.iter_calls:
            raise AssertionError("input was iterated more than once")
        self.iter_calls += 1
        return self

    def __next__(self):
        value = next(self._values)
        self.yielded += 1
        return value


class _ExplodingReceipts:
    def __init__(self, error: Exception | None = None) -> None:
        self.error = error or RuntimeError("receipt source exploded")

    def __iter__(self):
        return self

    def __next__(self):
        raise self.error


def test_causal_replay_normalizes_non_iterable_input(
    signed_work_order: WorkOrder,
) -> None:
    with pytest.raises(
        AuthorizationCausalityError,
        match="receipt history input is unavailable",
    ):
        replay_authorization_causality(signed_work_order, None)


def test_causal_replay_normalizes_iteration_failure(
    signed_work_order: WorkOrder,
) -> None:
    with pytest.raises(
        AuthorizationCausalityError,
        match="receipt history input is unavailable",
    ):
        replay_authorization_causality(
            signed_work_order,
            _ExplodingReceipts(),
        )


def test_causal_replay_preserves_domain_failure(
    signed_work_order: WorkOrder,
) -> None:
    error = AuthorizationCausalityError("upstream domain failure")

    with pytest.raises(AuthorizationCausalityError) as caught:
        replay_authorization_causality(
            signed_work_order,
            _ExplodingReceipts(error),
        )

    assert caught.value is error


def test_bounded_receipts_accepts_exact_capacity() -> None:
    receipts = tuple(range(MAX_AUTHORIZATION_RECEIPTS))

    assert _bounded_receipts(receipts) == receipts


def test_causal_replay_rejects_one_over_capacity(
    signed_work_order: WorkOrder,
) -> None:
    receipts = tuple(range(MAX_AUTHORIZATION_RECEIPTS + 1))

    with pytest.raises(
        AuthorizationCausalityError,
        match="receipt history exceeds its bounded input capacity",
    ):
        replay_authorization_causality(signed_work_order, receipts)


def test_causal_replay_consumes_at_most_one_over_once(
    signed_work_order: WorkOrder,
) -> None:
    receipts = _CountingSinglePass(MAX_AUTHORIZATION_RECEIPTS + 10)

    with pytest.raises(AuthorizationCausalityError):
        replay_authorization_causality(signed_work_order, receipts)

    assert receipts.iter_calls == 1
    assert receipts.yielded == MAX_AUTHORIZATION_RECEIPTS + 1


def _with_parents(receipt, parent_receipt_ids, role_keys):
    raw = receipt.model_dump(mode="json")
    raw["parent_receipt_ids"] = list(parent_receipt_ids)
    return evidence.ACTION_RECEIPT_ADAPTER.validate_python(
        sign_payload(
            "action-receipt",
            raw,
            role_keys["Sidecar"][0],
        )
    )


def _with_correlation_factors(receipt, updates, role_keys):
    raw = receipt.model_dump(mode="json")
    raw["correlation_factors"].update(copy.deepcopy(updates))
    return evidence.ACTION_RECEIPT_ADAPTER.validate_python(
        sign_payload(
            "action-receipt",
            raw,
            role_keys["Sidecar"][0],
        )
    )


def _with_compose_previous_report(receipt, report_digest, role_keys):
    raw = receipt.model_dump(mode="json")
    raw["request_arguments"]["previous_report_digest"] = report_digest
    raw["arguments_digest"] = evidence.request_arguments_digest(
        "owp.compose_proof",
        raw["request_arguments"],
    )
    claim = raw["nested_claim"]
    claim["arguments_digest"] = raw["arguments_digest"]
    claim = sign_payload(
        "agent-request",
        claim,
        role_keys["Manager"][0],
    )
    raw["nested_claim"] = claim
    raw["nested_claim_digest"] = claim["digest"]
    return evidence.ACTION_RECEIPT_ADAPTER.validate_python(
        sign_payload(
            "action-receipt",
            raw,
            role_keys["Sidecar"][0],
        )
    )


def _resign_human_decision(
    receipt,
    *,
    role_keys,
    raw_updates,
    claim_updates,
):
    raw = receipt.model_dump(mode="json")
    raw.update(copy.deepcopy(raw_updates))
    claim = raw["nested_claim"]
    claim.update(copy.deepcopy(claim_updates))
    claim = sign_payload(
        "human-decision",
        claim,
        role_keys["Maintainer"][0],
    )
    raw["nested_claim"] = claim
    raw["nested_claim_digest"] = claim["digest"]
    return evidence.ACTION_RECEIPT_ADAPTER.validate_python(
        sign_payload(
            "action-receipt",
            raw,
            role_keys["Sidecar"][0],
        )
    )


def _resign_agent_work_order(
    receipt,
    *,
    work_order_digest: str,
    actor_role: str,
    role_keys,
):
    raw = receipt.model_dump(mode="json")
    raw["work_order_digest"] = work_order_digest
    claim = raw["nested_claim"]
    claim["work_order_digest"] = work_order_digest
    claim = sign_payload(
        "agent-request",
        claim,
        role_keys[actor_role][0],
    )
    raw["nested_claim"] = claim
    raw["nested_claim_digest"] = claim["digest"]
    return evidence.ACTION_RECEIPT_ADAPTER.validate_python(
        sign_payload(
            "action-receipt",
            raw,
            role_keys["Sidecar"][0],
        )
    )


def _patch_history(
    *,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    label: str,
):
    root = sidecar_receipt_factory(
        state_before="issued",
        state_after="running",
        event_type="grant_issued",
        sequence=1,
    )
    patch = _linked_tool_receipt(
        tool_name="owp.apply_patch",
        state_before="running",
        state_after="running",
        sequence=2,
        previous_receipt=root,
        root=signed_root_grant,
        signed_work_order=signed_work_order,
        sidecar_receipt_factory=sidecar_receipt_factory,
        role_keys=ephemeral_role_keys,
        label=f"{label}:patch",
        remaining_after=49,
    )
    return root, patch


def _approval_history(
    *,
    approved: bool,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    label: str,
):
    root, patch = _patch_history(
        signed_work_order=signed_work_order,
        signed_root_grant=signed_root_grant,
        ephemeral_role_keys=ephemeral_role_keys,
        sidecar_receipt_factory=sidecar_receipt_factory,
        label=label,
    )
    request = _approval_request_for_patch(
        root=signed_root_grant,
        root_issuance=root,
        patch=patch,
        signed_work_order=signed_work_order,
        sidecar_receipt_factory=sidecar_receipt_factory,
        role_keys=ephemeral_role_keys,
        label=f"{label}:request",
    )
    decision = _approval_decision_for_request(
        request=request,
        previous_receipt=request,
        sequence=4,
        approved=approved,
        parent_receipt_ids=(request.receipt_id,),
        signed_work_order=signed_work_order,
        sidecar_receipt_factory=sidecar_receipt_factory,
        role_keys=ephemeral_role_keys,
        label=f"{label}:decision",
    )
    return root, patch, request, decision


def _linked_run_tests(
    *,
    state_before: str,
    state_after: str,
    sequence: int,
    previous_receipt,
    parent_receipt_ids: tuple[str, ...],
    grant: CapabilityGrant,
    signed_work_order: WorkOrder,
    sidecar_receipt_factory,
    role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    label: str,
    remaining_after: int,
    test_passed: bool = True,
):
    base = sidecar_receipt_factory(
        state_before=state_before,
        state_after=state_after,
        event_type="tool_call",
        actor_role="Verifier",
        sequence=sequence,
        previous_receipt_digest=previous_receipt.digest,
        parent_receipt_ids=parent_receipt_ids,
        occurred_at=f"2026-01-01T00:00:{sequence + 1:02d}Z",
        test_passed=test_passed,
    )
    return _resign_linked_agent_receipt(
        base,
        grant_id=grant.grant_id,
        tool_name="owp.run_tests",
        arguments=base.request_arguments.model_dump(mode="json"),
        actor_role="Verifier",
        label=label,
        role_keys=role_keys,
        work_order_digest=signed_work_order.digest,
        updates={
            "sequence": sequence,
            "previous_receipt_digest": previous_receipt.digest,
            "parent_receipt_ids": list(parent_receipt_ids),
            "occurred_at": f"2026-01-01T00:00:{sequence + 1:02d}Z",
            "quota_charge": {
                "grant_id": grant.grant_id,
                "metric": "tool_calls",
                "amount": 1,
                "remaining_after": remaining_after,
            },
        },
    )


def _proof_composed(
    *,
    initiator,
    sequence: int,
    state_before: str,
    state_after: str,
    signed_work_order: WorkOrder,
    sidecar_receipt_factory,
    role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    label: str,
    state_version_before: int | None = None,
):
    trigger = sidecar_receipt_factory(
        state_before=state_before,
        state_after=state_after,
        event_type="system_event",
        event_name="proof_composed",
        sequence=sequence,
        previous_receipt_digest=initiator.digest,
        parent_receipt_ids=(initiator.receipt_id,),
        occurred_at=f"2026-01-01T00:00:{sequence + 1:02d}Z",
    )
    raw = trigger.model_dump(mode="json")
    raw["work_order_digest"] = signed_work_order.digest
    raw["receipt_id"] = _grant_id(f"{label}:receipt")
    raw["nonce"] = _grant_id(f"{label}:nonce")
    cause = copy.deepcopy(raw["cause"])
    cause.update(
        {
            "initiator_receipt_digest": initiator.digest,
            "state_version_before": (
                sequence - 1
                if state_version_before is None
                else state_version_before
            ),
        }
    )
    digest = system_input_digest(
        "proof_composed",
        signed_work_order.digest,
        cause,
    )
    raw["cause"] = cause
    raw["input_digest"] = digest
    raw["nested_claim"]["work_order_digest"] = signed_work_order.digest
    raw["nested_claim"]["cause"] = cause
    raw["nested_claim"]["input_digest"] = digest
    raw["nested_claim"]["occurred_at"] = raw["occurred_at"]
    raw["nested_claim_digest"] = digest
    return evidence.ACTION_RECEIPT_ADAPTER.validate_python(
        sign_payload(
            "action-receipt",
            raw,
            role_keys["Sidecar"][0],
        )
    )


def _preactivation_genesis(
    *,
    event: str,
    signed_work_order: WorkOrder,
    sidecar_receipt_factory,
    role_keys,
    invalid: bool = False,
):
    if event == "expiry":
        receipt = sidecar_receipt_factory(
            state_before="issued",
            state_after="frozen",
            event_type="system_event",
            event_name="contract_expired",
            sequence=1,
            previous_receipt_digest=None,
            parent_receipt_ids=(),
            occurred_at="2026-01-02T00:00:01Z",
        )
        if not invalid:
            return receipt
        raw = receipt.model_dump(mode="json")
        cause = copy.deepcopy(raw["cause"])
        cause["deadline"] = "2026-01-01T23:59:59Z"
        digest = system_input_digest(
            "contract_expired",
            signed_work_order.digest,
            cause,
        )
        raw["cause"] = cause
        raw["input_digest"] = digest
        raw["nested_claim"]["cause"] = cause
        raw["nested_claim"]["input_digest"] = digest
        raw["nested_claim_digest"] = digest
    else:
        from test_state import _termination_receipt_at

        receipt = _termination_receipt_at(
            state_before="issued",
            decided_at="2026-01-01T00:00:01Z",
            occurred_at="2026-01-01T00:00:02Z",
            sequence=1,
            previous_receipt_digest=None,
            parent_receipt_ids=(),
            sidecar_receipt_factory=sidecar_receipt_factory,
            ephemeral_role_keys=role_keys,
        )
        if not invalid:
            return receipt
        raw = receipt.model_dump(mode="json")
        raw["state_before"] = "running"
    return evidence.ACTION_RECEIPT_ADAPTER.validate_python(
        sign_payload(
            "action-receipt",
            raw,
            role_keys["Sidecar"][0],
        )
    )


@pytest.mark.parametrize("event", ("expiry", "termination"))
def test_causal_replay_accepts_preactivation_genesis(
    event: str,
    signed_work_order: WorkOrder,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    sidecar_receipt_factory,
) -> None:
    receipt = _preactivation_genesis(
        event=event,
        signed_work_order=signed_work_order,
        sidecar_receipt_factory=sidecar_receipt_factory,
        role_keys=ephemeral_role_keys,
    )

    replay_authorization_causality(
        signed_work_order,
        (receipt,),
    )


@pytest.mark.parametrize("event", ("expiry", "termination"))
def test_causal_replay_rejects_invalid_preactivation_genesis(
    event: str,
    signed_work_order: WorkOrder,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    sidecar_receipt_factory,
) -> None:
    receipt = _preactivation_genesis(
        event=event,
        signed_work_order=signed_work_order,
        sidecar_receipt_factory=sidecar_receipt_factory,
        role_keys=ephemeral_role_keys,
        invalid=True,
    )

    with pytest.raises(AuthorizationCausalityError):
        replay_authorization_causality(
            signed_work_order,
            (receipt,),
        )


def test_causal_replay_rejects_second_active_patch(
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    sidecar_receipt_factory,
) -> None:
    root, first = _patch_history(
        signed_work_order=signed_work_order,
        signed_root_grant=signed_root_grant,
        ephemeral_role_keys=ephemeral_role_keys,
        sidecar_receipt_factory=sidecar_receipt_factory,
        label="second-active:first",
    )
    second = _linked_tool_receipt(
        tool_name="owp.apply_patch",
        state_before="running",
        state_after="running",
        sequence=3,
        previous_receipt=first,
        root=signed_root_grant,
        signed_work_order=signed_work_order,
        sidecar_receipt_factory=sidecar_receipt_factory,
        role_keys=ephemeral_role_keys,
        label="second-active:second",
        remaining_after=48,
    )
    second = _with_parents(
        second,
        (root.receipt_id,),
        ephemeral_role_keys,
    )

    with pytest.raises(AuthorizationCausalityError):
        replay_authorization_causality(
            signed_work_order,
            (root, first, second),
        )


@pytest.mark.parametrize("tamper", ("sequence_gap", "previous_digest"))
def test_causal_replay_rejects_nonadjacent_signed_chain(
    tamper: str,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    sidecar_receipt_factory,
) -> None:
    root, patch = _patch_history(
        signed_work_order=signed_work_order,
        signed_root_grant=signed_root_grant,
        ephemeral_role_keys=ephemeral_role_keys,
        sidecar_receipt_factory=sidecar_receipt_factory,
        label=f"chain-{tamper}",
    )
    raw = patch.model_dump(mode="json")
    if tamper == "sequence_gap":
        raw["sequence"] = 3
    else:
        raw["previous_receipt_digest"] = "f" * 64
    patch = evidence.ACTION_RECEIPT_ADAPTER.validate_python(
        sign_payload(
            "action-receipt",
            raw,
            ephemeral_role_keys["Sidecar"][0],
        )
    )

    with pytest.raises(AuthorizationCausalityError):
        replay_authorization_causality(
            signed_work_order,
            (root, patch),
        )


def test_causal_replay_rejects_cross_work_order_receipt(
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    sidecar_receipt_factory,
) -> None:
    root, patch = _patch_history(
        signed_work_order=signed_work_order,
        signed_root_grant=signed_root_grant,
        ephemeral_role_keys=ephemeral_role_keys,
        sidecar_receipt_factory=sidecar_receipt_factory,
        label="cross-work-order",
    )
    patch = _resign_agent_work_order(
        patch,
        work_order_digest="f" * 64,
        actor_role="Manager",
        role_keys=ephemeral_role_keys,
    )

    with pytest.raises(AuthorizationCausalityError):
        replay_authorization_causality(
            signed_work_order,
            (root, patch),
        )


def test_causal_replay_fails_closed_for_malformed_receipt(
    signed_work_order: WorkOrder,
) -> None:
    with pytest.raises(AuthorizationCausalityError):
        replay_authorization_causality(
            signed_work_order,
            (object(),),
        )


def test_causal_replay_rejects_stale_approval_decision(
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    sidecar_receipt_factory,
) -> None:
    root, patch, request, decision = _approval_history(
        approved=True,
        signed_work_order=signed_work_order,
        signed_root_grant=signed_root_grant,
        ephemeral_role_keys=ephemeral_role_keys,
        sidecar_receipt_factory=sidecar_receipt_factory,
        label="stale-decision",
    )
    stale_at = "2026-01-01T00:05:01Z"
    decision = _resign_human_decision(
        decision,
        role_keys=ephemeral_role_keys,
        raw_updates={
            "decided_at": stale_at,
            "occurred_at": stale_at,
        },
        claim_updates={"decided_at": stale_at},
    )

    with pytest.raises(AuthorizationCausalityError):
        replay_authorization_causality(
            signed_work_order,
            (root, patch, request, decision),
        )


def test_causal_replay_rejects_cross_request_decision(
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    sidecar_receipt_factory,
) -> None:
    root, patch, request, decision = _approval_history(
        approved=True,
        signed_work_order=signed_work_order,
        signed_root_grant=signed_root_grant,
        ephemeral_role_keys=ephemeral_role_keys,
        sidecar_receipt_factory=sidecar_receipt_factory,
        label="cross-request",
    )
    decision = _resign_human_decision(
        decision,
        role_keys=ephemeral_role_keys,
        raw_updates={"request_receipt_digest": root.digest},
        claim_updates={"request_receipt_digest": root.digest},
    )

    with pytest.raises(AuthorizationCausalityError):
        replay_authorization_causality(
            signed_work_order,
            (root, patch, request, decision),
        )


@pytest.mark.parametrize("approved", (True, False))
def test_causal_replay_accepts_pr_approval_outcome(
    approved: bool,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    sidecar_receipt_factory,
) -> None:
    root, patch, request, decision = _approval_history(
        approved=approved,
        signed_work_order=signed_work_order,
        signed_root_grant=signed_root_grant,
        ephemeral_role_keys=ephemeral_role_keys,
        sidecar_receipt_factory=sidecar_receipt_factory,
        label=f"pr-outcome-{approved}",
    )
    call = _pr_proposal_call(
        root=signed_root_grant,
        approval_id=decision.receipt_id,
        approval_digest=decision.digest,
        previous_receipt=decision,
        parent_receipt_ids=(
            root.receipt_id,
            patch.receipt_id,
            decision.receipt_id,
        ),
        target_patch_digest=patch.digest,
        occurred_at="2026-01-01T00:00:09Z",
        signed_work_order=signed_work_order,
        sidecar_receipt_factory=sidecar_receipt_factory,
        role_keys=ephemeral_role_keys,
        label=f"pr-outcome-{approved}:call",
    )
    if not approved:
        raw = call.model_dump(mode="json")
        raw.update(
            {
                "policy_decision": "deny",
                "policy_error_code": "APPROVAL_DENIED",
                "execution_status": "denied",
                "quota_charge": None,
                "output_digest": None,
            }
        )
        call = evidence.ACTION_RECEIPT_ADAPTER.validate_python(
            sign_payload(
                "action-receipt",
                raw,
                ephemeral_role_keys["Sidecar"][0],
            )
        )

    state = replay_authorization_causality(
        signed_work_order,
        (root, patch, request, decision, call),
    )

    assert state.approval_decision_by_request == (
        (request.receipt_id, decision.receipt_id),
    )


def _recomposition_history(
    *,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    sidecar_receipt_factory,
    independent_passed: bool = True,
):
    root, patch = _patch_history(
        signed_work_order=signed_work_order,
        signed_root_grant=signed_root_grant,
        ephemeral_role_keys=ephemeral_role_keys,
        sidecar_receipt_factory=sidecar_receipt_factory,
        label="recompose",
    )
    passing = _linked_run_tests(
        state_before="running",
        state_after="locally_verified",
        sequence=3,
        previous_receipt=patch,
        parent_receipt_ids=(root.receipt_id, patch.receipt_id),
        grant=signed_root_grant,
        signed_work_order=signed_work_order,
        sidecar_receipt_factory=sidecar_receipt_factory,
        role_keys=ephemeral_role_keys,
        label="recompose:passing",
        remaining_after=48,
    )
    first_compose = _linked_tool_receipt(
        tool_name="owp.compose_proof",
        state_before="locally_verified",
        state_after="locally_verified",
        sequence=4,
        previous_receipt=passing,
        root=signed_root_grant,
        signed_work_order=signed_work_order,
        sidecar_receipt_factory=sidecar_receipt_factory,
        role_keys=ephemeral_role_keys,
        label="recompose:first-compose",
        remaining_after=47,
    )
    first_compose = _with_parents(
        first_compose,
        (
            root.receipt_id,
            patch.receipt_id,
            passing.receipt_id,
        ),
        ephemeral_role_keys,
    )
    trigger = _proof_composed(
        initiator=first_compose,
        sequence=5,
        state_before="locally_verified",
        state_after="evidence_incomplete",
        signed_work_order=signed_work_order,
        sidecar_receipt_factory=sidecar_receipt_factory,
        role_keys=ephemeral_role_keys,
        label="recompose:trigger",
    )
    independent = _linked_run_tests(
        state_before="evidence_incomplete",
        state_after="evidence_incomplete",
        sequence=6,
        previous_receipt=trigger,
        parent_receipt_ids=(
            root.receipt_id,
            patch.receipt_id,
            trigger.receipt_id,
        ),
        grant=signed_root_grant,
        signed_work_order=signed_work_order,
        sidecar_receipt_factory=sidecar_receipt_factory,
        role_keys=ephemeral_role_keys,
        label="recompose:independent",
        remaining_after=46,
        test_passed=independent_passed,
    )
    independent = _with_correlation_factors(
        independent,
        {
            "execution_context_id": _grant_id(
                "recompose:independent:execution-context"
            ),
            "container_instance_id_digest": _grant_id(
                "recompose:independent:container-instance"
            ),
        },
        ephemeral_role_keys,
    )
    recomposition = _linked_tool_receipt(
        tool_name="owp.compose_proof",
        state_before="evidence_incomplete",
        state_after="evidence_incomplete",
        sequence=7,
        previous_receipt=independent,
        root=signed_root_grant,
        signed_work_order=signed_work_order,
        sidecar_receipt_factory=sidecar_receipt_factory,
        role_keys=ephemeral_role_keys,
        label="recompose:second-compose",
        remaining_after=45,
    )
    recomposition = _with_parents(
        recomposition,
        (
            root.receipt_id,
            trigger.receipt_id,
            independent.receipt_id,
        ),
        ephemeral_role_keys,
    )
    recomposition = _with_compose_previous_report(
        recomposition,
        trigger.cause.composition_report_digest,
        ephemeral_role_keys,
    )
    return (
        root,
        patch,
        passing,
        first_compose,
        trigger,
        independent,
        recomposition,
    )


def test_causal_replay_accepts_exact_recomposition_parents(
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    sidecar_receipt_factory,
) -> None:
    history = _recomposition_history(
        signed_work_order=signed_work_order,
        signed_root_grant=signed_root_grant,
        ephemeral_role_keys=ephemeral_role_keys,
        sidecar_receipt_factory=sidecar_receipt_factory,
    )

    state = replay_authorization_causality(
        signed_work_order,
        history,
    )

    assert state.active_patch_receipt_id == history[1].receipt_id
    assert state.latest_composition_trigger_id == history[4].receipt_id
    assert state.independent_result_receipt_id == history[5].receipt_id
    assert state.independent_failure_terminal is False


def test_causal_replay_exposes_terminal_independent_failure(
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    sidecar_receipt_factory,
) -> None:
    prefix = _recomposition_history(
        signed_work_order=signed_work_order,
        signed_root_grant=signed_root_grant,
        ephemeral_role_keys=ephemeral_role_keys,
        sidecar_receipt_factory=sidecar_receipt_factory,
        independent_passed=False,
    )[:6]

    state = replay_authorization_causality(
        signed_work_order,
        prefix,
    )

    assert state.independent_failure_terminal is True


@pytest.mark.parametrize("followup", ("false", "passing", "compose"))
def test_causal_replay_seals_after_first_false_independent_result(
    followup: str,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    sidecar_receipt_factory,
) -> None:
    prefix = _recomposition_history(
        signed_work_order=signed_work_order,
        signed_root_grant=signed_root_grant,
        ephemeral_role_keys=ephemeral_role_keys,
        sidecar_receipt_factory=sidecar_receipt_factory,
        independent_passed=False,
    )[:6]
    root, patch, _, _, trigger, failed = prefix
    if followup == "compose":
        next_receipt = _linked_tool_receipt(
            tool_name="owp.compose_proof",
            state_before="evidence_incomplete",
            state_after="evidence_incomplete",
            sequence=7,
            previous_receipt=failed,
            root=signed_root_grant,
            signed_work_order=signed_work_order,
            sidecar_receipt_factory=sidecar_receipt_factory,
            role_keys=ephemeral_role_keys,
            label="sealed:compose",
            remaining_after=45,
        )
        next_receipt = _with_parents(
            next_receipt,
            (
                root.receipt_id,
                trigger.receipt_id,
                failed.receipt_id,
            ),
            ephemeral_role_keys,
        )
    else:
        next_receipt = _linked_run_tests(
            state_before="evidence_incomplete",
            state_after="evidence_incomplete",
            sequence=7,
            previous_receipt=failed,
            parent_receipt_ids=(
                root.receipt_id,
                patch.receipt_id,
                trigger.receipt_id,
            ),
            grant=signed_root_grant,
            signed_work_order=signed_work_order,
            sidecar_receipt_factory=sidecar_receipt_factory,
            role_keys=ephemeral_role_keys,
            label=f"sealed:{followup}",
            remaining_after=45,
            test_passed=followup == "passing",
        )

    with pytest.raises(
        AuthorizationCausalityError,
        match="sealed",
    ):
        replay_authorization_causality(
            signed_work_order,
            (*prefix, next_receipt),
        )


@pytest.mark.parametrize(
    ("field_name", "replacement"),
    (
        ("execution_context_id", None),
        ("container_instance_id_digest", None),
        ("execution_context_id", "reuse"),
        ("container_instance_id_digest", "reuse"),
    ),
)
def test_causal_replay_requires_fresh_independent_context_factors(
    field_name: str,
    replacement: str | None,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    sidecar_receipt_factory,
) -> None:
    history = list(
        _recomposition_history(
            signed_work_order=signed_work_order,
            signed_root_grant=signed_root_grant,
            ephemeral_role_keys=ephemeral_role_keys,
            sidecar_receipt_factory=sidecar_receipt_factory,
        )[:6]
    )
    prior_value = getattr(history[2].correlation_factors, field_name)
    if replacement is None:
        with pytest.raises(ValueError, match="runtime correlation"):
            _with_correlation_factors(
                history[-1],
                {field_name: None},
                ephemeral_role_keys,
            )
        return
    history[-1] = _with_correlation_factors(
        history[-1],
        {field_name: prior_value},
        ephemeral_role_keys,
    )

    with pytest.raises(
        AuthorizationCausalityError,
        match="fresh",
    ):
        replay_authorization_causality(
            signed_work_order,
            tuple(history),
        )


@pytest.mark.parametrize("stage", ("first", "recomposition"))
def test_causal_replay_binds_compose_previous_report_digest(
    stage: str,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    sidecar_receipt_factory,
) -> None:
    history = list(
        _recomposition_history(
            signed_work_order=signed_work_order,
            signed_root_grant=signed_root_grant,
            ephemeral_role_keys=ephemeral_role_keys,
            sidecar_receipt_factory=sidecar_receipt_factory,
        )
    )
    index = 3 if stage == "first" else 6
    history[index] = _with_compose_previous_report(
        history[index],
        _grant_id(f"wrong:{stage}:report"),
        ephemeral_role_keys,
    )
    history = history[: index + 1]

    with pytest.raises(
        AuthorizationCausalityError,
        match="previous report",
    ):
        replay_authorization_causality(
            signed_work_order,
            tuple(history),
        )

@pytest.mark.parametrize("tamper", ("missing", "extra"))
def test_exact_parent_rejects_inexact_recomposition_closure(
    tamper: str,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    sidecar_receipt_factory,
) -> None:
    history = list(
        _recomposition_history(
            signed_work_order=signed_work_order,
            signed_root_grant=signed_root_grant,
            ephemeral_role_keys=ephemeral_role_keys,
            sidecar_receipt_factory=sidecar_receipt_factory,
        )
    )
    recomposition = history[-1]
    parent_ids = list(recomposition.parent_receipt_ids)
    if tamper == "missing":
        parent_ids.remove(history[4].receipt_id)
    else:
        parent_ids.append(history[1].receipt_id)
    history[-1] = _with_parents(
        recomposition,
        tuple(parent_ids),
        ephemeral_role_keys,
    )

    with pytest.raises(AuthorizationCausalityError):
        replay_authorization_causality(
            signed_work_order,
            tuple(history),
        )
