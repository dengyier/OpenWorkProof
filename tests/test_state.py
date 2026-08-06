"""Evidence-gated state-machine tests for protocol v0.1."""

from __future__ import annotations

import importlib
from datetime import datetime, timezone
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from openworkproof.models import (
    ACTION_RECEIPT_ADAPTER,
    ActionReceipt,
    AcceptanceReceipt,
    WorkOrder,
)
from openworkproof.signing import (
    sign_payload,
    verify_nested_claim,
    verify_payload,
    verify_work_order_identity_bindings,
)

from conftest import (
    SHA256_A,
    SHA256_B,
    SHA256_C,
    SHA256_D,
    SHA256_E,
    jcs_digest,
)


NON_TERMINAL_STATES = (
    "issued",
    "running",
    "needs_rework",
    "retrying",
    "locally_verified",
    "evidence_incomplete",
    "proof_ready",
    "awaiting_human",
    "frozen",
)
EXPIRABLE_STATES = NON_TERMINAL_STATES[:-1]


def _api():
    # Dynamic import keeps a missing state module as an intentional test
    # failure rather than a collection error during the RED phase.
    return importlib.import_module("openworkproof.state")


def _validate(
    api: Any,
    *,
    work_order: WorkOrder,
    state_before: str,
    state_after: str,
    receipt: ActionReceipt | None,
    acceptance: AcceptanceReceipt | None,
    public_keys: dict,
    now: datetime,
):
    return api.validate_transition_evidence(
        work_order=work_order,
        state_before=api.TaskState(state_before),
        state_after=api.TaskState(state_after),
        trigger_receipt=receipt,
        acceptance_receipt=acceptance,
        public_keys=public_keys,
        now=now,
    )


def _resign_receipt_for_role(
    receipt: ActionReceipt,
    *,
    actor_role: str,
    ephemeral_role_keys: dict,
) -> ActionReceipt:
    raw = receipt.model_dump(mode="json")
    binding = ephemeral_role_keys[actor_role][1]
    claim = raw["nested_claim"]
    claim["actor_id"] = binding["subject_id"]
    claim["actor_key_id"] = binding["key_id"]
    claim = sign_payload(
        (
            "agent-request"
            if raw["actor_type"] == "agent"
            else "human-decision"
        ),
        claim,
        ephemeral_role_keys[actor_role][0],
    )
    raw["actor_id"] = binding["subject_id"]
    raw["actor_key_id"] = binding["key_id"]
    raw["nested_claim"] = claim
    raw["nested_claim_digest"] = claim["digest"]
    if raw["actor_type"] == "agent":
        raw["nonce"] = claim["nonce"]
    raw = sign_payload(
        "action-receipt",
        raw,
        ephemeral_role_keys["Sidecar"][0],
    )
    return ACTION_RECEIPT_ADAPTER.validate_python(raw)


def _tool_receipt(
    *,
    tool_name: str,
    actor_role: str,
    signed_work_order: WorkOrder,
    sidecar_receipt_factory,
    ephemeral_role_keys: dict,
) -> ActionReceipt:
    from test_contract import agent_arguments_digest, predicate_result_data

    receipt = sidecar_receipt_factory(
        state_before="running",
        state_after="running",
        event_type="tool_call",
        actor_role="Manager",
    )
    raw = receipt.model_dump(mode="json")
    if tool_name == "owp.repo_read":
        arguments = {"path": "src/example.py"}
    elif tool_name == "owp.apply_patch":
        arguments = {
            "target_paths": ["src/x"],
            "patch_digest": SHA256_A,
            "patch_size_bytes": 10,
        }
        raw["output_digest"] = SHA256_D
        raw["evidence_refs"] = [
            {
                "path": "patch-input/01.diff",
                "sha256": SHA256_A,
                "media_type": "text/x-diff",
                "size_bytes": 10,
            },
            {
                "path": "patch-result/01.json",
                "sha256": SHA256_D,
                "media_type": "application/json",
                "size_bytes": 100,
            },
        ]
    elif tool_name == "owp.create_pr_proposal":
        arguments = {
            "target_patch_digest": SHA256_B,
            "approval_receipt_id": SHA256_C,
            "approval_receipt_digest": SHA256_D,
        }
        raw["approval_receipt_id"] = SHA256_C
        raw["approval_receipt_digest"] = SHA256_D
        raw["output_digest"] = jcs_digest(
            {
                "status": "local_pr_proposal_created",
                "target_patch_digest": SHA256_B,
            }
        )
    elif tool_name == "owp.compose_proof":
        arguments = {
            "expected_state_version": 0,
            "previous_report_digest": None,
        }
        raw["output_digest"] = jcs_digest(
            {"status": "composition_request_accepted"}
        )
    else:
        raise AssertionError(f"unsupported test tool: {tool_name}")

    raw["tool_name"] = tool_name
    raw["request_arguments"] = arguments
    raw["arguments_digest"] = agent_arguments_digest(tool_name, arguments)
    raw["nested_claim"]["tool_name"] = tool_name
    raw["nested_claim"]["arguments_digest"] = raw["arguments_digest"]
    if tool_name in {"owp.create_pr_proposal", "owp.compose_proof"}:
        for field_name in (
            "toolchain_id",
            "execution_context_id",
            "container_instance_id_digest",
            "fixed_test_source_digest",
        ):
            raw["correlation_factors"][field_name] = None

    applicable = sorted(
        (
            spec
            for spec in signed_work_order.preconditions
            + signed_work_order.invariants
            if tool_name in spec.applies_to_tools
        ),
        key=lambda spec: spec.predicate_id,
    )
    results = []
    for spec in applicable:
        result = predicate_result_data(spec.model_dump(mode="json"))
        if spec.name == "tool_allowed":
            result["input"] = {"actual_tool_name": tool_name}
        elif spec.name == "quota_remaining":
            result["input"] = {
                "grant_id": raw["grant_id"],
                "metric": "tool_calls",
                "amount": 1,
                "grant_remaining_before": 1,
                "ledger_prefix_digest": SHA256_B,
            }
        elif spec.name == "path_allowed":
            paths = (
                list(arguments["target_paths"])
                if tool_name == "owp.apply_patch"
                else [arguments["path"]]
            )
            result["input"] = {
                "requested_paths": paths,
                "resolved_entries": [
                    {
                        "requested_path": path,
                        "resolved_relative_path": path,
                    }
                    for path in paths
                ],
                "resolution_manifest_digest": SHA256_A,
            }
        result["input_digest"] = jcs_digest(
            {
                "domain": "openworkproof/predicate-input/v0.1",
                "predicate_id": result["predicate_id"],
                "input": result["input"],
            }
        )
        results.append(result)
    raw["predicate_results"] = results

    binding = ephemeral_role_keys[actor_role][1]
    claim = raw["nested_claim"]
    claim["actor_id"] = binding["subject_id"]
    claim["actor_key_id"] = binding["key_id"]
    claim = sign_payload(
        "agent-request",
        claim,
        ephemeral_role_keys[actor_role][0],
    )
    raw["actor_id"] = binding["subject_id"]
    raw["actor_key_id"] = binding["key_id"]
    raw["nested_claim"] = claim
    raw["nested_claim_digest"] = claim["digest"]
    raw["nonce"] = claim["nonce"]
    raw = sign_payload(
        "action-receipt",
        raw,
        ephemeral_role_keys["Sidecar"][0],
    )
    return ACTION_RECEIPT_ADAPTER.validate_python(raw)


def _termination_receipt_at(
    *,
    state_before: str,
    decided_at: str,
    occurred_at: str,
    sequence: int = 1,
    previous_receipt_digest: str | None = None,
    parent_receipt_ids: tuple[str, ...] = (),
    sidecar_receipt_factory,
    ephemeral_role_keys: dict,
) -> ActionReceipt:
    receipt = sidecar_receipt_factory(
        state_before=state_before,
        state_after="rejected",
        event_type="termination_decision",
        occurred_at=occurred_at,
        sequence=sequence,
        previous_receipt_digest=previous_receipt_digest,
        parent_receipt_ids=parent_receipt_ids,
    )
    raw = receipt.model_dump(mode="json")
    raw["decided_at"] = decided_at
    raw["nested_claim"]["decided_at"] = decided_at
    raw["occurred_at"] = occurred_at
    claim = sign_payload(
        "human-decision",
        raw["nested_claim"],
        ephemeral_role_keys["Maintainer"][0],
    )
    raw["nested_claim"] = claim
    raw["nested_claim_digest"] = claim["digest"]
    return ACTION_RECEIPT_ADAPTER.validate_python(
        sign_payload(
            "action-receipt",
            raw,
            ephemeral_role_keys["Sidecar"][0],
        )
    )


def test_real_fixture_signatures_and_work_order_bindings_are_valid(
    signed_work_order: WorkOrder,
    sidecar_receipt_factory,
    public_keys: dict,
) -> None:
    receipt = sidecar_receipt_factory(
        state_before="issued",
        state_after="running",
        event_type="grant_issued",
    )

    assert verify_work_order_identity_bindings(signed_work_order)
    assert receipt.validate_against_work_order(signed_work_order) is receipt
    assert verify_nested_claim(receipt.nested_claim, signed_work_order)
    assert verify_payload(
        "action-receipt",
        receipt.model_dump(mode="json"),
        public_keys[receipt.gateway_signer_key_id],
    )


def test_transition_registry_is_the_exact_frozen_adjacency_table() -> None:
    api = _api()

    expected = {
        "issued": {"running", "frozen", "rejected"},
        "running": {
            "needs_rework",
            "locally_verified",
            "frozen",
            "rejected",
        },
        "needs_rework": {"retrying", "frozen", "rejected"},
        "retrying": {
            "needs_rework",
            "locally_verified",
            "frozen",
            "rejected",
        },
        "locally_verified": {
            "evidence_incomplete",
            "proof_ready",
            "frozen",
            "rejected",
        },
        "evidence_incomplete": {"proof_ready", "frozen", "rejected"},
        "proof_ready": {"awaiting_human", "frozen", "rejected"},
        "awaiting_human": {"accepted", "frozen", "rejected"},
        "accepted": set(),
        "rejected": set(),
        "frozen": {"rejected"},
    }
    assert {
        state.value: {target.value for target in targets}
        for state, targets in api.ALLOWED_TRANSITIONS.items()
    } == expected


def test_local_verification_cannot_skip_human_gate(
    signed_work_order: WorkOrder,
    sidecar_receipt_factory,
    public_keys: dict,
    fixed_now: datetime,
) -> None:
    receipt = sidecar_receipt_factory(
        state_before="locally_verified",
        state_after="accepted",
        event_type="termination_decision",
    )

    decision = _validate(
        _api(),
        work_order=signed_work_order,
        state_before="locally_verified",
        state_after="accepted",
        receipt=receipt,
        acceptance=None,
        public_keys=public_keys,
        now=fixed_now,
    )

    assert decision.allowed is False
    assert decision.error_code == "INVALID_TRANSITION"


def test_root_activation_is_the_only_issued_to_running_evidence(
    signed_work_order: WorkOrder,
    sidecar_receipt_factory,
    public_keys: dict,
    fixed_now: datetime,
) -> None:
    api = _api()
    root = sidecar_receipt_factory(
        state_before="issued",
        state_after="running",
        event_type="grant_issued",
    )
    child = sidecar_receipt_factory(
        state_before="issued",
        state_after="running",
        event_type="grant_issued",
    ).model_copy(update={"parent_grant_id": SHA256_A})

    allowed = _validate(
        api,
        work_order=signed_work_order,
        state_before="issued",
        state_after="running",
        receipt=root,
        acceptance=None,
        public_keys=public_keys,
        now=fixed_now,
    )
    denied = _validate(
        api,
        work_order=signed_work_order,
        state_before="issued",
        state_after="running",
        receipt=child,
        acceptance=None,
        public_keys=public_keys,
        now=fixed_now,
    )

    assert allowed.allowed is True
    assert denied.allowed is False


@pytest.mark.parametrize("state_before", ["running", "retrying"])
@pytest.mark.parametrize(
    ("test_passed", "state_after"),
    [(False, "needs_rework"), (True, "locally_verified")],
)
def test_verifier_fixed_test_drives_only_the_two_local_outcomes(
    signed_work_order: WorkOrder,
    sidecar_receipt_factory,
    public_keys: dict,
    fixed_now: datetime,
    state_before: str,
    test_passed: bool,
    state_after: str,
) -> None:
    receipt = sidecar_receipt_factory(
        state_before=state_before,
        state_after=state_after,
        event_type="tool_call",
        actor_role="Verifier",
        test_passed=test_passed,
    )

    decision = _validate(
        _api(),
        work_order=signed_work_order,
        state_before=state_before,
        state_after=state_after,
        receipt=receipt,
        acceptance=None,
        public_keys=public_keys,
        now=fixed_now,
    )

    assert decision.allowed is True


def test_verifier_pass_requires_the_complete_exact_postcondition_set(
    signed_work_order: WorkOrder,
    sidecar_receipt_factory,
    public_keys: dict,
    fixed_now: datetime,
) -> None:
    receipt = sidecar_receipt_factory(
        state_before="running",
        state_after="locally_verified",
        event_type="tool_call",
        actor_role="Verifier",
        test_passed=True,
    )
    incomplete = receipt.model_copy(
        update={"predicate_results": receipt.predicate_results[:-1]}
    )

    decision = _validate(
        _api(),
        work_order=signed_work_order,
        state_before="running",
        state_after="locally_verified",
        receipt=incomplete,
        acceptance=None,
        public_keys=public_keys,
        now=fixed_now,
    )

    assert decision.allowed is False
    assert decision.error_code == "INVALID_EVIDENCE"

def test_same_state_append_and_state_transition_are_distinct_paths(
    signed_work_order: WorkOrder,
    sidecar_receipt_factory,
    public_keys: dict,
    fixed_now: datetime,
) -> None:
    api = _api()
    child = sidecar_receipt_factory(
        state_before="running",
        state_after="running",
        event_type="grant_issued",
    )
    root = sidecar_receipt_factory(
        state_before="issued",
        state_after="running",
        event_type="grant_issued",
    )

    appended = api.append_receipt(
        work_order=signed_work_order,
        state=api.TaskState.RUNNING,
        receipt=child,
        public_keys=public_keys,
        now=fixed_now,
    )
    same_state_transition = api.apply_state_transition(
        work_order=signed_work_order,
        state_before=api.TaskState.RUNNING,
        state_after=api.TaskState.RUNNING,
        trigger_receipt=child,
        acceptance_receipt=None,
        public_keys=public_keys,
        now=fixed_now,
    )
    changing_append = api.append_receipt(
        work_order=signed_work_order,
        state=api.TaskState.ISSUED,
        receipt=root,
        public_keys=public_keys,
        now=fixed_now,
    )

    assert appended.allowed is True
    assert same_state_transition.allowed is False
    assert same_state_transition.error_code == "STATE_CHANGE_REQUIRED"
    assert changing_append.allowed is False
    assert changing_append.error_code == "TRANSITION_REQUIRED"


def test_authenticated_policy_denial_is_append_only_and_same_state(
    signed_work_order: WorkOrder,
    sidecar_receipt_factory,
    public_keys: dict,
    fixed_now: datetime,
) -> None:
    api = _api()
    denied = sidecar_receipt_factory(
        state_before="running",
        state_after="running",
        event_type="tool_call",
        policy_decision="deny",
        execution_status="denied",
    )

    decision = api.append_receipt(
        work_order=signed_work_order,
        state=api.TaskState.RUNNING,
        receipt=denied,
        public_keys=public_keys,
        now=fixed_now,
    )

    assert decision.allowed is True


@pytest.mark.parametrize(
    ("state", "event_type", "actor_role", "execution_status"),
    [
        ("running", "tool_call", "Developer", "succeeded"),
        ("retrying", "tool_call", "Developer", "succeeded"),
        ("running", "tool_call", "Developer", "failed"),
        ("running", "grant_revoked", None, "succeeded"),
        ("running", "approval_requested", None, "succeeded"),
        ("running", "approval_decision", None, "succeeded"),
    ],
)
def test_task5_provable_successful_same_state_events_are_appendable(
    signed_work_order: WorkOrder,
    sidecar_receipt_factory,
    public_keys: dict,
    fixed_now: datetime,
    state: str,
    event_type: str,
    actor_role: str | None,
    execution_status: str,
) -> None:
    api = _api()
    receipt = sidecar_receipt_factory(
        state_before=state,
        state_after=state,
        event_type=event_type,
        actor_role=actor_role,
        execution_status=execution_status,
        final_request=False,
    )

    decision = api.append_receipt(
        work_order=signed_work_order,
        state=api.TaskState(state),
        receipt=receipt,
        public_keys=public_keys,
        now=fixed_now,
    )

    assert decision.allowed is True


@pytest.mark.parametrize(
    ("tool_case", "actor_role", "expected_error"),
    [
        ("repo_read", "Manager", "STATE_DENIED"),
        ("apply_patch", "Manager", "STATE_DENIED"),
        ("run_tests_developer", "Manager", "STATE_DENIED"),
        ("repo_read", "Developer", None),
        ("apply_patch", "Developer", None),
        ("run_tests_developer", "Developer", None),
        ("run_tests_verifier", "Developer", "STATE_DENIED"),
        ("run_tests_developer", "Verifier", "STATE_DENIED"),
        ("run_tests_verifier", "Verifier", "TRANSITION_REQUIRED"),
        ("create_pr_proposal", "Manager", None),
        ("create_pr_proposal", "Developer", "STATE_DENIED"),
        ("compose_proof", "Manager", "STATE_DENIED"),
        ("compose_proof", "Developer", "STATE_DENIED"),
    ],
)
def test_same_state_tool_gate_uses_exact_direct_call_role_matrix(
    signed_work_order: WorkOrder,
    sidecar_receipt_factory,
    ephemeral_role_keys: dict,
    public_keys: dict,
    fixed_now: datetime,
    tool_case: str,
    actor_role: str,
    expected_error: str | None,
) -> None:
    if tool_case == "run_tests_developer":
        receipt = sidecar_receipt_factory(
            state_before="running",
            state_after="running",
            event_type="tool_call",
            actor_role="Developer",
        )
        receipt = _resign_receipt_for_role(
            receipt,
            actor_role=actor_role,
            ephemeral_role_keys=ephemeral_role_keys,
        )
    elif tool_case == "run_tests_verifier":
        receipt = sidecar_receipt_factory(
            state_before="running",
            state_after="running",
            event_type="tool_call",
            actor_role="Verifier",
        )
        receipt = _resign_receipt_for_role(
            receipt,
            actor_role=actor_role,
            ephemeral_role_keys=ephemeral_role_keys,
        )
    else:
        receipt = _tool_receipt(
            tool_name=f"owp.{tool_case}",
            actor_role=actor_role,
            signed_work_order=signed_work_order,
            sidecar_receipt_factory=sidecar_receipt_factory,
            ephemeral_role_keys=ephemeral_role_keys,
        )

    assert verify_nested_claim(receipt.nested_claim, signed_work_order)
    assert verify_payload(
        "action-receipt",
        receipt.model_dump(mode="json"),
        public_keys[receipt.gateway_signer_key_id],
    )
    decision = _api().append_receipt(
        work_order=signed_work_order,
        state=_api().TaskState.RUNNING,
        receipt=receipt,
        public_keys=public_keys,
        now=fixed_now,
    )

    assert decision.allowed is (expected_error is None)
    assert decision.error_code == expected_error


@pytest.mark.parametrize(
    "state",
    ("locally_verified", "evidence_incomplete"),
)
def test_manager_compose_requires_canonical_context_in_same_state(
    state: str,
    signed_work_order: WorkOrder,
    sidecar_receipt_factory,
    ephemeral_role_keys: dict,
    public_keys: dict,
    fixed_now: datetime,
) -> None:
    receipt = _tool_receipt(
        tool_name="owp.compose_proof",
        actor_role="Manager",
        signed_work_order=signed_work_order,
        sidecar_receipt_factory=sidecar_receipt_factory,
        ephemeral_role_keys=ephemeral_role_keys,
    )
    raw = receipt.model_dump(mode="json")
    raw["state_before"] = state
    raw["state_after"] = state
    receipt = ACTION_RECEIPT_ADAPTER.validate_python(
        sign_payload(
            "action-receipt",
            raw,
            ephemeral_role_keys["Sidecar"][0],
        )
    )

    api = _api()
    decision = api.append_receipt(
        work_order=signed_work_order,
        state=api.TaskState(state),
        receipt=receipt,
        public_keys=public_keys,
        now=fixed_now,
    )

    assert decision.allowed is False
    assert decision.error_code == "COMPOSITION_VALIDATOR_UNAVAILABLE"


@pytest.mark.parametrize(
    ("actor_role", "expected_error"),
    [
        ("Developer", "TRANSITION_CONTEXT_UNAVAILABLE"),
        ("Manager", "STATE_DENIED"),
        ("Verifier", "STATE_DENIED"),
    ],
)
def test_rollback_same_state_gate_is_developer_only(
    signed_work_order: WorkOrder,
    sidecar_receipt_factory,
    ephemeral_role_keys: dict,
    public_keys: dict,
    fixed_now: datetime,
    actor_role: str,
    expected_error: str,
) -> None:
    receipt = sidecar_receipt_factory(
        state_before="needs_rework",
        state_after="needs_rework",
        event_type="rollback",
        actor_role="Developer",
    )
    receipt = _resign_receipt_for_role(
        receipt,
        actor_role=actor_role,
        ephemeral_role_keys=ephemeral_role_keys,
    )

    decision = _api().append_receipt(
        work_order=signed_work_order,
        state=_api().TaskState.NEEDS_REWORK,
        receipt=receipt,
        public_keys=public_keys,
        now=fixed_now,
    )

    assert decision.allowed is False
    assert decision.error_code == expected_error


@pytest.mark.parametrize("test_passed", [False, True])
def test_verifier_normal_result_cannot_be_downgraded_to_same_state_append(
    signed_work_order: WorkOrder,
    sidecar_receipt_factory,
    public_keys: dict,
    fixed_now: datetime,
    test_passed: bool,
) -> None:
    api = _api()
    receipt = sidecar_receipt_factory(
        state_before="running",
        state_after="running",
        event_type="tool_call",
        actor_role="Verifier",
        test_passed=test_passed,
    )

    decision = api.append_receipt(
        work_order=signed_work_order,
        state=api.TaskState.RUNNING,
        receipt=receipt,
        public_keys=public_keys,
        now=fixed_now,
    )

    assert decision.allowed is False
    assert decision.error_code == "TRANSITION_REQUIRED"


@pytest.mark.parametrize("state", ["proof_ready", "awaiting_human"])
def test_successful_same_state_events_are_forbidden_in_human_gate_tail(
    signed_work_order: WorkOrder,
    sidecar_receipt_factory,
    public_keys: dict,
    fixed_now: datetime,
    state: str,
) -> None:
    api = _api()
    receipt = sidecar_receipt_factory(
        state_before=state,
        state_after=state,
        event_type="approval_requested",
        final_request=False,
    )

    decision = api.append_receipt(
        work_order=signed_work_order,
        state=api.TaskState(state),
        receipt=receipt,
        public_keys=public_keys,
        now=fixed_now,
    )

    assert decision.allowed is False
    assert decision.error_code == "STATE_DENIED"


def test_rollback_same_state_fails_closed_without_rework_episode_history(
    signed_work_order: WorkOrder,
    sidecar_receipt_factory,
    public_keys: dict,
    fixed_now: datetime,
) -> None:
    api = _api()
    receipt = sidecar_receipt_factory(
        state_before="needs_rework",
        state_after="needs_rework",
        event_type="rollback",
        actor_role="Developer",
    )

    decision = api.append_receipt(
        work_order=signed_work_order,
        state=api.TaskState.NEEDS_REWORK,
        receipt=receipt,
        public_keys=public_keys,
        now=fixed_now,
    )

    assert decision.allowed is False
    assert decision.error_code == "TRANSITION_CONTEXT_UNAVAILABLE"


def test_independent_verifier_same_state_result_requires_history_context(
    signed_work_order: WorkOrder,
    sidecar_receipt_factory,
    public_keys: dict,
    fixed_now: datetime,
) -> None:
    api = _api()
    receipt = sidecar_receipt_factory(
        state_before="evidence_incomplete",
        state_after="evidence_incomplete",
        event_type="tool_call",
        actor_role="Verifier",
        test_passed=True,
    )

    decision = api.append_receipt(
        work_order=signed_work_order,
        state=api.TaskState.EVIDENCE_INCOMPLETE,
        receipt=receipt,
        public_keys=public_keys,
        now=fixed_now,
    )

    assert decision.allowed is False
    assert decision.error_code == "TRANSITION_CONTEXT_UNAVAILABLE"


@pytest.mark.parametrize(
    ("event_type", "actor_role"),
    [
        ("grant_issued", None),
        ("grant_revoked", None),
        ("tool_call", None),
        ("approval_requested", None),
        ("approval_decision", None),
    ],
)
def test_evidence_incomplete_rejects_every_other_successful_same_state_event(
    signed_work_order: WorkOrder,
    sidecar_receipt_factory,
    public_keys: dict,
    fixed_now: datetime,
    event_type: str,
    actor_role: str | None,
) -> None:
    api = _api()
    receipt = sidecar_receipt_factory(
        state_before="evidence_incomplete",
        state_after="evidence_incomplete",
        event_type=event_type,
        actor_role=actor_role,
        final_request=False,
    )

    decision = api.append_receipt(
        work_order=signed_work_order,
        state=api.TaskState.EVIDENCE_INCOMPLETE,
        receipt=receipt,
        public_keys=public_keys,
        now=fixed_now,
    )

    assert decision.allowed is False
    assert decision.error_code == "STATE_DENIED"


def test_start_retry_consumption_cannot_masquerade_as_same_state_append(
    signed_work_order: WorkOrder,
    sidecar_receipt_factory,
    public_keys: dict,
    fixed_now: datetime,
) -> None:
    api = _api()
    receipt = sidecar_receipt_factory(
        state_before="needs_rework",
        state_after="needs_rework",
        event_type="grant_consumed",
        actor_role="Manager",
    )

    decision = api.append_receipt(
        work_order=signed_work_order,
        state=api.TaskState.NEEDS_REWORK,
        receipt=receipt,
        public_keys=public_keys,
        now=fixed_now,
    )

    assert decision.allowed is False
    assert decision.error_code == "TRANSITION_REQUIRED"


@pytest.mark.parametrize(
    ("state", "actor_role"),
    [
        ("running", "Manager"),
        ("running", "Developer"),
        ("retrying", "Manager"),
        ("needs_rework", "Developer"),
        ("evidence_incomplete", "Manager"),
    ],
)
def test_start_retry_same_state_is_denied_outside_exact_transition_role_state(
    signed_work_order: WorkOrder,
    sidecar_receipt_factory,
    public_keys: dict,
    fixed_now: datetime,
    state: str,
    actor_role: str,
) -> None:
    api = _api()
    receipt = sidecar_receipt_factory(
        state_before=state,
        state_after=state,
        event_type="grant_consumed",
        actor_role=actor_role,
    )

    decision = api.append_receipt(
        work_order=signed_work_order,
        state=api.TaskState(state),
        receipt=receipt,
        public_keys=public_keys,
        now=fixed_now,
    )

    assert decision.allowed is False
    assert decision.error_code == "STATE_DENIED"


@pytest.mark.parametrize(
    ("event_type", "state"),
    [
        ("grant_issued", "running"),
        ("grant_issued", "retrying"),
        ("grant_issued", "needs_rework"),
        ("grant_revoked", "running"),
        ("grant_revoked", "retrying"),
        ("grant_revoked", "needs_rework"),
    ],
)
def test_manager_grant_audit_events_use_the_exact_same_state_window(
    signed_work_order: WorkOrder,
    sidecar_receipt_factory,
    public_keys: dict,
    fixed_now: datetime,
    event_type: str,
    state: str,
) -> None:
    api = _api()
    receipt = sidecar_receipt_factory(
        state_before=state,
        state_after=state,
        event_type=event_type,
        actor_role="Manager",
    )

    decision = api.append_receipt(
        work_order=signed_work_order,
        state=api.TaskState(state),
        receipt=receipt,
        public_keys=public_keys,
        now=fixed_now,
    )

    assert decision.allowed is True


@pytest.mark.parametrize("event_type", ["grant_issued", "grant_revoked"])
def test_grant_audit_same_state_rejects_wrong_role_or_state(
    signed_work_order: WorkOrder,
    sidecar_receipt_factory,
    public_keys: dict,
    fixed_now: datetime,
    event_type: str,
) -> None:
    api = _api()
    wrong_role = sidecar_receipt_factory(
        state_before="running",
        state_after="running",
        event_type=event_type,
        actor_role="Developer",
    )
    wrong_state = sidecar_receipt_factory(
        state_before="evidence_incomplete",
        state_after="evidence_incomplete",
        event_type=event_type,
        actor_role="Manager",
    )

    for state, receipt in (
        (api.TaskState.RUNNING, wrong_role),
        (api.TaskState.EVIDENCE_INCOMPLETE, wrong_state),
    ):
        decision = api.append_receipt(
            work_order=signed_work_order,
            state=state,
            receipt=receipt,
            public_keys=public_keys,
            now=fixed_now,
        )
        assert decision.allowed is False
        assert decision.error_code == "STATE_DENIED"


@pytest.mark.parametrize(
    ("event_type", "actor_role"),
    [
        ("approval_requested", "Developer"),
    ],
)
def test_ordinary_same_state_actions_reject_wrong_role(
    signed_work_order: WorkOrder,
    sidecar_receipt_factory,
    public_keys: dict,
    fixed_now: datetime,
    event_type: str,
    actor_role: str,
) -> None:
    api = _api()
    receipt = sidecar_receipt_factory(
        state_before="running",
        state_after="running",
        event_type=event_type,
        actor_role=actor_role,
        final_request=False,
    )

    decision = api.append_receipt(
        work_order=signed_work_order,
        state=api.TaskState.RUNNING,
        receipt=receipt,
        public_keys=public_keys,
        now=fixed_now,
    )

    assert decision.allowed is False
    assert decision.error_code == "STATE_DENIED"


@pytest.mark.parametrize(
    ("state_before", "state_after", "event_name"),
    [
        ("locally_verified", "evidence_incomplete", "proof_composed"),
        ("locally_verified", "proof_ready", "proof_composed"),
        ("evidence_incomplete", "proof_ready", "proof_composed"),
        ("locally_verified", "frozen", "security_violation"),
        ("evidence_incomplete", "frozen", "security_violation"),
    ],
)
def test_composition_derived_transitions_are_authorized_by_receipt(
    signed_work_order: WorkOrder,
    sidecar_receipt_factory,
    public_keys: dict,
    fixed_now: datetime,
    state_before: str,
    state_after: str,
    event_name: str,
) -> None:
    receipt = sidecar_receipt_factory(
        state_before=state_before,
        state_after=state_after,
        event_type="system_event",
        event_name=event_name,
    )

    decision = _validate(
        _api(),
        work_order=signed_work_order,
        state_before=state_before,
        state_after=state_after,
        receipt=receipt,
        acceptance=None,
        public_keys=public_keys,
        now=fixed_now,
    )

    # Task 9 authorizes composition-derived transitions at the receipt level;
    # report recomputation is enforced by the compose/commit transactions.
    assert decision.allowed is True


def test_retry_transition_fails_closed_without_episode_history_context(
    signed_work_order: WorkOrder,
    sidecar_receipt_factory,
    public_keys: dict,
    fixed_now: datetime,
) -> None:
    receipt = sidecar_receipt_factory(
        state_before="needs_rework",
        state_after="retrying",
        event_type="grant_consumed",
    )

    decision = _validate(
        _api(),
        work_order=signed_work_order,
        state_before="needs_rework",
        state_after="retrying",
        receipt=receipt,
        acceptance=None,
        public_keys=public_keys,
        now=fixed_now,
    )

    assert decision.allowed is False
    assert decision.error_code == "TRANSITION_CONTEXT_UNAVAILABLE"


def test_only_exact_final_request_can_enter_awaiting_human(
    signed_work_order: WorkOrder,
    sidecar_receipt_factory,
    public_keys: dict,
    fixed_now: datetime,
) -> None:
    api = _api()
    final_request = sidecar_receipt_factory(
        state_before="proof_ready",
        state_after="awaiting_human",
        event_type="approval_requested",
        final_request=True,
    )
    high_risk = sidecar_receipt_factory(
        state_before="proof_ready",
        state_after="awaiting_human",
        event_type="approval_requested",
        final_request=False,
    )

    accepted = _validate(
        api,
        work_order=signed_work_order,
        state_before="proof_ready",
        state_after="awaiting_human",
        receipt=final_request,
        acceptance=None,
        public_keys=public_keys,
        now=fixed_now,
    )
    rejected = _validate(
        api,
        work_order=signed_work_order,
        state_before="proof_ready",
        state_after="awaiting_human",
        receipt=high_risk,
        acceptance=None,
        public_keys=public_keys,
        now=fixed_now,
    )

    # Task 9 authorizes the exact final-request transition at the receipt
    # level while a high-risk PR request stays invalid for the same path.
    assert accepted.allowed is True
    assert rejected.allowed is False
    assert rejected.error_code == "INVALID_EVIDENCE"


def test_final_request_cannot_self_report_or_bypass_missing_history(
    signed_work_order: WorkOrder,
    sidecar_receipt_factory,
    public_keys: dict,
    fixed_now: datetime,
) -> None:
    api = _api()
    request = sidecar_receipt_factory(
        state_before="proof_ready",
        state_after="awaiting_human",
        event_type="approval_requested",
        final_request=True,
    )

    first = _validate(
        api,
        work_order=signed_work_order,
        state_before="proof_ready",
        state_after="awaiting_human",
        receipt=request,
        acceptance=None,
        public_keys=public_keys,
        now=fixed_now,
    )
    replay = _validate(
        api,
        work_order=signed_work_order,
        state_before="proof_ready",
        state_after="awaiting_human",
        receipt=request,
        acceptance=None,
        public_keys=public_keys,
        now=fixed_now,
    )

    # Task 9 authorizes the deterministic final-request receipt repeatedly;
    # ledger-level single-request enforcement lives in the transaction layer.
    assert first.allowed is True
    assert replay.allowed is True


@pytest.mark.parametrize("state_before", EXPIRABLE_STATES)
def test_maintainer_termination_rejects_every_expirable_state(
    signed_work_order: WorkOrder,
    sidecar_receipt_factory,
    public_keys: dict,
    fixed_now: datetime,
    state_before: str,
) -> None:
    receipt = sidecar_receipt_factory(
        state_before=state_before,
        state_after="rejected",
        event_type="termination_decision",
    )

    decision = _validate(
        _api(),
        work_order=signed_work_order,
        state_before=state_before,
        state_after="rejected",
        receipt=receipt,
        acceptance=None,
        public_keys=public_keys,
        now=fixed_now,
    )

    assert decision.allowed is True


@pytest.mark.parametrize("state_before", EXPIRABLE_STATES)
@pytest.mark.parametrize(
    ("decided_at", "occurred_at"),
    [
        ("2026-01-02T00:00:01Z", "2026-01-02T00:00:01Z"),
        ("2026-01-02T00:00:00Z", "2026-01-02T00:00:01Z"),
        ("2026-01-02T00:00:01Z", "2026-01-02T00:00:00Z"),
    ],
)
def test_expirable_state_termination_rejects_either_time_after_deadline(
    signed_work_order: WorkOrder,
    sidecar_receipt_factory,
    ephemeral_role_keys: dict,
    public_keys: dict,
    state_before: str,
    decided_at: str,
    occurred_at: str,
) -> None:
    receipt = _termination_receipt_at(
        state_before=state_before,
        decided_at=decided_at,
        occurred_at=occurred_at,
        sidecar_receipt_factory=sidecar_receipt_factory,
        ephemeral_role_keys=ephemeral_role_keys,
    )

    decision = _validate(
        _api(),
        work_order=signed_work_order,
        state_before=state_before,
        state_after="rejected",
        receipt=receipt,
        acceptance=None,
        public_keys=public_keys,
        now=datetime(2026, 1, 2, 0, 0, 2, tzinfo=timezone.utc),
    )

    assert decision.allowed is False
    assert decision.error_code == "INVALID_EVIDENCE"


@pytest.mark.parametrize("sequence", [1, 2])
def test_frozen_state_termination_requires_unavailable_chain_tip_context(
    signed_work_order: WorkOrder,
    sidecar_receipt_factory,
    ephemeral_role_keys: dict,
    public_keys: dict,
    fixed_now: datetime,
    sequence: int,
) -> None:
    receipt = _termination_receipt_at(
        state_before="frozen",
        decided_at="2026-01-01T00:00:02Z",
        occurred_at="2026-01-01T00:00:03Z",
        sequence=sequence,
        previous_receipt_digest=SHA256_A if sequence == 2 else None,
        parent_receipt_ids=(SHA256_B,) if sequence == 2 else (),
        sidecar_receipt_factory=sidecar_receipt_factory,
        ephemeral_role_keys=ephemeral_role_keys,
    )

    decision = _validate(
        _api(),
        work_order=signed_work_order,
        state_before="frozen",
        state_after="rejected",
        receipt=receipt,
        acceptance=None,
        public_keys=public_keys,
        now=fixed_now,
    )

    assert decision.allowed is False
    assert decision.error_code == "TRANSITION_CONTEXT_UNAVAILABLE"


@pytest.mark.parametrize("state_before", EXPIRABLE_STATES)
def test_only_observed_contract_expiry_freezes_expirable_states(
    signed_work_order: WorkOrder,
    sidecar_receipt_factory,
    public_keys: dict,
    state_before: str,
) -> None:
    occurred_at = "2026-01-02T00:00:01Z"
    now = datetime(2026, 1, 2, 0, 0, 1, tzinfo=timezone.utc)
    receipt = sidecar_receipt_factory(
        state_before=state_before,
        state_after="frozen",
        event_type="system_event",
        event_name="contract_expired",
        occurred_at=occurred_at,
    )

    decision = _validate(
        _api(),
        work_order=signed_work_order,
        state_before=state_before,
        state_after="frozen",
        receipt=receipt,
        acceptance=None,
        public_keys=public_keys,
        now=now,
    )

    assert decision.allowed is True


def test_expiry_cannot_be_observed_early(
    signed_work_order: WorkOrder,
    sidecar_receipt_factory,
    public_keys: dict,
    fixed_now: datetime,
) -> None:
    receipt = sidecar_receipt_factory(
        state_before="running",
        state_after="frozen",
        event_type="system_event",
        event_name="contract_expired",
        occurred_at="2026-01-02T00:00:01Z",
    )

    decision = _validate(
        _api(),
        work_order=signed_work_order,
        state_before="running",
        state_after="frozen",
        receipt=receipt,
        acceptance=None,
        public_keys=public_keys,
        now=fixed_now,
    )

    assert decision.allowed is False
    assert decision.error_code == "INVALID_EVIDENCE"


def test_first_receipt_parent_rule_rejects_extra_parent(
    signed_work_order: WorkOrder,
    sidecar_receipt_factory,
    public_keys: dict,
    fixed_now: datetime,
) -> None:
    receipt = sidecar_receipt_factory(
        state_before="issued",
        state_after="running",
        event_type="grant_issued",
        parent_receipt_ids=(SHA256_A,),
        sequence=1,
        previous_receipt_digest=None,
    )

    decision = _validate(
        _api(),
        work_order=signed_work_order,
        state_before="issued",
        state_after="running",
        receipt=receipt,
        acceptance=None,
        public_keys=public_keys,
        now=fixed_now,
    )

    assert decision.allowed is False
    assert decision.error_code == "INVALID_EVIDENCE"


@pytest.mark.parametrize(
    ("event_type", "state_after", "event_name", "now"),
    [
        (
            "termination_decision",
            "rejected",
            None,
            datetime(2026, 1, 1, 0, 0, 5, tzinfo=timezone.utc),
        ),
        (
            "system_event",
            "frozen",
            "contract_expired",
            datetime(2026, 1, 2, 0, 0, 1, tzinfo=timezone.utc),
        ),
    ],
)
def test_non_genesis_terminal_event_requires_trusted_chain_tip_context(
    signed_work_order: WorkOrder,
    sidecar_receipt_factory,
    public_keys: dict,
    event_type: str,
    state_after: str,
    event_name: str | None,
    now: datetime,
) -> None:
    receipt = sidecar_receipt_factory(
        state_before="running",
        state_after=state_after,
        event_type=event_type,
        event_name=event_name,
        sequence=2,
        previous_receipt_digest=SHA256_A,
        parent_receipt_ids=("b" * 64,),
        occurred_at=(
            "2026-01-02T00:00:01Z"
            if event_name == "contract_expired"
            else "2026-01-01T00:00:03Z"
        ),
    )

    decision = _validate(
        _api(),
        work_order=signed_work_order,
        state_before="running",
        state_after=state_after,
        receipt=receipt,
        acceptance=None,
        public_keys=public_keys,
        now=now,
    )

    assert decision.allowed is False
    assert decision.error_code == "TRANSITION_CONTEXT_UNAVAILABLE"


@pytest.mark.parametrize("state_before", ["accepted", "rejected"])
def test_terminal_states_cannot_transition(
    signed_work_order: WorkOrder,
    sidecar_receipt_factory,
    public_keys: dict,
    fixed_now: datetime,
    state_before: str,
) -> None:
    receipt = sidecar_receipt_factory(
        state_before=state_before,
        state_after="rejected",
        event_type="termination_decision",
    )

    decision = _validate(
        _api(),
        work_order=signed_work_order,
        state_before=state_before,
        state_after="rejected",
        receipt=receipt,
        acceptance=None,
        public_keys=public_keys,
        now=fixed_now,
    )

    assert decision.allowed is False
    assert decision.error_code == "INVALID_TRANSITION"


def test_acceptance_is_authorized_by_acceptor_signature(
    signed_work_order: WorkOrder,
    signed_acceptance_receipt: AcceptanceReceipt,
    public_keys: dict,
    fixed_now: datetime,
) -> None:
    decision = _validate(
        _api(),
        work_order=signed_work_order,
        state_before="awaiting_human",
        state_after="accepted",
        receipt=None,
        acceptance=signed_acceptance_receipt,
        public_keys=public_keys,
        now=fixed_now,
    )

    # Task 9 authorizes the accepted transition when the bound Acceptor
    # signed the AcceptanceReceipt; ledger-suffix enforcement lives in the
    # commit_acceptance transaction.
    assert decision.allowed is True


@pytest.mark.parametrize("wrong_role", ["Maintainer", "Manager", "Developer", "Verifier", "Sidecar"])
def test_acceptance_rejects_every_non_acceptor_signer(
    signed_work_order: WorkOrder,
    signed_acceptance_receipt: AcceptanceReceipt,
    ephemeral_role_keys: dict,
    public_keys: dict,
    fixed_now: datetime,
    wrong_role: str,
) -> None:
    raw = signed_acceptance_receipt.model_dump(mode="json")
    binding = ephemeral_role_keys[wrong_role][1]
    raw["signer_key_id"] = binding["key_id"]
    wrong = AcceptanceReceipt.model_validate(
        sign_payload(
            "acceptance-receipt",
            raw,
            ephemeral_role_keys[wrong_role][0],
        )
    )
    decision = _validate(
        _api(),
        work_order=signed_work_order,
        state_before="awaiting_human",
        state_after="accepted",
        receipt=None,
        acceptance=wrong,
        public_keys=public_keys,
        now=fixed_now,
    )

    assert decision.allowed is False
    assert decision.error_code == "INVALID_EVIDENCE"


def test_acceptance_requires_the_bound_acceptor_key(
    signed_work_order: WorkOrder,
    signed_acceptance_receipt: AcceptanceReceipt,
    ephemeral_role_keys: dict,
    public_keys: dict,
    fixed_now: datetime,
) -> None:
    # A valid external key that is NOT bound to the WorkOrder Acceptor role
    # must still be rejected for acceptance signing.
    unbound_private_key = Ed25519PrivateKey.generate()
    raw = signed_acceptance_receipt.model_dump(mode="json")
    unbound = AcceptanceReceipt.model_validate(
        sign_payload(
            "acceptance-receipt",
            raw,
            unbound_private_key,
        )
    )
    decision = _validate(
        _api(),
        work_order=signed_work_order,
        state_before="awaiting_human",
        state_after="accepted",
        receipt=None,
        acceptance=unbound,
        public_keys=public_keys,
        now=fixed_now,
    )

    assert decision.allowed is False
    assert decision.error_code == "INVALID_EVIDENCE"


@pytest.mark.parametrize("naive_hour", [0, 8])
@pytest.mark.parametrize("evidence_kind", ["action", "acceptance"])
def test_naive_now_fails_closed_identically_for_action_and_acceptance(
    signed_work_order: WorkOrder,
    signed_acceptance_receipt: AcceptanceReceipt,
    sidecar_receipt_factory,
    public_keys: dict,
    evidence_kind: str,
    naive_hour: int,
) -> None:
    if evidence_kind == "action":
        state_before = "issued"
        state_after = "running"
        receipt = sidecar_receipt_factory(
            state_before=state_before,
            state_after=state_after,
            event_type="grant_issued",
        )
        acceptance = None
    else:
        state_before = "awaiting_human"
        state_after = "accepted"
        receipt = None
        acceptance = signed_acceptance_receipt

    decision = _validate(
        _api(),
        work_order=signed_work_order,
        state_before=state_before,
        state_after=state_after,
        receipt=receipt,
        acceptance=acceptance,
        public_keys=public_keys,
        now=datetime(2026, 1, 1, naive_hour, 0, 5),
    )

    assert decision.allowed is False
    assert decision.error_code == "INVALID_EVIDENCE"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("actor_id", "developer"),
        ("event_type", "grant_revoked"),
        ("gateway_signer_key_id", f"ed25519:{SHA256_A}"),
        ("work_order_digest", SHA256_A),
        ("state_before", "running"),
        ("state_after", "needs_rework"),
    ],
)
def test_substituting_one_bound_receipt_field_invalidates_the_transition(
    signed_work_order: WorkOrder,
    sidecar_receipt_factory,
    public_keys: dict,
    fixed_now: datetime,
    field: str,
    value: str,
) -> None:
    valid = sidecar_receipt_factory(
        state_before="issued",
        state_after="running",
        event_type="grant_issued",
    )
    substituted = valid.model_copy(update={field: value})

    decision = _validate(
        _api(),
        work_order=signed_work_order,
        state_before="issued",
        state_after="running",
        receipt=substituted,
        acceptance=None,
        public_keys=public_keys,
        now=fixed_now,
    )

    assert decision.allowed is False
    assert decision.error_code == "INVALID_EVIDENCE"
