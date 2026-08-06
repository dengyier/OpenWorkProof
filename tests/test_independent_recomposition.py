"""Independent Verifier result and recomposition coverage.

This file reuses the test_mcp_server fixtures so each test starts from the
canonical running/retrying → locally_verified → evidence_incomplete chain.
The fixture-only Step 3 of Task 1 verifies the precondition without
changing any product behaviour.
"""

from __future__ import annotations

import pytest

import dataclasses

import openworkproof.acceptance as acceptance
import openworkproof.mcp_server as mcp_server
from openworkproof.models import (
    AgentRequest,
    ComposeProofArguments,
    request_arguments_digest,
)
from openworkproof.policy import ProspectiveExecutionFacts

from openworkproof.signing import sign_payload
from test_mcp_server import (
    _FakeRunTestsExecutionDriver,
    _current_run_tests_context,
    _execute_run_tests_case,
    _grant_id,
    _run_tests_case,
)


def _signed_compose_request(
    case,
    context,
    role_keys,
    now,
    *,
    previous_report_digest,
    nonce_label: str,
) -> AgentRequest:
    manager = role_keys["Manager"][1]
    arguments = ComposeProofArguments(
        expected_state_version=len(context.ledger_prefix.receipts),
        previous_report_digest=previous_report_digest,
    )
    return AgentRequest.model_validate(
        sign_payload(
            "agent-request",
            {
                "claim_type": "agent-request",
                "work_order_digest": case["work_order"].digest,
                "grant_id": case["root"].grant_id,
                "actor_id": manager["subject_id"],
                "actor_key_id": manager["key_id"],
                "tool_name": "owp.compose_proof",
                "arguments_digest": request_arguments_digest(
                    "owp.compose_proof", arguments
                ),
                "nonce": _grant_id(nonce_label),
                "requested_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "authentication_method": "agent_signature",
                "model_id": "model",
                "model_version": "1",
                "prompt_template_digest": "a" * 64,
                "context_source_digest": "b" * 64,
            },
            role_keys["Manager"][0],
        )
    )


def _independent_case(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
):
    case = _run_tests_case(
        tmp_path=tmp_path,
        signed_work_order=signed_work_order,
        role_keys=ephemeral_role_keys,
        sidecar_receipt_factory=sidecar_receipt_factory,
        now=fixed_now,
        verifier_tool_calls=2,
    )
    _execute_run_tests_case(
        case,
        tmp_path,
        ephemeral_role_keys,
        _FakeRunTestsExecutionDriver(),
    )
    locally_verified = _current_run_tests_context(case, fixed_now)
    compose_request = _signed_compose_request(
        case,
        locally_verified,
        ephemeral_role_keys,
        fixed_now,
        previous_report_digest=None,
        nonce_label="independent:first-compose",
    )
    first = acceptance.compose_proof_transaction(
        case["ledger_path"],
        evidence_root=case["evidence_root"],
        context=locally_verified,
        request=compose_request,
        sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
        clock=lambda: fixed_now,
    )
    incomplete = _current_run_tests_context(case, fixed_now)
    assert incomplete.current_state == "evidence_incomplete"
    return case, first, incomplete


@pytest.fixture(autouse=True)
def _stub_execution_snapshot(monkeypatch: pytest.MonkeyPatch) -> None:
    from openworkproof import repo_tools
    from openworkproof.repo_tools import (
        CandidateExecutionSnapshot,
        ExecutionSnapshotPlan,
    )

    def prepare(request):
        return CandidateExecutionSnapshot(
            head_commit=request.expected_head_commit,
            workspace_manifest_digest=request.expected_workspace_manifest_digest,
            plan=ExecutionSnapshotPlan(
                files=(),
                read_only=True,
                owner_uid=65532,
                owner_gid=65532,
                atime_unix_seconds=0,
                mtime_unix_seconds=0,
                clear_extended_attributes=True,
                clear_posix_acls=True,
                clear_file_capabilities=True,
            ),
        )

    monkeypatch.setattr(repo_tools, "prepare_candidate_execution_snapshot", prepare)


def test_five_dimension_case_stops_at_evidence_incomplete(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
) -> None:
    case, first_composition, incomplete_context = _independent_case(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        sidecar_receipt_factory,
        fixed_now,
        monkeypatch,
    )
    # First composition must agree that the independent_result dimension is
    # still missing while the first Verifier run produced a real slot.
    coverage = dict(first_composition.report.evidence_coverage)
    assert coverage.get("authority") is True
    assert coverage.get("scope") is True
    assert coverage.get("execution") is True
    assert coverage.get("result") is True
    assert coverage.get("independent_result") is False
    assert incomplete_context.current_state == "evidence_incomplete"
    import sqlite3 as _sql

    connection = _sql.connect(case["ledger_path"])
    try:
        report_rows = connection.execute(
            "SELECT COUNT(*) FROM composition_reports"
        ).fetchone()[0]
    finally:
        connection.close()
    assert report_rows == 1


def _independent_test_request(
    case,
    role_keys,
    now,
    *,
    nonce_label: str,
    execution_context_id: str,
    container_instance_id_digest: str,
    actor_role: str = "Verifier",
):
    from openworkproof.signing import sign_payload
    from test_mcp_server import _grant_id

    binding = role_keys[actor_role][1]
    arguments = case["arguments"]
    facts = dataclasses.replace(
        case["facts"],
        execution_context_id=execution_context_id,
        container_instance_id_digest=container_instance_id_digest,
    )
    request = AgentRequest.model_validate(
        sign_payload(
            "agent-request",
            {
                "claim_type": "agent-request",
                "work_order_digest": case["work_order"].digest,
                "grant_id": case["verifier"].grant_id,
                "actor_id": binding["subject_id"],
                "actor_key_id": binding["key_id"],
                "tool_name": "owp.run_tests",
                "arguments_digest": request_arguments_digest(
                    "owp.run_tests", arguments
                ),
                "nonce": _grant_id(nonce_label),
                "requested_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "authentication_method": "agent_signature",
                "model_id": "model",
                "model_version": "1",
                "prompt_template_digest": "a" * 64,
                "context_source_digest": "b" * 64,
            },
            role_keys[actor_role][0],
        )
    )
    return request, arguments, facts


def _execute_independent_run(
    case,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    *,
    execution_context_id: str = "a" * 64,
    container_instance_id_digest: str = "b" * 64,
    nonce_label: str = "independent:run-1",
    actual_exit_code: int | None = 0,
):
    from test_mcp_server import (
        _current_run_tests_context,
        _execute_run_tests_case,
    )

    request, arguments, facts = _independent_test_request(
        case,
        ephemeral_role_keys,
        fixed_now,
        nonce_label=nonce_label,
        execution_context_id=execution_context_id,
        container_instance_id_digest=container_instance_id_digest,
    )
    evidence_incomplete_context = _current_run_tests_context(case, fixed_now)
    return _execute_run_tests_case(
        case,
        case["ledger_path"].parent,
        ephemeral_role_keys,
        _FakeRunTestsExecutionDriver(actual_exit_code=actual_exit_code),
        context=evidence_incomplete_context,
        request=request,
        request_arguments=arguments,
        execution_facts=facts,
        now=fixed_now,
    )


def test_independent_slot_is_selected_in_evidence_incomplete(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
) -> None:
    case, first, incomplete = _independent_case(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        sidecar_receipt_factory,
        fixed_now,
        monkeypatch,
    )
    import openworkproof.mcp_server as mcp_server

    receipt = _execute_independent_run(
        case, ephemeral_role_keys, sidecar_receipt_factory, fixed_now
    )
    assert receipt.state_before == "evidence_incomplete"
    assert receipt.state_after == "evidence_incomplete"
    assert len(receipt.evidence_refs) == 1
    path = receipt.evidence_refs[0].path
    assert path.endswith("evidence/verifier-independent-result/01.json") or any(
        path == f"evidence/{artifact.path}"
        for artifact in case["work_order"].evidence_policy.artifacts
        if artifact.purpose == "verifier_independent_result"
    )
    assert receipt.evidence_refs[0].size_bytes > 0
    # Causal parents must include the latest proof_composed trigger.
    from openworkproof.models import SystemEventReceipt as _Ser

    triggers = [
        r for r in incomplete.ledger_prefix.receipts
        if isinstance(r, _Ser) and r.system_event_name == "proof_composed"
    ]
    assert triggers, "no proof_composed trigger in prefix"
    latest_trigger_id = max(triggers, key=lambda item: item.sequence).receipt_id
    assert latest_trigger_id in receipt.parent_receipt_ids


def test_independent_state_remains_incomplete_on_non_passing_closed_result(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
) -> None:
    case, first, incomplete = _independent_case(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        sidecar_receipt_factory,
        fixed_now,
        monkeypatch,
    )
    import openworkproof.mcp_server as mcp_server
    from test_mcp_server import _FakeRunTestsExecutionDriver

    class _FailDriver(_FakeRunTestsExecutionDriver):
        pass

    # Drive an independent run with a non-passing exit code.
    request, arguments, facts = _independent_test_request(
        case, ephemeral_role_keys, fixed_now,
        nonce_label="independent:fail",
        execution_context_id="3" * 64,
        container_instance_id_digest="4" * 64,
    )
    evidence_incomplete_context = _current_run_tests_context(case, fixed_now)
    _execute_run_tests_case(
        case,
        case["ledger_path"].parent,
        ephemeral_role_keys,
        _FakeRunTestsExecutionDriver(actual_exit_code=1),
        context=evidence_incomplete_context,
        request=request,
        request_arguments=arguments,
        execution_facts=facts,
        now=fixed_now,
    )
    # The state must still be evidence_incomplete because the run sealed
    # the independent episode rather than progressing to locally_verified.
    import sqlite3 as _sql

    connection = _sql.connect(case["ledger_path"])
    try:
        state = connection.execute(
            "SELECT current_state FROM work_order_state WHERE singleton = 1"
        ).fetchone()[0]
    finally:
        connection.close()
    assert state == "evidence_incomplete"
