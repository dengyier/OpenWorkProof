"""Independent Verifier result and recomposition coverage.

This file reuses the test_mcp_server fixtures so each test starts from the
canonical running/retrying → locally_verified → evidence_incomplete chain.
The fixture-only Step 3 of Task 1 verifies the precondition without
changing any product behaviour.
"""

from __future__ import annotations

import pytest

import openworkproof.acceptance as acceptance
from openworkproof.models import (
    AgentRequest,
    ComposeProofArguments,
    request_arguments_digest,
)
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
