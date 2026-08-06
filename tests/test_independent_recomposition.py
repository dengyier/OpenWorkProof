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
import openworkproof.evidence as evidence
import openworkproof.mcp_server as mcp_server
from openworkproof.models import (
    ACTION_RECEIPT_ADAPTER,
    AgentRequest,
    ComposeProofArguments,
    request_arguments_digest,
)
from openworkproof.policy import CommittedEvidence
from openworkproof.policy import ProspectiveExecutionFacts

from openworkproof.signing import (
    decode_and_verify_key_binding,
    sign_payload,
    verify_payload,
)
from test_mcp_server import (
    _FakeRunTestsExecutionDriver,
    _current_run_tests_context,
    _execute_run_tests_case,
    _grant_id,
    _grant_replay_inputs,
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
        expected_state_version=evidence._derive_protocol_transaction_version(
                action_receipts=context.ledger_prefix.receipts,
                acceptance_receipts=(),
            ),
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
    *,
    verifier_tool_calls: int = 2,
):
    case = _run_tests_case(
        tmp_path=tmp_path,
        signed_work_order=signed_work_order,
        role_keys=ephemeral_role_keys,
        sidecar_receipt_factory=sidecar_receipt_factory,
        now=fixed_now,
        verifier_tool_calls=verifier_tool_calls,
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
    failure_code: str | None = None,
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
        _FakeRunTestsExecutionDriver(
            actual_exit_code=(
                actual_exit_code if failure_code is None else None
            ),
            failure_code=failure_code,
        ),
        context=evidence_incomplete_context,
        request=request,
        request_arguments=arguments,
        execution_facts=facts,
        now=fixed_now,
    )


def _execute_independent_run_with_context(
    case,
    ephemeral_role_keys,
    fixed_now,
    *,
    context,
    execution_context_id: str,
    container_instance_id_digest: str,
    nonce_label: str,
):
    from test_mcp_server import _execute_run_tests_case

    request, arguments, facts = _independent_test_request(
        case,
        ephemeral_role_keys,
        fixed_now,
        nonce_label=nonce_label,
        execution_context_id=execution_context_id,
        container_instance_id_digest=container_instance_id_digest,
    )
    return _execute_run_tests_case(
        case,
        case["ledger_path"].parent,
        ephemeral_role_keys,
        _FakeRunTestsExecutionDriver(),
        context=context,
        request=request,
        request_arguments=arguments,
        execution_facts=facts,
        now=fixed_now,
    )


def test_independent_slot_mapping_is_strictly_one_to_one(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
) -> None:
    import hashlib  # noqa: PLC0415

    case, first, incomplete = _independent_case(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        sidecar_receipt_factory,
        fixed_now,
        monkeypatch,
    )
    receipt = _execute_independent_run(
        case,
        ephemeral_role_keys,
        sidecar_receipt_factory,
        fixed_now,
        execution_context_id="c3" * 32,
        container_instance_id_digest="d4" * 32,
        nonce_label="independent:slot-map",
    )
    assert receipt.state_before == "evidence_incomplete"
    independent_path = receipt.evidence_refs[0].path
    payload = (
        case["evidence_root"]
        / independent_path.removeprefix("evidence/")
    ).read_bytes()
    work_order = case["work_order"]

    # A) Primary-episode state with the independent slot is rejected.
    wrong_state = receipt.model_copy(update={"state_before": "running"})
    with pytest.raises(ValueError, match="wrong slot purpose"):
        wrong_state.validate_evidence_payloads(
            {independent_path: payload}, work_order
        )

    # B) evidence_incomplete with the primary verifier slot is rejected.
    verifier_slot = next(
        artifact
        for artifact in work_order.evidence_policy.artifacts
        if artifact.purpose == "verifier_result"
    )
    verifier_path = f"evidence/{verifier_slot.path}"
    swapped_ref = receipt.evidence_refs[0].model_copy(
        update={
            "path": verifier_path,
            "sha256": hashlib.sha256(payload).hexdigest(),
            "media_type": verifier_slot.media_type,
            "size_bytes": len(payload),
        }
    )
    wrong_slot = receipt.model_copy(
        update={"evidence_refs": (swapped_ref,)}
    )
    with pytest.raises(ValueError, match="wrong slot purpose"):
        wrong_slot.validate_evidence_payloads(
            {verifier_path: payload}, work_order
        )

    # C) The canonical mapping still validates.
    receipt.validate_evidence_payloads(
        {independent_path: payload}, work_order
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


def _tracking_driver(*args, **kwargs):
    """A driver that records prepare/start calls for gate-ordering proof."""
    from test_mcp_server import _FakeRunTestsExecutionDriver

    driver = _FakeRunTestsExecutionDriver(*args, **kwargs)
    return driver


def _snapshot_ledger(case) -> dict:
    import sqlite3 as _sql

    connection = _sql.connect(case["ledger_path"])
    try:
        return {
            "journal": connection.execute(
                "SELECT COUNT(*) FROM handler_executions"
            ).fetchone()[0],
            "events": connection.execute(
                "SELECT COUNT(*) FROM grant_events"
            ).fetchone()[0],
            "sequence": connection.execute(
                "SELECT next_sequence FROM sequence_counter WHERE singleton = 1"
            ).fetchone()[0],
            "state": connection.execute(
                "SELECT current_state, version FROM work_order_state "
                "WHERE singleton = 1"
            ).fetchone(),
            "receipts": connection.execute(
                "SELECT COUNT(*) FROM receipts"
            ).fetchone()[0],
            "reports": connection.execute(
                "SELECT COUNT(*) FROM composition_reports"
            ).fetchone()[0],
        }
    finally:
        connection.close()


def test_independent_episode_is_sealed_after_first_result(
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
    from test_mcp_server import _execute_run_tests_case

    # First independent run commits a passing result.
    request, arguments, facts = _independent_test_request(
        case, ephemeral_role_keys, fixed_now,
        nonce_label="independent:gate-run",
        execution_context_id="e" * 64,
        container_instance_id_digest="f" * 64,
    )
    from test_mcp_server import _current_run_tests_context

    context_after_first = _current_run_tests_context(case, fixed_now)
    _execute_run_tests_case(
        case,
        case["ledger_path"].parent,
        ephemeral_role_keys,
        _FakeRunTestsExecutionDriver(),
        context=context_after_first,
        request=request,
        request_arguments=arguments,
        execution_facts=facts,
        now=fixed_now,
    )
    # A second independent run on the same episode must be sealed closed.
    sealed_context = _current_run_tests_context(case, fixed_now)
    driver = _tracking_driver()
    second_request, second_arguments, second_facts = _independent_test_request(
        case, ephemeral_role_keys, fixed_now,
        nonce_label="independent:gate-sealed",
        execution_context_id="a1" * 32,
        container_instance_id_digest="b1" * 32,
    )
    with pytest.raises(
        (mcp_server.HandlerCoordinationError, mcp_server.ToolCallDenied),
        match="sealed|denied|unavailable|PREDICATE_DENIED",
    ):
        _execute_run_tests_case(
            case,
            case["ledger_path"].parent,
            ephemeral_role_keys,
            driver,
            context=sealed_context,
            request=second_request,
            request_arguments=second_arguments,
            execution_facts=second_facts,
            now=fixed_now,
        )
    # The execution driver must never have started a second run.
    assert all(call[0] not in {"prepare", "start_and_wait"} for call in driver.calls)


def test_independent_pre_start_gate_leaves_snapshot_unchanged(
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
    from test_mcp_server import _current_run_tests_context, _execute_run_tests_case

    # First independent run commits; then a sealed second run must be a
    # no-op for every authoritative table.
    request, arguments, facts = _independent_test_request(
        case, ephemeral_role_keys, fixed_now,
        nonce_label="independent:snap-1",
        execution_context_id="c1" * 32,
        container_instance_id_digest="d1" * 32,
    )
    context_before = _current_run_tests_context(case, fixed_now)
    _execute_run_tests_case(
        case,
        case["ledger_path"].parent,
        ephemeral_role_keys,
        _FakeRunTestsExecutionDriver(),
        context=context_before,
        request=request,
        request_arguments=arguments,
        execution_facts=facts,
        now=fixed_now,
    )
    before = _snapshot_ledger(case)
    sealed_context = _current_run_tests_context(case, fixed_now)
    second_request, second_arguments, second_facts = _independent_test_request(
        case, ephemeral_role_keys, fixed_now,
        nonce_label="independent:snap-2",
        execution_context_id="11" * 32,
        container_instance_id_digest="22" * 32,
    )
    driver = _tracking_driver()
    with pytest.raises(
        (mcp_server.HandlerCoordinationError, mcp_server.ToolCallDenied)
    ):
        _execute_run_tests_case(
            case,
            case["ledger_path"].parent,
            ephemeral_role_keys,
            driver,
            context=sealed_context,
            request=second_request,
            request_arguments=second_arguments,
            execution_facts=second_facts,
            now=fixed_now,
        )
    assert _snapshot_ledger(case) == before
    assert all(call[0] not in {"prepare", "start_and_wait"} for call in driver.calls)


def _recompose_request(
    case,
    context,
    role_keys,
    now,
    *,
    previous_report_digest,
    nonce_label: str,
) -> AgentRequest:
    return _signed_compose_request(
        case,
        context,
        role_keys,
        now,
        previous_report_digest=previous_report_digest,
        nonce_label=nonce_label,
    )


def _run_independent_and_recompose(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
):
    """Run an independent result then recompose against the first report."""
    case, first, incomplete = _independent_case(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        sidecar_receipt_factory,
        fixed_now,
        monkeypatch,
    )
    # Commit the independent result first; recomposition is only meaningful
    # after the independent episode has produced a receipt.
    from test_mcp_server import _current_run_tests_context

    receipt = _execute_independent_run(
        case,
        ephemeral_role_keys,
        sidecar_receipt_factory,
        fixed_now,
        execution_context_id="a1" * 32,
        container_instance_id_digest="b1" * 32,
        nonce_label="independent:recompose",
    )
    refreshed = _current_run_tests_context(case, fixed_now)
    first_digest = acceptance.composition_report_digest(first.report)
    assert first.trigger_receipt.cause.composition_report_digest == first_digest
    return case, first, refreshed, receipt, first_digest


def test_recomposition_requires_current_report_digest(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
) -> None:
    case, first, refreshed, receipt, first_digest = (
        _run_independent_and_recompose(
            tmp_path,
            signed_work_order,
            ephemeral_role_keys,
            sidecar_receipt_factory,
            fixed_now,
            monkeypatch,
        )
    )
    good = _recompose_request(
        case, refreshed, ephemeral_role_keys, fixed_now,
        previous_report_digest=first_digest,
        nonce_label="recompose:good",
    )
    result = acceptance.compose_proof_transaction(
        case["ledger_path"],
        evidence_root=case["evidence_root"],
        context=refreshed,
        request=good,
        sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
        clock=lambda: fixed_now,
    )
    # The five-dimension chain is closed now: recomposition reaches
    # proof_ready with both Verifier evidence refs in the report.
    assert result.report.verifier_conclusion == "proof_ready"
    coverage = dict(result.report.evidence_coverage)
    assert coverage["independent_result"] is True
    test_paths = [item.path for item in result.report.test_evidence_refs]
    assert any("verifier-independent-result" in path for path in test_paths)
    assert any("verifier-result" in path for path in test_paths)
    import sqlite3 as _sql

    connection = _sql.connect(case["ledger_path"])
    try:
        reports = connection.execute(
            "SELECT COUNT(*) FROM composition_reports"
        ).fetchone()[0]
        state = connection.execute(
            "SELECT current_state FROM work_order_state WHERE singleton = 1"
        ).fetchone()[0]
    finally:
        connection.close()
    assert reports == 2
    assert state == "proof_ready"


def test_recomposition_rejects_null_stale_or_unknown_digest(
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
    first_digest = acceptance.composition_report_digest(first.report)
    bad_digests = [
        None,
        "0" * 64,
        first_digest[::-1],
    ]
    for bad in bad_digests:
        bad_request = _recompose_request(
            case, incomplete, ephemeral_role_keys, fixed_now,
            previous_report_digest=bad,
            nonce_label=f"recompose:bad:{bad!s}"[:64],
        )
        with pytest.raises(
            acceptance.AcceptanceTransactionError,
            match="previous_report_digest|arguments|context",
        ):
            acceptance.compose_proof_transaction(
                case["ledger_path"],
                evidence_root=case["evidence_root"],
                context=incomplete,
                request=bad_request,
                sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
                clock=lambda: fixed_now,
            )


def test_recomposition_commit_ack_loss_recovers_exact_truth(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
) -> None:
    from openworkproof import evidence
    from test_acceptance import _AckLossConnection

    case, first, refreshed, receipt, first_digest = (
        _run_independent_and_recompose(
            tmp_path,
            signed_work_order,
            ephemeral_role_keys,
            sidecar_receipt_factory,
            fixed_now,
            monkeypatch,
        )
    )
    good = _recompose_request(
        case, refreshed, ephemeral_role_keys, fixed_now,
        previous_report_digest=first_digest,
        nonce_label="recompose:ack-loss",
    )
    real_connect = evidence.connect_ledger
    monkeypatch.setattr(
        evidence,
        "connect_ledger",
        lambda p: _AckLossConnection(real_connect(p)),
    )
    with pytest.raises(
        acceptance.AcceptanceCommittedError,
        match="acknowledgement was lost",
    ) as captured:
        acceptance.compose_proof_transaction(
            case["ledger_path"],
            evidence_root=case["evidence_root"],
            context=refreshed,
            request=good,
            sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
            clock=lambda: fixed_now,
        )
    monkeypatch.undo()
    committed = captured.value.committed
    assert committed.report.verifier_conclusion == "proof_ready"
    import sqlite3 as _sql

    connection = _sql.connect(case["ledger_path"])
    try:
        reports = connection.execute(
            "SELECT COUNT(*) FROM composition_reports"
        ).fetchone()[0]
        state = connection.execute(
            "SELECT current_state, version FROM work_order_state "
            "WHERE singleton = 1"
        ).fetchone()
    finally:
        connection.close()
    assert reports == 2
    assert state == ("proof_ready", 8)


def test_recomposition_readback_failure_is_indeterminate(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
) -> None:
    case, first, refreshed, receipt, first_digest = (
        _run_independent_and_recompose(
            tmp_path,
            signed_work_order,
            ephemeral_role_keys,
            sidecar_receipt_factory,
            fixed_now,
            monkeypatch,
        )
    )
    good = _recompose_request(
        case, refreshed, ephemeral_role_keys, fixed_now,
        previous_report_digest=first_digest,
        nonce_label="recompose:readback",
    )
    monkeypatch.setattr(
        acceptance,
        "_readback_compose_committed",
        lambda *a, **k: False,
    )
    with pytest.raises(
        acceptance.AcceptanceCommitIndeterminateError,
        match="readback could not confirm",
    ):
        acceptance.compose_proof_transaction(
            case["ledger_path"],
            evidence_root=case["evidence_root"],
            context=refreshed,
            request=good,
            sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
            clock=lambda: fixed_now,
        )


def test_concurrent_independent_runs_have_one_winner(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
) -> None:
    import threading  # noqa: PLC0415

    case, first, incomplete = _independent_case(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        sidecar_receipt_factory,
        fixed_now,
        monkeypatch,
    )
    from test_mcp_server import (
        _current_run_tests_context,
        _execute_run_tests_case,
    )

    base_context = _current_run_tests_context(case, fixed_now)
    outcomes = []
    barrier = threading.Barrier(2)

    def attempt(nonce_label, ctx_id, cid_id):
        barrier.wait()
        try:
            request, arguments, facts = _independent_test_request(
                case, ephemeral_role_keys, fixed_now,
                nonce_label=nonce_label,
                execution_context_id=ctx_id,
                container_instance_id_digest=cid_id,
            )
            _execute_run_tests_case(
                case,
                case["ledger_path"].parent,
                ephemeral_role_keys,
                _FakeRunTestsExecutionDriver(),
                context=base_context,
                request=request,
                request_arguments=arguments,
                execution_facts=facts,
                now=fixed_now,
            )
            outcomes.append("success")
        except Exception as error:  # noqa: BLE001
            outcomes.append(type(error).__name__)

    threads = [
        threading.Thread(
            target=attempt,
            args=("independent:race-a", "1a" * 32, "2a" * 32),
        ),
        threading.Thread(
            target=attempt,
            args=("independent:race-b", "1b" * 32, "2b" * 32),
        ),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert len(outcomes) == 2
    assert outcomes.count("success") == 1, outcomes
    import sqlite3 as _sql

    connection = _sql.connect(case["ledger_path"])
    try:
        independent_receipts = connection.execute(
            "SELECT COUNT(*) FROM receipts WHERE receipt_json LIKE "
            "'%verifier-independent-result%'"
        ).fetchone()[0]
    finally:
        connection.close()
    assert independent_receipts == 1


def test_concurrent_recompositions_have_one_second_report(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
) -> None:
    import threading  # noqa: PLC0415

    case, first, refreshed, receipt, first_digest = (
        _run_independent_and_recompose(
            tmp_path,
            signed_work_order,
            ephemeral_role_keys,
            sidecar_receipt_factory,
            fixed_now,
            monkeypatch,
        )
    )
    outcomes = []
    barrier = threading.Barrier(2)

    def attempt(nonce_label):
        barrier.wait()
        try:
            request = _recompose_request(
                case, refreshed, ephemeral_role_keys, fixed_now,
                previous_report_digest=first_digest,
                nonce_label=nonce_label,
            )
            acceptance.compose_proof_transaction(
                case["ledger_path"],
                evidence_root=case["evidence_root"],
                context=refreshed,
                request=request,
                sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
                clock=lambda: fixed_now,
            )
            outcomes.append("success")
        except Exception as error:  # noqa: BLE001
            outcomes.append(type(error).__name__)

    threads = [
        threading.Thread(target=attempt, args=("recompose:race-a",)),
        threading.Thread(target=attempt, args=("recompose:race-b",)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert len(outcomes) == 2
    assert outcomes.count("success") == 1, outcomes
    import sqlite3 as _sql

    connection = _sql.connect(case["ledger_path"])
    try:
        reports = connection.execute(
            "SELECT COUNT(*) FROM composition_reports"
        ).fetchone()[0]
    finally:
        connection.close()
    assert reports == 2


def test_non_passing_independent_result_seals_the_episode(
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
    from test_mcp_server import (
        _current_run_tests_context,
        _execute_run_tests_case,
    )

    # A non-passing closed independent result seals the episode.
    fail_request, fail_arguments, fail_facts = _independent_test_request(
        case, ephemeral_role_keys, fixed_now,
        nonce_label="independent:seal-fail",
        execution_context_id="ca" * 32,
        container_instance_id_digest="db" * 32,
    )
    base_context = _current_run_tests_context(case, fixed_now)
    _execute_run_tests_case(
        case,
        case["ledger_path"].parent,
        ephemeral_role_keys,
        _FakeRunTestsExecutionDriver(actual_exit_code=1),
        context=base_context,
        request=fail_request,
        request_arguments=fail_arguments,
        execution_facts=fail_facts,
        now=fixed_now,
    )
    sealed_context = _current_run_tests_context(case, fixed_now)
    # A further independent run is refused.
    again_request, again_arguments, again_facts = _independent_test_request(
        case, ephemeral_role_keys, fixed_now,
        nonce_label="independent:seal-again",
        execution_context_id="dd" * 32,
        container_instance_id_digest="ee" * 32,
    )
    from openworkproof.policy import AuthorizationPolicyError

    with pytest.raises(
        (
            mcp_server.HandlerCoordinationError,
            mcp_server.ToolCallDenied,
            AuthorizationPolicyError,
        )
    ):
        _execute_run_tests_case(
            case,
            case["ledger_path"].parent,
            ephemeral_role_keys,
            _FakeRunTestsExecutionDriver(),
            context=sealed_context,
            request=again_request,
            request_arguments=again_arguments,
            execution_facts=again_facts,
            now=fixed_now,
        )
    # A recomposition is refused too (no passing independent result).
    import sqlite3 as _sql

    connection = _sql.connect(case["ledger_path"])
    try:
        reports_before = connection.execute(
            "SELECT COUNT(*) FROM composition_reports"
        ).fetchone()[0]
    finally:
        connection.close()
    from openworkproof.policy import AuthorizationPolicyError

    with pytest.raises(
        (acceptance.AcceptanceTransactionError, AuthorizationPolicyError)
    ):
        acceptance.compose_proof_transaction(
            case["ledger_path"],
            evidence_root=case["evidence_root"],
            context=sealed_context,
            request=_recompose_request(
                case, sealed_context, ephemeral_role_keys, fixed_now,
                previous_report_digest=acceptance.composition_report_digest(
                    first.report
                ),
                nonce_label="recompose:sealed",
            ),
            sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
            clock=lambda: fixed_now,
        )
    connection = _sql.connect(case["ledger_path"])
    try:
        reports_after = connection.execute(
            "SELECT COUNT(*) FROM composition_reports"
        ).fetchone()[0]
    finally:
        connection.close()
    assert reports_after == reports_before


def _offline_bundle(case, work_order, first, second):
    """Copy the authoritative inputs for offline verification."""
    from openworkproof.policy import CommittedEvidence
    from test_mcp_server import _grant_replay_inputs

    receipts, grants, attempts = _grant_replay_inputs(
        case["ledger_path"], work_order
    )
    committed = []
    for receipt in receipts:
        for reference in receipt.evidence_refs:
            payload = (
                case["evidence_root"]
                / reference.path.removeprefix("evidence/")
            ).read_bytes()
            committed.append(
                CommittedEvidence(reference=reference, payload=payload)
            )
    committed.sort(key=lambda item: item.reference.path.encode())
    from openworkproof.signing import decode_and_verify_key_binding

    public_keys = {
        binding.key_id: decode_and_verify_key_binding(binding)
        for binding in work_order.key_bindings
    }
    return (
        tuple(sorted(grants.values(), key=lambda item: item.grant_id)),
        tuple(sorted(attempts.values(), key=lambda item: item.digest)),
        receipts,
        tuple(committed),
        public_keys,
    )


def test_two_report_bundle_verifies_offline(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
) -> None:
    case, first, refreshed, receipt, first_digest = (
        _run_independent_and_recompose(
            tmp_path,
            signed_work_order,
            ephemeral_role_keys,
            sidecar_receipt_factory,
            fixed_now,
            monkeypatch,
        )
    )
    second = acceptance.compose_proof_transaction(
        case["ledger_path"],
        evidence_root=case["evidence_root"],
        context=refreshed,
        request=_recompose_request(
            case, refreshed, ephemeral_role_keys, fixed_now,
            previous_report_digest=first_digest,
            nonce_label="recompose:offline",
        ),
        sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
        clock=lambda: fixed_now,
    )
    work_order = case["work_order"]
    effective_grants, grant_attempts, receipts, committed, public_keys = (
        _offline_bundle(case, work_order, first, second)
    )
    verified = acceptance.verify_composition_bundle(
        work_order=work_order,
        effective_grants=effective_grants,
        grant_attempts=grant_attempts,
        receipts=receipts,
        committed_evidence=committed,
        reports=(first.report, second.report),
        public_keys=public_keys,
    )
    assert verified == second.report
    assert verified.verifier_conclusion == "proof_ready"
    assert dict(verified.evidence_coverage)["independent_result"] is True
    test_paths = [item.path for item in verified.test_evidence_refs]
    assert any("verifier-independent-result" in path for path in test_paths)


def test_two_report_bundle_tampering_fails_closed(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
) -> None:
    case, first, refreshed, receipt, first_digest = (
        _run_independent_and_recompose(
            tmp_path,
            signed_work_order,
            ephemeral_role_keys,
            sidecar_receipt_factory,
            fixed_now,
            monkeypatch,
        )
    )
    second = acceptance.compose_proof_transaction(
        case["ledger_path"],
        evidence_root=case["evidence_root"],
        context=refreshed,
        request=_recompose_request(
            case, refreshed, ephemeral_role_keys, fixed_now,
            previous_report_digest=first_digest,
            nonce_label="recompose:tamper",
        ),
        sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
        clock=lambda: fixed_now,
    )
    work_order = case["work_order"]
    effective_grants, grant_attempts, receipts, committed, public_keys = (
        _offline_bundle(case, work_order, first, second)
    )

    def mutate_report(report, index):
        raw = report.model_dump(mode="json")
        raw["causal_graph_root"] = "0" * 64
        return type(report).model_validate(raw)

    mutated_first = mutate_report(first.report, 0)
    with pytest.raises(acceptance.AcceptanceTransactionError):
        acceptance.verify_composition_bundle(
            work_order=work_order,
            effective_grants=effective_grants,
            grant_attempts=grant_attempts,
            receipts=receipts,
            committed_evidence=committed,
            reports=(mutated_first, second.report),
            public_keys=public_keys,
        )

    tampered_evidence = list(committed)
    item = tampered_evidence[-1]
    payload = item.payload + b"\ntampered"
    tampered_evidence[-1] = CommittedEvidence(
        reference=item.reference,
        payload=payload,
    )
    with pytest.raises(acceptance.AcceptanceTransactionError):
        acceptance.verify_composition_bundle(
            work_order=work_order,
            effective_grants=effective_grants,
            grant_attempts=grant_attempts,
            receipts=receipts,
            committed_evidence=tuple(tampered_evidence),
            reports=(first.report, second.report),
            public_keys=public_keys,
        )

    wrong_reports = (first.report,)
    with pytest.raises(acceptance.AcceptanceTransactionError):
        acceptance.verify_composition_bundle(
            work_order=work_order,
            effective_grants=effective_grants,
            grant_attempts=grant_attempts,
            receipts=receipts,
            committed_evidence=committed,
            reports=wrong_reports,
            public_keys=public_keys,
        )


def _latest_proof_composed_trigger_id(ledger_path) -> str:
    """Find the latest proof_composed trigger receipt id."""
    from openworkproof.models import SystemEventReceipt  # noqa: PLC0415

    import sqlite3 as _sql

    connection = _sql.connect(ledger_path)
    try:
        _, receipts, _, _ = evidence._replay_receipt_publication_ledger(
            connection
        )
    finally:
        connection.close()
    triggers = [
        receipt
        for receipt in receipts
        if isinstance(receipt, SystemEventReceipt)
        and receipt.system_event_name == "proof_composed"
    ]
    return max(triggers, key=lambda item: item.sequence).receipt_id


@pytest.mark.parametrize(
    "failure_code", ["TIMEOUT", "OUTPUT_LIMIT", "DISK_LIMIT"]
)
def test_independent_infrastructure_failure_replays_exactly(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
    failure_code,
) -> None:
    case, first, incomplete = _independent_case(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        sidecar_receipt_factory,
        fixed_now,
        monkeypatch,
    )
    receipt = _execute_independent_run(
        case,
        ephemeral_role_keys,
        sidecar_receipt_factory,
        fixed_now,
        execution_context_id="a7" * 32,
        container_instance_id_digest="b8" * 32,
        nonce_label=f"independent:infra-{failure_code}",
        failure_code=failure_code,
    )
    assert receipt.execution_status == "failed"
    assert receipt.execution_error_code == failure_code
    assert receipt.state_before == "evidence_incomplete"
    assert receipt.state_after == "evidence_incomplete"
    assert receipt.policy_decision == "allow"
    # Infrastructure failures never produce an EvidenceRef.
    assert receipt.evidence_refs == ()
    # The closed failure still carries the proof_composed parent and exact
    # replay accepts it against the immutable first report.
    trigger_id = _latest_proof_composed_trigger_id(case["ledger_path"])
    assert trigger_id in receipt.parent_receipt_ids
    work_order = case["work_order"]
    effective_grants, grant_attempts, receipts, committed, public_keys = (
        _offline_bundle(case, work_order, first, None)
    )
    verified = acceptance.verify_composition_bundle(
        work_order=work_order,
        effective_grants=effective_grants,
        grant_attempts=grant_attempts,
        receipts=receipts,
        committed_evidence=committed,
        reports=(first.report,),
        public_keys=public_keys,
    )
    assert verified == first.report


def test_offline_bundle_rejects_duplicate_or_reordered_reports(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
) -> None:
    case, first, refreshed, receipt, first_digest = (
        _run_independent_and_recompose(
            tmp_path,
            signed_work_order,
            ephemeral_role_keys,
            sidecar_receipt_factory,
            fixed_now,
            monkeypatch,
        )
    )
    second = acceptance.compose_proof_transaction(
        case["ledger_path"],
        evidence_root=case["evidence_root"],
        context=refreshed,
        request=_recompose_request(
            case, refreshed, ephemeral_role_keys, fixed_now,
            previous_report_digest=first_digest,
            nonce_label="recompose:dup-reject",
        ),
        sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
        clock=lambda: fixed_now,
    )
    work_order = case["work_order"]
    effective_grants, grant_attempts, receipts, committed, public_keys = (
        _offline_bundle(case, work_order, first, second)
    )
    for reports in (
        (second.report, second.report),
        (first.report, first.report),
        (second.report, first.report),
    ):
        with pytest.raises(
            acceptance.AcceptanceTransactionError,
            match="duplicated|out of order",
        ):
            acceptance.verify_composition_bundle(
                work_order=work_order,
                effective_grants=effective_grants,
                grant_attempts=grant_attempts,
                receipts=receipts,
                committed_evidence=committed,
                reports=reports,
                public_keys=public_keys,
            )


def test_offline_bundle_rejects_receipt_correlation_and_key_tampering(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
) -> None:
    case, first, refreshed, receipt, first_digest = (
        _run_independent_and_recompose(
            tmp_path,
            signed_work_order,
            ephemeral_role_keys,
            sidecar_receipt_factory,
            fixed_now,
            monkeypatch,
        )
    )
    second = acceptance.compose_proof_transaction(
        case["ledger_path"],
        evidence_root=case["evidence_root"],
        context=refreshed,
        request=_recompose_request(
            case, refreshed, ephemeral_role_keys, fixed_now,
            previous_report_digest=first_digest,
            nonce_label="recompose:tamper-matrix",
        ),
        sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
        clock=lambda: fixed_now,
    )
    work_order = case["work_order"]
    effective_grants, grant_attempts, receipts, committed, public_keys = (
        _offline_bundle(case, work_order, first, second)
    )

    def verify_with(*, receipts_override=None, keys_override=None):
        return acceptance.verify_composition_bundle(
            work_order=work_order,
            effective_grants=effective_grants,
            grant_attempts=grant_attempts,
            receipts=(
                receipts if receipts_override is None else receipts_override
            ),
            committed_evidence=committed,
            reports=(first.report, second.report),
            public_keys=(
                public_keys if keys_override is None else keys_override
            ),
        )

    def rebuild(receipt, updates):
        """model_dump -> modify -> model_validate: full Pydantic rebuild."""
        raw = receipt.model_dump(mode="json")
        raw.update(updates)
        return ACTION_RECEIPT_ADAPTER.validate_python(raw)

    # 1) Receipt mutation: full rebuild; the stale signature no longer
    #    matches the rebuilt payload, so the bundle fails closed.
    tampered = tuple(
        rebuild(r, {"state_after": "locally_verified"})
        if r.receipt_id == receipt.receipt_id
        else r
        for r in receipts
    )
    with pytest.raises(acceptance.AcceptanceTransactionError):
        verify_with(receipts_override=tampered)

    # 2) Correlation-factor mutation: full rebuild with a well-formed but
    #    already-used execution context; the bundle still fails closed.
    factored = tuple(
        rebuild(
            r,
            {
                "correlation_factors": {
                    **r.correlation_factors.model_dump(mode="json"),
                    "execution_context_id": "1" * 64,
                }
            },
        )
        if r.receipt_id == receipt.receipt_id
        and r.correlation_factors is not None
        else r
        for r in receipts
    )
    with pytest.raises(acceptance.AcceptanceTransactionError):
        verify_with(receipts_override=factored)

    # 3) Public-key substitution breaks the grant chain signature checks.
    key_ids = list(public_keys)
    wrong = dict(public_keys)
    wrong[key_ids[0]] = wrong[key_ids[1]]
    with pytest.raises(acceptance.AcceptanceTransactionError):
        verify_with(keys_override=wrong)


@pytest.mark.parametrize(
    "table",
    [
        "receipts",
        "receipt_parents",
        "composition_reports",
        "evidence_publications",
    ],
)
def test_live_ledger_table_tamper_fails_replay(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
    table,
) -> None:
    case, first, refreshed, receipt, first_digest = (
        _run_independent_and_recompose(
            tmp_path,
            signed_work_order,
            ephemeral_role_keys,
            sidecar_receipt_factory,
            fixed_now,
            monkeypatch,
        )
    )
    second = acceptance.compose_proof_transaction(
        case["ledger_path"],
        evidence_root=case["evidence_root"],
        context=refreshed,
        request=_recompose_request(
            case, refreshed, ephemeral_role_keys, fixed_now,
            previous_report_digest=first_digest,
            nonce_label="recompose:table-tamper",
        ),
        sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
        clock=lambda: fixed_now,
    )
    import sqlite3 as _sql

    connection = _sql.connect(case["ledger_path"])
    try:
        if table == "receipts":
            connection.execute(
                "UPDATE receipts SET receipt_json = '{}' "
                "WHERE rowid = (SELECT MAX(rowid) FROM receipts)"
            )
        elif table == "receipt_parents":
            connection.execute(
                "DELETE FROM receipt_parents "
                "WHERE rowid = (SELECT MAX(rowid) FROM receipt_parents)"
            )
        elif table == "composition_reports":
            connection.execute(
                "UPDATE composition_reports SET report_json = '{}' "
                "WHERE rowid = 1"
            )
        elif table == "evidence_publications":
            connection.execute(
                "UPDATE evidence_publications SET digest = ?, state = 'COMMITTING' "
                "WHERE rowid = 1",
                ("0" * 64,),
            )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(Exception):
        connection = evidence.connect_ledger(case["ledger_path"])
        try:
            work_order, _, _, _ = (
                evidence._replay_receipt_publication_ledger(connection)
            )
            if table == "composition_reports":
                evidence._validated_composition_reports(
                    connection, work_order
                )
        finally:
            connection.close()


def test_recomposition_precommit_failure_is_atomic(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
) -> None:
    case, first, refreshed, receipt, first_digest = (
        _run_independent_and_recompose(
            tmp_path,
            signed_work_order,
            ephemeral_role_keys,
            sidecar_receipt_factory,
            fixed_now,
            monkeypatch,
        )
    )
    before = _snapshot_ledger(case)
    good = _recompose_request(
        case, refreshed, ephemeral_role_keys, fixed_now,
        previous_report_digest=first_digest,
        nonce_label="recompose:precommit",
    )

    def boom(*args, **kwargs):
        raise RuntimeError("injected pre-commit failure")

    monkeypatch.setattr(acceptance, "_insert_compose_rows", boom)
    with pytest.raises(RuntimeError, match="pre-commit"):
        acceptance.compose_proof_transaction(
            case["ledger_path"],
            evidence_root=case["evidence_root"],
            context=refreshed,
            request=good,
            sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
            clock=lambda: fixed_now,
        )
    monkeypatch.undo()
    # Every authoritative table and counter is unchanged.
    assert _snapshot_ledger(case) == before


def test_independent_cleanup_failure_keeps_committed_receipt(
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
    from test_mcp_server import (
        _current_run_tests_context,
        _execute_run_tests_case,
    )

    request, arguments, facts = _independent_test_request(
        case, ephemeral_role_keys, fixed_now,
        nonce_label="independent:cleanup-fail",
        execution_context_id="c9" * 32,
        container_instance_id_digest="d9" * 32,
    )
    context = _current_run_tests_context(case, fixed_now)
    driver = _FakeRunTestsExecutionDriver(
        cleanup_error=RuntimeError("cleanup exploded")
    )
    with pytest.raises(
        mcp_server.HandlerCoordinationError, match="RECOVERY_REQUIRED"
    ):
        _execute_run_tests_case(
            case,
            case["ledger_path"].parent,
            ephemeral_role_keys,
            driver,
            context=context,
            request=request,
            request_arguments=arguments,
            execution_facts=facts,
            now=fixed_now,
        )
    # The publication committed before cleanup; reopening proves the exact
    # receipt is present and the episode is not double-executed.
    import sqlite3 as _sql

    connection = _sql.connect(case["ledger_path"])
    try:
        independent_receipts = connection.execute(
            "SELECT COUNT(*) FROM receipts WHERE receipt_json LIKE "
            "'%verifier-independent-result%'"
        ).fetchone()[0]
    finally:
        connection.close()
    assert independent_receipts == 1
    # The stored execution record still exists for an explicit recovery pass;
    # the committed receipt is never double-applied by a fresh attempt, so a
    # re-entrant call with the same episode is refused or deferred, never a
    # second success.
    from test_mcp_server import _current_run_tests_context as _refresh

    reentrant_context = _refresh(case, fixed_now)
    request2, arguments2, facts2 = _independent_test_request(
        case, ephemeral_role_keys, fixed_now,
        nonce_label="independent:cleanup-reenter",
        execution_context_id="e9" * 32,
        container_instance_id_digest="f9" * 32,
    )
    with pytest.raises(
        (
            mcp_server.HandlerCoordinationError,
            mcp_server.ToolCallDenied,
        )
    ):
        _execute_run_tests_case(
            case,
            case["ledger_path"].parent,
            ephemeral_role_keys,
            _FakeRunTestsExecutionDriver(),
            context=reentrant_context,
            request=request2,
            request_arguments=arguments2,
            execution_facts=facts2,
            now=fixed_now,
        )
    connection = _sql.connect(case["ledger_path"])
    try:
        independent_receipts = connection.execute(
            "SELECT COUNT(*) FROM receipts WHERE receipt_json LIKE "
            "'%verifier-independent-result%'"
        ).fetchone()[0]
    finally:
        connection.close()
    assert independent_receipts == 1


def test_independent_prestart_rejects_non_incomplete_state(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
) -> None:
    from openworkproof.policy import AuthorizationPolicyError
    from test_mcp_server import (
        _current_run_tests_context,
        _execute_run_tests_case,
        _run_tests_case,
    )

    case = _run_tests_case(
        tmp_path=tmp_path,
        signed_work_order=signed_work_order,
        role_keys=ephemeral_role_keys,
        sidecar_receipt_factory=sidecar_receipt_factory,
        now=fixed_now,
    )
    _execute_run_tests_case(
        case,
        tmp_path,
        ephemeral_role_keys,
        _FakeRunTestsExecutionDriver(),
    )
    locally_verified = _current_run_tests_context(case, fixed_now)
    assert locally_verified.current_state == "locally_verified"
    before = _snapshot_ledger(case)
    request, arguments, facts = _independent_test_request(
        case, ephemeral_role_keys, fixed_now,
        nonce_label="independent:wrong-state",
        execution_context_id="f7" * 32,
        container_instance_id_digest="a8" * 32,
    )
    with pytest.raises(
        (
            mcp_server.HandlerCoordinationError,
            mcp_server.ToolCallDenied,
            AuthorizationPolicyError,
        )
    ):
        _execute_run_tests_case(
            case,
            tmp_path,
            ephemeral_role_keys,
            _FakeRunTestsExecutionDriver(),
            context=locally_verified,
            request=request,
            request_arguments=arguments,
            execution_facts=facts,
            now=fixed_now,
        )
    assert _snapshot_ledger(case) == before


def test_independent_payload_over_slot_limit_is_rejected(
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
    slot = next(
        artifact
        for artifact in case["work_order"].evidence_policy.artifacts
        if artifact.purpose == "verifier_independent_result"
    )
    oversized = b"x" * (slot.max_size_bytes + 1)
    with pytest.raises(
        mcp_server.HandlerCoordinationError, match="EVIDENCE_SLOT_UNAVAILABLE"
    ):
        mcp_server._next_test_reference(
            incomplete,
            case["arguments"],
            oversized,
            purpose="verifier_independent_result",
        )


def test_independent_reuses_primary_execution_ids_rejected(
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
    # "1" * 64 / "2" * 64 are the primary verifier execution identifiers;
    # reusing them in the independent episode must fail closed.
    with pytest.raises(
        mcp_server.ToolCallDenied, match="PREDICATE_DENIED"
    ):
        _execute_independent_run(
            case,
            ephemeral_role_keys,
            sidecar_receipt_factory,
            fixed_now,
            execution_context_id="1" * 64,
            container_instance_id_digest="2" * 64,
            nonce_label="independent:reuse-id",
        )


def test_independent_active_patch_mismatch_rejected(
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
    stale = dataclasses.replace(
        incomplete,
        causal_state=dataclasses.replace(
            incomplete.causal_state,
            active_patch_receipt_id="deadbeef" * 8,
        ),
    )
    before = _snapshot_ledger(case)
    with pytest.raises(
        mcp_server.HandlerCoordinationError,
        match="does not reproduce exactly|not the current ledger snapshot",
    ):
        _execute_independent_run_with_context(
            case,
            ephemeral_role_keys,
            fixed_now,
            context=stale,
            execution_context_id="f9" * 32,
            container_instance_id_digest="a0" * 32,
            nonce_label="independent:stale-patch",
        )
    assert _snapshot_ledger(case) == before


def _resign_receipt(receipt, private_key, updates=None):
    """model_dump -> modify -> re-sign with a valid Sidecar key."""
    raw = receipt.model_dump(mode="json")
    for key in ("digest", "signature_alg", "signer_key_id", "signature"):
        raw.pop(key, None)
    if updates:
        raw.update(updates)
    signed = sign_payload("action-receipt", raw, private_key)
    return ACTION_RECEIPT_ADAPTER.validate_python(signed)


def test_semantic_replay_rejects_correlation_tampering_with_valid_signature(
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
    receipt = _execute_independent_run(
        case,
        ephemeral_role_keys,
        sidecar_receipt_factory,
        fixed_now,
        execution_context_id="5a" * 32,
        container_instance_id_digest="6b" * 32,
        nonce_label="independent:sema",
    )
    # Rebuild and re-sign with the primary verifier's execution context id.
    # The signature is valid; the prefix replay must reject at the semantic
    # fresh-context check, not at a broken-signature layer.
    rebuilt = _resign_receipt(
        receipt,
        ephemeral_role_keys["Sidecar"][0],
        updates={
            "correlation_factors": {
                **receipt.correlation_factors.model_dump(mode="json"),
                "execution_context_id": "1" * 64,
            }
        },
    )
    sidecar_binding = next(
        binding
        for binding in case["work_order"].key_bindings
        if binding.role == "Sidecar"
    )
    assert verify_payload(
        "action-receipt",
        rebuilt.model_dump(mode="json"),
        decode_and_verify_key_binding(sidecar_binding),
    )
    receipts, grants, attempts = _grant_replay_inputs(
        case["ledger_path"], case["work_order"]
    )
    prefix = tuple(
        rebuilt if r.receipt_id == receipt.receipt_id else r
        for r in receipts
    )
    from openworkproof.composition import replay_authorization_causality  # noqa: PLC0415

    with pytest.raises(Exception, match="fresh execution context"):
        replay_authorization_causality(case["work_order"], prefix)


def test_infrastructure_failure_retry_succeeds_with_fresh_signature(
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
        verifier_tool_calls=3,
    )
    failed = _execute_independent_run(
        case,
        ephemeral_role_keys,
        sidecar_receipt_factory,
        fixed_now,
        execution_context_id="9e" * 32,
        container_instance_id_digest="0f" * 32,
        nonce_label="independent:retry-fail",
        failure_code="TIMEOUT",
    )
    assert failed.execution_status == "failed"
    assert failed.execution_error_code == "TIMEOUT"
    # Quota remains: a fresh signature with fresh execution identifiers
    # retries the episode and succeeds.
    succeeded = _execute_independent_run(
        case,
        ephemeral_role_keys,
        sidecar_receipt_factory,
        fixed_now,
        execution_context_id="a1b2" * 16,
        container_instance_id_digest="c3d4" * 16,
        nonce_label="independent:retry-ok",
    )
    assert succeeded.execution_status == "succeeded"
    assert succeeded.state_before == "evidence_incomplete"
    assert succeeded.state_after == "evidence_incomplete"


def test_independent_started_unconfirmed_recovery(
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
    from openworkproof import repo_tools  # noqa: PLC0415
    from test_mcp_server import _closed_run_tests_outcome

    request, arguments, facts = _independent_test_request(
        case, ephemeral_role_keys, fixed_now,
        nonce_label="independent:recover",
        execution_context_id="7c" * 32,
        container_instance_id_digest="8d" * 32,
    )
    refreshed = _current_run_tests_context(case, fixed_now)
    contract = repo_tools.RunTestsExecutionContract(
        execution_id=mcp_server._handler_execution_id(request, facts),
        request_digest=request.digest,
        arguments_digest=request.arguments_digest,
        candidate_workspace_id="c" * 64,
        source_artifact_sha256=(
            case["work_order"].replay_profile.source_artifact_sha256
        ),
        source_commit=arguments.source_commit,
        candidate_commit=arguments.candidate_commit,
        workspace_manifest_digest=arguments.workspace_manifest_digest,
        container_image_digest=arguments.container_image_digest,
        command_digest=arguments.command_digest,
        fixed_test_source_digest=arguments.fixed_test_source_digest,
    )
    lock_descriptor = evidence._acquire_target_lock(case["ledger_path"])
    try:
        mcp_server._reserve_handler_execution(
            case["ledger_path"],
            lock_descriptor,
            refreshed,
            request,
            facts,
            contract,
        )
        mcp_server._mark_handler_started(
            case["ledger_path"], lock_descriptor, contract.execution_id
        )
    finally:
        evidence._release_target_lock(lock_descriptor)
    driver = _FakeRunTestsExecutionDriver(
        reconciliation_outcomes=(_closed_run_tests_outcome(contract),)
    )
    receipt = _execute_run_tests_case(
        case,
        case["ledger_path"].parent,
        ephemeral_role_keys,
        driver,
        context=refreshed,
        request=request,
        request_arguments=arguments,
        execution_facts=facts,
        now=fixed_now,
    )
    assert receipt.state_before == "evidence_incomplete"
    assert receipt.state_after == "evidence_incomplete"
    assert receipt.policy_decision == "allow"
    assert [call[0] for call in driver.calls] == ["reconcile", "cleanup"]


def test_lock_release_failure_keeps_committed(
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
    request, arguments, facts = _independent_test_request(
        case, ephemeral_role_keys, fixed_now,
        nonce_label="independent:lock-release",
        execution_context_id="b5" * 32,
        container_instance_id_digest="c6" * 32,
    )
    refreshed = _current_run_tests_context(case, fixed_now)
    real_release = evidence._release_target_lock
    release_calls = []

    def broken_release(descriptor):
        release_calls.append(descriptor)
        if len(release_calls) == 2:
            # The first call belongs to evidence recovery; the second is the
            # main transaction's final release.
            return False, (RuntimeError("lock release exploded"),)
        return real_release(descriptor)

    monkeypatch.setattr(evidence, "_release_target_lock", broken_release)
    with pytest.raises(
        mcp_server.HandlerCoordinationError, match="lock release failed"
    ):
        _execute_run_tests_case(
            case,
            case["ledger_path"].parent,
            ephemeral_role_keys,
            _FakeRunTestsExecutionDriver(),
            context=refreshed,
            request=request,
            request_arguments=arguments,
            execution_facts=facts,
            now=fixed_now,
        )
    monkeypatch.undo()
    import sqlite3 as _sql

    connection = _sql.connect(case["ledger_path"])
    try:
        independent_receipts = connection.execute(
            "SELECT COUNT(*) FROM receipts WHERE receipt_json LIKE "
            "'%verifier-independent-result%'"
        ).fetchone()[0]
    finally:
        connection.close()
    assert independent_receipts == 1
