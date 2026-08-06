"""Acceptor rejection path coverage.

Reuses the test_acceptance fixtures so each test starts from a canonical
awaiting_human chain (request_acceptance_transaction committed).
"""

from __future__ import annotations

import hashlib

import pytest

import rfc8785

import openworkproof.acceptance as acceptance
import openworkproof.evidence as evidence
from openworkproof.models import (
    AcceptanceRejectionReceipt,
)
from openworkproof.signing import sign_payload


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


def _rejection_raw(
    case,
    context,
    request_receipt,
    ephemeral_role_keys,
    now,
    *,
    reason_code: str,
    reason_detail: str = "reviewed and declined",
    rejected_at=None,
    report=None,
):
    """Build the unsigned rejection payload bound to the current prefix."""
    from openworkproof.acceptance import (
        _sorted_unique_evidence_refs,
        causal_graph_root,
        composition_report_digest,
        evidence_snapshot_digest,
    )

    work_order = case["work_order"]
    selected_report = report
    if selected_report is None:
        selected_report = acceptance._current_report(
            case["ledger_path"], work_order
        )
    prefix = context.ledger_prefix.receipts
    refs = _sorted_unique_evidence_refs(prefix)
    snapshot = evidence_snapshot_digest(refs)
    rejection_id = hashlib.sha256(
        rfc8785.dumps(
            {
                "domain": "openworkproof/rejection-id/0.1",
                "work_order_digest": work_order.digest,
                "request_receipt_id": request_receipt.receipt_id,
                "request_receipt_digest": request_receipt.digest,
                "composition_report_digest": composition_report_digest(
                    selected_report
                ),
                "evidence_snapshot_digest": snapshot,
            }
        )
    ).hexdigest()
    return {
        "protocol_version": "0.1",
        "rejection_id": rejection_id,
        "work_order_digest": work_order.digest,
        "acceptance_request_receipt_id": request_receipt.receipt_id,
        "acceptance_request_receipt_digest": request_receipt.digest,
        "composition_report_digest": composition_report_digest(
            selected_report
        ),
        "evidence_snapshot_digest": snapshot,
        "receipt_digests": tuple(receipt.digest for receipt in prefix),
        "causal_graph_root": selected_report.causal_graph_root,
        "reason_code": reason_code,
        "reason_detail": reason_detail,
        "decision": "rejected",
        "rejected_at": (rejected_at or now).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def _sign_rejection(
    case,
    context,
    request_receipt,
    ephemeral_role_keys,
    now,
    *,
    reason_code: str = "BUSINESS_DECISION",
    reason_detail: str = "reviewed and declined",
    rejected_at=None,
    report=None,
) -> AcceptanceRejectionReceipt:
    raw = _rejection_raw(
        case,
        context,
        request_receipt,
        ephemeral_role_keys,
        now,
        reason_code=reason_code,
        reason_detail=reason_detail,
        rejected_at=rejected_at,
        report=report,
    )
    signed = sign_payload(
        "acceptance-rejection-receipt",
        raw,
        ephemeral_role_keys["Acceptor"][0],
    )
    return AcceptanceRejectionReceipt.model_validate(signed)


def test_rejection_model_accepts_canonical_object(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
) -> None:
    from test_acceptance import _awaiting_case

    case, context, composed, request_receipt = _awaiting_case(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        sidecar_receipt_factory,
        fixed_now,
        monkeypatch,
    )
    rejection = _sign_rejection(
        case, context, request_receipt, ephemeral_role_keys, fixed_now
    )
    assert rejection.decision == "rejected"
    assert rejection.reason_code == "BUSINESS_DECISION"
    assert rejection.acceptance_request_receipt_id == request_receipt.receipt_id
    assert rejection.work_order_digest == case["work_order"].digest


@pytest.mark.parametrize(
    "bad_code",
    ["BUSINESS_DECISION_EXTRA", "ACCEPTED", "reason", "EVIDENCE_OK"],
)
def test_rejection_model_rejects_invalid_reason_code(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
    bad_code,
) -> None:
    from test_acceptance import _awaiting_case

    case, context, composed, request_receipt = _awaiting_case(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        sidecar_receipt_factory,
        fixed_now,
        monkeypatch,
    )
    raw = _rejection_raw(
        case, context, request_receipt, ephemeral_role_keys, fixed_now,
        reason_code=bad_code,
    )
    with pytest.raises(Exception, match="reason_code|Literal|rejected"):
        AcceptanceRejectionReceipt.model_validate(
            sign_payload(
                "acceptance-rejection-receipt",
                raw,
                ephemeral_role_keys["Acceptor"][0],
            )
        )


def test_rejection_model_rejects_overlong_reason_detail(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
) -> None:
    from test_acceptance import _awaiting_case

    case, context, composed, request_receipt = _awaiting_case(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        sidecar_receipt_factory,
        fixed_now,
        monkeypatch,
    )
    raw = _rejection_raw(
        case, context, request_receipt, ephemeral_role_keys, fixed_now,
        reason_code="BUSINESS_DECISION",
        reason_detail="x" * 1025,
    )
    with pytest.raises(ValueError, match="reason detail"):
        AcceptanceRejectionReceipt.model_validate(
            sign_payload(
                "acceptance-rejection-receipt",
                raw,
                ephemeral_role_keys["Acceptor"][0],
            )
        )


def test_rejection_model_rejects_duplicate_receipt_digests(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
) -> None:
    from test_acceptance import _awaiting_case

    case, context, composed, request_receipt = _awaiting_case(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        sidecar_receipt_factory,
        fixed_now,
        monkeypatch,
    )
    raw = _rejection_raw(
        case, context, request_receipt, ephemeral_role_keys, fixed_now,
        reason_code="BUSINESS_DECISION",
    )
    prefix = context.ledger_prefix.receipts
    raw["receipt_digests"] = (prefix[0].digest,) * len(prefix)
    with pytest.raises(ValueError, match="receipt digests"):
        AcceptanceRejectionReceipt.model_validate(
            sign_payload(
                "acceptance-rejection-receipt",
                raw,
                ephemeral_role_keys["Acceptor"][0],
            )
        )


def _commit_rejection_row(
    case, context, request_receipt, ephemeral_role_keys, fixed_now,
    *, state_after="rejected", reason_code="BUSINESS_DECISION",
):
    """Manually insert a rejection row and advance the state (pre-transaction)."""
    from test_acceptance import _awaiting_case  # noqa: PLC0415

    rejection = _sign_rejection(
        case, context, request_receipt, ephemeral_role_keys, fixed_now,
        reason_code=reason_code,
    )
    connection = evidence.connect_ledger(case["ledger_path"])
    connection.execute("BEGIN IMMEDIATE")
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
            case["work_order"].digest,
            request_receipt.receipt_id,
            evidence._canonical_json(rejection.model_dump(mode="json")),
        ),
    )
    connection.execute(
        """
        UPDATE work_order_state
        SET current_state = ?, version = version + 1
        WHERE singleton = 1
        """,
        (state_after,),
    )
    connection.execute("COMMIT")
    connection.close()
    return rejection


def test_rejection_row_replays_to_rejected_state(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
) -> None:
    from test_acceptance import _awaiting_case

    case, context, composed, request_receipt = _awaiting_case(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        sidecar_receipt_factory,
        fixed_now,
        monkeypatch,
    )
    rejection = _commit_rejection_row(
        case, context, request_receipt, ephemeral_role_keys, fixed_now
    )
    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        work_order, receipts, _, _ = (
            evidence._replay_receipt_publication_ledger(connection)
        )
        state = connection.execute(
            "SELECT current_state, version FROM work_order_state "
            "WHERE singleton = 1"
        ).fetchone()
        rejections = evidence._validated_acceptance_rejections(
            connection, work_order
        )
    finally:
        connection.close()
    assert state == ("rejected", 8)
    assert len(rejections) == 1
    assert rejections[0].rejection_id == rejection.rejection_id
    assert rejections[0].decision == "rejected"


def test_tampered_rejection_row_fails_replay(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
) -> None:
    from test_acceptance import _awaiting_case

    case, context, composed, request_receipt = _awaiting_case(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        sidecar_receipt_factory,
        fixed_now,
        monkeypatch,
    )
    _commit_rejection_row(
        case, context, request_receipt, ephemeral_role_keys, fixed_now
    )
    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        row = connection.execute(
            "SELECT rejection_json FROM acceptance_rejection_receipts"
        ).fetchone()
        tampered = row[0] + "\ntampered"
        connection.execute(
            "UPDATE acceptance_rejection_receipts "
            "SET rejection_json = ?",
            (tampered,),
        )
        connection.commit()
    finally:
        connection.close()
    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        with pytest.raises(Exception):
            evidence._replay_receipt_publication_ledger(connection)
    finally:
        connection.close()


def test_rejection_suffix_requires_awaiting_human_tip(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
) -> None:
    from test_acceptance import _awaiting_case

    case, context, composed, request_receipt = _awaiting_case(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        sidecar_receipt_factory,
        fixed_now,
        monkeypatch,
    )
    # Advancing the state to accepted first makes a later rejection suffix
    # malformed: the tip is no longer awaiting_human.
    _commit_rejection_row(
        case, context, request_receipt, ephemeral_role_keys, fixed_now,
        state_after="accepted",
    )
    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        with pytest.raises(Exception, match="suffix|malformed|disagree"):
            evidence._replay_receipt_publication_ledger(connection)
    finally:
        connection.close()


def _rejection_table_snapshot(case) -> dict:
    import sqlite3 as _sql  # noqa: PLC0415

    connection = _sql.connect(case["ledger_path"])
    try:
        return {
            "rejections": connection.execute(
                "SELECT COUNT(*) FROM acceptance_rejection_receipts"
            ).fetchone()[0],
            "acceptances": connection.execute(
                "SELECT COUNT(*) FROM acceptance_receipts"
            ).fetchone()[0],
            "state": connection.execute(
                "SELECT current_state, version FROM work_order_state "
                "WHERE singleton = 1"
            ).fetchone(),
        }
    finally:
        connection.close()


def test_reject_acceptance_transaction_commits_rejected(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
) -> None:
    from test_acceptance import _awaiting_case

    case, context, composed, request_receipt = _awaiting_case(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        sidecar_receipt_factory,
        fixed_now,
        monkeypatch,
    )
    rejection = _sign_rejection(
        case, context, request_receipt, ephemeral_role_keys, fixed_now
    )
    committed = acceptance.reject_acceptance_transaction(
        case["ledger_path"],
        evidence_root=case["evidence_root"],
        context=context,
        rejection=rejection,
        public_keys=None,
        clock=lambda: fixed_now,
    )
    assert committed == rejection
    assert _rejection_table_snapshot(case) == {
        "rejections": 1,
        "acceptances": 0,
        "state": ("rejected", 8),
    }


def test_reject_acceptance_transaction_rejects_wrong_role_signer(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
) -> None:
    from test_acceptance import _awaiting_case

    case, context, composed, request_receipt = _awaiting_case(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        sidecar_receipt_factory,
        fixed_now,
        monkeypatch,
    )
    raw = _rejection_raw(
        case, context, request_receipt, ephemeral_role_keys, fixed_now,
        reason_code="BUSINESS_DECISION",
    )
    signed = sign_payload(
        "acceptance-rejection-receipt",
        raw,
        ephemeral_role_keys["Maintainer"][0],
    )
    wrong = AcceptanceRejectionReceipt.model_validate(signed)
    before = _rejection_table_snapshot(case)
    with pytest.raises(
        acceptance.AcceptanceTransactionError, match="bound Acceptor"
    ):
        acceptance.reject_acceptance_transaction(
            case["ledger_path"],
            evidence_root=case["evidence_root"],
            context=context,
            rejection=wrong,
            public_keys=None,
            clock=lambda: fixed_now,
        )
    assert _rejection_table_snapshot(case) == before


@pytest.mark.parametrize(
    "rejected_at_delta, message",
    [
        # The 300s freshness window is shadowed by the request-occurred_at
        # bound at the same frozen second, so only the future branch is
        # reachable end-to-end here.
        (1, "future"),
    ],
)
def test_reject_acceptance_transaction_rejects_bad_time(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
    rejected_at_delta,
    message,
) -> None:
    from datetime import timedelta  # noqa: PLC0415
    from test_acceptance import _awaiting_case

    case, context, composed, request_receipt = _awaiting_case(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        sidecar_receipt_factory,
        fixed_now,
        monkeypatch,
    )
    rejection = _sign_rejection(
        case, context, request_receipt, ephemeral_role_keys, fixed_now,
        rejected_at=fixed_now + timedelta(seconds=rejected_at_delta),
    )
    before = _rejection_table_snapshot(case)
    with pytest.raises(
        acceptance.AcceptanceTransactionError, match=message
    ):
        acceptance.reject_acceptance_transaction(
            case["ledger_path"],
            evidence_root=case["evidence_root"],
            context=context,
            rejection=rejection,
            public_keys=None,
            clock=lambda: fixed_now,
        )
    assert _rejection_table_snapshot(case) == before


def test_reject_commit_ack_loss_recovers_exact_truth(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
) -> None:
    from test_acceptance import _AckLossConnection, _awaiting_case  # noqa: PLC0415

    case, context, composed, request_receipt = _awaiting_case(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        sidecar_receipt_factory,
        fixed_now,
        monkeypatch,
    )
    rejection = _sign_rejection(
        case, context, request_receipt, ephemeral_role_keys, fixed_now
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
        acceptance.reject_acceptance_transaction(
            case["ledger_path"],
            evidence_root=case["evidence_root"],
            context=context,
            rejection=rejection,
            public_keys=None,
            clock=lambda: fixed_now,
        )
    monkeypatch.undo()
    committed = captured.value.committed
    assert committed == rejection
    assert _rejection_table_snapshot(case) == {
        "rejections": 1,
        "acceptances": 0,
        "state": ("rejected", 8),
    }


def test_reject_readback_failure_is_indeterminate(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
) -> None:
    from test_acceptance import _awaiting_case  # noqa: PLC0415

    case, context, composed, request_receipt = _awaiting_case(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        sidecar_receipt_factory,
        fixed_now,
        monkeypatch,
    )
    rejection = _sign_rejection(
        case, context, request_receipt, ephemeral_role_keys, fixed_now
    )
    monkeypatch.setattr(
        acceptance,
        "_readback_rejection_committed",
        lambda *a, **k: False,
    )
    with pytest.raises(
        acceptance.AcceptanceCommitIndeterminateError,
        match="readback could not confirm",
    ):
        acceptance.reject_acceptance_transaction(
            case["ledger_path"],
            evidence_root=case["evidence_root"],
            context=context,
            rejection=rejection,
            public_keys=None,
            clock=lambda: fixed_now,
        )


def test_accept_after_reject_fails_closed(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
) -> None:
    from test_acceptance import _awaiting_case, _sign_draft  # noqa: PLC0415

    case, context, composed, request_receipt = _awaiting_case(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        sidecar_receipt_factory,
        fixed_now,
        monkeypatch,
    )
    from test_mcp_server import _current_run_tests_context  # noqa: PLC0415

    draft = acceptance.prepare_acceptance(
        case["ledger_path"],
        evidence_root=case["evidence_root"],
        context=context,
        clock=lambda: fixed_now,
    )
    signed = _sign_draft(draft, ephemeral_role_keys)
    rejection = _sign_rejection(
        case, context, request_receipt, ephemeral_role_keys, fixed_now
    )
    acceptance.reject_acceptance_transaction(
        case["ledger_path"],
        evidence_root=case["evidence_root"],
        context=context,
        rejection=rejection,
        public_keys=None,
        clock=lambda: fixed_now,
    )
    rejected_context = _current_run_tests_context(case, fixed_now)
    before = _rejection_table_snapshot(case)
    from openworkproof.runtime_context import RuntimeContextError  # noqa: PLC0415

    with pytest.raises(
        (
            acceptance.AcceptanceTransactionError,
            acceptance.AcceptanceCommittedError,
            RuntimeContextError,
        ),
        match="awaiting_human|already has|already committed|does not reproduce",
    ):
        acceptance.commit_acceptance(
            case["ledger_path"],
            evidence_root=case["evidence_root"],
            context=rejected_context,
            acceptance=signed,
            public_keys=None,
            clock=lambda: fixed_now,
        )
    assert _rejection_table_snapshot(case) == before


def test_reject_after_accept_fails_closed(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
) -> None:
    from test_acceptance import _awaiting_case, _sign_draft  # noqa: PLC0415

    case, context, composed, request_receipt = _awaiting_case(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        sidecar_receipt_factory,
        fixed_now,
        monkeypatch,
    )
    draft = acceptance.prepare_acceptance(
        case["ledger_path"],
        evidence_root=case["evidence_root"],
        context=context,
        clock=lambda: fixed_now,
    )
    signed = _sign_draft(draft, ephemeral_role_keys)
    acceptance.commit_acceptance(
        case["ledger_path"],
        evidence_root=case["evidence_root"],
        context=context,
        acceptance=signed,
        public_keys=None,
        clock=lambda: fixed_now,
    )
    from test_mcp_server import _current_run_tests_context  # noqa: PLC0415

    accepted_context = _current_run_tests_context(case, fixed_now)
    before = _rejection_table_snapshot(case)
    rejection = _sign_rejection(
        case, context, request_receipt, ephemeral_role_keys, fixed_now
    )
    from openworkproof.runtime_context import RuntimeContextError  # noqa: PLC0415

    with pytest.raises(
        (
            acceptance.AcceptanceTransactionError,
            acceptance.AcceptanceCommittedError,
            RuntimeContextError,
        ),
        match="awaiting_human|already has|already committed|does not reproduce",
    ):
        acceptance.reject_acceptance_transaction(
            case["ledger_path"],
            evidence_root=case["evidence_root"],
            context=accepted_context,
            rejection=rejection,
            public_keys=None,
            clock=lambda: fixed_now,
        )
    assert _rejection_table_snapshot(case) == before


def test_second_rejection_fails_closed(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
) -> None:
    from test_acceptance import _awaiting_case  # noqa: PLC0415

    case, context, composed, request_receipt = _awaiting_case(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        sidecar_receipt_factory,
        fixed_now,
        monkeypatch,
    )
    rejection = _sign_rejection(
        case, context, request_receipt, ephemeral_role_keys, fixed_now
    )
    acceptance.reject_acceptance_transaction(
        case["ledger_path"],
        evidence_root=case["evidence_root"],
        context=context,
        rejection=rejection,
        public_keys=None,
        clock=lambda: fixed_now,
    )
    from test_mcp_server import _current_run_tests_context  # noqa: PLC0415

    rejected_context = _current_run_tests_context(case, fixed_now)
    before = _rejection_table_snapshot(case)
    second = _sign_rejection(
        case, context, request_receipt, ephemeral_role_keys, fixed_now,
        reason_code="EVIDENCE_INSUFFICIENT",
        reason_detail="second opinion",
    )
    with pytest.raises(
        (
            acceptance.AcceptanceTransactionError,
            acceptance.AcceptanceCommittedError,
        ),
        match="awaiting_human|already has|already committed",
    ):
        acceptance.reject_acceptance_transaction(
            case["ledger_path"],
            evidence_root=case["evidence_root"],
            context=rejected_context,
            rejection=second,
            public_keys=None,
            clock=lambda: fixed_now,
        )
    assert _rejection_table_snapshot(case) == before


def _offline_bundle(case, work_order):
    """Copy the authoritative inputs for offline verification."""
    from openworkproof.policy import CommittedEvidence  # noqa: PLC0415
    from test_mcp_server import _grant_replay_inputs  # noqa: PLC0415

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
    from openworkproof.signing import decode_and_verify_key_binding  # noqa: PLC0415

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


def test_rejection_bundle_verifies_offline(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
) -> None:
    from test_acceptance import _awaiting_case  # noqa: PLC0415

    case, context, composed, request_receipt = _awaiting_case(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        sidecar_receipt_factory,
        fixed_now,
        monkeypatch,
    )
    rejection = _sign_rejection(
        case, context, request_receipt, ephemeral_role_keys, fixed_now
    )
    committed = acceptance.reject_acceptance_transaction(
        case["ledger_path"],
        evidence_root=case["evidence_root"],
        context=context,
        rejection=rejection,
        public_keys=None,
        clock=lambda: fixed_now,
    )
    work_order = case["work_order"]
    report = acceptance._current_report(case["ledger_path"], work_order)
    effective_grants, grant_attempts, receipts, evidence_items, public_keys = (
        _offline_bundle(case, work_order)
    )
    verified = acceptance.verify_acceptance_bundle(
        work_order=work_order,
        report=report,
        effective_grants=effective_grants,
        grant_attempts=grant_attempts,
        receipts=receipts,
        committed_evidence=evidence_items,
        public_keys=public_keys,
        rejection=committed,
    )
    assert verified == committed
    assert verified.decision == "rejected"
    assert verified.reason_code == "BUSINESS_DECISION"


def test_rejection_bundle_requires_exactly_one_terminal_decision(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
) -> None:
    from test_acceptance import _awaiting_case  # noqa: PLC0415

    case, context, composed, request_receipt = _awaiting_case(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        sidecar_receipt_factory,
        fixed_now,
        monkeypatch,
    )
    rejection = _sign_rejection(
        case, context, request_receipt, ephemeral_role_keys, fixed_now
    )
    work_order = case["work_order"]
    report = acceptance._current_report(case["ledger_path"], work_order)
    effective_grants, grant_attempts, receipts, evidence_items, public_keys = (
        _offline_bundle(case, work_order)
    )
    with pytest.raises(
        acceptance.AcceptanceTransactionError, match="malformed"
    ):
        acceptance.verify_acceptance_bundle(
            work_order=work_order,
            report=report,
            effective_grants=effective_grants,
            grant_attempts=grant_attempts,
            receipts=receipts,
            committed_evidence=evidence_items,
            public_keys=public_keys,
            rejection=rejection,
            acceptance_receipt=rejection,  # type: ignore[arg-type]
        )


def test_rejection_bundle_tampering_fails_closed(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
) -> None:
    from test_acceptance import _awaiting_case  # noqa: PLC0415

    case, context, composed, request_receipt = _awaiting_case(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        sidecar_receipt_factory,
        fixed_now,
        monkeypatch,
    )
    rejection = _sign_rejection(
        case, context, request_receipt, ephemeral_role_keys, fixed_now
    )
    committed = acceptance.reject_acceptance_transaction(
        case["ledger_path"],
        evidence_root=case["evidence_root"],
        context=context,
        rejection=rejection,
        public_keys=None,
        clock=lambda: fixed_now,
    )
    work_order = case["work_order"]
    report = acceptance._current_report(case["ledger_path"], work_order)
    effective_grants, grant_attempts, receipts, evidence_items, public_keys = (
        _offline_bundle(case, work_order)
    )

    def verify_with(*, rejection_override=None, keys_override=None, ev_override=None):
        return acceptance.verify_acceptance_bundle(
            work_order=work_order,
            report=report,
            effective_grants=effective_grants,
            grant_attempts=grant_attempts,
            receipts=receipts,
            committed_evidence=(
                evidence_items if ev_override is None else ev_override
            ),
            public_keys=public_keys if keys_override is None else keys_override,
            rejection=(
                committed if rejection_override is None else rejection_override
            ),
        )

    # 1) Full-rebuild tamper of the rejection payload (reason flipped).
    raw = committed.model_dump(mode="json")
    raw["reason_code"] = "EVIDENCE_INSUFFICIENT"
    tampered = AcceptanceRejectionReceipt.model_validate(raw)
    with pytest.raises(acceptance.AcceptanceTransactionError):
        verify_with(rejection_override=tampered)

    # 2) Evidence-byte tamper fails closed.
    tampered_evidence = list(evidence_items)
    item = tampered_evidence[-1]
    tampered_evidence[-1] = type(item)(
        reference=item.reference,
        payload=item.payload + b"\ntampered",
    )
    with pytest.raises(acceptance.AcceptanceTransactionError):
        verify_with(ev_override=tuple(tampered_evidence))

    # 3) Public-key substitution fails closed.
    key_ids = list(public_keys)
    wrong = dict(public_keys)
    wrong[key_ids[0]] = wrong[key_ids[1]]
    with pytest.raises(acceptance.AcceptanceTransactionError):
        verify_with(keys_override=wrong)
