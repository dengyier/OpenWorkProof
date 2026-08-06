"""Acceptor rejection path coverage.

Reuses the test_acceptance fixtures so each test starts from a canonical
awaiting_human chain (request_acceptance_transaction committed).
"""

from __future__ import annotations

import hashlib

import pytest

import rfc8785

import openworkproof.acceptance as acceptance
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
        "causal_graph_root": causal_graph_root(prefix),
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
