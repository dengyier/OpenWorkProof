"""Export offline-replayable evidence bundles for Rich #4196 and Dify #33013.

This module runs the same nine-step five-role workflow as
``test_delivery_m2.py`` (Rich #4196) and ``test_delivery_m3_dify.py``
(Dify #33013), then exports every artifact needed for a third party to
re-verify the chain offline — without any live ledger, network access,
or trusting the runtime.

Run::

    python -m pytest tests/test_export_evidence_bundles.py -s -v

Output is written to ``tests/evidence-bundles/``.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
import rfc8785

import openworkproof.acceptance as acceptance
from openworkproof.models import (
    AcceptanceReceipt,
    ActionReceipt,
    CapabilityGrant,
    WorkOrder,
)
from openworkproof.signing import decode_and_verify_key_binding
from openworkproof.policy import CommittedEvidence

# Re-use every helper from the delivery test suites — no duplication.
from test_delivery_m2 import (
    WRAP_CANDIDATE,
    RICH_PINNED_COMMIT,
    _m2_through_proof_ready,
    _m2_through_repo_read,
    _m2_append_active_patch,
    _m2_through_patch,
    _m2_case,
    _AcceptorProcess,
    _free_port,
    _key_hex,
    _refresh_context,
    _verifier_run_tests_request,
)
from test_delivery_m3_dify import (
    DIFY_QCN_CANDIDATE,
    DIFY_FIX_PATCH,
    DIFY_PINNED_COMMIT,
    DIFY_FIX_COMMIT,
    CANDIDATE_PATH as DIFY_CANDIDATE_PATH,
    _m3_through_proof_ready,
)
from test_mcp_server import (
    _current_run_tests_context,
    _execute_run_tests_case,
    _FakeRunTestsExecutionDriver,
    _grant_replay_inputs,
    _run_tests_snapshot_request,
)
from test_independent_recomposition import (
    _execute_independent_run,
    _recompose_request,
    _signed_compose_request,
)

BUNDLE_DIR = Path(__file__).parent / "evidence-bundles"


# ---------------------------------------------------------------------------
# Export helpers
# ---------------------------------------------------------------------------

def _export_bundle(
    case: dict[str, Any],
    acceptance_receipt: AcceptanceReceipt,
    output_path: Path,
    *,
    bug_id: str,
    bug_url: str,
    pinned_commit: str,
    fix_commit: str | None,
    candidate_source: str,
    fix_description: str,
) -> None:
    """Export a complete offline-replayable evidence bundle as JSON."""
    work_order: WorkOrder = case["work_order"]
    ledger_path: Path = case["ledger_path"]
    evidence_root: Path = case["evidence_root"]

    # --- Extract all artifacts from the ledger ---
    receipts, grants, attempts = _grant_replay_inputs(ledger_path, work_order)

    # Extract composition reports
    connection = sqlite3.connect(ledger_path)
    try:
        report_rows = connection.execute(
            "SELECT report_json FROM composition_reports "
            "ORDER BY source_state_version"
        ).fetchall()
    finally:
        connection.close()
    reports = tuple(
        acceptance.CompositionReport.model_validate_json(row[0])
        for row in report_rows
    )

    # Extract committed evidence payloads
    committed_evidence = []
    for receipt in receipts:
        for reference in receipt.evidence_refs:
            payload = (
                evidence_root / reference.path.removeprefix("evidence/")
            ).read_bytes()
            committed_evidence.append(
                CommittedEvidence(reference=reference, payload=payload)
            )
    committed_evidence.sort(key=lambda item: item.reference.path.encode())

    # Extract public keys from WorkOrder key bindings
    public_keys_raw = {}
    for binding in work_order.key_bindings:
        public_keys_raw[binding.key_id] = decode_and_verify_key_binding(binding)

    # Final report
    final_report = reports[-1]

    # --- Build the bundle ---
    bundle: dict[str, Any] = {
        "schema_version": "openworkproof/evidence-bundle/v0.1",
        "metadata": {
            "bug_id": bug_id,
            "bug_url": bug_url,
            "pinned_commit": pinned_commit,
            "fix_commit": fix_commit,
            "fix_description": fix_description,
            "candidate_source_digest": hashlib.sha256(
                candidate_source.encode("utf-8")
            ).hexdigest(),
            "exported_at": datetime.now(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            "protocol_version": "v0.1",
            "signature_algorithm": "Ed25519",
            "canonicalization": "RFC 8785 JCS",
            "digest_algorithm": "SHA-256",
        },
        "work_order": work_order.model_dump(mode="json"),
        "public_keys": {
            key_id: {
                "role": binding.role,
                "subject_id": binding.subject_id,
                "key_id": binding.key_id,
                "public_key_b64url": binding.public_key_b64url,
            }
            for key_id, binding in zip(
                public_keys_raw.keys(), work_order.key_bindings
            )
        },
        "effective_grants": [
            grant.model_dump(mode="json")
            for grant in sorted(grants.values(), key=lambda g: g.grant_id)
        ],
        "grant_attempts": [
            attempt.model_dump(mode="json")
            for attempt in sorted(attempts.values(), key=lambda a: a.digest)
        ],
        "receipts": [receipt.model_dump(mode="json") for receipt in receipts],
        "composition_reports": [
            report.model_dump(mode="json") for report in reports
        ],
        "acceptance_receipt": acceptance_receipt.model_dump(mode="json"),
        "committed_evidence": [
            {
                "reference": item.reference.model_dump(mode="json"),
                "payload_b64": __import__("base64").b64encode(
                    item.payload
                ).decode("ascii"),
                "payload_sha256": hashlib.sha256(item.payload).hexdigest(),
            }
            for item in committed_evidence
        ],
        "verification_steps": [
            {
                "step": 1,
                "description": "Verify WorkOrder signature",
                "method": "verify_payload('work-order', work_order, public_keys[work_order.signer_key_id])",
            },
            {
                "step": 2,
                "description": "Verify all CapabilityGrant signatures",
                "method": "For each grant: verify_payload('capability-grant', grant, public_keys[grant.issuer_key_id])",
            },
            {
                "step": 3,
                "description": "Verify all ActionReceipt signatures",
                "method": "For each receipt: verify_payload('action-receipt', receipt, public_keys[receipt.signer_key_id])",
            },
            {
                "step": 4,
                "description": "Verify committed evidence hashes",
                "method": "For each evidence payload: SHA-256(payload) must match reference.sha256",
            },
            {
                "step": 5,
                "description": "Verify composition report chain",
                "method": "verify_composition_bundle(work_order, grants, attempts, receipts, evidence, reports, public_keys)",
            },
            {
                "step": 6,
                "description": "Verify acceptance receipt binding",
                "method": "validate_acceptance_bindings(work_order, final_report, receipts, acceptance_receipt)",
            },
            {
                "step": 7,
                "description": "Full offline verification",
                "method": "verify_acceptance_bundle(work_order, report, grants, attempts, receipts, evidence, acceptance_receipt, public_keys, reports)",
            },
        ],
    }

    # --- Verify the bundle offline before writing ---
    verified = acceptance.verify_acceptance_bundle(
        work_order=work_order,
        report=final_report,
        effective_grants=tuple(
            sorted(grants.values(), key=lambda item: item.grant_id)
        ),
        grant_attempts=tuple(
            sorted(attempts.values(), key=lambda item: item.digest)
        ),
        receipts=receipts,
        committed_evidence=tuple(committed_evidence),
        acceptance_receipt=acceptance_receipt,
        public_keys=public_keys_raw,
        reports=reports,
    )
    assert verified.acceptance_id == acceptance_receipt.acceptance_id, (
        "Bundle failed offline verification!"
    )

    # --- Write bundle ---
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(bundle, indent=2, ensure_ascii=False, default=str),
        encoding="utf-8",
    )
    print(f"\n✅ Evidence bundle exported: {output_path}")
    print(f"   Bug: {bug_id}")
    print(f"   Receipts: {len(receipts)}")
    print(f"   Grants: {len(grants)}")
    print(f"   Composition reports: {len(reports)}")
    print(f"   Committed evidence files: {len(committed_evidence)}")
    print(f"   Offline verification: PASSED")


# ---------------------------------------------------------------------------
# Export: Rich #4196
# ---------------------------------------------------------------------------

def test_export_rich_4196_bundle(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
) -> None:
    """Run the full Rich #4196 nine-step chain and export the evidence bundle."""
    from openworkproof import repo_tools

    # Stub the execution snapshot (same as test_delivery_m2)
    def prepare(request):
        from openworkproof.repo_tools import (
            CandidateExecutionSnapshot,
            ExecutionSnapshotPlan,
        )
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

    # Steps 1-7: running → repo_read → apply_patch → run_tests → compose →
    # independent Verifier → recompose (proof_ready)
    case = _m2_through_proof_ready(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        sidecar_receipt_factory,
        fixed_now,
    )
    proof_ready = _current_run_tests_context(case, fixed_now)
    assert proof_ready.current_state == "proof_ready"
    second = case["second_report"]

    # Step 8: request_acceptance → prepare draft → external Acceptor signs
    manager_binding = ephemeral_role_keys["Manager"][1]
    scope = {
        "work_order_digest": case["work_order"].digest,
        "operation": "submit_final_acceptance",
        "composition_report_digest": acceptance.composition_report_digest(
            second.report
        ),
    }
    target_action_digest = hashlib.sha256(
        rfc8785.dumps(
            {
                "domain": "openworkproof/final-acceptance-action/v0.1",
                "requested_scope": scope,
            }
        )
    ).hexdigest()
    arguments = {
        "request_kind": "final_acceptance",
        "target_action_digest": target_action_digest,
        "required_role": "Acceptor",
        "requested_scope": scope,
        "expires_at": "2026-01-01T00:30:00Z",
    }
    from openworkproof.models import AgentRequest, request_arguments_digest
    from openworkproof.signing import sign_payload

    request_receipt = acceptance.request_acceptance_transaction(
        case["ledger_path"],
        evidence_root=case["evidence_root"],
        context=proof_ready,
        request=AgentRequest.model_validate(
            sign_payload(
                "agent-request",
                {
                    "claim_type": "agent-request",
                    "work_order_digest": case["work_order"].digest,
                    "grant_id": case["root"].grant_id,
                    "actor_id": manager_binding["subject_id"],
                    "actor_key_id": manager_binding["key_id"],
                    "tool_name": "owp.request_acceptance",
                    "arguments_digest": request_arguments_digest(
                        "owp.request_acceptance", arguments
                    ),
                    "nonce": "e2" * 32,
                    "requested_at": fixed_now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "authentication_method": "agent_signature",
                    "model_id": "model",
                    "model_version": "1",
                    "prompt_template_digest": "a" * 64,
                    "context_source_digest": "b" * 64,
                },
                ephemeral_role_keys["Manager"][0],
            )
        ),
        sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
        expires_at=datetime(2026, 1, 1, 0, 30, 0, tzinfo=timezone.utc),
        clock=lambda: fixed_now,
    )
    awaiting = _current_run_tests_context(case, fixed_now)
    assert awaiting.current_state == "awaiting_human"

    draft = acceptance.prepare_acceptance(
        case["ledger_path"],
        evidence_root=case["evidence_root"],
        context=awaiting,
        clock=lambda: fixed_now,
    )

    acceptor_proc = _AcceptorProcess(
        _key_hex(ephemeral_role_keys["Acceptor"][0]),
        port=_free_port(),
    )
    try:
        from openworkproof.external_acceptor import ExternalAcceptorClient
        signed_acceptance = ExternalAcceptorClient(
            port=acceptor_proc.port, timeout=5.0
        ).sign_acceptance(draft)
    finally:
        acceptor_proc.stop()

    committed = acceptance.commit_acceptance(
        case["ledger_path"],
        evidence_root=case["evidence_root"],
        context=awaiting,
        acceptance=signed_acceptance,
        public_keys=None,
        clock=lambda: fixed_now,
    )
    terminal = _current_run_tests_context(case, fixed_now)
    assert terminal.current_state == "accepted"

    # Step 9: Export the complete evidence bundle
    _export_bundle(
        case=case,
        acceptance_receipt=signed_acceptance,
        output_path=BUNDLE_DIR / "rich-4196-evidence-bundle.json",
        bug_id="Textualize/Rich #4196",
        bug_url="https://github.com/Textualize/rich/issues/4196",
        pinned_commit=RICH_PINNED_COMMIT,
        fix_commit=None,
        candidate_source=WRAP_CANDIDATE,
        fix_description=(
            "NBSP (U+00A0) line breaking bug: re_word regex in "
            "rich/_wrap.py uses \\s which matches U+00A0 in Unicode mode, "
            "causing NBSP to be treated as a line break point."
        ),
    )


# ---------------------------------------------------------------------------
# Export: Dify #33013
# ---------------------------------------------------------------------------

def test_export_dify_33013_bundle(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
) -> None:
    """Run the full Dify #33013 nine-step chain and export the evidence bundle."""
    from openworkproof import repo_tools

    # Stub the execution snapshot (same as test_delivery_m3_dify)
    def prepare(request):
        from openworkproof.repo_tools import (
            CandidateExecutionSnapshot,
            ExecutionSnapshotPlan,
        )
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

    # Steps 1-7: same structure as M2 but with Dify candidate source
    case = _m3_through_proof_ready(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        sidecar_receipt_factory,
        fixed_now,
    )
    proof_ready = _current_run_tests_context(case, fixed_now)
    assert proof_ready.current_state == "proof_ready"
    second = case["second_report"]

    # Step 8: request_acceptance → prepare draft → external Acceptor signs
    manager_binding = ephemeral_role_keys["Manager"][1]
    scope = {
        "work_order_digest": case["work_order"].digest,
        "operation": "submit_final_acceptance",
        "composition_report_digest": acceptance.composition_report_digest(
            second.report
        ),
    }
    target_action_digest = hashlib.sha256(
        rfc8785.dumps(
            {
                "domain": "openworkproof/final-acceptance-action/v0.1",
                "requested_scope": scope,
            }
        )
    ).hexdigest()
    arguments = {
        "request_kind": "final_acceptance",
        "target_action_digest": target_action_digest,
        "required_role": "Acceptor",
        "requested_scope": scope,
        "expires_at": "2026-01-01T00:30:00Z",
    }
    from openworkproof.models import AgentRequest, request_arguments_digest
    from openworkproof.signing import sign_payload

    request_receipt = acceptance.request_acceptance_transaction(
        case["ledger_path"],
        evidence_root=case["evidence_root"],
        context=proof_ready,
        request=AgentRequest.model_validate(
            sign_payload(
                "agent-request",
                {
                    "claim_type": "agent-request",
                    "work_order_digest": case["work_order"].digest,
                    "grant_id": case["root"].grant_id,
                    "actor_id": manager_binding["subject_id"],
                    "actor_key_id": manager_binding["key_id"],
                    "tool_name": "owp.request_acceptance",
                    "arguments_digest": request_arguments_digest(
                        "owp.request_acceptance", arguments
                    ),
                    "nonce": "f3" * 32,
                    "requested_at": fixed_now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "authentication_method": "agent_signature",
                    "model_id": "model",
                    "model_version": "1",
                    "prompt_template_digest": "a" * 64,
                    "context_source_digest": "b" * 64,
                },
                ephemeral_role_keys["Manager"][0],
            )
        ),
        sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
        expires_at=datetime(2026, 1, 1, 0, 30, 0, tzinfo=timezone.utc),
        clock=lambda: fixed_now,
    )
    awaiting = _current_run_tests_context(case, fixed_now)
    assert awaiting.current_state == "awaiting_human"

    draft = acceptance.prepare_acceptance(
        case["ledger_path"],
        evidence_root=case["evidence_root"],
        context=awaiting,
        clock=lambda: fixed_now,
    )

    acceptor_proc = _AcceptorProcess(
        _key_hex(ephemeral_role_keys["Acceptor"][0]),
        port=_free_port(),
    )
    try:
        from openworkproof.external_acceptor import ExternalAcceptorClient
        signed_acceptance = ExternalAcceptorClient(
            port=acceptor_proc.port, timeout=5.0
        ).sign_acceptance(draft)
    finally:
        acceptor_proc.stop()

    committed = acceptance.commit_acceptance(
        case["ledger_path"],
        evidence_root=case["evidence_root"],
        context=awaiting,
        acceptance=signed_acceptance,
        public_keys=None,
        clock=lambda: fixed_now,
    )
    terminal = _current_run_tests_context(case, fixed_now)
    assert terminal.current_state == "accepted"

    # Step 9: Export the complete evidence bundle
    _export_bundle(
        case=case,
        acceptance_receipt=signed_acceptance,
        output_path=BUNDLE_DIR / "dify-33013-evidence-bundle.json",
        bug_id="langgenius/dify #33013",
        bug_url="https://github.com/langgenius/dify/issues/33013",
        pinned_commit=DIFY_PINNED_COMMIT,
        fix_commit=DIFY_FIX_COMMIT,
        candidate_source=DIFY_QCN_CANDIDATE,
        fix_description=(
            "TypeError: LLMNode.invoke_llm() got an unexpected keyword "
            "argument 'structured_output_enabled'. Dify v1.14.0-rc1 "
            "refactored invoke_llm's signature (replaced "
            "structured_output_enabled/structured_output with "
            "structured_output_schema) but QuestionClassifierNode's caller "
            "was not updated. Fix: PR #32902, commit 3a04aef82b38."
        ),
    )
