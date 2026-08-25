"""Build the deterministic test-only DeepSeek Harness delivery fixture.

This module deliberately reuses the repository's protocol fixtures.  It is a
developer preflight utility, not a customer case initializer and not evidence
of an external deployment.
"""

from __future__ import annotations

import hashlib
import os
from datetime import timedelta
from pathlib import Path

import rfc8785


def _current_context(case, now):
    from openworkproof import evidence, repo_tools
    from openworkproof.models import TestResultEvidence
    from openworkproof.policy import (
        AuthorizationLedgerPrefix,
        CommittedEvidence,
        derive_authorization_context,
    )
    from test_receipt_chain import _grant_replay_inputs

    receipts, grants, attempts = _grant_replay_inputs(
        case["ledger_path"], case["work_order"]
    )
    committed = []
    verified = []
    verifier_paths = {
        f"evidence/{artifact.path}"
        for artifact in case["work_order"].evidence_policy.artifacts
        if artifact.purpose in {"verifier_result", "verifier_independent_result"}
    }
    for receipt in receipts:
        for reference in receipt.evidence_refs:
            payload = (
                case["evidence_root"]
                / reference.path.removeprefix("evidence/")
            ).read_bytes()
            committed.append(CommittedEvidence(reference=reference, payload=payload))
            if reference.path in verifier_paths:
                verified.append(TestResultEvidence.model_validate_json(payload))
    git_dir = case["candidate"].git_dir
    worktree = case["candidate"].worktree
    head_commit = repo_tools._run_git_read_only(
        git_dir=git_dir,
        worktree=worktree,
        arguments=("rev-parse", "HEAD"),
    ).stdout.decode("ascii").strip()
    descriptor = os.open(worktree, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        manifest = repo_tools.scan_workspace_manifest(descriptor, head_commit)
    finally:
        os.close(descriptor)
    checkpoint = repo_tools.ReplayCheckpoint(
        files=(),
        head_commit=head_commit,
        workspace_manifest=manifest,
        workspace_manifest_digest=repo_tools.workspace_manifest_digest(manifest),
        verified_test_results=tuple(verified),
    )
    return derive_authorization_context(
        case["work_order"],
        AuthorizationLedgerPrefix(
            effective_grants=tuple(
                sorted(grants.values(), key=lambda item: item.grant_id)
            ),
            grant_attempts=tuple(
                sorted(attempts.values(), key=lambda item: item.digest)
            ),
            receipts=receipts,
        ),
        tuple(sorted(committed, key=lambda item: item.reference.path.encode())),
        checkpoint,
        now,
    )


def create_dsh_fixture(
    root: Path,
    *,
    signed_work_order,
    signed_subject_claim,
    evaluation_scope_payload_v03,
    verification_profile_v03,
    role_keys,
    now,
):
    """Close one real ledger from DSH patch through external acceptance."""

    from openworkproof import acceptance, evidence, repo_tools
    from openworkproof.binding import canonical_test_profile_digest
    from openworkproof.delivery_case import (
        DeliveryCaseError,
        export_delivery_case,
        initialize_delivery_case,
        verify_exported_delivery_case,
    )
    from openworkproof.dsh_case import DecisionTokenStore
    from openworkproof.dsh_execution import (
        DshApplyPatchInputV01,
        DshExecutionCaseV01,
        DshRunTestsInputV01,
        execute_dsh_patch,
        execute_dsh_tests,
    )
    from openworkproof.dsh_protocol import (
        DshExecutionIdentityV01,
        dsh_action_arguments_digest,
    )
    from openworkproof.dsh_verifier import (
        DshVerificationCaseV01,
        verify_dsh_code_change,
    )
    from openworkproof.mcp_server import execute_run_tests
    from openworkproof.models import (
        AgentRequest,
        ComposeProofArguments,
        request_arguments_digest,
    )
    from openworkproof.signing import sign_payload
    from test_acceptance import _four_dimension_work_order, _sign_draft
    from test_acceptance_decision_binding_v01 import (
        _install_v05_decision,
    )
    from test_apply_patch_transaction import _apply_patch_case, _src_app_patch
    from test_delivery_case_v01 import _populate_bundles, _write_sow
    from test_mcp_server import _FakeRunTestsExecutionDriver, _grant_id
    from test_receipt_chain import (
        _child_grant,
        _delegation_request,
        _issue_child,
    )

    selected = _four_dimension_work_order(signed_work_order, role_keys)
    protocol_root = root / "protocol"
    protocol_root.mkdir()
    base = _apply_patch_case(protocol_root, selected, role_keys, now)
    tokens = DecisionTokenStore(clock=lambda: now)
    runtime = DshExecutionCaseV01(
        case_id="c" * 64,
        ledger_path=base["ledger_path"],
        evidence_root=base["evidence_root"],
        context=base["context"],
        candidate_workspace=base["candidate"],
        sidecar_private_key=role_keys["Sidecar"][0],
        developer_private_key=role_keys["Developer"][0],
        decision_tokens=tokens,
    )
    patch_bytes = _src_app_patch()
    patch_execution = DshExecutionIdentityV01(
        session_id="dsh-e2e",
        call_id="patch-1",
        root_call_id="patch-1",
        tool_name="owp_apply_patch",
        arguments_digest=dsh_action_arguments_digest(
            {
                "patch_utf8": patch_bytes.decode("utf-8"),
                "target_paths": ["src/app.py"],
            }
        ),
    )
    patch_token = tokens.issue(
        patch_execution,
        expires_at=now + timedelta(seconds=30),
    )
    patch = execute_dsh_patch(
        runtime,
        DshApplyPatchInputV01.model_validate(
            {
                "schema_version": "openworkproof-dsh-apply-patch/0.1",
                "case_id": runtime.case_id,
                "execution": patch_execution.model_dump(mode="json"),
                "decision_token": patch_token.token,
                "patch_utf8": patch_bytes.decode("utf-8"),
                "target_paths": ["src/app.py"],
            }
        ),
        clock=lambda: now,
    )

    verifier = _child_grant(
        base["work_order"],
        base["root"],
        role_keys,
        label="dsh-e2e:verifier",
        subject_role="Verifier",
        updates={"quota": {"tool_calls": 1, "repair_rounds": 0}},
    )
    verifier_issuance = _issue_child(
        base["ledger_path"],
        verifier,
        _delegation_request(
            base["work_order"],
            base["root"],
            verifier,
            role_keys,
            actor_role="Manager",
            nonce=_grant_id("dsh-e2e:verifier-request"),
        ),
        role_keys,
        now,
    )
    base.update({"verifier": verifier, "verifier_issuance": verifier_issuance})
    before_tests = _current_context(base, now)
    profile = next(
        item
        for item in base["work_order"].test_profiles
        if item.test_mode == "verifier"
    )
    profile_digest = canonical_test_profile_digest(profile)
    driver = _FakeRunTestsExecutionDriver(actual_exit_code=0)

    def external_verifier(arguments, facts, execution, transaction_time):
        binding = role_keys["Verifier"][1]
        request = AgentRequest.model_validate(
            sign_payload(
                "agent-request",
                {
                    "claim_type": "agent-request",
                    "work_order_digest": base["work_order"].digest,
                    "grant_id": verifier.grant_id,
                    "actor_id": binding["subject_id"],
                    "actor_key_id": binding["key_id"],
                    "tool_name": "owp.run_tests",
                    "arguments_digest": request_arguments_digest(
                        "owp.run_tests", arguments
                    ),
                    "nonce": hashlib.sha256(
                        rfc8785.dumps(
                            {
                                "domain": "openworkproof/dsh-e2e-test-request/v0.1",
                                "execution": execution.model_dump(mode="json"),
                            }
                        )
                    ).hexdigest(),
                    "requested_at": transaction_time.strftime(
                        "%Y-%m-%dT%H:%M:%SZ"
                    ),
                    "authentication_method": "agent_signature",
                    "model_id": "dsh-external-verifier",
                    "model_version": "0.1",
                    "prompt_template_digest": "a" * 64,
                    "context_source_digest": "b" * 64,
                },
                role_keys["Verifier"][0],
            )
        )
        checkpoint = before_tests.replay_checkpoint
        snapshot_request = repo_tools.CandidateExecutionSnapshotRequest(
            runtime_root=base["candidate"].runtime_root,
            workspace_id=base["candidate"].workspace_id,
            source_artifact_sha256=base["candidate"].source_artifact_sha256,
            expected_head_commit=checkpoint.head_commit,
            expected_workspace_manifest_digest=checkpoint.workspace_manifest_digest,
        )
        repo_tools.prepare_candidate_execution_snapshot(snapshot_request)
        return execute_run_tests(
            base["ledger_path"],
            evidence_root=base["evidence_root"],
            context=before_tests,
            request=request,
            request_arguments=arguments,
            execution_facts=facts,
            candidate_snapshot_request=snapshot_request,
            sidecar_private_key=role_keys["Sidecar"][0],
            execution_driver=driver,
            clock=lambda: transaction_time,
        )

    test_runtime = DshExecutionCaseV01(
        case_id=runtime.case_id,
        ledger_path=base["ledger_path"],
        evidence_root=base["evidence_root"],
        context=before_tests,
        candidate_workspace=base["candidate"],
        sidecar_private_key=role_keys["Sidecar"][0],
        developer_private_key=role_keys["Developer"][0],
        decision_tokens=tokens,
        test_profile_digest=profile_digest,
        run_tests_executor=external_verifier,
    )
    test_execution = DshExecutionIdentityV01(
        session_id="dsh-e2e",
        call_id="tests-1",
        root_call_id="patch-1",
        tool_name="owp_run_tests",
        arguments_digest=dsh_action_arguments_digest(
            {"test_profile_digest": profile_digest}
        ),
    )
    test_token = tokens.issue(
        test_execution,
        expires_at=now + timedelta(seconds=30),
    )
    test_receipt = execute_dsh_tests(
        test_runtime,
        DshRunTestsInputV01.model_validate(
            {
                "schema_version": "openworkproof-dsh-run-tests/0.1",
                "case_id": runtime.case_id,
                "execution": test_execution.model_dump(mode="json"),
                "decision_token": test_token.token,
                "test_profile_digest": profile_digest,
            }
        ),
        clock=lambda: now,
    )

    context = _current_context(base, now)
    assert context.current_state == "locally_verified"
    base["context"] = context
    compose_arguments = ComposeProofArguments(
        expected_state_version=evidence._derive_protocol_transaction_version(
            action_receipts=context.ledger_prefix.receipts,
            acceptance_receipts=(),
        ),
        previous_report_digest=None,
    )
    manager = role_keys["Manager"][1]
    compose_request = AgentRequest.model_validate(
        sign_payload(
            "agent-request",
            {
                "claim_type": "agent-request",
                "work_order_digest": base["work_order"].digest,
                "grant_id": base["root"].grant_id,
                "actor_id": manager["subject_id"],
                "actor_key_id": manager["key_id"],
                "tool_name": "owp.compose_proof",
                "arguments_digest": request_arguments_digest(
                    "owp.compose_proof", compose_arguments
                ),
                "nonce": _grant_id("dsh-e2e:compose"),
                "requested_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "authentication_method": "agent_signature",
                "model_id": "manager",
                "model_version": "1",
                "prompt_template_digest": "a" * 64,
                "context_source_digest": "b" * 64,
            },
            role_keys["Manager"][0],
        )
    )
    composed = acceptance.compose_proof_transaction(
        base["ledger_path"],
        evidence_root=base["evidence_root"],
        context=context,
        request=compose_request,
        sidecar_private_key=role_keys["Sidecar"][0],
        clock=lambda: now,
    )
    assert composed.report.verifier_conclusion == "proof_ready"

    proof_ready = _current_context(base, now)
    verification_case = _install_v05_decision(
        case=base,
        context=proof_ready,
        signed_subject_claim=signed_subject_claim,
        evaluation_scope_payload_v03=evaluation_scope_payload_v03,
        verification_profile_v03=verification_profile_v03,
        ephemeral_role_keys=role_keys,
    )
    flow_now = now + timedelta(minutes=20)
    proof_ready = _current_context(base, flow_now)
    scope = {
        "work_order_digest": base["work_order"].digest,
        "operation": "submit_final_acceptance",
        "composition_report_digest": acceptance.composition_report_digest(
            composed.report
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
    expires_at = now.replace(minute=30, second=0)
    acceptance_arguments = {
        "request_kind": "final_acceptance",
        "target_action_digest": target_action_digest,
        "required_role": "Acceptor",
        "requested_scope": scope,
        "expires_at": expires_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    acceptance_request = AgentRequest.model_validate(
        sign_payload(
            "agent-request",
            {
                "claim_type": "agent-request",
                "work_order_digest": base["work_order"].digest,
                "grant_id": base["root"].grant_id,
                "actor_id": manager["subject_id"],
                "actor_key_id": manager["key_id"],
                "tool_name": "owp.request_acceptance",
                "arguments_digest": request_arguments_digest(
                    "owp.request_acceptance", acceptance_arguments
                ),
                "nonce": _grant_id("dsh-e2e:acceptance-request"),
                "requested_at": flow_now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "authentication_method": "agent_signature",
                "model_id": "manager",
                "model_version": "1",
                "prompt_template_digest": "a" * 64,
                "context_source_digest": "b" * 64,
            },
            role_keys["Manager"][0],
        )
    )
    requested = acceptance.request_acceptance_transaction(
        base["ledger_path"],
        evidence_root=base["evidence_root"],
        context=proof_ready,
        request=acceptance_request,
        sidecar_private_key=role_keys["Sidecar"][0],
        expires_at=expires_at,
        clock=lambda: flow_now,
    )
    awaiting = _current_context(base, flow_now)
    acceptance_draft = acceptance.prepare_acceptance(
        base["ledger_path"],
        evidence_root=base["evidence_root"],
        context=awaiting,
        clock=lambda: flow_now,
    )
    acceptance_draft_payload = dict(acceptance_draft.payload)
    terminal = _sign_draft(acceptance_draft, role_keys)
    acceptance.commit_acceptance(
        base["ledger_path"],
        evidence_root=base["evidence_root"],
        context=awaiting,
        acceptance=terminal,
        public_keys=None,
        clock=lambda: flow_now,
    )
    binding_now = flow_now + timedelta(minutes=1)

    verification = verify_dsh_code_change(
        DshVerificationCaseV01(
            case_id=runtime.case_id,
            repository_root=base["candidate"].worktree,
            source_revision=base["work_order"].source_commit,
            allowed_path_roots=("src",),
            denied_path_roots=(".git",),
            test_profile_digest=profile_digest,
            ledger_path=base["ledger_path"],
            evidence_root=base["evidence_root"],
            verification_runner=lambda repository: (
                0
                if (repository / "src" / "app.py").read_bytes() == b"patched\n"
                else 1
            ),
            git_dir=base["candidate"].git_dir,
        ),
        clock=lambda: binding_now,
    )

    delivery_case = root / "delivery-case"
    initialize_delivery_case(delivery_case, case_id=runtime.case_id, now=flow_now)
    delivery_data = {
        **base,
        "decision": verification_case["decision"],
        "verification_case": verification_case,
        "report": composed.report,
        "request": requested,
        "terminal": terminal,
        "keys": role_keys,
        "binding_now": binding_now,
    }
    _write_sow(delivery_case, evidenced=True)
    _populate_bundles(delivery_case, delivery_data)
    exported_path = root / "exported"
    export_dsh = export_delivery_case(delivery_case, exported_path)
    accepted = verify_exported_delivery_case(exported_path)
    assert export_dsh == accepted

    return {
        "patch": patch,
        "test_receipt": test_receipt,
        "verification": verification,
        "acceptance_draft_payload": acceptance_draft_payload,
        "accepted": accepted,
        "exported_path": exported_path,
        "delivery_error": DeliveryCaseError,
    }
