"""Trusted handler coordination tests for the first Task 13 slice."""

from __future__ import annotations

from datetime import datetime
import hashlib
import json
from pathlib import Path

import pytest
import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

import openworkproof.evidence as evidence
from openworkproof.mcp_server import (
    HandlerCoordinationError,
    ToolCallDenied,
    execute_run_tests,
)
from openworkproof.models import (
    AgentRequest,
    CapabilityGrant,
    RunTestsArguments,
    ToolCallReceipt,
    WorkOrder,
    request_arguments_digest,
)
from openworkproof.policy import (
    AuthorizationLedgerPrefix,
    CommittedEvidence,
    ProspectiveExecutionFacts,
    derive_authorization_context,
)
from openworkproof.repo_tools import (
    ReplayCheckpoint,
    ResolutionManifest,
    ResolutionManifestEntry,
    build_workspace_manifest,
    resolution_manifest_digest,
    workspace_manifest_digest,
)
from openworkproof.signing import sign_payload

from test_receipt_chain import (
    _activate_ledger_root,
    _append_action_receipt,
    _child_grant,
    _delegation_request,
    _grant_id,
    _grant_replay_inputs,
    _issue_child,
    _jcs_digest,
    _linked_tool_receipt,
    _resigned_work_order,
    _work_order_with_pr_chain_predicates,
)


def _resigned_root(
    work_order: WorkOrder,
    maintainer_key: Ed25519PrivateKey,
) -> CapabilityGrant:
    raw = work_order.root_grant_template.model_dump(mode="json")
    raw["work_order_digest"] = work_order.digest
    return CapabilityGrant.model_validate(
        sign_payload("capability-grant", raw, maintainer_key)
    )


def _append_active_patch(
    *,
    ledger_path: Path,
    evidence_root: Path,
    work_order: WorkOrder,
    developer: CapabilityGrant,
    developer_issuance,
    role_keys,
    sidecar_receipt_factory,
    now: datetime,
) -> tuple[ToolCallReceipt, ReplayCheckpoint, tuple[CommittedEvidence, ...]]:
    patch_bytes = b"0123456789"
    patch_digest = hashlib.sha256(patch_bytes).hexdigest()
    candidate_commit = "2" * 40
    source_manifest = build_workspace_manifest(work_order.source_commit, ())
    candidate_manifest = build_workspace_manifest(candidate_commit, ())
    candidate_manifest_digest = workspace_manifest_digest(candidate_manifest)
    result = {
        "schema_version": "openworkproof-patch-result/0.1",
        "parent_commit": work_order.source_commit,
        "parent_manifest_digest": workspace_manifest_digest(source_manifest),
        "candidate_commit": candidate_commit,
        "workspace_manifest_digest": candidate_manifest_digest,
        "patch_digest": patch_digest,
        "patch_size_bytes": len(patch_bytes),
        "replay_profile_digest": work_order.replay_profile_digest,
    }
    result_bytes = rfc8785.dumps(result)
    result_digest = hashlib.sha256(result_bytes).hexdigest()
    receipt = _linked_tool_receipt(
        tool_name="owp.apply_patch",
        state_before="running",
        state_after="running",
        sequence=developer_issuance.sequence + 1,
        previous_receipt=developer_issuance,
        root=developer,
        signed_work_order=work_order,
        sidecar_receipt_factory=sidecar_receipt_factory,
        role_keys=role_keys,
        label="handler-loop:patch",
        actor_role="Developer",
        remaining_after=1,
        occurred_at="2026-01-01T00:00:05Z",
    )
    raw = receipt.model_dump(mode="json")
    arguments = {
        "target_paths": ["src/x"],
        "patch_digest": patch_digest,
        "patch_size_bytes": len(patch_bytes),
    }
    manifest = ResolutionManifest(
        schema_version="openworkproof-resolution-manifest/0.1",
        workspace_manifest_digest=result["parent_manifest_digest"],
        requested_paths=("src/x",),
        resolved_entries=(
            ResolutionManifestEntry(
                requested_path="src/x",
                resolved_relative_path="src/x",
            ),
        ),
    )
    raw.update(
        {
            "request_arguments": arguments,
            "arguments_digest": request_arguments_digest(
                "owp.apply_patch", arguments
            ),
            "output_digest": result_digest,
            "evidence_refs": [
                {
                    "path": "evidence/patch-input/01.diff",
                    "sha256": patch_digest,
                    "media_type": "text/x-diff",
                    "size_bytes": len(patch_bytes),
                },
                {
                    "path": "evidence/patch-result/01.json",
                    "sha256": result_digest,
                    "media_type": "application/json",
                    "size_bytes": len(result_bytes),
                },
            ],
        }
    )
    for predicate in raw["predicate_results"]:
        if predicate["name"] == "path_allowed":
            predicate["input"]["resolution_manifest_digest"] = (
                resolution_manifest_digest(manifest)
            )
        elif predicate["name"] == "quota_remaining":
            predicate["input"].update(
                {
                    "grant_id": developer.grant_id,
                    "grant_remaining_before": 2,
                    "ledger_prefix_digest": developer_issuance.digest,
                }
            )
        else:
            continue
        predicate["input_digest"] = _jcs_digest(
            {
                "domain": "openworkproof/predicate-input/v0.1",
                "predicate_id": predicate["predicate_id"],
                "input": predicate["input"],
            }
        )
    claim = raw["nested_claim"]
    claim["arguments_digest"] = raw["arguments_digest"]
    claim = sign_payload("agent-request", claim, role_keys["Developer"][0])
    raw["nested_claim"] = claim
    raw["nested_claim_digest"] = claim["digest"]
    receipt = evidence.ACTION_RECEIPT_ADAPTER.validate_python(
        sign_payload("action-receipt", raw, role_keys["Sidecar"][0])
    )
    payloads = {
        receipt.evidence_refs[0].path: patch_bytes,
        receipt.evidence_refs[1].path: result_bytes,
    }
    evidence.complete_receipt_publication(
        ledger_path,
        evidence_root=evidence_root,
        receipt=receipt,
        payloads=payloads,
        clock=lambda: now,
        trusted_resolution_manifest=manifest,
    )
    checkpoint = ReplayCheckpoint(
        files=(),
        head_commit=candidate_commit,
        workspace_manifest=candidate_manifest,
        workspace_manifest_digest=candidate_manifest_digest,
        verified_test_results=(),
    )
    committed = tuple(
        CommittedEvidence(
            reference=reference,
            payload=payloads[reference.path],
        )
        for reference in receipt.evidence_refs
    )
    return receipt, checkpoint, committed


def _run_tests_case(
    *,
    tmp_path: Path,
    signed_work_order: WorkOrder,
    role_keys,
    sidecar_receipt_factory,
    now: datetime,
):
    work_order = _work_order_with_pr_chain_predicates(
        signed_work_order,
        role_keys["Maintainer"][0],
    )
    root = _resigned_root(work_order, role_keys["Maintainer"][0])
    ledger_path = tmp_path / "handler-loop.sqlite3"
    evidence_root = tmp_path / "handler-loop-evidence"
    evidence_root.mkdir()
    _activate_ledger_root(ledger_path, work_order, root, role_keys, now)
    verifier = _child_grant(
        work_order,
        root,
        role_keys,
        label="handler-loop:verifier",
        subject_role="Verifier",
        updates={"quota": {"tool_calls": 1, "repair_rounds": 0}},
    )
    verifier_issuance = _issue_child(
        ledger_path,
        verifier,
        _delegation_request(
            work_order,
            root,
            verifier,
            role_keys,
            actor_role="Manager",
            nonce=_grant_id("handler-loop:verifier-request"),
        ),
        role_keys,
        now,
    )
    developer = _child_grant(
        work_order,
        root,
        role_keys,
        label="handler-loop:developer",
    )
    developer_issuance = _issue_child(
        ledger_path,
        developer,
        _delegation_request(
            work_order,
            root,
            developer,
            role_keys,
            actor_role="Manager",
            nonce=_grant_id("handler-loop:developer-request"),
        ),
        role_keys,
        now,
    )
    patch, checkpoint, committed = _append_active_patch(
        ledger_path=ledger_path,
        evidence_root=evidence_root,
        work_order=work_order,
        developer=developer,
        developer_issuance=developer_issuance,
        role_keys=role_keys,
        sidecar_receipt_factory=sidecar_receipt_factory,
        now=now,
    )
    receipts, grants, attempts = _grant_replay_inputs(
        ledger_path, work_order
    )
    context = derive_authorization_context(
        work_order,
        AuthorizationLedgerPrefix(
            effective_grants=tuple(
                sorted(grants.values(), key=lambda item: item.grant_id)
            ),
            grant_attempts=tuple(
                sorted(attempts.values(), key=lambda item: item.digest)
            ),
            receipts=receipts,
        ),
        committed,
        checkpoint,
        now,
    )
    profile = next(
        item for item in work_order.test_profiles if item.test_mode == "verifier"
    )
    arguments = RunTestsArguments(
        test_mode="verifier",
        command_digest=profile.command_digest,
        source_commit=work_order.source_commit,
        candidate_commit=checkpoint.head_commit,
        workspace_manifest_digest=checkpoint.workspace_manifest_digest,
        container_image_digest=profile.container_image_digest,
        fixed_test_source_digest=profile.fixed_test_source_digest,
    )
    binding = role_keys["Verifier"][1]
    request = AgentRequest.model_validate(
        sign_payload(
            "agent-request",
            {
                "claim_type": "agent-request",
                "work_order_digest": work_order.digest,
                "grant_id": verifier.grant_id,
                "actor_id": binding["subject_id"],
                "actor_key_id": binding["key_id"],
                "tool_name": "owp.run_tests",
                "arguments_digest": request_arguments_digest(
                    "owp.run_tests", arguments
                ),
                "nonce": _grant_id("handler-loop:test-request"),
                "requested_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "authentication_method": "agent_signature",
                "model_id": "model",
                "model_version": "1",
                "prompt_template_digest": "a" * 64,
                "context_source_digest": "b" * 64,
            },
            role_keys["Verifier"][0],
        )
    )
    facts = ProspectiveExecutionFacts(
        execution_context_id="1" * 64,
        container_instance_id_digest="2" * 64,
        controller_id=role_keys["Sidecar"][1]["key_id"],
    )
    return {
        "ledger_path": ledger_path,
        "evidence_root": evidence_root,
        "work_order": work_order,
        "context": context,
        "request": request,
        "arguments": arguments,
        "facts": facts,
        "verifier": verifier,
        "developer": developer,
        "verifier_issuance": verifier_issuance,
        "patch": patch,
    }


def _request_for_grant(case, grant, role_keys) -> AgentRequest:
    binding = next(
        item
        for item in case["work_order"].key_bindings
        if item.key_id == grant.subject_key_id
    )
    role = next(
        name
        for name, (_, raw) in role_keys.items()
        if raw["key_id"] == binding.key_id
    )
    return AgentRequest.model_validate(
        sign_payload(
            "agent-request",
            {
                **case["request"].model_dump(
                    mode="json",
                    exclude={
                        "digest",
                        "signature_alg",
                        "signer_key_id",
                        "signature",
                    },
                ),
                "grant_id": grant.grant_id,
                "actor_id": binding.subject_id,
                "actor_key_id": binding.key_id,
                "nonce": _grant_id(f"handler-loop:{role}:denied"),
            },
            role_keys[role][0],
        )
    )


def test_execute_run_tests_completes_authorize_handler_publish_loop(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now: datetime,
) -> None:
    case = _run_tests_case(
        tmp_path=tmp_path,
        signed_work_order=signed_work_order,
        role_keys=ephemeral_role_keys,
        sidecar_receipt_factory=sidecar_receipt_factory,
        now=fixed_now,
    )
    calls = []

    def handler(arguments: RunTestsArguments) -> int:
        calls.append(arguments)
        return 0

    receipt = execute_run_tests(
        case["ledger_path"],
        evidence_root=case["evidence_root"],
        context=case["context"],
        request=case["request"],
        request_arguments=case["arguments"],
        execution_facts=case["facts"],
        sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
        handler=handler,
        clock=lambda: fixed_now,
    )

    assert calls == [case["arguments"]]
    assert receipt.policy_decision == "allow"
    assert receipt.execution_status == "succeeded"
    assert receipt.state_before == "running"
    assert receipt.state_after == "locally_verified"
    assert receipt.parent_receipt_ids == (
        case["verifier_issuance"].receipt_id,
        case["patch"].receipt_id,
    )
    assert receipt.quota_charge.remaining_after == 0
    assert len(receipt.evidence_refs) == 1
    final = (
        case["evidence_root"]
        / receipt.evidence_refs[0].path.removeprefix("evidence/")
    )
    result = json.loads(final.read_bytes())
    assert result["actual_exit_code"] == 0
    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        assert connection.execute(
            "SELECT current_state, version FROM work_order_state"
        ).fetchone() == ("locally_verified", receipt.sequence)
        assert connection.execute(
            "SELECT state FROM evidence_publications WHERE receipt_id = ?",
            (receipt.receipt_id,),
        ).fetchone() == ("COMMITTED",)
    finally:
        connection.close()


def test_execute_run_tests_commits_started_handler_failure_without_evidence(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now: datetime,
) -> None:
    case = _run_tests_case(
        tmp_path=tmp_path,
        signed_work_order=signed_work_order,
        role_keys=ephemeral_role_keys,
        sidecar_receipt_factory=sidecar_receipt_factory,
        now=fixed_now,
    )

    def handler(arguments: RunTestsArguments) -> int:
        del arguments
        raise RuntimeError("secret infrastructure detail")

    receipt = execute_run_tests(
        case["ledger_path"],
        evidence_root=case["evidence_root"],
        context=case["context"],
        request=case["request"],
        request_arguments=case["arguments"],
        execution_facts=case["facts"],
        sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
        handler=handler,
        clock=lambda: fixed_now,
    )

    assert receipt.execution_status == "failed"
    assert receipt.execution_error_code == "HANDLER_ERROR"
    assert receipt.state_before == receipt.state_after == "running"
    assert receipt.evidence_refs == ()
    assert receipt.quota_charge.remaining_after == 0
    assert "secret" not in receipt.model_dump_json()
    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM evidence_publications WHERE receipt_id = ?",
            (receipt.receipt_id,),
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT COUNT(*) FROM grant_events WHERE receipt_id = ?",
            (receipt.receipt_id,),
        ).fetchone() == (1,)
    finally:
        connection.close()


def test_execute_run_tests_denial_never_starts_handler_or_writes(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now: datetime,
) -> None:
    case = _run_tests_case(
        tmp_path=tmp_path,
        signed_work_order=signed_work_order,
        role_keys=ephemeral_role_keys,
        sidecar_receipt_factory=sidecar_receipt_factory,
        now=fixed_now,
    )
    request = _request_for_grant(
        case,
        case["developer"],
        ephemeral_role_keys,
    )
    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        before = connection.execute(
            "SELECT COUNT(*), MAX(sequence) FROM receipts"
        ).fetchone()
    finally:
        connection.close()

    with pytest.raises(ToolCallDenied) as captured:
        execute_run_tests(
            case["ledger_path"],
            evidence_root=case["evidence_root"],
            context=case["context"],
            request=request,
            request_arguments=case["arguments"],
            execution_facts=case["facts"],
            sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
            handler=lambda _: pytest.fail("denied handler started"),
            clock=lambda: fixed_now,
        )

    assert captured.value.decision.error_code == "ROLE_DENIED"
    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        assert connection.execute(
            "SELECT COUNT(*), MAX(sequence) FROM receipts"
        ).fetchone() == before
    finally:
        connection.close()


def test_execute_run_tests_rejects_stale_context_before_second_handler(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now: datetime,
) -> None:
    case = _run_tests_case(
        tmp_path=tmp_path,
        signed_work_order=signed_work_order,
        role_keys=ephemeral_role_keys,
        sidecar_receipt_factory=sidecar_receipt_factory,
        now=fixed_now,
    )
    execute_run_tests(
        case["ledger_path"],
        evidence_root=case["evidence_root"],
        context=case["context"],
        request=case["request"],
        request_arguments=case["arguments"],
        execution_facts=case["facts"],
        sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
        handler=lambda _: 0,
        clock=lambda: fixed_now,
    )

    with pytest.raises(
        HandlerCoordinationError,
        match="current ledger snapshot",
    ):
        execute_run_tests(
            case["ledger_path"],
            evidence_root=case["evidence_root"],
            context=case["context"],
            request=case["request"],
            request_arguments=case["arguments"],
            execution_facts=case["facts"],
            sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
            handler=lambda _: pytest.fail("stale handler started"),
            clock=lambda: fixed_now,
        )


def test_execute_run_tests_rejects_missing_evidence_capacity_before_handler(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now: datetime,
) -> None:
    artifacts = tuple(
        artifact.model_copy(update={"max_size_bytes": 1})
        if artifact.purpose == "verifier_result"
        else artifact
        for artifact in signed_work_order.evidence_policy.artifacts
    )
    policy = signed_work_order.evidence_policy.model_copy(
        update={"artifacts": artifacts}
    )
    constrained = _resigned_work_order(
        signed_work_order,
        ephemeral_role_keys["Maintainer"][0],
        json_updates={
            "evidence_policy": policy.model_dump(mode="json"),
        },
        model_updates={"evidence_policy": policy},
    )
    case = _run_tests_case(
        tmp_path=tmp_path,
        signed_work_order=constrained,
        role_keys=ephemeral_role_keys,
        sidecar_receipt_factory=sidecar_receipt_factory,
        now=fixed_now,
    )

    with pytest.raises(
        HandlerCoordinationError,
        match="EVIDENCE_SLOT_UNAVAILABLE",
    ):
        execute_run_tests(
            case["ledger_path"],
            evidence_root=case["evidence_root"],
            context=case["context"],
            request=case["request"],
            request_arguments=case["arguments"],
            execution_facts=case["facts"],
            sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
            handler=lambda _: pytest.fail("unreserved handler started"),
            clock=lambda: fixed_now,
        )
