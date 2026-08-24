"""Apply-patch production transaction coverage.

These tests drive the real ``execute_apply_patch`` executor against a real
candidate git workspace plus the frozen handler journal, and cover the
fail-closed/idempotent transaction semantics (success, handler failure,
COMMIT-ACK recovery, cleanup failure, evidence drift, pre-COMMIT zero-write,
concurrency, and the V5->V6 handler journal migration).
"""

from __future__ import annotations

import copy
from datetime import timedelta
import hashlib
import sqlite3
import threading
from pathlib import Path

import pytest

import openworkproof.evidence as evidence
import openworkproof.mcp_server as mcp_server
import openworkproof.policy as policy
import openworkproof.repo_tools as repo_tools
from openworkproof.models import (
    AgentRequest,
    ApplyPatchArguments,
    PolicyDecision,
    SubjectClaim,
    request_arguments_digest,
)
from openworkproof.policy import (
    AuthorizationLedgerPrefix,
    ProspectiveExecutionFacts,
    derive_authorization_context,
)
from openworkproof.signing import sign_payload

from test_receipt_chain import (
    _activate_ledger_root,
    _child_grant,
    _delegation_request,
    _grant_replay_inputs,
    _issue_child,
    _work_order_with_pr_chain_predicates,
)
from test_mcp_server import _grant_id, _resigned_root
from test_sandbox import _candidate_git, _candidate_manifest


def _src_source() -> repo_tools.ParsedSourceArchive:
    files = (repo_tools.SourceFile("src/app.py", "100644", b"base\n"),)
    tree_oid = repo_tools.git_tree_oid(files)
    commit_raw = (
        f"tree {tree_oid}\n"
        "author OpenWorkProof <owp@example.invalid> 0 +0000\n"
        "committer OpenWorkProof <owp@example.invalid> 0 +0000\n"
        "\n"
        "base\n"
    ).encode("ascii")
    return repo_tools.ParsedSourceArchive(
        files=files,
        commit_raw=commit_raw,
        tree_oid=tree_oid,
        source_commit=repo_tools.git_commit_oid(commit_raw),
        artifact_sha256="a" * 64,
        artifact_size_bytes=1,
        shallow_bytes=None,
    )


def _src_app_patch() -> bytes:
    old_oid = repo_tools.git_blob_oid(b"base\n")
    new_oid = repo_tools.git_blob_oid(b"patched\n")
    return (
        "diff --git a/src/app.py b/src/app.py\n"
        f"index {old_oid}..{new_oid} 100644\n"
        "--- a/src/app.py\n"
        "+++ b/src/app.py\n"
        "@@ -1 +1 @@\n"
        "-base\n"
        "+patched\n"
    ).encode("ascii")


def _real_apply_patch_work_order(
    signed_work_order,
    ephemeral_role_keys,
    source: repo_tools.ParsedSourceArchive,
):
    """Re-sign the ephemeral work order with the real source commit.

    Only the source commit changes: the frozen synthetic replay profile already
    uses ``source_artifact_sha256 = "a"*64``, which is the exact artifact
    identity carried by the real candidate source snapshot.
    """
    from openworkproof.models import WorkOrder  # noqa: PLC0415

    pr_work_order = _work_order_with_pr_chain_predicates(
        signed_work_order,
        ephemeral_role_keys["Maintainer"][0],
    )
    raw = pr_work_order.model_dump(mode="json")
    raw["source_commit"] = source.source_commit
    return WorkOrder.model_validate(
        sign_payload(
            "work-order",
            raw,
            ephemeral_role_keys["Maintainer"][0],
        )
    )


def _apply_patch_case(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    fixed_now,
):
    """Build a running, no-active-patch case bound to a real git workspace."""
    from openworkproof.repo_tools import ReplayCheckpoint  # noqa: PLC0415

    source = _src_source()
    runtime_root = tmp_path / "runtime"
    runtime_root.mkdir(mode=0o700)
    candidate = repo_tools.initialize_candidate_workspace(
        repo_tools.WorkspaceInitRequest(
            runtime_root=runtime_root,
            workspace_id="5" * 64,
            source=source,
        )
    )
    work_order = _real_apply_patch_work_order(
        signed_work_order,
        ephemeral_role_keys,
        source,
    )
    root = _resigned_root(work_order, ephemeral_role_keys["Maintainer"][0])
    ledger_path = tmp_path / "apply-patch.sqlite3"
    evidence_root = tmp_path / "apply-patch-evidence"
    evidence_root.mkdir()
    _activate_ledger_root(
        ledger_path,
        work_order,
        root,
        ephemeral_role_keys,
        fixed_now,
    )
    developer = _child_grant(
        work_order,
        root,
        ephemeral_role_keys,
        label="apply-patch:developer",
        updates={
            "allowed_tools": [
                "owp.apply_patch",
                "owp.repo_read",
                "owp.rollback_patch",
            ],
            "quota": {"tool_calls": 2, "repair_rounds": 0},
        },
    )
    developer_issuance = _issue_child(
        ledger_path,
        developer,
        _delegation_request(
            work_order,
            root,
            developer,
            ephemeral_role_keys,
            actor_role="Manager",
            nonce=_grant_id("apply-patch:developer-request"),
        ),
        ephemeral_role_keys,
        fixed_now,
    )
    manifest, manifest_digest = _candidate_manifest(
        candidate,
        candidate.head_commit,
    )
    checkpoint = ReplayCheckpoint(
        files=(),
        head_commit=candidate.head_commit,
        workspace_manifest=manifest,
        workspace_manifest_digest=manifest_digest,
        verified_test_results=(),
    )
    receipts, grants, attempts = _grant_replay_inputs(ledger_path, work_order)
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
        (),
        checkpoint,
        fixed_now,
    )
    patch_bytes = _src_app_patch()
    return {
        "ledger_path": ledger_path,
        "evidence_root": evidence_root,
        "work_order": work_order,
        "context": context,
        "root": root,
        "developer": developer,
        "developer_issuance": developer_issuance,
        "candidate": candidate,
        "source": source,
        "patch_bytes": patch_bytes,
        "manifest_digest": manifest_digest,
        "facts": {
            "execution_context_id": "1" * 64,
            "container_instance_id_digest": "2" * 64,
            "controller_id": ephemeral_role_keys["Sidecar"][1]["key_id"],
        },
    }


def _apply_patch_request(case, role_keys, now, *, patch_bytes, path="src/app.py"):
    arguments = ApplyPatchArguments(
        target_paths=(path,),
        patch_digest=hashlib.sha256(patch_bytes).hexdigest(),
        patch_size_bytes=len(patch_bytes),
    )
    binding = role_keys["Developer"][1]
    request = AgentRequest.model_validate(
        sign_payload(
            "agent-request",
            {
                "claim_type": "agent-request",
                "work_order_digest": case["work_order"].digest,
                "grant_id": case["developer"].grant_id,
                "actor_id": binding["subject_id"],
                "actor_key_id": binding["key_id"],
                "tool_name": "owp.apply_patch",
                "arguments_digest": request_arguments_digest(
                    "owp.apply_patch", arguments
                ),
                "nonce": _grant_id("apply-patch:request"),
                "requested_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "authentication_method": "agent_signature",
                "model_id": "model",
                "model_version": "1",
                "prompt_template_digest": "a" * 64,
                "context_source_digest": "b" * 64,
            },
            role_keys["Developer"][0],
        )
    )
    return request, arguments


def _prospective_facts(case) -> ProspectiveExecutionFacts:
    return ProspectiveExecutionFacts(**case["facts"])


def _fake_patch_handler(case, *, fail: bool = False):
    calls: list[object] = []

    def handler(command):
        calls.append(command)
        if fail:
            raise RuntimeError("unknown workspace state")
        head = case["context"].replay_checkpoint.head_commit
        manifest = case["context"].replay_checkpoint.workspace_manifest_digest
        evidence_payload = repo_tools.PatchResultEvidence(
            schema_version="openworkproof-patch-result/0.1",
            parent_commit=head,
            parent_manifest_digest=manifest,
            candidate_commit="2" * 40,
            workspace_manifest_digest="0" * 64,
            patch_digest=command.expected_patch_digest,
            patch_size_bytes=command.expected_patch_size_bytes,
            replay_profile_digest=case["work_order"].replay_profile_digest,
        )
        return repo_tools.PatchResult(
            parent_commit=head,
            parent_manifest_digest=manifest,
            candidate_commit="2" * 40,
            workspace_manifest_digest="0" * 64,
            patch_digest=command.expected_patch_digest,
            patch_size_bytes=command.expected_patch_size_bytes,
            changed_paths=tuple(command.declared_target_paths),
            evidence=evidence_payload,
        )

    return handler, calls


def _execute_apply_patch(
    case,
    role_keys,
    fixed_now,
    *,
    handler=None,
    context=None,
):
    request, arguments = _apply_patch_request(
        case,
        role_keys,
        fixed_now,
        patch_bytes=case["patch_bytes"],
    )
    return mcp_server.execute_apply_patch(
        case["ledger_path"],
        evidence_root=case["evidence_root"],
        context=case["context"] if context is None else context,
        request=request,
        request_arguments=arguments,
        execution_facts=_prospective_facts(case),
        sidecar_private_key=role_keys["Sidecar"][0],
        patch_bytes=case["patch_bytes"],
        candidate_workspace=case["candidate"],
        handler=(
            repo_tools.apply_patch_in_candidate_workspace
            if handler is None
            else handler
        ),
        clock=lambda: fixed_now,
    )


def _user_table_snapshot(path):
    connection = sqlite3.connect(path)
    try:
        names = tuple(
            row[0]
            for row in connection.execute(
                """
                SELECT name FROM sqlite_master
                WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
                ORDER BY name
                """
            )
        )
        return {
            name: tuple(connection.execute(f'SELECT * FROM "{name}"'))
            for name in names
        }
    finally:
        connection.close()


def _business_tables(path):
    snapshot = _user_table_snapshot(path)
    snapshot.pop("handler_executions", None)
    return snapshot


def _allow_decision() -> PolicyDecision:
    return PolicyDecision(
        allowed=True,
        decision="allow",
        error_code=None,
        reason="test-agency-allow",
    )


def _workspace_state(case):
    """Return the candidate workspace's visible bytes and HEAD for comparison."""
    files = {}
    for path in sorted(case["candidate"].worktree.rglob("*")):
        if path.is_file():
            files[path.relative_to(case["candidate"].worktree).as_posix()] = (
                path.read_bytes()
            )
    head = _candidate_git(case["candidate"], "rev-parse", "HEAD").decode().strip()
    return files, head


# --- success against a real candidate git workspace ---


def test_execute_apply_patch_success_with_real_workspace(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    fixed_now,
) -> None:
    case = _apply_patch_case(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        fixed_now,
    )
    before_head = case["candidate"].head_commit

    receipt = _execute_apply_patch(case, ephemeral_role_keys, fixed_now)

    assert receipt.tool_name == "owp.apply_patch"
    assert receipt.policy_decision == "allow"
    assert receipt.execution_status == "succeeded"
    assert receipt.state_before == receipt.state_after == "running"
    assert (case["candidate"].worktree / "src" / "app.py").read_bytes() == (
        b"patched\n"
    )
    assert (
        _candidate_git(case["candidate"], "rev-parse", "HEAD")
        .decode()
        .strip()
        != before_head
    )
    assert receipt.output_digest is not None
    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        assert connection.execute(
            "SELECT receipt_id FROM receipts WHERE nonce = ?",
            (receipt.nonce,),
        ).fetchone() is not None
        assert connection.execute(
            "SELECT COUNT(*) FROM handler_executions"
        ).fetchone() == (0,)
    finally:
        connection.close()
    for reference in receipt.evidence_refs:
        payload = (
            case["evidence_root"]
            / reference.path.removeprefix("evidence/")
        ).read_bytes()
        assert len(payload) == reference.size_bytes
        assert hashlib.sha256(payload).hexdigest() == reference.sha256


# --- authority: a non-Sidecar controller must be rejected before execution ---


def _forged_result(result, *, candidate_commit=None, manifest_digest=None, changed_paths=None):
    evidence_updates: dict[str, object] = {}
    if candidate_commit is not None:
        evidence_updates["candidate_commit"] = candidate_commit
    if manifest_digest is not None:
        evidence_updates["workspace_manifest_digest"] = manifest_digest
    return repo_tools.PatchResult(
        parent_commit=result.parent_commit,
        parent_manifest_digest=result.parent_manifest_digest,
        candidate_commit=(
            candidate_commit if candidate_commit is not None else result.candidate_commit
        ),
        workspace_manifest_digest=(
            manifest_digest if manifest_digest is not None else result.workspace_manifest_digest
        ),
        patch_digest=result.patch_digest,
        patch_size_bytes=result.patch_size_bytes,
        changed_paths=(
            changed_paths if changed_paths is not None else result.changed_paths
        ),
        evidence=result.evidence.model_copy(update=evidence_updates),
    )


def _assert_recovery_without_receipt(case, *, handler_calls):
    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        assert connection.execute(
            "SELECT tool_name, state FROM handler_executions"
        ).fetchone() == ("owp.apply_patch", "STARTED_UNCONFIRMED")
        assert connection.execute(
            "SELECT COUNT(*) FROM receipts "
            "WHERE receipt_json LIKE '%owp.apply_patch%'"
        ).fetchone() == (0,)
    finally:
        connection.close()
    assert len(handler_calls) == 1


def test_execute_apply_patch_v01_rejects_non_sidecar_controller(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    fixed_now,
) -> None:
    case = _apply_patch_case(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        fixed_now,
    )
    before = _business_tables(case["ledger_path"])
    before_workspace = _workspace_state(case)
    agency_calls: list[object] = []
    handler_calls: list[object] = []
    request, arguments = _apply_patch_request(
        case,
        ephemeral_role_keys,
        fixed_now,
        patch_bytes=case["patch_bytes"],
    )
    facts = ProspectiveExecutionFacts(
        execution_context_id="1" * 64,
        container_instance_id_digest="2" * 64,
        controller_id=ephemeral_role_keys["Developer"][1]["key_id"],
    )
    with pytest.raises(policy.AuthorizationPolicyError, match="not the Sidecar"):
        mcp_server.execute_apply_patch(
            case["ledger_path"],
            evidence_root=case["evidence_root"],
            context=case["context"],
            request=request,
            request_arguments=arguments,
            execution_facts=facts,
            sidecar_private_key=ephemeral_role_keys["Developer"][0],
            patch_bytes=case["patch_bytes"],
            candidate_workspace=case["candidate"],
            handler=lambda command: (
                handler_calls.append(command)
                or repo_tools.apply_patch_in_candidate_workspace(command)
            ),
            clock=lambda: fixed_now,
            agency_authorize=lambda: (
                agency_calls.append(True) or _allow_decision()
            ),
        )

    assert agency_calls == []
    assert handler_calls == []
    assert _business_tables(case["ledger_path"]) == before
    assert _workspace_state(case) == before_workspace


def _apply_patch_v04_case(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    fixed_now,
    scope_payload,
):
    from openworkproof.binding import canonical_test_profile_digest  # noqa: PLC0415
    from openworkproof.binding_transactions import (  # noqa: PLC0415
        JudgmentAuthorityContext,
        commit_action_binding_manifest,
        commit_judgment_commitment,
    )
    from openworkproof.verification import commit_evaluation_scope  # noqa: PLC0415
    from test_binding_gateway_v04 import _resign_v04_request  # noqa: PLC0415
    from test_binding_manifest_transactions_v04 import (  # noqa: PLC0415
        _profile_from_axes,
        _signed_judgment,
        _signed_manifest,
        _signed_scope,
    )

    now = fixed_now + timedelta(seconds=5)
    case = _apply_patch_case(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        now,
    )
    work_order = case["work_order"]
    claim = SubjectClaim.model_validate(
        sign_payload(
            "subject-claim",
            {
                "schema_version": "openworkproof-subject-claim/0.1",
                "claim_id": "7" * 64,
                "work_order_digest": work_order.digest,
                "claim_statement": (
                    "The frozen verifier tests pass for this delivery."
                ),
                "delivery_target": "customer/release-candidate",
                "source_revision": work_order.source_commit,
                "acceptance_conditions": ["artifact_digest_matches", "tests_passed"],
                "excluded_scope": ["payment_status"],
                "required_artifacts": ["evidence", "results"],
                "customer_acceptor_key_id": work_order.acceptor_key_ids[0],
                "created_at": "2026-01-01T00:00:05Z",
                "nonce": "8" * 64,
            },
            ephemeral_role_keys["Manager"][0],
        )
    )
    scope_payload = copy.deepcopy(scope_payload)
    for member in scope_payload["members"]:
        member["source_revision"] = work_order.source_commit
    scope = _signed_scope(
        payload=scope_payload,
        manager_key=ephemeral_role_keys["Manager"][0],
        work_order=work_order,
        claim=claim,
    )
    test_digests = tuple(
        sorted(
            canonical_test_profile_digest(profile)
            for profile in work_order.test_profiles
        )
    )
    profile, projection = _profile_from_axes(
        allowed_tool_names=("owp.apply_patch",),
        allowed_action_kinds=("patch",),
        allowed_path_roots=("src",),
        required_test_profile_digests=test_digests,
    )
    judgment = _signed_judgment(
        work_order=work_order,
        scope=scope,
        acceptor_key=ephemeral_role_keys["Acceptor"][0],
        projection=projection,
    )
    manifest = _signed_manifest(
        work_order=work_order,
        scope=scope,
        judgment=judgment,
        projection=projection,
        manager_key=ephemeral_role_keys["Manager"][0],
    )
    commit_evaluation_scope(case["ledger_path"], claim, scope)
    commit_judgment_commitment(
        case["ledger_path"],
        judgment,
        JudgmentAuthorityContext(
            authority_namespace=judgment.authority_namespace,
            authority_binding=next(
                item
                for item in work_order.key_bindings
                if item.role == "Acceptor"
            ),
            transaction_time=now - timedelta(seconds=3),
        ),
    )
    commit_action_binding_manifest(
        case["ledger_path"],
        manifest,
        profile,
        transaction_time=now - timedelta(seconds=1),
    )
    request_v01, arguments = _apply_patch_request(
        case,
        ephemeral_role_keys,
        now,
        patch_bytes=case["patch_bytes"],
    )
    request_v04 = _resign_v04_request(
        request_v01,
        ephemeral_role_keys["Developer"][0],
        judgment_id=judgment.commitment_id,
        judgment_digest=judgment.digest,
        manifest_id=manifest.binding_manifest_id,
        manifest_digest=manifest.digest,
    )
    case.update(
        {
            "now": now,
            "request_v04": request_v04,
            "arguments": arguments,
        }
    )
    return case


def test_execute_apply_patch_v04_rejects_non_sidecar_controller(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    fixed_now,
    evaluation_scope_payload_v03,
) -> None:
    case = _apply_patch_v04_case(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        fixed_now,
        evaluation_scope_payload_v03,
    )
    before = _business_tables(case["ledger_path"])
    before_workspace = _workspace_state(case)
    agency_calls: list[object] = []
    handler_calls: list[object] = []
    facts = ProspectiveExecutionFacts(
        execution_context_id="1" * 64,
        container_instance_id_digest="2" * 64,
        controller_id=ephemeral_role_keys["Developer"][1]["key_id"],
    )
    with pytest.raises(mcp_server.ToolCallDenied) as caught:
        mcp_server.execute_apply_patch(
            case["ledger_path"],
            evidence_root=case["evidence_root"],
            context=case["context"],
            request=case["request_v04"],
            request_arguments=case["arguments"],
            execution_facts=facts,
            sidecar_private_key=ephemeral_role_keys["Developer"][0],
            patch_bytes=case["patch_bytes"],
            candidate_workspace=case["candidate"],
            handler=lambda command: (
                handler_calls.append(command)
                or repo_tools.apply_patch_in_candidate_workspace(command)
            ),
            clock=lambda: case["now"],
            agency_authorize=lambda: (
                agency_calls.append(True) or _allow_decision()
            ),
        )

    assert caught.value.decision.error_code == "AUTH_SUBJECT_MISMATCH"
    assert agency_calls == []
    assert handler_calls == []
    assert _business_tables(case["ledger_path"]) == before
    assert _workspace_state(case) == before_workspace


# --- untrusted handler postconditions fail closed before publication ---


def test_execute_apply_patch_rejects_forged_self_consistent_result(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    fixed_now,
) -> None:
    case = _apply_patch_case(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        fixed_now,
    )
    before = _business_tables(case["ledger_path"])
    handler, calls = _fake_patch_handler(case)
    with pytest.raises(
        mcp_server.HandlerCoordinationError, match="RECOVERY_REQUIRED"
    ):
        _execute_apply_patch(case, ephemeral_role_keys, fixed_now, handler=handler)
    _assert_recovery_without_receipt(case, handler_calls=calls)
    assert _business_tables(case["ledger_path"]) == before


def test_execute_apply_patch_rejects_forged_candidate_commit(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    fixed_now,
) -> None:
    case = _apply_patch_case(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        fixed_now,
    )
    calls: list[object] = []

    def handler(command):
        calls.append(command)
        result = repo_tools.apply_patch_in_candidate_workspace(command)
        return _forged_result(result, candidate_commit="f" * 40)

    with pytest.raises(
        mcp_server.HandlerCoordinationError, match="RECOVERY_REQUIRED"
    ):
        _execute_apply_patch(case, ephemeral_role_keys, fixed_now, handler=handler)
    _assert_recovery_without_receipt(case, handler_calls=calls)


def test_execute_apply_patch_rejects_forged_manifest_and_changed_paths(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    fixed_now,
) -> None:
    case = _apply_patch_case(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        fixed_now,
    )
    calls: list[object] = []

    def handler(command):
        calls.append(command)
        result = repo_tools.apply_patch_in_candidate_workspace(command)
        return _forged_result(
            result,
            manifest_digest="0" * 64,
            changed_paths=("src/forged.py",),
        )

    with pytest.raises(
        mcp_server.HandlerCoordinationError, match="RECOVERY_REQUIRED"
    ):
        _execute_apply_patch(case, ephemeral_role_keys, fixed_now, handler=handler)
    _assert_recovery_without_receipt(case, handler_calls=calls)


def test_execute_apply_patch_rejects_extra_undeclared_path_mutation(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    fixed_now,
) -> None:
    case = _apply_patch_case(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        fixed_now,
    )
    calls: list[object] = []
    extra = case["candidate"].worktree / "extra.txt"

    def handler(command):
        calls.append(command)
        result = repo_tools.apply_patch_in_candidate_workspace(command)
        extra.write_bytes(b"undeclared\n")
        return result

    with pytest.raises(
        mcp_server.HandlerCoordinationError, match="RECOVERY_REQUIRED"
    ):
        _execute_apply_patch(case, ephemeral_role_keys, fixed_now, handler=handler)
    _assert_recovery_without_receipt(case, handler_calls=calls)
    # Production detects but does not silently bless; clean up for isolation.
    extra.unlink(missing_ok=True)


# --- handler failure leaves truth unresolved and zero business writes ---


def test_execute_apply_patch_handler_failure_requires_recovery(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    fixed_now,
) -> None:
    case = _apply_patch_case(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        fixed_now,
    )
    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        before = connection.execute(
            "SELECT COUNT(*), MAX(sequence) FROM receipts"
        ).fetchone()
    finally:
        connection.close()

    handler, calls = _fake_patch_handler(case, fail=True)
    with pytest.raises(
        mcp_server.HandlerCoordinationError, match="RECOVERY_REQUIRED"
    ):
        _execute_apply_patch(case, ephemeral_role_keys, fixed_now, handler=handler)

    assert len(calls) == 1
    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        assert connection.execute(
            "SELECT COUNT(*), MAX(sequence) FROM receipts"
        ).fetchone() == before
        assert connection.execute(
            """
            SELECT tool_name, state, authorization_prefix_digest,
                   agency_binding, agency_binding_json
            FROM handler_executions
            """
        ).fetchone() == (
            "owp.apply_patch",
            "STARTED_UNCONFIRMED",
            None,
            None,
            None,
        )
    finally:
        connection.close()


# --- COMMIT-ACK recovery: committed truth is finalized, never republished ---


def test_execute_apply_patch_recovers_committed_receipt_after_cleanup_failure(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    fixed_now,
    monkeypatch,
) -> None:
    case = _apply_patch_case(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        fixed_now,
    )
    real_finalize = mcp_server._finalize_handler_execution

    def fail_cleanup(*_):
        raise mcp_server.HandlerCoordinationError("injected cleanup failure")

    monkeypatch.setattr(
        mcp_server,
        "_finalize_handler_execution",
        fail_cleanup,
    )
    with pytest.raises(
        mcp_server.HandlerCoordinationError,
        match="injected cleanup failure",
    ):
        _execute_apply_patch(case, ephemeral_role_keys, fixed_now)
    monkeypatch.setattr(
        mcp_server,
        "_finalize_handler_execution",
        real_finalize,
    )

    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        committed = connection.execute(
            "SELECT COUNT(*), MAX(sequence) FROM receipts"
        ).fetchone()
        assert connection.execute(
            "SELECT tool_name, state FROM handler_executions"
        ).fetchone() == ("owp.apply_patch", "STARTED_UNCONFIRMED")
    finally:
        connection.close()

    # A stale-context retry clears the committed journal row and never
    # republishes the already-committed patch receipt.
    with pytest.raises(
        mcp_server.HandlerCoordinationError,
        match="current ledger snapshot",
    ):
        _execute_apply_patch(
            case,
            ephemeral_role_keys,
            fixed_now,
            handler=lambda _: pytest.fail("committed patch restarted"),
        )
    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM handler_executions"
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT COUNT(*), MAX(sequence) FROM receipts"
        ).fetchone() == committed
    finally:
        connection.close()


def test_execute_apply_patch_commit_ack_loss_recovers_without_rerunning_handler(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    fixed_now,
    monkeypatch,
) -> None:
    """A lost COMMIT-ACK leaves exactly one committed receipt on readback.

    Publication performs the real commit and then the acknowledgement is lost;
    a retry must observe the committed truth and never rerun the handler.
    """
    case = _apply_patch_case(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        fixed_now,
    )
    real_publish = evidence.complete_receipt_publication
    handler_calls: list[object] = []
    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        before_total = connection.execute(
            "SELECT COUNT(*) FROM receipts"
        ).fetchone()[0]
    finally:
        connection.close()

    def recording_handler(command):
        handler_calls.append(command)
        return repo_tools.apply_patch_in_candidate_workspace(command)

    def publish_then_lose_ack(*args, **kwargs):
        real_publish(*args, **kwargs)
        raise mcp_server.HandlerCoordinationError("COMMIT-ACK lost after publication")

    monkeypatch.setattr(evidence, "complete_receipt_publication", publish_then_lose_ack)
    with pytest.raises(
        mcp_server.HandlerCoordinationError,
        match="COMMIT-ACK lost after publication",
    ):
        _execute_apply_patch(
            case, ephemeral_role_keys, fixed_now, handler=recording_handler
        )
    monkeypatch.setattr(evidence, "complete_receipt_publication", real_publish)

    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        committed = connection.execute(
            "SELECT COUNT(*), MAX(sequence) FROM receipts"
        ).fetchone()
        assert committed[0] == before_total + 1
        assert connection.execute(
            "SELECT COUNT(*) FROM receipts "
            "WHERE receipt_json LIKE '%owp.apply_patch%'"
        ).fetchone() == (1,)
        assert connection.execute(
            "SELECT tool_name, state FROM handler_executions"
        ).fetchone() == ("owp.apply_patch", "STARTED_UNCONFIRMED")
    finally:
        connection.close()

    with pytest.raises(
        mcp_server.HandlerCoordinationError,
        match="current ledger snapshot",
    ):
        _execute_apply_patch(
            case,
            ephemeral_role_keys,
            fixed_now,
            handler=lambda _: pytest.fail("committed patch restarted"),
        )

    assert len(handler_calls) == 1
    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM handler_executions"
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT COUNT(*), MAX(sequence) FROM receipts"
        ).fetchone() == committed
    finally:
        connection.close()


# --- pre-COMMIT failure writes no business state ---


def test_execute_apply_patch_precommit_failure_is_zero_write(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    fixed_now,
) -> None:
    case = _apply_patch_case(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        fixed_now,
    )
    before = _user_table_snapshot(case["ledger_path"])
    handler, calls = _fake_patch_handler(case, fail=True)
    with pytest.raises(mcp_server.HandlerCoordinationError):
        _execute_apply_patch(case, ephemeral_role_keys, fixed_now, handler=handler)
    assert len(calls) == 1
    after = _user_table_snapshot(case["ledger_path"])
    # Only the handler journal changes (bookkeeping); business tables unchanged.
    del before["handler_executions"]
    del after["handler_executions"]
    assert after == before


def test_execute_apply_patch_precommit_publication_injection_is_zero_write(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    fixed_now,
    monkeypatch,
) -> None:
    """A staging-entry failure writes zero business/evidence state.

    Unlike a handler failure, the real handler here succeeds (the workspace is
    genuinely patched), but the publication coordinator raises at pending
    evidence staging entry — before any receipt or evidence journal row is
    written — so no receipt or evidence is written and only the allowed
    unresolved journal bookkeeping remains. This is distinct from the
    insert-then-raise pre-COMMIT rollback test below, which exercises the
    actual INSERT and ROLLBACK path.
    """
    case = _apply_patch_case(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        fixed_now,
    )
    before = _business_tables(case["ledger_path"])
    before_head = case["candidate"].head_commit
    calls: list[object] = []

    def fail_before_commit(*args, **kwargs):
        raise mcp_server.HandlerCoordinationError("pre-COMMIT publication injection")

    monkeypatch.setattr(
        evidence,
        "stage_pending_evidence_group",
        fail_before_commit,
    )
    with pytest.raises(
        mcp_server.HandlerCoordinationError,
        match="pre-COMMIT publication injection",
    ):
        _execute_apply_patch(
            case,
            ephemeral_role_keys,
            fixed_now,
            handler=lambda command: (
                calls.append(command)
                or repo_tools.apply_patch_in_candidate_workspace(command)
            ),
        )

    assert len(calls) == 1
    # The handler genuinely succeeded (distinct from a handler failure)...
    assert (case["candidate"].worktree / "src" / "app.py").read_bytes() == (
        b"patched\n"
    )
    assert (
        _candidate_git(case["candidate"], "rev-parse", "HEAD")
        .decode()
        .strip()
        != before_head
    )
    # ...but no receipt or evidence was committed.
    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        assert connection.execute(
            "SELECT tool_name, state FROM handler_executions"
        ).fetchone() == ("owp.apply_patch", "STARTED_UNCONFIRMED")
        assert connection.execute(
            "SELECT COUNT(*) FROM receipts "
            "WHERE receipt_json LIKE '%owp.apply_patch%'"
        ).fetchone() == (0,)
    finally:
        connection.close()
    assert _business_tables(case["ledger_path"]) == before
    evidence_files = [
        path for path in case["evidence_root"].rglob("*") if path.is_file()
    ]
    assert evidence_files == []


def test_execute_apply_patch_precommit_insert_failure_rolls_back_exactly(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    fixed_now,
    monkeypatch,
) -> None:
    """A raise after the real insert but before COMMIT rolls back exactly.

    Unlike the staging-entry injection above, the real
    ``evidence._insert_receipt_and_publication_group`` actually INSERTs the
    receipt, receipt_parents, grant-events, evidence_publications, state and
    sequence rows and the pending evidence files are actually staged, then
    ``sqlite3.OperationalError`` is raised before SQLite COMMIT. All of those
    business rows must roll back exactly; the handler journal may remain
    STARTED_UNCONFIRMED, the real workspace may already contain the immutable
    patch, and the orphaned pending evidence must be removed by recovery.
    """
    case = _apply_patch_case(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        fixed_now,
    )
    before = _business_tables(case["ledger_path"])
    before_head = case["candidate"].head_commit
    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        before_counts = {
            name: connection.execute(
                f"SELECT COUNT(*) FROM {name}"
            ).fetchone()[0]
            for name in (
                "receipts",
                "receipt_parents",
                "evidence_publications",
                "grant_events",
                "work_order_state",
                "sequence_counter",
            )
        }
    finally:
        connection.close()
    real_insert = evidence._insert_receipt_and_publication_group

    def insert_then_raise(*args, **kwargs):
        real_insert(*args, **kwargs)
        raise sqlite3.OperationalError("pre-COMMIT insert failure")

    monkeypatch.setattr(
        evidence,
        "_insert_receipt_and_publication_group",
        insert_then_raise,
    )
    with pytest.raises(
        sqlite3.OperationalError,
        match="pre-COMMIT insert failure",
    ):
        _execute_apply_patch(case, ephemeral_role_keys, fixed_now)

    # The real handler already committed the immutable Git candidate commit.
    assert (case["candidate"].worktree / "src" / "app.py").read_bytes() == (
        b"patched\n"
    )
    assert (
        _candidate_git(case["candidate"], "rev-parse", "HEAD")
        .decode()
        .strip()
        != before_head
    )

    # Every business row inserted before the failure rolled back exactly.
    assert _business_tables(case["ledger_path"]) == before
    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        assert connection.execute(
            "SELECT tool_name, state FROM handler_executions"
        ).fetchone() == ("owp.apply_patch", "STARTED_UNCONFIRMED")
        for name in before_counts:
            assert connection.execute(
                f"SELECT COUNT(*) FROM {name}"
            ).fetchone()[0] == before_counts[name]
    finally:
        connection.close()

    # The staged pending evidence is orphaned (rowless), not silently blessed;
    # recovery removes it idempotently.
    pending_dir = case["evidence_root"] / ".pending"
    pending_files = [
        path for path in pending_dir.iterdir() if path.is_file()
    ]
    assert len(pending_files) == 2
    final_files = [
        path
        for path in case["evidence_root"].rglob("*")
        if path.is_file() and ".pending" not in path.parts
    ]
    assert final_files == []

    evidence.recover_evidence_publications(
        case["ledger_path"],
        evidence_root=case["evidence_root"],
    )
    assert [path for path in pending_dir.iterdir() if path.is_file()] == []


# --- evidence drift/tamper fails closed ---


def test_execute_apply_patch_patch_digest_mismatch_fails_closed(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    fixed_now,
) -> None:
    case = _apply_patch_case(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        fixed_now,
    )
    request, arguments = _apply_patch_request(
        case,
        ephemeral_role_keys,
        fixed_now,
        patch_bytes=case["patch_bytes"],
    )
    tampered = case["patch_bytes"] + b"x"
    before = _user_table_snapshot(case["ledger_path"])
    with pytest.raises(
        mcp_server.HandlerCoordinationError,
        match="binding is invalid",
    ):
        mcp_server.execute_apply_patch(
            case["ledger_path"],
            evidence_root=case["evidence_root"],
            context=case["context"],
            request=request,
            request_arguments=arguments,
            execution_facts=_prospective_facts(case),
            sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
            patch_bytes=tampered,
            candidate_workspace=case["candidate"],
            handler=repo_tools.apply_patch_in_candidate_workspace,
            clock=lambda: fixed_now,
        )
    assert _user_table_snapshot(case["ledger_path"]) == before


# --- post-receipt workspace drift fails closed before any new patch ---


def test_execute_apply_patch_rejects_workspace_drift_before_next_candidate_operation(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    fixed_now,
) -> None:
    """The receipt certifies the immutable commit, not a forever-clean worktree.

    After a successful receipt, an out-of-band write drifts the mutable
    worktree. The next candidate operation revalidates the current candidate
    checkpoint via ``_verify_candidate_checkpoint`` and rejects the drift
    before applying any new patch, so the certified commit is not mutated and
    the drift is not silently blessed.
    """
    case = _apply_patch_case(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        fixed_now,
    )
    _execute_apply_patch(case, ephemeral_role_keys, fixed_now)
    after_head = (
        _candidate_git(case["candidate"], "rev-parse", "HEAD").decode().strip()
    )
    _, after_manifest_digest = _candidate_manifest(case["candidate"], after_head)

    drift = case["candidate"].worktree / "drift.txt"
    drift.write_bytes(b"later drift\n")

    with pytest.raises(
        repo_tools.CandidateWorkspaceError,
        match="candidate checkpoint does not match authority",
    ):
        repo_tools.apply_patch_in_candidate_workspace(
            repo_tools.PatchRequest(
                workspace=case["candidate"],
                patch_bytes=case["patch_bytes"],
                expected_patch_digest=hashlib.sha256(
                    case["patch_bytes"]
                ).hexdigest(),
                expected_patch_size_bytes=len(case["patch_bytes"]),
                declared_target_paths=("src/app.py",),
                parent_commit=after_head,
                parent_manifest_digest=after_manifest_digest,
                occurred_at=fixed_now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                replay_profile=case["work_order"].replay_profile,
                replay_profile_digest=case["work_order"].replay_profile_digest,
            )
        )

    # The drift is not blessed and the certified commit is not mutated.
    assert drift.read_bytes() == b"later drift\n"
    assert (
        _candidate_git(case["candidate"], "rev-parse", "HEAD").decode().strip()
        == after_head
    )
    assert (case["candidate"].worktree / "src" / "app.py").read_bytes() == (
        b"patched\n"
    )


# --- concurrency: exactly one result, deterministic serialization ---


def test_execute_apply_patch_concurrency_is_serialized(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    fixed_now,
) -> None:
    case = _apply_patch_case(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        fixed_now,
    )
    before_head = case["candidate"].head_commit
    outcomes: list[object] = []
    barrier = threading.Barrier(2)

    def run():
        barrier.wait(timeout=20)
        try:
            outcomes.append(
                _execute_apply_patch(
                    case,
                    ephemeral_role_keys,
                    fixed_now,
                    handler=repo_tools.apply_patch_in_candidate_workspace,
                )
            )
        except Exception as error:  # pragma: no cover - diagnostic only
            outcomes.append(error)

    threads = [threading.Thread(target=run) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=20)

    receipts = [
        outcome for outcome in outcomes if not isinstance(outcome, Exception)
    ]
    errors = [outcome for outcome in outcomes if isinstance(outcome, Exception)]
    assert len(receipts) == 1 and len(errors) == 1
    assert all(
        isinstance(error, mcp_server.HandlerCoordinationError)
        and "current ledger snapshot" in str(error)
        for error in errors
    )
    # Exactly one real patch was applied, not a no-op claim.
    assert (case["candidate"].worktree / "src" / "app.py").read_bytes() == (
        b"patched\n"
    )
    assert (
        _candidate_git(case["candidate"], "rev-parse", "HEAD")
        .decode()
        .strip()
        != before_head
    )
    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM receipts WHERE receipt_json LIKE "
            "'%owp.apply_patch%'"
        ).fetchone() == (1,)
        assert connection.execute(
            "SELECT COUNT(*) FROM handler_executions"
        ).fetchone() == (0,)
    finally:
        connection.close()


# --- schema migration: V5 -> V6 adds owp.apply_patch verbatim ---


def test_handler_journal_schema_v5_migrates_to_v6_preserving_signed_run_tests_row(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    fixed_now,
    sidecar_receipt_factory,
) -> None:
    """V5 -> V6 preserves a genuinely Sidecar-signed run-tests agency binding.

    The row carries a non-NULL agency binding marker plus its canonical
    Sidecar-signed envelope, and a subsequent load must verify both against the
    authoritative WorkOrder instead of laundering an unbound NULL row.
    """
    from test_mcp_server import _run_tests_case, _run_tests_contract  # noqa: PLC0415

    case = _run_tests_case(
        tmp_path=tmp_path,
        signed_work_order=signed_work_order,
        role_keys=ephemeral_role_keys,
        sidecar_receipt_factory=sidecar_receipt_factory,
        now=fixed_now,
    )
    request = case["request"]
    facts = case["facts"]
    work_order = case["work_order"]
    context = case["context"]
    contract = _run_tests_contract(case)

    execution_id = mcp_server._handler_execution_id(request, facts)
    reserved_at = context.transaction_time.strftime("%Y-%m-%dT%H:%M:%SZ")
    request_json = mcp_server._canonical_agent_request(request).decode("utf-8")
    contract_bytes = repo_tools.encode_run_tests_execution_contract(contract)
    contract_json = contract_bytes.decode("utf-8")
    contract_digest = hashlib.sha256(contract_bytes).hexdigest()
    agency_binding = evidence._HANDLER_AGENCY_BINDING_MARKER
    authorization_prefix_digest = mcp_server._authorization_prefix_digest(
        context.ledger_prefix,
        domain=mcp_server._agency_binding_prefix_domain(agency_binding),
    )
    agency_binding_json = mcp_server._build_agency_binding_envelope(
        work_order_digest=work_order.digest,
        execution_id=execution_id,
        request_digest=request.digest,
        authorization_prefix_digest=authorization_prefix_digest,
        controller_key_id=facts.controller_id,
        reserved_at=reserved_at,
        sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
    )

    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        connection.execute("DROP TABLE handler_executions")
        connection.execute(evidence._HANDLER_EXECUTION_SCHEMA_V5)
        connection.execute(
            """
            INSERT INTO handler_executions (
                execution_id, work_order_digest, request_digest, nonce,
                grant_id, tool_name, arguments_digest,
                execution_context_id, container_instance_id_digest,
                controller_id, reserved_at, state,
                authorization_prefix_digest, agency_binding,
                agency_binding_json, request_json,
                execution_contract_json, execution_contract_digest
            ) VALUES (
                ?, ?, ?, ?, ?, 'owp.run_tests', ?, ?, ?, ?, ?, 'RESERVED',
                ?, ?, ?, ?, ?, ?
            )
            """,
            (
                execution_id,
                work_order.digest,
                request.digest,
                request.nonce,
                request.grant_id,
                request.arguments_digest,
                facts.execution_context_id,
                facts.container_instance_id_digest,
                facts.controller_id,
                reserved_at,
                authorization_prefix_digest,
                agency_binding,
                agency_binding_json,
                request_json,
                contract_json,
                contract_digest,
            ),
        )
    finally:
        connection.close()
    lock_descriptor = evidence._acquire_target_lock(case["ledger_path"])
    try:
        mcp_server._ensure_handler_execution_schema(
            case["ledger_path"], lock_descriptor
        )
    finally:
        evidence._release_target_lock(lock_descriptor)

    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        stored = connection.execute(
            """
            SELECT sql FROM sqlite_master
            WHERE type = 'table' AND name = 'handler_executions'
            """
        ).fetchone()
        row = connection.execute(
            """
            SELECT execution_id, tool_name, agency_binding, agency_binding_json
            FROM handler_executions
            """
        ).fetchone()
    finally:
        connection.close()
    assert mcp_server._normalized_sql(stored[0]) == mcp_server._normalized_sql(
        evidence._HANDLER_EXECUTION_SCHEMA
    )
    assert row == (
        execution_id,
        "owp.run_tests",
        evidence._HANDLER_AGENCY_BINDING_MARKER,
        agency_binding_json,
    )

    # Subsequent load/verification replays the stored request truth and
    # verifies the Sidecar-signed envelope against the authoritative WorkOrder.
    lock_descriptor = evidence._acquire_target_lock(case["ledger_path"])
    try:
        stored_execution = mcp_server._load_stored_run_tests_execution(
            case["ledger_path"], lock_descriptor
        )
    finally:
        evidence._release_target_lock(lock_descriptor)
    assert stored_execution is not None
    assert stored_execution.execution_id == execution_id
    assert (
        stored_execution.agency_binding
        == evidence._HANDLER_AGENCY_BINDING_MARKER
    )


def test_handler_journal_schema_accepts_apply_patch_reservation(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    fixed_now,
) -> None:
    case = _apply_patch_case(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        fixed_now,
    )
    request, arguments = _apply_patch_request(
        case,
        ephemeral_role_keys,
        fixed_now,
        patch_bytes=case["patch_bytes"],
    )
    facts = _prospective_facts(case)
    lock_descriptor = evidence._acquire_target_lock(case["ledger_path"])
    try:
        mcp_server._reserve_handler_execution(
            case["ledger_path"],
            lock_descriptor,
            case["context"],
            request,
            facts,
            None,
        )
    finally:
        evidence._release_target_lock(lock_descriptor)
    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        assert connection.execute(
            "SELECT tool_name FROM handler_executions"
        ).fetchone() == ("owp.apply_patch",)
    finally:
        connection.close()
