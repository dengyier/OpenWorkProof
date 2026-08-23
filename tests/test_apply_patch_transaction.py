"""Apply-patch production transaction coverage.

These tests drive the real ``execute_apply_patch`` executor against a real
candidate git workspace plus the frozen handler journal, and cover the
fail-closed/idempotent transaction semantics (success, handler failure,
COMMIT-ACK recovery, cleanup failure, evidence drift, pre-COMMIT zero-write,
concurrency, and the V5->V6 handler journal migration).
"""

from __future__ import annotations

import hashlib
import sqlite3
import threading
from pathlib import Path

import pytest

import openworkproof.evidence as evidence
import openworkproof.mcp_server as mcp_server
import openworkproof.repo_tools as repo_tools
from openworkproof.models import (
    AgentRequest,
    ApplyPatchArguments,
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
    handler, calls = _fake_patch_handler(case)
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
                    handler=handler,
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
    assert len(calls) == 1
    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM receipts WHERE receipt_json LIKE "
            "'%owp.apply_patch%'"
        ).fetchone() == (1,)
    finally:
        connection.close()


# --- schema migration: V5 -> V6 adds owp.apply_patch verbatim ---


def test_handler_journal_schema_v5_migrates_to_v6_preserving_signed_row(
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
        connection.execute("DROP TABLE handler_executions")
        connection.execute(evidence._HANDLER_EXECUTION_SCHEMA_V5)
        connection.execute(
            """
            INSERT INTO handler_executions (
                execution_id, work_order_digest, request_digest, nonce,
                grant_id, tool_name, arguments_digest,
                execution_context_id, container_instance_id_digest,
                controller_id, reserved_at, state
            ) VALUES (?, ?, ?, ?, ?, 'owp.repo_read', ?, ?, ?, ?, ?, 'RESERVED')
            """,
            (
                "0" * 64,
                case["work_order"].digest,
                "1" * 64,
                "2" * 64,
                case["developer"].grant_id,
                "3" * 64,
                "4" * 64,
                "5" * 64,
                case["facts"]["controller_id"],
                fixed_now.strftime("%Y-%m-%dT%H:%M:%SZ"),
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
            "SELECT execution_id, tool_name FROM handler_executions"
        ).fetchone()
    finally:
        connection.close()
    assert mcp_server._normalized_sql(stored[0]) == mcp_server._normalized_sql(
        evidence._HANDLER_EXECUTION_SCHEMA
    )
    assert row == ("0" * 64, "owp.repo_read")


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
