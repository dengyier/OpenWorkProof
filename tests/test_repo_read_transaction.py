"""Repo-read production transaction coverage."""

from __future__ import annotations

import dataclasses
from pathlib import Path
import hashlib

import pytest

import rfc8785

import openworkproof.mcp_server as mcp_server
from openworkproof.models import (
    AgentRequest,
    RepoReadArguments,
    request_arguments_digest,
)
from openworkproof.signing import sign_payload
from test_mcp_server import (
    _current_run_tests_context,
    _grant_id,
    _run_tests_case,
)


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


def _repo_read_case(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
    *,
    manifest_path: bytes = b"README.md",
):
    import stat  # noqa: PLC0415

    from openworkproof import repo_tools
    from openworkproof.repo_tools import (
        WorkspaceScanRecord,
        build_workspace_manifest,
        workspace_manifest_digest,
    )

    case = _run_tests_case(
        tmp_path=tmp_path,
        signed_work_order=signed_work_order,
        role_keys=ephemeral_role_keys,
        sidecar_receipt_factory=sidecar_receipt_factory,
        now=fixed_now,
        developer_tools=(
            "owp.apply_patch",
            "owp.repo_read",
            "owp.rollback_patch",
        ),
    )
    context = _current_run_tests_context(case, fixed_now)
    manifest_digest = context.replay_checkpoint.workspace_manifest_digest
    return case, context, manifest_digest


def _repo_read_request(
    case,
    context,
    role_keys,
    now,
    *,
    path: str = "README.md",
    actor_role: str = "Developer",
    nonce_label: str = "repo-read:1",
):
    arguments = RepoReadArguments(path=path)
    binding = role_keys[actor_role][1]
    request = AgentRequest.model_validate(
        sign_payload(
            "agent-request",
            {
                "claim_type": "agent-request",
                "work_order_digest": case["work_order"].digest,
                "grant_id": case["developer"].grant_id,
                "actor_id": binding["subject_id"],
                "actor_key_id": binding["key_id"],
                "tool_name": "owp.repo_read",
                "arguments_digest": request_arguments_digest(
                    "owp.repo_read", arguments
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
    return request, arguments


def _read_handler(manifest_digest, *, content: bytes = b"test"):
    from openworkproof import repo_tools
    from openworkproof.repo_tools import RepoReadOutput

    def handler(command):
        return repo_tools.CandidateReadResult(
            content=content,
            output=RepoReadOutput(
                path=command.path,
                content_sha256=hashlib.sha256(content).hexdigest(),
                size_bytes=len(content),
                workspace_manifest_digest=manifest_digest,
            ),
        )

    return handler


def test_repo_read_rejects_path_outside_manifest(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
) -> None:
    case, context, manifest_digest = _repo_read_case(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        sidecar_receipt_factory,
        fixed_now,
        monkeypatch,
    )
    request, arguments = _repo_read_request(
        case, context, ephemeral_role_keys, fixed_now,
        path="src/main.py",
    )
    before = _snapshot_ledger(case)
    with pytest.raises(
        mcp_server.HandlerCoordinationError, match="REPO_READ_PATH_DENIED"
    ):
        mcp_server.execute_repo_read(
            case["ledger_path"],
            evidence_root=case["evidence_root"],
            context=context,
            request=request,
            request_arguments=arguments,
            execution_facts=case["facts"],
            sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
            candidate_runtime_root=tmp_path,
            handler=_read_handler(manifest_digest),
            clock=lambda: fixed_now,
        )
    assert _snapshot_ledger(case) == before


def _snapshot_ledger(case) -> dict:
    import sqlite3 as _sql

    connection = _sql.connect(case["ledger_path"])
    try:
        return {
            "receipts": connection.execute(
                "SELECT COUNT(*) FROM receipts"
            ).fetchone()[0],
            "state": connection.execute(
                "SELECT current_state, version FROM work_order_state "
                "WHERE singleton = 1"
            ).fetchone(),
        }
    finally:
        connection.close()


def test_pipeline_handler_reads_candidate_file(tmp_path: Path) -> None:
    """Pipeline-backed handler turns a candidate file into RepoReadOutput."""
    import hashlib as _h

    from openworkproof import repo_tools

    root = tmp_path / "candidate-repo"
    (root / "src").mkdir(parents=True)
    (root / "src" / "app.py").write_text("import os\n\nprint('hi')\n")
    manifest_digest = "a" * 64
    handler = mcp_server.make_repo_pipeline_read_handler()
    command = repo_tools.CandidateReadRequest(
        runtime_root=root,
        workspace_id="c" * 64,
        source_artifact_sha256="b" * 64,
        expected_head_commit="c" * 40,
        expected_workspace_manifest_digest=manifest_digest,
        path="src/app.py",
    )
    result = handler(command)
    expected = (root / "src" / "app.py").read_bytes()
    assert result.content == expected
    assert result.output.path == "src/app.py"
    assert result.output.content_sha256 == _h.sha256(expected).hexdigest()
    assert result.output.size_bytes == len(expected)
    assert result.output.workspace_manifest_digest == manifest_digest


def test_pipeline_handler_missing_path_is_coordination_error(
    tmp_path: Path,
) -> None:
    from openworkproof import repo_tools

    root = tmp_path / "candidate-repo"
    root.mkdir()
    handler = mcp_server.make_repo_pipeline_read_handler()
    command = repo_tools.CandidateReadRequest(
        runtime_root=root,
        workspace_id="c" * 64,
        source_artifact_sha256="b" * 64,
        expected_head_commit="c" * 40,
        expected_workspace_manifest_digest="a" * 64,
        path="missing.py",
    )
    with pytest.raises(
        mcp_server.HandlerCoordinationError, match="REPO_READ_PATH_MISSING"
    ):
        handler(command)


def test_pipeline_handler_rejects_binary_file(tmp_path: Path) -> None:
    from openworkproof import repo_tools

    root = tmp_path / "candidate-repo"
    root.mkdir()
    (root / "bin.dat").write_bytes(b"\x00\x01\xff")
    handler = mcp_server.make_repo_pipeline_read_handler()
    command = repo_tools.CandidateReadRequest(
        runtime_root=root,
        workspace_id="c" * 64,
        source_artifact_sha256="b" * 64,
        expected_head_commit="c" * 40,
        expected_workspace_manifest_digest="a" * 64,
        path="bin.dat",
    )
    with pytest.raises(
        mcp_server.HandlerCoordinationError, match="REPO_READ_READ_FAILED"
    ):
        handler(command)


def test_execute_repo_read_rejects_path_outside_manifest_with_pipeline_handler(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
) -> None:
    """The transaction gate still applies with the pipeline-backed handler."""
    case, context, manifest_digest = _repo_read_case(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        sidecar_receipt_factory,
        fixed_now,
        monkeypatch,
    )
    request, arguments = _repo_read_request(
        case, context, ephemeral_role_keys, fixed_now,
        path="src/main.py",
    )
    handler = mcp_server.make_repo_pipeline_read_handler()
    before = _snapshot_ledger(case)
    with pytest.raises(
        mcp_server.HandlerCoordinationError, match="REPO_READ_PATH_DENIED"
    ):
        mcp_server.execute_repo_read(
            case["ledger_path"],
            evidence_root=case["evidence_root"],
            context=context,
            request=request,
            request_arguments=arguments,
            execution_facts=case["facts"],
            sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
            candidate_runtime_root=tmp_path,
            handler=handler,
            clock=lambda: fixed_now,
        )
    assert _snapshot_ledger(case) == before
