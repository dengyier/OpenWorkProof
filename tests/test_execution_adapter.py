"""Execution adapter layer tests: AgentTeams -> Developer mode loop."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from openworkproof.execution_adapter import (
    ExecutionAdapterError,
    LocalTeamClient,
    TaskState,
    TeamExecutionAdapter,
    TeamTask,
    UnknownTaskKindError,
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


def _repo_read_payload(
    tmp_path, signed_work_order, ephemeral_role_keys, sidecar_receipt_factory, fixed_now, monkeypatch
) -> tuple[Path, dict[str, object]]:
    from test_repo_read_transaction import (
        _repo_read_request,
        _repo_read_success_case,
    )
    from test_mcp_server import _current_run_tests_context

    case, _ = _repo_read_success_case(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        sidecar_receipt_factory,
        fixed_now,
        monkeypatch,
    )
    context = _current_run_tests_context(case, fixed_now)
    request, arguments = _repo_read_request(
        case, context, ephemeral_role_keys, fixed_now, path="src/app.py"
    )
    candidate_root = tmp_path / "candidate-repo"
    (candidate_root / "src").mkdir(parents=True)
    (candidate_root / "src" / "app.py").write_text("import os\n")
    checkpoint = context.replay_checkpoint
    payload = {
        "now": fixed_now.isoformat(),
        "evidence_root": str(case["evidence_root"]),
        "request": request.model_dump(mode="json"),
        "arguments": arguments.model_dump(mode="json"),
        "checkpoint": {
            "head_commit": checkpoint.head_commit,
            "workspace_manifest_digest": checkpoint.workspace_manifest_digest,
            "workspace_manifest": {
                "schema_version": checkpoint.workspace_manifest.schema_version,
                "head_commit": checkpoint.workspace_manifest.head_commit,
                "entries": [
                    {
                        "path_bytes_b64url": entry.path_bytes_b64url,
                        "type": entry.type,
                        "posix_mode": entry.posix_mode,
                        "size_bytes": entry.size_bytes,
                        "sha256": entry.sha256,
                        "symlink_target_b64url": entry.symlink_target_b64url,
                    }
                    for entry in checkpoint.workspace_manifest.entries
                ],
            },
        },
        "facts": {
            "execution_context_id": "7" * 64,
            "container_instance_id_digest": "8" * 64,
            "controller_id": ephemeral_role_keys["Sidecar"][1]["key_id"],
        },
        "sidecar_key_hex": ephemeral_role_keys["Sidecar"][0].private_bytes(
            __import__("cryptography.hazmat.primitives", fromlist=["serialization"]).serialization.Encoding.Raw,
            __import__("cryptography.hazmat.primitives", fromlist=["serialization"]).serialization.PrivateFormat.Raw,
            __import__("cryptography.hazmat.primitives", fromlist=["serialization"]).serialization.NoEncryption(),
        ).hex(),
        "candidate_runtime_root": str(candidate_root),
    }
    return case["ledger_path"], payload


def test_adapter_closes_team_to_developer_loop(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
) -> None:
    ledger, payload = _repo_read_payload(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        sidecar_receipt_factory,
        fixed_now,
        monkeypatch,
    )
    client = LocalTeamClient()
    client.dispatch(
        TeamTask(task_id="t-1", kind="repo_read", ledger=str(ledger), payload=payload)
    )
    adapter = TeamExecutionAdapter(client)
    outcomes = adapter.run_pending_tasks()
    assert len(outcomes) == 1
    assert outcomes[0].task_id == "t-1"
    assert outcomes[0].status == TaskState.SUCCEEDED
    assert outcomes[0].result["tool_name"] == "owp.repo_read"
    assert outcomes[0].result["execution_status"] == "succeeded"
    collected = client.collect()
    assert len(collected) == 1
    assert collected[0].task_id == "t-1"


def test_adapter_status_task_round_trip(
    tmp_path, signed_work_order, ephemeral_role_keys, sidecar_receipt_factory, fixed_now
) -> None:
    from test_mcp_server import _run_tests_case

    case = _run_tests_case(
        tmp_path=tmp_path,
        signed_work_order=signed_work_order,
        role_keys=ephemeral_role_keys,
        sidecar_receipt_factory=sidecar_receipt_factory,
        now=fixed_now,
    )
    client = LocalTeamClient()
    client.dispatch(
        TeamTask(task_id="t-s", kind="status", ledger=str(case["ledger_path"]))
    )
    adapter = TeamExecutionAdapter(client)
    (outcome,) = adapter.run_pending_tasks()
    assert outcome.status == TaskState.SUCCEEDED
    assert outcome.result["current_state"] == "running"


def test_adapter_failed_task_has_stable_error_code(
    tmp_path, signed_work_order, ephemeral_role_keys, sidecar_receipt_factory, fixed_now
) -> None:
    from test_mcp_server import _run_tests_case

    case = _run_tests_case(
        tmp_path=tmp_path,
        signed_work_order=signed_work_order,
        role_keys=ephemeral_role_keys,
        sidecar_receipt_factory=sidecar_receipt_factory,
        now=fixed_now,
    )
    client = LocalTeamClient()
    client.dispatch(
        TeamTask(
            task_id="t-bad",
            kind="run_tests",
            ledger=str(case["ledger_path"]),
            payload={"now": fixed_now.isoformat()},
        )
    )
    adapter = TeamExecutionAdapter(client)
    (outcome,) = adapter.run_pending_tasks()
    assert outcome.status == TaskState.FAILED
    assert outcome.error == "CLI_TRANSPORT_ERROR"


def test_adapter_rejects_unknown_kind() -> None:
    client = LocalTeamClient()
    adapter = TeamExecutionAdapter(client)
    task = TeamTask(task_id="t-x", kind="fly_to_moon", ledger="/tmp/x.sqlite3")
    with pytest.raises(UnknownTaskKindError):
        adapter.execute_task(task)


def test_adapter_rejects_broken_client_contract() -> None:
    class Broken:
        def dispatch(self, task):
            pass

    with pytest.raises(ExecutionAdapterError, match="team client contract"):
        TeamExecutionAdapter(Broken())


def test_adapter_execute_task_tracks_running_state(
    tmp_path, signed_work_order, ephemeral_role_keys, sidecar_receipt_factory, fixed_now
) -> None:
    from test_mcp_server import _run_tests_case

    case = _run_tests_case(
        tmp_path=tmp_path,
        signed_work_order=signed_work_order,
        role_keys=ephemeral_role_keys,
        sidecar_receipt_factory=sidecar_receipt_factory,
        now=fixed_now,
    )
    client = LocalTeamClient()
    adapter = TeamExecutionAdapter(client)
    task = TeamTask(task_id="t-r", kind="status", ledger=str(case["ledger_path"]))
    outcome = adapter.execute_task(task)
    assert outcome.status == TaskState.SUCCEEDED
    assert task.task_id not in adapter._running
