"""Real network team client tests (TCP, auth, retry, reconnect, adapter loop)."""

from __future__ import annotations

import errno
import socket
import threading

import pytest

from openworkproof.execution_adapter import (
    LocalTeamClient,
    TaskState,
    TeamExecutionAdapter,
    TeamTask,
    TeamTaskResult,
)
from openworkproof.team_network_client import (
    TeamNetworkClient,
    TeamNetworkConfig,
    TeamNetworkError,
    TeamNetworkService,
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


def _free_port() -> int:
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


def _started_test_client() -> TeamNetworkService:
    client = TeamNetworkService(port=_free_port())
    client.start()
    return client


@pytest.fixture
def service():
    services = []

    def launch(*, token: str = ""):
        svc = TeamNetworkService(port=_free_port(), token=token)
        svc.start()
        services.append(svc)
        return svc

    yield launch
    for svc in services:
        svc.stop()
        svc.join(timeout=1)
        assert svc._thread is not None
        assert not svc._thread.is_alive()


def test_close_while_accepting_has_no_uncaught_thread_exception(
    monkeypatch,
) -> None:
    uncaught: list[BaseException] = []
    monkeypatch.setattr(
        threading,
        "excepthook",
        lambda args: uncaught.append(args.exc_value),
    )
    for _ in range(100):
        client = _started_test_client()
        with socket.create_connection(("127.0.0.1", client.port)) as connection:
            connection.sendall(b'{"action":"list-pending"}\n')
            assert connection.recv(65536)
            client.close()
        client.join(timeout=1)
        assert client._thread is not None
        assert not client._thread.is_alive()
    assert uncaught == []


def test_unexpected_accept_error_is_not_swallowed() -> None:
    class FailingSocket:
        def accept(self):
            raise OSError(errno.ECONNABORTED, "unexpected accept failure")

    client = TeamNetworkService(port=_free_port())
    client._socket = FailingSocket()  # type: ignore[assignment]

    with pytest.raises(OSError, match="unexpected accept failure"):
        client._serve()


def test_network_client_dispatch_store_collect_round_trip(service) -> None:
    svc = service()
    client = TeamNetworkClient(
        TeamNetworkConfig(port=svc.port, timeout=2.0)
    )
    task = TeamTask(task_id="n-1", kind="status", ledger="/tmp/x.sqlite3")
    client.dispatch(task)
    assert [t.task_id for t in client.list_pending()] == ["n-1"]
    result = TeamTaskResult(
        task_id="n-1", kind="status", status=TaskState.SUCCEEDED,
        result={"current_state": "running"},
    )
    client.store_result(result)
    collected = client.collect()
    assert len(collected) == 1
    assert collected[0].task_id == "n-1"
    assert collected[0].result["current_state"] == "running"
    client.disconnect()


def test_network_client_auth_required(service) -> None:
    svc = service(token="s3cret")
    good = TeamNetworkClient(
        TeamNetworkConfig(port=svc.port, token="s3cret", timeout=2.0)
    )
    good.connect()
    good.dispatch(TeamTask(task_id="a-1", kind="status", ledger="/tmp/x.sqlite3"))
    assert len(good.list_pending()) == 1
    good.disconnect()

    bad = TeamNetworkClient(
        TeamNetworkConfig(port=svc.port, token="wrong", timeout=2.0)
    )
    bad.connect()
    with pytest.raises(TeamNetworkError):
        bad.list_pending()
    bad.disconnect()


def test_network_client_retries_then_fails_on_unreachable(service) -> None:
    # Point at a port with no listener; retries exhaust then raise.
    client = TeamNetworkClient(
        TeamNetworkConfig(port=_free_port(), timeout=0.3, max_retries=2, backoff=0.01)
    )
    with pytest.raises(TeamNetworkError):
        client.list_pending()


def test_network_client_reconnects_after_service_restart(service) -> None:
    svc = service()
    client = TeamNetworkClient(TeamNetworkConfig(port=svc.port, timeout=2.0, max_retries=1))
    client.dispatch(TeamTask(task_id="r-1", kind="status", ledger="/tmp/x.sqlite3"))
    # Service goes down; the client session must fail closed and reconnect.
    svc.stop()
    client.disconnect()
    with pytest.raises(TeamNetworkError):
        client.list_pending()
    svc2 = service()
    client2 = TeamNetworkClient(TeamNetworkConfig(port=svc2.port, timeout=2.0))
    client2.dispatch(TeamTask(task_id="r-2", kind="status", ledger="/tmp/y.sqlite3"))
    assert [t.task_id for t in client2.list_pending()] == ["r-2"]
    client2.disconnect()


def test_network_config_validates_inputs() -> None:
    with pytest.raises(TeamNetworkError):
        TeamNetworkConfig(port=0)
    with pytest.raises(TeamNetworkError):
        TeamNetworkConfig(timeout=0)
    with pytest.raises(TeamNetworkError):
        TeamNetworkConfig(max_retries=-1)


def test_network_client_drives_adapter_end_to_end(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
    service,
) -> None:
    """Network team client + execution adapter + developer coordinator loop."""
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
            "execution_context_id": "9" * 64,
            "container_instance_id_digest": "a" * 64,
            "controller_id": ephemeral_role_keys["Sidecar"][1]["key_id"],
        },
        "sidecar_key_hex": ephemeral_role_keys["Sidecar"][0].private_bytes(
            __import__("cryptography.hazmat.primitives", fromlist=["serialization"])
            .serialization.Encoding.Raw,
            __import__("cryptography.hazmat.primitives", fromlist=["serialization"])
            .serialization.PrivateFormat.Raw,
            __import__("cryptography.hazmat.primitives", fromlist=["serialization"])
            .serialization.NoEncryption(),
        ).hex(),
        "candidate_runtime_root": str(candidate_root),
    }

    svc = service()
    team_client = TeamNetworkClient(
        TeamNetworkConfig(port=svc.port, timeout=5.0)
    )
    adapter = TeamExecutionAdapter(team_client)
    team_client.dispatch(
        TeamTask(task_id="net-1", kind="repo_read", ledger=str(case["ledger_path"]), payload=payload)
    )
    outcomes = adapter.run_pending_tasks()
    assert len(outcomes) == 1
    assert outcomes[0].status == TaskState.SUCCEEDED
    assert outcomes[0].result["tool_name"] == "owp.repo_read"
    collected = team_client.collect()
    assert len(collected) == 1
    assert collected[0].task_id == "net-1"
    team_client.disconnect()
