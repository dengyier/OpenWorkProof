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


class _BlockingAcceptSocket:
    def __init__(self) -> None:
        self.accept_entered = threading.Event()
        self.accept_release = threading.Event()
        self.listen_entered = threading.Event()
        self.listen_release = threading.Event()
        self.pause_listen = False
        self.shutdown_calls: list[int] = []
        self.close_calls = 0

    def setsockopt(self, *args) -> None:
        pass

    def bind(self, address) -> None:
        pass

    def listen(self, backlog: int) -> None:
        self.listen_entered.set()
        if self.pause_listen:
            assert self.listen_release.wait(timeout=1)

    def accept(self):
        self.accept_entered.set()
        assert self.accept_release.wait(timeout=2)
        raise OSError(errno.EBADF, "listener closed")

    def shutdown(self, how: int) -> None:
        self.shutdown_calls.append(how)
        self.accept_release.set()

    def close(self) -> None:
        self.close_calls += 1


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
        connection = None
        try:
            connection = socket.create_connection(("127.0.0.1", client.port))
            connection.sendall(b'{"action":"list-pending"}\n')
            assert connection.recv(65536)
            client.close()
            connection.close()
            connection = None
            client.join(timeout=1)
            assert client._thread is not None
            assert not client._thread.is_alive()
        finally:
            if connection is not None:
                connection.close()
            client.close()
            client.join(timeout=1)
    assert uncaught == []


def test_blocked_accept_is_woken_before_listener_close(monkeypatch) -> None:
    service_socket = _BlockingAcceptSocket()
    monkeypatch.setattr(socket, "socket", lambda *args, **kwargs: service_socket)
    client = TeamNetworkService(port=1)

    try:
        client.start()
        assert service_socket.accept_entered.wait(timeout=1)
        client.close()
        client.join(timeout=1)
        assert service_socket.shutdown_calls == [socket.SHUT_RDWR]
        assert service_socket.close_calls == 1
        assert client._thread is not None
        assert not client._thread.is_alive()
    finally:
        service_socket.accept_release.set()
        client.close()
        client.join(timeout=1)


def test_real_socket_close_wakes_worker_blocked_in_accept(monkeypatch) -> None:
    accept_entered = threading.Event()
    real_socket_type = socket.socket

    class AcceptBarrierSocket(real_socket_type):
        def accept(self):
            accept_entered.set()
            return super().accept()

    monkeypatch.setattr(socket, "socket", AcceptBarrierSocket)
    client = TeamNetworkService(port=_free_port())

    try:
        client.start()
        assert accept_entered.wait(timeout=1)
        client.close()
        client.join(timeout=1)
        assert client._thread is not None
        assert not client._thread.is_alive()
    finally:
        client.close()
        client.join(timeout=1)


def test_start_and_close_are_serialized(monkeypatch) -> None:
    service_socket = _BlockingAcceptSocket()
    service_socket.pause_listen = True
    monkeypatch.setattr(socket, "socket", lambda *args, **kwargs: service_socket)
    client = TeamNetworkService(port=1)
    close_lock_classified = threading.Event()

    class TrackingLock:
        def __init__(self) -> None:
            self._lock = threading.Lock()

        def __enter__(self):
            if threading.current_thread().name == "close-caller":
                acquired = self._lock.acquire(blocking=False)
                close_lock_classified.set()
                if not acquired:
                    self._lock.acquire()
            else:
                self._lock.acquire()
            return self

        def __exit__(self, exc_type, exc_value, traceback) -> None:
            self._lock.release()

    client._lifecycle_lock = TrackingLock()  # type: ignore[assignment]
    start_errors: list[BaseException] = []
    close_errors: list[BaseException] = []

    def start_client() -> None:
        try:
            client.start()
        except BaseException as error:
            start_errors.append(error)

    def close_client() -> None:
        try:
            client.close()
        except BaseException as error:
            close_errors.append(error)

    start_thread = threading.Thread(target=start_client, name="start-caller")
    close_thread = threading.Thread(target=close_client, name="close-caller")
    try:
        start_thread.start()
        assert service_socket.listen_entered.wait(timeout=1)
        close_thread.start()
        assert close_lock_classified.wait(timeout=1)
        service_socket.listen_release.set()
        start_thread.join(timeout=1)
        close_thread.join(timeout=1)
        client.join(timeout=1)
        assert start_errors == []
        assert close_errors == []
        assert not start_thread.is_alive()
        assert not close_thread.is_alive()
        assert client._thread is not None
        assert not client._thread.is_alive()
    finally:
        service_socket.listen_release.set()
        service_socket.accept_release.set()
        client.close()
        client.join(timeout=1)
        start_thread.join(timeout=1)
        close_thread.join(timeout=1)


def test_start_after_completed_close_is_rejected() -> None:
    client = TeamNetworkService(port=_free_port())
    client.close()

    with pytest.raises(RuntimeError, match="closed"):
        client.start()


def test_join_cannot_observe_an_unstarted_service_thread(monkeypatch) -> None:
    service_socket = _BlockingAcceptSocket()
    monkeypatch.setattr(socket, "socket", lambda *args, **kwargs: service_socket)
    real_thread_type = threading.Thread
    service_start_entered = threading.Event()
    service_start_release = threading.Event()
    join_lock_attempted = threading.Event()

    class BarrierThread(real_thread_type):
        def start(self) -> None:
            service_start_entered.set()
            assert service_start_release.wait(timeout=1)
            super().start()

    class TrackingLock:
        def __init__(self) -> None:
            self._lock = threading.Lock()

        def __enter__(self):
            if threading.current_thread().name == "join-caller":
                join_lock_attempted.set()
            self._lock.acquire()
            return self

        def __exit__(self, exc_type, exc_value, traceback) -> None:
            self._lock.release()

    client = TeamNetworkService(port=1)
    client._lifecycle_lock = TrackingLock()  # type: ignore[assignment]
    monkeypatch.setattr(threading, "Thread", BarrierThread)
    start_errors: list[BaseException] = []
    join_errors: list[BaseException] = []

    def capture(operation, errors: list[BaseException]) -> None:
        try:
            operation()
        except BaseException as error:
            errors.append(error)

    start_thread = real_thread_type(
        target=lambda: capture(client.start, start_errors),
        name="start-caller",
    )
    join_thread = real_thread_type(
        target=lambda: capture(lambda: client.join(timeout=0), join_errors),
        name="join-caller",
    )
    try:
        start_thread.start()
        assert service_start_entered.wait(timeout=1)
        join_thread.start()
        assert join_lock_attempted.wait(timeout=1)
        service_start_release.set()
        start_thread.join(timeout=1)
        join_thread.join(timeout=1)
        assert start_errors == []
        assert join_errors == []
    finally:
        service_start_release.set()
        service_socket.accept_release.set()
        client.close()
        client.join(timeout=1)
        start_thread.join(timeout=1)
        join_thread.join(timeout=1)


def test_start_closes_local_socket_when_setup_fails(monkeypatch) -> None:
    service_socket = _BlockingAcceptSocket()

    def fail_bind(address) -> None:
        raise OSError(errno.EADDRINUSE, "address already in use")

    service_socket.bind = fail_bind  # type: ignore[method-assign]
    monkeypatch.setattr(socket, "socket", lambda *args, **kwargs: service_socket)
    client = TeamNetworkService(port=1)

    with pytest.raises(OSError, match="address already in use"):
        client.start()

    assert service_socket.close_calls == 1
    assert client._socket is None
    assert client._thread is None


def test_start_failure_does_not_publish_unstarted_thread(monkeypatch) -> None:
    service_socket = _BlockingAcceptSocket()
    monkeypatch.setattr(socket, "socket", lambda *args, **kwargs: service_socket)

    class FailingThread:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def start(self) -> None:
            raise RuntimeError("thread start failed")

    monkeypatch.setattr(threading, "Thread", FailingThread)
    client = TeamNetworkService(port=1)

    with pytest.raises(RuntimeError, match="thread start failed"):
        client.start()

    assert service_socket.close_calls == 1
    assert client._socket is None
    assert client._thread is None


@pytest.mark.parametrize(
    "error_number",
    (
        errno.EBADF,
        errno.ECONNABORTED,
        errno.EINVAL,
        errno.ENOTSOCK,
        getattr(errno, "WSAENOTSOCK", 10038),
    ),
)
def test_allowlisted_accept_error_is_normal_only_after_stop(error_number) -> None:
    class FailingSocket:
        def accept(self):
            raise OSError(error_number, "listener closed")

    client = TeamNetworkService(port=_free_port())
    client._socket = FailingSocket()  # type: ignore[assignment]
    client._stop_event.set()

    client._serve()


def test_allowlisted_accept_error_before_stop_is_not_swallowed() -> None:
    class FailingSocket:
        def accept(self):
            raise OSError(errno.EBADF, "unexpected accept failure")

    client = TeamNetworkService(port=_free_port())
    client._socket = FailingSocket()  # type: ignore[assignment]

    with pytest.raises(OSError, match="unexpected accept failure"):
        client._serve()


def test_unexpected_accept_error_after_stop_is_not_swallowed() -> None:
    class FailingSocket:
        def accept(self):
            raise OSError(errno.EIO, "unexpected accept failure")

    client = TeamNetworkService(port=_free_port())
    client._socket = FailingSocket()  # type: ignore[assignment]
    client._stop_event.set()

    with pytest.raises(OSError, match="unexpected accept failure"):
        client._serve()


def test_close_propagates_unexpected_shutdown_error_after_close_attempt() -> None:
    service_socket = _BlockingAcceptSocket()

    def fail_shutdown(how: int) -> None:
        raise OSError(errno.EIO, "shutdown failed")

    service_socket.shutdown = fail_shutdown  # type: ignore[method-assign]
    client = TeamNetworkService(port=_free_port())
    client._socket = service_socket  # type: ignore[assignment]

    with pytest.raises(OSError, match="shutdown failed"):
        client.close()

    assert service_socket.close_calls == 1


@pytest.mark.parametrize("operation", ("shutdown", "close"))
def test_close_suppresses_only_allowlisted_cleanup_error(operation) -> None:
    service_socket = _BlockingAcceptSocket()

    if operation == "shutdown":
        def fail_shutdown(how: int) -> None:
            service_socket.shutdown_calls.append(how)
            raise OSError(errno.EBADF, "closed")

        service_socket.shutdown = fail_shutdown  # type: ignore[method-assign]
    else:
        def fail_close() -> None:
            service_socket.close_calls += 1
            raise OSError(errno.EBADF, "closed")

        service_socket.close = fail_close  # type: ignore[method-assign]
    client = TeamNetworkService(port=_free_port())
    client._socket = service_socket  # type: ignore[assignment]

    client.close()

    assert service_socket.shutdown_calls == [socket.SHUT_RDWR]
    assert service_socket.close_calls == 1


def test_close_propagates_unexpected_close_error() -> None:
    service_socket = _BlockingAcceptSocket()

    def fail_close() -> None:
        service_socket.close_calls += 1
        raise OSError(errno.EIO, "close failed")

    service_socket.close = fail_close  # type: ignore[method-assign]
    client = TeamNetworkService(port=_free_port())
    client._socket = service_socket  # type: ignore[assignment]

    with pytest.raises(OSError, match="close failed"):
        client.close()

    assert service_socket.shutdown_calls == [socket.SHUT_RDWR]
    assert service_socket.close_calls == 1


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
