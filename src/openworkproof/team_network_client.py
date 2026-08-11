"""Real network client for the AgentTeams execution layer.

The client implements the ``AgentTeamClient`` contract (see
``execution_adapter``) over a real TCP connection, so the team -> developer
loop works across processes and hosts, not just in-memory.

Network protocol (JSON lines over a persistent TCP session):

- ``{"action": "auth", "token": <str>}``         -> ``{"ok": true}``
- ``{"action": "dispatch", "task": <TeamTask>}``  -> ``{"ok": true}``
- ``{"action": "list-pending"}``                 -> ``{"ok": true, "tasks": [...]}``
- ``{"action": "store-result", "result": <...>}``-> ``{"ok": true}``
- ``{"action": "collect"}``                      -> ``{"ok": true, "results": [...]}``

Config comes from environment variables so the client deploys unchanged:

- ``OWP_TEAM_ENDPOINT``  — ``host:port`` (default ``127.0.0.1:18742``)
- ``OWP_TEAM_TOKEN``     — shared auth token (empty disables auth)
- ``OWP_TEAM_TIMEOUT``   — socket timeout seconds (default 5.0)
- ``OWP_TEAM_MAX_RETRIES`` — connect/request retries (default 3)

Note on the Alibaba Cloud AgentTeams SDK: a public SDK exists
(``@alicloud/agentteams20260605``) but currently ships only TypeScript/Java/
Swift/PHP, and its API surface is the governance/management plane
(workspaces, identity, policy) rather than task dispatch/recovery. Until a
Python SDK with an execution-plane API is published, this module provides the
real network transport for the task lifecycle over a documented protocol; the
adapter boundary in ``execution_adapter.py`` is where a future SDK would plug
in without changing the business layer.
"""

from __future__ import annotations

import errno
import json
import logging
import os
from pathlib import Path
import socket
import threading
import time
from typing import Any

from openworkproof.execution_adapter import (
    TaskState,
    TeamTask,
    TeamTaskResult,
)

_logger = logging.getLogger("openworkproof.team_network_client")

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 18742
DEFAULT_TIMEOUT = 5.0
DEFAULT_MAX_RETRIES = 3
DEFAULT_BACKOFF = 0.2

_ACTION_PATHS = frozenset(
    {"auth", "dispatch", "list-pending", "store-result", "collect"}
)
_CLOSED_SOCKET_ERRNOS = frozenset(
    {
        errno.EBADF,
        errno.ECONNABORTED,
        errno.EINVAL,
        errno.ENOTSOCK,
        getattr(errno, "WSAENOTSOCK", 10038),
    }
)
_SOCKET_CLEANUP_ERRNOS = _CLOSED_SOCKET_ERRNOS | {errno.ENOTCONN}


class TeamNetworkError(Exception):
    """Base class for network-layer team client failures."""


class TeamAuthenticationError(TeamNetworkError):
    """The remote team service rejected the auth token."""


class TeamTimeoutError(TeamNetworkError):
    """A request exceeded the configured timeout."""


class TeamProtocolError(TeamNetworkError):
    """The remote service returned a malformed or refused response."""


class TeamNetworkConfig:
    """Resolved client configuration (env-overridable)."""

    def __init__(
        self,
        *,
        host: str = DEFAULT_HOST,
        port: int = DEFAULT_PORT,
        token: str = "",
        timeout: float = DEFAULT_TIMEOUT,
        max_retries: int = DEFAULT_MAX_RETRIES,
        backoff: float = DEFAULT_BACKOFF,
    ) -> None:
        if not isinstance(host, str) or not host:
            raise TeamNetworkError("team endpoint host is invalid")
        if type(port) is not int or not 1 <= port <= 65535:
            raise TeamNetworkError("team endpoint port is invalid")
        if type(timeout) not in {int, float} or timeout <= 0:
            raise TeamNetworkError("team timeout is invalid")
        if type(max_retries) is not int or max_retries < 0:
            raise TeamNetworkError("team max retries is invalid")
        if type(backoff) not in {int, float} or backoff < 0:
            raise TeamNetworkError("team backoff is invalid")
        self.host = host
        self.port = port
        self.token = token
        self.timeout = timeout
        self.max_retries = max_retries
        self.backoff = backoff

    @classmethod
    def from_env(cls) -> "TeamNetworkConfig":
        endpoint = os.environ.get("OWP_TEAM_ENDPOINT")
        host, port = DEFAULT_HOST, DEFAULT_PORT
        if endpoint:
            parts = endpoint.rsplit(":", 1)
            if len(parts) == 2 and parts[1].isdigit():
                host, port = parts[0], int(parts[1])
        return cls(
            host=host,
            port=port,
            token=os.environ.get("OWP_TEAM_TOKEN", ""),
            timeout=float(os.environ.get("OWP_TEAM_TIMEOUT", str(DEFAULT_TIMEOUT))),
            max_retries=int(
                os.environ.get("OWP_TEAM_MAX_RETRIES", str(DEFAULT_MAX_RETRIES))
            ),
            backoff=float(os.environ.get("OWP_TEAM_BACKOFF", str(DEFAULT_BACKOFF))),
        )


class TeamNetworkClient:
    """Real TCP client implementing the AgentTeamClient contract."""

    def __init__(self, config: TeamNetworkConfig | None = None) -> None:
        self._config = config or TeamNetworkConfig.from_env()
        self._conn: socket.socket | None = None
        self._lock = threading.Lock()

    # ---- lifecycle ---------------------------------------------------------

    def connect(self) -> None:
        """Open the TCP session and perform the auth handshake."""
        self._ensure_connected()
        if self._config.token:
            self._request({"action": "auth", "token": self._config.token}, authed=False)

    def disconnect(self) -> None:
        with self._lock:
            if self._conn is not None:
                try:
                    self._conn.close()
                except OSError:
                    pass
                self._conn = None

    # ---- AgentTeamClient contract -------------------------------------------

    def dispatch(self, task: TeamTask) -> None:
        self._with_retry(
            lambda: self._request(
                {"action": "dispatch", "task": _task_to_dict(task)}
            )
        )

    def list_pending(self) -> tuple[TeamTask, ...]:
        response = self._with_retry(
            lambda: self._request({"action": "list-pending"})
        )
        return tuple(_task_from_dict(item) for item in response["tasks"])

    def store_result(self, result: TeamTaskResult) -> None:
        self._with_retry(
            lambda: self._request(
                {"action": "store-result", "result": _result_to_dict(result)}
            )
        )

    def collect(self) -> tuple[TeamTaskResult, ...]:
        response = self._with_retry(lambda: self._request({"action": "collect"}))
        return tuple(_result_from_dict(item) for item in response["results"])

    # ---- internals ----------------------------------------------------------

    def _ensure_connected(self) -> socket.socket:
        with self._lock:
            if self._conn is not None:
                return self._conn
            _logger.info(
                "connecting to team service %s:%s",
                self._config.host,
                self._config.port,
            )
            try:
                conn = socket.create_connection(
                    (self._config.host, self._config.port),
                    timeout=self._config.timeout,
                )
            except OSError as error:
                raise TeamNetworkError(
                    f"cannot connect to team service: {error}"
                ) from error
            conn.settimeout(self._config.timeout)
            self._conn = conn
            return conn

    def _request(
        self, request: dict[str, Any], *, authed: bool = True
    ) -> dict[str, Any]:
        conn = self._ensure_connected()
        try:
            conn.sendall((json.dumps(request) + "\n").encode("utf-8"))
            data = conn.recv(65536)
        except socket.timeout as error:
            self.disconnect()
            raise TeamTimeoutError("team request timed out") from error
        except OSError as error:
            self.disconnect()
            raise TeamNetworkError(f"team request failed: {error}") from error
        if not data:
            self.disconnect()
            raise TeamNetworkError("team service closed the connection")
        try:
            response = json.loads(data.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as error:
            self.disconnect()
            raise TeamProtocolError("team response is not JSON") from error
        if authed and not response.get("ok"):
            raise TeamProtocolError(response.get("error", "team refused the request"))
        return response

    def _with_retry(self, operation):
        last_error: Exception | None = None
        for attempt in range(self._config.max_retries + 1):
            try:
                return operation()
            except (TeamNetworkError, TeamTimeoutError) as error:
                last_error = error
                if attempt < self._config.max_retries:
                    self.disconnect()
                    delay = self._config.backoff * (2**attempt)
                    _logger.warning(
                        "team request attempt %d/%d failed: %s; retrying in %.2fs",
                        attempt + 1,
                        self._config.max_retries + 1,
                        error,
                        delay,
                    )
                    time.sleep(delay)
        assert last_error is not None
        raise last_error


def _task_to_dict(task: TeamTask) -> dict[str, Any]:
    return {
        "task_id": task.task_id,
        "kind": task.kind,
        "ledger": task.ledger,
        "payload": task.payload,
        "state": task.state.value,
        "created_at": task.created_at,
    }


def _task_from_dict(data: dict[str, Any]) -> TeamTask:
    return TeamTask(
        task_id=data["task_id"],
        kind=data["kind"],
        ledger=data["ledger"],
        payload=data.get("payload", {}),
        state=TaskState(data["state"]),
        created_at=data.get("created_at", ""),
    )


def _result_to_dict(result: TeamTaskResult) -> dict[str, Any]:
    return {
        "task_id": result.task_id,
        "kind": result.kind,
        "status": result.status.value,
        "result": result.result,
        "error": result.error,
    }


def _result_from_dict(data: dict[str, Any]) -> TeamTaskResult:
    return TeamTaskResult(
        task_id=data["task_id"],
        kind=data["kind"],
        status=TaskState(data["status"]),
        result=data.get("result", {}),
        error=data.get("error"),
    )


class TeamNetworkService:
    """Reference TCP team service implementing the documented protocol."""

    def __init__(
        self,
        *,
        host: str = DEFAULT_HOST,
        port: int = DEFAULT_PORT,
        token: str = "",
    ) -> None:
        self._host = host
        self._port = port
        self._token = token
        self._queue: list[TeamTask] = []
        self._results: dict[str, TeamTaskResult] = {}
        self._socket: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._lifecycle_lock = threading.Lock()
        self._stop_event = threading.Event()

    @property
    def port(self) -> int:
        return self._port

    def start(self) -> None:
        with self._lifecycle_lock:
            if self._stop_event.is_set():
                raise RuntimeError("team service is closed")
            if self._socket is not None or self._thread is not None:
                raise RuntimeError("team service is already started")
            service_socket: socket.socket | None = None
            try:
                service_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                service_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                service_socket.bind((self._host, self._port))
                service_socket.listen(4)
                thread = threading.Thread(target=self._serve, daemon=True)
                self._socket = service_socket
                thread.start()
            except BaseException:
                self._socket = None
                self._thread = None
                if service_socket is not None:
                    try:
                        service_socket.close()
                    except OSError:
                        _logger.exception(
                            "failed to close team service socket after start failure"
                        )
                raise
            self._thread = thread

    def stop(self) -> None:
        self.close()

    def close(self) -> None:
        self._stop_event.set()
        with self._lifecycle_lock:
            service_socket = self._socket
            self._socket = None
        if service_socket is not None:
            try:
                service_socket.shutdown(socket.SHUT_RDWR)
            except OSError as error:
                if error.errno not in _SOCKET_CLEANUP_ERRNOS:
                    shutdown_error: OSError | None = error
                else:
                    shutdown_error = None
            else:
                shutdown_error = None
            try:
                service_socket.close()
            except OSError as error:
                if error.errno not in _SOCKET_CLEANUP_ERRNOS:
                    if shutdown_error is None:
                        shutdown_error = error
                    else:
                        _logger.error(
                            "team service socket close also failed: %s",
                            error,
                        )
            if shutdown_error is not None:
                raise shutdown_error

    def join(self, timeout: float | None = None) -> None:
        with self._lifecycle_lock:
            thread = self._thread
        if thread is not None:
            thread.join(timeout=timeout)

    def _serve(self) -> None:
        while True:
            with self._lifecycle_lock:
                service_socket = self._socket
            if service_socket is None:
                if self._stop_event.is_set():
                    return
                raise RuntimeError("team service socket is not available")
            try:
                conn, _ = service_socket.accept()
            except OSError as error:
                if (
                    self._stop_event.is_set()
                    and error.errno in _CLOSED_SOCKET_ERRNOS
                ):
                    return
                raise
            try:
                self._handle(conn)
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

    def _handle(self, conn: socket.socket) -> None:
        authed = not self._token
        while True:
            try:
                data = conn.recv(65536)
            except OSError:
                return
            if not data:
                return
            for line in data.decode("utf-8").splitlines():
                if not line:
                    continue
                try:
                    request = json.loads(line)
                except ValueError:
                    self._send(conn, {"ok": False, "error": "bad json"})
                    continue
                if request.get("action") == "auth":
                    authed = request.get("token") == self._token
                    self._send(conn, {"ok": authed})
                    continue
                if not authed:
                    self._send(conn, {"ok": False, "error": "not authenticated"})
                    continue
                self._send(conn, self._dispatch(request))

    def _dispatch(self, request: dict[str, Any]) -> dict[str, Any]:
        action = request.get("action")
        if action == "dispatch":
            task = _task_from_dict(request["task"])
            self._queue.append(task)
            _logger.debug("service dispatched task %s", task.task_id)
            return {"ok": True}
        if action == "list-pending":
            return {
                "ok": True,
                "tasks": [_task_to_dict(task) for task in self._queue],
            }
        if action == "store-result":
            result = _result_from_dict(request["result"])
            self._results[result.task_id] = result
            return {"ok": True}
        if action == "collect":
            results = tuple(self._results.values())
            self._results.clear()
            return {
                "ok": True,
                "results": [_result_to_dict(item) for item in results],
            }
        return {"ok": False, "error": f"unknown action: {action}"}

    @staticmethod
    def _send(conn: socket.socket, payload: dict[str, Any]) -> None:
        try:
            conn.sendall((json.dumps(payload) + "\n").encode("utf-8"))
        except OSError:
            pass


def main() -> int:
    """Subprocess entry: ``python -m openworkproof.team_network_client``."""
    endpoint = os.environ.get("OWP_TEAM_ENDPOINT", f"{DEFAULT_HOST}:{DEFAULT_PORT}")
    host, port = endpoint.rsplit(":", 1)
    service = TeamNetworkService(
        host=host,
        port=int(port),
        token=os.environ.get("OWP_TEAM_TOKEN", ""),
    )
    service.start()
    threading.Event().wait()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
