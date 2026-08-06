"""Execution adapter layer between AgentTeams and the OpenWorkProof
Developer-mode coordinators.

The adapter closes the AgentTeams <-> Developer mode loop:

- **AgentTeams side**: a team client dispatches ``TeamTask`` objects and
  collects ``TeamTaskResult`` objects (team collaboration: assign, execute,
  gather).
- **Developer side**: the protocol coordinators execute the task payload
  (repo read, developer-mode test run, ledger status).
- **Adapter**: converts task payloads into coordinator calls, adapts results
  back into team results, keeps task state in sync (PENDING -> RUNNING ->
  SUCCEEDED/FAILED), isolates handler failures into stable error codes, and
  logs every transition.

The layer is deliberately transport-free: any team client implementing
``AgentTeamClient`` (local, network, or future AgentTeams SDK) plugs in
unchanged.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import logging
from pathlib import Path
from typing import Protocol

_logger = logging.getLogger("openworkproof.execution_adapter")

SUPPORTED_KINDS = frozenset({"repo_read", "run_tests", "status"})


class TaskState(Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ExecutionAdapterError(Exception):
    """Base class for adapter-layer failures."""


class UnknownTaskKindError(ExecutionAdapterError):
    """The task kind is not supported by the adapter."""


class InvalidTaskError(ExecutionAdapterError):
    """The task payload or ledger reference is malformed."""


class TaskDispatchError(ExecutionAdapterError):
    """The team client rejected the task or its result."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True, slots=True)
class TeamTask:
    """One unit of work assigned by a team to the Developer mode."""

    task_id: str
    kind: str
    ledger: str
    payload: dict[str, object] = field(default_factory=dict)
    state: TaskState = TaskState.PENDING
    created_at: str = field(default_factory=_utc_now)

    def with_state(self, state: TaskState) -> "TeamTask":
        return TeamTask(
            task_id=self.task_id,
            kind=self.kind,
            ledger=self.ledger,
            payload=self.payload,
            state=state,
            created_at=self.created_at,
        )


@dataclass(frozen=True, slots=True)
class TeamTaskResult:
    """The outcome of one team task after adapter execution."""

    task_id: str
    kind: str
    status: TaskState
    result: dict[str, object] = field(default_factory=dict)
    error: str | None = None


class AgentTeamClient(Protocol):
    """Team-collaboration contract the adapter depends on."""

    def dispatch(self, task: TeamTask) -> None: ...

    def collect(self) -> tuple[TeamTaskResult, ...]: ...

    def list_pending(self) -> tuple[TeamTask, ...]: ...

    def store_result(self, result: TeamTaskResult) -> None: ...


class LocalTeamClient:
    """In-process team client for local and single-host deployment.

    Tasks are dispatched into a FIFO queue and results are collected after
    the adapter runs them. This is the reference implementation of
    ``AgentTeamClient`` and is used by the adapter tests.
    """

    def __init__(self) -> None:
        self._queue: deque[TeamTask] = deque()
        self._results: dict[str, TeamTaskResult] = {}

    def dispatch(self, task: TeamTask) -> None:
        self._queue.append(task)
        _logger.debug("dispatched task %s (%s)", task.task_id, task.kind)

    def collect(self) -> tuple[TeamTaskResult, ...]:
        results = tuple(self._results.values())
        self._results.clear()
        return results

    def list_pending(self) -> tuple[TeamTask, ...]:
        return tuple(self._queue)

    def store_result(self, result: TeamTaskResult) -> None:
        self._results[result.task_id] = result

    def _pop_pending(self) -> TeamTask | None:
        return self._queue.popleft() if self._queue else None


class TeamExecutionAdapter:
    """Converts team tasks into Developer-mode coordinator calls and back.

    Responsibilities:

    - dispatch routing: task ``kind`` selects the coordinator call;
    - data conversion: task payload (protocol JSON) -> coordinator input,
      coordinator result -> ``TeamTaskResult``;
    - state synchronisation: PENDING -> RUNNING -> SUCCEEDED / FAILED;
    - error isolation: handler failures become stable error codes;
    - graded logging of every transition.
    """

    def __init__(self, client: AgentTeamClient) -> None:
        if not callable(getattr(client, "dispatch", None)) or not callable(
            getattr(client, "collect", None)
        ):
            raise ExecutionAdapterError("team client contract is unavailable")
        self._client = client
        self._running: dict[str, TeamTask] = {}

    @property
    def client(self) -> AgentTeamClient:
        return self._client

    def execute_task(self, task: TeamTask) -> TeamTaskResult:
        """Execute one task through the Developer-mode coordinators."""
        if task.kind not in SUPPORTED_KINDS:
            raise UnknownTaskKindError(f"unsupported task kind: {task.kind}")
        self._running[task.task_id] = task.with_state(TaskState.RUNNING)
        _logger.info(
            "task %s running (%s, ledger=%s)",
            task.task_id,
            task.kind,
            task.ledger,
        )
        try:
            if task.kind == "repo_read":
                result = self._run_repo_read(task)
            elif task.kind == "run_tests":
                result = self._run_run_tests(task)
            elif task.kind == "status":
                result = self._run_status(task)
            else:  # pragma: no cover - guarded by SUPPORTED_KINDS
                raise UnknownTaskKindError(f"unsupported task kind: {task.kind}")
        except Exception as error:  # noqa: BLE001
            _logger.error("task %s failed: %s", task.task_id, error)
            outcome = TeamTaskResult(
                task_id=task.task_id,
                kind=task.kind,
                status=TaskState.FAILED,
                error=_error_code(error),
            )
        else:
            _logger.info("task %s succeeded", task.task_id)
            outcome = TeamTaskResult(
                task_id=task.task_id,
                kind=task.kind,
                status=TaskState.SUCCEEDED,
                result=result,
            )
        self._running.pop(task.task_id, None)
        return outcome

    def run_pending_tasks(
        self, *, max_tasks: int | None = None
    ) -> tuple[TeamTaskResult, ...]:
        """Drain the team queue: dispatch, execute, and stage results.

        Returns the executed results after they are handed back to the team
        client via ``collect``.
        """
        pending = self._client.list_pending()
        if max_tasks is not None:
            pending = pending[:max_tasks]
        outcomes: list[TeamTaskResult] = []
        for task in pending:
            outcome = self.execute_task(task)
            if not callable(getattr(self._client, "store_result", None)):
                raise TaskDispatchError("team client cannot store results")
            self._client.store_result(outcome)
            outcomes.append(outcome)
        return tuple(outcomes)

    # ---- coordinator routing -------------------------------------------------

    def _run_repo_read(self, task: TeamTask) -> dict[str, object]:
        from openworkproof import cli

        return _strip_schema(cli.cli_repo_read(task.ledger, task.payload))

    def _run_run_tests(self, task: TeamTask) -> dict[str, object]:
        from openworkproof import cli

        return _strip_schema(cli.cli_run_tests(task.ledger, task.payload))

    def _run_status(self, task: TeamTask) -> dict[str, object]:
        from openworkproof import cli

        return _strip_schema(cli.cli_status(task.ledger))


def _strip_schema(result: dict[str, object]) -> dict[str, object]:
    return {key: value for key, value in result.items() if key != "schema_version"}


def _error_code(error: Exception) -> str:
    from openworkproof.cli import CliError
    from openworkproof.mcp_server import HandlerCoordinationError

    if isinstance(error, CliError):
        return "CLI_TRANSPORT_ERROR"
    if isinstance(error, HandlerCoordinationError):
        return "HANDLER_COORDINATION_ERROR"
    if isinstance(error, UnknownTaskKindError):
        return "UNKNOWN_TASK_KIND"
    return "INTERNAL_ERROR"
