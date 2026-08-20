"""Closed AgentTeams message contract and three-role workflow state machine.

Matrix identities and event ids are adapter provenance.  They become usable
only after exact sender-to-role and role-to-OpenWorkProof-key binding.  The
state machine commits core truth before attempting a platform announcement;
an announcement failure therefore cannot roll back a committed transition.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
import hashlib
import json
from pathlib import PurePosixPath
import re
from typing import Any, Literal

from pydantic import ConfigDict, TypeAdapter, field_validator, model_validator
import rfc8785

from openworkproof.models import Digest64, KeyId, ProtocolModel


AgentTeamsRole = Literal["Manager", "Developer", "Verifier"]
AgentTeamsPhase = Literal["dispatch", "development", "verification"]
AgentTeamsState = Literal[
    "awaiting_dispatch",
    "awaiting_development",
    "awaiting_verification",
    "ready_for_acceptance",
    "not_ready",
]

_MODEL_CONFIG = ConfigDict(
    extra="forbid",
    frozen=True,
    strict=True,
    validate_assignment=True,
    revalidate_instances="subclass-instances",
)
_MATRIX_USER_ID = re.compile(r"^@[^\s:]{1,255}:[^\s]{1,255}$")
_MATRIX_EVENT_ID = re.compile(r"^\$[^\s]{1,511}$")
_TASK_ID_ADAPTER = TypeAdapter(Digest64)


def _closed_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate JSON object key")
        result[name] = value
    return result


class AgentTeamsWorkflowError(RuntimeError):
    """AgentTeams input or workflow transition is not trustworthy."""


class AgentTeamsRoleBinding(ProtocolModel):
    model_config = _MODEL_CONFIG

    role: AgentTeamsRole
    matrix_user_id: str
    openworkproof_key_id: KeyId

    @field_validator("matrix_user_id", mode="before")
    @classmethod
    def _closed_matrix_user_id(cls, value: Any) -> str:
        if type(value) is not str or _MATRIX_USER_ID.fullmatch(value) is None:
            raise ValueError("matrix user id is invalid")
        return value


class AgentTeamsWorkflowMessageV01(ProtocolModel):
    model_config = _MODEL_CONFIG

    schema_version: Literal["openworkproof-agentteams-message/0.1"]
    task_id: Digest64
    event_id: str
    sender: str
    role: AgentTeamsRole
    phase: AgentTeamsPhase
    attempt: Literal[1, 2]
    artifact_path: str | None
    artifact_digest: Digest64 | None
    decision: Literal["VERIFIED", "REFUTED", "UNKNOWN"] | None

    @field_validator("event_id", mode="before")
    @classmethod
    def _closed_event_id(cls, value: Any) -> str:
        if type(value) is not str or _MATRIX_EVENT_ID.fullmatch(value) is None:
            raise ValueError("matrix event id is invalid")
        return value

    @field_validator("sender", mode="before")
    @classmethod
    def _closed_sender(cls, value: Any) -> str:
        if type(value) is not str or _MATRIX_USER_ID.fullmatch(value) is None:
            raise ValueError("matrix sender is invalid")
        return value

    @field_validator("artifact_path", mode="before")
    @classmethod
    def _closed_artifact_path(cls, value: Any) -> str | None:
        if value is None:
            return None
        if (
            type(value) is not str
            or not value
            or len(value.encode("utf-8")) > 1024
            or "\x00" in value
            or "\\" in value
        ):
            raise ValueError("artifact path is invalid")
        parsed = PurePosixPath(value)
        if (
            parsed.is_absolute()
            or ".." in parsed.parts
            or parsed.as_posix() != value
            or value in {".", "./"}
        ):
            raise ValueError("artifact path is invalid")
        return value

    @model_validator(mode="after")
    def _closed_role_payload(self) -> AgentTeamsWorkflowMessageV01:
        expected = {
            "Manager": "dispatch",
            "Developer": "development",
            "Verifier": "verification",
        }[self.role]
        if self.phase != expected:
            raise ValueError("role and phase are inconsistent")
        has_artifact = (
            self.artifact_path is not None and self.artifact_digest is not None
        )
        if (self.artifact_path is None) != (self.artifact_digest is None):
            raise ValueError("artifact path and digest must appear together")
        if self.role == "Manager" and (has_artifact or self.decision is not None):
            raise ValueError("dispatch cannot claim an artifact or decision")
        if self.role == "Developer" and (
            not has_artifact or self.decision is not None
        ):
            raise ValueError("development requires only an artifact")
        if self.role == "Verifier" and (
            not has_artifact or self.decision is None
        ):
            raise ValueError("verification requires an artifact and decision")
        return self


class AgentTeamsWorkflowStateV01(ProtocolModel):
    model_config = _MODEL_CONFIG

    schema_version: Literal["openworkproof-agentteams-state/0.1"]
    task_id: Digest64
    state: AgentTeamsState
    attempt: Literal[1, 2]
    artifact_path: str | None
    artifact_digest: Digest64 | None
    last_event_id: str | None


class AgentTeamsWorkflowOutcome(ProtocolModel):
    model_config = _MODEL_CONFIG

    schema_version: Literal["openworkproof-agentteams-outcome/0.1"]
    task_id: Digest64
    event_id: str
    state: AgentTeamsState
    attempt: Literal[1, 2]
    openworkproof_key_id: KeyId
    delivery_status: Literal[
        "committed", "announced", "committed_but_unannounced"
    ]


class AgentTeamsCommitAcknowledgementLost(RuntimeError):
    """The core committed an exact state but its acknowledgement was lost."""

    def __init__(self, committed: AgentTeamsWorkflowStateV01) -> None:
        super().__init__("AgentTeams core commit acknowledgement was lost")
        self.committed = committed


CommitCallback = Callable[
    [AgentTeamsWorkflowMessageV01, AgentTeamsWorkflowStateV01], None
]
AnnounceCallback = Callable[
    [AgentTeamsWorkflowMessageV01, AgentTeamsWorkflowStateV01], None
]


class AgentTeamsWorkflow:
    """One-task deterministic Manager -> Developer -> Verifier workflow."""

    def __init__(
        self,
        *,
        task_id: str,
        bindings: Sequence[AgentTeamsRoleBinding],
        commit: CommitCallback | None = None,
        announce: AnnounceCallback | None = None,
    ) -> None:
        try:
            self._task_id = _TASK_ID_ADAPTER.validate_python(task_id)
        except Exception as error:
            raise AgentTeamsWorkflowError("task id is invalid") from error
        if type(bindings) not in {tuple, list} or len(bindings) != 3:
            raise AgentTeamsWorkflowError("three role bindings are required")
        try:
            rebuilt = tuple(
                AgentTeamsRoleBinding.model_validate(
                    item.model_dump(mode="json", warnings="error")
                )
                for item in bindings
            )
        except Exception as error:
            raise AgentTeamsWorkflowError("role binding is invalid") from error
        by_role = {item.role: item for item in rebuilt}
        if set(by_role) != {"Manager", "Developer", "Verifier"}:
            raise AgentTeamsWorkflowError("each AgentTeams role is required")
        if len({item.matrix_user_id for item in rebuilt}) != 3:
            raise AgentTeamsWorkflowError("roles require distinct senders")
        if len({item.openworkproof_key_id for item in rebuilt}) != 3:
            raise AgentTeamsWorkflowError("roles require distinct keys")
        self._bindings = by_role
        self._commit = commit
        self._announce = announce
        self._snapshot = AgentTeamsWorkflowStateV01(
            schema_version="openworkproof-agentteams-state/0.1",
            task_id=self._task_id,
            state="awaiting_dispatch",
            attempt=1,
            artifact_path=None,
            artifact_digest=None,
            last_event_id=None,
        )
        self._events: dict[
            str, tuple[str, AgentTeamsWorkflowOutcome]
        ] = {}

    @property
    def state(self) -> AgentTeamsState:
        return self._snapshot.state

    @property
    def attempt(self) -> Literal[1, 2]:
        return self._snapshot.attempt

    @property
    def snapshot(self) -> AgentTeamsWorkflowStateV01:
        return self._snapshot

    def accept(
        self, message: AgentTeamsWorkflowMessageV01
    ) -> AgentTeamsWorkflowOutcome:
        rebuilt = self._rebuild_message(message)
        if rebuilt.task_id != self._task_id:
            raise AgentTeamsWorkflowError("task id does not match workflow")
        message_digest = hashlib.sha256(
            rfc8785.dumps(rebuilt.model_dump(mode="json"))
        ).hexdigest()
        previous = self._events.get(rebuilt.event_id)
        if previous is not None:
            if previous[0] != message_digest:
                raise AgentTeamsWorkflowError("event id conflict")
            return previous[1]
        binding = self._bindings[rebuilt.role]
        if binding.matrix_user_id != rebuilt.sender:
            raise AgentTeamsWorkflowError("sender binding does not match role")
        if self._snapshot.state in {"ready_for_acceptance", "not_ready"}:
            raise AgentTeamsWorkflowError("workflow is already terminal")
        next_state = self._transition(rebuilt)
        self._commit_core(rebuilt, next_state)
        self._snapshot = next_state
        delivery_status: Literal[
            "committed", "announced", "committed_but_unannounced"
        ] = "committed"
        if self._announce is not None:
            try:
                self._announce(rebuilt, next_state)
            except Exception:
                delivery_status = "committed_but_unannounced"
            else:
                delivery_status = "announced"
        outcome = AgentTeamsWorkflowOutcome(
            schema_version="openworkproof-agentteams-outcome/0.1",
            task_id=self._task_id,
            event_id=rebuilt.event_id,
            state=next_state.state,
            attempt=next_state.attempt,
            openworkproof_key_id=binding.openworkproof_key_id,
            delivery_status=delivery_status,
        )
        self._events[rebuilt.event_id] = (message_digest, outcome)
        return outcome

    def accept_matrix_event(
        self, event: Mapping[str, Any]
    ) -> AgentTeamsWorkflowOutcome:
        if type(event) is not dict or set(event) != {"event_id", "sender", "body"}:
            raise AgentTeamsWorkflowError("Matrix event shape is invalid")
        raw_event_id = event["event_id"]
        raw_sender = event["sender"]
        body = event["body"]
        if type(body) is not str or len(body.encode("utf-8")) > 16 * 1024:
            raise AgentTeamsWorkflowError("message body must be structured JSON")
        try:
            raw = json.loads(body, object_pairs_hook=_closed_json_object)
            if type(raw) is not dict:
                raise ValueError("message body is not an object")
            if "event_id" in raw:
                raise AgentTeamsWorkflowError(
                    "message body must not claim event id"
                )
            raw["event_id"] = raw_event_id
            message = AgentTeamsWorkflowMessageV01.model_validate(raw)
        except AgentTeamsWorkflowError:
            raise
        except Exception as error:
            raise AgentTeamsWorkflowError(
                "message body must be structured JSON"
            ) from error
        if raw_event_id != message.event_id:
            raise AgentTeamsWorkflowError("raw event id does not match message")
        if raw_sender != message.sender:
            raise AgentTeamsWorkflowError("raw sender does not match message")
        return self.accept(message)

    def _rebuild_message(
        self, message: AgentTeamsWorkflowMessageV01
    ) -> AgentTeamsWorkflowMessageV01:
        if not isinstance(message, AgentTeamsWorkflowMessageV01):
            raise AgentTeamsWorkflowError("workflow message type is invalid")
        try:
            return AgentTeamsWorkflowMessageV01.model_validate(
                message.model_dump(mode="json", warnings="error")
            )
        except Exception as error:
            raise AgentTeamsWorkflowError("workflow message is invalid") from error

    def _transition(
        self, message: AgentTeamsWorkflowMessageV01
    ) -> AgentTeamsWorkflowStateV01:
        state = self._snapshot.state
        expected = {
            "awaiting_dispatch": ("Manager", "dispatch"),
            "awaiting_development": ("Developer", "development"),
            "awaiting_verification": ("Verifier", "verification"),
        }.get(state)
        if expected is None or (message.role, message.phase) != expected:
            raise AgentTeamsWorkflowError("message transition is out of order")
        if message.attempt != self._snapshot.attempt:
            raise AgentTeamsWorkflowError("message attempt does not match state")
        next_name: AgentTeamsState
        next_attempt: Literal[1, 2] = self._snapshot.attempt
        artifact_path = self._snapshot.artifact_path
        artifact_digest = self._snapshot.artifact_digest
        if state == "awaiting_dispatch":
            next_name = "awaiting_development"
        elif state == "awaiting_development":
            next_name = "awaiting_verification"
            artifact_path = message.artifact_path
            artifact_digest = message.artifact_digest
        else:
            if (
                message.artifact_path != artifact_path
                or message.artifact_digest != artifact_digest
            ):
                raise AgentTeamsWorkflowError(
                    "verification artifact digest does not match development"
                )
            if message.decision == "VERIFIED":
                next_name = "ready_for_acceptance"
            elif self._snapshot.attempt == 1:
                next_name = "awaiting_development"
                next_attempt = 2
                artifact_path = None
                artifact_digest = None
            else:
                next_name = "not_ready"
        return AgentTeamsWorkflowStateV01(
            schema_version="openworkproof-agentteams-state/0.1",
            task_id=self._task_id,
            state=next_name,
            attempt=next_attempt,
            artifact_path=artifact_path,
            artifact_digest=artifact_digest,
            last_event_id=message.event_id,
        )

    def _commit_core(
        self,
        message: AgentTeamsWorkflowMessageV01,
        next_state: AgentTeamsWorkflowStateV01,
    ) -> None:
        if self._commit is None:
            return
        try:
            self._commit(message, next_state)
        except AgentTeamsCommitAcknowledgementLost as error:
            if error.committed != next_state:
                raise AgentTeamsWorkflowError(
                    "core commit acknowledgement conflicts with proposed state"
                ) from error
        except Exception as error:
            raise AgentTeamsWorkflowError("core commit failed") from error


__all__ = [
    "AgentTeamsCommitAcknowledgementLost",
    "AgentTeamsRoleBinding",
    "AgentTeamsWorkflow",
    "AgentTeamsWorkflowError",
    "AgentTeamsWorkflowMessageV01",
    "AgentTeamsWorkflowOutcome",
    "AgentTeamsWorkflowStateV01",
]
