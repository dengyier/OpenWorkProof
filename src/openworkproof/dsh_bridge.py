"""Deterministic JSONL bridge for the DeepSeek Harness companion."""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import BinaryIO, TextIO

from openworkproof.dsh_case import (
    DecisionTokenStore,
    DshCaseManifestV01,
    load_dsh_case,
)
from openworkproof.dsh_execution import DshExecutionDenied
from openworkproof.dsh_protocol import (
    DshActionExecutePayloadV01,
    DshBridgeRequestV01,
    DshBridgeResponseV01,
    DshResultPayloadV01,
    canonical_bytes,
)


_MAX_LINE_BYTES = 1_048_576
_RESPONSE_TYPES = {
    "hello": "ready",
    "case_open": "case_status",
    "authorization_check": "authorization_result",
    "observation_commit": "observation_result",
    "action_execute": "action_result",
    "verify_request": "verify_result",
    "acceptance_draft": "acceptance_draft_result",
    "export_request": "export_result",
    "shutdown": "shutdown",
}


def _strict_json_object(raw: bytes) -> dict[str, object]:
    def pairs_hook(pairs):
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON object key")
            result[key] = value
        return result

    try:
        value = json.loads(raw, object_pairs_hook=pairs_hook)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("bridge line is not strict UTF-8 JSON") from error
    if type(value) is not dict:
        raise ValueError("bridge line must contain one JSON object")
    return value


class DshBridgeApplication:
    """One stateful, single-session bridge protocol endpoint."""

    def __init__(
        self,
        *,
        clock: Callable[[], datetime],
        action_handler: Callable[[DshActionExecutePayloadV01], str] | None = None,
    ) -> None:
        self._clock = clock
        self._action_handler = action_handler
        self._session_id: str | None = None
        self._next_sequence = 0
        self._shutdown = False
        self._responses: dict[str, tuple[bytes, bytes]] = {}
        self._cases: dict[str, DshCaseManifestV01] = {}
        self._decision_tokens = DecisionTokenStore(clock=clock)

    @property
    def shutdown_complete(self) -> bool:
        return self._shutdown

    def _now(self) -> datetime:
        now = self._clock()
        if now.tzinfo is None or now.utcoffset() is None or now.microsecond:
            raise ValueError("bridge clock must return an exact aware second")
        return now.astimezone(timezone.utc)

    @staticmethod
    def _response(
        request,
        *,
        message_type: str,
        status: str,
        result_digest: str | None = None,
        reason_code: str | None = None,
        error_kind: str | None = None,
        decision_token: str | None = None,
        expires_at: datetime | None = None,
        include_versions: bool = False,
    ) -> bytes:
        payload = DshResultPayloadV01.model_validate(
            {
                "status": status,
                "result_digest": result_digest,
                "reason_code": reason_code,
                "error_kind": error_kind,
                "decision_token": decision_token,
                "expires_at": (
                    None
                    if expires_at is None
                    else expires_at.strftime("%Y-%m-%dT%H:%M:%SZ")
                ),
                "bridge_version": "0.1.0" if include_versions else None,
                "openworkproof_version": "1.3.0" if include_versions else None,
                "host_version": "0.1.1-rc.2" if include_versions else None,
            }
        )
        response = DshBridgeResponseV01.model_validate(
            {
                "schema_version": "openworkproof-dsh-bridge/0.1",
                "request_id": request.request_id,
                "session_id": request.session_id,
                "message_type": message_type,
                "sequence": request.sequence,
                "timestamp": request.timestamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "payload": payload.model_dump(mode="json"),
            }
        )
        return canonical_bytes(response)

    def _error(self, request, reason_code: str) -> bytes:
        return self._response(
            request,
            message_type="error",
            status="error",
            reason_code=reason_code,
            error_kind="operational_failure",
        )

    def handle_line(self, raw_line: bytes) -> bytes:
        if type(raw_line) is not bytes:
            raise ValueError("bridge line must be exact bytes")
        raw = raw_line.rstrip(b"\n")
        if len(raw) > _MAX_LINE_BYTES:
            raise ValueError("bridge line exceeds 1 MiB")
        parsed = DshBridgeRequestV01.model_validate(_strict_json_object(raw)).root
        previous = self._responses.get(parsed.request_id)
        if previous is not None:
            previous_request, previous_response = previous
            if previous_request == raw:
                return previous_response
            return self._error(parsed, "REQUEST_ID_CONFLICT")
        if self._shutdown:
            response = self._error(parsed, "MESSAGE_AFTER_SHUTDOWN")
        elif self._session_id is None:
            if parsed.message_type != "hello" or parsed.sequence != 0:
                response = self._error(parsed, "HELLO_REQUIRED")
            else:
                self._session_id = parsed.session_id
                self._next_sequence = 1
                response = self._response(
                    parsed,
                    message_type="ready",
                    status="ready",
                    include_versions=True,
                )
        elif parsed.session_id != self._session_id:
            response = self._error(parsed, "SESSION_MISMATCH")
        elif parsed.sequence != self._next_sequence:
            response = self._error(parsed, "SEQUENCE_MISMATCH")
        else:
            self._next_sequence += 1
            response = self._dispatch(parsed)
        self._responses[parsed.request_id] = (raw, response)
        return response

    def _dispatch(self, request) -> bytes:
        message_type = request.message_type
        if message_type == "case_open":
            supplied = Path(request.payload.case_manifest_path)
            case_root = supplied.parent if supplied.is_file() else supplied
            manifest = load_dsh_case(case_root)
            self._cases[manifest.case_id] = manifest
            return self._response(
                request,
                message_type="case_status",
                status="ok",
                result_digest=manifest.case_id,
            )
        if message_type == "authorization_check":
            manifest = self._cases.get(request.payload.case_id)
            if manifest is None:
                return self._response(
                    request,
                    message_type="authorization_result",
                    status="denied",
                    reason_code="CASE_NOT_OPEN",
                    error_kind="protocol_denial",
                )
            if request.payload.execution.tool_name not in manifest.allowed_tools:
                return self._response(
                    request,
                    message_type="authorization_result",
                    status="denied",
                    reason_code="TOOL_NOT_ALLOWED",
                    error_kind="protocol_denial",
                )
            expires_at = self._now() + timedelta(seconds=30)
            token = self._decision_tokens.issue(
                request.payload.execution,
                expires_at=expires_at,
            )
            return self._response(
                request,
                message_type="authorization_result",
                status="ok",
                decision_token=token.token,
                expires_at=expires_at,
            )
        if message_type == "action_execute":
            if self._action_handler is None:
                return self._response(
                    request,
                    message_type="action_result",
                    status="error",
                    reason_code="EXECUTION_CASE_UNAVAILABLE",
                    error_kind="operational_failure",
                )
            try:
                result_digest = self._action_handler(request.payload)
            except DshExecutionDenied as error:
                return self._response(
                    request,
                    message_type="action_result",
                    status="denied",
                    reason_code=str(error),
                    error_kind="protocol_denial",
                )
            return self._response(
                request,
                message_type="action_result",
                status="ok",
                result_digest=result_digest,
            )
        if message_type == "shutdown":
            self._shutdown = True
            return self._response(
                request,
                message_type="shutdown",
                status="ok",
            )
        response_type = _RESPONSE_TYPES[message_type]
        return self._response(
            request,
            message_type=response_type,
            status="unknown",
            reason_code="HANDLER_NOT_CONFIGURED",
        )


def run_stdio_bridge(
    stdin: TextIO,
    stdout: TextIO,
    stderr: TextIO,
    *,
    clock: Callable[[], datetime],
    application: DshBridgeApplication | None = None,
) -> int:
    """Run one bounded JSONL session; stdout is protocol bytes only."""

    app = application or DshBridgeApplication(clock=clock)
    for line in stdin:
        raw = line.encode("utf-8") if isinstance(line, str) else bytes(line)
        try:
            response = app.handle_line(raw)
        except Exception as error:
            stderr.write(f"OWP_BRIDGE_PROTOCOL_ERROR: {error}\n")
            return 2
        stdout.write(response.decode("utf-8") + "\n")
        stdout.flush()
        if app.shutdown_complete:
            break
    return 0


__all__ = ["DshBridgeApplication", "run_stdio_bridge"]
