"""Production handler assembly for the DeepSeek Harness bridge."""

from __future__ import annotations

import json
import os
import socket
import stat
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

import rfc8785

from openworkproof.dsh_protocol import (
    DshExecutionIdentityV01,
    dsh_execution_identity_digest,
)
from openworkproof.models import RunTestsArguments, ToolCallReceipt
from openworkproof.policy import ProspectiveExecutionFacts


_MAX_VERIFIER_MESSAGE_BYTES = 1_048_576
_VERIFIER_TIMEOUT_SECONDS = 5.0


def _strict_canonical_object(raw: bytes) -> dict[str, object]:
    def pairs_hook(pairs):
        value: dict[str, object] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate verifier response field")
            value[key] = item
        return value

    try:
        value = json.loads(raw, object_pairs_hook=pairs_hook)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise RuntimeError("VERIFIER_RESPONSE_INVALID") from error
    if type(value) is not dict or rfc8785.dumps(value) != raw:
        raise RuntimeError("VERIFIER_RESPONSE_INVALID")
    return value


def _require_private_verifier_socket(path: Path) -> None:
    if (
        not path.is_absolute()
        or path != Path(os.path.abspath(path))
        or path.is_symlink()
    ):
        raise RuntimeError("VERIFIER_TRANSPORT_UNAVAILABLE")
    try:
        metadata = os.stat(path, follow_symlinks=False)
    except OSError as error:
        raise RuntimeError("VERIFIER_TRANSPORT_UNAVAILABLE") from error
    if (
        not stat.S_ISSOCK(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_uid != os.geteuid()
    ):
        raise RuntimeError("VERIFIER_TRANSPORT_UNAVAILABLE")


def _receive_verifier_response(connection: socket.socket) -> bytes:
    chunks: list[bytes] = []
    size = 0
    while True:
        chunk = connection.recv(min(65_536, _MAX_VERIFIER_MESSAGE_BYTES + 1 - size))
        if not chunk:
            raise RuntimeError("VERIFIER_RESPONSE_INVALID")
        newline = chunk.find(b"\n")
        if newline >= 0:
            if newline != len(chunk) - 1:
                raise RuntimeError("VERIFIER_RESPONSE_INVALID")
            chunks.append(chunk[:newline])
            break
        chunks.append(chunk)
        size += len(chunk)
        if size > _MAX_VERIFIER_MESSAGE_BYTES:
            raise RuntimeError("VERIFIER_RESPONSE_INVALID")
    raw = b"".join(chunks)
    if not raw or len(raw) > _MAX_VERIFIER_MESSAGE_BYTES:
        raise RuntimeError("VERIFIER_RESPONSE_INVALID")
    return raw


def make_external_verifier_executor(
    *,
    socket_path: Path,
    case_id: str,
) -> Callable[
    [
        RunTestsArguments,
        ProspectiveExecutionFacts,
        DshExecutionIdentityV01,
        datetime,
    ],
    ToolCallReceipt,
]:
    """Return a fail-closed client for one case-bound Verifier process."""

    def execute(
        arguments: RunTestsArguments,
        facts: ProspectiveExecutionFacts,
        execution: DshExecutionIdentityV01,
        now: datetime,
    ) -> ToolCallReceipt:
        _require_private_verifier_socket(socket_path)
        if now.tzinfo is None or now.utcoffset() is None or now.microsecond:
            raise RuntimeError("VERIFIER_REQUEST_INVALID")
        execution_digest = dsh_execution_identity_digest(execution)
        request = rfc8785.dumps(
            {
                "schema_version": "openworkproof-dsh-verifier-request/0.1",
                "case_id": case_id,
                "execution_identity_digest": execution_digest,
                "execution": execution.model_dump(mode="json"),
                "arguments": arguments.model_dump(mode="json"),
                "facts": {
                    "execution_context_id": facts.execution_context_id,
                    "container_instance_id_digest": (
                        facts.container_instance_id_digest
                    ),
                    "controller_id": facts.controller_id,
                },
                "requested_at": now.astimezone(timezone.utc).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                ),
            }
        )
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(_VERIFIER_TIMEOUT_SECONDS)
                connection.connect(str(socket_path))
                connection.sendall(request + b"\n")
                raw = _receive_verifier_response(connection)
        except RuntimeError:
            raise
        except (OSError, TimeoutError) as error:
            raise RuntimeError("VERIFIER_TRANSPORT_UNAVAILABLE") from error
        response = _strict_canonical_object(raw)
        if (
            set(response)
            != {
                "schema_version",
                "case_id",
                "execution_identity_digest",
                "receipt",
            }
            or response["schema_version"]
            != "openworkproof-dsh-verifier-response/0.1"
            or response["case_id"] != case_id
            or response["execution_identity_digest"] != execution_digest
        ):
            raise RuntimeError("VERIFIER_RESPONSE_INVALID")
        try:
            return ToolCallReceipt.model_validate(response["receipt"])
        except ValueError as error:
            raise RuntimeError("VERIFIER_RESPONSE_INVALID") from error

    return execute


__all__ = ["make_external_verifier_executor"]
