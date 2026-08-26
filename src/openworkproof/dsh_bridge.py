"""Deterministic JSONL bridge for the DeepSeek Harness companion."""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import BinaryIO, TextIO

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import openworkproof.evidence as evidence
from openworkproof.binding import canonical_test_profile_digest
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
    dsh_execution_context_id,
    sign_dsh_observation,
)
from openworkproof.models import ApplyPatchArguments, RunTestsArguments, ToolCallReceipt


_MAX_LINE_BYTES = 1_048_576
_UNKNOWN_OPERATIONAL_REASON_CODES = frozenset(
    {
        "VERIFIER_REQUEST_INVALID",
        "VERIFIER_RESPONSE_INVALID",
        "VERIFIER_TRANSPORT_UNAVAILABLE",
    }
)
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


@dataclass(frozen=True, slots=True)
class DshCaseHandlers:
    """Trusted handlers assembled for one already validated case."""

    action: Callable[[DshActionExecutePayloadV01], str]
    verify: Callable[[object], str]
    acceptance_draft: Callable[[object], str]
    export: Callable[[object], str]


def _durable_action_receipt_digest(
    manifest: DshCaseManifestV01,
    payload: DshActionExecutePayloadV01,
) -> str | None:
    """Read exact committed action truth before any consequential retry."""

    connection = evidence.connect_ledger(Path(manifest.ledger_path))
    try:
        work_order, receipts, _, _ = (
            evidence._replay_receipt_publication_ledger(connection)
        )
    finally:
        connection.close()
    if work_order.digest != manifest.work_order_digest:
        raise ValueError("case WorkOrder binding is invalid")
    execution_context_id = dsh_execution_context_id(payload.execution)
    candidates = tuple(
        receipt
        for receipt in receipts
        if isinstance(receipt, ToolCallReceipt)
        and receipt.policy_decision == "allow"
        and receipt.execution_status == "succeeded"
        and receipt.correlation_factors is not None
        and receipt.correlation_factors.execution_context_id
        == execution_context_id
    )
    if payload.execution.tool_name == "owp_apply_patch":
        patch = payload.patch_text
        targets = payload.target_paths
        if patch is None or targets is None:
            raise ValueError("patch action payload is incomplete")
        expected = ApplyPatchArguments(
            target_paths=targets,
            patch_digest=hashlib.sha256(patch.encode("utf-8")).hexdigest(),
            patch_size_bytes=len(patch.encode("utf-8")),
        )
        candidates = tuple(
            receipt
            for receipt in candidates
            if receipt.tool_name == "owp.apply_patch"
            and receipt.request_arguments == expected
        )
    else:
        profile_digest = payload.test_profile_digest
        profiles = tuple(
            profile
            for profile in work_order.test_profiles
            if profile.test_mode == "verifier"
            and canonical_test_profile_digest(profile) == profile_digest
        )
        if len(profiles) != 1:
            raise ValueError("test profile binding is invalid")
        profile = profiles[0]
        candidates = tuple(
            receipt
            for receipt in candidates
            if receipt.tool_name == "owp.run_tests"
            and isinstance(receipt.request_arguments, RunTestsArguments)
            and receipt.request_arguments.command_digest
            == profile.command_digest
            and receipt.request_arguments.source_commit
            == work_order.source_commit
            and receipt.request_arguments.container_image_digest
            == profile.container_image_digest
            and receipt.request_arguments.fixed_test_source_digest
            == profile.fixed_test_source_digest
        )
    if len(candidates) > 1:
        raise ValueError("committed action binding is ambiguous")
    return None if not candidates else candidates[0].digest


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
        handler_factory: Callable[
            [DshCaseManifestV01, DecisionTokenStore], DshCaseHandlers
        ]
        | None = None,
        committed_truth_lookup: Callable[
            [DshCaseManifestV01, DshActionExecutePayloadV01], str | None
        ] = _durable_action_receipt_digest,
    ) -> None:
        self._clock = clock
        self._action_handler = action_handler
        self._handler_factory = handler_factory
        self._committed_truth_lookup = committed_truth_lookup
        self._session_id: str | None = None
        self._next_sequence = 0
        self._shutdown = False
        self._responses: dict[str, tuple[bytes, bytes]] = {}
        self._cases: dict[str, DshCaseManifestV01] = {}
        self._case_handlers: dict[str, DshCaseHandlers] = {}
        self._decision_tokens = DecisionTokenStore(clock=clock)
        self._committed_receipts: dict[tuple[str, str], str] = {}

    @property
    def decision_tokens(self) -> DecisionTokenStore:
        return self._decision_tokens

    @property
    def shutdown_complete(self) -> bool:
        return self._shutdown

    def _now(self) -> datetime:
        now = self._clock()
        if now.tzinfo is None or now.utcoffset() is None or now.microsecond:
            raise ValueError("bridge clock must return an exact aware second")
        return now.astimezone(timezone.utc)

    @staticmethod
    def _execution_digest(execution) -> str:
        return hashlib.sha256(canonical_bytes(execution)).hexdigest()

    @staticmethod
    def _load_sidecar_private_key(manifest) -> Ed25519PrivateKey:
        try:
            raw = Path(manifest.sidecar_key_path).read_bytes()
        except OSError as error:
            raise ValueError("sidecar key is unavailable") from error
        if len(raw) != 32:
            raise ValueError("sidecar key must contain exactly 32 bytes")
        return Ed25519PrivateKey.from_private_bytes(raw)

    @staticmethod
    def _store_observation(manifest, record) -> None:
        root = Path(manifest.evidence_root)
        directory = root / "dsh-observations"
        if directory.is_symlink():
            raise ValueError("observation directory must not be a symlink")
        directory.mkdir(mode=0o700, exist_ok=True)
        path = directory / f"{record.record_id}.json"
        raw = canonical_bytes(record) + b"\n"
        try:
            descriptor = os.open(
                path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
        except FileExistsError:
            if path.is_symlink() or path.read_bytes() != raw:
                raise ValueError("observation record conflicts with immutable truth")
            return
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
        except BaseException:
            path.unlink(missing_ok=True)
            raise

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
                "openworkproof_version": "1.4.0" if include_versions else None,
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
            if self._handler_factory is not None:
                self._case_handlers[manifest.case_id] = self._handler_factory(
                    manifest,
                    self._decision_tokens,
                )
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
        if message_type == "observation_commit":
            manifest = self._cases.get(request.payload.case_id)
            if manifest is None:
                return self._response(
                    request,
                    message_type="observation_result",
                    status="denied",
                    reason_code="CASE_NOT_OPEN",
                    error_kind="protocol_denial",
                )
            observation = request.payload.observation
            receipt_digest = observation.receipt_digest
            committed = self._committed_receipts.get(
                (
                    request.payload.case_id,
                    self._execution_digest(observation.execution),
                )
            )
            if observation.authorization_status == "authorized" and (
                receipt_digest is None or committed != receipt_digest
            ):
                return self._response(
                    request,
                    message_type="observation_result",
                    status="denied",
                    reason_code="RECEIPT_BINDING_MISSING",
                    error_kind="protocol_denial",
                )
            try:
                record = sign_dsh_observation(
                    observation.model_dump(mode="json"),
                    self._load_sidecar_private_key(manifest),
                )
                self._store_observation(manifest, record)
            except (OSError, ValueError):
                return self._response(
                    request,
                    message_type="observation_result",
                    status="error",
                    reason_code="OBSERVATION_COMMIT_FAILED",
                    error_kind="operational_failure",
                )
            return self._response(
                request,
                message_type="observation_result",
                status="ok",
                result_digest=record.record_id,
            )
        if message_type == "action_execute":
            manifest = self._cases.get(request.payload.case_id)
            if manifest is None:
                return self._response(
                    request,
                    message_type="action_result",
                    status="denied",
                    reason_code="CASE_NOT_OPEN",
                    error_kind="protocol_denial",
                )
            try:
                committed_digest = self._committed_truth_lookup(
                    manifest, request.payload
                )
            except Exception:
                return self._response(
                    request,
                    message_type="action_result",
                    status="unknown",
                    reason_code="COMMITTED_TRUTH_UNAVAILABLE",
                )
            if committed_digest is not None:
                self._committed_receipts[
                    (
                        request.payload.case_id,
                        self._execution_digest(request.payload.execution),
                    )
                ] = committed_digest
                return self._response(
                    request,
                    message_type="action_result",
                    status="ok",
                    result_digest=committed_digest,
                )
            handlers = self._case_handlers.get(request.payload.case_id)
            action_handler = (
                handlers.action if handlers is not None else self._action_handler
            )
            if action_handler is None:
                return self._response(
                    request,
                    message_type="action_result",
                    status="error",
                    reason_code="EXECUTION_CASE_UNAVAILABLE",
                    error_kind="operational_failure",
                )
            try:
                result_digest = action_handler(request.payload)
            except DshExecutionDenied as error:
                return self._response(
                    request,
                    message_type="action_result",
                    status="denied",
                    reason_code=str(error),
                    error_kind="protocol_denial",
                )
            except RuntimeError as error:
                reason_code = str(error)
                if reason_code in _UNKNOWN_OPERATIONAL_REASON_CODES:
                    return self._response(
                        request,
                        message_type="action_result",
                        status="unknown",
                        reason_code=reason_code,
                    )
                raise
            self._committed_receipts[
                (
                    request.payload.case_id,
                    self._execution_digest(request.payload.execution),
                )
            ] = result_digest
            return self._response(
                request,
                message_type="action_result",
                status="ok",
                result_digest=result_digest,
            )
        if message_type in {"verify_request", "acceptance_draft", "export_request"}:
            handlers = self._case_handlers.get(request.payload.case_id)
            if handlers is None:
                return self._response(
                    request,
                    message_type=_RESPONSE_TYPES[message_type],
                    status="unknown",
                    reason_code="HANDLER_NOT_CONFIGURED",
                )
            handler = {
                "verify_request": handlers.verify,
                "acceptance_draft": handlers.acceptance_draft,
                "export_request": handlers.export,
            }[message_type]
            try:
                result_digest = handler(request.payload)
            except RuntimeError as error:
                reason_code = str(error)
                if reason_code in _UNKNOWN_OPERATIONAL_REASON_CODES:
                    return self._response(
                        request,
                        message_type=_RESPONSE_TYPES[message_type],
                        status="unknown",
                        reason_code=reason_code,
                    )
                return self._response(
                    request,
                    message_type=_RESPONSE_TYPES[message_type],
                    status="error",
                    reason_code="HANDLER_FAILED",
                    error_kind="operational_failure",
                )
            except Exception:
                return self._response(
                    request,
                    message_type=_RESPONSE_TYPES[message_type],
                    status="error",
                    reason_code="HANDLER_FAILED",
                    error_kind="operational_failure",
                )
            return self._response(
                request,
                message_type=_RESPONSE_TYPES[message_type],
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

    if application is None:
        from openworkproof.dsh_handlers import build_dsh_case_handlers

        app = DshBridgeApplication(
            clock=clock,
            handler_factory=lambda manifest, tokens: build_dsh_case_handlers(
                manifest,
                tokens,
                clock=clock,
            ),
        )
    else:
        app = application
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


__all__ = [
    "DshBridgeApplication",
    "DshCaseHandlers",
    "_durable_action_receipt_digest",
    "run_stdio_bridge",
]
