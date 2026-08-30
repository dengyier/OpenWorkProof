"""Closed companion protocol for the DeepSeek Harness adapter."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import Annotated, Any, Literal

import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import AfterValidator, Field, RootModel, model_validator

from openworkproof.models import (
    CanonicalRoot,
    CanonicalUTCTime,
    Digest64,
    Identifier,
    ProtocolModel,
    SafeNonNegativeInt,
    SignedProtocolModel,
)
from openworkproof.signing import key_id, sign_payload, verify_payload


_OBSERVATION_ID_DOMAIN = "openworkproof/dsh-observation-record-id/v0.1"
_SIGNING_FIELDS = frozenset(
    {"record_id", "digest", "signature_alg", "signer_key_id", "signature"}
)

DshToolName = Literal[
    "owp_apply_patch",
    "owp_run_tests",
    "read",
    "glob",
    "grep",
    "web_search",
    "write",
    "edit",
    "bash",
    "pwsh",
    "str_replace_editor",
    "cordis_define",
    "cordis_run",
    "cordis_stop",
    "cordis_undefine",
]
DshEvidenceGapCode = Literal[
    "AUTHORIZATION_NOT_EVIDENCED",
    "DURABLE_CALL_MISSING",
    "DURABLE_RESULT_MISSING",
    "EVENT_SEQUENCE_CONFLICT",
    "OUT_OF_BAND_EXECUTION",
    "OBSERVATION_COMMIT_FAILED",
    "HOST_VERSION_INCOMPATIBLE",
]


def _utf8_sorted_unique(values: tuple[str, ...]) -> bool:
    return list(values) == sorted(set(values), key=lambda item: item.encode("utf-8"))


def _bounded_path(value: str, *, field_name: str) -> str:
    encoded = value.encode("utf-8")
    if not encoded or len(encoded) > 4096 or "\x00" in value:
        raise ValueError(f"{field_name} must contain 1..4096 UTF-8 bytes")
    return value


def _bounded_version(value: str) -> str:
    encoded = value.encode("utf-8")
    if not encoded or len(encoded) > 64 or any(ord(char) < 0x20 for char in value):
        raise ValueError("host version must be 1..64 UTF-8 bytes without controls")
    return value


HostVersion = Annotated[str, AfterValidator(_bounded_version)]


def canonical_bytes(value: ProtocolModel | RootModel[Any] | Mapping[str, Any]) -> bytes:
    """Return raw RFC 8785 bytes for one already-closed bridge object."""

    if isinstance(value, (ProtocolModel, RootModel)):
        payload = value.model_dump(mode="json")
    elif isinstance(value, Mapping):
        payload = dict(value)
    else:
        raise ValueError("DSH canonical value must be a protocol model or mapping")
    try:
        return rfc8785.dumps(payload)
    except (TypeError, ValueError, OverflowError) as error:
        raise ValueError("DSH value is not canonicalizable JCS") from error


def dsh_action_arguments_digest(arguments: Mapping[str, Any]) -> str:
    """Bind one Harness tool call to its exact closed argument object."""

    if not isinstance(arguments, Mapping):
        raise ValueError("DSH action arguments must be a mapping")
    return hashlib.sha256(canonical_bytes(arguments)).hexdigest()


class DshExecutionIdentityV01(ProtocolModel):
    session_id: Identifier
    call_id: Identifier
    root_call_id: Identifier
    tool_name: DshToolName
    arguments_digest: Digest64


def dsh_execution_identity_digest(
    execution: DshExecutionIdentityV01,
) -> str:
    """Bind a verification result to one exact Harness execution identity."""

    return hashlib.sha256(
        rfc8785.dumps(
            {
                "domain": "openworkproof/dsh-execution-identity/v0.1",
                "payload": execution.model_dump(mode="json"),
            }
        )
    ).hexdigest()


def dsh_execution_context_id(execution: DshExecutionIdentityV01) -> str:
    """Derive the correlation id committed in an OWP ActionReceipt."""

    return hashlib.sha256(
        rfc8785.dumps(
            {
                "domain": "openworkproof/dsh-execution-context/v0.1",
                "payload": {
                    "session_id": execution.session_id,
                    "call_id": execution.call_id,
                    "root_call_id": execution.root_call_id,
                },
            }
        )
    ).hexdigest()


class DshObservationDraftV01(ProtocolModel):
    schema_version: Literal["openworkproof-dsh-observation/0.1"]
    host: Literal["deepseek-harness"]
    host_version: HostVersion
    adapter_version: Literal["0.1.0"]
    execution: DshExecutionIdentityV01
    authorization_status: Literal["not_evidenced", "authorized", "denied"]
    live_result_digest: Digest64 | None
    durable_call_sequence: SafeNonNegativeInt | None
    durable_result_sequence: SafeNonNegativeInt | None
    receipt_digest: Digest64 | None
    evidence_gap_codes: tuple[DshEvidenceGapCode, ...]
    observed_at: CanonicalUTCTime
    nonce: Digest64

    @model_validator(mode="after")
    def _validate_observation(self) -> DshObservationDraftV01:
        if not _utf8_sorted_unique(self.evidence_gap_codes):
            raise ValueError("evidence gap codes must be UTF-8 sorted and unique")
        paired = (self.durable_call_sequence is None) == (
            self.durable_result_sequence is None
        )
        if not paired:
            raise ValueError("durable sequences must be paired")
        if (
            self.durable_call_sequence is not None
            and self.durable_result_sequence is not None
            and self.durable_result_sequence <= self.durable_call_sequence
        ):
            raise ValueError("durable result sequence must follow call sequence")
        if self.receipt_digest is not None and (
            self.authorization_status != "authorized" or self.evidence_gap_codes
        ):
            raise ValueError("receipt requires authorized status without evidence gaps")
        if (
            self.authorization_status == "not_evidenced"
            and "AUTHORIZATION_NOT_EVIDENCED" not in self.evidence_gap_codes
        ):
            raise ValueError("not_evidenced requires its evidence gap code")
        return self


class DshObservationRecordV01(SignedProtocolModel):
    _signed_domain = "dsh-observation-record"

    schema_version: Literal["openworkproof-dsh-observation/0.1"]
    record_id: Digest64
    host: Literal["deepseek-harness"]
    host_version: HostVersion
    adapter_version: Literal["0.1.0"]
    execution: DshExecutionIdentityV01
    authorization_status: Literal["not_evidenced", "authorized", "denied"]
    live_result_digest: Digest64 | None
    durable_call_sequence: SafeNonNegativeInt | None
    durable_result_sequence: SafeNonNegativeInt | None
    receipt_digest: Digest64 | None
    evidence_gap_codes: tuple[DshEvidenceGapCode, ...]
    observed_at: CanonicalUTCTime
    nonce: Digest64

    @model_validator(mode="after")
    def _validate_observation(self) -> DshObservationRecordV01:
        DshObservationDraftV01.model_validate(
            {
                key: value
                for key, value in self.model_dump(mode="json").items()
                if key not in _SIGNING_FIELDS
            }
        )
        if self.record_id != dsh_observation_record_id(
            self.model_dump(mode="json")
        ):
            raise ValueError("record_id does not match canonical observation")
        return self


def dsh_observation_record_id(payload: Mapping[str, Any]) -> str:
    content = {
        key: value
        for key, value in payload.items()
        if key not in {"record_id", "digest", "signature"}
    }
    return hashlib.sha256(
        rfc8785.dumps({"domain": _OBSERVATION_ID_DOMAIN, "payload": content})
    ).hexdigest()


def sign_dsh_observation(
    payload: Mapping[str, Any],
    private_key: Ed25519PrivateKey,
) -> DshObservationRecordV01:
    if not isinstance(payload, Mapping):
        raise ValueError("observation payload must be a mapping")
    if any(field in payload for field in _SIGNING_FIELDS):
        raise ValueError("observation payload must not pre-supply signing fields")
    candidate = dict(payload)
    candidate["signature_alg"] = "Ed25519"
    candidate["signer_key_id"] = key_id(private_key.public_key())
    candidate["record_id"] = dsh_observation_record_id(candidate)
    return DshObservationRecordV01.model_validate(
        sign_payload("dsh-observation-record", candidate, private_key)
    )


def verify_dsh_observation(
    record: DshObservationRecordV01 | Mapping[str, Any],
    public_key: Ed25519PublicKey,
) -> bool:
    try:
        validated = (
            record
            if isinstance(record, DshObservationRecordV01)
            else DshObservationRecordV01.model_validate(record)
        )
    except (TypeError, ValueError):
        return False
    return verify_payload(
        "dsh-observation-record",
        validated.model_dump(mode="json"),
        public_key,
    )


class _BridgeMessageV01(ProtocolModel):
    schema_version: Literal["openworkproof-dsh-bridge/0.1"]
    request_id: Digest64
    session_id: Identifier
    sequence: SafeNonNegativeInt
    timestamp: CanonicalUTCTime


class DshHelloPayloadV01(ProtocolModel):
    host: Literal["deepseek-harness"]
    host_version: HostVersion
    adapter_version: Literal["0.1.0"]
    bridge_protocol: Literal["0.1"]


class DshCaseOpenPayloadV01(ProtocolModel):
    case_manifest_path: str

    @model_validator(mode="after")
    def _validate_path(self) -> DshCaseOpenPayloadV01:
        _bounded_path(self.case_manifest_path, field_name="case_manifest_path")
        return self


class DshAuthorizationCheckPayloadV01(ProtocolModel):
    case_id: Digest64
    execution: DshExecutionIdentityV01


class DshObservationCommitPayloadV01(ProtocolModel):
    case_id: Digest64
    observation: DshObservationDraftV01


class DshActionExecutePayloadV01(ProtocolModel):
    case_id: Digest64
    execution: DshExecutionIdentityV01
    decision_token: Digest64
    patch_text: str | None
    target_paths: tuple[CanonicalRoot, ...] | None
    test_profile_digest: Digest64 | None

    @model_validator(mode="after")
    def _validate_action(self) -> DshActionExecutePayloadV01:
        if self.execution.tool_name == "owp_apply_patch":
            if (
                self.patch_text is None
                or self.target_paths is None
                or not self.target_paths
                or self.test_profile_digest is not None
            ):
                raise ValueError("owp_apply_patch requires only patch_text")
            if list(self.target_paths) != sorted(set(self.target_paths)):
                raise ValueError("target_paths must be sorted and unique")
            if len(self.patch_text.encode("utf-8")) > 65_536:
                raise ValueError("patch_text exceeds 65536 UTF-8 bytes")
        elif self.execution.tool_name == "owp_run_tests":
            if (
                self.patch_text is not None
                or self.target_paths is not None
                or self.test_profile_digest is None
            ):
                raise ValueError("owp_run_tests requires only test_profile_digest")
        else:
            raise ValueError("action_execute accepts only OWP-owned tools")
        return self


class DshVerifyRequestPayloadV01(ProtocolModel):
    case_id: Digest64
    action_receipt_digest: Digest64


class DshAcceptanceDraftPayloadV01(ProtocolModel):
    case_id: Digest64
    verification_digest: Digest64


class DshExportRequestPayloadV01(ProtocolModel):
    case_id: Digest64
    destination: str
    verification_digest: Digest64
    acceptance_draft_digest: Digest64

    @model_validator(mode="after")
    def _validate_destination(self) -> DshExportRequestPayloadV01:
        _bounded_path(self.destination, field_name="destination")
        return self


class DshShutdownPayloadV01(ProtocolModel):
    reason: Literal["client_shutdown"]


class DshHelloRequestV01(_BridgeMessageV01):
    message_type: Literal["hello"]
    payload: DshHelloPayloadV01


class DshCaseOpenRequestV01(_BridgeMessageV01):
    message_type: Literal["case_open"]
    payload: DshCaseOpenPayloadV01


class DshAuthorizationCheckRequestV01(_BridgeMessageV01):
    message_type: Literal["authorization_check"]
    payload: DshAuthorizationCheckPayloadV01


class DshObservationCommitRequestV01(_BridgeMessageV01):
    message_type: Literal["observation_commit"]
    payload: DshObservationCommitPayloadV01


class DshActionExecuteRequestV01(_BridgeMessageV01):
    message_type: Literal["action_execute"]
    payload: DshActionExecutePayloadV01


class DshVerifyRequestV01(_BridgeMessageV01):
    message_type: Literal["verify_request"]
    payload: DshVerifyRequestPayloadV01


class DshAcceptanceDraftRequestV01(_BridgeMessageV01):
    message_type: Literal["acceptance_draft"]
    payload: DshAcceptanceDraftPayloadV01


class DshExportRequestV01(_BridgeMessageV01):
    message_type: Literal["export_request"]
    payload: DshExportRequestPayloadV01


class DshShutdownRequestV01(_BridgeMessageV01):
    message_type: Literal["shutdown"]
    payload: DshShutdownPayloadV01


DshBridgeRequestPayloadV01 = Annotated[
    DshHelloRequestV01
    | DshCaseOpenRequestV01
    | DshAuthorizationCheckRequestV01
    | DshObservationCommitRequestV01
    | DshActionExecuteRequestV01
    | DshVerifyRequestV01
    | DshAcceptanceDraftRequestV01
    | DshExportRequestV01
    | DshShutdownRequestV01,
    Field(discriminator="message_type"),
]


class DshBridgeRequestV01(RootModel[DshBridgeRequestPayloadV01]):
    pass


class DshResultPayloadV01(ProtocolModel):
    status: Literal["ready", "ok", "denied", "unknown", "error"]
    result_digest: Digest64 | None
    reason_code: Identifier | None
    error_kind: Literal["protocol_denial", "operational_failure"] | None = None
    decision_token: Digest64 | None = None
    expires_at: CanonicalUTCTime | None = None
    bridge_version: Literal["0.1.0"] | None = None
    openworkproof_version: Literal["1.4.0"] | None = None
    host_version: HostVersion | None = None
    case_mode: Literal["audit", "enforce"] | None = None

    @model_validator(mode="after")
    def _validate_result(self) -> DshResultPayloadV01:
        if (self.decision_token is None) != (self.expires_at is None):
            raise ValueError("decision token and expiry must be paired")
        if self.decision_token is not None and self.status != "ok":
            raise ValueError("decision token requires ok status")
        if self.status in {"denied", "unknown", "error"} and self.reason_code is None:
            raise ValueError("non-success status requires a reason code")
        if self.status in {"ready", "ok"} and self.error_kind is not None:
            raise ValueError("success status cannot contain an error kind")
        versions = (
            self.bridge_version,
            self.openworkproof_version,
            self.host_version,
        )
        if self.status == "ready" and any(value is None for value in versions):
            raise ValueError("ready status requires exact negotiated versions")
        if self.status != "ready" and any(value is not None for value in versions):
            raise ValueError("only ready status may contain negotiated versions")
        return self


class DshReadyResponseV01(_BridgeMessageV01):
    message_type: Literal["ready"]
    payload: DshResultPayloadV01


class DshCaseStatusResponseV01(_BridgeMessageV01):
    message_type: Literal["case_status"]
    payload: DshResultPayloadV01


class DshAuthorizationResultResponseV01(_BridgeMessageV01):
    message_type: Literal["authorization_result"]
    payload: DshResultPayloadV01


class DshObservationResultResponseV01(_BridgeMessageV01):
    message_type: Literal["observation_result"]
    payload: DshResultPayloadV01


class DshActionResultResponseV01(_BridgeMessageV01):
    message_type: Literal["action_result"]
    payload: DshResultPayloadV01


class DshVerifyResultResponseV01(_BridgeMessageV01):
    message_type: Literal["verify_result"]
    payload: DshResultPayloadV01


class DshAcceptanceDraftResultResponseV01(_BridgeMessageV01):
    message_type: Literal["acceptance_draft_result"]
    payload: DshResultPayloadV01


class DshExportResultResponseV01(_BridgeMessageV01):
    message_type: Literal["export_result"]
    payload: DshResultPayloadV01


class DshShutdownResponseV01(_BridgeMessageV01):
    message_type: Literal["shutdown"]
    payload: DshResultPayloadV01


class DshErrorResponseV01(_BridgeMessageV01):
    message_type: Literal["error"]
    payload: DshResultPayloadV01


DshBridgeResponsePayloadV01 = Annotated[
    DshReadyResponseV01
    | DshCaseStatusResponseV01
    | DshAuthorizationResultResponseV01
    | DshObservationResultResponseV01
    | DshActionResultResponseV01
    | DshVerifyResultResponseV01
    | DshAcceptanceDraftResultResponseV01
    | DshExportResultResponseV01
    | DshShutdownResponseV01
    | DshErrorResponseV01,
    Field(discriminator="message_type"),
]


class DshBridgeResponseV01(RootModel[DshBridgeResponsePayloadV01]):
    pass
