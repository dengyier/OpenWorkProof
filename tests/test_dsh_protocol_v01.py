from __future__ import annotations

import hashlib

import pytest
import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from openworkproof.dsh_protocol import (
    DshBridgeRequestV01,
    DshExecutionIdentityV01,
    DshObservationRecordV01,
    canonical_bytes,
    sign_dsh_observation,
    verify_dsh_observation,
)


SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64

DSH_TOOL_NAMES = (
    "owp_apply_patch",
    "owp_run_tests",
    "write",
    "edit",
    "bash",
    "pwsh",
    "str_replace_editor",
    "cordis_define",
    "cordis_run",
    "cordis_stop",
    "cordis_undefine",
)


def _hello_request() -> dict[str, object]:
    return {
        "schema_version": "openworkproof-dsh-bridge/0.1",
        "request_id": SHA_A,
        "session_id": "session-1",
        "message_type": "hello",
        "sequence": 0,
        "timestamp": "2026-08-26T00:00:00Z",
        "payload": {
            "host": "deepseek-harness",
            "host_version": "0.1.1-rc.2",
            "adapter_version": "0.1.0",
            "bridge_protocol": "0.1",
        },
    }


def _observation_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": "openworkproof-dsh-observation/0.1",
        "host": "deepseek-harness",
        "host_version": "0.1.1-rc.2",
        "adapter_version": "0.1.0",
        "execution": {
            "session_id": "session-1",
            "call_id": "call-1",
            "root_call_id": "call-1",
            "tool_name": "write",
            "arguments_digest": SHA_B,
        },
        "authorization_status": "not_evidenced",
        "live_result_digest": SHA_C,
        "durable_call_sequence": 1,
        "durable_result_sequence": 2,
        "receipt_digest": None,
        "evidence_gap_codes": ("AUTHORIZATION_NOT_EVIDENCED",),
        "observed_at": "2026-08-26T00:00:01Z",
        "nonce": SHA_D,
    }
    payload.update(overrides)
    return payload


def test_audit_observation_never_claims_authorization() -> None:
    private_key = Ed25519PrivateKey.generate()
    record = sign_dsh_observation(_observation_payload(), private_key)

    assert record.authorization_status == "not_evidenced"
    assert record.receipt_digest is None
    assert verify_dsh_observation(record, private_key.public_key())


@pytest.mark.parametrize("tool_name", DSH_TOOL_NAMES)
def test_every_closed_tool_name_is_a_valid_execution_identity(tool_name: str) -> None:
    identity = DshExecutionIdentityV01.model_validate(
        {
            "session_id": "session-1",
            "call_id": "call-1",
            "root_call_id": "call-1",
            "tool_name": tool_name,
            "arguments_digest": SHA_B,
        }
    )
    assert identity.tool_name == tool_name


@pytest.mark.parametrize("tool_name", DSH_TOOL_NAMES)
def test_every_native_tool_name_signs_a_closed_observation(tool_name: str) -> None:
    private_key = Ed25519PrivateKey.generate()
    record = sign_dsh_observation(
        _observation_payload(
            execution={
                "session_id": "session-1",
                "call_id": "call-1",
                "root_call_id": "call-1",
                "tool_name": tool_name,
                "arguments_digest": SHA_B,
            }
        ),
        private_key,
    )
    assert record.execution.tool_name == tool_name
    assert verify_dsh_observation(record, private_key.public_key())


def test_observation_rejects_action_receipt_without_authorization() -> None:
    private_key = Ed25519PrivateKey.generate()

    with pytest.raises(ValidationError, match="receipt requires authorized"):
        sign_dsh_observation(
            _observation_payload(receipt_digest=SHA_A),
            private_key,
        )


def test_observation_rejects_unsorted_or_duplicate_gap_codes() -> None:
    private_key = Ed25519PrivateKey.generate()

    with pytest.raises(ValidationError, match="UTF-8 sorted and unique"):
        sign_dsh_observation(
            _observation_payload(
                evidence_gap_codes=(
                    "DURABLE_RESULT_MISSING",
                    "AUTHORIZATION_NOT_EVIDENCED",
                )
            ),
            private_key,
        )


def test_observation_requires_paired_durable_sequences() -> None:
    private_key = Ed25519PrivateKey.generate()

    with pytest.raises(ValidationError, match="durable sequences must be paired"):
        sign_dsh_observation(
            _observation_payload(durable_result_sequence=None),
            private_key,
        )


def test_bridge_message_is_closed_and_canonical() -> None:
    request = DshBridgeRequestV01.model_validate(_hello_request())

    assert canonical_bytes(request) == rfc8785.dumps(
        request.model_dump(mode="json")
    )
    assert hashlib.sha256(canonical_bytes(request)).hexdigest()
    with pytest.raises(ValidationError):
        DshBridgeRequestV01.model_validate(
            {**_hello_request(), "extra": True}
        )


def test_bridge_rejects_unknown_message_type() -> None:
    with pytest.raises(ValidationError):
        DshBridgeRequestV01.model_validate(
            {**_hello_request(), "message_type": "native_write"}
        )


def test_signed_observation_model_is_closed() -> None:
    private_key = Ed25519PrivateKey.generate()
    record = sign_dsh_observation(_observation_payload(), private_key)
    raw = record.model_dump(mode="json")

    with pytest.raises(ValidationError):
        DshObservationRecordV01.model_validate({**raw, "extra": True})


@pytest.mark.parametrize(
    "gap_code", ("OBSERVATION_COMMIT_FAILED", "HOST_VERSION_INCOMPATIBLE")
)
def test_observation_accepts_extended_evidence_gap_codes(gap_code: str) -> None:
    private_key = Ed25519PrivateKey.generate()
    record = sign_dsh_observation(
        _observation_payload(
            evidence_gap_codes=("AUTHORIZATION_NOT_EVIDENCED", gap_code),
        ),
        private_key,
    )
    assert gap_code in record.evidence_gap_codes


def test_observation_records_a_non_canonical_host_version() -> None:
    private_key = Ed25519PrivateKey.generate()
    record = sign_dsh_observation(
        _observation_payload(host_version="0.1.0-rc.6"),
        private_key,
    )
    assert record.host_version == "0.1.0-rc.6"


def test_hello_payload_accepts_any_bounded_host_version() -> None:
    request = DshBridgeRequestV01.model_validate(
        {**_hello_request(), "payload": {
            "host": "deepseek-harness",
            "host_version": "0.1.0-rc.6",
            "adapter_version": "0.1.0",
            "bridge_protocol": "0.1",
        }}
    )
    assert request.root.payload.host_version == "0.1.0-rc.6"


def test_host_version_must_be_bounded_and_control_free() -> None:
    with pytest.raises(ValidationError):
        DshBridgeRequestV01.model_validate(
            {**_hello_request(), "payload": {
                "host": "deepseek-harness",
                "host_version": "",
                "adapter_version": "0.1.0",
                "bridge_protocol": "0.1",
            }}
        )
