"""Adversarial tests for the companion execution-environment fingerprint v0.1.

This module exercises the closed environment fingerprint models, the fixed
canonical signing bytes, Ed25519 signing, and caller-supplied trust-map
verification.  All seed values, digests, and signatures below are synthetic
test-only constants and MUST NOT be used as real OpenWorkProof keys.
"""

from __future__ import annotations

import base64
import hashlib
from collections.abc import Mapping
from typing import Any

import pytest
import rfc8785
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import ValidationError

from openworkproof.environment_fingerprint import (
    EnvironmentFingerprintPayloadV01,
    SignedEnvironmentFingerprintV01,
    environment_signing_bytes,
    sign_environment_fingerprint,
    verify_environment_fingerprint,
)
from openworkproof.signing import key_id


SCHEMA_VERSION = "openworkproof-execution-environment/0.1"

ALL_MISSING_REASON_CODES = [
    "CONTAINER_DIGEST_UNAVAILABLE",
    "RUNNER_IMAGE_UNAVAILABLE",
    "SANDBOX_POLICY_UNAVAILABLE",
    "TOOLCHAIN_LOCK_UNAVAILABLE",
    "WORKFLOW_IDENTITY_UNVERIFIED",
]


def _complete_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "source_revision": "0" * 40,
        "runner_os": "linux",
        "runner_arch": "amd64",
        "runner_image_digest": "a" * 64,
        "container_image_digest": "b" * 64,
        "toolchain_lock_digest": "c" * 64,
        "command_digest": "d" * 64,
        "arguments_digest": "e" * 64,
        "environment_allowlist_digest": "f" * 64,
        "sandbox_policy_digest": "0" * 64,
        "workflow_identity_digest": "1" * 64,
        "collection_status": "complete",
        "missing_reason_codes": [],
        "collected_at": "2026-01-01T00:00:00Z",
        "collector_actor_id": "verifier",
    }
    payload.update(overrides)
    return payload


def _partial_payload() -> dict[str, Any]:
    return _complete_payload(
        collection_status="partial",
        runner_image_digest=None,
        toolchain_lock_digest=None,
        missing_reason_codes=[
            "RUNNER_IMAGE_UNAVAILABLE",
            "TOOLCHAIN_LOCK_UNAVAILABLE",
        ],
    )


def _unavailable_payload() -> dict[str, Any]:
    return _complete_payload(
        collection_status="unavailable",
        runner_image_digest=None,
        container_image_digest=None,
        toolchain_lock_digest=None,
        sandbox_policy_digest=None,
        workflow_identity_digest=None,
        missing_reason_codes=ALL_MISSING_REASON_CODES,
    )


def _seed_key(byte: int = 0x42) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes([byte]) * 32)


def _public_key_b64url(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _signed(overrides: dict[str, Any] | None = None) -> SignedEnvironmentFingerprintV01:
    private_key = _seed_key()
    payload = EnvironmentFingerprintPayloadV01.model_validate(_complete_payload())
    signed = sign_environment_fingerprint(payload, private_key)
    if overrides:
        return signed.model_copy(update=overrides)
    return signed


def _trust(private_key: Ed25519PrivateKey) -> Mapping[str, Ed25519PublicKey]:
    return {key_id(private_key.public_key()): private_key.public_key()}


# --------------------------------------------------------------------------- #
# 1. complete / partial / unavailable roundtrip
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "payload_data",
    [
        _complete_payload(),
        _partial_payload(),
        _unavailable_payload(),
    ],
)
def test_complete_partial_unavailable_roundtrip(payload_data: dict[str, Any]) -> None:
    private_key = _seed_key()
    payload = EnvironmentFingerprintPayloadV01.model_validate(payload_data)
    signed = sign_environment_fingerprint(payload, private_key)
    trust = {signed.collector_key_id: private_key.public_key()}
    assert verify_environment_fingerprint(signed, trust)
    rebuilt = SignedEnvironmentFingerprintV01.model_validate_json(
        signed.model_dump_json()
    )
    assert rebuilt == signed
    assert signed.signature_alg == "Ed25519"
    assert signed.collector_key_id == key_id(private_key.public_key())


def test_valid_exact_instances_and_json_roundtrip() -> None:
    payload = EnvironmentFingerprintPayloadV01.model_validate(_complete_payload())
    assert EnvironmentFingerprintPayloadV01.model_validate(payload) is payload
    assert (
        EnvironmentFingerprintPayloadV01.model_validate_json(
            payload.model_dump_json()
        )
        == payload
    )

    signed = _signed()
    assert SignedEnvironmentFingerprintV01.model_validate(signed) is signed
    assert (
        SignedEnvironmentFingerprintV01.model_validate_json(signed.model_dump_json())
        == signed
    )


# --------------------------------------------------------------------------- #
# 2. shape rejection: extra fields, strict types, revisions, digests, times
# --------------------------------------------------------------------------- #


def test_extra_field_is_forbidden() -> None:
    with pytest.raises(ValidationError):
        EnvironmentFingerprintPayloadV01.model_validate(
            {**_complete_payload(), "unexpected": "boom"}
        )


@pytest.mark.parametrize(
    "field,value",
    [
        ("command_digest", 123),
        ("runner_os", 5),
        ("missing_reason_codes", "RUNNER_IMAGE_UNAVAILABLE"),
        ("collected_at", 123456),
        ("collection_status", True),
        ("runner_image_digest", 42),
    ],
)
def test_strict_type_rejection(field: str, value: Any) -> None:
    with pytest.raises(ValidationError):
        EnvironmentFingerprintPayloadV01.model_validate(
            _complete_payload(**{field: value})
        )


@pytest.mark.parametrize(
    "revision",
    ["abc", "A" * 40, "g" * 40, "0" * 41, "0" * 39, ""],
)
def test_source_revision_must_be_lowercase_40_hex(revision: str) -> None:
    with pytest.raises(ValidationError):
        EnvironmentFingerprintPayloadV01.model_validate(
            _complete_payload(source_revision=revision)
        )


@pytest.mark.parametrize(
    "field",
    [
        "runner_image_digest",
        "container_image_digest",
        "toolchain_lock_digest",
        "command_digest",
        "arguments_digest",
        "environment_allowlist_digest",
        "sandbox_policy_digest",
        "workflow_identity_digest",
    ],
)
@pytest.mark.parametrize("length", [63, 65])
def test_digest_must_be_exactly_64_hex(field: str, length: int) -> None:
    with pytest.raises(ValidationError):
        EnvironmentFingerprintPayloadV01.model_validate(
            _complete_payload(**{field: "a" * length})
        )


@pytest.mark.parametrize(
    "collected_at",
    [
        "2026-01-01T00:00:00.000Z",
        "2026-01-01T00:00Z",
        "2026-01-01T00:00:00+00:00",
        "2026-01-01 00:00:00Z",
        "1969-12-31T23:59:59Z",
        "2026-01-01T00:00:60Z",
    ],
)
def test_collected_at_must_be_utc_seconds_after_epoch(collected_at: str) -> None:
    with pytest.raises(ValidationError):
        EnvironmentFingerprintPayloadV01.model_validate(
            _complete_payload(collected_at=collected_at)
        )


@pytest.mark.parametrize(
    "field,max_bytes",
    [
        ("runner_os", 64),
        ("runner_arch", 64),
        ("collector_actor_id", 128),
    ],
)
def test_bounded_string_utf8_byte_limits(field: str, max_bytes: int) -> None:
    with pytest.raises(ValidationError):
        EnvironmentFingerprintPayloadV01.model_validate(
            _complete_payload(**{field: "\u00e9" * (max_bytes + 1)})
        )
    with pytest.raises(ValidationError):
        EnvironmentFingerprintPayloadV01.model_validate(
            _complete_payload(**{field: ""})
        )


# --------------------------------------------------------------------------- #
# 3. collection status closure
# --------------------------------------------------------------------------- #


def test_complete_with_missing_axis_is_rejected() -> None:
    with pytest.raises(ValidationError):
        EnvironmentFingerprintPayloadV01.model_validate(
            _complete_payload(runner_image_digest=None)
        )


def test_complete_with_any_missing_reason_is_rejected() -> None:
    with pytest.raises(ValidationError):
        EnvironmentFingerprintPayloadV01.model_validate(
            _complete_payload(
                missing_reason_codes=["RUNNER_IMAGE_UNAVAILABLE"]
            )
        )


def test_partial_with_no_missing_axis_is_rejected() -> None:
    with pytest.raises(ValidationError):
        EnvironmentFingerprintPayloadV01.model_validate(
            _complete_payload(
                collection_status="partial",
                missing_reason_codes=[],
            )
        )


def test_partial_with_all_axes_missing_is_rejected() -> None:
    with pytest.raises(ValidationError):
        EnvironmentFingerprintPayloadV01.model_validate(
            _unavailable_payload()
            | {"collection_status": "partial"}
        )


def test_unavailable_with_collected_axis_is_rejected() -> None:
    with pytest.raises(ValidationError):
        EnvironmentFingerprintPayloadV01.model_validate(
            _unavailable_payload() | {"runner_image_digest": "a" * 64}
        )


def test_missing_reasons_over_reported_are_rejected() -> None:
    with pytest.raises(ValidationError):
        EnvironmentFingerprintPayloadV01.model_validate(
            _complete_payload(
                collection_status="partial",
                runner_image_digest=None,
                missing_reason_codes=[
                    "RUNNER_IMAGE_UNAVAILABLE",
                    "CONTAINER_DIGEST_UNAVAILABLE",
                ],
            )
        )


def test_missing_reasons_under_reported_are_rejected() -> None:
    with pytest.raises(ValidationError):
        EnvironmentFingerprintPayloadV01.model_validate(
            _complete_payload(
                collection_status="partial",
                runner_image_digest=None,
                container_image_digest=None,
                missing_reason_codes=["RUNNER_IMAGE_UNAVAILABLE"],
            )
        )


def test_missing_reasons_out_of_order_are_rejected() -> None:
    with pytest.raises(ValidationError):
        EnvironmentFingerprintPayloadV01.model_validate(
            _complete_payload(
                collection_status="partial",
                runner_image_digest=None,
                sandbox_policy_digest=None,
                missing_reason_codes=[
                    "SANDBOX_POLICY_UNAVAILABLE",
                    "RUNNER_IMAGE_UNAVAILABLE",
                ],
            )
        )


def test_missing_reasons_duplicated_are_rejected() -> None:
    with pytest.raises(ValidationError):
        EnvironmentFingerprintPayloadV01.model_validate(
            _complete_payload(
                collection_status="partial",
                runner_image_digest=None,
                missing_reason_codes=[
                    "RUNNER_IMAGE_UNAVAILABLE",
                    "RUNNER_IMAGE_UNAVAILABLE",
                ],
            )
        )


def test_missing_reasons_unknown_code_is_rejected() -> None:
    with pytest.raises(ValidationError):
        EnvironmentFingerprintPayloadV01.model_validate(
            _complete_payload(
                collection_status="partial",
                runner_image_digest=None,
                missing_reason_codes=["RUNNER_IMAGE_UNAVAILABLE", "UNKNOWN_CODE"],
            )
        )


# --------------------------------------------------------------------------- #
# 4. signature and trust-map verification
# --------------------------------------------------------------------------- #


def test_bad_signature_is_rejected() -> None:
    private_key = _seed_key()
    signed = _signed()
    bad_signature = base64.urlsafe_b64encode(b"\x00" * 64).decode("ascii").rstrip(
        "="
    )
    tampered = signed.model_copy(update={"signature": bad_signature})
    assert not verify_environment_fingerprint(tampered, _trust(private_key))


def test_wrong_collector_key_id_is_rejected() -> None:
    private_key = _seed_key()
    signed = _signed()
    tampered = signed.model_copy(
        update={"collector_key_id": "ed25519:" + "f" * 64}
    )
    assert not verify_environment_fingerprint(tampered, _trust(private_key))


def test_untrusted_key_is_rejected() -> None:
    signed = _signed()
    other_key = _seed_key(0x99)
    trust = {key_id(other_key.public_key()): other_key.public_key()}
    assert not verify_environment_fingerprint(signed, trust)
    assert not verify_environment_fingerprint(signed, {})


def test_trust_map_key_mismatching_public_key_is_rejected() -> None:
    private_key = _seed_key()
    signed = _signed()
    other_key = _seed_key(0x99)
    trust = {key_id(private_key.public_key()): other_key.public_key()}
    assert not verify_environment_fingerprint(signed, trust)


@pytest.mark.parametrize(
    "field,value",
    [
        ("source_revision", "1" * 40),
        ("runner_image_digest", "9" * 64),
        ("command_digest", "9" * 64),
        ("sandbox_policy_digest", "9" * 64),
        ("workflow_identity_digest", "9" * 64),
    ],
)
def test_post_sign_tampering_is_rejected(field: str, value: str) -> None:
    private_key = _seed_key()
    payload = EnvironmentFingerprintPayloadV01.model_validate(_complete_payload())
    signed = sign_environment_fingerprint(payload, private_key)
    tampered_payload = payload.model_copy(update={field: value})
    tampered = signed.model_copy(update={"payload": tampered_payload})
    assert not verify_environment_fingerprint(tampered, _trust(private_key))


def test_verify_rejects_non_model_and_non_mapping_without_raising() -> None:
    signed = _signed()
    assert not verify_environment_fingerprint({}, {})  # type: ignore[arg-type]
    assert not verify_environment_fingerprint(signed, None)  # type: ignore[arg-type]
    assert not verify_environment_fingerprint(None, _trust(_seed_key()))  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# 5. malicious model_construct subclass revalidation
# --------------------------------------------------------------------------- #


def test_payload_revalidates_malicious_model_construct_subclass() -> None:
    valid = EnvironmentFingerprintPayloadV01.model_validate(_complete_payload())
    malicious_type = type(
        "_MaliciousEnvironmentFingerprintPayloadV01",
        (EnvironmentFingerprintPayloadV01,),
        {},
    )
    data = valid.model_dump(mode="python")
    data["source_revision"] = "NOT-40-HEX"
    malicious = malicious_type.model_construct(**data)
    with pytest.raises(ValidationError):
        EnvironmentFingerprintPayloadV01.model_validate(malicious)


def test_signed_revalidates_malicious_model_construct_subclass() -> None:
    valid = _signed()
    malicious_type = type(
        "_MaliciousSignedEnvironmentFingerprintV01",
        (SignedEnvironmentFingerprintV01,),
        {},
    )
    data = valid.model_dump(mode="python")
    data["signature"] = "A" * 64
    malicious = malicious_type.model_construct(**data)
    with pytest.raises(ValidationError):
        SignedEnvironmentFingerprintV01.model_validate(malicious)


def test_models_are_frozen() -> None:
    payload = EnvironmentFingerprintPayloadV01.model_validate(_complete_payload())
    with pytest.raises(ValidationError, match="frozen"):
        payload.runner_os = "windows"  # type: ignore[misc]

    signed = _signed()
    with pytest.raises(ValidationError, match="frozen"):
        signed.signature_alg = "Ed25519"  # type: ignore[misc]


# --------------------------------------------------------------------------- #
# 6. golden test with a fixed 32-byte Ed25519 seed
# --------------------------------------------------------------------------- #

GOLDEN_SEED = bytes(range(32))
GOLDEN_COLLECTOR_KEY_ID = (
    "ed25519:56475aa75463474c0285df5dbf2bcab73da651358839e9b77481b2eab107708c"
)
GOLDEN_SIGNING_BYTES_SHA256 = (
    "1e77e37abe8b724e27c3938ab4abf5cef01d82e3cd419db7e197c210e1809d03"
)
GOLDEN_SIGNATURE = (
    "KKfPPptqS6618SBZ4xGMYt4a8pVPyHbqN5WwRZCIh-U"
    "JjY9iKzYReKQZSaDb0_5ZUGdY10OaoYNBWHb4U_I0CA"
)


def test_golden_signing_bytes_digest_and_signature_are_frozen() -> None:
    private_key = Ed25519PrivateKey.from_private_bytes(GOLDEN_SEED)
    payload = EnvironmentFingerprintPayloadV01.model_validate(
        _complete_payload(source_revision="0" * 40)
    )
    collector_key_id = key_id(private_key.public_key())
    assert collector_key_id == GOLDEN_COLLECTOR_KEY_ID

    encoded = environment_signing_bytes(payload, collector_key_id)
    assert hashlib.sha256(encoded).hexdigest() == GOLDEN_SIGNING_BYTES_SHA256

    signed = sign_environment_fingerprint(payload, private_key)
    assert signed.digest == GOLDEN_SIGNING_BYTES_SHA256
    assert signed.signature == GOLDEN_SIGNATURE

    signed_again = sign_environment_fingerprint(payload, private_key)
    assert signed_again == signed
    assert signed_again.digest == signed.digest
    assert signed_again.signature == signed.signature


# --------------------------------------------------------------------------- #
# 7. signing boundaries reject malicious model_construct / hostile inputs
# --------------------------------------------------------------------------- #


def _malicious_complete_payload() -> EnvironmentFingerprintPayloadV01:
    """A model_construct subclass whose collection closure is invalid."""
    valid = EnvironmentFingerprintPayloadV01.model_validate(_complete_payload())
    malicious_type = type(
        "_MaliciousEnvironmentFingerprintPayloadV01",
        (EnvironmentFingerprintPayloadV01,),
        {},
    )
    data = valid.model_dump(mode="python")
    data["collected_at"] = valid.collected_at
    data["runner_image_digest"] = None
    return malicious_type.model_construct(**data)


def test_environment_signing_bytes_rejects_malicious_model_construct() -> None:
    private_key = _seed_key()
    collector_key_id = key_id(private_key.public_key())
    malicious = _malicious_complete_payload()
    with pytest.raises(ValueError):
        environment_signing_bytes(malicious, collector_key_id)


def test_sign_environment_fingerprint_rejects_malicious_model_construct() -> None:
    private_key = _seed_key()
    malicious = _malicious_complete_payload()
    with pytest.raises(ValueError):
        sign_environment_fingerprint(malicious, private_key)


def test_verify_rejects_constructed_envelope_with_valid_signature() -> None:
    private_key = _seed_key()
    collector_key_id = key_id(private_key.public_key())
    malicious = _malicious_complete_payload()

    encoded = rfc8785.dumps(
        {
            "domain": "openworkproof/execution-environment/v0.1",
            "payload": malicious.model_dump(mode="json"),
            "signature_alg": "Ed25519",
            "collector_key_id": collector_key_id,
        }
    )
    digest = hashlib.sha256(encoded).hexdigest()
    signature = (
        base64.urlsafe_b64encode(private_key.sign(encoded))
        .decode("ascii")
        .rstrip("=")
    )

    # The signature is cryptographically valid over the semantically invalid
    # state; verification must reject it on rebuild/revalidation, not crypto.
    private_key.public_key().verify(
        base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4)),
        encoded,
    )

    envelope = SignedEnvironmentFingerprintV01.model_construct(
        payload=malicious,
        digest=digest,
        signature_alg="Ed25519",
        collector_key_id=collector_key_id,
        signature=signature,
    )
    assert not verify_environment_fingerprint(
        envelope, {collector_key_id: private_key.public_key()}
    )


def test_verify_returns_false_for_hostile_mapping_get() -> None:
    private_key = _seed_key()
    signed = _signed()

    class HostileMapping(dict[str, Ed25519PublicKey]):
        def get(self, key: str, default: Any = None) -> Any:
            raise RuntimeError("hostile mapping .get")

    trust = HostileMapping(
        {key_id(private_key.public_key()): private_key.public_key()}
    )
    assert not verify_environment_fingerprint(signed, trust)


@pytest.mark.parametrize(
    "bad_key_id",
    [
        "not-a-key-id",
        "",
        "ed25519:" + "0" * 63,
        "ed25519:" + "0" * 65,
        "ED25519:" + "0" * 64,
        "ed25519:" + "A" * 64,
    ],
)
def test_environment_signing_bytes_rejects_malformed_collector_key_id(
    bad_key_id: str,
) -> None:
    payload = EnvironmentFingerprintPayloadV01.model_validate(_complete_payload())
    with pytest.raises(ValueError):
        environment_signing_bytes(payload, bad_key_id)


def test_valid_normal_roundtrip_unchanged() -> None:
    private_key = _seed_key()
    payload = EnvironmentFingerprintPayloadV01.model_validate(_complete_payload())
    collector_key_id = key_id(private_key.public_key())

    encoded = environment_signing_bytes(payload, collector_key_id)
    signed = sign_environment_fingerprint(payload, private_key)

    assert signed.digest == hashlib.sha256(encoded).hexdigest()
    assert verify_environment_fingerprint(
        signed, {collector_key_id: private_key.public_key()}
    )
