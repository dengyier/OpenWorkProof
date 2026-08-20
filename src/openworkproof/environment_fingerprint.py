"""Closed, immutable companion execution-environment fingerprint models (0.1).

These models sit *outside* the frozen v0.1-v0.5 protocol registry and describe
the signed collection environment of an execution arm.  The signature bytes are
a fixed canonical domain so two collectors producing the same payload over the
same key always produce the same digest and signature.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from collections.abc import Mapping
from typing import Annotated, Any, Literal

import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import BeforeValidator, ConfigDict, TypeAdapter, model_validator

from openworkproof.models import (
    CanonicalUTCTime,
    Digest64,
    KeyId,
    ProtocolModel,
    Signature,
)
from openworkproof.signing import key_id


__all__ = [
    "EnvironmentFingerprintPayloadV01",
    "SignedEnvironmentFingerprintV01",
    "environment_signing_bytes",
    "sign_environment_fingerprint",
    "verify_environment_fingerprint",
]

CollectionStatus = Literal["complete", "partial", "unavailable"]
MissingReasonCode = Literal[
    "RUNNER_IMAGE_UNAVAILABLE",
    "CONTAINER_DIGEST_UNAVAILABLE",
    "TOOLCHAIN_LOCK_UNAVAILABLE",
    "SANDBOX_POLICY_UNAVAILABLE",
    "WORKFLOW_IDENTITY_UNVERIFIED",
]

_SIGNING_DOMAIN = "openworkproof/execution-environment/v0.1"

_LOWER_HEX_40 = re.compile(r"^[0-9a-f]{40}$")
_BASE64URL_NO_PAD = re.compile(r"^[A-Za-z0-9_-]+$")

# Field name -> missing reason code.  Order below is the declaration order; the
# canonical reason set is always re-derived and UTF-8 sorted during validation.
_OPTIONAL_AXES: tuple[tuple[str, MissingReasonCode], ...] = (
    ("runner_image_digest", "RUNNER_IMAGE_UNAVAILABLE"),
    ("container_image_digest", "CONTAINER_DIGEST_UNAVAILABLE"),
    ("toolchain_lock_digest", "TOOLCHAIN_LOCK_UNAVAILABLE"),
    ("sandbox_policy_digest", "SANDBOX_POLICY_UNAVAILABLE"),
    ("workflow_identity_digest", "WORKFLOW_IDENTITY_UNVERIFIED"),
)

MAX_RUNNER_OS_BYTES = 64
MAX_RUNNER_ARCH_BYTES = 64
MAX_COLLECTOR_ACTOR_BYTES = 128


def _strict_bounded_utf8(
    value: Any, *, max_bytes: int, field_name: str
) -> str:
    if type(value) is not str:
        raise ValueError(f"{field_name} must be a strict string")
    encoded = value.encode("utf-8")
    if not encoded or len(encoded) > max_bytes:
        raise ValueError(f"{field_name} must contain 1..{max_bytes} UTF-8 bytes")
    return value


def _source_revision(value: Any) -> str:
    if type(value) is not str or _LOWER_HEX_40.fullmatch(value) is None:
        raise ValueError(
            "source revision must be 40 lowercase hexadecimal characters"
        )
    return value


def _runner_os(value: Any) -> str:
    return _strict_bounded_utf8(
        value, max_bytes=MAX_RUNNER_OS_BYTES, field_name="runner_os"
    )


def _runner_arch(value: Any) -> str:
    return _strict_bounded_utf8(
        value, max_bytes=MAX_RUNNER_ARCH_BYTES, field_name="runner_arch"
    )


def _collector_actor_id(value: Any) -> str:
    return _strict_bounded_utf8(
        value,
        max_bytes=MAX_COLLECTOR_ACTOR_BYTES,
        field_name="collector_actor_id",
    )


def _sorted_reasons(reasons: tuple[MissingReasonCode, ...]) -> tuple[str, ...]:
    return tuple(sorted(set(reasons), key=lambda item: item.encode("utf-8")))


_ENVIRONMENT_FINGERPRINT_CONFIG = ConfigDict(
    extra="forbid",
    frozen=True,
    strict=True,
    validate_assignment=True,
    revalidate_instances="subclass-instances",
)


class EnvironmentFingerprintPayloadV01(ProtocolModel):
    model_config = _ENVIRONMENT_FINGERPRINT_CONFIG

    schema_version: Literal["openworkproof-execution-environment/0.1"]
    source_revision: Annotated[str, BeforeValidator(_source_revision)]
    runner_os: Annotated[str, BeforeValidator(_runner_os)]
    runner_arch: Annotated[str, BeforeValidator(_runner_arch)]
    runner_image_digest: Digest64 | None
    container_image_digest: Digest64 | None
    toolchain_lock_digest: Digest64 | None
    command_digest: Digest64
    arguments_digest: Digest64
    environment_allowlist_digest: Digest64
    sandbox_policy_digest: Digest64 | None
    workflow_identity_digest: Digest64 | None
    collection_status: CollectionStatus
    missing_reason_codes: tuple[MissingReasonCode, ...]
    collected_at: CanonicalUTCTime
    collector_actor_id: Annotated[str, BeforeValidator(_collector_actor_id)]

    @model_validator(mode="after")
    def _validate_collection_closure(self) -> EnvironmentFingerprintPayloadV01:
        missing = tuple(
            reason
            for field, reason in _OPTIONAL_AXES
            if getattr(self, field) is None
        )
        if self.collection_status == "complete":
            if missing:
                raise ValueError("complete fingerprint must collect every axis")
            if self.missing_reason_codes:
                raise ValueError(
                    "complete fingerprint must carry no missing reason codes"
                )
        elif self.collection_status == "partial":
            if not missing or len(missing) == len(_OPTIONAL_AXES):
                raise ValueError(
                    "partial fingerprint must collect at least one axis "
                    "and miss at least one"
                )
        elif len(missing) != len(_OPTIONAL_AXES):
            raise ValueError("unavailable fingerprint must miss every axis")

        expected = _sorted_reasons(missing)
        if self.missing_reason_codes != expected:
            raise ValueError(
                "missing reason codes must be UTF-8 sorted, unique, and "
                "exactly cover the missing axes"
            )
        return self


class SignedEnvironmentFingerprintV01(ProtocolModel):
    model_config = _ENVIRONMENT_FINGERPRINT_CONFIG

    payload: EnvironmentFingerprintPayloadV01
    digest: Digest64
    signature_alg: Literal["Ed25519"]
    collector_key_id: KeyId
    signature: Signature


def _encode_base64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _decode_base64url(value: Any, expected_bytes: int) -> bytes:
    if (
        type(value) is not str
        or not value
        or "=" in value
        or _BASE64URL_NO_PAD.fullmatch(value) is None
    ):
        raise ValueError("value is not unpadded base64url")
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, binascii.Error) as error:
        raise ValueError("value is not valid base64url") from error
    if len(raw) != expected_bytes or _encode_base64url(raw) != value:
        raise ValueError("base64url value has the wrong length or encoding")
    return raw


_KEY_ID_ADAPTER = TypeAdapter(KeyId)


def _validate_collector_key_id(collector_key_id: Any) -> str:
    if type(collector_key_id) is not str:
        raise ValueError("collector_key_id must be a strict string")
    _KEY_ID_ADAPTER.validate_python(collector_key_id)
    return collector_key_id


def _rebuild_payload(payload: Any) -> EnvironmentFingerprintPayloadV01:
    """Canonically rebuild and fully revalidate a payload before signing."""
    if not isinstance(payload, EnvironmentFingerprintPayloadV01):
        raise ValueError(
            "payload must be an EnvironmentFingerprintPayloadV01"
        )
    return EnvironmentFingerprintPayloadV01.model_validate(
        payload.model_dump(mode="json", warnings="error")
    )


def _rebuild_signed(signed: Any) -> SignedEnvironmentFingerprintV01:
    """Canonically rebuild and fully revalidate a signed envelope (and payload)."""
    if not isinstance(signed, SignedEnvironmentFingerprintV01):
        raise ValueError("signed must be a SignedEnvironmentFingerprintV01")
    return SignedEnvironmentFingerprintV01.model_validate(
        signed.model_dump(mode="json", warnings="error")
    )


def environment_signing_bytes(
    payload: EnvironmentFingerprintPayloadV01,
    collector_key_id: str,
) -> bytes:
    rebuilt = _rebuild_payload(payload)
    _validate_collector_key_id(collector_key_id)
    return rfc8785.dumps(
        {
            "domain": _SIGNING_DOMAIN,
            "payload": rebuilt.model_dump(mode="json"),
            "signature_alg": "Ed25519",
            "collector_key_id": collector_key_id,
        }
    )


def sign_environment_fingerprint(
    payload: EnvironmentFingerprintPayloadV01,
    private_key: Ed25519PrivateKey,
) -> SignedEnvironmentFingerprintV01:
    rebuilt = _rebuild_payload(payload)
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ValueError("private key must be Ed25519")
    collector_key_id = key_id(private_key.public_key())
    encoded = environment_signing_bytes(rebuilt, collector_key_id)
    return SignedEnvironmentFingerprintV01(
        payload=rebuilt.model_dump(mode="json"),
        digest=hashlib.sha256(encoded).hexdigest(),
        signature_alg="Ed25519",
        collector_key_id=collector_key_id,
        signature=_encode_base64url(private_key.sign(encoded)),
    )


def verify_environment_fingerprint(
    signed: SignedEnvironmentFingerprintV01,
    trust_map: Mapping[str, Ed25519PublicKey],
) -> bool:
    if not isinstance(signed, SignedEnvironmentFingerprintV01):
        return False
    if not isinstance(trust_map, Mapping):
        return False
    try:
        rebuilt = _rebuild_signed(signed)
        collector_key_id = rebuilt.collector_key_id
        public_key = trust_map.get(collector_key_id)
        if not isinstance(public_key, Ed25519PublicKey):
            return False
        if key_id(public_key) != collector_key_id:
            return False
        if rebuilt.signature_alg != "Ed25519":
            return False
        encoded = environment_signing_bytes(rebuilt.payload, collector_key_id)
        if rebuilt.digest != hashlib.sha256(encoded).hexdigest():
            return False
        signature = _decode_base64url(rebuilt.signature, 64)
        public_key.verify(signature, encoded)
    except Exception:
        # Caller-controlled inputs (a hostile Mapping, malformed/constructed
        # payloads, bad signatures) may raise any ordinary exception; the
        # verifier must fail closed rather than leak it. BaseException is not
        # caught, so KeyboardInterrupt/SystemExit still propagate.
        return False
    return True
