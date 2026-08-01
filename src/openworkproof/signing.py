from __future__ import annotations

import base64
import hashlib
import math
import re
from collections.abc import Mapping
from typing import Any

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from openworkproof.models import (
    AgentRequest,
    ApprovalHumanDecision,
    HumanDecision,
    KeyBinding,
    TerminationHumanDecision,
    WorkOrder,
)


ALLOWED_CANONICAL_DOMAINS = frozenset(
    {
        "work-order",
        "capability-grant",
        "action-receipt",
        "acceptance-receipt",
        "agent-request",
        "human-decision",
        "sidecar-event",
        "manifest",
    }
)
ALLOWED_SIGNED_DOMAINS = ALLOWED_CANONICAL_DOMAINS - {"sidecar-event"}

MAX_JSON_DEPTH = 128
MAX_JSON_NODES = 10_000

_BASE64URL_NO_PAD = re.compile(r"^[A-Za-z0-9_-]+$")
_MAX_SAFE_INTEGER = 2**53 - 1
_NON_NEGATIVE_INTEGER_FIELDS = frozenset(
    {
        "actual_exit_code",
        "amount",
        "expected_exit_code",
        "expected_state_version",
        "grant_remaining_before",
        "max_size_bytes",
        "max_validity_seconds",
        "ordinal",
        "patch_size_bytes",
        "remaining_after",
        "repair_rounds",
        "sequence",
        "size_bytes",
        "state_version_before",
        "tool_calls",
    }
)


def unsigned_payload(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError("signed payload must be a mapping")
    result = _snapshot_json(
        value,
        omitted_top_level_fields=frozenset({"digest", "signature"}),
    )
    if not isinstance(result, dict):
        raise ValueError("signed payload snapshot must be an object")
    return result


def _snapshot_json(
    value: Any,
    *,
    omitted_top_level_fields: frozenset[str] = frozenset(),
) -> Any:
    holder: list[Any] = [None]
    active_containers: set[int] = set()
    node_count = 0
    work: list[tuple[Any, ...]] = [
        ("visit", value, holder, 0, 0, None, True)
    ]

    while work:
        operation = work.pop()
        if operation[0] == "exit":
            active_containers.remove(operation[1])
            continue

        _, current, parent, slot, depth, field_name, is_top_level = operation
        node_count += 1
        if node_count > MAX_JSON_NODES:
            raise ValueError("JSON payload exceeds node budget")
        nullable_non_negative = field_name in {
            "actual_exit_code",
            "remaining_after",
        } and current is None
        if field_name in _NON_NEGATIVE_INTEGER_FIELDS and not (
            nullable_non_negative
        ) and (
            type(current) is not int
            or not 0 <= current <= _MAX_SAFE_INTEGER
        ):
            raise ValueError(
                f"{field_name} must be a safe non-negative integer"
            )

        if current is None or type(current) in {str, bool}:
            parent[slot] = current
            continue
        if type(current) is int:
            if not 0 <= current <= _MAX_SAFE_INTEGER:
                raise ValueError(
                    "JSON integer is outside the safe non-negative range"
                )
            parent[slot] = current
            continue
        if type(current) is float:
            if not math.isfinite(current):
                raise ValueError("NaN and infinity are forbidden")
            raise ValueError("floating-point JSON numbers are forbidden")

        if isinstance(current, Mapping):
            if depth > MAX_JSON_DEPTH:
                raise ValueError("JSON payload exceeds maximum depth")
            identity = id(current)
            if identity in active_containers:
                raise ValueError("JSON payload contains a cycle")
            try:
                iterator = iter(current.items())
            except Exception as error:
                raise ValueError("JSON object cannot be traversed") from error

            items: list[tuple[str, Any]] = []
            seen_keys: set[str] = set()
            child_budget = MAX_JSON_NODES - node_count
            while True:
                try:
                    pair = next(iterator)
                except StopIteration:
                    break
                except Exception as error:
                    raise ValueError(
                        "JSON object cannot be traversed"
                    ) from error
                if type(pair) is not tuple or len(pair) != 2:
                    raise ValueError(
                        "JSON object item is not a key/value pair"
                    )
                key, item = pair
                if type(key) is not str:
                    raise ValueError("JSON object keys must be strings")
                if key in seen_keys:
                    raise ValueError("JSON object keys must be unique")
                seen_keys.add(key)
                if (
                    is_top_level
                    and key in omitted_top_level_fields
                ):
                    continue
                if len(items) >= child_budget:
                    raise ValueError("JSON payload exceeds node budget")
                items.append((key, item))

            snapshot: dict[str, Any] = {}
            parent[slot] = snapshot
            active_containers.add(identity)
            work.append(("exit", identity))
            for key, item in reversed(items):
                work.append(
                    (
                        "visit",
                        item,
                        snapshot,
                        key,
                        depth + 1,
                        key,
                        False,
                    )
                )
            continue

        if isinstance(current, (list, tuple)):
            if depth > MAX_JSON_DEPTH:
                raise ValueError("JSON payload exceeds maximum depth")
            identity = id(current)
            if identity in active_containers:
                raise ValueError("JSON payload contains a cycle")
            try:
                if len(current) > MAX_JSON_NODES - node_count:
                    raise ValueError("JSON payload exceeds node budget")
                items = list(current)
            except Exception as error:
                if isinstance(error, ValueError):
                    raise
                raise ValueError("JSON array cannot be traversed") from error
            snapshot_list: list[Any] = [None] * len(items)
            parent[slot] = snapshot_list
            active_containers.add(identity)
            work.append(("exit", identity))
            for index in range(len(items) - 1, -1, -1):
                work.append(
                    (
                        "visit",
                        items[index],
                        snapshot_list,
                        index,
                        depth + 1,
                        None,
                        False,
                    )
                )
            continue

        raise ValueError("payload contains a non-JSON value")

    return holder[0]


def canonical_bytes(object_type: str, payload: Mapping[str, Any]) -> bytes:
    if (
        type(object_type) is not str
        or object_type not in ALLOWED_CANONICAL_DOMAINS
    ):
        raise ValueError("unknown canonical domain")
    canonical_input = {
        "domain": f"openworkproof/{object_type}/v0.1",
        "payload": unsigned_payload(payload),
    }
    try:
        return rfc8785.dumps(canonical_input)
    except (ValueError, TypeError, OverflowError) as error:
        raise ValueError("payload is not canonicalizable JCS") from error


def digest_payload(object_type: str, payload: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_bytes(object_type, payload)).hexdigest()


def key_id(public_key: Ed25519PublicKey) -> str:
    if not isinstance(public_key, Ed25519PublicKey):
        raise ValueError("public key must be Ed25519")
    raw = public_key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return f"ed25519:{hashlib.sha256(raw).hexdigest()}"


def _encode_base64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _decode_base64url(value: Any, expected_length: int) -> bytes:
    if (
        type(value) is not str
        or not _BASE64URL_NO_PAD.fullmatch(value)
        or "=" in value
    ):
        raise ValueError("value is not unpadded base64url")
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, TypeError) as error:
        raise ValueError("value is not valid base64url") from error
    if len(raw) != expected_length or _encode_base64url(raw) != value:
        raise ValueError("base64url value has the wrong length or encoding")
    return raw


def sign_payload(
    object_type: str,
    payload: Mapping[str, Any],
    private_key: Ed25519PrivateKey,
) -> dict[str, Any]:
    if type(object_type) is not str or object_type not in ALLOWED_SIGNED_DOMAINS:
        raise ValueError("object type cannot be signed")
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ValueError("private key must be Ed25519")
    result = unsigned_payload(payload)
    result["signature_alg"] = "Ed25519"
    result["signer_key_id"] = key_id(private_key.public_key())
    encoded = canonical_bytes(object_type, result)
    result["digest"] = hashlib.sha256(encoded).hexdigest()
    result["signature"] = _encode_base64url(private_key.sign(encoded))
    signed_snapshot = _snapshot_json(result)
    if not isinstance(signed_snapshot, dict):
        raise ValueError("signed payload snapshot must be an object")
    return signed_snapshot


def verify_payload(
    object_type: str,
    signed: Mapping[str, Any],
    public_key: Ed25519PublicKey,
) -> bool:
    if (
        type(object_type) is not str
        or object_type not in ALLOWED_SIGNED_DOMAINS
        or not isinstance(signed, Mapping)
        or not isinstance(public_key, Ed25519PublicKey)
    ):
        return False
    try:
        snapshot = _snapshot_json(signed)
        if not isinstance(snapshot, dict):
            return False
        if (
            snapshot.get("signature_alg") != "Ed25519"
            or snapshot.get("signer_key_id") != key_id(public_key)
        ):
            return False
        encoded = canonical_bytes(object_type, snapshot)
        if snapshot.get("digest") != hashlib.sha256(encoded).hexdigest():
            return False
        signature = _decode_base64url(snapshot.get("signature"), 64)
        public_key.verify(signature, encoded)
    except (InvalidSignature, ValueError, TypeError):
        return False
    return True


def decode_and_verify_key_binding(binding: KeyBinding) -> Ed25519PublicKey:
    if not isinstance(binding, KeyBinding):
        raise ValueError("binding must be a KeyBinding")
    raw = _decode_base64url(binding.public_key_b64url, 32)
    public_key = Ed25519PublicKey.from_public_bytes(raw)
    if binding.key_id != key_id(public_key):
        raise ValueError("key binding fingerprint does not match public key")
    return public_key


def verify_work_order_identity_bindings(work_order: WorkOrder) -> bool:
    if not isinstance(work_order, WorkOrder):
        return False
    try:
        bindings = work_order.key_bindings
        if (
            tuple(binding.role for binding in bindings) != (
                "Maintainer",
                "Manager",
                "Developer",
                "Verifier",
                "Sidecar",
            )
            or len({binding.key_id for binding in bindings}) != 5
        ):
            return False
        public_keys = [
            decode_and_verify_key_binding(binding) for binding in bindings
        ]
        maintainer = bindings[0]
        if (
            work_order.issuer_id != maintainer.subject_id
            or work_order.signer_key_id != maintainer.key_id
            or work_order.acceptor_key_ids != (maintainer.key_id,)
        ):
            return False
        return verify_payload(
            "work-order",
            work_order.model_dump(mode="json"),
            public_keys[0],
        )
    except (ValueError, TypeError):
        return False


def verify_nested_claim(
    claim: AgentRequest | HumanDecision,
    work_order: WorkOrder,
) -> bool:
    if not verify_work_order_identity_bindings(work_order):
        return False
    if not isinstance(
        claim,
        (AgentRequest, ApprovalHumanDecision, TerminationHumanDecision),
    ):
        return False
    try:
        if claim.work_order_digest != work_order.digest:
            return False
        matches = [
            binding
            for binding in work_order.key_bindings
            if (
                binding.subject_id == claim.actor_id
                and binding.key_id == claim.actor_key_id
                and binding.key_id == claim.signer_key_id
            )
        ]
        if len(matches) != 1:
            return False
        binding = matches[0]
        public_key = decode_and_verify_key_binding(binding)
        if isinstance(claim, AgentRequest):
            if binding.role not in {"Manager", "Developer", "Verifier"}:
                return False
            domain = "agent-request"
        else:
            if binding.role != "Maintainer":
                return False
            domain = "human-decision"
        return verify_payload(
            domain,
            claim.model_dump(mode="json"),
            public_key,
        )
    except (ValueError, TypeError):
        return False
