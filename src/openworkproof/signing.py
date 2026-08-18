from __future__ import annotations

import base64
import hashlib
import math
import re
from collections.abc import Mapping
from typing import Any, Literal

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from openworkproof.models import (
    ActionReceiptEnvelope,
    AgentRequest,
    AgentRequestV04,
    ApprovalHumanDecision,
    AuthorityCheckpoint,
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
        "acceptance-rejection-receipt",
        "acceptance-transition",
        "agent-request",
        "human-decision",
        "sidecar-event",
        "manifest",
        "subject-claim",
        "verification-profile",
        "verification-arm-result",
        "verification-decision",
        "scope-member",
        "scope-requirement",
        "scope-population",
        "evaluation-scope",
    }
)
_UNSIGNED_ONLY_DOMAINS = frozenset({
    "sidecar-event",
    "verification-decision",
    "scope-member",
    "scope-requirement",
    "scope-population",
    "evaluation-scope",
})
ALLOWED_SIGNED_DOMAINS = ALLOWED_CANONICAL_DOMAINS - _UNSIGNED_ONLY_DOMAINS

_V01_CANONICAL_DOMAINS = ALLOWED_CANONICAL_DOMAINS - {
    "scope-member",
    "scope-requirement",
    "scope-population",
    "evaluation-scope",
}
_V03_CANONICAL_DOMAINS = frozenset(
    {
        "scope-member",
        "scope-requirement",
        "scope-population",
        "evaluation-scope",
        "verification-profile",
        "verification-arm-result",
        "verification-decision",
    }
)
_V03_SIGNED_DOMAINS = frozenset(
    {"evaluation-scope", "verification-profile", "verification-arm-result"}
)
_V04_CANONICAL_DOMAINS = frozenset(
    {
        "action-binding-manifest",
        "action-receipt",
        "agent-request",
        "authority-checkpoint",
        "binding-decision",
        "judgment-commitment",
    }
)
_V04_SIGNED_DOMAINS = frozenset(
    {
        "action-binding-manifest",
        "action-receipt",
        "agent-request",
        "binding-decision",
        "judgment-commitment",
    }
)
_V05_CANONICAL_DOMAINS = frozenset(
    {
        "verification-profile",
        "verification-arm-result",
        "verification-decision",
        "retraction-receipt",
    }
)
_V05_SIGNED_DOMAINS = frozenset(
    {
        "verification-profile",
        "verification-arm-result",
        "retraction-receipt",
    }
)


def _canonical_domains_for_version(version: str) -> frozenset[str]:
    if version == "0.1":
        return _V01_CANONICAL_DOMAINS
    if version == "0.3":
        return _V03_CANONICAL_DOMAINS
    if version == "0.4":
        return _V04_CANONICAL_DOMAINS
    if version == "0.5":
        return _V05_CANONICAL_DOMAINS
    raise ValueError("unknown protocol version")


def _signed_domains_for_version(version: str) -> frozenset[str]:
    if version == "0.1":
        return ALLOWED_SIGNED_DOMAINS
    if version == "0.3":
        return _V03_SIGNED_DOMAINS
    if version == "0.4":
        return _V04_SIGNED_DOMAINS
    if version == "0.5":
        return _V05_SIGNED_DOMAINS
    raise ValueError("unknown protocol version")

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


def canonical_bytes(
    object_type: str,
    payload: Mapping[str, Any],
    *,
    version: Literal["0.1", "0.3", "0.4", "0.5"] = "0.1",
) -> bytes:
    allowed_domains = _canonical_domains_for_version(version)
    if (
        type(object_type) is not str
        or object_type not in allowed_domains
    ):
        raise ValueError("unknown canonical domain")
    canonical_input = {
        "domain": f"openworkproof/{object_type}/v{version}",
        "payload": unsigned_payload(payload),
    }
    try:
        return rfc8785.dumps(canonical_input)
    except (ValueError, TypeError, OverflowError) as error:
        raise ValueError("payload is not canonicalizable JCS") from error


def digest_payload(
    object_type: str,
    payload: Mapping[str, Any],
    *,
    version: Literal["0.1", "0.3", "0.4", "0.5"] = "0.1",
) -> str:
    return hashlib.sha256(
        canonical_bytes(object_type, payload, version=version)
    ).hexdigest()


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
    *,
    version: Literal["0.1", "0.3", "0.4", "0.5"] = "0.1",
) -> dict[str, Any]:
    allowed_domains = _signed_domains_for_version(version)
    if type(object_type) is not str or object_type not in allowed_domains:
        raise ValueError("object type cannot be signed")
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ValueError("private key must be Ed25519")
    result = unsigned_payload(payload)
    result["signature_alg"] = "Ed25519"
    result["signer_key_id"] = key_id(private_key.public_key())
    encoded = canonical_bytes(object_type, result, version=version)
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
    *,
    version: Literal["0.1", "0.3", "0.4", "0.5"] = "0.1",
) -> bool:
    try:
        allowed_domains = _signed_domains_for_version(version)
    except ValueError:
        return False
    if (
        type(object_type) is not str
        or object_type not in allowed_domains
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
        encoded = canonical_bytes(object_type, snapshot, version=version)
        if snapshot.get("digest") != hashlib.sha256(encoded).hexdigest():
            return False
        signature = _decode_base64url(snapshot.get("signature"), 64)
        public_key.verify(signature, encoded)
    except (InvalidSignature, ValueError, TypeError):
        return False
    return True


def authority_checkpoint_signing_bytes(
    checkpoint: AuthorityCheckpoint | Mapping[str, Any],
) -> bytes:
    if isinstance(checkpoint, AuthorityCheckpoint):
        payload = checkpoint.model_dump(mode="json")
    elif isinstance(checkpoint, Mapping):
        payload = checkpoint
    else:
        raise ValueError("authority checkpoint must be a mapping")
    if "signer_key_id" in payload:
        raise ValueError("authority checkpoint must use authority_key_id")
    return canonical_bytes("authority-checkpoint", payload, version="0.4")


def sign_authority_checkpoint(
    payload: Mapping[str, Any],
    private_key: Ed25519PrivateKey,
) -> dict[str, Any]:
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ValueError("private key must be Ed25519")
    result = unsigned_payload(payload)
    expected_key_id = key_id(private_key.public_key())
    supplied_key_id = result.get("authority_key_id")
    if supplied_key_id not in {None, expected_key_id}:
        raise ValueError("authority_key_id does not match private key")
    result["authority_key_id"] = expected_key_id
    result["signature_alg"] = "Ed25519"
    encoded = authority_checkpoint_signing_bytes(result)
    result["digest"] = hashlib.sha256(encoded).hexdigest()
    result["signature"] = _encode_base64url(private_key.sign(encoded))
    signed_snapshot = _snapshot_json(result)
    if not isinstance(signed_snapshot, dict):
        raise ValueError("authority checkpoint snapshot must be an object")
    return signed_snapshot


def verify_authority_checkpoint(
    checkpoint: AuthorityCheckpoint | Mapping[str, Any],
    public_key: Ed25519PublicKey,
) -> bool:
    if not isinstance(public_key, Ed25519PublicKey):
        return False
    try:
        if isinstance(checkpoint, AuthorityCheckpoint):
            snapshot = checkpoint.model_dump(mode="json")
        elif isinstance(checkpoint, Mapping):
            snapshot = _snapshot_json(checkpoint)
        else:
            return False
        if not isinstance(snapshot, dict):
            return False
        if (
            snapshot.get("signature_alg") != "Ed25519"
            or snapshot.get("authority_key_id") != key_id(public_key)
            or "signer_key_id" in snapshot
        ):
            return False
        encoded = authority_checkpoint_signing_bytes(snapshot)
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
                "Acceptor",
            )
            or len({binding.key_id for binding in bindings}) != 6
            or len({binding.subject_id for binding in bindings}) != 6
        ):
            return False
        public_keys = [
            decode_and_verify_key_binding(binding) for binding in bindings
        ]
        maintainer = bindings[0]
        acceptor = bindings[5]
        if (
            work_order.issuer_id != maintainer.subject_id
            or work_order.signer_key_id != maintainer.key_id
            or work_order.acceptor_key_ids != (acceptor.key_id,)
            or acceptor.key_id == maintainer.key_id
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
    if type(claim) not in {
        AgentRequest,
        AgentRequestV04,
        ApprovalHumanDecision,
        TerminationHumanDecision,
    }:
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
        if type(claim) in {AgentRequest, AgentRequestV04}:
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
            version="0.4" if type(claim) is AgentRequestV04 else "0.1",
        )
    except (ValueError, TypeError):
        return False


def verify_action_receipt_signature(
    receipt: ActionReceiptEnvelope,
    public_key: Ed25519PublicKey,
) -> bool:
    """Verify an ActionReceipt in its explicit protocol signing domain."""

    if not isinstance(receipt, ActionReceiptEnvelope):
        return False
    version = receipt.protocol_version
    if version not in {"0.1", "0.4"}:
        return False
    return verify_payload(
        "action-receipt",
        receipt.model_dump(mode="json"),
        public_key,
        version=version,
    )
