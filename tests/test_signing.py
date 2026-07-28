from __future__ import annotations

import base64
import copy
import hashlib
from collections import UserDict
from collections.abc import Iterator, Mapping
from types import MappingProxyType

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import openworkproof.signing as signing
from conftest import SHA256_A, SHA256_B, SHA256_C, SHA256_D, SHA256_E
from openworkproof.models import (
    AgentRequest,
    ApprovalHumanDecision,
    FrozenDict,
    KeyBinding,
    WorkOrder,
)
from openworkproof.signing import (
    ALLOWED_CANONICAL_DOMAINS,
    ALLOWED_SIGNED_DOMAINS,
    canonical_bytes,
    decode_and_verify_key_binding,
    digest_payload,
    key_id,
    sign_payload,
    unsigned_payload,
    verify_nested_claim,
    verify_payload,
    verify_work_order_identity_bindings,
)


ROLES = ("Maintainer", "Manager", "Developer", "Verifier", "Sidecar")


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


@pytest.fixture
def role_keys() -> dict[str, tuple[Ed25519PrivateKey, dict[str, str]]]:
    result = {}
    for role in ROLES:
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        raw = public_key.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        result[role] = (
            private_key,
            {
                "role": role,
                "subject_id": role.lower(),
                "key_id": key_id(public_key),
                "public_key_b64url": _b64url(raw),
            },
        )
    return result


def _signed_work_order(
    work_order_dict: dict,
    role_keys: dict[str, tuple[Ed25519PrivateKey, dict[str, str]]],
) -> WorkOrder:
    candidate = copy.deepcopy(work_order_dict)
    bindings = [copy.deepcopy(role_keys[role][1]) for role in ROLES]
    maintainer = bindings[0]
    manager = bindings[1]
    candidate["key_bindings"] = bindings
    candidate["issuer_id"] = maintainer["subject_id"]
    candidate["signer_key_id"] = maintainer["key_id"]
    candidate["acceptor_key_ids"] = [maintainer["key_id"]]
    candidate["root_grant_template"]["issuer_key_id"] = maintainer["key_id"]
    candidate["root_grant_template"]["subject_agent_id"] = manager["subject_id"]
    candidate["root_grant_template"]["subject_key_id"] = manager["key_id"]
    return WorkOrder.model_validate(
        sign_payload("work-order", candidate, role_keys["Maintainer"][0])
    )


def _agent_request(
    work_order: WorkOrder,
    private_key: Ed25519PrivateKey,
    binding: KeyBinding,
) -> AgentRequest:
    return AgentRequest.model_validate(
        sign_payload(
            "agent-request",
            {
                "claim_type": "agent-request",
                "work_order_digest": work_order.digest,
                "grant_id": SHA256_A,
                "actor_id": binding.subject_id,
                "actor_key_id": binding.key_id,
                "tool_name": "owp.repo_read",
                "arguments_digest": SHA256_B,
                "nonce": SHA256_C,
                "requested_at": "2026-01-01T00:00:01Z",
                "authentication_method": "agent_signature",
                "model_id": "model",
                "model_version": "1",
                "prompt_template_digest": SHA256_D,
                "context_source_digest": SHA256_E,
            },
            private_key,
        )
    )


def _human_decision(
    work_order: WorkOrder,
    private_key: Ed25519PrivateKey,
    binding: KeyBinding,
) -> ApprovalHumanDecision:
    return ApprovalHumanDecision.model_validate(
        sign_payload(
            "human-decision",
            {
                "claim_type": "human-decision",
                "decision_type": "approval_decision",
                "work_order_digest": work_order.digest,
                "decision": "approved",
                "reason": "APPROVAL_GRANTED",
                "decided_at": "2026-01-01T00:00:02Z",
                "actor_id": binding.subject_id,
                "actor_key_id": binding.key_id,
                "request_receipt_id": SHA256_A,
                "request_receipt_digest": SHA256_B,
                "approved_scope": {
                    "work_order_digest": work_order.digest,
                    "operation": "create_local_pr_proposal",
                    "target_patch_digest": SHA256_C,
                },
                "expires_at": "2026-01-01T01:00:00Z",
            },
            private_key,
        )
    )


def test_canonical_domains_are_exact_and_key_order_is_irrelevant() -> None:
    assert ALLOWED_CANONICAL_DOMAINS == frozenset(
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
    assert ALLOWED_SIGNED_DOMAINS == ALLOWED_CANONICAL_DOMAINS - {
        "sidecar-event"
    }
    assert canonical_bytes("manifest", {"b": 2, "a": 1}) == canonical_bytes(
        "manifest", {"a": 1, "b": 2}
    )
    with pytest.raises(ValueError):
        canonical_bytes("unknown", {"a": 1})


def test_unsigned_payload_excludes_only_digest_and_signature() -> None:
    assert unsigned_payload(
        {
            "value": 1,
            "digest": SHA256_A,
            "signature_alg": "Ed25519",
            "signer_key_id": "ed25519:" + SHA256_B,
            "signature": "invalid",
        }
    ) == {
        "value": 1,
        "signature_alg": "Ed25519",
        "signer_key_id": "ed25519:" + SHA256_B,
    }


def test_signature_cannot_cross_domains_or_survive_mutation() -> None:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    signed = sign_payload(
        "work-order",
        {"work_order_id": SHA256_A},
        private_key,
    )
    assert verify_payload("work-order", signed, public_key)
    assert not verify_payload("capability-grant", signed, public_key)
    assert not verify_payload(
        "work-order",
        {**signed, "work_order_id": SHA256_B},
        public_key,
    )


def test_sidecar_event_is_digest_only_and_cannot_be_inner_signed() -> None:
    private_key = Ed25519PrivateKey.generate()
    payload = {"claim_type": "sidecar-event", "input_digest": SHA256_A}
    assert len(digest_payload("sidecar-event", payload)) == 64
    with pytest.raises(ValueError):
        sign_payload("sidecar-event", payload, private_key)
    assert not verify_payload(
        "sidecar-event",
        {"digest": digest_payload("sidecar-event", payload), **payload},
        private_key.public_key(),
    )


def test_key_ids_are_full_fingerprints_and_key_encoding_is_strict() -> None:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    raw = public_key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    assert key_id(public_key) == f"ed25519:{hashlib.sha256(raw).hexdigest()}"
    assert len(key_id(public_key)) == len("ed25519:") + 64

    valid = KeyBinding(
        role="Maintainer",
        subject_id="maintainer",
        key_id=key_id(public_key),
        public_key_b64url=_b64url(raw),
    )
    assert decode_and_verify_key_binding(valid).public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    ) == raw
    for encoded in (_b64url(raw) + "=", "////", _b64url(raw[:-1])):
        malformed = KeyBinding.model_construct(
            role="Maintainer",
            subject_id="maintainer",
            key_id=key_id(public_key),
            public_key_b64url=encoded,
        )
        with pytest.raises(ValueError):
            decode_and_verify_key_binding(malformed)


def test_work_order_recomputes_all_keys_and_binds_maintainer(
    work_order_dict: dict,
    role_keys: dict[str, tuple[Ed25519PrivateKey, dict[str, str]]],
) -> None:
    work_order = _signed_work_order(work_order_dict, role_keys)
    assert verify_work_order_identity_bindings(work_order)
    assert not verify_work_order_identity_bindings(
        work_order.model_copy(update={"issuer_id": "manager"})
    )
    assert not verify_work_order_identity_bindings(
        work_order.model_copy(update={"objective": "tampered"})
    )
    assert not verify_work_order_identity_bindings(
        work_order.model_copy(
            update={"signer_key_id": work_order.key_bindings[1].key_id}
        )
    )
    assert not verify_work_order_identity_bindings(
        work_order.model_copy(
            update={"acceptor_key_ids": (work_order.key_bindings[1].key_id,)}
        )
    )
    forged_binding = work_order.key_bindings[4].model_copy(
        update={"key_id": work_order.key_bindings[0].key_id}
    )
    assert not verify_work_order_identity_bindings(
        work_order.model_copy(
            update={"key_bindings": (*work_order.key_bindings[:4], forged_binding)}
        )
    )


def test_nested_agent_and_human_claims_bind_exact_work_order_identity(
    work_order_dict: dict,
    role_keys: dict[str, tuple[Ed25519PrivateKey, dict[str, str]]],
) -> None:
    work_order = _signed_work_order(work_order_dict, role_keys)
    manager = work_order.key_bindings[1]
    agent = _agent_request(work_order, role_keys["Manager"][0], manager)
    assert verify_nested_claim(agent, work_order)
    assert not verify_nested_claim(
        agent.model_copy(update={"actor_id": "developer"}),
        work_order,
    )
    assert not verify_nested_claim(
        agent.model_copy(update={"actor_key_id": work_order.key_bindings[2].key_id}),
        work_order,
    )
    assert not verify_nested_claim(
        agent.model_copy(update={"signer_key_id": work_order.key_bindings[2].key_id}),
        work_order,
    )

    maintainer = work_order.key_bindings[0]
    human = _human_decision(work_order, role_keys["Maintainer"][0], maintainer)
    assert verify_nested_claim(human, work_order)
    for field, value in (
        ("actor_id", "manager"),
        ("actor_key_id", work_order.key_bindings[1].key_id),
        ("signer_key_id", work_order.key_bindings[1].key_id),
    ):
        assert not verify_nested_claim(human.model_copy(update={field: value}), work_order)
    for role in ("Manager", "Developer", "Verifier", "Sidecar"):
        wrong_binding = next(
            binding for binding in work_order.key_bindings if binding.role == role
        )
        wrong = _human_decision(work_order, role_keys[role][0], wrong_binding)
        assert not verify_nested_claim(wrong, work_order)


@pytest.mark.parametrize(
    "invalid",
    [
        2**53,
        -1,
        1.0,
        True,
        "1",
        float("nan"),
        float("inf"),
        float("-inf"),
    ],
)
def test_canonicalization_rejects_invalid_protocol_numbers(invalid: object) -> None:
    with pytest.raises(ValueError):
        canonical_bytes("manifest", {"sequence": invalid})


def test_canonicalization_accepts_maximum_safe_integer() -> None:
    assert canonical_bytes("manifest", {"sequence": 2**53 - 1})


@pytest.mark.parametrize(
    ("field_name", "invalid"),
    [
        ("expected_state_version", True),
        ("expected_state_version", "1"),
        ("grant_remaining_before", True),
        ("grant_remaining_before", "1"),
    ],
)
def test_all_protocol_integer_slots_reject_non_integer_values(
    field_name: str,
    invalid: object,
) -> None:
    with pytest.raises(ValueError):
        canonical_bytes("manifest", {field_name: invalid})


def test_signing_integer_slot_registry_matches_protocol_models_audit() -> None:
    assert signing._NON_NEGATIVE_INTEGER_FIELDS == frozenset(
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


@pytest.mark.parametrize("invalid_domain", [[], {}])
def test_untrusted_unhashable_domains_fail_closed(invalid_domain: object) -> None:
    private_key = Ed25519PrivateKey.generate()
    assert not verify_payload(
        invalid_domain,  # type: ignore[arg-type]
        {},
        private_key.public_key(),
    )
    with pytest.raises(ValueError):
        canonical_bytes(invalid_domain, {})  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        digest_payload(invalid_domain, {})  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        sign_payload(invalid_domain, {}, private_key)  # type: ignore[arg-type]


def test_untrusted_signature_failures_return_false() -> None:
    private_key = Ed25519PrivateKey.generate()
    signed = sign_payload("manifest", {"sequence": 1}, private_key)
    assert not verify_payload(
        "manifest",
        {**signed, "signature": signed["signature"] + "="},
        private_key.public_key(),
    )
    assert not verify_payload(
        "manifest",
        {**signed, "signature": _b64url(b"x" * 63)},
        private_key.public_key(),
    )


def _nested_lists(depth: int) -> dict:
    value: object = 0
    for _ in range(depth):
        value = [value]
    return {"value": value}


def test_deep_and_cyclic_payloads_fail_closed_without_recursion_error() -> None:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    deep = _nested_lists(1_100)
    cyclic: dict[str, object] = {}
    cyclic["self"] = cyclic

    for payload in (deep, cyclic):
        with pytest.raises(ValueError):
            canonical_bytes("manifest", payload)
        with pytest.raises(ValueError):
            sign_payload("manifest", payload, private_key)

        untrusted = {
            "signature_alg": "Ed25519",
            "signer_key_id": key_id(public_key),
            "digest": SHA256_A,
            "signature": _b64url(b"x" * 64),
            "value": payload,
        }
        assert not verify_payload("manifest", untrusted, public_key)


def test_json_snapshot_depth_and_node_budgets_have_exact_boundaries() -> None:
    assert signing.MAX_JSON_DEPTH == 128
    assert signing.MAX_JSON_NODES == 10_000
    assert canonical_bytes(
        "manifest",
        _nested_lists(signing.MAX_JSON_DEPTH),
    )
    with pytest.raises(ValueError):
        canonical_bytes(
            "manifest",
            _nested_lists(signing.MAX_JSON_DEPTH + 1),
        )

    assert canonical_bytes(
        "manifest",
        {"items": [0] * (signing.MAX_JSON_NODES - 2)},
    )
    with pytest.raises(ValueError):
        canonical_bytes(
            "manifest",
            {"items": [0] * (signing.MAX_JSON_NODES - 1)},
        )


def test_signing_and_unsigned_payload_take_independent_nested_snapshots() -> None:
    private_key = Ed25519PrivateKey.generate()
    source = {"nested": {"items": [1, {"value": "original"}]}}
    unsigned = unsigned_payload(source)
    signed = sign_payload("manifest", source, private_key)

    source["nested"]["items"].append(2)
    source["nested"]["items"][1]["value"] = "mutated"

    expected = {"items": [1, {"value": "original"}]}
    assert unsigned["nested"] == expected
    assert signed["nested"] == expected
    assert verify_payload("manifest", signed, private_key.public_key())


class _ExplodingGetMapping(Mapping[str, object]):
    def __init__(self, source: dict[str, object]) -> None:
        self.source = source

    def __getitem__(self, key: str) -> object:
        return self.source[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self.source)

    def __len__(self) -> int:
        return len(self.source)

    def get(self, key: str, default: object = None) -> object:
        raise RuntimeError("hostile get")


class _LyingUnboundedItemsMapping(Mapping[str, object]):
    def __init__(self, headers: dict[str, object] | None = None) -> None:
        self.headers = headers or {}
        self.consumed = 0

    def __getitem__(self, key: str) -> object:
        return self.headers[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self.headers)

    def __len__(self) -> int:
        return 0

    def items(self) -> Iterator[tuple[str, object]]:
        for item in self.headers.items():
            self.consumed += 1
            yield item
        for index in range(signing.MAX_JSON_NODES + 100):
            self.consumed += 1
            yield f"extra-{index}", 0


class _ExplodingItemsMapping(_LyingUnboundedItemsMapping):
    def items(self) -> Iterator[tuple[str, object]]:
        for item in self.headers.items():
            yield item
        yield "value", 1
        raise RuntimeError("hostile items iterator")


class _MalformedPairMapping(Mapping[str, object]):
    def __init__(
        self,
        malformed_pair: object,
        headers: dict[str, object] | None = None,
    ) -> None:
        self.malformed_pair = malformed_pair
        self.headers = headers or {}

    def __getitem__(self, key: str) -> object:
        return self.headers[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self.headers)

    def __len__(self) -> int:
        return len(self.headers) + 1

    def items(self) -> Iterator[object]:
        yield from self.headers.items()
        yield self.malformed_pair


def test_verify_never_reads_get_from_the_untrusted_mapping() -> None:
    private_key = Ed25519PrivateKey.generate()
    signed = sign_payload("manifest", {"value": 1}, private_key)
    hostile = _ExplodingGetMapping(signed)
    assert verify_payload("manifest", hostile, private_key.public_key())


def test_supported_mapping_wrappers_preserve_canonical_bytes_and_verify() -> None:
    private_key = Ed25519PrivateKey.generate()
    signed = sign_payload(
        "manifest",
        {"nested": {"items": [1, 2]}},
        private_key,
    )
    expected = canonical_bytes("manifest", signed)
    for wrapped in (
        MappingProxyType(signed),
        UserDict(signed),
        FrozenDict(signed),
    ):
        assert canonical_bytes("manifest", wrapped) == expected
        assert verify_payload("manifest", wrapped, private_key.public_key())


def test_lying_mapping_is_consumed_only_to_the_node_budget() -> None:
    private_key = Ed25519PrivateKey.generate()
    headers = {
        "signature_alg": "Ed25519",
        "signer_key_id": key_id(private_key.public_key()),
        "digest": SHA256_A,
        "signature": _b64url(b"x" * 64),
    }
    cases = (
        (
            _LyingUnboundedItemsMapping(),
            lambda value: canonical_bytes("manifest", value),
            ValueError,
        ),
        (
            _LyingUnboundedItemsMapping(),
            lambda value: sign_payload("manifest", value, private_key),
            ValueError,
        ),
    )
    for hostile, operation, error_type in cases:
        with pytest.raises(error_type):
            operation(hostile)
        assert hostile.consumed <= signing.MAX_JSON_NODES + 3

    untrusted = _LyingUnboundedItemsMapping(headers)
    assert not verify_payload("manifest", untrusted, private_key.public_key())
    assert untrusted.consumed <= signing.MAX_JSON_NODES + 3


def test_mapping_iteration_errors_are_normalized() -> None:
    private_key = Ed25519PrivateKey.generate()
    headers = {
        "signature_alg": "Ed25519",
        "signer_key_id": key_id(private_key.public_key()),
        "digest": SHA256_A,
        "signature": _b64url(b"x" * 64),
    }
    with pytest.raises(ValueError):
        canonical_bytes("manifest", _ExplodingItemsMapping())
    with pytest.raises(ValueError):
        sign_payload("manifest", _ExplodingItemsMapping(), private_key)
    assert not verify_payload(
        "manifest",
        _ExplodingItemsMapping(headers),
        private_key.public_key(),
    )


@pytest.mark.parametrize("malformed_pair", ["ab", ["value", 1]])
def test_mapping_items_require_actual_two_tuple_pairs(
    malformed_pair: object,
) -> None:
    private_key = Ed25519PrivateKey.generate()
    headers = {
        "signature_alg": "Ed25519",
        "signer_key_id": key_id(private_key.public_key()),
        "digest": SHA256_A,
        "signature": _b64url(b"x" * 64),
    }
    with pytest.raises(ValueError):
        canonical_bytes("manifest", _MalformedPairMapping(malformed_pair))
    with pytest.raises(ValueError):
        sign_payload(
            "manifest",
            _MalformedPairMapping(malformed_pair),
            private_key,
        )
    assert not verify_payload(
        "manifest",
        _MalformedPairMapping(malformed_pair, headers),
        private_key.public_key(),
    )


def _payload_with_node_count(node_count: int) -> dict[str, object]:
    return {"items": [0] * (node_count - 2)}


def test_every_returned_signed_payload_fits_the_verify_node_budget() -> None:
    private_key = Ed25519PrivateKey.generate()
    maximum_signable_nodes = signing.MAX_JSON_NODES - 4

    signed = sign_payload(
        "manifest",
        _payload_with_node_count(maximum_signable_nodes),
        private_key,
    )
    assert verify_payload("manifest", signed, private_key.public_key())

    for node_count in (
        maximum_signable_nodes + 1,
        maximum_signable_nodes + 2,
    ):
        with pytest.raises(ValueError):
            sign_payload(
                "manifest",
                _payload_with_node_count(node_count),
                private_key,
            )


def test_resigning_still_excludes_old_top_level_digest_and_signature() -> None:
    private_key = Ed25519PrivateKey.generate()
    original = sign_payload("manifest", {"value": 1}, private_key)
    with_stale_signature = {
        **original,
        "digest": SHA256_A,
        "signature": "stale",
    }
    resigned = sign_payload("manifest", with_stale_signature, private_key)
    assert resigned == original
    assert verify_payload("manifest", resigned, private_key.public_key())
