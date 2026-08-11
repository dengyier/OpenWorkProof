from __future__ import annotations

import base64
import copy
import hashlib
from typing import get_args

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from openworkproof.models import (
    ActionBindingManifest,
    AgentRequest,
    AgentRequestV04,
    AuthorityCheckpoint,
    AuthorityStatus,
    BindingDecision,
    BindingDecisionDraft,
    BindingOutcome,
    BindingReasonCode,
    EvaluationScopeManifest,
    JudgmentCommitment,
    VerificationProfileV02,
)
from openworkproof.signing import (
    authority_checkpoint_signing_bytes,
    canonical_bytes,
    key_id,
    sign_authority_checkpoint,
    sign_payload,
    verify_authority_checkpoint,
    verify_payload,
)


def _resign_v04(
    domain: str, candidate: dict, private_key: Ed25519PrivateKey
) -> dict:
    return sign_payload(domain, candidate, private_key, version="0.4")


def _redigest_binding_decision(candidate: dict) -> None:
    payload = {
        key: value
        for key, value in candidate.items()
        if key not in {"digest", "verifier_signatures"}
    }
    candidate["digest"] = hashlib.sha256(
        canonical_bytes("binding-decision", payload, version="0.4")
    ).hexdigest()


def _rebuild_binding_shape(candidate: dict, model_kind: str) -> object:
    rebuilt = copy.deepcopy(candidate)
    if model_kind == "draft":
        rebuilt.pop("schema_version")
        rebuilt.pop("verifier_signatures")
        rebuilt.pop("digest")
        return BindingDecisionDraft.model_validate(rebuilt)
    _redigest_binding_decision(rebuilt)
    return BindingDecision.model_validate(rebuilt)


def _public_key_b64url(private_key: Ed25519PrivateKey) -> str:
    raw = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _rebuild_authority_checkpoint(candidate: dict) -> AuthorityCheckpoint:
    rebuilt = copy.deepcopy(candidate)
    payload = {
        key: value
        for key, value in rebuilt.items()
        if key not in {"digest", "signature"}
    }
    rebuilt["digest"] = hashlib.sha256(
        canonical_bytes("authority-checkpoint", payload, version="0.4")
    ).hexdigest()
    return AuthorityCheckpoint.model_validate(rebuilt)


def test_valid_v04_models_construct(
    judgment_commitment_v04: JudgmentCommitment,
    action_binding_manifest_v04: ActionBindingManifest,
    authority_checkpoint_v04: AuthorityCheckpoint,
    binding_decision_v04: BindingDecision,
    agent_request_v04: AgentRequestV04,
) -> None:
    assert judgment_commitment_v04.schema_version.endswith("/0.4")
    assert action_binding_manifest_v04.schema_version.endswith("/0.4")
    assert authority_checkpoint_v04.schema_version.endswith("/0.4")
    assert binding_decision_v04.decision == "BOUND"
    assert agent_request_v04.schema_version.endswith("/0.4")


def test_v04_fixtures_separate_internal_and_external_trust_domains(
    judgment_commitment_v04: JudgmentCommitment,
    action_binding_manifest_v04: ActionBindingManifest,
    authority_checkpoint_v04: AuthorityCheckpoint,
    binding_decision_v04: BindingDecision,
    agent_request_v04: AgentRequestV04,
    binding_acceptor_private_key_v04: Ed25519PrivateKey,
    binding_manager_private_key_v04: Ed25519PrivateKey,
    binding_developer_private_key_v04: Ed25519PrivateKey,
    binding_verifier_private_key_v04: Ed25519PrivateKey,
    binding_authority_private_key_v04: Ed25519PrivateKey,
    binding_secondary_verifier_private_key_v04: Ed25519PrivateKey,
) -> None:
    internal_key_ids = {
        judgment_commitment_v04.signer_key_id,
        action_binding_manifest_v04.signer_key_id,
        agent_request_v04.signer_key_id,
        binding_decision_v04.verifier_signatures[0].verifier_key_id,
    }
    assert internal_key_ids == {
        key_id(binding_acceptor_private_key_v04.public_key()),
        key_id(binding_manager_private_key_v04.public_key()),
        key_id(binding_developer_private_key_v04.public_key()),
        key_id(binding_verifier_private_key_v04.public_key()),
    }
    assert authority_checkpoint_v04.authority_key_id == key_id(
        binding_authority_private_key_v04.public_key()
    )
    assert authority_checkpoint_v04.authority_key_id not in internal_key_ids
    assert key_id(
        binding_secondary_verifier_private_key_v04.public_key()
    ) not in internal_key_ids | {authority_checkpoint_v04.authority_key_id}


def test_v04_outcomes_statuses_and_reason_codes_are_exactly_closed() -> None:
    assert set(get_args(BindingOutcome)) == {"BOUND", "UNBOUND", "INDETERMINATE"}
    assert set(get_args(AuthorityStatus)) == {
        "not_required",
        "current",
        "missing",
        "stale",
        "forked",
        "unavailable",
    }
    assert set(get_args(BindingReasonCode)) == {
        "JUDGMENT_SIGNATURE_INVALID",
        "JUDGMENT_EXPIRED",
        "JUDGMENT_ARTIFACT_MISSING",
        "JUDGMENT_DIGEST_MISMATCH",
        "JUDGMENT_FACTS_DIGEST_MISMATCH",
        "JUDGMENT_DISPOSITION_DIGEST_MISMATCH",
        "JUDGMENT_SUPERSEDED",
        "ADAPTER_PROFILE_DIGEST_MISMATCH",
        "ACTION_DIGEST_MISMATCH",
        "ACTION_ARGUMENTS_MISMATCH",
        "ACTION_MAPPING_REJECTED",
        "ACTION_OUTSIDE_APPROVED_SCOPE",
        "ACTION_SIDE_EFFECT_UNDECLARED",
        "REPLAY_UNAVAILABLE",
        "REPLAY_DIVERGED",
        "EVALUATOR_VERSION_DRIFT",
        "AUTHORITY_CHECKPOINT_MISSING",
        "AUTHORITY_CHECKPOINT_STALE",
        "AUTHORITY_CHECKPOINT_SIGNATURE_INVALID",
        "AUTHORITY_FORK_DETECTED",
        "AUTHORITY_ROLLBACK_DETECTED",
        "ALTERNATIVE_WORK_ORDER_DETECTED",
        "UNSIGNED_METADATA_REFERENCE",
        "EVIDENCE_INCOMPLETE",
        "VERIFICATION_NOT_CURRENT",
        "INDEPENDENCE_UNPROVEN",
    }


@pytest.mark.parametrize(
    "field_name",
    [
        "acceptance_condition_digests",
        "excluded_scope_digests",
        "required_artifact_digests",
    ],
)
def test_judgment_commitment_requires_nonempty_sorted_unique_customer_intent(
    judgment_commitment_v04_dict: dict,
    binding_acceptor_private_key_v04: Ed25519PrivateKey,
    field_name: str,
) -> None:
    for invalid in ([], ["b" * 64, "a" * 64], ["a" * 64, "a" * 64]):
        candidate = copy.deepcopy(judgment_commitment_v04_dict)
        candidate[field_name] = invalid
        candidate = _resign_v04(
            "judgment-commitment", candidate, binding_acceptor_private_key_v04
        )
        with pytest.raises(ValidationError, match=field_name):
            JudgmentCommitment.model_validate(candidate)


def test_judgment_commitment_enforces_collection_and_string_bounds(
    judgment_commitment_v04_dict: dict,
) -> None:
    too_many = copy.deepcopy(judgment_commitment_v04_dict)
    too_many["acceptance_condition_digests"] = [
        f"{index:064x}" for index in range(65)
    ]
    with pytest.raises(ValidationError, match="64"):
        JudgmentCommitment.model_validate(too_many)

    too_long = copy.deepcopy(judgment_commitment_v04_dict)
    too_long["repository"] = "x" * 4097
    with pytest.raises(ValidationError, match="4096"):
        JudgmentCommitment.model_validate(too_long)


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("valid_from", "2026-01-02T00:00:00Z"),
        ("created_at", "2026-01-01T00:00:02Z"),
    ],
)
def test_judgment_commitment_requires_ordered_times(
    judgment_commitment_v04_dict: dict,
    binding_acceptor_private_key_v04: Ed25519PrivateKey,
    field_name: str,
    value: str,
) -> None:
    candidate = copy.deepcopy(judgment_commitment_v04_dict)
    candidate[field_name] = value
    candidate = _resign_v04(
        "judgment-commitment", candidate, binding_acceptor_private_key_v04
    )
    with pytest.raises(ValidationError, match="time|created|valid"):
        JudgmentCommitment.model_validate(candidate)


def test_judgment_commitment_rejects_digest_mismatch(
    judgment_commitment_v04_dict: dict,
) -> None:
    candidate = copy.deepcopy(judgment_commitment_v04_dict)
    candidate["digest"] = "f" * 64
    with pytest.raises(ValidationError, match="digest"):
        JudgmentCommitment.model_validate(candidate)


@pytest.mark.parametrize(
    "field_name",
    [
        "allowed_tool_names",
        "allowed_action_kinds",
        "allowed_path_roots",
        "required_test_profile_digests",
    ],
)
def test_action_binding_manifest_requires_nonempty_sorted_unique_collections(
    action_binding_manifest_v04_dict: dict,
    binding_manager_private_key_v04: Ed25519PrivateKey,
    field_name: str,
) -> None:
    valid_item = action_binding_manifest_v04_dict[field_name][0]
    for invalid in ([], [valid_item, valid_item]):
        candidate = copy.deepcopy(action_binding_manifest_v04_dict)
        candidate[field_name] = invalid
        candidate = _resign_v04(
            "action-binding-manifest", candidate, binding_manager_private_key_v04
        )
        with pytest.raises(ValidationError, match=field_name):
            ActionBindingManifest.model_validate(candidate)


def test_action_binding_manifest_rejects_unsorted_and_overlong_collections(
    action_binding_manifest_v04_dict: dict,
    binding_manager_private_key_v04: Ed25519PrivateKey,
) -> None:
    unsorted = copy.deepcopy(action_binding_manifest_v04_dict)
    unsorted["allowed_action_kinds"] = ["test", "patch"]
    unsorted = _resign_v04(
        "action-binding-manifest", unsorted, binding_manager_private_key_v04
    )
    with pytest.raises(ValidationError, match="allowed_action_kinds"):
        ActionBindingManifest.model_validate(unsorted)

    too_many = copy.deepcopy(action_binding_manifest_v04_dict)
    too_many["causal_parent_manifest_ids"] = [
        f"{index:064x}" for index in range(65)
    ]
    with pytest.raises(ValidationError, match="64"):
        ActionBindingManifest.model_validate(too_many)


def test_action_binding_manifest_requires_supersedes_pair_and_matching_parent(
    action_binding_manifest_v04_dict: dict,
    binding_manager_private_key_v04: Ed25519PrivateKey,
) -> None:
    unpaired = copy.deepcopy(action_binding_manifest_v04_dict)
    unpaired["supersedes_binding_manifest_id"] = "a" * 64
    unpaired = _resign_v04(
        "action-binding-manifest", unpaired, binding_manager_private_key_v04
    )
    with pytest.raises(ValidationError, match="supersedes"):
        ActionBindingManifest.model_validate(unpaired)

    wrong_parent = copy.deepcopy(action_binding_manifest_v04_dict)
    wrong_parent["supersedes_binding_manifest_id"] = "a" * 64
    wrong_parent["supersedes_binding_manifest_digest"] = "b" * 64
    wrong_parent = _resign_v04(
        "action-binding-manifest", wrong_parent, binding_manager_private_key_v04
    )
    with pytest.raises(ValidationError, match="causal"):
        ActionBindingManifest.model_validate(wrong_parent)


def test_action_binding_manifest_requires_created_before_expiry(
    action_binding_manifest_v04_dict: dict,
    binding_manager_private_key_v04: Ed25519PrivateKey,
) -> None:
    candidate = copy.deepcopy(action_binding_manifest_v04_dict)
    candidate["expires_at"] = candidate["created_at"]
    candidate = _resign_v04(
        "action-binding-manifest", candidate, binding_manager_private_key_v04
    )
    with pytest.raises(ValidationError, match="time|expires"):
        ActionBindingManifest.model_validate(candidate)


def test_authority_checkpoint_enforces_revision_predecessor_and_times(
    authority_checkpoint_v04_dict: dict,
) -> None:
    zero = copy.deepcopy(authority_checkpoint_v04_dict)
    zero["monotonic_revision"] = 0
    with pytest.raises(ValidationError, match="monotonic_revision|1"):
        AuthorityCheckpoint.model_validate(zero)

    first_with_parent = copy.deepcopy(authority_checkpoint_v04_dict)
    first_with_parent["predecessor_checkpoint_digest"] = "a" * 64
    with pytest.raises(ValidationError, match="predecessor"):
        AuthorityCheckpoint.model_validate(first_with_parent)

    later_without_parent = copy.deepcopy(authority_checkpoint_v04_dict)
    later_without_parent["monotonic_revision"] = 2
    with pytest.raises(ValidationError, match="predecessor"):
        AuthorityCheckpoint.model_validate(later_without_parent)

    unordered = copy.deepcopy(authority_checkpoint_v04_dict)
    unordered["expires_at"] = unordered["effective_at"]
    with pytest.raises(ValidationError, match="time|expires"):
        AuthorityCheckpoint.model_validate(unordered)


def test_authority_checkpoint_rejects_digest_or_signature_shape_mismatch(
    authority_checkpoint_v04_dict: dict,
) -> None:
    bad_digest = copy.deepcopy(authority_checkpoint_v04_dict)
    bad_digest["digest"] = "f" * 64
    with pytest.raises(ValidationError, match="digest"):
        AuthorityCheckpoint.model_validate(bad_digest)

    bad_signature = copy.deepcopy(authority_checkpoint_v04_dict)
    bad_signature["signature"] = "not-a-signature"
    with pytest.raises(ValidationError, match="signature"):
        AuthorityCheckpoint.model_validate(bad_signature)


def test_authority_checkpoint_detached_signing_uses_authority_key_id(
    authority_checkpoint_v04_dict: dict,
    binding_authority_private_key_v04: Ed25519PrivateKey,
) -> None:
    checkpoint = AuthorityCheckpoint.model_validate(authority_checkpoint_v04_dict)
    encoded = authority_checkpoint_signing_bytes(checkpoint)
    assert b'"authority_key_id"' in encoded
    assert b'"signer_key_id"' not in encoded
    assert verify_authority_checkpoint(
        checkpoint, binding_authority_private_key_v04.public_key()
    )


def test_sign_authority_checkpoint_builds_valid_detached_envelope(
    authority_checkpoint_v04_dict: dict,
    binding_authority_private_key_v04: Ed25519PrivateKey,
) -> None:
    payload = {
        key: value
        for key, value in authority_checkpoint_v04_dict.items()
        if key not in {"digest", "signature"}
    }
    signed = sign_authority_checkpoint(
        payload, binding_authority_private_key_v04
    )
    checkpoint = AuthorityCheckpoint.model_validate(signed)
    assert checkpoint.authority_key_id == key_id(
        binding_authority_private_key_v04.public_key()
    )
    assert verify_authority_checkpoint(
        checkpoint, binding_authority_private_key_v04.public_key()
    )


def test_authority_checkpoint_crypto_negative_matrix_uses_valid_models(
    authority_checkpoint_v04_dict: dict,
    binding_authority_private_key_v04: Ed25519PrivateKey,
    binding_manager_private_key_v04: Ed25519PrivateKey,
) -> None:
    original = AuthorityCheckpoint.model_validate(authority_checkpoint_v04_dict)
    assert not verify_authority_checkpoint(
        original, binding_manager_private_key_v04.public_key()
    )

    stale_signature = copy.deepcopy(authority_checkpoint_v04_dict)
    stale_signature["expires_at"] = "2026-01-03T00:00:00Z"
    stale_model = _rebuild_authority_checkpoint(stale_signature)
    assert not verify_authority_checkpoint(
        stale_model, binding_authority_private_key_v04.public_key()
    )

    conflicting_key = copy.deepcopy(authority_checkpoint_v04_dict)
    conflicting_key["authority_key_id"] = key_id(
        binding_manager_private_key_v04.public_key()
    )
    conflicting_payload = {
        key: value
        for key, value in conflicting_key.items()
        if key not in {"digest", "signature"}
    }
    conflicting_encoded = canonical_bytes(
        "authority-checkpoint", conflicting_payload, version="0.4"
    )
    conflicting_key["signature"] = base64.urlsafe_b64encode(
        binding_authority_private_key_v04.sign(conflicting_encoded)
    ).decode("ascii").rstrip("=")
    conflicting_model = _rebuild_authority_checkpoint(conflicting_key)
    assert not verify_authority_checkpoint(
        conflicting_model, binding_manager_private_key_v04.public_key()
    )

    cross_domain = copy.deepcopy(authority_checkpoint_v04_dict)
    cross_payload = {
        key: value
        for key, value in cross_domain.items()
        if key not in {"digest", "signature"}
    }
    cross_encoded = canonical_bytes(
        "evaluation-scope", cross_payload, version="0.3"
    )
    cross_domain["signature"] = base64.urlsafe_b64encode(
        binding_authority_private_key_v04.sign(cross_encoded)
    ).decode("ascii").rstrip("=")
    cross_model = _rebuild_authority_checkpoint(cross_domain)
    assert not verify_authority_checkpoint(
        cross_model, binding_authority_private_key_v04.public_key()
    )


def test_agent_request_v04_requires_exact_commitment_and_manifest_fields(
    agent_request_v04_dict: dict,
) -> None:
    for field_name in (
        "judgment_commitment_id",
        "judgment_commitment_digest",
        "action_binding_manifest_id",
        "action_binding_manifest_digest",
    ):
        candidate = copy.deepcopy(agent_request_v04_dict)
        candidate.pop(field_name)
        with pytest.raises(ValidationError, match=field_name):
            AgentRequestV04.model_validate(candidate)


def test_agent_request_v04_rejects_digest_and_signature_mismatch(
    agent_request_v04_dict: dict,
    binding_developer_private_key_v04: Ed25519PrivateKey,
) -> None:
    bad_digest = copy.deepcopy(agent_request_v04_dict)
    bad_digest["digest"] = "f" * 64
    with pytest.raises(ValidationError, match="digest"):
        AgentRequestV04.model_validate(bad_digest)

    unpaired_signer = copy.deepcopy(agent_request_v04_dict)
    unpaired_signer["actor_key_id"] = "ed25519:" + "f" * 64
    unpaired_signer = _resign_v04(
        "agent-request", unpaired_signer, binding_developer_private_key_v04
    )
    with pytest.raises(ValidationError, match="signer|actor"):
        AgentRequestV04.model_validate(unpaired_signer)


def test_binding_decision_requires_nonempty_ordered_one_to_one_receipt_pairs(
    binding_decision_v04_dict: dict,
) -> None:
    empty = copy.deepcopy(binding_decision_v04_dict)
    empty["action_receipt_ids"] = []
    empty["action_receipt_digests"] = []
    with pytest.raises(ValidationError, match="receipt"):
        BindingDecision.model_validate(empty)

    unequal = copy.deepcopy(binding_decision_v04_dict)
    unequal["action_receipt_digests"] = unequal["action_receipt_digests"][:1]
    with pytest.raises(ValidationError, match="one-to-one|receipt"):
        BindingDecision.model_validate(unequal)

    duplicate = copy.deepcopy(binding_decision_v04_dict)
    duplicate["action_receipt_ids"] = ["5" * 64, "5" * 64]
    with pytest.raises(ValidationError, match="receipt"):
        BindingDecision.model_validate(duplicate)

    unsorted = copy.deepcopy(binding_decision_v04_dict)
    unsorted["action_receipt_ids"] = ["6" * 64, "5" * 64]
    with pytest.raises(ValidationError, match="receipt"):
        BindingDecision.model_validate(unsorted)


def test_binding_decision_enforces_reason_outcome_and_authority_compatibility(
    binding_decision_v04_dict: dict,
) -> None:
    bound_reason = copy.deepcopy(binding_decision_v04_dict)
    bound_reason["reason_codes"] = ["EVIDENCE_INCOMPLETE"]
    with pytest.raises(ValidationError, match="reason|BOUND"):
        BindingDecision.model_validate(bound_reason)

    bound_missing = copy.deepcopy(binding_decision_v04_dict)
    bound_missing["authority_status"] = "missing"
    with pytest.raises(ValidationError, match="authority|BOUND"):
        BindingDecision.model_validate(bound_missing)

    unbound_ambiguous = copy.deepcopy(binding_decision_v04_dict)
    unbound_ambiguous["decision"] = "UNBOUND"
    unbound_ambiguous["reason_codes"] = ["EVIDENCE_INCOMPLETE"]
    with pytest.raises(ValidationError, match="reason|UNBOUND"):
        BindingDecision.model_validate(unbound_ambiguous)

    indeterminate_counterevidence = copy.deepcopy(binding_decision_v04_dict)
    indeterminate_counterevidence["decision"] = "INDETERMINATE"
    indeterminate_counterevidence["reason_codes"] = ["ACTION_ARGUMENTS_MISMATCH"]
    with pytest.raises(ValidationError, match="reason|INDETERMINATE"):
        BindingDecision.model_validate(indeterminate_counterevidence)


@pytest.mark.parametrize("model_kind", ["draft", "decision"])
def test_adapter_profile_digest_mismatch_is_unbound_only(
    binding_decision_v04_dict: dict,
    model_kind: str,
) -> None:
    unbound = copy.deepcopy(binding_decision_v04_dict)
    unbound["decision"] = "UNBOUND"
    unbound["reason_codes"] = ["ADAPTER_PROFILE_DIGEST_MISMATCH"]
    assert _rebuild_binding_shape(unbound, model_kind).decision == "UNBOUND"

    candidate = copy.deepcopy(binding_decision_v04_dict)
    candidate["decision"] = "INDETERMINATE"
    candidate["reason_codes"] = ["ADAPTER_PROFILE_DIGEST_MISMATCH"]
    with pytest.raises(ValidationError, match="reason|INDETERMINATE"):
        _rebuild_binding_shape(candidate, model_kind)


@pytest.mark.parametrize(
    "model_kind", ["draft", "decision"]
)
@pytest.mark.parametrize(
    (
        "decision",
        "reason_codes",
        "authority_status",
        "authority_checkpoint_digest",
    ),
    [
        ("BOUND", [], "not_required", None),
        (
            "UNBOUND",
            ["ALTERNATIVE_WORK_ORDER_DETECTED"],
            "current",
            "1" * 64,
        ),
        (
            "INDETERMINATE",
            ["AUTHORITY_CHECKPOINT_MISSING"],
            "missing",
            None,
        ),
        (
            "UNBOUND",
            ["AUTHORITY_CHECKPOINT_STALE"],
            "stale",
            "1" * 64,
        ),
        (
            "UNBOUND",
            ["AUTHORITY_ROLLBACK_DETECTED"],
            "stale",
            "1" * 64,
        ),
        (
            "UNBOUND",
            ["AUTHORITY_FORK_DETECTED"],
            "forked",
            "1" * 64,
        ),
        (
            "INDETERMINATE",
            ["EVIDENCE_INCOMPLETE", "REPLAY_UNAVAILABLE"],
            "unavailable",
            None,
        ),
    ],
)
def test_binding_authority_status_valid_matrix_is_shared_by_both_shapes(
    binding_decision_v04_dict: dict,
    model_kind: str,
    decision: str,
    reason_codes: list[str],
    authority_status: str,
    authority_checkpoint_digest: str | None,
) -> None:
    candidate = copy.deepcopy(binding_decision_v04_dict)
    candidate["decision"] = decision
    candidate["reason_codes"] = reason_codes
    candidate["authority_status"] = authority_status
    candidate["authority_checkpoint_digest"] = authority_checkpoint_digest
    assert _rebuild_binding_shape(candidate, model_kind).authority_status == (
        authority_status
    )


@pytest.mark.parametrize("model_kind", ["draft", "decision"])
@pytest.mark.parametrize(
    (
        "decision",
        "reason_codes",
        "authority_status",
        "authority_checkpoint_digest",
    ),
    [
        ("BOUND", [], "not_required", "1" * 64),
        (
            "UNBOUND",
            ["AUTHORITY_CHECKPOINT_STALE"],
            "not_required",
            None,
        ),
        ("BOUND", [], "current", None),
        (
            "INDETERMINATE",
            ["AUTHORITY_CHECKPOINT_MISSING"],
            "current",
            "1" * 64,
        ),
        (
            "INDETERMINATE",
            ["AUTHORITY_CHECKPOINT_MISSING"],
            "missing",
            "1" * 64,
        ),
        (
            "INDETERMINATE",
            ["EVIDENCE_INCOMPLETE"],
            "missing",
            None,
        ),
        (
            "UNBOUND",
            ["AUTHORITY_CHECKPOINT_STALE"],
            "stale",
            None,
        ),
        (
            "UNBOUND",
            ["ACTION_ARGUMENTS_MISMATCH"],
            "stale",
            "1" * 64,
        ),
        (
            "UNBOUND",
            ["ALTERNATIVE_WORK_ORDER_DETECTED"],
            "forked",
            "1" * 64,
        ),
        (
            "INDETERMINATE",
            ["REPLAY_UNAVAILABLE"],
            "unavailable",
            "1" * 64,
        ),
        (
            "INDETERMINATE",
            ["EVIDENCE_INCOMPLETE"],
            "unavailable",
            None,
        ),
    ],
)
def test_binding_authority_status_invalid_matrix_is_shared_by_both_shapes(
    binding_decision_v04_dict: dict,
    model_kind: str,
    decision: str,
    reason_codes: list[str],
    authority_status: str,
    authority_checkpoint_digest: str | None,
) -> None:
    candidate = copy.deepcopy(binding_decision_v04_dict)
    candidate["decision"] = decision
    candidate["reason_codes"] = reason_codes
    candidate["authority_status"] = authority_status
    candidate["authority_checkpoint_digest"] = authority_checkpoint_digest
    with pytest.raises(ValidationError, match="authority|checkpoint"):
        _rebuild_binding_shape(candidate, model_kind)


@pytest.mark.parametrize(
    ("decision", "reason_code"),
    [
        ("UNBOUND", "JUDGMENT_SIGNATURE_INVALID"),
        ("INDETERMINATE", "AUTHORITY_CHECKPOINT_SIGNATURE_INVALID"),
    ],
)
def test_structural_signature_failures_are_not_semantic_binding_decisions(
    binding_decision_v04_dict: dict,
    decision: str,
    reason_code: str,
) -> None:
    candidate = copy.deepcopy(binding_decision_v04_dict)
    candidate["decision"] = decision
    candidate["reason_codes"] = [reason_code]
    _redigest_binding_decision(candidate)
    with pytest.raises(ValidationError, match="reason"):
        BindingDecision.model_validate(candidate)


@pytest.mark.parametrize("decision", ["UNBOUND", "INDETERMINATE"])
def test_alternative_work_order_is_compatible_with_both_nonbound_outcomes(
    binding_decision_v04_dict: dict,
    decision: str,
) -> None:
    candidate = copy.deepcopy(binding_decision_v04_dict)
    candidate["decision"] = decision
    candidate["reason_codes"] = ["ALTERNATIVE_WORK_ORDER_DETECTED"]
    candidate["authority_status"] = "current"
    _redigest_binding_decision(candidate)
    assert BindingDecision.model_validate(candidate).decision == decision


def test_binding_decision_rejects_unsorted_duplicate_or_empty_reasons(
    binding_decision_v04_dict: dict,
) -> None:
    for reasons in (
        [],
        ["REPLAY_DIVERGED", "ACTION_ARGUMENTS_MISMATCH"],
        ["ACTION_ARGUMENTS_MISMATCH", "ACTION_ARGUMENTS_MISMATCH"],
    ):
        candidate = copy.deepcopy(binding_decision_v04_dict)
        candidate["decision"] = "UNBOUND"
        candidate["reason_codes"] = reasons
        with pytest.raises(ValidationError, match="reason"):
            BindingDecision.model_validate(candidate)


def test_binding_decision_requires_supersedes_pair_and_exact_parent(
    binding_decision_v04_dict: dict,
) -> None:
    unpaired = copy.deepcopy(binding_decision_v04_dict)
    unpaired["supersedes_binding_decision_id"] = "b" * 64
    with pytest.raises(ValidationError, match="supersedes"):
        BindingDecision.model_validate(unpaired)

    wrong_parent = copy.deepcopy(binding_decision_v04_dict)
    wrong_parent["supersedes_binding_decision_id"] = "b" * 64
    wrong_parent["supersedes_binding_decision_digest"] = "c" * 64
    with pytest.raises(ValidationError, match="causal"):
        BindingDecision.model_validate(wrong_parent)


def test_binding_decision_enforces_detached_signature_structure_and_digest(
    binding_decision_v04_dict: dict,
) -> None:
    for signatures in ([], binding_decision_v04_dict["verifier_signatures"] * 2):
        candidate = copy.deepcopy(binding_decision_v04_dict)
        candidate["verifier_signatures"] = signatures
        with pytest.raises(ValidationError, match="signature"):
            BindingDecision.model_validate(candidate)

    bad_digest = copy.deepcopy(binding_decision_v04_dict)
    bad_digest["digest"] = "f" * 64
    with pytest.raises(ValidationError, match="digest"):
        BindingDecision.model_validate(bad_digest)


def test_binding_decision_rejects_duplicate_verifier_subjects(
    binding_decision_v04_dict: dict,
    binding_verifier_private_key_v04: Ed25519PrivateKey,
    binding_secondary_verifier_private_key_v04: Ed25519PrivateKey,
) -> None:
    candidate = copy.deepcopy(binding_decision_v04_dict)
    payload = {
        key: value
        for key, value in candidate.items()
        if key not in {"digest", "verifier_signatures"}
    }
    encoded = canonical_bytes("binding-decision", payload, version="0.4")
    verifier_keys = (
        binding_verifier_private_key_v04,
        binding_secondary_verifier_private_key_v04,
    )
    candidate["verifier_signatures"] = sorted(
        (
            {
                "verifier_subject_id": "same-verifier-subject",
                "verifier_key_id": key_id(private_key.public_key()),
                "signature_alg": "Ed25519",
                "signature": base64.urlsafe_b64encode(
                    private_key.sign(encoded)
                ).decode("ascii").rstrip("="),
            }
            for private_key in verifier_keys
        ),
        key=lambda item: item["verifier_key_id"].encode("utf-8"),
    )
    with pytest.raises(ValidationError, match="subject"):
        BindingDecision.model_validate(candidate)


def test_binding_decision_accepts_two_distinct_verifier_subjects_and_keys(
    binding_decision_v04_dict: dict,
    binding_verifier_private_key_v04: Ed25519PrivateKey,
    binding_secondary_verifier_private_key_v04: Ed25519PrivateKey,
) -> None:
    candidate = copy.deepcopy(binding_decision_v04_dict)
    payload = {
        key: value
        for key, value in candidate.items()
        if key not in {"digest", "verifier_signatures"}
    }
    encoded = canonical_bytes("binding-decision", payload, version="0.4")
    candidate["verifier_signatures"] = sorted(
        (
            {
                "verifier_subject_id": subject,
                "verifier_key_id": key_id(private_key.public_key()),
                "signature_alg": "Ed25519",
                "signature": base64.urlsafe_b64encode(
                    private_key.sign(encoded)
                ).decode("ascii").rstrip("="),
            }
            for subject, private_key in (
                ("verifier-primary", binding_verifier_private_key_v04),
                (
                    "verifier-secondary",
                    binding_secondary_verifier_private_key_v04,
                ),
            )
        ),
        key=lambda item: item["verifier_key_id"].encode("utf-8"),
    )
    decision = BindingDecision.model_validate(candidate)
    assert len(decision.verifier_signatures) == 2


def test_binding_decision_draft_has_exact_unsigned_shape(
    binding_decision_v04_dict: dict,
) -> None:
    candidate = copy.deepcopy(binding_decision_v04_dict)
    candidate.pop("schema_version")
    candidate.pop("verifier_signatures")
    candidate.pop("digest")
    draft = BindingDecisionDraft.model_validate(candidate)
    assert draft.binding_decision_id == binding_decision_v04_dict["binding_decision_id"]


def test_v04_domains_are_version_scoped_and_old_bytes_are_frozen(
    binding_verifier_private_key_v04: Ed25519PrivateKey,
) -> None:
    assert canonical_bytes("manifest", {"b": 2, "a": 1}) == (
        b'{"domain":"openworkproof/manifest/v0.1","payload":{"a":1,"b":2}}'
    )
    assert canonical_bytes("scope-member", {"b": 2, "a": 1}, version="0.3") == (
        b'{"domain":"openworkproof/scope-member/v0.3","payload":{"a":1,"b":2}}'
    )
    signed = sign_payload(
        "judgment-commitment",
        {"value": 1},
        binding_verifier_private_key_v04,
        version="0.4",
    )
    assert verify_payload(
        "judgment-commitment",
        signed,
        binding_verifier_private_key_v04.public_key(),
        version="0.4",
    )
    assert not verify_payload(
        "action-binding-manifest",
        signed,
        binding_verifier_private_key_v04.public_key(),
        version="0.4",
    )
    assert not verify_payload(
        "judgment-commitment",
        signed,
        binding_verifier_private_key_v04.public_key(),
        version="0.3",
    )
    with pytest.raises(ValueError, match="domain"):
        canonical_bytes("judgment-commitment", {}, version="0.3")
    with pytest.raises(ValueError, match="domain"):
        canonical_bytes("manifest", {}, version="0.4")


def test_complete_legacy_signed_object_goldens(
    agent_request_v04_dict: dict,
    binding_developer_private_key_v04: Ed25519PrivateKey,
    verification_profile_dict: dict,
    binding_manager_private_key_v04: Ed25519PrivateKey,
    binding_verifier_private_key_v04: Ed25519PrivateKey,
    evaluation_scope_payload_v03: dict,
    scope_manager_private_key_v03: Ed25519PrivateKey,
) -> None:
    agent_payload = {
        key: value
        for key, value in agent_request_v04_dict.items()
        if key
        not in {
            "digest",
            "signature_alg",
            "signer_key_id",
            "signature",
            "schema_version",
            "judgment_commitment_id",
            "judgment_commitment_digest",
            "action_binding_manifest_id",
            "action_binding_manifest_digest",
        }
    }
    agent = AgentRequest.model_validate(
        sign_payload(
            "agent-request",
            agent_payload,
            binding_developer_private_key_v04,
        )
    )

    profile_payload = copy.deepcopy(verification_profile_dict)
    profile_payload["work_order_digest"] = "a" * 64
    profile_payload["subject_claim_digest"] = "b" * 64
    profile_payload["verifier_bindings"][0].update(
        {
            "verifier_subject_id": "verifier-v02-golden",
            "verifier_key_id": key_id(
                binding_verifier_private_key_v04.public_key()
            ),
            "verifier_public_key_b64url": _public_key_b64url(
                binding_verifier_private_key_v04
            ),
        }
    )
    profile = VerificationProfileV02.model_validate(
        sign_payload(
            "verification-profile",
            profile_payload,
            binding_manager_private_key_v04,
        )
    )

    scope = EvaluationScopeManifest.model_validate(
        sign_payload(
            "evaluation-scope",
            evaluation_scope_payload_v03,
            scope_manager_private_key_v03,
            version="0.3",
        )
    )
    objects = (
        ("v0.1-agent-request", "agent-request", "0.1", agent),
        ("v0.2-verification-profile", "verification-profile", "0.1", profile),
        ("v0.3-evaluation-scope", "evaluation-scope", "0.3", scope),
    )
    observed = {
        label: (
            hashlib.sha256(
                canonical_bytes(
                    domain, value.model_dump(mode="json"), version=version
                )
            ).hexdigest(),
            value.digest,
            value.signature,
        )
        for label, domain, version, value in objects
    }
    assert observed == {
        "v0.1-agent-request": (
            "29ed53245f98f295aeccc1c544eb90d4bccf6dbd8b4a50997ed81d66169ba228",
            "29ed53245f98f295aeccc1c544eb90d4bccf6dbd8b4a50997ed81d66169ba228",
            "89EnUtW690Ms2iBslrQjcobQZawl7sTi73O3zK9nF8D40rMouhjgKxb0"
            "W8YIiWY8xUAXhIeuBvTCsD7lvcJBBg",
        ),
        "v0.2-verification-profile": (
            "7e94bd79667c504acb0b2626d206769e2e21d3055b9e7d13a5ed957190cd7bd3",
            "7e94bd79667c504acb0b2626d206769e2e21d3055b9e7d13a5ed957190cd7bd3",
            "n8DJHN79XLGHSl1DUup5G_SCEGqfKbptdHaO8YbndQko1Qu8dC3KhMe_"
            "EtuAnW6Li74hJ5nawqV_-GfF6g5tDQ",
        ),
        "v0.3-evaluation-scope": (
            "13365cbb1a2af3a4951fc838ab07e58f63387e0cd79ca61c8635981626fa1f83",
            "13365cbb1a2af3a4951fc838ab07e58f63387e0cd79ca61c8635981626fa1f83",
            "ktEnletSX2ROHAiOeYUlX2XCg6U1b7xKEkf07TV2_zBhlhRHTg27Opr"
            "AqhFrCFVyarCJ5S6oCQtxcIQpG_htAA",
        ),
    }
