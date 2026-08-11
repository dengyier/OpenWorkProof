from __future__ import annotations

import copy
import json
import hashlib
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

import openworkproof.evidence as evidence
import openworkproof.binding_transactions as binding_transactions
from openworkproof.binding import (
    CanonicalAdapterProfile,
    DeterministicConstraintProjection,
    canonical_test_profile_digest,
    constraint_projection_digest,
    projection_from_adapter_profile,
    validate_action_binding_manifest,
)
from openworkproof.binding_transactions import (
    BindingCommittedError,
    BindingInputError,
    BindingTransactionError,
    JudgmentAuthorityContext,
    commit_action_binding_manifest,
    commit_judgment_commitment,
    load_current_action_binding_manifest,
)
from openworkproof.models import (
    ActionBindingManifest,
    EvaluationScopeManifest,
    JudgmentCommitment,
    SubjectClaim,
    WorkOrder,
)
from openworkproof.scope import evaluation_scope_id, requirement_digest
from openworkproof.signing import sign_payload
from openworkproof.verification import commit_evaluation_scope


UTC = timezone.utc


def _snapshot(path: Path) -> dict[str, tuple[tuple[object, ...], ...]]:
    connection = sqlite3.connect(path)
    try:
        tables = tuple(
            row[0]
            for row in connection.execute(
                """
                SELECT name FROM sqlite_master
                WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
                ORDER BY name
                """
            )
        )
        return {
            table: tuple(connection.execute(f'SELECT * FROM "{table}"'))
            for table in tables
        }
    finally:
        connection.close()


def _resign_manifest(
    manifest: ActionBindingManifest,
    private_key: Ed25519PrivateKey,
    **updates: object,
) -> ActionBindingManifest:
    payload = manifest.model_dump(
        mode="json",
        exclude={"digest", "signature_alg", "signer_key_id", "signature"},
    )
    payload.update(copy.deepcopy(updates))
    return ActionBindingManifest.model_validate(
        sign_payload(
            "action-binding-manifest", payload, private_key, version="0.4"
        )
    )


def _resign_judgment(
    judgment: JudgmentCommitment,
    private_key: Ed25519PrivateKey,
    **updates: object,
) -> JudgmentCommitment:
    payload = judgment.model_dump(
        mode="json",
        exclude={"digest", "signature_alg", "signer_key_id", "signature"},
    )
    payload.update(copy.deepcopy(updates))
    return JudgmentCommitment.model_validate(
        sign_payload("judgment-commitment", payload, private_key, version="0.4")
    )


def _profile_from_axes(
    *,
    adapter_id: str = "openworkproof/code-delivery-github/0.1",
    adapter_version: str = "0.1",
    allowed_tool_names: tuple[str, ...],
    allowed_action_kinds: tuple[str, ...],
    allowed_path_roots: tuple[str, ...],
    required_test_profile_digests: tuple[str, ...],
) -> tuple[CanonicalAdapterProfile, DeterministicConstraintProjection]:
    profile = _profile_artifact_from_axes(
        adapter_id=adapter_id,
        adapter_version=adapter_version,
        allowed_tool_names=allowed_tool_names,
        allowed_action_kinds=allowed_action_kinds,
        allowed_path_roots=allowed_path_roots,
        required_test_profile_digests=required_test_profile_digests,
    )
    return profile, projection_from_adapter_profile(profile)


def _profile_artifact_from_axes(
    *,
    adapter_id: str = "openworkproof/code-delivery-github/0.1",
    adapter_version: str = "0.1",
    allowed_tool_names: tuple[str, ...],
    allowed_action_kinds: tuple[str, ...],
    allowed_path_roots: tuple[str, ...],
    required_test_profile_digests: tuple[str, ...],
) -> CanonicalAdapterProfile:
    canonical = rfc8785.dumps(
        {
            "schema_version": "openworkproof-adapter-profile/0.4",
            "adapter_id": adapter_id,
            "adapter_version": adapter_version,
            "allowed_tool_names": list(allowed_tool_names),
            "allowed_action_kinds": list(allowed_action_kinds),
            "allowed_path_roots": list(allowed_path_roots),
            "required_test_profile_digests": list(
                required_test_profile_digests
            ),
        }
    )
    return CanonicalAdapterProfile(
        canonical_json=canonical,
        adapter_profile_digest=hashlib.sha256(canonical).hexdigest(),
    )


def _signed_scope(
    *,
    payload: dict[str, object],
    manager_key: Ed25519PrivateKey,
    work_order: WorkOrder,
    claim: SubjectClaim,
) -> EvaluationScopeManifest:
    candidate = copy.deepcopy(payload)
    candidate.update(
        {
            "work_order_digest": work_order.digest,
            "subject_claim_digest": claim.digest,
            "source_revision": claim.source_revision,
            "created_at": "2026-01-01T00:00:06Z",
            "expires_at": "2026-01-01T00:50:00Z",
            "nonce": "a" * 64,
            "excluded_locator_digests": ["b" * 64],
        }
    )
    source_member = next(
        member for member in candidate["members"] if member["member_kind"] == "source_file"
    )
    test_member = next(
        member for member in candidate["members"] if member["member_kind"] == "test_case"
    )
    candidate["requirement_bindings"] = sorted(
        [
            *(
                {
                    "requirement_kind": "acceptance_condition",
                    "requirement_digest": requirement_digest(
                        "acceptance_condition", value
                    ),
                    "member_ids": [test_member["member_id"]],
                }
                for value in claim.acceptance_conditions
            ),
            *(
                {
                    "requirement_kind": "required_artifact",
                    "requirement_digest": requirement_digest(
                        "required_artifact", value
                    ),
                    "member_ids": [source_member["member_id"]],
                }
                for value in claim.required_artifacts
            ),
        ],
        key=lambda item: (
            item["requirement_kind"].encode("utf-8"),
            item["requirement_digest"],
        ),
    )
    candidate["required_target_ids"] = sorted(
        {
            member_id
            for binding in candidate["requirement_bindings"]
            for member_id in binding["member_ids"]
        }
    )
    identity = {
        key: value
        for key, value in candidate.items()
        if key != "scope_id"
    }
    candidate["scope_id"] = evaluation_scope_id(identity)
    return EvaluationScopeManifest.model_validate(
        sign_payload("evaluation-scope", candidate, manager_key, version="0.3")
    )


def _resign_scope(
    scope: EvaluationScopeManifest,
    private_key: Ed25519PrivateKey,
    **updates: object,
) -> EvaluationScopeManifest:
    payload = scope.model_dump(
        mode="json",
        exclude={
            "scope_id",
            "digest",
            "signature_alg",
            "signer_key_id",
            "signature",
        },
    )
    payload.update(copy.deepcopy(updates))
    payload["scope_id"] = evaluation_scope_id(payload)
    return EvaluationScopeManifest.model_validate(
        sign_payload("evaluation-scope", payload, private_key, version="0.3")
    )


def _signed_judgment(
    *,
    work_order: WorkOrder,
    scope: EvaluationScopeManifest,
    acceptor_key: Ed25519PrivateKey,
    projection: DeterministicConstraintProjection,
) -> JudgmentCommitment:
    by_kind = {
        kind: sorted(
            binding.requirement_digest
            for binding in scope.requirement_bindings
            if binding.requirement_kind == kind
        )
        for kind in ("acceptance_condition", "required_artifact")
    }
    return JudgmentCommitment.model_validate(
        sign_payload(
            "judgment-commitment",
            {
                "schema_version": "openworkproof-judgment-commitment/0.4",
                "commitment_id": "c" * 64,
                "authority_namespace": "customer.example",
                "subject_id": "issue-123",
                "judgment_kind": "code-delivery",
                "judgment_artifact_uri": "evidence/judgment.json",
                "judgment_artifact_digest": "d" * 64,
                "normalized_facts_digest": "e" * 64,
                "disposition_digest": "f" * 64,
                "action_constraint_digest": constraint_projection_digest(projection),
                "adapter_id": projection.adapter_id,
                "adapter_version": projection.adapter_version,
                "adapter_profile_digest": projection.adapter_profile_digest,
                "repository": work_order.repository,
                "source_revision": work_order.source_commit,
                "target_branch": work_order.branch,
                "acceptance_condition_digests": by_kind["acceptance_condition"],
                "excluded_scope_digests": list(scope.excluded_locator_digests),
                "required_artifact_digests": by_kind["required_artifact"],
                "valid_from": "2026-01-01T00:00:01Z",
                "expires_at": "2026-01-01T00:45:00Z",
                "created_at": "2026-01-01T00:00:00Z",
                "nonce": "1" * 64,
            },
            acceptor_key,
            version="0.4",
        )
    )


def _signed_manifest(
    *,
    work_order: WorkOrder,
    scope: EvaluationScopeManifest,
    judgment: JudgmentCommitment,
    projection: DeterministicConstraintProjection,
    manager_key: Ed25519PrivateKey,
    manifest_id: str = "2" * 64,
    nonce: str = "3" * 64,
    supersedes: ActionBindingManifest | None = None,
    created_at: str | None = None,
) -> ActionBindingManifest:
    return ActionBindingManifest.model_validate(
        sign_payload(
            "action-binding-manifest",
            {
                "schema_version": "openworkproof-action-binding-manifest/0.4",
                "binding_manifest_id": manifest_id,
                "work_order_digest": work_order.digest,
                "judgment_commitment_id": judgment.commitment_id,
                "judgment_commitment_digest": judgment.digest,
                "evaluation_scope_id": scope.scope_id,
                "evaluation_scope_digest": scope.digest,
                "adapter_id": projection.adapter_id,
                "adapter_version": projection.adapter_version,
                "adapter_profile_digest": projection.adapter_profile_digest,
                "allowed_tool_names": list(projection.allowed_tool_names),
                "allowed_action_kinds": list(projection.allowed_action_kinds),
                "allowed_path_roots": list(projection.allowed_path_roots),
                "required_test_profile_digests": list(
                    projection.required_test_profile_digests
                ),
                "source_revision": work_order.source_commit,
                "supersedes_binding_manifest_id": (
                    None if supersedes is None else supersedes.binding_manifest_id
                ),
                "supersedes_binding_manifest_digest": (
                    None if supersedes is None else supersedes.digest
                ),
                "causal_parent_manifest_ids": (
                    [] if supersedes is None else [supersedes.binding_manifest_id]
                ),
                "created_at": (
                    created_at
                    or (
                        "2026-01-01T00:00:08Z"
                        if supersedes is None
                        else "2026-01-01T00:00:09Z"
                    )
                ),
                "expires_at": "2026-01-01T00:40:00Z",
                "nonce": nonce,
            },
            manager_key,
            version="0.4",
        )
    )


@pytest.fixture
def binding_case(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    signed_subject_claim: SubjectClaim,
    evaluation_scope_payload_v03: dict[str, object],
    ephemeral_role_keys,
):
    manager_key = ephemeral_role_keys["Manager"][0]
    acceptor_key = ephemeral_role_keys["Acceptor"][0]
    test_digests = tuple(
        sorted(
            canonical_test_profile_digest(profile)
            for profile in signed_work_order.test_profiles
        )
    )
    profile, projection = _profile_from_axes(
        allowed_tool_names=("owp.apply_patch", "owp.run_tests"),
        allowed_action_kinds=("patch", "test"),
        allowed_path_roots=("src",),
        required_test_profile_digests=test_digests,
    )
    scope = _signed_scope(
        payload=evaluation_scope_payload_v03,
        manager_key=manager_key,
        work_order=signed_work_order,
        claim=signed_subject_claim,
    )
    judgment = _signed_judgment(
        work_order=signed_work_order,
        scope=scope,
        acceptor_key=acceptor_key,
        projection=projection,
    )
    manifest = _signed_manifest(
        work_order=signed_work_order,
        scope=scope,
        judgment=judgment,
        projection=projection,
        manager_key=manager_key,
    )
    ledger = tmp_path / "binding.sqlite3"
    evidence.initialize_ledger(ledger, signed_work_order)
    commit_evaluation_scope(ledger, signed_subject_claim, scope)
    commit_judgment_commitment(
        ledger,
        judgment,
        JudgmentAuthorityContext(
            authority_namespace=judgment.authority_namespace,
            authority_binding=next(
                binding
                for binding in signed_work_order.key_bindings
                if binding.role == "Acceptor"
            ),
            transaction_time=datetime(2026, 1, 1, 0, 0, 7, tzinfo=UTC),
        ),
    )
    return {
        "ledger": ledger,
        "work_order": signed_work_order,
        "claim": signed_subject_claim,
        "scope": scope,
        "judgment": judgment,
        "projection": projection,
        "profile": profile,
        "manifest": manifest,
        "manager_key": manager_key,
        "acceptor_key": acceptor_key,
        "transaction_time": datetime(2026, 1, 1, 0, 0, 9, tzinfo=UTC),
    }


def _validate(case, manifest: ActionBindingManifest | None = None, **overrides):
    values = {
        "work_order": case["work_order"],
        "judgment": case["judgment"],
        "scope": case["scope"],
        "adapter_profile": case["profile"],
        "manifest": manifest or case["manifest"],
        "transaction_time": case["transaction_time"],
    }
    values.update(overrides)
    return validate_action_binding_manifest(**values)


def _commit(case, manifest: ActionBindingManifest | None = None, **kwargs):
    transaction_time = kwargs.pop("transaction_time", case["transaction_time"])
    return commit_action_binding_manifest(
        case["ledger"],
        manifest or case["manifest"],
        case["profile"],
        transaction_time=transaction_time,
        **kwargs,
    )


def test_pure_validator_accepts_exact_signed_intersection(binding_case) -> None:
    assert _validate(binding_case) == binding_case["manifest"]


@pytest.mark.parametrize(
    ("field", "replacement", "message"),
    [
        ("work_order_digest", "9" * 64, "WorkOrder"),
        ("judgment_commitment_digest", "9" * 64, "Judgment"),
        ("evaluation_scope_digest", "9" * 64, "Scope"),
        ("adapter_profile_digest", "9" * 64, "adapter"),
    ],
)
def test_pure_validator_requires_full_digest_chain(
    binding_case, field: str, replacement: str, message: str
) -> None:
    attacked = _resign_manifest(
        binding_case["manifest"],
        binding_case["manager_key"],
        **{field: replacement},
    )
    with pytest.raises(BindingInputError, match=message):
        _validate(binding_case, attacked)


def test_judgment_must_be_signed_by_work_order_acceptor(binding_case) -> None:
    attacked = _resign_judgment(
        binding_case["judgment"], binding_case["manager_key"]
    )
    with pytest.raises(BindingInputError, match="Acceptor"):
        _validate(binding_case, judgment=attacked)


def test_manifest_must_be_signed_by_work_order_manager(binding_case) -> None:
    attacked = _resign_manifest(
        binding_case["manifest"], binding_case["acceptor_key"]
    )
    with pytest.raises(BindingInputError, match="Manager"):
        _validate(binding_case, attacked)


def test_scope_must_be_signed_by_work_order_manager(binding_case) -> None:
    payload = binding_case["scope"].model_dump(
        mode="json",
        exclude={"digest", "signature_alg", "signer_key_id", "signature"},
    )
    attacked_scope = EvaluationScopeManifest.model_validate(
        sign_payload(
            "evaluation-scope",
            payload,
            binding_case["acceptor_key"],
            version="0.3",
        )
    )
    attacked_manifest = _resign_manifest(
        binding_case["manifest"],
        binding_case["manager_key"],
        evaluation_scope_digest=attacked_scope.digest,
    )
    with pytest.raises(BindingInputError, match="Scope.*Manager"):
        _validate(binding_case, attacked_manifest, scope=attacked_scope)


@pytest.mark.parametrize(
    ("created_at", "message"),
    [
        ("2025-12-31T23:59:59Z", "WorkOrder"),
        ("2026-01-01T00:00:04Z", "Scope"),
    ],
)
def test_manifest_cannot_predate_work_order_or_scope(
    binding_case, created_at: str, message: str
) -> None:
    attacked = _resign_manifest(
        binding_case["manifest"],
        binding_case["manager_key"],
        created_at=created_at,
    )
    with pytest.raises(BindingInputError, match=message):
        _validate(binding_case, attacked)


def test_manifest_cannot_predate_judgment_validity(binding_case) -> None:
    judgment = _resign_judgment(
        binding_case["judgment"],
        binding_case["acceptor_key"],
        valid_from="2026-01-01T00:00:10Z",
    )
    manifest = _resign_manifest(
        binding_case["manifest"],
        binding_case["manager_key"],
        judgment_commitment_digest=judgment.digest,
    )
    with pytest.raises(BindingInputError, match="Judgment"):
        _validate(
            binding_case,
            manifest,
            judgment=judgment,
            transaction_time=datetime(2026, 1, 1, 0, 0, 11, tzinfo=UTC),
        )


def test_manifest_model_rejects_noncanonical_causal_parent_order(binding_case) -> None:
    dumped = binding_case["manifest"].model_dump(
        mode="json",
        exclude={"digest", "signature_alg", "signer_key_id", "signature"},
    )
    dumped["causal_parent_manifest_ids"] = ["9" * 64, "8" * 64]
    signed = sign_payload(
        "action-binding-manifest",
        dumped,
        binding_case["manager_key"],
        version="0.4",
    )
    with pytest.raises(ValidationError, match="causal_parent_manifest_ids"):
        ActionBindingManifest.model_validate(signed)


@pytest.mark.parametrize(
    ("manifest_update", "judgment_update", "message"),
    [
        ({"expires_at": "2026-01-01T00:46:00Z"}, {}, "Judgment"),
        (
            {"expires_at": "2026-01-01T00:51:00Z"},
            {"expires_at": "2026-01-01T00:55:00Z"},
            "Scope",
        ),
        ({}, {"valid_from": "2026-01-01T00:00:10Z"}, "valid"),
    ],
)
def test_validity_is_the_exact_work_order_judgment_scope_intersection(
    binding_case, manifest_update, judgment_update, message
) -> None:
    judgment = _resign_judgment(
        binding_case["judgment"],
        binding_case["acceptor_key"],
        **judgment_update,
    )
    manifest = _resign_manifest(
        binding_case["manifest"],
        binding_case["manager_key"],
        judgment_commitment_digest=judgment.digest,
        **manifest_update,
    )
    with pytest.raises(BindingInputError, match=message):
        _validate(binding_case, manifest, judgment=judgment)


def test_manifest_expiry_cannot_exceed_work_order_deadline(binding_case) -> None:
    scope = _resign_scope(
        binding_case["scope"],
        binding_case["manager_key"],
        expires_at="2026-01-03T00:00:00Z",
    )
    judgment = _resign_judgment(
        binding_case["judgment"],
        binding_case["acceptor_key"],
        expires_at="2026-01-03T00:00:00Z",
    )
    manifest = _resign_manifest(
        binding_case["manifest"],
        binding_case["manager_key"],
        judgment_commitment_digest=judgment.digest,
        evaluation_scope_id=scope.scope_id,
        evaluation_scope_digest=scope.digest,
        expires_at="2026-01-02T00:00:01Z",
    )
    with pytest.raises(BindingInputError, match="WorkOrder"):
        _validate(binding_case, manifest, judgment=judgment, scope=scope)


@pytest.mark.parametrize(
    ("kind", "judgment_field"),
    [
        ("acceptance_condition", "acceptance_condition_digests"),
        ("required_artifact", "required_artifact_digests"),
    ],
)
def test_scope_requirement_bindings_must_exactly_match_judgment(
    binding_case, kind: str, judgment_field: str
) -> None:
    current = list(getattr(binding_case["judgment"], judgment_field))
    replacement = sorted([*current, "9" * 64])
    attacked = _resign_judgment(
        binding_case["judgment"],
        binding_case["acceptor_key"],
        **{judgment_field: replacement},
    )
    manifest = _resign_manifest(
        binding_case["manifest"],
        binding_case["manager_key"],
        judgment_commitment_digest=attacked.digest,
    )
    with pytest.raises(BindingInputError, match=kind):
        _validate(binding_case, manifest, judgment=attacked)


def test_scope_exclusions_must_exactly_match_judgment(binding_case) -> None:
    attacked = _resign_judgment(
        binding_case["judgment"],
        binding_case["acceptor_key"],
        excluded_scope_digests=["9" * 64],
    )
    manifest = _resign_manifest(
        binding_case["manifest"],
        binding_case["manager_key"],
        judgment_commitment_digest=attacked.digest,
    )
    with pytest.raises(BindingInputError, match="excluded"):
        _validate(binding_case, manifest, judgment=attacked)


@pytest.mark.parametrize(
    ("field", "outside"),
    [
        ("allowed_tool_names", "owp.repo_read"),
        ("allowed_action_kinds", "deploy"),
        ("allowed_path_roots", "docs"),
    ],
)
def test_manifest_cannot_expand_signed_constraint_intersection(
    binding_case, field: str, outside: str
) -> None:
    values = sorted([*getattr(binding_case["manifest"], field), outside])
    attacked = _resign_manifest(
        binding_case["manifest"],
        binding_case["manager_key"],
        **{field: values},
    )
    with pytest.raises(BindingInputError, match="exceeds"):
        _validate(binding_case, attacked)


def test_path_coverage_is_segment_aware_not_string_prefix(binding_case) -> None:
    profile, projection = _profile_from_axes(
        allowed_tool_names=binding_case["projection"].allowed_tool_names,
        allowed_action_kinds=binding_case["projection"].allowed_action_kinds,
        allowed_path_roots=("src", "src2"),
        required_test_profile_digests=(
            binding_case["projection"].required_test_profile_digests
        ),
    )
    judgment = _resign_judgment(
        binding_case["judgment"],
        binding_case["acceptor_key"],
        adapter_profile_digest=profile.adapter_profile_digest,
        action_constraint_digest=constraint_projection_digest(projection),
    )
    attacked = _resign_manifest(
        binding_case["manifest"],
        binding_case["manager_key"],
        allowed_path_roots=["src", "src2"],
        adapter_profile_digest=profile.adapter_profile_digest,
        judgment_commitment_digest=judgment.digest,
    )
    with pytest.raises(BindingInputError, match="WorkOrder"):
        _validate(
            binding_case,
            attacked,
            adapter_profile=profile,
            judgment=judgment,
        )


def test_required_test_profiles_cannot_be_omitted(binding_case) -> None:
    attacked = _resign_manifest(
        binding_case["manifest"],
        binding_case["manager_key"],
        required_test_profile_digests=[
            binding_case["projection"].required_test_profile_digests[0]
        ],
    )
    with pytest.raises(BindingInputError, match="test profile"):
        _validate(binding_case, attacked)


def test_full_chain_cannot_shrink_work_order_required_test_profiles(
    binding_case,
) -> None:
    profile, projection = _profile_from_axes(
        allowed_tool_names=binding_case["projection"].allowed_tool_names,
        allowed_action_kinds=binding_case["projection"].allowed_action_kinds,
        allowed_path_roots=binding_case["projection"].allowed_path_roots,
        required_test_profile_digests=(
            binding_case["projection"].required_test_profile_digests[0],
        ),
    )
    judgment = _resign_judgment(
        binding_case["judgment"],
        binding_case["acceptor_key"],
        adapter_profile_digest=profile.adapter_profile_digest,
        action_constraint_digest=constraint_projection_digest(projection),
    )
    manifest = _resign_manifest(
        binding_case["manifest"],
        binding_case["manager_key"],
        adapter_profile_digest=profile.adapter_profile_digest,
        judgment_commitment_digest=judgment.digest,
        required_test_profile_digests=list(
            projection.required_test_profile_digests
        ),
    )
    with pytest.raises(BindingInputError, match="test profile.*WorkOrder"):
        _validate(
            binding_case,
            manifest,
            adapter_profile=profile,
            judgment=judgment,
        )


def test_adapter_profile_digest_must_be_recomputed_from_canonical_bytes(
    binding_case,
) -> None:
    attacked = replace(
        binding_case["profile"], adapter_profile_digest="9" * 64
    )
    with pytest.raises(BindingInputError, match="profile digest"):
        _validate(binding_case, adapter_profile=attacked)


def test_adapter_profile_bytes_must_be_canonical(binding_case) -> None:
    noncanonical = b" " + binding_case["profile"].canonical_json
    attacked = CanonicalAdapterProfile(
        canonical_json=noncanonical,
        adapter_profile_digest=hashlib.sha256(noncanonical).hexdigest(),
    )
    with pytest.raises(BindingInputError, match="canonical"):
        _validate(binding_case, adapter_profile=attacked)


def test_adapter_profile_id_and_version_are_pinned(binding_case) -> None:
    for field, value in (
        ("adapter_id", "attacker.example/adapter/9.9"),
        ("adapter_version", "9.9"),
    ):
        with pytest.raises(BindingInputError, match="unsupported"):
            _profile_from_axes(
                **{field: value},
                allowed_tool_names=binding_case["projection"].allowed_tool_names,
                allowed_action_kinds=binding_case["projection"].allowed_action_kinds,
                allowed_path_roots=binding_case["projection"].allowed_path_roots,
                required_test_profile_digests=(
                    binding_case["projection"].required_test_profile_digests
                ),
            )


def test_adapter_profile_is_required_not_a_shadow_projection(binding_case) -> None:
    with pytest.raises(BindingInputError, match="profile"):
        _validate(binding_case, adapter_profile=None)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        ("allowed_tool_names", ("attacker.exec",), "tool"),
        ("allowed_action_kinds", ("deploy",), "action"),
        ("allowed_path_roots", ("src/../secret",), "root"),
    ),
)
def test_adapter_profile_raw_axes_are_closed_before_manifest_narrowing(
    binding_case,
    field: str,
    value: tuple[str, ...],
    message: str,
) -> None:
    axes = {
        "allowed_tool_names": binding_case["projection"].allowed_tool_names,
        "allowed_action_kinds": binding_case["projection"].allowed_action_kinds,
        "allowed_path_roots": binding_case["projection"].allowed_path_roots,
        "required_test_profile_digests": (
            binding_case["projection"].required_test_profile_digests
        ),
    }
    axes[field] = value
    profile = _profile_artifact_from_axes(**axes)
    with pytest.raises(BindingInputError, match=message):
        _validate(binding_case, adapter_profile=profile)


def test_adapter_profile_accepts_complete_first_release_code_delivery_vocabulary(
    binding_case,
) -> None:
    profile = _profile_artifact_from_axes(
        allowed_tool_names=(
            "owp.apply_patch",
            "owp.create_pr_proposal",
            "owp.repo_read",
            "owp.rollback_patch",
            "owp.run_tests",
        ),
        allowed_action_kinds=("patch", "proposal", "read", "rollback", "test"),
        allowed_path_roots=("src",),
        required_test_profile_digests=(
            binding_case["projection"].required_test_profile_digests
        ),
    )
    projection = projection_from_adapter_profile(profile)
    assert projection.allowed_tool_names == (
        "owp.apply_patch",
        "owp.create_pr_proposal",
        "owp.repo_read",
        "owp.rollback_patch",
        "owp.run_tests",
    )
    assert projection.allowed_action_kinds == (
        "patch",
        "proposal",
        "read",
        "rollback",
        "test",
    )


def test_mutating_action_paths_must_be_within_work_order_write_roots(
    binding_case,
) -> None:
    profile, projection = _profile_from_axes(
        allowed_tool_names=binding_case["projection"].allowed_tool_names,
        allowed_action_kinds=binding_case["projection"].allowed_action_kinds,
        allowed_path_roots=("src", "tests"),
        required_test_profile_digests=(
            binding_case["projection"].required_test_profile_digests
        ),
    )
    judgment = _resign_judgment(
        binding_case["judgment"],
        binding_case["acceptor_key"],
        adapter_profile_digest=profile.adapter_profile_digest,
        action_constraint_digest=constraint_projection_digest(projection),
    )
    manifest = _resign_manifest(
        binding_case["manifest"],
        binding_case["manager_key"],
        adapter_profile_digest=profile.adapter_profile_digest,
        judgment_commitment_digest=judgment.digest,
        allowed_path_roots=["src", "tests"],
    )
    with pytest.raises(BindingInputError, match="write roots"):
        _validate(
            binding_case,
            manifest,
            adapter_profile=profile,
            judgment=judgment,
        )


def test_pure_read_profile_may_use_work_order_read_only_root(binding_case) -> None:
    profile, projection = _profile_from_axes(
        allowed_tool_names=("owp.repo_read",),
        allowed_action_kinds=("read",),
        allowed_path_roots=("tests",),
        required_test_profile_digests=(
            binding_case["projection"].required_test_profile_digests
        ),
    )
    judgment = _resign_judgment(
        binding_case["judgment"],
        binding_case["acceptor_key"],
        adapter_profile_digest=profile.adapter_profile_digest,
        action_constraint_digest=constraint_projection_digest(projection),
    )
    manifest = _resign_manifest(
        binding_case["manifest"],
        binding_case["manager_key"],
        adapter_profile_digest=profile.adapter_profile_digest,
        judgment_commitment_digest=judgment.digest,
        allowed_tool_names=["owp.repo_read"],
        allowed_action_kinds=["read"],
        allowed_path_roots=["tests"],
    )
    assert _validate(
        binding_case,
        manifest,
        adapter_profile=profile,
        judgment=judgment,
    ) == manifest


def test_projection_digest_covers_all_four_constraint_axes(binding_case) -> None:
    base = constraint_projection_digest(binding_case["projection"])
    for field, value in (
        ("allowed_tool_names", ("owp.repo_read",)),
        ("allowed_action_kinds", ("inspect",)),
        ("allowed_path_roots", ("tests",)),
        ("required_test_profile_digests", ("9" * 64,)),
    ):
        assert constraint_projection_digest(
            replace(binding_case["projection"], **{field: value})
        ) != base


def test_first_manifest_becomes_the_only_derived_current(binding_case) -> None:
    assert _commit(binding_case) == binding_case["manifest"]
    assert load_current_action_binding_manifest(
        binding_case["ledger"], binding_case["work_order"].digest
    ) == binding_case["manifest"]

    connection = evidence.connect_ledger(binding_case["ledger"])
    try:
        manifest_columns = {
            row[1]
            for row in connection.execute(
                "PRAGMA table_info(action_binding_manifests_v04)"
            )
        }
        assert "active" not in manifest_columns
        assert connection.execute(
            """
            SELECT adapter_profile_digest, adapter_profile_json
            FROM action_binding_manifests_v04
            """
        ).fetchone() == (
            binding_case["profile"].adapter_profile_digest,
            binding_case["profile"].canonical_json,
        )
        assert any(
            row[2] == "work_orders" and row[3] == "work_order_digest"
            for row in connection.execute(
                "PRAGMA foreign_key_list(action_binding_manifests_v04)"
            )
        )
        assert connection.execute(
            "SELECT COUNT(*) FROM action_binding_manifest_supersessions_v04"
        ).fetchone() == (0,)
    finally:
        connection.close()


def test_transaction_loads_exact_committed_judgment_not_shadow_object(
    binding_case
) -> None:
    unattested = _resign_judgment(
        binding_case["judgment"],
        binding_case["acceptor_key"],
        commitment_id="9" * 64,
        nonce="8" * 64,
    )
    attacked = _resign_manifest(
        binding_case["manifest"],
        binding_case["manager_key"],
        judgment_commitment_id=unattested.commitment_id,
        judgment_commitment_digest=unattested.digest,
    )
    before = _snapshot(binding_case["ledger"])
    with pytest.raises(BindingInputError, match="committed Judgment"):
        _commit(binding_case, attacked)
    assert _snapshot(binding_case["ledger"]) == before


def test_transaction_loads_exact_committed_scope_not_shadow_object(binding_case) -> None:
    attacked = _resign_manifest(
        binding_case["manifest"],
        binding_case["manager_key"],
        evaluation_scope_id="9" * 64,
        evaluation_scope_digest="8" * 64,
    )
    before = _snapshot(binding_case["ledger"])
    with pytest.raises(BindingInputError, match="committed Scope"):
        _commit(binding_case, attacked)
    assert _snapshot(binding_case["ledger"]) == before


def test_transaction_rejects_committed_judgment_index_drift(binding_case) -> None:
    connection = evidence.connect_ledger(binding_case["ledger"])
    try:
        connection.execute(
            "DROP TRIGGER judgment_commitments_v04_are_immutable_update"
        )
        connection.execute(
            "UPDATE judgment_commitments_v04 "
            "SET authority_namespace = 'attacker.example'"
        )
    finally:
        connection.close()
    with pytest.raises(BindingTransactionError, match="Judgment.*index|row"):
        _commit(binding_case)


def test_transaction_rejects_committed_scope_index_drift(binding_case) -> None:
    connection = evidence.connect_ledger(binding_case["ledger"])
    try:
        connection.execute(
            "UPDATE evaluation_scopes_v03 SET work_order_digest = ?",
            ("9" * 64,),
        )
    finally:
        connection.close()
    with pytest.raises(BindingTransactionError, match="Scope.*index|row"):
        _commit(binding_case)


def test_transaction_replays_scope_claim_acceptor_authority(binding_case) -> None:
    claim_payload = binding_case["claim"].model_dump(
        mode="json",
        exclude={"digest", "signature_alg", "signer_key_id", "signature"},
    )
    claim_payload["customer_acceptor_key_id"] = next(
        binding.key_id
        for binding in binding_case["work_order"].key_bindings
        if binding.role == "Manager"
    )
    attacked_claim = SubjectClaim.model_validate(
        sign_payload(
            "subject-claim", claim_payload, binding_case["manager_key"]
        )
    )
    attacked_scope = _resign_scope(
        binding_case["scope"],
        binding_case["manager_key"],
        subject_claim_digest=attacked_claim.digest,
    )
    attacked_manifest = _resign_manifest(
        binding_case["manifest"],
        binding_case["manager_key"],
        evaluation_scope_id=attacked_scope.scope_id,
        evaluation_scope_digest=attacked_scope.digest,
    )
    connection = evidence.connect_ledger(binding_case["ledger"])
    try:
        connection.execute(
            "UPDATE subject_claims SET claim_json = ? WHERE claim_id = ?",
            (
                evidence._canonical_json(
                    attacked_claim.model_dump(mode="json")
                ).encode("utf-8"),
                attacked_claim.claim_id,
            ),
        )
        connection.execute(
            """
            UPDATE evaluation_scopes_v03
            SET scope_id = ?, scope_digest = ?, subject_claim_digest = ?,
                scope_json = ?
            WHERE scope_id = ?
            """,
            (
                attacked_scope.scope_id,
                attacked_scope.digest,
                attacked_scope.subject_claim_digest,
                evidence._canonical_json(
                    attacked_scope.model_dump(mode="json")
                ).encode("utf-8"),
                binding_case["scope"].scope_id,
            ),
        )
    finally:
        connection.close()
    with pytest.raises(BindingTransactionError, match="Acceptor|claim authority"):
        _commit(binding_case, attacked_manifest)


def test_transaction_replays_complete_scope_manager_grant_validity(
    binding_case,
) -> None:
    attacked_scope = _resign_scope(
        binding_case["scope"],
        binding_case["manager_key"],
        expires_at=(
            binding_case["work_order"].deadline + timedelta(seconds=1)
        ).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )
    attacked_manifest = _resign_manifest(
        binding_case["manifest"],
        binding_case["manager_key"],
        evaluation_scope_id=attacked_scope.scope_id,
        evaluation_scope_digest=attacked_scope.digest,
    )
    connection = evidence.connect_ledger(binding_case["ledger"])
    try:
        connection.execute(
            """
            UPDATE evaluation_scopes_v03
            SET scope_id = ?, scope_digest = ?, subject_claim_digest = ?,
                scope_json = ?
            WHERE scope_id = ?
            """,
            (
                attacked_scope.scope_id,
                attacked_scope.digest,
                attacked_scope.subject_claim_digest,
                evidence._canonical_json(
                    attacked_scope.model_dump(mode="json")
                ).encode("utf-8"),
                binding_case["scope"].scope_id,
            ),
        )
    finally:
        connection.close()
    with pytest.raises(BindingTransactionError, match="Manager grant|authority"):
        _commit(binding_case, attacked_manifest)


def test_supersession_requires_exact_current_id_and_digest(binding_case) -> None:
    _commit(binding_case)
    stale = _signed_manifest(
        work_order=binding_case["work_order"],
        scope=binding_case["scope"],
        judgment=binding_case["judgment"],
        projection=binding_case["projection"],
        manager_key=binding_case["manager_key"],
        manifest_id="5" * 64,
        nonce="6" * 64,
        supersedes=binding_case["manifest"],
    )
    stale = _resign_manifest(
        stale,
        binding_case["manager_key"],
        supersedes_binding_manifest_digest="9" * 64,
    )
    before = _snapshot(binding_case["ledger"])
    with pytest.raises(BindingTransactionError, match="current"):
        _commit(binding_case, stale)
    assert _snapshot(binding_case["ledger"]) == before


def test_supersession_requires_committed_parent(binding_case) -> None:
    parent = binding_case["manifest"]
    child = _signed_manifest(
        work_order=binding_case["work_order"],
        scope=binding_case["scope"],
        judgment=binding_case["judgment"],
        projection=binding_case["projection"],
        manager_key=binding_case["manager_key"],
        manifest_id="5" * 64,
        nonce="6" * 64,
        supersedes=parent,
    )
    with pytest.raises(BindingTransactionError, match="parent"):
        _commit(binding_case, child)


def test_second_root_without_exact_supersession_is_rejected(binding_case) -> None:
    _commit(binding_case)
    second_root = _signed_manifest(
        work_order=binding_case["work_order"],
        scope=binding_case["scope"],
        judgment=binding_case["judgment"],
        projection=binding_case["projection"],
        manager_key=binding_case["manager_key"],
        manifest_id="5" * 64,
        nonce="6" * 64,
    )
    with pytest.raises(BindingTransactionError, match="current"):
        _commit(binding_case, second_root)


def test_manifest_nonce_is_unique_per_manager(binding_case) -> None:
    _commit(binding_case)
    child = _signed_manifest(
        work_order=binding_case["work_order"],
        scope=binding_case["scope"],
        judgment=binding_case["judgment"],
        projection=binding_case["projection"],
        manager_key=binding_case["manager_key"],
        manifest_id="5" * 64,
        nonce=binding_case["manifest"].nonce,
        supersedes=binding_case["manifest"],
    )
    with pytest.raises(BindingTransactionError, match="nonce"):
        _commit(binding_case, child)


def test_valid_supersession_is_append_only_and_changes_derived_current(
    binding_case,
) -> None:
    _commit(binding_case)
    child = _signed_manifest(
        work_order=binding_case["work_order"],
        scope=binding_case["scope"],
        judgment=binding_case["judgment"],
        projection=binding_case["projection"],
        manager_key=binding_case["manager_key"],
        manifest_id="5" * 64,
        nonce="6" * 64,
        supersedes=binding_case["manifest"],
    )
    assert _commit(binding_case, child) == child
    assert load_current_action_binding_manifest(
        binding_case["ledger"], binding_case["work_order"].digest
    ) == child
    connection = evidence.connect_ledger(binding_case["ledger"])
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM action_binding_manifests_v04"
        ).fetchone() == (2,)
        assert connection.execute(
            "SELECT parent_manifest_id, parent_manifest_digest, child_manifest_id "
            "FROM action_binding_manifest_supersessions_v04"
        ).fetchone() == (
            binding_case["manifest"].binding_manifest_id,
            binding_case["manifest"].digest,
            child.binding_manifest_id,
        )
    finally:
        connection.close()


def test_concurrent_children_have_exactly_one_winner(binding_case) -> None:
    _commit(binding_case)
    children = tuple(
        _signed_manifest(
            work_order=binding_case["work_order"],
            scope=binding_case["scope"],
            judgment=binding_case["judgment"],
            projection=binding_case["projection"],
            manager_key=binding_case["manager_key"],
            manifest_id=character * 64,
            nonce=nonce * 64,
            supersedes=binding_case["manifest"],
        )
        for character, nonce in (("5", "6"), ("7", "8"))
    )

    def attempt(child):
        try:
            return _commit(binding_case, child)
        except BindingTransactionError as error:
            return error

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = tuple(pool.map(attempt, children))
    winners = [result for result in results if isinstance(result, ActionBindingManifest)]
    assert len(winners) == 1
    assert len([result for result in results if isinstance(result, Exception)]) == 1
    assert load_current_action_binding_manifest(
        binding_case["ledger"], binding_case["work_order"].digest
    ) == winners[0]


def test_exact_replay_returns_original_committed_truth_after_expiry(
    binding_case,
) -> None:
    _commit(binding_case)
    connection = evidence.connect_ledger(binding_case["ledger"])
    try:
        committed_at = connection.execute(
            "SELECT committed_at FROM action_binding_manifests_v04"
        ).fetchone()[0]
    finally:
        connection.close()
    with pytest.raises(BindingCommittedError) as raised:
        commit_action_binding_manifest(
            binding_case["ledger"],
            binding_case["manifest"],
            binding_case["profile"],
            transaction_time=datetime(2026, 1, 2, 0, 0, 1, tzinfo=UTC),
        )
    assert raised.value.committed == binding_case["manifest"]
    connection = evidence.connect_ledger(binding_case["ledger"])
    try:
        assert connection.execute(
            "SELECT committed_at FROM action_binding_manifests_v04"
        ).fetchone() == (committed_at,)
    finally:
        connection.close()


def test_exact_replay_rejects_supersession_relation_drift(binding_case) -> None:
    _commit(binding_case)
    connection = evidence.connect_ledger(binding_case["ledger"])
    try:
        connection.execute(
            """
            INSERT INTO action_binding_manifest_supersessions_v04 (
                child_manifest_id, parent_manifest_id, parent_manifest_digest
            ) VALUES (?, ?, ?)
            """,
            (
                binding_case["manifest"].binding_manifest_id,
                binding_case["manifest"].binding_manifest_id,
                binding_case["manifest"].digest,
            ),
        )
    finally:
        connection.close()
    with pytest.raises(BindingTransactionError, match="relation|graph"):
        _commit(binding_case)


def test_exact_replay_rejects_noncanonical_committed_at(binding_case) -> None:
    _commit(binding_case)
    connection = evidence.connect_ledger(binding_case["ledger"])
    try:
        connection.execute(
            "DROP TRIGGER action_binding_manifests_v04_are_immutable_update"
        )
        connection.execute(
            "UPDATE action_binding_manifests_v04 SET committed_at = 'not-a-time'"
        )
    finally:
        connection.close()
    with pytest.raises(BindingTransactionError, match="committed_at"):
        _commit(binding_case)


def test_manifest_rejects_judgment_committed_after_manifest_commit_time(
    binding_case,
) -> None:
    connection = evidence.connect_ledger(binding_case["ledger"])
    try:
        connection.execute(
            "DROP TRIGGER judgment_commitments_v04_are_immutable_update"
        )
        connection.execute(
            "UPDATE judgment_commitments_v04 "
            "SET committed_at = '2026-01-01T00:00:10Z'"
        )
    finally:
        connection.close()
    with pytest.raises(BindingTransactionError, match="Judgment.*committed|order"):
        _commit(binding_case)


def test_manifest_rejects_judgment_commit_time_outside_its_validity(
    binding_case,
) -> None:
    connection = evidence.connect_ledger(binding_case["ledger"])
    try:
        connection.execute(
            "DROP TRIGGER judgment_commitments_v04_are_immutable_update"
        )
        connection.execute(
            "UPDATE judgment_commitments_v04 "
            "SET committed_at = '2026-01-01T00:46:00Z'"
        )
    finally:
        connection.close()
    with pytest.raises(BindingTransactionError, match="Judgment.*validity"):
        _commit(binding_case)


def test_history_replay_rejects_commit_time_after_manifest_expiry(
    binding_case,
) -> None:
    _commit(binding_case)
    connection = evidence.connect_ledger(binding_case["ledger"])
    try:
        connection.execute(
            "DROP TRIGGER action_binding_manifests_v04_are_immutable_update"
        )
        connection.execute(
            "UPDATE action_binding_manifests_v04 "
            "SET committed_at = '2026-01-01T00:41:00Z'"
        )
    finally:
        connection.close()
    with pytest.raises(BindingTransactionError, match="validity|history"):
        load_current_action_binding_manifest(
            binding_case["ledger"], binding_case["work_order"].digest
        )


def test_two_payloads_cannot_reuse_one_manifest_id(binding_case) -> None:
    _commit(binding_case)
    attacked = _resign_manifest(
        binding_case["manifest"],
        binding_case["manager_key"],
        expires_at="2026-01-01T00:39:59Z",
    )
    with pytest.raises(BindingTransactionError, match="id"):
        _commit(binding_case, attacked)


@pytest.mark.parametrize("fault", ["insert_failure", "before_commit", "commit_failure"])
def test_precommit_faults_leave_all_tables_unchanged(binding_case, fault) -> None:
    before = _snapshot(binding_case["ledger"])
    with pytest.raises(BindingTransactionError):
        _commit(binding_case, fault=fault)
    assert _snapshot(binding_case["ledger"]) == before


def test_commit_ack_loss_returns_exact_committed_truth(binding_case) -> None:
    with pytest.raises(BindingCommittedError) as raised:
        _commit(binding_case, fault="commit_ack_loss")
    assert raised.value.committed == binding_case["manifest"]
    assert load_current_action_binding_manifest(
        binding_case["ledger"], binding_case["work_order"].digest
    ) == binding_case["manifest"]


def test_supersession_ack_loss_readback_confirms_full_relation_history(
    binding_case,
) -> None:
    _commit(binding_case)
    child = _signed_manifest(
        work_order=binding_case["work_order"],
        scope=binding_case["scope"],
        judgment=binding_case["judgment"],
        projection=binding_case["projection"],
        manager_key=binding_case["manager_key"],
        manifest_id="5" * 64,
        nonce="6" * 64,
        supersedes=binding_case["manifest"],
    )
    with pytest.raises(BindingCommittedError) as raised:
        _commit(binding_case, child, fault="commit_ack_loss")
    assert raised.value.committed == child
    assert load_current_action_binding_manifest(
        binding_case["ledger"], binding_case["work_order"].digest
    ) == child


def test_ack_gap_allows_legal_child_before_parent_exact_readback(
    binding_case,
    monkeypatch,
) -> None:
    parent = binding_case["manifest"]
    child = _signed_manifest(
        work_order=binding_case["work_order"],
        scope=binding_case["scope"],
        judgment=binding_case["judgment"],
        projection=binding_case["projection"],
        manager_key=binding_case["manager_key"],
        manifest_id="5" * 64,
        nonce="6" * 64,
        supersedes=parent,
    )
    readback_entered = threading.Event()
    allow_readback = threading.Event()
    exact_readback = binding_transactions._exact_manifest_readback

    def delayed_readback(path, manifest, adapter_profile, committed_at):
        if manifest.binding_manifest_id == parent.binding_manifest_id:
            readback_entered.set()
            assert allow_readback.wait(timeout=5)
        return exact_readback(path, manifest, adapter_profile, committed_at)

    monkeypatch.setattr(
        binding_transactions, "_exact_manifest_readback", delayed_readback
    )

    def commit_parent_after_lost_ack():
        try:
            _commit(binding_case, parent, fault="commit_ack_loss")
        except BindingTransactionError as error:
            return error
        raise AssertionError("commit acknowledgement loss must raise")

    with ThreadPoolExecutor(max_workers=2) as pool:
        parent_future = pool.submit(commit_parent_after_lost_ack)
        assert readback_entered.wait(timeout=5)
        try:
            assert _commit(binding_case, child) == child
        finally:
            allow_readback.set()
        parent_result = parent_future.result(timeout=5)
    assert isinstance(parent_result, BindingCommittedError)
    assert parent_result.committed == parent
    assert load_current_action_binding_manifest(
        binding_case["ledger"], binding_case["work_order"].digest
    ) == child


def test_child_commit_time_cannot_precede_parent_commit_time(binding_case) -> None:
    _commit(
        binding_case,
        transaction_time=datetime(2026, 1, 1, 0, 0, 20, tzinfo=UTC),
    )
    child = _signed_manifest(
        work_order=binding_case["work_order"],
        scope=binding_case["scope"],
        judgment=binding_case["judgment"],
        projection=binding_case["projection"],
        manager_key=binding_case["manager_key"],
        manifest_id="5" * 64,
        nonce="6" * 64,
        supersedes=binding_case["manifest"],
    )
    before = _snapshot(binding_case["ledger"])
    with pytest.raises(BindingTransactionError, match="parent.*committed|order"):
        _commit(
            binding_case,
            child,
            transaction_time=datetime(2026, 1, 1, 0, 0, 10, tzinfo=UTC),
        )
    assert _snapshot(binding_case["ledger"]) == before


def test_cleanup_failure_returns_exact_committed_truth(binding_case) -> None:
    with pytest.raises(BindingCommittedError) as raised:
        _commit(binding_case, fault="cleanup_failure")
    assert raised.value.committed == binding_case["manifest"]
    assert load_current_action_binding_manifest(
        binding_case["ledger"], binding_case["work_order"].digest
    ) == binding_case["manifest"]


def test_manifest_tables_are_physically_immutable(binding_case) -> None:
    _commit(binding_case)
    connection = evidence.connect_ledger(binding_case["ledger"])
    try:
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute(
                "UPDATE action_binding_manifests_v04 SET committed_at = 'changed'"
            )
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute("DELETE FROM action_binding_manifests_v04")
    finally:
        connection.close()


def test_supersession_relations_are_physically_immutable(binding_case) -> None:
    _commit(binding_case)
    child = _signed_manifest(
        work_order=binding_case["work_order"],
        scope=binding_case["scope"],
        judgment=binding_case["judgment"],
        projection=binding_case["projection"],
        manager_key=binding_case["manager_key"],
        manifest_id="5" * 64,
        nonce="6" * 64,
        supersedes=binding_case["manifest"],
    )
    _commit(binding_case, child)
    connection = evidence.connect_ledger(binding_case["ledger"])
    try:
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute(
                "UPDATE action_binding_manifest_supersessions_v04 "
                "SET parent_manifest_digest = 'changed'"
            )
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute(
                "DELETE FROM action_binding_manifest_supersessions_v04"
            )
    finally:
        connection.close()


def test_current_loader_rejects_rewired_signed_history(binding_case) -> None:
    _commit(binding_case)
    child = _signed_manifest(
        work_order=binding_case["work_order"],
        scope=binding_case["scope"],
        judgment=binding_case["judgment"],
        projection=binding_case["projection"],
        manager_key=binding_case["manager_key"],
        manifest_id="5" * 64,
        nonce="6" * 64,
        supersedes=binding_case["manifest"],
    )
    _commit(binding_case, child)
    grandchild = _signed_manifest(
        work_order=binding_case["work_order"],
        scope=binding_case["scope"],
        judgment=binding_case["judgment"],
        projection=binding_case["projection"],
        manager_key=binding_case["manager_key"],
        manifest_id="7" * 64,
        nonce="8" * 64,
        supersedes=child,
        created_at="2026-01-01T00:00:10Z",
    )
    _commit(
        binding_case,
        grandchild,
        transaction_time=datetime(2026, 1, 1, 0, 0, 10, tzinfo=UTC),
    )
    connection = evidence.connect_ledger(binding_case["ledger"])
    try:
        connection.execute(
            "DROP TRIGGER action_binding_supersessions_v04_are_immutable_delete"
        )
        connection.execute(
            "DELETE FROM action_binding_manifest_supersessions_v04"
        )
        connection.executemany(
            """
            INSERT INTO action_binding_manifest_supersessions_v04 (
                child_manifest_id, parent_manifest_id, parent_manifest_digest
            ) VALUES (?, ?, ?)
            """,
            (
                (
                    child.binding_manifest_id,
                    grandchild.binding_manifest_id,
                    grandchild.digest,
                ),
                (
                    grandchild.binding_manifest_id,
                    binding_case["manifest"].binding_manifest_id,
                    binding_case["manifest"].digest,
                ),
            ),
        )
    finally:
        connection.close()
    with pytest.raises(BindingTransactionError, match="relation|history"):
        load_current_action_binding_manifest(
            binding_case["ledger"], binding_case["work_order"].digest
        )


def test_new_root_rejected_when_history_is_a_cycle(binding_case) -> None:
    _commit(binding_case)
    child = _signed_manifest(
        work_order=binding_case["work_order"],
        scope=binding_case["scope"],
        judgment=binding_case["judgment"],
        projection=binding_case["projection"],
        manager_key=binding_case["manager_key"],
        manifest_id="5" * 64,
        nonce="6" * 64,
        supersedes=binding_case["manifest"],
    )
    _commit(binding_case, child)
    connection = evidence.connect_ledger(binding_case["ledger"])
    try:
        connection.execute(
            "DROP TRIGGER action_binding_supersessions_v04_are_immutable_delete"
        )
        connection.execute(
            "DELETE FROM action_binding_manifest_supersessions_v04"
        )
        connection.executemany(
            """
            INSERT INTO action_binding_manifest_supersessions_v04 (
                child_manifest_id, parent_manifest_id, parent_manifest_digest
            ) VALUES (?, ?, ?)
            """,
            (
                (
                    binding_case["manifest"].binding_manifest_id,
                    child.binding_manifest_id,
                    child.digest,
                ),
                (
                    child.binding_manifest_id,
                    binding_case["manifest"].binding_manifest_id,
                    binding_case["manifest"].digest,
                ),
            ),
        )
    finally:
        connection.close()
    new_root = _signed_manifest(
        work_order=binding_case["work_order"],
        scope=binding_case["scope"],
        judgment=binding_case["judgment"],
        projection=binding_case["projection"],
        manager_key=binding_case["manager_key"],
        manifest_id="7" * 64,
        nonce="8" * 64,
    )
    with pytest.raises(BindingTransactionError, match="cycle|history"):
        _commit(binding_case, new_root)


def test_current_loader_rejects_historical_manager_signature_drift(
    binding_case,
) -> None:
    _commit(binding_case)
    child = _signed_manifest(
        work_order=binding_case["work_order"],
        scope=binding_case["scope"],
        judgment=binding_case["judgment"],
        projection=binding_case["projection"],
        manager_key=binding_case["manager_key"],
        manifest_id="5" * 64,
        nonce="6" * 64,
        supersedes=binding_case["manifest"],
    )
    _commit(binding_case, child)
    corrupted = binding_case["manifest"].model_dump(mode="json")
    corrupted["signature"] = binding_case["judgment"].signature
    connection = evidence.connect_ledger(binding_case["ledger"])
    try:
        connection.execute(
            "DROP TRIGGER action_binding_manifests_v04_are_immutable_update"
        )
        connection.execute(
            "UPDATE action_binding_manifests_v04 SET manifest_json = ? "
            "WHERE binding_manifest_id = ?",
            (
                evidence._canonical_json(corrupted).encode("utf-8"),
                binding_case["manifest"].binding_manifest_id,
            ),
        )
    finally:
        connection.close()
    with pytest.raises(BindingTransactionError, match="signature|history"):
        load_current_action_binding_manifest(
            binding_case["ledger"], binding_case["work_order"].digest
        )
