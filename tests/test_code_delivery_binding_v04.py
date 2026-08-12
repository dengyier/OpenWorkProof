"""Deterministic GitHub code-delivery adapter replay coverage (Task 7)."""

from __future__ import annotations

import dataclasses
import hashlib

import pytest
import rfc8785

from openworkproof.adapters.code_delivery_github import (
    ADAPTER_ID,
    ADAPTER_VERSION,
    BindingReplayResult,
    CodeDeliveryAdapterProfile,
    CodeDeliveryJudgmentInput,
    CodeDeliveryReplayInput,
    NormalizedJudgment,
    ObservedAction,
    action_constraint_digest,
    normalize_code_delivery_judgment,
    replay_code_delivery_binding,
)
from openworkproof.binding import (
    DeterministicConstraintProjection,
    constraint_projection_digest,
)


# ---------------------------------------------------------------------------
# Step 1: frozen canonical fixtures
# ---------------------------------------------------------------------------

ISSUE_SNAPSHOT_DIGEST = "a" * 64
REPOSITORY_IDENTITY = "owner/repo"
SOURCE_REVISION = "f" * 40
TARGET_BRANCH = "main"

# Unicode/path normalization is part of the contract: byte-order and NFC forms
# must not change the digest.
CHANGED_PATHS = ("src/agent/gateway.py", "src/agent/models.py")


def _profile() -> CodeDeliveryAdapterProfile:
    return CodeDeliveryAdapterProfile(
        adapter_id=ADAPTER_ID,
        adapter_version=ADAPTER_VERSION,
        adapter_profile_digest="b" * 64,
        allowed_tool_names=("owp.apply_patch", "owp.repo_read", "owp.run_tests"),
        allowed_action_kinds=("patch", "read", "test"),
        allowed_path_roots=("src",),
        required_test_profile_digests=("c" * 64,),
    )


def _judgment_input() -> CodeDeliveryJudgmentInput:
    return CodeDeliveryJudgmentInput(
        adapter_id=ADAPTER_ID,
        adapter_version=ADAPTER_VERSION,
        adapter_profile_digest="b" * 64,
        issue_snapshot_digest=ISSUE_SNAPSHOT_DIGEST,
        repository_identity=REPOSITORY_IDENTITY,
        source_revision=SOURCE_REVISION,
        target_branch=TARGET_BRANCH,
        acceptance_condition_digests=("d" * 64, "e" * 64),
        excluded_scope_digests=(),
        excluded_path_roots=("docs",),
        required_artifact_digests=("9" * 64,),
        allowed_path_roots=("src",),
        allowed_action_kinds=("patch", "read", "test"),
        required_test_profile_digests=("c" * 64,),
    )


def _clean_action() -> ObservedAction:
    return ObservedAction(
        tool_name="owp.apply_patch",
        action_kind="patch",
        changed_paths=CHANGED_PATHS,
        patch_digest="1" * 64,
        candidate_commit_digest="2" * 64,
        workspace_digest="3" * 64,
        artifact_digests=("9" * 64,),
        covered_condition_digests=("d" * 64, "e" * 64),
        undeclared_side_effects=(),
    )


def _replay_input(
    *,
    judgment: CodeDeliveryJudgmentInput | None = None,
    profile: CodeDeliveryAdapterProfile | None = None,
    observed: ObservedAction | None = None,
) -> CodeDeliveryReplayInput:
    return CodeDeliveryReplayInput(
        judgment=judgment if judgment is not None else _judgment_input(),
        profile=profile if profile is not None else _profile(),
        observed=observed if observed is not None else _clean_action(),
    )


# ---------------------------------------------------------------------------
# Step 1: canonicalization / digest determinism
# ---------------------------------------------------------------------------


def test_action_constraint_digest_matches_task5_projection_bytes() -> None:
    profile = _profile()
    projection = DeterministicConstraintProjection(
        adapter_id=profile.adapter_id,
        adapter_version=profile.adapter_version,
        adapter_profile_digest=profile.adapter_profile_digest,
        allowed_tool_names=profile.allowed_tool_names,
        allowed_action_kinds=profile.allowed_action_kinds,
        allowed_path_roots=profile.allowed_path_roots,
        required_test_profile_digests=profile.required_test_profile_digests,
    )
    assert action_constraint_digest(profile) == constraint_projection_digest(
        projection
    )


def test_normalized_facts_digest_is_deterministic() -> None:
    first = normalize_code_delivery_judgment(_judgment_input())
    second = normalize_code_delivery_judgment(_judgment_input())
    assert isinstance(first, NormalizedJudgment)
    assert first.normalized_facts_digest == second.normalized_facts_digest
    assert first.normalized_facts_digest == hashlib.sha256(
        rfc8785.dumps(
            {
                "schema_version": "openworkproof-code-delivery-adapter/0.4",
                "adapter_id": ADAPTER_ID,
                "adapter_version": ADAPTER_VERSION,
                "adapter_profile_digest": "b" * 64,
                "issue_snapshot_digest": ISSUE_SNAPSHOT_DIGEST,
                "repository_identity": REPOSITORY_IDENTITY,
                "source_revision": SOURCE_REVISION,
                "target_branch": TARGET_BRANCH,
                "acceptance_condition_digests": ["d" * 64, "e" * 64],
                "excluded_scope_digests": [],
                "excluded_path_roots": ["docs"],
                "required_artifact_digests": ["9" * 64],
                "allowed_path_roots": ["src"],
                "allowed_action_kinds": ["patch", "read", "test"],
                "required_test_profile_digests": ["c" * 64],
            }
        )
    ).hexdigest()


def test_unicode_and_byte_order_do_not_change_replay() -> None:
    # Composed é (U+00E9) and decomposed e + U+0301 are NFC-equivalent and
    # must produce the same canonical replay digest.
    composed = dataclasses.replace(
        _clean_action(),
        changed_paths=("src/agent/gateway\u00e9.py", "src/agent/models.py"),
    )
    decomposed = dataclasses.replace(
        _clean_action(),
        changed_paths=("src/agent/gateway\u0065\u0301.py", "src/agent/models.py"),
    )
    composed_result = replay_code_delivery_binding(
        _replay_input(observed=composed)
    )
    decomposed_result = replay_code_delivery_binding(
        _replay_input(observed=decomposed)
    )
    assert composed_result.replay_digest == decomposed_result.replay_digest
    assert composed_result.outcome == decomposed_result.outcome == "BOUND"


# ---------------------------------------------------------------------------
# Step 2: mapping outcomes
# ---------------------------------------------------------------------------


def test_clean_delivery_replays_bound() -> None:
    result = replay_code_delivery_binding(_replay_input())
    assert result.outcome == "BOUND"
    assert result.reason_codes == ()


def test_coherently_resigned_action_outside_judgment_is_unbound() -> None:
    attacked = dataclasses.replace(
        _clean_action(), changed_paths=("docs/outside.md",)
    )
    result = replay_code_delivery_binding(_replay_input(observed=attacked))
    assert result.outcome == "UNBOUND"
    assert result.reason_codes == ("ACTION_OUTSIDE_APPROVED_SCOPE",)


def test_disallowed_tool_is_unbound() -> None:
    attacked = dataclasses.replace(_clean_action(), tool_name="owp.rollback_patch")
    result = replay_code_delivery_binding(_replay_input(observed=attacked))
    assert result.outcome == "UNBOUND"
    assert result.reason_codes == ("ACTION_OUTSIDE_APPROVED_SCOPE",)


def test_excluded_path_hit_is_unbound() -> None:
    attacked = dataclasses.replace(
        _clean_action(), changed_paths=("docs/internal.md",)
    )
    result = replay_code_delivery_binding(_replay_input(observed=attacked))
    assert result.outcome == "UNBOUND"
    assert result.reason_codes == ("ACTION_OUTSIDE_APPROVED_SCOPE",)


def test_missing_required_artifact_is_unbound() -> None:
    attacked = dataclasses.replace(_clean_action(), artifact_digests=("8" * 64,))
    result = replay_code_delivery_binding(_replay_input(observed=attacked))
    assert result.outcome == "UNBOUND"
    assert result.reason_codes == ("ACTION_ARGUMENTS_MISMATCH",)


def test_incomplete_acceptance_condition_mapping_is_unbound() -> None:
    attacked = dataclasses.replace(
        _clean_action(), covered_condition_digests=("d" * 64,)
    )
    result = replay_code_delivery_binding(_replay_input(observed=attacked))
    assert result.outcome == "UNBOUND"
    assert result.reason_codes == ("ACTION_MAPPING_REJECTED",)


def test_undeclared_side_effect_is_unbound() -> None:
    attacked = dataclasses.replace(
        _clean_action(), undeclared_side_effects=("git-push",)
    )
    result = replay_code_delivery_binding(_replay_input(observed=attacked))
    assert result.outcome == "UNBOUND"
    assert result.reason_codes == ("ACTION_SIDE_EFFECT_UNDECLARED",)


def test_execution_chain_divergence_is_unbound() -> None:
    attacked = dataclasses.replace(_clean_action(), workspace_digest=None)
    result = replay_code_delivery_binding(_replay_input(observed=attacked))
    assert result.outcome == "UNBOUND"
    assert result.reason_codes == ("REPLAY_DIVERGED",)


def test_adapter_version_drift_is_indeterminate() -> None:
    drifted = dataclasses.replace(_profile(), adapter_version="9.9")
    result = replay_code_delivery_binding(_replay_input(profile=drifted))
    assert result.outcome == "INDETERMINATE"
    assert result.reason_codes == ("EVALUATOR_VERSION_DRIFT",)


def test_adapter_profile_digest_mismatch_is_indeterminate() -> None:
    drifted = dataclasses.replace(_profile(), adapter_profile_digest="7" * 64)
    result = replay_code_delivery_binding(_replay_input(profile=drifted))
    assert result.outcome == "INDETERMINATE"
    assert result.reason_codes == ("ADAPTER_PROFILE_DIGEST_MISMATCH",)
