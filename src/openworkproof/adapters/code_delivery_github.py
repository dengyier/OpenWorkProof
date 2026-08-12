"""Deterministic GitHub code-delivery binding adapter (Task 7).

The first (and, for this release, only) domain adapter for judgment-to-action
binding. It replays the mapping from a customer-signed judgment to the action
a receipt observed, using only canonical data and Git-derived facts.

Boundaries:
- Pure functions only: no filesystem, no network, no execution inside the
  mapping; callers supply immutable observations and digests.
- Deterministic: identical canonical input produces identical replay digests
  regardless of hash randomization or byte order.
- No LLM inference of customer intent, no general policy language, and no
  second domain adapter.
"""

from __future__ import annotations

import dataclasses
import hashlib
import re
import unicodedata

import rfc8785

from openworkproof.binding import (
    BindingInputError,
    DeterministicConstraintProjection,
    constraint_projection_digest,
)

ADAPTER_ID = "openworkproof/code-delivery-github/0.1"
ADAPTER_VERSION = "0.1"

_SCHEMA_VERSION = "openworkproof-code-delivery-adapter/0.4"

_DIGEST64 = re.compile(r"^[0-9a-f]{64}$")
_OID40 = re.compile(r"^[0-9a-f]{40}$")

_BOUND = "BOUND"
_UNBOUND = "UNBOUND"
_INDETERMINATE = "INDETERMINATE"

_MAX_PATH_BYTES = 4096
_MAX_COLLECTION = 1024


@dataclasses.dataclass(frozen=True, slots=True)
class CodeDeliveryAdapterProfile:
    """Immutable adapter profile; byte-equivalent to the Task 5 projection.

    ``adapter_profile_digest`` is the digest of the exact canonical profile
    bytes accepted by the Acceptor-signed Judgment.
    """

    adapter_id: str
    adapter_version: str
    adapter_profile_digest: str
    allowed_tool_names: tuple[str, ...]
    allowed_action_kinds: tuple[str, ...]
    allowed_path_roots: tuple[str, ...]
    required_test_profile_digests: tuple[str, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class CodeDeliveryJudgmentInput:
    """Canonical customer-side judgment input for one code-delivery action.

    Fields mirror the Acceptor-signed ``JudgmentCommitment`` surface that the
    adapter is able to re-derive: adapter identity, repository identity, the
    immutable source revision, the target branch, acceptance conditions,
    excluded scope, required artifacts, and the deterministic constraint axes.
    """

    adapter_id: str
    adapter_version: str
    adapter_profile_digest: str
    issue_snapshot_digest: str
    repository_identity: str
    source_revision: str
    target_branch: str
    acceptance_condition_digests: tuple[str, ...]
    excluded_scope_digests: tuple[str, ...]
    excluded_path_roots: tuple[str, ...]
    required_artifact_digests: tuple[str, ...]
    allowed_path_roots: tuple[str, ...]
    allowed_action_kinds: tuple[str, ...]
    required_test_profile_digests: tuple[str, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class NormalizedJudgment:
    """Deterministic normalization result of one judgment input."""

    normalized_facts_digest: str


@dataclasses.dataclass(frozen=True, slots=True)
class ObservedAction:
    """Immutable facts a verifier observed from the execution receipt chain."""

    tool_name: str
    action_kind: str
    changed_paths: tuple[str, ...]
    patch_digest: str | None
    candidate_commit_digest: str | None
    workspace_digest: str | None
    artifact_digests: tuple[str, ...]
    covered_condition_digests: tuple[str, ...]
    undeclared_side_effects: tuple[str, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class CodeDeliveryReplayInput:
    """Everything the pure replay needs: judgment, profile, observed action."""

    judgment: CodeDeliveryJudgmentInput
    profile: CodeDeliveryAdapterProfile
    observed: ObservedAction


@dataclasses.dataclass(frozen=True, slots=True)
class BindingReplayResult:
    """One deterministic replay verdict and its canonical digest."""

    outcome: str
    reason_codes: tuple[str, ...]
    replay_digest: str


# ---------------------------------------------------------------------------
# Canonicalization helpers
# ---------------------------------------------------------------------------


def _canonical_path(value: str) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= _MAX_PATH_BYTES:
        raise BindingInputError("canonical path is malformed")
    normalized = unicodedata.normalize("NFC", value)
    if "\x00" in normalized or "\\" in normalized or ".." in normalized:
        raise BindingInputError("canonical path is unsafe")
    return normalized.rstrip("/") or "/"


def _validated_sorted_unique(
    values: tuple[str, ...],
    label: str,
    *,
    allow_empty: bool = False,
) -> tuple[str, ...]:
    if not isinstance(values, (tuple, list)) or not all(
        isinstance(item, str) for item in values
    ):
        raise BindingInputError(f"{label} must be a sequence of strings")
    if not allow_empty and not values:
        raise BindingInputError(f"{label} must not be empty")
    if len(values) > _MAX_COLLECTION:
        raise BindingInputError(f"{label} exceeds the collection bound")
    if list(values) != sorted(values):
        raise BindingInputError(f"{label} must be sorted")
    if len(set(values)) != len(values):
        raise BindingInputError(f"{label} must be unique")
    return tuple(values)


def _validate_digest64(value: str, label: str) -> str:
    if not isinstance(value, str) or _DIGEST64.fullmatch(value) is None:
        raise BindingInputError(f"{label} is not a sha256 digest")
    return value


def _validate_oid40(value: str, label: str) -> str:
    if not isinstance(value, str) or _OID40.fullmatch(value) is None:
        raise BindingInputError(f"{label} is not a 40-char object id")
    return value


def _validate_identifier(value: str, label: str) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 1024
        or "\x00" in value
    ):
        raise BindingInputError(f"{label} is malformed")
    return value


def _validated_roots(
    roots: tuple[str, ...], label: str, *, allow_empty: bool = False
) -> tuple[str, ...]:
    validated = tuple(_canonical_path(root) for root in roots)
    return _validated_sorted_unique(validated, label, allow_empty=allow_empty)


def _path_within(path: str, root: str) -> bool:
    return path == root or path.startswith(f"{root}/")


# ---------------------------------------------------------------------------
# Public pure operations
# ---------------------------------------------------------------------------


def action_constraint_digest(profile: CodeDeliveryAdapterProfile) -> str:
    """Hash the closed four-axis deterministic constraint projection.

    Byte-identical to the Task 5 ``constraint_projection_digest`` so an
    Acceptor-signed ``action_constraint_digest`` replays exactly.
    """

    if not isinstance(profile, CodeDeliveryAdapterProfile):
        raise BindingInputError("adapter profile is required")
    projection = DeterministicConstraintProjection(
        adapter_id=profile.adapter_id,
        adapter_version=profile.adapter_version,
        adapter_profile_digest=profile.adapter_profile_digest,
        allowed_tool_names=profile.allowed_tool_names,
        allowed_action_kinds=profile.allowed_action_kinds,
        allowed_path_roots=profile.allowed_path_roots,
        required_test_profile_digests=profile.required_test_profile_digests,
    )
    return constraint_projection_digest(projection)


def normalize_code_delivery_judgment(
    value: CodeDeliveryJudgmentInput,
) -> NormalizedJudgment:
    """Normalize one judgment input into a deterministic facts digest."""

    if not isinstance(value, CodeDeliveryJudgmentInput):
        raise BindingInputError("code delivery judgment input is required")
    _validate_identifier(value.adapter_id, "adapter_id")
    _validate_identifier(value.adapter_version, "adapter_version")
    _validate_digest64(value.adapter_profile_digest, "adapter_profile_digest")
    _validate_digest64(
        value.issue_snapshot_digest, "issue_snapshot_digest"
    )
    _validate_identifier(value.repository_identity, "repository_identity")
    _validate_oid40(value.source_revision, "source_revision")
    _validate_identifier(value.target_branch, "target_branch")
    acceptance = _validated_sorted_unique(
        value.acceptance_condition_digests, "acceptance_condition_digests"
    )
    excluded_scope = _validated_sorted_unique(
        value.excluded_scope_digests, "excluded_scope_digests", allow_empty=True
    )
    artifacts = _validated_sorted_unique(
        value.required_artifact_digests, "required_artifact_digests"
    )
    allowed_paths = _validated_roots(
        value.allowed_path_roots, "allowed_path_roots"
    )
    excluded_paths = _validated_roots(
        value.excluded_path_roots, "excluded_path_roots", allow_empty=True
    )
    actions = _validated_sorted_unique(
        value.allowed_action_kinds, "allowed_action_kinds"
    )
    test_profiles = _validated_sorted_unique(
        value.required_test_profile_digests, "required_test_profile_digests"
    )

    normalized = {
        "schema_version": _SCHEMA_VERSION,
        "adapter_id": value.adapter_id,
        "adapter_version": value.adapter_version,
        "adapter_profile_digest": value.adapter_profile_digest,
        "issue_snapshot_digest": value.issue_snapshot_digest,
        "repository_identity": value.repository_identity,
        "source_revision": value.source_revision,
        "target_branch": value.target_branch,
        "acceptance_condition_digests": list(acceptance),
        "excluded_scope_digests": list(excluded_scope),
        "excluded_path_roots": list(excluded_paths),
        "required_artifact_digests": list(artifacts),
        "allowed_path_roots": list(allowed_paths),
        "allowed_action_kinds": list(actions),
        "required_test_profile_digests": list(test_profiles),
    }
    facts_digest = hashlib.sha256(
        rfc8785.dumps(normalized)
    ).hexdigest()
    return NormalizedJudgment(normalized_facts_digest=facts_digest)


def replay_code_delivery_binding(
    value: CodeDeliveryReplayInput,
) -> BindingReplayResult:
    """Replay the judgment-to-action mapping for one observed execution.

    Outcomes follow the design: BOUND requires positive evidence on every
    axis; explicit mismatches are UNBOUND; unavailable or drifting inputs are
    INDETERMINATE. Absence of detected error is never BOUND on its own.
    """

    if not isinstance(value, CodeDeliveryReplayInput):
        raise BindingInputError("code delivery replay input is required")
    judgment = value.judgment
    profile = value.profile
    observed = value.observed

    # Step 4: adapter version drift is explicit, never a silent fallback.
    reason_codes: list[str] = []
    if (
        not isinstance(profile, CodeDeliveryAdapterProfile)
        or profile.adapter_id != ADAPTER_ID
        or profile.adapter_version != ADAPTER_VERSION
        or judgment.adapter_id != profile.adapter_id
        or judgment.adapter_version != profile.adapter_version
    ):
        return _indeterminate("EVALUATOR_VERSION_DRIFT")
    if judgment.adapter_profile_digest != profile.adapter_profile_digest:
        return _indeterminate("ADAPTER_PROFILE_DIGEST_MISMATCH")

    try:
        observed_paths = tuple(_canonical_path(path) for path in observed.changed_paths)
        allowed_paths = tuple(
            _canonical_path(root) for root in profile.allowed_path_roots
        )
        excluded_paths = tuple(
            _canonical_path(root) for root in judgment.excluded_path_roots
        )
        observed_artifacts = _validated_sorted_unique(
            observed.artifact_digests,
            "observed artifact digests",
            allow_empty=True,
        )
        covered_conditions = _validated_sorted_unique(
            observed.covered_condition_digests,
            "covered condition digests",
            allow_empty=True,
        )
    except BindingInputError:
        return _indeterminate("EVIDENCE_INCOMPLETE")

    # 1. tool and action kind must be approved.
    if (
        observed.tool_name not in profile.allowed_tool_names
        or observed.action_kind not in profile.allowed_action_kinds
        or observed.action_kind not in judgment.allowed_action_kinds
    ):
        return _unbound("ACTION_OUTSIDE_APPROVED_SCOPE")

    # 2. every actual path inside allowed roots, none inside excluded roots.
    if any(
        not any(_path_within(path, root) for root in allowed_paths)
        or any(_path_within(path, root) for root in excluded_paths)
        for path in observed_paths
    ):
        return _unbound("ACTION_OUTSIDE_APPROVED_SCOPE")

    # 3. patch / candidate commit / workspace belong to the same chain.
    chain = (
        observed.patch_digest,
        observed.candidate_commit_digest,
        observed.workspace_digest,
    )
    if len({item is None for item in chain}) != 1:
        return _unbound("REPLAY_DIVERGED")

    # 4. every required artifact exists and matches.
    if not set(judgment.required_artifact_digests).issubset(
        set(observed_artifacts)
    ):
        return _unbound("ACTION_ARGUMENTS_MISMATCH")

    # 6. every acceptance condition maps to a covered target.
    if (
        not judgment.acceptance_condition_digests
        or covered_conditions
        != tuple(sorted(judgment.acceptance_condition_digests))
    ):
        return _unbound("ACTION_MAPPING_REJECTED")

    # 7. no undeclared side effects.
    if observed.undeclared_side_effects:
        return _unbound("ACTION_SIDE_EFFECT_UNDECLARED")

    return _bound(judgment, profile, observed_paths)


def _bound(
    judgment: CodeDeliveryJudgmentInput,
    profile: CodeDeliveryAdapterProfile,
    observed_paths: tuple[str, ...],
) -> BindingReplayResult:
    digest = _replay_digest(
        "BOUND",
        (),
        judgment,
        profile,
        observed_paths,
    )
    return BindingReplayResult(
        outcome=_BOUND,
        reason_codes=(),
        replay_digest=digest,
    )


def _unbound(code: str) -> BindingReplayResult:
    return BindingReplayResult(
        outcome=_UNBOUND,
        reason_codes=(code,),
        replay_digest=hashlib.sha256(
            rfc8785.dumps(
                {
                    "schema_version": _SCHEMA_VERSION,
                    "outcome": _UNBOUND,
                    "reason_codes": [code],
                }
            )
        ).hexdigest(),
    )


def _indeterminate(code: str) -> BindingReplayResult:
    return BindingReplayResult(
        outcome=_INDETERMINATE,
        reason_codes=(code,),
        replay_digest=hashlib.sha256(
            rfc8785.dumps(
                {
                    "schema_version": _SCHEMA_VERSION,
                    "outcome": _INDETERMINATE,
                    "reason_codes": [code],
                }
            )
        ).hexdigest(),
    )


def _replay_digest(
    outcome: str,
    reason_codes: tuple[str, ...],
    judgment: CodeDeliveryJudgmentInput,
    profile: CodeDeliveryAdapterProfile,
    observed_paths: tuple[str, ...],
) -> str:
    payload = {
        "schema_version": _SCHEMA_VERSION,
        "outcome": outcome,
        "reason_codes": list(reason_codes),
        "normalized_facts_digest": normalize_code_delivery_judgment(
            judgment
        ).normalized_facts_digest,
        "action_constraint_digest": action_constraint_digest(profile),
        "observed_paths": list(observed_paths),
    }
    return hashlib.sha256(rfc8785.dumps(payload)).hexdigest()
