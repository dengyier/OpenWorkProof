"""Pure Judgment-to-Action binding validation for protocol v0.4."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone

import rfc8785
from pydantic import TypeAdapter

from openworkproof.models import (
    ActionBindingManifest,
    CanonicalRoot,
    EvaluationScopeManifest,
    JudgmentCommitment,
    TestProfile,
    WorkOrder,
)
from openworkproof.signing import (
    decode_and_verify_key_binding,
    verify_payload,
    verify_work_order_identity_bindings,
)


class BindingInputError(ValueError):
    """A signed object does not satisfy the v0.4 binding intersection."""


BindingValidationError = BindingInputError

_SUPPORTED_ADAPTER_ID = "openworkproof/code-delivery-github/0.1"
_SUPPORTED_ADAPTER_VERSION = "0.1"
_DIGEST64 = re.compile(r"^[0-9a-f]{64}$")
_MUTATING_TOOLS = frozenset({"owp.apply_patch", "owp.rollback_patch"})
_MUTATING_ACTIONS = frozenset({"patch", "rollback"})
_CODE_DELIVERY_TOOLS = frozenset(
    {
        "owp.apply_patch",
        "owp.create_pr_proposal",
        "owp.repo_read",
        "owp.rollback_patch",
        "owp.run_tests",
    }
)
_CODE_DELIVERY_ACTION_KINDS = frozenset(
    {"patch", "proposal", "read", "rollback", "test"}
)
_CANONICAL_ROOT_ADAPTER = TypeAdapter(CanonicalRoot)


@dataclass(frozen=True, slots=True)
class CanonicalAdapterProfile:
    """Complete immutable bytes for one generic adapter profile artifact."""

    canonical_json: bytes
    adapter_profile_digest: str


@dataclass(frozen=True, slots=True)
class DeterministicConstraintProjection:
    """Minimal Task 5 input later recomputed by the deterministic adapter.

    This is neither a signed object nor a committed adapter profile. Its four
    constraint axes are covered by ``constraint_projection_digest`` and the
    resulting digest must equal the Acceptor-signed Judgment constraint digest.
    """

    adapter_id: str
    adapter_version: str
    adapter_profile_digest: str
    allowed_tool_names: tuple[str, ...]
    allowed_action_kinds: tuple[str, ...]
    allowed_path_roots: tuple[str, ...]
    required_test_profile_digests: tuple[str, ...]


def projection_from_adapter_profile(
    profile: CanonicalAdapterProfile,
) -> DeterministicConstraintProjection:
    """Validate canonical profile bytes and derive the exact four-axis view."""

    if not isinstance(profile, CanonicalAdapterProfile):
        raise BindingInputError("canonical adapter profile is required")
    raw = profile.canonical_json
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= 1_048_576:
        raise BindingInputError("adapter profile canonical bytes are malformed")
    if (
        not isinstance(profile.adapter_profile_digest, str)
        or _DIGEST64.fullmatch(profile.adapter_profile_digest) is None
        or hashlib.sha256(raw).hexdigest() != profile.adapter_profile_digest
    ):
        raise BindingInputError("adapter profile digest does not match canonical bytes")
    try:
        payload = json.loads(raw.decode("utf-8"))
        canonical = rfc8785.dumps(payload)
    except (UnicodeDecodeError, ValueError, TypeError) as error:
        raise BindingInputError("adapter profile canonical JSON is invalid") from error
    if canonical != raw or not isinstance(payload, dict):
        raise BindingInputError("adapter profile bytes are not canonical")
    expected_keys = {
        "schema_version",
        "adapter_id",
        "adapter_version",
        "allowed_tool_names",
        "allowed_action_kinds",
        "allowed_path_roots",
        "required_test_profile_digests",
    }
    if set(payload) != expected_keys or payload.get("schema_version") != (
        "openworkproof-adapter-profile/0.4"
    ):
        raise BindingInputError("adapter profile JSON shape is not closed")
    if (
        payload.get("adapter_id") != _SUPPORTED_ADAPTER_ID
        or payload.get("adapter_version") != _SUPPORTED_ADAPTER_VERSION
    ):
        raise BindingInputError("adapter profile id or version is unsupported")
    axes: dict[str, tuple[str, ...]] = {}
    for field in (
        "allowed_tool_names",
        "allowed_action_kinds",
        "allowed_path_roots",
        "required_test_profile_digests",
    ):
        values = payload.get(field)
        if (
            not isinstance(values, list)
            or not values
            or any(not isinstance(value, str) or not value for value in values)
        ):
            raise BindingInputError(f"adapter profile {field} is malformed")
        axes[field] = tuple(values)
    projection = DeterministicConstraintProjection(
        adapter_id=payload["adapter_id"],
        adapter_version=payload["adapter_version"],
        adapter_profile_digest=profile.adapter_profile_digest,
        allowed_tool_names=axes["allowed_tool_names"],
        allowed_action_kinds=axes["allowed_action_kinds"],
        allowed_path_roots=axes["allowed_path_roots"],
        required_test_profile_digests=axes["required_test_profile_digests"],
    )
    for values, label in (
        (projection.allowed_tool_names, "allowed_tool_names"),
        (projection.allowed_action_kinds, "allowed_action_kinds"),
        (projection.allowed_path_roots, "allowed_path_roots"),
        (
            projection.required_test_profile_digests,
            "required_test_profile_digests",
        ),
    ):
        if not _is_nonempty_sorted_unique(values):
            raise BindingInputError(
                f"adapter profile {label} is not sorted and unique"
            )
    if any(
        _DIGEST64.fullmatch(value) is None
        for value in projection.required_test_profile_digests
    ):
        raise BindingInputError("adapter profile test profile digest is malformed")
    if any(
        tool not in _CODE_DELIVERY_TOOLS
        for tool in projection.allowed_tool_names
    ):
        raise BindingInputError("adapter profile contains an unsupported tool")
    if any(
        action not in _CODE_DELIVERY_ACTION_KINDS
        for action in projection.allowed_action_kinds
    ):
        raise BindingInputError("adapter profile contains an unsupported action kind")
    try:
        for root in projection.allowed_path_roots:
            _CANONICAL_ROOT_ADAPTER.validate_python(root)
    except ValueError as error:
        raise BindingInputError(
            "adapter profile contains a noncanonical root"
        ) from error
    return projection


def canonical_test_profile_digest(profile: TestProfile) -> str:
    """Hash the exact canonical TestProfile embedded in the signed WorkOrder."""

    if not isinstance(profile, TestProfile):
        raise BindingValidationError("WorkOrder test profile is malformed")
    return hashlib.sha256(rfc8785.dumps(profile.model_dump(mode="json"))).hexdigest()


def constraint_projection_digest(
    projection: DeterministicConstraintProjection,
) -> str:
    """Hash the closed four-axis deterministic constraint projection."""

    if not isinstance(projection, DeterministicConstraintProjection):
        raise BindingValidationError("deterministic constraint projection is malformed")
    return hashlib.sha256(
        rfc8785.dumps(
            {
                "schema_version": (
                    "openworkproof-deterministic-constraint-projection/0.4"
                ),
                "adapter_id": projection.adapter_id,
                "adapter_version": projection.adapter_version,
                "adapter_profile_digest": projection.adapter_profile_digest,
                "allowed_tool_names": list(projection.allowed_tool_names),
                "allowed_action_kinds": list(projection.allowed_action_kinds),
                "allowed_path_roots": list(projection.allowed_path_roots),
                "required_test_profile_digests": list(
                    projection.required_test_profile_digests
                ),
            }
        )
    ).hexdigest()


def _binding_for_role(work_order: WorkOrder, role: str):
    candidates = tuple(
        binding for binding in work_order.key_bindings if binding.role == role
    )
    if len(candidates) != 1:
        raise BindingValidationError(f"WorkOrder {role} authority is unavailable")
    return candidates[0]


def _is_nonempty_sorted_unique(values: tuple[str, ...]) -> bool:
    return bool(values) and values == tuple(sorted(set(values), key=str.encode))


def _root_is_covered(root: str, allowed_root: str) -> bool:
    return root == allowed_root or root.startswith(f"{allowed_root}/")


def _roots_are_covered(
    roots: tuple[str, ...], allowed_roots: tuple[str, ...]
) -> bool:
    return all(
        any(_root_is_covered(root, allowed) for allowed in allowed_roots)
        for root in roots
    )


def _canonical_utc_second(value: datetime) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() != timezone.utc.utcoffset(value)
        or value.microsecond != 0
    ):
        raise BindingValidationError(
            "binding transaction time must be a canonical UTC second"
        )
    return value


def validate_action_binding_manifest(
    *,
    work_order: WorkOrder,
    judgment: JudgmentCommitment,
    scope: EvaluationScopeManifest,
    adapter_profile: CanonicalAdapterProfile,
    manifest: ActionBindingManifest,
    transaction_time: datetime,
) -> ActionBindingManifest:
    """Validate the exact signed authority and four-axis constraint intersection."""

    try:
        parsed_work_order = WorkOrder.model_validate(work_order.model_dump(mode="json"))
        parsed_judgment = JudgmentCommitment.model_validate(
            judgment.model_dump(mode="json")
        )
        parsed_scope = EvaluationScopeManifest.model_validate(
            scope.model_dump(mode="json")
        )
        parsed_manifest = ActionBindingManifest.model_validate(
            manifest.model_dump(mode="json")
        )
    except Exception as error:
        raise BindingValidationError("binding input model is malformed") from error
    now = _canonical_utc_second(transaction_time)
    projection = projection_from_adapter_profile(adapter_profile)

    if not verify_work_order_identity_bindings(parsed_work_order):
        raise BindingValidationError("WorkOrder authority is invalid")
    acceptor = _binding_for_role(parsed_work_order, "Acceptor")
    manager = _binding_for_role(parsed_work_order, "Manager")
    try:
        acceptor_key = decode_and_verify_key_binding(acceptor)
        manager_key = decode_and_verify_key_binding(manager)
    except Exception as error:
        raise BindingValidationError("WorkOrder authority key is invalid") from error
    if (
        parsed_judgment.signer_key_id != acceptor.key_id
        or parsed_judgment.signer_key_id not in parsed_work_order.acceptor_key_ids
        or not verify_payload(
            "judgment-commitment",
            parsed_judgment.model_dump(mode="json"),
            acceptor_key,
            version="0.4",
        )
    ):
        raise BindingValidationError(
            "Judgment signer is not the WorkOrder Customer Acceptor"
        )
    if (
        parsed_manifest.signer_key_id != manager.key_id
        or not verify_payload(
            "action-binding-manifest",
            parsed_manifest.model_dump(mode="json"),
            manager_key,
            version="0.4",
        )
    ):
        raise BindingValidationError(
            "ActionBindingManifest signer is not the WorkOrder Manager"
        )
    if (
        parsed_scope.signer_key_id != manager.key_id
        or not verify_payload(
            "evaluation-scope",
            parsed_scope.model_dump(mode="json"),
            manager_key,
            version="0.3",
        )
    ):
        raise BindingValidationError(
            "Evaluation Scope signer is not the WorkOrder Manager"
        )

    if parsed_manifest.work_order_digest != parsed_work_order.digest:
        raise BindingValidationError("Manifest WorkOrder digest does not match")
    if (
        parsed_judgment.repository != parsed_work_order.repository
        or parsed_judgment.source_revision != parsed_work_order.source_commit
        or parsed_judgment.target_branch != parsed_work_order.branch
        or parsed_scope.work_order_digest != parsed_work_order.digest
        or parsed_scope.source_revision != parsed_work_order.source_commit
        or parsed_manifest.source_revision != parsed_work_order.source_commit
    ):
        raise BindingValidationError("WorkOrder source constraints do not match")
    if (
        parsed_manifest.judgment_commitment_id != parsed_judgment.commitment_id
        or parsed_manifest.judgment_commitment_digest != parsed_judgment.digest
    ):
        raise BindingValidationError("Manifest Judgment digest chain does not match")
    if (
        parsed_manifest.evaluation_scope_id != parsed_scope.scope_id
        or parsed_manifest.evaluation_scope_digest != parsed_scope.digest
    ):
        raise BindingValidationError("Manifest Scope digest chain does not match")

    adapter_tuple = (
        projection.adapter_id,
        projection.adapter_version,
        projection.adapter_profile_digest,
    )
    if adapter_tuple != (
        parsed_judgment.adapter_id,
        parsed_judgment.adapter_version,
        parsed_judgment.adapter_profile_digest,
    ) or adapter_tuple != (
        parsed_manifest.adapter_id,
        parsed_manifest.adapter_version,
        parsed_manifest.adapter_profile_digest,
    ):
        raise BindingValidationError("adapter identity or profile digest does not match")
    if constraint_projection_digest(projection) != parsed_judgment.action_constraint_digest:
        raise BindingValidationError(
            "deterministic constraint projection does not match Judgment"
        )

    for values, label in (
        (projection.allowed_tool_names, "allowed_tool_names"),
        (projection.allowed_action_kinds, "allowed_action_kinds"),
        (projection.allowed_path_roots, "allowed_path_roots"),
        (
            projection.required_test_profile_digests,
            "required_test_profile_digests",
        ),
    ):
        if not _is_nonempty_sorted_unique(values):
            raise BindingValidationError(f"projection {label} is not sorted and unique")

    if not set(parsed_manifest.allowed_tool_names).issubset(
        projection.allowed_tool_names
    ):
        raise BindingValidationError(
            "manifest constraint exceeds Judgment: allowed tools"
        )
    if not set(parsed_manifest.allowed_tool_names).issubset(
        parsed_work_order.allowed_tools
    ):
        raise BindingValidationError(
            "manifest constraint exceeds WorkOrder: allowed tools"
        )
    if not set(parsed_manifest.allowed_action_kinds).issubset(
        projection.allowed_action_kinds
    ):
        raise BindingValidationError(
            "manifest constraint exceeds Judgment: allowed actions"
        )
    if not _roots_are_covered(
        parsed_manifest.allowed_path_roots, projection.allowed_path_roots
    ):
        raise BindingValidationError(
            "manifest constraint exceeds Judgment: allowed paths"
        )
    work_order_roots = tuple(
        sorted(
            set(
                (
                    *parsed_work_order.allowed_read_roots,
                    *parsed_work_order.allowed_write_roots,
                )
            ),
            key=str.encode,
        )
    )
    if not _roots_are_covered(parsed_manifest.allowed_path_roots, work_order_roots):
        raise BindingValidationError(
            "manifest constraint exceeds WorkOrder: allowed paths"
        )
    if (
        _MUTATING_TOOLS.intersection(parsed_manifest.allowed_tool_names)
        or _MUTATING_ACTIONS.intersection(parsed_manifest.allowed_action_kinds)
    ) and not _roots_are_covered(
        parsed_manifest.allowed_path_roots,
        parsed_work_order.allowed_write_roots,
    ):
        raise BindingValidationError(
            "mutating manifest paths exceed WorkOrder write roots"
        )

    work_order_test_digests = tuple(
        sorted(
            (
                canonical_test_profile_digest(profile)
                for profile in parsed_work_order.test_profiles
            ),
            key=str.encode,
        )
    )
    if (
        parsed_manifest.required_test_profile_digests
        != projection.required_test_profile_digests
        or projection.required_test_profile_digests != work_order_test_digests
    ):
        raise BindingValidationError(
            "required test profile constraints do not match the WorkOrder"
        )

    requirements_by_kind = {
        kind: tuple(
            sorted(
                (
                    binding.requirement_digest
                    for binding in parsed_scope.requirement_bindings
                    if binding.requirement_kind == kind
                ),
                key=str.encode,
            )
        )
        for kind in ("acceptance_condition", "required_artifact")
    }
    if requirements_by_kind["acceptance_condition"] != (
        parsed_judgment.acceptance_condition_digests
    ):
        raise BindingValidationError(
            "Scope acceptance_condition bindings do not match Judgment"
        )
    if requirements_by_kind["required_artifact"] != (
        parsed_judgment.required_artifact_digests
    ):
        raise BindingValidationError(
            "Scope required_artifact bindings do not match Judgment"
        )
    if parsed_scope.excluded_locator_digests != parsed_judgment.excluded_scope_digests:
        raise BindingValidationError("Scope excluded locators do not match Judgment")

    if parsed_manifest.created_at < parsed_work_order.issued_at:
        raise BindingValidationError("manifest predates the WorkOrder")
    if parsed_manifest.created_at < parsed_scope.created_at:
        raise BindingValidationError("manifest predates the Scope")
    if parsed_manifest.created_at < parsed_judgment.valid_from:
        raise BindingValidationError("manifest predates Judgment validity")

    if not (
        parsed_judgment.valid_from <= now < parsed_judgment.expires_at
        and parsed_scope.created_at <= now < parsed_scope.expires_at
        and parsed_manifest.created_at <= now < parsed_manifest.expires_at
    ):
        raise BindingValidationError("binding validity intersection is not current")
    if parsed_manifest.expires_at > parsed_judgment.expires_at:
        raise BindingValidationError("manifest expiry exceeds Judgment")
    if parsed_manifest.expires_at > parsed_scope.expires_at:
        raise BindingValidationError("manifest expiry exceeds Scope")
    if parsed_manifest.expires_at > parsed_work_order.deadline:
        raise BindingValidationError("manifest expiry exceeds WorkOrder")
    return parsed_manifest


__all__ = [
    "BindingInputError",
    "BindingValidationError",
    "CanonicalAdapterProfile",
    "DeterministicConstraintProjection",
    "canonical_test_profile_digest",
    "constraint_projection_digest",
    "projection_from_adapter_profile",
    "validate_action_binding_manifest",
]
