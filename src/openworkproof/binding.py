"""Pure Judgment-to-Action binding validation for protocol v0.4."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Mapping, Protocol, runtime_checkable
from datetime import datetime, timezone

import rfc8785
from pydantic import TypeAdapter

from openworkproof.models import (
    ActionBindingManifest,
    ActionReceiptEnvelope,
    AgentRequestV04,
    AuthorityCheckpoint,
    BindingDecision,
    BindingDecisionDraft,
    CanonicalRoot,
    EvaluationScopeManifest,
    JudgmentCommitment,
    RollbackReceiptV04,
    TestProfile,
    ToolCallReceiptV04,
    VerificationDecisionV03,
    WorkOrder,
    _INDETERMINATE_BINDING_REASONS,
    _UNBOUND_BINDING_REASONS,
)
from openworkproof.signing import (
    canonical_bytes,
    decode_and_verify_key_binding,
    key_id,
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




# --- Task 8: pure BindingDecision composition and verification -------------

_BINDING_DECISION_ID_DOMAIN = "openworkproof/binding-decision-id/v0.4"
_BINDING_DECISION_SCHEMA = "openworkproof-binding-decision/0.4"


@runtime_checkable
class BindingReplayView(Protocol):
    """Duck-typed replay result to avoid an adapters import cycle."""

    outcome: str
    reason_codes: tuple[str, ...]
    replay_digest: str


@dataclass(frozen=True, slots=True)
class BindingDecisionDraftRequest:
    """One pure composer request; never carries outcome or reason codes."""

    decided_at: str
    nonce: str
    causal_parent_decision_ids: tuple[str, ...] = ()
    supersedes_binding_decision_id: str | None = None
    supersedes_binding_decision_digest: str | None = None


def _parse_canonical_utc(value: str) -> datetime:
    if not isinstance(value, str):
        raise BindingInputError("canonical UTC time is malformed")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as error:
        raise BindingInputError(
            "canonical UTC time is malformed"
        ) from error
    return parsed.replace(tzinfo=timezone.utc)


def binding_decision_signing_bytes(
    value: BindingDecisionDraft | BindingDecision,
) -> bytes:
    """Return the canonical v0.4 bytes signed by every decision verifier.

    The payload excludes digest and verifier signatures, matching the
    ``BindingDecision`` digest computation byte-for-byte.
    """

    if isinstance(value, BindingDecision):
        payload = value.model_dump(
            mode="json", exclude={"digest", "verifier_signatures"}
        )
    elif isinstance(value, BindingDecisionDraft):
        payload = {
            "schema_version": _BINDING_DECISION_SCHEMA,
            **value.model_dump(mode="json"),
        }
    else:
        raise BindingInputError("binding decision payload type is invalid")
    return canonical_bytes("binding-decision", payload, version="0.4")


def _binding_decision_id(
    *,
    work_order_digest: str,
    judgment_commitment_digest: str,
    action_binding_manifest_digest: str,
    verification_decision_digest: str,
    action_receipt_ids: tuple[str, ...],
    adapter_replay_digest: str,
    decided_at: str,
    nonce: str,
) -> str:
    return hashlib.sha256(
        rfc8785.dumps(
            {
                "domain": _BINDING_DECISION_ID_DOMAIN,
                "work_order_digest": work_order_digest,
                "judgment_commitment_digest": judgment_commitment_digest,
                "action_binding_manifest_digest": (
                    action_binding_manifest_digest
                ),
                "verification_decision_digest": verification_decision_digest,
                "action_receipt_ids": list(action_receipt_ids),
                "adapter_replay_digest": adapter_replay_digest,
                "decided_at": decided_at,
                "nonce": nonce,
            }
        )
    ).hexdigest()


def _verify_replay_reason_codes(
    outcome: str,
    reason_codes: tuple[str, ...],
) -> bool:
    allowed = (
        _UNBOUND_BINDING_REASONS
        if outcome == "UNBOUND"
        else _INDETERMINATE_BINDING_REASONS
    )
    return all(code in allowed for code in reason_codes)


def compose_binding_decision(
    *,
    judgment: JudgmentCommitment,
    manifest: ActionBindingManifest,
    verification: VerificationDecisionV03,
    receipts: tuple[ActionReceiptEnvelope, ...],
    replay: BindingReplayView,
    checkpoint: AuthorityCheckpoint | None,
    request: BindingDecisionDraftRequest,
) -> BindingDecisionDraft:
    """Compose one BindingDecision draft, recomputing every reference.

    The composer never trusts caller-provided reason codes or digests; it
    derives the outcome from the signed inputs and fails closed toward
    INDETERMINATE when evidence classification is inconsistent.
    """

    if not isinstance(request, BindingDecisionDraftRequest):
        raise BindingInputError("binding decision request is required")
    if not isinstance(replay, BindingReplayView) or not isinstance(
        replay.reason_codes, tuple
    ):
        raise BindingInputError("binding replay view is required")

    def draft(
        decision: str,
        reason_codes: tuple[str, ...],
        *,
        authority_status: str = "not_required",
        authority_checkpoint_digest: str | None = None,
    ) -> BindingDecisionDraft:
        action_receipt_ids = tuple(
            sorted(receipt.receipt_id for receipt in receipts)
        )
        by_id = {receipt.receipt_id: receipt.digest for receipt in receipts}
        action_receipt_digests = tuple(
            by_id[receipt_id] for receipt_id in action_receipt_ids
        )
        return BindingDecisionDraft(
            binding_decision_id=_binding_decision_id(
                work_order_digest=manifest.work_order_digest,
                judgment_commitment_digest=judgment.digest,
                action_binding_manifest_digest=manifest.digest,
                verification_decision_digest=verification.digest,
                action_receipt_ids=action_receipt_ids,
                adapter_replay_digest=replay.replay_digest,
                decided_at=request.decided_at,
                nonce=request.nonce,
            ),
            work_order_digest=manifest.work_order_digest,
            judgment_commitment_digest=judgment.digest,
            action_binding_manifest_digest=manifest.digest,
            verification_decision_id=verification.decision_id,
            verification_decision_digest=verification.digest,
            action_receipt_ids=action_receipt_ids,
            action_receipt_digests=action_receipt_digests,
            adapter_replay_digest=replay.replay_digest,
            authority_checkpoint_digest=authority_checkpoint_digest,
            decision=decision,
            reason_codes=reason_codes,
            authority_status=authority_status,
            causal_parent_decision_ids=request.causal_parent_decision_ids,
            supersedes_binding_decision_id=(
                request.supersedes_binding_decision_id
            ),
            supersedes_binding_decision_digest=(
                request.supersedes_binding_decision_digest
            ),
            decided_at=request.decided_at,
            nonce=request.nonce,
        )

    # Verification must be current, VERIFIED and bound to this manifest.
    if (
        verification.decision != "VERIFIED"
        or verification.work_order_digest != manifest.work_order_digest
    ):
        return draft("INDETERMINATE", ("VERIFICATION_NOT_CURRENT",))
    if verification.profile_digest != manifest.adapter_profile_digest:
        return draft("UNBOUND", ("ADAPTER_PROFILE_DIGEST_MISMATCH",))

    # Judgment must be the exact one bound by the manifest.
    if (
        manifest.judgment_commitment_id != judgment.commitment_id
        or manifest.judgment_commitment_digest != judgment.digest
    ):
        return draft("UNBOUND", ("JUDGMENT_DIGEST_MISMATCH",))
    decided_at = _parse_canonical_utc(request.decided_at)
    if not judgment.valid_from <= decided_at < judgment.expires_at:
        return draft("INDETERMINATE", ("VERIFICATION_NOT_CURRENT",))
    if not manifest.created_at <= decided_at < manifest.expires_at:
        return draft("INDETERMINATE", ("VERIFICATION_NOT_CURRENT",))

    # Receipts must exist and every one must be a v0.4 bound execution.
    if not receipts:
        # The frozen BindingDecision model requires non-empty action receipt
        # references; an empty receipt set cannot form a decision object at
        # all, so fail closed instead of fabricating evidence.
        raise BindingInputError(
            "binding decision requires at least one execution receipt"
        )
    for receipt in receipts:
        if not isinstance(receipt, (ToolCallReceiptV04, RollbackReceiptV04)):
            return draft("INDETERMINATE", ("UNSIGNED_METADATA_REFERENCE",))
        claim = receipt.nested_claim
        if not isinstance(claim, AgentRequestV04):
            return draft("INDETERMINATE", ("UNSIGNED_METADATA_REFERENCE",))
        if (
            claim.action_binding_manifest_id != manifest.binding_manifest_id
            or claim.action_binding_manifest_digest != manifest.digest
        ):
            return draft("UNBOUND", ("ACTION_DIGEST_MISMATCH",))

    # Replay verdict, with closed-code consistency enforced.
    if replay.outcome == "UNBOUND":
        if _verify_replay_reason_codes("UNBOUND", replay.reason_codes):
            return draft("UNBOUND", replay.reason_codes)
        return draft("INDETERMINATE", ("EVIDENCE_INCOMPLETE",))
    if replay.outcome == "INDETERMINATE":
        if _verify_replay_reason_codes(
            "INDETERMINATE", replay.reason_codes
        ):
            return draft("INDETERMINATE", replay.reason_codes)
        return draft("INDETERMINATE", ("EVIDENCE_INCOMPLETE",))
    if replay.outcome != "BOUND" or replay.reason_codes:
        return draft("INDETERMINATE", ("REPLAY_UNAVAILABLE",))

    # Authority: high-risk requires a current checkpoint (Task 10 expands
    # the chain validation; here we fail closed when it is absent).
    if verification.assurance_level == "high_risk":
        if checkpoint is None:
            return draft(
                "INDETERMINATE",
                ("AUTHORITY_CHECKPOINT_MISSING",),
                authority_status="missing",
            )
        return draft(
            "BOUND",
            (),
            authority_status="current",
            authority_checkpoint_digest=checkpoint.digest,
        )
    if checkpoint is not None:
        return draft(
            "BOUND",
            (),
            authority_status="current",
            authority_checkpoint_digest=checkpoint.digest,
        )
    return draft("BOUND", (), authority_status="not_required")


def verify_binding_decision(
    decision: BindingDecision,
    *,
    work_order: WorkOrder,
    public_keys: Mapping[str, Ed25519PublicKey],
    expected_signatures: int,
) -> bool:
    """Verify a BindingDecision against the external verifier trust map.

    Receipts never carry their own public keys; every verifier key must
    exist in the external trust map and match a Verifier-role key binding.
    Standard decisions require one signature; high-risk require two
    independent verifier signatures.
    """

    if not isinstance(decision, BindingDecision):
        return False
    if expected_signatures not in {1, 2}:
        return False
    if len(decision.verifier_signatures) != expected_signatures:
        return False
    if not verify_work_order_identity_bindings(work_order):
        return False
    verifier_bindings = [
        binding
        for binding in work_order.key_bindings
        if binding.role == "Verifier"
    ]
    if not verifier_bindings:
        return False
    try:
        encoded = binding_decision_signing_bytes(decision)
    except BindingInputError:
        return False
    for signature in decision.verifier_signatures:
        if signature.signature_alg != "Ed25519":
            return False
        public_key = public_keys.get(signature.verifier_key_id)
        if public_key is None:
            return False
        matched_binding = None
        for binding in verifier_bindings:
            try:
                if decode_and_verify_key_binding(binding) == public_key:
                    matched_binding = binding
                    break
            except (ValueError, TypeError):
                continue
        if matched_binding is None:
            return False
        try:
            raw_signature = base64.urlsafe_b64decode(
                signature.signature + "=" * (-len(signature.signature) % 4)
            )
            public_key.verify(raw_signature, encoded)
        except Exception:
            return False
    return True


__all__ = [
    "BindingInputError",
    "BindingValidationError",
    "CanonicalAdapterProfile",
    "DeterministicConstraintProjection",
    "canonical_test_profile_digest",
    "constraint_projection_digest",
    "projection_from_adapter_profile",
    "BindingDecisionDraftRequest",
    "binding_decision_signing_bytes",
    "compose_binding_decision",
    "validate_action_binding_manifest",
    "verify_binding_decision",
]
