"""Human agency profile v0.1 protocol objects.

This module adds a signed sibling profile that expresses, for one WorkOrder,
which actions the human delegates to the Agent and which decisions stay
reserved for a human decision. It does not modify the frozen WorkOrder v0.1,
CapabilityGrant, or any existing signed byte. The models are closed and
immutable; ids derive from canonical content, and signatures bind to the
WorkOrder role/subject/key the object declares.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal, Mapping, Sequence

import rfc8785
from pydantic import model_validator

from openworkproof.models import (
    CanonicalUTCTime,
    Digest64,
    Identifier,
    KeyBinding,
    ProtocolModel,
    SignedProtocolModel,
    WorkOrder,
)
from openworkproof.signing import (
    decode_and_verify_key_binding,
    verify_payload,
)


__all__ = [
    "AGENCY_PROFILE_BINDING_INVALID",
    "AGENCY_PROFILE_EXPIRED",
    "AGENCY_PROFILE_HISTORY_INVALID",
    "AGENCY_PROFILE_REQUIRED",
    "AgencyAppealV01",
    "AgencyProfileHistory",
    "AgencyProfileHistoryError",
    "AgencyProfileTransitionV01",
    "DelegatedActionV01",
    "EscalationConditionV01",
    "HumanAgencyProfileV01",
    "ReservedDecisionV01",
    "ResolvedAgencyProfile",
    "RevocationAndAppealPolicyV01",
    "agency_appeal_id",
    "agency_profile_transition_id",
    "delegated_action_id",
    "human_agency_profile_id",
    "reserved_decision_id",
    "resolve_current_human_agency_profile",
    "verify_agency_appeal",
    "verify_agency_profile_transition",
    "verify_human_agency_profile",
]

AGENCY_PROFILE_REQUIRED = "AGENCY_PROFILE_REQUIRED"
AGENCY_PROFILE_HISTORY_INVALID = "AGENCY_PROFILE_HISTORY_INVALID"
AGENCY_PROFILE_EXPIRED = "AGENCY_PROFILE_EXPIRED"
AGENCY_PROFILE_BINDING_INVALID = "AGENCY_PROFILE_BINDING_INVALID"


class AgencyProfileHistoryError(RuntimeError):
    """The signed profile history cannot resolve to one current profile."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code

_AgencyToolName = Literal[
    "owp.activate_root_grant",
    "owp.apply_patch",
    "owp.compose_proof",
    "owp.create_pr_proposal",
    "owp.delegate_grant",
    "owp.repo_read",
    "owp.request_acceptance",
    "owp.request_pr_proposal",
    "owp.revoke_grant",
    "owp.rollback_patch",
    "owp.run_tests",
    "owp.start_retry",
]

_APPEAL_ROLES = ("Developer", "Manager", "Verifier")

_ID_ENVELOPE_FIELDS = (
    "digest",
    "signature_alg",
    "signer_key_id",
    "signature",
)


def _jcs_digest(value: Any) -> str:
    return hashlib.sha256(rfc8785.dumps(value)).hexdigest()


def _is_utf8_sorted_unique(values: tuple[str, ...]) -> bool:
    return list(values) == sorted(
        set(values), key=lambda item: item.encode("utf-8")
    )


def delegated_action_id(value: Mapping[str, Any]) -> str:
    """Recompute the content-addressed id for one delegated action."""

    source = dict(value)
    source.pop("action_id", None)
    return _jcs_digest(
        {
            "domain": "openworkproof/delegated-action/v0.1",
            "payload": source,
        }
    )


def reserved_decision_id(value: Mapping[str, Any]) -> str:
    """Recompute the content-addressed id for one reserved decision.

    The domain is frozen as ``openworkproof/reserved-decision/v0.1``.
    """

    source = dict(value)
    source.pop("decision_id", None)
    return _jcs_digest(
        {
            "domain": "openworkproof/reserved-decision/v0.1",
            "payload": source,
        }
    )


def _signed_object_id(value: Mapping[str, Any], own_id: str, domain: str) -> str:
    source = dict(value)
    source.pop(own_id, None)
    for field in _ID_ENVELOPE_FIELDS:
        source.pop(field, None)
    return _jcs_digest(
        {
            "domain": f"openworkproof/{domain}/v0.1",
            "payload": source,
        }
    )


def human_agency_profile_id(value: Mapping[str, Any]) -> str:
    return _signed_object_id(
        value, "profile_id", "human-agency-profile-id"
    )


def agency_profile_transition_id(value: Mapping[str, Any]) -> str:
    return _signed_object_id(
        value, "transition_id", "agency-profile-transition-id"
    )


def agency_appeal_id(value: Mapping[str, Any]) -> str:
    return _signed_object_id(value, "appeal_id", "agency-appeal-id")


class DelegatedActionV01(ProtocolModel):
    action_id: Digest64
    tool_name: _AgencyToolName
    autonomy: Literal["delegated"]

    @model_validator(mode="after")
    def _validate_action_id(self) -> DelegatedActionV01:
        if self.action_id != delegated_action_id(self.model_dump(mode="json")):
            raise ValueError(
                "delegated action_id does not match canonical content"
            )
        return self


class ReservedDecisionV01(ProtocolModel):
    decision_id: Digest64
    decision_kind: Literal[
        "scope_or_criteria_change",
        "external_publication",
        "external_communication",
        "acceptance",
        "payment_or_settlement",
    ]
    blocked_tools: tuple[_AgencyToolName, ...]
    required_role: Literal["Acceptor"]

    @model_validator(mode="after")
    def _validate_decision(self) -> ReservedDecisionV01:
        if not _is_utf8_sorted_unique(self.blocked_tools):
            raise ValueError(
                "reserved decision blocked_tools must be UTF-8 sorted and unique"
            )
        if self.decision_id != reserved_decision_id(self.model_dump(mode="json")):
            raise ValueError(
                "reserved decision_id does not match canonical content"
            )
        return self


class EscalationConditionV01(ProtocolModel):
    condition_code: Literal[
        "reserved_decision_requested",
        "scope_change_requested",
        "evidence_incomplete",
        "verifier_conflict",
        "authorization_revoked",
        "deadline_or_quota_exceeded",
    ]


class RevocationAndAppealPolicyV01(ProtocolModel):
    revocation_mode: Literal["acceptor_signed_transition"]
    appeal_mode: Literal["signed_request_then_acceptor_decision"]
    appeal_roles: tuple[Literal["Developer", "Manager", "Verifier"], ...]

    @model_validator(mode="after")
    def _validate_policy(self) -> RevocationAndAppealPolicyV01:
        if self.appeal_roles != _APPEAL_ROLES:
            raise ValueError(
                "appeal_roles must be the fixed Developer/Manager/Verifier order"
            )
        return self


class HumanAgencyProfileV01(SignedProtocolModel):
    _signed_domain = "human-agency-profile"

    schema_version: Literal["openworkproof-human-agency-profile/0.1"]
    profile_id: Digest64
    work_order_digest: Digest64
    delegated_actions: tuple[DelegatedActionV01, ...]
    reserved_decisions: tuple[ReservedDecisionV01, ...]
    escalation_conditions: tuple[EscalationConditionV01, ...]
    revocation_and_appeal: RevocationAndAppealPolicyV01
    valid_from: CanonicalUTCTime
    expires_at: CanonicalUTCTime
    issued_at: CanonicalUTCTime
    nonce: Digest64

    @model_validator(mode="after")
    def _validate_profile(self) -> HumanAgencyProfileV01:
        if self.profile_id != human_agency_profile_id(
            self.model_dump(mode="json")
        ):
            raise ValueError("profile_id does not match canonical content")
        delegated_tools = tuple(
            action.tool_name for action in self.delegated_actions
        )
        if not _is_utf8_sorted_unique(delegated_tools):
            raise ValueError(
                "delegated_actions must be tool_name sorted and unique"
            )
        reserved_ids = tuple(
            decision.decision_id for decision in self.reserved_decisions
        )
        if len(self.reserved_decisions) > 5:
            raise ValueError("reserved_decisions must contain at most 5 entries")
        if not _is_utf8_sorted_unique(reserved_ids):
            raise ValueError(
                "reserved_decisions must be decision_id sorted and unique"
            )
        reserved_kinds = tuple(
            decision.decision_kind for decision in self.reserved_decisions
        )
        if len(set(reserved_kinds)) != len(reserved_kinds):
            raise ValueError(
                "reserved_decisions decision_kind values must be unique"
            )
        escalation_codes = tuple(
            condition.condition_code for condition in self.escalation_conditions
        )
        if not _is_utf8_sorted_unique(escalation_codes):
            raise ValueError(
                "escalation_conditions must be condition_code sorted and unique"
            )
        if not self.delegated_actions and not self.reserved_decisions:
            raise ValueError(
                "profile must contain at least one delegated action or reserved decision"
            )
        blocked = {
            tool_name
            for decision in self.reserved_decisions
            for tool_name in decision.blocked_tools
        }
        if blocked & set(delegated_tools):
            raise ValueError("delegated and reserved tools must be disjoint")
        if not self.issued_at <= self.valid_from < self.expires_at:
            raise ValueError("profile times are not ordered")
        return self


class AgencyProfileTransitionV01(SignedProtocolModel):
    _signed_domain = "agency-profile-transition"

    schema_version: Literal["openworkproof-agency-profile-transition/0.1"]
    transition_id: Digest64
    work_order_digest: Digest64
    target_profile_id: Digest64
    target_profile_digest: Digest64
    transition: Literal["revoked", "superseded"]
    replacement_profile_id: Digest64 | None
    replacement_profile_digest: Digest64 | None
    reason_code: Literal[
        "human_withdrawal", "scope_changed", "risk_changed", "correction"
    ]
    transitioned_at: CanonicalUTCTime
    nonce: Digest64

    @model_validator(mode="after")
    def _validate_transition(self) -> AgencyProfileTransitionV01:
        if self.transition_id != agency_profile_transition_id(
            self.model_dump(mode="json")
        ):
            raise ValueError("transition_id does not match canonical content")
        if self.transition == "revoked":
            if (
                self.replacement_profile_id is not None
                or self.replacement_profile_digest is not None
            ):
                raise ValueError("revoked transition must not name a replacement")
        elif (
            self.replacement_profile_id is None
            or self.replacement_profile_digest is None
            or self.replacement_profile_id == self.target_profile_id
        ):
            raise ValueError(
                "superseded transition requires a different replacement profile"
            )
        return self


class AgencyAppealV01(SignedProtocolModel):
    _signed_domain = "agency-appeal"

    schema_version: Literal["openworkproof-agency-appeal/0.1"]
    appeal_id: Digest64
    work_order_digest: Digest64
    profile_id: Digest64
    profile_digest: Digest64
    appellant_role: Literal["Manager", "Developer", "Verifier"]
    appellant_subject_id: Identifier
    requested_change_digest: Digest64
    reason_code: Literal[
        "task_blocked", "scope_mismatch", "evidence_available",
        "verifier_disagreement",
    ]
    created_at: CanonicalUTCTime
    nonce: Digest64

    @model_validator(mode="after")
    def _validate_appeal(self) -> AgencyAppealV01:
        if self.appeal_id != agency_appeal_id(self.model_dump(mode="json")):
            raise ValueError("appeal_id does not match canonical content")
        return self


def _acceptor_binding(work_order: WorkOrder) -> KeyBinding | None:
    if not isinstance(work_order, WorkOrder):
        return None
    matches = [
        binding for binding in work_order.key_bindings
        if binding.role == "Acceptor"
    ]
    if len(matches) != 1:
        return None
    return matches[0]


def verify_human_agency_profile(
    profile: HumanAgencyProfileV01,
    work_order: WorkOrder,
) -> bool:
    """Verify a profile's WorkOrder binding, tool subset, and Acceptor signature."""

    if not isinstance(profile, HumanAgencyProfileV01) or not isinstance(
        work_order, WorkOrder
    ):
        return False
    binding = _acceptor_binding(work_order)
    if binding is None or profile.signer_key_id != binding.key_id:
        return False
    if profile.work_order_digest != work_order.digest:
        return False
    if profile.expires_at > work_order.deadline:
        return False
    allowed_tools = set(work_order.allowed_tools)
    if not {action.tool_name for action in profile.delegated_actions}.issubset(
        allowed_tools
    ):
        return False
    if not {
        tool_name
        for decision in profile.reserved_decisions
        for tool_name in decision.blocked_tools
    }.issubset(allowed_tools):
        return False
    try:
        public_key = decode_and_verify_key_binding(binding)
    except (ValueError, TypeError):
        return False
    return verify_payload(
        "human-agency-profile",
        profile.model_dump(mode="json"),
        public_key,
    )


def verify_agency_profile_transition(
    transition: AgencyProfileTransitionV01,
    work_order: WorkOrder,
) -> bool:
    """Verify a profile transition's WorkOrder binding and Acceptor signature."""

    if not isinstance(transition, AgencyProfileTransitionV01) or not isinstance(
        work_order, WorkOrder
    ):
        return False
    binding = _acceptor_binding(work_order)
    if binding is None or transition.signer_key_id != binding.key_id:
        return False
    if transition.work_order_digest != work_order.digest:
        return False
    try:
        public_key = decode_and_verify_key_binding(binding)
    except (ValueError, TypeError):
        return False
    return verify_payload(
        "agency-profile-transition",
        transition.model_dump(mode="json"),
        public_key,
    )


def verify_agency_appeal(
    appeal: AgencyAppealV01,
    work_order: WorkOrder,
) -> bool:
    """Verify an appeal's role/subject/key consistency and signature."""

    if not isinstance(appeal, AgencyAppealV01) or not isinstance(
        work_order, WorkOrder
    ):
        return False
    if appeal.work_order_digest != work_order.digest:
        return False
    matches = [
        binding
        for binding in work_order.key_bindings
        if (
            binding.role == appeal.appellant_role
            and binding.subject_id == appeal.appellant_subject_id
            and binding.key_id == appeal.signer_key_id
        )
    ]
    if len(matches) != 1:
        return False
    try:
        public_key = decode_and_verify_key_binding(matches[0])
    except (ValueError, TypeError):
        return False
    return verify_payload(
        "agency-appeal",
        appeal.model_dump(mode="json"),
        public_key,
    )


@dataclass(frozen=True, slots=True)
class ResolvedAgencyProfile:
    status: Literal["active", "revoked"]
    current_profile: HumanAgencyProfileV01 | None
    ordered_profile_ids: tuple[str, ...]
    ordered_transition_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class AgencyProfileHistory:
    profiles: tuple[HumanAgencyProfileV01, ...]
    transitions: tuple[AgencyProfileTransitionV01, ...]

    def __post_init__(self) -> None:
        if type(self.profiles) is not tuple or type(self.transitions) is not tuple:
            raise AgencyProfileHistoryError(
                AGENCY_PROFILE_HISTORY_INVALID,
                "agency profile history collections must be exact tuples",
            )
        if any(
            not isinstance(profile, HumanAgencyProfileV01)
            for profile in self.profiles
        ) or any(
            not isinstance(transition, AgencyProfileTransitionV01)
            for transition in self.transitions
        ):
            raise AgencyProfileHistoryError(
                AGENCY_PROFILE_HISTORY_INVALID,
                "agency profile history contains a malformed entry",
            )


def resolve_current_human_agency_profile(
    work_order: WorkOrder,
    profiles: Sequence[HumanAgencyProfileV01],
    transitions: Sequence[AgencyProfileTransitionV01],
    *,
    now: datetime,
) -> ResolvedAgencyProfile:
    """Resolve the unique current profile from a signed append-only history.

    The resolution is decided by the signed graph only: superseded edges are
    followed to a unique terminal, revoked edges close the chain, and any
    fork, cycle, missing replacement, digest mismatch, time reversal, or
    multiple genesis fails closed. Timestamps never select a "latest" profile.
    """

    if not isinstance(work_order, WorkOrder):
        raise AgencyProfileHistoryError(
            AGENCY_PROFILE_HISTORY_INVALID, "work order is malformed"
        )
    profile_tuple = tuple(profiles)
    transition_tuple = tuple(transitions)
    if any(
        not isinstance(profile, HumanAgencyProfileV01)
        for profile in profile_tuple
    ) or any(
        not isinstance(transition, AgencyProfileTransitionV01)
        for transition in transition_tuple
    ):
        raise AgencyProfileHistoryError(
            AGENCY_PROFILE_HISTORY_INVALID, "agency profile history is malformed"
        )

    if not profile_tuple:
        raise AgencyProfileHistoryError(
            AGENCY_PROFILE_REQUIRED, "no human agency profile is available"
        )

    profiles_by_id: dict[str, HumanAgencyProfileV01] = {}
    for profile in profile_tuple:
        if profile.work_order_digest != work_order.digest:
            raise AgencyProfileHistoryError(
                AGENCY_PROFILE_BINDING_INVALID,
                "agency profile is bound to a different WorkOrder",
            )
        if not verify_human_agency_profile(profile, work_order):
            raise AgencyProfileHistoryError(
                AGENCY_PROFILE_HISTORY_INVALID,
                "agency profile signature or binding is invalid",
            )
        if profile.profile_id in profiles_by_id:
            raise AgencyProfileHistoryError(
                AGENCY_PROFILE_HISTORY_INVALID,
                "duplicate agency profile id",
            )
        profiles_by_id[profile.profile_id] = profile

    outgoing: dict[str, AgencyProfileTransitionV01] = {}
    replacement_targets: set[str] = set()
    for transition in transition_tuple:
        if transition.work_order_digest != work_order.digest:
            raise AgencyProfileHistoryError(
                AGENCY_PROFILE_BINDING_INVALID,
                "agency profile transition is bound to a different WorkOrder",
            )
        if not verify_agency_profile_transition(transition, work_order):
            raise AgencyProfileHistoryError(
                AGENCY_PROFILE_HISTORY_INVALID,
                "agency profile transition signature or binding is invalid",
            )
        target = profiles_by_id.get(transition.target_profile_id)
        if target is None:
            raise AgencyProfileHistoryError(
                AGENCY_PROFILE_HISTORY_INVALID,
                "transition targets an unknown profile",
            )
        if transition.target_profile_digest != target.digest:
            raise AgencyProfileHistoryError(
                AGENCY_PROFILE_HISTORY_INVALID,
                "transition target digest does not match profile",
            )
        if transition.transitioned_at < target.issued_at:
            raise AgencyProfileHistoryError(
                AGENCY_PROFILE_HISTORY_INVALID,
                "transition precedes the target profile issuance",
            )
        if transition.target_profile_id in outgoing:
            raise AgencyProfileHistoryError(
                AGENCY_PROFILE_HISTORY_INVALID,
                "profile has multiple outgoing transitions",
            )
        outgoing[transition.target_profile_id] = transition
        if transition.transition == "superseded":
            replacement = profiles_by_id.get(transition.replacement_profile_id)
            if replacement is None:
                raise AgencyProfileHistoryError(
                    AGENCY_PROFILE_HISTORY_INVALID,
                    "superseded transition names a missing replacement",
                )
            if transition.replacement_profile_digest != replacement.digest:
                raise AgencyProfileHistoryError(
                    AGENCY_PROFILE_HISTORY_INVALID,
                    "superseded transition replacement digest does not match",
                )
            replacement_targets.add(transition.replacement_profile_id)

    genesis = [
        profile
        for profile in profile_tuple
        if profile.profile_id not in replacement_targets
    ]
    if len(genesis) != 1:
        raise AgencyProfileHistoryError(
            AGENCY_PROFILE_HISTORY_INVALID,
            "profile history must contain exactly one genesis profile",
        )

    ordered_profile_ids: list[str] = []
    ordered_transition_ids: list[str] = []
    current = genesis[0]
    visited: set[str] = set()
    revoked_terminal = False
    while True:
        if current.profile_id in visited:
            raise AgencyProfileHistoryError(
                AGENCY_PROFILE_HISTORY_INVALID,
                "profile history contains a supersession cycle",
            )
        visited.add(current.profile_id)
        ordered_profile_ids.append(current.profile_id)
        transition = outgoing.get(current.profile_id)
        if transition is None:
            break
        ordered_transition_ids.append(transition.transition_id)
        if transition.transition == "revoked":
            revoked_terminal = True
            break
        current = profiles_by_id[transition.replacement_profile_id]

    supplied_profile_ids = {profile.profile_id for profile in profile_tuple}
    supplied_transition_ids = {
        transition.transition_id for transition in transition_tuple
    }
    if visited != supplied_profile_ids:
        raise AgencyProfileHistoryError(
            AGENCY_PROFILE_HISTORY_INVALID,
            "profile history contains a disconnected profile",
        )
    if set(ordered_transition_ids) != supplied_transition_ids:
        raise AgencyProfileHistoryError(
            AGENCY_PROFILE_HISTORY_INVALID,
            "profile history contains an unreachable transition",
        )

    if revoked_terminal:
        return ResolvedAgencyProfile(
            status="revoked",
            current_profile=None,
            ordered_profile_ids=tuple(ordered_profile_ids),
            ordered_transition_ids=tuple(ordered_transition_ids),
        )

    if not current.valid_from <= now <= current.expires_at:
        raise AgencyProfileHistoryError(
            AGENCY_PROFILE_EXPIRED,
            "agency profile is outside its validity window",
        )
    return ResolvedAgencyProfile(
        status="active",
        current_profile=current,
        ordered_profile_ids=tuple(ordered_profile_ids),
        ordered_transition_ids=tuple(ordered_transition_ids),
    )
