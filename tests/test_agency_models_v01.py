from __future__ import annotations

import base64
import copy
from dataclasses import dataclass
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from conftest import EPHEMERAL_ROLES, SHA256_A, SHA256_B, SHA256_C, SHA256_D, SHA256_E
from openworkproof.agency import (
    AgencyAppealV01,
    AgencyProfileTransitionV01,
    DelegatedActionV01,
    EscalationConditionV01,
    HumanAgencyProfileV01,
    ReservedDecisionV01,
    RevocationAndAppealPolicyV01,
    agency_appeal_id,
    agency_profile_transition_id,
    delegated_action_id,
    human_agency_profile_id,
    reserved_decision_id,
    verify_agency_appeal,
    verify_agency_profile_transition,
    verify_human_agency_profile,
)
from openworkproof.models import WorkOrder
from openworkproof.signing import key_id, sign_payload


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


@dataclass(frozen=True)
class _AgencyCase:
    work_order: WorkOrder
    keys: dict[str, tuple[Ed25519PrivateKey, dict[str, str]]]


@pytest.fixture
def agency_case(
    signed_work_order: WorkOrder,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
) -> _AgencyCase:
    return _AgencyCase(
        work_order=signed_work_order,
        keys=copy.deepcopy(ephemeral_role_keys),
    )


def _delegated_action_dict(tool_name: str) -> dict[str, Any]:
    body = {"tool_name": tool_name, "autonomy": "delegated"}
    return {"action_id": delegated_action_id(body), **body}


def _reserved_decision_dict(
    kind: str, blocked_tools: tuple[str, ...]
) -> dict[str, Any]:
    body = {
        "decision_kind": kind,
        "blocked_tools": list(blocked_tools),
        "required_role": "Acceptor",
    }
    return {"decision_id": reserved_decision_id(body), **body}


def _profile_payload(
    case: _AgencyCase,
    *,
    delegated: tuple[str, ...] = (),
    reserved: tuple[tuple[str, tuple[str, ...]], ...] = (),
    escalation: tuple[str, ...] = ("reserved_decision_requested",),
) -> dict[str, Any]:
    payload = {
        "schema_version": "openworkproof-human-agency-profile/0.1",
        "work_order_digest": case.work_order.digest,
        "delegated_actions": [
            _delegated_action_dict(tool) for tool in delegated
        ],
        "reserved_decisions": [
            _reserved_decision_dict(kind, blocked) for kind, blocked in reserved
        ],
        "escalation_conditions": [
            {"condition_code": code} for code in escalation
        ],
        "revocation_and_appeal": {
            "revocation_mode": "acceptor_signed_transition",
            "appeal_mode": "signed_request_then_acceptor_decision",
            "appeal_roles": ["Developer", "Manager", "Verifier"],
        },
        "valid_from": "2026-01-01T00:00:01Z",
        "expires_at": "2026-01-01T23:59:59Z",
        "issued_at": "2026-01-01T00:00:00Z",
        "nonce": SHA256_C,
    }
    payload["profile_id"] = human_agency_profile_id(payload)
    return payload


def _signed_profile(
    case: _AgencyCase,
    *,
    signer: str = "Acceptor",
    **kwargs: Any,
) -> HumanAgencyProfileV01:
    payload = _profile_payload(case, **kwargs)
    return HumanAgencyProfileV01.model_validate(
        sign_payload("human-agency-profile", payload, case.keys[signer][0])
    )


def _transition_payload(
    case: _AgencyCase,
    *,
    target_profile_id: str,
    target_profile_digest: str,
    transition: str = "revoked",
    replacement_profile_id: str | None = None,
    replacement_profile_digest: str | None = None,
) -> dict[str, Any]:
    payload = {
        "schema_version": "openworkproof-agency-profile-transition/0.1",
        "work_order_digest": case.work_order.digest,
        "target_profile_id": target_profile_id,
        "target_profile_digest": target_profile_digest,
        "transition": transition,
        "replacement_profile_id": replacement_profile_id,
        "replacement_profile_digest": replacement_profile_digest,
        "reason_code": "human_withdrawal",
        "transitioned_at": "2026-01-01T01:00:00Z",
        "nonce": SHA256_D,
    }
    payload["transition_id"] = agency_profile_transition_id(payload)
    return payload


def _signed_transition(
    case: _AgencyCase,
    *,
    signer: str = "Acceptor",
    **kwargs: Any,
) -> AgencyProfileTransitionV01:
    payload = _transition_payload(case, **kwargs)
    return AgencyProfileTransitionV01.model_validate(
        sign_payload("agency-profile-transition", payload, case.keys[signer][0])
    )


def _appeal_payload(
    case: _AgencyCase,
    *,
    role: str,
    profile_id: str,
    profile_digest: str,
) -> dict[str, Any]:
    binding = case.keys[role][1]
    payload = {
        "schema_version": "openworkproof-agency-appeal/0.1",
        "work_order_digest": case.work_order.digest,
        "profile_id": profile_id,
        "profile_digest": profile_digest,
        "appellant_role": role,
        "appellant_subject_id": binding["subject_id"],
        "requested_change_digest": SHA256_E,
        "reason_code": "task_blocked",
        "created_at": "2026-01-01T01:05:00Z",
        "nonce": SHA256_A,
    }
    payload["appeal_id"] = agency_appeal_id(payload)
    return payload


def _signed_appeal(
    case: _AgencyCase,
    *,
    role: str = "Manager",
    signing_role: str | None = None,
    **kwargs: Any,
) -> AgencyAppealV01:
    payload = _appeal_payload(case, role=role, **kwargs)
    return AgencyAppealV01.model_validate(
        sign_payload(
            "agency-appeal",
            payload,
            case.keys[signing_role or role][0],
        )
    )


# --- Nested object closed JSON and id/digest recomputation ---


def test_delegated_action_recomputes_action_id() -> None:
    action = DelegatedActionV01.model_validate(
        _delegated_action_dict("owp.repo_read")
    )
    assert action.action_id == delegated_action_id(
        {"tool_name": "owp.repo_read", "autonomy": "delegated"}
    )
    tampered = {
        "action_id": action.action_id,
        "tool_name": "owp.apply_patch",
        "autonomy": "delegated",
    }
    with pytest.raises(ValidationError):
        DelegatedActionV01.model_validate(tampered)


def test_reserved_decision_uses_frozen_domain() -> None:
    decision = ReservedDecisionV01.model_validate(
        _reserved_decision_dict("scope_or_criteria_change", ("owp.apply_patch",))
    )
    assert decision.decision_id == reserved_decision_id(
        {
            "decision_kind": "scope_or_criteria_change",
            "blocked_tools": ["owp.apply_patch"],
            "required_role": "Acceptor",
        }
    )
    assert decision.blocked_tools == ("owp.apply_patch",)
    assert decision.required_role == "Acceptor"


def test_reserved_decision_blocks_unsorted_tools() -> None:
    body = {
        "decision_kind": "scope_or_criteria_change",
        "blocked_tools": ["owp.repo_read", "owp.apply_patch"],
        "required_role": "Acceptor",
    }
    with pytest.raises(ValidationError):
        ReservedDecisionV01.model_validate(
            {"decision_id": reserved_decision_id(body), **body}
        )


def test_reserved_decision_blocks_duplicate_tools() -> None:
    body = {
        "decision_kind": "scope_or_criteria_change",
        "blocked_tools": ["owp.repo_read", "owp.repo_read"],
        "required_role": "Acceptor",
    }
    with pytest.raises(ValidationError):
        ReservedDecisionV01.model_validate(
            {"decision_id": reserved_decision_id(body), **body}
        )


def test_reserved_decision_accepts_empty_declarative_blocked_tools() -> None:
    decision = ReservedDecisionV01.model_validate(
        _reserved_decision_dict("payment_or_settlement", ())
    )
    assert decision.blocked_tools == ()


def test_escalation_condition_closed_enum() -> None:
    assert EscalationConditionV01.model_validate(
        {"condition_code": "reserved_decision_requested"}
    ).condition_code == "reserved_decision_requested"
    with pytest.raises(ValidationError):
        EscalationConditionV01.model_validate({"condition_code": "unknown"})


def test_revocation_policy_fixes_appeal_roles() -> None:
    policy = RevocationAndAppealPolicyV01.model_validate(
        {
            "revocation_mode": "acceptor_signed_transition",
            "appeal_mode": "signed_request_then_acceptor_decision",
            "appeal_roles": ["Developer", "Manager", "Verifier"],
        }
    )
    assert policy.appeal_roles == ("Developer", "Manager", "Verifier")
    with pytest.raises(ValidationError):
        RevocationAndAppealPolicyV01.model_validate(
            {
                "revocation_mode": "acceptor_signed_transition",
                "appeal_mode": "signed_request_then_acceptor_decision",
                "appeal_roles": ["Manager", "Verifier"],
            }
        )


# --- Profile invariants ---


def test_profile_requires_sorted_disjoint_tool_sets(agency_case: _AgencyCase) -> None:
    payload = _profile_payload(
        agency_case,
        delegated=("owp.repo_read",),
        reserved=(("scope_or_criteria_change", ("owp.repo_read",)),),
    )
    payload["profile_id"] = human_agency_profile_id(payload)
    with pytest.raises(ValidationError, match="disjoint"):
        HumanAgencyProfileV01.model_validate(
            sign_payload(
                "human-agency-profile",
                payload,
                agency_case.keys["Acceptor"][0],
            )
        )


def test_profile_rejects_both_action_sets_empty(agency_case: _AgencyCase) -> None:
    with pytest.raises(ValidationError):
        _signed_profile(agency_case, delegated=(), reserved=())


def test_profile_rejects_unsorted_delegated_actions(agency_case: _AgencyCase) -> None:
    payload = _profile_payload(
        agency_case, delegated=("owp.repo_read", "owp.apply_patch")
    )
    payload["profile_id"] = human_agency_profile_id(payload)
    with pytest.raises(ValidationError, match="sorted"):
        HumanAgencyProfileV01.model_validate(
            sign_payload(
                "human-agency-profile",
                payload,
                agency_case.keys["Acceptor"][0],
            )
        )


def test_profile_rejects_duplicate_reserved_decision_kind(
    agency_case: _AgencyCase,
) -> None:
    payload = _profile_payload(
        agency_case,
        delegated=("owp.repo_read",),
        reserved=(
            ("scope_or_criteria_change", ("owp.apply_patch",)),
            ("scope_or_criteria_change", ("owp.run_tests",)),
        ),
    )
    payload["reserved_decisions"].sort(
        key=lambda decision: decision["decision_id"].encode("utf-8")
    )
    payload["profile_id"] = human_agency_profile_id(payload)
    with pytest.raises(ValidationError, match="decision_kind.*unique"):
        HumanAgencyProfileV01.model_validate(
            sign_payload(
                "human-agency-profile",
                payload,
                agency_case.keys["Acceptor"][0],
            )
        )


def test_profile_rejects_more_than_five_reserved_decisions(
    agency_case: _AgencyCase,
) -> None:
    payload = _profile_payload(
        agency_case,
        delegated=("owp.repo_read",),
        reserved=(
            ("scope_or_criteria_change", ()),
            ("external_publication", ()),
            ("external_communication", ()),
            ("acceptance", ()),
            ("payment_or_settlement", ()),
            ("acceptance", ("owp.apply_patch",)),
        ),
    )
    payload["reserved_decisions"].sort(
        key=lambda decision: decision["decision_id"].encode("utf-8")
    )
    payload["profile_id"] = human_agency_profile_id(payload)
    with pytest.raises(ValidationError, match="at most 5"):
        HumanAgencyProfileV01.model_validate(
            sign_payload(
                "human-agency-profile",
                payload,
                agency_case.keys["Acceptor"][0],
            )
        )


def test_profile_rejects_unknown_field(agency_case: _AgencyCase) -> None:
    payload = _profile_payload(agency_case, delegated=("owp.repo_read",))
    payload["extra"] = "unexpected"
    payload["profile_id"] = human_agency_profile_id(payload)
    with pytest.raises(ValidationError):
        HumanAgencyProfileV01.model_validate(
            sign_payload(
                "human-agency-profile",
                payload,
                agency_case.keys["Acceptor"][0],
            )
        )


def test_profile_rejects_non_canonical_time(agency_case: _AgencyCase) -> None:
    payload = _profile_payload(agency_case, delegated=("owp.repo_read",))
    payload["valid_from"] = "2026-01-01T00:00:01+00:00"
    payload["profile_id"] = human_agency_profile_id(payload)
    with pytest.raises(ValidationError):
        HumanAgencyProfileV01.model_validate(
            sign_payload(
                "human-agency-profile",
                payload,
                agency_case.keys["Acceptor"][0],
            )
        )


def test_profile_recomputes_profile_id(agency_case: _AgencyCase) -> None:
    profile = _signed_profile(agency_case, delegated=("owp.repo_read",))
    assert profile.profile_id == human_agency_profile_id(
        profile.model_dump(mode="json")
    )
    tampered = copy.deepcopy(profile.model_dump(mode="json"))
    tampered["expires_at"] = "2026-01-01T23:59:58Z"
    with pytest.raises(ValidationError):
        HumanAgencyProfileV01.model_validate(tampered)


def test_profile_adversarial_rebuild_rejects_mutation(agency_case: _AgencyCase) -> None:
    profile = _signed_profile(agency_case, delegated=("owp.repo_read",))
    rebuilt = copy.deepcopy(profile.model_dump(mode="json"))
    rebuilt["delegated_actions"][0]["tool_name"] = "owp.apply_patch"
    rebuilt["profile_id"] = human_agency_profile_id(rebuilt)
    with pytest.raises(ValidationError):
        HumanAgencyProfileV01.model_validate(
            sign_payload(
                "human-agency-profile",
                rebuilt,
                agency_case.keys["Acceptor"][0],
            )
        )


# --- Transition invariants ---


def test_transition_requires_paired_replacement(agency_case: _AgencyCase) -> None:
    profile = _signed_profile(agency_case, delegated=("owp.repo_read",))
    with pytest.raises(ValidationError):
        _signed_transition(
            agency_case,
            target_profile_id=profile.profile_id,
            target_profile_digest=profile.digest,
            transition="superseded",
            replacement_profile_id="a" * 64,
            replacement_profile_digest=None,
        )
    with pytest.raises(ValidationError):
        _signed_transition(
            agency_case,
            target_profile_id=profile.profile_id,
            target_profile_digest=profile.digest,
            transition="revoked",
            replacement_profile_id="a" * 64,
            replacement_profile_digest="b" * 64,
        )


# --- WorkOrder binding verification ---


def test_profile_is_bound_to_exact_work_order_and_acceptor(
    agency_case: _AgencyCase,
) -> None:
    profile = _signed_profile(agency_case, delegated=("owp.repo_read",))
    assert profile.work_order_digest == agency_case.work_order.digest
    assert verify_human_agency_profile(profile, agency_case.work_order)


def test_profile_rejects_non_acceptor_signer(agency_case: _AgencyCase) -> None:
    profile = _signed_profile(agency_case, delegated=("owp.repo_read",), signer="Manager")
    assert not verify_human_agency_profile(profile, agency_case.work_order)


def test_profile_rejects_wrong_work_order_binding(agency_case: _AgencyCase) -> None:
    profile = _signed_profile(agency_case, delegated=("owp.repo_read",))
    wrong = profile.model_copy(update={"work_order_digest": SHA256_B})
    assert not verify_human_agency_profile(wrong, agency_case.work_order)


def test_profile_rejects_out_of_work_order_tool(agency_case: _AgencyCase) -> None:
    profile = _signed_profile(agency_case, delegated=("owp.repo_read",))
    narrowed = agency_case.work_order.model_copy(
        update={"allowed_tools": tuple(t for t in agency_case.work_order.allowed_tools if t != "owp.repo_read")}
    )
    assert not verify_human_agency_profile(profile, narrowed)


def test_transition_is_bound_to_acceptor(agency_case: _AgencyCase) -> None:
    profile = _signed_profile(agency_case, delegated=("owp.repo_read",))
    transition = _signed_transition(
        agency_case,
        target_profile_id=profile.profile_id,
        target_profile_digest=profile.digest,
        transition="revoked",
    )
    assert verify_agency_profile_transition(transition, agency_case.work_order)
    assert not verify_agency_profile_transition(
        _signed_transition(
            agency_case,
            signer="Manager",
            target_profile_id=profile.profile_id,
            target_profile_digest=profile.digest,
            transition="revoked",
        ),
        agency_case.work_order,
    )


def test_appeal_signer_must_match_declared_role_and_subject(
    agency_case: _AgencyCase,
) -> None:
    profile = _signed_profile(agency_case, delegated=("owp.repo_read",))
    appeal = _signed_appeal(
        agency_case,
        role="Manager",
        signing_role="Developer",
        profile_id=profile.profile_id,
        profile_digest=profile.digest,
    )
    assert not verify_agency_appeal(appeal, agency_case.work_order)


def test_appeal_verifies_correct_role_subject_and_key(
    agency_case: _AgencyCase,
) -> None:
    profile = _signed_profile(agency_case, delegated=("owp.repo_read",))
    appeal = _signed_appeal(
        agency_case,
        role="Manager",
        profile_id=profile.profile_id,
        profile_digest=profile.digest,
    )
    assert verify_agency_appeal(appeal, agency_case.work_order)
    assert not verify_agency_appeal(
        appeal.model_copy(update={"work_order_digest": SHA256_B}),
        agency_case.work_order,
    )


# --- Frozen WorkOrder digest snapshot ---


_DETERMINISTIC_ROLE_BYTES = {
    "Maintainer": 1,
    "Manager": 2,
    "Developer": 3,
    "Verifier": 4,
    "Sidecar": 5,
    "Acceptor": 6,
}


def _deterministic_signed_work_order(work_order_dict: dict[str, Any]) -> WorkOrder:
    candidate = copy.deepcopy(work_order_dict)
    keys: dict[str, tuple[Ed25519PrivateKey, dict[str, str]]] = {}
    bindings: list[dict[str, str]] = []
    for role in EPHEMERAL_ROLES:
        private_key = Ed25519PrivateKey.from_private_bytes(
            bytes([_DETERMINISTIC_ROLE_BYTES[role]]) * 32
        )
        public_key = private_key.public_key()
        raw = public_key.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        binding = {
            "role": role,
            "subject_id": role.lower(),
            "key_id": key_id(public_key),
            "public_key_b64url": _b64url(raw),
        }
        keys[role] = (private_key, binding)
        bindings.append(binding)
    maintainer = bindings[0]
    manager = bindings[1]
    acceptor = bindings[5]
    candidate["key_bindings"] = bindings
    candidate["issuer_id"] = maintainer["subject_id"]
    candidate["signer_key_id"] = maintainer["key_id"]
    candidate["acceptor_key_ids"] = [acceptor["key_id"]]
    candidate["root_grant_template"]["issuer_key_id"] = maintainer["key_id"]
    candidate["root_grant_template"]["subject_agent_id"] = manager["subject_id"]
    candidate["root_grant_template"]["subject_key_id"] = manager["key_id"]
    return WorkOrder.model_validate(
        sign_payload("work-order", candidate, keys["Maintainer"][0])
    )


_FROZEN_WORK_ORDER_DIGEST = (
    "541e9b4b25d3a10d611bd35be9b6cc35fd1c9ea2f06efe366e27cf775f4c23e4"
)


def test_frozen_work_order_digest_unchanged(
    work_order_dict: dict[str, Any],
) -> None:
    work_order = _deterministic_signed_work_order(work_order_dict)
    assert work_order.digest == _FROZEN_WORK_ORDER_DIGEST
