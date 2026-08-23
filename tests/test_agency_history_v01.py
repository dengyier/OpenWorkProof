from __future__ import annotations

import copy
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from conftest import SHA256_A, SHA256_B, SHA256_C, SHA256_D
from openworkproof.agency import (
    AGENCY_PROFILE_BINDING_INVALID,
    AGENCY_PROFILE_EXPIRED,
    AGENCY_PROFILE_HISTORY_INVALID,
    AGENCY_PROFILE_REQUIRED,
    AgencyProfileHistory,
    AgencyProfileHistoryError,
    AgencyProfileTransitionV01,
    HumanAgencyProfileV01,
    ResolvedAgencyProfile,
    agency_profile_transition_id,
    delegated_action_id,
    human_agency_profile_id,
    resolve_current_human_agency_profile,
)
from openworkproof.models import WorkOrder
from openworkproof.signing import sign_payload


_NOW = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


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


def _mk_profile(
    case: _AgencyCase,
    nonce: str,
    *,
    delegated: tuple[str, ...] = ("owp.repo_read",),
    issued_at: str = "2026-01-01T00:00:00Z",
    valid_from: str = "2026-01-01T00:00:01Z",
    expires_at: str = "2026-01-01T23:59:59Z",
    signer: str = "Acceptor",
) -> HumanAgencyProfileV01:
    payload = {
        "schema_version": "openworkproof-human-agency-profile/0.1",
        "work_order_digest": case.work_order.digest,
        "delegated_actions": [
            {
                "action_id": delegated_action_id(
                    {"tool_name": tool, "autonomy": "delegated"}
                ),
                "tool_name": tool,
                "autonomy": "delegated",
            }
            for tool in delegated
        ],
        "reserved_decisions": [],
        "escalation_conditions": [{"condition_code": "reserved_decision_requested"}],
        "revocation_and_appeal": {
            "revocation_mode": "acceptor_signed_transition",
            "appeal_mode": "signed_request_then_acceptor_decision",
            "appeal_roles": ["Developer", "Manager", "Verifier"],
        },
        "valid_from": valid_from,
        "expires_at": expires_at,
        "issued_at": issued_at,
        "nonce": nonce,
    }
    payload["profile_id"] = human_agency_profile_id(payload)
    return HumanAgencyProfileV01.model_validate(
        sign_payload("human-agency-profile", payload, case.keys[signer][0])
    )


def _mk_transition(
    case: _AgencyCase,
    *,
    target: HumanAgencyProfileV01,
    transition: str = "revoked",
    replacement: HumanAgencyProfileV01 | None = None,
    transitioned_at: str = "2026-01-01T02:00:00Z",
    nonce: str = SHA256_D,
    signer: str = "Acceptor",
) -> AgencyProfileTransitionV01:
    payload = {
        "schema_version": "openworkproof-agency-profile-transition/0.1",
        "work_order_digest": case.work_order.digest,
        "target_profile_id": target.profile_id,
        "target_profile_digest": target.digest,
        "transition": transition,
        "replacement_profile_id": (
            replacement.profile_id if replacement is not None else None
        ),
        "replacement_profile_digest": (
            replacement.digest if replacement is not None else None
        ),
        "reason_code": "scope_changed" if transition == "superseded" else "human_withdrawal",
        "transitioned_at": transitioned_at,
        "nonce": nonce,
    }
    payload["transition_id"] = agency_profile_transition_id(payload)
    return AgencyProfileTransitionV01.model_validate(
        sign_payload("agency-profile-transition", payload, case.keys[signer][0])
    )


def _resolve(
    case: _AgencyCase,
    profiles: tuple[HumanAgencyProfileV01, ...],
    transitions: tuple[AgencyProfileTransitionV01, ...],
    *,
    now: datetime = _NOW,
) -> ResolvedAgencyProfile:
    return resolve_current_human_agency_profile(
        case.work_order, profiles, transitions, now=now
    )


# --- happy paths ---


def test_genesis_profile_is_active(agency_case: _AgencyCase) -> None:
    profile = _mk_profile(agency_case, SHA256_A)
    resolved = _resolve(agency_case, (profile,), ())
    assert resolved.status == "active"
    assert resolved.current_profile == profile
    assert resolved.ordered_profile_ids == (profile.profile_id,)
    assert resolved.ordered_transition_ids == ()


def test_supersede_chain_resolves_terminal(agency_case: _AgencyCase) -> None:
    first = _mk_profile(agency_case, SHA256_A)
    second = _mk_profile(agency_case, SHA256_B)
    third = _mk_profile(agency_case, SHA256_C)
    t1 = _mk_transition(agency_case, target=first, transition="superseded", replacement=second)
    t2 = _mk_transition(agency_case, target=second, transition="superseded", replacement=third)
    resolved = _resolve(agency_case, (third, first, second), (t2, t1))
    assert resolved.status == "active"
    assert resolved.current_profile == third
    assert resolved.ordered_profile_ids == (
        first.profile_id,
        second.profile_id,
        third.profile_id,
    )
    assert resolved.ordered_transition_ids == (t1.transition_id, t2.transition_id)


def test_revoked_profile_is_not_active(agency_case: _AgencyCase) -> None:
    profile = _mk_profile(agency_case, SHA256_A)
    revoke = _mk_transition(agency_case, target=profile, transition="revoked")
    resolved = _resolve(agency_case, (profile,), (revoke,))
    assert resolved.status == "revoked"
    assert resolved.current_profile is None
    assert resolved.ordered_profile_ids == (profile.profile_id,)
    assert resolved.ordered_transition_ids == (revoke.transition_id,)


def test_revoked_terminal_after_supersede(agency_case: _AgencyCase) -> None:
    first = _mk_profile(agency_case, SHA256_A)
    second = _mk_profile(agency_case, SHA256_B)
    t1 = _mk_transition(agency_case, target=first, transition="superseded", replacement=second)
    t2 = _mk_transition(agency_case, target=second, transition="revoked")
    resolved = _resolve(agency_case, (second, first), (t2, t1))
    assert resolved.status == "revoked"
    assert resolved.current_profile is None


# --- fail closed: missing profile / binding ---


def test_no_profiles_fails_closed(agency_case: _AgencyCase) -> None:
    with pytest.raises(AgencyProfileHistoryError) as caught:
        _resolve(agency_case, (), ())
    assert caught.value.code == AGENCY_PROFILE_REQUIRED


def test_profile_bound_to_different_work_order_fails_closed(
    agency_case: _AgencyCase,
) -> None:
    profile = _mk_profile(agency_case, SHA256_A)
    wrong = profile.model_copy(update={"work_order_digest": SHA256_B})
    with pytest.raises(AgencyProfileHistoryError) as caught:
        _resolve(agency_case, (wrong,), ())
    assert caught.value.code == AGENCY_PROFILE_BINDING_INVALID


# --- invalid histories never select latest by timestamp ---


@pytest.mark.parametrize(
    "mutation",
    ("fork", "cycle", "missing_replacement", "multiple_genesis", "time_reversal"),
)
def test_invalid_history_never_selects_latest_by_timestamp(
    agency_case: _AgencyCase,
    mutation: str,
) -> None:
    with pytest.raises(AgencyProfileHistoryError) as caught:
        _mutated_history(agency_case, mutation)
    assert caught.value.code == AGENCY_PROFILE_HISTORY_INVALID


def _mutated_history(
    case: _AgencyCase,
    mutation: str,
) -> ResolvedAgencyProfile:
    first = _mk_profile(case, SHA256_A)
    second = _mk_profile(case, SHA256_B)
    if mutation == "missing_replacement":
        missing = _mk_transition(
            case, target=first, transition="superseded",
            replacement=second,
        ).model_copy(
            update={"replacement_profile_id": "9" * 64}
        )
        return _resolve(case, (first, second), (missing,))
    if mutation == "multiple_genesis":
        return _resolve(case, (first, second), ())
    if mutation == "fork":
        third = _mk_profile(case, SHA256_C)
        t1 = _mk_transition(case, target=first, transition="superseded", replacement=second)
        t2 = _mk_transition(
            case, target=first, transition="superseded", replacement=third,
            nonce="e" * 64,
        )
        return _resolve(case, (first, second, third), (t1, t2))
    if mutation == "cycle":
        t1 = _mk_transition(case, target=first, transition="superseded", replacement=second)
        t2 = _mk_transition(case, target=second, transition="superseded", replacement=first)
        return _resolve(case, (first, second), (t1, t2))
    if mutation == "time_reversal":
        t1 = _mk_transition(
            case, target=first, transition="superseded", replacement=second,
            transitioned_at="2025-12-31T23:59:59Z",
        )
        return _resolve(case, (first, second), (t1,))
    raise AssertionError(f"unknown mutation {mutation}")


def test_replacement_digest_mismatch_fails_closed(agency_case: _AgencyCase) -> None:
    first = _mk_profile(agency_case, SHA256_A)
    second = _mk_profile(agency_case, SHA256_B)
    t1 = _mk_transition(
        case=agency_case,
        target=first,
        transition="superseded",
        replacement=second,
    ).model_copy(update={"replacement_profile_digest": "f" * 64})
    with pytest.raises(AgencyProfileHistoryError) as caught:
        _resolve(agency_case, (first, second), (t1,))
    assert caught.value.code == AGENCY_PROFILE_HISTORY_INVALID


# --- expired profile ---


def test_expired_profile_fails_closed(agency_case: _AgencyCase) -> None:
    profile = _mk_profile(
        agency_case, SHA256_A, expires_at="2026-01-01T00:00:02Z"
    )
    with pytest.raises(AgencyProfileHistoryError) as caught:
        _resolve(agency_case, (profile,), ())
    assert caught.value.code == AGENCY_PROFILE_EXPIRED


def test_agency_profile_history_holds_exact_tuples(agency_case: _AgencyCase) -> None:
    profile = _mk_profile(agency_case, SHA256_A)
    history = AgencyProfileHistory(profiles=(profile,), transitions=())
    assert history.profiles == (profile,)
    assert history.transitions == ()
