from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from conftest import SHA256_A, SHA256_B, SHA256_C, SHA256_D
from openworkproof.agency import (
    AgencyProfileHistory,
    AgencyProfileTransitionV01,
    HumanAgencyProfileV01,
    agency_profile_transition_id,
    delegated_action_id,
    human_agency_profile_id,
    reserved_decision_id,
)
from openworkproof.agency_policy import (
    AGENCY_ACTION_NOT_DELEGATED,
    AGENCY_HUMAN_DECISION_REQUIRED,
    authorize_agency_profile_layer,
    authorize_tool_call_with_agency_profile,
)
from openworkproof.models import (
    ApplyPatchArguments,
    RepoReadArguments,
    WorkOrder,
)
from openworkproof.policy import authorize_tool_call
from openworkproof.signing import sign_payload

from test_policy import _prospective_context, _signed_tool_request


@dataclass(frozen=True)
class _PolicyCase:
    context: Any
    developer_grant: Any
    work_order: WorkOrder
    keys: dict[str, tuple[Ed25519PrivateKey, dict[str, str]]]


@pytest.fixture
def policy_case(
    tmp_path,
    signed_work_order,
    signed_root_grant,
    ephemeral_role_keys,
    fixed_now,
) -> _PolicyCase:
    context, developer = _prospective_context(
        tmp_path=tmp_path,
        label="agency-policy",
        signed_work_order=signed_work_order,
        signed_root_grant=signed_root_grant,
        ephemeral_role_keys=ephemeral_role_keys,
        fixed_now=fixed_now,
    )
    return _PolicyCase(
        context=context,
        developer_grant=developer,
        work_order=signed_work_order,
        keys=copy.deepcopy(ephemeral_role_keys),
    )


def _delegated(tool: str) -> dict[str, Any]:
    body = {"tool_name": tool, "autonomy": "delegated"}
    return {"action_id": delegated_action_id(body), **body}


def _reserved(kind: str, blocked: tuple[str, ...]) -> dict[str, Any]:
    body = {
        "decision_kind": kind,
        "blocked_tools": list(blocked),
        "required_role": "Acceptor",
    }
    return {"decision_id": reserved_decision_id(body), **body}


def _mk_profile(
    case: _PolicyCase,
    nonce: str,
    *,
    delegated: tuple[str, ...] = (),
    reserved: tuple[tuple[str, tuple[str, ...]], ...] = (),
    work_order_digest: str | None = None,
    expires_at: str = "2026-01-01T23:59:59Z",
    signer: str = "Acceptor",
) -> HumanAgencyProfileV01:
    payload = {
        "schema_version": "openworkproof-human-agency-profile/0.1",
        "work_order_digest": work_order_digest or case.work_order.digest,
        "delegated_actions": [_delegated(tool) for tool in delegated],
        "reserved_decisions": [
            _reserved(kind, blocked) for kind, blocked in reserved
        ],
        "escalation_conditions": [{"condition_code": "reserved_decision_requested"}],
        "revocation_and_appeal": {
            "revocation_mode": "acceptor_signed_transition",
            "appeal_mode": "signed_request_then_acceptor_decision",
            "appeal_roles": ["Developer", "Manager", "Verifier"],
        },
        "valid_from": "2026-01-01T00:00:01Z",
        "expires_at": expires_at,
        "issued_at": "2026-01-01T00:00:00Z",
        "nonce": nonce,
    }
    payload["profile_id"] = human_agency_profile_id(payload)
    return HumanAgencyProfileV01.model_validate(
        sign_payload("human-agency-profile", payload, case.keys[signer][0])
    )


def _mk_transition(
    case: _PolicyCase,
    *,
    target: HumanAgencyProfileV01,
    transition: str = "revoked",
    replacement: HumanAgencyProfileV01 | None = None,
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
        "reason_code": (
            "scope_changed" if transition == "superseded" else "human_withdrawal"
        ),
        "transitioned_at": "2026-01-01T02:00:00Z",
        "nonce": SHA256_D,
    }
    payload["transition_id"] = agency_profile_transition_id(payload)
    return AgencyProfileTransitionV01.model_validate(
        sign_payload("agency-profile-transition", payload, case.keys[signer][0])
    )


def _history(
    profiles: tuple[HumanAgencyProfileV01, ...] = (),
    transitions: tuple[AgencyProfileTransitionV01, ...] = (),
) -> AgencyProfileHistory:
    return AgencyProfileHistory(profiles=profiles, transitions=transitions)


def _request(case: _PolicyCase, arguments: Any) -> Any:
    return _signed_tool_request(
        case.work_order,
        case.developer_grant,
        arguments,
        case.keys,
        case.context.transaction_time,
    )


def _authorize(
    case: _PolicyCase,
    history: AgencyProfileHistory,
    arguments: Any,
) -> Any:
    request = _request(case, arguments)
    return authorize_tool_call_with_agency_profile(
        case.context,
        history,
        request,
        arguments,
    )


def _authorize_profile_layer(
    case: _PolicyCase,
    history: AgencyProfileHistory,
    arguments: Any,
) -> Any:
    request = _request(case, arguments)
    return authorize_agency_profile_layer(case.context, history, request)


def test_all_three_layers_allow_repo_read(policy_case: _PolicyCase) -> None:
    profile = _mk_profile(policy_case, SHA256_A, delegated=("owp.repo_read",))
    decision = _authorize(
        policy_case, _history((profile,)), RepoReadArguments(path="src")
    )
    assert decision.allowed is True


def test_reserved_action_is_denied_after_base_policy_allows(
    policy_case: _PolicyCase,
) -> None:
    profile = _mk_profile(
        policy_case,
        SHA256_A,
        delegated=("owp.repo_read",),
        reserved=(("scope_or_criteria_change", ("owp.apply_patch",)),),
    )
    decision = _authorize(
        policy_case,
        _history((profile,)),
        ApplyPatchArguments(
            target_paths=("src/app.py",),
            patch_digest=SHA256_B,
            patch_size_bytes=1,
        ),
    )
    assert decision.allowed is False
    assert decision.error_code == AGENCY_HUMAN_DECISION_REQUIRED


def test_undelegated_action_is_denied(policy_case: _PolicyCase) -> None:
    profile = _mk_profile(policy_case, SHA256_A, delegated=("owp.repo_read",))
    decision = _authorize(
        policy_case,
        _history((profile,)),
        ApplyPatchArguments(
            target_paths=("src/app.py",),
            patch_digest=SHA256_B,
            patch_size_bytes=1,
        ),
    )
    assert decision.allowed is False
    assert decision.error_code == AGENCY_ACTION_NOT_DELEGATED


def test_declarative_reserved_decision_does_not_block_unrelated_tool(
    policy_case: _PolicyCase,
) -> None:
    profile = _mk_profile(
        policy_case,
        SHA256_A,
        delegated=("owp.repo_read",),
        reserved=(("payment_or_settlement", ()),),
    )
    decision = _authorize(
        policy_case, _history((profile,)), RepoReadArguments(path="src")
    )
    assert decision.allowed is True


def test_missing_profile_fails_closed(policy_case: _PolicyCase) -> None:
    decision = _authorize(
        policy_case, _history(), RepoReadArguments(path="src")
    )
    assert decision.allowed is False
    assert decision.error_code == "AGENCY_PROFILE_REQUIRED"


def test_invalid_history_fails_closed(policy_case: _PolicyCase) -> None:
    first = _mk_profile(policy_case, SHA256_A, delegated=("owp.repo_read",))
    second = _mk_profile(policy_case, SHA256_B, delegated=("owp.repo_read",))
    decision = _authorize(
        policy_case, _history((first, second)), RepoReadArguments(path="src")
    )
    assert decision.allowed is False
    assert decision.error_code == "AGENCY_PROFILE_HISTORY_INVALID"


def test_forged_historical_profile_fails_closed(policy_case: _PolicyCase) -> None:
    forged_first = _mk_profile(
        policy_case, SHA256_A, delegated=("owp.repo_read",), signer="Manager"
    )
    second = _mk_profile(policy_case, SHA256_B, delegated=("owp.repo_read",))
    supersede = _mk_transition(
        policy_case,
        target=forged_first,
        transition="superseded",
        replacement=second,
    )
    decision = _authorize(
        policy_case,
        _history((second, forged_first), (supersede,)),
        RepoReadArguments(path="src"),
    )
    assert decision.allowed is False
    assert decision.error_code == "AGENCY_PROFILE_HISTORY_INVALID"


def test_expired_profile_fails_closed(policy_case: _PolicyCase) -> None:
    profile = _mk_profile(
        policy_case,
        SHA256_A,
        delegated=("owp.repo_read",),
        expires_at="2026-01-01T00:00:04Z",
    )
    decision = _authorize(
        policy_case, _history((profile,)), RepoReadArguments(path="src")
    )
    assert decision.allowed is False
    assert decision.error_code == "AGENCY_PROFILE_EXPIRED"


def test_binding_invalid_fails_closed(policy_case: _PolicyCase) -> None:
    profile = _mk_profile(
        policy_case,
        SHA256_A,
        delegated=("owp.repo_read",),
        work_order_digest=SHA256_C,
    )
    decision = _authorize(
        policy_case, _history((profile,)), RepoReadArguments(path="src")
    )
    assert decision.allowed is False
    assert decision.error_code == "AGENCY_PROFILE_BINDING_INVALID"


def test_base_policy_denial_takes_precedence(
    tmp_path,
    signed_work_order,
    signed_root_grant,
    ephemeral_role_keys,
    fixed_now,
) -> None:
    capability_context, capability_grant = _prospective_context(
        tmp_path=tmp_path,
        label="agency-policy-precedence",
        signed_work_order=signed_work_order,
        signed_root_grant=signed_root_grant,
        ephemeral_role_keys=ephemeral_role_keys,
        fixed_now=fixed_now,
        child_updates={"allowed_tools": ["owp.apply_patch"]},
    )
    case = _PolicyCase(
        context=capability_context,
        developer_grant=capability_grant,
        work_order=signed_work_order,
        keys=copy.deepcopy(ephemeral_role_keys),
    )
    profile = _mk_profile(case, SHA256_A, delegated=("owp.repo_read",))
    decision = _authorize(
        case, _history((profile,)), RepoReadArguments(path="src")
    )
    assert decision.allowed is False
    assert decision.error_code == "CAPABILITY_DENIED"


# --- profile-only layer: reserved / not-delegated / invalid / expired /
# --- binding failures, without rerunning the base policy. ---


def test_profile_layer_reserved_action_is_denied(
    policy_case: _PolicyCase,
) -> None:
    profile = _mk_profile(
        policy_case,
        SHA256_A,
        delegated=("owp.repo_read",),
        reserved=(("scope_or_criteria_change", ("owp.apply_patch",)),),
    )
    decision = _authorize_profile_layer(
        policy_case,
        _history((profile,)),
        ApplyPatchArguments(
            target_paths=("src/app.py",),
            patch_digest=SHA256_B,
            patch_size_bytes=1,
        ),
    )
    assert decision.allowed is False
    assert decision.error_code == AGENCY_HUMAN_DECISION_REQUIRED


def test_profile_layer_undelegated_action_is_denied(
    policy_case: _PolicyCase,
) -> None:
    profile = _mk_profile(policy_case, SHA256_A, delegated=("owp.repo_read",))
    decision = _authorize_profile_layer(
        policy_case,
        _history((profile,)),
        ApplyPatchArguments(
            target_paths=("src/app.py",),
            patch_digest=SHA256_B,
            patch_size_bytes=1,
        ),
    )
    assert decision.allowed is False
    assert decision.error_code == AGENCY_ACTION_NOT_DELEGATED


def test_profile_layer_missing_profile_fails_closed(
    policy_case: _PolicyCase,
) -> None:
    decision = _authorize_profile_layer(
        policy_case, _history(), RepoReadArguments(path="src")
    )
    assert decision.allowed is False
    assert decision.error_code == "AGENCY_PROFILE_REQUIRED"


def test_profile_layer_invalid_history_fails_closed(
    policy_case: _PolicyCase,
) -> None:
    first = _mk_profile(policy_case, SHA256_A, delegated=("owp.repo_read",))
    second = _mk_profile(policy_case, SHA256_B, delegated=("owp.repo_read",))
    decision = _authorize_profile_layer(
        policy_case,
        _history((first, second)),
        RepoReadArguments(path="src"),
    )
    assert decision.allowed is False
    assert decision.error_code == "AGENCY_PROFILE_HISTORY_INVALID"


def test_profile_layer_expired_profile_fails_closed(
    policy_case: _PolicyCase,
) -> None:
    profile = _mk_profile(
        policy_case,
        SHA256_A,
        delegated=("owp.repo_read",),
        expires_at="2026-01-01T00:00:04Z",
    )
    decision = _authorize_profile_layer(
        policy_case, _history((profile,)), RepoReadArguments(path="src")
    )
    assert decision.allowed is False
    assert decision.error_code == "AGENCY_PROFILE_EXPIRED"


def test_profile_layer_binding_invalid_fails_closed(
    policy_case: _PolicyCase,
) -> None:
    profile = _mk_profile(
        policy_case,
        SHA256_A,
        delegated=("owp.repo_read",),
        work_order_digest=SHA256_C,
    )
    decision = _authorize_profile_layer(
        policy_case, _history((profile,)), RepoReadArguments(path="src")
    )
    assert decision.allowed is False
    assert decision.error_code == "AGENCY_PROFILE_BINDING_INVALID"


def test_profile_layer_allows_delegated_action(
    policy_case: _PolicyCase,
) -> None:
    profile = _mk_profile(policy_case, SHA256_A, delegated=("owp.repo_read",))
    decision = _authorize_profile_layer(
        policy_case, _history((profile,)), RepoReadArguments(path="src")
    )
    assert decision.allowed is True
    assert decision.error_code is None


def test_profile_layer_does_not_rerun_base_policy(
    policy_case: _PolicyCase,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = _mk_profile(policy_case, SHA256_A, delegated=("owp.repo_read",))

    def _explode(*args, **kwargs):
        raise AssertionError("base policy must not rerun inside profile layer")

    monkeypatch.setattr(
        "openworkproof.agency_policy.authorize_tool_call", _explode
    )
    decision = _authorize_profile_layer(
        policy_case, _history((profile,)), RepoReadArguments(path="src")
    )
    assert decision.allowed is True


def test_combined_function_preserves_base_allow_decision(
    policy_case: _PolicyCase,
) -> None:
    profile = _mk_profile(policy_case, SHA256_A, delegated=("owp.repo_read",))
    arguments = RepoReadArguments(path="src")
    request = _request(policy_case, arguments)
    base_decision = authorize_tool_call(
        policy_case.context,
        request,
        arguments,
        None,
    )
    assert base_decision.allowed is True
    combined = authorize_tool_call_with_agency_profile(
        policy_case.context,
        _history((profile,)),
        request,
        arguments,
    )
    assert combined.allowed is True
    assert combined == base_decision
