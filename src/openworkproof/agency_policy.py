"""Opt-in human agency authorization intersection.

This module computes ``WorkOrder ∩ Grant ∩ active profile`` for a single
prospective tool call. It reuses the existing immutable base authorization and
only adds the agency layer on top: the base decision wins whenever it denies,
and the profile is consulted only after the base policy allows the call.
"""

from __future__ import annotations

from openworkproof.agency import (
    AGENCY_PROFILE_BINDING_INVALID,
    AGENCY_PROFILE_EXPIRED,
    AGENCY_PROFILE_HISTORY_INVALID,
    AGENCY_PROFILE_REQUIRED,
    AgencyProfileHistory,
    AgencyProfileHistoryError,
    resolve_current_human_agency_profile,
    verify_human_agency_profile,
)
from openworkproof.models import AgentRequest, PolicyDecision, ToolRequestArguments
from openworkproof.policy import (
    AuthorizationContext,
    ProspectiveExecutionFacts,
    authorize_tool_call,
)


__all__ = [
    "AGENCY_ACTION_NOT_DELEGATED",
    "AGENCY_HUMAN_DECISION_REQUIRED",
    "authorize_agency_profile_layer",
    "authorize_tool_call_with_agency_profile",
]

AGENCY_HUMAN_DECISION_REQUIRED = "AGENCY_HUMAN_DECISION_REQUIRED"
AGENCY_ACTION_NOT_DELEGATED = "AGENCY_ACTION_NOT_DELEGATED"

_RESOLVER_ERROR_REASONS = {
    AGENCY_PROFILE_REQUIRED: "no active human agency profile",
    AGENCY_PROFILE_HISTORY_INVALID: "human agency profile history is invalid",
    AGENCY_PROFILE_EXPIRED: "human agency profile has expired",
    AGENCY_PROFILE_BINDING_INVALID: (
        "human agency profile WorkOrder binding is invalid"
    ),
}


def _deny(error_code: str, reason: str) -> PolicyDecision:
    return PolicyDecision(
        allowed=False,
        decision="deny",
        error_code=error_code,
        reason=reason,
    )


def _allow() -> PolicyDecision:
    return PolicyDecision(
        allowed=True,
        decision="allow",
        error_code=None,
        reason="HUMAN_AGENCY_PROFILE_AUTHORIZED",
    )


def authorize_agency_profile_layer(
    context: AuthorizationContext,
    profile_history: AgencyProfileHistory,
    request: AgentRequest,
) -> PolicyDecision:
    """Resolve and apply only the human agency profile layer.

    This function never reruns the base ``authorize_tool_call`` policy. It
    assumes the caller has already established that the base WorkOrder/Grant
    authorization allowed the request, and computes only the agency boundary:
    resolve the unique current profile from the signed history, then deny when
    the tool is reserved for a human decision, not delegated, or when the
    history is missing, invalid, expired, revoked, or bound to another
    WorkOrder. On success it returns an allow decision.
    """

    if not isinstance(profile_history, AgencyProfileHistory):
        return _deny(
            AGENCY_PROFILE_HISTORY_INVALID,
            "human agency profile history is malformed",
        )

    try:
        resolved = resolve_current_human_agency_profile(
            context.work_order,
            profile_history.profiles,
            profile_history.transitions,
            now=context.transaction_time,
        )
    except AgencyProfileHistoryError as error:
        return _deny(
            error.code,
            _RESOLVER_ERROR_REASONS.get(
                error.code,
                "human agency profile is unavailable",
            ),
        )

    if resolved.status == "revoked" or resolved.current_profile is None:
        return _deny(
            AGENCY_PROFILE_REQUIRED,
            _RESOLVER_ERROR_REASONS[AGENCY_PROFILE_REQUIRED],
        )

    profile = resolved.current_profile
    if not verify_human_agency_profile(profile, context.work_order):
        return _deny(
            AGENCY_PROFILE_HISTORY_INVALID,
            "human agency profile signature is invalid",
        )

    delegated_tool_names = frozenset(
        action.tool_name for action in profile.delegated_actions
    )
    reserved_tool_names = frozenset(
        tool_name
        for decision in profile.reserved_decisions
        for tool_name in decision.blocked_tools
    )
    if request.tool_name in reserved_tool_names:
        return _deny(
            AGENCY_HUMAN_DECISION_REQUIRED,
            "human agency profile reserves this decision",
        )
    if request.tool_name not in delegated_tool_names:
        return _deny(
            AGENCY_ACTION_NOT_DELEGATED,
            "human agency profile does not delegate this action",
        )
    return _allow()


def authorize_tool_call_with_agency_profile(
    context: AuthorizationContext,
    profile_history: AgencyProfileHistory,
    request: AgentRequest,
    request_arguments: ToolRequestArguments,
    execution_facts: ProspectiveExecutionFacts | None = None,
) -> PolicyDecision:
    """Authorize a tool call against the base policy plus the active profile.

    The base policy runs first so an existing security error (bad signature,
    bad WorkOrder/Grant, freshness, quota) always wins over any agency-specific
    code. Only after the base policy allows the call is the profile-only layer
    consulted, and the exact base allow decision is preserved on success.
    """

    base_decision = authorize_tool_call(
        context,
        request,
        request_arguments,
        execution_facts,
    )
    if not base_decision.allowed:
        return base_decision

    profile_decision = authorize_agency_profile_layer(
        context,
        profile_history,
        request,
    )
    if not profile_decision.allowed:
        return profile_decision
    return base_decision
