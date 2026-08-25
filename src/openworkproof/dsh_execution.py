"""OWP-owned execution adapters for DeepSeek Harness actions."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import model_validator

import openworkproof.repo_tools as repo_tools
from openworkproof.dsh_case import DecisionTokenStore
from openworkproof.dsh_protocol import DshExecutionIdentityV01
from openworkproof.mcp_server import ToolCallDenied, execute_apply_patch
from openworkproof.models import (
    AgentRequest,
    ApplyPatchArguments,
    CanonicalRoot,
    Digest64,
    ProtocolModel,
    ToolCallReceipt,
    request_arguments_digest,
)
from openworkproof.policy import AuthorizationContext, ProspectiveExecutionFacts
from openworkproof.signing import key_id, sign_payload


class DshExecutionDenied(RuntimeError):
    """The DSH action failed a closed protocol authorization boundary."""


class DshApplyPatchInputV01(ProtocolModel):
    schema_version: Literal["openworkproof-dsh-apply-patch/0.1"]
    case_id: Digest64
    execution: DshExecutionIdentityV01
    decision_token: Digest64
    patch_utf8: str
    target_paths: tuple[CanonicalRoot, ...]

    @model_validator(mode="after")
    def _validate_targets(self) -> DshApplyPatchInputV01:
        encoded = tuple(path.encode("utf-8") for path in self.target_paths)
        if (
            not 1 <= len(self.target_paths) <= 32
            or encoded != tuple(sorted(encoded))
            or len(set(self.target_paths)) != len(self.target_paths)
        ):
            raise ValueError("target_paths must be UTF-8 sorted and unique")
        return self


@dataclass(frozen=True, slots=True)
class DshExecutionCaseV01:
    """Trusted runtime objects assembled after a frozen case is opened."""

    case_id: str
    ledger_path: Path
    evidence_root: Path
    context: AuthorizationContext
    candidate_workspace: repo_tools.CandidateWorkspace
    sidecar_private_key: Ed25519PrivateKey
    developer_private_key: Ed25519PrivateKey
    decision_tokens: DecisionTokenStore
    patch_handler: Callable[
        [repo_tools.PatchRequest], repo_tools.PatchResult
    ] = repo_tools.apply_patch_in_candidate_workspace


@dataclass(frozen=True, slots=True)
class DshPatchExecutionResult:
    receipt: ToolCallReceipt
    changed_paths: tuple[str, ...]


def _digest_payload(domain: str, payload: object) -> str:
    return hashlib.sha256(
        rfc8785.dumps({"domain": domain, "payload": payload})
    ).hexdigest()


def _trusted_now(clock: Callable[[], datetime]) -> datetime:
    now = clock()
    if now.tzinfo is None or now.utcoffset() is None or now.microsecond:
        raise ValueError("DSH execution clock must return an exact aware second")
    return now.astimezone(timezone.utc)


def _developer_grant(case: DshExecutionCaseV01):
    developer_key_id = key_id(case.developer_private_key.public_key())
    grants = tuple(
        grant
        for grant in case.context.ledger_prefix.effective_grants
        if grant.subject_key_id == developer_key_id
        and "owp.apply_patch" in grant.allowed_tools
    )
    if len(grants) != 1:
        raise DshExecutionDenied("OWP_AUTHORIZATION_DENIED")
    return grants[0]


def _agent_request(
    case: DshExecutionCaseV01,
    payload: DshApplyPatchInputV01,
    arguments: ApplyPatchArguments,
    now: datetime,
) -> AgentRequest:
    grant = _developer_grant(case)
    execution_bytes = payload.execution.model_dump(mode="json")
    prompt_digest = _digest_payload(
        "openworkproof/dsh-prompt-profile/v0.1",
        {"host": "deepseek-harness", "adapter_version": "0.1.0"},
    )
    context_digest = _digest_payload(
        "openworkproof/dsh-request-context/v0.1", execution_bytes
    )
    nonce = _digest_payload(
        "openworkproof/dsh-agent-request-nonce/v0.1",
        {
            "case_id": case.case_id,
            "execution": execution_bytes,
            "arguments_digest": request_arguments_digest(
                "owp.apply_patch", arguments
            ),
        },
    )
    raw = {
        "claim_type": "agent-request",
        "work_order_digest": case.context.work_order.digest,
        "grant_id": grant.grant_id,
        "actor_id": grant.subject_agent_id,
        "actor_key_id": grant.subject_key_id,
        "tool_name": "owp.apply_patch",
        "arguments_digest": request_arguments_digest(
            "owp.apply_patch", arguments
        ),
        "nonce": nonce,
        "requested_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "authentication_method": "agent_signature",
        "model_id": "deepseek-harness",
        "model_version": "0.1.1-rc.2",
        "prompt_template_digest": prompt_digest,
        "context_source_digest": context_digest,
    }
    return AgentRequest.model_validate(
        sign_payload("agent-request", raw, case.developer_private_key)
    )


def _execution_facts(
    case: DshExecutionCaseV01,
    execution: DshExecutionIdentityV01,
) -> ProspectiveExecutionFacts:
    return ProspectiveExecutionFacts(
        execution_context_id=_digest_payload(
            "openworkproof/dsh-execution-context/v0.1",
            {
                "session_id": execution.session_id,
                "call_id": execution.call_id,
                "root_call_id": execution.root_call_id,
            },
        ),
        container_instance_id_digest=_digest_payload(
            "openworkproof/dsh-host-instance/v0.1",
            {"session_id": execution.session_id},
        ),
        controller_id=key_id(case.sidecar_private_key.public_key()),
    )


def execute_dsh_patch(
    case: DshExecutionCaseV01,
    payload: DshApplyPatchInputV01,
    *,
    clock: Callable[[], datetime],
) -> DshPatchExecutionResult:
    """Execute a canonical patch only through the existing OWP transaction."""

    if payload.case_id != case.case_id:
        raise DshExecutionDenied("CASE_ID_MISMATCH")
    if payload.execution.tool_name != "owp_apply_patch":
        raise DshExecutionDenied("ACTION_TYPE_MISMATCH")
    patch_bytes = payload.patch_utf8.encode("utf-8")
    arguments = ApplyPatchArguments(
        target_paths=payload.target_paths,
        patch_digest=hashlib.sha256(patch_bytes).hexdigest(),
        patch_size_bytes=len(patch_bytes),
    )
    if payload.execution.arguments_digest != request_arguments_digest(
        "owp.apply_patch", arguments
    ):
        raise DshExecutionDenied("ACTION_ARGUMENTS_MISMATCH")
    try:
        parsed = repo_tools.parse_patch_phase_a(
            patch_bytes,
            expected_patch_digest=arguments.patch_digest,
            expected_patch_size_bytes=arguments.patch_size_bytes,
            declared_target_paths=arguments.target_paths,
        )
    except repo_tools.PatchError as error:
        raise DshExecutionDenied("PATCH_INPUT_INVALID") from error
    if parsed.derived_patch_paths != arguments.target_paths:
        raise DshExecutionDenied("PATCH_TARGET_MISMATCH")
    if not case.decision_tokens.consume(
        payload.decision_token, payload.execution
    ):
        raise DshExecutionDenied("DECISION_TOKEN_INVALID")

    now = _trusted_now(clock)
    request = _agent_request(case, payload, arguments, now)
    try:
        receipt = execute_apply_patch(
            case.ledger_path,
            evidence_root=case.evidence_root,
            context=case.context,
            request=request,
            request_arguments=arguments,
            execution_facts=_execution_facts(case, payload.execution),
            sidecar_private_key=case.sidecar_private_key,
            patch_bytes=patch_bytes,
            candidate_workspace=case.candidate_workspace,
            handler=case.patch_handler,
            clock=lambda: now,
        )
    except ToolCallDenied as error:
        raise DshExecutionDenied("OWP_AUTHORIZATION_DENIED") from error
    return DshPatchExecutionResult(
        receipt=receipt,
        changed_paths=tuple(arguments.target_paths),
    )


__all__ = [
    "DshApplyPatchInputV01",
    "DshExecutionCaseV01",
    "DshExecutionDenied",
    "DshPatchExecutionResult",
    "execute_dsh_patch",
]
