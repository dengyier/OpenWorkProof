"""Pre-execution Judgment-to-Action binding gateway coverage."""

from __future__ import annotations

import copy
import dataclasses
from datetime import timedelta
import hashlib
import sqlite3

import pytest
import rfc8785
import jsonschema
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

import openworkproof.evidence as evidence
import openworkproof.binding_transactions as binding_transactions
import openworkproof.mcp_server as mcp_server
import openworkproof.models as models
import openworkproof.policy as policy
import openworkproof.repo_tools as repo_tools
import openworkproof.state as state
from openworkproof.binding import canonical_test_profile_digest
from openworkproof.binding_transactions import (
    JudgmentAuthorityContext,
    commit_action_binding_manifest,
    commit_judgment_commitment,
)
from openworkproof.models import (
    AgentRequest,
    AgentRequestV04,
    ApplyPatchArguments,
    ComposeProofArguments,
    RepoReadArguments,
    SubjectClaim,
)
from openworkproof.signing import (
    canonical_bytes,
    sign_payload,
    verify_nested_claim,
    verify_payload,
)
from openworkproof.verification import commit_evaluation_scope
from test_binding_manifest_transactions_v04 import (
    _profile_from_axes,
    _signed_judgment,
    _signed_manifest,
    _signed_scope,
)
from test_mcp_server import (
    _FakeRunTestsExecutionDriver,
    _closed_run_tests_outcome,
    _current_run_tests_context,
    _run_tests_case,
    _run_tests_contract,
    _run_tests_snapshot,
    _run_tests_snapshot_request,
)


def test_versioned_request_parser_routes_only_explicit_v04(
    agent_request_v04: AgentRequestV04,
    agent_request_v04_dict: dict[str, object],
) -> None:
    parsed = models.parse_agent_request(agent_request_v04_dict)
    assert type(parsed) is AgentRequestV04
    assert parsed == agent_request_v04

    legacy_payload = {
        key: value
        for key, value in agent_request_v04_dict.items()
        if key
        not in {
            "schema_version",
            "judgment_commitment_id",
            "judgment_commitment_digest",
            "action_binding_manifest_id",
            "action_binding_manifest_digest",
        }
    }
    assert type(models.parse_agent_request(legacy_payload)) is AgentRequest


@pytest.mark.parametrize(
    "missing_field",
    (
        "judgment_commitment_id",
        "judgment_commitment_digest",
        "action_binding_manifest_id",
        "action_binding_manifest_digest",
    ),
)
def test_explicit_v04_request_rejects_missing_binding_pair_fields(
    agent_request_v04_dict: dict[str, object],
    missing_field: str,
) -> None:
    candidate = copy.deepcopy(agent_request_v04_dict)
    candidate.pop(missing_field)
    with pytest.raises(ValidationError):
        models.parse_agent_request(candidate)


def test_metadata_names_never_upgrade_a_legacy_request(
    agent_request_v04_dict: dict[str, object],
    binding_developer_private_key_v04,
) -> None:
    payload = {
        key: value
        for key, value in agent_request_v04_dict.items()
        if key
        not in {
            "schema_version",
            "judgment_commitment_id",
            "judgment_commitment_digest",
            "action_binding_manifest_id",
            "action_binding_manifest_digest",
            "digest",
            "signature_alg",
            "signer_key_id",
            "signature",
        }
    }
    candidate = sign_payload(
        "agent-request", payload, binding_developer_private_key_v04
    )
    candidate["metadata"] = {
        "judgment_commitment_id": "1" * 64,
        "judgment_commitment_digest": "2" * 64,
        "action_binding_manifest_id": "3" * 64,
        "action_binding_manifest_digest": "4" * 64,
    }
    with pytest.raises(ValidationError):
        models.parse_agent_request(candidate)


def _resign_v04_request(
    request: AgentRequest,
    private_key: Ed25519PrivateKey,
    *,
    judgment_id: str,
    judgment_digest: str,
    manifest_id: str,
    manifest_digest: str,
    **updates: object,
) -> AgentRequestV04:
    payload = request.model_dump(
        mode="json",
        exclude={"digest", "signature_alg", "signer_key_id", "signature"},
    )
    payload.update(
        {
            "schema_version": "openworkproof-agent-request/0.4",
            "judgment_commitment_id": judgment_id,
            "judgment_commitment_digest": judgment_digest,
            "action_binding_manifest_id": manifest_id,
            "action_binding_manifest_digest": manifest_digest,
            **updates,
        }
    )
    return AgentRequestV04.model_validate(
        sign_payload("agent-request", payload, private_key, version="0.4")
    )


def _ledger_rows(path) -> dict[str, tuple[tuple[object, ...], ...]]:
    connection = sqlite3.connect(path)
    try:
        tables = tuple(
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type = 'table' AND name NOT LIKE 'sqlite_%' "
                "ORDER BY name"
            )
        )
        return {
            table: tuple(connection.execute(f'SELECT * FROM "{table}"'))
            for table in tables
        }
    finally:
        connection.close()


def _artifact_tree(root) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _assert_run_tests_denied_without_side_effects(
    case,
    *,
    request: AgentRequest,
    expected_error_code: str,
    context=None,
    now=None,
) -> None:
    driver = _FakeRunTestsExecutionDriver()
    before_rows = _ledger_rows(case["ledger_path"])
    before_artifacts = _artifact_tree(case["evidence_root"])
    before_balances = case["context"].replay_state.balances

    with pytest.raises(mcp_server.ToolCallDenied) as denied:
        mcp_server.execute_run_tests(
            case["ledger_path"],
            evidence_root=case["evidence_root"],
            context=context or case["context"],
            request=request,
            request_arguments=case["arguments"],
            execution_facts=case["facts"],
            candidate_snapshot_request=_run_tests_snapshot_request(
                case, case["evidence_root"]
            ),
            sidecar_private_key=case["role_keys"]["Sidecar"][0],
            execution_driver=driver,
            clock=lambda: now or case["now"],
        )

    assert denied.value.decision.error_code == expected_error_code
    assert driver.calls == []
    assert case["context"].replay_state.balances == before_balances
    assert _ledger_rows(case["ledger_path"]) == before_rows
    assert _artifact_tree(case["evidence_root"]) == before_artifacts


@pytest.fixture
def binding_gateway_case(
    tmp_path,
    signed_work_order,
    signed_subject_claim,
    evaluation_scope_payload_v03,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
):
    now = fixed_now + timedelta(seconds=5)
    case = _run_tests_case(
        tmp_path=tmp_path,
        signed_work_order=signed_work_order,
        role_keys=ephemeral_role_keys,
        sidecar_receipt_factory=sidecar_receipt_factory,
        now=fixed_now,
    )
    work_order = case["work_order"]
    claim_payload = signed_subject_claim.model_dump(
        mode="json",
        exclude={"digest", "signature_alg", "signer_key_id", "signature"},
    )
    claim_payload["work_order_digest"] = work_order.digest
    claim = SubjectClaim.model_validate(
        sign_payload(
            "subject-claim",
            claim_payload,
            ephemeral_role_keys["Manager"][0],
        )
    )
    scope = _signed_scope(
        payload=evaluation_scope_payload_v03,
        manager_key=ephemeral_role_keys["Manager"][0],
        work_order=work_order,
        claim=claim,
    )
    test_digests = tuple(
        sorted(
            canonical_test_profile_digest(profile)
            for profile in work_order.test_profiles
        )
    )
    profile, projection = _profile_from_axes(
        allowed_tool_names=(
            "owp.apply_patch",
            "owp.create_pr_proposal",
            "owp.repo_read",
            "owp.rollback_patch",
            "owp.run_tests",
        ),
        # Deliberately omit patch: Task 6 must enforce tool and action axes
        # independently even when the signed profile is internally unusual.
        allowed_action_kinds=("proposal", "read", "rollback", "test"),
        allowed_path_roots=("src",),
        required_test_profile_digests=test_digests,
    )
    judgment = _signed_judgment(
        work_order=work_order,
        scope=scope,
        acceptor_key=ephemeral_role_keys["Acceptor"][0],
        projection=projection,
    )
    manifest = _signed_manifest(
        work_order=work_order,
        scope=scope,
        judgment=judgment,
        projection=projection,
        manager_key=ephemeral_role_keys["Manager"][0],
    )
    commit_evaluation_scope(case["ledger_path"], claim, scope)
    commit_judgment_commitment(
        case["ledger_path"],
        judgment,
        JudgmentAuthorityContext(
            authority_namespace=judgment.authority_namespace,
            authority_binding=next(
                item
                for item in work_order.key_bindings
                if item.role == "Acceptor"
            ),
            transaction_time=fixed_now + timedelta(seconds=2),
        ),
    )
    commit_action_binding_manifest(
        case["ledger_path"],
        manifest,
        profile,
        transaction_time=fixed_now + timedelta(seconds=4),
    )
    request = _resign_v04_request(
        case["request"],
        ephemeral_role_keys["Verifier"][0],
        judgment_id=judgment.commitment_id,
        judgment_digest=judgment.digest,
        manifest_id=manifest.binding_manifest_id,
        manifest_digest=manifest.digest,
        requested_at=now.strftime("%Y-%m-%dT%H:%M:%SZ"),
    )
    context = _current_run_tests_context(case, now)
    monkeypatch.setattr(
        repo_tools,
        "prepare_candidate_execution_snapshot",
        lambda candidate_request: _run_tests_snapshot(case),
    )
    case.update(
        {
            "now": now,
            "claim": claim,
            "scope": scope,
            "profile": profile,
            "projection": projection,
            "judgment": judgment,
            "manifest": manifest,
            "request_v04": request,
            "context": context,
            "role_keys": ephemeral_role_keys,
        }
    )
    return case


def test_bound_action_authorizes_exact_current_request(binding_gateway_case) -> None:
    case = binding_gateway_case
    decision = policy.authorize_bound_action(
        case["ledger_path"],
        case["context"],
        case["request_v04"],
        case["arguments"],
        case["facts"],
    )
    assert decision.allowed is True
    assert decision.error_code is None
    assert decision.reason == "TOOL_CALL_AUTHORIZED"


@pytest.mark.parametrize("offset_seconds", (-301, 1))
def test_bound_action_returns_closed_code_for_v04_freshness_failure(
    binding_gateway_case,
    offset_seconds: int,
) -> None:
    case = binding_gateway_case
    request = _resign_v04_request(
        case["request_v04"],
        case["role_keys"]["Verifier"][0],
        judgment_id=case["judgment"].commitment_id,
        judgment_digest=case["judgment"].digest,
        manifest_id=case["manifest"].binding_manifest_id,
        manifest_digest=case["manifest"].digest,
        requested_at=(case["now"] + timedelta(seconds=offset_seconds)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
    )

    decision = policy.authorize_bound_action(
        case["ledger_path"],
        case["context"],
        request,
        case["arguments"],
        case["facts"],
    )

    assert decision.error_code == "AUTH_FRESHNESS_INVALID"
    receipt = mcp_server.produce_deny_receipt(
        case["ledger_path"],
        evidence_root=case["evidence_root"],
        context=case["context"],
        request=request,
        arguments=case["arguments"],
        execution_facts=case["facts"],
        sidecar_private_key=case["role_keys"]["Sidecar"][0],
        decision=decision,
        clock=lambda: case["now"],
    )
    assert receipt.policy_error_code == "AUTH_FRESHNESS_INVALID"


def test_bound_action_returns_closed_code_for_v04_signature_failure(
    binding_gateway_case,
) -> None:
    case = binding_gateway_case
    payload = case["request_v04"].model_dump(mode="json")
    other = _resign_v04_request(
        case["request_v04"],
        case["role_keys"]["Verifier"][0],
        judgment_id=case["judgment"].commitment_id,
        judgment_digest=case["judgment"].digest,
        manifest_id=case["manifest"].binding_manifest_id,
        manifest_digest=case["manifest"].digest,
        nonce="f" * 64,
    )
    payload["signature"] = other.signature
    request = AgentRequestV04.model_validate(payload)

    decision = policy.authorize_bound_action(
        case["ledger_path"],
        case["context"],
        request,
        case["arguments"],
        case["facts"],
    )

    assert decision.error_code == "AUTH_SIGNATURE_INVALID"


def test_bound_action_returns_closed_code_for_v04_actor_binding_failure(
    binding_gateway_case,
) -> None:
    case = binding_gateway_case
    request = _resign_v04_request(
        case["request_v04"],
        case["role_keys"]["Verifier"][0],
        judgment_id=case["judgment"].commitment_id,
        judgment_digest=case["judgment"].digest,
        manifest_id=case["manifest"].binding_manifest_id,
        manifest_digest=case["manifest"].digest,
        actor_id=case["role_keys"]["Developer"][1]["subject_id"],
    )

    decision = policy.authorize_bound_action(
        case["ledger_path"],
        case["context"],
        request,
        case["arguments"],
        case["facts"],
    )

    assert decision.error_code == "AUTH_SUBJECT_MISMATCH"


@pytest.mark.parametrize(
    ("context_update", "expected_code"),
    (
        ({"routine_capacity_remaining": 0}, "QUOTA_EXHAUSTED"),
        ({"independent_failure_terminal": True}, "PREDICATE_DENIED"),
    ),
)
def test_bound_action_returns_receipt_closed_terminal_policy_codes(
    binding_gateway_case,
    context_update: dict[str, object],
    expected_code: str,
) -> None:
    case = binding_gateway_case
    decision = policy._authorize_bound_action_with_manifest(
        dataclasses.replace(case["context"], **context_update),
        case["request_v04"],
        case["arguments"],
        case["facts"],
        case["manifest"],
    )

    assert decision.error_code == expected_code
    assert expected_code in models.POLICY_ERROR_CODES_V04


def test_bound_action_returns_receipt_closed_contract_expiry_code(
    binding_gateway_case,
) -> None:
    case = binding_gateway_case
    transaction_time = case["work_order"].deadline + timedelta(seconds=1)
    request = _resign_v04_request(
        case["request_v04"],
        case["role_keys"]["Verifier"][0],
        judgment_id=case["judgment"].commitment_id,
        judgment_digest=case["judgment"].digest,
        manifest_id=case["manifest"].binding_manifest_id,
        manifest_digest=case["manifest"].digest,
        requested_at=transaction_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
    )
    manifest = case["manifest"].model_copy(
        update={"expires_at": transaction_time + timedelta(seconds=1)}
    )
    decision = policy._authorize_bound_action_with_manifest(
        dataclasses.replace(
            case["context"], transaction_time=transaction_time
        ),
        request,
        case["arguments"],
        case["facts"],
        manifest,
    )

    assert decision.error_code == "CAPABILITY_DENIED"
    assert decision.error_code in models.POLICY_ERROR_CODES_V04


def test_legacy_public_policy_api_never_allows_v04(
    binding_gateway_case,
) -> None:
    case = binding_gateway_case
    decision = policy.authorize_tool_call(
        case["context"],
        case["request_v04"],
        case["arguments"],
        case["facts"],
    )
    assert decision.allowed is False
    assert decision.error_code == "BINDING_MANIFEST_UNAVAILABLE"


@pytest.mark.parametrize(
    ("field", "reason"),
    (
        ("judgment_commitment_digest", "BINDING_REFERENCE_MISMATCH"),
        ("action_binding_manifest_digest", "BINDING_REFERENCE_MISMATCH"),
        ("action_binding_manifest_id", "BINDING_MANIFEST_NOT_CURRENT"),
    ),
)
def test_bound_action_denies_reference_substitution(
    binding_gateway_case,
    field: str,
    reason: str,
) -> None:
    case = binding_gateway_case
    request = _resign_v04_request(
        case["request_v04"],
        case["role_keys"]["Verifier"][0],
        judgment_id=case["judgment"].commitment_id,
        judgment_digest=case["judgment"].digest,
        manifest_id=case["manifest"].binding_manifest_id,
        manifest_digest=case["manifest"].digest,
        **{field: "9" * 64},
    )
    decision = policy.authorize_bound_action(
        case["ledger_path"], case["context"], request, case["arguments"]
    )
    assert decision.allowed is False
    assert decision.error_code == reason


def test_bound_action_denies_after_customer_judgment_expiry(
    binding_gateway_case,
) -> None:
    case = binding_gateway_case
    context = dataclasses.replace(
        case["context"],
        transaction_time=case["judgment"].expires_at + timedelta(seconds=1),
    )
    decision = policy.authorize_bound_action(
        case["ledger_path"], context, case["request_v04"], case["arguments"]
    )
    # Task 5 proves Manifest expiry cannot outlive Judgment expiry.
    assert decision.error_code == "BINDING_MANIFEST_EXPIRED"


def test_bound_action_enforces_tool_action_and_path_axes(
    binding_gateway_case,
) -> None:
    case = binding_gateway_case
    developer_key = case["role_keys"]["Developer"][0]
    developer_binding = case["role_keys"]["Developer"][1]

    patch_arguments = ApplyPatchArguments(
        target_paths=("src/app.py",),
        patch_digest="d" * 64,
        patch_size_bytes=1,
    )
    patch = _resign_v04_request(
        case["request_v04"],
        developer_key,
        judgment_id=case["judgment"].commitment_id,
        judgment_digest=case["judgment"].digest,
        manifest_id=case["manifest"].binding_manifest_id,
        manifest_digest=case["manifest"].digest,
        actor_id=developer_binding["subject_id"],
        actor_key_id=developer_binding["key_id"],
        grant_id=case["developer"].grant_id,
        tool_name="owp.apply_patch",
        arguments_digest=models.request_arguments_digest(
            "owp.apply_patch", patch_arguments
        ),
        nonce="4" * 64,
    )
    assert policy.authorize_bound_action(
        case["ledger_path"], case["context"], patch, patch_arguments
    ).error_code == "ACTION_OUTSIDE_APPROVED_SCOPE"

    read_arguments = RepoReadArguments(path="tests/test_app.py")
    read = _resign_v04_request(
        patch,
        developer_key,
        judgment_id=case["judgment"].commitment_id,
        judgment_digest=case["judgment"].digest,
        manifest_id=case["manifest"].binding_manifest_id,
        manifest_digest=case["manifest"].digest,
        tool_name="owp.repo_read",
        arguments_digest=models.request_arguments_digest(
            "owp.repo_read", read_arguments
        ),
        nonce="5" * 64,
    )
    assert policy.authorize_bound_action(
        case["ledger_path"], case["context"], read, read_arguments
    ).error_code == "ACTION_OUTSIDE_APPROVED_SCOPE"

    management_arguments = ComposeProofArguments(
        expected_state_version=0, previous_report_digest=None
    )
    management = _resign_v04_request(
        case["request_v04"],
        case["role_keys"]["Manager"][0],
        judgment_id=case["judgment"].commitment_id,
        judgment_digest=case["judgment"].digest,
        manifest_id=case["manifest"].binding_manifest_id,
        manifest_digest=case["manifest"].digest,
        actor_id=case["role_keys"]["Manager"][1]["subject_id"],
        actor_key_id=case["role_keys"]["Manager"][1]["key_id"],
        grant_id=case["root"].grant_id,
        tool_name="owp.compose_proof",
        arguments_digest=models.request_arguments_digest(
            "owp.compose_proof", management_arguments
        ),
        nonce="6" * 64,
    )
    assert policy.authorize_bound_action(
        case["ledger_path"], case["context"], management, management_arguments
    ).error_code == "ACTION_OUTSIDE_APPROVED_SCOPE"


def test_bound_action_denies_reused_nonce(binding_gateway_case) -> None:
    case = binding_gateway_case
    request = _resign_v04_request(
        case["request_v04"],
        case["role_keys"]["Verifier"][0],
        judgment_id=case["judgment"].commitment_id,
        judgment_digest=case["judgment"].digest,
        manifest_id=case["manifest"].binding_manifest_id,
        manifest_digest=case["manifest"].digest,
        nonce=case["context"].ledger_prefix.receipts[-1].nonce,
    )
    decision = policy.authorize_bound_action(
        case["ledger_path"], case["context"], request, case["arguments"]
    )
    assert decision.error_code == "AUTH_NONCE_REUSED"


def test_bound_action_denies_argument_digest_substitution(
    binding_gateway_case,
) -> None:
    case = binding_gateway_case
    request = _resign_v04_request(
        case["request_v04"],
        case["role_keys"]["Verifier"][0],
        judgment_id=case["judgment"].commitment_id,
        judgment_digest=case["judgment"].digest,
        manifest_id=case["manifest"].binding_manifest_id,
        manifest_digest=case["manifest"].digest,
        arguments_digest="9" * 64,
    )
    decision = policy.authorize_bound_action(
        case["ledger_path"], case["context"], request, case["arguments"]
    )
    assert decision.error_code == "ACTION_ARGUMENTS_MISMATCH"


def test_bound_action_denies_high_risk_action_without_checkpoint(
    binding_gateway_case,
) -> None:
    case = binding_gateway_case
    request = _resign_v04_request(
        case["request_v04"],
        case["role_keys"]["Manager"][0],
        judgment_id=case["judgment"].commitment_id,
        judgment_digest=case["judgment"].digest,
        manifest_id=case["manifest"].binding_manifest_id,
        manifest_digest=case["manifest"].digest,
        actor_id=case["role_keys"]["Manager"][1]["subject_id"],
        actor_key_id=case["role_keys"]["Manager"][1]["key_id"],
        grant_id=case["root"].grant_id,
        tool_name="owp.create_pr_proposal",
        arguments_digest="7" * 64,
        nonce="8" * 64,
    )
    decision = policy.authorize_bound_action(
        case["ledger_path"], case["context"], request, object()
    )
    assert decision.error_code == "AUTHORITY_CHECKPOINT_MISSING"


def test_bound_action_does_not_bypass_rollback_state_policy(
    binding_gateway_case,
) -> None:
    case = binding_gateway_case
    target = next(
        receipt
        for receipt in case["context"].ledger_prefix.receipts
        if receipt.receipt_id == case["context"].active_patch_receipt_id
    )
    expected_arguments = {
        "target_patch_receipt_id": target.receipt_id,
        "target_patch_digest": target.digest,
        "before_commit": case["context"].replay_checkpoint.head_commit,
    }
    request = _resign_v04_request(
        case["request_v04"],
        case["role_keys"]["Developer"][0],
        judgment_id=case["judgment"].commitment_id,
        judgment_digest=case["judgment"].digest,
        manifest_id=case["manifest"].binding_manifest_id,
        manifest_digest=case["manifest"].digest,
        actor_id=case["role_keys"]["Developer"][1]["subject_id"],
        actor_key_id=case["role_keys"]["Developer"][1]["key_id"],
        grant_id=case["developer"].grant_id,
        tool_name="owp.rollback_patch",
        arguments_digest=models.request_arguments_digest(
            "owp.rollback_patch", expected_arguments
        ),
        nonce="7" * 64,
    )

    decision = policy.authorize_bound_action(
        case["ledger_path"], case["context"], request, None
    )
    assert decision.allowed is False
    assert decision.error_code == "STATE_DENIED"
    legacy_entrypoint = policy.validate_rollback(case["context"], request)
    assert legacy_entrypoint.allowed is False
    assert legacy_entrypoint.error_code == "BINDING_MANIFEST_UNAVAILABLE"


@pytest.mark.parametrize(
    ("variant", "expected_error_code"),
    (
        ("uncommitted_manifest", "BINDING_MANIFEST_NOT_CURRENT"),
        ("judgment_digest", "BINDING_REFERENCE_MISMATCH"),
        ("manifest_digest", "BINDING_REFERENCE_MISMATCH"),
        ("reused_nonce", "AUTH_NONCE_REUSED"),
        ("arguments_digest", "ACTION_ARGUMENTS_MISMATCH"),
        ("wrong_action", "ACTION_OUTSIDE_APPROVED_SCOPE"),
        ("high_risk", "AUTHORITY_CHECKPOINT_MISSING"),
    ),
)
def test_rejected_v04_requests_have_zero_execution_and_zero_writes(
    binding_gateway_case,
    variant: str,
    expected_error_code: str,
) -> None:
    case = binding_gateway_case
    updates: dict[str, object] = {}
    private_key = case["role_keys"]["Verifier"][0]
    if variant == "uncommitted_manifest":
        updates["action_binding_manifest_id"] = "9" * 64
    elif variant == "judgment_digest":
        updates["judgment_commitment_digest"] = "9" * 64
    elif variant == "manifest_digest":
        updates["action_binding_manifest_digest"] = "9" * 64
    elif variant == "reused_nonce":
        updates["nonce"] = case["context"].ledger_prefix.receipts[-1].nonce
    elif variant == "arguments_digest":
        updates["arguments_digest"] = "9" * 64
    elif variant == "wrong_action":
        updates["tool_name"] = "owp.compose_proof"
    else:
        private_key = case["role_keys"]["Manager"][0]
        updates.update(
            {
                "actor_id": case["role_keys"]["Manager"][1]["subject_id"],
                "actor_key_id": case["role_keys"]["Manager"][1]["key_id"],
                "grant_id": case["root"].grant_id,
                "tool_name": "owp.create_pr_proposal",
                "arguments_digest": "7" * 64,
                "nonce": "8" * 64,
            }
        )
    request = _resign_v04_request(
        case["request_v04"],
        private_key,
        judgment_id=case["judgment"].commitment_id,
        judgment_digest=updates.pop(
            "judgment_commitment_digest", case["judgment"].digest
        ),
        manifest_id=updates.pop(
            "action_binding_manifest_id",
            case["manifest"].binding_manifest_id,
        ),
        manifest_digest=updates.pop(
            "action_binding_manifest_digest", case["manifest"].digest
        ),
        **updates,
    )
    _assert_run_tests_denied_without_side_effects(
        case,
        request=request,
        expected_error_code=expected_error_code,
    )


def test_active_manifest_rejects_legacy_downgrade_before_execution(
    binding_gateway_case,
) -> None:
    case = binding_gateway_case
    _assert_run_tests_denied_without_side_effects(
        case,
        request=case["request"],
        expected_error_code="UNSIGNED_METADATA_REFERENCE",
    )


def test_v04_management_action_is_closed_by_generic_policy(
    binding_gateway_case,
) -> None:
    case = binding_gateway_case
    arguments = ComposeProofArguments(
        expected_state_version=0,
        previous_report_digest=None,
    )
    request = _resign_v04_request(
        case["request_v04"],
        case["role_keys"]["Manager"][0],
        judgment_id=case["judgment"].commitment_id,
        judgment_digest=case["judgment"].digest,
        manifest_id=case["manifest"].binding_manifest_id,
        manifest_digest=case["manifest"].digest,
        actor_id=case["role_keys"]["Manager"][1]["subject_id"],
        actor_key_id=case["role_keys"]["Manager"][1]["key_id"],
        grant_id=case["root"].grant_id,
        tool_name="owp.compose_proof",
        arguments_digest=models.request_arguments_digest(
            "owp.compose_proof", arguments
        ),
        nonce="6" * 64,
    )

    decision = policy.authorize_tool_call(case["context"], request, arguments)
    assert decision.error_code == "BINDING_MANIFEST_UNAVAILABLE"


@pytest.mark.parametrize(
    ("expiry_field", "expected_error_code"),
    (
        ("manifest", "BINDING_MANIFEST_EXPIRED"),
        ("judgment", "BINDING_MANIFEST_EXPIRED"),
    ),
)
def test_expired_v04_authority_has_zero_execution_and_zero_writes(
    binding_gateway_case,
    expiry_field: str,
    expected_error_code: str,
) -> None:
    case = binding_gateway_case
    now = case[expiry_field].expires_at + timedelta(seconds=1)
    context = _current_run_tests_context(case, now)
    request = _resign_v04_request(
        case["request_v04"],
        case["role_keys"]["Verifier"][0],
        judgment_id=case["judgment"].commitment_id,
        judgment_digest=case["judgment"].digest,
        manifest_id=case["manifest"].binding_manifest_id,
        manifest_digest=case["manifest"].digest,
        requested_at=now.strftime("%Y-%m-%dT%H:%M:%SZ"),
    )
    _assert_run_tests_denied_without_side_effects(
        case,
        request=request,
        expected_error_code=expected_error_code,
        context=context,
        now=now,
    )


def test_superseded_manifest_has_zero_execution_and_zero_writes(
    binding_gateway_case,
) -> None:
    case = binding_gateway_case
    superseding = _signed_manifest(
        work_order=case["work_order"],
        scope=case["scope"],
        judgment=case["judgment"],
        projection=case["projection"],
        manager_key=case["role_keys"]["Manager"][0],
        manifest_id="4" * 64,
        nonce="5" * 64,
        supersedes=case["manifest"],
    )
    commit_action_binding_manifest(
        case["ledger_path"],
        superseding,
        case["profile"],
        transaction_time=case["now"],
    )

    _assert_run_tests_denied_without_side_effects(
        case,
        request=case["request_v04"],
        expected_error_code="BINDING_MANIFEST_NOT_CURRENT",
    )


def test_unknown_adapter_has_zero_execution_and_zero_writes(
    binding_gateway_case,
    monkeypatch,
) -> None:
    case = binding_gateway_case
    unknown = case["manifest"].model_copy(
        update={"adapter_id": "unknown/adapter", "adapter_version": "9"}
    )
    monkeypatch.setattr(
        binding_transactions,
        "load_current_action_binding_manifest",
        lambda *_: unknown,
    )

    _assert_run_tests_denied_without_side_effects(
        case,
        request=case["request_v04"],
        expected_error_code="ADAPTER_PROFILE_UNSUPPORTED",
    )


def test_binding_loader_failure_is_a_closed_zero_execution_denial(
    binding_gateway_case,
    monkeypatch,
) -> None:
    case = binding_gateway_case

    def fail_loader(*_):
        raise RuntimeError("unexpected loader failure")

    monkeypatch.setattr(
        binding_transactions,
        "load_current_action_binding_manifest",
        fail_loader,
    )
    _assert_run_tests_denied_without_side_effects(
        case,
        request=case["request_v04"],
        expected_error_code="BINDING_HISTORY_INVALID",
    )


def test_committed_v04_request_nonce_cannot_execute_twice(
    binding_gateway_case,
) -> None:
    case = binding_gateway_case
    mcp_server.execute_run_tests(
        case["ledger_path"],
        evidence_root=case["evidence_root"],
        context=case["context"],
        request=case["request_v04"],
        request_arguments=case["arguments"],
        execution_facts=case["facts"],
        candidate_snapshot_request=_run_tests_snapshot_request(
            case, case["evidence_root"]
        ),
        sidecar_private_key=case["role_keys"]["Sidecar"][0],
        execution_driver=_FakeRunTestsExecutionDriver(),
        clock=lambda: case["now"],
    )
    replay_time = case["now"] + timedelta(seconds=1)
    replay_context = _current_run_tests_context(case, replay_time)
    replay = _resign_v04_request(
        case["request_v04"],
        case["role_keys"]["Verifier"][0],
        judgment_id=case["judgment"].commitment_id,
        judgment_digest=case["judgment"].digest,
        manifest_id=case["manifest"].binding_manifest_id,
        manifest_digest=case["manifest"].digest,
        requested_at=replay_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
    )

    _assert_run_tests_denied_without_side_effects(
        case,
        request=replay,
        expected_error_code="AUTH_NONCE_REUSED",
        context=replay_context,
        now=replay_time,
    )


def test_started_v04_execution_closes_after_manifest_supersession(
    binding_gateway_case,
) -> None:
    case = binding_gateway_case
    contract = dataclasses.replace(
        _run_tests_contract(case),
        execution_id=mcp_server._handler_execution_id(
            case["request_v04"], case["facts"]
        ),
        request_digest=case["request_v04"].digest,
    )
    lock_descriptor = evidence._acquire_target_lock(case["ledger_path"])
    try:
        mcp_server._reserve_handler_execution(
            case["ledger_path"],
            lock_descriptor,
            case["context"],
            case["request_v04"],
            case["facts"],
            contract,
        )
        mcp_server._mark_handler_started(
            case["ledger_path"], lock_descriptor, contract.execution_id
        )
    finally:
        evidence._release_target_lock(lock_descriptor)

    superseding = _signed_manifest(
        work_order=case["work_order"],
        scope=case["scope"],
        judgment=case["judgment"],
        projection=case["projection"],
        manager_key=case["role_keys"]["Manager"][0],
        manifest_id="4" * 64,
        nonce="5" * 64,
        supersedes=case["manifest"],
        created_at=(case["now"] + timedelta(seconds=1)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
    )
    commit_action_binding_manifest(
        case["ledger_path"],
        superseding,
        case["profile"],
        transaction_time=case["now"] + timedelta(seconds=1),
    )
    driver = _FakeRunTestsExecutionDriver(
        reconciliation_outcomes=(_closed_run_tests_outcome(contract),)
    )
    recovery_time = case["now"] + timedelta(seconds=1)
    recovery_context = dataclasses.replace(
        case["context"], transaction_time=recovery_time
    )

    receipt = mcp_server.execute_run_tests(
        case["ledger_path"],
        evidence_root=case["evidence_root"],
        context=recovery_context,
        request=case["request_v04"],
        request_arguments=case["arguments"],
        execution_facts=case["facts"],
        candidate_snapshot_request=_run_tests_snapshot_request(
            case, case["evidence_root"]
        ),
        sidecar_private_key=case["role_keys"]["Sidecar"][0],
        execution_driver=driver,
        clock=lambda: recovery_time,
    )

    assert receipt.nested_claim == case["request_v04"]
    assert [call[0] for call in driver.calls] == ["reconcile", "cleanup"]


def test_committed_v04_receipt_with_stale_journal_recovers_before_replay_denial(
    binding_gateway_case,
) -> None:
    case = binding_gateway_case
    first_driver = _FakeRunTestsExecutionDriver(
        cleanup_error=RuntimeError("injected cleanup failure")
    )
    with pytest.raises(
        mcp_server.HandlerCoordinationError, match="RECOVERY_REQUIRED"
    ):
        mcp_server.execute_run_tests(
            case["ledger_path"],
            evidence_root=case["evidence_root"],
            context=case["context"],
            request=case["request_v04"],
            request_arguments=case["arguments"],
            execution_facts=case["facts"],
            candidate_snapshot_request=_run_tests_snapshot_request(
                case, case["evidence_root"]
            ),
            sidecar_private_key=case["role_keys"]["Sidecar"][0],
            execution_driver=first_driver,
            clock=lambda: case["now"],
        )

    current_context = _current_run_tests_context(case, case["now"])
    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        before = connection.execute(
            "SELECT COUNT(*) FROM receipts"
        ).fetchone()
        assert connection.execute(
            "SELECT state FROM handler_executions"
        ).fetchone() == ("STARTED_UNCONFIRMED",)
    finally:
        connection.close()
    recovery_driver = _FakeRunTestsExecutionDriver(
        reconciliation_outcomes=(
            repo_tools.RunTestsExecutionOutcome("CLOSED_RESULT", None),
        )
    )

    with pytest.raises(mcp_server.ToolCallDenied) as captured:
        mcp_server.execute_run_tests(
            case["ledger_path"],
            evidence_root=case["evidence_root"],
            context=current_context,
            request=case["request_v04"],
            request_arguments=case["arguments"],
            execution_facts=case["facts"],
            candidate_snapshot_request=_run_tests_snapshot_request(
                case, case["evidence_root"]
            ),
            sidecar_private_key=case["role_keys"]["Sidecar"][0],
            execution_driver=recovery_driver,
            clock=lambda: case["now"],
        )

    assert captured.value.decision.error_code == "AUTH_NONCE_REUSED"
    assert [call[0] for call in recovery_driver.calls] == ["reconcile"]
    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM handler_executions"
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT COUNT(*) FROM receipts"
        ).fetchone() == before
    finally:
        connection.close()


def test_forged_stored_v04_binding_is_rejected_before_reconcile(
    binding_gateway_case,
) -> None:
    case = binding_gateway_case
    forged = _resign_v04_request(
        case["request_v04"],
        case["role_keys"]["Verifier"][0],
        judgment_id="8" * 64,
        judgment_digest="9" * 64,
        manifest_id="6" * 64,
        manifest_digest="7" * 64,
    )
    contract = dataclasses.replace(
        _run_tests_contract(case),
        execution_id=mcp_server._handler_execution_id(forged, case["facts"]),
        request_digest=forged.digest,
    )
    lock_descriptor = evidence._acquire_target_lock(case["ledger_path"])
    try:
        mcp_server._reserve_handler_execution(
            case["ledger_path"],
            lock_descriptor,
            case["context"],
            forged,
            case["facts"],
            contract,
        )
        mcp_server._mark_handler_started(
            case["ledger_path"], lock_descriptor, contract.execution_id
        )
    finally:
        evidence._release_target_lock(lock_descriptor)
    driver = _FakeRunTestsExecutionDriver(
        reconciliation_outcomes=(_closed_run_tests_outcome(contract),)
    )

    with pytest.raises(
        mcp_server.HandlerCoordinationError, match="RECOVERY_REQUIRED"
    ):
        mcp_server.execute_run_tests(
            case["ledger_path"],
            evidence_root=case["evidence_root"],
            context=case["context"],
            request=case["request_v04"],
            request_arguments=case["arguments"],
            execution_facts=case["facts"],
            candidate_snapshot_request=_run_tests_snapshot_request(
                case, case["evidence_root"]
            ),
            sidecar_private_key=case["role_keys"]["Sidecar"][0],
            execution_driver=driver,
            clock=lambda: case["now"],
        )

    assert driver.calls == []


def test_v04_receipt_preserves_native_request_and_signature_binding(
    binding_gateway_case,
    public_keys,
) -> None:
    case = binding_gateway_case
    driver = _FakeRunTestsExecutionDriver()
    receipt = mcp_server.execute_run_tests(
        case["ledger_path"],
        evidence_root=case["evidence_root"],
        context=case["context"],
        request=case["request_v04"],
        request_arguments=case["arguments"],
        execution_facts=case["facts"],
        candidate_snapshot_request=_run_tests_snapshot_request(
            case, case["evidence_root"]
        ),
        sidecar_private_key=case["role_keys"]["Sidecar"][0],
        execution_driver=driver,
        clock=lambda: case["now"],
    )
    assert type(receipt.nested_claim) is AgentRequestV04
    assert receipt.nested_claim.action_binding_manifest_digest == (
        case["manifest"].digest
    )
    assert verify_nested_claim(receipt.nested_claim, case["work_order"])
    assert state._validate_action_receipt(
        receipt,
        case["work_order"],
        public_keys,
        case["now"],
    ) == receipt
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(
            receipt.model_dump(mode="json"),
            models.ACTION_RECEIPT_ADAPTER.json_schema(),
        )
    jsonschema.validate(
        receipt.model_dump(mode="json"),
        models.ACTION_RECEIPT_V04_ADAPTER.json_schema(),
    )

    attacked = receipt.model_dump(mode="json")
    attacked["nested_claim"]["signature"] = "A" * 86
    attacked = sign_payload(
        "action-receipt",
        attacked,
        case["role_keys"]["Sidecar"][0],
        version="0.4",
    )
    attacked_receipt = models.ACTION_RECEIPT_V04_ADAPTER.validate_python(
        attacked
    )
    assert verify_nested_claim(
        attacked_receipt.nested_claim, case["work_order"]
    ) is False
    assert state._validate_action_receipt(
        attacked_receipt,
        case["work_order"],
        public_keys,
        case["now"],
    ) is None

    substituted_request = _resign_v04_request(
        receipt.nested_claim,
        case["role_keys"]["Verifier"][0],
        judgment_id=case["judgment"].commitment_id,
        judgment_digest=case["judgment"].digest,
        manifest_id=case["manifest"].binding_manifest_id,
        manifest_digest="9" * 64,
    )
    assert substituted_request.digest != receipt.nested_claim.digest
    substituted_outer = receipt.model_dump(mode="json")
    substituted_outer["nested_claim"] = substituted_request.model_dump(
        mode="json"
    )
    substituted_outer["nested_claim_digest"] = substituted_request.digest
    substituted_outer = sign_payload(
        "action-receipt",
        substituted_outer,
        case["role_keys"]["Sidecar"][0],
        version="0.4",
    )
    substituted_outer["signature"] = receipt.signature
    substituted_receipt = models.ACTION_RECEIPT_V04_ADAPTER.validate_python(
        substituted_outer
    )
    assert not verify_payload(
        "action-receipt",
        substituted_receipt.model_dump(mode="json"),
        case["role_keys"]["Sidecar"][0].public_key(),
        version="0.4",
    )


def test_v04_binding_denial_can_be_recorded_with_closed_error_code(
    binding_gateway_case,
) -> None:
    case = binding_gateway_case
    decision = policy.authorize_tool_call(
        case["context"],
        case["request_v04"],
        case["arguments"],
        case["facts"],
    )

    receipt = mcp_server.produce_deny_receipt(
        case["ledger_path"],
        evidence_root=case["evidence_root"],
        context=case["context"],
        request=case["request_v04"],
        arguments=case["arguments"],
        execution_facts=case["facts"],
        sidecar_private_key=case["role_keys"]["Sidecar"][0],
        decision=decision,
        clock=lambda: case["now"],
    )

    assert type(receipt) is models.ToolCallReceiptV04
    assert receipt.protocol_version == "0.4"
    assert receipt.policy_error_code == "BINDING_MANIFEST_UNAVAILABLE"


def test_legacy_request_schema_signing_bytes_and_nested_replay_are_frozen(
    binding_gateway_case,
) -> None:
    case = binding_gateway_case
    legacy = case["request"]
    payload = legacy.model_dump(mode="json")

    assert hashlib.sha256(
        rfc8785.dumps(models.ACTION_RECEIPT_ADAPTER.json_schema())
    ).hexdigest() == (
        "1aba0e2a9cf3b55478d5def0ef7f89d84976fc22798bb6d709d21afb31cedde8"
    )
    assert canonical_bytes("agent-request", payload) == canonical_bytes(
        "agent-request", payload, version="0.1"
    )
    assert verify_nested_claim(legacy, case["work_order"])


def test_legacy_state_replay_still_requires_actor_trust_key(
    binding_gateway_case,
    public_keys,
) -> None:
    case = binding_gateway_case
    legacy_receipt = next(
        receipt
        for receipt in case["context"].ledger_prefix.receipts
        if receipt.actor_type == "agent"
    )
    missing_actor_key = dict(public_keys)
    missing_actor_key.pop(legacy_receipt.actor_key_id)

    assert state._validate_action_receipt(
        legacy_receipt,
        case["work_order"],
        missing_actor_key,
        case["now"],
    ) is None

    substituted_actor_key = dict(public_keys)
    substituted_actor_key[legacy_receipt.actor_key_id] = (
        case["role_keys"]["Developer"][0].public_key()
    )
    assert state._validate_action_receipt(
        legacy_receipt,
        case["work_order"],
        substituted_actor_key,
        case["now"],
    ) is None


def test_legacy_request_allowed_when_v04_binding_tables_absent(
    binding_gateway_case,
) -> None:
    """A pre-v0.4 ledger (no binding tables) must not deny legacy requests.

    Regression: a legacy account lacking action_binding_manifests_v04 used
    to surface sqlite3.OperationalError which was misclassified as
    BINDING_HISTORY_INVALID, breaking v0.1-v0.3 compatibility.
    """
    case = binding_gateway_case
    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        connection.execute(
            "DROP TABLE IF EXISTS action_binding_manifest_parents_v04"
        )
        connection.execute(
            "DROP TABLE IF EXISTS action_binding_manifests_v04"
        )
        connection.commit()
    finally:
        connection.close()
    decision = policy.authorize_bound_action(
        case["ledger_path"],
        case["context"],
        case["request"],
        case["arguments"],
        case["facts"],
    )
    assert decision.allowed is True
    assert decision.error_code is None


@pytest.mark.parametrize(
    ("message", "expected_code"),
    [
        ("rollback request signature is invalid", "AUTH_SIGNATURE_INVALID"),
        (
            "rollback request is outside the freshness window",
            "AUTH_FRESHNESS_INVALID",
        ),
        (
            "rollback request Grant or actor binding is invalid",
            "AUTH_SUBJECT_MISMATCH",
        ),
        ("rollback target patch is unavailable", "ACTION_ARGUMENTS_MISMATCH"),
        ("rollback target binding is invalid", "ACTION_ARGUMENTS_MISMATCH"),
        (
            "contract expired before rollback authorization",
            "CAPABILITY_DENIED",
        ),
        ("rollback authorization inputs are malformed", "ACTION_ARGUMENTS_MISMATCH"),
    ],
)
def test_bound_action_rollback_failure_maps_to_closed_code(
    message,
    expected_code,
) -> None:
    """v0.4 rollback failures must map to their design reason codes (§9)."""
    from openworkproof.policy import _bound_authorization_error_code

    assert (
        _bound_authorization_error_code(
            policy.AuthorizationPolicyError(message)
        )
        == expected_code
    )


def test_produce_deny_receipt_legacy_binding_code_fails_loudly(
    binding_gateway_case,
) -> None:
    """A legacy binding-denial code must never crash with ValidationError.

    produce_deny_receipt is a public audit API; when a legacy request is
    denied by the binding gate (e.g. UNSIGNED_METADATA_REFERENCE), the code
    is not representable in the v0.1 Literal. The API must fail loudly with
    ToolCallDenied, not leak a pydantic ValidationError.
    """
    case = binding_gateway_case
    decision = models.PolicyDecision(
        allowed=False,
        decision="deny",
        error_code="UNSIGNED_METADATA_REFERENCE",
        reason="BOUND_ACTION_DENIED",
    )
    with pytest.raises(mcp_server.ToolCallDenied):
        mcp_server.produce_deny_receipt(
            case["ledger_path"],
            evidence_root=case["evidence_root"],
            context=case["context"],
            request=case["request"],
            arguments=case["arguments"],
            execution_facts=case["facts"],
            sidecar_private_key=case["role_keys"]["Sidecar"][0],
            decision=decision,
            clock=lambda: case["now"],
        )
