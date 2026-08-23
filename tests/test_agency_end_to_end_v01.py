"""End-to-end coverage for the human agency executor seam.

These tests exercise the opt-in ``agency_authorize`` callback on the three
protected executors, not the final dispatcher. They prove the seam that a
dispatcher will later plug into:

* a reserved or not-delegated decision raises ``ToolCallDenied`` before any
  handler call and leaves every user table byte-for-byte unchanged;
* an allow decision reaches the handler exactly once;
* the default ``None`` keeps legacy execution unchanged;
* the callback is validated fail-closed;
* an Acceptor transition commit deterministically waits while the executor
  callback holds the target lock, and the next protected call observes the
  revocation (no sleep-based winner).
"""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path
from typing import Any

import pytest

import openworkproof.mcp_server as mcp_server
from openworkproof.agency import (
    AgencyProfileTransitionV01,
    HumanAgencyProfileV01,
    agency_profile_transition_id,
    delegated_action_id,
    human_agency_profile_id,
    reserved_decision_id,
)
from openworkproof.agency_ledger import (
    commit_agency_profile_transition,
    commit_human_agency_profile,
    load_agency_history,
)
from openworkproof.agency_policy import (
    AGENCY_ACTION_NOT_DELEGATED,
    AGENCY_HUMAN_DECISION_REQUIRED,
    authorize_agency_profile_layer,
)
from openworkproof.models import WorkOrder
from openworkproof.signing import sign_payload

from conftest import SHA256_A, SHA256_D
from test_mcp_server import (
    _FakeRunTestsExecutionDriver,
    _current_run_tests_context,
    _run_tests_case,
    _run_tests_snapshot_request,
)
from test_repo_read_transaction import (
    _read_handler,
    _repo_read_request,
    _repo_read_success_case,
)

# The fixed_now fixture from conftest is 2026-01-01T00:00:05Z. Profiles below
# are valid from 00:00:01Z through 23:59:59Z, so they are active at fixed_now.
_PROFILE_VALID_FROM = "2026-01-01T00:00:01Z"
_PROFILE_EXPIRES_AT = "2026-01-01T23:59:59Z"
_PROFILE_ISSUED_AT = "2026-01-01T00:00:00Z"


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
    work_order: WorkOrder,
    keys,
    nonce: str,
    *,
    delegated: tuple[str, ...] = (),
    reserved: tuple[tuple[str, tuple[str, ...]], ...] = (),
) -> HumanAgencyProfileV01:
    payload = {
        "schema_version": "openworkproof-human-agency-profile/0.1",
        "work_order_digest": work_order.digest,
        "delegated_actions": [_delegated(tool) for tool in delegated],
        "reserved_decisions": [
            _reserved(kind, blocked) for kind, blocked in reserved
        ],
        "escalation_conditions": [
            {"condition_code": "reserved_decision_requested"}
        ],
        "revocation_and_appeal": {
            "revocation_mode": "acceptor_signed_transition",
            "appeal_mode": "signed_request_then_acceptor_decision",
            "appeal_roles": ["Developer", "Manager", "Verifier"],
        },
        "valid_from": _PROFILE_VALID_FROM,
        "expires_at": _PROFILE_EXPIRES_AT,
        "issued_at": _PROFILE_ISSUED_AT,
        "nonce": nonce,
    }
    payload["profile_id"] = human_agency_profile_id(payload)
    return HumanAgencyProfileV01.model_validate(
        sign_payload("human-agency-profile", payload, keys["Acceptor"][0])
    )


def _mk_transition(
    work_order: WorkOrder,
    keys,
    *,
    target: HumanAgencyProfileV01,
    transition: str = "revoked",
    replacement: HumanAgencyProfileV01 | None = None,
) -> AgencyProfileTransitionV01:
    payload = {
        "schema_version": "openworkproof-agency-profile-transition/0.1",
        "work_order_digest": work_order.digest,
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
        sign_payload("agency-profile-transition", payload, keys["Acceptor"][0])
    )


def _all_user_table_snapshot(path: Path) -> dict[str, tuple[tuple[object, ...], ...]]:
    connection = sqlite3.connect(path)
    try:
        names = tuple(
            row[0]
            for row in connection.execute(
                """
                SELECT name FROM sqlite_master
                WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
                ORDER BY name
                """
            )
        )
        return {
            name: tuple(connection.execute(f'SELECT * FROM "{name}"'))
            for name in names
        }
    finally:
        connection.close()


def _agency_authorize(ledger_path: Path, context, request):
    """A lazy callback: history is loaded only inside the executor lock."""

    work_order_digest = context.work_order.digest

    def callback():
        history = load_agency_history(ledger_path, work_order_digest)
        return authorize_agency_profile_layer(context, history, request)

    return callback


def _counting_handler(manifest_digest: str):
    calls: list[object] = []
    inner = _read_handler(manifest_digest)

    def handler(command):
        calls.append(command)
        return inner(command)

    return handler, calls


# --- repo-read: reserved deny is fail-closed with zero handler calls ---


def test_repo_read_reserved_deny_has_zero_handler_calls_and_no_writes(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
) -> None:
    case, context = _repo_read_success_case(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        sidecar_receipt_factory,
        fixed_now,
        monkeypatch,
    )
    profile = _mk_profile(
        case["work_order"],
        ephemeral_role_keys,
        SHA256_A,
        delegated=("owp.run_tests",),
        reserved=(("scope_or_criteria_change", ("owp.repo_read",)),),
    )
    commit_human_agency_profile(case["ledger_path"], profile)
    request, arguments = _repo_read_request(
        case, context, ephemeral_role_keys, fixed_now, path="src/app.py"
    )
    manifest_digest = context.replay_checkpoint.workspace_manifest_digest
    handler, calls = _counting_handler(manifest_digest)

    before = _all_user_table_snapshot(case["ledger_path"])
    with pytest.raises(mcp_server.ToolCallDenied) as caught:
        mcp_server.execute_repo_read(
            case["ledger_path"],
            evidence_root=case["evidence_root"],
            context=context,
            request=request,
            request_arguments=arguments,
            execution_facts=case["facts"],
            sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
            candidate_runtime_root=tmp_path,
            handler=handler,
            clock=lambda: fixed_now,
            agency_authorize=_agency_authorize(
                case["ledger_path"], context, request
            ),
        )
    assert caught.value.decision.error_code == AGENCY_HUMAN_DECISION_REQUIRED
    assert calls == []
    assert _all_user_table_snapshot(case["ledger_path"]) == before


# --- run-tests: not-delegated deny is fail-closed with zero driver calls ---


def test_run_tests_not_delegated_deny_has_zero_driver_calls_and_no_writes(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
) -> None:
    case = _run_tests_case(
        tmp_path=tmp_path,
        signed_work_order=signed_work_order,
        role_keys=ephemeral_role_keys,
        sidecar_receipt_factory=sidecar_receipt_factory,
        now=fixed_now,
    )
    profile = _mk_profile(
        case["work_order"],
        ephemeral_role_keys,
        SHA256_A,
        delegated=("owp.repo_read",),
    )
    commit_human_agency_profile(case["ledger_path"], profile)
    driver = _FakeRunTestsExecutionDriver()

    before = _all_user_table_snapshot(case["ledger_path"])
    with pytest.raises(mcp_server.ToolCallDenied) as caught:
        mcp_server.execute_run_tests(
            case["ledger_path"],
            evidence_root=case["evidence_root"],
            context=case["context"],
            request=case["request"],
            request_arguments=case["arguments"],
            execution_facts=case["facts"],
            candidate_snapshot_request=_run_tests_snapshot_request(
                case, tmp_path.resolve()
            ),
            sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
            execution_driver=driver,
            clock=lambda: fixed_now,
            agency_authorize=_agency_authorize(
                case["ledger_path"], case["context"], case["request"]
            ),
        )
    assert caught.value.decision.error_code == AGENCY_ACTION_NOT_DELEGATED
    assert driver.calls == []
    assert _all_user_table_snapshot(case["ledger_path"]) == before


# --- allow reaches the handler exactly once ---


def test_repo_read_allow_reaches_handler(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
) -> None:
    case, context = _repo_read_success_case(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        sidecar_receipt_factory,
        fixed_now,
        monkeypatch,
    )
    profile = _mk_profile(
        case["work_order"],
        ephemeral_role_keys,
        SHA256_A,
        delegated=("owp.repo_read",),
    )
    commit_human_agency_profile(case["ledger_path"], profile)
    request, arguments = _repo_read_request(
        case, context, ephemeral_role_keys, fixed_now, path="src/app.py"
    )
    manifest_digest = context.replay_checkpoint.workspace_manifest_digest
    handler, calls = _counting_handler(manifest_digest)

    receipt = mcp_server.execute_repo_read(
        case["ledger_path"],
        evidence_root=case["evidence_root"],
        context=context,
        request=request,
        request_arguments=arguments,
        execution_facts=case["facts"],
        sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
        candidate_runtime_root=tmp_path,
        handler=handler,
        clock=lambda: fixed_now,
        agency_authorize=_agency_authorize(
            case["ledger_path"], context, request
        ),
    )
    assert receipt.policy_decision == "allow"
    assert receipt.execution_status == "succeeded"
    assert len(calls) == 1


# --- default None regression: legacy path ignores any committed profile ---


def test_default_none_preserves_legacy_execution(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
) -> None:
    case, context = _repo_read_success_case(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        sidecar_receipt_factory,
        fixed_now,
        monkeypatch,
    )
    # A profile that would reserve repo_read if the seam were active.
    profile = _mk_profile(
        case["work_order"],
        ephemeral_role_keys,
        SHA256_A,
        delegated=("owp.run_tests",),
        reserved=(("scope_or_criteria_change", ("owp.repo_read",)),),
    )
    commit_human_agency_profile(case["ledger_path"], profile)
    request, arguments = _repo_read_request(
        case, context, ephemeral_role_keys, fixed_now, path="src/app.py"
    )
    manifest_digest = context.replay_checkpoint.workspace_manifest_digest
    handler, calls = _counting_handler(manifest_digest)

    receipt = mcp_server.execute_repo_read(
        case["ledger_path"],
        evidence_root=case["evidence_root"],
        context=context,
        request=request,
        request_arguments=arguments,
        execution_facts=case["facts"],
        sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
        candidate_runtime_root=tmp_path,
        handler=handler,
        clock=lambda: fixed_now,
    )
    assert receipt.policy_decision == "allow"
    assert len(calls) == 1


# --- callback return type is validated fail-closed ---


def test_invalid_callback_return_type_fails_closed(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
) -> None:
    case, context = _repo_read_success_case(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        sidecar_receipt_factory,
        fixed_now,
        monkeypatch,
    )
    request, arguments = _repo_read_request(
        case, context, ephemeral_role_keys, fixed_now, path="src/app.py"
    )
    manifest_digest = context.replay_checkpoint.workspace_manifest_digest
    handler, calls = _counting_handler(manifest_digest)

    before = _all_user_table_snapshot(case["ledger_path"])
    with pytest.raises(
        mcp_server.HandlerCoordinationError, match="agency authorization"
    ):
        mcp_server.execute_repo_read(
            case["ledger_path"],
            evidence_root=case["evidence_root"],
            context=context,
            request=request,
            request_arguments=arguments,
            execution_facts=case["facts"],
            sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
            candidate_runtime_root=tmp_path,
            handler=handler,
            clock=lambda: fixed_now,
            agency_authorize=lambda: "allow",
        )
    assert calls == []
    assert _all_user_table_snapshot(case["ledger_path"]) == before


# --- deterministic revocation race without a sleep-based winner ---


def test_acceptor_revocation_waits_for_executor_lock_and_next_call_sees_it(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
) -> None:
    case, context = _repo_read_success_case(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        sidecar_receipt_factory,
        fixed_now,
        monkeypatch,
    )
    profile = _mk_profile(
        case["work_order"],
        ephemeral_role_keys,
        SHA256_A,
        delegated=("owp.repo_read",),
    )
    commit_human_agency_profile(case["ledger_path"], profile)
    revoke = _mk_transition(
        case["work_order"],
        ephemeral_role_keys,
        target=profile,
        transition="revoked",
    )
    request, arguments = _repo_read_request(
        case, context, ephemeral_role_keys, fixed_now, path="src/app.py"
    )
    manifest_digest = context.replay_checkpoint.workspace_manifest_digest
    handler, calls = _counting_handler(manifest_digest)

    entered = threading.Event()
    proceed = threading.Event()
    commit_started = threading.Event()
    commit_finished = threading.Event()
    executor_outcome: dict[str, object] = {}

    def agency_authorize_hold():
        # The executor already holds the target lock when this runs.
        entered.set()
        assert proceed.wait(timeout=20)
        history = load_agency_history(
            case["ledger_path"], case["work_order"].digest
        )
        return authorize_agency_profile_layer(context, history, request)

    def run_executor():
        try:
            executor_outcome["receipt"] = mcp_server.execute_repo_read(
                case["ledger_path"],
                evidence_root=case["evidence_root"],
                context=context,
                request=request,
                request_arguments=arguments,
                execution_facts=case["facts"],
                sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
                candidate_runtime_root=tmp_path,
                handler=handler,
                clock=lambda: fixed_now,
                agency_authorize=agency_authorize_hold,
            )
        except Exception as error:  # pragma: no cover - diagnostic only
            executor_outcome["error"] = error

    def run_revocation():
        commit_started.set()
        commit_agency_profile_transition(case["ledger_path"], revoke)
        commit_finished.set()

    executor_thread = threading.Thread(target=run_executor)
    executor_thread.start()
    assert entered.wait(timeout=20)
    revocation_thread = threading.Thread(target=run_revocation)
    revocation_thread.start()
    assert commit_started.wait(timeout=20)

    # The executor callback still holds the target lock, so the Acceptor
    # transition commit cannot have completed. This is deterministic: the
    # commit needs the same target lock the callback is holding.
    assert not commit_finished.is_set()

    proceed.set()
    executor_thread.join(timeout=20)
    revocation_thread.join(timeout=20)

    assert "error" not in executor_outcome
    receipt = executor_outcome["receipt"]
    assert receipt is not None
    assert getattr(receipt, "policy_decision", None) == "allow"
    assert len(calls) == 1
    assert commit_finished.is_set()

    # The next protected call re-derives current context and observes the
    # revocation: no active profile remains, so it is denied before the handler.
    context_after = _current_run_tests_context(case, fixed_now)
    request_after, arguments_after = _repo_read_request(
        case,
        context_after,
        ephemeral_role_keys,
        fixed_now,
        path="src/app.py",
        nonce_label="repo-read:after-revocation",
    )
    after_handler, after_calls = _counting_handler(
        context_after.replay_checkpoint.workspace_manifest_digest
    )
    with pytest.raises(mcp_server.ToolCallDenied) as caught:
        mcp_server.execute_repo_read(
            case["ledger_path"],
            evidence_root=case["evidence_root"],
            context=context_after,
            request=request_after,
            request_arguments=arguments_after,
            execution_facts=case["facts"],
            sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
            candidate_runtime_root=tmp_path,
            handler=after_handler,
            clock=lambda: fixed_now,
            agency_authorize=_agency_authorize(
                case["ledger_path"], context_after, request_after
            ),
        )
    assert caught.value.decision.error_code == "AGENCY_PROFILE_REQUIRED"
    assert after_calls == []
