"""End-to-end coverage for the human agency executor seam.

These tests exercise the opt-in ``agency_authorize`` callback on the three
protected executors, not the final dispatcher. They prove the seam that a
dispatcher will later plug into:

* a reserved or not-delegated decision raises ``ToolCallDenied`` before any
  handler call and leaves every user table byte-for-byte unchanged;
* an allow decision reaches the handler exactly once and invokes the agency
  callback exactly once;
* a rollback reserved deny leaves the handler uncalled and the business
  snapshot unchanged, while an allow reaches the handler once;
* the default ``None`` keeps legacy execution unchanged;
* the callback is validated fail-closed;
* an Acceptor transition commit deterministically waits while the executor
  callback holds the target lock, and the next protected call observes the
  revocation (no sleep-based winner);
* a denied brand-new run-tests leaves the handler execution journal empty and
  never calls the driver;
* a denied repo-read or rollback over a provably stale RESERVED journal row
  performs only the intended recovery cleanup (C) before denying, with no new
  handler/receipt/business execution.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import sqlite3
import threading
from pathlib import Path
from typing import Any

import pytest
import rfc8785

import openworkproof.evidence as evidence
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
from openworkproof.signing import key_id, sign_payload

from conftest import SHA256_A, SHA256_D
from test_mcp_server import (
    _FakeRunTestsExecutionDriver,
    _closed_run_tests_outcome,
    _current_run_tests_context,
    _rollback_case,
    _run_tests_case,
    _run_tests_contract,
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


@pytest.fixture(autouse=True)
def _stub_candidate_execution_snapshot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Stub candidate snapshot preparation for rollback seam coverage.

    ``_rollback_case`` runs a full run-tests execution before building the
    rollback request; this mirrors test_mcp_server's autouse snapshot stub so
    that preparation succeeds without touching the real filesystem.
    """

    from openworkproof import repo_tools

    def prepare(request):
        return repo_tools.CandidateExecutionSnapshot(
            head_commit=request.expected_head_commit,
            workspace_manifest_digest=(
                request.expected_workspace_manifest_digest
            ),
            plan=repo_tools.ExecutionSnapshotPlan(
                files=(),
                read_only=True,
                owner_uid=65532,
                owner_gid=65532,
                atime_unix_seconds=0,
                mtime_unix_seconds=0,
                clear_extended_attributes=True,
                clear_posix_acls=True,
                clear_file_capabilities=True,
            ),
        )

    monkeypatch.setattr(
        repo_tools,
        "prepare_candidate_execution_snapshot",
        prepare,
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


def _counting_agency_authorize(ledger_path: Path, context, request):
    """Wrap the lazy agency callback with an invocation counter."""

    invocations: list[object] = []
    inner = _agency_authorize(ledger_path, context, request)

    def callback():
        invocations.append(True)
        return inner()

    return callback, invocations


def _counting_handler(manifest_digest: str):
    calls: list[object] = []
    inner = _read_handler(manifest_digest)

    def handler(command):
        calls.append(command)
        return inner(command)

    return handler, calls


def _reserve_stale_handler_execution(case, context, request) -> None:
    """Reserve a provably stale RESERVED row through the production seam.

    The row has no matching receipt, so the pre-agency recovery boundary must
    clean it up without executing a handler or writing business state.
    """

    lock_descriptor = evidence._acquire_target_lock(case["ledger_path"])
    try:
        mcp_server._reserve_handler_execution(
            case["ledger_path"],
            lock_descriptor,
            context,
            request,
            case["facts"],
            None,
        )
    finally:
        evidence._release_target_lock(lock_descriptor)


def _reserve_run_tests_execution_bound(
    case,
    *,
    agency_bound: bool,
    sidecar_private_key=None,
    started: bool = False,
):
    """Reserve a run-tests execution through the production seam with an
    explicit agency binding."""
    contract = _run_tests_contract(case)
    lock_descriptor = evidence._acquire_target_lock(case["ledger_path"])
    try:
        mcp_server._reserve_handler_execution(
            case["ledger_path"],
            lock_descriptor,
            case["context"],
            case["request"],
            case["facts"],
            contract,
            agency_bound=agency_bound,
            sidecar_private_key=sidecar_private_key,
        )
        if started:
            mcp_server._mark_handler_started(
                case["ledger_path"],
                lock_descriptor,
                contract.execution_id,
            )
    finally:
        evidence._release_target_lock(lock_descriptor)
    return contract


def _stored_agency_binding_json(path: Path) -> str:
    connection = evidence.connect_ledger(path)
    try:
        row = connection.execute(
            "SELECT agency_binding_json FROM handler_executions"
        ).fetchone()
        return row[0]
    finally:
        connection.close()


def _overwrite_agency_binding_json(path: Path, value: str) -> None:
    connection = evidence.connect_ledger(path)
    try:
        connection.execute(
            "UPDATE handler_executions SET agency_binding_json = ?",
            (value,),
        )
    finally:
        connection.close()


def _agency_prefix_digest(case) -> str:
    return mcp_server._authorization_prefix_digest(
        case["context"].ledger_prefix,
        domain=mcp_server._AGENCY_AUTHORIZATION_PREFIX_DOMAIN,
    )


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
    # Recovery boundary: a denied brand-new run-tests leaves the handler
    # execution journal empty (no RESERVED/STARTED_UNCONFIRMED residue).
    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM handler_executions"
        ).fetchone() == (0,)
    finally:
        connection.close()


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
    agency_authorize, invocations = _counting_agency_authorize(
        case["ledger_path"], context, request
    )

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
        agency_authorize=agency_authorize,
    )
    assert receipt.policy_decision == "allow"
    assert receipt.execution_status == "succeeded"
    assert len(calls) == 1
    assert len(invocations) == 1


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
    revoker_reached_acquire = threading.Event()
    commit_finished = threading.Event()
    executor_outcome: dict[str, object] = {}
    revocation_outcome: dict[str, object] = {}

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
        try:
            # The revoker itself observes nonblocking flock failure before
            # signaling, proving the executor still holds the target lock, and
            # only then enters the real blocking acquire.
            probe_fd = os.open(
                evidence._target_lock_path(case["ledger_path"]),
                os.O_RDWR | os.O_CREAT,
                0o600,
            )
            try:
                try:
                    fcntl.flock(probe_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    revoker_reached_acquire.set()
                else:
                    fcntl.flock(probe_fd, fcntl.LOCK_UN)
                    revocation_outcome["error"] = AssertionError(
                        "revoker observed no target-lock contention"
                    )
                    return
            finally:
                os.close(probe_fd)
            commit_agency_profile_transition(case["ledger_path"], revoke)
        except Exception as error:  # pragma: no cover - diagnostic only
            revocation_outcome["error"] = error
        finally:
            commit_finished.set()

    executor_thread = threading.Thread(target=run_executor, name="executor")
    executor_thread.start()
    assert entered.wait(timeout=20)

    revocation_thread = threading.Thread(target=run_revocation, name="revoker")
    revocation_thread.start()
    assert revoker_reached_acquire.wait(timeout=20)

    # The revoker observed its own nonblocking flock fail and signaled before
    # entering the real blocking acquire, while the executor callback still
    # holds the same target lock, so the Acceptor transition commit cannot
    # have completed. Deterministic: no sleeps and no thread-start-only signal.
    assert not commit_finished.is_set()

    proceed.set()
    executor_thread.join(timeout=20)
    revocation_thread.join(timeout=20)

    assert "error" not in executor_outcome
    assert "error" not in revocation_outcome
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


# --- rollback seam: reserved deny / allow reach the handler correctly ---


def _rollback_failed_result(case):
    before = case["context"].replay_checkpoint.head_commit
    manifest = case["context"].replay_checkpoint.workspace_manifest_digest
    return mcp_server.RollbackHandlerResult(
        execution_status="failed",
        before_commit=before,
        after_commit=before,
        after_manifest_digest=manifest,
    )


def test_rollback_reserved_deny_has_zero_handler_calls_and_no_writes(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
) -> None:
    case = _rollback_case(
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
        delegated=("owp.run_tests",),
        reserved=(("scope_or_criteria_change", ("owp.rollback_patch",)),),
    )
    commit_human_agency_profile(case["ledger_path"], profile)
    calls: list[object] = []

    def handler(command):
        calls.append(command)
        return _rollback_failed_result(case)

    before = _all_user_table_snapshot(case["ledger_path"])
    with pytest.raises(mcp_server.ToolCallDenied) as caught:
        mcp_server.execute_rollback(
            case["ledger_path"],
            evidence_root=case["evidence_root"],
            context=case["context"],
            request=case["request"],
            execution_facts=case["facts"],
            sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
            handler=handler,
            clock=lambda: fixed_now,
            agency_authorize=_agency_authorize(
                case["ledger_path"], case["context"], case["request"]
            ),
        )
    assert caught.value.decision.error_code == AGENCY_HUMAN_DECISION_REQUIRED
    assert calls == []
    assert _all_user_table_snapshot(case["ledger_path"]) == before


def test_rollback_allow_reaches_handler_once_and_callback_once(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
) -> None:
    case = _rollback_case(
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
        delegated=("owp.rollback_patch",),
    )
    commit_human_agency_profile(case["ledger_path"], profile)
    calls: list[object] = []
    agency_authorize, invocations = _counting_agency_authorize(
        case["ledger_path"], case["context"], case["request"]
    )

    def handler(command):
        calls.append(command)
        return _rollback_failed_result(case)

    receipt = mcp_server.execute_rollback(
        case["ledger_path"],
        evidence_root=case["evidence_root"],
        context=case["context"],
        request=case["request"],
        execution_facts=case["facts"],
        sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
        handler=handler,
        clock=lambda: fixed_now,
        agency_authorize=agency_authorize,
    )
    assert receipt.execution_status == "failed"
    assert len(calls) == 1
    assert len(invocations) == 1


# --- run-tests allow reaches the driver exactly once and the callback once ---


def test_run_tests_allow_reaches_driver_once_and_callback_once(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
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
        delegated=("owp.run_tests",),
    )
    commit_human_agency_profile(case["ledger_path"], profile)
    driver = _FakeRunTestsExecutionDriver()
    agency_authorize, invocations = _counting_agency_authorize(
        case["ledger_path"], case["context"], case["request"]
    )

    receipt = mcp_server.execute_run_tests(
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
        agency_authorize=agency_authorize,
    )
    assert receipt.policy_decision == "allow"
    assert [call[0] for call in driver.calls] == [
        "prepare",
        "start_and_wait",
        "cleanup",
    ]
    assert len(invocations) == 1


# --- recovery boundary: stale RESERVED journal rows are cleaned, not executed ---


def test_repo_read_denied_with_stale_reserved_journal_cleans_then_denies(
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
    _reserve_stale_handler_execution(case, context, request)
    manifest_digest = context.replay_checkpoint.workspace_manifest_digest
    handler, calls = _counting_handler(manifest_digest)

    before = _all_user_table_snapshot(case["ledger_path"])
    assert before["handler_executions"] != ()

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

    after = _all_user_table_snapshot(case["ledger_path"])
    assert after["handler_executions"] == ()
    del before["handler_executions"]
    del after["handler_executions"]
    assert after == before


def test_rollback_denied_with_stale_reserved_journal_cleans_then_denies(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
) -> None:
    case = _rollback_case(
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
        delegated=("owp.run_tests",),
        reserved=(("scope_or_criteria_change", ("owp.rollback_patch",)),),
    )
    commit_human_agency_profile(case["ledger_path"], profile)
    _reserve_stale_handler_execution(case, case["context"], case["request"])
    calls: list[object] = []

    def handler(command):
        calls.append(command)
        return _rollback_failed_result(case)

    before = _all_user_table_snapshot(case["ledger_path"])
    assert before["handler_executions"] != ()

    with pytest.raises(mcp_server.ToolCallDenied) as caught:
        mcp_server.execute_rollback(
            case["ledger_path"],
            evidence_root=case["evidence_root"],
            context=case["context"],
            request=case["request"],
            execution_facts=case["facts"],
            sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
            handler=handler,
            clock=lambda: fixed_now,
            agency_authorize=_agency_authorize(
                case["ledger_path"], case["context"], case["request"]
            ),
        )
    assert caught.value.decision.error_code == AGENCY_HUMAN_DECISION_REQUIRED
    assert calls == []

    after = _all_user_table_snapshot(case["ledger_path"])
    assert after["handler_executions"] == ()
    del before["handler_executions"]
    del after["handler_executions"]
    assert after == before


# --- mixed-mode run-tests recovery binding ---


def test_protected_caller_rejects_legacy_unbound_recovery(
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
    contract = _run_tests_contract(case)
    _reserve_run_tests_execution_bound(case, agency_bound=False)
    agency_authorize, invocations = _counting_agency_authorize(
        case["ledger_path"], case["context"], case["request"]
    )
    driver = _FakeRunTestsExecutionDriver(
        reconciliation_outcomes=(
            _closed_run_tests_outcome(contract, actual_exit_code=0),
        )
    )
    with pytest.raises(
        mcp_server.HandlerCoordinationError, match="AGENCY_UNBOUND_RECOVERY"
    ) as caught:
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
            agency_authorize=agency_authorize,
        )
    assert str(caught.value) == "AGENCY_UNBOUND_RECOVERY"
    # The callback is never re-invoked; the stored truth is finalized (receipt
    # committed) and the journal is cleaned, so the unprotected prior result is
    # neither stranded nor returned to the protected caller.
    assert invocations == []
    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM receipts WHERE nonce = ?",
            (case["request"].nonce,),
        ).fetchone() == (1,)
        assert connection.execute(
            "SELECT COUNT(*) FROM handler_executions"
        ).fetchone() == (0,)
    finally:
        connection.close()


def test_protected_agency_bound_reservation_finalizes_after_revoke_without_callback(
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
        delegated=("owp.run_tests",),
    )
    commit_human_agency_profile(case["ledger_path"], profile)
    contract = _reserve_run_tests_execution_bound(
        case,
        agency_bound=True,
        sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
    )
    revoke = _mk_transition(
        case["work_order"],
        ephemeral_role_keys,
        target=profile,
        transition="revoked",
    )
    commit_agency_profile_transition(case["ledger_path"], revoke)
    agency_authorize, invocations = _counting_agency_authorize(
        case["ledger_path"], case["context"], case["request"]
    )
    driver = _FakeRunTestsExecutionDriver(
        reconciliation_outcomes=(
            _closed_run_tests_outcome(contract, actual_exit_code=0),
        )
    )
    receipt = mcp_server.execute_run_tests(
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
        agency_authorize=agency_authorize,
    )
    # A later revocation is non-retroactive: the stored agency-bound truth is
    # replayed and finalized without re-invoking the (now-deny) callback.
    assert invocations == []
    assert receipt.nonce == case["request"].nonce
    assert receipt.policy_decision == "allow"
    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM handler_executions"
        ).fetchone() == (0,)
    finally:
        connection.close()


@pytest.mark.parametrize("agency_bound", [False, True])
def test_legacy_caller_recovers_stored_reservation(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    agency_bound: bool,
) -> None:
    case = _run_tests_case(
        tmp_path=tmp_path,
        signed_work_order=signed_work_order,
        role_keys=ephemeral_role_keys,
        sidecar_receipt_factory=sidecar_receipt_factory,
        now=fixed_now,
    )
    contract = _reserve_run_tests_execution_bound(
        case,
        agency_bound=agency_bound,
        sidecar_private_key=(
            ephemeral_role_keys["Sidecar"][0] if agency_bound else None
        ),
    )
    driver = _FakeRunTestsExecutionDriver(
        reconciliation_outcomes=(
            _closed_run_tests_outcome(contract, actual_exit_code=0),
        )
    )
    receipt = mcp_server.execute_run_tests(
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
    )
    assert receipt.nonce == case["request"].nonce
    assert receipt.policy_decision == "allow"
    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM handler_executions"
        ).fetchone() == (0,)
    finally:
        connection.close()


@pytest.mark.parametrize(
    "tamper",
    (
        "malformed",
        "noncanonical_duplicate",
        "edited_stale_signature",
        "recomputed_digest_wrong_signer",
        "borrowed_valid_envelope",
    ),
)
def test_agency_binding_envelope_tamper_fails_closed(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    tamper: str,
) -> None:
    """Editing any signed envelope field without a valid Sidecar signature,
    or supplying malformed/noncanonical/borrowed JSON, must fail closed."""
    case = _run_tests_case(
        tmp_path=tmp_path,
        signed_work_order=signed_work_order,
        role_keys=ephemeral_role_keys,
        sidecar_receipt_factory=sidecar_receipt_factory,
        now=fixed_now,
    )
    _reserve_run_tests_execution_bound(
        case,
        agency_bound=True,
        sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
    )
    original = _stored_agency_binding_json(case["ledger_path"])
    envelope = json.loads(original)
    if tamper == "malformed":
        _overwrite_agency_binding_json(case["ledger_path"], '{"claim_type":')
    elif tamper == "noncanonical_duplicate":
        raw = original.replace(
            '"claim_type":', '"claim_type":"x","claim_type":', 1
        )
        _overwrite_agency_binding_json(case["ledger_path"], raw)
    elif tamper == "edited_stale_signature":
        envelope["request_digest"] = "f" * 64
        _overwrite_agency_binding_json(
            case["ledger_path"], rfc8785.dumps(envelope)
        )
    elif tamper == "recomputed_digest_wrong_signer":
        payload = {
            "claim_type": envelope["claim_type"],
            "work_order_digest": envelope["work_order_digest"],
            "execution_id": envelope["execution_id"],
            "request_digest": "f" * 64,
            "authorization_prefix_digest": envelope[
                "authorization_prefix_digest"
            ],
            "agency_marker": envelope["agency_marker"],
            "controller_key_id": envelope["controller_key_id"],
            "reserved_at": envelope["reserved_at"],
        }
        wrong = sign_payload(
            "handler-agency-binding",
            payload,
            ephemeral_role_keys["Maintainer"][0],
            version="0.1",
        )
        _overwrite_agency_binding_json(
            case["ledger_path"], rfc8785.dumps(wrong)
        )
    else:
        borrowed = mcp_server._build_agency_binding_envelope(
            work_order_digest=case["work_order"].digest,
            execution_id="9" * 64,
            request_digest="8" * 64,
            authorization_prefix_digest=(
                mcp_server._authorization_prefix_digest(
                    case["context"].ledger_prefix,
                    domain=mcp_server._AGENCY_AUTHORIZATION_PREFIX_DOMAIN,
                )
            ),
            controller_key_id=case["facts"].controller_id,
            reserved_at="2026-01-01T00:00:05Z",
            sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
        )
        _overwrite_agency_binding_json(case["ledger_path"], borrowed)
    with pytest.raises(
        mcp_server.HandlerCoordinationError, match="RECOVERY_REQUIRED"
    ):
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
            execution_driver=_FakeRunTestsExecutionDriver(),
            clock=lambda: fixed_now,
        )


def test_oversized_stored_agency_binding_json_recovery_fails_closed(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
) -> None:
    """A stored agency-binding envelope larger than its byte budget is a
    recovery tamper.

    The oversized value stays canonical JSON, so only the size gate is in
    play: recovery must fail closed (RECOVERY_REQUIRED) without re-running the
    agency authorization callback and without publishing any receipt.
    """
    case = _run_tests_case(
        tmp_path=tmp_path,
        signed_work_order=signed_work_order,
        role_keys=ephemeral_role_keys,
        sidecar_receipt_factory=sidecar_receipt_factory,
        now=fixed_now,
    )
    _reserve_run_tests_execution_bound(
        case,
        agency_bound=True,
        sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
    )
    original = _stored_agency_binding_json(case["ledger_path"])
    envelope = json.loads(original)
    envelope["padding"] = "x" * 4096
    oversized = rfc8785.dumps(envelope).decode("utf-8")
    assert len(oversized.encode("utf-8")) > mcp_server._MAX_AGENCY_BINDING_BYTES
    _overwrite_agency_binding_json(case["ledger_path"], oversized)
    agency_authorize, invocations = _counting_agency_authorize(
        case["ledger_path"], case["context"], case["request"]
    )
    with pytest.raises(
        mcp_server.HandlerCoordinationError, match="RECOVERY_REQUIRED"
    ):
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
            execution_driver=_FakeRunTestsExecutionDriver(),
            clock=lambda: fixed_now,
            agency_authorize=agency_authorize,
        )
    assert invocations == []
    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM receipts WHERE nonce = ?",
            (case["request"].nonce,),
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT COUNT(*) FROM handler_executions"
        ).fetchone() == (1,)
    finally:
        connection.close()


@pytest.mark.parametrize(
    "binding_json_kind",
    ("malformed", "borrowed", "edited"),
)
def test_legacy_row_flipped_to_bound_recomputing_digest_fails_closed(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    binding_json_kind: str,
) -> None:
    """Coordinated tamper: flip a legacy row to the marker, recompute the
    public agency-domain authorization-prefix digest, and supply a forged
    (malformed/borrowed/edited) binding JSON — all fail closed without a valid
    Sidecar signature."""
    case = _run_tests_case(
        tmp_path=tmp_path,
        signed_work_order=signed_work_order,
        role_keys=ephemeral_role_keys,
        sidecar_receipt_factory=sidecar_receipt_factory,
        now=fixed_now,
    )
    _reserve_run_tests_execution_bound(case, agency_bound=False)
    agency_digest = _agency_prefix_digest(case)
    if binding_json_kind == "malformed":
        binding_json = '{"claim_type":'
    elif binding_json_kind == "borrowed":
        binding_json = mcp_server._build_agency_binding_envelope(
            work_order_digest=case["work_order"].digest,
            execution_id="9" * 64,
            request_digest="8" * 64,
            authorization_prefix_digest=agency_digest,
            controller_key_id=case["facts"].controller_id,
            reserved_at="2026-01-01T00:00:05Z",
            sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
        )
    else:
        valid = mcp_server._build_agency_binding_envelope(
            work_order_digest=case["work_order"].digest,
            execution_id=mcp_server._handler_execution_id(
                case["request"], case["facts"]
            ),
            request_digest=case["request"].digest,
            authorization_prefix_digest=agency_digest,
            controller_key_id=case["facts"].controller_id,
            reserved_at="2026-01-01T00:00:05Z",
            sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
        )
        edited = json.loads(valid)
        edited["request_digest"] = "f" * 64
        binding_json = rfc8785.dumps(edited)
    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        connection.execute(
            """
            UPDATE handler_executions
            SET agency_binding = ?,
                agency_binding_json = ?,
                authorization_prefix_digest = ?
            """,
            (
                evidence._HANDLER_AGENCY_BINDING_MARKER,
                binding_json,
                agency_digest,
            ),
        )
    finally:
        connection.close()
    with pytest.raises(
        mcp_server.HandlerCoordinationError, match="RECOVERY_REQUIRED"
    ):
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
            execution_driver=_FakeRunTestsExecutionDriver(),
            clock=lambda: fixed_now,
        )


# --- apply-patch protected executor seam ---


def _apply_patch_agency_case(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    fixed_now,
):
    from test_apply_patch_transaction import _apply_patch_case

    return _apply_patch_case(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        fixed_now,
    )


def _execute_apply_patch_with_agency(
    case,
    role_keys,
    fixed_now,
    *,
    handler,
    agency_authorize,
):
    from test_apply_patch_transaction import (
        _apply_patch_request,
        _prospective_facts,
    )

    request, arguments = _apply_patch_request(
        case,
        role_keys,
        fixed_now,
        patch_bytes=case["patch_bytes"],
    )
    return mcp_server.execute_apply_patch(
        case["ledger_path"],
        evidence_root=case["evidence_root"],
        context=case["context"],
        request=request,
        request_arguments=arguments,
        execution_facts=_prospective_facts(case),
        sidecar_private_key=role_keys["Sidecar"][0],
        patch_bytes=case["patch_bytes"],
        candidate_workspace=case["candidate"],
        handler=handler,
        clock=lambda: fixed_now,
        agency_authorize=agency_authorize,
    )


def test_apply_patch_reserved_deny_zero_handler_and_no_writes(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    fixed_now,
) -> None:
    from test_apply_patch_transaction import (
        _apply_patch_request,
        _fake_patch_handler,
    )

    case = _apply_patch_agency_case(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        fixed_now,
    )
    profile = _mk_profile(
        case["work_order"],
        ephemeral_role_keys,
        SHA256_A,
        delegated=("owp.repo_read",),
        reserved=(("scope_or_criteria_change", ("owp.apply_patch",)),),
    )
    commit_human_agency_profile(case["ledger_path"], profile)
    request, _ = _apply_patch_request(
        case,
        ephemeral_role_keys,
        fixed_now,
        patch_bytes=case["patch_bytes"],
    )
    handler, calls = _fake_patch_handler(case)

    before = _all_user_table_snapshot(case["ledger_path"])
    with pytest.raises(mcp_server.ToolCallDenied) as caught:
        _execute_apply_patch_with_agency(
            case,
            ephemeral_role_keys,
            fixed_now,
            handler=handler,
            agency_authorize=_agency_authorize(
                case["ledger_path"], case["context"], request
            ),
        )
    assert caught.value.decision.error_code == AGENCY_HUMAN_DECISION_REQUIRED
    assert calls == []
    assert _all_user_table_snapshot(case["ledger_path"]) == before


def test_apply_patch_superseded_allow_reaches_handler(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    fixed_now,
) -> None:
    from test_apply_patch_transaction import (
        _apply_patch_request,
        _fake_patch_handler,
    )

    case = _apply_patch_agency_case(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        fixed_now,
    )
    reserved = _mk_profile(
        case["work_order"],
        ephemeral_role_keys,
        SHA256_A,
        delegated=("owp.repo_read",),
        reserved=(("scope_or_criteria_change", ("owp.apply_patch",)),),
    )
    replacement = _mk_profile(
        case["work_order"],
        ephemeral_role_keys,
        "b" * 64,
        delegated=("owp.apply_patch",),
    )
    commit_human_agency_profile(case["ledger_path"], reserved)
    commit_human_agency_profile(case["ledger_path"], replacement)
    commit_agency_profile_transition(
        case["ledger_path"],
        _mk_transition(
            case["work_order"],
            ephemeral_role_keys,
            target=reserved,
            transition="superseded",
            replacement=replacement,
        ),
    )
    request, _ = _apply_patch_request(
        case,
        ephemeral_role_keys,
        fixed_now,
        patch_bytes=case["patch_bytes"],
    )
    handler, calls = _fake_patch_handler(case)

    receipt = _execute_apply_patch_with_agency(
        case,
        ephemeral_role_keys,
        fixed_now,
        handler=handler,
        agency_authorize=_agency_authorize(
            case["ledger_path"], case["context"], request
        ),
    )
    assert receipt.policy_decision == "allow"
    assert receipt.execution_status == "succeeded"
    assert len(calls) == 1


def test_apply_patch_revocation_deny_zero_handler(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    fixed_now,
) -> None:
    from test_apply_patch_transaction import (
        _apply_patch_request,
        _fake_patch_handler,
    )

    case = _apply_patch_agency_case(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        fixed_now,
    )
    profile = _mk_profile(
        case["work_order"],
        ephemeral_role_keys,
        SHA256_A,
        delegated=("owp.apply_patch",),
    )
    commit_human_agency_profile(case["ledger_path"], profile)
    commit_agency_profile_transition(
        case["ledger_path"],
        _mk_transition(
            case["work_order"],
            ephemeral_role_keys,
            target=profile,
            transition="revoked",
        ),
    )
    request, _ = _apply_patch_request(
        case,
        ephemeral_role_keys,
        fixed_now,
        patch_bytes=case["patch_bytes"],
    )
    handler, calls = _fake_patch_handler(case)

    before = _all_user_table_snapshot(case["ledger_path"])
    with pytest.raises(mcp_server.ToolCallDenied) as caught:
        _execute_apply_patch_with_agency(
            case,
            ephemeral_role_keys,
            fixed_now,
            handler=handler,
            agency_authorize=_agency_authorize(
                case["ledger_path"], case["context"], request
            ),
        )
    assert caught.value.decision.error_code == "AGENCY_PROFILE_REQUIRED"
    assert calls == []
    assert _all_user_table_snapshot(case["ledger_path"]) == before


def test_apply_patch_started_unconfirmed_recovery_without_callback(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    fixed_now,
    monkeypatch,
) -> None:
    from test_apply_patch_transaction import (
        _apply_patch_request,
        _fake_patch_handler,
        _execute_apply_patch,
    )

    case = _apply_patch_agency_case(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        fixed_now,
    )
    profile = _mk_profile(
        case["work_order"],
        ephemeral_role_keys,
        SHA256_A,
        delegated=("owp.apply_patch",),
    )
    commit_human_agency_profile(case["ledger_path"], profile)

    real_finalize = mcp_server._finalize_handler_execution

    def fail_cleanup(*_):
        raise mcp_server.HandlerCoordinationError("injected cleanup failure")

    handler, _ = _fake_patch_handler(case)
    monkeypatch.setattr(
        mcp_server, "_finalize_handler_execution", fail_cleanup
    )
    with pytest.raises(
        mcp_server.HandlerCoordinationError, match="injected cleanup failure"
    ):
        _execute_apply_patch(
            case, ephemeral_role_keys, fixed_now, handler=handler
        )
    monkeypatch.setattr(
        mcp_server, "_finalize_handler_execution", real_finalize
    )

    # Revoke: a fresh agency callback would now deny the (already committed)
    # action, but recovery replays stored truth and never re-invokes it.
    commit_agency_profile_transition(
        case["ledger_path"],
        _mk_transition(
            case["work_order"],
            ephemeral_role_keys,
            target=profile,
            transition="revoked",
        ),
    )
    request, _ = _apply_patch_request(
        case,
        ephemeral_role_keys,
        fixed_now,
        patch_bytes=case["patch_bytes"],
    )
    agency_authorize, invocations = _counting_agency_authorize(
        case["ledger_path"], case["context"], request
    )
    before_connection = evidence.connect_ledger(case["ledger_path"])
    try:
        before_receipts = before_connection.execute(
            "SELECT COUNT(*) FROM receipts"
        ).fetchone()[0]
    finally:
        before_connection.close()

    with pytest.raises(
        mcp_server.HandlerCoordinationError, match="current ledger snapshot"
    ):
        _execute_apply_patch_with_agency(
            case,
            ephemeral_role_keys,
            fixed_now,
            handler=handler,
            agency_authorize=agency_authorize,
        )

    assert invocations == []
    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM handler_executions"
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT COUNT(*) FROM receipts"
        ).fetchone() == (before_receipts,)
    finally:
        connection.close()
