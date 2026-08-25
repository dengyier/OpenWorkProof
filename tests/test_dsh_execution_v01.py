from __future__ import annotations

import hashlib
from datetime import timedelta

import pytest

from openworkproof.dsh_case import DecisionTokenStore
from openworkproof.dsh_execution import (
    DshApplyPatchInputV01,
    DshExecutionCaseV01,
    DshExecutionDenied,
    DshRunTestsInputV01,
    execute_dsh_patch,
    execute_dsh_tests,
)
from openworkproof.dsh_protocol import DshExecutionIdentityV01
from openworkproof.dsh_protocol import dsh_action_arguments_digest
from openworkproof.models import ApplyPatchArguments, request_arguments_digest
from openworkproof.binding import canonical_test_profile_digest

from test_apply_patch_transaction import (
    _apply_patch_case,
    _src_app_patch,
    _user_table_snapshot,
)
from test_mcp_server import (
    _FakeRunTestsExecutionDriver,
    _execute_run_tests_case,
    _run_tests_case,
    _run_tests_snapshot,
)


def _create_patch(path: str, content: bytes) -> bytes:
    new_oid = hashlib.sha1(
        f"blob {len(content)}\0".encode("ascii") + content
    ).hexdigest()
    return (
        f"diff --git a/{path} b/{path}\n"
        "new file mode 100644\n"
        f"index {'0' * 40}..{new_oid}\n"
        "--- /dev/null\n"
        f"+++ b/{path}\n"
        "@@ -0,0 +1 @@\n"
        f"+{content.decode('ascii').rstrip()}\n"
    ).encode("ascii")


def _input(
    case: DshExecutionCaseV01,
    patch_bytes: bytes,
    target_paths: tuple[str, ...],
    *,
    token: str,
    call_id: str,
) -> DshApplyPatchInputV01:
    arguments = ApplyPatchArguments(
        target_paths=target_paths,
        patch_digest=hashlib.sha256(patch_bytes).hexdigest(),
        patch_size_bytes=len(patch_bytes),
    )
    execution = DshExecutionIdentityV01(
        session_id="session-1",
        call_id=call_id,
        root_call_id="root-1",
        tool_name="owp_apply_patch",
        arguments_digest=dsh_action_arguments_digest(
            {
                "patch_utf8": patch_bytes.decode("utf-8"),
                "target_paths": list(target_paths),
            }
        ),
    )
    return DshApplyPatchInputV01.model_validate(
        {
            "schema_version": "openworkproof-dsh-apply-patch/0.1",
            "case_id": case.case_id,
            "execution": execution.model_dump(mode="json"),
            "decision_token": token,
            "patch_utf8": patch_bytes.decode("utf-8"),
            "target_paths": list(target_paths),
        }
    )


@pytest.fixture
def dsh_patch_case(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    fixed_now,
):
    base = _apply_patch_case(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        fixed_now,
    )
    store = DecisionTokenStore(clock=lambda: fixed_now)
    calls: list[object] = []

    def handler(command):
        calls.append(command)
        from openworkproof.repo_tools import apply_patch_in_candidate_workspace

        return apply_patch_in_candidate_workspace(command)

    runtime = DshExecutionCaseV01(
        case_id="c" * 64,
        ledger_path=base["ledger_path"],
        evidence_root=base["evidence_root"],
        context=base["context"],
        candidate_workspace=base["candidate"],
        sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
        developer_private_key=ephemeral_role_keys["Developer"][0],
        decision_tokens=store,
        patch_handler=handler,
    )
    return runtime, calls, fixed_now


def _authorized_input(
    runtime: DshExecutionCaseV01,
    store: DecisionTokenStore,
    fixed_now,
    *,
    patch_bytes: bytes,
    paths: tuple[str, ...],
    call_id: str,
) -> DshApplyPatchInputV01:
    provisional = _input(
        runtime,
        patch_bytes,
        paths,
        token="0" * 64,
        call_id=call_id,
    )
    decision = store.issue(
        provisional.execution,
        expires_at=fixed_now + timedelta(seconds=30),
    )
    return provisional.model_copy(update={"decision_token": decision.token})


def test_unauthorized_patch_never_calls_handler_or_writes_ledger(
    dsh_patch_case,
) -> None:
    runtime, calls, fixed_now = dsh_patch_case
    patch_bytes = _create_patch("outside.txt", b"outside\n")
    payload = _authorized_input(
        runtime,
        runtime.decision_tokens,
        fixed_now,
        patch_bytes=patch_bytes,
        paths=("outside.txt",),
        call_id="call-denied",
    )
    before = _user_table_snapshot(runtime.ledger_path)

    with pytest.raises(DshExecutionDenied, match="OWP_AUTHORIZATION_DENIED"):
        execute_dsh_patch(runtime, payload, clock=lambda: fixed_now)

    assert calls == []
    assert _user_table_snapshot(runtime.ledger_path) == before


def test_missing_or_replayed_decision_token_is_zero_write(
    dsh_patch_case,
) -> None:
    runtime, calls, fixed_now = dsh_patch_case
    patch_bytes = _src_app_patch()
    payload = _input(
        runtime,
        patch_bytes,
        ("src/app.py",),
        token="f" * 64,
        call_id="call-missing-token",
    )
    before = _user_table_snapshot(runtime.ledger_path)

    with pytest.raises(DshExecutionDenied, match="DECISION_TOKEN_INVALID"):
        execute_dsh_patch(runtime, payload, clock=lambda: fixed_now)

    assert calls == []
    assert _user_table_snapshot(runtime.ledger_path) == before


def test_authorized_patch_uses_existing_transaction(dsh_patch_case) -> None:
    runtime, calls, fixed_now = dsh_patch_case
    patch_bytes = _src_app_patch()
    payload = _authorized_input(
        runtime,
        runtime.decision_tokens,
        fixed_now,
        patch_bytes=patch_bytes,
        paths=("src/app.py",),
        call_id="call-authorized",
    )

    result = execute_dsh_patch(runtime, payload, clock=lambda: fixed_now)

    assert len(calls) == 1
    assert result.receipt.tool_name == "owp.apply_patch"
    assert result.changed_paths == ("src/app.py",)
    assert result.receipt.request_arguments.target_paths == result.changed_paths


@pytest.fixture
def dsh_tests_case(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
):
    base = _run_tests_case(
        tmp_path=tmp_path,
        signed_work_order=signed_work_order,
        role_keys=ephemeral_role_keys,
        sidecar_receipt_factory=sidecar_receipt_factory,
        now=fixed_now,
    )
    profile = next(
        item
        for item in base["work_order"].test_profiles
        if item.test_mode == "verifier"
    )
    store = DecisionTokenStore(clock=lambda: fixed_now)
    driver = _FakeRunTestsExecutionDriver(actual_exit_code=0)
    monkeypatch.setattr(
        "openworkproof.mcp_server.repo_tools.prepare_candidate_execution_snapshot",
        lambda _request: _run_tests_snapshot(base),
    )

    def external_verifier(arguments, facts, _execution, now):
        return _execute_run_tests_case(
            base,
            tmp_path.resolve(),
            ephemeral_role_keys,
            driver,
            request_arguments=arguments,
            execution_facts=facts,
            now=now,
        )

    runtime = DshExecutionCaseV01(
        case_id="d" * 64,
        ledger_path=base["ledger_path"],
        evidence_root=base["evidence_root"],
        context=base["context"],
        candidate_workspace=None,
        sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
        developer_private_key=ephemeral_role_keys["Developer"][0],
        decision_tokens=store,
        test_profile_digest=canonical_test_profile_digest(profile),
        run_tests_executor=external_verifier,
    )
    return runtime, driver, fixed_now, profile


def _run_tests_payload(
    runtime: DshExecutionCaseV01,
    profile,
    *,
    token: str,
    profile_digest: str | None = None,
) -> DshRunTestsInputV01:
    from openworkproof.models import RunTestsArguments

    checkpoint = runtime.context.replay_checkpoint
    arguments = RunTestsArguments(
        test_mode="verifier",
        command_digest=profile.command_digest,
        source_commit=runtime.context.work_order.source_commit,
        candidate_commit=checkpoint.head_commit,
        workspace_manifest_digest=checkpoint.workspace_manifest_digest,
        container_image_digest=profile.container_image_digest,
        fixed_test_source_digest=profile.fixed_test_source_digest,
    )
    execution = DshExecutionIdentityV01(
        session_id="session-tests",
        call_id="call-tests",
        root_call_id="root-tests",
        tool_name="owp_run_tests",
        arguments_digest=dsh_action_arguments_digest(
            {"test_profile_digest": runtime.test_profile_digest}
        ),
    )
    return DshRunTestsInputV01.model_validate(
        {
            "schema_version": "openworkproof-dsh-run-tests/0.1",
            "case_id": runtime.case_id,
            "execution": execution.model_dump(mode="json"),
            "decision_token": token,
            "test_profile_digest": (
                runtime.test_profile_digest
                if profile_digest is None
                else profile_digest
            ),
        }
    )


def test_agent_cannot_supply_an_arbitrary_test_profile(dsh_tests_case) -> None:
    runtime, driver, fixed_now, profile = dsh_tests_case
    payload = _run_tests_payload(
        runtime,
        profile,
        token="f" * 64,
        profile_digest="f" * 64,
    )
    before = _user_table_snapshot(runtime.ledger_path)

    with pytest.raises(DshExecutionDenied, match="TEST_PROFILE_MISMATCH"):
        execute_dsh_tests(runtime, payload, clock=lambda: fixed_now)

    assert driver.calls == []
    assert _user_table_snapshot(runtime.ledger_path) == before


def test_authorized_tests_use_frozen_profile_and_existing_transaction(
    dsh_tests_case,
) -> None:
    runtime, driver, fixed_now, profile = dsh_tests_case
    provisional = _run_tests_payload(
        runtime,
        profile,
        token="0" * 64,
    )
    decision = runtime.decision_tokens.issue(
        provisional.execution,
        expires_at=fixed_now + timedelta(seconds=30),
    )
    payload = provisional.model_copy(
        update={"decision_token": decision.token}
    )

    receipt = execute_dsh_tests(runtime, payload, clock=lambda: fixed_now)

    assert receipt.tool_name == "owp.run_tests"
    assert receipt.request_arguments.test_mode == "verifier"
    assert receipt.request_arguments.command_digest == profile.command_digest
    assert [call[0] for call in driver.calls] == [
        "prepare",
        "start_and_wait",
        "cleanup",
    ]
