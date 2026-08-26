"""One ledger from Harness-owned patching through external acceptance."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
import rfc8785

from openworkproof.delivery_case import DeliveryCaseError, verify_exported_delivery_case
from openworkproof import repo_tools
from openworkproof.dsh_bridge import (
    DshBridgeApplication,
    _durable_action_receipt_digest,
)
from openworkproof.dsh_case import dsh_case_id
from openworkproof.dsh_protocol import DshActionExecutePayloadV01
from scripts.create_dsh_fixture import create_dsh_fixture


def _write_private_key(path: Path, key) -> None:
    path.write_bytes(key.private_bytes_raw())
    os.chmod(path, 0o600)


def _run_restarted_bridge(
    case_root: Path,
    *,
    case_id: str,
    execution: dict[str, object],
    patch_text: str,
    now,
    session_id: str,
) -> dict[str, object]:
    process = subprocess.Popen(
        [sys.executable, "-m", "openworkproof.cli", "dsh-bridge", "--stdio"],
        cwd=Path(__file__).parents[1],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert process.stdin is not None
    assert process.stdout is not None
    assert process.stderr is not None

    def message(sequence, message_type, payload):
        body = {
            "schema_version": "openworkproof-dsh-bridge/0.1",
            "request_id": str(sequence + 1) * 64,
            "session_id": session_id,
            "message_type": message_type,
            "sequence": sequence,
            "timestamp": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "payload": payload,
        }
        return json.dumps(body, separators=(",", ":")) + "\n"

    requests = (
        message(
            0,
            "hello",
            {
                "host": "deepseek-harness",
                "host_version": "0.1.1-rc.2",
                "adapter_version": "0.1.0",
                "bridge_protocol": "0.1",
            },
        ),
        message(
            1,
            "case_open",
            {"case_manifest_path": str(case_root)},
        ),
        message(
            2,
            "action_execute",
            {
                "case_id": case_id,
                "execution": execution,
                "decision_token": "d" * 64,
                "patch_text": patch_text,
                "target_paths": ["src/app.py"],
                "test_profile_digest": None,
            },
        ),
    )
    try:
        for request in requests:
            process.stdin.write(request)
        process.stdin.flush()
        response_lines = [process.stdout.readline() for _ in requests]
        if any(not line for line in response_lines):
            raise AssertionError(process.stderr.read())
        responses = [json.loads(line) for line in response_lines]
        return responses[-1]
    finally:
        process.kill()
        process.wait(timeout=5)


def test_verified_code_change_closed_loop(
    tmp_path: Path,
    signed_work_order,
    signed_subject_claim,
    evaluation_scope_payload_v03,
    frozen_verification_profile_v03,
    ephemeral_role_keys,
    fixed_now,
    monkeypatch,
) -> None:
    fixture_root = Path(__file__).parent / "fixtures" / "dsh-code-change"
    assert (fixture_root / "src" / "app.py").read_bytes() == b"base\n"
    case = create_dsh_fixture(
        tmp_path,
        signed_work_order=signed_work_order,
        signed_subject_claim=signed_subject_claim,
        evaluation_scope_payload_v03=evaluation_scope_payload_v03,
        verification_profile_v03=frozen_verification_profile_v03,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
    )

    assert case["patch"].receipt.digest
    passed = next(
        result
        for result in case["test_receipt"].predicate_results
        if result.name == "tests_passed"
    )
    assert passed.input.actual_exit_code == 0
    assert case["verification"].status == "VERIFIED"
    assert case["verification"].work_order_digest
    assert case["verification"].execution_identity_digest
    assert (
        case["verification"].action_receipt_digest
        == case["patch"].receipt.digest
    )
    assert tuple(
        binding.path for binding in case["verification"].artifact_bindings
    ) == ("src/app.py",)
    assert "signature" not in case["acceptance_draft_payload"]
    assert case["accepted"].case_stage == "ACCEPTED"

    result_path = case["exported_path"] / "delivery-result.json"
    result_path.write_bytes(result_path.read_bytes() + b"\n")
    with pytest.raises(DeliveryCaseError, match="integrity failed"):
        verify_exported_delivery_case(case["exported_path"])

    recovered = _durable_action_receipt_digest(
        SimpleNamespace(
            ledger_path=str(case["ledger_path"]),
            work_order_digest=case["work_order_digest"],
        ),
        DshActionExecutePayloadV01.model_validate(
            {
                "case_id": case["case_id"],
                "execution": case["patch_execution"].model_dump(mode="json"),
                "decision_token": "d" * 64,
                "patch_text": case["patch_bytes"].decode("utf-8"),
                "target_paths": ["src/app.py"],
                "test_profile_digest": None,
            }
        ),
    )
    assert recovered == case["patch"].receipt.digest

    manifest = SimpleNamespace(
        case_id=case["case_id"],
        ledger_path=str(case["ledger_path"]),
        work_order_digest=case["work_order_digest"],
        allowed_tools=("owp_apply_patch",),
    )
    monkeypatch.setattr(
        "openworkproof.dsh_bridge.load_dsh_case", lambda _path: manifest
    )
    replayed_calls: list[str] = []
    restarted = DshBridgeApplication(
        clock=lambda: fixed_now,
        action_handler=lambda _payload: replayed_calls.append("replayed") or "0" * 64,
    )

    def request(
        request_id: str,
        sequence: int,
        message_type: str,
        payload: dict[str, object],
    ) -> bytes:
        return rfc8785.dumps(
            {
                "schema_version": "openworkproof-dsh-bridge/0.1",
                "request_id": request_id,
                "session_id": "restart-session",
                "message_type": message_type,
                "sequence": sequence,
                "timestamp": fixed_now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "payload": payload,
            }
        )

    restarted.handle_line(
        request(
            "1" * 64,
            0,
            "hello",
            {
                "host": "deepseek-harness",
                "host_version": "0.1.1-rc.2",
                "adapter_version": "0.1.0",
                "bridge_protocol": "0.1",
            },
        )
    )
    restarted.handle_line(
        request(
            "2" * 64,
            1,
            "case_open",
            {"case_manifest_path": "/private/restarted-case"},
        )
    )
    action_response = json.loads(
        restarted.handle_line(
            request(
                "3" * 64,
                2,
                "action_execute",
                {
                    "case_id": case["case_id"],
                    "execution": case["patch_execution"].model_dump(
                        mode="json"
                    ),
                    "decision_token": "d" * 64,
                    "patch_text": case["patch_bytes"].decode("utf-8"),
                    "target_paths": ["src/app.py"],
                    "test_profile_digest": None,
                },
            )
        )
    )
    assert action_response["payload"]["result_digest"] == recovered
    assert replayed_calls == []

    shutil.rmtree(tmp_path / "delivery-case")
    shutil.rmtree(tmp_path / "exported")
    source_runtime = tmp_path / "source-runtime"
    source_runtime.mkdir(mode=0o700)
    source_workspace = repo_tools.initialize_candidate_workspace(
        repo_tools.WorkspaceInitRequest(
            runtime_root=source_runtime,
            workspace_id="6" * 64,
            source=case["source"],
        )
    )
    (source_workspace.worktree / ".git").write_text(
        f"gitdir: {source_workspace.git_dir}\n",
        encoding="utf-8",
    )
    subprocess.run(
        [
            "git",
            f"--git-dir={source_workspace.git_dir}",
            "config",
            "core.bare",
            "false",
        ],
        check=True,
    )
    subprocess.run(
        [
            "git",
            f"--git-dir={source_workspace.git_dir}",
            "config",
            "core.worktree",
            str(source_workspace.worktree),
        ],
        check=True,
    )
    key_root = tmp_path / "keys"
    key_root.mkdir(mode=0o700)
    sidecar_key = key_root / "sidecar.key"
    developer_key = key_root / "developer.key"
    _write_private_key(sidecar_key, ephemeral_role_keys["Sidecar"][0])
    _write_private_key(developer_key, ephemeral_role_keys["Developer"][0])
    stable_manifest = {
        "schema_version": "openworkproof-dsh-case/0.1",
        "work_order_digest": case["work_order_digest"],
        "source_revision": case["work_order"].source_commit,
        "allowed_path_roots": ["src"],
        "denied_path_roots": ["secrets"],
        "allowed_tools": ["owp_apply_patch"],
        "test_profile_digest": case["profile_digest"],
        "mode": "audit",
    }
    process_case_id = dsh_case_id(stable_manifest)
    case_manifest = {
        **stable_manifest,
        "case_id": process_case_id,
        "repository_root": str(source_workspace.worktree),
        "ledger_path": str(case["ledger_path"]),
        "evidence_root": str(case["evidence_root"]),
        "candidate_runtime_root": str(case["candidate"].runtime_root),
        "candidate_workspace_id": case["candidate"].workspace_id,
        "verifier_socket_path": None,
        "sidecar_key_path": str(sidecar_key),
        "developer_key_path": str(developer_key),
    }
    (tmp_path / "case.json").write_bytes(rfc8785.dumps(case_manifest) + b"\n")

    first_process = _run_restarted_bridge(
        tmp_path,
        case_id=process_case_id,
        execution=case["patch_execution"].model_dump(mode="json"),
        patch_text=case["patch_bytes"].decode("utf-8"),
        now=fixed_now,
        session_id="process-restart-1",
    )
    second_process = _run_restarted_bridge(
        tmp_path,
        case_id=process_case_id,
        execution=case["patch_execution"].model_dump(mode="json"),
        patch_text=case["patch_bytes"].decode("utf-8"),
        now=fixed_now,
        session_id="process-restart-2",
    )
    assert first_process["payload"]["result_digest"] == recovered
    assert second_process == {
        **first_process,
        "request_id": "3" * 64,
        "session_id": "process-restart-2",
    }


def test_verification_without_action_receipt_binding_is_unknown(
    tmp_path: Path,
    signed_work_order,
    signed_subject_claim,
    evaluation_scope_payload_v03,
    frozen_verification_profile_v03,
    ephemeral_role_keys,
    fixed_now,
) -> None:
    case = create_dsh_fixture(
        tmp_path,
        signed_work_order=signed_work_order,
        signed_subject_claim=signed_subject_claim,
        evaluation_scope_payload_v03=evaluation_scope_payload_v03,
        verification_profile_v03=frozen_verification_profile_v03,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
        include_action_receipt_binding=False,
    )

    assert case["verification"].status == "UNKNOWN"
    assert case["verification"].reason_codes == (
        "ACTION_RECEIPT_BINDING_MISSING",
    )


def test_verification_with_wrong_action_receipt_binding_is_unknown(
    tmp_path: Path,
    signed_work_order,
    signed_subject_claim,
    evaluation_scope_payload_v03,
    frozen_verification_profile_v03,
    ephemeral_role_keys,
    fixed_now,
) -> None:
    case = create_dsh_fixture(
        tmp_path,
        signed_work_order=signed_work_order,
        signed_subject_claim=signed_subject_claim,
        evaluation_scope_payload_v03=evaluation_scope_payload_v03,
        verification_profile_v03=frozen_verification_profile_v03,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
        action_receipt_digest_override="f" * 64,
    )

    assert case["verification"].status == "UNKNOWN"
    assert case["verification"].reason_codes == (
        "ACTION_RECEIPT_BINDING_INVALID",
    )
