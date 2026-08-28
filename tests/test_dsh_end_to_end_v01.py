"""One ledger from Harness-owned patching through external acceptance."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
import rfc8785

from openworkproof.delivery_case import DeliveryCaseError, verify_exported_delivery_case
from openworkproof.dsh_bridge import (
    DshBridgeApplication,
    _durable_action_receipt_digest,
)
from openworkproof.dsh_protocol import (
    DshActionExecutePayloadV01,
    canonical_bytes,
    sign_dsh_observation,
)
from scripts.create_dsh_fixture import (
    create_dsh_fixture,
    prepare_dsh_process_case,
)


def _run_restarted_bridge(
    case_root: Path,
    *,
    case_id: str,
    execution: dict[str, object],
    patch_text: str,
    now,
    session_id: str,
    export_destination: Path | None = None,
) -> dict[str, dict[str, object]]:
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

    requests = [
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
    ]
    try:
        responses: list[dict[str, object]] = []
        for request in requests:
            process.stdin.write(request)
            process.stdin.flush()
            line = process.stdout.readline()
            if not line:
                raise AssertionError(process.stderr.read())
            responses.append(json.loads(line))
        result = {"action": responses[-1]}
        if export_destination is not None:
            verify_request = message(
                3,
                "verify_request",
                {
                    "case_id": case_id,
                    "action_receipt_digest": responses[-1]["payload"][
                        "result_digest"
                    ],
                },
            )
            process.stdin.write(verify_request)
            process.stdin.flush()
            verify_response = json.loads(process.stdout.readline())
            result["verify"] = verify_response
            verification_digest = verify_response["payload"]["result_digest"]
            acceptance_request = message(
                4,
                "acceptance_draft",
                {
                    "case_id": case_id,
                    "verification_digest": verification_digest,
                },
            )
            process.stdin.write(acceptance_request)
            process.stdin.flush()
            acceptance_response = json.loads(process.stdout.readline())
            result["acceptance"] = acceptance_response
            export_request = message(
                5,
                "export_request",
                {
                    "case_id": case_id,
                    "destination": str(export_destination),
                    "verification_digest": verification_digest,
                    "acceptance_draft_digest": acceptance_response["payload"][
                        "result_digest"
                    ],
                },
            )
            process.stdin.write(export_request)
            process.stdin.flush()
            result["export"] = json.loads(process.stdout.readline())
        return result
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
        mode="enforce",
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

    process_case_id = prepare_dsh_process_case(
        tmp_path,
        case,
        ephemeral_role_keys,
    )
    observation = sign_dsh_observation(
        {
            "schema_version": "openworkproof-dsh-observation/0.1",
            "host": "deepseek-harness",
            "host_version": "0.1.1-rc.2",
            "adapter_version": "0.1.0",
            "execution": case["patch_execution"].model_dump(mode="json"),
            "authorization_status": "authorized",
            "live_result_digest": recovered,
            "durable_call_sequence": 1,
            "durable_result_sequence": 2,
            "receipt_digest": recovered,
            "evidence_gap_codes": [],
            "observed_at": fixed_now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "nonce": "e" * 64,
        },
        ephemeral_role_keys["Sidecar"][0],
    )
    observation_root = case["evidence_root"] / "dsh-observations"
    observation_root.mkdir(mode=0o700)
    (observation_root / f"{observation.record_id}.json").write_bytes(
        canonical_bytes(observation) + b"\n"
    )

    process_export = tmp_path.parent / f"{tmp_path.name}-process-export"
    first_process = _run_restarted_bridge(
        tmp_path,
        case_id=process_case_id,
        execution=case["patch_execution"].model_dump(mode="json"),
        patch_text=case["patch_bytes"].decode("utf-8"),
        now=fixed_now,
        session_id="process-restart-1",
        export_destination=process_export,
    )
    second_process = _run_restarted_bridge(
        tmp_path,
        case_id=process_case_id,
        execution=case["patch_execution"].model_dump(mode="json"),
        patch_text=case["patch_bytes"].decode("utf-8"),
        now=fixed_now,
        session_id="process-restart-2",
    )
    assert first_process["action"]["payload"]["result_digest"] == recovered
    assert first_process["verify"]["payload"]["status"] == "ok"
    assert first_process["acceptance"]["payload"]["status"] == "ok"
    assert first_process["export"]["payload"]["status"] == "ok"
    assert second_process["action"] == {
        **first_process["action"],
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
