"""One ledger from Harness-owned patching through external acceptance."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
import rfc8785

from openworkproof.delivery_case import DeliveryCaseError, verify_exported_delivery_case
from openworkproof.dsh_bridge import (
    DshBridgeApplication,
    _durable_action_receipt_digest,
)
from openworkproof.dsh_protocol import DshActionExecutePayloadV01
from scripts.create_dsh_fixture import create_dsh_fixture


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
