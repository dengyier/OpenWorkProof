"""One ledger from Harness-owned patching through external acceptance."""

from __future__ import annotations

from pathlib import Path

import pytest

from openworkproof.delivery_case import DeliveryCaseError, verify_exported_delivery_case
from scripts.create_dsh_fixture import create_dsh_fixture


def test_verified_code_change_closed_loop(
    tmp_path: Path,
    signed_work_order,
    signed_subject_claim,
    evaluation_scope_payload_v03,
    frozen_verification_profile_v03,
    ephemeral_role_keys,
    fixed_now,
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
