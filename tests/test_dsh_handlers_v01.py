from __future__ import annotations

import json
import os
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from openworkproof.delivery_package import DeliveryPackageError
from openworkproof.dsh_bridge import DshHandlerResult
from openworkproof.dsh_case import DecisionTokenStore
from openworkproof.dsh_handlers import _store_result, build_dsh_case_handlers
from openworkproof.dsh_delivery import audit_dsh_delivery
from openworkproof.dsh_protocol import (
    DshActionExecutePayloadV01,
    DshAcceptanceDraftPayloadV01,
    DshExecutionIdentityV01,
    DshExportRequestPayloadV01,
    DshVerifyRequestPayloadV01,
    canonical_bytes,
    dsh_action_arguments_digest,
    sign_dsh_observation,
)
from openworkproof.dsh_verifier import DshVerificationResultV01
from scripts.create_dsh_fixture import create_dsh_fixture

from test_apply_patch_transaction import _apply_patch_case, _src_app_patch


def _write_key(path: Path, key) -> None:
    path.write_bytes(key.private_bytes_raw())
    os.chmod(path, 0o600)


def test_result_store_rejects_symlinked_kind_directory(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    outside = tmp_path / "outside"
    evidence_root.mkdir()
    outside.mkdir()
    (evidence_root / "dsh-verifications").symlink_to(
        outside, target_is_directory=True
    )

    with pytest.raises(RuntimeError, match="RESULT_DIRECTORY_INVALID"):
        _store_result(evidence_root, "dsh-verifications", {"status": "x"})

    assert tuple(outside.iterdir()) == ()


def test_production_handler_executes_patch_from_durable_case(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    fixed_now,
) -> None:
    base = _apply_patch_case(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        fixed_now,
    )
    sidecar_key = tmp_path / "sidecar.key"
    developer_key = tmp_path / "developer.key"
    _write_key(sidecar_key, ephemeral_role_keys["Sidecar"][0])
    _write_key(developer_key, ephemeral_role_keys["Developer"][0])
    profile = next(
        item
        for item in base["work_order"].test_profiles
        if item.test_mode == "verifier"
    )
    from openworkproof.binding import canonical_test_profile_digest

    manifest = SimpleNamespace(
        case_id="c" * 64,
        work_order_digest=base["work_order"].digest,
        source_revision=base["work_order"].source_commit,
        ledger_path=str(base["ledger_path"]),
        evidence_root=str(base["evidence_root"]),
        candidate_runtime_root=str(base["candidate"].runtime_root),
        candidate_workspace_id=base["candidate"].workspace_id,
        sidecar_key_path=str(sidecar_key),
        developer_key_path=str(developer_key),
        verifier_socket_path=str(tmp_path / "verifier.sock"),
        test_profile_digest=canonical_test_profile_digest(profile),
        allowed_path_roots=("src",),
        denied_path_roots=("secrets",),
    )
    tokens = DecisionTokenStore(clock=lambda: fixed_now)
    handlers = build_dsh_case_handlers(
        manifest,
        tokens,
        clock=lambda: fixed_now,
    )
    patch = _src_app_patch().decode("utf-8")
    execution = DshExecutionIdentityV01(
        session_id="production-session",
        call_id="patch-1",
        root_call_id="patch-1",
        tool_name="owp_apply_patch",
        arguments_digest=dsh_action_arguments_digest(
            {"patch_utf8": patch, "target_paths": ["src/app.py"]}
        ),
    )
    decision = tokens.issue(
        execution,
        expires_at=fixed_now + timedelta(seconds=30),
    )
    payload = DshActionExecutePayloadV01.model_validate(
        {
            "case_id": manifest.case_id,
            "execution": execution.model_dump(mode="json"),
            "decision_token": decision.token,
            "patch_text": patch,
            "target_paths": ["src/app.py"],
            "test_profile_digest": None,
        }
    )

    receipt_digest = handlers.action(payload)

    assert len(receipt_digest) == 64
    assert (base["candidate"].worktree / "src/app.py").read_bytes() != b"base\n"


def test_production_verify_handler_binds_observed_patch_and_committed_test(
    tmp_path,
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
    )
    keys = tmp_path / "handler-keys"
    keys.mkdir()
    sidecar_key = keys / "sidecar.key"
    developer_key = keys / "developer.key"
    _write_key(sidecar_key, ephemeral_role_keys["Sidecar"][0])
    _write_key(developer_key, ephemeral_role_keys["Developer"][0])
    manifest = SimpleNamespace(
        case_id=case["case_id"],
        work_order_digest=case["work_order_digest"],
        source_revision=case["work_order"].source_commit,
        ledger_path=str(case["ledger_path"]),
        evidence_root=str(case["evidence_root"]),
        candidate_runtime_root=str(case["candidate"].runtime_root),
        candidate_workspace_id=case["candidate"].workspace_id,
        sidecar_key_path=str(sidecar_key),
        developer_key_path=str(developer_key),
        verifier_socket_path=str(tmp_path / "verifier.sock"),
        test_profile_digest=case["profile_digest"],
        allowed_path_roots=("src",),
        denied_path_roots=("secrets",),
    )
    observation = sign_dsh_observation(
        {
            "schema_version": "openworkproof-dsh-observation/0.1",
            "host": "deepseek-harness",
            "host_version": "0.1.1-rc.2",
            "adapter_version": "0.1.0",
            "execution": case["patch_execution"].model_dump(mode="json"),
            "authorization_status": "authorized",
            "live_result_digest": case["patch"].receipt.digest,
            "durable_call_sequence": 1,
            "durable_result_sequence": 2,
            "receipt_digest": case["patch"].receipt.digest,
            "evidence_gap_codes": [],
            "observed_at": fixed_now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "nonce": "e" * 64,
        },
        ephemeral_role_keys["Sidecar"][0],
    )
    observations = case["evidence_root"] / "dsh-observations"
    observations.mkdir(mode=0o700)
    (observations / f"{observation.record_id}.json").write_bytes(
        canonical_bytes(observation) + b"\n"
    )
    handlers = build_dsh_case_handlers(
        manifest,
        DecisionTokenStore(clock=lambda: case["binding_now"]),
        clock=lambda: case["binding_now"],
    )

    digest = handlers.verify(
        DshVerifyRequestPayloadV01(
            case_id=case["case_id"],
            action_receipt_digest=case["patch"].receipt.digest,
        )
    )

    verification_path = (
        case["evidence_root"] / "dsh-verifications" / f"{digest}.json"
    )
    verification_bytes = verification_path.read_bytes()
    result = DshVerificationResultV01.model_validate_json(verification_bytes)
    assert result.status == "VERIFIED"
    assert result.action_receipt_digest == case["patch"].receipt.digest
    assert result.action_receipt_id == case["patch"].receipt.receipt_id
    assert result.test_receipt_id == case["test_receipt"].receipt_id
    assert result.core_verification_decision_id is not None
    assert result.core_verification_decision_digest is not None

    candidate_path = case["candidate"].worktree / "src/app.py"
    verified_bytes = candidate_path.read_bytes()
    candidate_path.write_bytes(b"tampered-after-tests\n")
    drifted_result = handlers.verify(
        DshVerifyRequestPayloadV01(
            case_id=case["case_id"],
            action_receipt_digest=case["patch"].receipt.digest,
        )
    )
    assert isinstance(drifted_result, DshHandlerResult)
    assert drifted_result.status == "denied"
    assert drifted_result.reason_code == "TESTED_WORKSPACE_DRIFT"
    candidate_path.write_bytes(verified_bytes)

    drifted = result.model_copy(
        update={"verified_at": result.verified_at + timedelta(seconds=1)}
    )
    verification_path.write_bytes(canonical_bytes(drifted) + b"\n")
    with pytest.raises(RuntimeError, match="VERIFICATION_RESULT_INVALID"):
        handlers.acceptance_draft(
            DshAcceptanceDraftPayloadV01(
                case_id=case["case_id"],
                verification_digest=digest,
            )
        )
    verification_path.write_bytes(verification_bytes)

    draft_digest = handlers.acceptance_draft(
        DshAcceptanceDraftPayloadV01(
            case_id=case["case_id"],
            verification_digest=digest,
        )
    )
    draft = json.loads(
        (
            case["evidence_root"]
            / "dsh-acceptance-drafts"
            / f"{draft_digest}.json"
        ).read_bytes()
    )
    assert "signature" not in draft
    assert len(draft["binding_id"]) == 64
    assert draft["dsh_verification_digest"] == digest
    assert (
        draft["core_verification_decision_id"]
        == result.core_verification_decision_id
    )
    assert (
        draft["core_acceptance_binding"]["verification_decision_digest"]
        == result.core_verification_decision_digest
    )

    export_root = tmp_path / "handler-export"
    export_digest = handlers.export(
        DshExportRequestPayloadV01(
            case_id=case["case_id"],
            destination=str(export_root),
            verification_digest=digest,
            acceptance_draft_digest=draft_digest,
        )
    )
    audit = audit_dsh_delivery(export_root)
    assert audit["manifest_digest"] == export_digest
    assert audit["current_decision"] == "VERIFIED"
    verification_export = export_root / "dsh-verification.json"
    verification_export.write_bytes(verification_export.read_bytes() + b" ")
    with pytest.raises(DeliveryPackageError):
        audit_dsh_delivery(export_root)
