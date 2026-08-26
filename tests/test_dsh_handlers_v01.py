from __future__ import annotations

import os
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

from openworkproof.dsh_case import DecisionTokenStore
from openworkproof.dsh_handlers import build_dsh_case_handlers
from openworkproof.dsh_protocol import (
    DshActionExecutePayloadV01,
    DshExecutionIdentityV01,
    dsh_action_arguments_digest,
)

from test_apply_patch_transaction import _apply_patch_case, _src_app_patch


def _write_key(path: Path, key) -> None:
    path.write_bytes(key.private_bytes_raw())
    os.chmod(path, 0o600)


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
