"""CLI and MCP transport tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import openworkproof.cli as cli
from openworkproof import mcp_server
from openworkproof.models import RepoReadArguments


@pytest.fixture(autouse=True)
def _stub_execution_snapshot(monkeypatch: pytest.MonkeyPatch) -> None:
    from openworkproof import repo_tools
    from openworkproof.repo_tools import (
        CandidateExecutionSnapshot,
        ExecutionSnapshotPlan,
    )

    def prepare(request):
        return CandidateExecutionSnapshot(
            head_commit=request.expected_head_commit,
            workspace_manifest_digest=request.expected_workspace_manifest_digest,
            plan=ExecutionSnapshotPlan(
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

    monkeypatch.setattr(repo_tools, "prepare_candidate_execution_snapshot", prepare)


def _activated_ledger(
    tmp_path, signed_work_order, ephemeral_role_keys, sidecar_receipt_factory, fixed_now
):
    from test_mcp_server import _run_tests_case

    case = _run_tests_case(
        tmp_path=tmp_path,
        signed_work_order=signed_work_order,
        role_keys=ephemeral_role_keys,
        sidecar_receipt_factory=sidecar_receipt_factory,
        now=fixed_now,
    )
    return case["ledger_path"]


def _sidecar_key_hex(ephemeral_role_keys) -> str:
    key = ephemeral_role_keys["Sidecar"][0]
    return key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    ).hex()


def test_cli_status_replays_ledger(
    tmp_path, signed_work_order, ephemeral_role_keys, sidecar_receipt_factory, fixed_now
) -> None:
    from test_mcp_server import _run_tests_case

    case = _run_tests_case(
        tmp_path=tmp_path,
        signed_work_order=signed_work_order,
        role_keys=ephemeral_role_keys,
        sidecar_receipt_factory=sidecar_receipt_factory,
        now=fixed_now,
    )
    result = cli.cli_status(case["ledger_path"])
    assert result["schema_version"] == "openworkproof/cli-status/0.1"
    assert result["work_order_digest"] == case["work_order"].digest
    assert result["current_state"] == "running"
    assert result["version"] >= 1
    assert result["receipt_count"] >= 1


def test_cli_status_missing_ledger(tmp_path) -> None:
    with pytest.raises(cli.CliError, match="does not exist"):
        cli.cli_status(tmp_path / "missing.sqlite3")


def test_cli_repo_read_forwards_payload(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
) -> None:
    from test_repo_read_transaction import (
        _repo_read_request,
        _repo_read_success_case,
    )
    from test_mcp_server import _current_run_tests_context

    case, _ = _repo_read_success_case(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        sidecar_receipt_factory,
        fixed_now,
        monkeypatch,
    )
    context = _current_run_tests_context(case, fixed_now)
    request, arguments = _repo_read_request(
        case, context, ephemeral_role_keys, fixed_now, path="src/app.py"
    )
    candidate_root = tmp_path / "candidate-repo"
    (candidate_root / "src").mkdir(parents=True)
    (candidate_root / "src" / "app.py").write_text("import os\n")
    checkpoint = context.replay_checkpoint
    payload = {
        "now": fixed_now.isoformat(),
        "evidence_root": str(case["evidence_root"]),
        "request": request.model_dump(mode="json"),
        "arguments": RepoReadArguments(path="src/app.py").model_dump(
            mode="json"
        ),
        "checkpoint": {
            "head_commit": checkpoint.head_commit,
            "workspace_manifest_digest": (
                checkpoint.workspace_manifest_digest
            ),
            "workspace_manifest": {
                "schema_version": (
                    checkpoint.workspace_manifest.schema_version
                ),
                "head_commit": checkpoint.workspace_manifest.head_commit,
                "entries": [
                    {
                        "path_bytes_b64url": entry.path_bytes_b64url,
                        "type": entry.type,
                        "posix_mode": entry.posix_mode,
                        "size_bytes": entry.size_bytes,
                        "sha256": entry.sha256,
                        "symlink_target_b64url": entry.symlink_target_b64url,
                    }
                    for entry in checkpoint.workspace_manifest.entries
                ],
            },
        },
        "facts": {
            "execution_context_id": "3" * 64,
            "container_instance_id_digest": "4" * 64,
            "controller_id": ephemeral_role_keys["Sidecar"][1]["key_id"],
        },
        "sidecar_key_hex": _sidecar_key_hex(ephemeral_role_keys),
        "candidate_runtime_root": str(candidate_root),
    }
    result = cli.cli_repo_read(case["ledger_path"], payload)
    assert result["schema_version"] == "openworkproof/cli-result/0.1"
    assert result["tool_name"] == "owp.repo_read"
    assert result["execution_status"] == "succeeded"
    assert result["state_after"] == context.current_state


def test_cli_payload_missing_field_is_clear_error(
    tmp_path, signed_work_order, ephemeral_role_keys, sidecar_receipt_factory, fixed_now
) -> None:
    ledger_path = _activated_ledger(
        tmp_path, signed_work_order, ephemeral_role_keys, sidecar_receipt_factory, fixed_now
    )
    with pytest.raises(cli.CliError, match="missing a required field"):
        cli.cli_run_tests(ledger_path, {})


def test_mcp_server_registers_transport_tools() -> None:
    from openworkproof import mcp_transport

    tools = mcp_transport.mcp._tool_manager._tools
    names = set(tools)
    assert "owp_status" in names
    assert "owp_run_tests" in names
    assert "owp_repo_read" in names


@pytest.mark.parametrize(
    ("status", "expected"),
    (("VERIFIED", 0), ("REFUTED", 2), ("UNKNOWN", 3)),
)
def test_surface_verify_uses_closed_exit_codes(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    status: str,
    expected: int,
) -> None:
    result = {
        "decision_status": status,
        "reason_codes": (
            []
            if status == "VERIFIED"
            else [
                "DELIVERY_REFUTED"
                if status == "REFUTED"
                else "DELIVERY_UNKNOWN"
            ]
        ),
        "bundle_digest": "a" * 64,
    }
    monkeypatch.setattr(cli, "cli_surface_verify", lambda _path: result)
    assert cli.app(["surface-verify", "bundle"]) == expected
    assert json.loads(capsys.readouterr().out) == result


def test_surface_verify_operational_error_is_four(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fail(_path):
        raise cli.CliError("surface input is invalid")

    monkeypatch.setattr(cli, "cli_surface_verify", fail)
    assert cli.app(["surface-verify", "/private/customer/surface"]) == 4
    captured = capsys.readouterr()
    assert json.loads(captured.out) == {
        "decision_status": None,
        "reason_codes": ["OPERATIONAL_ERROR"],
        "bundle_digest": None,
    }
    assert "surface input is invalid" in captured.err
    assert "/private/customer/surface" not in captured.out


def test_surface_build_parser_accepts_signed_fingerprints_only() -> None:
    parsed = cli.build_parser().parse_args(
        [
            "surface-build",
            "delivery",
            "--fingerprint",
            "environment-a.json",
            "--fingerprint",
            "environment-b.json",
            "--output",
            "surface",
        ]
    )
    assert parsed.command == "surface-build"
    assert parsed.fingerprints == [
        "environment-a.json",
        "environment-b.json",
    ]
    assert not any("private_key" in name for name in vars(parsed))


def test_mcp_owp_status_tool(
    tmp_path, signed_work_order, ephemeral_role_keys, sidecar_receipt_factory, fixed_now
) -> None:
    from openworkproof import mcp_transport

    ledger_path = _activated_ledger(
        tmp_path, signed_work_order, ephemeral_role_keys, sidecar_receipt_factory, fixed_now
    )
    result = mcp_transport.owp_status(str(ledger_path))
    assert result["schema_version"] == "openworkproof/mcp/0.2"
    assert result["ok"] is True
    assert result["current_state"] == "running"


def test_mcp_owp_repo_read_tool(
    tmp_path,
    signed_work_order,
    ephemeral_role_keys,
    sidecar_receipt_factory,
    fixed_now,
    monkeypatch,
) -> None:
    from openworkproof import mcp_transport
    from test_repo_read_transaction import (
        _repo_read_request,
        _repo_read_success_case,
    )
    from test_mcp_server import _current_run_tests_context

    case, _ = _repo_read_success_case(
        tmp_path,
        signed_work_order,
        ephemeral_role_keys,
        sidecar_receipt_factory,
        fixed_now,
        monkeypatch,
    )
    context = _current_run_tests_context(case, fixed_now)
    request, arguments = _repo_read_request(
        case, context, ephemeral_role_keys, fixed_now, path="src/app.py"
    )
    candidate_root = tmp_path / "candidate-repo"
    (candidate_root / "src").mkdir(parents=True)
    (candidate_root / "src" / "app.py").write_text("import os\n")
    checkpoint = context.replay_checkpoint
    payload = {
        "now": fixed_now.isoformat(),
        "evidence_root": str(case["evidence_root"]),
        "request": request.model_dump(mode="json"),
        "arguments": arguments.model_dump(mode="json"),
        "checkpoint": {
            "head_commit": checkpoint.head_commit,
            "workspace_manifest_digest": (
                checkpoint.workspace_manifest_digest
            ),
            "workspace_manifest": {
                "schema_version": (
                    checkpoint.workspace_manifest.schema_version
                ),
                "head_commit": checkpoint.workspace_manifest.head_commit,
                "entries": [
                    {
                        "path_bytes_b64url": entry.path_bytes_b64url,
                        "type": entry.type,
                        "posix_mode": entry.posix_mode,
                        "size_bytes": entry.size_bytes,
                        "sha256": entry.sha256,
                        "symlink_target_b64url": entry.symlink_target_b64url,
                    }
                    for entry in checkpoint.workspace_manifest.entries
                ],
            },
        },
        "facts": {
            "execution_context_id": "5" * 64,
            "container_instance_id_digest": "6" * 64,
            "controller_id": ephemeral_role_keys["Sidecar"][1]["key_id"],
        },
        "sidecar_key_hex": _sidecar_key_hex(ephemeral_role_keys),
        "candidate_runtime_root": str(candidate_root),
    }
    result = mcp_transport.owp_repo_read(
        str(case["ledger_path"]), json.dumps(payload)
    )
    assert result["schema_version"] == "openworkproof/mcp/0.2"
    assert result["ok"] is True
    assert result["tool_name"] == "owp.repo_read"
    assert result["execution_status"] == "succeeded"


@pytest.mark.parametrize(
    ("argv", "command"),
    (
        (["profile-validate", "profile.json"], "profile-validate"),
        (["verify-positive", "ledger.sqlite3", "result.json"], "verify-positive"),
        (["verify-negative", "ledger.sqlite3", "result.json"], "verify-negative"),
        (
            [
                "verify-compose",
                "ledger.sqlite3",
                "decision.json",
                "--mode",
                "commit",
            ],
            "verify-compose",
        ),
        (
            [
                "delivery-build",
                "ledger.sqlite3",
                "package",
                "--privacy-view",
                "public",
            ],
            "delivery-build",
        ),
        (["audit-replay", "package"], "audit-replay"),
        (["audit-explain", "package"], "audit-explain"),
        (["audit-compare", "old", "new"], "audit-compare"),
        (["settlement-status", "ledger.sqlite3"], "settlement-status"),
    ),
)
def test_v02_cli_parser_registers_explicit_commands(argv, command) -> None:
    parsed = cli.build_parser().parse_args(argv)
    assert parsed.command == command
    assert not any("private_key" in key for key in vars(parsed))


def test_v02_cli_requires_explicit_compose_mode_and_privacy_view() -> None:
    parser = cli.build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["verify-compose", "ledger.sqlite3", "payload.json"])
    with pytest.raises(SystemExit):
        parser.parse_args(["delivery-build", "ledger.sqlite3", "package"])


def test_v02_cli_routes_through_services(tmp_path, monkeypatch) -> None:
    payload = tmp_path / "payload.json"
    payload.write_text('{"arm_kind":"positive"}', encoding="utf-8")
    calls = []

    class FakeServices:
        def commit_arm_result(self, ledger, value):
            calls.append((ledger, value))
            return {"arm_kind": "positive", "committed": True}

    monkeypatch.setattr(cli, "OpenWorkProofServices", FakeServices)
    result = cli.cli_verify_arm(
        tmp_path / "ledger.sqlite3",
        cli._load_payload(payload),
        expected_kind="positive",
    )
    assert result == {"arm_kind": "positive", "committed": True}
    assert calls == [
        (tmp_path / "ledger.sqlite3", {"arm_kind": "positive"})
    ]


def test_read_only_v02_cli_operations_have_no_private_key_parameters() -> None:
    import inspect

    for function in (
        cli.cli_profile_validate,
        cli.cli_delivery_build,
        cli.cli_audit_replay,
        cli.cli_audit_explain,
        cli.cli_audit_compare,
        cli.cli_settlement_status,
    ):
        assert "private_key" not in inspect.signature(function).parameters


def test_v02_cli_and_mcp_report_equivalent_json_errors(
    tmp_path, monkeypatch, capsys
) -> None:
    from openworkproof import mcp_transport

    profile = tmp_path / "profile.json"
    profile.write_text('{"profile_id":"invalid"}', encoding="utf-8")

    class FakeServices:
        def validate_profile(self, payload):
            raise ValueError("profile is not valid")

    monkeypatch.setattr(cli, "OpenWorkProofServices", FakeServices)
    monkeypatch.setattr(mcp_transport, "OpenWorkProofServices", FakeServices)

    assert cli.app(["profile-validate", str(profile)]) == 1
    cli_error = json.loads(capsys.readouterr().err)
    mcp_error = mcp_transport.owp_validate_profile(profile.read_text())

    assert cli_error == {"error": "profile is not valid"}
    assert mcp_error["ok"] is False
    assert mcp_error["error"] == cli_error["error"]
