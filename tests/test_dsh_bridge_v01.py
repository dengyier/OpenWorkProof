from __future__ import annotations

import hashlib
import io
import json
import os
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from openworkproof.dsh_bridge import (
    DshBridgeApplication,
    DshCaseHandlers,
    run_stdio_bridge,
)
from openworkproof.dsh_protocol import (
    DshObservationRecordV01,
    verify_dsh_observation,
)
from openworkproof.cli import build_parser


NOW = datetime(2026, 8, 26, tzinfo=timezone.utc)


def _request(
    message_type: str,
    sequence: int,
    payload: dict[str, object],
    *,
    request_id: str | None = None,
) -> dict[str, object]:
    candidate = {
        "schema_version": "openworkproof-dsh-bridge/0.1",
        "request_id": "0" * 64,
        "session_id": "session-1",
        "message_type": message_type,
        "sequence": sequence,
        "timestamp": "2026-08-26T00:00:00Z",
        "payload": payload,
    }
    candidate["request_id"] = request_id or hashlib.sha256(
        rfc8785.dumps(
            {key: value for key, value in candidate.items() if key != "request_id"}
        )
    ).hexdigest()
    return candidate


def _hello() -> dict[str, object]:
    return _request(
        "hello",
        0,
        {
            "host": "deepseek-harness",
            "host_version": "0.1.1-rc.2",
            "adapter_version": "0.1.0",
            "bridge_protocol": "0.1",
        },
    )


def _shutdown() -> dict[str, object]:
    return _request("shutdown", 1, {"reason": "client_shutdown"})


def _observation(
    *,
    authorization_status: str = "not_evidenced",
    receipt_digest: str | None = None,
    evidence_gap_codes: list[str] | None = None,
) -> dict[str, object]:
    return {
        "schema_version": "openworkproof-dsh-observation/0.1",
        "host": "deepseek-harness",
        "host_version": "0.1.1-rc.2",
        "adapter_version": "0.1.0",
        "execution": {
            "session_id": "session-1",
            "call_id": "call-1",
            "root_call_id": "call-1",
            "tool_name": "owp_run_tests",
            "arguments_digest": "b" * 64,
        },
        "authorization_status": authorization_status,
        "live_result_digest": "f" * 64,
        "durable_call_sequence": 10,
        "durable_result_sequence": 11,
        "receipt_digest": receipt_digest,
        "evidence_gap_codes": evidence_gap_codes
        if evidence_gap_codes is not None
        else ["AUTHORIZATION_NOT_EVIDENCED"],
        "observed_at": "2026-08-26T00:00:00Z",
        "nonce": "e" * 64,
    }


def _open_fake_case(
    monkeypatch,
    tmp_path,
    *,
    action_handler=None,
    handler_factory=None,
    committed_truth_lookup=None,
):
    private_key = Ed25519PrivateKey.generate()
    raw_key = private_key.private_bytes_raw()
    key_path = tmp_path / "sidecar.key"
    key_path.write_bytes(raw_key)
    os.chmod(key_path, 0o600)
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    manifest = SimpleNamespace(
        case_id="c" * 64,
        sidecar_key_path=str(key_path),
        evidence_root=str(evidence_root),
        allowed_tools=("owp_apply_patch", "owp_run_tests"),
    )
    monkeypatch.setattr(
        "openworkproof.dsh_bridge.load_dsh_case",
        lambda _path: manifest,
    )
    app = DshBridgeApplication(
        clock=lambda: NOW,
        action_handler=action_handler,
        handler_factory=handler_factory,
        committed_truth_lookup=(
            committed_truth_lookup
            or (lambda _manifest, _payload: None)
        ),
    )
    app.handle_line(rfc8785.dumps(_hello()))
    response = json.loads(
        app.handle_line(
            rfc8785.dumps(
                _request(
                    "case_open",
                    1,
                    {"case_manifest_path": str(tmp_path)},
                )
            )
        )
    )
    assert response["payload"]["result_digest"] == "c" * 64
    return app, private_key, evidence_root


def test_open_case_builds_case_scoped_handlers_with_shared_tokens(
    monkeypatch,
    tmp_path,
) -> None:
    seen = []

    def factory(manifest, decision_tokens):
        seen.append((manifest.case_id, decision_tokens))
        return DshCaseHandlers(
            action=lambda _payload: "a" * 64,
            verify=lambda _payload: "b" * 64,
            acceptance_draft=lambda _payload: "c" * 64,
            export=lambda _payload: "d" * 64,
        )

    app, _private_key, _evidence_root = _open_fake_case(
        monkeypatch,
        tmp_path,
        handler_factory=factory,
    )

    assert len(seen) == 1
    assert seen[0][0] == "c" * 64
    assert seen[0][1] is app.decision_tokens


def test_bridge_stdout_contains_jsonl_only() -> None:
    source = "".join(
        json.dumps(item, separators=(",", ":")) + "\n"
        for item in (_hello(), _shutdown())
    )
    stdout = io.StringIO()

    result = run_stdio_bridge(
        io.StringIO(source),
        stdout,
        io.StringIO(),
        clock=lambda: NOW,
    )

    assert result == 0
    messages = [json.loads(line) for line in stdout.getvalue().splitlines()]
    assert [item["message_type"] for item in messages] == ["ready", "shutdown"]
    assert all(line == line.strip() for line in stdout.getvalue().splitlines())


def test_stdio_default_wires_production_case_handlers(
    monkeypatch,
    tmp_path,
) -> None:
    manifest = SimpleNamespace(
        case_id="c" * 64,
        allowed_tools=("owp_apply_patch",),
    )
    monkeypatch.setattr(
        "openworkproof.dsh_bridge.load_dsh_case",
        lambda _path: manifest,
    )
    calls: list[object] = []

    def factory(opened, tokens, *, clock):
        calls.append((opened, tokens, clock()))
        return DshCaseHandlers(
            action=lambda _payload: "a" * 64,
            verify=lambda _payload: "b" * 64,
            acceptance_draft=lambda _payload: "c" * 64,
            export=lambda _payload: "d" * 64,
        )

    monkeypatch.setattr(
        "openworkproof.dsh_handlers.build_dsh_case_handlers",
        factory,
    )
    messages = (
        _hello(),
        _request(
            "case_open",
            1,
            {"case_manifest_path": str(tmp_path)},
        ),
        _request("shutdown", 2, {"reason": "client_shutdown"}),
    )
    source = "".join(
        json.dumps(item, separators=(",", ":")) + "\n" for item in messages
    )

    result = run_stdio_bridge(
        io.StringIO(source),
        io.StringIO(),
        io.StringIO(),
        clock=lambda: NOW,
    )

    assert result == 0
    assert len(calls) == 1
    assert calls[0][0] is manifest
    assert calls[0][2] == NOW


def test_duplicate_request_bytes_return_the_exact_cached_response() -> None:
    app = DshBridgeApplication(clock=lambda: NOW)
    raw = rfc8785.dumps(_hello())

    first = app.handle_line(raw)
    second = app.handle_line(raw)

    assert second == first


def test_duplicate_request_id_with_different_bytes_is_protocol_error() -> None:
    app = DshBridgeApplication(clock=lambda: NOW)
    hello = _hello()
    app.handle_line(rfc8785.dumps(hello))
    conflicting = {**hello, "timestamp": "2026-08-26T00:00:01Z"}

    response = json.loads(app.handle_line(rfc8785.dumps(conflicting)))

    assert response["message_type"] == "error"
    assert response["payload"]["error_kind"] == "operational_failure"
    assert response["payload"]["reason_code"] == "REQUEST_ID_CONFLICT"


def test_lost_ack_replays_cached_committed_truth(monkeypatch, tmp_path) -> None:
    calls: list[str] = []

    def action(_payload):
        calls.append("committed")
        return "a" * 64

    app, _private_key, _evidence_root = _open_fake_case(
        monkeypatch,
        tmp_path,
        action_handler=action,
    )
    execution = {
        "session_id": "session-1",
        "call_id": "call-1",
        "root_call_id": "call-1",
        "tool_name": "owp_run_tests",
        "arguments_digest": "b" * 64,
    }
    request = _request(
        "action_execute",
        2,
        {
            "case_id": "c" * 64,
            "execution": execution,
            "decision_token": "d" * 64,
            "patch_text": None,
            "target_paths": None,
            "test_profile_digest": "e" * 64,
        },
    )
    raw = rfc8785.dumps(request)

    first = app.handle_line(raw)
    second = app.handle_line(raw)

    assert json.loads(first)["payload"]["result_digest"] == "a" * 64
    assert second == first
    assert calls == ["committed"]


def test_indeterminate_committed_truth_never_replays_action(
    monkeypatch,
    tmp_path,
) -> None:
    calls: list[str] = []

    def action(_payload):
        calls.append("replayed")
        return "a" * 64

    def unavailable(_manifest, _payload):
        raise OSError("ledger unavailable")

    app, _private_key, _evidence_root = _open_fake_case(
        monkeypatch,
        tmp_path,
        action_handler=action,
        committed_truth_lookup=unavailable,
    )
    response = json.loads(
        app.handle_line(
            rfc8785.dumps(
                _request(
                    "action_execute",
                    2,
                    {
                        "case_id": "c" * 64,
                        "execution": _observation()["execution"],
                        "decision_token": "d" * 64,
                        "patch_text": None,
                        "target_paths": None,
                        "test_profile_digest": "e" * 64,
                    },
                )
            )
        )
    )

    assert response["payload"]["status"] == "unknown"
    assert response["payload"]["reason_code"] == "COMMITTED_TRUTH_UNAVAILABLE"
    assert calls == []


def test_observation_commit_is_signed_by_bridge_and_stored_immutably(
    monkeypatch,
    tmp_path,
) -> None:
    app, private_key, evidence_root = _open_fake_case(monkeypatch, tmp_path)

    response = json.loads(
        app.handle_line(
            rfc8785.dumps(
                _request(
                    "observation_commit",
                    2,
                    {"case_id": "c" * 64, "observation": _observation()},
                )
            )
        )
    )

    assert response["message_type"] == "observation_result"
    assert response["payload"]["status"] == "ok"
    record_id = response["payload"]["result_digest"]
    record_path = evidence_root / "dsh-observations" / f"{record_id}.json"
    record = DshObservationRecordV01.model_validate_json(
        record_path.read_bytes()
    )
    assert record.record_id == record_id
    assert verify_dsh_observation(record, private_key.public_key())


def test_observation_cannot_substitute_an_uncommitted_receipt(
    monkeypatch,
    tmp_path,
) -> None:
    app, _private_key, evidence_root = _open_fake_case(monkeypatch, tmp_path)

    response = json.loads(
        app.handle_line(
            rfc8785.dumps(
                _request(
                    "observation_commit",
                    2,
                    {
                        "case_id": "c" * 64,
                        "observation": _observation(
                            authorization_status="authorized",
                            receipt_digest="a" * 64,
                            evidence_gap_codes=[],
                        ),
                    },
                )
            )
        )
    )

    assert response["payload"]["status"] == "denied"
    assert response["payload"]["reason_code"] == "RECEIPT_BINDING_MISSING"
    assert not (evidence_root / "dsh-observations").exists()


def test_observation_binds_the_exact_action_committed_by_the_bridge(
    monkeypatch,
    tmp_path,
) -> None:
    receipt_digest = "a" * 64
    app, _private_key, evidence_root = _open_fake_case(
        monkeypatch,
        tmp_path,
        action_handler=lambda _payload: receipt_digest,
    )
    execution = _observation()["execution"]
    authorization = json.loads(
        app.handle_line(
            rfc8785.dumps(
                _request(
                    "authorization_check",
                    2,
                    {"case_id": "c" * 64, "execution": execution},
                )
            )
        )
    )
    token = authorization["payload"]["decision_token"]
    action = json.loads(
        app.handle_line(
            rfc8785.dumps(
                _request(
                    "action_execute",
                    3,
                    {
                        "case_id": "c" * 64,
                        "execution": execution,
                        "decision_token": token,
                        "patch_text": None,
                        "target_paths": None,
                        "test_profile_digest": "e" * 64,
                    },
                )
            )
        )
    )
    assert action["payload"]["result_digest"] == receipt_digest

    observation = json.loads(
        app.handle_line(
            rfc8785.dumps(
                _request(
                    "observation_commit",
                    4,
                    {
                        "case_id": "c" * 64,
                        "observation": _observation(
                            authorization_status="authorized",
                            receipt_digest=receipt_digest,
                            evidence_gap_codes=[],
                        ),
                    },
                )
            )
        )
    )

    assert observation["payload"]["status"] == "ok"
    assert len(list((evidence_root / "dsh-observations").iterdir())) == 1


def test_line_over_one_mib_is_rejected_without_dispatch() -> None:
    app = DshBridgeApplication(clock=lambda: NOW)

    with pytest.raises(ValueError, match="1 MiB"):
        app.handle_line(b"{" + b" " * 1_048_576 + b"}")


def test_cli_exposes_stdio_and_keyless_case_commands() -> None:
    parser = build_parser()

    assert parser.parse_args(["dsh-bridge", "--stdio"]).command == "dsh-bridge"
    draft = parser.parse_args(
        ["dsh-case", "acceptance-draft", "/case", "--output", "/draft"]
    )
    assert draft.dsh_case_action == "acceptance-draft"
    assert not hasattr(draft, "private_key")
