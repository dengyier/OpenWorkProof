from __future__ import annotations

import hashlib
import io
import json
from datetime import datetime, timezone

import pytest
import rfc8785

from openworkproof.dsh_bridge import DshBridgeApplication, run_stdio_bridge
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


def test_lost_ack_replays_cached_committed_truth() -> None:
    calls: list[str] = []

    def action(_payload):
        calls.append("committed")
        return "a" * 64

    app = DshBridgeApplication(clock=lambda: NOW, action_handler=action)
    app.handle_line(rfc8785.dumps(_hello()))
    execution = {
        "session_id": "session-1",
        "call_id": "call-1",
        "root_call_id": "call-1",
        "tool_name": "owp_run_tests",
        "arguments_digest": "b" * 64,
    }
    request = _request(
        "action_execute",
        1,
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
