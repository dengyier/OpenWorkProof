"""Unit tests for the AgentTeams (hiclaw) controller and Matrix adapters.

These tests mock the subprocess and HTTP boundaries so they run offline
without a live AgentTeams deployment. The real end-to-end walkthrough is
covered separately by the live verification script/notes (Phase 1 step 5).
"""

import json
from unittest import mock

import pytest

from openworkproof.agentteams_controller_client import (
    AgentTeamsControllerClient,
    AgentTeamsControllerError,
    AgentTeamsUnavailableError,
)
from openworkproof.agentteams_matrix_client import (
    AgentTeamsMatrixAuthError,
    AgentTeamsMatrixClient,
    AgentTeamsMatrixError,
)


def _worker(name: str, phase: str = "Running") -> dict:
    return {
        "name": name,
        "phase": phase,
        "model": "deepseek-v4-pro",
        "runtime": "openclaw",
        "matrixUserID": f"@{name}:matrix-local.agentteams.io:18080",
        "roomID": f"!room-{name}:matrix-local.agentteams.io:18080",
        "team": "owp-team",
        "role": "worker",
    }


class _Completed:
    def __init__(self, stdout: str, returncode: int = 0, stderr: str = "") -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


class _JsonResponder:
    """Fake urllib urlopen returning scripted JSON per request."""

    def __init__(self, responses) -> None:
        self._responses = responses
        self.calls: list[tuple[str, str, dict | None]] = []

    def __call__(self, request, data=None, timeout=None):
        path = request.full_url.split("18080", 1)[-1]
        body = json.loads(data) if data else None
        self.calls.append((request.get_method(), path, body))
        response = self._responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return _BytesResponse(response)


class _BytesResponse:
    def __init__(self, payload: dict) -> None:
        self._payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *exc_info) -> None:
        return None

    def read(self) -> bytes:
        return json.dumps(self._payload).encode("utf-8")


# ---- controller client ----------------------------------------------------


def test_controller_client_parses_workers_json(monkeypatch) -> None:
    client = AgentTeamsControllerClient(
        docker="podman", container="at-controller"
    )
    payload = json.dumps({"workers": [_worker("dev-worker")], "total": 1})
    with mock.patch(
        "subprocess.run", return_value=_Completed(payload)
    ) as run:
        workers = client.get_workers()
    run.assert_called_once()
    command = run.call_args.args[0]
    assert command[:4] == [
        "podman",
        "exec",
        "at-controller",
        "agt",
    ]
    assert command[4:] == ["get", "workers", "-o", "json"]
    assert workers[0]["name"] == "dev-worker"
    assert workers[0]["roomID"].startswith("!room-")


def test_controller_client_get_worker_absent(monkeypatch) -> None:
    client = AgentTeamsControllerClient()
    with mock.patch(
        "subprocess.run",
        return_value=_Completed(json.dumps({"workers": []})),
    ):
        assert client.get_worker("nobody") is None


def test_controller_client_apply_yaml_missing_file() -> None:
    client = AgentTeamsControllerClient()
    with pytest.raises(AgentTeamsControllerError):
        client.apply_yaml("/nonexistent/team.yaml")


def test_controller_client_failure_raises(monkeypatch) -> None:
    client = AgentTeamsControllerClient()
    with mock.patch(
        "subprocess.run",
        return_value=_Completed("", returncode=1, stderr="boom"),
    ):
        with pytest.raises(AgentTeamsControllerError) as captured:
            client.get_managers()
    assert "boom" in str(captured.value)


def test_controller_client_unreachable(monkeypatch) -> None:
    client = AgentTeamsControllerClient()
    with mock.patch(
        "subprocess.run", side_effect=OSError("no such container")
    ):
        with pytest.raises(AgentTeamsUnavailableError):
            client.get_teams()


# ---- matrix client --------------------------------------------------------


def test_matrix_login_stores_token(monkeypatch) -> None:
    responder = _JsonResponder([{"access_token": "tok-123", "user_id": "@admin:hs"}])
    monkeypatch.setattr(
        "openworkproof.agentteams_matrix_client.urllib.request.urlopen",
        responder,
    )
    client = AgentTeamsMatrixClient(homeserver="http://hs:18080")
    token = client.login("admin", "pw")
    assert token == "tok-123"
    assert client.token == "tok-123"
    method, path, body = responder.calls[0]
    assert method == "POST"
    assert path == "/_matrix/client/v3/login"
    assert body["password"] == "pw"


def test_matrix_joined_rooms_and_names(monkeypatch) -> None:
    responder = _JsonResponder(
        [
            {"joined_rooms": ["!a:hs", "!b:hs"]},
        ]
    )
    monkeypatch.setattr(
        "openworkproof.agentteams_matrix_client.urllib.request.urlopen",
        responder,
    )
    client = AgentTeamsMatrixClient(homeserver="http://hs:18080", token="t")
    assert client.joined_rooms() == ["!a:hs", "!b:hs"]
    assert responder.calls[0][1] == "/_matrix/client/v3/joined_rooms"


def test_matrix_find_room_by_name(monkeypatch) -> None:
    responder = _JsonResponder(
        [
            {"joined_rooms": ["!a:hs", "!b:hs"]},
            {"name": "Manager: default"},
            {"name": "Worker: dev-worker"},
        ]
    )
    monkeypatch.setattr(
        "openworkproof.agentteams_matrix_client.urllib.request.urlopen",
        responder,
    )
    client = AgentTeamsMatrixClient(homeserver="http://hs:18080", token="t")
    assert client.find_room("Worker:") == "!b:hs"


def test_matrix_worker_room_lookup(monkeypatch) -> None:
    responder = _JsonResponder(
        [
            {"joined_rooms": ["!a:hs", "!b:hs"]},
            {"name": "Manager: default"},
            {"name": "Worker: dev-worker"},
        ]
    )
    monkeypatch.setattr(
        "openworkproof.agentteams_matrix_client.urllib.request.urlopen",
        responder,
    )
    client = AgentTeamsMatrixClient(homeserver="http://hs:18080", token="t")
    assert client.worker_room("dev-worker") == "!b:hs"


def test_matrix_send_text_returns_event_id(monkeypatch) -> None:
    responder = _JsonResponder([{"event_id": "$evt"}])
    monkeypatch.setattr(
        "openworkproof.agentteams_matrix_client.urllib.request.urlopen",
        responder,
    )
    client = AgentTeamsMatrixClient(homeserver="http://hs:18080", token="t")
    event_id = client.send_text("!a:hs", "hello")
    assert event_id == "$evt"
    method, path, body = responder.calls[0]
    assert method == "PUT"
    assert "/send/m.room.message/" in path
    assert body == {"msgtype": "m.text", "body": "hello"}


def test_matrix_read_timeline_filters_messages(monkeypatch) -> None:
    events = [
        {
            "type": "m.room.message",
            "sender": "@manager:hs",
            "content": {"msgtype": "m.text", "body": "reply"},
        },
        {"type": "m.room.member", "sender": "@admin:hs", "content": {}},
        {
            "type": "m.room.message",
            "sender": "@admin:hs",
            "content": {"msgtype": "m.text", "body": "ask"},
        },
    ]
    responder = _JsonResponder([{"chunk": events}])
    monkeypatch.setattr(
        "openworkproof.agentteams_matrix_client.urllib.request.urlopen",
        responder,
    )
    client = AgentTeamsMatrixClient(homeserver="http://hs:18080", token="t")
    timeline = client.read_timeline("!a:hs", limit=10)
    assert timeline == [
        {"sender": "@manager:hs", "body": "reply"},
        {"sender": "@admin:hs", "body": "ask"},
    ]
    assert "dir=b" in responder.calls[0][1]


def test_matrix_requires_token() -> None:
    client = AgentTeamsMatrixClient(homeserver="http://hs:18080")
    with pytest.raises(AgentTeamsMatrixAuthError):
        client.joined_rooms()


def test_matrix_auth_failure(monkeypatch) -> None:
    import urllib.error

    error = urllib.error.HTTPError(
        "http://hs:18080/x", 401, "unauthorized", None, None
    )
    responder = _JsonResponder([error])
    monkeypatch.setattr(
        "openworkproof.agentteams_matrix_client.urllib.request.urlopen",
        responder,
    )
    client = AgentTeamsMatrixClient(homeserver="http://hs:18080", token="t")
    with pytest.raises(AgentTeamsMatrixAuthError):
        client.joined_rooms()


def test_matrix_unreachable(monkeypatch) -> None:
    responder = _JsonResponder([OSError("connection refused")])
    monkeypatch.setattr(
        "openworkproof.agentteams_matrix_client.urllib.request.urlopen",
        responder,
    )
    client = AgentTeamsMatrixClient(homeserver="http://hs:18080", token="t")
    with pytest.raises(AgentTeamsMatrixError):
        client.send_text("!a:hs", "x")
