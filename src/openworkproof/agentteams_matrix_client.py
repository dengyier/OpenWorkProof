"""Execution-plane client for AgentTeams (hiclaw) over the Matrix
client-server API.

AgentTeams routes all task submission and collaboration through Matrix
rooms: humans @mention the Manager, the Manager delegates to Team Leaders,
and Leaders assign Workers. There is no task-dispatch REST API, so the
execution plane must speak Matrix directly. This client implements the
minimal Matrix surface OWP needs (login, room discovery, message send,
timeline read) using only the standard library, so it deploys unchanged in
offline candidate images.

Config comes from environment variables:

- ``AGENTTEAMS_HOMESERVER`` — Matrix homeserver base URL (default
  ``http://127.0.0.1:18080``)
- ``AGENTTEAMS_MATRIX_TIMEOUT`` — per-request timeout seconds (default 10.0)

The admin password is accepted only at login time; the client never stores
it. The access token is kept in memory (or injected via ``set_token``) and
is never written to disk or to any repository file.
"""

from __future__ import annotations

import json
import logging
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

_logger = logging.getLogger("openworkproof.agentteams_matrix_client")

DEFAULT_HOMESERVER = "http://127.0.0.1:18080"
DEFAULT_TIMEOUT = 10.0


class AgentTeamsMatrixError(Exception):
    """Base class for execution-plane (Matrix) failures."""


class AgentTeamsMatrixAuthError(AgentTeamsMatrixError):
    """The Matrix login or bearer token was rejected."""


class AgentTeamsMatrixRequestError(AgentTeamsMatrixError):
    """The homeserver returned an error response."""


class AgentTeamsMatrixClient:
    """Minimal Matrix client-server API client for AgentTeams rooms."""

    def __init__(
        self,
        *,
        homeserver: str | None = None,
        timeout: float | None = None,
        token: str | None = None,
    ) -> None:
        self._homeserver = (
            homeserver
            or os.environ.get("AGENTTEAMS_HOMESERVER", DEFAULT_HOMESERVER)
        ).rstrip("/")
        self._timeout = float(
            os.environ.get("AGENTTEAMS_MATRIX_TIMEOUT", str(DEFAULT_TIMEOUT))
        )
        self._token = token

    # ---- auth --------------------------------------------------------------

    @property
    def token(self) -> str | None:
        return self._token

    def set_token(self, token: str) -> None:
        self._token = token

    def login(self, user: str, password: str) -> str:
        """Password login; returns and stores the access token."""
        response = self._request(
            "POST",
            "/_matrix/client/v3/login",
            body={
                "type": "m.login.password",
                "identifier": {"type": "m.id.user", "user": user},
                "password": password,
            },
            authed=False,
        )
        token = response.get("access_token")
        if not isinstance(token, str) or not token:
            raise AgentTeamsMatrixAuthError("login response has no token")
        self._token = token
        return token

    # ---- rooms -------------------------------------------------------------

    def joined_rooms(self) -> list[str]:
        """Return the joined room IDs."""
        response = self._request("GET", "/_matrix/client/v3/joined_rooms")
        return list(response.get("joined_rooms", []))

    def room_name(self, room_id: str) -> str | None:
        """Return the ``m.room.name`` state of one room, or ``None``."""
        response = self._request(
            "GET",
            f"/_matrix/client/v3/rooms/{_quote(room_id)}/state/m.room.name",
        )
        name = response.get("name")
        return name if isinstance(name, str) else None

    def find_room(self, name_fragment: str) -> str | None:
        """Return the room ID whose name contains ``name_fragment``."""
        for room_id in self.joined_rooms():
            name = self.room_name(room_id)
            if name and name_fragment in name:
                return room_id
        return None

    def worker_room(self, worker_name: str) -> str | None:
        """Locate the worker's own room (named ``Worker: <name>``)."""
        return self.find_room(f"Worker: {worker_name}")

    # ---- messaging ---------------------------------------------------------

    def send_text(self, room_id: str, body: str) -> str:
        """Send an ``m.text`` message; returns the event id."""
        txn_id = f"owp-{int(time.time() * 1000)}"
        response = self._request(
            "PUT",
            f"/_matrix/client/v3/rooms/{_quote(room_id)}/send/"
            f"m.room.message/{txn_id}",
            body={"msgtype": "m.text", "body": body},
        )
        event_id = response.get("event_id")
        if not isinstance(event_id, str):
            raise AgentTeamsMatrixRequestError("send response has no event id")
        return event_id

    def read_timeline(
        self, room_id: str, *, limit: int = 20
    ) -> list[dict[str, Any]]:
        """Return recent ``m.room.message`` events (id, sender, body) newest
        first, as a plain list of dicts."""
        query = urllib.parse.urlencode({"dir": "b", "limit": str(limit)})
        response = self._request(
            "GET",
            f"/_matrix/client/v3/rooms/{_quote(room_id)}/messages?{query}",
        )
        events: list[dict[str, Any]] = []
        chunks = response.get("chunk", [])
        if not isinstance(chunks, list):
            raise AgentTeamsMatrixRequestError("timeline chunk is not a list")
        for chunk in chunks:
            if not isinstance(chunk, dict):
                raise AgentTeamsMatrixRequestError(
                    "timeline event is not an object"
                )
            if chunk.get("type") != "m.room.message":
                continue
            content = chunk.get("content") or {}
            if not isinstance(content, dict):
                raise AgentTeamsMatrixRequestError(
                    "timeline message content is not an object"
                )
            if content.get("msgtype") != "m.text":
                continue
            event_id = chunk.get("event_id")
            sender = chunk.get("sender")
            body = content.get("body")
            if not isinstance(event_id, str) or not event_id:
                raise AgentTeamsMatrixRequestError(
                    "timeline message has no event id"
                )
            if not isinstance(sender, str) or not sender:
                raise AgentTeamsMatrixRequestError(
                    "timeline message has no sender"
                )
            if not isinstance(body, str):
                raise AgentTeamsMatrixRequestError(
                    "timeline message has no text body"
                )
            events.append(
                {
                    "event_id": event_id,
                    "sender": sender,
                    "body": body,
                }
            )
        return events

    # ---- internals ---------------------------------------------------------

    def _request(
        self,
        method: str,
        path: str,
        *,
        body: dict[str, Any] | None = None,
        authed: bool = True,
    ) -> dict[str, Any]:
        request = urllib.request.Request(
            self._homeserver + path, method=method
        )
        data: bytes | None = None
        if body is not None:
            request.add_header("Content-Type", "application/json")
            data = json.dumps(body).encode("utf-8")
        if authed:
            if not self._token:
                raise AgentTeamsMatrixAuthError(
                    "access token is required (login first)"
                )
            request.add_header("Authorization", f"Bearer {self._token}")
        try:
            with urllib.request.urlopen(
                request, data=data, timeout=self._timeout
            ) as response:
                raw = response.read().decode("utf-8")
        except urllib.error.HTTPError as error:
            try:
                detail = error.read().decode("utf-8", errors="replace")
            finally:
                error.close()
            if error.code in (401, 403):
                raise AgentTeamsMatrixAuthError(
                    f"matrix auth failed ({error.code}): {detail}"
                ) from error
            raise AgentTeamsMatrixRequestError(
                f"matrix request failed ({error.code}): {detail}"
            ) from error
        except OSError as error:
            raise AgentTeamsMatrixError(
                f"matrix homeserver unreachable: {error}"
            ) from error
        if not raw:
            return {}
        try:
            parsed = json.loads(raw)
        except ValueError as error:
            raise AgentTeamsMatrixRequestError(
                "matrix response is not JSON"
            ) from error
        if not isinstance(parsed, dict):
            raise AgentTeamsMatrixRequestError(
                "matrix response is not an object"
            )
        return parsed


def _quote(value: str) -> str:
    return urllib.parse.quote(value, safe="")
