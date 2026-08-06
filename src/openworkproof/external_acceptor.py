"""Reference external Acceptor service and client for delivery validation.

The external Acceptor is a *separate process* that holds only the Acceptor
private key and the draft messages sent to it over a real TCP connection. It
never touches the system ledger, the system keys, or the evidence root.

Protocol (JSON lines over TCP):

- request  ``{"action": "sign-acceptance", "draft": <AcceptanceReceipt json>}``
- request  ``{"action": "sign-rejection", "rejection": <raw json>}``
- response ``{"ok": true, "receipt": <signed receipt json>}``
- response ``{"ok": false, "error": <str>}``

Behavioural fault injection (for V6/V7 verification):

- ``OWP_ACCEPTOR_DELAY_MS``  — respond after N ms (client timeout test)
- ``OWP_ACCEPTOR_DROP``     — close the connection without a response
- ``OWP_ACCEPTOR_REFUSE``   — reject with an error response
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import sys
import threading
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from openworkproof.models import AcceptanceReceipt, AcceptanceRejectionReceipt
from openworkproof.signing import sign_payload

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 18741


def load_acceptor_key(key_hex: str) -> Ed25519PrivateKey:
    raw = bytes.fromhex(key_hex)
    if len(raw) != 32:
        raise ValueError("acceptor key must be 32 raw bytes")
    return Ed25519PrivateKey.from_private_bytes(raw)


class ExternalAcceptorServer:
    """A minimal TCP server that signs acceptance/rejection drafts."""

    def __init__(
        self,
        private_key: Ed25519PrivateKey,
        *,
        host: str = DEFAULT_HOST,
        port: int = DEFAULT_PORT,
        delay_ms: int = 0,
        drop: bool = False,
        refuse: bool = False,
    ) -> None:
        self._key = private_key
        self._host = host
        self._port = port
        self._delay_ms = delay_ms
        self._drop = drop
        self._refuse = refuse
        self._socket: socket.socket | None = None
        self._thread: threading.Thread | None = None

    @property
    def port(self) -> int:
        return self._port

    def start(self) -> None:
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind((self._host, self._port))
        self._socket.listen(4)
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._socket is not None:
            try:
                self._socket.close()
            except OSError:
                pass
            self._socket = None

    def _serve(self) -> None:
        assert self._socket is not None
        while True:
            try:
                conn, _ = self._socket.accept()
            except OSError:
                return
            try:
                self._handle(conn)
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

    def _handle(self, conn: socket.socket) -> None:
        try:
            raw = conn.recv(65536)
        except OSError:
            return
        if not raw:
            return
        if self._delay_ms:
            threading.Event().wait(self._delay_ms / 1000.0)
        if self._drop:
            return
        try:
            request = json.loads(raw.decode("utf-8"))
            if self._refuse:
                response = {"ok": False, "error": "acceptor refused the request"}
            else:
                response = self._dispatch(request)
        except Exception as error:  # noqa: BLE001
            response = {"ok": False, "error": repr(error)}
        try:
            conn.sendall((json.dumps(response) + "\n").encode("utf-8"))
        except OSError:
            pass

    def _dispatch(self, request: dict[str, Any]) -> dict[str, Any]:
        action = request.get("action")
        if action == "sign-acceptance":
            draft = request["draft"]
            if type(draft) is not dict:
                return {"ok": False, "error": "draft must be an object"}
            signed = sign_payload("acceptance-receipt", draft, self._key)
            return {"ok": True, "receipt": signed}
        if action == "sign-rejection":
            rejection = request["rejection"]
            if type(rejection) is not dict:
                return {"ok": False, "error": "rejection must be an object"}
            signed = sign_payload(
                "acceptance-rejection-receipt", rejection, self._key
            )
            return {"ok": True, "receipt": signed}
        return {"ok": False, "error": "unknown action"}


class ExternalAcceptorClient:
    """Client side: send drafts to the external Acceptor over TCP."""

    def __init__(self, *, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT, timeout: float = 5.0):
        self._host = host
        self._port = port
        self._timeout = timeout

    def sign_acceptance(self, draft) -> AcceptanceReceipt:
        """Sign an externally signable acceptance draft over the socket."""
        from openworkproof.acceptance import AcceptanceSigningDraft

        if not isinstance(draft, AcceptanceSigningDraft):
            raise TypeError("expected an AcceptanceSigningDraft")
        request = {
            "action": "sign-acceptance",
            "draft": json.loads(draft.canonical_payload),
        }
        response = self._round_trip(request)
        return AcceptanceReceipt.model_validate(response["receipt"])

    def sign_rejection(self, rejection: dict[str, object]) -> AcceptanceRejectionReceipt:
        request = {"action": "sign-rejection", "rejection": rejection}
        response = self._round_trip(request)
        return AcceptanceRejectionReceipt.model_validate(response["receipt"])

    def _round_trip(self, request: dict[str, Any]) -> dict[str, Any]:
        with socket.create_connection(
            (self._host, self._port), timeout=self._timeout
        ) as conn:
            conn.settimeout(self._timeout)
            conn.sendall((json.dumps(request) + "\n").encode("utf-8"))
            data = conn.recv(65536)
        if not data:
            raise ConnectionError("external acceptor closed the connection without a response")
        response = json.loads(data.decode("utf-8"))
        if not response.get("ok"):
            raise RuntimeError(response.get("error", "external acceptor refused"))
        return response


def main() -> int:
    """Subprocess entry point: ``python -m openworkproof.external_acceptor``."""
    key_hex = os.environ["OWP_ACCEPTOR_KEY_HEX"]
    host = os.environ.get("OWP_ACCEPTOR_HOST", DEFAULT_HOST)
    port = int(os.environ.get("OWP_ACCEPTOR_PORT", str(DEFAULT_PORT)))
    delay_ms = int(os.environ.get("OWP_ACCEPTOR_DELAY_MS", "0"))
    drop = os.environ.get("OWP_ACCEPTOR_DROP", "") == "1"
    refuse = os.environ.get("OWP_ACCEPTOR_REFUSE", "") == "1"
    server = ExternalAcceptorServer(
        load_acceptor_key(key_hex),
        host=host,
        port=port,
        delay_ms=delay_ms,
        drop=drop,
        refuse=refuse,
    )
    server.start()
    # Keep the process alive until terminated.
    threading.Event().wait()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
