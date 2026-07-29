"""Atomic SQLite authority and root-reservation tests for Task 7A."""

from __future__ import annotations

import copy
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import threading
from typing import Callable

import pytest
import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

import openworkproof.evidence as evidence
from openworkproof.evidence import (
    BUSY_TIMEOUT_MS,
    LedgerInitializationError,
    RootActivationError,
    activate_root_grant,
    connect_ledger,
    initialize_ledger,
    load_authoritative_work_order,
)
from openworkproof.models import AgentRequest, CapabilityGrant, WorkOrder
from openworkproof.repo_tools import (
    ResolutionManifest,
    ResolutionManifestEntry,
    resolution_manifest_digest,
)
from openworkproof.signing import digest_payload, key_id, sign_payload


def _jcs_digest(value: object) -> str:
    return hashlib.sha256(rfc8785.dumps(value)).hexdigest()


def _canonical_json(value: object) -> str:
    return rfc8785.dumps(value).decode("utf-8")


def _resigned_work_order(
    work_order: WorkOrder,
    private_key: Ed25519PrivateKey,
    *,
    json_updates: dict[str, object],
    model_updates: dict[str, object],
) -> WorkOrder:
    raw = work_order.model_dump(mode="json")
    raw.update(copy.deepcopy(json_updates))
    signed = sign_payload("work-order", raw, private_key)
    return work_order.model_copy(
        update={
            **model_updates,
            "digest": signed["digest"],
            "signature_alg": signed["signature_alg"],
            "signer_key_id": signed["signer_key_id"],
            "signature": signed["signature"],
        }
    )


def _invalid_work_order(
    case: str,
    work_order: WorkOrder,
    role_keys: dict[str, tuple[Ed25519PrivateKey, dict[str, str]]],
) -> WorkOrder:
    if case == "signature":
        return work_order.model_copy(update={"objective": "tampered"})
    if case == "key_binding":
        bindings = list(work_order.key_bindings)
        bindings[1] = bindings[1].model_copy(
            update={
                "public_key_b64url": bindings[2].public_key_b64url,
            }
        )
        return _resigned_work_order(
            work_order,
            role_keys["Maintainer"][0],
            json_updates={
                "key_bindings": [
                    binding.model_dump(mode="json") for binding in bindings
                ],
            },
            model_updates={"key_bindings": tuple(bindings)},
        )
    if case == "issuer":
        return _resigned_work_order(
            work_order,
            role_keys["Maintainer"][0],
            json_updates={"issuer_id": "manager"},
            model_updates={"issuer_id": "manager"},
        )
    if case == "signer":
        manager_key = role_keys["Manager"][0]
        return _resigned_work_order(
            work_order,
            manager_key,
            json_updates={},
            model_updates={},
        )
    if case == "acceptor":
        manager_key_id = work_order.key_bindings[1].key_id
        return _resigned_work_order(
            work_order,
            role_keys["Maintainer"][0],
            json_updates={"acceptor_key_ids": [manager_key_id]},
            model_updates={"acceptor_key_ids": (manager_key_id,)},
        )
    raise AssertionError(f"unknown invalid WorkOrder case: {case}")


def _resigned_root_grant(
    grant: CapabilityGrant,
    private_key: Ed25519PrivateKey,
) -> CapabilityGrant:
    raw = grant.model_dump(mode="json")
    raw["quota"]["tool_calls"] -= 1
    return CapabilityGrant.model_validate(
        sign_payload("capability-grant", raw, private_key)
    )


def _activation_request(
    work_order: WorkOrder,
    candidate: CapabilityGrant,
    role_keys: dict[str, tuple[Ed25519PrivateKey, dict[str, str]]],
    *,
    actor_role: str,
    nonce: str,
) -> AgentRequest:
    binding = role_keys[actor_role][1]
    arguments = {
        "operation": "activate_root",
        "authorizing_grant_id": candidate.grant_id,
        "candidate_grant_digest": candidate.digest,
    }
    return AgentRequest.model_validate(
        sign_payload(
            "agent-request",
            {
                "claim_type": "agent-request",
                "work_order_digest": work_order.digest,
                "grant_id": candidate.grant_id,
                "actor_id": binding["subject_id"],
                "actor_key_id": binding["key_id"],
                "tool_name": "owp.activate_root_grant",
                "arguments_digest": _jcs_digest(
                    {
                        "domain": "openworkproof/agent-arguments/v0.1",
                        "tool_name": "owp.activate_root_grant",
                        "arguments": arguments,
                    }
                ),
                "nonce": nonce,
                "requested_at": "2026-01-01T00:00:02Z",
                "authentication_method": "agent_signature",
                "model_id": "model",
                "model_version": "1",
                "prompt_template_digest": "a" * 64,
                "context_source_digest": "b" * 64,
            },
            role_keys[actor_role][0],
        )
    )


def _grant_id(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _child_grant(
    work_order: WorkOrder,
    parent: CapabilityGrant,
    role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    *,
    label: str,
    subject_role: str = "Developer",
    signer_role: str = "Manager",
    updates: dict[str, object] | None = None,
) -> CapabilityGrant:
    subject = role_keys[subject_role][1]
    signer = role_keys[signer_role][1]
    raw: dict[str, object] = {
        "grant_id": _grant_id(label),
        "work_order_digest": work_order.digest,
        "parent_grant_id": parent.grant_id,
        "issuer_key_id": signer["key_id"],
        "subject_agent_id": subject["subject_id"],
        "subject_key_id": subject["key_id"],
        "allowed_tools": ["owp.apply_patch", "owp.repo_read"],
        "allowed_read_roots": ["src", "tests"],
        "allowed_write_roots": ["src"],
        "usage_mode": "metered",
        "quota": {"tool_calls": 2, "repair_rounds": 0},
        "valid_from": "2026-01-01T00:00:02Z",
        "expires_at": "2026-01-02T00:00:00Z",
        "may_delegate": False,
        "issued_at": "2026-01-01T00:00:01Z",
    }
    if subject_role == "Verifier":
        raw["allowed_tools"] = ["owp.run_tests"]
        raw["allowed_write_roots"] = []
    if updates:
        raw.update(copy.deepcopy(updates))
    return CapabilityGrant.model_validate(
        sign_payload(
            "capability-grant",
            raw,
            role_keys[signer_role][0],
        )
    )


def _signed_unvalidated_child_update(
    candidate: CapabilityGrant,
    private_key: Ed25519PrivateKey,
    **updates: object,
) -> CapabilityGrant:
    raw = candidate.model_dump(mode="json")
    raw.update(copy.deepcopy(updates))
    signed = sign_payload("capability-grant", raw, private_key)
    return candidate.model_copy(
        update={
            **updates,
            "digest": signed["digest"],
            "signature_alg": signed["signature_alg"],
            "signer_key_id": signed["signer_key_id"],
            "signature": signed["signature"],
        }
    )


def _delegation_request(
    work_order: WorkOrder,
    parent: CapabilityGrant,
    candidate: CapabilityGrant,
    role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    *,
    actor_role: str,
    nonce: str,
    candidate_digest: str | None = None,
) -> AgentRequest:
    binding = role_keys[actor_role][1]
    arguments = {
        "operation": "delegate_child",
        "authorizing_grant_id": parent.grant_id,
        "candidate_grant_digest": (
            candidate.digest
            if candidate_digest is None
            else candidate_digest
        ),
    }
    return AgentRequest.model_validate(
        sign_payload(
            "agent-request",
            {
                "claim_type": "agent-request",
                "work_order_digest": work_order.digest,
                "grant_id": parent.grant_id,
                "actor_id": binding["subject_id"],
                "actor_key_id": binding["key_id"],
                "tool_name": "owp.delegate_grant",
                "arguments_digest": _jcs_digest(
                    {
                        "domain": "openworkproof/agent-arguments/v0.1",
                        "tool_name": "owp.delegate_grant",
                        "arguments": arguments,
                    }
                ),
                "nonce": nonce,
                "requested_at": "2026-01-01T00:00:04Z",
                "authentication_method": "agent_signature",
                "model_id": "model",
                "model_version": "1",
                "prompt_template_digest": "a" * 64,
                "context_source_digest": "b" * 64,
            },
            role_keys[actor_role][0],
        )
    )


def _revocation_request(
    work_order: WorkOrder,
    authorizing_grant: CapabilityGrant,
    revoked_grant: CapabilityGrant,
    role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    *,
    actor_role: str,
    nonce: str,
    revocation_reason: str = "LEAST_PRIVILEGE",
    authorizing_grant_id: str | None = None,
    revoked_grant_id: str | None = None,
    tool_name: str = "owp.revoke_grant",
    arguments_digest: str | None = None,
    work_order_digest: str | None = None,
    requested_at: str = "2026-01-01T00:00:04Z",
) -> AgentRequest:
    binding = role_keys[actor_role][1]
    authorizer_id = (
        authorizing_grant.grant_id
        if authorizing_grant_id is None
        else authorizing_grant_id
    )
    target_id = (
        revoked_grant.grant_id
        if revoked_grant_id is None
        else revoked_grant_id
    )
    arguments = {
        "authorizing_grant_id": authorizer_id,
        "revoked_grant_id": target_id,
        "revocation_reason": revocation_reason,
    }
    return AgentRequest.model_validate(
        sign_payload(
            "agent-request",
            {
                "claim_type": "agent-request",
                "work_order_digest": (
                    work_order.digest
                    if work_order_digest is None
                    else work_order_digest
                ),
                "grant_id": authorizer_id,
                "actor_id": binding["subject_id"],
                "actor_key_id": binding["key_id"],
                "tool_name": tool_name,
                "arguments_digest": (
                    _jcs_digest(
                        {
                            "domain": (
                                "openworkproof/agent-arguments/v0.1"
                            ),
                            "tool_name": tool_name,
                            "arguments": arguments,
                        }
                    )
                    if arguments_digest is None
                    else arguments_digest
                ),
                "nonce": nonce,
                "requested_at": requested_at,
                "authentication_method": "agent_signature",
                "model_id": "model",
                "model_version": "1",
                "prompt_template_digest": "a" * 64,
                "context_source_digest": "b" * 64,
            },
            role_keys[actor_role][0],
        )
    )


def _activate_ledger_root(
    ledger_path: Path,
    work_order: WorkOrder,
    root: CapabilityGrant,
    role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    now: datetime,
) -> None:
    initialize_ledger(ledger_path, work_order)
    activate_root_grant(
        ledger_path,
        root,
        _activation_request(
            work_order,
            root,
            role_keys,
            actor_role="Manager",
            nonce=_grant_id(f"activate:{ledger_path.name}"),
        ),
        sidecar_private_key=role_keys["Sidecar"][0],
        clock=lambda: now,
    )


def _issue_child(
    ledger_path: Path,
    candidate: CapabilityGrant,
    request: AgentRequest,
    role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    now: datetime,
):
    return evidence.issue_child_grant(
        ledger_path,
        candidate,
        request,
        sidecar_private_key=role_keys["Sidecar"][0],
        clock=lambda: now,
    )


def _revoke_child(
    ledger_path: Path,
    authorizing_grant: CapabilityGrant,
    revoked_grant: CapabilityGrant,
    request: AgentRequest,
    role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    now: datetime,
    *,
    revocation_reason: str = "LEAST_PRIVILEGE",
):
    return evidence.revoke_child_grant(
        ledger_path,
        authorizing_grant_id=authorizing_grant.grant_id,
        revoked_grant_id=revoked_grant.grant_id,
        revocation_reason=revocation_reason,
        request=request,
        sidecar_private_key=role_keys["Sidecar"][0],
        clock=lambda: now,
    )


def _rewrite_grant_issuance_history(
    connection: sqlite3.Connection,
    *,
    sequence: int,
    candidate_raw: dict[str, object],
    allowed: bool,
    work_order: WorkOrder,
    role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
) -> dict[str, object]:
    signed_candidate = sign_payload(
        "capability-grant",
        candidate_raw,
        role_keys["Manager"][0],
    )
    grant_id = signed_candidate["grant_id"]
    candidate_digest = signed_candidate["digest"]
    if allowed:
        connection.execute(
            """
            UPDATE grants
            SET
                work_order_digest = ?,
                parent_grant_id = ?,
                subject_agent_id = ?,
                usage_mode = ?,
                grant_json = ?
            WHERE grant_id = ?
            """,
            (
                work_order.digest,
                signed_candidate["parent_grant_id"],
                signed_candidate["subject_agent_id"],
                signed_candidate["usage_mode"],
                _canonical_json(signed_candidate),
                grant_id,
            ),
        )
    else:
        connection.execute(
            """
            UPDATE grant_attempts
            SET
                candidate_grant_digest = ?,
                work_order_digest = ?,
                candidate_grant_json = ?
            WHERE grant_id = ?
            """,
            (
                candidate_digest,
                work_order.digest,
                _canonical_json(signed_candidate),
                grant_id,
            ),
        )
    connection.execute(
        """
        UPDATE grant_id_reservations
        SET candidate_grant_digest = ?
        WHERE grant_id = ?
        """,
        (candidate_digest, grant_id),
    )
    receipt_raw = json.loads(
        connection.execute(
            "SELECT receipt_json FROM receipts WHERE sequence = ?",
            (sequence,),
        ).fetchone()[0]
    )
    receipt_raw["candidate_grant_digest"] = candidate_digest
    nested = copy.deepcopy(receipt_raw["nested_claim"])
    nested["arguments_digest"] = _jcs_digest(
        {
            "domain": "openworkproof/agent-arguments/v0.1",
            "tool_name": "owp.delegate_grant",
            "arguments": {
                "operation": "delegate_child",
                "authorizing_grant_id": (
                    receipt_raw["authorizing_grant_id"]
                ),
                "candidate_grant_digest": candidate_digest,
            },
        }
    )
    manager = role_keys["Manager"][1]
    nested["actor_id"] = manager["subject_id"]
    nested["actor_key_id"] = manager["key_id"]
    signed_nested = sign_payload(
        "agent-request",
        nested,
        role_keys["Manager"][0],
    )
    receipt_raw["actor_id"] = manager["subject_id"]
    receipt_raw["actor_key_id"] = manager["key_id"]
    receipt_raw["nested_claim"] = signed_nested
    receipt_raw["nested_claim_digest"] = signed_nested["digest"]
    signed_receipt = sign_payload(
        "action-receipt",
        receipt_raw,
        role_keys["Sidecar"][0],
    )
    connection.execute(
        "UPDATE receipts SET receipt_json = ? WHERE sequence = ?",
        (_canonical_json(signed_receipt), sequence),
    )
    return signed_candidate


def _assert_child_rejection(error: BaseException) -> None:
    expected = getattr(evidence, "ChildGrantIssuanceError", None)
    assert expected is not None
    assert isinstance(error, expected)


def _assert_write_free_child_integrity_failure(
    *,
    ledger_path: Path,
    candidate: CapabilityGrant,
    request: AgentRequest,
    role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    now: datetime,
    before,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_sign_payload = evidence.sign_payload
    action_receipt_signatures = 0

    def tracked_sign_payload(
        object_type: str,
        value,
        private_key: Ed25519PrivateKey,
    ):
        nonlocal action_receipt_signatures
        if object_type == "action-receipt":
            action_receipt_signatures += 1
        return real_sign_payload(object_type, value, private_key)

    monkeypatch.setattr(evidence, "sign_payload", tracked_sign_payload)
    with pytest.raises(evidence.ChildGrantIssuanceError):
        _issue_child(
            ledger_path,
            candidate,
            request,
            role_keys,
            now,
        )
    assert action_receipt_signatures == 0
    connection = connect_ledger(ledger_path)
    try:
        assert _ledger_integrity_snapshot(connection) == before
    finally:
        connection.close()


def _rows(
    connection: sqlite3.Connection,
    query: str,
) -> tuple[tuple[object, ...], ...]:
    return tuple(tuple(row) for row in connection.execute(query).fetchall())


def _ledger_snapshot(
    connection: sqlite3.Connection,
) -> dict[str, tuple[tuple[object, ...], ...]]:
    return {
        "sequence": _rows(
            connection,
            "SELECT singleton, next_sequence FROM sequence_counter",
        ),
        "state": _rows(
            connection,
            (
                "SELECT work_order_digest, current_state, version "
                "FROM work_order_state"
            ),
        ),
        "reservations": _rows(
            connection,
            (
                "SELECT grant_id, work_order_digest, candidate_grant_digest, "
                "reservation_kind FROM grant_id_reservations ORDER BY grant_id"
            ),
        ),
        "grants": _rows(
            connection,
            "SELECT grant_id, grant_json FROM grants ORDER BY grant_id",
        ),
        "attempts": _rows(
            connection,
            (
                "SELECT candidate_grant_digest, grant_id "
                "FROM grant_attempts ORDER BY candidate_grant_digest"
            ),
        ),
        "receipts": _rows(
            connection,
            (
                "SELECT receipt_id, nonce, sequence "
                "FROM receipts ORDER BY sequence"
            ),
        ),
    }


def _ledger_integrity_snapshot(
    connection: sqlite3.Connection,
) -> tuple[
    dict[str, tuple[tuple[object, ...], ...]],
    tuple[tuple[object, ...], ...],
    tuple[tuple[object, ...], ...],
]:
    return (
        _ledger_snapshot(connection),
        _rows(
            connection,
            """
            SELECT child_receipt_id, parent_receipt_id
            FROM receipt_parents
            ORDER BY child_receipt_id, parent_receipt_id
            """,
        ),
        _rows(
            connection,
            """
            SELECT event_id, receipt_id, grant_id, event_type, metric, amount
            FROM grant_events
            ORDER BY event_id
            """,
        ),
    )


class _FaultingConnection:
    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        fail_when: Callable[[str], bool],
        fail_after_execute: bool = False,
    ) -> None:
        self._connection = connection
        self._fail_when = fail_when
        self._fail_after_execute = fail_after_execute
        self._failed = False
        self.closed = False

    @property
    def in_transaction(self) -> bool:
        return self._connection.in_transaction

    def execute(
        self,
        statement: str,
        parameters: tuple[object, ...] = (),
    ):
        normalized = " ".join(statement.split()).upper()
        should_fail = not self._failed and self._fail_when(normalized)
        if should_fail and self._fail_after_execute:
            self._connection.execute(statement, parameters)
        if should_fail:
            self._failed = True
            raise sqlite3.OperationalError(
                f"injected SQLite failure: {normalized}"
            )
        return self._connection.execute(statement, parameters)

    def close(self) -> None:
        self.closed = True
        self._connection.close()


class _StaticCursor:
    def __init__(self, row: tuple[int, int, int]) -> None:
        self._row = row

    def fetchone(self) -> tuple[int, int, int]:
        return self._row


class _ReadAuditCursor:
    def __init__(
        self,
        cursor,
        normalized_sql: str,
        audit_log: list[tuple[str, str, int | None]],
    ) -> None:
        self._cursor = cursor
        self._normalized_sql = normalized_sql
        self._audit_log = audit_log

    def fetchone(self):
        return self._cursor.fetchone()

    def fetchall(self):
        rows = self._cursor.fetchall()
        self._audit_log.append(
            ("fetchall", self._normalized_sql, len(rows))
        )
        return rows

    def __getattr__(self, name: str):
        return getattr(self._cursor, name)


class _ReadAuditConnection:
    def __init__(
        self,
        connection: sqlite3.Connection,
        audit_log: list[tuple[str, str, int | None]],
    ) -> None:
        self._connection = connection
        self._audit_log = audit_log

    @property
    def in_transaction(self) -> bool:
        return self._connection.in_transaction

    def execute(
        self,
        statement: str,
        parameters: tuple[object, ...] = (),
    ):
        normalized = " ".join(statement.split()).upper()
        self._audit_log.append(("execute", normalized, None))
        return _ReadAuditCursor(
            self._connection.execute(statement, parameters),
            normalized,
            self._audit_log,
        )

    def close(self) -> None:
        self._connection.close()


class _AfterReceiptCountCursor:
    def __init__(self, cursor, callback: Callable[[], None]) -> None:
        self._cursor = cursor
        self._callback = callback
        self._triggered = False

    def fetchone(self):
        row = self._cursor.fetchone()
        if not self._triggered:
            self._triggered = True
            self._callback()
        return row

    def __getattr__(self, name: str):
        return getattr(self._cursor, name)


class _AfterReceiptCountConnection:
    def __init__(
        self,
        connection: sqlite3.Connection,
        callback: Callable[[], None],
    ) -> None:
        self._connection = connection
        self._callback = callback
        self._triggered = False
        self.closed = False

    @property
    def in_transaction(self) -> bool:
        return self._connection.in_transaction

    def execute(
        self,
        statement: str,
        parameters: tuple[object, ...] = (),
    ):
        cursor = self._connection.execute(statement, parameters)
        normalized = " ".join(statement.split()).upper()
        if (
            not self._triggered
            and "COUNT(" in normalized
            and "FROM RECEIPTS" in normalized
        ):
            self._triggered = True
            return _AfterReceiptCountCursor(
                cursor,
                self._callback,
            )
        return cursor

    def close(self) -> None:
        self.closed = True
        self._connection.close()


class _CheckpointConnection(_FaultingConnection):
    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        row: tuple[int, int, int] | None,
    ) -> None:
        super().__init__(connection, fail_when=lambda sql: False)
        self._row = row

    def execute(
        self,
        statement: str,
        parameters: tuple[object, ...] = (),
    ):
        normalized = " ".join(statement.split()).upper()
        if normalized == "PRAGMA WAL_CHECKPOINT(TRUNCATE)":
            if self._row is None:
                raise sqlite3.OperationalError(
                    "injected checkpoint failure"
                )
            return _StaticCursor(self._row)
        return super().execute(statement, parameters)


class _CorruptOnFirstCloseConnection(_FaultingConnection):
    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        database_path: Path,
        corruption: str,
        should_corrupt: list[bool],
    ) -> None:
        super().__init__(connection, fail_when=lambda sql: False)
        self._database_path = database_path
        self._corruption = corruption
        self._should_corrupt = should_corrupt

    def close(self) -> None:
        super().close()
        if not self._should_corrupt[0]:
            return
        self._should_corrupt[0] = False
        connection = sqlite3.connect(
            self._database_path,
            isolation_level=None,
        )
        try:
            if self._corruption == "authority":
                connection.execute(
                    "DROP TRIGGER work_orders_are_immutable_update"
                )
                connection.execute(
                    "UPDATE work_orders SET work_order_json = '{}'"
                )
            elif self._corruption == "sequence":
                connection.execute(
                    "UPDATE sequence_counter SET next_sequence = 2"
                )
            elif self._corruption == "state":
                connection.execute(
                    """
                    UPDATE work_order_state
                    SET current_state = 'running', version = 1
                    """
                )
            elif self._corruption == "reservation":
                connection.execute(
                    """
                    UPDATE grant_id_reservations
                    SET reservation_kind = 'effective',
                        candidate_grant_digest = ?
                    """,
                    ("f" * 64,),
                )
            else:
                raise AssertionError(
                    f"unknown corruption: {self._corruption}"
                )
        finally:
            connection.close()


class _CloseFailsOnceConnection(_FaultingConnection):
    def __init__(self, connection: sqlite3.Connection) -> None:
        super().__init__(connection, fail_when=lambda sql: False)
        self.close_attempts = 0

    def close(self) -> None:
        self.close_attempts += 1
        if self.close_attempts == 1:
            raise sqlite3.OperationalError("injected close failure")
        super().close()

    def force_close(self) -> None:
        if not self.closed:
            self._connection.close()
            self.closed = True


class _CloseAlwaysFailsConnection(_FaultingConnection):
    def __init__(self, connection: sqlite3.Connection) -> None:
        super().__init__(connection, fail_when=lambda sql: False)
        self.close_attempts = 0

    def close(self) -> None:
        self.close_attempts += 1
        raise sqlite3.OperationalError("persistent close failure")

    def force_close(self) -> None:
        if not self.closed:
            self._connection.close()
            self.closed = True


def _exception_tree(error: BaseException) -> tuple[BaseException, ...]:
    found: list[BaseException] = []
    pending = [error]
    seen: set[int] = set()
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        found.append(current)
        if current.__cause__ is not None:
            pending.append(current.__cause__)
        if current.__context__ is not None:
            pending.append(current.__context__)
        if isinstance(current, BaseExceptionGroup):
            pending.extend(current.exceptions)
    return tuple(found)


def _assert_domain_error_with_cause(
    error: BaseException,
    expected_type: type[BaseException],
) -> None:
    assert isinstance(error, expected_type)
    assert not isinstance(error, sqlite3.Error)
    assert error.__cause__ is not None


def _ledger_lock_path(ledger_path: Path) -> Path:
    return ledger_path.with_name(f".{ledger_path.name}.lock")


def _assert_initialization_left_nothing(
    tmp_path: Path,
    ledger_path: Path,
) -> None:
    assert set(tmp_path.iterdir()) <= {_ledger_lock_path(ledger_path)}


@pytest.mark.parametrize(
    "case",
    ("signature", "key_binding", "issuer", "signer", "acceptor"),
)
def test_invalid_work_order_never_creates_ledger_file(
    tmp_path: Path,
    case: str,
    signed_work_order: WorkOrder,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
) -> None:
    ledger_path = tmp_path / f"{case}.sqlite3"
    invalid = _invalid_work_order(
        case,
        signed_work_order,
        ephemeral_role_keys,
    )

    with pytest.raises(LedgerInitializationError):
        initialize_ledger(ledger_path, invalid)

    assert not ledger_path.exists()
    assert not Path(f"{ledger_path}-wal").exists()
    assert not Path(f"{ledger_path}-shm").exists()


def test_initialization_persists_one_immutable_canonical_work_order(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
) -> None:
    ledger_path = tmp_path / "ledger.sqlite3"
    initialize_ledger(ledger_path, signed_work_order)

    connection = connect_ledger(ledger_path)
    try:
        assert _rows(
            connection,
            "SELECT work_order_digest, work_order_json FROM work_orders",
        ) == (
            (
                signed_work_order.digest,
                _canonical_json(signed_work_order.model_dump(mode="json")),
            ),
        )
        assert load_authoritative_work_order(connection) == signed_work_order
        before = _ledger_snapshot(connection)
    finally:
        connection.close()

    with pytest.raises(LedgerInitializationError):
        initialize_ledger(ledger_path, signed_work_order)

    replacement_raw = signed_work_order.model_dump(mode="json")
    replacement_raw["objective"] = "replacement"
    replacement = WorkOrder.model_validate(
        sign_payload(
            "work-order",
            replacement_raw,
            ephemeral_role_keys["Maintainer"][0],
        )
    )
    with pytest.raises(LedgerInitializationError):
        initialize_ledger(ledger_path, replacement)

    connection = connect_ledger(ledger_path)
    try:
        assert load_authoritative_work_order(connection) == signed_work_order
        assert _ledger_snapshot(connection) == before
    finally:
        connection.close()


@pytest.mark.parametrize(
    ("statement", "parameters"),
    (
        (
            "UPDATE work_orders SET work_order_json = ?",
            ("{}",),
        ),
        (
            "UPDATE work_orders SET work_order_digest = ?",
            ("f" * 64,),
        ),
        (
            "DELETE FROM work_orders",
            (),
        ),
        (
            (
                "INSERT INTO work_orders "
                "(work_order_digest, work_order_json) VALUES (?, ?)"
            ),
            ("f" * 64, "{}"),
        ),
    ),
)
def test_authoritative_work_order_row_cannot_be_replaced(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    statement: str,
    parameters: tuple[object, ...],
) -> None:
    ledger_path = tmp_path / "ledger.sqlite3"
    initialize_ledger(ledger_path, signed_work_order)
    connection = connect_ledger(ledger_path)
    try:
        before = _rows(
            connection,
            "SELECT work_order_digest, work_order_json FROM work_orders",
        )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(statement, parameters)
        assert _rows(
            connection,
            "SELECT work_order_digest, work_order_json FROM work_orders",
        ) == before
    finally:
        connection.close()


def test_initialization_sets_sequence_state_and_root_reservation_atomically(
    tmp_path: Path,
    signed_work_order: WorkOrder,
) -> None:
    ledger_path = tmp_path / "ledger.sqlite3"
    initialize_ledger(ledger_path, signed_work_order)

    connection = connect_ledger(ledger_path)
    try:
        snapshot = _ledger_snapshot(connection)
    finally:
        connection.close()

    assert snapshot["sequence"] == ((1, 1),)
    assert snapshot["state"] == (
        (signed_work_order.digest, "issued", 0),
    )
    assert snapshot["reservations"] == (
        (
            signed_work_order.root_grant_template.grant_id,
            signed_work_order.digest,
            None,
            "root_template",
        ),
    )
    assert snapshot["grants"] == ()
    assert snapshot["attempts"] == ()
    assert snapshot["receipts"] == ()


@pytest.mark.parametrize(
    "invalid_kind",
    ("different_candidate", "wrong_actor"),
)
def test_only_exact_root_activation_converts_reserved_identity(
    tmp_path: Path,
    invalid_kind: str,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now,
) -> None:
    ledger_path = tmp_path / "ledger.sqlite3"
    initialize_ledger(ledger_path, signed_work_order)

    invalid_candidate = (
        _resigned_root_grant(
            signed_root_grant,
            ephemeral_role_keys["Maintainer"][0],
        )
        if invalid_kind == "different_candidate"
        else signed_root_grant
    )
    invalid_request = _activation_request(
        signed_work_order,
        invalid_candidate,
        ephemeral_role_keys,
        actor_role=(
            "Developer" if invalid_kind == "wrong_actor" else "Manager"
        ),
        nonce="1" * 64,
    )
    connection = connect_ledger(ledger_path)
    try:
        initialized = _ledger_snapshot(connection)
    finally:
        connection.close()

    with pytest.raises(RootActivationError) as error:
        activate_root_grant(
            ledger_path,
            invalid_candidate,
            invalid_request,
            sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
            clock=lambda: fixed_now,
        )
    assert error.value.code == "ROOT_ACTIVATION_INVALID"

    connection = connect_ledger(ledger_path)
    try:
        assert _ledger_snapshot(connection) == initialized
    finally:
        connection.close()

    exact_request = _activation_request(
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        actor_role="Manager",
        nonce="2" * 64,
    )
    receipt = activate_root_grant(
        ledger_path,
        signed_root_grant,
        exact_request,
        sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
        clock=lambda: fixed_now,
    )

    assert receipt.event_type == "grant_issued"
    assert receipt.sequence == 1
    assert receipt.state_before == "issued"
    assert receipt.state_after == "running"
    connection = connect_ledger(ledger_path)
    try:
        activated = _ledger_snapshot(connection)
        assert activated["sequence"] == ((1, 2),)
        assert activated["state"] == (
            (signed_work_order.digest, "running", 1),
        )
        assert activated["reservations"] == (
            (
                signed_root_grant.grant_id,
                signed_work_order.digest,
                signed_root_grant.digest,
                "effective",
            ),
        )
        assert len(activated["grants"]) == 1
        assert activated["attempts"] == ()
        assert len(activated["receipts"]) == 1
        assert activated["receipts"][0][1:] == (exact_request.nonce, 1)
    finally:
        connection.close()

    reuse_request = _activation_request(
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        actor_role="Manager",
        nonce="3" * 64,
    )
    with pytest.raises(RootActivationError) as error:
        activate_root_grant(
            ledger_path,
            signed_root_grant,
            reuse_request,
            sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
            clock=lambda: fixed_now,
        )
    assert error.value.code == "ROOT_ACTIVATION_INVALID"

    connection = connect_ledger(ledger_path)
    try:
        assert _ledger_snapshot(connection) == activated
    finally:
        connection.close()


@pytest.mark.parametrize(
    ("clock_value", "expected_occurred_at"),
    (
        (
            datetime(
                2026,
                1,
                1,
                0,
                5,
                2,
                500_000,
                tzinfo=timezone.utc,
            ),
            datetime(2026, 1, 1, 0, 5, 2, tzinfo=timezone.utc),
        ),
        (
            datetime(
                2026,
                1,
                1,
                8,
                5,
                2,
                500_000,
                tzinfo=timezone(timedelta(hours=8)),
            ),
            datetime(2026, 1, 1, 0, 5, 2, tzinfo=timezone.utc),
        ),
    ),
)
def test_root_clock_is_frozen_to_utc_seconds_before_freshness_and_receipt(
    tmp_path: Path,
    clock_value: datetime,
    expected_occurred_at: datetime,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
) -> None:
    ledger_path = tmp_path / (
        f"root-frozen-clock-{clock_value.utcoffset()}.sqlite3"
    )
    initialize_ledger(ledger_path, signed_work_order)
    request = _activation_request(
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        actor_role="Manager",
        nonce=_grant_id(
            f"root-frozen-clock:{clock_value.utcoffset()}"
        ),
    )

    receipt = activate_root_grant(
        ledger_path,
        signed_root_grant,
        request,
        sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
        clock=lambda: clock_value,
    )

    assert receipt.policy_decision == "allow"
    assert receipt.occurred_at == expected_occurred_at


def test_root_clock_rejects_exactly_301_seconds_without_writes(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
) -> None:
    ledger_path = tmp_path / "root-clock-301.sqlite3"
    initialize_ledger(ledger_path, signed_work_order)
    connection = connect_ledger(ledger_path)
    try:
        before = _ledger_integrity_snapshot(connection)
    finally:
        connection.close()

    with pytest.raises(RootActivationError):
        activate_root_grant(
            ledger_path,
            signed_root_grant,
            _activation_request(
                signed_work_order,
                signed_root_grant,
                ephemeral_role_keys,
                actor_role="Manager",
                nonce=_grant_id("root-clock-301"),
            ),
            sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
            clock=lambda: datetime(
                2026,
                1,
                1,
                0,
                5,
                3,
                tzinfo=timezone.utc,
            ),
        )

    connection = connect_ledger(ledger_path)
    try:
        assert _ledger_integrity_snapshot(connection) == before
    finally:
        connection.close()


def test_root_clock_is_read_once_and_shared_with_receipt(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
) -> None:
    ledger_path = tmp_path / "root-mutating-clock.sqlite3"
    initialize_ledger(ledger_path, signed_work_order)
    values = (
        datetime(
            2026,
            1,
            1,
            0,
            5,
            2,
            500_000,
            tzinfo=timezone.utc,
        ),
        datetime(2026, 1, 1, 0, 5, 3, tzinfo=timezone.utc),
    )
    clock_calls = 0

    def mutating_clock() -> datetime:
        nonlocal clock_calls
        value = values[min(clock_calls, 1)]
        clock_calls += 1
        return value

    receipt = activate_root_grant(
        ledger_path,
        signed_root_grant,
        _activation_request(
            signed_work_order,
            signed_root_grant,
            ephemeral_role_keys,
            actor_role="Manager",
            nonce=_grant_id("root-mutating-clock"),
        ),
        sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
        clock=mutating_clock,
    )

    assert clock_calls == 1
    assert receipt.occurred_at == datetime(
        2026,
        1,
        1,
        0,
        5,
        2,
        tzinfo=timezone.utc,
    )


@pytest.mark.parametrize(
    ("occurred_at", "expected_valid"),
    (
        ("2026-01-01T00:05:03Z", False),
        ("2026-01-01T00:05:02Z", True),
    ),
)
def test_root_history_replays_request_freshness_from_receipt_time(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    occurred_at: str,
    expected_valid: bool,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
) -> None:
    ledger_path = tmp_path / (
        f"root-history-skew-{expected_valid}.sqlite3"
    )
    _activate_ledger_root(
        ledger_path,
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        fixed_now,
    )
    connection = connect_ledger(ledger_path)
    try:
        raw = json.loads(
            connection.execute(
                "SELECT receipt_json FROM receipts WHERE sequence = 1"
            ).fetchone()[0]
        )
        raw["occurred_at"] = occurred_at
        resigned = sign_payload(
            "action-receipt",
            raw,
            ephemeral_role_keys["Sidecar"][0],
        )
        connection.execute(
            "UPDATE receipts SET receipt_json = ? WHERE sequence = 1",
            (_canonical_json(resigned),),
        )
        before = _ledger_integrity_snapshot(connection)
    finally:
        connection.close()
    candidate = _child_grant(
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        label=f"root-history-skew-next:{expected_valid}",
    )
    request = _delegation_request(
        signed_work_order,
        signed_root_grant,
        candidate,
        ephemeral_role_keys,
        actor_role="Manager",
        nonce=_grant_id(
            f"root-history-skew-next-request:{expected_valid}"
        ),
    )
    now = datetime.fromisoformat(
        occurred_at.replace("Z", "+00:00")
    )
    if expected_valid:
        receipt = _issue_child(
            ledger_path,
            candidate,
            request,
            ephemeral_role_keys,
            now,
        )
        assert receipt.sequence == 2
    else:
        _assert_write_free_child_integrity_failure(
            ledger_path=ledger_path,
            candidate=candidate,
            request=request,
            role_keys=ephemeral_role_keys,
            now=now,
            before=before,
            monkeypatch=monkeypatch,
        )


def test_second_root_activation_receipt_is_never_valid_history(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
) -> None:
    ledger_path = tmp_path / "second-root-history.sqlite3"
    _activate_ledger_root(
        ledger_path,
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        fixed_now,
    )
    connection = connect_ledger(ledger_path)
    try:
        root_id, root_json = connection.execute(
            """
            SELECT receipt_id, receipt_json
            FROM receipts
            WHERE sequence = 1
            """
        ).fetchone()
        first = json.loads(root_json)
        request = _activation_request(
            signed_work_order,
            signed_root_grant,
            ephemeral_role_keys,
            actor_role="Manager",
            nonce=_grant_id("second-root-history:request"),
        )
        second = copy.deepcopy(first)
        second["receipt_id"] = _grant_id(
            "second-root-history:receipt"
        )
        second["nested_claim"] = request.model_dump(mode="json")
        second["nested_claim_digest"] = request.digest
        second["nonce"] = request.nonce
        second["sequence"] = 2
        second["previous_receipt_digest"] = first["digest"]
        second["parent_receipt_ids"] = [root_id]
        second["state_before"] = "running"
        second["state_after"] = "running"
        resigned = sign_payload(
            "action-receipt",
            second,
            ephemeral_role_keys["Sidecar"][0],
        )
        connection.execute(
            """
            INSERT INTO receipts (
                receipt_id,
                work_order_digest,
                nonce,
                sequence,
                previous_digest,
                receipt_json
            )
            VALUES (?, ?, ?, 2, ?, ?)
            """,
            (
                resigned["receipt_id"],
                signed_work_order.digest,
                resigned["nonce"],
                first["digest"],
                _canonical_json(resigned),
            ),
        )
        connection.execute(
            """
            INSERT INTO receipt_parents (
                child_receipt_id,
                parent_receipt_id
            )
            VALUES (?, ?)
            """,
            (resigned["receipt_id"], root_id),
        )
        connection.execute(
            """
            INSERT INTO grant_events (
                event_id,
                receipt_id,
                grant_id,
                event_type,
                metric,
                amount
            )
            VALUES (?, ?, ?, 'grant_issued', NULL, NULL)
            """,
            (
                hashlib.sha256(
                    (
                        "grant-issued:"
                        f"{resigned['receipt_id']}"
                    ).encode("ascii")
                ).hexdigest(),
                resigned["receipt_id"],
                signed_root_grant.grant_id,
            ),
        )
        connection.execute(
            "UPDATE sequence_counter SET next_sequence = 3"
        )
        connection.execute(
            "UPDATE work_order_state SET version = 2"
        )
        before = _ledger_integrity_snapshot(connection)
    finally:
        connection.close()
    candidate = _child_grant(
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        label="second-root-history:next",
    )
    _assert_write_free_child_integrity_failure(
        ledger_path=ledger_path,
        candidate=candidate,
        request=_delegation_request(
            signed_work_order,
            signed_root_grant,
            candidate,
            ephemeral_role_keys,
            actor_role="Manager",
            nonce=_grant_id("second-root-history:next-request"),
        ),
        role_keys=ephemeral_role_keys,
        now=fixed_now,
        before=before,
        monkeypatch=monkeypatch,
    )


@pytest.mark.parametrize(
    "invalid_kind",
    ("unknown_key", "invalid_signature", "inner_outer_mismatch"),
)
def test_child_preauth_failures_leave_no_protocol_mutation(
    tmp_path: Path,
    invalid_kind: str,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
) -> None:
    ledger_path = tmp_path / f"{invalid_kind}.sqlite3"
    _activate_ledger_root(
        ledger_path,
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        fixed_now,
    )
    candidate = _child_grant(
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        label=f"preauth:{invalid_kind}",
    )
    request = _delegation_request(
        signed_work_order,
        signed_root_grant,
        candidate,
        ephemeral_role_keys,
        actor_role="Manager",
        nonce=_grant_id(f"preauth-request:{invalid_kind}"),
    )
    if invalid_kind == "unknown_key":
        unknown_key = Ed25519PrivateKey.generate()
        raw = candidate.model_dump(mode="json")
        raw["issuer_key_id"] = key_id(unknown_key.public_key())
        candidate = CapabilityGrant.model_validate(
            sign_payload("capability-grant", raw, unknown_key)
        )
        request = _delegation_request(
            signed_work_order,
            signed_root_grant,
            candidate,
            ephemeral_role_keys,
            actor_role="Manager",
            nonce=_grant_id("preauth-request:unknown-key"),
        )
    elif invalid_kind == "invalid_signature":
        candidate = candidate.model_copy(
            update={"subject_agent_id": "signature-tamper"}
        )
    else:
        request = _delegation_request(
            signed_work_order,
            signed_root_grant,
            candidate,
            ephemeral_role_keys,
            actor_role="Manager",
            nonce=_grant_id("preauth-request:mismatch"),
            candidate_digest="0" * 64,
        )

    connection = connect_ledger(ledger_path)
    try:
        before = _ledger_snapshot(connection)
    finally:
        connection.close()

    with pytest.raises(Exception) as captured:
        _issue_child(
            ledger_path,
            candidate,
            request,
            ephemeral_role_keys,
            fixed_now,
        )
    _assert_child_rejection(captured.value)

    connection = connect_ledger(ledger_path)
    try:
        assert _ledger_snapshot(connection) == before
    finally:
        connection.close()


@pytest.mark.parametrize(
    "denial_kind",
    (
        "developer_self_signed",
        "verifier_self_signed",
        "verifier_write_scope",
        "may_delegate",
        "tools",
        "read_scope",
        "write_scope",
        "validity",
        "quota",
        "subject_binding",
    ),
)
def test_authenticated_child_policy_denial_is_atomic_attempt_only(
    tmp_path: Path,
    denial_kind: str,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
) -> None:
    ledger_path = tmp_path / f"{denial_kind}.sqlite3"
    if denial_kind == "tools":
        raw_work_order = signed_work_order.model_dump(mode="json")
        raw_work_order["allowed_tools"].remove("owp.rollback_patch")
        raw_work_order["root_grant_template"]["allowed_tools"].remove(
            "owp.rollback_patch"
        )
        signed_work_order = WorkOrder.model_validate(
            sign_payload(
                "work-order",
                raw_work_order,
                ephemeral_role_keys["Maintainer"][0],
            )
        )
        raw_root = signed_work_order.root_grant_template.model_dump(
            mode="json"
        )
        raw_root["work_order_digest"] = signed_work_order.digest
        signed_root_grant = CapabilityGrant.model_validate(
            sign_payload(
                "capability-grant",
                raw_root,
                ephemeral_role_keys["Maintainer"][0],
            )
        )
    _activate_ledger_root(
        ledger_path,
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        fixed_now,
    )
    subject_role = (
        "Verifier"
        if denial_kind in {
            "verifier_self_signed",
            "verifier_write_scope",
        }
        else "Developer"
    )
    signer_role = (
        subject_role
        if denial_kind.endswith("self_signed")
        else "Manager"
    )
    updates_by_kind: dict[str, dict[str, object]] = {
        "verifier_write_scope": {"allowed_write_roots": ["src"]},
        "tools": {
            "allowed_tools": [
                "owp.repo_read",
                "owp.rollback_patch",
            ]
        },
        "read_scope": {
            "allowed_read_roots": ["docs"],
            "allowed_write_roots": [],
        },
        "write_scope": {
            "allowed_read_roots": ["src", "tests"],
            "allowed_write_roots": ["tests"],
        },
        "validity": {
            "issued_at": "2026-01-01T00:00:00Z",
            "valid_from": "2026-01-01T00:00:00Z",
        },
        "quota": {"quota": {"tool_calls": 51, "repair_rounds": 0}},
        "subject_binding": {"subject_agent_id": "unbound-developer"},
    }
    candidate = _child_grant(
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        label=f"denial:{denial_kind}",
        subject_role=subject_role,
        signer_role=signer_role,
        updates=updates_by_kind.get(denial_kind),
    )
    if denial_kind == "may_delegate":
        candidate = _signed_unvalidated_child_update(
            candidate,
            ephemeral_role_keys["Manager"][0],
            may_delegate=True,
        )
    request = _delegation_request(
        signed_work_order,
        signed_root_grant,
        candidate,
        ephemeral_role_keys,
        actor_role=signer_role,
        nonce=_grant_id(f"denial-request:{denial_kind}"),
    )

    connection = connect_ledger(ledger_path)
    try:
        before_events = _rows(
            connection,
            "SELECT event_id, receipt_id FROM grant_events",
        )
    finally:
        connection.close()

    receipt = _issue_child(
        ledger_path,
        candidate,
        request,
        ephemeral_role_keys,
        fixed_now,
    )

    assert receipt.event_type == "grant_issued"
    assert receipt.policy_decision == "deny"
    assert receipt.execution_status == "denied"
    assert receipt.candidate_grant_digest == candidate.digest
    assert "issued_grant_id" not in receipt.model_dump(mode="json")
    connection = connect_ledger(ledger_path)
    try:
        snapshot = _ledger_snapshot(connection)
        assert snapshot["sequence"] == ((1, 3),)
        assert snapshot["state"] == (
            (signed_work_order.digest, "running", 2),
        )
        candidate_reservation = next(
            row
            for row in snapshot["reservations"]
            if row[0] == candidate.grant_id
        )
        assert candidate_reservation == (
            candidate.grant_id,
            signed_work_order.digest,
            candidate.digest,
            "attempt",
        )
        assert snapshot["attempts"] == (
            (candidate.digest, candidate.grant_id),
        )
        assert len(snapshot["grants"]) == 1
        assert len(snapshot["receipts"]) == 2
        assert _rows(
            connection,
            "SELECT event_id, receipt_id FROM grant_events",
        ) == before_events
    finally:
        connection.close()


@pytest.mark.parametrize("subject_role", ("Developer", "Verifier"))
def test_successful_child_is_strictly_attenuated_and_receipted(
    tmp_path: Path,
    subject_role: str,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
) -> None:
    ledger_path = tmp_path / f"success-{subject_role}.sqlite3"
    _activate_ledger_root(
        ledger_path,
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        fixed_now,
    )
    candidate = _child_grant(
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        label=f"success:{subject_role}",
        subject_role=subject_role,
    )
    request = _delegation_request(
        signed_work_order,
        signed_root_grant,
        candidate,
        ephemeral_role_keys,
        actor_role="Manager",
        nonce=_grant_id(f"success-request:{subject_role}"),
    )

    receipt = _issue_child(
        ledger_path,
        candidate,
        request,
        ephemeral_role_keys,
        fixed_now,
    )

    subject = ephemeral_role_keys[subject_role][1]
    manager = ephemeral_role_keys["Manager"][1]
    assert receipt.policy_decision == "allow"
    assert receipt.execution_status == "succeeded"
    assert receipt.issued_grant_id == candidate.grant_id
    assert candidate.issuer_key_id == manager["key_id"]
    assert candidate.signer_key_id == manager["key_id"]
    assert candidate.subject_agent_id == subject["subject_id"]
    assert candidate.subject_key_id == subject["key_id"]
    assert candidate.may_delegate is False
    assert set(candidate.allowed_tools) <= set(
        signed_root_grant.allowed_tools
    )
    assert set(candidate.allowed_read_roots) <= set(
        signed_root_grant.allowed_read_roots
    )
    assert set(candidate.allowed_write_roots) <= set(
        signed_root_grant.allowed_write_roots
    )
    assert candidate.quota.tool_calls <= signed_root_grant.quota.tool_calls
    assert candidate.expires_at == signed_work_order.deadline
    if subject_role == "Verifier":
        assert candidate.allowed_write_roots == ()

    connection = connect_ledger(ledger_path)
    try:
        snapshot = _ledger_snapshot(connection)
        assert snapshot["reservations"][-1][-1] == "effective"
        assert len(snapshot["grants"]) == 2
        assert snapshot["attempts"] == ()
        assert len(snapshot["receipts"]) == 2
    finally:
        connection.close()


def test_manager_atomically_revokes_direct_child_without_deleting_or_charging(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
) -> None:
    ledger_path = tmp_path / "revoke-success.sqlite3"
    _activate_ledger_root(
        ledger_path,
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        fixed_now,
    )
    child = _child_grant(
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        label="revoke-success:child",
    )
    _issue_child(
        ledger_path,
        child,
        _delegation_request(
            signed_work_order,
            signed_root_grant,
            child,
            ephemeral_role_keys,
            actor_role="Manager",
            nonce=_grant_id("revoke-success:issue"),
        ),
        ephemeral_role_keys,
        fixed_now,
    )
    request = _revocation_request(
        signed_work_order,
        signed_root_grant,
        child,
        ephemeral_role_keys,
        actor_role="Manager",
        nonce=_grant_id("revoke-success:request"),
    )

    receipt = _revoke_child(
        ledger_path,
        signed_root_grant,
        child,
        request,
        ephemeral_role_keys,
        fixed_now,
    )

    assert receipt.event_type == "grant_revoked"
    assert receipt.authorizing_grant_id == signed_root_grant.grant_id
    assert receipt.revoked_grant_id == child.grant_id
    assert receipt.revocation_reason == "LEAST_PRIVILEGE"
    assert receipt.policy_decision == "allow"
    assert receipt.execution_status == "succeeded"
    assert receipt.quota_charge is None
    assert receipt.state_before == receipt.state_after == "running"
    connection = connect_ledger(ledger_path)
    try:
        snapshot = _ledger_integrity_snapshot(connection)
        assert snapshot[0]["sequence"] == ((1, 4),)
        assert snapshot[0]["state"][0][2] == 3
        assert len(snapshot[0]["grants"]) == 2
        assert len(snapshot[0]["receipts"]) == 3
        assert len(snapshot[1]) == 2
        assert len(snapshot[2]) == 2
    finally:
        connection.close()


def test_duplicate_nonce_and_repeat_revocation_are_write_free(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
) -> None:
    ledger_path = tmp_path / "revoke-replay.sqlite3"
    _activate_ledger_root(
        ledger_path,
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        fixed_now,
    )
    child = _child_grant(
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        label="revoke-replay:child",
    )
    issuance_nonce = _grant_id("revoke-replay:issue")
    _issue_child(
        ledger_path,
        child,
        _delegation_request(
            signed_work_order,
            signed_root_grant,
            child,
            ephemeral_role_keys,
            actor_role="Manager",
            nonce=issuance_nonce,
        ),
        ephemeral_role_keys,
        fixed_now,
    )
    duplicate_nonce_request = _revocation_request(
        signed_work_order,
        signed_root_grant,
        child,
        ephemeral_role_keys,
        actor_role="Manager",
        nonce=issuance_nonce,
    )
    connection = connect_ledger(ledger_path)
    try:
        before_duplicate = _ledger_integrity_snapshot(connection)
    finally:
        connection.close()

    with pytest.raises(evidence.GrantRevocationError) as duplicate:
        _revoke_child(
            ledger_path,
            signed_root_grant,
            child,
            duplicate_nonce_request,
            ephemeral_role_keys,
            fixed_now,
        )
    assert duplicate.value.code == "GRANT_REVOCATION_INVALID"
    connection = connect_ledger(ledger_path)
    try:
        assert _ledger_integrity_snapshot(connection) == before_duplicate
    finally:
        connection.close()

    first_request = _revocation_request(
        signed_work_order,
        signed_root_grant,
        child,
        ephemeral_role_keys,
        actor_role="Manager",
        nonce=_grant_id("revoke-replay:first"),
    )
    _revoke_child(
        ledger_path,
        signed_root_grant,
        child,
        first_request,
        ephemeral_role_keys,
        fixed_now,
    )
    connection = connect_ledger(ledger_path)
    try:
        before_repeat = _ledger_integrity_snapshot(connection)
    finally:
        connection.close()
    repeat_request = _revocation_request(
        signed_work_order,
        signed_root_grant,
        child,
        ephemeral_role_keys,
        actor_role="Manager",
        nonce=_grant_id("revoke-replay:second"),
    )

    with pytest.raises(evidence.GrantRevocationError):
        _revoke_child(
            ledger_path,
            signed_root_grant,
            child,
            repeat_request,
            ephemeral_role_keys,
            fixed_now,
        )
    connection = connect_ledger(ledger_path)
    try:
        assert _ledger_integrity_snapshot(connection) == before_repeat
    finally:
        connection.close()


def test_concurrent_revocation_of_same_child_has_one_winner(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
) -> None:
    ledger_path = tmp_path / "revoke-concurrent.sqlite3"
    _activate_ledger_root(
        ledger_path,
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        fixed_now,
    )
    child = _child_grant(
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        label="revoke-concurrent:child",
    )
    _issue_child(
        ledger_path,
        child,
        _delegation_request(
            signed_work_order,
            signed_root_grant,
            child,
            ephemeral_role_keys,
            actor_role="Manager",
            nonce=_grant_id("revoke-concurrent:issue"),
        ),
        ephemeral_role_keys,
        fixed_now,
    )
    requests = tuple(
        _revocation_request(
            signed_work_order,
            signed_root_grant,
            child,
            ephemeral_role_keys,
            actor_role="Manager",
            nonce=_grant_id(f"revoke-concurrent:{index}"),
        )
        for index in range(2)
    )

    def revoke(request: AgentRequest):
        try:
            return _revoke_child(
                ledger_path,
                signed_root_grant,
                child,
                request,
                ephemeral_role_keys,
                fixed_now,
            )
        except evidence.GrantRevocationError as error:
            return error

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = tuple(pool.map(revoke, requests))

    assert sum(
        getattr(result, "event_type", None) == "grant_revoked"
        for result in results
    ) == 1
    assert sum(
        isinstance(result, evidence.GrantRevocationError)
        for result in results
    ) == 1
    connection = connect_ledger(ledger_path)
    try:
        snapshot = _ledger_integrity_snapshot(connection)
        assert len(snapshot[0]["receipts"]) == 3
        assert snapshot[0]["sequence"] == ((1, 4),)
        assert snapshot[0]["state"][0][2] == 3
    finally:
        connection.close()


@pytest.mark.parametrize(
    "invalid_kind",
    (
        "developer_actor",
        "bad_request_signature",
        "wrong_tool",
        "wrong_arguments_digest",
        "foreign_work_order",
        "requested_at_old",
        "requested_at_future",
        "wrong_sidecar",
        "unknown_target",
        "root_target",
        "attempt_target",
        "cross_parent_target",
    ),
)
def test_revocation_security_boundary_failures_are_write_free(
    tmp_path: Path,
    invalid_kind: str,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
) -> None:
    ledger_path = tmp_path / f"revoke-invalid-{invalid_kind}.sqlite3"
    _activate_ledger_root(
        ledger_path,
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        fixed_now,
    )
    child = _child_grant(
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        label=f"revoke-invalid:{invalid_kind}:child",
    )
    _issue_child(
        ledger_path,
        child,
        _delegation_request(
            signed_work_order,
            signed_root_grant,
            child,
            ephemeral_role_keys,
            actor_role="Manager",
            nonce=_grant_id(f"revoke-invalid:{invalid_kind}:issue"),
        ),
        ephemeral_role_keys,
        fixed_now,
    )
    authorizing_id = signed_root_grant.grant_id
    target_id = child.grant_id
    actor_role = "Manager"
    sidecar_private_key = ephemeral_role_keys["Sidecar"][0]
    request_options: dict[str, str] = {}
    if invalid_kind == "developer_actor":
        actor_role = "Developer"
    elif invalid_kind == "wrong_tool":
        request_options["tool_name"] = "owp.delegate_grant"
    elif invalid_kind == "wrong_arguments_digest":
        request_options["arguments_digest"] = "f" * 64
    elif invalid_kind == "foreign_work_order":
        request_options["work_order_digest"] = _grant_id(
            "revoke-invalid:foreign-work-order"
        )
    elif invalid_kind == "requested_at_old":
        request_options["requested_at"] = "2025-12-31T23:59:59Z"
    elif invalid_kind == "requested_at_future":
        request_options["requested_at"] = "2026-01-01T00:00:06Z"
    elif invalid_kind == "wrong_sidecar":
        sidecar_private_key = Ed25519PrivateKey.generate()
    elif invalid_kind == "unknown_target":
        target_id = _grant_id("revoke-invalid:unknown")
    elif invalid_kind == "root_target":
        target_id = signed_root_grant.grant_id
    elif invalid_kind == "attempt_target":
        attempt = _child_grant(
            signed_work_order,
            signed_root_grant,
            ephemeral_role_keys,
            label="revoke-invalid:attempt",
            subject_role="Verifier",
            updates={"allowed_write_roots": ["src"]},
        )
        denied = _issue_child(
            ledger_path,
            attempt,
            _delegation_request(
                signed_work_order,
                signed_root_grant,
                attempt,
                ephemeral_role_keys,
                actor_role="Manager",
                nonce=_grant_id("revoke-invalid:attempt:issue"),
            ),
            ephemeral_role_keys,
            fixed_now,
        )
        assert denied.policy_decision == "deny"
        target_id = attempt.grant_id
    elif invalid_kind == "cross_parent_target":
        sibling = _child_grant(
            signed_work_order,
            signed_root_grant,
            ephemeral_role_keys,
            label="revoke-invalid:cross-parent:sibling",
        )
        _issue_child(
            ledger_path,
            sibling,
            _delegation_request(
                signed_work_order,
                signed_root_grant,
                sibling,
                ephemeral_role_keys,
                actor_role="Manager",
                nonce=_grant_id(
                    "revoke-invalid:cross-parent:sibling:issue"
                ),
            ),
            ephemeral_role_keys,
            fixed_now,
        )
        authorizing_id = child.grant_id
        target_id = sibling.grant_id
    request = _revocation_request(
        signed_work_order,
        signed_root_grant,
        child,
        ephemeral_role_keys,
        actor_role=actor_role,
        nonce=_grant_id(f"revoke-invalid:{invalid_kind}:request"),
        authorizing_grant_id=authorizing_id,
        revoked_grant_id=target_id,
        **request_options,
    )
    if invalid_kind == "bad_request_signature":
        request = request.model_copy(
            update={"arguments_digest": "f" * 64}
        )
    connection = connect_ledger(ledger_path)
    try:
        before = _ledger_integrity_snapshot(connection)
    finally:
        connection.close()

    with pytest.raises(evidence.GrantRevocationError) as captured:
        evidence.revoke_child_grant(
            ledger_path,
            authorizing_grant_id=authorizing_id,
            revoked_grant_id=target_id,
            revocation_reason="LEAST_PRIVILEGE",
            request=request,
            sidecar_private_key=sidecar_private_key,
            clock=lambda: fixed_now,
        )

    assert captured.value.code == "GRANT_REVOCATION_INVALID"
    connection = connect_ledger(ledger_path)
    try:
        assert _ledger_integrity_snapshot(connection) == before
    finally:
        connection.close()


def test_resigned_revocation_target_tamper_is_rejected_before_next_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
) -> None:
    ledger_path = tmp_path / "revoke-history-target-tamper.sqlite3"
    _activate_ledger_root(
        ledger_path,
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        fixed_now,
    )
    child = _child_grant(
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        label="revoke-history-target-tamper:child",
    )
    _issue_child(
        ledger_path,
        child,
        _delegation_request(
            signed_work_order,
            signed_root_grant,
            child,
            ephemeral_role_keys,
            actor_role="Manager",
            nonce=_grant_id("revoke-history-target-tamper:issue"),
        ),
        ephemeral_role_keys,
        fixed_now,
    )
    _revoke_child(
        ledger_path,
        signed_root_grant,
        child,
        _revocation_request(
            signed_work_order,
            signed_root_grant,
            child,
            ephemeral_role_keys,
            actor_role="Manager",
            nonce=_grant_id("revoke-history-target-tamper:revoke"),
        ),
        ephemeral_role_keys,
        fixed_now,
    )
    connection = connect_ledger(ledger_path)
    try:
        raw = json.loads(
            connection.execute(
                "SELECT receipt_json FROM receipts WHERE sequence = 3"
            ).fetchone()[0]
        )
        raw["revoked_grant_id"] = signed_root_grant.grant_id
        nested = copy.deepcopy(raw["nested_claim"])
        nested["arguments_digest"] = _jcs_digest(
            {
                "domain": "openworkproof/agent-arguments/v0.1",
                "tool_name": "owp.revoke_grant",
                "arguments": {
                    "authorizing_grant_id": signed_root_grant.grant_id,
                    "revoked_grant_id": signed_root_grant.grant_id,
                    "revocation_reason": "LEAST_PRIVILEGE",
                },
            }
        )
        resigned_nested = sign_payload(
            "agent-request",
            nested,
            ephemeral_role_keys["Manager"][0],
        )
        raw["nested_claim"] = resigned_nested
        raw["nested_claim_digest"] = resigned_nested["digest"]
        resigned_receipt = sign_payload(
            "action-receipt",
            raw,
            ephemeral_role_keys["Sidecar"][0],
        )
        connection.execute(
            "UPDATE receipts SET receipt_json = ? WHERE sequence = 3",
            (_canonical_json(resigned_receipt),),
        )
        replay_work_order = load_authoritative_work_order(connection)
        replay_receipts = evidence._validated_receipt_prefix(
            connection,
            replay_work_order,
        )
        replay_grants = evidence._validated_effective_grants(
            connection,
            replay_work_order,
            replay_receipts,
        )
        replay_attempts = evidence._validated_grant_attempts(
            connection,
            replay_work_order,
            replay_receipts,
        )
        with pytest.raises(
            evidence.ChildGrantIssuanceError,
            match="revocation history failed semantic replay",
        ):
            evidence._validate_grant_history_semantics(
                replay_work_order,
                replay_receipts,
                replay_grants,
                replay_attempts,
            )
        before = _ledger_integrity_snapshot(connection)
    finally:
        connection.close()
    next_child = _child_grant(
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        label="revoke-history-target-tamper:next",
    )
    _assert_write_free_child_integrity_failure(
        ledger_path=ledger_path,
        candidate=next_child,
        request=_delegation_request(
            signed_work_order,
            signed_root_grant,
            next_child,
            ephemeral_role_keys,
            actor_role="Manager",
            nonce=_grant_id(
                "revoke-history-target-tamper:next-request"
            ),
        ),
        role_keys=ephemeral_role_keys,
        now=fixed_now,
        before=before,
        monkeypatch=monkeypatch,
    )


@pytest.mark.parametrize(
    "failure_kind",
    ("close_failure", "commit_ack_failure"),
)
def test_committed_revocation_reports_one_committed_fact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_kind: str,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
) -> None:
    ledger_path = tmp_path / f"revoke-committed-{failure_kind}.sqlite3"
    _activate_ledger_root(
        ledger_path,
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        fixed_now,
    )
    child = _child_grant(
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        label=f"revoke-committed:{failure_kind}:child",
    )
    _issue_child(
        ledger_path,
        child,
        _delegation_request(
            signed_work_order,
            signed_root_grant,
            child,
            ephemeral_role_keys,
            actor_role="Manager",
            nonce=_grant_id(f"revoke-committed:{failure_kind}:issue"),
        ),
        ephemeral_role_keys,
        fixed_now,
    )
    request = _revocation_request(
        signed_work_order,
        signed_root_grant,
        child,
        ephemeral_role_keys,
        actor_role="Manager",
        nonce=_grant_id(f"revoke-committed:{failure_kind}:request"),
    )
    real_connect = evidence.connect_ledger
    before_connection = real_connect(ledger_path)
    try:
        before = _ledger_integrity_snapshot(before_connection)
    finally:
        before_connection.close()
    connections: list[
        _CloseAlwaysFailsConnection | _FaultingConnection
    ] = []

    def faulting_connect(path: Path):
        raw = real_connect(path)
        if failure_kind == "close_failure":
            connection = _CloseAlwaysFailsConnection(raw)
        else:
            connection = _FaultingConnection(
                raw,
                fail_when=lambda sql: sql == "COMMIT",
                fail_after_execute=True,
            )
        connections.append(connection)
        return connection

    monkeypatch.setattr(evidence, "connect_ledger", faulting_connect)
    try:
        with pytest.raises(
            evidence.GrantRevocationCommittedError
        ) as captured:
            _revoke_child(
                ledger_path,
                signed_root_grant,
                child,
                request,
                ephemeral_role_keys,
                fixed_now,
            )
        assert captured.value.committed is True
        assert captured.value.receipt.revoked_grant_id == child.grant_id
    finally:
        monkeypatch.setattr(evidence, "connect_ledger", real_connect)
        for connection in connections:
            if isinstance(connection, _CloseAlwaysFailsConnection):
                connection.force_close()

    after_connection = real_connect(ledger_path)
    try:
        after = _ledger_integrity_snapshot(after_connection)
        assert len(after[0]["receipts"]) == len(before[0]["receipts"]) + 1
        assert len(after[1]) == len(before[1]) + 1
        assert len(after[2]) == len(before[2])
        assert after[0]["sequence"][0][1] == (
            before[0]["sequence"][0][1] + 1
        )
        assert after[0]["state"][0][2] == before[0]["state"][0][2] + 1
        assert sum(
            row[0] == captured.value.receipt.receipt_id
            for row in after[0]["receipts"]
        ) == 1
    finally:
        after_connection.close()


@pytest.mark.parametrize(
    ("subject_role", "forbidden_tool"),
    (
        ("Verifier", "owp.apply_patch"),
        ("Verifier", "owp.repo_read"),
        ("Verifier", "owp.rollback_patch"),
        ("Developer", "owp.run_tests"),
    ),
)
def test_child_role_tool_crossovers_are_authenticated_denials(
    tmp_path: Path,
    subject_role: str,
    forbidden_tool: str,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
) -> None:
    ledger_path = tmp_path / (
        f"role-tool-{subject_role}-{forbidden_tool}.sqlite3"
    )
    if subject_role == "Developer":
        raw_work_order = signed_work_order.model_dump(mode="json")
        raw_work_order["test_profiles"] = [
            profile
            for profile in raw_work_order["test_profiles"]
            if profile["test_mode"] != "developer"
        ]
        raw_work_order["evidence_policy"]["artifacts"] = [
            artifact
            for artifact in raw_work_order["evidence_policy"]["artifacts"]
            if artifact["purpose"] != "developer_test_result"
        ]
        signed_work_order = WorkOrder.model_validate(
            sign_payload(
                "work-order",
                raw_work_order,
                ephemeral_role_keys["Maintainer"][0],
            )
        )
        raw_root = signed_work_order.root_grant_template.model_dump(
            mode="json"
        )
        raw_root["work_order_digest"] = signed_work_order.digest
        signed_root_grant = CapabilityGrant.model_validate(
            sign_payload(
                "capability-grant",
                raw_root,
                ephemeral_role_keys["Maintainer"][0],
            )
        )
    _activate_ledger_root(
        ledger_path,
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        fixed_now,
    )
    candidate = _child_grant(
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        label=f"role-tool:{subject_role}:{forbidden_tool}",
        subject_role=subject_role,
        updates={
            "allowed_tools": [forbidden_tool],
            "allowed_write_roots": [],
        },
    )
    request = _delegation_request(
        signed_work_order,
        signed_root_grant,
        candidate,
        ephemeral_role_keys,
        actor_role="Manager",
        nonce=_grant_id(
            f"role-tool-request:{subject_role}:{forbidden_tool}"
        ),
    )

    receipt = _issue_child(
        ledger_path,
        candidate,
        request,
        ephemeral_role_keys,
        fixed_now,
    )

    assert receipt.policy_decision == "deny"
    assert receipt.execution_status == "denied"
    connection = connect_ledger(ledger_path)
    try:
        snapshot = _ledger_snapshot(connection)
        assert (candidate.digest, candidate.grant_id) in (
            snapshot["attempts"]
        )
        assert all(
            row[0] != candidate.grant_id
            for row in snapshot["grants"]
        )
    finally:
        connection.close()


def test_child_receipt_cannot_precede_receipt_chain_tip(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
) -> None:
    ledger_path = tmp_path / "receipt-time-regression.sqlite3"
    _activate_ledger_root(
        ledger_path,
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        fixed_now,
    )
    candidate = _child_grant(
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        label="receipt-time-regression",
    )
    request = _delegation_request(
        signed_work_order,
        signed_root_grant,
        candidate,
        ephemeral_role_keys,
        actor_role="Manager",
        nonce=_grant_id("receipt-time-regression:request"),
    )
    connection = connect_ledger(ledger_path)
    try:
        before = _ledger_snapshot(connection)
    finally:
        connection.close()
    regressed_now = datetime(
        2026,
        1,
        1,
        0,
        0,
        4,
        tzinfo=timezone.utc,
    )

    with pytest.raises(Exception) as captured:
        _issue_child(
            ledger_path,
            candidate,
            request,
            ephemeral_role_keys,
            regressed_now,
        )
    _assert_child_rejection(captured.value)
    connection = connect_ledger(ledger_path)
    try:
        assert _ledger_snapshot(connection) == before
    finally:
        connection.close()


@pytest.mark.parametrize(
    ("skew_seconds", "expected_decision"),
    ((0, "allow"), (300, "allow"), (-1, "deny"), (301, "deny")),
)
def test_child_receipt_skew_boundaries_are_exact(
    tmp_path: Path,
    skew_seconds: int,
    expected_decision: str,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
) -> None:
    issued_second = 5 if skew_seconds == 0 else 1
    if skew_seconds == -1:
        issued_second = 6
    now_second = issued_second + skew_seconds
    now = datetime(
        2026,
        1,
        1,
        0,
        now_second // 60,
        now_second % 60,
        tzinfo=timezone.utc,
    )
    issued_at = (
        f"2026-01-01T00:{issued_second // 60:02d}:"
        f"{issued_second % 60:02d}Z"
    )
    ledger_path = tmp_path / f"skew-{skew_seconds}.sqlite3"
    _activate_ledger_root(
        ledger_path,
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        now,
    )
    candidate = _child_grant(
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        label=f"skew:{skew_seconds}",
        updates={"issued_at": issued_at, "valid_from": issued_at},
    )
    request = _delegation_request(
        signed_work_order,
        signed_root_grant,
        candidate,
        ephemeral_role_keys,
        actor_role="Manager",
        nonce=_grant_id(f"skew-request:{skew_seconds}"),
    )

    receipt = _issue_child(
        ledger_path,
        candidate,
        request,
        ephemeral_role_keys,
        now,
    )

    assert receipt.policy_decision == expected_decision
    assert receipt.occurred_at == now
    if expected_decision == "allow":
        assert receipt.issued_grant_id == candidate.grant_id
        assert candidate.expires_at == signed_work_order.deadline
    else:
        assert "issued_grant_id" not in receipt.model_dump(mode="json")


@pytest.mark.parametrize(
    ("clock_value", "expected_decision", "expected_occurred_at"),
    (
        (
            datetime(
                2026,
                1,
                1,
                0,
                5,
                1,
                500_000,
                tzinfo=timezone.utc,
            ),
            "allow",
            datetime(2026, 1, 1, 0, 5, 1, tzinfo=timezone.utc),
        ),
        (
            datetime(
                2026,
                1,
                1,
                8,
                5,
                1,
                500_000,
                tzinfo=timezone(timedelta(hours=8)),
            ),
            "allow",
            datetime(2026, 1, 1, 0, 5, 1, tzinfo=timezone.utc),
        ),
        (
            datetime(2026, 1, 1, 0, 5, 2, tzinfo=timezone.utc),
            "deny",
            datetime(2026, 1, 1, 0, 5, 2, tzinfo=timezone.utc),
        ),
    ),
)
def test_child_clock_is_frozen_to_utc_seconds_before_policy(
    tmp_path: Path,
    clock_value: datetime,
    expected_decision: str,
    expected_occurred_at: datetime,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
) -> None:
    ledger_path = tmp_path / (
        f"frozen-clock-{expected_decision}-"
        f"{clock_value.utcoffset()}.sqlite3"
    )
    root_now = datetime(
        2026,
        1,
        1,
        0,
        0,
        5,
        tzinfo=timezone.utc,
    )
    _activate_ledger_root(
        ledger_path,
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        root_now,
    )
    candidate = _child_grant(
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        label=(
            f"frozen-clock:{expected_decision}:"
            f"{clock_value.utcoffset()}"
        ),
        updates={
            "issued_at": "2026-01-01T00:00:01Z",
            "valid_from": "2026-01-01T00:00:01Z",
        },
    )
    request = _delegation_request(
        signed_work_order,
        signed_root_grant,
        candidate,
        ephemeral_role_keys,
        actor_role="Manager",
        nonce=_grant_id(
            f"frozen-clock-request:{expected_decision}:"
            f"{clock_value.utcoffset()}"
        ),
    )

    receipt = _issue_child(
        ledger_path,
        candidate,
        request,
        ephemeral_role_keys,
        clock_value,
    )

    assert receipt.policy_decision == expected_decision
    assert receipt.occurred_at == expected_occurred_at


def test_child_clock_is_read_once_and_frozen_for_policy_and_receipt(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
) -> None:
    ledger_path = tmp_path / "mutating-clock.sqlite3"
    root_now = datetime(
        2026,
        1,
        1,
        0,
        0,
        5,
        tzinfo=timezone.utc,
    )
    _activate_ledger_root(
        ledger_path,
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        root_now,
    )
    candidate = _child_grant(
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        label="mutating-clock",
        updates={
            "issued_at": "2026-01-01T00:00:01Z",
            "valid_from": "2026-01-01T00:00:01Z",
        },
    )
    request = _delegation_request(
        signed_work_order,
        signed_root_grant,
        candidate,
        ephemeral_role_keys,
        actor_role="Manager",
        nonce=_grant_id("mutating-clock:request"),
    )
    values = (
        datetime(
            2026,
            1,
            1,
            0,
            5,
            1,
            500_000,
            tzinfo=timezone.utc,
        ),
        datetime(2026, 1, 1, 0, 5, 2, tzinfo=timezone.utc),
    )
    clock_calls = 0

    def mutating_clock() -> datetime:
        nonlocal clock_calls
        value = values[min(clock_calls, 1)]
        clock_calls += 1
        return value

    receipt = evidence.issue_child_grant(
        ledger_path,
        candidate,
        request,
        sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
        clock=mutating_clock,
    )

    assert clock_calls == 1
    assert receipt.policy_decision == "allow"
    assert receipt.occurred_at == datetime(
        2026,
        1,
        1,
        0,
        5,
        1,
        tzinfo=timezone.utc,
    )


def test_naive_child_clock_fails_before_signing_or_writes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
) -> None:
    ledger_path = tmp_path / "naive-child-clock.sqlite3"
    _activate_ledger_root(
        ledger_path,
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        fixed_now,
    )
    candidate = _child_grant(
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        label="naive-child-clock",
    )
    request = _delegation_request(
        signed_work_order,
        signed_root_grant,
        candidate,
        ephemeral_role_keys,
        actor_role="Manager",
        nonce=_grant_id("naive-child-clock:request"),
    )
    connection = connect_ledger(ledger_path)
    try:
        before = _ledger_integrity_snapshot(connection)
    finally:
        connection.close()
    real_sign_payload = evidence.sign_payload
    action_receipt_signatures = 0

    def tracked_sign_payload(
        object_type: str,
        value,
        private_key: Ed25519PrivateKey,
    ):
        nonlocal action_receipt_signatures
        if object_type == "action-receipt":
            action_receipt_signatures += 1
        return real_sign_payload(object_type, value, private_key)

    monkeypatch.setattr(evidence, "sign_payload", tracked_sign_payload)
    with pytest.raises(evidence.ChildGrantIssuanceError):
        _issue_child(
            ledger_path,
            candidate,
            request,
            ephemeral_role_keys,
            datetime(2026, 1, 1, 0, 0, 5),
        )

    assert action_receipt_signatures == 0
    connection = connect_ledger(ledger_path)
    try:
        assert _ledger_integrity_snapshot(connection) == before
    finally:
        connection.close()


def test_denied_sibling_allocation_does_not_reduce_parent_quota(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
) -> None:
    ledger_path = tmp_path / "siblings.sqlite3"
    _activate_ledger_root(
        ledger_path,
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        fixed_now,
    )

    def issue(label: str, amount: int):
        candidate = _child_grant(
            signed_work_order,
            signed_root_grant,
            ephemeral_role_keys,
            label=label,
            updates={
                "quota": {
                    "tool_calls": amount,
                    "repair_rounds": 0,
                }
            },
        )
        request = _delegation_request(
            signed_work_order,
            signed_root_grant,
            candidate,
            ephemeral_role_keys,
            actor_role="Manager",
            nonce=_grant_id(f"sibling-request:{label}"),
        )
        return candidate, _issue_child(
            ledger_path,
            candidate,
            request,
            ephemeral_role_keys,
            fixed_now,
        )

    first, first_receipt = issue("sibling:first", 30)
    denied, denied_receipt = issue("sibling:denied", 21)
    last, last_receipt = issue("sibling:last", 20)

    assert first_receipt.policy_decision == "allow"
    assert denied_receipt.policy_decision == "deny"
    assert last_receipt.policy_decision == "allow"
    connection = connect_ledger(ledger_path)
    try:
        assert _rows(
            connection,
            "SELECT grant_id FROM grants ORDER BY grant_id",
        ) == tuple(
            (grant_id,)
            for grant_id in sorted(
                (
                    signed_root_grant.grant_id,
                    first.grant_id,
                    last.grant_id,
                )
            )
        )
        assert _rows(
            connection,
            "SELECT grant_id FROM grant_attempts",
        ) == ((denied.grant_id,),)
    finally:
        connection.close()


@pytest.mark.parametrize(
    ("first_kind", "second_kind", "same_bytes"),
    (
        ("effective", "effective", True),
        ("effective", "effective", False),
        ("effective", "attempt", False),
        ("attempt", "effective", False),
        ("attempt", "attempt", True),
        ("attempt", "attempt", False),
    ),
)
def test_grant_id_is_permanent_across_effective_and_attempt_namespaces(
    tmp_path: Path,
    first_kind: str,
    second_kind: str,
    same_bytes: bool,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
) -> None:
    ledger_path = tmp_path / (
        f"unique-{first_kind}-{second_kind}-{same_bytes}.sqlite3"
    )
    _activate_ledger_root(
        ledger_path,
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        fixed_now,
    )
    shared_id = _grant_id(
        f"shared:{first_kind}:{second_kind}:{same_bytes}"
    )

    def candidate_for(kind: str, label: str) -> CapabilityGrant:
        return _child_grant(
            signed_work_order,
            signed_root_grant,
            ephemeral_role_keys,
            label=label,
            subject_role="Verifier" if kind == "attempt" else "Developer",
            updates=(
                {
                    "grant_id": shared_id,
                    "allowed_write_roots": ["src"],
                }
                if kind == "attempt"
                else {"grant_id": shared_id}
            ),
        )

    first = candidate_for(first_kind, "unique:first")
    first_request = _delegation_request(
        signed_work_order,
        signed_root_grant,
        first,
        ephemeral_role_keys,
        actor_role="Manager",
        nonce=_grant_id("unique-request:first"),
    )
    first_receipt = _issue_child(
        ledger_path,
        first,
        first_request,
        ephemeral_role_keys,
        fixed_now,
    )
    assert first_receipt.policy_decision == (
        "allow" if first_kind == "effective" else "deny"
    )

    second = (
        first
        if same_bytes
        else candidate_for(second_kind, "unique:second")
    )
    second_request = _delegation_request(
        signed_work_order,
        signed_root_grant,
        second,
        ephemeral_role_keys,
        actor_role="Manager",
        nonce=_grant_id("unique-request:second"),
    )
    connection = connect_ledger(ledger_path)
    try:
        before = _ledger_snapshot(connection)
    finally:
        connection.close()

    with pytest.raises(Exception) as captured:
        _issue_child(
            ledger_path,
            second,
            second_request,
            ephemeral_role_keys,
            fixed_now,
        )
    _assert_child_rejection(captured.value)
    connection = connect_ledger(ledger_path)
    try:
        assert _ledger_snapshot(connection) == before
    finally:
        connection.close()


def test_root_reserved_grant_id_cannot_be_reused_by_child(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
) -> None:
    ledger_path = tmp_path / "root-id-reuse.sqlite3"
    _activate_ledger_root(
        ledger_path,
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        fixed_now,
    )
    candidate = _child_grant(
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        label="ignored",
        updates={"grant_id": signed_root_grant.grant_id},
    )
    request = _delegation_request(
        signed_work_order,
        signed_root_grant,
        candidate,
        ephemeral_role_keys,
        actor_role="Manager",
        nonce=_grant_id("root-id-reuse:request"),
    )
    connection = connect_ledger(ledger_path)
    try:
        before = _ledger_snapshot(connection)
    finally:
        connection.close()

    with pytest.raises(Exception) as captured:
        _issue_child(
            ledger_path,
            candidate,
            request,
            ephemeral_role_keys,
            fixed_now,
        )
    _assert_child_rejection(captured.value)
    connection = connect_ledger(ledger_path)
    try:
        assert _ledger_snapshot(connection) == before
    finally:
        connection.close()


def test_concurrent_same_grant_id_reservation_has_one_winner(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
) -> None:
    ledger_path = tmp_path / "concurrent-child.sqlite3"
    _activate_ledger_root(
        ledger_path,
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        fixed_now,
    )
    shared_id = _grant_id("concurrent:shared")
    candidates = tuple(
        _child_grant(
            signed_work_order,
            signed_root_grant,
            ephemeral_role_keys,
            label=f"concurrent:{index}",
            updates={"grant_id": shared_id},
        )
        for index in range(2)
    )
    requests = tuple(
        _delegation_request(
            signed_work_order,
            signed_root_grant,
            candidate,
            ephemeral_role_keys,
            actor_role="Manager",
            nonce=_grant_id(f"concurrent-request:{index}"),
        )
        for index, candidate in enumerate(candidates)
    )
    barrier = threading.Barrier(2)

    def race(index: int):
        barrier.wait(timeout=5)
        try:
            return _issue_child(
                ledger_path,
                candidates[index],
                requests[index],
                ephemeral_role_keys,
                fixed_now,
            )
        except Exception as error:
            return error

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = tuple(executor.map(race, range(2)))

    winners = [
        result
        for result in results
        if not isinstance(result, BaseException)
    ]
    losers = [
        result
        for result in results
        if isinstance(result, BaseException)
    ]
    assert len(winners) == 1
    assert len(losers) == 1
    _assert_child_rejection(losers[0])
    connection = connect_ledger(ledger_path)
    try:
        snapshot = _ledger_snapshot(connection)
        matching_reservations = [
            row
            for row in snapshot["reservations"]
            if row[0] == shared_id
        ]
        assert len(matching_reservations) == 1
        assert matching_reservations[0][2] in {
            candidate.digest for candidate in candidates
        }
        assert len(snapshot["grants"]) == 2
        assert snapshot["attempts"] == ()
        assert len(snapshot["receipts"]) == 2
    finally:
        connection.close()


def test_eighth_effective_grant_commits_and_ninth_is_write_free(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
) -> None:
    ledger_path = tmp_path / "effective-cap.sqlite3"
    _activate_ledger_root(
        ledger_path,
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        fixed_now,
    )
    for index in range(7):
        candidate = _child_grant(
            signed_work_order,
            signed_root_grant,
            ephemeral_role_keys,
            label=f"effective-cap:{index}",
            updates={
                "quota": {"tool_calls": 1, "repair_rounds": 0}
            },
        )
        receipt = _issue_child(
            ledger_path,
            candidate,
            _delegation_request(
                signed_work_order,
                signed_root_grant,
                candidate,
                ephemeral_role_keys,
                actor_role="Manager",
                nonce=_grant_id(f"effective-cap-request:{index}"),
            ),
            ephemeral_role_keys,
            fixed_now,
        )
        assert receipt.policy_decision == "allow"

    connection = connect_ledger(ledger_path)
    try:
        before = _ledger_snapshot(connection)
        assert len(before["grants"]) == 8
    finally:
        connection.close()
    ninth = _child_grant(
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        label="effective-cap:ninth",
    )
    with pytest.raises(Exception) as captured:
        _issue_child(
            ledger_path,
            ninth,
            _delegation_request(
                signed_work_order,
                signed_root_grant,
                ninth,
                ephemeral_role_keys,
                actor_role="Manager",
                nonce=_grant_id("effective-cap-request:ninth"),
            ),
            ephemeral_role_keys,
            fixed_now,
        )
    _assert_child_rejection(captured.value)
    connection = connect_ledger(ledger_path)
    try:
        assert _ledger_snapshot(connection) == before
    finally:
        connection.close()


def test_eighth_grant_attempt_commits_and_ninth_is_write_free(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
) -> None:
    ledger_path = tmp_path / "attempt-cap.sqlite3"
    _activate_ledger_root(
        ledger_path,
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        fixed_now,
    )

    def denied_candidate(index: int) -> CapabilityGrant:
        return _child_grant(
            signed_work_order,
            signed_root_grant,
            ephemeral_role_keys,
            label=f"attempt-cap:{index}",
            subject_role="Verifier",
            updates={
                "allowed_write_roots": ["src"],
                "quota": {"tool_calls": 1, "repair_rounds": 0},
            },
        )

    for index in range(8):
        candidate = denied_candidate(index)
        receipt = _issue_child(
            ledger_path,
            candidate,
            _delegation_request(
                signed_work_order,
                signed_root_grant,
                candidate,
                ephemeral_role_keys,
                actor_role="Manager",
                nonce=_grant_id(f"attempt-cap-request:{index}"),
            ),
            ephemeral_role_keys,
            fixed_now,
        )
        assert receipt.policy_decision == "deny"

    connection = connect_ledger(ledger_path)
    try:
        before = _ledger_snapshot(connection)
        assert len(before["attempts"]) == 8
    finally:
        connection.close()
    ninth = denied_candidate(9)
    with pytest.raises(Exception) as captured:
        _issue_child(
            ledger_path,
            ninth,
            _delegation_request(
                signed_work_order,
                signed_root_grant,
                ninth,
                ephemeral_role_keys,
                actor_role="Manager",
                nonce=_grant_id("attempt-cap-request:ninth"),
            ),
            ephemeral_role_keys,
            fixed_now,
        )
    _assert_child_rejection(captured.value)
    connection = connect_ledger(ledger_path)
    try:
        assert _ledger_snapshot(connection) == before
    finally:
        connection.close()


@pytest.mark.parametrize(
    "tamper_kind",
    (
        "noncanonical_json",
        "digest",
        "signature",
        "quota",
        "row_subject",
        "row_usage_mode",
    ),
)
def test_tampered_effective_parent_fails_integrity_before_child_writes(
    tmp_path: Path,
    tamper_kind: str,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
) -> None:
    ledger_path = tmp_path / f"parent-tamper-{tamper_kind}.sqlite3"
    _activate_ledger_root(
        ledger_path,
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        fixed_now,
    )
    connection = connect_ledger(ledger_path)
    try:
        parent_json = connection.execute(
            "SELECT grant_json FROM grants WHERE grant_id = ?",
            (signed_root_grant.grant_id,),
        ).fetchone()[0]
        if tamper_kind == "noncanonical_json":
            connection.execute(
                "UPDATE grants SET grant_json = ? WHERE grant_id = ?",
                (f" {parent_json}", signed_root_grant.grant_id),
            )
        elif tamper_kind in {"digest", "signature", "quota"}:
            raw = json.loads(parent_json)
            if tamper_kind == "digest":
                raw["digest"] = "0" * 64
            elif tamper_kind == "signature":
                raw["signature"] = "A" * 86
            else:
                raw["quota"]["tool_calls"] = 100
            connection.execute(
                "UPDATE grants SET grant_json = ? WHERE grant_id = ?",
                (_canonical_json(raw), signed_root_grant.grant_id),
            )
        elif tamper_kind == "row_subject":
            connection.execute(
                """
                UPDATE grants
                SET subject_agent_id = 'tampered-manager'
                WHERE grant_id = ?
                """,
                (signed_root_grant.grant_id,),
            )
        else:
            connection.execute(
                """
                UPDATE grants
                SET usage_mode = 'single_use'
                WHERE grant_id = ?
                """,
                (signed_root_grant.grant_id,),
            )
        before = _ledger_integrity_snapshot(connection)
    finally:
        connection.close()
    candidate = _child_grant(
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        label=f"parent-tamper-candidate:{tamper_kind}",
    )
    request = _delegation_request(
        signed_work_order,
        signed_root_grant,
        candidate,
        ephemeral_role_keys,
        actor_role="Manager",
        nonce=_grant_id(f"parent-tamper-request:{tamper_kind}"),
    )

    with pytest.raises(Exception) as captured:
        _issue_child(
            ledger_path,
            candidate,
            request,
            ephemeral_role_keys,
            fixed_now,
        )
    _assert_child_rejection(captured.value)
    connection = connect_ledger(ledger_path)
    try:
        assert _ledger_integrity_snapshot(connection) == before
    finally:
        connection.close()


def test_effective_history_actor_matches_candidate_issuer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
) -> None:
    ledger_path = tmp_path / "effective-history-actor.sqlite3"
    _activate_ledger_root(
        ledger_path,
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        fixed_now,
    )
    issued = _child_grant(
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        label="effective-history-actor:issued",
    )
    _issue_child(
        ledger_path,
        issued,
        _delegation_request(
            signed_work_order,
            signed_root_grant,
            issued,
            ephemeral_role_keys,
            actor_role="Manager",
            nonce=_grant_id("effective-history-actor:issued-request"),
        ),
        ephemeral_role_keys,
        fixed_now,
    )
    connection = connect_ledger(ledger_path)
    try:
        raw = json.loads(
            connection.execute(
                "SELECT receipt_json FROM receipts WHERE sequence = 2"
            ).fetchone()[0]
        )
        developer = ephemeral_role_keys["Developer"][1]
        nested = copy.deepcopy(raw["nested_claim"])
        nested["actor_id"] = developer["subject_id"]
        nested["actor_key_id"] = developer["key_id"]
        signed_nested = sign_payload(
            "agent-request",
            nested,
            ephemeral_role_keys["Developer"][0],
        )
        raw["actor_id"] = developer["subject_id"]
        raw["actor_key_id"] = developer["key_id"]
        raw["nested_claim"] = signed_nested
        raw["nested_claim_digest"] = signed_nested["digest"]
        resigned = sign_payload(
            "action-receipt",
            raw,
            ephemeral_role_keys["Sidecar"][0],
        )
        connection.execute(
            "UPDATE receipts SET receipt_json = ? WHERE sequence = 2",
            (_canonical_json(resigned),),
        )
        before = _ledger_integrity_snapshot(connection)
    finally:
        connection.close()
    candidate = _child_grant(
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        label="effective-history-actor:next",
    )
    _assert_write_free_child_integrity_failure(
        ledger_path=ledger_path,
        candidate=candidate,
        request=_delegation_request(
            signed_work_order,
            signed_root_grant,
            candidate,
            ephemeral_role_keys,
            actor_role="Manager",
            nonce=_grant_id("effective-history-actor:next-request"),
        ),
        role_keys=ephemeral_role_keys,
        now=fixed_now,
        before=before,
        monkeypatch=monkeypatch,
    )


def test_duplicate_successful_issuance_for_one_grant_is_write_free_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
) -> None:
    ledger_path = tmp_path / "duplicate-successful-issuance.sqlite3"
    _activate_ledger_root(
        ledger_path,
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        fixed_now,
    )
    child = _child_grant(
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        label="duplicate-successful-issuance:child",
    )
    first_receipt = _issue_child(
        ledger_path,
        child,
        _delegation_request(
            signed_work_order,
            signed_root_grant,
            child,
            ephemeral_role_keys,
            actor_role="Manager",
            nonce=_grant_id(
                "duplicate-successful-issuance:first-request"
            ),
        ),
        ephemeral_role_keys,
        fixed_now,
    )
    duplicate_request = _delegation_request(
        signed_work_order,
        signed_root_grant,
        child,
        ephemeral_role_keys,
        actor_role="Manager",
        nonce=_grant_id(
            "duplicate-successful-issuance:second-request"
        ),
    )
    duplicate_raw = first_receipt.model_dump(mode="json")
    duplicate_raw.update(
        {
            "receipt_id": _grant_id(
                "duplicate-successful-issuance:second-receipt"
            ),
            "nested_claim": duplicate_request.model_dump(mode="json"),
            "nested_claim_digest": duplicate_request.digest,
            "nonce": duplicate_request.nonce,
            "sequence": 3,
            "previous_receipt_digest": first_receipt.digest,
            "parent_receipt_ids": [first_receipt.receipt_id],
        }
    )
    duplicate_receipt = evidence.ACTION_RECEIPT_ADAPTER.validate_python(
        sign_payload(
            "action-receipt",
            duplicate_raw,
            ephemeral_role_keys["Sidecar"][0],
        )
    )
    duplicate_receipt.validate_against_work_order(signed_work_order)
    duplicate_receipt.validate_candidate(child)
    connection = connect_ledger(ledger_path)
    try:
        _append_action_receipt(connection, duplicate_receipt)
        connection.execute(
            """
            INSERT INTO grant_events (
                event_id,
                receipt_id,
                grant_id,
                event_type,
                metric,
                amount
            )
            VALUES (?, ?, ?, 'grant_issued', NULL, NULL)
            """,
            (
                hashlib.sha256(
                    (
                        "grant-issued:"
                        f"{duplicate_receipt.receipt_id}"
                    ).encode("ascii")
                ).hexdigest(),
                duplicate_receipt.receipt_id,
                child.grant_id,
            ),
        )
        connection.execute(
            "UPDATE sequence_counter SET next_sequence = 4"
        )
        connection.execute(
            "UPDATE work_order_state SET version = 3"
        )
        before = _ledger_integrity_snapshot(connection)
    finally:
        connection.close()

    next_child = _child_grant(
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        label="duplicate-successful-issuance:next-child",
    )
    _assert_write_free_child_integrity_failure(
        ledger_path=ledger_path,
        candidate=next_child,
        request=_delegation_request(
            signed_work_order,
            signed_root_grant,
            next_child,
            ephemeral_role_keys,
            actor_role="Manager",
            nonce=_grant_id(
                "duplicate-successful-issuance:next-request"
            ),
        ),
        role_keys=ephemeral_role_keys,
        now=fixed_now,
        before=before,
        monkeypatch=monkeypatch,
    )


def test_distinct_grants_each_have_one_successful_issuance_guard(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
) -> None:
    ledger_path = tmp_path / "distinct-successful-issuances.sqlite3"
    _activate_ledger_root(
        ledger_path,
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        fixed_now,
    )
    receipts = []
    children = []
    for index in range(2):
        child = _child_grant(
            signed_work_order,
            signed_root_grant,
            ephemeral_role_keys,
            label=f"distinct-successful-issuance:{index}",
        )
        children.append(child)
        receipts.append(
            _issue_child(
                ledger_path,
                child,
                _delegation_request(
                    signed_work_order,
                    signed_root_grant,
                    child,
                    ephemeral_role_keys,
                    actor_role="Manager",
                    nonce=_grant_id(
                        f"distinct-successful-issuance-request:{index}"
                    ),
                ),
                ephemeral_role_keys,
                fixed_now,
            )
        )

    assert tuple(receipt.sequence for receipt in receipts) == (2, 3)
    assert {receipt.issued_grant_id for receipt in receipts} == {
        child.grant_id for child in children
    }
    connection = connect_ledger(ledger_path)
    try:
        assert evidence._validated_receipt_prefix(
            connection,
            signed_work_order,
        )[-1] == receipts[-1]
    finally:
        connection.close()


@pytest.mark.parametrize(
    "invalid_policy",
    ("role", "tools", "roots", "time_skew"),
)
def test_effective_history_replays_child_policy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    invalid_policy: str,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
) -> None:
    ledger_path = tmp_path / (
        f"effective-history-policy-{invalid_policy}.sqlite3"
    )
    _activate_ledger_root(
        ledger_path,
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        fixed_now,
    )
    issued = _child_grant(
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        label=f"effective-history-policy:{invalid_policy}",
    )
    _issue_child(
        ledger_path,
        issued,
        _delegation_request(
            signed_work_order,
            signed_root_grant,
            issued,
            ephemeral_role_keys,
            actor_role="Manager",
            nonce=_grant_id(
                f"effective-history-policy-request:{invalid_policy}"
            ),
        ),
        ephemeral_role_keys,
        fixed_now,
    )
    candidate_raw = issued.model_dump(mode="json")
    if invalid_policy == "role":
        manager = ephemeral_role_keys["Manager"][1]
        candidate_raw["subject_agent_id"] = manager["subject_id"]
        candidate_raw["subject_key_id"] = manager["key_id"]
    elif invalid_policy == "tools":
        candidate_raw["allowed_tools"] = ["owp.start_retry"]
    elif invalid_policy == "roots":
        candidate_raw["allowed_read_roots"] = ["docs"]
        candidate_raw["allowed_write_roots"] = []
    else:
        candidate_raw["issued_at"] = "2026-01-01T00:10:00Z"
        candidate_raw["valid_from"] = "2026-01-01T00:10:01Z"
    connection = connect_ledger(ledger_path)
    try:
        _rewrite_grant_issuance_history(
            connection,
            sequence=2,
            candidate_raw=candidate_raw,
            allowed=True,
            work_order=signed_work_order,
            role_keys=ephemeral_role_keys,
        )
        before = _ledger_integrity_snapshot(connection)
    finally:
        connection.close()
    next_candidate = _child_grant(
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        label=f"effective-history-policy-next:{invalid_policy}",
    )
    _assert_write_free_child_integrity_failure(
        ledger_path=ledger_path,
        candidate=next_candidate,
        request=_delegation_request(
            signed_work_order,
            signed_root_grant,
            next_candidate,
            ephemeral_role_keys,
            actor_role="Manager",
            nonce=_grant_id(
                f"effective-history-policy-next-request:{invalid_policy}"
            ),
        ),
        role_keys=ephemeral_role_keys,
        now=fixed_now,
        before=before,
        monkeypatch=monkeypatch,
    )


def test_effective_history_replays_sibling_quota_in_order(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
) -> None:
    ledger_path = tmp_path / "effective-history-sibling-quota.sqlite3"
    _activate_ledger_root(
        ledger_path,
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        fixed_now,
    )
    children = []
    for index in range(2):
        child = _child_grant(
            signed_work_order,
            signed_root_grant,
            ephemeral_role_keys,
            label=f"effective-history-sibling-quota:{index}",
        )
        children.append(child)
        _issue_child(
            ledger_path,
            child,
            _delegation_request(
                signed_work_order,
                signed_root_grant,
                child,
                ephemeral_role_keys,
                actor_role="Manager",
                nonce=_grant_id(
                    f"effective-history-sibling-quota-request:{index}"
                ),
            ),
            ephemeral_role_keys,
            fixed_now,
        )
    second_raw = children[1].model_dump(mode="json")
    second_raw["quota"] = {
        "tool_calls": signed_root_grant.quota.tool_calls,
        "repair_rounds": 0,
    }
    connection = connect_ledger(ledger_path)
    try:
        _rewrite_grant_issuance_history(
            connection,
            sequence=3,
            candidate_raw=second_raw,
            allowed=True,
            work_order=signed_work_order,
            role_keys=ephemeral_role_keys,
        )
        before = _ledger_integrity_snapshot(connection)
    finally:
        connection.close()
    next_candidate = _child_grant(
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        label="effective-history-sibling-quota:next",
    )
    _assert_write_free_child_integrity_failure(
        ledger_path=ledger_path,
        candidate=next_candidate,
        request=_delegation_request(
            signed_work_order,
            signed_root_grant,
            next_candidate,
            ephemeral_role_keys,
            actor_role="Manager",
            nonce=_grant_id(
                "effective-history-sibling-quota:next-request"
            ),
        ),
        role_keys=ephemeral_role_keys,
        now=fixed_now,
        before=before,
        monkeypatch=monkeypatch,
    )


@pytest.mark.parametrize(
    "tamper_kind",
    ("negative_amount", "wrong_metric", "zero_amount", "receipt_linkage"),
)
def test_tampered_grant_event_index_never_changes_parent_quota(
    tmp_path: Path,
    tamper_kind: str,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
) -> None:
    ledger_path = tmp_path / f"event-tamper-{tamper_kind}.sqlite3"
    _activate_ledger_root(
        ledger_path,
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        fixed_now,
    )
    if tamper_kind == "receipt_linkage":
        first = _child_grant(
            signed_work_order,
            signed_root_grant,
            ephemeral_role_keys,
            label="event-tamper:first",
        )
        first_receipt = _issue_child(
            ledger_path,
            first,
            _delegation_request(
                signed_work_order,
                signed_root_grant,
                first,
                ephemeral_role_keys,
                actor_role="Manager",
                nonce=_grant_id("event-tamper:first-request"),
            ),
            ephemeral_role_keys,
            fixed_now,
        )
    connection = connect_ledger(ledger_path)
    try:
        if tamper_kind == "negative_amount":
            connection.execute(
                """
                UPDATE grant_events
                SET metric = 'tool_calls', amount = -1
                WHERE grant_id = ?
                """,
                (signed_root_grant.grant_id,),
            )
        elif tamper_kind == "wrong_metric":
            connection.execute(
                """
                UPDATE grant_events
                SET metric = 'unknown_metric', amount = 1
                WHERE grant_id = ?
                """,
                (signed_root_grant.grant_id,),
            )
        elif tamper_kind == "zero_amount":
            connection.execute(
                """
                UPDATE grant_events
                SET metric = 'tool_calls', amount = 0
                WHERE grant_id = ?
                """,
                (signed_root_grant.grant_id,),
            )
        else:
            connection.execute(
                "DELETE FROM grant_events WHERE grant_id = ?",
                (first.grant_id,),
            )
            connection.execute(
                """
                UPDATE grant_events
                SET receipt_id = ?
                WHERE grant_id = ?
                """,
                (
                    first_receipt.receipt_id,
                    signed_root_grant.grant_id,
                ),
            )
        before = _ledger_integrity_snapshot(connection)
    finally:
        connection.close()
    candidate = _child_grant(
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        label=f"event-tamper-candidate:{tamper_kind}",
    )
    request = _delegation_request(
        signed_work_order,
        signed_root_grant,
        candidate,
        ephemeral_role_keys,
        actor_role="Manager",
        nonce=_grant_id(f"event-tamper-request:{tamper_kind}"),
    )

    with pytest.raises(Exception) as captured:
        _issue_child(
            ledger_path,
            candidate,
            request,
            ephemeral_role_keys,
            fixed_now,
        )
    _assert_child_rejection(captured.value)
    connection = connect_ledger(ledger_path)
    try:
        assert _ledger_integrity_snapshot(connection) == before
    finally:
        connection.close()


@pytest.mark.parametrize(
    "tamper_kind",
    (
        "noncanonical_json",
        "json_digest",
        "json_signature",
        "json_receipt_id",
        "row_receipt_id",
        "row_sequence",
        "previous_digest",
        "parent_edges",
    ),
)
def test_tampered_receipt_tip_fails_before_signing_or_writes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tamper_kind: str,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
) -> None:
    ledger_path = tmp_path / f"tip-tamper-{tamper_kind}.sqlite3"
    _activate_ledger_root(
        ledger_path,
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        fixed_now,
    )
    raw_connection = sqlite3.connect(
        ledger_path,
        isolation_level=None,
    )
    raw_connection.execute("PRAGMA foreign_keys = OFF")
    try:
        row = raw_connection.execute(
            """
            SELECT receipt_id, receipt_json
            FROM receipts
            WHERE sequence = 1
            """
        ).fetchone()
        root_receipt_id, receipt_json = row
        if tamper_kind == "noncanonical_json":
            raw_connection.execute(
                "UPDATE receipts SET receipt_json = ? WHERE sequence = 1",
                (f" {receipt_json}",),
            )
        elif tamper_kind.startswith("json_"):
            raw = json.loads(receipt_json)
            if tamper_kind == "json_digest":
                raw["digest"] = "0" * 64
            elif tamper_kind == "json_signature":
                raw["signature"] = "A" * 86
            else:
                raw["receipt_id"] = "0" * 64
            raw_connection.execute(
                "UPDATE receipts SET receipt_json = ? WHERE sequence = 1",
                (_canonical_json(raw),),
            )
        elif tamper_kind == "row_receipt_id":
            raw_connection.execute(
                "UPDATE receipts SET receipt_id = ? WHERE sequence = 1",
                ("0" * 64,),
            )
        elif tamper_kind == "row_sequence":
            raw_connection.execute(
                "UPDATE receipts SET sequence = 2 WHERE sequence = 1"
            )
        elif tamper_kind == "previous_digest":
            raw_connection.execute(
                """
                UPDATE receipts
                SET previous_digest = ?
                WHERE sequence = 1
                """,
                ("0" * 64,),
            )
        else:
            raw_connection.execute(
                """
                INSERT INTO receipt_parents (
                    child_receipt_id,
                    parent_receipt_id
                )
                VALUES (?, ?)
                """,
                (root_receipt_id, root_receipt_id),
            )
    finally:
        raw_connection.close()
    connection = connect_ledger(ledger_path)
    try:
        before = _ledger_integrity_snapshot(connection)
    finally:
        connection.close()
    candidate = _child_grant(
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        label=f"tip-tamper-candidate:{tamper_kind}",
    )
    request = _delegation_request(
        signed_work_order,
        signed_root_grant,
        candidate,
        ephemeral_role_keys,
        actor_role="Manager",
        nonce=_grant_id(f"tip-tamper-request:{tamper_kind}"),
    )
    real_sign_payload = evidence.sign_payload
    action_receipt_signatures = 0

    def tracked_sign_payload(
        object_type: str,
        value,
        private_key: Ed25519PrivateKey,
    ):
        nonlocal action_receipt_signatures
        if object_type == "action-receipt":
            action_receipt_signatures += 1
        return real_sign_payload(object_type, value, private_key)

    monkeypatch.setattr(evidence, "sign_payload", tracked_sign_payload)
    with pytest.raises(Exception) as captured:
        _issue_child(
            ledger_path,
            candidate,
            request,
            ephemeral_role_keys,
            fixed_now,
        )
    _assert_child_rejection(captured.value)
    assert action_receipt_signatures == 0
    connection = connect_ledger(ledger_path)
    try:
        assert _ledger_integrity_snapshot(connection) == before
    finally:
        connection.close()


@pytest.mark.parametrize(
    "tamper_kind",
    ("signature", "actor", "signer", "arguments", "digest"),
)
def test_receipt_prefix_verifies_denied_attempt_nested_agent_request(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tamper_kind: str,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
) -> None:
    ledger_path = tmp_path / f"nested-agent-{tamper_kind}.sqlite3"
    _activate_ledger_root(
        ledger_path,
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        fixed_now,
    )
    denied = _child_grant(
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        label=f"nested-agent-denied:{tamper_kind}",
        subject_role="Verifier",
        updates={"allowed_write_roots": ["src"]},
    )
    denied_receipt = _issue_child(
        ledger_path,
        denied,
        _delegation_request(
            signed_work_order,
            signed_root_grant,
            denied,
            ephemeral_role_keys,
            actor_role="Manager",
            nonce=_grant_id(
                f"nested-agent-denied-request:{tamper_kind}"
            ),
        ),
        ephemeral_role_keys,
        fixed_now,
    )
    assert denied_receipt.policy_decision == "deny"
    connection = connect_ledger(ledger_path)
    try:
        receipt_json = connection.execute(
            "SELECT receipt_json FROM receipts WHERE sequence = 2"
        ).fetchone()[0]
        raw = json.loads(receipt_json)
        nested = raw["nested_claim"]
        if tamper_kind == "signature":
            nested["signature"] = "A" * 86
        elif tamper_kind in {"actor", "signer"}:
            role = "Developer" if tamper_kind == "actor" else "Verifier"
            binding = ephemeral_role_keys[role][1]
            nested["actor_id"] = binding["subject_id"]
            nested["actor_key_id"] = binding["key_id"]
            nested["signer_key_id"] = binding["key_id"]
            raw["actor_id"] = binding["subject_id"]
            raw["actor_key_id"] = binding["key_id"]
        elif tamper_kind == "arguments":
            nested["arguments_digest"] = "0" * 64
        else:
            nested["digest"] = "0" * 64
            raw["nested_claim_digest"] = "0" * 64
        if tamper_kind in {"actor", "signer", "arguments"}:
            nested["digest"] = digest_payload(
                "agent-request",
                nested,
            )
            raw["nested_claim_digest"] = nested["digest"]
        resigned = sign_payload(
            "action-receipt",
            raw,
            ephemeral_role_keys["Sidecar"][0],
        )
        connection.execute(
            "UPDATE receipts SET receipt_json = ? WHERE sequence = 2",
            (_canonical_json(resigned),),
        )
        before = _ledger_integrity_snapshot(connection)
    finally:
        connection.close()
    candidate = _child_grant(
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        label=f"nested-agent-next:{tamper_kind}",
    )
    request = _delegation_request(
        signed_work_order,
        signed_root_grant,
        candidate,
        ephemeral_role_keys,
        actor_role="Manager",
        nonce=_grant_id(f"nested-agent-next-request:{tamper_kind}"),
    )
    real_sign_payload = evidence.sign_payload
    action_receipt_signatures = 0

    def tracked_sign_payload(
        object_type: str,
        value,
        private_key: Ed25519PrivateKey,
    ):
        nonlocal action_receipt_signatures
        if object_type == "action-receipt":
            action_receipt_signatures += 1
        return real_sign_payload(object_type, value, private_key)

    monkeypatch.setattr(evidence, "sign_payload", tracked_sign_payload)
    with pytest.raises(evidence.ChildGrantIssuanceError):
        _issue_child(
            ledger_path,
            candidate,
            request,
            ephemeral_role_keys,
            fixed_now,
        )

    assert action_receipt_signatures == 0
    connection = connect_ledger(ledger_path)
    try:
        assert _ledger_integrity_snapshot(connection) == before
    finally:
        connection.close()


@pytest.mark.parametrize(
    ("replacement_role", "expected_valid"),
    (("Developer", False), ("Manager", True)),
)
def test_denied_receipt_actor_matches_candidate_issuer_binding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    replacement_role: str,
    expected_valid: bool,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
) -> None:
    ledger_path = tmp_path / (
        f"denied-actor-binding-{replacement_role}.sqlite3"
    )
    _activate_ledger_root(
        ledger_path,
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        fixed_now,
    )
    denied = _child_grant(
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        label=f"denied-actor-binding:{replacement_role}",
        subject_role="Verifier",
        updates={"allowed_write_roots": ["src"]},
    )
    denied_receipt = _issue_child(
        ledger_path,
        denied,
        _delegation_request(
            signed_work_order,
            signed_root_grant,
            denied,
            ephemeral_role_keys,
            actor_role="Manager",
            nonce=_grant_id(
                f"denied-actor-binding-request:{replacement_role}"
            ),
        ),
        ephemeral_role_keys,
        fixed_now,
    )
    assert denied_receipt.policy_decision == "deny"
    connection = connect_ledger(ledger_path)
    try:
        receipt_json = connection.execute(
            "SELECT receipt_json FROM receipts WHERE sequence = 2"
        ).fetchone()[0]
        raw = json.loads(receipt_json)
        original_nonce = raw["nested_claim"]["nonce"]
        original_arguments = raw["nested_claim"]["arguments_digest"]
        binding = ephemeral_role_keys[replacement_role][1]
        nested = copy.deepcopy(raw["nested_claim"])
        nested["actor_id"] = binding["subject_id"]
        nested["actor_key_id"] = binding["key_id"]
        resigned_nested = sign_payload(
            "agent-request",
            nested,
            ephemeral_role_keys[replacement_role][0],
        )
        assert resigned_nested["nonce"] == original_nonce
        assert (
            resigned_nested["arguments_digest"]
            == original_arguments
        )
        raw["actor_id"] = binding["subject_id"]
        raw["actor_key_id"] = binding["key_id"]
        raw["nested_claim"] = resigned_nested
        raw["nested_claim_digest"] = resigned_nested["digest"]
        resigned_receipt = sign_payload(
            "action-receipt",
            raw,
            ephemeral_role_keys["Sidecar"][0],
        )
        connection.execute(
            "UPDATE receipts SET receipt_json = ? WHERE sequence = 2",
            (_canonical_json(resigned_receipt),),
        )
        before = _ledger_integrity_snapshot(connection)
    finally:
        connection.close()
    candidate = _child_grant(
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        label=f"denied-actor-binding-next:{replacement_role}",
    )
    request = _delegation_request(
        signed_work_order,
        signed_root_grant,
        candidate,
        ephemeral_role_keys,
        actor_role="Manager",
        nonce=_grant_id(
            f"denied-actor-binding-next-request:{replacement_role}"
        ),
    )
    real_sign_payload = evidence.sign_payload
    action_receipt_signatures = 0

    def tracked_sign_payload(
        object_type: str,
        value,
        private_key: Ed25519PrivateKey,
    ):
        nonlocal action_receipt_signatures
        if object_type == "action-receipt":
            action_receipt_signatures += 1
        return real_sign_payload(object_type, value, private_key)

    monkeypatch.setattr(evidence, "sign_payload", tracked_sign_payload)
    if expected_valid:
        receipt = _issue_child(
            ledger_path,
            candidate,
            request,
            ephemeral_role_keys,
            fixed_now,
        )
        assert receipt.policy_decision == "allow"
        assert action_receipt_signatures == 1
    else:
        with pytest.raises(evidence.ChildGrantIssuanceError):
            _issue_child(
                ledger_path,
                candidate,
                request,
                ephemeral_role_keys,
                fixed_now,
            )
        assert action_receipt_signatures == 0
        connection = connect_ledger(ledger_path)
        try:
            assert _ledger_integrity_snapshot(connection) == before
        finally:
            connection.close()


@pytest.mark.parametrize(
    ("claim_kind", "event_type"),
    (
        ("human_signature", "approval_decision"),
        ("sidecar_digest", "system_event"),
    ),
)
def test_receipt_prefix_validates_human_and_sidecar_nested_claims(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    claim_kind: str,
    event_type: str,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    ledger_path = tmp_path / f"nested-{claim_kind}.sqlite3"
    _activate_ledger_root(
        ledger_path,
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        fixed_now,
    )
    connection = connect_ledger(ledger_path)
    try:
        root_id, root_json = connection.execute(
            """
            SELECT receipt_id, receipt_json
            FROM receipts
            WHERE sequence = 1
            """
        ).fetchone()
        root_digest = json.loads(root_json)["digest"]
        receipt = sidecar_receipt_factory(
            state_before=(
                "locally_verified"
                if claim_kind == "sidecar_digest"
                else "running"
            ),
            state_after=(
                "proof_ready"
                if claim_kind == "sidecar_digest"
                else "running"
            ),
            event_type=event_type,
            parent_receipt_ids=(root_id,),
            sequence=2,
            previous_receipt_digest=root_digest,
            occurred_at="2026-01-01T00:00:05Z",
        )
        raw = receipt.model_dump(mode="json")
        if claim_kind == "human_signature":
            raw["nested_claim"]["signature"] = "A" * 86
        else:
            raw["nested_claim"]["input_digest"] = "0" * 64
            raw["nested_claim_digest"] = "0" * 64
            raw["input_digest"] = "0" * 64
        resigned = sign_payload(
            "action-receipt",
            raw,
            ephemeral_role_keys["Sidecar"][0],
        )
        connection.execute(
            """
            INSERT INTO receipts (
                receipt_id,
                work_order_digest,
                nonce,
                sequence,
                previous_digest,
                receipt_json
            )
            VALUES (?, ?, ?, 2, ?, ?)
            """,
            (
                resigned["receipt_id"],
                signed_work_order.digest,
                resigned["nonce"],
                root_digest,
                _canonical_json(resigned),
            ),
        )
        connection.execute(
            """
            INSERT INTO receipt_parents (
                child_receipt_id,
                parent_receipt_id
            )
            VALUES (?, ?)
            """,
            (resigned["receipt_id"], root_id),
        )
        connection.execute(
            """
            UPDATE sequence_counter
            SET next_sequence = 3
            WHERE singleton = 1
            """
        )
        before = _ledger_integrity_snapshot(connection)
    finally:
        connection.close()
    candidate = _child_grant(
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        label=f"nested-{claim_kind}:next",
    )
    request = _delegation_request(
        signed_work_order,
        signed_root_grant,
        candidate,
        ephemeral_role_keys,
        actor_role="Manager",
        nonce=_grant_id(f"nested-{claim_kind}:request"),
    )
    real_sign_payload = evidence.sign_payload
    action_receipt_signatures = 0

    def tracked_sign_payload(
        object_type: str,
        value,
        private_key: Ed25519PrivateKey,
    ):
        nonlocal action_receipt_signatures
        if object_type == "action-receipt":
            action_receipt_signatures += 1
        return real_sign_payload(object_type, value, private_key)

    monkeypatch.setattr(evidence, "sign_payload", tracked_sign_payload)
    with pytest.raises(evidence.ChildGrantIssuanceError):
        _issue_child(
            ledger_path,
            candidate,
            request,
            ephemeral_role_keys,
            fixed_now,
        )

    assert action_receipt_signatures == 0
    connection = connect_ledger(ledger_path)
    try:
        assert _ledger_integrity_snapshot(connection) == before
    finally:
        connection.close()


@pytest.mark.parametrize(
    "state_tamper",
    ("root_transition", "child_transition", "version"),
)
def test_receipt_state_chain_and_ledger_version_are_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    state_tamper: str,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
) -> None:
    ledger_path = tmp_path / f"state-chain-{state_tamper}.sqlite3"
    _activate_ledger_root(
        ledger_path,
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        fixed_now,
    )
    if state_tamper == "child_transition":
        issued = _child_grant(
            signed_work_order,
            signed_root_grant,
            ephemeral_role_keys,
            label="state-chain:issued",
        )
        _issue_child(
            ledger_path,
            issued,
            _delegation_request(
                signed_work_order,
                signed_root_grant,
                issued,
                ephemeral_role_keys,
                actor_role="Manager",
                nonce=_grant_id("state-chain:issued-request"),
            ),
            ephemeral_role_keys,
            fixed_now,
        )
    connection = connect_ledger(ledger_path)
    try:
        if state_tamper == "version":
            connection.execute(
                "UPDATE work_order_state SET version = 99"
            )
        else:
            sequence = 1 if state_tamper == "root_transition" else 2
            raw = json.loads(
                connection.execute(
                    "SELECT receipt_json FROM receipts WHERE sequence = ?",
                    (sequence,),
                ).fetchone()[0]
            )
            if state_tamper == "root_transition":
                raw["state_before"] = "running"
            else:
                raw["state_after"] = "needs_rework"
            resigned = sign_payload(
                "action-receipt",
                raw,
                ephemeral_role_keys["Sidecar"][0],
            )
            connection.execute(
                "UPDATE receipts SET receipt_json = ? WHERE sequence = ?",
                (_canonical_json(resigned), sequence),
            )
        before = _ledger_integrity_snapshot(connection)
    finally:
        connection.close()
    candidate = _child_grant(
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        label=f"state-chain-next:{state_tamper}",
    )
    _assert_write_free_child_integrity_failure(
        ledger_path=ledger_path,
        candidate=candidate,
        request=_delegation_request(
            signed_work_order,
            signed_root_grant,
            candidate,
            ephemeral_role_keys,
            actor_role="Manager",
            nonce=_grant_id(f"state-chain-next-request:{state_tamper}"),
        ),
        role_keys=ephemeral_role_keys,
        now=fixed_now,
        before=before,
        monkeypatch=monkeypatch,
    )


def test_protocol_version_is_derived_from_transactions_not_raw_rows(
    signed_work_order: WorkOrder,
    signed_acceptance_receipt,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    sidecar_receipt_factory,
) -> None:
    from test_contract import system_input_digest
    from test_state import _tool_receipt

    compose = _tool_receipt(
        tool_name="owp.compose_proof",
        actor_role="Manager",
        signed_work_order=signed_work_order,
        sidecar_receipt_factory=sidecar_receipt_factory,
        ephemeral_role_keys=ephemeral_role_keys,
    )
    compose_raw = compose.model_dump(mode="json")
    compose_raw["state_before"] = "locally_verified"
    compose_raw["state_after"] = "locally_verified"
    compose = evidence.ACTION_RECEIPT_ADAPTER.validate_python(
        sign_payload(
            "action-receipt",
            compose_raw,
            ephemeral_role_keys["Sidecar"][0],
        )
    )
    trigger = sidecar_receipt_factory(
        state_before="locally_verified",
        state_after="proof_ready",
        event_type="system_event",
        event_name="proof_composed",
        sequence=2,
        previous_receipt_digest=compose.digest,
        parent_receipt_ids=(compose.receipt_id,),
    )
    trigger_raw = trigger.model_dump(mode="json")
    cause = copy.deepcopy(trigger_raw["cause"])
    cause["initiator_receipt_digest"] = compose.digest
    input_digest = system_input_digest(
        "proof_composed",
        signed_work_order.digest,
        cause,
    )
    trigger_raw["cause"] = cause
    trigger_raw["input_digest"] = input_digest
    trigger_raw["nested_claim"]["cause"] = cause
    trigger_raw["nested_claim"]["input_digest"] = input_digest
    trigger_raw["nested_claim_digest"] = input_digest
    trigger = evidence.ACTION_RECEIPT_ADAPTER.validate_python(
        sign_payload(
            "action-receipt",
            trigger_raw,
            ephemeral_role_keys["Sidecar"][0],
        )
    )
    root = sidecar_receipt_factory(
        state_before="issued",
        state_after="running",
        event_type="grant_issued",
        sequence=1,
    )
    child = sidecar_receipt_factory(
        state_before="running",
        state_after="running",
        event_type="grant_issued",
        sequence=2,
        previous_receipt_digest=root.digest,
        parent_receipt_ids=(root.receipt_id,),
    )

    derive = getattr(
        evidence,
        "_derive_protocol_transaction_version",
        None,
    )
    assert callable(derive)
    assert derive(
        action_receipts=(compose, trigger),
        acceptance_receipts=(),
    ) == 1
    assert derive(
        action_receipts=(root, child),
        acceptance_receipts=(),
    ) == 2
    assert derive(
        action_receipts=(),
        acceptance_receipts=(signed_acceptance_receipt,),
    ) == 1
    with pytest.raises(evidence.ChildGrantIssuanceError):
        derive(
            action_receipts=({"event_type": "system_event"},),
            acceptance_receipts=(),
        )


def _linked_tool_receipt(
    *,
    tool_name: str,
    state_before: str,
    state_after: str,
    sequence: int,
    previous_receipt,
    root: CapabilityGrant,
    signed_work_order: WorkOrder,
    sidecar_receipt_factory,
    role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    label: str,
    policy_decision: str = "allow",
    policy_error_code: str | None = None,
    actor_role: str = "Manager",
    execution_status: str = "succeeded",
    expected_state_version: int | None = None,
    remaining_after: int | None = None,
    requested_at: str = "2026-01-01T00:00:02Z",
    occurred_at: str = "2026-01-01T00:00:05Z",
):
    from test_contract import agent_arguments_digest
    from test_state import _tool_receipt

    receipt = _tool_receipt(
        tool_name=tool_name,
        actor_role=actor_role,
        signed_work_order=signed_work_order,
        sidecar_receipt_factory=sidecar_receipt_factory,
        ephemeral_role_keys=role_keys,
    )
    raw = receipt.model_dump(mode="json")
    raw.update(
        {
            "receipt_id": _grant_id(f"{label}:receipt"),
            "grant_id": root.grant_id,
            "state_before": state_before,
            "state_after": state_after,
            "parent_receipt_ids": [previous_receipt.receipt_id],
            "sequence": sequence,
            "nonce": _grant_id(f"{label}:nonce"),
            "previous_receipt_digest": previous_receipt.digest,
            "occurred_at": occurred_at,
            "policy_decision": policy_decision,
            "policy_error_code": (
                policy_error_code or "STATE_DENIED"
                if policy_decision == "deny"
                else None
            ),
            "execution_status": (
                "denied"
                if policy_decision == "deny"
                else execution_status
            ),
            "execution_error_code": (
                "HANDLER_ERROR"
                if execution_status == "failed"
                else None
            ),
            "output_digest": (
                None
                if policy_decision == "deny"
                else (
                    _jcs_digest(
                        {
                            "status": "failed",
                            "error_code": "HANDLER_ERROR",
                        }
                    )
                    if execution_status == "failed"
                    else raw["output_digest"]
                )
            ),
            "quota_charge": (
                None
                if policy_decision == "deny"
                else {
                    "grant_id": root.grant_id,
                    "metric": "tool_calls",
                    "amount": 1,
                    "remaining_after": remaining_after,
                }
            ),
        }
    )
    if policy_decision == "deny":
        for field_name in (
            "toolchain_id",
            "execution_context_id",
            "container_instance_id_digest",
            "fixed_test_source_digest",
        ):
            raw["correlation_factors"][field_name] = None
    if expected_state_version is not None:
        raw["request_arguments"]["expected_state_version"] = (
            expected_state_version
        )
        raw["arguments_digest"] = agent_arguments_digest(
            tool_name,
            raw["request_arguments"],
        )
    for result in raw["predicate_results"]:
        if result["name"] != "quota_remaining":
            continue
        result["input"].update(
            {
                "grant_id": root.grant_id,
                "grant_remaining_before": (
                    remaining_after + 1
                    if remaining_after is not None
                    else root.quota.tool_calls
                ),
                "ledger_prefix_digest": previous_receipt.digest,
            }
        )
        result["input_digest"] = _jcs_digest(
            {
                "domain": "openworkproof/predicate-input/v0.1",
                "predicate_id": result["predicate_id"],
                "input": result["input"],
            }
        )
    claim = raw["nested_claim"]
    claim["grant_id"] = root.grant_id
    claim["arguments_digest"] = raw["arguments_digest"]
    claim["nonce"] = raw["nonce"]
    claim["requested_at"] = requested_at
    signed_claim = sign_payload(
        "agent-request",
        claim,
        role_keys[actor_role][0],
    )
    raw["nested_claim"] = signed_claim
    raw["nested_claim_digest"] = signed_claim["digest"]
    return evidence.ACTION_RECEIPT_ADAPTER.validate_python(
        sign_payload(
            "action-receipt",
            raw,
            role_keys["Sidecar"][0],
        )
    )


def _grant_replay_inputs(
    ledger_path: Path,
    work_order: WorkOrder,
):
    connection = connect_ledger(ledger_path)
    try:
        receipts = evidence._validated_receipt_prefix(
            connection,
            work_order,
        )
        grants = evidence._validated_effective_grants(
            connection,
            work_order,
            receipts,
        )
        attempts = evidence._validated_grant_attempts(
            connection,
            work_order,
            receipts,
        )
    finally:
        connection.close()
    return receipts, grants, attempts


def _grant_replay_context(
    *,
    tmp_path: Path,
    label: str,
    work_order: WorkOrder,
    root: CapabilityGrant,
    role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    now: datetime,
    child_updates: dict[str, object] | None = None,
    with_child: bool = False,
):
    ledger_path = tmp_path / f"{label}.sqlite3"
    _activate_ledger_root(
        ledger_path,
        work_order,
        root,
        role_keys,
        now,
    )
    child = None
    if with_child:
        child = _child_grant(
            work_order,
            root,
            role_keys,
            label=label,
            updates=child_updates,
        )
        _issue_child(
            ledger_path,
            child,
            _delegation_request(
                work_order,
                root,
                child,
                role_keys,
                actor_role="Manager",
                nonce=_grant_id(f"{label}:request"),
            ),
            role_keys,
            now,
        )
    receipts, grants, attempts = _grant_replay_inputs(
        ledger_path,
        work_order,
    )
    return ledger_path, child, receipts, grants, attempts


def _resign_linked_agent_receipt(
    receipt,
    *,
    grant_id: str,
    tool_name: str,
    arguments: dict[str, object],
    actor_role: str,
    label: str,
    role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    updates: dict[str, object],
):
    raw = receipt.model_dump(mode="json")
    raw.update(
        {
            "receipt_id": _grant_id(f"{label}:receipt"),
            "nonce": _grant_id(f"{label}:nonce"),
            **updates,
        }
    )
    if "grant_id" in raw:
        raw["grant_id"] = grant_id
    claim = raw["nested_claim"]
    claim.update(
        {
            "grant_id": grant_id,
            "arguments_digest": evidence.request_arguments_digest(
                tool_name,
                arguments,
            ),
            "nonce": raw["nonce"],
            "requested_at": "2026-01-01T00:00:02Z",
        }
    )
    signed_claim = sign_payload(
        "agent-request",
        claim,
        role_keys[actor_role][0],
    )
    raw["nested_claim"] = signed_claim
    raw["nested_claim_digest"] = signed_claim["digest"]
    return evidence.ACTION_RECEIPT_ADAPTER.validate_python(
        sign_payload(
            "action-receipt",
            raw,
            role_keys["Sidecar"][0],
        )
    )


def _linked_grant_consumed_receipt(
    *,
    grant: CapabilityGrant,
    sequence: int,
    previous_receipt,
    remaining_after: int | None,
    signed_work_order: WorkOrder,
    sidecar_receipt_factory,
    role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    label: str,
    policy_decision: str = "allow",
    amount: int = 1,
):
    receipt = sidecar_receipt_factory(
        state_before="needs_rework",
        state_after=(
            "needs_rework"
            if policy_decision == "deny"
            else "retrying"
        ),
        event_type="grant_consumed",
        actor_role="Manager",
        policy_decision=policy_decision,
        execution_status=(
            "denied" if policy_decision == "deny" else "succeeded"
        ),
        sequence=sequence,
        previous_receipt_digest=previous_receipt.digest,
        parent_receipt_ids=(previous_receipt.receipt_id,),
    )
    arguments = {
        "grant_id": grant.grant_id,
        "metric": "repair_rounds",
        "amount": amount,
    }
    return _resign_linked_agent_receipt(
        receipt,
        grant_id=grant.grant_id,
        tool_name="owp.start_retry",
        arguments=arguments,
        actor_role="Manager",
        label=label,
        role_keys=role_keys,
        updates={
            "amount": amount,
            "remaining_after": remaining_after,
            "quota_charge": (
                None
                if policy_decision == "deny"
                else {
                    "grant_id": grant.grant_id,
                    "metric": "repair_rounds",
                    "amount": amount,
                    "remaining_after": remaining_after,
                }
            ),
        },
    )


def _linked_failed_rollback_receipt(
    *,
    grant: CapabilityGrant,
    sequence: int,
    previous_receipt,
    remaining_after: int,
    signed_work_order: WorkOrder,
    sidecar_receipt_factory,
    role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    label: str,
    actor_role: str = "Developer",
):
    receipt = sidecar_receipt_factory(
        state_before="running",
        state_after="running",
        event_type="rollback",
        actor_role=actor_role,
        execution_status="failed",
        sequence=sequence,
        previous_receipt_digest=previous_receipt.digest,
        parent_receipt_ids=(previous_receipt.receipt_id,),
    )
    raw = receipt.model_dump(mode="json")
    arguments = {
        "target_patch_receipt_id": raw["target_patch_receipt_id"],
        "target_patch_digest": raw["target_patch_digest"],
        "before_commit": raw["before_commit"],
    }
    return _resign_linked_agent_receipt(
        receipt,
        grant_id=grant.grant_id,
        tool_name="owp.rollback_patch",
        arguments=arguments,
        actor_role=actor_role,
        label=label,
        role_keys=role_keys,
        updates={
            "quota_charge": {
                "grant_id": grant.grant_id,
                "metric": "tool_calls",
                "amount": 1,
                "remaining_after": remaining_after,
            },
        },
    )


def _linked_denied_revocation_receipt(
    *,
    authorizer: CapabilityGrant,
    target: CapabilityGrant,
    sequence: int,
    previous_receipt,
    signed_work_order: WorkOrder,
    sidecar_receipt_factory,
    role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    label: str,
):
    receipt = sidecar_receipt_factory(
        state_before="running",
        state_after="running",
        event_type="grant_revoked",
        actor_role="Manager",
        policy_decision="deny",
        execution_status="denied",
        sequence=sequence,
        previous_receipt_digest=previous_receipt.digest,
        parent_receipt_ids=(previous_receipt.receipt_id,),
    )
    raw = receipt.model_dump(mode="json")
    arguments = {
        "authorizing_grant_id": authorizer.grant_id,
        "revoked_grant_id": target.grant_id,
        "revocation_reason": raw["revocation_reason"],
    }
    return _resign_linked_agent_receipt(
        receipt,
        grant_id=authorizer.grant_id,
        tool_name="owp.revoke_grant",
        arguments=arguments,
        actor_role="Manager",
        label=label,
        role_keys=role_keys,
        updates={
            "authorizing_grant_id": authorizer.grant_id,
            "revoked_grant_id": target.grant_id,
        },
    )


def test_grant_quota_replay_allows_last_child_unit_without_double_charging_parent(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    _, child, receipts, grants, attempts = _grant_replay_context(
        tmp_path=tmp_path,
        label="last-child-unit",
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
        with_child=True,
        child_updates={"quota": {"tool_calls": 1, "repair_rounds": 0}},
    )
    assert child is not None
    wrong = _linked_tool_receipt(
        tool_name="owp.repo_read",
        state_before="running",
        state_after="running",
        sequence=3,
        previous_receipt=receipts[-1],
        root=child,
        signed_work_order=signed_work_order,
        sidecar_receipt_factory=sidecar_receipt_factory,
        role_keys=ephemeral_role_keys,
        label="last-child-unit:wrong",
        actor_role="Developer",
        remaining_after=1,
    )
    with pytest.raises(
        evidence.ChildGrantIssuanceError,
        match="quota",
    ):
        evidence._validate_grant_history_semantics(
            signed_work_order,
            (*receipts, wrong),
            grants,
            attempts,
        )
    charged = _linked_tool_receipt(
        tool_name="owp.repo_read",
        state_before="running",
        state_after="running",
        sequence=3,
        previous_receipt=receipts[-1],
        root=child,
        signed_work_order=signed_work_order,
        sidecar_receipt_factory=sidecar_receipt_factory,
        role_keys=ephemeral_role_keys,
        label="last-child-unit:charge",
        actor_role="Developer",
        remaining_after=0,
    )
    root_remaining = signed_root_grant.quota.tool_calls - 2
    parent_charge = _linked_tool_receipt(
        tool_name="owp.create_pr_proposal",
        state_before="running",
        state_after="running",
        sequence=4,
        previous_receipt=charged,
        root=signed_root_grant,
        signed_work_order=signed_work_order,
        sidecar_receipt_factory=sidecar_receipt_factory,
        role_keys=ephemeral_role_keys,
        label="last-child-unit:parent-charge",
        remaining_after=root_remaining,
    )
    replay = evidence._validate_grant_history_semantics(
        signed_work_order,
        (*receipts, charged, parent_charge),
        grants,
        attempts,
    )

    assert replay[child.grant_id].remaining_tool_calls == 0
    assert replay[signed_root_grant.grant_id].remaining_tool_calls == root_remaining


@pytest.mark.parametrize("case", ("revoked", "single_use", "wrong_actor"))
def test_grant_quota_replay_rejects_invalid_child_charge(
    tmp_path: Path,
    case: str,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    ledger_path, child, _, _, _ = _grant_replay_context(
        tmp_path=tmp_path,
        label=f"invalid-child-charge:{case}",
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
        with_child=True,
        child_updates=(
            {"usage_mode": "single_use"}
            if case == "single_use"
            else None
        ),
    )
    assert child is not None
    if case == "revoked":
        _revoke_child(
            ledger_path,
            signed_root_grant,
            child,
            _revocation_request(
                signed_work_order,
                signed_root_grant,
                child,
                ephemeral_role_keys,
                actor_role="Manager",
                nonce=_grant_id("invalid-child-charge:revoke"),
            ),
            ephemeral_role_keys,
            fixed_now,
        )
    receipts, grants, attempts = _grant_replay_inputs(
        ledger_path,
        signed_work_order,
    )
    first = _linked_tool_receipt(
        tool_name="owp.repo_read",
        state_before="running",
        state_after="running",
        sequence=len(receipts) + 1,
        previous_receipt=receipts[-1],
        root=child,
        signed_work_order=signed_work_order,
        sidecar_receipt_factory=sidecar_receipt_factory,
        role_keys=ephemeral_role_keys,
        label=f"invalid-child-charge:{case}:first",
        actor_role="Manager" if case == "wrong_actor" else "Developer",
        remaining_after=1,
    )
    replay_receipts = (*receipts, first)
    if case == "single_use":
        second = _linked_tool_receipt(
            tool_name="owp.repo_read",
            state_before="running",
            state_after="running",
            sequence=len(receipts) + 2,
            previous_receipt=first,
            root=child,
            signed_work_order=signed_work_order,
            sidecar_receipt_factory=sidecar_receipt_factory,
            role_keys=ephemeral_role_keys,
            label="invalid-child-charge:single-use:second",
            actor_role="Developer",
            remaining_after=0,
        )
        replay_receipts = (*replay_receipts, second)

    with pytest.raises(evidence.ChildGrantIssuanceError):
        evidence._validate_grant_history_semantics(
            signed_work_order,
            replay_receipts,
            grants,
            attempts,
        )


def test_denied_charge_is_free_and_does_not_consume_single_use_grant(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    _, child, receipts, grants, attempts = _grant_replay_context(
        tmp_path=tmp_path,
        label="denied-is-free",
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
        with_child=True,
        child_updates={
            "usage_mode": "single_use",
            "quota": {"tool_calls": 1, "repair_rounds": 0},
        },
    )
    assert child is not None
    valid_consumption_denial = _linked_grant_consumed_receipt(
        grant=signed_root_grant,
        sequence=3,
        previous_receipt=receipts[-1],
        remaining_after=None,
        signed_work_order=signed_work_order,
        sidecar_receipt_factory=sidecar_receipt_factory,
        role_keys=ephemeral_role_keys,
        label="denied-is-free:valid-consumption",
        policy_decision="deny",
    )
    denied_replay = evidence._validate_grant_history_semantics(
        signed_work_order,
        (*receipts, valid_consumption_denial),
        grants,
        attempts,
    )
    assert denied_replay[signed_root_grant.grant_id].remaining_repair_rounds == 1
    invalid_amount = _linked_grant_consumed_receipt(
        grant=signed_root_grant,
        sequence=3,
        previous_receipt=receipts[-1],
        remaining_after=None,
        signed_work_order=signed_work_order,
        sidecar_receipt_factory=sidecar_receipt_factory,
        role_keys=ephemeral_role_keys,
        label="denied-is-free:invalid-amount",
        policy_decision="deny",
        amount=2,
    )
    with pytest.raises(evidence.ChildGrantIssuanceError):
        evidence._validate_grant_history_semantics(
            signed_work_order,
            (*receipts, invalid_amount),
            grants,
            attempts,
        )
    denied = _linked_tool_receipt(
        tool_name="owp.repo_read",
        state_before="running",
        state_after="running",
        sequence=3,
        previous_receipt=receipts[-1],
        root=child,
        signed_work_order=signed_work_order,
        sidecar_receipt_factory=sidecar_receipt_factory,
        role_keys=ephemeral_role_keys,
        label="denied-is-free:deny",
        policy_decision="deny",
        actor_role="Developer",
    )
    charged = _linked_tool_receipt(
        tool_name="owp.repo_read",
        state_before="running",
        state_after="running",
        sequence=4,
        previous_receipt=denied,
        root=child,
        signed_work_order=signed_work_order,
        sidecar_receipt_factory=sidecar_receipt_factory,
        role_keys=ephemeral_role_keys,
        label="denied-is-free:allow",
        actor_role="Developer",
        remaining_after=0,
    )

    replay = evidence._validate_grant_history_semantics(
        signed_work_order,
        (*receipts, denied, charged),
        grants,
        attempts,
    )

    assert replay[child.grant_id].remaining_tool_calls == 0
    assert replay[child.grant_id].use_count == 1


def test_started_failures_charge_and_metrics_replay_independently(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    _, child, receipts, grants, attempts = _grant_replay_context(
        tmp_path=tmp_path,
        label="started-failures",
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
        with_child=True,
        child_updates={
            "allowed_tools": [
                "owp.apply_patch",
                "owp.repo_read",
                "owp.rollback_patch",
            ],
        },
    )
    assert child is not None
    failed_tool = _linked_tool_receipt(
        tool_name="owp.repo_read",
        state_before="running",
        state_after="running",
        sequence=3,
        previous_receipt=receipts[-1],
        root=child,
        signed_work_order=signed_work_order,
        sidecar_receipt_factory=sidecar_receipt_factory,
        role_keys=ephemeral_role_keys,
        label="started-failures:tool",
        actor_role="Developer",
        execution_status="failed",
        remaining_after=child.quota.tool_calls - 1,
    )
    failed_rollback = _linked_failed_rollback_receipt(
        grant=child,
        sequence=4,
        previous_receipt=failed_tool,
        remaining_after=child.quota.tool_calls - 2,
        signed_work_order=signed_work_order,
        sidecar_receipt_factory=sidecar_receipt_factory,
        role_keys=ephemeral_role_keys,
        label="started-failures:rollback",
    )
    repair = _linked_grant_consumed_receipt(
        grant=signed_root_grant,
        sequence=5,
        previous_receipt=failed_rollback,
        remaining_after=0,
        signed_work_order=signed_work_order,
        sidecar_receipt_factory=sidecar_receipt_factory,
        role_keys=ephemeral_role_keys,
        label="started-failures:repair",
    )

    replay = evidence._validate_grant_history_semantics(
        signed_work_order,
        (*receipts, failed_tool, failed_rollback, repair),
        grants,
        attempts,
    )

    root = replay[signed_root_grant.grant_id]
    assert (
        root.remaining_tool_calls
        == signed_root_grant.quota.tool_calls - child.quota.tool_calls
    )
    assert root.remaining_repair_rounds == 0
    assert replay[child.grant_id].remaining_tool_calls == 0


@pytest.mark.parametrize("receipt_kind", ("tool", "rollback"))
def test_manager_root_cannot_charge_developer_direct_calls(
    tmp_path: Path,
    receipt_kind: str,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    _, _, receipts, grants, attempts = _grant_replay_context(
        tmp_path=tmp_path,
        label=f"manager-direct-{receipt_kind}",
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
    )
    if receipt_kind == "tool":
        charged = _linked_tool_receipt(
            tool_name="owp.repo_read",
            state_before="running",
            state_after="running",
            sequence=2,
            previous_receipt=receipts[-1],
            root=signed_root_grant,
            signed_work_order=signed_work_order,
            sidecar_receipt_factory=sidecar_receipt_factory,
            role_keys=ephemeral_role_keys,
            label="manager-direct-tool",
            remaining_after=signed_root_grant.quota.tool_calls - 1,
        )
    else:
        charged = _linked_failed_rollback_receipt(
            grant=signed_root_grant,
            sequence=2,
            previous_receipt=receipts[-1],
            remaining_after=signed_root_grant.quota.tool_calls - 1,
            signed_work_order=signed_work_order,
            sidecar_receipt_factory=sidecar_receipt_factory,
            role_keys=ephemeral_role_keys,
            label="manager-direct-rollback",
            actor_role="Manager",
        )

    with pytest.raises(
        evidence.ChildGrantIssuanceError,
        match="role",
    ):
        evidence._validate_grant_history_semantics(
            signed_work_order,
            (*receipts, charged),
            grants,
            attempts,
        )
    if receipt_kind == "tool":
        denied = _linked_tool_receipt(
            tool_name="owp.repo_read",
            state_before="running",
            state_after="running",
            sequence=2,
            previous_receipt=receipts[-1],
            root=signed_root_grant,
            signed_work_order=signed_work_order,
            sidecar_receipt_factory=sidecar_receipt_factory,
            role_keys=ephemeral_role_keys,
            label="manager-direct-role-denied",
            policy_decision="deny",
            policy_error_code="ROLE_DENIED",
        )
        replay = evidence._validate_grant_history_semantics(
            signed_work_order,
            (*receipts, denied),
            grants,
            attempts,
        )
        assert replay[signed_root_grant.grant_id].use_count == 0


@pytest.mark.parametrize(
    "case",
    ("unknown", "wrong_actor", "wrong_role", "stale"),
)
def test_denied_tool_receipt_still_requires_authentic_grant_call_binding(
    tmp_path: Path,
    case: str,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    _, child, receipts, grants, attempts = _grant_replay_context(
        tmp_path=tmp_path,
        label=f"denied-binding:{case}",
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
        with_child=True,
    )
    assert child is not None
    unissued = _child_grant(
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        label="denied-binding:never-issued",
    )
    grant = (
        unissued
        if case == "unknown"
        else signed_root_grant
        if case == "wrong_role"
        else child
    )
    actor_role = (
        "Manager"
        if case in {"wrong_actor", "wrong_role"}
        else "Developer"
    )
    denied = _linked_tool_receipt(
        tool_name="owp.repo_read",
        state_before="running",
        state_after="running",
        sequence=3,
        previous_receipt=receipts[-1],
        root=grant,
        signed_work_order=signed_work_order,
        sidecar_receipt_factory=sidecar_receipt_factory,
        role_keys=ephemeral_role_keys,
        label=f"denied-binding:{case}:receipt",
        policy_decision="deny",
        actor_role=actor_role,
        occurred_at=(
            "2026-01-01T00:05:03Z"
            if case == "stale"
            else "2026-01-01T00:00:05Z"
        ),
    )

    with pytest.raises(evidence.ChildGrantIssuanceError):
        evidence._validate_grant_history_semantics(
            signed_work_order,
            (*receipts, denied),
            grants,
            attempts,
        )


def test_denied_revocation_is_authenticated_but_does_not_revoke_or_consume(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    _, child, receipts, grants, attempts = _grant_replay_context(
        tmp_path=tmp_path,
        label="denied-revocation",
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
        with_child=True,
    )
    assert child is not None
    denied = _linked_denied_revocation_receipt(
        authorizer=signed_root_grant,
        target=child,
        sequence=3,
        previous_receipt=receipts[-1],
        signed_work_order=signed_work_order,
        sidecar_receipt_factory=sidecar_receipt_factory,
        role_keys=ephemeral_role_keys,
        label="denied-revocation",
    )

    replay = evidence._validate_grant_history_semantics(
        signed_work_order,
        (*receipts, denied),
        grants,
        attempts,
    )

    assert replay[child.grant_id].revoked is False
    assert replay[signed_root_grant.grant_id].use_count == 1


def test_denied_tool_on_revoked_grant_is_free_but_authentic(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    ledger_path, child, _, _, _ = _grant_replay_context(
        tmp_path=tmp_path,
        label="denied-on-revoked",
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
        with_child=True,
        child_updates={
            "usage_mode": "single_use",
            "quota": {"tool_calls": 1, "repair_rounds": 0},
        },
    )
    assert child is not None
    _revoke_child(
        ledger_path,
        signed_root_grant,
        child,
        _revocation_request(
            signed_work_order,
            signed_root_grant,
            child,
            ephemeral_role_keys,
            actor_role="Manager",
            nonce=_grant_id("denied-on-revoked:revoke"),
        ),
        ephemeral_role_keys,
        fixed_now,
    )
    receipts, grants, attempts = _grant_replay_inputs(
        ledger_path,
        signed_work_order,
    )
    denied = _linked_tool_receipt(
        tool_name="owp.repo_read",
        state_before="running",
        state_after="running",
        sequence=4,
        previous_receipt=receipts[-1],
        root=child,
        signed_work_order=signed_work_order,
        sidecar_receipt_factory=sidecar_receipt_factory,
        role_keys=ephemeral_role_keys,
        label="denied-on-revoked:receipt",
        policy_decision="deny",
        actor_role="Developer",
    )

    replay = evidence._validate_grant_history_semantics(
        signed_work_order,
        (*receipts, denied),
        grants,
        attempts,
    )

    assert replay[child.grant_id].revoked is True
    assert replay[child.grant_id].use_count == 0


def _composition_trigger(
    *,
    initiator,
    state_version_before: int,
    sequence: int,
    signed_work_order: WorkOrder,
    sidecar_receipt_factory,
    role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    label: str,
):
    from test_contract import system_input_digest

    trigger = sidecar_receipt_factory(
        state_before="locally_verified",
        state_after="proof_ready",
        event_type="system_event",
        event_name="proof_composed",
        sequence=sequence,
        previous_receipt_digest=initiator.digest,
        parent_receipt_ids=(initiator.receipt_id,),
        occurred_at="2026-01-01T00:00:05Z",
    )
    raw = trigger.model_dump(mode="json")
    raw["receipt_id"] = _grant_id(f"{label}:receipt")
    raw["nonce"] = _grant_id(f"{label}:nonce")
    cause = copy.deepcopy(raw["cause"])
    cause.update(
        {
            "initiator_receipt_digest": initiator.digest,
            "state_version_before": state_version_before,
        }
    )
    input_digest = system_input_digest(
        "proof_composed",
        signed_work_order.digest,
        cause,
    )
    raw["cause"] = cause
    raw["input_digest"] = input_digest
    raw["nested_claim"]["cause"] = cause
    raw["nested_claim"]["input_digest"] = input_digest
    raw["nested_claim_digest"] = input_digest
    return evidence.ACTION_RECEIPT_ADAPTER.validate_python(
        sign_payload(
            "action-receipt",
            raw,
            role_keys["Sidecar"][0],
        )
    )


def _append_action_receipt(
    connection: sqlite3.Connection,
    receipt,
) -> None:
    connection.execute(
        """
        INSERT INTO receipts (
            receipt_id,
            work_order_digest,
            nonce,
            sequence,
            previous_digest,
            receipt_json
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            receipt.receipt_id,
            receipt.work_order_digest,
            receipt.nonce,
            receipt.sequence,
            receipt.previous_receipt_digest,
            _canonical_json(receipt.model_dump(mode="json")),
        ),
    )
    for parent_id in receipt.parent_receipt_ids:
        connection.execute(
            """
            INSERT INTO receipt_parents (
                child_receipt_id,
                parent_receipt_id
            )
            VALUES (?, ?)
            """,
            (receipt.receipt_id, parent_id),
        )
    if receipt.quota_charge is not None:
        charge = receipt.quota_charge
        connection.execute(
            """
            INSERT INTO grant_events (
                event_id,
                receipt_id,
                grant_id,
                event_type,
                metric,
                amount
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                _grant_id(f"grant-event:{receipt.receipt_id}"),
                receipt.receipt_id,
                charge.grant_id,
                receipt.event_type,
                charge.metric,
                charge.amount,
            ),
        )


def _retry_request(
    work_order: WorkOrder,
    root: CapabilityGrant,
    role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    *,
    nonce: str,
    actor_role: str = "Manager",
    requested_at: str = "2026-01-01T00:00:05Z",
    tool_name: str = "owp.start_retry",
    arguments: dict[str, object] | None = None,
    grant_id: str | None = None,
) -> AgentRequest:
    binding = role_keys[actor_role][1]
    effective_grant_id = root.grant_id if grant_id is None else grant_id
    exact_arguments = arguments or {
        "grant_id": effective_grant_id,
        "metric": "repair_rounds",
        "amount": 1,
    }
    return AgentRequest.model_validate(
        sign_payload(
            "agent-request",
            {
                "claim_type": "agent-request",
                "work_order_digest": work_order.digest,
                "grant_id": effective_grant_id,
                "actor_id": binding["subject_id"],
                "actor_key_id": binding["key_id"],
                "tool_name": tool_name,
                "arguments_digest": evidence.request_arguments_digest(
                    tool_name,
                    exact_arguments,
                ),
                "nonce": nonce,
                "requested_at": requested_at,
                "authentication_method": "agent_signature",
                "model_id": "model",
                "model_version": "1",
                "prompt_template_digest": "a" * 64,
                "context_source_digest": "b" * 64,
            },
            role_keys[actor_role][0],
        )
    )


def _retry_episode(
    *,
    tmp_path: Path,
    label: str,
    work_order: WorkOrder,
    root: CapabilityGrant,
    role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    now: datetime,
    sidecar_receipt_factory,
    failure_test_passed: bool = False,
):
    from test_state import _tool_receipt

    ledger_path = tmp_path / f"{label}.sqlite3"
    evidence_root = tmp_path / f"{label}-evidence"
    evidence_root.mkdir()
    _activate_ledger_root(
        ledger_path,
        work_order,
        root,
        role_keys,
        now,
    )
    developer = _child_grant(
        work_order,
        root,
        role_keys,
        label=f"{label}:developer",
        updates={
            "allowed_tools": [
                "owp.apply_patch",
                "owp.rollback_patch",
            ],
            "quota": {"tool_calls": 4, "repair_rounds": 0},
        },
    )
    verifier = _child_grant(
        work_order,
        root,
        role_keys,
        label=f"{label}:verifier",
        subject_role="Verifier",
        updates={"quota": {"tool_calls": 2, "repair_rounds": 0}},
    )
    developer_issuance = _issue_child(
        ledger_path,
        developer,
        _delegation_request(
            work_order,
            root,
            developer,
            role_keys,
            actor_role="Manager",
            nonce=_grant_id(f"{label}:developer-request"),
        ),
        role_keys,
        now,
    )
    verifier_issuance = _issue_child(
        ledger_path,
        verifier,
        _delegation_request(
            work_order,
            root,
            verifier,
            role_keys,
            actor_role="Manager",
            nonce=_grant_id(f"{label}:verifier-request"),
        ),
        role_keys,
        now,
    )
    receipts, _, _ = _grant_replay_inputs(ledger_path, work_order)
    root_issuance = receipts[0]

    patch_bytes = b"0123456789"
    patch_digest = hashlib.sha256(patch_bytes).hexdigest()
    patch_result = {
        "schema_version": "openworkproof-patch-result/0.1",
        "parent_commit": work_order.source_commit,
        "parent_manifest_digest": "b" * 64,
        "candidate_commit": "2" * 40,
        "workspace_manifest_digest": "c" * 64,
        "patch_digest": patch_digest,
        "patch_size_bytes": len(patch_bytes),
        "replay_profile_digest": work_order.replay_profile_digest,
    }
    result_bytes = rfc8785.dumps(patch_result)
    result_digest = hashlib.sha256(result_bytes).hexdigest()
    result_path = "evidence/patch-result/01.json"
    final_path = evidence_root / "patch-result/01.json"
    final_path.parent.mkdir()
    final_path.write_bytes(result_bytes)

    patch = _tool_receipt(
        tool_name="owp.apply_patch",
        actor_role="Developer",
        signed_work_order=work_order,
        sidecar_receipt_factory=sidecar_receipt_factory,
        ephemeral_role_keys=role_keys,
    )
    patch_raw = patch.model_dump(mode="json")
    patch_arguments = {
        "target_paths": ["src/x"],
        "patch_digest": patch_digest,
        "patch_size_bytes": len(patch_bytes),
    }
    patch_raw.update(
        {
            "receipt_id": _grant_id(f"{label}:patch-receipt"),
            "grant_id": developer.grant_id,
            "request_arguments": patch_arguments,
            "arguments_digest": evidence.request_arguments_digest(
                "owp.apply_patch",
                patch_arguments,
            ),
            "output_digest": result_digest,
            "state_before": "running",
            "state_after": "running",
            "parent_receipt_ids": [developer_issuance.receipt_id],
            "sequence": 4,
            "nonce": _grant_id(f"{label}:patch-nonce"),
            "previous_receipt_digest": verifier_issuance.digest,
            "occurred_at": "2026-01-01T00:00:05Z",
            "evidence_refs": [
                {
                    "path": "evidence/patch-input/01.diff",
                    "sha256": patch_digest,
                    "media_type": "text/x-diff",
                    "size_bytes": len(patch_bytes),
                },
                {
                    "path": result_path,
                    "sha256": result_digest,
                    "media_type": "application/json",
                    "size_bytes": len(result_bytes),
                },
            ],
            "quota_charge": {
                "grant_id": developer.grant_id,
                "metric": "tool_calls",
                "amount": 1,
                "remaining_after": 3,
            },
        }
    )
    patch_claim = patch_raw["nested_claim"]
    patch_claim.update(
        {
            "grant_id": developer.grant_id,
            "arguments_digest": patch_raw["arguments_digest"],
            "nonce": patch_raw["nonce"],
            "requested_at": "2026-01-01T00:00:05Z",
        }
    )
    patch_claim = sign_payload(
        "agent-request",
        patch_claim,
        role_keys["Developer"][0],
    )
    patch_raw["nested_claim"] = patch_claim
    patch_raw["nested_claim_digest"] = patch_claim["digest"]
    patch = evidence.ACTION_RECEIPT_ADAPTER.validate_python(
        sign_payload(
            "action-receipt",
            patch_raw,
            role_keys["Sidecar"][0],
        )
    )

    failure = sidecar_receipt_factory(
        state_before="running",
        state_after="needs_rework",
        event_type="tool_call",
        actor_role="Verifier",
        sequence=5,
        previous_receipt_digest=patch.digest,
        parent_receipt_ids=(
            verifier_issuance.receipt_id,
            patch.receipt_id,
        ),
        occurred_at="2026-01-01T00:00:05Z",
        test_passed=failure_test_passed,
    )
    failure_raw = failure.model_dump(mode="json")
    failure_arguments = failure_raw["request_arguments"]
    failure_arguments["candidate_commit"] = patch_result[
        "candidate_commit"
    ]
    failure_arguments["workspace_manifest_digest"] = patch_result[
        "workspace_manifest_digest"
    ]
    failure_raw.update(
        {
            "receipt_id": _grant_id(f"{label}:failure-receipt"),
            "grant_id": verifier.grant_id,
            "arguments_digest": evidence.request_arguments_digest(
                "owp.run_tests",
                failure_arguments,
            ),
            "nonce": _grant_id(f"{label}:failure-nonce"),
            "quota_charge": {
                "grant_id": verifier.grant_id,
                "metric": "tool_calls",
                "amount": 1,
                "remaining_after": 1,
            },
        }
    )
    failure_claim = failure_raw["nested_claim"]
    failure_claim.update(
        {
            "grant_id": verifier.grant_id,
            "arguments_digest": failure_raw["arguments_digest"],
            "nonce": failure_raw["nonce"],
            "requested_at": "2026-01-01T00:00:05Z",
        }
    )
    failure_claim = sign_payload(
        "agent-request",
        failure_claim,
        role_keys["Verifier"][0],
    )
    failure_raw["nested_claim"] = failure_claim
    failure_raw["nested_claim_digest"] = failure_claim["digest"]
    failure = evidence.ACTION_RECEIPT_ADAPTER.validate_python(
        sign_payload(
            "action-receipt",
            failure_raw,
            role_keys["Sidecar"][0],
        )
    )

    rollback = sidecar_receipt_factory(
        state_before="needs_rework",
        state_after="needs_rework",
        event_type="rollback",
        actor_role="Developer",
        sequence=6,
        previous_receipt_digest=failure.digest,
        parent_receipt_ids=(
            developer_issuance.receipt_id,
            patch.receipt_id,
            failure.receipt_id,
        ),
        occurred_at="2026-01-01T00:00:05Z",
    )
    rollback_raw = rollback.model_dump(mode="json")
    rollback_arguments = {
        "target_patch_receipt_id": patch.receipt_id,
        "target_patch_digest": patch.digest,
        "before_commit": patch_result["candidate_commit"],
    }
    rollback_raw.update(
        {
            "receipt_id": _grant_id(f"{label}:rollback-receipt"),
            "grant_id": developer.grant_id,
            "target_patch_receipt_id": patch.receipt_id,
            "target_patch_digest": patch.digest,
            "before_commit": patch_result["candidate_commit"],
            "after_commit": patch_result["parent_commit"],
            "after_manifest_digest": patch_result[
                "parent_manifest_digest"
            ],
            "nonce": _grant_id(f"{label}:rollback-nonce"),
            "quota_charge": {
                "grant_id": developer.grant_id,
                "metric": "tool_calls",
                "amount": 1,
                "remaining_after": 2,
            },
        }
    )
    rollback_claim = rollback_raw["nested_claim"]
    rollback_claim.update(
        {
            "grant_id": developer.grant_id,
            "arguments_digest": evidence.request_arguments_digest(
                "owp.rollback_patch",
                rollback_arguments,
            ),
            "nonce": rollback_raw["nonce"],
            "requested_at": "2026-01-01T00:00:05Z",
        }
    )
    rollback_claim = sign_payload(
        "agent-request",
        rollback_claim,
        role_keys["Developer"][0],
    )
    rollback_raw["nested_claim"] = rollback_claim
    rollback_raw["nested_claim_digest"] = rollback_claim["digest"]
    rollback = evidence.ACTION_RECEIPT_ADAPTER.validate_python(
        sign_payload(
            "action-receipt",
            rollback_raw,
            role_keys["Sidecar"][0],
        )
    )

    connection = connect_ledger(ledger_path)
    try:
        for receipt in (patch, failure, rollback):
            _append_action_receipt(connection, receipt)
        connection.execute(
            "UPDATE sequence_counter SET next_sequence = 7"
        )
        connection.execute(
            """
            UPDATE work_order_state
            SET current_state = 'needs_rework', version = 6
            """
        )
        connection.execute(
            """
            INSERT INTO evidence_publications (
                publication_id,
                receipt_id,
                pending_path,
                final_path,
                digest,
                media_type,
                size_bytes,
                state
            )
            VALUES (?, ?, ?, ?, ?, 'application/json', ?, 'COMMITTED')
            """,
            (
                _grant_id(f"{label}:publication"),
                patch.receipt_id,
                f".pending/{_grant_id(f'{label}:publication')}",
                result_path,
                result_digest,
                len(result_bytes),
            ),
        )
    finally:
        connection.close()
    return {
        "ledger_path": ledger_path,
        "evidence_root": evidence_root,
        "final_path": final_path,
        "root_issuance": root_issuance,
        "developer_issuance": developer_issuance,
        "verifier_issuance": verifier_issuance,
        "developer": developer,
        "verifier": verifier,
        "patch": patch,
        "failure": failure,
        "rollback": rollback,
        "patch_result": patch_result,
        "result_path": result_path,
    }


def _move_retry_patch_result_ref(
    episode,
    *,
    new_path: str,
    role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
) -> None:
    new_final = episode["evidence_root"] / new_path.removeprefix(
        "evidence/"
    )
    new_final.parent.mkdir(parents=True, exist_ok=True)
    new_final.write_bytes(episode["final_path"].read_bytes())

    patch_raw = episode["patch"].model_dump(mode="json")
    patch_raw["evidence_refs"][1]["path"] = new_path
    patch = evidence.ACTION_RECEIPT_ADAPTER.validate_python(
        sign_payload(
            "action-receipt",
            patch_raw,
            role_keys["Sidecar"][0],
        )
    )
    failure_raw = episode["failure"].model_dump(mode="json")
    failure_raw["previous_receipt_digest"] = patch.digest
    failure = evidence.ACTION_RECEIPT_ADAPTER.validate_python(
        sign_payload(
            "action-receipt",
            failure_raw,
            role_keys["Sidecar"][0],
        )
    )
    rollback_raw = episode["rollback"].model_dump(mode="json")
    rollback_raw["previous_receipt_digest"] = failure.digest
    rollback_raw["target_patch_digest"] = patch.digest
    rollback_arguments = {
        "target_patch_receipt_id": patch.receipt_id,
        "target_patch_digest": patch.digest,
        "before_commit": rollback_raw["before_commit"],
    }
    rollback_claim = rollback_raw["nested_claim"]
    rollback_claim["arguments_digest"] = evidence.request_arguments_digest(
        "owp.rollback_patch",
        rollback_arguments,
    )
    rollback_claim = sign_payload(
        "agent-request",
        rollback_claim,
        role_keys["Developer"][0],
    )
    rollback_raw["nested_claim"] = rollback_claim
    rollback_raw["nested_claim_digest"] = rollback_claim["digest"]
    rollback = evidence.ACTION_RECEIPT_ADAPTER.validate_python(
        sign_payload(
            "action-receipt",
            rollback_raw,
            role_keys["Sidecar"][0],
        )
    )

    connection = connect_ledger(episode["ledger_path"])
    try:
        for receipt in (patch, failure, rollback):
            connection.execute(
                """
                UPDATE receipts
                SET previous_digest = ?, receipt_json = ?
                WHERE receipt_id = ?
                """,
                (
                    receipt.previous_receipt_digest,
                    _canonical_json(receipt.model_dump(mode="json")),
                    receipt.receipt_id,
                ),
            )
        connection.execute(
            """
            UPDATE evidence_publications
            SET final_path = ?
            WHERE receipt_id = ?
            """,
            (new_path, patch.receipt_id),
        )
    finally:
        connection.close()
    episode.update(
        {
            "patch": patch,
            "failure": failure,
            "rollback": rollback,
            "final_path": new_final,
            "result_path": new_path,
        }
    )


def _verifier_result_payload(receipt) -> bytes:
    return rfc8785.dumps(
        {
            "schema_version": "openworkproof-test-result/0.1",
            **receipt.request_arguments.model_dump(mode="json"),
            "actual_exit_code": 1,
        }
    )


def _publication_candidate(episode, sidecar_receipt_factory):
    return sidecar_receipt_factory(
        state_before=episode["rollback"].state_after,
        state_after=episode["rollback"].state_after,
        event_type="tool_call",
        actor_role="Verifier",
        sequence=episode["rollback"].sequence + 1,
        previous_receipt_digest=episode["rollback"].digest,
        parent_receipt_ids=(episode["rollback"].receipt_id,),
        occurred_at="2026-01-01T00:00:05Z",
        test_passed=False,
    )


def _two_publication_candidate(episode, role_keys):
    patch_bytes = b"0123456789"
    result_bytes = rfc8785.dumps(episode["patch_result"])
    connection = connect_ledger(episode["ledger_path"])
    try:
        connection.execute(
            "DELETE FROM evidence_publications WHERE receipt_id = ?",
            (episode["patch"].receipt_id,),
        )
    finally:
        connection.close()
    episode["final_path"].unlink()

    raw = episode["patch"].model_dump(mode="json")
    nonce = _grant_id(
        f"publication-candidate:{episode['patch'].receipt_id}:nonce"
    )
    raw.update(
        {
            "receipt_id": _grant_id(
                f"publication-candidate:{episode['patch'].receipt_id}"
            ),
            "state_before": episode["rollback"].state_after,
            "state_after": episode["rollback"].state_after,
            "parent_receipt_ids": [episode["rollback"].receipt_id],
            "sequence": episode["rollback"].sequence + 1,
            "nonce": nonce,
            "previous_receipt_digest": episode["rollback"].digest,
            "occurred_at": "2026-01-01T00:00:05Z",
        }
    )
    claim = raw["nested_claim"]
    claim["nonce"] = nonce
    claim["requested_at"] = "2026-01-01T00:00:05Z"
    claim = sign_payload("agent-request", claim, role_keys["Developer"][0])
    raw["nested_claim"] = claim
    raw["nested_claim_digest"] = claim["digest"]
    receipt = evidence.ACTION_RECEIPT_ADAPTER.validate_python(
        sign_payload(
            "action-receipt",
            raw,
            role_keys["Sidecar"][0],
        )
    )
    return receipt, {
        receipt.evidence_refs[0].path: patch_bytes,
        receipt.evidence_refs[1].path: result_bytes,
    }


def _bounded_publication_candidate(
    episode,
    work_order: WorkOrder,
    role_keys,
    sidecar_receipt_factory,
    *,
    count: int,
):
    connection = connect_ledger(episode["ledger_path"])
    try:
        connection.execute(
            "DELETE FROM evidence_publications WHERE receipt_id = ?",
            (episode["patch"].receipt_id,),
        )
    finally:
        connection.close()
    episode["final_path"].unlink(missing_ok=True)
    receipt = sidecar_receipt_factory(
        state_before=episode["rollback"].state_after,
        state_after="frozen",
        event_type="system_event",
        event_name="contract_expired",
        sequence=episode["rollback"].sequence + 1,
        previous_receipt_digest=episode["rollback"].digest,
        parent_receipt_ids=(episode["rollback"].receipt_id,),
        occurred_at="2026-01-02T00:00:01Z",
    )
    payloads = {}
    refs = []
    for artifact in work_order.evidence_policy.artifacts[:count]:
        final_path = f"evidence/{artifact.path}"
        payload = (
            f"diff:{artifact.path}".encode("ascii")
            if artifact.media_type == "text/x-diff"
            else rfc8785.dumps({"artifact": artifact.path})
        )
        payloads[final_path] = payload
        refs.append(
            {
                "path": final_path,
                "sha256": hashlib.sha256(payload).hexdigest(),
                "media_type": artifact.media_type,
                "size_bytes": len(payload),
            }
        )
    raw = receipt.model_dump(mode="json")
    raw["evidence_refs"] = sorted(
        refs,
        key=lambda item: item["path"].encode("utf-8"),
    )
    receipt = evidence.ACTION_RECEIPT_ADAPTER.validate_python(
        sign_payload(
            "action-receipt",
            raw,
            role_keys["Sidecar"][0],
        )
    )
    return receipt, payloads


def _ledger_publication_snapshot(ledger_path: Path) -> tuple:
    connection = connect_ledger(ledger_path)
    try:
        return (
            tuple(connection.execute("SELECT * FROM receipts ORDER BY sequence")),
            tuple(
                connection.execute(
                    "SELECT * FROM receipt_parents "
                    "ORDER BY child_receipt_id, parent_receipt_id"
                )
            ),
            tuple(
                connection.execute(
                    "SELECT * FROM evidence_publications ORDER BY publication_id"
                )
            ),
            tuple(connection.execute("SELECT * FROM sequence_counter")),
            tuple(connection.execute("SELECT * FROM work_order_state")),
        )
    finally:
        connection.close()


def _receipt_publication_protocol_snapshot(ledger_path: Path) -> tuple:
    connection = connect_ledger(ledger_path)
    try:
        return (
            tuple(connection.execute("SELECT * FROM receipts ORDER BY sequence")),
            tuple(
                connection.execute(
                    "SELECT * FROM receipt_parents "
                    "ORDER BY child_receipt_id, parent_receipt_id"
                )
            ),
            tuple(
                connection.execute(
                    "SELECT * FROM grant_events "
                    "ORDER BY receipt_id, event_type, metric"
                )
            ),
            tuple(connection.execute("SELECT * FROM sequence_counter")),
            tuple(connection.execute("SELECT * FROM work_order_state")),
        )
    finally:
        connection.close()


def _commit_publication_candidate_for_test(
    ledger_path: Path,
    receipt,
    group,
) -> None:
    connection = connect_ledger(ledger_path)
    try:
        connection.execute("BEGIN IMMEDIATE")
        _append_action_receipt(connection, receipt)
        for publication in group.publications:
            connection.execute(
                """
                INSERT INTO evidence_publications (
                    publication_id, receipt_id, pending_path, final_path,
                    digest, size_bytes, media_type, state
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, 'COMMITTING')
                """,
                (
                    publication.publication_id,
                    receipt.receipt_id,
                    publication.pending_path,
                    publication.final_path,
                    publication.digest,
                    publication.size_bytes,
                    publication.media_type,
                ),
            )
        connection.execute(
            "UPDATE sequence_counter SET next_sequence = ?",
            (receipt.sequence + 1,),
        )
        connection.execute(
            """
            UPDATE work_order_state
            SET current_state = ?, version = ?
            """,
            (receipt.state_after, receipt.sequence),
        )
        connection.execute("COMMIT")
    except Exception:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    finally:
        connection.close()


def _staged_retrying_verifier_candidate(
    *,
    tmp_path: Path,
    work_order: WorkOrder,
    root: CapabilityGrant,
    role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
    label: str,
):
    ledger_path = tmp_path / f"{label}.sqlite3"
    evidence_root = tmp_path / f"{label}-evidence"
    evidence_root.mkdir()
    _activate_ledger_root(
        ledger_path,
        work_order,
        root,
        role_keys,
        fixed_now,
    )
    verifier = _child_grant(
        work_order,
        root,
        role_keys,
        label=f"{label}:verifier",
        subject_role="Verifier",
        updates={"quota": {"tool_calls": 1, "repair_rounds": 0}},
    )
    verifier_issuance = _issue_child(
        ledger_path,
        verifier,
        _delegation_request(
            work_order,
            root,
            verifier,
            role_keys,
            actor_role="Manager",
            nonce=_grant_id(f"{label}:verifier-request"),
        ),
        role_keys,
        fixed_now,
    )
    receipt = sidecar_receipt_factory(
        state_before="running",
        state_after="needs_rework",
        event_type="tool_call",
        actor_role="Verifier",
        sequence=verifier_issuance.sequence + 1,
        previous_receipt_digest=verifier_issuance.digest,
        parent_receipt_ids=(verifier_issuance.receipt_id,),
        occurred_at="2026-01-01T00:00:05Z",
        test_passed=False,
    )
    raw = receipt.model_dump(mode="json")
    raw.update(
        {
            "receipt_id": _grant_id(f"{label}:receipt"),
            "grant_id": verifier.grant_id,
            "nonce": _grant_id(f"{label}:nonce"),
            "quota_charge": {
                "grant_id": verifier.grant_id,
                "metric": "tool_calls",
                "amount": 1,
                "remaining_after": 0,
            },
        }
    )
    for result in raw["predicate_results"]:
        if result["name"] == "quota_remaining":
            result["input"].update(
                {
                    "grant_id": verifier.grant_id,
                    "grant_remaining_before": 1,
                    "ledger_prefix_digest": verifier_issuance.digest,
                }
            )
        elif result["name"] == "tests_passed":
            expected_payload = rfc8785.dumps(
                {
                    "schema_version": "openworkproof-test-result/0.1",
                    **raw["request_arguments"],
                    "actual_exit_code": 1,
                }
            )
            result["input"]["test_evidence_digest"] = hashlib.sha256(
                expected_payload
            ).hexdigest()
        else:
            continue
        result["input_digest"] = _jcs_digest(
            {
                "domain": "openworkproof/predicate-input/v0.1",
                "predicate_id": result["predicate_id"],
                "input": result["input"],
            }
        )
    claim = raw["nested_claim"]
    claim.update(
        {
            "grant_id": verifier.grant_id,
            "nonce": raw["nonce"],
            "requested_at": "2026-01-01T00:00:05Z",
        }
    )
    claim = sign_payload("agent-request", claim, role_keys["Verifier"][0])
    raw["nested_claim"] = claim
    raw["nested_claim_digest"] = claim["digest"]
    receipt = evidence.ACTION_RECEIPT_ADAPTER.validate_python(
        sign_payload("action-receipt", raw, role_keys["Sidecar"][0])
    )
    payload = _verifier_result_payload(receipt)
    reference = receipt.evidence_refs[0]
    assert hashlib.sha256(payload).hexdigest() == reference.sha256
    group = evidence.stage_pending_evidence_group(
        ledger_path,
        evidence_root=evidence_root,
        receipt=receipt,
        payloads={reference.path: payload},
    )
    return (
        {
            "ledger_path": ledger_path,
            "evidence_root": evidence_root,
            "verifier": verifier,
            "verifier_issuance": verifier_issuance,
        },
        receipt,
        group,
        payload,
    )


def _staged_running_patch_candidate(
    *,
    tmp_path: Path,
    work_order: WorkOrder,
    root: CapabilityGrant,
    role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
    label: str,
    execution_status: str = "succeeded",
):
    from test_state import _tool_receipt

    work_order_raw = work_order.model_dump(mode="json")
    for spec in work_order_raw["preconditions"]:
        if spec["name"] != "tool_allowed":
            continue
        spec["arguments"]["tool_name"] = "owp.apply_patch"
        spec["predicate_id"] = _jcs_digest(
            {
                "domain": "openworkproof/predicate-id/v0.1",
                "name": spec["name"],
                "version": spec["version"],
                "applies_to_tools": spec["applies_to_tools"],
                "arguments": spec["arguments"],
            }
        )
    work_order_raw["preconditions"].sort(
        key=lambda item: item["predicate_id"]
    )
    work_order = WorkOrder.model_validate(
        sign_payload(
            "work-order",
            work_order_raw,
            role_keys["Maintainer"][0],
        )
    )
    root_raw = root.model_dump(mode="json")
    root_raw["work_order_digest"] = work_order.digest
    root = CapabilityGrant.model_validate(
        sign_payload(
            "capability-grant",
            root_raw,
            role_keys["Maintainer"][0],
        )
    )
    ledger_path = tmp_path / f"{label}.sqlite3"
    evidence_root = tmp_path / f"{label}-evidence"
    evidence_root.mkdir()
    _activate_ledger_root(
        ledger_path,
        work_order,
        root,
        role_keys,
        fixed_now,
    )
    developer = _child_grant(
        work_order,
        root,
        role_keys,
        label=f"{label}:developer",
        updates={
            "allowed_tools": ["owp.apply_patch"],
            "quota": {"tool_calls": 1, "repair_rounds": 0},
        },
    )
    issuance = _issue_child(
        ledger_path,
        developer,
        _delegation_request(
            work_order,
            root,
            developer,
            role_keys,
            actor_role="Manager",
            nonce=_grant_id(f"{label}:developer-request"),
        ),
        role_keys,
        fixed_now,
    )
    patch_bytes = b"0123456789"
    patch_digest = hashlib.sha256(patch_bytes).hexdigest()
    result = {
        "schema_version": "openworkproof-patch-result/0.1",
        "parent_commit": work_order.source_commit,
        "parent_manifest_digest": "b" * 64,
        "candidate_commit": "2" * 40,
        "workspace_manifest_digest": "c" * 64,
        "patch_digest": patch_digest,
        "patch_size_bytes": len(patch_bytes),
        "replay_profile_digest": work_order.replay_profile_digest,
    }
    result_bytes = rfc8785.dumps(result)
    result_digest = hashlib.sha256(result_bytes).hexdigest()
    receipt = _tool_receipt(
        tool_name="owp.apply_patch",
        actor_role="Developer",
        signed_work_order=work_order,
        sidecar_receipt_factory=sidecar_receipt_factory,
        ephemeral_role_keys=role_keys,
    )
    raw = receipt.model_dump(mode="json")
    arguments = {
        "target_paths": ["src/x"],
        "patch_digest": patch_digest,
        "patch_size_bytes": len(patch_bytes),
    }
    trusted_resolution_manifest = ResolutionManifest(
        schema_version="openworkproof-resolution-manifest/0.1",
        workspace_manifest_digest=result["parent_manifest_digest"],
        requested_paths=tuple(arguments["target_paths"]),
        resolved_entries=tuple(
            ResolutionManifestEntry(
                requested_path=path,
                resolved_relative_path=path,
            )
            for path in arguments["target_paths"]
        ),
    )
    expected_resolution_manifest_digest = resolution_manifest_digest(
        trusted_resolution_manifest
    )
    raw.update(
        {
            "work_order_digest": work_order.digest,
            "receipt_id": _grant_id(f"{label}:receipt"),
            "grant_id": developer.grant_id,
            "request_arguments": arguments,
            "arguments_digest": evidence.request_arguments_digest(
                "owp.apply_patch",
                arguments,
            ),
            "execution_status": execution_status,
            "execution_error_code": (
                "HANDLER_ERROR"
                if execution_status == "failed"
                else None
            ),
            "output_digest": (
                _jcs_digest(
                    {
                        "status": "failed",
                        "error_code": "HANDLER_ERROR",
                    }
                )
                if execution_status == "failed"
                else result_digest
            ),
            "state_before": "running",
            "state_after": "running",
            "parent_receipt_ids": [issuance.receipt_id],
            "sequence": issuance.sequence + 1,
            "nonce": _grant_id(f"{label}:nonce"),
            "previous_receipt_digest": issuance.digest,
            "occurred_at": "2026-01-01T00:00:05Z",
            "evidence_refs": [
                {
                    "path": "evidence/patch-input/01.diff",
                    "sha256": patch_digest,
                    "media_type": "text/x-diff",
                    "size_bytes": len(patch_bytes),
                },
                {
                    "path": "evidence/patch-result/01.json",
                    "sha256": result_digest,
                    "media_type": "application/json",
                    "size_bytes": len(result_bytes),
                },
            ][: 1 if execution_status == "failed" else 2],
            "quota_charge": {
                "grant_id": developer.grant_id,
                "metric": "tool_calls",
                "amount": 1,
                "remaining_after": 0,
            },
        }
    )
    for predicate in raw["predicate_results"]:
        if predicate["name"] == "path_allowed":
            predicate["input"]["resolution_manifest_digest"] = (
                expected_resolution_manifest_digest
            )
            predicate["input_digest"] = _jcs_digest(
                {
                    "domain": "openworkproof/predicate-input/v0.1",
                    "predicate_id": predicate["predicate_id"],
                    "input": predicate["input"],
                }
            )
            continue
        if predicate["name"] != "quota_remaining":
            continue
        predicate["input"].update(
            {
                "grant_id": developer.grant_id,
                "grant_remaining_before": 1,
                "ledger_prefix_digest": issuance.digest,
            }
        )
        predicate["input_digest"] = _jcs_digest(
            {
                "domain": "openworkproof/predicate-input/v0.1",
                "predicate_id": predicate["predicate_id"],
                "input": predicate["input"],
            }
        )
    claim = raw["nested_claim"]
    claim.update(
        {
            "work_order_digest": work_order.digest,
            "grant_id": developer.grant_id,
            "arguments_digest": raw["arguments_digest"],
            "nonce": raw["nonce"],
            "requested_at": "2026-01-01T00:00:05Z",
        }
    )
    claim = sign_payload(
        "agent-request",
        claim,
        role_keys["Developer"][0],
    )
    raw["nested_claim"] = claim
    raw["nested_claim_digest"] = claim["digest"]
    receipt = evidence.ACTION_RECEIPT_ADAPTER.validate_python(
        sign_payload(
            "action-receipt",
            raw,
            role_keys["Sidecar"][0],
        )
    )
    payloads = {
        receipt.evidence_refs[0].path: patch_bytes,
    }
    if execution_status == "succeeded":
        payloads[receipt.evidence_refs[1].path] = result_bytes
    group = evidence.stage_pending_evidence_group(
        ledger_path,
        evidence_root=evidence_root,
        receipt=receipt,
        payloads=payloads,
    )
    return {
        "ledger_path": ledger_path,
        "evidence_root": evidence_root,
        "developer": developer,
        "issuance": issuance,
        "trusted_resolution_manifest": trusted_resolution_manifest,
    }, receipt, group, payloads


def test_commit_receipt_with_publications_atomically_journals_signed_receipt(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    episode, receipt, group, payload = (
        _staged_retrying_verifier_candidate(
        tmp_path=tmp_path,
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        fixed_now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
        label="publication-commit-success",
        )
    )

    evidence.commit_receipt_with_publications(
        episode["ledger_path"],
        evidence_root=episode["evidence_root"],
        receipt=receipt,
        group=group,
        clock=lambda: fixed_now,
    )

    connection = connect_ledger(episode["ledger_path"])
    try:
        assert evidence._validated_receipt_prefix(
            connection,
            signed_work_order,
        )[-1] == receipt
        assert tuple(
            connection.execute(
                """
                SELECT parent_receipt_id
                FROM receipt_parents
                WHERE child_receipt_id = ?
                ORDER BY parent_receipt_id
                """,
                (receipt.receipt_id,),
            )
        ) == tuple((item,) for item in sorted(receipt.parent_receipt_ids))
        assert connection.execute(
            """
            SELECT grant_id, event_type, metric, amount
            FROM grant_events
            WHERE receipt_id = ?
            """,
            (receipt.receipt_id,),
        ).fetchone() == (
            episode["verifier"].grant_id,
            "tool_call",
            "tool_calls",
            1,
        )
        assert connection.execute(
            """
            SELECT publication_id, receipt_id, pending_path, final_path,
                   digest, size_bytes, media_type, state
            FROM evidence_publications
            WHERE receipt_id = ?
            """,
            (receipt.receipt_id,),
        ).fetchone() == (
            group.publications[0].publication_id,
            receipt.receipt_id,
            group.publications[0].pending_path,
            group.publications[0].final_path,
            hashlib.sha256(payload).hexdigest(),
            len(payload),
            "application/json",
            "COMMITTING",
        )
        assert connection.execute(
            "SELECT current_state, version FROM work_order_state"
        ).fetchone() == ("needs_rework", receipt.sequence)
        assert connection.execute(
            "SELECT next_sequence FROM sequence_counter"
        ).fetchone() == (receipt.sequence + 1,)
    finally:
        connection.close()
    pending = episode["evidence_root"] / group.publications[0].pending_path
    final = episode["evidence_root"] / receipt.evidence_refs[0].path.removeprefix(
        "evidence/"
    )
    assert pending.read_bytes() == payload
    assert not final.exists()


def test_receipt_publication_replays_authoritative_patch_paths(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    context, receipt, group, payloads = _staged_running_patch_candidate(
        tmp_path=tmp_path,
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        fixed_now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
        label="publication-authoritative-patch-path",
    )
    raw = receipt.model_dump(mode="json")
    raw["request_arguments"]["target_paths"] = ["private/escape"]
    raw["arguments_digest"] = evidence.request_arguments_digest(
        receipt.tool_name,
        raw["request_arguments"],
    )
    claim = raw["nested_claim"]
    claim["arguments_digest"] = raw["arguments_digest"]
    claim = sign_payload(
        "agent-request",
        claim,
        ephemeral_role_keys["Developer"][0],
    )
    raw["nested_claim"] = claim
    raw["nested_claim_digest"] = claim["digest"]
    candidate = evidence.ACTION_RECEIPT_ADAPTER.validate_python(
        sign_payload(
            "action-receipt",
            raw,
            ephemeral_role_keys["Sidecar"][0],
        )
    )
    trusted_manifest = ResolutionManifest(
        schema_version=context["trusted_resolution_manifest"].schema_version,
        workspace_manifest_digest=(
            context[
                "trusted_resolution_manifest"
            ].workspace_manifest_digest
        ),
        requested_paths=("private/escape",),
        resolved_entries=(
            ResolutionManifestEntry(
                requested_path="private/escape",
                resolved_relative_path="private/escape",
            ),
        ),
    )
    before = _ledger_publication_snapshot(context["ledger_path"])

    with pytest.raises(ValueError):
        evidence.commit_receipt_with_publications(
            context["ledger_path"],
            evidence_root=context["evidence_root"],
            receipt=candidate,
            group=group,
            clock=lambda: fixed_now,
            trusted_resolution_manifest=trusted_manifest,
        )

    assert _ledger_publication_snapshot(context["ledger_path"]) == before
    for publication in group.publications:
        pending = context["evidence_root"] / publication.pending_path
        assert pending.read_bytes() == payloads[publication.final_path]


def test_receipt_publication_accepts_authoritative_patch_predicates(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    context, receipt, group, payloads = _staged_running_patch_candidate(
        tmp_path=tmp_path,
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        fixed_now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
        label="publication-authoritative-patch-success",
    )

    evidence.commit_receipt_with_publications(
        context["ledger_path"],
        evidence_root=context["evidence_root"],
        receipt=receipt,
        group=group,
        clock=lambda: fixed_now,
        trusted_resolution_manifest=context["trusted_resolution_manifest"],
    )

    connection = connect_ledger(context["ledger_path"])
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM receipts WHERE receipt_id = ?",
            (receipt.receipt_id,),
        ).fetchone() == (1,)
        assert connection.execute(
            "SELECT COUNT(*) FROM evidence_publications WHERE receipt_id = ?",
            (receipt.receipt_id,),
        ).fetchone() == (2,)
    finally:
        connection.close()
    for publication in group.publications:
        pending = context["evidence_root"] / publication.pending_path
        assert pending.read_bytes() == payloads[publication.final_path]


def test_receipt_publication_preserves_failed_patch_semantics(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    context, receipt, group, payloads = _staged_running_patch_candidate(
        tmp_path=tmp_path,
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        fixed_now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
        label="publication-failed-patch",
        execution_status="failed",
    )

    evidence.commit_receipt_with_publications(
        context["ledger_path"],
        evidence_root=context["evidence_root"],
        receipt=receipt,
        group=group,
        clock=lambda: fixed_now,
        trusted_resolution_manifest=context["trusted_resolution_manifest"],
    )

    connection = connect_ledger(context["ledger_path"])
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM receipts WHERE receipt_id = ?",
            (receipt.receipt_id,),
        ).fetchone() == (1,)
        assert connection.execute(
            """
            SELECT grant_id, event_type, metric, amount
            FROM grant_events
            WHERE receipt_id = ?
            """,
            (receipt.receipt_id,),
        ).fetchone() == (
            context["developer"].grant_id,
            "tool_call",
            "tool_calls",
            1,
        )
        assert connection.execute(
            """
            SELECT receipt_id, state
            FROM evidence_publications
            WHERE receipt_id = ?
            """,
            (receipt.receipt_id,),
        ).fetchone() == (receipt.receipt_id, "COMMITTING")
    finally:
        connection.close()
    for publication in group.publications:
        pending = context["evidence_root"] / publication.pending_path
        final = (
            context["evidence_root"]
            / publication.final_path.removeprefix("evidence/")
        )
        assert pending.read_bytes() == payloads[publication.final_path]
        assert not final.exists()


@pytest.mark.parametrize(
    "case",
    (
        "missing",
        "missing_failed",
        "wrong_type",
        "requested_paths",
        "entry_request",
        "resolved_entry",
        "unresolved_entry",
        "workspace_manifest",
    ),
)
def test_receipt_publication_rejects_untrusted_patch_resolution_manifest(
    case: str,
    tmp_path: Path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    context, receipt, group, payloads = _staged_running_patch_candidate(
        tmp_path=tmp_path,
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        fixed_now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
        label=f"publication-untrusted-patch-manifest-{case}",
        execution_status=(
            "failed" if case == "missing_failed" else "succeeded"
        ),
    )
    trusted_manifest = context["trusted_resolution_manifest"]
    trusted_entry = trusted_manifest.resolved_entries[0]
    candidate_manifest = {
        "missing": None,
        "missing_failed": None,
        "wrong_type": object(),
        "requested_paths": replace(
            trusted_manifest,
            requested_paths=("src/y",),
            resolved_entries=(
                replace(
                    trusted_entry,
                    requested_path="src/y",
                    resolved_relative_path="src/y",
                ),
            ),
        ),
        "resolved_entry": replace(
            trusted_manifest,
            resolved_entries=(
                replace(
                    trusted_entry,
                    resolved_relative_path="src/y",
                ),
            ),
        ),
        "entry_request": replace(
            trusted_manifest,
            resolved_entries=(
                replace(
                    trusted_entry,
                    requested_path="src/y",
                    resolved_relative_path="src/y",
                ),
            ),
        ),
        "unresolved_entry": replace(
            trusted_manifest,
            resolved_entries=(
                replace(
                    trusted_entry,
                    resolved_relative_path=None,
                ),
            ),
        ),
        "workspace_manifest": replace(
            trusted_manifest,
            workspace_manifest_digest="f" * 64,
        ),
    }[case]
    before = _ledger_publication_snapshot(context["ledger_path"])

    with pytest.raises(ValueError):
        evidence.commit_receipt_with_publications(
            context["ledger_path"],
            evidence_root=context["evidence_root"],
            receipt=receipt,
            group=group,
            clock=lambda: fixed_now,
            trusted_resolution_manifest=candidate_manifest,
        )

    assert _ledger_publication_snapshot(context["ledger_path"]) == before
    for publication in group.publications:
        pending = context["evidence_root"] / publication.pending_path
        assert pending.read_bytes() == payloads[publication.final_path]


def test_receipt_publication_rejects_resolution_manifest_for_non_patch(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    context, receipt, group, payload = (
        _staged_retrying_verifier_candidate(
            tmp_path=tmp_path,
            work_order=signed_work_order,
            root=signed_root_grant,
            role_keys=ephemeral_role_keys,
            fixed_now=fixed_now,
            sidecar_receipt_factory=sidecar_receipt_factory,
            label="publication-extra-resolution-manifest",
        )
    )
    manifest = ResolutionManifest(
        schema_version="openworkproof-resolution-manifest/0.1",
        workspace_manifest_digest="b" * 64,
        requested_paths=("src/x",),
        resolved_entries=(
            ResolutionManifestEntry(
                requested_path="src/x",
                resolved_relative_path="src/x",
            ),
        ),
    )
    before = _ledger_publication_snapshot(context["ledger_path"])

    with pytest.raises(ValueError):
        evidence.commit_receipt_with_publications(
            context["ledger_path"],
            evidence_root=context["evidence_root"],
            receipt=receipt,
            group=group,
            clock=lambda: fixed_now,
            trusted_resolution_manifest=manifest,
        )

    assert _ledger_publication_snapshot(context["ledger_path"]) == before
    pending = context["evidence_root"] / group.publications[0].pending_path
    assert pending.read_bytes() == payload


@pytest.mark.parametrize(
    "tampering",
    ("resolution_manifest_digest", "resolved_entry"),
)
def test_receipt_publication_rejects_resigned_patch_path_claim(
    tampering: str,
    tmp_path: Path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    context, receipt, group, payloads = _staged_running_patch_candidate(
        tmp_path=tmp_path,
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        fixed_now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
        label=f"publication-forged-patch-{tampering}",
    )
    raw = receipt.model_dump(mode="json")
    forged_digest = "f" * 64
    for predicate in raw["predicate_results"]:
        if predicate["name"] != "path_allowed":
            continue
        if tampering == "resolution_manifest_digest":
            assert (
                predicate["input"]["resolution_manifest_digest"]
                != forged_digest
            )
            predicate["input"]["resolution_manifest_digest"] = forged_digest
        else:
            predicate["input"]["resolved_entries"][0][
                "resolved_relative_path"
            ] = "src/y"
        predicate["input_digest"] = _jcs_digest(
            {
                "domain": "openworkproof/predicate-input/v0.1",
                "predicate_id": predicate["predicate_id"],
                "input": predicate["input"],
            }
        )
    candidate = evidence.ACTION_RECEIPT_ADAPTER.validate_python(
        sign_payload(
            "action-receipt",
            raw,
            ephemeral_role_keys["Sidecar"][0],
        )
    )
    before = _ledger_publication_snapshot(context["ledger_path"])

    with pytest.raises(ValueError):
        evidence.commit_receipt_with_publications(
            context["ledger_path"],
            evidence_root=context["evidence_root"],
            receipt=candidate,
            group=group,
            clock=lambda: fixed_now,
            trusted_resolution_manifest=context[
                "trusted_resolution_manifest"
            ],
        )

    assert _ledger_publication_snapshot(context["ledger_path"]) == before
    for publication in group.publications:
        pending = context["evidence_root"] / publication.pending_path
        assert pending.read_bytes() == payloads[publication.final_path]


def test_receipt_publication_binds_pending_name_to_opened_inode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    context, receipt, group, payload = _staged_retrying_verifier_candidate(
        tmp_path=tmp_path,
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        fixed_now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
        label="publication-pending-name-inode",
    )
    pending = context["evidence_root"] / group.publications[0].pending_path
    displaced = pending.with_name(f"{pending.name}.displaced")
    real_insert = evidence._insert_receipt_and_publication_group

    def swap_pending_name(*args, **kwargs):
        pending.rename(displaced)
        pending.write_bytes(payload)
        pending.chmod(0o600)
        return real_insert(*args, **kwargs)

    monkeypatch.setattr(
        evidence,
        "_insert_receipt_and_publication_group",
        swap_pending_name,
    )
    before = _ledger_publication_snapshot(context["ledger_path"])

    with pytest.raises(Exception) as captured:
        evidence.commit_receipt_with_publications(
            context["ledger_path"],
            evidence_root=context["evidence_root"],
            receipt=receipt,
            group=group,
            clock=lambda: fixed_now,
        )

    assert not isinstance(
        captured.value,
        evidence.ReceiptPublicationCommittedError,
    )
    assert _ledger_publication_snapshot(context["ledger_path"]) == before
    assert pending.read_bytes() == payload
    assert displaced.read_bytes() == payload


def test_receipt_publication_has_final_gate_after_sqlite_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    context, receipt, group, payload = _staged_retrying_verifier_candidate(
        tmp_path=tmp_path,
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        fixed_now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
        label="publication-cleanup-final-gate",
    )
    final = (
        context["evidence_root"]
        / receipt.evidence_refs[0].path.removeprefix("evidence/")
    )
    real_connect = evidence.connect_ledger

    class FinalCreatingConnection:
        def __init__(self, raw):
            self.raw = raw
            self.created = False

        def __getattr__(self, name):
            return getattr(self.raw, name)

        def close(self):
            if not self.created:
                self.created = True
                final.parent.mkdir(parents=True, exist_ok=True)
                final.write_bytes(payload)
            return self.raw.close()

    monkeypatch.setattr(
        evidence,
        "connect_ledger",
        lambda path: FinalCreatingConnection(real_connect(path)),
    )

    with pytest.raises(
        evidence.ReceiptPublicationCommittedError
    ) as captured:
        evidence.commit_receipt_with_publications(
            context["ledger_path"],
            evidence_root=context["evidence_root"],
            receipt=receipt,
            group=group,
            clock=lambda: fixed_now,
        )

    assert captured.value.committed is True
    assert final.read_bytes() == payload


def test_receipt_publication_binds_locked_ledger_name_to_one_inode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    context, receipt, group, _ = _staged_retrying_verifier_candidate(
        tmp_path=tmp_path,
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        fixed_now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
        label="publication-ledger-name-inode",
    )
    ledger_path = context["ledger_path"]
    connection = connect_ledger(ledger_path)
    try:
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    finally:
        connection.close()
    clone_path = tmp_path / "ledger-clone.sqlite3"
    clone_path.write_bytes(ledger_path.read_bytes())
    displaced_path = tmp_path / "ledger-displaced.sqlite3"
    before = _ledger_publication_snapshot(ledger_path)
    real_connect = evidence.connect_ledger
    swapped = False

    def swap_before_connect(path: Path):
        nonlocal swapped
        if not swapped and Path(path) == ledger_path:
            swapped = True
            ledger_path.rename(displaced_path)
            clone_path.rename(ledger_path)
        return real_connect(path)

    monkeypatch.setattr(
        evidence,
        "connect_ledger",
        swap_before_connect,
    )

    with pytest.raises(Exception) as captured:
        evidence.commit_receipt_with_publications(
            ledger_path,
            evidence_root=context["evidence_root"],
            receipt=receipt,
            group=group,
            clock=lambda: fixed_now,
        )

    assert swapped
    assert not isinstance(
        captured.value,
        evidence.ReceiptPublicationCommittedError,
    )
    assert _ledger_publication_snapshot(ledger_path) == before
    assert _ledger_publication_snapshot(displaced_path) == before


def test_receipt_publication_swap_restore_cannot_report_plain_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    context, receipt, group, _ = _staged_retrying_verifier_candidate(
        tmp_path=tmp_path,
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        fixed_now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
        label="publication-ledger-swap-restore",
    )
    ledger_path = context["ledger_path"]
    connection = connect_ledger(ledger_path)
    try:
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    finally:
        connection.close()
    clone_path = tmp_path / "swap-restore-clone.sqlite3"
    clone_path.write_bytes(ledger_path.read_bytes())
    displaced_path = tmp_path / "swap-restore-displaced.sqlite3"
    before = _ledger_publication_snapshot(ledger_path)
    real_connect = evidence.connect_ledger
    swapped = False

    def bind_clone_then_restore_name(path: Path):
        nonlocal swapped
        assert Path(path) == ledger_path
        clone_connection = real_connect(clone_path)
        ledger_path.rename(displaced_path)
        clone_path.rename(ledger_path)
        ledger_path.rename(clone_path)
        displaced_path.rename(ledger_path)
        swapped = True
        return clone_connection

    monkeypatch.setattr(
        evidence,
        "connect_ledger",
        bind_clone_then_restore_name,
    )

    with pytest.raises(
        evidence.ReceiptPublicationCommitIndeterminateError
    ) as captured:
        evidence.commit_receipt_with_publications(
            ledger_path,
            evidence_root=context["evidence_root"],
            receipt=receipt,
            group=group,
            clock=lambda: fixed_now,
        )

    assert swapped
    assert captured.value.committed is None
    assert captured.value.truth == "unknown"
    assert _ledger_publication_snapshot(ledger_path) == before


@pytest.mark.parametrize(
    "fault_sql",
    (
        "INSERT INTO RECEIPTS",
        "INSERT INTO RECEIPT_PARENTS",
        "INSERT INTO GRANT_EVENTS",
        "INSERT INTO EVIDENCE_PUBLICATIONS",
        "UPDATE WORK_ORDER_STATE",
        "UPDATE SEQUENCE_COUNTER",
        "SELECT COUNT(*) FROM RECEIPTS",
    ),
)
def test_receipt_publication_precommit_faults_roll_back_every_protocol_row(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fault_sql: str,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    context, receipt, group, payload = (
        _staged_retrying_verifier_candidate(
            tmp_path=tmp_path,
            work_order=signed_work_order,
            root=signed_root_grant,
            role_keys=ephemeral_role_keys,
            fixed_now=fixed_now,
            sidecar_receipt_factory=sidecar_receipt_factory,
            label=f"publication-rollback-{fault_sql.split()[0].lower()}-"
            f"{hashlib.sha256(fault_sql.encode()).hexdigest()[:8]}",
        )
    )
    before = _ledger_publication_snapshot(context["ledger_path"])
    real_connect = evidence.connect_ledger
    wrapped: list[_FaultingConnection] = []

    def failing_connect(path: Path):
        connection = _FaultingConnection(
            real_connect(path),
            fail_when=lambda sql: fault_sql in sql,
        )
        wrapped.append(connection)
        return connection

    monkeypatch.setattr(evidence, "connect_ledger", failing_connect)
    with pytest.raises(Exception) as captured:
        evidence.commit_receipt_with_publications(
            context["ledger_path"],
            evidence_root=context["evidence_root"],
            receipt=receipt,
            group=group,
            clock=lambda: fixed_now,
        )
    assert not isinstance(
        captured.value,
        (
            evidence.ReceiptPublicationCommittedError,
            evidence.ReceiptPublicationCommitIndeterminateError,
        ),
    )
    assert wrapped and wrapped[0].closed
    monkeypatch.setattr(evidence, "connect_ledger", real_connect)
    assert _ledger_publication_snapshot(context["ledger_path"]) == before
    pending = context["evidence_root"] / group.publications[0].pending_path
    final = context["evidence_root"] / receipt.evidence_refs[0].path.removeprefix(
        "evidence/"
    )
    assert pending.read_bytes() == payload
    assert not final.exists()


@pytest.mark.parametrize("failure_ordinal", (1, 2))
def test_each_publication_journal_insert_failure_rolls_back_the_whole_group(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_ordinal: int,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    context, receipt, group, payloads = _staged_running_patch_candidate(
        tmp_path=tmp_path,
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        fixed_now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
        label=f"publication-journal-fault-{failure_ordinal}",
    )
    before = _ledger_publication_snapshot(context["ledger_path"])
    real_connect = evidence.connect_ledger

    class FailJournalOrdinal:
        def __init__(self, connection):
            self._connection = connection
            self.count = 0
            self.closed = False

        @property
        def in_transaction(self):
            return self._connection.in_transaction

        def execute(self, statement, parameters=()):
            normalized = " ".join(statement.split()).upper()
            if normalized.startswith(
                "INSERT INTO EVIDENCE_PUBLICATIONS"
            ):
                self.count += 1
                if self.count == failure_ordinal:
                    raise sqlite3.OperationalError(
                        "injected publication journal failure"
                    )
            return self._connection.execute(statement, parameters)

        def close(self):
            self.closed = True
            self._connection.close()

    wrapped: list[FailJournalOrdinal] = []

    def failing_connect(path: Path):
        connection = FailJournalOrdinal(real_connect(path))
        wrapped.append(connection)
        return connection

    monkeypatch.setattr(evidence, "connect_ledger", failing_connect)
    with pytest.raises(sqlite3.OperationalError):
        evidence.commit_receipt_with_publications(
            context["ledger_path"],
            evidence_root=context["evidence_root"],
            receipt=receipt,
            group=group,
            clock=lambda: fixed_now,
            trusted_resolution_manifest=context[
                "trusted_resolution_manifest"
            ],
        )
    monkeypatch.setattr(evidence, "connect_ledger", real_connect)
    assert wrapped[0].count == failure_ordinal
    assert wrapped[0].closed
    assert _ledger_publication_snapshot(context["ledger_path"]) == before
    for publication in group.publications:
        assert (
            context["evidence_root"] / publication.pending_path
        ).read_bytes() == payloads[publication.final_path]
        assert not (
            context["evidence_root"]
            / publication.final_path.removeprefix("evidence/")
        ).exists()


@pytest.mark.parametrize(
    "case",
    (
        "pending_bytes",
        "pending_mode",
        "pending_hardlink",
        "final_occupied",
        "group_receipt",
        "group_publication_id",
        "group_pending_path",
        "group_digest",
        "group_size",
        "group_media",
        "deny",
        "stale_sequence",
        "stale_state",
    ),
)
def test_receipt_publication_rejects_tampered_candidate_without_writes(
    tmp_path: Path,
    case: str,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    context, receipt, group, payload = (
        _staged_retrying_verifier_candidate(
            tmp_path=tmp_path,
            work_order=signed_work_order,
            root=signed_root_grant,
            role_keys=ephemeral_role_keys,
            fixed_now=fixed_now,
            sidecar_receipt_factory=sidecar_receipt_factory,
            label=f"publication-tamper-{case}",
        )
    )
    pending = context["evidence_root"] / group.publications[0].pending_path
    final = context["evidence_root"] / receipt.evidence_refs[0].path.removeprefix(
        "evidence/"
    )
    candidate_receipt = receipt
    candidate_group = group
    publication = group.publications[0]
    if case == "pending_bytes":
        pending.write_bytes(b"x" * len(payload))
    elif case == "pending_mode":
        pending.chmod(0o640)
    elif case == "pending_hardlink":
        os.link(pending, tmp_path / "pending-second-link")
    elif case == "final_occupied":
        final.parent.mkdir(parents=True, exist_ok=True)
        final.write_bytes(payload)
    elif case == "group_receipt":
        candidate_group = evidence._PublicationGroup(
            receipt_id="f" * 64,
            publications=group.publications,
        )
    elif case.startswith("group_"):
        updates = {
            "group_publication_id": {
                "publication_id": "f" * 64,
            },
            "group_pending_path": {
                "pending_path": ".pending/" + "f" * 64,
            },
            "group_digest": {"digest": "f" * 64},
            "group_size": {"size_bytes": publication.size_bytes + 1},
            "group_media": {"media_type": "text/x-diff"},
        }[case]
        candidate_group = evidence._PublicationGroup(
            receipt_id=group.receipt_id,
            publications=(
                evidence._Publication(
                    **{
                        **publication.__dict__,
                        **updates,
                    }
                ),
            ),
        )
    elif case == "deny":
        candidate_receipt = receipt.model_copy(
            update={"policy_decision": "deny"}
        )
    else:
        connection = connect_ledger(context["ledger_path"])
        try:
            if case == "stale_sequence":
                connection.execute(
                    "UPDATE sequence_counter SET next_sequence = next_sequence + 1"
                )
            else:
                connection.execute(
                    "UPDATE work_order_state SET version = version + 1"
                )
        finally:
            connection.close()
    before = _ledger_publication_snapshot(context["ledger_path"])

    with pytest.raises(Exception) as captured:
        evidence.commit_receipt_with_publications(
            context["ledger_path"],
            evidence_root=context["evidence_root"],
            receipt=candidate_receipt,
            group=candidate_group,
            clock=lambda: fixed_now,
        )
    assert not isinstance(
        captured.value,
        evidence.ReceiptPublicationCommittedError,
    )
    assert _ledger_publication_snapshot(context["ledger_path"]) == before
    if case != "final_occupied":
        assert not final.exists()
    assert pending.exists()


def _synchronize_two_publication_lock_attempts(
    monkeypatch: pytest.MonkeyPatch,
    ledger_path: Path,
):
    real_acquire = evidence._acquire_target_lock
    arrivals = threading.Barrier(2)
    both_at_lock = threading.Event()
    counter_lock = threading.Lock()
    arrival_count = 0
    acquisition_count = 0
    loser_snapshots = []

    def synchronized_acquire(path: Path):
        nonlocal arrival_count, acquisition_count
        with counter_lock:
            arrival_count += 1
            if arrival_count == 2:
                both_at_lock.set()
        arrivals.wait(timeout=5)
        descriptor = real_acquire(path)
        with counter_lock:
            acquisition_count += 1
            is_loser = acquisition_count == 2
        if is_loser:
            loser_snapshots.append(
                _ledger_publication_snapshot(ledger_path)
            )
        return descriptor

    monkeypatch.setattr(
        evidence,
        "_acquire_target_lock",
        synchronized_acquire,
    )
    return both_at_lock, loser_snapshots


def test_concurrent_exact_receipt_publication_inserts_once_and_keeps_pending(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    context, receipt, group, payload = (
        _staged_retrying_verifier_candidate(
            tmp_path=tmp_path,
            work_order=signed_work_order,
            root=signed_root_grant,
            role_keys=ephemeral_role_keys,
            fixed_now=fixed_now,
            sidecar_receipt_factory=sidecar_receipt_factory,
            label="publication-concurrent-exact",
        )
    )
    both_at_lock, loser_snapshots = (
        _synchronize_two_publication_lock_attempts(
            monkeypatch,
            context["ledger_path"],
        )
    )

    def commit():
        try:
            evidence.commit_receipt_with_publications(
                context["ledger_path"],
                evidence_root=context["evidence_root"],
                receipt=receipt,
                group=group,
                clock=lambda: fixed_now,
            )
            return None
        except Exception as error:
            return error

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = tuple(executor.map(lambda _: commit(), range(2)))

    assert both_at_lock.is_set()
    losers = tuple(error for error in outcomes if error is not None)
    assert len(losers) == 1
    assert type(losers[0]) is ValueError
    assert str(losers[0]) == (
        "an existing evidence publication requires recovery"
    )
    assert len(loser_snapshots) == 1
    assert (
        _ledger_publication_snapshot(context["ledger_path"])
        == loser_snapshots[0]
    )
    connection = connect_ledger(context["ledger_path"])
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM receipts WHERE receipt_id = ?",
            (receipt.receipt_id,),
        ).fetchone() == (1,)
        assert connection.execute(
            "SELECT COUNT(*) FROM evidence_publications WHERE receipt_id = ?",
            (receipt.receipt_id,),
        ).fetchone() == (len(group.publications),)
    finally:
        connection.close()
    assert (
        context["evidence_root"] / group.publications[0].pending_path
    ).read_bytes() == payload


def test_concurrent_distinct_candidates_on_one_tip_commit_only_one(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    context, first, first_group, payload = (
        _staged_retrying_verifier_candidate(
            tmp_path=tmp_path,
            work_order=signed_work_order,
            root=signed_root_grant,
            role_keys=ephemeral_role_keys,
            fixed_now=fixed_now,
            sidecar_receipt_factory=sidecar_receipt_factory,
            label="publication-concurrent-distinct",
        )
    )
    raw = first.model_dump(mode="json")
    raw["receipt_id"] = _grant_id(
        "publication-concurrent-distinct:second-receipt"
    )
    raw["nonce"] = _grant_id(
        "publication-concurrent-distinct:second-nonce"
    )
    claim = raw["nested_claim"]
    claim["nonce"] = raw["nonce"]
    claim = sign_payload(
        "agent-request",
        claim,
        ephemeral_role_keys["Verifier"][0],
    )
    raw["nested_claim"] = claim
    raw["nested_claim_digest"] = claim["digest"]
    second = evidence.ACTION_RECEIPT_ADAPTER.validate_python(
        sign_payload(
            "action-receipt",
            raw,
            ephemeral_role_keys["Sidecar"][0],
        )
    )
    second_group = evidence.stage_pending_evidence_group(
        context["ledger_path"],
        evidence_root=context["evidence_root"],
        receipt=second,
        payloads={second.evidence_refs[0].path: payload},
    )
    both_at_lock, loser_snapshots = (
        _synchronize_two_publication_lock_attempts(
            monkeypatch,
            context["ledger_path"],
        )
    )

    def commit(candidate):
        candidate_receipt, candidate_group = candidate
        try:
            evidence.commit_receipt_with_publications(
                context["ledger_path"],
                evidence_root=context["evidence_root"],
                receipt=candidate_receipt,
                group=candidate_group,
                clock=lambda: fixed_now,
            )
            return candidate_receipt.receipt_id, None
        except Exception as error:
            return candidate_receipt.receipt_id, error

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = tuple(
            executor.map(
                commit,
                ((first, first_group), (second, second_group)),
            )
        )

    assert both_at_lock.is_set()
    winners = tuple(
        receipt_id
        for receipt_id, error in outcomes
        if error is None
    )
    losers = tuple(
        (receipt_id, error)
        for receipt_id, error in outcomes
        if error is not None
    )
    assert len(winners) == 1
    assert len(losers) == 1
    loser_id, loser_error = losers[0]
    assert type(loser_error) is ValueError
    assert str(loser_error) == (
        "an existing evidence publication requires recovery"
    )
    assert len(loser_snapshots) == 1
    assert (
        _ledger_publication_snapshot(context["ledger_path"])
        == loser_snapshots[0]
    )
    connection = connect_ledger(context["ledger_path"])
    try:
        assert connection.execute(
            """
            SELECT COUNT(*)
            FROM receipts
            WHERE receipt_id IN (?, ?)
            """,
            (first.receipt_id, second.receipt_id),
        ).fetchone() == (1,)
        assert connection.execute(
            """
            SELECT receipt_id
            FROM evidence_publications
            WHERE receipt_id IN (?, ?)
            """,
            (first.receipt_id, second.receipt_id),
        ).fetchone() == (winners[0],)
        assert connection.execute(
            "SELECT COUNT(*) FROM receipts WHERE receipt_id = ?",
            (loser_id,),
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT COUNT(*) FROM receipt_parents WHERE child_receipt_id = ?",
            (loser_id,),
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT COUNT(*) FROM grant_events WHERE receipt_id = ?",
            (loser_id,),
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT COUNT(*) FROM evidence_publications WHERE receipt_id = ?",
            (loser_id,),
        ).fetchone() == (0,)
    finally:
        connection.close()
    for group in (first_group, second_group):
        assert (
            context["evidence_root"] / group.publications[0].pending_path
        ).read_bytes() == payload


@pytest.mark.parametrize(
    "confirmation_failure",
    ("none", "connect", "read", "close"),
)
def test_receipt_publication_commit_ack_error_reports_exact_truth(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    confirmation_failure: str,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    context, receipt, group, payload = (
        _staged_retrying_verifier_candidate(
            tmp_path=tmp_path,
            work_order=signed_work_order,
            root=signed_root_grant,
            role_keys=ephemeral_role_keys,
            fixed_now=fixed_now,
            sidecar_receipt_factory=sidecar_receipt_factory,
            label=f"publication-ack-{confirmation_failure}",
        )
    )
    real_direct = evidence._connect_ledger_direct
    main_connections: list[_FaultingConnection] = []
    confirmation_connections: list[object] = []

    def failing_main_connect(path: Path):
        connection = _FaultingConnection(
            real_direct(path),
            fail_when=lambda sql: sql == "COMMIT",
            fail_after_execute=True,
        )
        main_connections.append(connection)
        return connection

    def confirmation_connect(path: Path):
        if confirmation_failure == "connect":
            raise sqlite3.OperationalError(
                "injected direct confirmation connect failure"
            )
        raw = real_direct(path)
        if confirmation_failure == "read":
            connection = _FaultingConnection(
                raw,
                fail_when=lambda sql: (
                    "SELECT COUNT(*) FROM RECEIPTS" in sql
                ),
            )
        elif confirmation_failure == "close":
            connection = _CloseAlwaysFailsConnection(raw)
        else:
            connection = raw
        confirmation_connections.append(connection)
        return connection

    monkeypatch.setattr(evidence, "connect_ledger", failing_main_connect)
    monkeypatch.setattr(
        evidence,
        "_connect_ledger_direct",
        confirmation_connect,
    )
    expected = (
        evidence.ReceiptPublicationCommittedError
        if confirmation_failure == "none"
        else evidence.ReceiptPublicationCommitIndeterminateError
    )
    try:
        with pytest.raises(expected) as captured:
            evidence.commit_receipt_with_publications(
                context["ledger_path"],
                evidence_root=context["evidence_root"],
                receipt=receipt,
                group=group,
                clock=lambda: fixed_now,
            )
        assert captured.value.receipt == receipt
        assert captured.value.group == group
        assert captured.value.committed is (
            True if confirmation_failure == "none" else None
        )
        if confirmation_failure != "none":
            assert captured.value.truth == "unknown"
    finally:
        monkeypatch.setattr(
            evidence,
            "_connect_ledger_direct",
            real_direct,
        )
        for connection in confirmation_connections:
            if isinstance(connection, _CloseAlwaysFailsConnection):
                connection.force_close()
    assert main_connections and main_connections[0].closed
    connection = real_direct(context["ledger_path"])
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM receipts WHERE receipt_id = ?",
            (receipt.receipt_id,),
        ).fetchone() == (1,)
    finally:
        connection.close()
    assert (
        context["evidence_root"] / group.publications[0].pending_path
    ).read_bytes() == payload


def test_receipt_publication_unapplied_commit_error_propagates_original(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    context, receipt, group, payload = _staged_retrying_verifier_candidate(
        tmp_path=tmp_path,
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        fixed_now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
        label="publication-commit-not-applied",
    )
    before = _ledger_publication_snapshot(context["ledger_path"])
    real_connect = evidence.connect_ledger

    def failing_connect(path: Path):
        return _FaultingConnection(
            real_connect(path),
            fail_when=lambda sql: sql == "COMMIT",
        )

    monkeypatch.setattr(evidence, "connect_ledger", failing_connect)
    with pytest.raises(sqlite3.OperationalError) as captured:
        evidence.commit_receipt_with_publications(
            context["ledger_path"],
            evidence_root=context["evidence_root"],
            receipt=receipt,
            group=group,
            clock=lambda: fixed_now,
        )
    assert "injected SQLite failure: COMMIT" in str(captured.value)
    monkeypatch.setattr(evidence, "connect_ledger", real_connect)
    assert _ledger_publication_snapshot(context["ledger_path"]) == before
    assert (
        context["evidence_root"] / group.publications[0].pending_path
    ).read_bytes() == payload


def test_receipt_publication_successful_commit_with_close_failure_is_committed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    context, receipt, group, _ = _staged_retrying_verifier_candidate(
        tmp_path=tmp_path,
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        fixed_now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
        label="publication-close-committed",
    )
    real_connect = evidence.connect_ledger
    wrapped: list[_CloseAlwaysFailsConnection] = []

    def close_failing_connect(path: Path):
        connection = _CloseAlwaysFailsConnection(real_connect(path))
        wrapped.append(connection)
        return connection

    monkeypatch.setattr(evidence, "connect_ledger", close_failing_connect)
    try:
        with pytest.raises(
            evidence.ReceiptPublicationCommittedError
        ) as captured:
            evidence.commit_receipt_with_publications(
                context["ledger_path"],
                evidence_root=context["evidence_root"],
                receipt=receipt,
                group=group,
                clock=lambda: fixed_now,
            )
        assert captured.value.receipt == receipt
        assert captured.value.group == group
    finally:
        monkeypatch.setattr(evidence, "connect_ledger", real_connect)
        for connection in wrapped:
            connection.force_close()
    assert wrapped[0].close_attempts == 3


def test_receipt_publication_reads_clock_once_and_freezes_one_utc_second(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    sidecar_receipt_factory,
) -> None:
    fixed_now = datetime(
        2026,
        1,
        1,
        0,
        0,
        5,
        tzinfo=timezone.utc,
    )
    context, receipt, group, _ = _staged_retrying_verifier_candidate(
        tmp_path=tmp_path,
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        fixed_now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
        label="publication-clock-once",
    )
    values = (
        fixed_now.replace(microsecond=900_000),
        fixed_now + timedelta(seconds=1),
    )
    calls = 0

    def clock() -> datetime:
        nonlocal calls
        value = values[min(calls, 1)]
        calls += 1
        return value

    evidence.commit_receipt_with_publications(
        context["ledger_path"],
        evidence_root=context["evidence_root"],
        receipt=receipt,
        group=group,
        clock=clock,
    )

    assert calls == 1


@pytest.mark.parametrize("failure_kind", ("raw_fd", "unlock", "lock_close"))
def test_postcommit_raw_resource_cleanup_failure_reports_committed_truth(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_kind: str,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    context, receipt, group, _ = _staged_retrying_verifier_candidate(
        tmp_path=tmp_path,
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        fixed_now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
        label=f"publication-cleanup-{failure_kind}",
    )
    real_connect = evidence.connect_ledger
    real_close = evidence.os.close
    real_flock = evidence.fcntl.flock
    real_acquire = evidence._acquire_target_lock
    committed = [False]
    failed = [False]
    failed_descriptor: list[int] = []
    lock_descriptor: list[int] = []

    class CommitTrackingConnection(_FaultingConnection):
        def execute(self, statement, parameters=()):
            result = super().execute(statement, parameters)
            if " ".join(statement.split()).upper() == "COMMIT":
                committed[0] = True
            return result

    def tracking_connect(path: Path):
        return CommitTrackingConnection(
            real_connect(path),
            fail_when=lambda sql: False,
        )

    def tracking_acquire(path: Path):
        descriptor = real_acquire(path)
        lock_descriptor.append(descriptor)
        return descriptor

    def failing_close(descriptor: int):
        target = (
            failure_kind == "raw_fd"
            and committed[0]
            and descriptor not in lock_descriptor
        ) or (
            failure_kind == "lock_close"
            and committed[0]
            and descriptor in lock_descriptor
        )
        if target and not failed[0]:
            failed[0] = True
            failed_descriptor.append(descriptor)
            raise OSError("injected raw descriptor close failure")
        return real_close(descriptor)

    def failing_flock(descriptor: int, operation: int):
        if (
            failure_kind == "unlock"
            and committed[0]
            and operation == evidence.fcntl.LOCK_UN
            and not failed[0]
        ):
            failed[0] = True
            raise OSError("injected target unlock failure")
        return real_flock(descriptor, operation)

    monkeypatch.setattr(evidence, "connect_ledger", tracking_connect)
    monkeypatch.setattr(
        evidence,
        "_acquire_target_lock",
        tracking_acquire,
    )
    monkeypatch.setattr(evidence.os, "close", failing_close)
    monkeypatch.setattr(evidence.fcntl, "flock", failing_flock)
    try:
        with pytest.raises(
            evidence.ReceiptPublicationCommittedError
        ) as captured:
            evidence.commit_receipt_with_publications(
                context["ledger_path"],
                evidence_root=context["evidence_root"],
                receipt=receipt,
                group=group,
                clock=lambda: fixed_now,
            )
        assert captured.value.receipt == receipt
        assert captured.value.group == group
        assert failed[0]
    finally:
        monkeypatch.setattr(evidence.os, "close", real_close)
        monkeypatch.setattr(evidence.fcntl, "flock", real_flock)
        for descriptor in failed_descriptor:
            try:
                real_close(descriptor)
            except OSError:
                pass

    descriptor = real_acquire(context["ledger_path"])
    closed, errors = evidence._release_target_lock(descriptor)
    assert closed and not errors


def test_precommit_pending_validation_preserves_raw_close_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    context, receipt, group, payload = _staged_retrying_verifier_candidate(
        tmp_path=tmp_path,
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        fixed_now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
        label="publication-precommit-raw-close",
    )
    pending = context["evidence_root"] / group.publications[0].pending_path
    pending.write_bytes(b"x" * len(payload))
    before = _ledger_publication_snapshot(context["ledger_path"])
    real_close = evidence.os.close
    failed_descriptor: list[int] = []

    def failing_close(descriptor: int):
        if not failed_descriptor:
            failed_descriptor.append(descriptor)
            raise OSError("injected pending validation close failure")
        return real_close(descriptor)

    monkeypatch.setattr(evidence.os, "close", failing_close)
    try:
        with pytest.raises(RuntimeError) as captured:
            evidence.commit_receipt_with_publications(
                context["ledger_path"],
                evidence_root=context["evidence_root"],
                receipt=receipt,
                group=group,
                clock=lambda: fixed_now,
            )
        assert any(
            "injected pending validation close failure" in str(error)
            for error in _exception_tree(captured.value)
        )
    finally:
        monkeypatch.setattr(evidence.os, "close", real_close)
        for descriptor in failed_descriptor:
            try:
                real_close(descriptor)
            except OSError:
                pass
    assert _ledger_publication_snapshot(context["ledger_path"]) == before


def test_duplicate_signed_nonce_is_rejected_without_journal_writes(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    context, receipt, group, payload = _staged_retrying_verifier_candidate(
        tmp_path=tmp_path,
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        fixed_now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
        label="publication-duplicate-nonce",
    )
    raw = receipt.model_dump(mode="json")
    raw["nonce"] = context["verifier_issuance"].nonce
    claim = raw["nested_claim"]
    claim["nonce"] = raw["nonce"]
    claim = sign_payload(
        "agent-request",
        claim,
        ephemeral_role_keys["Verifier"][0],
    )
    raw["nested_claim"] = claim
    raw["nested_claim_digest"] = claim["digest"]
    duplicate = evidence.ACTION_RECEIPT_ADAPTER.validate_python(
        sign_payload(
            "action-receipt",
            raw,
            ephemeral_role_keys["Sidecar"][0],
        )
    )
    before = _ledger_publication_snapshot(context["ledger_path"])

    with pytest.raises(ValueError):
        evidence.commit_receipt_with_publications(
            context["ledger_path"],
            evidence_root=context["evidence_root"],
            receipt=duplicate,
            group=group,
            clock=lambda: fixed_now,
        )

    assert _ledger_publication_snapshot(context["ledger_path"]) == before
    assert (
        context["evidence_root"] / group.publications[0].pending_path
    ).read_bytes() == payload


@pytest.mark.parametrize(
    "case",
    (
        "outer_signature",
        "nested_signature",
        "previous_digest",
        "missing_tip_parent",
        "clock_mismatch",
        "non_tool_receipt",
    ),
)
def test_receipt_publication_rejects_invalid_signed_tip_bindings(
    tmp_path: Path,
    case: str,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    context, receipt, group, payload = _staged_retrying_verifier_candidate(
        tmp_path=tmp_path,
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        fixed_now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
        label=f"publication-signed-binding-{case}",
    )
    candidate = receipt
    candidate_group = group
    clock = lambda: fixed_now
    if case == "outer_signature":
        candidate = receipt.model_copy(update={"output_digest": "f" * 64})
    elif case == "nested_signature":
        candidate = receipt.model_copy(
            update={
                "nested_claim": receipt.nested_claim.model_copy(
                    update={"model_id": "tampered"}
                )
            }
        )
    elif case in {"previous_digest", "missing_tip_parent"}:
        raw = receipt.model_dump(mode="json")
        if case == "previous_digest":
            raw["previous_receipt_digest"] = "f" * 64
        else:
            raw["parent_receipt_ids"] = [
                context["verifier_issuance"].parent_receipt_ids[0]
            ]
        candidate = evidence.ACTION_RECEIPT_ADAPTER.validate_python(
            sign_payload(
                "action-receipt",
                raw,
                ephemeral_role_keys["Sidecar"][0],
            )
        )
    elif case == "clock_mismatch":
        clock = lambda: fixed_now + timedelta(seconds=1)
    else:
        candidate = context["verifier_issuance"]
        candidate_group = evidence._PublicationGroup(
            receipt_id=candidate.receipt_id,
            publications=group.publications,
        )
    before = _ledger_publication_snapshot(context["ledger_path"])

    with pytest.raises(ValueError):
        evidence.commit_receipt_with_publications(
            context["ledger_path"],
            evidence_root=context["evidence_root"],
            receipt=candidate,
            group=candidate_group,
            clock=clock,
        )

    assert _ledger_publication_snapshot(context["ledger_path"]) == before
    assert (
        context["evidence_root"] / group.publications[0].pending_path
    ).read_bytes() == payload


def test_existing_committing_journal_blocks_new_facts_and_keeps_pending(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    context, receipt, group, payload = _staged_retrying_verifier_candidate(
        tmp_path=tmp_path,
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        fixed_now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
        label="publication-existing-committing",
    )
    _commit_publication_candidate_for_test(
        context["ledger_path"],
        receipt,
        group,
    )
    before = _ledger_publication_snapshot(context["ledger_path"])

    with pytest.raises(ValueError):
        evidence.commit_receipt_with_publications(
            context["ledger_path"],
            evidence_root=context["evidence_root"],
            receipt=receipt,
            group=group,
            clock=lambda: fixed_now,
        )

    assert _ledger_publication_snapshot(context["ledger_path"]) == before
    assert (
        context["evidence_root"] / group.publications[0].pending_path
    ).read_bytes() == payload


def test_receipt_publication_never_calls_publish_mark_or_deletes_pending(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    context, receipt, group, payload = (
        _staged_retrying_verifier_candidate(
            tmp_path=tmp_path,
            work_order=signed_work_order,
            root=signed_root_grant,
            role_keys=ephemeral_role_keys,
            fixed_now=fixed_now,
            sidecar_receipt_factory=sidecar_receipt_factory,
            label="publication-no-publish",
        )
    )

    def forbidden(*args, **kwargs):
        raise AssertionError("publish/mark/unlink must not be called")

    monkeypatch.setattr(evidence, "publish_group_no_replace", forbidden)
    monkeypatch.setattr(
        evidence,
        "mark_publication_group_committed",
        forbidden,
    )
    monkeypatch.setattr(evidence.os, "unlink", forbidden)
    unrelated = context["evidence_root"] / ".pending" / ("e" * 64)
    unrelated.write_bytes(b"unrelated rowless pending")
    unrelated.chmod(0o600)

    evidence.commit_receipt_with_publications(
        context["ledger_path"],
        evidence_root=context["evidence_root"],
        receipt=receipt,
        group=group,
        clock=lambda: fixed_now,
    )

    pending = context["evidence_root"] / group.publications[0].pending_path
    assert pending.read_bytes() == payload
    assert unrelated.read_bytes() == b"unrelated rowless pending"


def test_complete_receipt_publication_finishes_group_under_one_target_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    context, receipt, staged_group, payload = (
        _staged_retrying_verifier_candidate(
            tmp_path=tmp_path,
            work_order=signed_work_order,
            root=signed_root_grant,
            role_keys=ephemeral_role_keys,
            fixed_now=fixed_now,
            sidecar_receipt_factory=sidecar_receipt_factory,
            label="publication-complete-success",
        )
    )
    (
        context["evidence_root"]
        / staged_group.publications[0].pending_path
    ).unlink()
    phase_descriptors = []
    acquired_descriptors = []
    released_descriptors = []
    phase_names = (
        "stage_pending_evidence_group",
        "commit_receipt_with_publications",
        "publish_group_no_replace",
        "mark_publication_group_committed",
    )
    for phase_name in phase_names:
        real_phase = getattr(evidence, phase_name)

        def phase_wrapper(*args, _phase=real_phase, **kwargs):
            descriptor = kwargs["_borrowed_lock_descriptor"]
            os.fstat(descriptor)
            phase_descriptors.append(descriptor)
            return _phase(*args, **kwargs)

        monkeypatch.setattr(evidence, phase_name, phase_wrapper)
    real_acquire = evidence._acquire_target_lock
    real_release = evidence._release_target_lock

    def recording_acquire(path: Path) -> int:
        descriptor = real_acquire(path)
        acquired_descriptors.append(descriptor)
        return descriptor

    def recording_release(descriptor: int | None):
        released_descriptors.append(descriptor)
        return real_release(descriptor)

    monkeypatch.setattr(evidence, "_acquire_target_lock", recording_acquire)
    monkeypatch.setattr(evidence, "_release_target_lock", recording_release)

    group = evidence.complete_receipt_publication(
        context["ledger_path"],
        evidence_root=context["evidence_root"],
        receipt=receipt,
        payloads={receipt.evidence_refs[0].path: payload},
        clock=lambda: fixed_now,
    )

    assert type(group) is evidence._PublicationGroup
    assert group.receipt_id == receipt.receipt_id
    assert len(acquired_descriptors) == 1
    assert phase_descriptors == [acquired_descriptors[0]] * len(phase_names)
    assert released_descriptors == [acquired_descriptors[0]]
    connection = connect_ledger(context["ledger_path"])
    try:
        assert evidence._validated_receipt_prefix(
            connection,
            signed_work_order,
        )[-1] == receipt
        assert tuple(
            connection.execute(
                """
                SELECT parent_receipt_id
                FROM receipt_parents
                WHERE child_receipt_id = ?
                ORDER BY parent_receipt_id
                """,
                (receipt.receipt_id,),
            )
        ) == tuple((item,) for item in sorted(receipt.parent_receipt_ids))
        assert connection.execute(
            """
            SELECT COUNT(*)
            FROM grant_events
            WHERE receipt_id = ? AND event_type = 'tool_call'
                  AND metric = 'tool_calls' AND amount = 1
            """,
            (receipt.receipt_id,),
        ).fetchone() == (1,)
        assert connection.execute(
            "SELECT current_state, version FROM work_order_state"
        ).fetchone() == (receipt.state_after, receipt.sequence)
        assert connection.execute(
            "SELECT next_sequence FROM sequence_counter"
        ).fetchone() == (receipt.sequence + 1,)
        assert connection.execute(
            """
            SELECT COUNT(*), COUNT(DISTINCT publication_id),
                   MIN(state), MAX(state)
            FROM evidence_publications
            WHERE receipt_id = ?
            """,
            (receipt.receipt_id,),
        ).fetchone() == (
            len(group.publications),
            len(group.publications),
            "COMMITTED",
            "COMMITTED",
        )
    finally:
        connection.close()
    for publication in group.publications:
        final = (
            context["evidence_root"]
            / publication.final_path.removeprefix("evidence/")
        )
        assert final.read_bytes() == payload
        assert not (
            context["evidence_root"] / publication.pending_path
        ).exists()
    assert not tuple((context["evidence_root"] / ".pending").iterdir())
    monkeypatch.setattr(evidence, "_acquire_target_lock", real_acquire)
    monkeypatch.setattr(evidence, "_release_target_lock", real_release)
    evidence.require_all_publications_committed(
        context["ledger_path"],
        evidence_root=context["evidence_root"],
    )


@pytest.mark.parametrize(
    "failure_phase",
    (
        "stage",
        "precommit",
        "commit_indeterminate",
        "commit_postverify",
        "publish",
        "mark",
    ),
)
def test_complete_receipt_publication_preserves_each_phase_boundary(
    failure_phase: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    context, receipt, staged_group, payload = (
        _staged_retrying_verifier_candidate(
            tmp_path=tmp_path,
            work_order=signed_work_order,
            root=signed_root_grant,
            role_keys=ephemeral_role_keys,
            fixed_now=fixed_now,
            sidecar_receipt_factory=sidecar_receipt_factory,
            label=f"publication-complete-{failure_phase}",
        )
    )
    (
        context["evidence_root"]
        / staged_group.publications[0].pending_path
    ).unlink()
    before = _receipt_publication_protocol_snapshot(context["ledger_path"])
    real_stage = evidence.stage_pending_evidence_group
    real_commit = evidence.commit_receipt_with_publications
    real_publish = evidence.publish_group_no_replace
    real_mark = evidence.mark_publication_group_committed

    def forbidden(*args, **kwargs):
        raise AssertionError("later publication phase must not run")

    def failing_stage(*args, **kwargs):
        real_stage(*args, **kwargs)
        raise OSError("injected post-stage failure")

    def failing_commit(*args, **kwargs):
        group = kwargs["group"]
        if failure_phase == "precommit":
            raise ValueError("injected pre-commit failure")
        if failure_phase == "commit_indeterminate":
            raise evidence.ReceiptPublicationCommitIndeterminateError(
                receipt,
                group,
            )
        real_commit(*args, **kwargs)
        raise evidence.ReceiptPublicationCommittedError(receipt, group)

    if failure_phase == "stage":
        monkeypatch.setattr(
            evidence,
            "stage_pending_evidence_group",
            failing_stage,
        )
        monkeypatch.setattr(
            evidence,
            "commit_receipt_with_publications",
            forbidden,
        )
        monkeypatch.setattr(evidence, "publish_group_no_replace", forbidden)
        monkeypatch.setattr(
            evidence,
            "mark_publication_group_committed",
            forbidden,
        )
    elif failure_phase in {
        "precommit",
        "commit_indeterminate",
        "commit_postverify",
    }:
        monkeypatch.setattr(
            evidence,
            "commit_receipt_with_publications",
            failing_commit,
        )
        monkeypatch.setattr(evidence, "publish_group_no_replace", forbidden)
        monkeypatch.setattr(
            evidence,
            "mark_publication_group_committed",
            forbidden,
        )
    elif failure_phase == "publish":
        monkeypatch.setattr(
            evidence,
            "publish_group_no_replace",
            lambda *args, **kwargs: (_ for _ in ()).throw(
                OSError("injected publish failure")
            ),
        )
        monkeypatch.setattr(
            evidence,
            "mark_publication_group_committed",
            forbidden,
        )
    else:
        monkeypatch.setattr(
            evidence,
            "mark_publication_group_committed",
            lambda *args, **kwargs: (_ for _ in ()).throw(
                OSError("injected mark failure")
            ),
        )

    expected_error = (
        OSError
        if failure_phase == "stage"
        else ValueError
        if failure_phase == "precommit"
        else evidence.ReceiptPublicationCommitIndeterminateError
        if failure_phase == "commit_indeterminate"
        else evidence.ReceiptPublicationCommittedError
    )
    with pytest.raises(expected_error) as captured:
        evidence.complete_receipt_publication(
            context["ledger_path"],
            evidence_root=context["evidence_root"],
            receipt=receipt,
            payloads={receipt.evidence_refs[0].path: payload},
            clock=lambda: fixed_now,
        )

    pending_files = tuple(
        (context["evidence_root"] / ".pending").iterdir()
    )
    final = (
        context["evidence_root"]
        / receipt.evidence_refs[0].path.removeprefix("evidence/")
    )
    if failure_phase in {
        "stage",
        "precommit",
        "commit_indeterminate",
    }:
        assert _receipt_publication_protocol_snapshot(
            context["ledger_path"]
        ) == before
        assert len(pending_files) == 1
        assert pending_files[0].read_bytes() == payload
        assert not final.exists()
        if failure_phase == "commit_indeterminate":
            assert captured.value.receipt == receipt
            assert captured.value.group.receipt_id == receipt.receipt_id
            return
        monkeypatch.setattr(
            evidence,
            "stage_pending_evidence_group",
            real_stage,
        )
        monkeypatch.setattr(
            evidence,
            "commit_receipt_with_publications",
            real_commit,
        )
        evidence.recover_evidence_publications(
            context["ledger_path"],
            evidence_root=context["evidence_root"],
        )
        assert not tuple(
            (context["evidence_root"] / ".pending").iterdir()
        )
        return

    assert captured.value.receipt == receipt
    group = captured.value.group
    connection = connect_ledger(context["ledger_path"])
    try:
        assert connection.execute(
            "SELECT state FROM evidence_publications"
        ).fetchall() == [("COMMITTING",)]
        assert connection.execute(
            "SELECT COUNT(*) FROM receipts WHERE receipt_id = ?",
            (receipt.receipt_id,),
        ).fetchone() == (1,)
        assert connection.execute(
            "SELECT COUNT(*) FROM grant_events WHERE receipt_id = ?",
            (receipt.receipt_id,),
        ).fetchone() == (1,)
    finally:
        connection.close()
    if failure_phase == "mark":
        assert not pending_files
        assert final.read_bytes() == payload
    else:
        assert len(pending_files) == 1
        assert pending_files[0].read_bytes() == payload
        assert not final.exists()
    committed_protocol = _receipt_publication_protocol_snapshot(
        context["ledger_path"]
    )
    monkeypatch.setattr(
        evidence,
        "commit_receipt_with_publications",
        real_commit,
    )
    monkeypatch.setattr(
        evidence,
        "publish_group_no_replace",
        real_publish,
    )
    monkeypatch.setattr(
        evidence,
        "mark_publication_group_committed",
        real_mark,
    )
    evidence.recover_evidence_publications(
        context["ledger_path"],
        evidence_root=context["evidence_root"],
    )
    assert _receipt_publication_protocol_snapshot(
        context["ledger_path"]
    ) == committed_protocol
    assert final.read_bytes() == payload
    assert not (
        context["evidence_root"] / group.publications[0].pending_path
    ).exists()
    evidence.require_all_publications_committed(
        context["ledger_path"],
        evidence_root=context["evidence_root"],
    )


@pytest.mark.parametrize(
    "failure_case",
    (
        "mark_ack_committed",
        "mark_ack_indeterminate",
        "lock_cleanup_committed",
        "lock_cleanup_indeterminate",
    ),
)
def test_complete_receipt_publication_preserves_ack_and_cleanup_truth(
    failure_case: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    context, receipt, staged_group, payload = (
        _staged_retrying_verifier_candidate(
            tmp_path=tmp_path,
            work_order=signed_work_order,
            root=signed_root_grant,
            role_keys=ephemeral_role_keys,
            fixed_now=fixed_now,
            sidecar_receipt_factory=sidecar_receipt_factory,
            label=f"publication-complete-{failure_case}",
        )
    )
    (
        context["evidence_root"]
        / staged_group.publications[0].pending_path
    ).unlink()
    before = _receipt_publication_protocol_snapshot(context["ledger_path"])
    phase_calls = {
        "stage": 0,
        "commit": 0,
        "publish": 0,
        "mark": 0,
    }
    real_stage = evidence.stage_pending_evidence_group
    real_commit = evidence.commit_receipt_with_publications
    real_publish = evidence.publish_group_no_replace
    real_mark = evidence.mark_publication_group_committed
    real_release = evidence._release_target_lock

    def counting_stage(*args, **kwargs):
        phase_calls["stage"] += 1
        return real_stage(*args, **kwargs)

    def counting_commit(*args, **kwargs):
        phase_calls["commit"] += 1
        if failure_case == "lock_cleanup_indeterminate":
            raise evidence.ReceiptPublicationCommitIndeterminateError(
                receipt,
                kwargs["group"],
            )
        return real_commit(*args, **kwargs)

    def counting_publish(*args, **kwargs):
        phase_calls["publish"] += 1
        return real_publish(*args, **kwargs)

    def counting_mark(*args, **kwargs):
        phase_calls["mark"] += 1
        group = kwargs["group"]
        if failure_case == "mark_ack_indeterminate":
            raise evidence.EvidencePublicationCommitIndeterminateError(group)
        result = real_mark(*args, **kwargs)
        if failure_case == "mark_ack_committed":
            raise evidence.EvidencePublicationCommittedError(group)
        return result

    def failing_release(descriptor: int | None):
        closed, errors = real_release(descriptor)
        return closed, (*errors, OSError("injected lock cleanup failure"))

    monkeypatch.setattr(
        evidence,
        "stage_pending_evidence_group",
        counting_stage,
    )
    monkeypatch.setattr(
        evidence,
        "commit_receipt_with_publications",
        counting_commit,
    )
    monkeypatch.setattr(
        evidence,
        "publish_group_no_replace",
        counting_publish,
    )
    monkeypatch.setattr(
        evidence,
        "mark_publication_group_committed",
        counting_mark,
    )
    if failure_case.startswith("lock_cleanup"):
        monkeypatch.setattr(
            evidence,
            "_release_target_lock",
            failing_release,
        )

    expected_error = (
        evidence.ReceiptPublicationCommitIndeterminateError
        if failure_case == "lock_cleanup_indeterminate"
        else evidence.ReceiptPublicationCommittedError
    )
    with pytest.raises(expected_error) as captured:
        evidence.complete_receipt_publication(
            context["ledger_path"],
            evidence_root=context["evidence_root"],
            receipt=receipt,
            payloads={receipt.evidence_refs[0].path: payload},
            clock=lambda: fixed_now,
        )

    assert phase_calls["stage"] == 1
    assert phase_calls["commit"] == 1
    if failure_case == "lock_cleanup_indeterminate":
        assert phase_calls["publish"] == 0
        assert phase_calls["mark"] == 0
        assert _receipt_publication_protocol_snapshot(
            context["ledger_path"]
        ) == before
        pending_files = tuple(
            (context["evidence_root"] / ".pending").iterdir()
        )
        assert len(pending_files) == 1
        assert pending_files[0].read_bytes() == payload
        assert any(
            "injected lock cleanup failure" in str(error)
            for error in _exception_tree(captured.value)
        )
        if isinstance(captured.value.__cause__, BaseExceptionGroup):
            assert captured.value not in captured.value.__cause__.exceptions
        return

    assert phase_calls["publish"] == 1
    assert phase_calls["mark"] == 1
    assert captured.value.receipt == receipt
    group = captured.value.group
    final = (
        context["evidence_root"]
        / group.publications[0].final_path.removeprefix("evidence/")
    )
    assert final.read_bytes() == payload
    assert not tuple((context["evidence_root"] / ".pending").iterdir())
    connection = connect_ledger(context["ledger_path"])
    try:
        state_value = connection.execute(
            "SELECT state FROM evidence_publications"
        ).fetchone()
    finally:
        connection.close()
    if failure_case == "mark_ack_indeterminate":
        assert state_value == ("COMMITTING",)
        assert any(
            isinstance(
                error,
                evidence.EvidencePublicationCommitIndeterminateError,
            )
            for error in _exception_tree(captured.value)
        )
        committed_protocol = _receipt_publication_protocol_snapshot(
            context["ledger_path"]
        )
        monkeypatch.setattr(
            evidence,
            "_release_target_lock",
            real_release,
        )
        evidence.recover_evidence_publications(
            context["ledger_path"],
            evidence_root=context["evidence_root"],
        )
        assert _receipt_publication_protocol_snapshot(
            context["ledger_path"]
        ) == committed_protocol
    else:
        assert state_value == ("COMMITTED",)
        if failure_case == "lock_cleanup_committed":
            assert any(
                "injected lock cleanup failure" in str(error)
                for error in _exception_tree(captured.value)
            )
    monkeypatch.setattr(
        evidence,
        "_release_target_lock",
        real_release,
    )
    evidence.require_all_publications_committed(
        context["ledger_path"],
        evidence_root=context["evidence_root"],
    )


def test_complete_receipt_publication_requires_committed_truth_before_return(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    context, receipt, staged_group, payload = (
        _staged_retrying_verifier_candidate(
            tmp_path=tmp_path,
            work_order=signed_work_order,
            root=signed_root_grant,
            role_keys=ephemeral_role_keys,
            fixed_now=fixed_now,
            sidecar_receipt_factory=sidecar_receipt_factory,
            label="publication-complete-missing-mark-truth",
        )
    )
    (
        context["evidence_root"]
        / staged_group.publications[0].pending_path
    ).unlink()
    monkeypatch.setattr(
        evidence,
        "mark_publication_group_committed",
        lambda *args, **kwargs: None,
    )

    with pytest.raises(
        evidence.ReceiptPublicationCommittedError
    ) as captured:
        evidence.complete_receipt_publication(
            context["ledger_path"],
            evidence_root=context["evidence_root"],
            receipt=receipt,
            payloads={receipt.evidence_refs[0].path: payload},
            clock=lambda: fixed_now,
        )

    assert captured.value.receipt == receipt
    connection = connect_ledger(context["ledger_path"])
    try:
        assert connection.execute(
            "SELECT state FROM evidence_publications"
        ).fetchall() == [("COMMITTING",)]
    finally:
        connection.close()
    final = (
        context["evidence_root"]
        / receipt.evidence_refs[0].path.removeprefix("evidence/")
    )
    assert final.read_bytes() == payload
    assert not tuple((context["evidence_root"] / ".pending").iterdir())


def test_complete_receipt_publication_replays_quota_before_return(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    context, receipt, staged_group, payload = (
        _staged_retrying_verifier_candidate(
            tmp_path=tmp_path,
            work_order=signed_work_order,
            root=signed_root_grant,
            role_keys=ephemeral_role_keys,
            fixed_now=fixed_now,
            sidecar_receipt_factory=sidecar_receipt_factory,
            label="publication-complete-missing-quota-event",
        )
    )
    (
        context["evidence_root"]
        / staged_group.publications[0].pending_path
    ).unlink()
    real_mark = evidence.mark_publication_group_committed

    def mark_then_delete_quota(*args, **kwargs):
        real_mark(*args, **kwargs)
        connection = connect_ledger(context["ledger_path"])
        try:
            connection.execute(
                "DELETE FROM grant_events WHERE receipt_id = ?",
                (receipt.receipt_id,),
            )
        finally:
            connection.close()

    monkeypatch.setattr(
        evidence,
        "mark_publication_group_committed",
        mark_then_delete_quota,
    )

    with pytest.raises(
        evidence.ReceiptPublicationCommittedError
    ) as captured:
        evidence.complete_receipt_publication(
            context["ledger_path"],
            evidence_root=context["evidence_root"],
            receipt=receipt,
            payloads={receipt.evidence_refs[0].path: payload},
            clock=lambda: fixed_now,
        )

    assert captured.value.receipt == receipt
    assert any(
        isinstance(error, evidence.RetryEvidenceRecoveryError)
        for error in _exception_tree(captured.value)
    )
    connection = connect_ledger(context["ledger_path"])
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM receipts WHERE receipt_id = ?",
            (receipt.receipt_id,),
        ).fetchone() == (1,)
        assert connection.execute(
            "SELECT COUNT(*) FROM grant_events WHERE receipt_id = ?",
            (receipt.receipt_id,),
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT DISTINCT state FROM evidence_publications"
        ).fetchall() == [("COMMITTED",)]
        assert connection.execute(
            "SELECT current_state, version FROM work_order_state"
        ).fetchone() == (receipt.state_after, receipt.sequence)
        assert connection.execute(
            "SELECT next_sequence FROM sequence_counter"
        ).fetchone() == (receipt.sequence + 1,)
    finally:
        connection.close()


def test_complete_receipt_publication_recovers_partial_multi_file_publish(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    context, receipt, staged_group, payloads = (
        _staged_running_patch_candidate(
            tmp_path=tmp_path,
            work_order=signed_work_order,
            root=signed_root_grant,
            role_keys=ephemeral_role_keys,
            fixed_now=fixed_now,
            sidecar_receipt_factory=sidecar_receipt_factory,
            label="publication-complete-partial-publish",
        )
    )
    for publication in staged_group.publications:
        (
            context["evidence_root"] / publication.pending_path
        ).unlink()
    real_publish_one = evidence._publish_one_no_replace
    publish_calls = 0

    def fail_second_publish(**kwargs):
        nonlocal publish_calls
        publish_calls += 1
        if publish_calls == 2:
            raise OSError("injected second publication failure")
        return real_publish_one(**kwargs)

    monkeypatch.setattr(
        evidence,
        "_publish_one_no_replace",
        fail_second_publish,
    )

    with pytest.raises(
        evidence.ReceiptPublicationCommittedError
    ) as captured:
        evidence.complete_receipt_publication(
            context["ledger_path"],
            evidence_root=context["evidence_root"],
            receipt=receipt,
            payloads=payloads,
            clock=lambda: fixed_now,
            trusted_resolution_manifest=(
                context["trusted_resolution_manifest"]
            ),
        )

    assert publish_calls == 2
    group = captured.value.group
    connection = connect_ledger(context["ledger_path"])
    try:
        assert connection.execute(
            "SELECT DISTINCT state FROM evidence_publications"
        ).fetchall() == [("COMMITTING",)]
    finally:
        connection.close()
    first, second = group.publications
    first_final = (
        context["evidence_root"]
        / first.final_path.removeprefix("evidence/")
    )
    second_final = (
        context["evidence_root"]
        / second.final_path.removeprefix("evidence/")
    )
    assert first_final.read_bytes() == payloads[first.final_path]
    assert not (
        context["evidence_root"] / first.pending_path
    ).exists()
    assert not second_final.exists()
    assert (
        context["evidence_root"] / second.pending_path
    ).read_bytes() == payloads[second.final_path]
    committed_protocol = _receipt_publication_protocol_snapshot(
        context["ledger_path"]
    )
    monkeypatch.setattr(
        evidence,
        "_publish_one_no_replace",
        real_publish_one,
    )
    evidence.recover_evidence_publications(
        context["ledger_path"],
        evidence_root=context["evidence_root"],
    )
    assert _receipt_publication_protocol_snapshot(
        context["ledger_path"]
    ) == committed_protocol
    for publication in group.publications:
        final = (
            context["evidence_root"]
            / publication.final_path.removeprefix("evidence/")
        )
        assert final.read_bytes() == payloads[publication.final_path]
        assert not (
            context["evidence_root"] / publication.pending_path
        ).exists()
    evidence.require_all_publications_committed(
        context["ledger_path"],
        evidence_root=context["evidence_root"],
    )


def test_stage_pending_evidence_group_writes_one_exact_durable_pending_file(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    episode = _retry_episode(
        tmp_path=tmp_path,
        label="publication-stage-one",
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
    )
    receipt = _publication_candidate(episode, sidecar_receipt_factory)
    payload = _verifier_result_payload(receipt)
    reference = receipt.evidence_refs[0]
    assert hashlib.sha256(payload).hexdigest() == reference.sha256
    before = _ledger_publication_snapshot(episode["ledger_path"])

    group = evidence.stage_pending_evidence_group(
        episode["ledger_path"],
        evidence_root=episode["evidence_root"],
        receipt=receipt,
        payloads={reference.path: payload},
    )

    assert _ledger_publication_snapshot(episode["ledger_path"]) == before
    assert group.receipt_id == receipt.receipt_id
    assert len(group.publications) == 1
    publication = group.publications[0]
    pending = episode["evidence_root"] / publication.pending_path
    assert pending.read_bytes() == payload
    assert stat.S_IMODE(pending.stat().st_mode) == 0o600
    assert not (
        episode["evidence_root"]
        / reference.path.removeprefix("evidence/")
    ).exists()
    assert before[2] == _ledger_publication_snapshot(
        episode["ledger_path"]
    )[2]


def test_stage_fails_if_new_pending_directory_parent_fsync_fails(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    episode = _retry_episode(
        tmp_path=tmp_path,
        label="publication-stage-root-fsync",
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
    )
    receipt = _publication_candidate(episode, sidecar_receipt_factory)
    payload = _verifier_result_payload(receipt)
    reference = receipt.evidence_refs[0]
    root_identity = episode["evidence_root"].stat()
    before = _ledger_publication_snapshot(episode["ledger_path"])
    real_fsync = os.fsync

    def fail_root_fsync(descriptor: int) -> None:
        metadata = os.fstat(descriptor)
        if (metadata.st_dev, metadata.st_ino) == (
            root_identity.st_dev,
            root_identity.st_ino,
        ):
            raise OSError("injected evidence root fsync failure")
        real_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", fail_root_fsync)

    with pytest.raises(OSError, match="root fsync"):
        evidence.stage_pending_evidence_group(
            episode["ledger_path"],
            evidence_root=episode["evidence_root"],
            receipt=receipt,
            payloads={reference.path: payload},
        )

    assert _ledger_publication_snapshot(episode["ledger_path"]) == before
    pending = episode["evidence_root"] / ".pending"
    assert not pending.exists() or not tuple(pending.iterdir())


@pytest.mark.parametrize(
    "fault",
    ["write", "file_fsync", "pending_dir_fsync"],
)
def test_stage_interruption_cleans_only_its_owned_pending(
    fault: str,
    tmp_path: Path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    episode = _retry_episode(
        tmp_path=tmp_path,
        label=f"publication-stage-{fault}",
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
    )
    receipt = _publication_candidate(episode, sidecar_receipt_factory)
    payload = _verifier_result_payload(receipt)
    reference = receipt.evidence_refs[0]
    pending_root = episode["evidence_root"] / ".pending"
    pending_root.mkdir()
    survivor = pending_root / ("f" * 64)
    survivor.write_bytes(b"not-owned")
    before = _ledger_publication_snapshot(episode["ledger_path"])
    if fault == "write":
        real_write_all = evidence._write_all

        def fail_write(descriptor: int, exact_payload: bytes) -> None:
            os.write(descriptor, exact_payload[:1])
            raise OSError("injected write interruption")

        monkeypatch.setattr(evidence, "_write_all", fail_write)
    else:
        real_fsync = os.fsync
        pending_identity = pending_root.stat()
        failed = False

        def fail_selected_fsync(descriptor: int) -> None:
            nonlocal failed
            metadata = os.fstat(descriptor)
            is_target = (
                fault == "file_fsync"
                and stat.S_ISREG(metadata.st_mode)
                and metadata.st_ino != survivor.stat().st_ino
            ) or (
                fault == "pending_dir_fsync"
                and (metadata.st_dev, metadata.st_ino)
                == (pending_identity.st_dev, pending_identity.st_ino)
            )
            if is_target and not failed:
                failed = True
                raise OSError(f"injected {fault}")
            real_fsync(descriptor)

        monkeypatch.setattr(os, "fsync", fail_selected_fsync)

    with pytest.raises(OSError, match="injected"):
        evidence.stage_pending_evidence_group(
            episode["ledger_path"],
            evidence_root=episode["evidence_root"],
            receipt=receipt,
            payloads={reference.path: payload},
        )

    assert _ledger_publication_snapshot(episode["ledger_path"]) == before
    assert survivor.read_bytes() == b"not-owned"
    assert tuple(pending_root.iterdir()) == (survivor,)
    if fault == "write":
        monkeypatch.setattr(evidence, "_write_all", real_write_all)


def test_stage_rejects_non_toolcall_evidence_producer_and_zero_or_nine(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    episode = _retry_episode(
        tmp_path=tmp_path,
        label="publication-stage-bounds",
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
    )
    receipt, payloads = _bounded_publication_candidate(
        episode,
        signed_work_order,
        ephemeral_role_keys,
        sidecar_receipt_factory,
        count=8,
    )
    before = _ledger_publication_snapshot(episode["ledger_path"])

    with pytest.raises(ValueError, match="producer"):
        evidence.stage_pending_evidence_group(
            episode["ledger_path"],
            evidence_root=episode["evidence_root"],
            receipt=receipt,
            payloads=payloads,
        )

    assert _ledger_publication_snapshot(episode["ledger_path"]) == before
    assert not (episode["evidence_root"] / ".pending").exists()

    zero = receipt.model_copy(update={"evidence_refs": ()})
    with pytest.raises(ValueError):
        evidence.stage_pending_evidence_group(
            episode["ledger_path"],
            evidence_root=episode["evidence_root"],
            receipt=zero,
            payloads={},
        )
    nine = receipt.model_copy(
        update={
            "evidence_refs": receipt.evidence_refs
            + (receipt.evidence_refs[0],),
        }
    )
    with pytest.raises(ValueError):
        evidence.stage_pending_evidence_group(
            episode["ledger_path"],
            evidence_root=episode["evidence_root"],
            receipt=nine,
            payloads=payloads,
        )


def test_stage_rejects_a_pending_hardlink_added_during_file_fsync(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    episode = _retry_episode(
        tmp_path=tmp_path,
        label="publication-stage-hardlink",
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
    )
    receipt = _publication_candidate(episode, sidecar_receipt_factory)
    payload = _verifier_result_payload(receipt)
    reference = receipt.evidence_refs[0]
    outside = tmp_path / "outside-hardlink"
    real_fsync = os.fsync
    linked = False

    def add_hardlink(descriptor: int) -> None:
        nonlocal linked
        metadata = os.fstat(descriptor)
        if stat.S_ISREG(metadata.st_mode) and not linked:
            pending_files = tuple(
                (episode["evidence_root"] / ".pending").iterdir()
            )
            assert len(pending_files) == 1
            os.link(pending_files[0], outside)
            linked = True
        real_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", add_hardlink)

    with pytest.raises(OSError, match="stable regular"):
        evidence.stage_pending_evidence_group(
            episode["ledger_path"],
            evidence_root=episode["evidence_root"],
            receipt=receipt,
            payloads={reference.path: payload},
        )

    assert linked
    assert outside.read_bytes() == payload
    assert not tuple((episode["evidence_root"] / ".pending").iterdir())


def test_publish_group_uses_atomic_no_replace_and_removes_pending(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    episode = _retry_episode(
        tmp_path=tmp_path,
        label="publication-publish-one",
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
    )
    receipt = _publication_candidate(episode, sidecar_receipt_factory)
    payload = _verifier_result_payload(receipt)
    reference = receipt.evidence_refs[0]
    group = evidence.stage_pending_evidence_group(
        episode["ledger_path"],
        evidence_root=episode["evidence_root"],
        receipt=receipt,
        payloads={reference.path: payload},
    )
    _commit_publication_candidate_for_test(
        episode["ledger_path"],
        receipt,
        group,
    )

    evidence.publish_group_no_replace(
        episode["ledger_path"],
        evidence_root=episode["evidence_root"],
        group=group,
    )

    publication = group.publications[0]
    assert not (
        episode["evidence_root"] / publication.pending_path
    ).exists()
    final = (
        episode["evidence_root"]
        / publication.final_path.removeprefix("evidence/")
    )
    assert final.read_bytes() == payload
    assert final.stat().st_nlink == 1
    connection = connect_ledger(episode["ledger_path"])
    try:
        assert connection.execute(
            """
            SELECT state FROM evidence_publications
            WHERE publication_id = ?
            """,
            (publication.publication_id,),
        ).fetchone() == ("COMMITTING",)
    finally:
        connection.close()


def test_publish_group_never_overwrites_an_existing_final(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    episode = _retry_episode(
        tmp_path=tmp_path,
        label="publication-no-replace",
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
    )
    receipt = _publication_candidate(episode, sidecar_receipt_factory)
    payload = _verifier_result_payload(receipt)
    reference = receipt.evidence_refs[0]
    group = evidence.stage_pending_evidence_group(
        episode["ledger_path"],
        evidence_root=episode["evidence_root"],
        receipt=receipt,
        payloads={reference.path: payload},
    )
    _commit_publication_candidate_for_test(
        episode["ledger_path"],
        receipt,
        group,
    )
    final = (
        episode["evidence_root"]
        / reference.path.removeprefix("evidence/")
    )
    final.parent.mkdir(parents=True)
    attacker_bytes = b"do-not-overwrite"
    final.write_bytes(attacker_bytes)

    with pytest.raises(FileExistsError):
        evidence.publish_group_no_replace(
            episode["ledger_path"],
            evidence_root=episode["evidence_root"],
            group=group,
        )

    assert final.read_bytes() == attacker_bytes
    assert (
        episode["evidence_root"] / group.publications[0].pending_path
    ).read_bytes() == payload


def test_final_verification_rejects_real_root_swap_and_substitute(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _single_publication_context(
        tmp_path=tmp_path,
        label="publication-final-root-swap",
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
    )
    root = context["evidence_root"]
    moved_root = tmp_path / "publication-final-root-moved"
    substitute_root = tmp_path / "publication-final-root-substitute"
    retired_substitute = tmp_path / "publication-final-root-retired"
    relative_final = context["reference"].path.removeprefix("evidence/")
    substitute_final = substitute_root / relative_final
    substitute_final.parent.mkdir(parents=True)
    substitute_final.write_bytes(context["payload"])
    tampered_payload = bytearray(context["payload"])
    tampered_payload[0] ^= 1
    real_verify = evidence._verify_exact_final
    swapped = False

    def swap_validate_restore(
        root_anchor,
        work_order: WorkOrder,
        publication,
    ) -> None:
        nonlocal swapped
        assert not swapped
        swapped = True
        root.rename(moved_root)
        substitute_root.rename(root)
        moved_final = moved_root / relative_final
        moved_final.write_bytes(bytes(tampered_payload))
        try:
            real_verify(root_anchor, work_order, publication)
        finally:
            root.rename(retired_substitute)
            moved_root.rename(root)

    monkeypatch.setattr(
        evidence,
        "_verify_exact_final",
        swap_validate_restore,
    )

    with pytest.raises(OSError):
        evidence.publish_group_no_replace(
            context["ledger_path"],
            evidence_root=root,
            group=context["group"],
        )

    assert swapped
    assert (root / relative_final).read_bytes() == bytes(tampered_payload)


def test_mark_publication_group_commits_all_rows_without_protocol_writes(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    episode = _retry_episode(
        tmp_path=tmp_path,
        label="publication-mark-group",
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
    )
    receipt, payloads = _two_publication_candidate(
        episode,
        ephemeral_role_keys,
    )
    group = evidence.stage_pending_evidence_group(
        episode["ledger_path"],
        evidence_root=episode["evidence_root"],
        receipt=receipt,
        payloads=payloads,
    )
    _commit_publication_candidate_for_test(
        episode["ledger_path"],
        receipt,
        group,
    )
    evidence.publish_group_no_replace(
        episode["ledger_path"],
        evidence_root=episode["evidence_root"],
        group=group,
    )
    before = _ledger_publication_snapshot(episode["ledger_path"])

    evidence.mark_publication_group_committed(
        episode["ledger_path"],
        evidence_root=episode["evidence_root"],
        group=group,
    )

    after = _ledger_publication_snapshot(episode["ledger_path"])
    assert after[:2] == before[:2]
    assert after[3:] == before[3:]
    assert {row[-1] for row in after[2]} == {"COMMITTED"}


def test_mark_publication_group_is_all_or_none_on_one_mismatch(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    episode = _retry_episode(
        tmp_path=tmp_path,
        label="publication-mark-mismatch",
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
    )
    receipt, payloads = _two_publication_candidate(
        episode,
        ephemeral_role_keys,
    )
    group = evidence.stage_pending_evidence_group(
        episode["ledger_path"],
        evidence_root=episode["evidence_root"],
        receipt=receipt,
        payloads=payloads,
    )
    _commit_publication_candidate_for_test(
        episode["ledger_path"],
        receipt,
        group,
    )
    evidence.publish_group_no_replace(
        episode["ledger_path"],
        evidence_root=episode["evidence_root"],
        group=group,
    )
    tampered = (
        episode["evidence_root"]
        / group.publications[0].final_path.removeprefix("evidence/")
    )
    tampered.write_bytes(b"tampered")
    before = _ledger_publication_snapshot(episode["ledger_path"])

    with pytest.raises(OSError):
        evidence.mark_publication_group_committed(
            episode["ledger_path"],
            evidence_root=episode["evidence_root"],
            group=group,
        )

    after = _ledger_publication_snapshot(episode["ledger_path"])
    assert after == before
    assert {row[-1] for row in after[2]} == {"COMMITTING"}


def test_mark_commit_ack_is_confirmed_and_recovery_treats_it_as_done(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    contexts = [
        _single_publication_context(
            tmp_path=tmp_path,
            label=f"publication-commit-ack-{index}",
            work_order=signed_work_order,
            root=signed_root_grant,
            role_keys=ephemeral_role_keys,
            now=fixed_now,
            sidecar_receipt_factory=sidecar_receipt_factory,
        )
        for index in range(2)
    ]
    for context in contexts:
        evidence.publish_group_no_replace(
            context["ledger_path"],
            evidence_root=context["evidence_root"],
            group=context["group"],
        )
    real_connect = evidence.connect_ledger

    def commit_ack_failing_connect(path: Path):
        return _FaultingConnection(
            real_connect(path),
            fail_when=lambda sql: sql == "COMMIT",
            fail_after_execute=True,
        )

    monkeypatch.setattr(
        evidence,
        "connect_ledger",
        commit_ack_failing_connect,
    )
    with pytest.raises(
        evidence.EvidencePublicationCommittedError
    ) as captured:
        evidence.mark_publication_group_committed(
            contexts[0]["ledger_path"],
            evidence_root=contexts[0]["evidence_root"],
            group=contexts[0]["group"],
        )
    assert captured.value.committed is True
    assert captured.value.group == contexts[0]["group"]
    assert captured.value.receipt_id == contexts[0]["receipt"].receipt_id

    evidence.recover_evidence_publications(
        contexts[1]["ledger_path"],
        evidence_root=contexts[1]["evidence_root"],
    )
    monkeypatch.setattr(evidence, "connect_ledger", real_connect)
    for context in contexts:
        connection = real_connect(context["ledger_path"])
        try:
            assert connection.execute(
                "SELECT state FROM evidence_publications"
            ).fetchall() == [("COMMITTED",)]
        finally:
            connection.close()


@pytest.mark.parametrize(
    "confirmation_failure",
    ["connect", "read", "close"],
)
def test_commit_ack_confirmation_failure_reports_unknown_and_recovery_blocks(
    confirmation_failure: str,
    tmp_path: Path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    contexts = [
        _single_publication_context(
            tmp_path=tmp_path,
            label=(
                f"publication-confirmation-{confirmation_failure}-{index}"
            ),
            work_order=signed_work_order,
            root=signed_root_grant,
            role_keys=ephemeral_role_keys,
            now=fixed_now,
            sidecar_receipt_factory=sidecar_receipt_factory,
        )
        for index in range(2)
    ]
    evidence.publish_group_no_replace(
        contexts[0]["ledger_path"],
        evidence_root=contexts[0]["evidence_root"],
        group=contexts[0]["group"],
    )
    real_connect = evidence.connect_ledger
    real_direct = evidence._connect_ledger_direct
    direct_wrapped: list[_CloseAlwaysFailsConnection] = []

    def commit_ack_failing_connect(path: Path):
        return _FaultingConnection(
            real_direct(path),
            fail_when=lambda sql: sql == "COMMIT",
            fail_after_execute=True,
        )

    def confirmation_failing_connect(path: Path):
        if confirmation_failure == "connect":
            raise sqlite3.OperationalError(
                "injected confirmation connect failure"
            )
        if confirmation_failure == "read":
            return _FaultingConnection(
                real_direct(path),
                fail_when=lambda sql: (
                    sql.startswith("SELECT")
                    and "FROM EVIDENCE_PUBLICATIONS" in sql
                ),
            )
        connection = _CloseAlwaysFailsConnection(real_direct(path))
        direct_wrapped.append(connection)
        return connection

    monkeypatch.setattr(
        evidence,
        "connect_ledger",
        commit_ack_failing_connect,
    )
    monkeypatch.setattr(
        evidence,
        "_connect_ledger_direct",
        confirmation_failing_connect,
    )
    try:
        with pytest.raises(
            evidence.EvidencePublicationCommitIndeterminateError
        ) as captured:
            evidence.mark_publication_group_committed(
                contexts[0]["ledger_path"],
                evidence_root=contexts[0]["evidence_root"],
                group=contexts[0]["group"],
            )
        assert captured.value.committed is None
        assert captured.value.truth == "unknown"
        assert captured.value.group == contexts[0]["group"]
        assert (
            captured.value.receipt_id
            == contexts[0]["receipt"].receipt_id
        )

        with pytest.raises(evidence.RetryEvidenceRecoveryError) as recovery:
            evidence.recover_evidence_publications(
                contexts[1]["ledger_path"],
                evidence_root=contexts[1]["evidence_root"],
            )
        assert any(
            isinstance(
                error,
                evidence.EvidencePublicationCommitIndeterminateError,
            )
            for error in _exception_tree(recovery.value)
        )
    finally:
        monkeypatch.setattr(evidence, "connect_ledger", real_connect)
        monkeypatch.setattr(
            evidence,
            "_connect_ledger_direct",
            real_direct,
        )
        for connection in direct_wrapped:
            connection.force_close()

    for context in contexts:
        connection = real_connect(context["ledger_path"])
        try:
            assert connection.execute(
                "SELECT state FROM evidence_publications"
            ).fetchall() == [("COMMITTED",)]
        finally:
            connection.close()


def test_mark_persistent_sqlite_close_failure_reports_committed_truth(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _single_publication_context(
        tmp_path=tmp_path,
        label="publication-close-failure",
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
    )
    evidence.publish_group_no_replace(
        context["ledger_path"],
        evidence_root=context["evidence_root"],
        group=context["group"],
    )
    real_connect = evidence.connect_ledger
    wrapped: list[_CloseAlwaysFailsConnection] = []

    def close_failing_connect(path: Path):
        connection = _CloseAlwaysFailsConnection(real_connect(path))
        wrapped.append(connection)
        return connection

    monkeypatch.setattr(evidence, "connect_ledger", close_failing_connect)
    try:
        with pytest.raises(
            evidence.EvidencePublicationCommittedError
        ) as captured:
            evidence.mark_publication_group_committed(
                context["ledger_path"],
                evidence_root=context["evidence_root"],
                group=context["group"],
            )
        assert captured.value.committed is True
        assert wrapped[0].close_attempts == 3
    finally:
        monkeypatch.setattr(evidence, "connect_ledger", real_connect)
        for connection in wrapped:
            connection.force_close()

    connection = real_connect(context["ledger_path"])
    try:
        assert connection.execute(
            "SELECT state FROM evidence_publications"
        ).fetchall() == [("COMMITTED",)]
    finally:
        connection.close()


def test_mark_raw_fd_close_failure_does_not_skip_other_cleanup_or_retry_fd(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _single_publication_context(
        tmp_path=tmp_path,
        label="publication-raw-close-failure",
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
    )
    evidence.publish_group_no_replace(
        context["ledger_path"],
        evidence_root=context["evidence_root"],
        group=context["group"],
    )
    pending_identity = (context["evidence_root"] / ".pending").stat()
    victim = tmp_path / "publication-close-victim"
    real_close = os.close
    real_open = os.open
    ambiguous_attempts = 0
    victim_descriptor: int | None = None

    def ambiguous_pending_close(descriptor: int) -> None:
        nonlocal ambiguous_attempts, victim_descriptor
        metadata = os.fstat(descriptor)
        if (
            ambiguous_attempts == 0
            and stat.S_ISDIR(metadata.st_mode)
            and (metadata.st_dev, metadata.st_ino)
            == (pending_identity.st_dev, pending_identity.st_ino)
        ):
            ambiguous_attempts += 1
            real_close(descriptor)
            victim_descriptor = real_open(
                victim,
                os.O_RDWR | os.O_CREAT,
                0o600,
            )
            assert victim_descriptor == descriptor
            raise OSError("ambiguous publication fd close failure")
        real_close(descriptor)

    monkeypatch.setattr(evidence.os, "close", ambiguous_pending_close)
    try:
        with pytest.raises(
            evidence.EvidencePublicationCommittedError
        ) as captured:
            evidence.mark_publication_group_committed(
                context["ledger_path"],
                evidence_root=context["evidence_root"],
                group=context["group"],
            )
        assert captured.value.committed is True
        assert ambiguous_attempts == 1
        assert victim_descriptor is not None
        os.fstat(victim_descriptor)
        probe = evidence._acquire_target_lock(context["ledger_path"])
        closed, release_errors = evidence._release_target_lock(probe)
        assert closed
        assert release_errors == ()
    finally:
        monkeypatch.setattr(evidence.os, "close", real_close)
        if victim_descriptor is not None:
            real_close(victim_descriptor)


def test_mark_lock_unlock_and_close_failures_are_both_reported(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _single_publication_context(
        tmp_path=tmp_path,
        label="publication-lock-cleanup-failure",
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
    )
    evidence.publish_group_no_replace(
        context["ledger_path"],
        evidence_root=context["evidence_root"],
        group=context["group"],
    )
    real_acquire = evidence._acquire_target_lock
    real_flock = evidence.fcntl.flock
    real_close = evidence.os.close
    lock_descriptors: set[int] = set()
    unlock_attempts = 0
    close_attempts = 0

    def tracked_acquire(path: Path) -> int:
        descriptor = real_acquire(path)
        lock_descriptors.add(descriptor)
        return descriptor

    def failing_unlock(descriptor: int, operation: int) -> None:
        nonlocal unlock_attempts
        if (
            descriptor in lock_descriptors
            and operation == evidence.fcntl.LOCK_UN
        ):
            unlock_attempts += 1
            raise OSError("publication lock unlock failure")
        real_flock(descriptor, operation)

    def failing_lock_close(descriptor: int) -> None:
        nonlocal close_attempts
        if descriptor in lock_descriptors:
            close_attempts += 1
            real_close(descriptor)
            raise OSError("publication lock close failure")
        real_close(descriptor)

    monkeypatch.setattr(evidence, "_acquire_target_lock", tracked_acquire)
    monkeypatch.setattr(evidence.fcntl, "flock", failing_unlock)
    monkeypatch.setattr(evidence.os, "close", failing_lock_close)

    with pytest.raises(
        evidence.EvidencePublicationCommittedError
    ) as captured:
        evidence.mark_publication_group_committed(
            context["ledger_path"],
            evidence_root=context["evidence_root"],
            group=context["group"],
        )

    assert captured.value.committed is True
    assert unlock_attempts == 1
    assert close_attempts == 1
    errors = _exception_tree(captured.value)
    assert any("lock unlock failure" in str(error) for error in errors)
    assert any("lock close failure" in str(error) for error in errors)


@pytest.mark.parametrize("crash_state", ["pending_only", "final_only", "both"])
def test_recover_evidence_publications_completes_each_crash_shape(
    crash_state: str,
    tmp_path: Path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    context = _single_publication_context(
        tmp_path=tmp_path,
        label=f"publication-recover-{crash_state}",
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
    )
    group = context["group"]
    payloads = {context["reference"].path: context["payload"]}
    if crash_state == "final_only":
        evidence.publish_group_no_replace(
            context["ledger_path"],
            evidence_root=context["evidence_root"],
            group=group,
        )
    elif crash_state == "both":
        for publication in group.publications:
            pending = context["evidence_root"] / publication.pending_path
            final = (
                context["evidence_root"]
                / publication.final_path.removeprefix("evidence/")
            )
            final.parent.mkdir(parents=True, exist_ok=True)
            os.link(pending, final)
            assert pending.stat().st_ino == final.stat().st_ino
            assert final.stat().st_nlink == 2
    before = _ledger_publication_snapshot(context["ledger_path"])

    evidence.recover_evidence_publications(
        context["ledger_path"],
        evidence_root=context["evidence_root"],
    )

    after = _ledger_publication_snapshot(context["ledger_path"])
    assert after[:2] == before[:2]
    assert after[3:] == before[3:]
    assert {row[-1] for row in after[2]} == {"COMMITTED"}
    for publication in group.publications:
        assert not (
            context["evidence_root"] / publication.pending_path
        ).exists()
        final = (
            context["evidence_root"]
            / publication.final_path.removeprefix("evidence/")
        )
        assert final.read_bytes() == payloads[publication.final_path]
        assert final.stat().st_nlink == 1

    evidence.recover_evidence_publications(
        context["ledger_path"],
        evidence_root=context["evidence_root"],
    )
    assert _ledger_publication_snapshot(context["ledger_path"]) == after


@pytest.mark.parametrize(
    "existing_final_shape",
    ["final_only", "both_same_inode", "both_distinct_inode"],
)
def test_recovery_fsyncs_existing_final_parent_before_cleanup_or_mark(
    existing_final_shape: str,
    tmp_path: Path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _single_publication_context(
        tmp_path=tmp_path,
        label=f"publication-existing-final-{existing_final_shape}",
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
    )
    publication = context["group"].publications[0]
    pending = context["evidence_root"] / publication.pending_path
    final = (
        context["evidence_root"]
        / publication.final_path.removeprefix("evidence/")
    )
    if existing_final_shape == "final_only":
        evidence.publish_group_no_replace(
            context["ledger_path"],
            evidence_root=context["evidence_root"],
            group=context["group"],
        )
    else:
        final.parent.mkdir(parents=True)
        if existing_final_shape == "both_same_inode":
            os.link(pending, final)
        else:
            final.write_bytes(context["payload"])
    parent_identity = final.parent.stat()
    pending_identity = (context["evidence_root"] / ".pending").stat()
    events: list[str] = []
    real_fsync = os.fsync
    real_unlink = os.unlink

    def audit_fsync(descriptor: int) -> None:
        metadata = os.fstat(descriptor)
        if (metadata.st_dev, metadata.st_ino) == (
            parent_identity.st_dev,
            parent_identity.st_ino,
        ):
            events.append("final_parent_fsync")
        real_fsync(descriptor)

    def audit_unlink(path, *args, **kwargs):
        dir_fd = kwargs.get("dir_fd")
        if dir_fd is not None:
            metadata = os.fstat(dir_fd)
            if (metadata.st_dev, metadata.st_ino) == (
                pending_identity.st_dev,
                pending_identity.st_ino,
            ):
                assert "final_parent_fsync" in events
                events.append("pending_unlink")
        return real_unlink(path, *args, **kwargs)

    monkeypatch.setattr(os, "fsync", audit_fsync)
    monkeypatch.setattr(os, "unlink", audit_unlink)

    evidence.recover_evidence_publications(
        context["ledger_path"],
        evidence_root=context["evidence_root"],
    )

    assert "final_parent_fsync" in events
    if existing_final_shape != "final_only":
        assert events.index("final_parent_fsync") < events.index(
            "pending_unlink"
        )


def test_recovery_final_parent_fsync_failure_preserves_pending_and_committing(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _single_publication_context(
        tmp_path=tmp_path,
        label="publication-existing-final-fsync-failure",
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
    )
    publication = context["group"].publications[0]
    pending = context["evidence_root"] / publication.pending_path
    final = (
        context["evidence_root"]
        / publication.final_path.removeprefix("evidence/")
    )
    final.parent.mkdir(parents=True)
    os.link(pending, final)
    parent_identity = final.parent.stat()
    real_fsync = os.fsync

    def fail_final_parent_fsync(descriptor: int) -> None:
        metadata = os.fstat(descriptor)
        if (metadata.st_dev, metadata.st_ino) == (
            parent_identity.st_dev,
            parent_identity.st_ino,
        ):
            raise OSError("injected final parent fsync failure")
        real_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", fail_final_parent_fsync)

    with pytest.raises(evidence.RetryEvidenceRecoveryError):
        evidence.recover_evidence_publications(
            context["ledger_path"],
            evidence_root=context["evidence_root"],
        )

    assert pending.exists()
    assert final.exists()
    assert pending.stat().st_ino == final.stat().st_ino
    connection = connect_ledger(context["ledger_path"])
    try:
        assert connection.execute(
            "SELECT state FROM evidence_publications"
        ).fetchall() == [("COMMITTING",)]
    finally:
        connection.close()


def test_recover_evidence_publications_blocks_missing_and_committed_tamper(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    episode = _retry_episode(
        tmp_path=tmp_path,
        label="publication-recover-block",
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
    )
    receipt, payloads = _two_publication_candidate(
        episode,
        ephemeral_role_keys,
    )
    group = evidence.stage_pending_evidence_group(
        episode["ledger_path"],
        evidence_root=episode["evidence_root"],
        receipt=receipt,
        payloads=payloads,
    )
    _commit_publication_candidate_for_test(
        episode["ledger_path"],
        receipt,
        group,
    )
    missing = episode["evidence_root"] / group.publications[0].pending_path
    missing.unlink()
    before = _ledger_publication_snapshot(episode["ledger_path"])

    with pytest.raises(evidence.RetryEvidenceRecoveryError) as caught:
        evidence.recover_evidence_publications(
            episode["ledger_path"],
            evidence_root=episode["evidence_root"],
        )

    assert caught.value.code == "RECOVERY_REQUIRED"
    assert _ledger_publication_snapshot(episode["ledger_path"]) == before


def test_recovery_cleans_rowless_but_preserves_journaled_pending_on_conflict(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    context = _single_publication_context(
        tmp_path=tmp_path,
        label="publication-rowless",
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
    )
    pending_root = context["evidence_root"] / ".pending"
    rowless = pending_root / ("e" * 64)
    rowless.write_bytes(b"orphan")
    journaled = pending_root / context["group"].publications[0].publication_id
    final = (
        context["evidence_root"]
        / context["reference"].path.removeprefix("evidence/")
    )
    final.parent.mkdir(parents=True)
    final.write_bytes(b"conflict")

    with pytest.raises(evidence.RetryEvidenceRecoveryError):
        evidence.recover_evidence_publications(
            context["ledger_path"],
            evidence_root=context["evidence_root"],
        )

    assert not rowless.exists()
    assert journaled.read_bytes() == context["payload"]
    assert final.read_bytes() == b"conflict"


def test_recovery_missing_entire_journal_group_preserves_all_pending(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    context = _single_publication_context(
        tmp_path=tmp_path,
        label="publication-missing-journal-group",
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
    )
    pending_root = context["evidence_root"] / ".pending"
    journal_pending = (
        pending_root / context["group"].publications[0].publication_id
    )
    rowless = pending_root / ("d" * 64)
    rowless.write_bytes(b"rowless-must-wait-for-coverage-gate")
    connection = connect_ledger(context["ledger_path"])
    try:
        connection.execute("DELETE FROM evidence_publications")
    finally:
        connection.close()
    before = _ledger_publication_snapshot(context["ledger_path"])

    with pytest.raises(evidence.RetryEvidenceRecoveryError):
        evidence.recover_evidence_publications(
            context["ledger_path"],
            evidence_root=context["evidence_root"],
        )

    assert _ledger_publication_snapshot(context["ledger_path"]) == before
    assert journal_pending.read_bytes() == context["payload"]
    assert rowless.read_bytes() == b"rowless-must-wait-for-coverage-gate"


def test_recovery_rejects_escaping_pending_basename_without_deleting_victim(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    context = _single_publication_context(
        tmp_path=tmp_path,
        label="publication-escaping-pending",
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
    )
    evidence.publish_group_no_replace(
        context["ledger_path"],
        evidence_root=context["evidence_root"],
        group=context["group"],
    )
    victim = tmp_path / "victim-copy"
    victim.write_bytes(context["payload"])
    connection = connect_ledger(context["ledger_path"])
    try:
        connection.execute(
            """
            UPDATE evidence_publications
            SET publication_id = '../../victim-copy',
                pending_path = '.pending/../../victim-copy'
            """
        )
    finally:
        connection.close()

    with pytest.raises(evidence.RetryEvidenceRecoveryError):
        evidence.recover_evidence_publications(
            context["ledger_path"],
            evidence_root=context["evidence_root"],
        )

    assert victim.read_bytes() == context["payload"]


def test_recovery_rejects_committed_leftover_pending_and_mixed_group_state(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    context = _single_publication_context(
        tmp_path=tmp_path,
        label="publication-committed-pending",
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
    )
    evidence.recover_evidence_publications(
        context["ledger_path"],
        evidence_root=context["evidence_root"],
    )
    pending = (
        context["evidence_root"]
        / context["group"].publications[0].pending_path
    )
    pending.write_bytes(context["payload"])
    with pytest.raises(evidence.RetryEvidenceRecoveryError):
        evidence.recover_evidence_publications(
            context["ledger_path"],
            evidence_root=context["evidence_root"],
        )
    assert pending.exists()

    episode = _retry_episode(
        tmp_path=tmp_path,
        label="publication-mixed-state",
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
    )
    receipt, payloads = _two_publication_candidate(
        episode,
        ephemeral_role_keys,
    )
    group = evidence.stage_pending_evidence_group(
        episode["ledger_path"],
        evidence_root=episode["evidence_root"],
        receipt=receipt,
        payloads=payloads,
    )
    _commit_publication_candidate_for_test(
        episode["ledger_path"],
        receipt,
        group,
    )
    connection = connect_ledger(episode["ledger_path"])
    try:
        connection.execute(
            """
            UPDATE evidence_publications SET state = 'COMMITTED'
            WHERE publication_id = ?
            """,
            (group.publications[0].publication_id,),
        )
    finally:
        connection.close()
    before = _ledger_publication_snapshot(episode["ledger_path"])
    with pytest.raises(evidence.RetryEvidenceRecoveryError):
        evidence.recover_evidence_publications(
            episode["ledger_path"],
            evidence_root=episode["evidence_root"],
        )
    assert _ledger_publication_snapshot(episode["ledger_path"]) == before


def test_recovery_rehashes_committed_final_and_blocks_tamper(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    context = _single_publication_context(
        tmp_path=tmp_path,
        label="publication-committed-tamper",
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
    )
    evidence.recover_evidence_publications(
        context["ledger_path"],
        evidence_root=context["evidence_root"],
    )
    final = (
        context["evidence_root"]
        / context["reference"].path.removeprefix("evidence/")
    )
    final.write_bytes(b"tampered")
    before = _ledger_publication_snapshot(context["ledger_path"])

    with pytest.raises(evidence.RetryEvidenceRecoveryError):
        evidence.recover_evidence_publications(
            context["ledger_path"],
            evidence_root=context["evidence_root"],
        )

    assert _ledger_publication_snapshot(context["ledger_path"]) == before
    assert before[2][0][-1] == "COMMITTED"


def test_two_concurrent_recoveries_serialize_and_converge(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    context = _single_publication_context(
        tmp_path=tmp_path,
        label="publication-concurrent-recover",
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
    )
    start = threading.Barrier(2)

    def recover() -> None:
        start.wait()
        evidence.recover_evidence_publications(
            context["ledger_path"],
            evidence_root=context["evidence_root"],
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(recover) for _ in range(2)]
        for future in futures:
            future.result()

    connection = connect_ledger(context["ledger_path"])
    try:
        assert connection.execute(
            "SELECT state FROM evidence_publications"
        ).fetchall() == [("COMMITTED",)]
    finally:
        connection.close()


def test_recovery_rejects_intermediate_symlink_and_midcall_directory_rename(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _single_publication_context(
        tmp_path=tmp_path,
        label="publication-namespace-symlink",
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
    )
    outside = tmp_path / "outside"
    outside.mkdir()
    parent = (
        context["evidence_root"]
        / context["reference"].path.removeprefix("evidence/")
    ).parent
    parent.symlink_to(outside, target_is_directory=True)
    with pytest.raises(evidence.RetryEvidenceRecoveryError):
        evidence.recover_evidence_publications(
            context["ledger_path"],
            evidence_root=context["evidence_root"],
        )
    assert not tuple(outside.iterdir())

    renamed = _single_publication_context(
        tmp_path=tmp_path,
        label="publication-namespace-rename",
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
    )
    final = (
        renamed["evidence_root"]
        / renamed["reference"].path.removeprefix("evidence/")
    )
    moved_parent = renamed["evidence_root"] / "moved-parent"
    real_link = os.link
    swapped = False

    def swap_parent_then_link(*args, **kwargs):
        nonlocal swapped
        if not swapped:
            swapped = True
            final.parent.rename(moved_parent)
            final.parent.mkdir()
        return real_link(*args, **kwargs)

    monkeypatch.setattr(os, "link", swap_parent_then_link)
    with pytest.raises(evidence.RetryEvidenceRecoveryError):
        evidence.publish_group_no_replace(
            renamed["ledger_path"],
            evidence_root=renamed["evidence_root"],
            group=renamed["group"],
        )
    assert not final.exists()
    assert not (moved_parent / final.name).exists()
    pending = (
        renamed["evidence_root"]
        / renamed["group"].publications[0].pending_path
    )
    assert pending.read_bytes() == renamed["payload"]
    assert pending.stat().st_nlink == 1
    connection = connect_ledger(renamed["ledger_path"])
    try:
        assert connection.execute(
            "SELECT state FROM evidence_publications"
        ).fetchall() == [("COMMITTING",)]
    finally:
        connection.close()


def test_recovery_mark_reuses_outer_anchor_across_root_swap(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _single_publication_context(
        tmp_path=tmp_path,
        label="publication-recovery-mark-root-swap",
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
    )
    root = context["evidence_root"]
    moved_root = tmp_path / "publication-recovery-mark-moved"
    substitute_root = tmp_path / "publication-recovery-mark-substitute"
    retired_substitute = tmp_path / "publication-recovery-mark-retired"
    relative_final = context["reference"].path.removeprefix("evidence/")
    substitute_final = substitute_root / relative_final
    substitute_final.parent.mkdir(parents=True)
    substitute_final.write_bytes(context["payload"])
    (substitute_root / ".pending").mkdir(mode=0o700)
    tampered_payload = bytearray(context["payload"])
    tampered_payload[0] ^= 1
    real_mark = evidence._mark_group_committed_locked
    swapped = False

    def swap_mark_restore(connection, **kwargs) -> None:
        nonlocal swapped
        assert not swapped
        swapped = True
        root.rename(moved_root)
        substitute_root.rename(root)
        moved_final = moved_root / relative_final
        moved_final.write_bytes(bytes(tampered_payload))
        try:
            real_mark(connection, **kwargs)
        finally:
            root.rename(retired_substitute)
            moved_root.rename(root)

    monkeypatch.setattr(
        evidence,
        "_mark_group_committed_locked",
        swap_mark_restore,
    )

    with pytest.raises(evidence.RetryEvidenceRecoveryError):
        evidence.recover_evidence_publications(
            context["ledger_path"],
            evidence_root=root,
        )

    assert swapped
    assert (root / relative_final).read_bytes() == bytes(tampered_payload)
    connection = connect_ledger(context["ledger_path"])
    try:
        assert connection.execute(
            "SELECT state FROM evidence_publications"
        ).fetchall() == [("COMMITTING",)]
    finally:
        connection.close()


def test_recovery_rejects_named_root_replacement_before_commit(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _single_publication_context(
        tmp_path=tmp_path,
        label="publication-named-root-pre-commit",
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
    )
    root = context["evidence_root"]
    moved_root = tmp_path / "publication-named-root-pre-moved"
    substitute_root = tmp_path / "publication-named-root-pre-substitute"
    retired_substitute = tmp_path / "publication-named-root-pre-retired"
    substitute_root.mkdir()
    real_require = evidence._require_group_finals_on_anchor
    require_calls = 0
    swapped = False

    def swap_after_precommit_validation(**kwargs) -> None:
        nonlocal require_calls, swapped
        real_require(**kwargs)
        require_calls += 1
        if require_calls == 1:
            root.rename(moved_root)
            substitute_root.rename(root)
            swapped = True

    monkeypatch.setattr(
        evidence,
        "_require_group_finals_on_anchor",
        swap_after_precommit_validation,
    )

    try:
        with pytest.raises(evidence.RetryEvidenceRecoveryError):
            evidence.recover_evidence_publications(
                context["ledger_path"],
                evidence_root=root,
            )
    finally:
        if swapped:
            root.rename(retired_substitute)
            moved_root.rename(root)

    assert require_calls >= 1
    connection = connect_ledger(context["ledger_path"])
    try:
        assert connection.execute(
            "SELECT state FROM evidence_publications"
        ).fetchall() == [("COMMITTING",)]
    finally:
        connection.close()


def test_mark_reports_unverified_commit_after_postcommit_root_replacement(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _single_publication_context(
        tmp_path=tmp_path,
        label="publication-named-root-post-commit",
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
    )
    evidence.publish_group_no_replace(
        context["ledger_path"],
        evidence_root=context["evidence_root"],
        group=context["group"],
    )
    root = context["evidence_root"]
    moved_root = tmp_path / "publication-named-root-post-moved"
    substitute_root = tmp_path / "publication-named-root-post-substitute"
    retired_substitute = tmp_path / "publication-named-root-post-retired"
    substitute_root.mkdir()
    real_require = evidence._require_group_finals_on_anchor
    require_calls = 0
    swapped = False

    def swap_after_postcommit_validation(**kwargs) -> None:
        nonlocal require_calls, swapped
        real_require(**kwargs)
        require_calls += 1
        if require_calls == 2:
            root.rename(moved_root)
            substitute_root.rename(root)
            swapped = True

    monkeypatch.setattr(
        evidence,
        "_require_group_finals_on_anchor",
        swap_after_postcommit_validation,
    )

    try:
        with pytest.raises(
            evidence.EvidencePublicationCommittedError
        ) as captured:
            evidence.mark_publication_group_committed(
                context["ledger_path"],
                evidence_root=root,
                group=context["group"],
            )
    finally:
        if swapped:
            root.rename(retired_substitute)
            moved_root.rename(root)

    assert require_calls == 2
    assert captured.value.committed is True
    assert captured.value.evidence_verified is False
    connection = connect_ledger(context["ledger_path"])
    try:
        assert connection.execute(
            "SELECT state FROM evidence_publications"
        ).fetchall() == [("COMMITTED",)]
    finally:
        connection.close()


def test_stage_namespace_failure_does_not_leak_file_descriptors(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    episode = _retry_episode(
        tmp_path=tmp_path,
        label="publication-fd-leak",
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
    )
    receipt = _publication_candidate(episode, sidecar_receipt_factory)
    payload = _verifier_result_payload(receipt)
    reference = receipt.evidence_refs[0]
    outside = tmp_path / "pending-outside"
    outside.mkdir()
    (episode["evidence_root"] / ".pending").symlink_to(
        outside,
        target_is_directory=True,
    )
    before = len(os.listdir("/dev/fd"))

    for _ in range(20):
        with pytest.raises(OSError):
            evidence.stage_pending_evidence_group(
                episode["ledger_path"],
                evidence_root=episode["evidence_root"],
                receipt=receipt,
                payloads={reference.path: payload},
            )

    assert len(os.listdir("/dev/fd")) <= before + 1


def _single_publication_context(
    *,
    tmp_path: Path,
    label: str,
    work_order: WorkOrder,
    root: CapabilityGrant,
    role_keys,
    now: datetime,
    sidecar_receipt_factory,
):
    ledger_path = tmp_path / f"{label}.sqlite3"
    evidence_root = tmp_path / f"{label}-evidence"
    evidence_root.mkdir()
    _activate_ledger_root(
        ledger_path,
        work_order,
        root,
        role_keys,
        now,
    )
    receipts, _, _ = _grant_replay_inputs(ledger_path, work_order)
    root_receipt = receipts[0]
    receipt = sidecar_receipt_factory(
        state_before="running",
        state_after="running",
        event_type="tool_call",
        actor_role="Verifier",
        sequence=2,
        previous_receipt_digest=root_receipt.digest,
        parent_receipt_ids=(root_receipt.receipt_id,),
        occurred_at="2026-01-01T00:00:05Z",
        test_passed=False,
    )
    payload = _verifier_result_payload(receipt)
    reference = receipt.evidence_refs[0]
    group = evidence.stage_pending_evidence_group(
        ledger_path,
        evidence_root=evidence_root,
        receipt=receipt,
        payloads={reference.path: payload},
    )
    _commit_publication_candidate_for_test(ledger_path, receipt, group)
    return {
        "ledger_path": ledger_path,
        "evidence_root": evidence_root,
        "receipt": receipt,
        "payload": payload,
        "reference": reference,
        "group": group,
    }


def _authoritative_publication_context(
    *,
    tmp_path: Path,
    label: str,
    work_order: WorkOrder,
    root: CapabilityGrant,
    role_keys,
    now: datetime,
    sidecar_receipt_factory,
):
    context, receipt, group, payload = (
        _staged_retrying_verifier_candidate(
            tmp_path=tmp_path,
            work_order=work_order,
            root=root,
            role_keys=role_keys,
            fixed_now=now,
            sidecar_receipt_factory=sidecar_receipt_factory,
            label=label,
        )
    )
    evidence.commit_receipt_with_publications(
        context["ledger_path"],
        evidence_root=context["evidence_root"],
        receipt=receipt,
        group=group,
        clock=lambda: now,
    )
    return {
        **context,
        "receipt": receipt,
        "payload": payload,
        "reference": receipt.evidence_refs[0],
        "group": group,
    }


def test_empty_journal_recovery_creates_and_fsyncs_pending_directory(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ledger_path = tmp_path / "publication-empty-recovery.sqlite3"
    evidence_root = tmp_path / "publication-empty-recovery-evidence"
    evidence_root.mkdir()
    _activate_ledger_root(
        ledger_path,
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        fixed_now,
    )
    root_identity = evidence_root.stat()
    real_fsync = os.fsync
    root_fsyncs = 0

    def audit_root_fsync(descriptor: int) -> None:
        nonlocal root_fsyncs
        metadata = os.fstat(descriptor)
        if (metadata.st_dev, metadata.st_ino) == (
            root_identity.st_dev,
            root_identity.st_ino,
        ):
            root_fsyncs += 1
        real_fsync(descriptor)

    monkeypatch.setattr(evidence.os, "fsync", audit_root_fsync)

    evidence.recover_evidence_publications(
        ledger_path,
        evidence_root=evidence_root,
    )

    pending = evidence_root / ".pending"
    assert pending.is_dir()
    assert stat.S_IMODE(pending.stat().st_mode) == 0o700
    assert root_fsyncs >= 1


def test_empty_journal_require_treats_missing_pending_directory_as_empty(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
) -> None:
    ledger_path = tmp_path / "publication-empty-require.sqlite3"
    evidence_root = tmp_path / "publication-empty-require-evidence"
    evidence_root.mkdir()
    _activate_ledger_root(
        ledger_path,
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        fixed_now,
    )

    evidence.require_all_publications_committed(
        ledger_path,
        evidence_root=evidence_root,
    )

    assert not (evidence_root / ".pending").exists()


def test_require_all_publications_committed_is_read_only_and_rehashes_final(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    context = _authoritative_publication_context(
        tmp_path=tmp_path,
        label="publication-require",
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
    )
    evidence.publish_group_no_replace(
        context["ledger_path"],
        evidence_root=context["evidence_root"],
        group=context["group"],
    )
    evidence.mark_publication_group_committed(
        context["ledger_path"],
        evidence_root=context["evidence_root"],
        group=context["group"],
    )
    before = _ledger_publication_snapshot(context["ledger_path"])

    assert (
        evidence.require_all_publications_committed(
            context["ledger_path"],
            evidence_root=context["evidence_root"],
        )
        is None
    )

    assert _ledger_publication_snapshot(context["ledger_path"]) == before


def test_require_all_publications_committed_rejects_committing_and_tamper(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    context = _authoritative_publication_context(
        tmp_path=tmp_path,
        label="publication-require-block",
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
    )
    with pytest.raises(evidence.RetryEvidenceRecoveryError):
        evidence.require_all_publications_committed(
            context["ledger_path"],
            evidence_root=context["evidence_root"],
        )
    evidence.recover_evidence_publications(
        context["ledger_path"],
        evidence_root=context["evidence_root"],
    )
    final = (
        context["evidence_root"]
        / context["reference"].path.removeprefix("evidence/")
    )
    final.write_bytes(b"tampered")

    with pytest.raises(evidence.RetryEvidenceRecoveryError):
        evidence.require_all_publications_committed(
            context["ledger_path"],
            evidence_root=context["evidence_root"],
        )


@pytest.mark.parametrize("journal_shape", ["missing", "extra"])
def test_require_all_publications_committed_rejects_missing_or_extra_rows(
    journal_shape: str,
    tmp_path: Path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    context = _authoritative_publication_context(
        tmp_path=tmp_path,
        label=f"publication-require-{journal_shape}",
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
    )
    evidence.recover_evidence_publications(
        context["ledger_path"],
        evidence_root=context["evidence_root"],
    )
    connection = connect_ledger(context["ledger_path"])
    try:
        if journal_shape == "missing":
            connection.execute("DELETE FROM evidence_publications")
        else:
            root_receipt_id = connection.execute(
                "SELECT receipt_id FROM receipts ORDER BY sequence LIMIT 1"
            ).fetchone()[0]
            extra_id = _grant_id("publication-extra-row")
            connection.execute(
                """
                INSERT INTO evidence_publications (
                    publication_id, receipt_id, pending_path, final_path,
                    digest, size_bytes, media_type, state
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, 'COMMITTED')
                """,
                (
                    extra_id,
                    root_receipt_id,
                    f".pending/{extra_id}",
                    "evidence/patch-input/02.diff",
                    hashlib.sha256(b"x").hexdigest(),
                    1,
                    "text/x-diff",
                ),
            )
    finally:
        connection.close()

    with pytest.raises(evidence.RetryEvidenceRecoveryError):
        evidence.require_all_publications_committed(
            context["ledger_path"],
            evidence_root=context["evidence_root"],
        )


def _rewrite_retry_failure_argument(
    episode,
    *,
    field: str,
    value: str,
    role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
) -> None:
    failure_raw = episode["failure"].model_dump(mode="json")
    failure_raw["request_arguments"][field] = value
    if field == "fixed_test_source_digest":
        failure_raw["correlation_factors"][field] = value
    failure_raw["arguments_digest"] = evidence.request_arguments_digest(
        "owp.run_tests",
        failure_raw["request_arguments"],
    )
    failure_claim = failure_raw["nested_claim"]
    failure_claim["arguments_digest"] = failure_raw["arguments_digest"]
    failure_claim = sign_payload(
        "agent-request",
        failure_claim,
        role_keys["Verifier"][0],
    )
    failure_raw["nested_claim"] = failure_claim
    failure_raw["nested_claim_digest"] = failure_claim["digest"]
    failure = evidence.ACTION_RECEIPT_ADAPTER.validate_python(
        sign_payload(
            "action-receipt",
            failure_raw,
            role_keys["Sidecar"][0],
        )
    )
    rollback_raw = episode["rollback"].model_dump(mode="json")
    rollback_raw["previous_receipt_digest"] = failure.digest
    rollback = evidence.ACTION_RECEIPT_ADAPTER.validate_python(
        sign_payload(
            "action-receipt",
            rollback_raw,
            role_keys["Sidecar"][0],
        )
    )
    connection = connect_ledger(episode["ledger_path"])
    try:
        for receipt in (failure, rollback):
            connection.execute(
                """
                UPDATE receipts
                SET previous_digest = ?, receipt_json = ?
                WHERE receipt_id = ?
                """,
                (
                    receipt.previous_receipt_digest,
                    _canonical_json(receipt.model_dump(mode="json")),
                    receipt.receipt_id,
                ),
            )
    finally:
        connection.close()
    episode.update({"failure": failure, "rollback": rollback})


def test_start_retry_atomically_consumes_last_root_repair_round(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    episode = _retry_episode(
        tmp_path=tmp_path,
        label="retry-success",
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
    )
    request = _retry_request(
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        nonce=_grant_id("retry-success:request"),
    )

    receipt = evidence.start_retry(
        episode["ledger_path"],
        request=request,
        sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
        evidence_root=episode["evidence_root"],
        clock=lambda: fixed_now,
    )

    assert receipt.policy_decision == "allow"
    assert receipt.execution_status == "succeeded"
    assert receipt.state_before == "needs_rework"
    assert receipt.state_after == "retrying"
    assert receipt.remaining_after == 0
    assert receipt.quota_charge.model_dump(mode="json") == {
        "grant_id": signed_root_grant.grant_id,
        "metric": "repair_rounds",
        "amount": 1,
        "remaining_after": 0,
    }
    assert receipt.parent_receipt_ids == (
        episode["root_issuance"].receipt_id,
        episode["failure"].receipt_id,
        episode["rollback"].receipt_id,
    )
    assert receipt.parent_receipt_ids != tuple(
        sorted(receipt.parent_receipt_ids)
    )
    assert receipt.previous_receipt_digest == episode["rollback"].digest
    connection = connect_ledger(episode["ledger_path"])
    try:
        assert tuple(
            row[1]
            for row in connection.execute(
                "PRAGMA table_info(evidence_publications)"
            ).fetchall()
        ) == (
            "publication_id",
            "receipt_id",
            "pending_path",
            "final_path",
            "digest",
            "size_bytes",
            "media_type",
            "state",
        )
        assert connection.execute(
            "SELECT current_state, version FROM work_order_state"
        ).fetchone() == ("retrying", 7)
        assert connection.execute(
            "SELECT next_sequence FROM sequence_counter"
        ).fetchone() == (8,)
        assert connection.execute(
            """
            SELECT grant_id, event_type, metric, amount
            FROM grant_events
            WHERE receipt_id = ?
            """,
            (receipt.receipt_id,),
        ).fetchone() == (
            signed_root_grant.grant_id,
            "grant_consumed",
            "repair_rounds",
            1,
        )
    finally:
        connection.close()


def test_start_retry_rejects_all_pass_verifier_failure_without_writes(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    episode = _retry_episode(
        tmp_path=tmp_path,
        label="retry-all-pass-failure",
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
        failure_test_passed=True,
    )
    connection = connect_ledger(episode["ledger_path"])
    try:
        before = _ledger_integrity_snapshot(connection)
    finally:
        connection.close()

    with pytest.raises(evidence.RetryEvidenceIntegrityError):
        evidence.start_retry(
            episode["ledger_path"],
            request=_retry_request(
                signed_work_order,
                signed_root_grant,
                ephemeral_role_keys,
                nonce=_grant_id("retry-all-pass-failure:request"),
            ),
            sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
            evidence_root=episode["evidence_root"],
            clock=lambda: fixed_now,
        )
    connection = connect_ledger(episode["ledger_path"])
    try:
        assert _ledger_integrity_snapshot(connection) == before
    finally:
        connection.close()


def test_start_retry_authenticated_developer_child_appends_role_denial(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    episode = _retry_episode(
        tmp_path=tmp_path,
        label="retry-role-denial",
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
    )
    denied = evidence.start_retry(
        episode["ledger_path"],
        request=_retry_request(
            signed_work_order,
            signed_root_grant,
            ephemeral_role_keys,
            nonce=_grant_id("retry-role-denial:request"),
            actor_role="Developer",
            grant_id=episode["developer"].grant_id,
        ),
        sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
        evidence_root=episode["evidence_root"],
        clock=lambda: fixed_now,
    )

    assert denied.grant_id == episode["developer"].grant_id
    assert denied.policy_decision == "deny"
    assert denied.execution_status == "denied"
    assert denied.policy_error_code == "ROLE_DENIED"
    assert denied.state_before == denied.state_after == "needs_rework"
    assert denied.remaining_after is None
    assert denied.quota_charge is None
    assert denied.parent_receipt_ids == (
        episode["developer_issuance"].receipt_id,
        episode["failure"].receipt_id,
        episode["rollback"].receipt_id,
    )
    connection = connect_ledger(episode["ledger_path"])
    try:
        assert tuple(
            row[0]
            for row in connection.execute(
                """
                SELECT parent.parent_receipt_id
                FROM receipt_parents AS parent
                JOIN receipts AS receipt
                  ON receipt.receipt_id = parent.parent_receipt_id
                WHERE parent.child_receipt_id = ?
                ORDER BY receipt.sequence
                """,
                (denied.receipt_id,),
            ).fetchall()
        ) == denied.parent_receipt_ids
        assert connection.execute(
            "SELECT current_state, version FROM work_order_state"
        ).fetchone() == ("needs_rework", 7)
        assert connection.execute(
            "SELECT next_sequence FROM sequence_counter"
        ).fetchone() == (8,)
        assert connection.execute(
            "SELECT COUNT(*) FROM grant_events WHERE receipt_id = ?",
            (denied.receipt_id,),
        ).fetchone() == (0,)
    finally:
        connection.close()


def test_start_retry_state_denial_precedes_role_denial_for_developer_child(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    episode = _retry_episode(
        tmp_path=tmp_path,
        label="retry-child-state-denial",
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
    )
    allowed = evidence.start_retry(
        episode["ledger_path"],
        request=_retry_request(
            signed_work_order,
            signed_root_grant,
            ephemeral_role_keys,
            nonce=_grant_id("retry-child-state-denial:allow"),
        ),
        sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
        evidence_root=episode["evidence_root"],
        clock=lambda: fixed_now,
    )
    denied = evidence.start_retry(
        episode["ledger_path"],
        request=_retry_request(
            signed_work_order,
            signed_root_grant,
            ephemeral_role_keys,
            nonce=_grant_id("retry-child-state-denial:deny"),
            actor_role="Developer",
            grant_id=episode["developer"].grant_id,
        ),
        sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
        evidence_root=episode["evidence_root"],
        clock=lambda: fixed_now,
    )

    assert denied.grant_id == episode["developer"].grant_id
    assert denied.policy_decision == "deny"
    assert denied.execution_status == "denied"
    assert denied.policy_error_code == "STATE_DENIED"
    assert denied.state_before == denied.state_after == "retrying"
    assert denied.remaining_after is None
    assert denied.quota_charge is None
    assert denied.parent_receipt_ids == (
        episode["developer_issuance"].receipt_id,
        episode["failure"].receipt_id,
        episode["rollback"].receipt_id,
        allowed.receipt_id,
    )
    connection = connect_ledger(episode["ledger_path"])
    try:
        assert tuple(
            row[0]
            for row in connection.execute(
                """
                SELECT parent.parent_receipt_id
                FROM receipt_parents AS parent
                JOIN receipts AS receipt
                  ON receipt.receipt_id = parent.parent_receipt_id
                WHERE parent.child_receipt_id = ?
                ORDER BY receipt.sequence
                """,
                (denied.receipt_id,),
            ).fetchall()
        ) == denied.parent_receipt_ids
        assert connection.execute(
            "SELECT current_state, version FROM work_order_state"
        ).fetchone() == ("retrying", 8)
        assert connection.execute(
            "SELECT next_sequence FROM sequence_counter"
        ).fetchone() == (9,)
        assert connection.execute(
            "SELECT COUNT(*) FROM grant_events WHERE receipt_id = ?",
            (denied.receipt_id,),
        ).fetchone() == (0,)
    finally:
        connection.close()


@pytest.mark.parametrize(
    ("field", "invalid_value"),
    (
        ("command_digest", "0" * 64),
        ("source_commit", "3" * 40),
        ("container_image_digest", f"sha256:{'0' * 64}"),
        ("fixed_test_source_digest", "0" * 64),
    ),
)
def test_start_retry_rejects_failure_outside_fixed_verifier_profile_without_writes(
    tmp_path: Path,
    field: str,
    invalid_value: str,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    episode = _retry_episode(
        tmp_path=tmp_path,
        label=f"retry-verifier-profile-{field}",
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
    )
    assert (
        getattr(episode["failure"].request_arguments, field)
        != invalid_value
    )
    _rewrite_retry_failure_argument(
        episode,
        field=field,
        value=invalid_value,
        role_keys=ephemeral_role_keys,
    )
    connection = connect_ledger(episode["ledger_path"])
    try:
        before = _ledger_integrity_snapshot(connection)
    finally:
        connection.close()

    with pytest.raises(evidence.RetryEvidenceIntegrityError):
        evidence.start_retry(
            episode["ledger_path"],
            request=_retry_request(
                signed_work_order,
                signed_root_grant,
                ephemeral_role_keys,
                nonce=_grant_id(f"retry-verifier-profile-{field}:request"),
            ),
            sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
            evidence_root=episode["evidence_root"],
            clock=lambda: fixed_now,
        )
    connection = connect_ledger(episode["ledger_path"])
    try:
        assert _ledger_integrity_snapshot(connection) == before
    finally:
        connection.close()


@pytest.mark.parametrize(
    "result_path",
    (
        "evidence/verifier-result/01.json",
        "evidence/patch-result/02.json",
    ),
)
def test_start_retry_rejects_patch_result_in_wrong_work_order_slot_without_writes(
    tmp_path: Path,
    result_path: str,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    episode = _retry_episode(
        tmp_path=tmp_path,
        label=f"retry-slot-{result_path.split('/')[-2]}",
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
    )
    _move_retry_patch_result_ref(
        episode,
        new_path=result_path,
        role_keys=ephemeral_role_keys,
    )
    connection = connect_ledger(episode["ledger_path"])
    try:
        before = _ledger_integrity_snapshot(connection)
    finally:
        connection.close()

    with pytest.raises(evidence.RetryEvidenceIntegrityError):
        evidence.start_retry(
            episode["ledger_path"],
            request=_retry_request(
                signed_work_order,
                signed_root_grant,
                ephemeral_role_keys,
                nonce=_grant_id(f"retry-slot-{result_path}:request"),
            ),
            sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
            evidence_root=episode["evidence_root"],
            clock=lambda: fixed_now,
        )
    connection = connect_ledger(episode["ledger_path"])
    try:
        assert _ledger_integrity_snapshot(connection) == before
    finally:
        connection.close()


@pytest.mark.parametrize("replacement_kind", ("directory", "symlink"))
def test_start_retry_rejects_changed_intermediate_evidence_namespace_without_writes(
    tmp_path: Path,
    replacement_kind: str,
    monkeypatch: pytest.MonkeyPatch,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    episode = _retry_episode(
        tmp_path=tmp_path,
        label="retry-directory-race",
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
    )
    trusted_directory = episode["evidence_root"] / "patch-result"
    renamed_directory = episode["evidence_root"] / "patch-result-trusted"
    outside_directory = tmp_path / "outside-evidence"
    outside_directory.mkdir()
    outside_file = outside_directory / "01.json"
    trusted_bytes = episode["final_path"].read_bytes()
    outside_file.write_bytes(trusted_bytes)
    connection = connect_ledger(episode["ledger_path"])
    try:
        before = _ledger_integrity_snapshot(connection)
    finally:
        connection.close()
    original_open = evidence.os.open
    swapped = False

    def replace_canonical_directory() -> None:
        trusted_directory.rename(renamed_directory)
        if replacement_kind == "symlink":
            trusted_directory.symlink_to(outside_directory)
        else:
            trusted_directory.mkdir()
            (trusted_directory / "01.json").write_bytes(
                b"x" * len(trusted_bytes)
            )

    def racing_open(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal swapped
        path_value = os.fspath(path)
        if (
            not swapped
            and path_value == "patch-result"
            and dir_fd is not None
        ):
            descriptor = original_open(
                path,
                flags,
                mode,
                dir_fd=dir_fd,
            )
            replace_canonical_directory()
            swapped = True
            return descriptor
        if not swapped and Path(path_value) == episode["final_path"]:
            replace_canonical_directory()
            swapped = True
        return original_open(
            path,
            flags,
            mode,
            dir_fd=dir_fd,
        )

    monkeypatch.setattr(evidence.os, "open", racing_open)
    with pytest.raises(evidence.RetryEvidenceIntegrityError):
        evidence.start_retry(
            episode["ledger_path"],
            request=_retry_request(
                signed_work_order,
                signed_root_grant,
                ephemeral_role_keys,
                nonce=_grant_id(
                    f"retry-directory-race:{replacement_kind}:request"
                ),
            ),
            sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
            evidence_root=episode["evidence_root"],
            clock=lambda: fixed_now,
        )

    assert swapped
    connection = connect_ledger(episode["ledger_path"])
    try:
        assert _ledger_integrity_snapshot(connection) == before
    finally:
        connection.close()


def test_start_retry_closes_pinned_evidence_descriptors_when_read_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    episode = _retry_episode(
        tmp_path=tmp_path,
        label="retry-read-failure",
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
    )
    connection = connect_ledger(episode["ledger_path"])
    try:
        before = _ledger_integrity_snapshot(connection)
    finally:
        connection.close()
    original_open = evidence.os.open
    original_close = evidence.os.close
    opened_descriptors: set[int] = set()
    closed_descriptors: set[int] = set()

    def tracking_open(path, flags, mode=0o777, *, dir_fd=None):
        descriptor = original_open(
            path,
            flags,
            mode,
            dir_fd=dir_fd,
        )
        opened_descriptors.add(descriptor)
        return descriptor

    def tracking_close(descriptor):
        closed_descriptors.add(descriptor)
        return original_close(descriptor)

    def failing_read(descriptor, size):
        raise OSError("injected evidence read failure")

    monkeypatch.setattr(evidence.os, "open", tracking_open)
    monkeypatch.setattr(evidence.os, "close", tracking_close)
    monkeypatch.setattr(evidence.os, "read", failing_read)
    with pytest.raises(evidence.RetryEvidenceIntegrityError):
        evidence.start_retry(
            episode["ledger_path"],
            request=_retry_request(
                signed_work_order,
                signed_root_grant,
                ephemeral_role_keys,
                nonce=_grant_id("retry-read-failure:request"),
            ),
            sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
            evidence_root=episode["evidence_root"],
            clock=lambda: fixed_now,
        )

    assert opened_descriptors
    assert opened_descriptors <= closed_descriptors
    connection = connect_ledger(episode["ledger_path"])
    try:
        assert _ledger_integrity_snapshot(connection) == before
    finally:
        connection.close()


@pytest.mark.parametrize(
    "case",
    (
        "missing",
        "committing",
        "final_path",
        "media_type",
        "size",
        "tampered",
        "symlink",
        "hardlink",
    ),
)
def test_start_retry_rejects_uncommitted_or_unsafe_patch_evidence_without_writes(
    tmp_path: Path,
    case: str,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    episode = _retry_episode(
        tmp_path=tmp_path,
        label=f"retry-evidence-{case}",
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
    )
    connection = connect_ledger(episode["ledger_path"])
    try:
        if case == "missing":
            connection.execute("DELETE FROM evidence_publications")
        elif case == "committing":
            connection.execute(
                "UPDATE evidence_publications SET state = 'COMMITTING'"
            )
        elif case == "final_path":
            connection.execute(
                "UPDATE evidence_publications SET final_path = 'evidence/other.json'"
            )
        elif case == "media_type":
            connection.execute(
                "UPDATE evidence_publications SET media_type = 'text/x-diff'"
            )
        elif case == "size":
            connection.execute(
                "UPDATE evidence_publications SET size_bytes = size_bytes + 1"
            )
        before = _ledger_integrity_snapshot(connection)
    finally:
        connection.close()
    if case == "tampered":
        episode["final_path"].write_bytes(
            b"x" * episode["final_path"].stat().st_size
        )
    elif case == "symlink":
        target = tmp_path / "symlink-target.json"
        target.write_bytes(episode["final_path"].read_bytes())
        episode["final_path"].unlink()
        episode["final_path"].symlink_to(target)
    elif case == "hardlink":
        os.link(
            episode["final_path"],
            tmp_path / "second-evidence-link.json",
        )

    expected_error = (
        evidence.RetryEvidenceRecoveryError
        if case == "committing"
        else evidence.RetryEvidenceIntegrityError
    )
    with pytest.raises(expected_error) as captured:
        evidence.start_retry(
            episode["ledger_path"],
            request=_retry_request(
                signed_work_order,
                signed_root_grant,
                ephemeral_role_keys,
                nonce=_grant_id(f"retry-evidence-{case}:request"),
            ),
            sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
            evidence_root=episode["evidence_root"],
            clock=lambda: fixed_now,
        )
    assert captured.value.code == (
        "RECOVERY_REQUIRED"
        if case == "committing"
        else "REQUEST_INTEGRITY_INVALID"
    )
    connection = connect_ledger(episode["ledger_path"])
    try:
        assert _ledger_integrity_snapshot(connection) == before
    finally:
        connection.close()


@pytest.mark.parametrize(
    "case",
    (
        "wrong_actor",
        "bad_signature",
        "wrong_arguments",
        "unknown_grant",
        "stale",
        "duplicate_nonce",
    ),
)
def test_start_retry_rejects_unauthenticated_or_duplicate_requests_without_writes(
    tmp_path: Path,
    case: str,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    episode = _retry_episode(
        tmp_path=tmp_path,
        label=f"retry-request-{case}",
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
    )
    request = _retry_request(
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        nonce=_grant_id(f"retry-request-{case}:request"),
        actor_role="Developer" if case == "wrong_actor" else "Manager",
        requested_at=(
            "2026-01-01T00:00:05Z"
            if case != "stale"
            else "2026-01-01T00:00:00Z"
        ),
        arguments=(
            {
                "grant_id": signed_root_grant.grant_id,
                "metric": "repair_rounds",
                "amount": 2,
            }
            if case == "wrong_arguments"
            else None
        ),
        grant_id=(
            _grant_id("retry-request:unknown")
            if case == "unknown_grant"
            else None
        ),
    )
    clock = (
        lambda: datetime(
            2026,
            1,
            1,
            0,
            5,
            1,
            tzinfo=timezone.utc,
        )
        if case == "stale"
        else lambda: fixed_now
    )
    if case == "bad_signature":
        request = request.model_copy(update={"model_id": "tampered"})
    if case == "duplicate_nonce":
        evidence.start_retry(
            episode["ledger_path"],
            request=request,
            sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
            evidence_root=episode["evidence_root"],
            clock=lambda: fixed_now,
        )
    connection = connect_ledger(episode["ledger_path"])
    try:
        before = _ledger_integrity_snapshot(connection)
    finally:
        connection.close()

    with pytest.raises(evidence.RetryConsumptionError):
        evidence.start_retry(
            episode["ledger_path"],
            request=request,
            sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
            evidence_root=episode["evidence_root"],
            clock=clock,
        )
    connection = connect_ledger(episode["ledger_path"])
    try:
        assert _ledger_integrity_snapshot(connection) == before
    finally:
        connection.close()


@pytest.mark.parametrize(
    "case",
    ("wrong_failure_context", "wrong_rollback_result", "ambiguous_rollback"),
)
def test_start_retry_rejects_wrong_or_ambiguous_episode_without_writes(
    tmp_path: Path,
    case: str,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    episode = _retry_episode(
        tmp_path=tmp_path,
        label=f"retry-episode-{case}",
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
    )
    connection = connect_ledger(episode["ledger_path"])
    try:
        failure = episode["failure"]
        rollback = episode["rollback"]
        if case == "wrong_failure_context":
            failure_raw = failure.model_dump(mode="json")
            failure_raw["request_arguments"]["candidate_commit"] = "3" * 40
            failure_raw["arguments_digest"] = (
                evidence.request_arguments_digest(
                    "owp.run_tests",
                    failure_raw["request_arguments"],
                )
            )
            failure_claim = failure_raw["nested_claim"]
            failure_claim["arguments_digest"] = failure_raw[
                "arguments_digest"
            ]
            failure_claim = sign_payload(
                "agent-request",
                failure_claim,
                ephemeral_role_keys["Verifier"][0],
            )
            failure_raw["nested_claim"] = failure_claim
            failure_raw["nested_claim_digest"] = failure_claim["digest"]
            failure = evidence.ACTION_RECEIPT_ADAPTER.validate_python(
                sign_payload(
                    "action-receipt",
                    failure_raw,
                    ephemeral_role_keys["Sidecar"][0],
                )
            )
            rollback_raw = rollback.model_dump(mode="json")
            rollback_raw["previous_receipt_digest"] = failure.digest
            rollback = evidence.ACTION_RECEIPT_ADAPTER.validate_python(
                sign_payload(
                    "action-receipt",
                    rollback_raw,
                    ephemeral_role_keys["Sidecar"][0],
                )
            )
            connection.execute(
                "UPDATE receipts SET receipt_json = ? WHERE receipt_id = ?",
                (
                    _canonical_json(failure.model_dump(mode="json")),
                    failure.receipt_id,
                ),
            )
            connection.execute(
                """
                UPDATE receipts
                SET previous_digest = ?, receipt_json = ?
                WHERE receipt_id = ?
                """,
                (
                    failure.digest,
                    _canonical_json(rollback.model_dump(mode="json")),
                    rollback.receipt_id,
                ),
            )
        elif case == "wrong_rollback_result":
            rollback_raw = rollback.model_dump(mode="json")
            rollback_raw["after_commit"] = "3" * 40
            rollback = evidence.ACTION_RECEIPT_ADAPTER.validate_python(
                sign_payload(
                    "action-receipt",
                    rollback_raw,
                    ephemeral_role_keys["Sidecar"][0],
                )
            )
            connection.execute(
                "UPDATE receipts SET receipt_json = ? WHERE receipt_id = ?",
                (
                    _canonical_json(rollback.model_dump(mode="json")),
                    rollback.receipt_id,
                ),
            )
        else:
            duplicate_raw = rollback.model_dump(mode="json")
            duplicate_raw.update(
                {
                    "receipt_id": _grant_id(
                        "retry-episode:duplicate-rollback-receipt"
                    ),
                    "sequence": 7,
                    "nonce": _grant_id(
                        "retry-episode:duplicate-rollback-nonce"
                    ),
                    "previous_receipt_digest": rollback.digest,
                    "quota_charge": {
                        "grant_id": episode["developer"].grant_id,
                        "metric": "tool_calls",
                        "amount": 1,
                        "remaining_after": 1,
                    },
                }
            )
            duplicate_claim = duplicate_raw["nested_claim"]
            duplicate_claim["nonce"] = duplicate_raw["nonce"]
            duplicate_claim = sign_payload(
                "agent-request",
                duplicate_claim,
                ephemeral_role_keys["Developer"][0],
            )
            duplicate_raw["nested_claim"] = duplicate_claim
            duplicate_raw["nested_claim_digest"] = duplicate_claim["digest"]
            duplicate = evidence.ACTION_RECEIPT_ADAPTER.validate_python(
                sign_payload(
                    "action-receipt",
                    duplicate_raw,
                    ephemeral_role_keys["Sidecar"][0],
                )
            )
            _append_action_receipt(connection, duplicate)
            connection.execute("UPDATE sequence_counter SET next_sequence = 8")
            connection.execute("UPDATE work_order_state SET version = 7")
        before = _ledger_integrity_snapshot(connection)
    finally:
        connection.close()

    with pytest.raises(evidence.RetryEvidenceIntegrityError):
        evidence.start_retry(
            episode["ledger_path"],
            request=_retry_request(
                signed_work_order,
                signed_root_grant,
                ephemeral_role_keys,
                nonce=_grant_id(f"retry-episode-{case}:request"),
            ),
            sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
            evidence_root=episode["evidence_root"],
            clock=lambda: fixed_now,
        )
    connection = connect_ledger(episode["ledger_path"])
    try:
        assert _ledger_integrity_snapshot(connection) == before
    finally:
        connection.close()


def test_start_retry_authenticated_non_needs_rework_appends_state_denial(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    episode = _retry_episode(
        tmp_path=tmp_path,
        label="retry-state-denial",
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
    )
    allowed = evidence.start_retry(
        episode["ledger_path"],
        request=_retry_request(
            signed_work_order,
            signed_root_grant,
            ephemeral_role_keys,
            nonce=_grant_id("retry-state-denial:allow"),
        ),
        sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
        evidence_root=episode["evidence_root"],
        clock=lambda: fixed_now,
    )

    denied = evidence.start_retry(
        episode["ledger_path"],
        request=_retry_request(
            signed_work_order,
            signed_root_grant,
            ephemeral_role_keys,
            nonce=_grant_id("retry-state-denial:deny"),
        ),
        sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
        evidence_root=episode["evidence_root"],
        clock=lambda: fixed_now,
    )

    assert denied.policy_decision == "deny"
    assert denied.execution_status == "denied"
    assert denied.policy_error_code == "STATE_DENIED"
    assert denied.state_before == denied.state_after == "retrying"
    assert denied.remaining_after is None
    assert denied.quota_charge is None
    assert denied.parent_receipt_ids == (
        episode["root_issuance"].receipt_id,
        episode["failure"].receipt_id,
        episode["rollback"].receipt_id,
        allowed.receipt_id,
    )
    assert denied.parent_receipt_ids != tuple(
        sorted(denied.parent_receipt_ids)
    )
    connection = connect_ledger(episode["ledger_path"])
    try:
        assert connection.execute(
            "SELECT current_state, version FROM work_order_state"
        ).fetchone() == ("retrying", 8)
        assert connection.execute(
            "SELECT next_sequence FROM sequence_counter"
        ).fetchone() == (9,)
        assert connection.execute(
            "SELECT COUNT(*) FROM grant_events WHERE receipt_id = ?",
            (denied.receipt_id,),
        ).fetchone() == (0,)
    finally:
        connection.close()


def _append_followup_retry_episode(
    episode,
    *,
    previous_receipt,
    role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
):
    patch_raw = episode["patch"].model_dump(mode="json")
    result_path = "evidence/patch-result/02.json"
    patch_raw.update(
        {
            "receipt_id": _grant_id("followup:patch-receipt"),
            "state_before": "retrying",
            "state_after": "retrying",
            "parent_receipt_ids": [
                episode["developer_issuance"].receipt_id
            ],
            "sequence": 8,
            "nonce": _grant_id("followup:patch-nonce"),
            "previous_receipt_digest": previous_receipt.digest,
            "evidence_refs": [
                {
                    **patch_raw["evidence_refs"][0],
                    "path": "evidence/patch-input/02.diff",
                },
                {
                    **patch_raw["evidence_refs"][1],
                    "path": result_path,
                },
            ],
            "quota_charge": {
                "grant_id": episode["developer"].grant_id,
                "metric": "tool_calls",
                "amount": 1,
                "remaining_after": 1,
            },
        }
    )
    patch_claim = patch_raw["nested_claim"]
    patch_claim["nonce"] = patch_raw["nonce"]
    patch_claim = sign_payload(
        "agent-request",
        patch_claim,
        role_keys["Developer"][0],
    )
    patch_raw["nested_claim"] = patch_claim
    patch_raw["nested_claim_digest"] = patch_claim["digest"]
    patch = evidence.ACTION_RECEIPT_ADAPTER.validate_python(
        sign_payload(
            "action-receipt",
            patch_raw,
            role_keys["Sidecar"][0],
        )
    )

    failure_raw = episode["failure"].model_dump(mode="json")
    failure_raw.update(
        {
            "receipt_id": _grant_id("followup:failure-receipt"),
            "state_before": "retrying",
            "state_after": "needs_rework",
            "parent_receipt_ids": [
                episode["verifier_issuance"].receipt_id,
                patch.receipt_id,
            ],
            "sequence": 9,
            "nonce": _grant_id("followup:failure-nonce"),
            "previous_receipt_digest": patch.digest,
            "quota_charge": {
                "grant_id": episode["verifier"].grant_id,
                "metric": "tool_calls",
                "amount": 1,
                "remaining_after": 0,
            },
        }
    )
    failure_claim = failure_raw["nested_claim"]
    failure_claim["nonce"] = failure_raw["nonce"]
    failure_claim = sign_payload(
        "agent-request",
        failure_claim,
        role_keys["Verifier"][0],
    )
    failure_raw["nested_claim"] = failure_claim
    failure_raw["nested_claim_digest"] = failure_claim["digest"]
    failure = evidence.ACTION_RECEIPT_ADAPTER.validate_python(
        sign_payload(
            "action-receipt",
            failure_raw,
            role_keys["Sidecar"][0],
        )
    )

    rollback_raw = episode["rollback"].model_dump(mode="json")
    rollback_arguments = {
        "target_patch_receipt_id": patch.receipt_id,
        "target_patch_digest": patch.digest,
        "before_commit": rollback_raw["before_commit"],
    }
    rollback_raw.update(
        {
            "receipt_id": _grant_id("followup:rollback-receipt"),
            "target_patch_receipt_id": patch.receipt_id,
            "target_patch_digest": patch.digest,
            "parent_receipt_ids": [
                episode["developer_issuance"].receipt_id,
                patch.receipt_id,
                failure.receipt_id,
            ],
            "sequence": 10,
            "nonce": _grant_id("followup:rollback-nonce"),
            "previous_receipt_digest": failure.digest,
            "quota_charge": {
                "grant_id": episode["developer"].grant_id,
                "metric": "tool_calls",
                "amount": 1,
                "remaining_after": 0,
            },
        }
    )
    rollback_claim = rollback_raw["nested_claim"]
    rollback_claim.update(
        {
            "arguments_digest": evidence.request_arguments_digest(
                "owp.rollback_patch",
                rollback_arguments,
            ),
            "nonce": rollback_raw["nonce"],
        }
    )
    rollback_claim = sign_payload(
        "agent-request",
        rollback_claim,
        role_keys["Developer"][0],
    )
    rollback_raw["nested_claim"] = rollback_claim
    rollback_raw["nested_claim_digest"] = rollback_claim["digest"]
    rollback = evidence.ACTION_RECEIPT_ADAPTER.validate_python(
        sign_payload(
            "action-receipt",
            rollback_raw,
            role_keys["Sidecar"][0],
        )
    )

    connection = connect_ledger(episode["ledger_path"])
    try:
        for receipt in (patch, failure, rollback):
            _append_action_receipt(connection, receipt)
        connection.execute(
            "UPDATE sequence_counter SET next_sequence = 11"
        )
        connection.execute(
            """
            UPDATE work_order_state
            SET current_state = 'needs_rework', version = 10
            """
        )
        second_path = episode["final_path"].with_name("02.json")
        second_path.write_bytes(episode["final_path"].read_bytes())
        connection.execute(
            """
            INSERT INTO evidence_publications (
                publication_id,
                receipt_id,
                pending_path,
                final_path,
                digest,
                media_type,
                size_bytes,
                state
            )
            SELECT
                ?, ?, ?, ?, digest, media_type, size_bytes, state
            FROM evidence_publications
            WHERE receipt_id = ?
            """,
            (
                _grant_id("followup:publication"),
                patch.receipt_id,
                ".pending/followup-publication",
                result_path,
                episode["patch"].receipt_id,
            ),
        )
    finally:
        connection.close()
    return failure, rollback


def test_start_retry_quota_exhaustion_appends_free_same_state_denial(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    episode = _retry_episode(
        tmp_path=tmp_path,
        label="retry-quota-denial",
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
    )
    consumed = evidence.start_retry(
        episode["ledger_path"],
        request=_retry_request(
            signed_work_order,
            signed_root_grant,
            ephemeral_role_keys,
            nonce=_grant_id("retry-quota-denial:consume"),
        ),
        sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
        evidence_root=episode["evidence_root"],
        clock=lambda: fixed_now,
    )
    failure, rollback = _append_followup_retry_episode(
        episode,
        previous_receipt=consumed,
        role_keys=ephemeral_role_keys,
    )

    denied = evidence.start_retry(
        episode["ledger_path"],
        request=_retry_request(
            signed_work_order,
            signed_root_grant,
            ephemeral_role_keys,
            nonce=_grant_id("retry-quota-denial:deny"),
        ),
        sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
        evidence_root=episode["evidence_root"],
        clock=lambda: fixed_now,
    )

    assert denied.policy_decision == "deny"
    assert denied.policy_error_code == "QUOTA_EXHAUSTED"
    assert denied.execution_status == "denied"
    assert denied.state_before == denied.state_after == "needs_rework"
    assert denied.remaining_after is None
    assert denied.quota_charge is None
    assert denied.parent_receipt_ids == (
        episode["root_issuance"].receipt_id,
        failure.receipt_id,
        rollback.receipt_id,
    )
    connection = connect_ledger(episode["ledger_path"])
    try:
        assert connection.execute(
            "SELECT current_state, version FROM work_order_state"
        ).fetchone() == ("needs_rework", 11)
        assert connection.execute(
            "SELECT next_sequence FROM sequence_counter"
        ).fetchone() == (12,)
        assert connection.execute(
            "SELECT COUNT(*) FROM grant_events WHERE receipt_id = ?",
            (denied.receipt_id,),
        ).fetchone() == (0,)
    finally:
        connection.close()


def test_concurrent_start_retry_serializes_the_last_repair_round(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    episode = _retry_episode(
        tmp_path=tmp_path,
        label="retry-concurrent",
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
    )
    requests = tuple(
        _retry_request(
            signed_work_order,
            signed_root_grant,
            ephemeral_role_keys,
            nonce=_grant_id(f"retry-concurrent:request:{index}"),
        )
        for index in range(2)
    )

    def consume(request: AgentRequest):
        return evidence.start_retry(
            episode["ledger_path"],
            request=request,
            sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
            evidence_root=episode["evidence_root"],
            clock=lambda: fixed_now,
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = tuple(executor.map(consume, requests))

    allowed = tuple(
        receipt
        for receipt in results
        if receipt.policy_decision == "allow"
    )
    denied = tuple(
        receipt
        for receipt in results
        if receipt.policy_decision == "deny"
    )
    assert len(allowed) == 1
    assert len(denied) == 1
    assert denied[0].policy_error_code == "STATE_DENIED"
    assert allowed[0].quota_charge.remaining_after == 0
    connection = connect_ledger(episode["ledger_path"])
    try:
        assert connection.execute(
            """
            SELECT COUNT(*)
            FROM grant_events
            WHERE event_type = 'grant_consumed'
              AND metric = 'repair_rounds'
            """
        ).fetchone() == (1,)
        assert connection.execute(
            "SELECT current_state, version FROM work_order_state"
        ).fetchone() == ("retrying", 8)
        assert connection.execute(
            "SELECT next_sequence FROM sequence_counter"
        ).fetchone() == (9,)
    finally:
        connection.close()


@pytest.mark.parametrize("failure_kind", ("commit_ack", "close_failure"))
def test_start_retry_reports_committed_truth_after_local_completion_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_kind: str,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    episode = _retry_episode(
        tmp_path=tmp_path,
        label=f"retry-committed-{failure_kind}",
        work_order=signed_work_order,
        root=signed_root_grant,
        role_keys=ephemeral_role_keys,
        now=fixed_now,
        sidecar_receipt_factory=sidecar_receipt_factory,
    )
    real_connect = evidence.connect_ledger
    wrapped: list[_FaultingConnection] = []

    def failing_connect(path: Path):
        raw = real_connect(path)
        if failure_kind == "commit_ack":
            connection = _FaultingConnection(
                raw,
                fail_when=lambda sql: sql == "COMMIT",
                fail_after_execute=True,
            )
        else:
            connection = _CloseAlwaysFailsConnection(raw)
        wrapped.append(connection)
        return connection

    monkeypatch.setattr(evidence, "connect_ledger", failing_connect)
    request = _retry_request(
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        nonce=_grant_id(f"retry-committed-{failure_kind}:request"),
    )
    try:
        with pytest.raises(
            evidence.RetryConsumptionCommittedError
        ) as captured:
            evidence.start_retry(
                episode["ledger_path"],
                request=request,
                sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
                evidence_root=episode["evidence_root"],
                clock=lambda: fixed_now,
            )
        assert captured.value.committed is True
        assert captured.value.receipt.policy_decision == "allow"
        assert captured.value.receipt.remaining_after == 0
    finally:
        monkeypatch.setattr(evidence, "connect_ledger", real_connect)
        for connection in wrapped:
            if isinstance(connection, _CloseAlwaysFailsConnection):
                connection.force_close()

    connection = real_connect(episode["ledger_path"])
    try:
        assert connection.execute(
            "SELECT current_state, version FROM work_order_state"
        ).fetchone() == ("retrying", 7)
        assert connection.execute(
            """
            SELECT COUNT(*)
            FROM grant_events
            WHERE receipt_id = ?
              AND event_type = 'grant_consumed'
            """,
            (captured.value.receipt.receipt_id,),
        ).fetchone() == (1,)
    finally:
        connection.close()


@pytest.mark.parametrize(
    ("signed_preversion", "expected_valid"),
    ((1, True), (7, False)),
)
def test_denied_compose_replays_signed_pretransaction_version(
    tmp_path: Path,
    signed_preversion: int,
    expected_valid: bool,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    ledger_path = tmp_path / "denied-compose.sqlite3"
    _activate_ledger_root(
        ledger_path,
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        fixed_now,
    )
    connection = connect_ledger(ledger_path)
    try:
        root = evidence.ACTION_RECEIPT_ADAPTER.validate_json(
            connection.execute(
                "SELECT receipt_json FROM receipts WHERE sequence = 1"
            ).fetchone()[0]
        )
        denied = _linked_tool_receipt(
            tool_name="owp.compose_proof",
            state_before="running",
            state_after="running",
            sequence=2,
            previous_receipt=root,
            root=signed_root_grant,
            signed_work_order=signed_work_order,
            sidecar_receipt_factory=sidecar_receipt_factory,
            role_keys=ephemeral_role_keys,
            label="denied-compose",
            policy_decision="deny",
            expected_state_version=signed_preversion,
        )
        _append_action_receipt(connection, denied)
        connection.execute(
            "UPDATE sequence_counter SET next_sequence = 3"
        )
        connection.execute(
            "UPDATE work_order_state SET version = 2"
        )
        before = _ledger_integrity_snapshot(connection)
    finally:
        connection.close()

    if not expected_valid:
        connection = connect_ledger(ledger_path)
        try:
            with pytest.raises(evidence.ChildGrantIssuanceError):
                evidence._validated_receipt_prefix(
                    connection,
                    signed_work_order,
                )
            assert _ledger_integrity_snapshot(connection) == before
        finally:
            connection.close()
        return

    candidate = _child_grant(
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        label="after-denied-compose",
    )
    issued = _issue_child(
        ledger_path,
        candidate,
        _delegation_request(
            signed_work_order,
            signed_root_grant,
            candidate,
            ephemeral_role_keys,
            actor_role="Manager",
            nonce=_grant_id("after-denied-compose:request"),
        ),
        ephemeral_role_keys,
        fixed_now,
    )
    assert issued.sequence == 3


@pytest.mark.parametrize(
    ("signed_preversion", "expected_valid"),
    ((7, False), (2, True)),
)
def test_compose_pair_replays_signed_pretransaction_version(
    tmp_path: Path,
    signed_preversion: int,
    expected_valid: bool,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    ledger_path = tmp_path / (
        f"compose-preversion-{signed_preversion}.sqlite3"
    )
    _activate_ledger_root(
        ledger_path,
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        fixed_now,
    )
    connection = connect_ledger(ledger_path)
    try:
        root = evidence.ACTION_RECEIPT_ADAPTER.validate_json(
            connection.execute(
                "SELECT receipt_json FROM receipts WHERE sequence = 1"
            ).fetchone()[0]
        )
        ordinary = _linked_tool_receipt(
            tool_name="owp.repo_read",
            state_before="running",
            state_after="locally_verified",
            sequence=2,
            previous_receipt=root,
            root=signed_root_grant,
            signed_work_order=signed_work_order,
            sidecar_receipt_factory=sidecar_receipt_factory,
            role_keys=ephemeral_role_keys,
            label=f"preversion-{signed_preversion}:ordinary",
            remaining_after=signed_root_grant.quota.tool_calls - 1,
        )
        compose = _linked_tool_receipt(
            tool_name="owp.compose_proof",
            state_before="locally_verified",
            state_after="locally_verified",
            sequence=3,
            previous_receipt=ordinary,
            root=signed_root_grant,
            signed_work_order=signed_work_order,
            sidecar_receipt_factory=sidecar_receipt_factory,
            role_keys=ephemeral_role_keys,
            label=f"preversion-{signed_preversion}:compose",
            expected_state_version=signed_preversion,
            remaining_after=signed_root_grant.quota.tool_calls - 2,
        )
        trigger = _composition_trigger(
            initiator=compose,
            state_version_before=signed_preversion,
            sequence=4,
            signed_work_order=signed_work_order,
            sidecar_receipt_factory=sidecar_receipt_factory,
            role_keys=ephemeral_role_keys,
            label=f"preversion-{signed_preversion}:trigger",
        )
        for receipt in (ordinary, compose, trigger):
            _append_action_receipt(connection, receipt)
        connection.execute(
            "UPDATE sequence_counter SET next_sequence = 5"
        )
        connection.execute(
            """
            UPDATE work_order_state
            SET current_state = 'proof_ready', version = 3
            """
        )
        before = _ledger_integrity_snapshot(connection)
    finally:
        connection.close()

    connection = connect_ledger(ledger_path)
    try:
        if expected_valid:
            receipts = evidence._validated_receipt_prefix(
                connection,
                signed_work_order,
            )
            assert tuple(receipt.sequence for receipt in receipts) == (
                1,
                2,
                3,
                4,
            )
        else:
            with pytest.raises(evidence.ChildGrantIssuanceError):
                evidence._validated_receipt_prefix(
                    connection,
                    signed_work_order,
                )
        assert _ledger_integrity_snapshot(connection) == before
    finally:
        connection.close()


@pytest.mark.parametrize(
    "closure_tamper",
    (
        "orphan_effective",
        "orphan_root_template",
        "foreign_child_edge",
        "extra_known_edge",
    ),
)
def test_reservation_and_receipt_parent_tables_are_fully_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    closure_tamper: str,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
) -> None:
    ledger_path = tmp_path / f"table-closure-{closure_tamper}.sqlite3"
    _activate_ledger_root(
        ledger_path,
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        fixed_now,
    )
    child_receipt = None
    if closure_tamper == "extra_known_edge":
        child = _child_grant(
            signed_work_order,
            signed_root_grant,
            ephemeral_role_keys,
            label="table-closure:child",
        )
        child_receipt = _issue_child(
            ledger_path,
            child,
            _delegation_request(
                signed_work_order,
                signed_root_grant,
                child,
                ephemeral_role_keys,
                actor_role="Manager",
                nonce=_grant_id("table-closure:child-request"),
            ),
            ephemeral_role_keys,
            fixed_now,
        )
    raw_connection = sqlite3.connect(
        ledger_path,
        isolation_level=None,
    )
    raw_connection.execute("PRAGMA foreign_keys = OFF")
    try:
        if closure_tamper.startswith("orphan_"):
            kind = closure_tamper.removeprefix("orphan_")
            raw_connection.execute(
                """
                INSERT INTO grant_id_reservations (
                    grant_id,
                    work_order_digest,
                    candidate_grant_digest,
                    reservation_kind
                )
                VALUES (?, ?, ?, ?)
                """,
                (
                    _grant_id(f"table-closure:{closure_tamper}"),
                    signed_work_order.digest,
                    (
                        None
                        if kind == "root_template"
                        else _grant_id("table-closure:orphan-candidate")
                    ),
                    kind,
                ),
            )
        else:
            root_id = raw_connection.execute(
                "SELECT receipt_id FROM receipts WHERE sequence = 1"
            ).fetchone()[0]
            raw_connection.execute(
                """
                INSERT INTO receipt_parents (
                    child_receipt_id,
                    parent_receipt_id
                )
                VALUES (?, ?)
                """,
                (
                    (
                        _grant_id("table-closure:foreign-child")
                        if closure_tamper == "foreign_child_edge"
                        else child_receipt.receipt_id
                    ),
                    (
                        root_id
                        if closure_tamper == "foreign_child_edge"
                        else child_receipt.receipt_id
                    ),
                ),
            )
    finally:
        raw_connection.close()
    connection = connect_ledger(ledger_path)
    try:
        before = _ledger_integrity_snapshot(connection)
    finally:
        connection.close()
    candidate = _child_grant(
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        label=f"table-closure-next:{closure_tamper}",
    )
    _assert_write_free_child_integrity_failure(
        ledger_path=ledger_path,
        candidate=candidate,
        request=_delegation_request(
            signed_work_order,
            signed_root_grant,
            candidate,
            ephemeral_role_keys,
            actor_role="Manager",
            nonce=_grant_id(
                f"table-closure-next-request:{closure_tamper}"
            ),
        ),
        role_keys=ephemeral_role_keys,
        now=fixed_now,
        before=before,
        monkeypatch=monkeypatch,
    )


def test_protocol_table_reads_are_counted_before_bounded_fetch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
) -> None:
    ledger_path = tmp_path / "bounded-read-order.sqlite3"
    _activate_ledger_root(
        ledger_path,
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        fixed_now,
    )
    audit_log: list[tuple[str, str, int | None]] = []
    real_connect = evidence.connect_ledger

    def audited_connect(path: Path):
        return _ReadAuditConnection(
            real_connect(path),
            audit_log,
        )

    monkeypatch.setattr(evidence, "connect_ledger", audited_connect)
    candidate = _child_grant(
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        label="bounded-read-order:candidate",
    )
    receipt = _issue_child(
        ledger_path,
        candidate,
        _delegation_request(
            signed_work_order,
            signed_root_grant,
            candidate,
            ephemeral_role_keys,
            actor_role="Manager",
            nonce=_grant_id("bounded-read-order:request"),
        ),
        ephemeral_role_keys,
        fixed_now,
    )
    assert receipt.policy_decision == "allow"
    receipt_counts = [
        index
        for index, (operation, sql, _) in enumerate(audit_log)
        if (
            operation == "execute"
            and "COUNT(" in sql
            and "FROM RECEIPTS" in sql
        )
    ]
    receipt_reads = [
        (index, sql)
        for index, (operation, sql, _) in enumerate(audit_log)
        if (
            operation == "execute"
            and "FROM RECEIPTS" in sql
            and "ORDER BY SEQUENCE" in sql
        )
    ]
    assert receipt_counts
    assert receipt_reads
    assert receipt_counts[0] < receipt_reads[0][0]
    assert "LIMIT" in receipt_reads[0][1]


def test_receipt_overflow_fails_before_unbounded_fetchall(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
) -> None:
    ledger_path = tmp_path / "receipt-overflow.sqlite3"
    _activate_ledger_root(
        ledger_path,
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        fixed_now,
    )
    raw_connection = sqlite3.connect(
        ledger_path,
        isolation_level=None,
    )
    raw_connection.execute("PRAGMA foreign_keys = OFF")
    try:
        root_json = raw_connection.execute(
            "SELECT receipt_json FROM receipts WHERE sequence = 1"
        ).fetchone()[0]
        for index in range(65):
            raw_connection.execute(
                """
                INSERT INTO receipts (
                    receipt_id,
                    work_order_digest,
                    nonce,
                    sequence,
                    previous_digest,
                    receipt_json
                )
                VALUES (?, ?, ?, ?, NULL, ?)
                """,
                (
                    _grant_id(f"receipt-overflow:id:{index}"),
                    signed_work_order.digest,
                    _grant_id(f"receipt-overflow:nonce:{index}"),
                    index + 2,
                    root_json,
                ),
            )
    finally:
        raw_connection.close()
    connection = connect_ledger(ledger_path)
    try:
        before = _ledger_integrity_snapshot(connection)
    finally:
        connection.close()
    audit_log: list[tuple[str, str, int | None]] = []
    real_connect = evidence.connect_ledger

    def audited_connect(path: Path):
        return _ReadAuditConnection(
            real_connect(path),
            audit_log,
        )

    monkeypatch.setattr(evidence, "connect_ledger", audited_connect)
    candidate = _child_grant(
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        label="receipt-overflow:candidate",
    )
    with pytest.raises(evidence.ChildGrantIssuanceError):
        _issue_child(
            ledger_path,
            candidate,
            _delegation_request(
                signed_work_order,
                signed_root_grant,
                candidate,
                ephemeral_role_keys,
                actor_role="Manager",
                nonce=_grant_id("receipt-overflow:request"),
            ),
            ephemeral_role_keys,
            fixed_now,
        )
    receipt_fetch_sizes = [
        size
        for operation, sql, size in audit_log
        if (
            operation == "fetchall"
            and "FROM RECEIPTS" in sql
            and "ORDER BY SEQUENCE" in sql
        )
    ]
    assert all(
        size is not None and size <= 65
        for size in receipt_fetch_sizes
    )
    assert any(
        operation == "execute"
        and "COUNT(" in sql
        and "FROM RECEIPTS" in sql
        for operation, sql, _ in audit_log
    )
    connection = connect_ledger(ledger_path)
    try:
        assert _ledger_integrity_snapshot(connection) == before
    finally:
        connection.close()


def test_foreign_work_order_receipt_row_cannot_hide_from_prefix_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
) -> None:
    ledger_path = tmp_path / "foreign-receipt-row.sqlite3"
    _activate_ledger_root(
        ledger_path,
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        fixed_now,
    )
    raw_connection = sqlite3.connect(
        ledger_path,
        isolation_level=None,
    )
    raw_connection.execute("PRAGMA foreign_keys = OFF")
    try:
        root_json = raw_connection.execute(
            "SELECT receipt_json FROM receipts WHERE sequence = 1"
        ).fetchone()[0]
        raw_connection.execute(
            """
            INSERT INTO receipts (
                receipt_id,
                work_order_digest,
                nonce,
                sequence,
                previous_digest,
                receipt_json
            )
            VALUES (?, ?, ?, ?, NULL, ?)
            """,
            (
                "0" * 64,
                "1" * 64,
                "2" * 64,
                99,
                root_json,
            ),
        )
    finally:
        raw_connection.close()
    connection = connect_ledger(ledger_path)
    try:
        before = _ledger_integrity_snapshot(connection)
    finally:
        connection.close()
    candidate = _child_grant(
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        label="foreign-receipt-row:candidate",
    )
    request = _delegation_request(
        signed_work_order,
        signed_root_grant,
        candidate,
        ephemeral_role_keys,
        actor_role="Manager",
        nonce=_grant_id("foreign-receipt-row:request"),
    )
    real_sign_payload = evidence.sign_payload
    action_receipt_signatures = 0

    def tracked_sign_payload(
        object_type: str,
        value,
        private_key: Ed25519PrivateKey,
    ):
        nonlocal action_receipt_signatures
        if object_type == "action-receipt":
            action_receipt_signatures += 1
        return real_sign_payload(object_type, value, private_key)

    monkeypatch.setattr(evidence, "sign_payload", tracked_sign_payload)
    with pytest.raises(evidence.ChildGrantIssuanceError):
        _issue_child(
            ledger_path,
            candidate,
            request,
            ephemeral_role_keys,
            fixed_now,
        )

    assert action_receipt_signatures == 0
    connection = connect_ledger(ledger_path)
    try:
        assert _ledger_integrity_snapshot(connection) == before
    finally:
        connection.close()


def test_orphan_attempt_reservation_fails_integrity_without_writes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
) -> None:
    ledger_path = tmp_path / "orphan-attempt-reservation.sqlite3"
    _activate_ledger_root(
        ledger_path,
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        fixed_now,
    )
    orphan_grant_id = _grant_id("orphan-attempt-reservation")
    orphan_candidate_digest = _grant_id(
        "orphan-attempt-candidate-digest"
    )
    connection = connect_ledger(ledger_path)
    try:
        connection.execute(
            """
            INSERT INTO grant_id_reservations (
                grant_id,
                work_order_digest,
                candidate_grant_digest,
                reservation_kind
            )
            VALUES (?, ?, ?, 'attempt')
            """,
            (
                orphan_grant_id,
                signed_work_order.digest,
                orphan_candidate_digest,
            ),
        )
        before = _ledger_integrity_snapshot(connection)
    finally:
        connection.close()
    candidate = _child_grant(
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        label="orphan-attempt-reservation:next",
    )
    request = _delegation_request(
        signed_work_order,
        signed_root_grant,
        candidate,
        ephemeral_role_keys,
        actor_role="Manager",
        nonce=_grant_id("orphan-attempt-reservation:request"),
    )
    real_sign_payload = evidence.sign_payload
    action_receipt_signatures = 0

    def tracked_sign_payload(
        object_type: str,
        value,
        private_key: Ed25519PrivateKey,
    ):
        nonlocal action_receipt_signatures
        if object_type == "action-receipt":
            action_receipt_signatures += 1
        return real_sign_payload(object_type, value, private_key)

    monkeypatch.setattr(evidence, "sign_payload", tracked_sign_payload)
    with pytest.raises(evidence.ChildGrantIssuanceError):
        _issue_child(
            ledger_path,
            candidate,
            request,
            ephemeral_role_keys,
            fixed_now,
        )

    assert action_receipt_signatures == 0
    connection = connect_ledger(ledger_path)
    try:
        assert _ledger_integrity_snapshot(connection) == before
    finally:
        connection.close()


@pytest.mark.parametrize(
    "tamper_kind",
    (
        "noncanonical_json",
        "signature",
        "candidate_digest",
        "reservation",
        "deny_receipt_binding",
        "missing",
        "extra",
    ),
)
def test_grant_attempt_rows_match_signed_denial_history_one_to_one(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tamper_kind: str,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
) -> None:
    ledger_path = tmp_path / f"attempt-integrity-{tamper_kind}.sqlite3"
    _activate_ledger_root(
        ledger_path,
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        fixed_now,
    )
    denied = _child_grant(
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        label=f"attempt-integrity-denied:{tamper_kind}",
        subject_role="Verifier",
        updates={"allowed_write_roots": ["src"]},
    )
    denied_receipt = _issue_child(
        ledger_path,
        denied,
        _delegation_request(
            signed_work_order,
            signed_root_grant,
            denied,
            ephemeral_role_keys,
            actor_role="Manager",
            nonce=_grant_id(
                f"attempt-integrity-denied-request:{tamper_kind}"
            ),
        ),
        ephemeral_role_keys,
        fixed_now,
    )
    assert denied_receipt.policy_decision == "deny"
    connection = connect_ledger(ledger_path)
    try:
        attempt_json = connection.execute(
            """
            SELECT candidate_grant_json
            FROM grant_attempts
            WHERE grant_id = ?
            """,
            (denied.grant_id,),
        ).fetchone()[0]
        if tamper_kind == "noncanonical_json":
            connection.execute(
                """
                UPDATE grant_attempts
                SET candidate_grant_json = ?
                WHERE grant_id = ?
                """,
                (f" {attempt_json}", denied.grant_id),
            )
        elif tamper_kind == "signature":
            raw = json.loads(attempt_json)
            raw["signature"] = "A" * 86
            connection.execute(
                """
                UPDATE grant_attempts
                SET candidate_grant_json = ?
                WHERE grant_id = ?
                """,
                (_canonical_json(raw), denied.grant_id),
            )
        elif tamper_kind == "candidate_digest":
            connection.execute(
                """
                UPDATE grant_attempts
                SET candidate_grant_digest = ?
                WHERE grant_id = ?
                """,
                ("0" * 64, denied.grant_id),
            )
        elif tamper_kind == "reservation":
            connection.execute(
                """
                UPDATE grant_id_reservations
                SET reservation_kind = 'effective'
                WHERE grant_id = ?
                """,
                (denied.grant_id,),
            )
        elif tamper_kind == "deny_receipt_binding":
            replacement = _child_grant(
                signed_work_order,
                signed_root_grant,
                ephemeral_role_keys,
                label="ignored-replacement-label",
                subject_role="Verifier",
                updates={
                    "grant_id": denied.grant_id,
                    "allowed_write_roots": ["src"],
                    "quota": {
                        "tool_calls": 3,
                        "repair_rounds": 0,
                    },
                },
            )
            connection.execute(
                """
                UPDATE grant_attempts
                SET
                    candidate_grant_digest = ?,
                    candidate_grant_json = ?
                WHERE grant_id = ?
                """,
                (
                    replacement.digest,
                    _canonical_json(
                        replacement.model_dump(mode="json")
                    ),
                    denied.grant_id,
                ),
            )
            connection.execute(
                """
                UPDATE grant_id_reservations
                SET candidate_grant_digest = ?
                WHERE grant_id = ?
                """,
                (replacement.digest, denied.grant_id),
            )
        elif tamper_kind == "missing":
            connection.execute(
                "DELETE FROM grant_attempts WHERE grant_id = ?",
                (denied.grant_id,),
            )
        else:
            extra = _child_grant(
                signed_work_order,
                signed_root_grant,
                ephemeral_role_keys,
                label="attempt-integrity-extra",
                subject_role="Verifier",
                updates={"allowed_write_roots": ["src"]},
            )
            connection.execute(
                """
                INSERT INTO grant_id_reservations (
                    grant_id,
                    work_order_digest,
                    candidate_grant_digest,
                    reservation_kind
                )
                VALUES (?, ?, ?, 'attempt')
                """,
                (
                    extra.grant_id,
                    signed_work_order.digest,
                    extra.digest,
                ),
            )
            connection.execute(
                """
                INSERT INTO grant_attempts (
                    candidate_grant_digest,
                    grant_id,
                    work_order_digest,
                    candidate_grant_json
                )
                VALUES (?, ?, ?, ?)
                """,
                (
                    extra.digest,
                    extra.grant_id,
                    signed_work_order.digest,
                    _canonical_json(extra.model_dump(mode="json")),
                ),
            )
        before = _ledger_integrity_snapshot(connection)
    finally:
        connection.close()
    candidate = _child_grant(
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        label=f"attempt-integrity-next:{tamper_kind}",
    )
    request = _delegation_request(
        signed_work_order,
        signed_root_grant,
        candidate,
        ephemeral_role_keys,
        actor_role="Manager",
        nonce=_grant_id(f"attempt-integrity-next-request:{tamper_kind}"),
    )
    real_sign_payload = evidence.sign_payload
    action_receipt_signatures = 0

    def tracked_sign_payload(
        object_type: str,
        value,
        private_key: Ed25519PrivateKey,
    ):
        nonlocal action_receipt_signatures
        if object_type == "action-receipt":
            action_receipt_signatures += 1
        return real_sign_payload(object_type, value, private_key)

    monkeypatch.setattr(evidence, "sign_payload", tracked_sign_payload)
    with pytest.raises(evidence.ChildGrantIssuanceError):
        _issue_child(
            ledger_path,
            candidate,
            request,
            ephemeral_role_keys,
            fixed_now,
        )

    assert action_receipt_signatures == 0
    connection = connect_ledger(ledger_path)
    try:
        assert _ledger_integrity_snapshot(connection) == before
    finally:
        connection.close()


@pytest.mark.parametrize(
    "history_tamper",
    ("allowed_candidate", "wrong_error_code"),
)
def test_denied_attempt_history_replays_exact_policy_decision(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    history_tamper: str,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
) -> None:
    ledger_path = tmp_path / (
        f"denied-policy-replay-{history_tamper}.sqlite3"
    )
    _activate_ledger_root(
        ledger_path,
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        fixed_now,
    )
    denied = _child_grant(
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        label=f"denied-policy-replay:{history_tamper}",
        subject_role="Verifier",
        updates={"allowed_write_roots": ["src"]},
    )
    receipt = _issue_child(
        ledger_path,
        denied,
        _delegation_request(
            signed_work_order,
            signed_root_grant,
            denied,
            ephemeral_role_keys,
            actor_role="Manager",
            nonce=_grant_id(
                f"denied-policy-replay-request:{history_tamper}"
            ),
        ),
        ephemeral_role_keys,
        fixed_now,
    )
    assert receipt.policy_error_code == "CAPABILITY_DENIED"
    connection = connect_ledger(ledger_path)
    try:
        if history_tamper == "allowed_candidate":
            legal_raw = denied.model_dump(mode="json")
            legal_raw["allowed_write_roots"] = []
            _rewrite_grant_issuance_history(
                connection,
                sequence=2,
                candidate_raw=legal_raw,
                allowed=False,
                work_order=signed_work_order,
                role_keys=ephemeral_role_keys,
            )
        else:
            raw = json.loads(
                connection.execute(
                    "SELECT receipt_json FROM receipts WHERE sequence = 2"
                ).fetchone()[0]
            )
            raw["policy_error_code"] = "ROLE_DENIED"
            resigned = sign_payload(
                "action-receipt",
                raw,
                ephemeral_role_keys["Sidecar"][0],
            )
            connection.execute(
                "UPDATE receipts SET receipt_json = ? WHERE sequence = 2",
                (_canonical_json(resigned),),
            )
        before = _ledger_integrity_snapshot(connection)
    finally:
        connection.close()
    candidate = _child_grant(
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        label=f"denied-policy-replay-next:{history_tamper}",
    )
    _assert_write_free_child_integrity_failure(
        ledger_path=ledger_path,
        candidate=candidate,
        request=_delegation_request(
            signed_work_order,
            signed_root_grant,
            candidate,
            ephemeral_role_keys,
            actor_role="Manager",
            nonce=_grant_id(
                f"denied-policy-replay-next-request:{history_tamper}"
            ),
        ),
        role_keys=ephemeral_role_keys,
        now=fixed_now,
        before=before,
        monkeypatch=monkeypatch,
    )


def test_attempt_capacity_comes_from_validated_signed_denial_history(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
) -> None:
    ledger_path = tmp_path / "attempt-history-cap.sqlite3"
    _activate_ledger_root(
        ledger_path,
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        fixed_now,
    )
    attempts: list[CapabilityGrant] = []
    for index in range(8):
        candidate = _child_grant(
            signed_work_order,
            signed_root_grant,
            ephemeral_role_keys,
            label=f"attempt-history-cap:{index}",
            subject_role="Verifier",
            updates={"allowed_write_roots": ["src"]},
        )
        attempts.append(candidate)
        receipt = _issue_child(
            ledger_path,
            candidate,
            _delegation_request(
                signed_work_order,
                signed_root_grant,
                candidate,
                ephemeral_role_keys,
                actor_role="Manager",
                nonce=_grant_id(
                    f"attempt-history-cap-request:{index}"
                ),
            ),
            ephemeral_role_keys,
            fixed_now,
        )
        assert receipt.policy_decision == "deny"
    connection = connect_ledger(ledger_path)
    try:
        connection.execute(
            "DELETE FROM grant_attempts WHERE grant_id = ?",
            (attempts[0].grant_id,),
        )
        before = _ledger_integrity_snapshot(connection)
    finally:
        connection.close()
    ninth = _child_grant(
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        label="attempt-history-cap:ninth",
        subject_role="Verifier",
        updates={"allowed_write_roots": ["src"]},
    )
    real_sign_payload = evidence.sign_payload
    action_receipt_signatures = 0

    def tracked_sign_payload(
        object_type: str,
        value,
        private_key: Ed25519PrivateKey,
    ):
        nonlocal action_receipt_signatures
        if object_type == "action-receipt":
            action_receipt_signatures += 1
        return real_sign_payload(object_type, value, private_key)

    monkeypatch.setattr(evidence, "sign_payload", tracked_sign_payload)
    with pytest.raises(evidence.ChildGrantIssuanceError):
        _issue_child(
            ledger_path,
            ninth,
            _delegation_request(
                signed_work_order,
                signed_root_grant,
                ninth,
                ephemeral_role_keys,
                actor_role="Manager",
                nonce=_grant_id(
                    "attempt-history-cap-request:ninth"
                ),
            ),
            ephemeral_role_keys,
            fixed_now,
        )

    assert action_receipt_signatures == 0
    connection = connect_ledger(ledger_path)
    try:
        assert _ledger_integrity_snapshot(connection) == before
    finally:
        connection.close()


@pytest.mark.parametrize("policy_outcome", ("allow", "deny"))
def test_routine_child_reserves_terminal_receipt_capacity_at_sixty_one(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    policy_outcome: str,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
    sidecar_receipt_factory,
) -> None:
    ledger_path = tmp_path / f"routine-cap-{policy_outcome}.sqlite3"
    _activate_ledger_root(
        ledger_path,
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        fixed_now,
    )
    connection = connect_ledger(ledger_path)
    try:
        previous = evidence.ACTION_RECEIPT_ADAPTER.validate_json(
            connection.execute(
                "SELECT receipt_json FROM receipts WHERE sequence = 1"
            ).fetchone()[0]
        )
        for sequence in range(2, 62):
            denied_compose = _linked_tool_receipt(
                tool_name="owp.compose_proof",
                state_before="running",
                state_after="running",
                sequence=sequence,
                previous_receipt=previous,
                root=signed_root_grant,
                signed_work_order=signed_work_order,
                sidecar_receipt_factory=sidecar_receipt_factory,
                role_keys=ephemeral_role_keys,
                label=f"routine-cap-{policy_outcome}:{sequence}",
                policy_decision="deny",
                expected_state_version=sequence - 1,
            )
            _append_action_receipt(connection, denied_compose)
            previous = denied_compose
        connection.execute(
            "UPDATE sequence_counter SET next_sequence = 62"
        )
        connection.execute(
            "UPDATE work_order_state SET version = 61"
        )
        before_rows = _ledger_integrity_snapshot(connection)
        before_bytes = "\n".join(connection.iterdump()).encode("utf-8")
    finally:
        connection.close()

    candidate = _child_grant(
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        label=f"routine-cap-next:{policy_outcome}",
        subject_role=(
            "Developer" if policy_outcome == "allow" else "Verifier"
        ),
        updates=(
            None
            if policy_outcome == "allow"
            else {"allowed_write_roots": ["src"]}
        ),
    )
    request = _delegation_request(
        signed_work_order,
        signed_root_grant,
        candidate,
        ephemeral_role_keys,
        actor_role="Manager",
        nonce=_grant_id(f"routine-cap-request:{policy_outcome}"),
    )
    real_sign_payload = evidence.sign_payload
    action_receipt_signatures = 0

    def tracked_sign_payload(
        object_type: str,
        value,
        private_key: Ed25519PrivateKey,
    ):
        nonlocal action_receipt_signatures
        if object_type == "action-receipt":
            action_receipt_signatures += 1
        return real_sign_payload(object_type, value, private_key)

    monkeypatch.setattr(evidence, "sign_payload", tracked_sign_payload)
    with pytest.raises(evidence.ChildGrantIssuanceError):
        _issue_child(
            ledger_path,
            candidate,
            request,
            ephemeral_role_keys,
            fixed_now,
        )
    assert action_receipt_signatures == 0
    connection = connect_ledger(ledger_path)
    try:
        assert _ledger_integrity_snapshot(connection) == before_rows
        assert (
            "\n".join(connection.iterdump()).encode("utf-8")
            == before_bytes
        )
    finally:
        connection.close()


@pytest.mark.parametrize(
    "failure_kind",
    ("close_failure", "commit_ack_failure"),
)
def test_committed_child_issuance_reports_committed_truth(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_kind: str,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
) -> None:
    ledger_path = tmp_path / f"child-committed-{failure_kind}.sqlite3"
    _activate_ledger_root(
        ledger_path,
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        fixed_now,
    )
    candidate = _child_grant(
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        label=f"child-committed:{failure_kind}",
    )
    request = _delegation_request(
        signed_work_order,
        signed_root_grant,
        candidate,
        ephemeral_role_keys,
        actor_role="Manager",
        nonce=_grant_id(f"child-committed-request:{failure_kind}"),
    )
    real_connect = evidence.connect_ledger
    before_connection = real_connect(ledger_path)
    try:
        before = _ledger_integrity_snapshot(before_connection)
    finally:
        before_connection.close()
    connections: list[
        _CloseAlwaysFailsConnection | _FaultingConnection
    ] = []

    def faulting_connect(path: Path):
        raw = real_connect(path)
        if failure_kind == "close_failure":
            connection = _CloseAlwaysFailsConnection(raw)
        else:
            connection = _FaultingConnection(
                raw,
                fail_when=lambda sql: sql == "COMMIT",
                fail_after_execute=True,
            )
        connections.append(connection)
        return connection

    monkeypatch.setattr(evidence, "connect_ledger", faulting_connect)
    try:
        with pytest.raises(Exception) as captured:
            _issue_child(
                ledger_path,
                candidate,
                request,
                ephemeral_role_keys,
                fixed_now,
            )

        committed_type = getattr(
            evidence,
            "ChildGrantIssuanceCommittedError",
            None,
        )
        assert committed_type is not None
        assert isinstance(captured.value, committed_type)
        assert not isinstance(captured.value, evidence.ChildGrantIssuanceError)
        assert captured.value.committed is True
        assert captured.value.receipt.candidate_grant_digest == (
            candidate.digest
        )
        errors = _exception_tree(captured.value)
        marker = (
            "close"
            if failure_kind == "close_failure"
            else "COMMIT"
        )
        assert any(marker in str(error) for error in errors)
    finally:
        monkeypatch.setattr(evidence, "connect_ledger", real_connect)
        for connection in connections:
            if isinstance(connection, _CloseAlwaysFailsConnection):
                connection.force_close()

    after_connection = real_connect(ledger_path)
    try:
        after = _ledger_integrity_snapshot(after_connection)
        assert len(after[0]["reservations"]) == (
            len(before[0]["reservations"]) + 1
        )
        assert len(after[0]["grants"]) == len(before[0]["grants"]) + 1
        assert len(after[0]["attempts"]) == len(before[0]["attempts"])
        assert len(after[0]["receipts"]) == len(before[0]["receipts"]) + 1
        assert sum(
            row[0] == captured.value.receipt.receipt_id
            for row in after[0]["receipts"]
        ) == 1
        assert len(after[1]) == len(before[1]) + 1
        assert len(after[2]) == len(before[2]) + 1
    finally:
        after_connection.close()


@pytest.mark.parametrize(
    "confirmation_cleanup_failure",
    ("rollback_ack", "close"),
)
def test_committed_truth_survives_confirmation_cleanup_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    confirmation_cleanup_failure: str,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
) -> None:
    ledger_path = tmp_path / (
        f"committed-confirm-cleanup-{confirmation_cleanup_failure}.sqlite3"
    )
    _activate_ledger_root(
        ledger_path,
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        fixed_now,
    )
    candidate = _child_grant(
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        label=f"committed-confirm-cleanup:{confirmation_cleanup_failure}",
    )
    request = _delegation_request(
        signed_work_order,
        signed_root_grant,
        candidate,
        ephemeral_role_keys,
        actor_role="Manager",
        nonce=_grant_id(
            f"committed-confirm-cleanup-request:"
            f"{confirmation_cleanup_failure}"
        ),
    )
    real_connect = evidence.connect_ledger
    real_direct = evidence._connect_ledger_direct
    main_connections: list[_CloseAlwaysFailsConnection] = []
    confirmation_connections: list[
        _FaultingConnection | _CloseAlwaysFailsConnection
    ] = []

    def main_close_failing_connect(path: Path):
        connection = _CloseAlwaysFailsConnection(real_direct(path))
        main_connections.append(connection)
        return connection

    def cleanup_failing_direct(path: Path):
        raw = real_direct(path)
        if confirmation_cleanup_failure == "rollback_ack":
            connection = _FaultingConnection(
                raw,
                fail_when=lambda sql: sql == "ROLLBACK",
                fail_after_execute=True,
            )
        else:
            connection = _CloseAlwaysFailsConnection(raw)
        confirmation_connections.append(connection)
        return connection

    monkeypatch.setattr(
        evidence,
        "connect_ledger",
        main_close_failing_connect,
    )
    monkeypatch.setattr(
        evidence,
        "_connect_ledger_direct",
        cleanup_failing_direct,
    )
    try:
        with pytest.raises(Exception) as captured:
            _issue_child(
                ledger_path,
                candidate,
                request,
                ephemeral_role_keys,
                fixed_now,
            )
        assert main_connections
        assert main_connections[0].close_attempts >= 3
        assert confirmation_connections
        confirmation = confirmation_connections[0]
        if confirmation_cleanup_failure == "rollback_ack":
            assert isinstance(confirmation, _FaultingConnection)
            assert confirmation.closed
        else:
            assert isinstance(confirmation, _CloseAlwaysFailsConnection)
            assert confirmation.close_attempts >= 1
            assert not confirmation.in_transaction

        assert isinstance(
            captured.value,
            evidence.ChildGrantIssuanceCommittedError,
        )
        assert captured.value.committed is True
    finally:
        monkeypatch.setattr(evidence, "connect_ledger", real_connect)
        monkeypatch.setattr(
            evidence,
            "_connect_ledger_direct",
            real_direct,
        )
        for connection in (
            *main_connections,
            *confirmation_connections,
        ):
            if isinstance(connection, _CloseAlwaysFailsConnection):
                connection.force_close()

    connection = real_connect(ledger_path)
    try:
        row = connection.execute(
            "SELECT receipt_json FROM receipts WHERE sequence = 2"
        ).fetchone()
        assert row is not None
        committed_receipt = evidence.ACTION_RECEIPT_ADAPTER.validate_json(
            row[0]
        )
        assert captured.value.receipt == committed_receipt
        assert committed_receipt.candidate_grant_digest == candidate.digest
        assert connection.execute(
            "SELECT COUNT(*) FROM grants WHERE grant_id = ?",
            (candidate.grant_id,),
        ).fetchone() == (1,)
    finally:
        connection.close()


def test_committed_confirmation_uses_one_read_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
) -> None:
    ledger_path = tmp_path / "committed-confirm-snapshot.sqlite3"
    _activate_ledger_root(
        ledger_path,
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        fixed_now,
    )
    first = _child_grant(
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        label="committed-confirm-snapshot:first",
    )
    first_receipt = _issue_child(
        ledger_path,
        first,
        _delegation_request(
            signed_work_order,
            signed_root_grant,
            first,
            ephemeral_role_keys,
            actor_role="Manager",
            nonce=_grant_id(
                "committed-confirm-snapshot:first-request"
            ),
        ),
        ephemeral_role_keys,
        fixed_now,
    )
    second = _child_grant(
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        label="committed-confirm-snapshot:second",
    )
    second_request = _delegation_request(
        signed_work_order,
        signed_root_grant,
        second,
        ephemeral_role_keys,
        actor_role="Manager",
        nonce=_grant_id(
            "committed-confirm-snapshot:second-request"
        ),
    )
    writer_receipts = []

    def commit_second_child() -> None:
        writer_receipts.append(
            _issue_child(
                ledger_path,
                second,
                second_request,
                ephemeral_role_keys,
                fixed_now,
            )
        )

    real_direct = evidence._connect_ledger_direct
    confirm_connections: list[_AfterReceiptCountConnection] = []
    direct_calls = 0

    def hooked_direct(path: Path):
        nonlocal direct_calls
        direct_calls += 1
        connection = real_direct(path)
        if direct_calls != 1:
            return connection
        wrapped = _AfterReceiptCountConnection(
            connection,
            commit_second_child,
        )
        confirm_connections.append(wrapped)
        return wrapped

    monkeypatch.setattr(
        evidence,
        "_connect_ledger_direct",
        hooked_direct,
    )
    confirmed = evidence._confirm_committed_child_receipt(
        ledger_path,
        first_receipt,
    )

    assert writer_receipts and writer_receipts[0].sequence == 3
    assert confirmed == first_receipt
    assert confirm_connections
    assert all(connection.closed for connection in confirm_connections)
    connection = connect_ledger(ledger_path)
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM receipts"
        ).fetchone() == (3,)
    finally:
        connection.close()


def test_precommit_child_failure_remains_ordinary_and_write_free(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now: datetime,
) -> None:
    ledger_path = tmp_path / "child-precommit-failure.sqlite3"
    _activate_ledger_root(
        ledger_path,
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        fixed_now,
    )
    candidate = _child_grant(
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        label="child-precommit-failure",
    )
    request = _delegation_request(
        signed_work_order,
        signed_root_grant,
        candidate,
        ephemeral_role_keys,
        actor_role="Manager",
        nonce=_grant_id("child-precommit-failure:request"),
    )
    real_connect = evidence.connect_ledger
    before_connection = real_connect(ledger_path)
    try:
        before = _ledger_integrity_snapshot(before_connection)
    finally:
        before_connection.close()
    connections: list[_FaultingConnection] = []

    def faulting_connect(path: Path) -> _FaultingConnection:
        connection = _FaultingConnection(
            real_connect(path),
            fail_when=lambda sql: sql.startswith("INSERT INTO GRANTS"),
        )
        connections.append(connection)
        return connection

    monkeypatch.setattr(evidence, "connect_ledger", faulting_connect)
    with pytest.raises(evidence.ChildGrantIssuanceError) as captured:
        _issue_child(
            ledger_path,
            candidate,
            request,
            ephemeral_role_keys,
            fixed_now,
        )

    committed_type = getattr(
        evidence,
        "ChildGrantIssuanceCommittedError",
        None,
    )
    if committed_type is not None:
        assert not isinstance(captured.value, committed_type)
    assert connections and all(connection.closed for connection in connections)
    monkeypatch.setattr(evidence, "connect_ledger", real_connect)
    after_connection = real_connect(ledger_path)
    try:
        assert _ledger_integrity_snapshot(after_connection) == before
    finally:
        after_connection.close()


def test_every_connection_uses_frozen_sqlite_pragmas(
    tmp_path: Path,
    signed_work_order: WorkOrder,
) -> None:
    ledger_path = tmp_path / "ledger.sqlite3"
    initialize_ledger(ledger_path, signed_work_order)

    assert BUSY_TIMEOUT_MS == 135_000
    for _ in range(2):
        connection = connect_ledger(ledger_path)
        try:
            assert connection.isolation_level is None
            assert connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1
            assert connection.execute("PRAGMA synchronous").fetchone()[0] == 2
            assert (
                connection.execute("PRAGMA journal_mode").fetchone()[0].lower()
                == "wal"
            )
            assert (
                connection.execute("PRAGMA busy_timeout").fetchone()[0]
                == BUSY_TIMEOUT_MS
            )
        finally:
            connection.close()


@pytest.mark.parametrize(
    "marker",
    (
        "CREATE TABLE SEQUENCE_COUNTER",
        "INSERT INTO WORK_ORDERS",
        "INSERT INTO GRANT_ID_RESERVATIONS",
        "COMMIT",
    ),
    ids=("schema", "authority_insert", "root_reservation", "commit"),
)
def test_initialization_fault_removes_only_its_owned_artifacts_and_can_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    signed_work_order: WorkOrder,
    marker: str,
) -> None:
    ledger_path = tmp_path / "ledger.sqlite3"
    real_connect = evidence.connect_ledger
    connections: list[_FaultingConnection] = []

    def faulting_connect(path: Path) -> _FaultingConnection:
        connection = _FaultingConnection(
            real_connect(path),
            fail_when=lambda sql: marker in sql,
        )
        connections.append(connection)
        return connection

    monkeypatch.setattr(evidence, "connect_ledger", faulting_connect)
    with pytest.raises(LedgerInitializationError) as captured:
        evidence.initialize_ledger(ledger_path, signed_work_order)

    _assert_domain_error_with_cause(
        captured.value,
        LedgerInitializationError,
    )
    assert connections and all(connection.closed for connection in connections)
    _assert_initialization_left_nothing(tmp_path, ledger_path)

    monkeypatch.setattr(evidence, "connect_ledger", real_connect)
    evidence.initialize_ledger(ledger_path, signed_work_order)
    connection = real_connect(ledger_path)
    try:
        assert (
            evidence.load_authoritative_work_order(connection)
            == signed_work_order
        )
    finally:
        connection.close()


def test_initialization_connect_failure_leaves_no_artifact_and_can_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    signed_work_order: WorkOrder,
) -> None:
    ledger_path = tmp_path / "ledger.sqlite3"
    real_connect = evidence.connect_ledger

    def fail_after_open(path: Path) -> sqlite3.Connection:
        connection = real_connect(path)
        connection.close()
        raise sqlite3.OperationalError("injected connection setup failure")

    monkeypatch.setattr(evidence, "connect_ledger", fail_after_open)
    with pytest.raises(LedgerInitializationError) as captured:
        evidence.initialize_ledger(ledger_path, signed_work_order)

    _assert_domain_error_with_cause(
        captured.value,
        LedgerInitializationError,
    )
    _assert_initialization_left_nothing(tmp_path, ledger_path)

    monkeypatch.setattr(evidence, "connect_ledger", real_connect)
    evidence.initialize_ledger(ledger_path, signed_work_order)
    assert ledger_path.is_file()


def test_concurrent_initialization_never_clobbers_the_winning_authority(
    tmp_path: Path,
    signed_work_order: WorkOrder,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
) -> None:
    ledger_path = tmp_path / "ledger.sqlite3"
    replacement_raw = signed_work_order.model_dump(mode="json")
    replacement_raw["objective"] = "competing authority"
    replacement = WorkOrder.model_validate(
        sign_payload(
            "work-order",
            replacement_raw,
            ephemeral_role_keys["Maintainer"][0],
        )
    )
    barrier = threading.Barrier(2)

    def initialize(work_order: WorkOrder) -> tuple[str, Exception | None]:
        barrier.wait()
        try:
            evidence.initialize_ledger(ledger_path, work_order)
        except Exception as error:
            return work_order.digest, error
        return work_order.digest, None

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = tuple(
            executor.map(initialize, (signed_work_order, replacement))
        )

    winners = [digest for digest, error in results if error is None]
    losers = [error for _, error in results if error is not None]
    assert len(winners) == 1
    assert len(losers) == 1
    assert isinstance(losers[0], LedgerInitializationError)
    assert ledger_path.is_file()
    connection = evidence.connect_ledger(ledger_path)
    try:
        assert evidence.load_authoritative_work_order(connection).digest == (
            winners[0]
        )
    finally:
        connection.close()
    assert {path.name for path in tmp_path.iterdir()} <= {
        ledger_path.name,
        _ledger_lock_path(ledger_path).name,
    }


def test_target_lock_serializes_from_existence_check_through_publish(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    signed_work_order: WorkOrder,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
) -> None:
    ledger_path = tmp_path / "ledger.sqlite3"
    replacement_raw = signed_work_order.model_dump(mode="json")
    replacement_raw["objective"] = "lock contender"
    replacement = WorkOrder.model_validate(
        sign_payload(
            "work-order",
            replacement_raw,
            ephemeral_role_keys["Maintainer"][0],
        )
    )
    real_link = evidence.os.link
    first_at_link = threading.Event()
    release_first = threading.Event()
    second_started = threading.Event()
    second_reached_link = threading.Event()
    link_calls = 0
    calls_guard = threading.Lock()

    def blocking_link(source, target, *args, **kwargs) -> None:
        nonlocal link_calls
        with calls_guard:
            link_calls += 1
            invocation = link_calls
        if invocation == 1:
            first_at_link.set()
            assert release_first.wait(timeout=5)
        else:
            second_reached_link.set()
        real_link(source, target, *args, **kwargs)

    def initialize(
        work_order: WorkOrder,
        *,
        contender: bool,
    ) -> tuple[str, Exception | None]:
        if contender:
            second_started.set()
        try:
            evidence.initialize_ledger(ledger_path, work_order)
        except Exception as error:
            return work_order.digest, error
        return work_order.digest, None

    monkeypatch.setattr(evidence.os, "link", blocking_link)
    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(
            initialize,
            signed_work_order,
            contender=False,
        )
        assert first_at_link.wait(timeout=5)
        second = executor.submit(
            initialize,
            replacement,
            contender=True,
        )
        assert second_started.wait(timeout=5)
        try:
            assert not second_reached_link.wait(timeout=0.2)
        finally:
            release_first.set()
        first_result = first.result(timeout=5)
        second_result = second.result(timeout=5)

    assert first_result == (signed_work_order.digest, None)
    assert isinstance(second_result[1], LedgerInitializationError)
    assert link_calls == 1
    assert _ledger_lock_path(ledger_path).is_file()
    connection = evidence.connect_ledger(ledger_path)
    try:
        assert (
            evidence.load_authoritative_work_order(connection)
            == signed_work_order
        )
    finally:
        connection.close()


# Threat boundary: these lock tests cover cooperative OpenWorkProof writers
# operating in a trusted parent directory. A non-cooperating process that
# replaces directory entries without taking this lock is outside this contract.
def test_unlock_failure_with_successful_close_does_not_negate_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    signed_work_order: WorkOrder,
) -> None:
    ledger_path = tmp_path / "ledger.sqlite3"
    real_flock = evidence.fcntl.flock
    unlock_attempts = 0

    def unlock_failing_flock(descriptor: int, operation: int) -> None:
        nonlocal unlock_attempts
        if operation == evidence.fcntl.LOCK_UN:
            unlock_attempts += 1
            raise OSError("injected explicit unlock failure")
        real_flock(descriptor, operation)

    monkeypatch.setattr(evidence.fcntl, "flock", unlock_failing_flock)
    evidence.initialize_ledger(ledger_path, signed_work_order)

    assert unlock_attempts >= 1
    assert ledger_path.is_file()
    assert _ledger_lock_path(ledger_path).is_file()
    connection = evidence.connect_ledger(ledger_path)
    try:
        assert (
            evidence.load_authoritative_work_order(connection)
            == signed_work_order
        )
    finally:
        connection.close()


def test_ambiguous_lock_close_failure_does_not_close_reused_descriptor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    signed_work_order: WorkOrder,
) -> None:
    ledger_path = tmp_path / "ledger.sqlite3"
    victim_path = tmp_path / "victim.txt"
    real_acquire = evidence._acquire_target_lock
    real_open = evidence.os.open
    real_close = evidence.os.close
    lock_descriptors: list[int] = []
    victim_descriptor: int | None = None
    close_attempts = 0

    def tracked_acquire(path: Path) -> int:
        descriptor = real_acquire(path)
        lock_descriptors.append(descriptor)
        return descriptor

    def ambiguous_close(descriptor: int) -> None:
        nonlocal close_attempts, victim_descriptor
        if lock_descriptors and descriptor == lock_descriptors[0]:
            close_attempts += 1
            if close_attempts == 1:
                real_close(descriptor)
                victim_descriptor = real_open(
                    victim_path,
                    evidence.os.O_RDWR | evidence.os.O_CREAT,
                    0o600,
                )
                assert victim_descriptor == descriptor
                raise OSError("ambiguous target lock close failure")
        real_close(descriptor)

    monkeypatch.setattr(evidence, "_acquire_target_lock", tracked_acquire)
    monkeypatch.setattr(evidence.os, "close", ambiguous_close)
    try:
        initialization_error: Exception | None = None
        try:
            evidence.initialize_ledger(ledger_path, signed_work_order)
        except Exception as error:
            initialization_error = error

        assert close_attempts == 1
        assert victim_descriptor is not None
        evidence.os.fstat(victim_descriptor)
        committed_error_type = getattr(
            evidence,
            "LedgerInitializationCommittedError",
            None,
        )
        assert committed_error_type is not None
        assert isinstance(initialization_error, committed_error_type)
        assert not isinstance(
            initialization_error,
            LedgerInitializationError,
        )
        assert initialization_error.committed is True
        assert initialization_error.ledger_path == ledger_path
        assert (
            initialization_error.work_order_digest
            == signed_work_order.digest
        )
        errors = _exception_tree(initialization_error)
        close_errors = [
            error
            for error in errors
            if (
            isinstance(error, OSError)
                and "ambiguous target lock close" in str(error)
            )
        ]
        assert len(close_errors) == 1

        assert ledger_path.is_file()
        connection = evidence.connect_ledger(ledger_path)
        try:
            assert (
                evidence.load_authoritative_work_order(connection)
                == signed_work_order
            )
            assert _ledger_snapshot(connection)["sequence"] == ((1, 1),)
            assert _ledger_snapshot(connection)["state"] == (
                (signed_work_order.digest, "issued", 0),
            )
        finally:
            connection.close()
    finally:
        if victim_descriptor is not None:
            try:
                real_close(victim_descriptor)
            except OSError:
                pass


def test_prepublish_close_failure_does_not_close_reused_descriptor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    signed_work_order: WorkOrder,
) -> None:
    ledger_path = tmp_path / "ledger.sqlite3"
    victim_path = tmp_path / "victim.txt"
    real_open = evidence.os.open
    real_close = evidence.os.close
    lock_descriptors: list[int] = []
    victim_descriptor: int | None = None
    close_attempts = 0

    def tracked_open(path, flags, mode=0o777) -> int:
        descriptor = real_open(path, flags, mode)
        if Path(path) == _ledger_lock_path(ledger_path):
            lock_descriptors.append(descriptor)
        return descriptor

    def primary_validation_failure(
        descriptor: int,
        lock_path: Path,
    ) -> None:
        raise OSError("primary lock validation failure")

    def ambiguous_close(descriptor: int) -> None:
        nonlocal close_attempts, victim_descriptor
        if lock_descriptors and descriptor == lock_descriptors[0]:
            close_attempts += 1
            if close_attempts == 1:
                real_close(descriptor)
                victim_descriptor = real_open(
                    victim_path,
                    evidence.os.O_RDWR | evidence.os.O_CREAT,
                    0o600,
                )
                assert victim_descriptor == descriptor
                raise OSError("ambiguous lock cleanup close failure")
        real_close(descriptor)

    monkeypatch.setattr(evidence.os, "open", tracked_open)
    monkeypatch.setattr(
        evidence,
        "_validate_open_lock",
        primary_validation_failure,
    )
    monkeypatch.setattr(evidence.os, "close", ambiguous_close)
    try:
        initialization_error: Exception | None = None
        try:
            evidence.initialize_ledger(ledger_path, signed_work_order)
        except Exception as error:
            initialization_error = error

        assert close_attempts == 1
        assert victim_descriptor is not None
        evidence.os.fstat(victim_descriptor)
        assert isinstance(
            initialization_error,
            LedgerInitializationError,
        )
        assert not getattr(initialization_error, "committed", False)
        errors = _exception_tree(initialization_error)
        assert any(
            isinstance(error, OSError)
            and "primary lock validation" in str(error)
            for error in errors
        )
        close_errors = [
            error
            for error in errors
            if (
                isinstance(error, OSError)
                and "ambiguous lock cleanup close" in str(error)
            )
        ]
        assert len(close_errors) == 1
        assert not ledger_path.exists()
        assert not any(
            candidate.name.startswith(f".{ledger_path.name}.")
            and candidate.name.endswith(".tmp")
            for candidate in tmp_path.iterdir()
        )
    finally:
        if victim_descriptor is not None:
            try:
                real_close(victim_descriptor)
            except OSError:
                pass


@pytest.mark.parametrize(
    "storage_case",
    ("not_sqlite", "missing_table", "missing_row", "bad_json", "query_error"),
)
def test_authority_load_maps_storage_failures_to_ledger_error_with_cause(
    tmp_path: Path,
    storage_case: str,
) -> None:
    database_path = tmp_path / f"{storage_case}.sqlite3"
    if storage_case == "not_sqlite":
        database_path.write_bytes(b"not a SQLite database")
        connection: sqlite3.Connection | _FaultingConnection = (
            sqlite3.connect(database_path, isolation_level=None)
        )
    else:
        raw_connection = sqlite3.connect(
            database_path,
            isolation_level=None,
        )
        if storage_case in {"missing_row", "bad_json"}:
            raw_connection.execute(
                """
                CREATE TABLE work_orders (
                    work_order_digest TEXT PRIMARY KEY,
                    work_order_json TEXT NOT NULL
                )
                """
            )
        if storage_case == "bad_json":
            raw_connection.execute(
                """
                INSERT INTO work_orders (
                    work_order_digest,
                    work_order_json
                )
                VALUES (?, ?)
                """,
                ("0" * 64, "{"),
            )
        connection = (
            _FaultingConnection(
                raw_connection,
                fail_when=lambda sql: "FROM WORK_ORDERS" in sql,
            )
            if storage_case == "query_error"
            else raw_connection
        )

    before = database_path.read_bytes()
    try:
        with pytest.raises(LedgerInitializationError) as captured:
            evidence.load_authoritative_work_order(connection)
        _assert_domain_error_with_cause(
            captured.value,
            LedgerInitializationError,
        )
        assert not connection.in_transaction
        assert database_path.read_bytes() == before
    finally:
        connection.close()


@pytest.mark.parametrize(
    "storage_case",
    ("not_sqlite", "missing_table", "missing_row", "bad_json"),
)
def test_root_activation_maps_malformed_storage_and_closes_connection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    storage_case: str,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now,
) -> None:
    ledger_path = tmp_path / f"{storage_case}.sqlite3"
    if storage_case == "not_sqlite":
        ledger_path.write_bytes(b"not a SQLite database")
    else:
        raw_connection = sqlite3.connect(
            ledger_path,
            isolation_level=None,
        )
        if storage_case in {"missing_row", "bad_json"}:
            raw_connection.execute(
                """
                CREATE TABLE work_orders (
                    work_order_digest TEXT PRIMARY KEY,
                    work_order_json TEXT NOT NULL
                )
                """
            )
        if storage_case == "bad_json":
            raw_connection.execute(
                """
                INSERT INTO work_orders (
                    work_order_digest,
                    work_order_json
                )
                VALUES (?, ?)
                """,
                ("0" * 64, "{"),
            )
        raw_connection.close()

    request = _activation_request(
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        actor_role="Manager",
        nonce="7" * 64,
    )
    real_connect = evidence.connect_ledger
    connections: list[_FaultingConnection] = []

    def tracked_connect(path: Path) -> _FaultingConnection:
        connection = _FaultingConnection(
            real_connect(path),
            fail_when=lambda sql: False,
        )
        connections.append(connection)
        return connection

    monkeypatch.setattr(evidence, "connect_ledger", tracked_connect)
    with pytest.raises(RootActivationError) as captured:
        evidence.activate_root_grant(
            ledger_path,
            signed_root_grant,
            request,
            sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
            clock=lambda: fixed_now,
        )

    _assert_domain_error_with_cause(captured.value, RootActivationError)
    assert all(connection.closed for connection in connections)


def test_root_activation_maps_connect_failure_without_sqlite_leak(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now,
) -> None:
    ledger_path = tmp_path / "ledger.sqlite3"
    initialize_ledger(ledger_path, signed_work_order)
    real_connect = evidence.connect_ledger
    before_connection = real_connect(ledger_path)
    try:
        before = _ledger_snapshot(before_connection)
    finally:
        before_connection.close()
    request = _activation_request(
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        actor_role="Manager",
        nonce="8" * 64,
    )

    def failing_connect(path: Path) -> sqlite3.Connection:
        raise sqlite3.OperationalError("injected connection failure")

    monkeypatch.setattr(evidence, "connect_ledger", failing_connect)
    with pytest.raises(RootActivationError) as captured:
        evidence.activate_root_grant(
            ledger_path,
            signed_root_grant,
            request,
            sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
            clock=lambda: fixed_now,
        )

    _assert_domain_error_with_cause(captured.value, RootActivationError)
    monkeypatch.setattr(evidence, "connect_ledger", real_connect)
    after_connection = real_connect(ledger_path)
    try:
        assert _ledger_snapshot(after_connection) == before
    finally:
        after_connection.close()


@pytest.mark.parametrize(
    "query_marker",
    ("FROM WORK_ORDERS", "FROM WORK_ORDER_STATE"),
)
def test_root_activation_maps_query_failure_and_closes_without_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    query_marker: str,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now,
) -> None:
    ledger_path = tmp_path / "ledger.sqlite3"
    initialize_ledger(ledger_path, signed_work_order)
    request = _activation_request(
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        actor_role="Manager",
        nonce="9" * 64,
    )
    real_connect = evidence.connect_ledger
    before_connection = real_connect(ledger_path)
    try:
        before = _ledger_snapshot(before_connection)
    finally:
        before_connection.close()
    connections: list[_FaultingConnection] = []

    def faulting_connect(path: Path) -> _FaultingConnection:
        connection = _FaultingConnection(
            real_connect(path),
            fail_when=lambda sql: query_marker in sql,
        )
        connections.append(connection)
        return connection

    monkeypatch.setattr(evidence, "connect_ledger", faulting_connect)
    with pytest.raises(RootActivationError) as captured:
        evidence.activate_root_grant(
            ledger_path,
            signed_root_grant,
            request,
            sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
            clock=lambda: fixed_now,
        )

    _assert_domain_error_with_cause(captured.value, RootActivationError)
    assert connections and all(connection.closed for connection in connections)
    monkeypatch.setattr(evidence, "connect_ledger", real_connect)
    after_connection = real_connect(ledger_path)
    try:
        assert _ledger_snapshot(after_connection) == before
    finally:
        after_connection.close()


def test_root_activation_preserves_domain_error_when_rollback_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now,
) -> None:
    ledger_path = tmp_path / "ledger.sqlite3"
    initialize_ledger(ledger_path, signed_work_order)
    wrong_actor_request = _activation_request(
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        actor_role="Developer",
        nonce="a" * 64,
    )
    real_connect = evidence.connect_ledger
    before_connection = real_connect(ledger_path)
    try:
        before = _ledger_snapshot(before_connection)
    finally:
        before_connection.close()
    connections: list[_FaultingConnection] = []

    def rollback_failing_connect(path: Path) -> _FaultingConnection:
        connection = _FaultingConnection(
            real_connect(path),
            fail_when=lambda sql: sql == "ROLLBACK",
            fail_after_execute=True,
        )
        connections.append(connection)
        return connection

    monkeypatch.setattr(
        evidence,
        "connect_ledger",
        rollback_failing_connect,
    )
    with pytest.raises(RootActivationError) as captured:
        evidence.activate_root_grant(
            ledger_path,
            signed_root_grant,
            wrong_actor_request,
            sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
            clock=lambda: fixed_now,
        )

    _assert_domain_error_with_cause(captured.value, RootActivationError)
    assert connections and all(connection.closed for connection in connections)
    monkeypatch.setattr(evidence, "connect_ledger", real_connect)
    after_connection = real_connect(ledger_path)
    try:
        assert _ledger_snapshot(after_connection) == before
    finally:
        after_connection.close()


@pytest.mark.parametrize(
    "checkpoint_row",
    ((1, 1, 0), (0, 2, 2), None),
    ids=("busy", "nonempty", "exception"),
)
def test_checkpoint_must_be_clean_before_initialization_can_publish(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    signed_work_order: WorkOrder,
    checkpoint_row: tuple[int, int, int] | None,
) -> None:
    ledger_path = tmp_path / "ledger.sqlite3"
    real_connect = evidence.connect_ledger
    connections: list[_CheckpointConnection] = []

    def checkpoint_connect(path: Path) -> _CheckpointConnection:
        connection = _CheckpointConnection(
            real_connect(path),
            row=checkpoint_row,
        )
        connections.append(connection)
        return connection

    monkeypatch.setattr(evidence, "connect_ledger", checkpoint_connect)
    with pytest.raises(LedgerInitializationError) as captured:
        evidence.initialize_ledger(ledger_path, signed_work_order)

    _assert_domain_error_with_cause(
        captured.value,
        LedgerInitializationError,
    )
    assert connections and all(connection.closed for connection in connections)
    _assert_initialization_left_nothing(tmp_path, ledger_path)

    monkeypatch.setattr(evidence, "connect_ledger", real_connect)
    evidence.initialize_ledger(ledger_path, signed_work_order)
    assert ledger_path.is_file()


@pytest.mark.parametrize(
    "corruption",
    ("authority", "sequence", "state", "reservation"),
)
def test_initialization_reopens_and_revalidates_frozen_snapshot_before_publish(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    signed_work_order: WorkOrder,
    corruption: str,
) -> None:
    ledger_path = tmp_path / "ledger.sqlite3"
    real_connect = evidence.connect_ledger
    should_corrupt = [True]
    connections: list[_CorruptOnFirstCloseConnection] = []

    def corrupting_connect(path: Path) -> _CorruptOnFirstCloseConnection:
        connection = _CorruptOnFirstCloseConnection(
            real_connect(path),
            database_path=Path(path),
            corruption=corruption,
            should_corrupt=should_corrupt,
        )
        connections.append(connection)
        return connection

    monkeypatch.setattr(evidence, "connect_ledger", corrupting_connect)
    with pytest.raises(LedgerInitializationError) as captured:
        evidence.initialize_ledger(ledger_path, signed_work_order)

    _assert_domain_error_with_cause(
        captured.value,
        LedgerInitializationError,
    )
    assert len(connections) >= 2
    assert all(connection.closed for connection in connections)
    _assert_initialization_left_nothing(tmp_path, ledger_path)

    monkeypatch.setattr(evidence, "connect_ledger", real_connect)
    evidence.initialize_ledger(ledger_path, signed_work_order)
    assert ledger_path.is_file()


def test_directory_fsync_failure_with_owned_final_withdraws_only_owned_inode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    signed_work_order: WorkOrder,
) -> None:
    ledger_path = tmp_path / "ledger.sqlite3"
    real_fsync_directory = evidence._fsync_directory
    calls = 0

    def fail_after_owned_publish(path: Path) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            temporary_paths = tuple(
                candidate
                for candidate in tmp_path.iterdir()
                if candidate.name.startswith(f".{ledger_path.name}.")
                and candidate.name.endswith(".tmp")
            )
            assert len(temporary_paths) == 1
            assert ledger_path.is_file()
            assert ledger_path.samefile(temporary_paths[0])
            raise OSError("injected directory fsync failure")
        real_fsync_directory(path)

    monkeypatch.setattr(
        evidence,
        "_fsync_directory",
        fail_after_owned_publish,
    )
    with pytest.raises(LedgerInitializationError) as captured:
        evidence.initialize_ledger(ledger_path, signed_work_order)

    _assert_domain_error_with_cause(
        captured.value,
        LedgerInitializationError,
    )
    assert calls >= 2
    _assert_initialization_left_nothing(tmp_path, ledger_path)

    monkeypatch.setattr(
        evidence,
        "_fsync_directory",
        real_fsync_directory,
    )
    evidence.initialize_ledger(ledger_path, signed_work_order)
    assert ledger_path.is_file()


def test_target_lock_covers_post_link_failure_and_withdrawal_before_next_writer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    signed_work_order: WorkOrder,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
) -> None:
    ledger_path = tmp_path / "ledger.sqlite3"
    replacement_raw = signed_work_order.model_dump(mode="json")
    replacement_raw["objective"] = "coordinated successor"
    replacement = WorkOrder.model_validate(
        sign_payload(
            "work-order",
            replacement_raw,
            ephemeral_role_keys["Maintainer"][0],
        )
    )
    real_fsync_directory = evidence._fsync_directory
    first_at_post_link_fsync = threading.Event()
    release_first = threading.Event()
    second_done = threading.Event()
    calls = 0

    def block_then_fail(path: Path) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            assert ledger_path.is_file()
            first_at_post_link_fsync.set()
            assert release_first.wait(timeout=5)
            raise OSError("injected directory fsync failure")
        real_fsync_directory(path)

    def initialize(
        work_order: WorkOrder,
    ) -> tuple[str, Exception | None]:
        try:
            evidence.initialize_ledger(ledger_path, work_order)
        except Exception as error:
            return work_order.digest, error
        return work_order.digest, None

    monkeypatch.setattr(evidence, "_fsync_directory", block_then_fail)
    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(initialize, signed_work_order)
        assert first_at_post_link_fsync.wait(timeout=5)
        second = executor.submit(initialize, replacement)
        second.add_done_callback(lambda _: second_done.set())
        try:
            assert not second_done.wait(timeout=0.2)
        finally:
            release_first.set()
        first_result = first.result(timeout=5)
        second_result = second.result(timeout=5)

    assert calls >= 2
    assert isinstance(first_result[1], LedgerInitializationError)
    assert second_result == (replacement.digest, None)
    assert ledger_path.is_file()
    assert _ledger_lock_path(ledger_path).is_file()
    connection = evidence.connect_ledger(ledger_path)
    try:
        assert (
            evidence.load_authoritative_work_order(connection)
            == replacement
        )
    finally:
        connection.close()


def test_owned_temporary_unlink_failure_cannot_report_initialization_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    signed_work_order: WorkOrder,
) -> None:
    ledger_path = tmp_path / "ledger.sqlite3"
    real_unlink = Path.unlink
    failed = False

    def fail_once(
        path: Path,
        missing_ok: bool = False,
    ) -> None:
        nonlocal failed
        if (
            not failed
            and path.parent == tmp_path
            and path.name.startswith(f".{ledger_path.name}.")
            and path.name.endswith(".tmp")
        ):
            failed = True
            raise OSError("injected owned temporary unlink failure")
        real_unlink(path, missing_ok=missing_ok)

    monkeypatch.setattr(Path, "unlink", fail_once)
    with pytest.raises(LedgerInitializationError) as captured:
        evidence.initialize_ledger(ledger_path, signed_work_order)

    _assert_domain_error_with_cause(
        captured.value,
        LedgerInitializationError,
    )
    assert failed
    _assert_initialization_left_nothing(tmp_path, ledger_path)

    monkeypatch.setattr(Path, "unlink", real_unlink)
    evidence.initialize_ledger(ledger_path, signed_work_order)
    assert ledger_path.is_file()


def test_rollback_and_original_activation_failures_remain_inspectable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now,
) -> None:
    ledger_path = tmp_path / "ledger.sqlite3"
    initialize_ledger(ledger_path, signed_work_order)
    wrong_actor_request = _activation_request(
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        actor_role="Developer",
        nonce="c" * 64,
    )
    real_connect = evidence.connect_ledger

    def rollback_failing_connect(path: Path) -> _FaultingConnection:
        return _FaultingConnection(
            real_connect(path),
            fail_when=lambda sql: sql == "ROLLBACK",
            fail_after_execute=True,
        )

    monkeypatch.setattr(
        evidence,
        "connect_ledger",
        rollback_failing_connect,
    )
    with pytest.raises(RootActivationError) as captured:
        evidence.activate_root_grant(
            ledger_path,
            signed_root_grant,
            wrong_actor_request,
            sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
            clock=lambda: fixed_now,
        )

    errors = _exception_tree(captured.value)
    assert any(
        isinstance(error, RootActivationError)
        and "authority is invalid" in str(error)
        for error in errors
    )
    assert any(
        isinstance(error, sqlite3.OperationalError)
        and "rollback" in str(error)
        for error in errors
    )


def test_transient_close_failure_returns_committed_receipt_after_retry_closes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now,
) -> None:
    ledger_path = tmp_path / "ledger.sqlite3"
    initialize_ledger(ledger_path, signed_work_order)
    request = _activation_request(
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        actor_role="Manager",
        nonce="d" * 64,
    )
    real_connect = evidence.connect_ledger
    connections: list[_CloseFailsOnceConnection] = []

    def close_failing_connect(path: Path) -> _CloseFailsOnceConnection:
        connection = _CloseFailsOnceConnection(real_connect(path))
        connections.append(connection)
        return connection

    monkeypatch.setattr(evidence, "connect_ledger", close_failing_connect)
    try:
        receipt = evidence.activate_root_grant(
            ledger_path,
            signed_root_grant,
            request,
            sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
            clock=lambda: fixed_now,
        )
        assert connections and all(
            connection.closed for connection in connections
        )
        assert connections[0].close_attempts == 2
        with pytest.raises(sqlite3.ProgrammingError):
            connections[0]._connection.execute("SELECT 1")
        assert receipt.event_type == "grant_issued"
        assert receipt.sequence == 1
        monkeypatch.setattr(evidence, "connect_ledger", real_connect)
        connection = real_connect(ledger_path)
        try:
            snapshot = _ledger_snapshot(connection)
            assert len(snapshot["receipts"]) == 1
            assert snapshot["receipts"][0][0] == receipt.receipt_id
            assert snapshot["state"] == (
                (signed_work_order.digest, "running", 1),
            )
        finally:
            connection.close()
    finally:
        for connection in connections:
            connection.force_close()


def test_persistent_close_failure_reports_committed_indeterminate_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now,
) -> None:
    ledger_path = tmp_path / "ledger.sqlite3"
    initialize_ledger(ledger_path, signed_work_order)
    request = _activation_request(
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        actor_role="Manager",
        nonce="f" * 64,
    )
    real_connect = evidence.connect_ledger
    connections: list[_CloseAlwaysFailsConnection] = []

    def close_failing_connect(path: Path) -> _CloseAlwaysFailsConnection:
        connection = _CloseAlwaysFailsConnection(real_connect(path))
        connections.append(connection)
        return connection

    monkeypatch.setattr(evidence, "connect_ledger", close_failing_connect)
    try:
        with pytest.raises(Exception) as captured:
            evidence.activate_root_grant(
                ledger_path,
                signed_root_grant,
                request,
                sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
                clock=lambda: fixed_now,
            )

        committed_error_type = getattr(
            evidence,
            "RootActivationCommittedError",
            None,
        )
        assert committed_error_type is not None
        assert isinstance(captured.value, committed_error_type)
        assert not isinstance(captured.value, RootActivationError)
        assert captured.value.committed is True
        receipt = captured.value.receipt
        assert receipt.event_type == "grant_issued"
        assert receipt.sequence == 1
        assert any(
            isinstance(error, sqlite3.OperationalError)
            and "close" in str(error)
            for error in _exception_tree(captured.value)
        )
        assert connections[0].close_attempts >= 3

        monkeypatch.setattr(evidence, "connect_ledger", real_connect)
        connection = real_connect(ledger_path)
        try:
            snapshot = _ledger_snapshot(connection)
            assert len(snapshot["receipts"]) == 1
            assert snapshot["receipts"][0] == (
                receipt.receipt_id,
                request.nonce,
                1,
            )
            assert len(snapshot["grants"]) == 1
            assert snapshot["sequence"] == ((1, 2),)
            assert snapshot["state"] == (
                (signed_work_order.digest, "running", 1),
            )
        finally:
            connection.close()
    finally:
        for connection in connections:
            connection.force_close()


def test_original_and_secondary_close_failures_are_both_preserved(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    signed_work_order: WorkOrder,
    signed_root_grant: CapabilityGrant,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
    fixed_now,
) -> None:
    ledger_path = tmp_path / "ledger.sqlite3"
    initialize_ledger(ledger_path, signed_work_order)
    request = _activation_request(
        signed_work_order,
        signed_root_grant,
        ephemeral_role_keys,
        actor_role="Developer",
        nonce="e" * 64,
    )
    real_connect = evidence.connect_ledger
    connections: list[_CloseFailsOnceConnection] = []

    def close_failing_connect(path: Path) -> _CloseFailsOnceConnection:
        connection = _CloseFailsOnceConnection(real_connect(path))
        connections.append(connection)
        return connection

    monkeypatch.setattr(evidence, "connect_ledger", close_failing_connect)
    try:
        with pytest.raises(RootActivationError) as captured:
            evidence.activate_root_grant(
                ledger_path,
                signed_root_grant,
                request,
                sidecar_private_key=ephemeral_role_keys["Sidecar"][0],
                clock=lambda: fixed_now,
            )

        errors = _exception_tree(captured.value)
        assert any(
            isinstance(error, RootActivationError)
            and "authority is invalid" in str(error)
            for error in errors
        )
        assert any(
            isinstance(error, sqlite3.OperationalError)
            and "close" in str(error)
            for error in errors
        )
        assert connections and all(
            connection.closed for connection in connections
        )
    finally:
        for connection in connections:
            connection.force_close()
