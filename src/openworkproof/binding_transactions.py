"""Atomic append-only transactions for Judgment-to-Action Binding v0.4."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Literal, TypeVar

from openworkproof import evidence
from openworkproof.models import JudgmentCommitment, KeyBinding
from openworkproof.signing import decode_and_verify_key_binding, verify_payload


class BindingInputError(ValueError):
    """A v0.4 binding input is invalid and must not be committed."""


class BindingTransactionError(RuntimeError):
    """A v0.4 binding ledger transaction did not commit."""


class BindingCommittedError(BindingTransactionError):
    """The exact v0.4 object committed despite an incomplete local response."""

    def __init__(self, message: str, committed: object) -> None:
        super().__init__(message)
        self.committed = committed


class BindingCommitIndeterminateError(BindingTransactionError):
    """The v0.4 transaction outcome cannot be proved; blind retry is unsafe."""


@dataclass(frozen=True, slots=True)
class JudgmentAuthorityContext:
    """Explicit customer authority facts for a WorkOrder-independent commitment.

    ``transaction_time`` is a caller-frozen protocol input, not an independently
    attested wall clock.
    """

    authority_namespace: str
    authority_binding: KeyBinding
    transaction_time: datetime


_Fault = Literal[
    "insert_failure",
    "before_commit",
    "commit_failure",
    "commit_ack_loss",
    "readback_failure",
    "cleanup_failure",
]
_T = TypeVar("_T")


def _canonical_model_blob(value: JudgmentCommitment) -> bytes:
    return evidence._canonical_json(value.model_dump(mode="json")).encode("utf-8")


def _canonical_utc_second(value: datetime) -> str:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() != timezone.utc.utcoffset(value)
        or value.microsecond != 0
    ):
        raise BindingInputError(
            "judgment transaction time must be a canonical UTC second"
        )
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def _validate_judgment_authority(
    commitment: JudgmentCommitment,
    context: JudgmentAuthorityContext,
) -> str:
    if not isinstance(context, JudgmentAuthorityContext):
        raise BindingInputError("judgment authority context is malformed")
    if type(context.authority_namespace) is not str or (
        context.authority_namespace != commitment.authority_namespace
    ):
        raise BindingInputError("judgment authority namespace does not match")
    binding = context.authority_binding
    if not isinstance(binding, KeyBinding) or binding.role != "Acceptor":
        raise BindingInputError("judgment signer must be the Customer Acceptor")
    try:
        public_key = decode_and_verify_key_binding(binding)
    except Exception as error:
        raise BindingInputError("Customer Acceptor key binding is invalid") from error
    if commitment.signer_key_id != binding.key_id:
        raise BindingInputError("judgment signer is not the Customer Acceptor")
    if not verify_payload(
        "judgment-commitment",
        commitment.model_dump(mode="json"),
        public_key,
        version="0.4",
    ):
        raise BindingInputError("judgment commitment signature is invalid")
    return _canonical_utc_second(context.transaction_time)


def _cleanup_transaction(
    connection: sqlite3.Connection | None,
    lock_descriptor: int | None,
) -> tuple[Exception, ...]:
    errors: list[Exception] = []
    close_error = evidence._best_effort_close(connection)
    if close_error is not None:
        errors.append(close_error)
    _, release_errors = evidence._release_target_lock(lock_descriptor)
    errors.extend(release_errors)
    return tuple(errors)


def _commit_with_readback(
    path: Path,
    *,
    stage: Callable[[sqlite3.Connection], _T],
    readback: Callable[[_T], bool],
    fault: _Fault | None,
) -> _T:
    if fault not in {
        None,
        "insert_failure",
        "before_commit",
        "commit_failure",
        "commit_ack_loss",
        "readback_failure",
        "cleanup_failure",
    }:
        raise BindingTransactionError("unknown binding transaction fault")
    if not path.is_file():
        raise BindingTransactionError("binding ledger is unavailable")
    lock_descriptor: int | None = None
    connection: sqlite3.Connection | None = None
    commit_attempted = False
    result: _T | None = None
    try:
        lock_descriptor, _ = evidence._borrow_or_acquire_target_lock(path, None)
        connection = evidence.connect_ledger(path)
        connection.execute("BEGIN IMMEDIATE")
        result = stage(connection)
        if fault == "before_commit":
            raise BindingTransactionError("injected fault before commit")
        if fault in {"insert_failure", "commit_failure"}:
            raise BindingTransactionError(
                f"injected fault: {fault.replace('_', ' ')}"
            )
        commit_attempted = True
        connection.execute("COMMIT")
        if fault == "commit_ack_loss":
            raise OSError("injected commit acknowledgement loss")
        if fault == "readback_failure":
            raise BindingCommitIndeterminateError(
                "binding readback was deliberately unavailable"
            )
        if not readback(result):
            raise BindingCommitIndeterminateError(
                "binding readback could not confirm the exact commit"
            )
    except Exception as error:
        evidence._best_effort_rollback(connection)
        cleanup_errors = _cleanup_transaction(connection, lock_descriptor)
        if isinstance(error, (BindingCommittedError, BindingCommitIndeterminateError)):
            raise error
        if commit_attempted and result is not None:
            try:
                confirmed = readback(result)
            except Exception as readback_error:
                raise BindingCommitIndeterminateError(
                    "binding commit outcome is indeterminate"
                ) from readback_error
            if confirmed:
                raise BindingCommittedError(
                    "binding object committed but acknowledgement was lost",
                    result,
                ) from error
            raise BindingCommitIndeterminateError(
                "binding commit outcome is indeterminate"
            ) from error
        if isinstance(error, (BindingInputError, BindingTransactionError)) and not cleanup_errors:
            raise error
        raise BindingTransactionError("binding transaction failed") from error
    assert result is not None
    cleanup_errors = list(_cleanup_transaction(connection, lock_descriptor))
    if fault == "cleanup_failure":
        cleanup_errors.append(OSError("injected cleanup failure"))
    if cleanup_errors:
        raise BindingCommittedError(
            "binding object committed but cleanup failed", result
        ) from cleanup_errors[0]
    return result


def _exact_judgment_readback(
    path: Path,
    commitment: JudgmentCommitment,
    committed_at: str,
) -> bool:
    connection = evidence.connect_ledger(path)
    try:
        row = connection.execute(
            """
            SELECT commitment_digest, authority_namespace, subject_id, nonce,
                   signer_key_id, commitment_json, committed_at
            FROM judgment_commitments_v04 WHERE commitment_id = ?
            """,
            (commitment.commitment_id,),
        ).fetchone()
        return row == (
            commitment.digest,
            commitment.authority_namespace,
            commitment.subject_id,
            commitment.nonce,
            commitment.signer_key_id,
            _canonical_model_blob(commitment),
            committed_at,
        )
    finally:
        connection.close()


def commit_judgment_commitment(
    ledger_path: Path,
    commitment: JudgmentCommitment,
    context: JudgmentAuthorityContext,
    *,
    fault: _Fault | None = None,
) -> JudgmentCommitment:
    """Commit one Acceptor-signed judgment without claiming WorkOrder binding."""

    path = Path(ledger_path)
    try:
        parsed = JudgmentCommitment.model_validate(
            commitment.model_dump(mode="json")
        )
    except Exception as error:
        raise BindingInputError("judgment commitment is malformed") from error
    committed_at = _validate_judgment_authority(parsed, context)
    canonical = _canonical_model_blob(parsed)

    def stage(connection: sqlite3.Connection) -> JudgmentCommitment:
        existing = connection.execute(
            """
            SELECT commitment_digest, authority_namespace, subject_id, nonce,
                   signer_key_id, commitment_json
            FROM judgment_commitments_v04 WHERE commitment_id = ?
            """,
            (parsed.commitment_id,),
        ).fetchone()
        exact = (
            parsed.digest,
            parsed.authority_namespace,
            parsed.subject_id,
            parsed.nonce,
            parsed.signer_key_id,
            canonical,
        )
        if existing is not None:
            if existing == exact:
                raise BindingCommittedError(
                    "the exact judgment commitment is already committed", parsed
                )
            raise BindingTransactionError("judgment commitment id is already used")
        if not parsed.valid_from <= context.transaction_time < parsed.expires_at:
            raise BindingInputError(
                "judgment commitment validity window is not current"
            )
        if connection.execute(
            """
            SELECT 1 FROM judgment_commitments_v04
            WHERE signer_key_id = ? AND nonce = ?
            """,
            (parsed.signer_key_id, parsed.nonce),
        ).fetchone() is not None:
            raise BindingTransactionError("judgment commitment nonce is already used")
        connection.execute(
            """
            INSERT INTO judgment_commitments_v04 (
                commitment_id, commitment_digest, authority_namespace,
                subject_id, nonce, signer_key_id, commitment_json, committed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                parsed.commitment_id,
                parsed.digest,
                parsed.authority_namespace,
                parsed.subject_id,
                parsed.nonce,
                parsed.signer_key_id,
                canonical,
                committed_at,
            ),
        )
        return parsed

    return _commit_with_readback(
        path,
        stage=stage,
        readback=lambda _: _exact_judgment_readback(path, parsed, committed_at),
        fault=fault,
    )
