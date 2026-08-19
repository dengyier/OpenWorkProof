"""RetractionReceipt v0.5 transaction layer.

A retraction is a first-class, signed, append-only record that marks a
previously issued receipt's conclusion as refuted or downgraded. The original
receipt is never modified; the retraction layers on top and is queryable.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, Sequence

import rfc8785

import openworkproof.evidence as evidence
from openworkproof.models import (
    RetractionReceiptV05,
    retraction_receipt_id,
)
from openworkproof.signing import (
    decode_and_verify_key_binding,
    verify_payload,
)


class RetractionTransactionError(RuntimeError):
    """A retraction receipt could not be committed."""


class RetractionCommittedError(RetractionTransactionError):
    """The exact retraction receipt is already committed."""


class RetractionCommitIndeterminateError(RetractionTransactionError):
    """The retraction commit outcome is indeterminate."""


_RETRACTION_TABLE = "retraction_receipts_v05"
_RETRACTION_PARENT_TABLE = "retraction_receipt_parents_v05"


def _target_receipt_committed(connection, receipt_id: str) -> bool:
    return (
        connection.execute(
            "SELECT 1 FROM receipts WHERE receipt_id = ?",
            (receipt_id,),
        ).fetchone()
        is not None
    )


def _exact_retraction_readback(
    ledger_path: Path,
    retraction: RetractionReceiptV05,
) -> bool:
    """Replay the committed retraction row and parents exactly."""

    try:
        connection = evidence.connect_ledger(ledger_path)
        try:
            row = connection.execute(
                f"""
                SELECT retraction_digest, target_receipt_id,
                       target_receipt_digest, retraction_json
                FROM {_RETRACTION_TABLE}
                WHERE retraction_id = ?
                """,
                (retraction.retraction_id,),
            ).fetchone()
            expected = (
                retraction.digest,
                retraction.target_receipt_id,
                retraction.target_receipt_digest,
                rfc8785.dumps(retraction.model_dump(mode="json")),
            )
            parents = tuple(
                connection.execute(
                    f"""
                    SELECT ordinal, parent_id
                    FROM {_RETRACTION_PARENT_TABLE}
                    WHERE retraction_id = ?
                    ORDER BY ordinal
                    """,
                    (retraction.retraction_id,),
                )
            )
        finally:
            connection.close()
    except Exception:
        return False
    return row == expected and parents == tuple(
        (ordinal, parent_id)
        for ordinal, parent_id in enumerate(retraction.causal_parent_ids)
    )


def _latest_retraction_for(
    connection,
    receipt_id: str,
) -> RetractionReceiptV05 | None:
    """Return the latest committed retraction targeting a receipt, if any.

    This version does not allow retracting a retraction, so a receipt has at
    most one effective retraction; the earliest committed row is the binding
    one. Ordering by committed_at with the earliest row keeps the status
    stable under replay.
    """

    row = connection.execute(
        f"""
        SELECT retraction_json
        FROM {_RETRACTION_TABLE}
        WHERE target_receipt_id = ?
        ORDER BY committed_at ASC, retraction_id ASC
        LIMIT 1
        """,
        (receipt_id,),
    ).fetchone()
    if row is None:
        return None
    try:
        return RetractionReceiptV05.model_validate_json(row[0])
    except Exception as error:
        raise RetractionTransactionError(
            "committed retraction row is malformed"
        ) from error


def commit_retraction_receipt(
    ledger_path: Path,
    retraction: RetractionReceiptV05,
    *,
    fault: Literal[
        "before_commit",
        "commit_ack_loss",
        "readback_failure",
        "cleanup_failure",
    ]
    | None = None,
) -> RetractionReceiptV05:
    """Append a signed Manager/Verifier retraction receipt.

    The original receipt stays immutable; this transaction appends the
    retraction as a new append-only row and binds its causal parents. The
    retraction is only valid when the target receipt exists in the same
    ledger with the exact digest, the signer is a WorkOrder-bound Manager or
    Verifier, the signature verifies, the nonce is unused, and the retraction
    time follows the target receipt's time.
    """

    if fault not in {
        None,
        "before_commit",
        "commit_ack_loss",
        "readback_failure",
        "cleanup_failure",
    }:
        raise RetractionTransactionError("unknown retraction fault")
    path = Path(ledger_path)
    if not path.is_file():
        raise RetractionTransactionError("retraction ledger is unavailable")
    try:
        parsed = RetractionReceiptV05.model_validate(
            retraction.model_dump(mode="json")
        )
    except Exception as error:
        raise RetractionTransactionError(
            "retraction receipt is malformed"
        ) from error
    if parsed.retraction_id != retraction_receipt_id(parsed):
        raise RetractionTransactionError("retraction id does not match content")

    lock_descriptor: int | None = None
    connection = None
    committed = False
    try:
        lock_descriptor, _ = evidence._borrow_or_acquire_target_lock(path, None)
        connection = evidence.connect_ledger(path)
        connection.execute("BEGIN IMMEDIATE")
        work_order = evidence.load_authoritative_work_order(connection)
        try:
            parsed.validate_against_work_order(work_order)
        except ValueError as error:
            raise RetractionTransactionError(str(error)) from error
        signer = next(
            (
                binding
                for binding in work_order.key_bindings
                if binding.key_id == parsed.signer_key_id
            ),
            None,
        )
        if signer is None:
            raise RetractionTransactionError(
                "retraction signer is not WorkOrder-bound"
            )
        signer_key = decode_and_verify_key_binding(signer)
        if not verify_payload(
            "retraction-receipt",
            parsed.model_dump(mode="json"),
            signer_key,
            version="0.5",
        ):
            raise RetractionTransactionError(
                "retraction receipt signature is invalid"
            )
        if not _target_receipt_committed(connection, parsed.target_receipt_id):
            raise RetractionTransactionError(
                "retraction target receipt is not committed"
            )
        target_row = connection.execute(
            "SELECT receipt_json FROM receipts WHERE receipt_id = ?",
            (parsed.target_receipt_id,),
        ).fetchone()
        if target_row is None:
            raise RetractionTransactionError(
                "retraction target receipt is unavailable"
            )
        target = target_row[0]
        # The target digest is the receipt's signed canonical digest; reparse
        # the stored row and compare the model digest.
        try:
            from openworkproof.models import parse_action_receipt_json

            target_receipt = parse_action_receipt_json(target)
            target_receipt.validate_against_work_order(work_order)
        except Exception as error:
            raise RetractionTransactionError(
                "retraction target receipt cannot be replayed"
            ) from error
        if parsed.target_receipt_digest != target_receipt.digest:
            raise RetractionTransactionError(
                "retraction target digest does not match committed receipt"
            )
        if not (
            target_receipt.occurred_at < parsed.retracted_at
        ):
            raise RetractionTransactionError(
                "retraction time must follow the target receipt time"
            )
        existing = connection.execute(
            f"""
            SELECT retraction_digest, target_receipt_id,
                   target_receipt_digest, retraction_json
            FROM {_RETRACTION_TABLE}
            WHERE retraction_id = ?
            """,
            (parsed.retraction_id,),
        ).fetchone()
        expected = (
            parsed.digest,
            parsed.target_receipt_id,
            parsed.target_receipt_digest,
            rfc8785.dumps(parsed.model_dump(mode="json")),
        )
        if existing is not None:
            if existing == expected and _exact_retraction_readback(
                path, parsed
            ):
                raise RetractionCommittedError(
                    "the exact retraction receipt is already committed",
                    parsed,
                )
            raise RetractionTransactionError(
                "retraction receipt id is already used"
            )
        prior = _latest_retraction_for(connection, parsed.target_receipt_id)
        if prior is not None:
            raise RetractionTransactionError(
                "target receipt already has a retraction"
            )
        _assert_retraction_nonce_unused(connection, parsed.nonce)
        connection.execute(
            f"""
            INSERT INTO {_RETRACTION_TABLE} (
                retraction_id, retraction_digest, work_order_digest,
                target_receipt_id, target_receipt_digest,
                retraction_json, committed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                parsed.retraction_id,
                parsed.digest,
                parsed.work_order_digest,
                parsed.target_receipt_id,
                parsed.target_receipt_digest,
                rfc8785.dumps(parsed.model_dump(mode="json")),
                datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            ),
        )
        for ordinal, parent_id in enumerate(parsed.causal_parent_ids):
            connection.execute(
                f"""
                INSERT INTO {_RETRACTION_PARENT_TABLE} (
                    retraction_id, ordinal, parent_id
                ) VALUES (?, ?, ?)
                """,
                (parsed.retraction_id, ordinal, parent_id),
            )
        if fault == "before_commit":
            raise RetractionTransactionError("injected fault before commit")
        connection.execute("COMMIT")
        committed = True
        if fault == "commit_ack_loss":
            raise OSError("injected commit acknowledgement loss")
        if fault == "readback_failure":
            raise RetractionCommitIndeterminateError(
                "retraction readback was unavailable"
            )
        if not _exact_retraction_readback(path, parsed):
            raise RetractionCommitIndeterminateError(
                "retraction readback did not confirm commit"
            )
    except Exception as error:
        evidence._best_effort_rollback(connection)
        if isinstance(error, RetractionCommittedError):
            raise
        if isinstance(error, RetractionCommitIndeterminateError):
            raise
        if committed:
            if _exact_retraction_readback(path, parsed):
                raise RetractionCommittedError(
                    "retraction committed but acknowledgement was lost",
                    parsed,
                ) from error
            raise RetractionCommitIndeterminateError(
                "retraction commit outcome is indeterminate"
            ) from error
        if isinstance(error, RetractionTransactionError):
            raise
        raise RetractionTransactionError(
            f"retraction transaction failed: {type(error).__name__}: {error}"
        ) from error
    finally:
        close_error = evidence._best_effort_close(connection)
        _, release_errors = evidence._release_target_lock(lock_descriptor)
        cleanup_errors = tuple(
            item
            for item in (close_error, *release_errors)
            if item is not None
        )
    if fault == "cleanup_failure":
        cleanup_errors += (OSError("injected cleanup failure"),)
    if cleanup_errors:
        raise RetractionCommittedError(
            "retraction committed but cleanup failed",
            parsed,
        ) from cleanup_errors[0]
    return parsed


def _assert_retraction_nonce_unused(
    connection,
    nonce: str,
) -> None:
    """Reject a nonce already used by any protocol object in this ledger.

    The shared ``_assert_nonce_unused`` scans every protocol table that
    carries a nonce, including ``retraction_receipts_v05``, so a retraction
    nonce collides with any prior object (and vice versa).
    """

    from openworkproof.verification import _assert_nonce_unused

    _assert_nonce_unused(connection, nonce)


def receipt_retraction_status(
    ledger_path: Path,
    receipt_id: str,
) -> Literal["standing", "refuted", "confidence_downgraded"]:
    """Return whether a receipt's conclusion is still standing."""

    connection = evidence.connect_ledger(ledger_path)
    try:
        latest = _latest_retraction_for(connection, receipt_id)
    finally:
        connection.close()
    if latest is None:
        return "standing"
    if latest.retraction_effect == "refuted":
        return "refuted"
    return "confidence_downgraded"


def retraction_chain(
    ledger_path: Path,
    receipt_id: str,
) -> Sequence[RetractionReceiptV05]:
    """Return every committed retraction targeting a receipt, oldest first."""

    connection = evidence.connect_ledger(ledger_path)
    try:
        rows = connection.execute(
            f"""
            SELECT retraction_json
            FROM {_RETRACTION_TABLE}
            WHERE target_receipt_id = ?
            ORDER BY committed_at ASC, retraction_id ASC
            """,
            (receipt_id,),
        ).fetchall()
        try:
            return tuple(
                RetractionReceiptV05.model_validate_json(row[0])
                for row in rows
            )
        except Exception as error:
            raise RetractionTransactionError(
                "committed retraction row is malformed"
            ) from error
    finally:
        connection.close()
