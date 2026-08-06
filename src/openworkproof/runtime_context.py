"""Current ledger, evidence, and replay-checkpoint revalidation.

Package-internal module shared by trusted handlers and acceptance
transactions. It extracts the "is this AuthorizationContext still the
current authority" check from mcp_server.py without changing behavior.
"""

from __future__ import annotations

import os
from pathlib import Path
import stat
from datetime import datetime

import openworkproof.evidence as evidence
from openworkproof.policy import (
    AuthorizationContext,
    AuthorizationLedgerPrefix,
    derive_authorization_context,
)


class RuntimeContextError(RuntimeError):
    """The supplied authorization context is not the current authority."""


def committed_evidence_matches_context(
    root: Path,
    context: AuthorizationContext,
) -> None:
    expected = {
        item.reference.path: item
        for item in context.committed_evidence
    }
    actual_paths = {
        reference.path
        for receipt in context.ledger_prefix.receipts
        for reference in receipt.evidence_refs
    }
    if set(expected) != actual_paths:
        raise RuntimeContextError(
            "authorization evidence coverage is stale"
        )
    root_metadata = os.stat(root, follow_symlinks=False)
    if not stat.S_ISDIR(root_metadata.st_mode):
        raise RuntimeContextError(
            "authorization evidence root is unavailable"
        )
    for path, item in expected.items():
        relative = path.removeprefix("evidence/")
        parts = Path(relative).parts
        if (
            relative == path
            or not parts
            or Path(relative).is_absolute()
            or any(part in {"", ".", ".."} for part in parts)
        ):
            raise RuntimeContextError(
                "authorization evidence path is outside the root"
            )
        descriptors: list[int] = []
        recheck_descriptors: list[int] = []
        try:
            descriptors, identities = evidence._open_evidence_chain(
                root,
                parts,
                expected_size=item.reference.size_bytes,
            )
            payload, metadata = evidence._read_exact_descriptor(
                descriptors[-1],
                digest=item.reference.sha256,
                size_bytes=item.reference.size_bytes,
                allowed_links=(1,),
            )
            metadata_identity = (
                metadata.st_dev,
                metadata.st_ino,
                metadata.st_mode,
                metadata.st_nlink,
                metadata.st_size,
            )
            recheck_descriptors, recheck_identities = (
                evidence._open_evidence_chain(
                    root,
                    parts,
                    expected_size=item.reference.size_bytes,
                )
            )
            if (
                payload != item.payload
                or metadata_identity != identities[-1]
                or recheck_identities != identities
            ):
                raise OSError("authorization evidence changed")
        except OSError as error:
            raise RuntimeContextError(
                "authorization evidence bytes are stale"
            ) from error
        finally:
            evidence._close_evidence_descriptors(recheck_descriptors)
            evidence._close_evidence_descriptors(descriptors)
    root_after = os.stat(root, follow_symlinks=False)
    if (root_metadata.st_dev, root_metadata.st_ino) != (
        root_after.st_dev,
        root_after.st_ino,
    ):
        raise RuntimeContextError(
            "authorization evidence root changed during validation"
        )


def require_current_context(
    ledger_path: Path,
    evidence_root: Path,
    context: AuthorizationContext,
    now: datetime,
    lock_descriptor: int,
) -> None:
    evidence.require_all_publications_committed(
        ledger_path,
        evidence_root=evidence_root,
        _borrowed_lock_descriptor=lock_descriptor,
    )
    connection = evidence.connect_ledger(ledger_path)
    try:
        work_order, receipts, grants, groups = (
            evidence._replay_receipt_publication_ledger(connection)
        )
        attempts = evidence._validated_grant_attempts(
            connection,
            work_order,
            receipts,
        )
        state_row = connection.execute(
            """
            SELECT current_state, version
            FROM work_order_state
            WHERE singleton = 1
            """
        ).fetchone()
    finally:
        connection.close()
    current_prefix = AuthorizationLedgerPrefix(
        effective_grants=tuple(
            sorted(grants.values(), key=lambda item: item.grant_id)
        ),
        grant_attempts=tuple(
            sorted(attempts.values(), key=lambda item: item.digest)
        ),
        receipts=receipts,
    )
    if (
        work_order != context.work_order
        or current_prefix != context.ledger_prefix
        or context.transaction_time != now
        or state_row
        != (
            context.current_state,
            evidence._derive_protocol_transaction_version(
                action_receipts=receipts,
                acceptance_receipts=(),
            ),
        )
        or any(state_value != "COMMITTED" for _, state_value in groups)
    ):
        raise RuntimeContextError(
            "authorization context is not the current ledger snapshot"
        )
    committed_evidence_matches_context(evidence_root, context)
    rebuilt = derive_authorization_context(
        work_order,
        current_prefix,
        context.committed_evidence,
        context.replay_checkpoint,
        now,
    )
    if rebuilt != context:
        raise RuntimeContextError(
            "authorization context does not reproduce exactly"
        )
