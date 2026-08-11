from __future__ import annotations

import base64
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import openworkproof.evidence as evidence
from openworkproof.binding_transactions import (
    BindingCommitIndeterminateError,
    BindingCommittedError,
    BindingInputError,
    BindingTransactionError,
    JudgmentAuthorityContext,
    commit_judgment_commitment,
)
from openworkproof.models import JudgmentCommitment, KeyBinding
from openworkproof.signing import key_id, sign_payload


class _CommitThenRaiseConnection:
    """Proxy a real SQLite COMMIT, then lose its acknowledgement."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        self._connection = connection

    def execute(self, sql: str, parameters: object = ()):
        cursor = self._connection.execute(sql, parameters)
        if sql == "COMMIT":
            raise OSError("real COMMIT completed but acknowledgement was lost")
        return cursor

    def __getattr__(self, name: str):
        return getattr(self._connection, name)


class _RaiseBeforeCommitConnection(_CommitThenRaiseConnection):
    """Reject COMMIT before the wrapped SQLite connection executes it."""

    def execute(self, sql: str, parameters: object = ()):
        if sql == "COMMIT":
            raise OSError("real COMMIT did not execute")
        return self._connection.execute(sql, parameters)


def _snapshot_all_tables(path: Path) -> dict[str, tuple[tuple[object, ...], ...]]:
    connection = sqlite3.connect(path)
    try:
        names = tuple(
            row[0]
            for row in connection.execute(
                """
                SELECT name FROM sqlite_master
                WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
                ORDER BY name
                """
            )
        )
        return {
            name: tuple(connection.execute(f'SELECT * FROM "{name}"'))
            for name in names
        }
    finally:
        connection.close()


def _key_binding(
    private_key: Ed25519PrivateKey,
    *,
    role: str = "Acceptor",
) -> KeyBinding:
    public_key = private_key.public_key()
    raw = public_key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return KeyBinding.model_validate(
        {
            "role": role,
            "subject_id": f"{role.lower()}-authority",
            "key_id": key_id(public_key),
            "public_key_b64url": base64.urlsafe_b64encode(raw)
            .decode("ascii")
            .rstrip("="),
        }
    )


def _resign(
    commitment: JudgmentCommitment,
    private_key: Ed25519PrivateKey,
    **updates: object,
) -> JudgmentCommitment:
    payload = commitment.model_dump(
        mode="json",
        exclude={"digest", "signature_alg", "signer_key_id", "signature"},
    )
    payload.update(updates)
    return JudgmentCommitment.model_validate(
        sign_payload(
            "judgment-commitment",
            payload,
            private_key,
            version="0.4",
        )
    )


@pytest.fixture
def judgment_ledger(tmp_path, signed_work_order) -> Path:
    path = tmp_path / "judgment-ledger.sqlite3"
    evidence.initialize_ledger(path, signed_work_order)
    return path


@pytest.fixture
def authority_context(
    binding_acceptor_private_key_v04: Ed25519PrivateKey,
) -> JudgmentAuthorityContext:
    return JudgmentAuthorityContext(
        authority_namespace="customer.example",
        authority_binding=_key_binding(binding_acceptor_private_key_v04),
        transaction_time=datetime(2026, 1, 1, 0, 0, 5, tzinfo=timezone.utc),
    )


def test_judgment_commitment_table_is_initialized_and_commit_is_canonical(
    judgment_ledger: Path,
    judgment_commitment_v04: JudgmentCommitment,
    authority_context: JudgmentAuthorityContext,
) -> None:
    committed = commit_judgment_commitment(
        judgment_ledger, judgment_commitment_v04, authority_context
    )
    assert committed == judgment_commitment_v04

    connection = evidence.connect_ledger(judgment_ledger)
    try:
        columns = tuple(
            row[1]
            for row in connection.execute(
                "PRAGMA table_info(judgment_commitments_v04)"
            )
        )
        row = connection.execute(
            """
            SELECT commitment_id, commitment_digest, authority_namespace,
                   subject_id, nonce, signer_key_id, commitment_json, committed_at
            FROM judgment_commitments_v04
            """
        ).fetchone()
    finally:
        connection.close()

    assert columns == (
        "commitment_id",
        "commitment_digest",
        "authority_namespace",
        "subject_id",
        "nonce",
        "signer_key_id",
        "commitment_json",
        "committed_at",
    )
    assert row == (
        judgment_commitment_v04.commitment_id,
        judgment_commitment_v04.digest,
        judgment_commitment_v04.authority_namespace,
        judgment_commitment_v04.subject_id,
        judgment_commitment_v04.nonce,
        judgment_commitment_v04.signer_key_id,
        evidence._canonical_json(
            judgment_commitment_v04.model_dump(mode="json")
        ).encode(),
        "2026-01-01T00:00:05Z",
    )


def test_judgment_commitment_table_has_only_required_indexes(
    judgment_ledger: Path,
) -> None:
    connection = evidence.connect_ledger(judgment_ledger)
    try:
        indexes = tuple(
            connection.execute("PRAGMA index_list(judgment_commitments_v04)")
        )
        observed = {
            (
                row[2],
                row[3],
                tuple(
                    info[2]
                    for info in connection.execute(
                        f'PRAGMA index_info("{row[1]}")'
                    )
                ),
            )
            for row in indexes
        }
    finally:
        connection.close()

    assert len(indexes) == 3
    assert observed == {
        (1, "pk", ("commitment_id",)),
        (1, "u", ("signer_key_id", "nonce")),
        (
            0,
            "c",
            (
                "authority_namespace",
                "subject_id",
                "committed_at",
                "commitment_id",
            ),
        ),
    }


@pytest.mark.parametrize("wrong_authority", ("role", "key"))
def test_judgment_commit_rejects_wrong_role_or_key_with_zero_writes(
    judgment_ledger: Path,
    judgment_commitment_v04: JudgmentCommitment,
    authority_context: JudgmentAuthorityContext,
    binding_manager_private_key_v04: Ed25519PrivateKey,
    wrong_authority: str,
) -> None:
    if wrong_authority == "role":
        context = replace(
            authority_context,
            authority_binding=_key_binding(
                binding_manager_private_key_v04, role="Manager"
            ),
        )
        commitment = judgment_commitment_v04
    else:
        context = authority_context
        commitment = _resign(
            judgment_commitment_v04, binding_manager_private_key_v04
        )
    before = _snapshot_all_tables(judgment_ledger)

    with pytest.raises(BindingInputError, match="Acceptor"):
        commit_judgment_commitment(judgment_ledger, commitment, context)

    assert _snapshot_all_tables(judgment_ledger) == before


def test_judgment_commit_rejects_invalid_signature_with_zero_writes(
    judgment_ledger: Path,
    judgment_commitment_v04: JudgmentCommitment,
    authority_context: JudgmentAuthorityContext,
) -> None:
    raw = judgment_commitment_v04.model_dump(mode="json")
    raw["signature"] = "A" * 86
    invalid = JudgmentCommitment.model_validate(raw)
    before = _snapshot_all_tables(judgment_ledger)

    with pytest.raises(BindingInputError, match="signature"):
        commit_judgment_commitment(judgment_ledger, invalid, authority_context)

    assert _snapshot_all_tables(judgment_ledger) == before


@pytest.mark.parametrize(
    "transaction_time",
    (
        datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
        datetime(2026, 1, 2, 0, 0, 0, tzinfo=timezone.utc),
    ),
)
def test_judgment_commit_rejects_outside_validity_window_with_zero_writes(
    judgment_ledger: Path,
    judgment_commitment_v04: JudgmentCommitment,
    authority_context: JudgmentAuthorityContext,
    transaction_time: datetime,
) -> None:
    context = replace(authority_context, transaction_time=transaction_time)
    before = _snapshot_all_tables(judgment_ledger)

    with pytest.raises(BindingInputError, match="validity"):
        commit_judgment_commitment(
            judgment_ledger, judgment_commitment_v04, context
        )

    assert _snapshot_all_tables(judgment_ledger) == before


def test_judgment_commit_rejects_duplicate_nonce(
    judgment_ledger: Path,
    judgment_commitment_v04: JudgmentCommitment,
    authority_context: JudgmentAuthorityContext,
    binding_acceptor_private_key_v04: Ed25519PrivateKey,
) -> None:
    commit_judgment_commitment(
        judgment_ledger, judgment_commitment_v04, authority_context
    )
    duplicate = _resign(
        judgment_commitment_v04,
        binding_acceptor_private_key_v04,
        commitment_id="6" * 64,
        judgment_artifact_digest="7" * 64,
    )

    with pytest.raises(BindingTransactionError, match="nonce"):
        commit_judgment_commitment(judgment_ledger, duplicate, authority_context)

    connection = evidence.connect_ledger(judgment_ledger)
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM judgment_commitments_v04"
        ).fetchone() == (1,)
    finally:
        connection.close()


def test_judgment_commit_rejects_same_id_with_different_payload(
    judgment_ledger: Path,
    judgment_commitment_v04: JudgmentCommitment,
    authority_context: JudgmentAuthorityContext,
    binding_acceptor_private_key_v04: Ed25519PrivateKey,
) -> None:
    commit_judgment_commitment(
        judgment_ledger, judgment_commitment_v04, authority_context
    )
    conflicting = _resign(
        judgment_commitment_v04,
        binding_acceptor_private_key_v04,
        judgment_artifact_digest="7" * 64,
        nonce="8" * 64,
    )

    with pytest.raises(BindingTransactionError, match="id"):
        commit_judgment_commitment(
            judgment_ledger, conflicting, authority_context
        )


def test_judgment_commit_exact_replay_reports_committed_truth(
    judgment_ledger: Path,
    judgment_commitment_v04: JudgmentCommitment,
    authority_context: JudgmentAuthorityContext,
) -> None:
    commit_judgment_commitment(
        judgment_ledger, judgment_commitment_v04, authority_context
    )

    with pytest.raises(BindingCommittedError) as raised:
        commit_judgment_commitment(
            judgment_ledger, judgment_commitment_v04, authority_context
        )

    assert raised.value.committed == judgment_commitment_v04


def test_judgment_exact_replay_reports_committed_truth_after_expiry(
    judgment_ledger: Path,
    judgment_commitment_v04: JudgmentCommitment,
    authority_context: JudgmentAuthorityContext,
) -> None:
    commit_judgment_commitment(
        judgment_ledger, judgment_commitment_v04, authority_context
    )
    expired_context = replace(
        authority_context,
        transaction_time=judgment_commitment_v04.expires_at,
    )

    with pytest.raises(BindingCommittedError) as raised:
        commit_judgment_commitment(
            judgment_ledger, judgment_commitment_v04, expired_context
        )

    assert raised.value.committed == judgment_commitment_v04
    connection = evidence.connect_ledger(judgment_ledger)
    try:
        assert connection.execute(
            "SELECT COUNT(*), committed_at FROM judgment_commitments_v04"
        ).fetchone() == (1, "2026-01-01T00:00:05Z")
    finally:
        connection.close()


@pytest.mark.parametrize(
    "fault", ("insert_failure", "before_commit", "commit_failure")
)
def test_judgment_precommit_fault_is_zero_write(
    judgment_ledger: Path,
    judgment_commitment_v04: JudgmentCommitment,
    authority_context: JudgmentAuthorityContext,
    fault: str,
) -> None:
    before = _snapshot_all_tables(judgment_ledger)

    with pytest.raises(BindingTransactionError):
        commit_judgment_commitment(
            judgment_ledger,
            judgment_commitment_v04,
            authority_context,
            fault=fault,
        )

    assert _snapshot_all_tables(judgment_ledger) == before


def test_judgment_readback_failure_reports_indeterminate_committed_state(
    judgment_ledger: Path,
    judgment_commitment_v04: JudgmentCommitment,
    authority_context: JudgmentAuthorityContext,
) -> None:
    with pytest.raises(BindingCommitIndeterminateError):
        commit_judgment_commitment(
            judgment_ledger,
            judgment_commitment_v04,
            authority_context,
            fault="readback_failure",
        )

    connection = evidence.connect_ledger(judgment_ledger)
    try:
        assert connection.execute(
            "SELECT commitment_digest FROM judgment_commitments_v04"
        ).fetchone() == (judgment_commitment_v04.digest,)
    finally:
        connection.close()


@pytest.mark.parametrize("fault", ("commit_ack_loss", "cleanup_failure"))
def test_judgment_postcommit_fault_preserves_exact_truth(
    judgment_ledger: Path,
    judgment_commitment_v04: JudgmentCommitment,
    authority_context: JudgmentAuthorityContext,
    fault: str,
) -> None:
    with pytest.raises(BindingCommittedError) as raised:
        commit_judgment_commitment(
            judgment_ledger,
            judgment_commitment_v04,
            authority_context,
            fault=fault,
        )

    assert raised.value.committed == judgment_commitment_v04
    connection = evidence.connect_ledger(judgment_ledger)
    try:
        assert connection.execute(
            """
            SELECT commitment_digest, commitment_json
            FROM judgment_commitments_v04 WHERE commitment_id = ?
            """,
            (judgment_commitment_v04.commitment_id,),
        ).fetchone() == (
            judgment_commitment_v04.digest,
            evidence._canonical_json(
                judgment_commitment_v04.model_dump(mode="json")
            ).encode(),
        )
    finally:
        connection.close()


def test_real_commit_ack_loss_is_recovered_by_exact_readback(
    judgment_ledger: Path,
    judgment_commitment_v04: JudgmentCommitment,
    authority_context: JudgmentAuthorityContext,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_connect = evidence.connect_ledger
    connection_count = 0

    def connect_with_lost_first_ack(path: Path):
        nonlocal connection_count
        connection_count += 1
        connection = real_connect(path)
        if connection_count == 1:
            return _CommitThenRaiseConnection(connection)
        return connection

    monkeypatch.setattr(evidence, "connect_ledger", connect_with_lost_first_ack)

    with pytest.raises(BindingCommittedError) as raised:
        commit_judgment_commitment(
            judgment_ledger, judgment_commitment_v04, authority_context
        )

    assert raised.value.committed == judgment_commitment_v04
    connection = real_connect(judgment_ledger)
    try:
        assert connection.execute(
            "SELECT commitment_digest FROM judgment_commitments_v04"
        ).fetchone() == (judgment_commitment_v04.digest,)
    finally:
        connection.close()


def test_real_commit_failure_with_absent_row_is_indeterminate_and_zero_write(
    judgment_ledger: Path,
    judgment_commitment_v04: JudgmentCommitment,
    authority_context: JudgmentAuthorityContext,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_connect = evidence.connect_ledger
    connection_count = 0

    def connect_with_rejected_first_commit(path: Path):
        nonlocal connection_count
        connection_count += 1
        connection = real_connect(path)
        if connection_count == 1:
            return _RaiseBeforeCommitConnection(connection)
        return connection

    monkeypatch.setattr(
        evidence, "connect_ledger", connect_with_rejected_first_commit
    )

    with pytest.raises(BindingCommitIndeterminateError):
        commit_judgment_commitment(
            judgment_ledger, judgment_commitment_v04, authority_context
        )

    connection = real_connect(judgment_ledger)
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM judgment_commitments_v04"
        ).fetchone() == (0,)
    finally:
        connection.close()


def test_real_commit_ack_loss_with_unavailable_readback_is_indeterminate(
    judgment_ledger: Path,
    judgment_commitment_v04: JudgmentCommitment,
    authority_context: JudgmentAuthorityContext,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_connect = evidence.connect_ledger
    connection_count = 0

    def connect_with_lost_ack_and_readback(path: Path):
        nonlocal connection_count
        connection_count += 1
        if connection_count == 1:
            return _CommitThenRaiseConnection(real_connect(path))
        raise OSError("exact readback is unavailable")

    monkeypatch.setattr(
        evidence, "connect_ledger", connect_with_lost_ack_and_readback
    )

    with pytest.raises(BindingCommitIndeterminateError):
        commit_judgment_commitment(
            judgment_ledger, judgment_commitment_v04, authority_context
        )

    connection = real_connect(judgment_ledger)
    try:
        assert connection.execute(
            "SELECT commitment_digest FROM judgment_commitments_v04"
        ).fetchone() == (judgment_commitment_v04.digest,)
    finally:
        connection.close()


def test_identical_concurrent_judgment_commits_share_one_exact_truth(
    judgment_ledger: Path,
    judgment_commitment_v04: JudgmentCommitment,
    authority_context: JudgmentAuthorityContext,
) -> None:
    barrier = threading.Barrier(2)

    def commit_once(_: int) -> tuple[str, JudgmentCommitment]:
        barrier.wait()
        try:
            return (
                "committed",
                commit_judgment_commitment(
                    judgment_ledger,
                    judgment_commitment_v04,
                    authority_context,
                ),
            )
        except BindingCommittedError as error:
            assert isinstance(error.committed, JudgmentCommitment)
            return "already_committed", error.committed

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = tuple(pool.map(commit_once, range(2)))

    assert sorted(status for status, _ in outcomes) == [
        "already_committed",
        "committed",
    ]
    assert tuple(value for _, value in outcomes) == (
        judgment_commitment_v04,
        judgment_commitment_v04,
    )
    connection = evidence.connect_ledger(judgment_ledger)
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM judgment_commitments_v04"
        ).fetchone() == (1,)
    finally:
        connection.close()


def test_same_id_concurrent_judgments_have_one_winner_and_one_conflict(
    judgment_ledger: Path,
    judgment_commitment_v04: JudgmentCommitment,
    authority_context: JudgmentAuthorityContext,
    binding_acceptor_private_key_v04: Ed25519PrivateKey,
) -> None:
    conflicting = _resign(
        judgment_commitment_v04,
        binding_acceptor_private_key_v04,
        judgment_artifact_digest="7" * 64,
        nonce="8" * 64,
    )
    barrier = threading.Barrier(2)

    def attempt(commitment: JudgmentCommitment):
        barrier.wait()
        try:
            committed = commit_judgment_commitment(
                judgment_ledger, commitment, authority_context
            )
        except BindingTransactionError as error:
            return "conflict", str(error)
        return "committed", committed.digest

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = tuple(
            pool.map(attempt, (judgment_commitment_v04, conflicting))
        )

    assert sorted(status for status, _ in outcomes) == ["committed", "conflict"]
    committed_digest = next(
        value for status, value in outcomes if status == "committed"
    )
    conflict_message = next(
        value for status, value in outcomes if status == "conflict"
    )
    assert "id" in conflict_message
    connection = evidence.connect_ledger(judgment_ledger)
    try:
        assert connection.execute(
            "SELECT commitment_digest FROM judgment_commitments_v04"
        ).fetchall() == [(committed_digest,)]
    finally:
        connection.close()


def test_judgment_rows_cannot_be_updated_or_deleted(
    judgment_ledger: Path,
    judgment_commitment_v04: JudgmentCommitment,
    authority_context: JudgmentAuthorityContext,
) -> None:
    commit_judgment_commitment(
        judgment_ledger, judgment_commitment_v04, authority_context
    )
    connection = evidence.connect_ledger(judgment_ledger)
    try:
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute(
                "UPDATE judgment_commitments_v04 SET subject_id = 'changed'"
            )
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute("DELETE FROM judgment_commitments_v04")
    finally:
        connection.close()
