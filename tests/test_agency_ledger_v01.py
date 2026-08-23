from __future__ import annotations

import re
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import openworkproof.evidence as evidence
from openworkproof.agency import (
    AGENCY_PROFILE_HISTORY_INVALID,
    AgencyAppealV01,
    AgencyProfileHistory,
    AgencyProfileHistoryError,
    AgencyProfileTransitionV01,
    HumanAgencyProfileV01,
    agency_appeal_id,
    agency_profile_transition_id,
    delegated_action_id,
    human_agency_profile_id,
)
from openworkproof.agency_ledger import (
    AgencyCommitIndeterminateError,
    AgencyCommittedError,
    AgencyLedgerError,
    commit_agency_appeal,
    commit_agency_profile_transition,
    commit_human_agency_profile,
    load_agency_appeals,
    load_agency_history,
    load_current_human_agency_profile,
)
from openworkproof.models import WorkOrder
from openworkproof.signing import sign_payload

from conftest import SHA256_A, SHA256_B, SHA256_D, SHA256_E

_NOW = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


@dataclass(frozen=True)
class _AgencyCase:
    work_order: WorkOrder
    keys: dict[str, tuple[Ed25519PrivateKey, dict[str, str]]]


@pytest.fixture
def agency_case(
    signed_work_order: WorkOrder,
    ephemeral_role_keys: dict[
        str, tuple[Ed25519PrivateKey, dict[str, str]]
    ],
) -> _AgencyCase:
    return _AgencyCase(
        work_order=signed_work_order,
        keys=ephemeral_role_keys,
    )


@pytest.fixture
def ledger_case(
    tmp_path: Path,
    signed_work_order: WorkOrder,
) -> dict[str, Any]:
    ledger = tmp_path / "agency-ledger.sqlite3"
    evidence.initialize_ledger(ledger, signed_work_order)
    return {"ledger": ledger, "work_order": signed_work_order}


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


def _tamper_column(
    ledger: Path,
    table: str,
    column: str,
    value: object,
    *,
    where_column: str,
    where_value: object,
) -> None:
    """Drop one immutable UPDATE trigger (test-only) and mutate a column."""
    connection = evidence.connect_ledger(ledger)
    try:
        connection.execute(f"DROP TRIGGER IF EXISTS {table}_are_immutable_update")
        connection.execute(
            f"UPDATE {table} SET {column} = ? WHERE {where_column} = ?",
            (value, where_value),
        )
    finally:
        connection.close()


def _mk_profile(
    case: _AgencyCase,
    nonce: str,
    *,
    delegated: tuple[str, ...] = ("owp.repo_read",),
    issued_at: str = "2026-01-01T00:00:00Z",
    valid_from: str = "2026-01-01T00:00:01Z",
    expires_at: str = "2026-01-01T23:59:59Z",
    signer: str = "Acceptor",
) -> HumanAgencyProfileV01:
    payload = {
        "schema_version": "openworkproof-human-agency-profile/0.1",
        "work_order_digest": case.work_order.digest,
        "delegated_actions": [
            {
                "action_id": delegated_action_id(
                    {"tool_name": tool, "autonomy": "delegated"}
                ),
                "tool_name": tool,
                "autonomy": "delegated",
            }
            for tool in delegated
        ],
        "reserved_decisions": [],
        "escalation_conditions": [{"condition_code": "reserved_decision_requested"}],
        "revocation_and_appeal": {
            "revocation_mode": "acceptor_signed_transition",
            "appeal_mode": "signed_request_then_acceptor_decision",
            "appeal_roles": ["Developer", "Manager", "Verifier"],
        },
        "valid_from": valid_from,
        "expires_at": expires_at,
        "issued_at": issued_at,
        "nonce": nonce,
    }
    payload["profile_id"] = human_agency_profile_id(payload)
    return HumanAgencyProfileV01.model_validate(
        sign_payload("human-agency-profile", payload, case.keys[signer][0])
    )


def _mk_transition(
    case: _AgencyCase,
    *,
    target: HumanAgencyProfileV01,
    transition: str = "revoked",
    replacement: HumanAgencyProfileV01 | None = None,
    transitioned_at: str = "2026-01-01T02:00:00Z",
    nonce: str = SHA256_D,
    signer: str = "Acceptor",
    target_profile_digest: str | None = None,
    replacement_profile_digest: str | None = None,
) -> AgencyProfileTransitionV01:
    payload = {
        "schema_version": "openworkproof-agency-profile-transition/0.1",
        "work_order_digest": case.work_order.digest,
        "target_profile_id": target.profile_id,
        "target_profile_digest": (
            target.digest if target_profile_digest is None else target_profile_digest
        ),
        "transition": transition,
        "replacement_profile_id": (
            replacement.profile_id if replacement is not None else None
        ),
        "replacement_profile_digest": (
            replacement.digest
            if replacement is not None and replacement_profile_digest is None
            else replacement_profile_digest
        ),
        "reason_code": (
            "scope_changed" if transition == "superseded" else "human_withdrawal"
        ),
        "transitioned_at": transitioned_at,
        "nonce": nonce,
    }
    payload["transition_id"] = agency_profile_transition_id(payload)
    return AgencyProfileTransitionV01.model_validate(
        sign_payload("agency-profile-transition", payload, case.keys[signer][0])
    )


def _mk_appeal(
    case: _AgencyCase,
    *,
    profile: HumanAgencyProfileV01,
    role: str = "Manager",
    signing_role: str | None = None,
    nonce: str = SHA256_A,
    profile_digest: str | None = None,
) -> AgencyAppealV01:
    binding = case.keys[role][1]
    payload = {
        "schema_version": "openworkproof-agency-appeal/0.1",
        "work_order_digest": case.work_order.digest,
        "profile_id": profile.profile_id,
        "profile_digest": (
            profile.digest if profile_digest is None else profile_digest
        ),
        "appellant_role": role,
        "appellant_subject_id": binding["subject_id"],
        "requested_change_digest": SHA256_E,
        "reason_code": "task_blocked",
        "created_at": "2026-01-01T01:05:00Z",
        "nonce": nonce,
    }
    payload["appeal_id"] = agency_appeal_id(payload)
    return AgencyAppealV01.model_validate(
        sign_payload(
            "agency-appeal",
            payload,
            case.keys[signing_role or role][0],
        )
    )


# --- happy-path commit and load roundtrips ---


def test_commit_profile_roundtrips_and_loads_history(
    agency_case: _AgencyCase,
    ledger_case: dict[str, Any],
) -> None:
    profile = _mk_profile(agency_case, SHA256_A)
    committed = commit_human_agency_profile(ledger_case["ledger"], profile)
    assert committed.profile_id == profile.profile_id

    history = load_agency_history(ledger_case["ledger"], profile.work_order_digest)
    assert history == AgencyProfileHistory(profiles=(profile,), transitions=())

    resolved = load_current_human_agency_profile(ledger_case["ledger"], now=_NOW)
    assert resolved.status == "active"
    assert resolved.current_profile == profile


def test_commit_transition_and_loads_resolved_current(
    agency_case: _AgencyCase,
    ledger_case: dict[str, Any],
) -> None:
    first = _mk_profile(agency_case, SHA256_A)
    second = _mk_profile(agency_case, SHA256_B)
    commit_human_agency_profile(ledger_case["ledger"], first)
    commit_human_agency_profile(ledger_case["ledger"], second)
    transition = _mk_transition(
        agency_case, target=first, transition="superseded", replacement=second
    )
    committed = commit_agency_profile_transition(
        ledger_case["ledger"], transition
    )
    assert committed.transition_id == transition.transition_id

    resolved = load_current_human_agency_profile(ledger_case["ledger"], now=_NOW)
    assert resolved.status == "active"
    assert resolved.current_profile == second


def test_commit_appeal_and_loads_appeals(
    agency_case: _AgencyCase,
    ledger_case: dict[str, Any],
) -> None:
    profile = _mk_profile(agency_case, SHA256_A)
    commit_human_agency_profile(ledger_case["ledger"], profile)
    appeal = _mk_appeal(agency_case, profile=profile)
    committed = commit_agency_appeal(ledger_case["ledger"], appeal)
    assert committed.appeal_id == appeal.appeal_id
    assert load_agency_appeals(ledger_case["ledger"], profile.work_order_digest) == (
        appeal,
    )


# --- duplicate / idempotency / nonce ---


def test_commit_exact_profile_is_idempotent_and_reports_committed_truth(
    agency_case: _AgencyCase,
    ledger_case: dict[str, Any],
) -> None:
    profile = _mk_profile(agency_case, SHA256_A)
    commit_human_agency_profile(ledger_case["ledger"], profile)
    with pytest.raises(AgencyCommittedError) as raised:
        commit_human_agency_profile(ledger_case["ledger"], profile)
    assert raised.value.committed == profile


def test_commit_duplicate_nonce_fails_closed(
    agency_case: _AgencyCase,
    ledger_case: dict[str, Any],
) -> None:
    first = _mk_profile(agency_case, SHA256_A)
    commit_human_agency_profile(ledger_case["ledger"], first)
    # Same nonce, different content -> different id.
    duplicate = _mk_profile(
        agency_case, SHA256_A, delegated=("owp.apply_patch",)
    )
    with pytest.raises(AgencyLedgerError, match="nonce"):
        commit_human_agency_profile(ledger_case["ledger"], duplicate)


def test_commit_wrong_authority_profile_fails_closed(
    agency_case: _AgencyCase,
    ledger_case: dict[str, Any],
) -> None:
    # Same content but signed by a non-Acceptor: same id, different bytes.
    forged = _mk_profile(agency_case, SHA256_A, signer="Manager")
    with pytest.raises(AgencyLedgerError):
        commit_human_agency_profile(ledger_case["ledger"], forged)


def test_commit_wrong_authority_transition_fails_closed(
    agency_case: _AgencyCase,
    ledger_case: dict[str, Any],
) -> None:
    first = _mk_profile(agency_case, SHA256_A)
    commit_human_agency_profile(ledger_case["ledger"], first)
    forged = _mk_transition(
        agency_case, target=first, transition="revoked", signer="Manager"
    )
    with pytest.raises(AgencyLedgerError):
        commit_agency_profile_transition(ledger_case["ledger"], forged)


def test_commit_appeal_role_key_subject_mismatch_fails_closed(
    agency_case: _AgencyCase,
    ledger_case: dict[str, Any],
) -> None:
    profile = _mk_profile(agency_case, SHA256_A)
    commit_human_agency_profile(ledger_case["ledger"], profile)
    forged = _mk_appeal(
        agency_case, profile=profile, role="Manager", signing_role="Developer"
    )
    with pytest.raises(AgencyLedgerError):
        commit_agency_appeal(ledger_case["ledger"], forged)


# --- reference binding validation ---


def test_commit_transition_requires_committed_target(
    agency_case: _AgencyCase,
    ledger_case: dict[str, Any],
) -> None:
    missing = _mk_profile(agency_case, SHA256_A)
    transition = _mk_transition(
        agency_case, target=missing, transition="revoked"
    )
    with pytest.raises(AgencyLedgerError, match="target"):
        commit_agency_profile_transition(ledger_case["ledger"], transition)


def test_commit_transition_requires_exact_target_digest(
    agency_case: _AgencyCase,
    ledger_case: dict[str, Any],
) -> None:
    first = _mk_profile(agency_case, SHA256_A)
    commit_human_agency_profile(ledger_case["ledger"], first)
    wrong = _mk_transition(
        agency_case,
        target=first,
        transition="revoked",
        target_profile_digest="f" * 64,
    )
    with pytest.raises(AgencyLedgerError, match="digest"):
        commit_agency_profile_transition(ledger_case["ledger"], wrong)


def test_commit_transition_requires_committed_replacement(
    agency_case: _AgencyCase,
    ledger_case: dict[str, Any],
) -> None:
    first = _mk_profile(agency_case, SHA256_A)
    commit_human_agency_profile(ledger_case["ledger"], first)
    missing = _mk_profile(agency_case, SHA256_B)
    transition = _mk_transition(
        agency_case, target=first, transition="superseded", replacement=missing
    )
    with pytest.raises(AgencyLedgerError, match="replacement"):
        commit_agency_profile_transition(ledger_case["ledger"], transition)


def test_commit_appeal_requires_committed_profile_and_exact_digest(
    agency_case: _AgencyCase,
    ledger_case: dict[str, Any],
) -> None:
    profile = _mk_profile(agency_case, SHA256_A)
    appeal = _mk_appeal(agency_case, profile=profile)
    with pytest.raises(AgencyLedgerError, match="profile"):
        commit_agency_appeal(ledger_case["ledger"], appeal)

    commit_human_agency_profile(ledger_case["ledger"], profile)
    wrong = _mk_appeal(
        agency_case, profile=profile, profile_digest="f" * 64
    )
    with pytest.raises(AgencyLedgerError, match="digest"):
        commit_agency_appeal(ledger_case["ledger"], wrong)


# --- fault injection: pre-commit zero write ---


def test_before_commit_fault_is_zero_write_across_all_tables(
    agency_case: _AgencyCase,
    ledger_case: dict[str, Any],
) -> None:
    profile = _mk_profile(agency_case, SHA256_A)
    before = _snapshot_all_tables(ledger_case["ledger"])
    with pytest.raises(AgencyLedgerError):
        commit_human_agency_profile(
            ledger_case["ledger"], profile, fault="before_commit"
        )
    assert _snapshot_all_tables(ledger_case["ledger"]) == before


# --- fault injection: commit-ack loss / readback / cleanup ---


def test_commit_ack_loss_recovers_exact_committed_truth(
    agency_case: _AgencyCase,
    ledger_case: dict[str, Any],
) -> None:
    profile = _mk_profile(agency_case, SHA256_A)
    with pytest.raises(AgencyCommittedError) as raised:
        commit_human_agency_profile(
            ledger_case["ledger"], profile, fault="commit_ack_loss"
        )
    assert raised.value.committed == profile
    assert load_current_human_agency_profile(
        ledger_case["ledger"], now=_NOW
    ).current_profile == profile


def test_readback_failure_is_indeterminate(
    agency_case: _AgencyCase,
    ledger_case: dict[str, Any],
) -> None:
    profile = _mk_profile(agency_case, SHA256_A)
    with pytest.raises(AgencyCommitIndeterminateError):
        commit_human_agency_profile(
            ledger_case["ledger"], profile, fault="readback_failure"
        )


def test_cleanup_failure_preserves_committed_truth(
    agency_case: _AgencyCase,
    ledger_case: dict[str, Any],
) -> None:
    profile = _mk_profile(agency_case, SHA256_A)
    with pytest.raises(AgencyCommittedError) as raised:
        commit_human_agency_profile(
            ledger_case["ledger"], profile, fault="cleanup_failure"
        )
    assert raised.value.committed == profile
    assert load_current_human_agency_profile(
        ledger_case["ledger"], now=_NOW
    ).current_profile == profile


# --- replacement may precede its transition; multiple genesis fails closed ---


def test_replacement_committed_before_transition_fails_closed(
    agency_case: _AgencyCase,
    ledger_case: dict[str, Any],
) -> None:
    first = _mk_profile(agency_case, SHA256_A)
    second = _mk_profile(agency_case, SHA256_B)
    commit_human_agency_profile(ledger_case["ledger"], first)
    commit_human_agency_profile(ledger_case["ledger"], second)
    with pytest.raises(AgencyProfileHistoryError) as caught:
        load_current_human_agency_profile(ledger_case["ledger"], now=_NOW)
    assert caught.value.code == AGENCY_PROFILE_HISTORY_INVALID


# --- supersession concurrency yields a single winner ---


def test_supersession_concurrency_yields_single_winner(
    agency_case: _AgencyCase,
    ledger_case: dict[str, Any],
) -> None:
    first = _mk_profile(agency_case, SHA256_A)
    second = _mk_profile(agency_case, SHA256_B)
    commit_human_agency_profile(ledger_case["ledger"], first)
    commit_human_agency_profile(ledger_case["ledger"], second)
    transition_a = _mk_transition(
        agency_case,
        target=first,
        transition="superseded",
        replacement=second,
        nonce="1" * 64,
    )
    transition_b = _mk_transition(
        agency_case,
        target=first,
        transition="superseded",
        replacement=second,
        nonce="2" * 64,
    )

    def attempt(transition: AgencyProfileTransitionV01) -> str:
        try:
            commit_agency_profile_transition(ledger_case["ledger"], transition)
            return "committed"
        except AgencyCommittedError:
            return "committed"
        except AgencyLedgerError:
            return "rejected"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(attempt, (transition_a, transition_b)))
    assert outcomes.count("committed") == 1
    assert outcomes.count("rejected") == 1
    resolved = load_current_human_agency_profile(ledger_case["ledger"], now=_NOW)
    assert resolved.status == "active"
    assert resolved.current_profile == second


# --- immutable UPDATE/DELETE triggers for all three tables ---


def _inserted_profile_row(ledger: Path, profile: HumanAgencyProfileV01) -> None:
    connection = evidence.connect_ledger(ledger)
    try:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            """
            INSERT INTO human_agency_profiles_v01 (
                profile_id, work_order_digest, profile_digest,
                profile_json, nonce, issued_at, committed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                profile.profile_id,
                profile.work_order_digest,
                profile.digest,
                evidence._canonical_json(profile.model_dump(mode="json")),
                profile.nonce,
                profile.model_dump(mode="json")["issued_at"],
                "2026-01-01T00:00:00Z",
            ),
        )
        connection.execute("COMMIT")
    finally:
        connection.close()


def test_agency_tables_are_immutable_on_update_and_delete(
    agency_case: _AgencyCase,
    ledger_case: dict[str, Any],
) -> None:
    profile = _mk_profile(agency_case, SHA256_A)
    commit_human_agency_profile(ledger_case["ledger"], profile)
    second = _mk_profile(agency_case, SHA256_B)
    _inserted_profile_row(ledger_case["ledger"], second)
    transition = _mk_transition(
        agency_case,
        target=profile,
        transition="superseded",
        replacement=second,
    )
    commit_agency_profile_transition(ledger_case["ledger"], transition)
    appeal = _mk_appeal(agency_case, profile=profile)
    commit_agency_appeal(ledger_case["ledger"], appeal)

    connection = evidence.connect_ledger(ledger_case["ledger"])
    try:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE human_agency_profiles_v01 SET nonce = ? "
                "WHERE profile_id = ?",
                ("0" * 64, profile.profile_id),
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "DELETE FROM human_agency_profiles_v01 WHERE profile_id = ?",
                (profile.profile_id,),
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE agency_profile_transitions_v01 SET nonce = ? "
                "WHERE transition_id = ?",
                ("0" * 64, transition.transition_id),
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "DELETE FROM agency_profile_transitions_v01 "
                "WHERE transition_id = ?",
                (transition.transition_id,),
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE agency_appeals_v01 SET nonce = ? WHERE appeal_id = ?",
                ("0" * 64, appeal.appeal_id),
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "DELETE FROM agency_appeals_v01 WHERE appeal_id = ?",
                (appeal.appeal_id,),
            )
    finally:
        connection.close()


# --- P1-1: idempotency ordering ---


def test_commit_exact_transition_retry_reports_committed_truth(
    agency_case: _AgencyCase,
    ledger_case: dict[str, Any],
) -> None:
    first = _mk_profile(agency_case, SHA256_A)
    commit_human_agency_profile(ledger_case["ledger"], first)
    transition = _mk_transition(agency_case, target=first, transition="revoked")
    commit_agency_profile_transition(ledger_case["ledger"], transition)
    with pytest.raises(AgencyCommittedError) as raised:
        commit_agency_profile_transition(ledger_case["ledger"], transition)
    assert raised.value.committed == transition


def test_commit_exact_appeal_retry_reports_committed_truth(
    agency_case: _AgencyCase,
    ledger_case: dict[str, Any],
) -> None:
    profile = _mk_profile(agency_case, SHA256_A)
    commit_human_agency_profile(ledger_case["ledger"], profile)
    appeal = _mk_appeal(agency_case, profile=profile)
    commit_agency_appeal(ledger_case["ledger"], appeal)
    with pytest.raises(AgencyCommittedError) as raised:
        commit_agency_appeal(ledger_case["ledger"], appeal)
    assert raised.value.committed == appeal


def test_commit_same_id_different_canonical_bytes_fails_closed(
    agency_case: _AgencyCase,
    ledger_case: dict[str, Any],
) -> None:
    profile = _mk_profile(agency_case, SHA256_A)
    commit_human_agency_profile(ledger_case["ledger"], profile)
    _tamper_column(
        ledger_case["ledger"],
        "human_agency_profiles_v01",
        "profile_digest",
        "f" * 64,
        where_column="profile_id",
        where_value=profile.profile_id,
    )
    with pytest.raises(AgencyLedgerError, match="id is already used"):
        commit_human_agency_profile(ledger_case["ledger"], profile)


# --- P1-2: final graph validity before COMMIT ---


def test_commit_transition_that_creates_cycle_is_rejected_zero_write(
    agency_case: _AgencyCase,
    ledger_case: dict[str, Any],
) -> None:
    first = _mk_profile(agency_case, SHA256_A)
    second = _mk_profile(agency_case, SHA256_B)
    commit_human_agency_profile(ledger_case["ledger"], first)
    commit_human_agency_profile(ledger_case["ledger"], second)
    forward = _mk_transition(
        agency_case,
        target=first,
        transition="superseded",
        replacement=second,
        nonce="1" * 64,
    )
    commit_agency_profile_transition(ledger_case["ledger"], forward)
    back = _mk_transition(
        agency_case,
        target=second,
        transition="superseded",
        replacement=first,
        nonce="2" * 64,
    )
    before = _snapshot_all_tables(ledger_case["ledger"])
    with pytest.raises(AgencyLedgerError):
        commit_agency_profile_transition(ledger_case["ledger"], back)
    assert _snapshot_all_tables(ledger_case["ledger"]) == before


def test_commit_transition_that_leaves_disconnected_profile_is_rejected_zero_write(
    agency_case: _AgencyCase,
    ledger_case: dict[str, Any],
) -> None:
    first = _mk_profile(agency_case, SHA256_A)
    second = _mk_profile(agency_case, SHA256_B)
    third = _mk_profile(agency_case, "c" * 64)
    commit_human_agency_profile(ledger_case["ledger"], first)
    commit_human_agency_profile(ledger_case["ledger"], second)
    commit_human_agency_profile(ledger_case["ledger"], third)
    transition = _mk_transition(
        agency_case,
        target=first,
        transition="superseded",
        replacement=second,
        nonce="1" * 64,
    )
    before = _snapshot_all_tables(ledger_case["ledger"])
    with pytest.raises(AgencyLedgerError):
        commit_agency_profile_transition(ledger_case["ledger"], transition)
    assert _snapshot_all_tables(ledger_case["ledger"]) == before


# --- P1-3: row integrity ---


def test_load_history_rejects_non_authoritative_work_order_digest(
    agency_case: _AgencyCase,
    ledger_case: dict[str, Any],
) -> None:
    profile = _mk_profile(agency_case, SHA256_A)
    commit_human_agency_profile(ledger_case["ledger"], profile)
    with pytest.raises(AgencyLedgerError, match="authoritative"):
        load_agency_history(ledger_case["ledger"], "f" * 64)


def test_load_history_rejects_tampered_profile_digest_column(
    agency_case: _AgencyCase,
    ledger_case: dict[str, Any],
) -> None:
    profile = _mk_profile(agency_case, SHA256_A)
    commit_human_agency_profile(ledger_case["ledger"], profile)
    _tamper_column(
        ledger_case["ledger"],
        "human_agency_profiles_v01",
        "profile_digest",
        "f" * 64,
        where_column="profile_id",
        where_value=profile.profile_id,
    )
    with pytest.raises(AgencyLedgerError):
        load_agency_history(ledger_case["ledger"], profile.work_order_digest)


def test_load_history_rejects_tampered_transition_target_digest_column(
    agency_case: _AgencyCase,
    ledger_case: dict[str, Any],
) -> None:
    first = _mk_profile(agency_case, SHA256_A)
    commit_human_agency_profile(ledger_case["ledger"], first)
    transition = _mk_transition(agency_case, target=first, transition="revoked")
    commit_agency_profile_transition(ledger_case["ledger"], transition)
    _tamper_column(
        ledger_case["ledger"],
        "agency_profile_transitions_v01",
        "target_profile_digest",
        "f" * 64,
        where_column="transition_id",
        where_value=transition.transition_id,
    )
    with pytest.raises(AgencyLedgerError):
        load_agency_history(ledger_case["ledger"], first.work_order_digest)


def test_load_appeals_rejects_tampered_appeal_profile_digest_column(
    agency_case: _AgencyCase,
    ledger_case: dict[str, Any],
) -> None:
    profile = _mk_profile(agency_case, SHA256_A)
    commit_human_agency_profile(ledger_case["ledger"], profile)
    appeal = _mk_appeal(agency_case, profile=profile)
    commit_agency_appeal(ledger_case["ledger"], appeal)
    _tamper_column(
        ledger_case["ledger"],
        "agency_appeals_v01",
        "profile_digest",
        "f" * 64,
        where_column="appeal_id",
        where_value=appeal.appeal_id,
    )
    with pytest.raises(AgencyLedgerError):
        load_agency_appeals(ledger_case["ledger"], profile.work_order_digest)


def test_commit_transition_reference_rejects_tampered_target_row(
    agency_case: _AgencyCase,
    ledger_case: dict[str, Any],
) -> None:
    first = _mk_profile(agency_case, SHA256_A)
    commit_human_agency_profile(ledger_case["ledger"], first)
    _tamper_column(
        ledger_case["ledger"],
        "human_agency_profiles_v01",
        "profile_digest",
        "f" * 64,
        where_column="profile_id",
        where_value=first.profile_id,
    )
    transition = _mk_transition(agency_case, target=first, transition="revoked")
    before = _snapshot_all_tables(ledger_case["ledger"])
    with pytest.raises(AgencyLedgerError):
        commit_agency_profile_transition(ledger_case["ledger"], transition)
    assert _snapshot_all_tables(ledger_case["ledger"]) == before


# --- P1-4: committed_at ---


def test_commit_populates_canonical_committed_at_column(
    agency_case: _AgencyCase,
    ledger_case: dict[str, Any],
) -> None:
    profile = _mk_profile(agency_case, SHA256_A)
    commit_human_agency_profile(ledger_case["ledger"], profile)
    connection = evidence.connect_ledger(ledger_case["ledger"])
    try:
        row = connection.execute(
            "SELECT committed_at FROM human_agency_profiles_v01 "
            "WHERE profile_id = ?",
            (profile.profile_id,),
        ).fetchone()
    finally:
        connection.close()
    assert row is not None
    assert re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
        row[0],
    )


def test_load_rejects_noncanonical_committed_at(
    agency_case: _AgencyCase,
    ledger_case: dict[str, Any],
) -> None:
    profile = _mk_profile(agency_case, SHA256_A)
    commit_human_agency_profile(ledger_case["ledger"], profile)
    _tamper_column(
        ledger_case["ledger"],
        "human_agency_profiles_v01",
        "committed_at",
        "not-a-time",
        where_column="profile_id",
        where_value=profile.profile_id,
    )
    with pytest.raises(AgencyLedgerError, match="committed_at"):
        load_agency_history(ledger_case["ledger"], profile.work_order_digest)


# --- P2: public commit parse failures are ledger errors ---


def test_commit_profile_rejects_malformed_payload_as_ledger_error(
    ledger_case: dict[str, Any],
) -> None:
    with pytest.raises(AgencyLedgerError):
        commit_human_agency_profile(ledger_case["ledger"], {"bad": "payload"})


def test_commit_transition_rejects_malformed_payload_as_ledger_error(
    ledger_case: dict[str, Any],
) -> None:
    with pytest.raises(AgencyLedgerError):
        commit_agency_profile_transition(ledger_case["ledger"], None)


def test_commit_appeal_rejects_malformed_payload_as_ledger_error(
    ledger_case: dict[str, Any],
) -> None:
    with pytest.raises(AgencyLedgerError):
        commit_agency_appeal(ledger_case["ledger"], None)


# --- before-commit zero write across transition and appeal ---


def test_before_commit_transition_fault_is_zero_write_across_all_tables(
    agency_case: _AgencyCase,
    ledger_case: dict[str, Any],
) -> None:
    first = _mk_profile(agency_case, SHA256_A)
    commit_human_agency_profile(ledger_case["ledger"], first)
    transition = _mk_transition(agency_case, target=first, transition="revoked")
    before = _snapshot_all_tables(ledger_case["ledger"])
    with pytest.raises(AgencyLedgerError):
        commit_agency_profile_transition(
            ledger_case["ledger"], transition, fault="before_commit"
        )
    assert _snapshot_all_tables(ledger_case["ledger"]) == before


def test_before_commit_appeal_fault_is_zero_write_across_all_tables(
    agency_case: _AgencyCase,
    ledger_case: dict[str, Any],
) -> None:
    profile = _mk_profile(agency_case, SHA256_A)
    commit_human_agency_profile(ledger_case["ledger"], profile)
    appeal = _mk_appeal(agency_case, profile=profile)
    before = _snapshot_all_tables(ledger_case["ledger"])
    with pytest.raises(AgencyLedgerError):
        commit_agency_appeal(
            ledger_case["ledger"], appeal, fault="before_commit"
        )
    assert _snapshot_all_tables(ledger_case["ledger"]) == before
