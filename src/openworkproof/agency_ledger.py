"""Append-only transaction layer for human agency profile history.

This module commits and loads the three signed protocol objects from
``openworkproof.agency`` (profiles, transitions, appeals) as immutable ledger
rows. It never mutates or deletes a committed row; supersession and
revocation are expressed by appending a new signed transition instead of
rewriting the profile. Each commit loads the authoritative WorkOrder from the
ledger and re-verifies the exact role, signature, and WorkOrder binding before
any write, then uses ``BEGIN IMMEDIATE``, canonical JSON, defensive exact
readback, and the shared target lock so that a lost COMMIT acknowledgement is
resolved into either the exact committed truth or an explicit indeterminate
error.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

import openworkproof.evidence as evidence
from openworkproof.agency import (
    AgencyAppealV01,
    AgencyProfileHistory,
    AgencyProfileHistoryError,
    AgencyProfileTransitionV01,
    HumanAgencyProfileV01,
    ResolvedAgencyProfile,
    resolve_current_human_agency_profile,
    resolve_human_agency_profile_structure,
    verify_agency_appeal,
    verify_agency_profile_transition,
    verify_human_agency_profile,
)
from openworkproof.models import WorkOrder


__all__ = [
    "AgencyCommitIndeterminateError",
    "AgencyCommittedError",
    "AgencyLedgerError",
    "commit_agency_appeal",
    "commit_agency_profile_transition",
    "commit_human_agency_profile",
    "load_agency_appeals",
    "load_agency_history",
    "load_current_human_agency_profile",
]


_PROFILE_TABLE = "human_agency_profiles_v01"
_TRANSITION_TABLE = "agency_profile_transitions_v01"
_APPEAL_TABLE = "agency_appeals_v01"

# Canonical identity columns only. ``committed_at`` is a ledger operational
# timestamp and is deliberately excluded from signed-object identity, so it is
# kept out of every values/readback comparison below.
_PROFILE_IDENTITY_COLUMNS = (
    "profile_id",
    "work_order_digest",
    "profile_digest",
    "profile_json",
    "nonce",
    "issued_at",
)
_TRANSITION_IDENTITY_COLUMNS = (
    "transition_id",
    "work_order_digest",
    "target_profile_id",
    "target_profile_digest",
    "replacement_profile_id",
    "replacement_profile_digest",
    "transition",
    "transition_digest",
    "transition_json",
    "nonce",
    "transitioned_at",
)
_APPEAL_IDENTITY_COLUMNS = (
    "appeal_id",
    "work_order_digest",
    "profile_id",
    "profile_digest",
    "requested_change_digest",
    "reason_code",
    "appeal_digest",
    "appeal_json",
    "nonce",
    "created_at",
)

_AgencyFault = Literal[
    "before_commit",
    "commit_ack_loss",
    "readback_failure",
    "cleanup_failure",
]

_FAULTS = frozenset(
    {
        None,
        "before_commit",
        "commit_ack_loss",
        "readback_failure",
        "cleanup_failure",
    }
)

_COMMITTED_AT_RE = re.compile(
    r"^([0-9]{4})-([0-9]{2})-([0-9]{2})T"
    r"([0-9]{2}):([0-9]{2}):([0-9]{2})Z$"
)

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


class AgencyLedgerError(RuntimeError):
    """A human agency history object could not be committed or loaded."""


class AgencyCommittedError(AgencyLedgerError):
    """The exact agency object is already committed (idempotent or post-commit)."""

    committed = True

    def __init__(self, message: str, committed: object) -> None:
        super().__init__(message)
        self.committed = committed


class AgencyCommitIndeterminateError(AgencyLedgerError):
    """The commit outcome could not be proven."""

    committed = None
    truth = "unknown"


def _canonical(value: Any) -> str:
    return evidence._canonical_json(value)


def _signed_time(value: Any, field: str) -> str:
    return value.model_dump(mode="json")[field]


def _operational_utc_timestamp() -> str:
    """Compute one canonical UTC second for a single insert operation."""
    return (
        datetime.now(timezone.utc)
        .astimezone(timezone.utc)
        .replace(microsecond=0)
        .strftime("%Y-%m-%dT%H:%M:%SZ")
    )


def _validate_committed_at(value: Any) -> str:
    if type(value) is not str:
        raise AgencyLedgerError("committed_at is not a canonical UTC timestamp")
    match = _COMMITTED_AT_RE.fullmatch(value)
    if match is None:
        raise AgencyLedgerError("committed_at is not a canonical UTC timestamp")
    year, month, day, hour, minute, second = map(int, match.groups())
    if second > 59:
        raise AgencyLedgerError("committed_at is not a canonical UTC timestamp")
    try:
        parsed = datetime(
            year, month, day, hour, minute, second, tzinfo=timezone.utc
        )
    except ValueError:
        raise AgencyLedgerError("committed_at is not a canonical UTC timestamp")
    if parsed < _EPOCH:
        raise AgencyLedgerError("committed_at is not a canonical UTC timestamp")
    return value


def _parse_agency_json(raw: Any, model_type: type[Any], label: str) -> Any:
    try:
        return model_type.model_validate_json(raw)
    except Exception as error:
        raise AgencyLedgerError(label) from error


def _profile_values(profile: HumanAgencyProfileV01) -> tuple[Any, ...]:
    return (
        profile.profile_id,
        profile.work_order_digest,
        profile.digest,
        _canonical(profile.model_dump(mode="json")),
        profile.nonce,
        _signed_time(profile, "issued_at"),
    )


def _transition_values(
    transition: AgencyProfileTransitionV01,
) -> tuple[Any, ...]:
    return (
        transition.transition_id,
        transition.work_order_digest,
        transition.target_profile_id,
        transition.target_profile_digest,
        transition.replacement_profile_id,
        transition.replacement_profile_digest,
        transition.transition,
        transition.digest,
        _canonical(transition.model_dump(mode="json")),
        transition.nonce,
        _signed_time(transition, "transitioned_at"),
    )


def _appeal_values(appeal: AgencyAppealV01) -> tuple[Any, ...]:
    return (
        appeal.appeal_id,
        appeal.work_order_digest,
        appeal.profile_id,
        appeal.profile_digest,
        appeal.requested_change_digest,
        appeal.reason_code,
        appeal.digest,
        _canonical(appeal.model_dump(mode="json")),
        appeal.nonce,
        _signed_time(appeal, "created_at"),
    )


def _exact_profile_readback(
    ledger_path: Path,
    profile: HumanAgencyProfileV01,
) -> bool:
    try:
        connection = evidence.connect_ledger(ledger_path)
        try:
            row = connection.execute(
                f"""
                SELECT {", ".join(_PROFILE_IDENTITY_COLUMNS)}
                FROM {_PROFILE_TABLE}
                WHERE profile_id = ?
                """,
                (profile.profile_id,),
            ).fetchone()
        finally:
            connection.close()
    except Exception:
        return False
    return row == _profile_values(profile)


def _exact_transition_readback(
    ledger_path: Path,
    transition: AgencyProfileTransitionV01,
) -> bool:
    try:
        connection = evidence.connect_ledger(ledger_path)
        try:
            row = connection.execute(
                f"""
                SELECT {", ".join(_TRANSITION_IDENTITY_COLUMNS)}
                FROM {_TRANSITION_TABLE}
                WHERE transition_id = ?
                """,
                (transition.transition_id,),
            ).fetchone()
        finally:
            connection.close()
    except Exception:
        return False
    return row == _transition_values(transition)


def _exact_appeal_readback(
    ledger_path: Path,
    appeal: AgencyAppealV01,
) -> bool:
    try:
        connection = evidence.connect_ledger(ledger_path)
        try:
            row = connection.execute(
                f"""
                SELECT {", ".join(_APPEAL_IDENTITY_COLUMNS)}
                FROM {_APPEAL_TABLE}
                WHERE appeal_id = ?
                """,
                (appeal.appeal_id,),
            ).fetchone()
        finally:
            connection.close()
    except Exception:
        return False
    return row == _appeal_values(appeal)


def _load_committed_profile(
    connection,
    work_order: WorkOrder,
    profile_id: str,
    label: str,
) -> HumanAgencyProfileV01:
    row = connection.execute(
        f"""
        SELECT {", ".join(_PROFILE_IDENTITY_COLUMNS)}, committed_at
        FROM {_PROFILE_TABLE}
        WHERE profile_id = ?
        """,
        (profile_id,),
    ).fetchone()
    if row is None:
        raise AgencyLedgerError(f"{label} is not committed")
    (pid, wod, pdigest, pjson, nonce, issued_at, committed_at) = row
    profile = _parse_agency_json(
        pjson, HumanAgencyProfileV01, f"{label} row is malformed"
    )
    _validate_committed_at(committed_at)
    if (pid, wod, pdigest, pjson, nonce, issued_at) != _profile_values(profile):
        raise AgencyLedgerError(f"{label} row does not match its canonical model")
    if not verify_human_agency_profile(profile, work_order):
        raise AgencyLedgerError(f"{label} is invalid")
    return profile


def _check_transition_references(
    connection,
    work_order: WorkOrder,
    transition: AgencyProfileTransitionV01,
) -> None:
    existing = connection.execute(
        f"""
        SELECT transition_id FROM {_TRANSITION_TABLE}
        WHERE target_profile_id = ?
        """,
        (transition.target_profile_id,),
    ).fetchone()
    if existing is not None:
        raise AgencyLedgerError("target profile already has a transition")
    target = _load_committed_profile(
        connection, work_order, transition.target_profile_id,
        "transition target profile",
    )
    if target.digest != transition.target_profile_digest:
        raise AgencyLedgerError(
            "transition target profile digest does not match"
        )
    if transition.transition == "superseded":
        replacement = _load_committed_profile(
            connection, work_order, transition.replacement_profile_id,
            "transition replacement profile",
        )
        if replacement.digest != transition.replacement_profile_digest:
            raise AgencyLedgerError(
                "transition replacement profile digest does not match"
            )


def _check_appeal_references(
    connection,
    work_order: WorkOrder,
    appeal: AgencyAppealV01,
) -> None:
    profile = _load_committed_profile(
        connection, work_order, appeal.profile_id, "appeal target profile"
    )
    if profile.digest != appeal.profile_digest:
        raise AgencyLedgerError("appeal target profile digest does not match")


def _assert_agency_nonce_unused(
    connection,
    table: str,
    nonce: str,
) -> None:
    row = connection.execute(
        f"SELECT 1 FROM {table} WHERE nonce = ?",
        (nonce,),
    ).fetchone()
    if row is not None:
        raise AgencyLedgerError("agency object nonce is already used")


def _load_profiles(
    connection,
    work_order: WorkOrder,
) -> tuple[HumanAgencyProfileV01, ...]:
    rows = connection.execute(
        f"""
        SELECT {", ".join(_PROFILE_IDENTITY_COLUMNS)}, committed_at
        FROM {_PROFILE_TABLE}
        ORDER BY profile_id
        """,
    ).fetchall()
    profiles: list[HumanAgencyProfileV01] = []
    for row in rows:
        (pid, wod, pdigest, pjson, nonce, issued_at, committed_at) = row
        profile = _parse_agency_json(
            pjson,
            HumanAgencyProfileV01,
            "committed agency profile row is malformed",
        )
        _validate_committed_at(committed_at)
        if (pid, wod, pdigest, pjson, nonce, issued_at) != _profile_values(
            profile
        ):
            raise AgencyLedgerError(
                "committed agency profile row does not match its canonical model"
            )
        if not verify_human_agency_profile(profile, work_order):
            raise AgencyLedgerError("committed agency profile is invalid")
        profiles.append(profile)
    return tuple(profiles)


def _load_transitions(
    connection,
    work_order: WorkOrder,
) -> tuple[AgencyProfileTransitionV01, ...]:
    rows = connection.execute(
        f"""
        SELECT {", ".join(_TRANSITION_IDENTITY_COLUMNS)}, committed_at
        FROM {_TRANSITION_TABLE}
        ORDER BY transition_id
        """,
    ).fetchall()
    transitions: list[AgencyProfileTransitionV01] = []
    for row in rows:
        (
            tid, wod, target_id, target_digest, repl_id, repl_digest,
            kind, tdigest, tjson, nonce, transitioned_at, committed_at,
        ) = row
        transition = _parse_agency_json(
            tjson,
            AgencyProfileTransitionV01,
            "committed agency transition row is malformed",
        )
        _validate_committed_at(committed_at)
        expected = (
            tid, wod, target_id, target_digest, repl_id, repl_digest,
            kind, tdigest, tjson, nonce, transitioned_at,
        )
        if expected != _transition_values(transition):
            raise AgencyLedgerError(
                "committed agency transition row does not match its canonical model"
            )
        if not verify_agency_profile_transition(transition, work_order):
            raise AgencyLedgerError("committed agency transition is invalid")
        transitions.append(transition)
    return tuple(transitions)


def _load_appeals(
    connection,
    work_order: WorkOrder,
) -> tuple[AgencyAppealV01, ...]:
    rows = connection.execute(
        f"""
        SELECT {", ".join(_APPEAL_IDENTITY_COLUMNS)}, committed_at
        FROM {_APPEAL_TABLE}
        ORDER BY appeal_id
        """,
    ).fetchall()
    appeals: list[AgencyAppealV01] = []
    for row in rows:
        (
            aid, wod, profile_id, profile_digest, requested_digest, reason,
            adigest, ajson, nonce, created_at, committed_at,
        ) = row
        appeal = _parse_agency_json(
            ajson, AgencyAppealV01, "committed agency appeal row is malformed"
        )
        _validate_committed_at(committed_at)
        expected = (
            aid, wod, profile_id, profile_digest, requested_digest, reason,
            adigest, ajson, nonce, created_at,
        )
        if expected != _appeal_values(appeal):
            raise AgencyLedgerError(
                "committed agency appeal row does not match its canonical model"
            )
        if not verify_agency_appeal(appeal, work_order):
            raise AgencyLedgerError("committed agency appeal is invalid")
        appeals.append(appeal)
    return tuple(appeals)


def _validate_transition_references(
    profiles: tuple[HumanAgencyProfileV01, ...],
    transitions: tuple[AgencyProfileTransitionV01, ...],
) -> None:
    profiles_by_id = {profile.profile_id: profile for profile in profiles}
    for transition in transitions:
        target = profiles_by_id.get(transition.target_profile_id)
        if target is None or target.digest != transition.target_profile_digest:
            raise AgencyLedgerError(
                "committed agency transition references an unknown or mismatched profile"
            )
        if transition.transition == "superseded":
            replacement = profiles_by_id.get(transition.replacement_profile_id)
            if (
                replacement is None
                or replacement.digest != transition.replacement_profile_digest
            ):
                raise AgencyLedgerError(
                    "committed agency transition references an unknown or mismatched replacement profile"
                )


def _validate_appeal_references(
    profiles: tuple[HumanAgencyProfileV01, ...],
    appeals: tuple[AgencyAppealV01, ...],
) -> None:
    profiles_by_id = {profile.profile_id: profile for profile in profiles}
    for appeal in appeals:
        target = profiles_by_id.get(appeal.profile_id)
        if target is None or target.digest != appeal.profile_digest:
            raise AgencyLedgerError(
                "committed agency appeal references an unknown or mismatched profile"
            )


def _validate_transition_structure(
    connection,
    work_order: WorkOrder,
    transition: AgencyProfileTransitionV01,
) -> None:
    profiles = _load_profiles(connection, work_order)
    transitions = _load_transitions(connection, work_order)
    staged = transitions + (transition,)
    try:
        resolve_human_agency_profile_structure(work_order, profiles, staged)
    except AgencyProfileHistoryError as error:
        raise AgencyLedgerError(
            f"agency profile transition would leave an invalid history: {error}"
        ) from error


def _noop_reference_check(
    connection,
    work_order: WorkOrder,
    value: Any,
) -> None:
    return None


def _noop_structure_check(
    connection,
    work_order: WorkOrder,
    value: Any,
) -> None:
    return None


def _reparse(obj: Any, model_type: type[Any], label: str) -> Any:
    try:
        return model_type.model_validate(obj.model_dump(mode="json"))
    except Exception as error:
        raise AgencyLedgerError(f"{label} payload is malformed") from error


def _commit_agency_object(
    ledger_path: Path,
    parsed: Any,
    *,
    object_label: str,
    table: str,
    id_column: str,
    identity_columns: tuple[str, ...],
    verify: Callable[[Any, WorkOrder], bool],
    verify_failure: str,
    check_references: Callable[[Any, WorkOrder, Any], None],
    validate_structure: Callable[[Any, WorkOrder, Any], None],
    values: Callable[[Any], tuple[Any, ...]],
    insert_row: Callable[[Any, Any, str], None],
    readback: Callable[[Path, Any], bool],
    fault: _AgencyFault | None,
) -> Any:
    if fault not in _FAULTS:
        raise AgencyLedgerError("unknown agency ledger fault")
    path = Path(ledger_path)
    if not path.is_file():
        raise AgencyLedgerError(f"{object_label} ledger is unavailable")

    lock_descriptor = None
    connection = None
    committed = False
    try:
        lock_descriptor, _ = evidence._borrow_or_acquire_target_lock(path, None)
        connection = evidence.connect_ledger(path)
        connection.execute("BEGIN IMMEDIATE")
        work_order = evidence.load_authoritative_work_order(connection)
        if not verify(parsed, work_order):
            raise AgencyLedgerError(verify_failure)
        # Check exact existing-id truth before reference/nonce checks so an
        # already-committed object is reported as idempotent, never as a
        # reference collision.
        existing = connection.execute(
            f"SELECT {', '.join(identity_columns)} FROM {table} "
            f"WHERE {id_column} = ?",
            (getattr(parsed, id_column),),
        ).fetchone()
        expected = values(parsed)
        if existing is not None:
            if existing == expected and readback(path, parsed):
                raise AgencyCommittedError(
                    f"the exact {object_label} is already committed",
                    parsed,
                )
            raise AgencyLedgerError(f"{object_label} id is already used")
        check_references(connection, work_order, parsed)
        validate_structure(connection, work_order, parsed)
        _assert_agency_nonce_unused(connection, table, parsed.nonce)
        committed_at = _operational_utc_timestamp()
        insert_row(connection, parsed, committed_at)
        if fault == "before_commit":
            raise AgencyLedgerError("injected fault before commit")
        connection.execute("COMMIT")
        committed = True
        if fault == "commit_ack_loss":
            raise OSError("injected commit acknowledgement loss")
        if fault == "readback_failure":
            raise AgencyCommitIndeterminateError(
                f"{object_label} readback was unavailable"
            )
        if not readback(path, parsed):
            raise AgencyCommitIndeterminateError(
                f"{object_label} readback did not confirm commit"
            )
    except Exception as error:
        evidence._best_effort_rollback(connection)
        if isinstance(error, AgencyCommittedError):
            raise
        if isinstance(error, AgencyCommitIndeterminateError):
            raise
        if committed:
            if readback(path, parsed):
                raise AgencyCommittedError(
                    f"{object_label} committed but acknowledgement was lost",
                    parsed,
                ) from error
            raise AgencyCommitIndeterminateError(
                f"{object_label} commit outcome is indeterminate"
            ) from error
        if isinstance(error, AgencyLedgerError):
            raise
        raise AgencyLedgerError(
            f"{object_label} transaction failed: "
            f"{type(error).__name__}: {error}"
        ) from error
    finally:
        close_error = evidence._best_effort_close(connection)
        _, release_errors = evidence._release_target_lock(lock_descriptor)
        cleanup_errors = tuple(
            item for item in (close_error, *release_errors) if item is not None
        )
    if fault == "cleanup_failure":
        cleanup_errors += (OSError("injected cleanup failure"),)
    if cleanup_errors:
        raise AgencyCommittedError(
            f"{object_label} committed but cleanup failed",
            parsed,
        ) from cleanup_errors[0]
    return parsed


def commit_human_agency_profile(
    ledger_path: Path,
    profile: HumanAgencyProfileV01,
    *,
    fault: _AgencyFault | None = None,
) -> HumanAgencyProfileV01:
    """Append one Acceptor-signed HumanAgencyProfile to the ledger."""

    parsed = _reparse(profile, HumanAgencyProfileV01, "human agency profile")

    def _insert(
        connection, value: HumanAgencyProfileV01, committed_at: str
    ) -> None:
        connection.execute(
            f"""
            INSERT INTO {_PROFILE_TABLE} (
                profile_id, work_order_digest, profile_digest,
                profile_json, nonce, issued_at, committed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (*_profile_values(value), committed_at),
        )

    return _commit_agency_object(
        ledger_path,
        parsed,
        object_label="human agency profile",
        table=_PROFILE_TABLE,
        id_column="profile_id",
        identity_columns=_PROFILE_IDENTITY_COLUMNS,
        verify=verify_human_agency_profile,
        verify_failure="human agency profile signature or binding is invalid",
        check_references=_noop_reference_check,
        validate_structure=_noop_structure_check,
        values=_profile_values,
        insert_row=_insert,
        readback=_exact_profile_readback,
        fault=fault,
    )


def commit_agency_profile_transition(
    ledger_path: Path,
    transition: AgencyProfileTransitionV01,
    *,
    fault: _AgencyFault | None = None,
) -> AgencyProfileTransitionV01:
    """Append one Acceptor-signed profile transition to the ledger."""

    parsed = _reparse(
        transition, AgencyProfileTransitionV01, "agency profile transition"
    )

    def _insert(
        connection, value: AgencyProfileTransitionV01, committed_at: str
    ) -> None:
        connection.execute(
            f"""
            INSERT INTO {_TRANSITION_TABLE} (
                transition_id, work_order_digest, target_profile_id,
                target_profile_digest, replacement_profile_id,
                replacement_profile_digest, transition,
                transition_digest, transition_json, nonce, transitioned_at,
                committed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (*_transition_values(value), committed_at),
        )

    return _commit_agency_object(
        ledger_path,
        parsed,
        object_label="agency profile transition",
        table=_TRANSITION_TABLE,
        id_column="transition_id",
        identity_columns=_TRANSITION_IDENTITY_COLUMNS,
        verify=verify_agency_profile_transition,
        verify_failure="agency profile transition signature or binding is invalid",
        check_references=_check_transition_references,
        validate_structure=_validate_transition_structure,
        values=_transition_values,
        insert_row=_insert,
        readback=_exact_transition_readback,
        fault=fault,
    )


def commit_agency_appeal(
    ledger_path: Path,
    appeal: AgencyAppealV01,
    *,
    fault: _AgencyFault | None = None,
) -> AgencyAppealV01:
    """Append one signed agency appeal to the ledger."""

    parsed = _reparse(appeal, AgencyAppealV01, "agency appeal")

    def _insert(
        connection, value: AgencyAppealV01, committed_at: str
    ) -> None:
        connection.execute(
            f"""
            INSERT INTO {_APPEAL_TABLE} (
                appeal_id, work_order_digest, profile_id, profile_digest,
                requested_change_digest, reason_code, appeal_digest,
                appeal_json, nonce, created_at, committed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (*_appeal_values(value), committed_at),
        )

    return _commit_agency_object(
        ledger_path,
        parsed,
        object_label="agency appeal",
        table=_APPEAL_TABLE,
        id_column="appeal_id",
        identity_columns=_APPEAL_IDENTITY_COLUMNS,
        verify=verify_agency_appeal,
        verify_failure="agency appeal signature or binding is invalid",
        check_references=_check_appeal_references,
        validate_structure=_noop_structure_check,
        values=_appeal_values,
        insert_row=_insert,
        readback=_exact_appeal_readback,
        fault=fault,
    )


def load_agency_history(
    ledger_path: Path,
    work_order_digest: str,
) -> AgencyProfileHistory:
    """Load the revalidated profile and transition history for one WorkOrder."""

    path = Path(ledger_path)
    connection = evidence.connect_ledger(path)
    try:
        work_order = evidence.load_authoritative_work_order(connection)
        if work_order_digest != work_order.digest:
            raise AgencyLedgerError(
                "agency history work_order_digest is not authoritative"
            )
        profiles = _load_profiles(connection, work_order)
        transitions = _load_transitions(connection, work_order)
        _validate_transition_references(profiles, transitions)
        return AgencyProfileHistory(
            profiles=profiles,
            transitions=transitions,
        )
    finally:
        connection.close()


def load_current_human_agency_profile(
    ledger_path: Path,
    *,
    now: datetime,
) -> ResolvedAgencyProfile:
    """Resolve the unique current profile from the committed signed history."""

    path = Path(ledger_path)
    connection = evidence.connect_ledger(path)
    try:
        work_order = evidence.load_authoritative_work_order(connection)
        profiles = _load_profiles(connection, work_order)
        transitions = _load_transitions(connection, work_order)
        return resolve_current_human_agency_profile(
            work_order, profiles, transitions, now=now
        )
    finally:
        connection.close()


def load_agency_appeals(
    ledger_path: Path,
    work_order_digest: str,
) -> tuple[AgencyAppealV01, ...]:
    """Load every committed appeal bound to one WorkOrder."""

    path = Path(ledger_path)
    connection = evidence.connect_ledger(path)
    try:
        work_order = evidence.load_authoritative_work_order(connection)
        if work_order_digest != work_order.digest:
            raise AgencyLedgerError(
                "agency appeals work_order_digest is not authoritative"
            )
        profiles = _load_profiles(connection, work_order)
        appeals = _load_appeals(connection, work_order)
        _validate_appeal_references(profiles, appeals)
        return appeals
    finally:
        connection.close()
