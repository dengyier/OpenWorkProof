"""Atomic authority ledger primitives for the OpenWorkProof genesis flow."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
import fcntl
import hashlib
from itertools import islice
import json
import os
from pathlib import Path
import secrets
import sqlite3
import stat
import tempfile

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
import rfc8785

from openworkproof.composition import (
    AuthorizationCausalityError,
    replay_authorization_causality,
)
from openworkproof.models import (
    ACTION_RECEIPT_ADAPTER,
    AcceptanceReceipt,
    AcceptanceRejectionReceipt,
    ActionReceiptEnvelope,
    AgentRequest,
    ApplyPatchArguments,
    ApprovalDecisionReceipt,
    ApprovalRequestedReceipt,
    CapabilityGrant,
    CompositionCause,
    CompositionReport,
    ComposeProofArguments,
    CreatePrProposalArguments,
    GrantConsumedReceipt,
    GrantIssuedReceipt,
    GrantRevokedReceipt,
    PatchResultEvidence,
    RepoReadArguments,
    RollbackReceipt,
    RunTestsArguments,
    SidecarEvent,
    SystemEventReceipt,
    TestResultEvidence,
    TerminationDecisionReceipt,
    ToolCallReceipt,
    WorkOrder,
    _load_canonical_json,
    request_arguments_digest,
)
from openworkproof.predicates import (
    EvaluationContext,
    evaluate_required_predicates,
    select_required_predicates,
)
from openworkproof.policy import (
    AuthorizationPolicyError,
    _child_policy_decision as _policy_child_decision,
    _replay_grant_quota_history as _policy_quota_replay,
    _validate_grant_history_semantics as _policy_history_replay,
    replay_authorization_policy,
)
from openworkproof.repo_tools import (
    ResolutionManifest,
    ResolutionManifestEntry,
    resolution_manifest_digest,
)
from openworkproof.signing import (
    decode_and_verify_key_binding,
    key_id,
    sign_payload,
    unsigned_payload,
    verify_nested_claim,
    verify_payload,
    verify_work_order_identity_bindings,
)
from openworkproof.state import (
    TaskState,
    _agent_direct_call_is_authorized,
    _validate_contract_expiry,
    _validate_termination,
    append_receipt,
    apply_state_transition,
)


BUSY_TIMEOUT_MS = 135_000
MAX_RECEIPTS = 64
MAX_ROUTINE_ACTION_RECEIPTS = 61
MAX_EFFECTIVE_GRANTS = 8
MAX_GRANT_ATTEMPTS = 8
MAX_GRANT_RESERVATIONS = (
    MAX_EFFECTIVE_GRANTS + MAX_GRANT_ATTEMPTS
)
MAX_GRANT_EVENTS = MAX_RECEIPTS
MAX_RECEIPT_PARENT_EDGES = MAX_RECEIPTS * 16
MAX_ACCEPTANCE_RECEIPTS = 1
MAX_ACCEPTANCE_REJECTION_RECEIPTS = 1
_MAX_PUBLICATIONS_PER_GROUP = 8


class LedgerInitializationError(RuntimeError):
    """The authoritative WorkOrder ledger could not be initialized or loaded."""


class LedgerInitializationCommittedError(RuntimeError):
    """Ledger publication committed, but target-lock closure is indeterminate."""

    committed = True

    def __init__(
        self,
        ledger_path: Path,
        work_order_digest: str,
    ) -> None:
        super().__init__(
            "ledger initialization committed but target-lock closure failed"
        )
        self.ledger_path = ledger_path
        self.work_order_digest = work_order_digest


class RootActivationError(RuntimeError):
    """Root activation failed before it could become a ledger fact."""

    code = "ROOT_ACTIVATION_INVALID"


class RootActivationCommittedError(RuntimeError):
    """Root activation committed, but local connection closure is indeterminate."""

    committed = True

    def __init__(self, receipt: GrantIssuedReceipt) -> None:
        super().__init__(
            "root activation committed but connection closure failed"
        )
        self.receipt = receipt


class ChildGrantIssuanceError(RuntimeError):
    """Child Grant issuance failed before it became a ledger fact."""

    code = "CHILD_GRANT_ISSUANCE_INVALID"


class ChildGrantIssuanceCommittedError(RuntimeError):
    """Child issuance committed, but local completion was indeterminate."""

    committed = True

    def __init__(self, receipt: GrantIssuedReceipt) -> None:
        super().__init__(
            "child Grant issuance committed but completion was indeterminate"
        )
        self.receipt = receipt


@dataclass(frozen=True)
class AuthorizationChainResult:
    """Immutable success marker for a fully validated authorization chain."""


class GrantRevocationError(RuntimeError):
    """Grant revocation failed before it became a ledger fact."""

    code = "GRANT_REVOCATION_INVALID"


class GrantRevocationCommittedError(RuntimeError):
    """Grant revocation committed, but local completion was indeterminate."""

    committed = True

    def __init__(self, receipt: GrantRevokedReceipt) -> None:
        super().__init__(
            "Grant revocation committed but completion was indeterminate"
        )
        self.receipt = receipt


class RetryConsumptionError(RuntimeError):
    """A retry request failed before it became a ledger fact."""

    code = "REQUEST_INTEGRITY_INVALID"


class RetryEvidenceRecoveryError(RetryConsumptionError):
    """Committed evidence cannot be read until publication recovery completes."""

    code = "RECOVERY_REQUIRED"


class RetryEvidenceIntegrityError(RetryConsumptionError):
    """The immutable evidence needed for retry authorization is invalid."""

    code = "REQUEST_INTEGRITY_INVALID"


class EvidencePublicationCommittedError(RuntimeError):
    """Evidence publication committed, but local completion was indeterminate."""

    committed = True

    def __init__(
        self,
        group: _PublicationGroup,
        *,
        evidence_verified: bool = True,
    ) -> None:
        super().__init__(
            "evidence publication committed but completion was indeterminate"
        )
        self.group = group
        self.receipt_id = group.receipt_id
        self.evidence_verified = evidence_verified


class EvidencePublicationCommitIndeterminateError(RuntimeError):
    """Evidence publication COMMIT truth could not be confirmed."""

    committed = None
    truth = "unknown"

    def __init__(self, group: _PublicationGroup) -> None:
        super().__init__(
            "evidence publication commit outcome is indeterminate"
        )
        self.group = group
        self.receipt_id = group.receipt_id


class ReceiptPublicationCommittedError(RuntimeError):
    """The receipt journal committed, but local completion failed."""

    committed = True

    def __init__(
        self,
        receipt: ActionReceiptEnvelope,
        group: _PublicationGroup,
    ) -> None:
        super().__init__(
            "receipt publication journal committed but completion failed"
        )
        self.receipt = receipt
        self.group = group
        self.receipt_id = receipt.receipt_id


class ReceiptPublicationCommitIndeterminateError(RuntimeError):
    """The receipt publication journal COMMIT truth is unknown."""

    committed = None
    truth = "unknown"

    def __init__(
        self,
        receipt: ActionReceiptEnvelope,
        group: _PublicationGroup,
    ) -> None:
        super().__init__(
            "receipt publication journal commit outcome is indeterminate"
        )
        self.receipt = receipt
        self.group = group
        self.receipt_id = receipt.receipt_id


class RetryConsumptionCommittedError(RuntimeError):
    """Retry consumption committed, but local completion was indeterminate."""

    committed = True

    def __init__(self, receipt: GrantConsumedReceipt) -> None:
        super().__init__(
            "retry consumption committed but completion was indeterminate"
        )
        self.receipt = receipt


@dataclass(frozen=True)
class _Publication:
    publication_id: str
    pending_path: str
    final_path: str
    digest: str
    size_bytes: int
    media_type: str


@dataclass(frozen=True)
class _PublicationGroup:
    receipt_id: str
    publications: tuple[_Publication, ...]


_LEGACY_HANDLER_EXECUTION_SCHEMA = """
CREATE TABLE handler_executions (
    execution_id TEXT PRIMARY KEY,
    work_order_digest TEXT NOT NULL
        REFERENCES work_orders(work_order_digest),
    request_digest TEXT NOT NULL UNIQUE,
    nonce TEXT NOT NULL UNIQUE,
    grant_id TEXT NOT NULL REFERENCES grants(grant_id),
    tool_name TEXT NOT NULL CHECK (tool_name = 'owp.run_tests'),
    arguments_digest TEXT NOT NULL,
    execution_context_id TEXT NOT NULL UNIQUE,
    container_instance_id_digest TEXT NOT NULL UNIQUE,
    controller_id TEXT NOT NULL,
    reserved_at TEXT NOT NULL,
    state TEXT NOT NULL CHECK (
        state IN ('RESERVED', 'STARTED_UNCONFIRMED')
    )
)
"""


_HANDLER_EXECUTION_SCHEMA_V1 = """
CREATE TABLE handler_executions (
    execution_id TEXT PRIMARY KEY,
    work_order_digest TEXT NOT NULL
        REFERENCES work_orders(work_order_digest),
    request_digest TEXT NOT NULL UNIQUE,
    nonce TEXT NOT NULL UNIQUE,
    grant_id TEXT NOT NULL REFERENCES grants(grant_id),
    tool_name TEXT NOT NULL CHECK (
        tool_name IN (
            'owp.run_tests',
            'owp.rollback_patch',
            'owp.repo_read'
        )
    ),
    arguments_digest TEXT NOT NULL,
    execution_context_id TEXT NOT NULL UNIQUE,
    container_instance_id_digest TEXT NOT NULL UNIQUE,
    controller_id TEXT NOT NULL,
    reserved_at TEXT NOT NULL,
    state TEXT NOT NULL CHECK (
        state IN ('RESERVED', 'STARTED_UNCONFIRMED')
    )
)
"""


_HANDLER_EXECUTION_SCHEMA_V2 = """
CREATE TABLE handler_executions (
    execution_id TEXT PRIMARY KEY,
    work_order_digest TEXT NOT NULL
        REFERENCES work_orders(work_order_digest),
    request_digest TEXT NOT NULL UNIQUE,
    nonce TEXT NOT NULL UNIQUE,
    grant_id TEXT NOT NULL REFERENCES grants(grant_id),
    tool_name TEXT NOT NULL CHECK (
        tool_name IN ('owp.run_tests', 'owp.rollback_patch')
    ),
    arguments_digest TEXT NOT NULL,
    execution_context_id TEXT NOT NULL UNIQUE,
    container_instance_id_digest TEXT NOT NULL UNIQUE,
    controller_id TEXT NOT NULL,
    reserved_at TEXT NOT NULL,
    state TEXT NOT NULL CHECK (
        state IN ('RESERVED', 'STARTED_UNCONFIRMED')
    ),
    request_json TEXT,
    execution_contract_json TEXT,
    execution_contract_digest TEXT,
    CHECK (
        (
            tool_name = 'owp.run_tests'
            AND request_json IS NOT NULL
            AND execution_contract_json IS NOT NULL
            AND execution_contract_digest IS NOT NULL
        )
        OR
        (
            tool_name = 'owp.rollback_patch'
            AND request_json IS NULL
            AND execution_contract_json IS NULL
            AND execution_contract_digest IS NULL
        )
        OR
        (
            tool_name = 'owp.repo_read'
            AND request_json IS NULL
            AND execution_contract_json IS NULL
            AND execution_contract_digest IS NULL
        )
    )
)
"""


_HANDLER_EXECUTION_SCHEMA = """
CREATE TABLE handler_executions (
    execution_id TEXT PRIMARY KEY,
    work_order_digest TEXT NOT NULL
        REFERENCES work_orders(work_order_digest),
    request_digest TEXT NOT NULL UNIQUE,
    nonce TEXT NOT NULL UNIQUE,
    grant_id TEXT NOT NULL REFERENCES grants(grant_id),
    tool_name TEXT NOT NULL CHECK (
        tool_name IN (
            'owp.run_tests',
            'owp.rollback_patch',
            'owp.repo_read'
        )
    ),
    arguments_digest TEXT NOT NULL,
    execution_context_id TEXT NOT NULL UNIQUE,
    container_instance_id_digest TEXT NOT NULL UNIQUE,
    controller_id TEXT NOT NULL,
    reserved_at TEXT NOT NULL,
    state TEXT NOT NULL CHECK (
        state IN ('RESERVED', 'STARTED_UNCONFIRMED')
    ),
    authorization_prefix_digest TEXT,
    request_json TEXT,
    execution_contract_json TEXT,
    execution_contract_digest TEXT,
    CHECK (
        (
            tool_name = 'owp.run_tests'
            AND authorization_prefix_digest IS NOT NULL
            AND request_json IS NOT NULL
            AND execution_contract_json IS NOT NULL
            AND execution_contract_digest IS NOT NULL
        )
        OR
        (
            tool_name IN ('owp.rollback_patch', 'owp.repo_read')
            AND authorization_prefix_digest IS NULL
            AND request_json IS NULL
            AND execution_contract_json IS NULL
            AND execution_contract_digest IS NULL
        )
    )
)
"""


_SCHEMA = (
    """
    CREATE TABLE sequence_counter (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        next_sequence INTEGER NOT NULL CHECK (next_sequence >= 1)
    )
    """,
    """
    CREATE TABLE work_orders (
        work_order_digest TEXT PRIMARY KEY,
        work_order_json TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE work_order_state (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        work_order_digest TEXT NOT NULL UNIQUE
            REFERENCES work_orders(work_order_digest),
        current_state TEXT NOT NULL,
        version INTEGER NOT NULL CHECK (version >= 0)
    )
    """,
    """
    CREATE TABLE grant_id_reservations (
        grant_id TEXT PRIMARY KEY,
        work_order_digest TEXT NOT NULL
            REFERENCES work_orders(work_order_digest),
        candidate_grant_digest TEXT UNIQUE,
        reservation_kind TEXT NOT NULL CHECK (
            reservation_kind IN ('root_template', 'effective', 'attempt')
        )
    )
    """,
    """
    CREATE TABLE grants (
        grant_id TEXT PRIMARY KEY REFERENCES grant_id_reservations(grant_id),
        work_order_digest TEXT NOT NULL
            REFERENCES work_orders(work_order_digest),
        parent_grant_id TEXT REFERENCES grants(grant_id),
        subject_agent_id TEXT NOT NULL,
        usage_mode TEXT NOT NULL,
        grant_json TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE grant_attempts (
        candidate_grant_digest TEXT PRIMARY KEY,
        grant_id TEXT NOT NULL UNIQUE
            REFERENCES grant_id_reservations(grant_id),
        work_order_digest TEXT NOT NULL
            REFERENCES work_orders(work_order_digest),
        candidate_grant_json TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE receipts (
        receipt_id TEXT PRIMARY KEY,
        work_order_digest TEXT NOT NULL
            REFERENCES work_orders(work_order_digest),
        nonce TEXT NOT NULL UNIQUE,
        sequence INTEGER NOT NULL UNIQUE,
        previous_digest TEXT,
        receipt_json TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE receipt_parents (
        child_receipt_id TEXT NOT NULL REFERENCES receipts(receipt_id),
        parent_receipt_id TEXT NOT NULL REFERENCES receipts(receipt_id),
        PRIMARY KEY (child_receipt_id, parent_receipt_id)
    )
    """,
    """
    CREATE TABLE grant_events (
        event_id TEXT PRIMARY KEY,
        receipt_id TEXT NOT NULL UNIQUE REFERENCES receipts(receipt_id),
        grant_id TEXT NOT NULL REFERENCES grants(grant_id),
        event_type TEXT NOT NULL,
        metric TEXT,
        amount INTEGER
    )
    """,
    """
    CREATE TABLE evidence_publications (
        publication_id TEXT PRIMARY KEY,
        receipt_id TEXT NOT NULL REFERENCES receipts(receipt_id),
        pending_path TEXT NOT NULL UNIQUE,
        final_path TEXT NOT NULL UNIQUE,
        digest TEXT NOT NULL,
        size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
        media_type TEXT NOT NULL,
        state TEXT NOT NULL CHECK (
            state IN ('COMMITTING', 'COMMITTED')
        ),
        UNIQUE (receipt_id, final_path)
    )
    """,
    _HANDLER_EXECUTION_SCHEMA,
    """
    CREATE TABLE acceptance_receipts (
        acceptance_id TEXT PRIMARY KEY,
        work_order_digest TEXT NOT NULL UNIQUE
            REFERENCES work_orders(work_order_digest),
        acceptance_json TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE acceptance_rejection_receipts (
        rejection_id TEXT PRIMARY KEY,
        work_order_digest TEXT NOT NULL UNIQUE
            REFERENCES work_orders(work_order_digest),
        acceptance_request_receipt_id TEXT NOT NULL UNIQUE
            REFERENCES receipts(receipt_id),
        rejection_json TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE acceptance_transitions (
        transition_id TEXT PRIMARY KEY,
        target_acceptance_id TEXT NOT NULL UNIQUE
            REFERENCES acceptance_receipts(acceptance_id),
        verification_decision_id TEXT NOT NULL
            REFERENCES verification_decisions(decision_id),
        transition_json BLOB NOT NULL UNIQUE
    )
    """,
    """
    CREATE TABLE acceptance_transition_parents (
        transition_id TEXT NOT NULL
            REFERENCES acceptance_transitions(transition_id),
        ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
        parent_id TEXT NOT NULL,
        PRIMARY KEY (transition_id, ordinal),
        UNIQUE (transition_id, parent_id)
    )
    """,
    """
    CREATE TABLE composition_reports (
        report_digest TEXT PRIMARY KEY,
        work_order_digest TEXT NOT NULL
            REFERENCES work_orders(work_order_digest),
        initiator_receipt_id TEXT NOT NULL UNIQUE
            REFERENCES receipts(receipt_id),
        initiator_receipt_digest TEXT NOT NULL,
        source_state_version INTEGER NOT NULL CHECK (source_state_version >= 0),
        report_json TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE subject_claims (
        claim_id TEXT PRIMARY KEY,
        claim_json BLOB NOT NULL UNIQUE
    )
    """,
    """
    CREATE TABLE verification_profiles_v02 (
        profile_id TEXT PRIMARY KEY,
        subject_claim_id TEXT NOT NULL UNIQUE
            REFERENCES subject_claims(claim_id),
        profile_json BLOB NOT NULL UNIQUE
    )
    """,
    """
    CREATE TABLE external_anchors (
        anchor_digest TEXT PRIMARY KEY,
        anchor_kind TEXT NOT NULL CHECK (
            anchor_kind IN ('policy', 'commitment')
        ),
        anchor_json BLOB NOT NULL UNIQUE
    )
    """,
    """
    CREATE TABLE verification_arm_results (
        arm_result_id TEXT PRIMARY KEY,
        profile_id TEXT NOT NULL
            REFERENCES verification_profiles_v02(profile_id),
        arm_id TEXT NOT NULL,
        arm_result_json BLOB NOT NULL UNIQUE,
        UNIQUE(profile_id, arm_id, arm_result_id)
    )
    """,
    """
    CREATE TABLE verification_decisions (
        decision_id TEXT PRIMARY KEY,
        predecessor_id TEXT UNIQUE
            REFERENCES verification_decisions(decision_id),
        decision_json BLOB NOT NULL UNIQUE
    )
    """,
    """
    CREATE TABLE verification_decision_parents (
        decision_id TEXT NOT NULL
            REFERENCES verification_decisions(decision_id),
        ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
        arm_result_id TEXT NOT NULL
            REFERENCES verification_arm_results(arm_result_id),
        PRIMARY KEY(decision_id, ordinal),
        UNIQUE(decision_id, arm_result_id)
    )
    """,
    """
    CREATE TABLE evaluation_scopes_v03 (
        scope_id TEXT PRIMARY KEY,
        scope_digest TEXT NOT NULL UNIQUE,
        work_order_digest TEXT NOT NULL,
        claim_id TEXT NOT NULL,
        subject_claim_digest TEXT NOT NULL,
        scope_json BLOB NOT NULL UNIQUE
    )
    """,
    """
    CREATE TABLE verification_profiles_v03 (
        profile_id TEXT PRIMARY KEY,
        profile_digest TEXT NOT NULL UNIQUE,
        scope_id TEXT NOT NULL UNIQUE
            REFERENCES evaluation_scopes_v03(scope_id),
        scope_digest TEXT NOT NULL,
        subject_claim_id TEXT NOT NULL UNIQUE,
        profile_json BLOB NOT NULL UNIQUE
    )
    """,
    """
    CREATE TABLE verification_arm_results_v03 (
        arm_result_id TEXT PRIMARY KEY,
        arm_result_digest TEXT NOT NULL UNIQUE,
        profile_id TEXT NOT NULL
            REFERENCES verification_profiles_v03(profile_id),
        arm_id TEXT NOT NULL,
        arm_result_json BLOB NOT NULL UNIQUE,
        UNIQUE(profile_id, arm_id, arm_result_id)
    )
    """,
    """
    CREATE TABLE verification_decisions_v03 (
        decision_id TEXT PRIMARY KEY,
        decision_digest TEXT NOT NULL UNIQUE,
        profile_id TEXT NOT NULL
            REFERENCES verification_profiles_v03(profile_id),
        scope_id TEXT NOT NULL
            REFERENCES evaluation_scopes_v03(scope_id),
        predecessor_id TEXT UNIQUE
            REFERENCES verification_decisions_v03(decision_id),
        decision_json BLOB NOT NULL UNIQUE
    )
    """,
    """
    CREATE TABLE verification_decision_parents_v03 (
        decision_id TEXT NOT NULL
            REFERENCES verification_decisions_v03(decision_id),
        ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
        arm_result_id TEXT NOT NULL
            REFERENCES verification_arm_results_v03(arm_result_id),
        PRIMARY KEY(decision_id, ordinal),
        UNIQUE(decision_id, arm_result_id)
    )
    """,
    """
    CREATE TABLE acceptance_transitions_v03 (
        transition_id TEXT PRIMARY KEY,
        transition_digest TEXT NOT NULL UNIQUE,
        target_acceptance_id TEXT NOT NULL UNIQUE,
        verification_decision_id TEXT NOT NULL
            REFERENCES verification_decisions_v03(decision_id),
        transition_json BLOB NOT NULL UNIQUE
    )
    """,
    """
    CREATE TABLE acceptance_transition_parents_v03 (
        transition_id TEXT NOT NULL
            REFERENCES acceptance_transitions_v03(transition_id),
        ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
        parent_id TEXT NOT NULL,
        PRIMARY KEY(transition_id, ordinal),
        UNIQUE(transition_id, parent_id)
    )
    """,
    """
    CREATE TABLE judgment_commitments_v04 (
        commitment_id TEXT PRIMARY KEY,
        commitment_digest TEXT NOT NULL,
        authority_namespace TEXT NOT NULL,
        subject_id TEXT NOT NULL,
        nonce TEXT NOT NULL,
        signer_key_id TEXT NOT NULL,
        commitment_json BLOB NOT NULL,
        committed_at TEXT NOT NULL,
        UNIQUE (signer_key_id, nonce)
    )
    """,
    """
    CREATE INDEX judgment_commitments_v04_authority_subject
    ON judgment_commitments_v04 (
        authority_namespace, subject_id, committed_at, commitment_id
    )
    """,
    """
    CREATE TRIGGER judgment_commitments_v04_are_immutable_update
    BEFORE UPDATE ON judgment_commitments_v04
    BEGIN
        SELECT RAISE(ABORT, 'judgment commitment is immutable');
    END
    """,
    """
    CREATE TRIGGER judgment_commitments_v04_are_immutable_delete
    BEFORE DELETE ON judgment_commitments_v04
    BEGIN
        SELECT RAISE(ABORT, 'judgment commitment is immutable');
    END
    """,
    """
    CREATE TABLE action_binding_manifests_v04 (
        binding_manifest_id TEXT PRIMARY KEY,
        manifest_digest TEXT NOT NULL,
        work_order_digest TEXT NOT NULL
            REFERENCES work_orders(work_order_digest),
        judgment_commitment_id TEXT NOT NULL
            REFERENCES judgment_commitments_v04(commitment_id),
        judgment_commitment_digest TEXT NOT NULL,
        evaluation_scope_id TEXT NOT NULL
            REFERENCES evaluation_scopes_v03(scope_id),
        evaluation_scope_digest TEXT NOT NULL,
        adapter_profile_digest TEXT NOT NULL,
        adapter_profile_json BLOB NOT NULL,
        nonce TEXT NOT NULL,
        signer_key_id TEXT NOT NULL,
        manifest_json BLOB NOT NULL,
        committed_at TEXT NOT NULL,
        UNIQUE (signer_key_id, nonce)
    )
    """,
    """
    CREATE INDEX action_binding_manifests_v04_work_order
    ON action_binding_manifests_v04 (
        work_order_digest, committed_at, binding_manifest_id
    )
    """,
    """
    CREATE TABLE action_binding_manifest_supersessions_v04 (
        child_manifest_id TEXT PRIMARY KEY
            REFERENCES action_binding_manifests_v04(binding_manifest_id),
        parent_manifest_id TEXT NOT NULL UNIQUE
            REFERENCES action_binding_manifests_v04(binding_manifest_id),
        parent_manifest_digest TEXT NOT NULL
    )
    """,
    """
    CREATE TRIGGER action_binding_manifests_v04_are_immutable_update
    BEFORE UPDATE ON action_binding_manifests_v04
    BEGIN
        SELECT RAISE(ABORT, 'action binding manifest is immutable');
    END
    """,
    """
    CREATE TRIGGER action_binding_manifests_v04_are_immutable_delete
    BEFORE DELETE ON action_binding_manifests_v04
    BEGIN
        SELECT RAISE(ABORT, 'action binding manifest is immutable');
    END
    """,
    """
    CREATE TRIGGER action_binding_supersessions_v04_are_immutable_update
    BEFORE UPDATE ON action_binding_manifest_supersessions_v04
    BEGIN
        SELECT RAISE(ABORT, 'action binding supersession is immutable');
    END
    """,
    """
    CREATE TRIGGER action_binding_supersessions_v04_are_immutable_delete
    BEFORE DELETE ON action_binding_manifest_supersessions_v04
    BEGIN
        SELECT RAISE(ABORT, 'action binding supersession is immutable');
    END
    """,
    """
    CREATE TRIGGER work_orders_single_authority
    BEFORE INSERT ON work_orders
    WHEN EXISTS (SELECT 1 FROM work_orders)
    BEGIN
        SELECT RAISE(ABORT, 'the authoritative WorkOrder already exists');
    END
    """,
    """
    CREATE TRIGGER work_orders_are_immutable_update
    BEFORE UPDATE ON work_orders
    BEGIN
        SELECT RAISE(ABORT, 'the authoritative WorkOrder is immutable');
    END
    """,
    """
    CREATE TRIGGER work_orders_are_immutable_delete
    BEFORE DELETE ON work_orders
    BEGIN
        SELECT RAISE(ABORT, 'the authoritative WorkOrder is immutable');
    END
    """,
)


def _connect_ledger_direct(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(
        str(Path(path)),
        timeout=BUSY_TIMEOUT_MS / 1000,
        isolation_level=None,
    )
    try:
        connection.execute(f"PRAGMA busy_timeout = {BUSY_TIMEOUT_MS}")
        journal_mode = connection.execute(
            "PRAGMA journal_mode = WAL"
        ).fetchone()
        if journal_mode is None or str(journal_mode[0]).lower() != "wal":
            raise sqlite3.DatabaseError("SQLite WAL mode is unavailable")
        connection.execute("PRAGMA synchronous = FULL")
        connection.execute("PRAGMA foreign_keys = ON")
        foreign_keys = connection.execute("PRAGMA foreign_keys").fetchone()
        if foreign_keys is None or foreign_keys[0] != 1:
            raise sqlite3.DatabaseError("SQLite foreign keys are unavailable")
    except Exception:
        connection.close()
        raise
    return connection


def connect_ledger(path: Path) -> sqlite3.Connection:
    """Open one explicitly managed SQLite connection with frozen pragmas."""

    return _connect_ledger_direct(path)


def _canonical_json(value: object) -> str:
    return rfc8785.dumps(value).decode("utf-8")


def _create_schema(connection: sqlite3.Connection) -> None:
    for statement in _SCHEMA:
        connection.execute(statement)


def _best_effort_rollback(connection: sqlite3.Connection | None) -> Exception | None:
    if connection is None:
        return None
    try:
        in_transaction = connection.in_transaction
    except Exception as error:
        return error
    if not in_transaction:
        return None
    try:
        connection.execute("ROLLBACK")
    except Exception as error:
        return error
    return None


def _best_effort_close(connection: sqlite3.Connection | None) -> Exception | None:
    if connection is None:
        return None
    try:
        connection.close()
    except Exception as error:
        return error
    return None


def _close_with_retries(
    connection: sqlite3.Connection | None,
    *,
    attempts: int = 3,
) -> tuple[bool, tuple[Exception, ...]]:
    if connection is None:
        return True, ()
    errors: list[Exception] = []
    for _ in range(attempts):
        error = _best_effort_close(connection)
        if error is None:
            return True, tuple(errors)
        errors.append(error)
    return False, tuple(errors)


def _close_descriptors_once(
    descriptors: tuple[tuple[str, int | None], ...],
) -> tuple[Exception, ...]:
    errors: list[Exception] = []
    for label, descriptor in descriptors:
        if descriptor is None:
            continue
        try:
            os.close(descriptor)
        except OSError as error:
            errors.append(_contextualize_secondary(label, error))
    return tuple(errors)


def _cleanup_publication_resources(
    *,
    connection: sqlite3.Connection | None,
    descriptors: tuple[tuple[str, int | None], ...] = (),
    lock_descriptor: int | None,
) -> tuple[Exception, ...]:
    errors = list(_close_descriptors_once(descriptors))
    _, close_errors = _close_with_retries(connection)
    errors.extend(
        _contextualize_secondary("SQLite close", error)
        for error in close_errors
    )
    if lock_descriptor is not None:
        _, release_errors = _release_target_lock(lock_descriptor)
        errors.extend(
            _contextualize_secondary("target lock release", error)
            for error in release_errors
        )
    return tuple(errors)


def _error_cause(
    label: str,
    errors: tuple[Exception, ...] | list[Exception],
) -> Exception:
    if len(errors) == 1:
        return errors[0]
    # ExceptionGroup is Python 3.11+; fall back to RuntimeError on 3.10.
    try:
        return ExceptionGroup(label, list(errors))  # type: ignore[misc]
    except NameError:
        combined = "; ".join(str(e) for e in errors)
        return RuntimeError(f"{label}: {combined}")


def _contextualize_secondary(label: str, error: Exception) -> Exception:
    if isinstance(error, sqlite3.OperationalError):
        contextualized: Exception = sqlite3.OperationalError(
            f"{label} failed: {error}"
        )
    else:
        contextualized = RuntimeError(f"{label} failed: {error}")
    contextualized.__cause__ = error
    return contextualized


def _owned_sqlite_paths(database_path: Path) -> tuple[Path, ...]:
    return (
        database_path,
        Path(f"{database_path}-wal"),
        Path(f"{database_path}-shm"),
        Path(f"{database_path}-journal"),
    )


def _cleanup_owned_sqlite(
    database_path: Path | None,
) -> tuple[Exception, ...]:
    if database_path is None:
        return ()
    errors: list[Exception] = []
    for owned_path in _owned_sqlite_paths(database_path):
        for _ in range(2):
            try:
                owned_path.unlink(missing_ok=True)
                break
            except OSError as error:
                errors.append(error)
    return tuple(errors)


def _fsync_file(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _target_lock_path(ledger_path: Path) -> Path:
    return ledger_path.with_name(f".{ledger_path.name}.lock")


def _same_inode(left: os.stat_result, right: os.stat_result) -> bool:
    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


def _ledger_named_identity(path: Path) -> os.stat_result:
    metadata = os.stat(path, follow_symlinks=False)
    if not stat.S_ISREG(metadata.st_mode):
        raise OSError("receipt publication ledger is not a regular file")
    return metadata


def _require_named_ledger_identity(
    path: Path,
    expected: os.stat_result,
) -> None:
    current = _ledger_named_identity(path)
    if not _same_inode(expected, current):
        raise OSError(
            "receipt publication ledger name changed during validation"
        )


def _directory_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_DIRECTORY", 0)
    )


def _safe_evidence_parts(
    work_order: WorkOrder,
    final_path: str,
) -> tuple[str, ...]:
    prefix = f"{work_order.evidence_policy.evidence_root}/"
    if not final_path.startswith(prefix):
        raise ValueError("evidence path is outside the WorkOrder evidence root")
    relative = final_path[len(prefix) :]
    parts = tuple(relative.split("/"))
    if (
        not parts
        or any(part in {"", ".", ".."} for part in parts)
        or relative.startswith("/")
        or "\\" in relative
    ):
        raise ValueError("evidence path is not a safe relative path")
    return parts


def _open_stable_evidence_root(root: Path) -> tuple[int, os.stat_result]:
    descriptor = os.open(root, _directory_flags())
    try:
        metadata = os.fstat(descriptor)
        named = os.stat(root, follow_symlinks=False)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or not stat.S_ISDIR(named.st_mode)
            or not _same_inode(metadata, named)
        ):
            raise OSError("evidence root is not a stable directory")
        return descriptor, metadata
    except Exception:
        os.close(descriptor)
        raise


def _ensure_pending_directory(root_descriptor: int) -> int:
    created = False
    try:
        os.mkdir(".pending", 0o700, dir_fd=root_descriptor)
        created = True
    except FileExistsError:
        pass
    if created:
        os.fsync(root_descriptor)
    descriptor = os.open(
        ".pending",
        _directory_flags(),
        dir_fd=root_descriptor,
    )
    metadata = os.fstat(descriptor)
    if not stat.S_ISDIR(metadata.st_mode):
        os.close(descriptor)
        raise OSError("pending evidence namespace is not a directory")
    return descriptor


def _require_stable_pending_directory(
    root_descriptor: int,
    pending_descriptor: int,
    expected: os.stat_result,
) -> None:
    opened = os.fstat(pending_descriptor)
    named = os.stat(
        ".pending",
        dir_fd=root_descriptor,
        follow_symlinks=False,
    )
    if (
        not stat.S_ISDIR(opened.st_mode)
        or not stat.S_ISDIR(named.st_mode)
        or not _same_inode(expected, opened)
        or not _same_inode(expected, named)
    ):
        raise OSError("pending evidence namespace changed during validation")


def _require_final_absent(
    root_descriptor: int,
    parts: tuple[str, ...],
) -> None:
    descriptors: list[int] = []
    current = root_descriptor
    try:
        for part in parts[:-1]:
            try:
                current = os.open(
                    part,
                    _directory_flags(),
                    dir_fd=current,
                )
            except FileNotFoundError:
                return
            descriptors.append(current)
        try:
            os.stat(
                parts[-1],
                dir_fd=current,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            return
        raise FileExistsError("final evidence path already exists")
    finally:
        _close_evidence_descriptors(descriptors)


def _write_all(descriptor: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        written = os.write(descriptor, payload[offset:])
        if written <= 0:
            raise OSError("pending evidence write made no progress")
        offset += written


def _cleanup_owned_pending(
    pending_descriptor: int | None,
    owned: Mapping[str, tuple[int, int]],
) -> None:
    if pending_descriptor is None:
        return
    for name, identity in owned.items():
        pending_name = _validated_pending_basename(
            name,
            f".pending/{name}",
        )
        try:
            metadata = os.stat(
                pending_name,
                dir_fd=pending_descriptor,
                follow_symlinks=False,
            )
            if (
                stat.S_ISREG(metadata.st_mode)
                and (metadata.st_dev, metadata.st_ino) == identity
            ):
                os.unlink(pending_name, dir_fd=pending_descriptor)
        except FileNotFoundError:
            pass
    os.fsync(pending_descriptor)


def _validate_staged_payloads(
    receipt: ActionReceiptEnvelope,
    payloads: Mapping[str, bytes],
    work_order: WorkOrder,
) -> None:
    if (
        isinstance(receipt, RollbackReceipt)
        and not receipt.evidence_refs
        and not payloads
    ):
        return
    validator = getattr(receipt, "validate_evidence_payloads", None)
    if callable(validator):
        validator(payloads, work_order)
        return
    raise ValueError(
        "receipt type is not a closed evidence publication producer"
    )


def stage_pending_evidence_group(
    ledger_path: Path,
    *,
    evidence_root: Path,
    receipt: ActionReceiptEnvelope,
    payloads: Mapping[str, bytes],
    _borrowed_lock_descriptor: int | None = None,
) -> _PublicationGroup:
    """Durably stage one uncommitted receipt candidate's exact EvidenceRefs."""

    path = Path(ledger_path)
    root = Path(evidence_root)
    lock_descriptor: int | None = None
    owns_lock = False
    connection: sqlite3.Connection | None = None
    root_descriptor: int | None = None
    pending_descriptor: int | None = None
    owned: dict[str, tuple[int, int]] = {}
    try:
        exact_payloads = dict(payloads)
        lock_descriptor, owns_lock = _borrow_or_acquire_target_lock(
            path,
            _borrowed_lock_descriptor,
        )
        connection = connect_ledger(path)
        work_order = load_authoritative_work_order(connection)
        receipts = _validated_receipt_prefix(connection, work_order)
        try:
            validated_receipt = ACTION_RECEIPT_ADAPTER.validate_python(
                receipt.model_dump(mode="json")
            )
            validated_receipt.validate_against_work_order(work_order)
            _validate_receipt_nested_claim(validated_receipt, work_order)
            sidecar = next(
                binding
                for binding in work_order.key_bindings
                if binding.role == "Sidecar"
            )
            sidecar_key = decode_and_verify_key_binding(sidecar)
        except Exception as error:
            raise ValueError("receipt candidate is invalid") from error
        if (
            validated_receipt != receipt
            or not verify_payload(
                "action-receipt",
                receipt.model_dump(mode="json"),
                sidecar_key,
            )
            or connection.execute(
                """
                SELECT COUNT(*)
                FROM receipts
                WHERE receipt_id = ? OR nonce = ?
                """,
                (receipt.receipt_id, receipt.nonce),
            ).fetchone()
            != (0,)
        ):
            raise ValueError(
                "receipt candidate is not authentic, exact, or uncommitted"
            )
        if not 1 <= len(receipt.evidence_refs) <= _MAX_PUBLICATIONS_PER_GROUP:
            raise ValueError("publication group must contain 1..8 artifacts")
        _validate_staged_payloads(receipt, exact_payloads, work_order)

        root_descriptor, root_identity = _open_stable_evidence_root(root)
        pending_descriptor = _ensure_pending_directory(root_descriptor)
        pending_identity = os.fstat(pending_descriptor)
        publications: list[_Publication] = []
        for reference in receipt.evidence_refs:
            parts = _safe_evidence_parts(work_order, reference.path)
            _require_final_absent(root_descriptor, parts)
            publication_id = secrets.token_hex(32)
            pending_name = _validated_pending_basename(
                publication_id,
                f".pending/{publication_id}",
            )
            flags = (
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            descriptor = os.open(
                pending_name,
                flags,
                0o600,
                dir_fd=pending_descriptor,
            )
            try:
                opened = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(opened.st_mode)
                    or opened.st_nlink != 1
                    or opened.st_size != 0
                    or stat.S_IMODE(opened.st_mode) != 0o600
                ):
                    raise OSError(
                        "new pending evidence is not a regular single-link file"
                    )
                owned[pending_name] = (opened.st_dev, opened.st_ino)
                _write_all(descriptor, exact_payloads[reference.path])
                metadata = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_nlink != 1
                    or metadata.st_size != reference.size_bytes
                    or not _same_inode(opened, metadata)
                ):
                    raise OSError("pending evidence is not a stable regular file")
                os.fsync(descriptor)
                durable = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(durable.st_mode)
                    or durable.st_nlink != 1
                    or durable.st_size != reference.size_bytes
                    or stat.S_IMODE(durable.st_mode) != 0o600
                    or not _same_inode(opened, durable)
                ):
                    raise OSError(
                        "pending evidence is not a stable regular file after fsync"
                    )
            finally:
                os.close(descriptor)
            publications.append(
                _Publication(
                    publication_id=publication_id,
                    pending_path=f".pending/{pending_name}",
                    final_path=reference.path,
                    digest=reference.sha256,
                    size_bytes=reference.size_bytes,
                    media_type=reference.media_type,
                )
            )
        os.fsync(pending_descriptor)
        _require_stable_pending_directory(
            root_descriptor,
            pending_descriptor,
            pending_identity,
        )
        root_named = os.stat(root, follow_symlinks=False)
        root_after = os.fstat(root_descriptor)
        if (
            not _same_inode(root_identity, root_named)
            or not _same_inode(root_identity, root_after)
        ):
            raise OSError("evidence root changed while staging")
        for publication in publications:
            _require_final_absent(
                root_descriptor,
                _safe_evidence_parts(work_order, publication.final_path),
            )
        return _PublicationGroup(
            receipt_id=receipt.receipt_id,
            publications=tuple(publications),
        )
    except Exception as primary_error:
        secondary_errors: list[Exception] = []
        rollback_error = _best_effort_rollback(connection)
        if rollback_error is not None:
            secondary_errors.append(rollback_error)
        try:
            _cleanup_owned_pending(pending_descriptor, owned)
        except OSError as cleanup_error:
            secondary_errors.append(cleanup_error)
        if secondary_errors:
            raise RuntimeError(
                "pending evidence staging rollback failed"
            ) from _error_cause(
                "pending evidence staging failures",
                [primary_error, *secondary_errors],
            )
        raise
    finally:
        cleanup_errors = _cleanup_publication_resources(
            connection=connection,
            descriptors=(
                ("pending directory close", pending_descriptor),
                ("evidence root close", root_descriptor),
            ),
            lock_descriptor=lock_descriptor if owns_lock else None,
        )
        if cleanup_errors:
            raise RuntimeError(
                "pending evidence staging cleanup failed"
            ) from _error_cause(
                "pending evidence staging cleanup failures",
                list(cleanup_errors),
            )


def _replay_receipt_publication_ledger(
    connection: sqlite3.Connection,
):
    work_order = load_authoritative_work_order(connection)
    receipts = _validated_receipt_prefix(connection, work_order)
    grants = _validated_effective_grants(connection, work_order, receipts)
    attempts = _validated_grant_attempts(
        connection,
        work_order,
        receipts,
    )
    _validate_grant_reservation_closure(
        connection,
        work_order,
        grants,
        attempts,
    )
    _policy_history_replay(
        work_order,
        receipts,
        grants,
        attempts,
    )
    _validate_grant_event_index(connection, receipts, grants)
    groups = _journal_publication_groups(connection)
    _require_exact_publication_coverage(receipts, groups)
    return work_order, receipts, grants, groups


def _validate_new_receipt_publication(
    connection: sqlite3.Connection,
    *,
    receipt: ActionReceiptEnvelope,
    group: _PublicationGroup,
    now: datetime,
) -> tuple[WorkOrder, str, int]:
    work_order, receipts, _, groups = (
        _replay_receipt_publication_ledger(connection)
    )
    if any(state_value == "COMMITTING" for _, state_value in groups):
        raise ValueError(
            "an existing evidence publication requires recovery"
        )
    is_started_rollback = (
        type(receipt) is RollbackReceipt
        and receipt.policy_decision == "allow"
        and receipt.execution_status in {"succeeded", "failed"}
    )
    publication_count_valid = (
        1 <= len(group.publications) <= _MAX_PUBLICATIONS_PER_GROUP
    ) or (
        not group.publications
        and not receipt.evidence_refs
        and (
            (
                type(receipt) is ToolCallReceipt
                and receipt.policy_decision == "allow"
                and receipt.execution_status == "failed"
            )
            or is_started_rollback
            or (
                type(receipt) is ToolCallReceipt
                and receipt.tool_name == "owp.repo_read"
                and receipt.policy_decision == "allow"
                and receipt.execution_status == "succeeded"
            )
        )
    )
    if (
        type(receipt) not in {ToolCallReceipt, RollbackReceipt}
        or receipt.policy_decision != "allow"
        or type(group) is not _PublicationGroup
        or group.receipt_id != receipt.receipt_id
        or not publication_count_valid
        or any(type(item) is not _Publication for item in group.publications)
        or len(group.publications) != len(receipt.evidence_refs)
        or len(receipts) >= MAX_ROUTINE_ACTION_RECEIPTS
    ):
        raise ValueError(
            "receipt publication is outside the closed routine slice"
        )
    try:
        parsed = ACTION_RECEIPT_ADAPTER.validate_python(
            receipt.model_dump(mode="json")
        )
        parsed.validate_against_work_order(work_order)
        if isinstance(parsed, ToolCallReceipt):
            parsed.validate_predicates_against(work_order)
        _validate_receipt_nested_claim(parsed, work_order)
        sidecar = next(
            binding
            for binding in work_order.key_bindings
            if binding.role == "Sidecar"
        )
        sidecar_key = decode_and_verify_key_binding(sidecar)
    except Exception as error:
        raise ValueError(
            "receipt publication candidate is malformed"
        ) from error
    if (
        parsed != receipt
        or type(parsed) is not type(receipt)
        or receipt.work_order_digest != work_order.digest
        or not verify_payload(
            "action-receipt",
            receipt.model_dump(mode="json"),
            sidecar_key,
        )
        or any(
            item.receipt_id == receipt.receipt_id
            or item.nonce == receipt.nonce
            for item in receipts
        )
    ):
        raise ValueError(
            "receipt publication candidate is not exact or uncommitted"
        )
    tip = _tip_receipt(receipts)
    receipt_ids = {item.receipt_id for item in receipts}
    expected_sequence = len(receipts) + 1
    if (
        receipt.sequence != expected_sequence
        or receipt.previous_receipt_digest != tip.digest
        or receipt.state_before != tip.state_after
        or tip.receipt_id not in receipt.parent_receipt_ids
        or any(
            parent_id not in receipt_ids
            for parent_id in receipt.parent_receipt_ids
        )
        or receipt.occurred_at != now
        or not work_order.issued_at
        <= receipt.occurred_at
        <= work_order.deadline
        or receipt.occurred_at < tip.occurred_at
    ):
        raise ValueError(
            "receipt publication candidate does not extend the authority tip"
        )
    state_row = connection.execute(
        """
        SELECT current_state, version
        FROM work_order_state
        WHERE singleton = 1 AND work_order_digest = ?
        """,
        (work_order.digest,),
    ).fetchone()
    sequence_row = connection.execute(
        """
        SELECT next_sequence
        FROM sequence_counter
        WHERE singleton = 1
        """
    ).fetchone()
    if (
        state_row is None
        or state_row[0] != tip.state_after
        or sequence_row != (expected_sequence,)
    ):
        raise ValueError(
            "receipt publication state or sequence authority is stale"
        )
    try:
        state_before = TaskState(receipt.state_before)
        state_after = TaskState(receipt.state_after)
        public_keys = {
            binding.key_id: decode_and_verify_key_binding(binding)
            for binding in work_order.key_bindings
        }
        decision = None if isinstance(receipt, RollbackReceipt) else (
            append_receipt(
                work_order=work_order,
                state=state_before,
                receipt=receipt,
                public_keys=public_keys,
                now=now,
                allow_independent_verifier_rerun=True,
            )
            if state_before is state_after
            else apply_state_transition(
                work_order=work_order,
                state_before=state_before,
                state_after=state_after,
                trigger_receipt=receipt,
                acceptance_receipt=None,
                public_keys=public_keys,
                now=now,
            )
        )
    except Exception as error:
        raise ValueError(
            "receipt publication state validation failed"
        ) from error
    if decision is not None and not decision.allowed:
        raise ValueError(
            "receipt publication is denied by the frozen state machine"
        )
    return work_order, state_row[0], state_row[1]


def _validate_authoritative_receipt_predicates(
    connection: sqlite3.Connection,
    *,
    work_order: WorkOrder,
    receipt: ToolCallReceipt,
    payloads: Mapping[str, bytes],
    trusted_resolution_manifest: ResolutionManifest | None,
    resolution_manifest_bytes: bytes | None = None,
) -> None:
    replayed_work_order, receipts, grants, _ = (
        _replay_receipt_publication_ledger(connection)
    )
    if replayed_work_order != work_order or not receipts:
        raise ValueError("predicate authority replay is incomplete")
    tip = receipts[-1]
    grant = grants.get(receipt.grant_id)
    quota_states = _policy_quota_replay(
        work_order,
        receipts,
        grants,
    )
    quota_state = quota_states.get(receipt.grant_id)
    request = receipt.nested_claim
    if (
        grant is None
        or quota_state is None
        or quota_state.revoked
        or receipt.tool_name not in grant.allowed_tools
        or receipt.tool_name not in work_order.allowed_tools
        or receipt.actor_id != grant.subject_agent_id
        or receipt.actor_key_id != grant.subject_key_id
        or request.grant_id != grant.grant_id
    ):
        raise ValueError("predicate authority Grant is unavailable")
    arguments = receipt.request_arguments
    if isinstance(arguments, ApplyPatchArguments):
        if (
            receipt.execution_status in {"succeeded", "failed"}
            and type(trusted_resolution_manifest) is not ResolutionManifest
        ):
            raise ValueError(
                "trusted patch resolution manifest is unavailable or malformed"
            )
    elif trusted_resolution_manifest is not None:
        raise ValueError(
            "trusted resolution manifest is forbidden for this tool"
        )

    test_mode = (
        receipt.request_arguments.test_mode
        if isinstance(receipt.request_arguments, RunTestsArguments)
        else "developer"
    )
    selected = select_required_predicates(
        work_order=work_order,
        tool_name=receipt.tool_name,
        policy_decision=receipt.policy_decision,
        execution_status=receipt.execution_status,
        test_mode=test_mode,
    )
    supplied = {
        result.predicate_id: result
        for result in receipt.predicate_results
    }
    if tuple(supplied) != tuple(
        spec.predicate_id for spec in selected
    ):
        raise ValueError("predicate authority selection is not exact")

    authoritative: dict[str, object] = {}
    for spec in selected:
        result = supplied[spec.predicate_id]
        if spec.name == "tool_allowed":
            authoritative[spec.predicate_id] = {
                "actual_tool_name": receipt.tool_name,
            }
            continue
        if spec.name == "quota_remaining":
            charge = receipt.quota_charge
            if charge is None or charge.grant_id != grant.grant_id:
                raise ValueError("predicate quota authority is unavailable")
            remaining_before = (
                quota_state.remaining_tool_calls
                if charge.metric == "tool_calls"
                else quota_state.remaining_repair_rounds
            )
            if (
                charge.amount > remaining_before
                or charge.remaining_after
                != remaining_before - charge.amount
            ):
                raise ValueError("predicate quota authority is inconsistent")
            authoritative[spec.predicate_id] = {
                "grant_id": grant.grant_id,
                "metric": charge.metric,
                "amount": charge.amount,
                "grant_remaining_before": remaining_before,
                "ledger_prefix_digest": tip.digest,
            }
            continue
        if spec.name == "path_allowed":
            if isinstance(arguments, RepoReadArguments):
                if receipt.execution_status != "succeeded":
                    raise ValueError(
                        "predicate path authority is unavailable for this tool"
                    )
                requested_paths = (arguments.path,)
                grant_roots = grant.allowed_read_roots
                work_order_roots = work_order.allowed_read_roots
                path_input = supplied[spec.predicate_id].input
                if (
                    not all(
                        any(_root_contains(root, path) for root in grant_roots)
                        and any(
                            _root_contains(root, path)
                            for root in work_order_roots
                        )
                        for path in requested_paths
                    )
                    or path_input.resolution_manifest_digest is None
                ):
                    raise ValueError(
                        "predicate path authority is unavailable for this tool"
                    )
                authoritative[spec.predicate_id] = {
                    "requested_paths": list(requested_paths),
                    "resolved_entries": [
                        entry.model_dump(mode="json")
                        for entry in path_input.resolved_entries
                    ],
                    "resolution_manifest_digest": (
                        path_input.resolution_manifest_digest
                    ),
                }
                continue
            if (
                not isinstance(arguments, ApplyPatchArguments)
                or receipt.execution_status not in {"succeeded", "failed"}
                or trusted_resolution_manifest is None
            ):
                raise ValueError(
                    "predicate path authority is unavailable for this tool"
                )
            requested_paths = arguments.target_paths
            grant_roots = grant.allowed_write_roots
            work_order_roots = work_order.allowed_write_roots
            if not all(
                any(_root_contains(root, path) for root in grant_roots)
                and any(
                    _root_contains(root, path)
                    for root in work_order_roots
                )
                for path in requested_paths
            ):
                raise ValueError(
                    "predicate requested path is outside active authority"
                )
            manifest = trusted_resolution_manifest
            if resolution_manifest_bytes is not None:
                from openworkproof.repo_tools import (  # noqa: PLC0415
                    validate_resolution_manifest_bytes,
                )

                try:
                    validate_resolution_manifest_bytes(
                        manifest,
                        resolution_manifest_bytes,
                    )
                except Exception as error:
                    raise ValueError(
                        "resolution manifest bytes failed independent rehash"
                    ) from error
            resolved_entries = manifest.resolved_entries
            if (
                manifest.requested_paths != tuple(requested_paths)
                or len(resolved_entries) != len(requested_paths)
                or any(
                    not isinstance(entry, ResolutionManifestEntry)
                    or entry.requested_path != path
                    or entry.resolved_relative_path is None
                    for path, entry in zip(
                        requested_paths,
                        resolved_entries,
                        strict=True,
                    )
                )
            ):
                raise ValueError(
                    "trusted patch resolution vectors are inconsistent"
                )
            manifest_digest = resolution_manifest_digest(manifest)
            if receipt.execution_status == "succeeded":
                result_refs = tuple(
                    reference
                    for reference in receipt.evidence_refs
                    if reference.media_type == "application/json"
                )
                if len(result_refs) != 1:
                    raise ValueError(
                        "predicate path result evidence is unavailable"
                    )
                payload = payloads.get(result_refs[0].path)
                if payload is None:
                    raise ValueError(
                        "predicate path result payload is unavailable"
                    )
                patch_result = PatchResultEvidence.model_validate(
                    _load_canonical_json(payload)
                )
                if (
                    manifest.workspace_manifest_digest
                    != patch_result.parent_manifest_digest
                ):
                    raise ValueError(
                        "trusted resolution manifest is not bound "
                        "to the patch parent"
                    )
            authoritative[spec.predicate_id] = {
                "requested_paths": list(requested_paths),
                "resolved_entries": [
                    {
                        "requested_path": entry.requested_path,
                        "resolved_relative_path": entry.resolved_relative_path,
                    }
                    for entry in resolved_entries
                ],
                "resolution_manifest_digest": manifest_digest,
            }
            continue
        if spec.name == "tests_passed":
            arguments = receipt.request_arguments
            if (
                not isinstance(arguments, RunTestsArguments)
                or arguments.test_mode != "verifier"
            ):
                raise ValueError(
                    "predicate test authority is unavailable for this tool"
                )
            profile = next(
                (
                    candidate
                    for candidate in work_order.test_profiles
                    if candidate.test_mode == "verifier"
                ),
                None,
            )
            if receipt.execution_status == "failed":
                if receipt.evidence_refs or profile is None:
                    raise ValueError(
                        "failed test predicate authority is inconsistent"
                    )
                authoritative[spec.predicate_id] = {
                    "test_mode": "verifier",
                    "command_digest": arguments.command_digest,
                    "expected_exit_code": profile.expected_exit_code,
                    "actual_exit_code": None,
                    "test_evidence_digest": None,
                    "source_commit": arguments.source_commit,
                    "candidate_commit": arguments.candidate_commit,
                    "workspace_manifest_digest": (
                        arguments.workspace_manifest_digest
                    ),
                    "container_image_digest": (
                        arguments.container_image_digest
                    ),
                    "fixed_test_source_digest": (
                        arguments.fixed_test_source_digest
                    ),
                }
                continue
            if len(receipt.evidence_refs) != 1:
                raise ValueError(
                    "predicate test authority is unavailable for this tool"
                )
            reference = receipt.evidence_refs[0]
            payload = payloads.get(reference.path)
            if payload is None:
                raise ValueError("predicate test evidence is unavailable")
            test_result = TestResultEvidence.model_validate(
                _load_canonical_json(payload)
            )
            if (
                profile is None
                or test_result.test_mode != "verifier"
                or test_result.command_digest != arguments.command_digest
                or test_result.source_commit != arguments.source_commit
                or test_result.candidate_commit
                != arguments.candidate_commit
                or test_result.workspace_manifest_digest
                != arguments.workspace_manifest_digest
                or test_result.container_image_digest
                != arguments.container_image_digest
                or test_result.fixed_test_source_digest
                != arguments.fixed_test_source_digest
            ):
                raise ValueError("predicate test evidence is inconsistent")
            authoritative[spec.predicate_id] = {
                "test_mode": "verifier",
                "command_digest": profile.command_digest,
                "expected_exit_code": profile.expected_exit_code,
                "actual_exit_code": test_result.actual_exit_code,
                "test_evidence_digest": hashlib.sha256(payload).hexdigest(),
                "source_commit": test_result.source_commit,
                "candidate_commit": test_result.candidate_commit,
                "workspace_manifest_digest": (
                    test_result.workspace_manifest_digest
                ),
                "container_image_digest": (
                    test_result.container_image_digest
                ),
                "fixed_test_source_digest": (
                    test_result.fixed_test_source_digest
                ),
            }
            continue
        raise ValueError(
            "predicate authority is unavailable for this predicate"
        )

    context = EvaluationContext(
        inputs={
            result.predicate_id: result.input
            for result in receipt.predicate_results
        },
        authoritative_inputs=authoritative,
        authoritative_ledger_prefix_digests={
            grant.grant_id: tip.digest,
        },
    )
    evaluated = evaluate_required_predicates(selected, context)
    if evaluated != receipt.predicate_results:
        raise ValueError(
            "signed predicate results do not match authoritative replay"
        )


def _open_pending_receipt_publications(
    *,
    evidence_root: Path,
    work_order: WorkOrder,
    receipt: ToolCallReceipt | RollbackReceipt,
    group: _PublicationGroup,
):
    publications = tuple(group.publications)
    references = tuple(receipt.evidence_refs)
    if (
        tuple(item.final_path for item in publications)
        != tuple(item.path for item in references)
        or len({item.publication_id for item in publications})
        != len(publications)
        or len({item.pending_path for item in publications})
        != len(publications)
        or len({item.final_path for item in publications})
        != len(publications)
    ):
        raise ValueError(
            "publication descriptor does not exactly match EvidenceRef order"
        )
    root_descriptor, root_identity = _open_stable_evidence_root(
        evidence_root
    )
    pending_descriptor: int | None = None
    files: list[tuple[str, int]] = []
    pending_anchors: list[tuple[str, os.stat_result]] = []
    try:
        pending_descriptor = os.open(
            ".pending",
            _directory_flags(),
            dir_fd=root_descriptor,
        )
        pending_identity = os.fstat(pending_descriptor)
        payloads: dict[str, bytes] = {}
        for publication, reference in zip(
            publications,
            references,
            strict=True,
        ):
            name = _validated_pending_basename(
                publication.publication_id,
                publication.pending_path,
            )
            if (
                publication.final_path != reference.path
                or publication.digest != reference.sha256
                or publication.size_bytes != reference.size_bytes
                or publication.media_type != reference.media_type
            ):
                raise ValueError(
                    "publication descriptor disagrees with its EvidenceRef"
                )
            _require_final_absent(
                root_descriptor,
                _safe_evidence_parts(
                    work_order,
                    publication.final_path,
                ),
            )
            descriptor = os.open(
                name,
                (
                    os.O_RDONLY
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0)
                ),
                dir_fd=pending_descriptor,
            )
            files.append(
                (
                    f"pending evidence {publication.publication_id} close",
                    descriptor,
                )
            )
            payload, metadata = _read_exact_descriptor(
                descriptor,
                digest=publication.digest,
                size_bytes=publication.size_bytes,
                allowed_links=(1,),
            )
            named_metadata = os.stat(
                name,
                dir_fd=pending_descriptor,
                follow_symlinks=False,
            )
            if (
                not stat.S_ISREG(named_metadata.st_mode)
                or not _same_inode(metadata, named_metadata)
                or stat.S_IMODE(metadata.st_mode) != 0o600
            ):
                raise OSError("pending evidence mode is not 0600")
            pending_anchors.append((name, metadata))
            payloads[publication.final_path] = payload
        _validate_staged_payloads(receipt, payloads, work_order)
        _require_stable_pending_directory(
            root_descriptor,
            pending_descriptor,
            pending_identity,
        )
        if (
            not _same_inode(
                root_identity,
                os.stat(evidence_root, follow_symlinks=False),
            )
            or not _same_inode(
                root_identity,
                os.fstat(root_descriptor),
            )
        ):
            raise OSError(
                "evidence root changed while validating pending evidence"
            )
        return (
            root_descriptor,
            root_identity,
            pending_descriptor,
            pending_identity,
            tuple(files),
            tuple(pending_anchors),
            payloads,
        )
    except Exception as primary_error:
        cleanup_errors = list(
            _close_descriptors_once(tuple(files))
        )
        cleanup_errors.extend(
            _close_descriptors_once(
                (
                    ("pending directory close", pending_descriptor),
                    ("evidence root close", root_descriptor),
                )
            )
        )
        if cleanup_errors:
            raise RuntimeError(
                "pending receipt publication cleanup failed"
            ) from _error_cause(
                "pending receipt publication failures",
                [primary_error, *cleanup_errors],
            )
        raise


def _recheck_pending_receipt_publications(
    *,
    evidence_root: Path,
    root_descriptor: int,
    root_identity: os.stat_result,
    pending_descriptor: int,
    pending_identity: os.stat_result,
    pending_files: tuple[tuple[str, int], ...],
    pending_anchors: tuple[tuple[str, os.stat_result], ...],
    work_order: WorkOrder,
    receipt: ToolCallReceipt | RollbackReceipt,
    group: _PublicationGroup,
    payloads: Mapping[str, bytes],
) -> None:
    _require_stable_pending_directory(
        root_descriptor,
        pending_descriptor,
        pending_identity,
    )
    if (
        not _same_inode(
            root_identity,
            os.stat(evidence_root, follow_symlinks=False),
        )
        or not _same_inode(root_identity, os.fstat(root_descriptor))
    ):
        raise OSError(
            "evidence root changed during receipt publication"
        )
    for (_, descriptor), (name, expected), publication in zip(
        pending_files,
        pending_anchors,
        group.publications,
        strict=True,
    ):
        payload, metadata = _read_exact_descriptor(
            descriptor,
            digest=publication.digest,
            size_bytes=publication.size_bytes,
            allowed_links=(1,),
        )
        named_metadata = os.stat(
            name,
            dir_fd=pending_descriptor,
            follow_symlinks=False,
        )
        if (
            name
            != _validated_pending_basename(
                publication.publication_id,
                publication.pending_path,
            )
            or not stat.S_ISREG(named_metadata.st_mode)
            or not _same_inode(expected, metadata)
            or not _same_inode(expected, named_metadata)
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or payload != payloads[publication.final_path]
        ):
            raise OSError(
                "pending evidence changed during receipt publication"
            )
        _require_final_absent(
            root_descriptor,
            _safe_evidence_parts(
                work_order,
                publication.final_path,
            ),
        )
    _validate_staged_payloads(receipt, dict(payloads), work_order)


def _insert_receipt_and_publication_group(
    connection: sqlite3.Connection,
    *,
    work_order: WorkOrder,
    receipt: ToolCallReceipt | RollbackReceipt,
    group: _PublicationGroup,
    current_state: str,
    current_version: int,
) -> None:
    connection.execute(
        """
        INSERT INTO receipts (
            receipt_id, work_order_digest, nonce, sequence,
            previous_digest, receipt_json
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            receipt.receipt_id,
            work_order.digest,
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
                child_receipt_id, parent_receipt_id
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
                event_id, receipt_id, grant_id, event_type, metric, amount
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                hashlib.sha256(
                    f"grant-event:{receipt.receipt_id}".encode("ascii")
                ).hexdigest(),
                receipt.receipt_id,
                charge.grant_id,
                receipt.event_type,
                charge.metric,
                charge.amount,
            ),
        )
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
    state_update = connection.execute(
        """
        UPDATE work_order_state
        SET current_state = ?, version = version + 1
        WHERE singleton = 1
          AND work_order_digest = ?
          AND current_state = ?
          AND version = ?
        """,
        (
            receipt.state_after,
            work_order.digest,
            current_state,
            current_version,
        ),
    )
    sequence_update = connection.execute(
        """
        UPDATE sequence_counter
        SET next_sequence = next_sequence + 1
        WHERE singleton = 1 AND next_sequence = ?
        """,
        (receipt.sequence,),
    )
    if state_update.rowcount != 1 or sequence_update.rowcount != 1:
        raise ValueError(
            "receipt publication counters could not be advanced"
        )


def _confirm_receipt_publication_commit(
    ledger_path: Path,
    *,
    ledger_identity: os.stat_result,
    receipt: ToolCallReceipt,
    group: _PublicationGroup,
) -> tuple[str, Exception | None]:
    connection: sqlite3.Connection | None = None
    status = "INDETERMINATE"
    read_error: Exception | None = None
    try:
        _require_named_ledger_identity(
            ledger_path,
            ledger_identity,
        )
        connection = _connect_ledger_direct(ledger_path)
        _require_named_ledger_identity(
            ledger_path,
            ledger_identity,
        )
        connection.execute("BEGIN")
        _require_named_ledger_identity(
            ledger_path,
            ledger_identity,
        )
        _, receipts, _, groups = _replay_receipt_publication_ledger(
            connection
        )
        _require_named_ledger_identity(
            ledger_path,
            ledger_identity,
        )
        matches = tuple(
            item
            for item in receipts
            if item.receipt_id == receipt.receipt_id
            or item.nonce == receipt.nonce
        )
        publication_ids = {
            item.publication_id for item in group.publications
        }
        group_matches = tuple(
            (candidate, state_value)
            for candidate, state_value in groups
            if candidate.receipt_id == receipt.receipt_id
            or any(
                item.publication_id in publication_ids
                for item in candidate.publications
            )
        )
        expected_group_matches = (
            ((group, "COMMITTING"),)
            if group.publications
            else ()
        )
        if matches == (receipt,) and group_matches == expected_group_matches:
            status = "COMMITTED"
        elif not matches and not group_matches:
            status = "NOT_COMMITTED"
        else:
            raise ValueError(
                "receipt publication confirmation found a partial commit"
            )
    except Exception as error:
        read_error = error
    rollback_error = _best_effort_rollback(connection)
    closed, close_errors = _close_with_retries(connection)
    if (
        read_error is not None
        or rollback_error is not None
        or not closed
        or close_errors
    ):
        errors = (
            ([] if read_error is None else [read_error])
            + ([] if rollback_error is None else [rollback_error])
            + list(close_errors)
        )
        return (
            "INDETERMINATE",
            _error_cause(
                "receipt publication confirmation failures",
                errors,
            ),
        )
    return status, None


def _validate_authoritative_rollback_result(
    connection: sqlite3.Connection,
    *,
    work_order: WorkOrder,
    receipt: RollbackReceipt,
    evidence_root: Path,
    current_state: str,
) -> None:
    replayed_work_order, receipts, grants, _ = (
        _replay_receipt_publication_ledger(connection)
    )
    if replayed_work_order != work_order:
        raise ValueError("rollback authority replay is incomplete")
    try:
        episode = _validated_retry_episode(
            connection,
            work_order=work_order,
            receipts=(*receipts, receipt),
            grants=grants,
            evidence_root=evidence_root,
            current_state=current_state,
            rollback_candidate=receipt,
        )
    except RetryConsumptionError as error:
        raise ValueError(
            "rollback result does not match the authoritative rework episode"
        ) from error
    if episode.rollback != receipt:
        raise ValueError("rollback result is not the prospective episode rollback")


def commit_receipt_with_publications(
    ledger_path: Path,
    *,
    evidence_root: Path,
    receipt: ActionReceiptEnvelope,
    group: _PublicationGroup,
    clock: Callable[[], datetime],
    trusted_resolution_manifest: ResolutionManifest | None = None,
    _borrowed_lock_descriptor: int | None = None,
) -> None:
    """Commit one signed routine receipt and its publication group."""

    path = Path(ledger_path)
    root = Path(evidence_root)
    if not path.is_file():
        raise ValueError("receipt publication ledger is unavailable")
    lock_descriptor: int | None = None
    owns_lock = False
    ledger_identity: os.stat_result | None = None
    connection: sqlite3.Connection | None = None
    root_descriptor: int | None = None
    root_identity: os.stat_result | None = None
    pending_descriptor: int | None = None
    pending_identity: os.stat_result | None = None
    pending_files: tuple[tuple[str, int], ...] = ()
    pending_anchors: tuple[tuple[str, os.stat_result], ...] = ()
    work_order: WorkOrder | None = None
    payloads: Mapping[str, bytes] = {}
    primary_error: Exception | None = None
    commit_attempted = False
    committed = False
    authority_indeterminate = False
    try:
        lock_descriptor, owns_lock = _borrow_or_acquire_target_lock(
            path,
            _borrowed_lock_descriptor,
        )
        ledger_identity = _ledger_named_identity(path)
        connection = connect_ledger(path)
        _require_named_ledger_identity(path, ledger_identity)
        connection.execute("BEGIN IMMEDIATE")
        _require_named_ledger_identity(path, ledger_identity)
        try:
            now = _freeze_trusted_utc_second(clock())
        except Exception as error:
            raise ValueError(
                "receipt publication trusted clock is invalid"
            ) from error
        work_order, current_state, current_version = (
            _validate_new_receipt_publication(
                connection,
                receipt=receipt,
                group=group,
                now=now,
            )
        )
        (
            root_descriptor,
            root_identity,
            pending_descriptor,
            pending_identity,
            pending_files,
            pending_anchors,
            payloads,
        ) = _open_pending_receipt_publications(
            evidence_root=root,
            work_order=work_order,
            receipt=receipt,
            group=group,
        )
        if type(receipt) is ToolCallReceipt:
            _validate_authoritative_receipt_predicates(
                connection,
                work_order=work_order,
                receipt=receipt,
                payloads=payloads,
                trusted_resolution_manifest=trusted_resolution_manifest,
            )
        else:
            assert type(receipt) is RollbackReceipt
            if trusted_resolution_manifest is not None:
                raise ValueError(
                    "trusted resolution manifest is forbidden for rollback"
                )
            _validate_authoritative_rollback_result(
                connection,
                work_order=work_order,
                receipt=receipt,
                evidence_root=root,
                current_state=current_state,
            )
        _insert_receipt_and_publication_group(
            connection,
            work_order=work_order,
            receipt=receipt,
            group=group,
            current_state=current_state,
            current_version=current_version,
        )
        prospective_work_order, receipts, _, groups = (
            _replay_receipt_publication_ledger(connection)
        )
        candidate_groups = tuple(
            candidate
            for candidate, state_value in groups
            if candidate.receipt_id == receipt.receipt_id
            and state_value == "COMMITTING"
        )
        expected_candidate_groups = (
            (group,) if group.publications else ()
        )
        if (
            prospective_work_order != work_order
            or receipts[-1] != receipt
            or candidate_groups != expected_candidate_groups
        ):
            raise ValueError(
                "prospective receipt publication replay is incomplete"
            )
        _recheck_pending_receipt_publications(
            evidence_root=root,
            root_descriptor=root_descriptor,
            root_identity=root_identity,
            pending_descriptor=pending_descriptor,
            pending_identity=pending_identity,
            pending_files=pending_files,
            pending_anchors=pending_anchors,
            work_order=work_order,
            receipt=receipt,
            group=group,
            payloads=payloads,
        )
        _require_named_ledger_identity(path, ledger_identity)
        commit_attempted = True
        connection.execute("COMMIT")
        committed = True
        _require_named_ledger_identity(path, ledger_identity)
        _recheck_pending_receipt_publications(
            evidence_root=root,
            root_descriptor=root_descriptor,
            root_identity=root_identity,
            pending_descriptor=pending_descriptor,
            pending_identity=pending_identity,
            pending_files=pending_files,
            pending_anchors=pending_anchors,
            work_order=work_order,
            receipt=receipt,
            group=group,
            payloads=payloads,
        )
    except Exception as error:
        primary_error = error
        rollback_error = _best_effort_rollback(connection)
        if rollback_error is not None:
            primary_error = RuntimeError(
                "receipt publication rollback failed"
            )
            primary_error.__cause__ = _error_cause(
                "receipt publication rollback failures",
                [error, rollback_error],
            )

    cleanup_errors: list[Exception] = []
    _, sqlite_close_errors = _close_with_retries(connection)
    cleanup_errors.extend(
        _contextualize_secondary("SQLite close", error)
        for error in sqlite_close_errors
    )
    if commit_attempted and ledger_identity is not None:
        authority_status, authority_error = (
            _confirm_receipt_publication_commit(
                path,
                ledger_identity=ledger_identity,
                receipt=receipt,
                group=group,
            )
        )
        if authority_status == "INDETERMINATE" or (
            committed and authority_status != "COMMITTED"
        ):
            authority_indeterminate = True
            cleanup_errors.append(
                authority_error
                if authority_error is not None
                else RuntimeError(
                    "named ledger did not confirm the main connection commit"
                )
            )
    if (
        commit_attempted
        and ledger_identity is not None
        and work_order is not None
        and root_descriptor is not None
        and root_identity is not None
        and pending_descriptor is not None
        and pending_identity is not None
    ):
        try:
            _require_named_ledger_identity(path, ledger_identity)
            _recheck_pending_receipt_publications(
                evidence_root=root,
                root_descriptor=root_descriptor,
                root_identity=root_identity,
                pending_descriptor=pending_descriptor,
                pending_identity=pending_identity,
                pending_files=pending_files,
                pending_anchors=pending_anchors,
                work_order=work_order,
                receipt=receipt,
                group=group,
                payloads=payloads,
            )
        except Exception as error:
            cleanup_errors.append(
                _contextualize_secondary(
                    "final receipt publication gate",
                    error,
                )
            )
    cleanup_errors.extend(
        _close_descriptors_once(
            (
                *pending_files,
                ("pending directory close", pending_descriptor),
                ("evidence root close", root_descriptor),
            )
        )
    )
    release_errors = ()
    if owns_lock:
        _, release_errors = _release_target_lock(lock_descriptor)
    cleanup_errors.extend(
        _contextualize_secondary("target lock release", error)
        for error in release_errors
    )
    if (
        primary_error is None
        and not cleanup_errors
        and not authority_indeterminate
    ):
        return
    errors = (
        ([] if primary_error is None else [primary_error])
        + list(cleanup_errors)
    )
    if commit_attempted or committed:
        if authority_indeterminate:
            raise ReceiptPublicationCommitIndeterminateError(
                receipt,
                group,
            ) from _error_cause(
                "receipt publication authority is indeterminate",
                errors,
            )
        if ledger_identity is None:
            raise ReceiptPublicationCommitIndeterminateError(
                receipt,
                group,
            ) from _error_cause(
                "receipt publication identity is unavailable",
                errors,
            )
        status, confirmation_error = (
            _confirm_receipt_publication_commit(
                path,
                ledger_identity=ledger_identity,
                receipt=receipt,
                group=group,
            )
        )
        if status == "COMMITTED":
            raise ReceiptPublicationCommittedError(
                receipt,
                group,
            ) from _error_cause(
                "receipt publication committed completion failures",
                errors,
            )
        if status == "INDETERMINATE":
            if confirmation_error is not None:
                errors.append(confirmation_error)
            raise ReceiptPublicationCommitIndeterminateError(
                receipt,
                group,
            ) from _error_cause(
                "receipt publication indeterminate completion failures",
                errors,
            )
    if primary_error is not None and not cleanup_errors:
        raise primary_error
    raise RuntimeError(
        "receipt publication failed during cleanup"
    ) from _error_cause(
        "receipt publication failures",
        errors,
    )


def _validated_publication_group(
    connection: sqlite3.Connection,
    group: _PublicationGroup,
    *,
    required_state: str,
) -> tuple[WorkOrder, ActionReceiptEnvelope]:
    if (
        type(group) is not _PublicationGroup
        or not 1 <= len(group.publications) <= _MAX_PUBLICATIONS_PER_GROUP
        or any(type(item) is not _Publication for item in group.publications)
    ):
        raise ValueError("publication group descriptor is invalid")
    work_order = load_authoritative_work_order(connection)
    receipts = _validated_receipt_prefix(connection, work_order)
    matches = tuple(
        receipt for receipt in receipts if receipt.receipt_id == group.receipt_id
    )
    if len(matches) != 1:
        raise ValueError("publication receipt is not authoritative")
    receipt = matches[0]
    references = {reference.path: reference for reference in receipt.evidence_refs}
    rows = connection.execute(
        """
        SELECT publication_id, pending_path, final_path, digest,
               size_bytes, media_type, state
        FROM evidence_publications
        WHERE receipt_id = ?
        ORDER BY final_path
        LIMIT ?
        """,
        (group.receipt_id, _MAX_PUBLICATIONS_PER_GROUP + 1),
    ).fetchall()
    by_final = {item.final_path: item for item in group.publications}
    if (
        len(rows) != len(group.publications)
        or len(rows) != len(receipt.evidence_refs)
        or len(by_final) != len(group.publications)
        or set(by_final) != set(references)
    ):
        raise ValueError("publication group does not exactly match receipt refs")
    for row in rows:
        (
            publication_id,
            pending_path,
            final_path,
            digest,
            size_bytes,
            media_type,
            publication_state,
        ) = row
        _validated_pending_basename(
            publication_id,
            pending_path,
        )
        item = by_final.get(final_path)
        reference = references.get(final_path)
        if (
            item is None
            or reference is None
            or publication_state != required_state
            or pending_path != f".pending/{publication_id}"
            or item
            != _Publication(
                publication_id=publication_id,
                pending_path=pending_path,
                final_path=final_path,
                digest=digest,
                size_bytes=size_bytes,
                media_type=media_type,
            )
            or (
                digest,
                size_bytes,
                media_type,
            )
            != (
                reference.sha256,
                reference.size_bytes,
                reference.media_type,
            )
        ):
            raise ValueError(
                "publication journal row does not match its EvidenceRef"
            )
    return work_order, receipt


def _read_exact_descriptor(
    descriptor: int,
    *,
    digest: str,
    size_bytes: int,
    allowed_links: tuple[int, ...],
) -> tuple[bytes, os.stat_result]:
    before = os.fstat(descriptor)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink not in allowed_links
        or before.st_size != size_bytes
    ):
        raise OSError("evidence is not a stable regular file")
    payload = os.pread(descriptor, size_bytes + 1, 0)
    after = os.fstat(descriptor)
    if (
        len(payload) != size_bytes
        or (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_nlink,
            before.st_size,
        )
        != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_nlink,
            after.st_size,
        )
        or hashlib.sha256(payload).hexdigest() != digest
    ):
        raise OSError("evidence bytes are unavailable, unstable, or mismatched")
    return payload, after


def _validated_pending_basename(
    publication_id: str,
    pending_path: str,
) -> str:
    if (
        type(publication_id) is not str
        or len(publication_id) != 64
        or any(
            character not in "0123456789abcdef"
            for character in publication_id
        )
        or pending_path != f".pending/{publication_id}"
    ):
        raise ValueError("pending publication basename is invalid")
    return publication_id


def _open_final_parent(
    root_descriptor: int,
    parts: tuple[str, ...],
    *,
    create: bool,
) -> tuple[int, list[int]]:
    descriptors: list[int] = []
    current = root_descriptor
    try:
        for part in parts[:-1]:
            try:
                child = os.open(
                    part,
                    _directory_flags(),
                    dir_fd=current,
                )
            except FileNotFoundError:
                if not create:
                    raise
                os.mkdir(part, 0o700, dir_fd=current)
                os.fsync(current)
                child = os.open(
                    part,
                    _directory_flags(),
                    dir_fd=current,
                )
            descriptors.append(child)
            current = child
        return current, descriptors
    except Exception:
        _close_evidence_descriptors(descriptors)
        raise


def _directory_identity(metadata: os.stat_result) -> tuple[int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IFMT(metadata.st_mode),
    )


def _open_final_parent_anchored(
    root_descriptor: int,
    parts: tuple[str, ...],
    *,
    create: bool = True,
) -> tuple[int, list[int], tuple[tuple[int, int, int], ...]]:
    descriptors: list[int] = []
    identities = [_directory_identity(os.fstat(root_descriptor))]
    current = root_descriptor
    try:
        for part in parts[:-1]:
            try:
                child = os.open(
                    part,
                    _directory_flags(),
                    dir_fd=current,
                )
            except FileNotFoundError:
                if not create:
                    raise
                os.mkdir(part, 0o700, dir_fd=current)
                os.fsync(current)
                child = os.open(
                    part,
                    _directory_flags(),
                    dir_fd=current,
                )
            descriptors.append(child)
            current = child
            identities.append(_directory_identity(os.fstat(child)))
        return current, descriptors, tuple(identities)
    except Exception:
        _close_evidence_descriptors(descriptors)
        raise


def _require_stable_final_parent_chain(
    root_descriptor: int,
    parts: tuple[str, ...],
    expected: tuple[tuple[int, int, int], ...],
) -> None:
    descriptors: list[int] = []
    identities = [_directory_identity(os.fstat(root_descriptor))]
    current = root_descriptor
    try:
        for part in parts[:-1]:
            current = os.open(
                part,
                _directory_flags(),
                dir_fd=current,
            )
            descriptors.append(current)
            identities.append(_directory_identity(os.fstat(current)))
        if tuple(identities) != expected:
            raise OSError("final evidence parent namespace changed")
    finally:
        _close_evidence_descriptors(descriptors)


def _fsync_existing_final_parent(
    root_descriptor: int,
    work_order: WorkOrder,
    publication: _Publication,
) -> None:
    parts = _safe_evidence_parts(work_order, publication.final_path)
    parent_descriptors: list[int] = []
    try:
        parent, parent_descriptors, parent_identities = (
            _open_final_parent_anchored(
                root_descriptor,
                parts,
                create=False,
            )
        )
        os.fsync(parent)
        _require_stable_final_parent_chain(
            root_descriptor,
            parts,
            parent_identities,
        )
    finally:
        _close_evidence_descriptors(parent_descriptors)


def _publish_one_no_replace(
    *,
    root_descriptor: int,
    pending_descriptor: int,
    work_order: WorkOrder,
    publication: _Publication,
) -> None:
    pending_name = _validated_pending_basename(
        publication.publication_id,
        publication.pending_path,
    )
    pending_fd = os.open(
        pending_name,
        (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        ),
        dir_fd=pending_descriptor,
    )
    parent_descriptors: list[int] = []
    try:
        _, pending_metadata = _read_exact_descriptor(
            pending_fd,
            digest=publication.digest,
            size_bytes=publication.size_bytes,
            allowed_links=(1,),
        )
        parts = _safe_evidence_parts(work_order, publication.final_path)
        parent, parent_descriptors, parent_identities = (
            _open_final_parent_anchored(
                root_descriptor,
                parts,
            )
        )
        created_final = False
        try:
            os.link(
                pending_name,
                parts[-1],
                src_dir_fd=pending_descriptor,
                dst_dir_fd=parent,
                follow_symlinks=False,
            )
            created_final = True
        except FileExistsError:
            final_fd = os.open(
                parts[-1],
                (
                    os.O_RDONLY
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0)
                ),
                dir_fd=parent,
            )
            try:
                final_metadata = os.fstat(final_fd)
            finally:
                os.close(final_fd)
            if not _same_inode(pending_metadata, final_metadata):
                raise
        linked_pending = os.stat(
            pending_name,
            dir_fd=pending_descriptor,
            follow_symlinks=False,
        )
        linked_final = os.stat(
            parts[-1],
            dir_fd=parent,
            follow_symlinks=False,
        )
        if (
            not _same_inode(linked_pending, linked_final)
            or not stat.S_ISREG(linked_final.st_mode)
            or linked_final.st_nlink != 2
        ):
            raise OSError("published evidence hard-link state is invalid")
        os.fsync(parent)
        try:
            _require_stable_final_parent_chain(
                root_descriptor,
                parts,
                parent_identities,
            )
        except Exception as namespace_error:
            if created_final:
                old_final = os.stat(
                    parts[-1],
                    dir_fd=parent,
                    follow_symlinks=False,
                )
                if not _same_inode(linked_pending, old_final):
                    raise OSError(
                        "owned final link changed before withdrawal"
                    ) from namespace_error
                os.unlink(parts[-1], dir_fd=parent)
                os.fsync(parent)
            raise RetryEvidenceRecoveryError(
                "final evidence parent namespace changed during publication"
            ) from namespace_error
        os.unlink(pending_name, dir_fd=pending_descriptor)
        os.fsync(pending_descriptor)
        final_fd = os.open(
            parts[-1],
            (
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            ),
            dir_fd=parent,
        )
        try:
            _read_exact_descriptor(
                final_fd,
                digest=publication.digest,
                size_bytes=publication.size_bytes,
                allowed_links=(1,),
            )
        finally:
            os.close(final_fd)
    finally:
        _close_evidence_descriptors(
            [pending_fd, *parent_descriptors]
        )


def publish_group_no_replace(
    ledger_path: Path,
    *,
    evidence_root: Path,
    group: _PublicationGroup,
    _borrowed_lock_descriptor: int | None = None,
) -> None:
    """Publish a journaled COMMITTING group without replacing final paths."""

    path = Path(ledger_path)
    root = Path(evidence_root)
    lock_descriptor: int | None = None
    owns_lock = False
    connection: sqlite3.Connection | None = None
    root_descriptor: int | None = None
    pending_descriptor: int | None = None
    try:
        lock_descriptor, owns_lock = _borrow_or_acquire_target_lock(
            path,
            _borrowed_lock_descriptor,
        )
        connection = connect_ledger(path)
        work_order, _ = _validated_publication_group(
            connection,
            group,
            required_state="COMMITTING",
        )
        root_descriptor, root_identity = _open_stable_evidence_root(root)
        pending_descriptor = _ensure_pending_directory(root_descriptor)
        pending_identity = os.fstat(pending_descriptor)
        for publication in group.publications:
            _publish_one_no_replace(
                root_descriptor=root_descriptor,
                pending_descriptor=pending_descriptor,
                work_order=work_order,
                publication=publication,
            )
            _verify_exact_final(
                root_descriptor,
                work_order,
                publication,
            )
        _require_stable_pending_directory(
            root_descriptor,
            pending_descriptor,
            pending_identity,
        )
        root_named = os.stat(root, follow_symlinks=False)
        root_after = os.fstat(root_descriptor)
        if (
            not _same_inode(root_identity, root_named)
            or not _same_inode(root_identity, root_after)
        ):
            raise OSError("evidence root changed while publishing")
    finally:
        cleanup_errors = _cleanup_publication_resources(
            connection=connection,
            descriptors=(
                ("pending directory close", pending_descriptor),
                ("evidence root close", root_descriptor),
            ),
            lock_descriptor=lock_descriptor if owns_lock else None,
        )
        if cleanup_errors:
            raise RetryEvidenceRecoveryError(
                "evidence publication cleanup is required"
            ) from _error_cause(
                "evidence publication cleanup failures",
                list(cleanup_errors),
            )


def _verify_exact_final(
    root_descriptor: int,
    work_order: WorkOrder,
    publication: _Publication,
) -> None:
    parts = _safe_evidence_parts(work_order, publication.final_path)
    descriptors: list[int] = []
    try:
        parent, parent_descriptors, parent_identities = (
            _open_final_parent_anchored(
                root_descriptor,
                parts,
                create=False,
            )
        )
        descriptors.extend(parent_descriptors)
        final_descriptor = os.open(
            parts[-1],
            (
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            ),
            dir_fd=parent,
        )
        descriptors.append(final_descriptor)
        _, final_metadata = _read_exact_descriptor(
            final_descriptor,
            digest=publication.digest,
            size_bytes=publication.size_bytes,
            allowed_links=(1,),
        )
        _require_stable_final_parent_chain(
            root_descriptor,
            parts,
            parent_identities,
        )
        recheck_parent, recheck_descriptors, recheck_identities = (
            _open_final_parent_anchored(
                root_descriptor,
                parts,
                create=False,
            )
        )
        descriptors.extend(recheck_descriptors)
        if recheck_identities != parent_identities:
            raise OSError(
                "final evidence parent namespace changed during validation"
            )
        recheck_descriptor = os.open(
            parts[-1],
            (
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            ),
            dir_fd=recheck_parent,
        )
        descriptors.append(recheck_descriptor)
        _, recheck_metadata = _read_exact_descriptor(
            recheck_descriptor,
            digest=publication.digest,
            size_bytes=publication.size_bytes,
            allowed_links=(1,),
        )
        if (
            final_metadata.st_dev,
            final_metadata.st_ino,
            final_metadata.st_mode,
            final_metadata.st_nlink,
            final_metadata.st_size,
        ) != (
            recheck_metadata.st_dev,
            recheck_metadata.st_ino,
            recheck_metadata.st_mode,
            recheck_metadata.st_nlink,
            recheck_metadata.st_size,
        ):
            raise OSError("final evidence namespace changed during validation")
    finally:
        _close_evidence_descriptors(descriptors)


def mark_publication_group_committed(
    ledger_path: Path,
    *,
    evidence_root: Path,
    group: _PublicationGroup,
    _borrowed_lock_descriptor: int | None = None,
) -> None:
    """Atomically mark a fully published COMMITTING receipt group committed."""

    path = Path(ledger_path)
    root = Path(evidence_root)
    lock_descriptor: int | None = None
    owns_lock = False
    connection: sqlite3.Connection | None = None
    root_descriptor: int | None = None
    pending_descriptor: int | None = None
    primary_error: Exception | None = None
    committed = False
    try:
        lock_descriptor, owns_lock = _borrow_or_acquire_target_lock(
            path,
            _borrowed_lock_descriptor,
        )
        connection = connect_ledger(path)
        root_descriptor, root_identity = _open_stable_evidence_root(root)
        pending_descriptor = os.open(
            ".pending",
            _directory_flags(),
            dir_fd=root_descriptor,
        )
        pending_identity = os.fstat(pending_descriptor)
        _mark_group_committed_locked(
            connection,
            ledger_path=path,
            evidence_root=root,
            root_descriptor=root_descriptor,
            root_identity=root_identity,
            pending_descriptor=pending_descriptor,
            pending_identity=pending_identity,
            group=group,
        )
        committed = True
    except EvidencePublicationCommittedError as error:
        primary_error = error
        committed = True
    except EvidencePublicationCommitIndeterminateError as error:
        primary_error = error
    except Exception as error:
        primary_error = error
        rollback_error = _best_effort_rollback(connection)
        if rollback_error is not None:
            primary_error = RuntimeError(
                "evidence publication mark rollback failed"
            )
            primary_error.__cause__ = _error_cause(
                "evidence publication mark failures",
                [error, rollback_error],
            )

    cleanup_errors = _cleanup_publication_resources(
        connection=connection,
        descriptors=(
            ("pending directory close", pending_descriptor),
            ("evidence root close", root_descriptor),
        ),
        lock_descriptor=lock_descriptor if owns_lock else None,
    )
    if committed and (primary_error is not None or cleanup_errors):
        evidence_verified = not (
            isinstance(primary_error, EvidencePublicationCommittedError)
            and not primary_error.evidence_verified
        )
        error = EvidencePublicationCommittedError(
            group,
            evidence_verified=evidence_verified,
        )
        causes = (
            ([] if primary_error is None else [primary_error])
            + list(cleanup_errors)
        )
        raise error from _error_cause(
            "evidence publication completion failures",
            causes,
        )
    if primary_error is not None:
        if isinstance(
            primary_error,
            EvidencePublicationCommitIndeterminateError,
        ):
            if cleanup_errors:
                error = EvidencePublicationCommitIndeterminateError(group)
                raise error from _error_cause(
                    "evidence publication indeterminate completion failures",
                    [primary_error, *cleanup_errors],
                )
            raise primary_error
        if cleanup_errors:
            raise RuntimeError(
                "evidence publication mark failed during cleanup"
            ) from _error_cause(
                "evidence publication mark failures",
                [primary_error, *cleanup_errors],
            )
        raise primary_error
    if cleanup_errors:
        raise RuntimeError(
            "evidence publication mark cleanup failed"
        ) from _error_cause(
            "evidence publication cleanup failures",
            list(cleanup_errors),
        )


def complete_receipt_publication(
    ledger_path: Path,
    *,
    evidence_root: Path,
    receipt: ActionReceiptEnvelope,
    payloads: Mapping[str, bytes],
    clock: Callable[[], datetime],
    trusted_resolution_manifest: ResolutionManifest | None = None,
    _borrowed_lock_descriptor: int | None = None,
) -> _PublicationGroup:
    """Stage, journal, publish, and commit one receipt evidence group."""

    path = Path(ledger_path)
    root = Path(evidence_root)
    lock_descriptor: int | None = None
    owns_lock = False
    group: _PublicationGroup | None = None
    receipt_committed = False
    primary_error: Exception | None = None
    try:
        lock_descriptor, owns_lock = _borrow_or_acquire_target_lock(
            path,
            _borrowed_lock_descriptor,
        )
        if receipt.evidence_refs:
            group = stage_pending_evidence_group(
                path,
                evidence_root=root,
                receipt=receipt,
                payloads=payloads,
                _borrowed_lock_descriptor=lock_descriptor,
            )
        elif not payloads:
            group = _PublicationGroup(
                receipt_id=receipt.receipt_id,
                publications=(),
            )
        else:
            raise ValueError(
                "evidence-free receipt cannot stage payloads"
            )
        try:
            commit_receipt_with_publications(
                path,
                evidence_root=root,
                receipt=receipt,
                group=group,
                clock=clock,
                trusted_resolution_manifest=trusted_resolution_manifest,
                _borrowed_lock_descriptor=lock_descriptor,
            )
        except ReceiptPublicationCommittedError:
            receipt_committed = True
            raise
        receipt_committed = True
        if group.publications:
            publish_group_no_replace(
                path,
                evidence_root=root,
                group=group,
                _borrowed_lock_descriptor=lock_descriptor,
            )
            mark_publication_group_committed(
                path,
                evidence_root=root,
                group=group,
                _borrowed_lock_descriptor=lock_descriptor,
            )
        require_all_publications_committed(
            path,
            evidence_root=root,
            _borrowed_lock_descriptor=lock_descriptor,
        )
    except Exception as error:
        primary_error = error

    release_errors = ()
    if owns_lock:
        _, release_errors = _release_target_lock(lock_descriptor)
    cleanup_errors = [
        _contextualize_secondary("target lock release", error)
        for error in release_errors
    ]
    if primary_error is None and not cleanup_errors:
        assert group is not None
        return group
    causes = (
        ([] if primary_error is None else [primary_error])
        + cleanup_errors
    )
    if isinstance(
        primary_error,
        ReceiptPublicationCommitIndeterminateError,
    ):
        if cleanup_errors:
            error = ReceiptPublicationCommitIndeterminateError(
                receipt,
                primary_error.group,
            )
            raise error from _error_cause(
                "receipt publication coordinator cleanup failures",
                causes,
            )
        raise primary_error
    if receipt_committed:
        assert group is not None
        error = ReceiptPublicationCommittedError(receipt, group)
        raise error from _error_cause(
            "receipt publication coordinator completion failures",
            causes,
        )
    if primary_error is not None and not cleanup_errors:
        raise primary_error
    raise RuntimeError(
        "receipt publication coordinator failed during cleanup"
    ) from _error_cause(
        "receipt publication coordinator failures",
        causes,
    )


def _journal_publication_groups(
    connection: sqlite3.Connection,
) -> tuple[tuple[_PublicationGroup, str], ...]:
    rows = connection.execute(
        """
        SELECT receipt_id, publication_id, pending_path, final_path,
               digest, size_bytes, media_type, state
        FROM evidence_publications
        ORDER BY receipt_id, final_path
        LIMIT ?
        """,
        (MAX_RECEIPTS * _MAX_PUBLICATIONS_PER_GROUP + 1,),
    ).fetchall()
    if len(rows) > MAX_RECEIPTS * _MAX_PUBLICATIONS_PER_GROUP:
        raise ValueError("evidence publication journal exceeds its bound")
    grouped: dict[str, list[tuple[_Publication, str]]] = {}
    for (
        receipt_id,
        publication_id,
        pending_path,
        final_path,
        digest,
        size_bytes,
        media_type,
        publication_state,
    ) in rows:
        _validated_pending_basename(
            publication_id,
            pending_path,
        )
        grouped.setdefault(receipt_id, []).append(
            (
                _Publication(
                    publication_id=publication_id,
                    pending_path=pending_path,
                    final_path=final_path,
                    digest=digest,
                    size_bytes=size_bytes,
                    media_type=media_type,
                ),
                publication_state,
            )
        )
    result: list[tuple[_PublicationGroup, str]] = []
    for receipt_id, entries in grouped.items():
        states = {state_value for _, state_value in entries}
        if len(states) != 1:
            raise ValueError("one receipt publication group has mixed states")
        group = _PublicationGroup(
            receipt_id=receipt_id,
            publications=tuple(item for item, _ in entries),
        )
        state_value = next(iter(states))
        _validated_publication_group(
            connection,
            group,
            required_state=state_value,
        )
        result.append((group, state_value))
    return tuple(result)


def _require_exact_publication_coverage(
    receipts,
    groups: tuple[tuple[_PublicationGroup, str], ...],
) -> None:
    expected = [
        (
            receipt.receipt_id,
            reference.path,
            reference.sha256,
            reference.size_bytes,
            reference.media_type,
        )
        for receipt in receipts
        for reference in receipt.evidence_refs
    ]
    actual = [
        (
            group.receipt_id,
            publication.final_path,
            publication.digest,
            publication.size_bytes,
            publication.media_type,
        )
        for group, _ in groups
        for publication in group.publications
    ]
    if (
        len(expected) != len(set(expected))
        or len(actual) != len(set(actual))
        or sorted(expected) != sorted(actual)
    ):
        raise ValueError(
            "publication journal does not exactly cover authoritative refs"
        )


def _inspect_pending_publication(
    pending_descriptor: int,
    publication: _Publication,
) -> os.stat_result | None:
    name = _validated_pending_basename(
        publication.publication_id,
        publication.pending_path,
    )
    try:
        descriptor = os.open(
            name,
            (
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            ),
            dir_fd=pending_descriptor,
        )
    except FileNotFoundError:
        return None
    try:
        _, metadata = _read_exact_descriptor(
            descriptor,
            digest=publication.digest,
            size_bytes=publication.size_bytes,
            allowed_links=(1, 2),
        )
        return metadata
    finally:
        os.close(descriptor)


def _inspect_final_publication(
    root_descriptor: int,
    work_order: WorkOrder,
    publication: _Publication,
) -> os.stat_result | None:
    parts = _safe_evidence_parts(work_order, publication.final_path)
    parent_descriptors: list[int] = []
    try:
        try:
            parent, parent_descriptors = _open_final_parent(
                root_descriptor,
                parts,
                create=False,
            )
            descriptor = os.open(
                parts[-1],
                (
                    os.O_RDONLY
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0)
                ),
                dir_fd=parent,
            )
        except FileNotFoundError:
            return None
        try:
            _, metadata = _read_exact_descriptor(
                descriptor,
                digest=publication.digest,
                size_bytes=publication.size_bytes,
                allowed_links=(1, 2),
            )
            return metadata
        finally:
            os.close(descriptor)
    finally:
        _close_evidence_descriptors(parent_descriptors)


def _confirm_publication_group_committed(
    ledger_path: Path,
    group: _PublicationGroup,
) -> tuple[str, Exception | None]:
    connection: sqlite3.Connection | None = None
    try:
        connection = _connect_ledger_direct(ledger_path)
    except Exception as error:
        return "INDETERMINATE", error
    confirmation = "INDETERMINATE"
    confirmation_error: Exception | None = None
    try:
        try:
            _validated_publication_group(
                connection,
                group,
                required_state="COMMITTED",
            )
            confirmation = "COMMITTED"
        except Exception as committed_error:
            try:
                _validated_publication_group(
                    connection,
                    group,
                    required_state="COMMITTING",
                )
                confirmation = "NOT_COMMITTED"
            except Exception as not_committed_error:
                confirmation_error = _error_cause(
                    "publication confirmation read failures",
                    [committed_error, not_committed_error],
                )
    except Exception as error:
        confirmation_error = error
    _, close_errors = _close_with_retries(connection)
    if close_errors:
        return (
            "INDETERMINATE",
            _error_cause(
                "publication confirmation failures",
                (
                    []
                    if confirmation_error is None
                    else [confirmation_error]
                )
                + list(close_errors),
            ),
        )
    if confirmation_error is not None:
        return "INDETERMINATE", confirmation_error
    return confirmation, None


def _require_group_finals_on_anchor(
    *,
    root_descriptor: int,
    root_identity: os.stat_result,
    pending_descriptor: int,
    pending_identity: os.stat_result,
    work_order: WorkOrder,
    group: _PublicationGroup,
) -> None:
    _require_stable_pending_directory(
        root_descriptor,
        pending_descriptor,
        pending_identity,
    )
    if not _same_inode(root_identity, os.fstat(root_descriptor)):
        raise OSError("evidence root anchor changed during publication mark")
    for publication in group.publications:
        if (
            _inspect_pending_publication(
                pending_descriptor,
                publication,
            )
            is not None
        ):
            raise OSError(
                "pending evidence remains for a publication being committed"
            )
        _verify_exact_final(
            root_descriptor,
            work_order,
            publication,
        )
    _require_stable_pending_directory(
        root_descriptor,
        pending_descriptor,
        pending_identity,
    )
    if not _same_inode(root_identity, os.fstat(root_descriptor)):
        raise OSError("evidence root anchor changed during publication mark")


def _require_named_evidence_root(
    evidence_root: Path,
    root_descriptor: int,
    root_identity: os.stat_result,
) -> None:
    named = os.stat(evidence_root, follow_symlinks=False)
    opened = os.fstat(root_descriptor)
    if (
        not _same_inode(root_identity, named)
        or not _same_inode(root_identity, opened)
    ):
        raise OSError("named evidence root changed during publication mark")


def _mark_group_committed_locked(
    connection: sqlite3.Connection,
    *,
    ledger_path: Path,
    evidence_root: Path,
    root_descriptor: int,
    root_identity: os.stat_result,
    pending_descriptor: int,
    pending_identity: os.stat_result,
    group: _PublicationGroup,
) -> None:
    primary_error: Exception | None = None
    committed = False
    work_order: WorkOrder | None = None
    try:
        connection.execute("BEGIN IMMEDIATE")
        work_order, _ = _validated_publication_group(
            connection,
            group,
            required_state="COMMITTING",
        )
        updated = connection.execute(
            """
            UPDATE evidence_publications
            SET state = 'COMMITTED'
            WHERE receipt_id = ? AND state = 'COMMITTING'
            """,
            (group.receipt_id,),
        )
        if updated.rowcount != len(group.publications):
            raise sqlite3.DatabaseError(
                "publication group state changed before recovery commit"
            )
        _require_group_finals_on_anchor(
            root_descriptor=root_descriptor,
            root_identity=root_identity,
            pending_descriptor=pending_descriptor,
            pending_identity=pending_identity,
            work_order=work_order,
            group=group,
        )
        _require_named_evidence_root(
            evidence_root,
            root_descriptor,
            root_identity,
        )
        try:
            connection.execute("COMMIT")
            committed = True
        except Exception as error:
            confirmation, confirmation_error = (
                _confirm_publication_group_committed(ledger_path, group)
            )
            if confirmation == "COMMITTED":
                committed = True
                committed_error = EvidencePublicationCommittedError(group)
                committed_error.__cause__ = error
                primary_error = committed_error
            elif confirmation == "NOT_COMMITTED":
                primary_error = error
            else:
                indeterminate_error = (
                    EvidencePublicationCommitIndeterminateError(group)
                )
                indeterminate_error.__cause__ = _error_cause(
                    "publication COMMIT acknowledgement failures",
                    [error]
                    + (
                        []
                        if confirmation_error is None
                        else [confirmation_error]
                    ),
                )
                primary_error = indeterminate_error
    except Exception as error:
        primary_error = error

    if committed:
        assert work_order is not None
        try:
            _require_group_finals_on_anchor(
                root_descriptor=root_descriptor,
                root_identity=root_identity,
                pending_descriptor=pending_descriptor,
                pending_identity=pending_identity,
                work_order=work_order,
                group=group,
            )
            _require_named_evidence_root(
                evidence_root,
                root_descriptor,
                root_identity,
            )
        except Exception as post_commit_error:
            error = EvidencePublicationCommittedError(
                group,
                evidence_verified=False,
            )
            raise error from _error_cause(
                "post-commit evidence verification failures",
                (
                    []
                    if primary_error is None
                    else [primary_error]
                )
                + [post_commit_error],
            )

    if primary_error is not None and not committed:
        rollback_error = _best_effort_rollback(connection)
        if rollback_error is not None:
            operation_error = primary_error
            combined_error = RuntimeError(
                "publication group mark rollback failed"
            )
            combined_error.__cause__ = _error_cause(
                "publication group mark failures",
                [operation_error, rollback_error],
            )
            primary_error = combined_error
    if committed and primary_error is not None:
        error = EvidencePublicationCommittedError(group)
        raise error from _error_cause(
            "evidence publication committed completion failures",
            [primary_error],
        )
    if primary_error is not None:
        raise primary_error


def recover_evidence_publications(
    ledger_path: Path,
    *,
    evidence_root: Path,
) -> None:
    """Idempotently finish or validate all journaled evidence publications."""

    path = Path(ledger_path)
    root = Path(evidence_root)
    lock_descriptor: int | None = None
    connection: sqlite3.Connection | None = None
    root_descriptor: int | None = None
    pending_descriptor: int | None = None
    try:
        lock_descriptor = _acquire_target_lock(path)
        connection = connect_ledger(path)
        work_order = load_authoritative_work_order(connection)
        receipts = _validated_receipt_prefix(connection, work_order)
        groups = _journal_publication_groups(connection)
        _require_exact_publication_coverage(receipts, groups)
        root_descriptor, root_identity = _open_stable_evidence_root(root)
        pending_descriptor = _ensure_pending_directory(root_descriptor)
        pending_identity = os.fstat(pending_descriptor)

        referenced_pending = {
            publication.publication_id
            for group, _ in groups
            for publication in group.publications
        }
        removed_rowless = False
        for name in os.listdir(pending_descriptor):
            if name in referenced_pending:
                continue
            metadata = os.stat(
                name,
                dir_fd=pending_descriptor,
                follow_symlinks=False,
            )
            if stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1:
                os.unlink(name, dir_fd=pending_descriptor)
                removed_rowless = True
        if removed_rowless:
            os.fsync(pending_descriptor)

        for group, publication_state in groups:
            if publication_state == "COMMITTED":
                for publication in group.publications:
                    if (
                        _inspect_pending_publication(
                            pending_descriptor,
                            publication,
                        )
                        is not None
                    ):
                        raise OSError(
                            "committed publication still has pending evidence"
                        )
                    _verify_exact_final(
                        root_descriptor,
                        work_order,
                        publication,
                    )
                continue
            if publication_state != "COMMITTING":
                raise ValueError("publication journal state is invalid")
            for publication in group.publications:
                pending_metadata = _inspect_pending_publication(
                    pending_descriptor,
                    publication,
                )
                final_metadata = _inspect_final_publication(
                    root_descriptor,
                    work_order,
                    publication,
                )
                if pending_metadata is None and final_metadata is None:
                    raise FileNotFoundError(
                        "both pending and final publication are missing"
                    )
                if final_metadata is not None:
                    _fsync_existing_final_parent(
                        root_descriptor,
                        work_order,
                        publication,
                    )
                if pending_metadata is not None and final_metadata is None:
                    if pending_metadata.st_nlink != 1:
                        raise OSError("pending-only publication has extra links")
                    _publish_one_no_replace(
                        root_descriptor=root_descriptor,
                        pending_descriptor=pending_descriptor,
                        work_order=work_order,
                        publication=publication,
                    )
                elif pending_metadata is None and final_metadata is not None:
                    if final_metadata.st_nlink != 1:
                        raise OSError("final-only publication has extra links")
                else:
                    assert pending_metadata is not None
                    assert final_metadata is not None
                    same = _same_inode(pending_metadata, final_metadata)
                    if same and (
                        pending_metadata.st_nlink != 2
                        or final_metadata.st_nlink != 2
                    ):
                        raise OSError(
                            "linked pending/final publication is malformed"
                        )
                    if not same and (
                        pending_metadata.st_nlink != 1
                        or final_metadata.st_nlink != 1
                    ):
                        raise OSError(
                            "duplicate pending/final publication is malformed"
                        )
                    os.unlink(
                        _validated_pending_basename(
                            publication.publication_id,
                            publication.pending_path,
                        ),
                        dir_fd=pending_descriptor,
                    )
                    os.fsync(pending_descriptor)
                _verify_exact_final(
                    root_descriptor,
                    work_order,
                    publication,
                )
            try:
                _mark_group_committed_locked(
                    connection,
                    ledger_path=path,
                    evidence_root=root,
                    root_descriptor=root_descriptor,
                    root_identity=root_identity,
                    pending_descriptor=pending_descriptor,
                    pending_identity=pending_identity,
                    group=group,
                )
            except EvidencePublicationCommittedError as error:
                if not error.evidence_verified:
                    raise

        _require_stable_pending_directory(
            root_descriptor,
            pending_descriptor,
            pending_identity,
        )
        root_named = os.stat(root, follow_symlinks=False)
        root_after = os.fstat(root_descriptor)
        if (
            not _same_inode(root_identity, root_named)
            or not _same_inode(root_identity, root_after)
        ):
            raise OSError("evidence root changed during recovery")
    except RetryEvidenceRecoveryError:
        raise
    except Exception as error:
        raise RetryEvidenceRecoveryError(
            "evidence publication recovery is required"
        ) from error
    finally:
        cleanup_errors = _cleanup_publication_resources(
            connection=connection,
            descriptors=(
                ("pending directory close", pending_descriptor),
                ("evidence root close", root_descriptor),
            ),
            lock_descriptor=lock_descriptor,
        )
        if cleanup_errors:
            raise RetryEvidenceRecoveryError(
                "evidence publication recovery cleanup failed"
            ) from _error_cause(
                "evidence publication recovery cleanup failures",
                list(cleanup_errors),
            )


def require_all_publications_committed(
    ledger_path: Path,
    *,
    evidence_root: Path,
    _borrowed_lock_descriptor: int | None = None,
) -> None:
    """Read-only gate requiring an exact, rehashed COMMITTED publication set."""

    path = Path(ledger_path)
    root = Path(evidence_root)
    lock_descriptor: int | None = None
    owns_lock = False
    connection: sqlite3.Connection | None = None
    root_descriptor: int | None = None
    pending_descriptor: int | None = None
    try:
        lock_descriptor, owns_lock = _borrow_or_acquire_target_lock(
            path,
            _borrowed_lock_descriptor,
        )
        connection = connect_ledger(path)
        work_order, _, _, groups = _replay_receipt_publication_ledger(
            connection
        )
        if any(state_value != "COMMITTED" for _, state_value in groups):
            raise RetryEvidenceRecoveryError(
                "evidence publication recovery is required"
            )

        root_descriptor, root_identity = _open_stable_evidence_root(root)
        try:
            pending_descriptor = os.open(
                ".pending",
                _directory_flags(),
                dir_fd=root_descriptor,
            )
        except FileNotFoundError:
            pending_descriptor = None
        pending_identity = (
            None
            if pending_descriptor is None
            else os.fstat(pending_descriptor)
        )
        for group, _ in groups:
            for publication in group.publications:
                pending_metadata = (
                    None
                    if pending_descriptor is None
                    else _inspect_pending_publication(
                        pending_descriptor,
                        publication,
                    )
                )
                if pending_metadata is not None:
                    raise RetryEvidenceRecoveryError(
                        "committed publication still has pending evidence"
                    )
                _verify_exact_final(
                    root_descriptor,
                    work_order,
                    publication,
                )
        if pending_descriptor is not None:
            assert pending_identity is not None
            _require_stable_pending_directory(
                root_descriptor,
                pending_descriptor,
                pending_identity,
            )
        root_named = os.stat(root, follow_symlinks=False)
        root_after = os.fstat(root_descriptor)
        if (
            not _same_inode(root_identity, root_named)
            or not _same_inode(root_identity, root_after)
        ):
            raise RetryEvidenceRecoveryError(
                "committed evidence namespace changed during validation"
            )
    except RetryEvidenceRecoveryError:
        raise
    except Exception as error:
        raise RetryEvidenceRecoveryError(
            "committed evidence validation requires recovery"
        ) from error
    finally:
        cleanup_errors = _cleanup_publication_resources(
            connection=connection,
            descriptors=(
                ("pending directory close", pending_descriptor),
                ("evidence root close", root_descriptor),
            ),
            lock_descriptor=lock_descriptor if owns_lock else None,
        )
        if cleanup_errors:
            raise RetryEvidenceRecoveryError(
                "committed evidence validation cleanup failed"
            ) from _error_cause(
                "committed evidence validation cleanup failures",
                list(cleanup_errors),
            )


def _validate_open_lock(
    descriptor: int,
    lock_path: Path,
) -> None:
    opened = os.fstat(descriptor)
    named = os.stat(lock_path, follow_symlinks=False)
    if (
        not stat.S_ISREG(opened.st_mode)
        or not stat.S_ISREG(named.st_mode)
        or not _same_inode(opened, named)
    ):
        raise OSError("target lock is not a stable regular file")


def _acquire_target_lock(ledger_path: Path) -> int:
    lock_path = _target_lock_path(ledger_path)
    flags = os.O_RDWR | os.O_CREAT
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(lock_path, flags, 0o600)
        _validate_open_lock(descriptor, lock_path)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        _validate_open_lock(descriptor, lock_path)
        return descriptor
    except Exception as primary_error:
        errors: list[Exception] = [primary_error]
        if descriptor is not None:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            except OSError as unlock_error:
                errors.append(unlock_error)
            _, close_errors = _close_lock_descriptor(descriptor)
            errors.extend(close_errors)
        raise _error_cause(
            "target lock acquisition failures",
            errors,
        )


def _borrow_or_acquire_target_lock(
    ledger_path: Path,
    borrowed_descriptor: int | None,
) -> tuple[int, bool]:
    if borrowed_descriptor is None:
        return _acquire_target_lock(ledger_path), True
    if type(borrowed_descriptor) is not int:
        raise TypeError("borrowed target lock descriptor must be an integer")
    _validate_open_lock(
        borrowed_descriptor,
        _target_lock_path(ledger_path),
    )
    return borrowed_descriptor, False


def _close_lock_descriptor(
    descriptor: int,
) -> tuple[bool, tuple[Exception, ...]]:
    try:
        os.close(descriptor)
    except OSError as error:
        return False, (error,)
    return True, ()


def _release_target_lock(
    descriptor: int | None,
) -> tuple[bool, tuple[Exception, ...]]:
    if descriptor is None:
        return True, ()
    errors: list[Exception] = []
    try:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
    except OSError as error:
        errors.append(error)
    closed, close_errors = _close_lock_descriptor(descriptor)
    errors.extend(close_errors)
    return closed, tuple(errors)


def _verify_initialized_snapshot(
    connection: sqlite3.Connection,
    work_order: WorkOrder,
) -> None:
    loaded = load_authoritative_work_order(connection)
    sequence = tuple(
        connection.execute(
            """
            SELECT singleton, next_sequence
            FROM sequence_counter
            ORDER BY singleton
            """
        ).fetchall()
    )
    state = tuple(
        connection.execute(
            """
            SELECT singleton, work_order_digest, current_state, version
            FROM work_order_state
            ORDER BY singleton
            """
        ).fetchall()
    )
    reservations = tuple(
        connection.execute(
            """
            SELECT
                grant_id,
                work_order_digest,
                candidate_grant_digest,
                reservation_kind
            FROM grant_id_reservations
            ORDER BY grant_id
            """
        ).fetchall()
    )
    empty_tables = (
        "grants",
        "grant_attempts",
        "receipts",
        "receipt_parents",
        "grant_events",
        "evidence_publications",
        "handler_executions",
        "acceptance_receipts",
    )
    counts = tuple(
        connection.execute(
            f"SELECT COUNT(*) FROM {table}"
        ).fetchone()
        for table in empty_tables
    )
    if (
        loaded != work_order
        or sequence != ((1, 1),)
        or state
        != ((1, work_order.digest, "issued", 0),)
        or reservations
        != (
            (
                work_order.root_grant_template.grant_id,
                work_order.digest,
                None,
                "root_template",
            ),
        )
        or counts != ((0,),) * len(empty_tables)
    ):
        raise ValueError(
            "initialized ledger does not match its frozen genesis snapshot"
        )


def _file_identity(path: Path) -> tuple[int, int]:
    metadata = path.stat()
    return metadata.st_dev, metadata.st_ino


def _withdraw_final_if_owned(
    ledger_path: Path,
    temporary_identity: tuple[int, int] | None,
) -> tuple[Exception, ...]:
    if temporary_identity is None:
        return ()
    try:
        final_identity = _file_identity(ledger_path)
    except FileNotFoundError:
        return ()
    except OSError as error:
        return (error,)
    if final_identity != temporary_identity:
        return ()
    errors: list[Exception] = []
    try:
        ledger_path.unlink()
    except OSError as error:
        errors.append(error)
        return tuple(errors)
    try:
        _fsync_directory(ledger_path.parent)
    except OSError as error:
        errors.append(error)
    return tuple(errors)


def _initialize_ledger_locked(path: Path, work_order: WorkOrder) -> None:
    ledger_path = Path(path)
    if ledger_path.exists():
        cause = FileExistsError(f"ledger path already exists: {ledger_path}")
        raise LedgerInitializationError("ledger path already exists") from cause

    canonical_work_order = _canonical_json(
        work_order.model_dump(mode="json")
    )
    temporary_path: Path | None = None
    temporary_identity: tuple[int, int] | None = None
    published_by_this_call = False
    connection: sqlite3.Connection | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{ledger_path.name}.",
            suffix=".tmp",
            dir=ledger_path.parent,
        )
        os.close(descriptor)
        temporary_path = Path(temporary_name)
        connection = connect_ledger(temporary_path)
        connection.execute("BEGIN IMMEDIATE")
        _create_schema(connection)
        connection.execute(
            """
            INSERT INTO work_orders (work_order_digest, work_order_json)
            VALUES (?, ?)
            """,
            (work_order.digest, canonical_work_order),
        )
        connection.execute(
            """
            INSERT INTO sequence_counter (singleton, next_sequence)
            VALUES (1, 1)
            """
        )
        connection.execute(
            """
            INSERT INTO work_order_state (
                singleton,
                work_order_digest,
                current_state,
                version
            )
            VALUES (1, ?, 'issued', 0)
            """,
            (work_order.digest,),
        )
        connection.execute(
            """
            INSERT INTO grant_id_reservations (
                grant_id,
                work_order_digest,
                candidate_grant_digest,
                reservation_kind
            )
            VALUES (?, ?, NULL, 'root_template')
            """,
            (
                work_order.root_grant_template.grant_id,
                work_order.digest,
            ),
        )
        connection.execute("COMMIT")
        checkpoint = connection.execute(
            "PRAGMA wal_checkpoint(TRUNCATE)"
        ).fetchone()
        if checkpoint != (0, 0, 0):
            raise sqlite3.DatabaseError(
                f"SQLite checkpoint was not clean: {checkpoint!r}"
            )
        _, close_errors = _close_with_retries(connection)
        if close_errors:
            raise _error_cause(
                "initial ledger close failed",
                close_errors,
            )
        connection = None

        connection = connect_ledger(temporary_path)
        _verify_initialized_snapshot(connection, work_order)
        _, verification_close_errors = _close_with_retries(connection)
        if verification_close_errors:
            raise _error_cause(
                "verification connection close failed",
                verification_close_errors,
            )
        connection = None

        _fsync_file(temporary_path)
        temporary_identity = _file_identity(temporary_path)
        os.link(temporary_path, ledger_path)
        published_by_this_call = True
        _fsync_directory(ledger_path.parent)
        cleanup_errors = _cleanup_owned_sqlite(temporary_path)
        if cleanup_errors:
            raise _error_cause(
                "owned SQLite cleanup failed",
                cleanup_errors,
            )
        temporary_path = None
        _fsync_directory(ledger_path.parent)
    except Exception as error:
        errors: list[Exception] = [error]
        rollback_error = _best_effort_rollback(connection)
        if rollback_error is not None:
            errors.append(rollback_error)
        _, close_errors = _close_with_retries(connection)
        errors.extend(close_errors)
        connection = None
        if published_by_this_call:
            errors.extend(
                _withdraw_final_if_owned(
                    ledger_path,
                    temporary_identity,
                )
            )
        errors.extend(_cleanup_owned_sqlite(temporary_path))
        if temporary_path is not None:
            try:
                _fsync_directory(ledger_path.parent)
            except OSError as fsync_error:
                errors.append(fsync_error)
        raise LedgerInitializationError(
            "ledger initialization failed atomically"
        ) from _error_cause("ledger initialization failures", errors)


def initialize_ledger(path: Path, work_order: WorkOrder) -> None:
    """Create a ledger under the target's persistent coordination lock."""

    if not verify_work_order_identity_bindings(work_order):
        cause = ValueError("WorkOrder authority verification failed")
        raise LedgerInitializationError(str(cause)) from cause

    ledger_path = Path(path)
    lock_descriptor: int | None = None
    primary_error: Exception | None = None
    try:
        lock_descriptor = _acquire_target_lock(ledger_path)
        _initialize_ledger_locked(ledger_path, work_order)
    except Exception as error:
        primary_error = error

    lock_closed, release_errors = _release_target_lock(lock_descriptor)
    if primary_error is None:
        if lock_closed:
            return
        raise LedgerInitializationCommittedError(
            ledger_path,
            work_order.digest,
        ) from _error_cause(
            "target lock release failures",
            list(release_errors),
        )
    if (
        isinstance(primary_error, LedgerInitializationError)
        and not release_errors
    ):
        raise primary_error
    errors = (
        ([primary_error] if primary_error is not None else [])
        + list(release_errors)
    )
    raise LedgerInitializationError(
        "ledger initialization lock lifecycle failed"
    ) from _error_cause("ledger lock failures", errors)


def load_authoritative_work_order(
    connection: sqlite3.Connection,
) -> WorkOrder:
    """Load and revalidate the sole canonical WorkOrder authority row."""

    try:
        rows = connection.execute(
            """
            SELECT work_order_digest, work_order_json
            FROM work_orders
            ORDER BY work_order_digest
            LIMIT 2
            """
        ).fetchall()
        if len(rows) != 1:
            raise LookupError(
                "ledger does not contain exactly one WorkOrder authority"
            )
        stored_digest, stored_json = rows[0]
        work_order = WorkOrder.model_validate_json(stored_json)
        canonical = _canonical_json(work_order.model_dump(mode="json"))
        if (
            stored_digest != work_order.digest
            or stored_json != canonical
            or not verify_work_order_identity_bindings(work_order)
        ):
            raise ValueError(
                "authoritative WorkOrder row failed integrity verification"
            )
    except Exception as error:
        raise LedgerInitializationError(
            "authoritative WorkOrder could not be loaded"
        ) from error
    return work_order


def _root_activation_error(message: str) -> RootActivationError:
    return RootActivationError(message)


def _freeze_trusted_utc_second(value: object) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise ValueError("trusted clock must return an aware datetime")
    return value.astimezone(timezone.utc).replace(microsecond=0)


def _trusted_activation_inputs(
    work_order: WorkOrder,
    candidate: CapabilityGrant,
    request: AgentRequest,
    sidecar_private_key: Ed25519PrivateKey,
    now: datetime,
) -> datetime:
    try:
        utc_now = _freeze_trusted_utc_second(now)
    except ValueError as error:
        raise _root_activation_error(
            "root activation input is malformed"
        ) from error
    if (
        not isinstance(candidate, CapabilityGrant)
        or not isinstance(request, AgentRequest)
        or not isinstance(sidecar_private_key, Ed25519PrivateKey)
    ):
        raise _root_activation_error("root activation input is malformed")

    bindings = {binding.role: binding for binding in work_order.key_bindings}
    maintainer = bindings["Maintainer"]
    manager = bindings["Manager"]
    sidecar = bindings["Sidecar"]
    expected_candidate = (
        work_order.root_grant_template.model_dump(mode="json")
    )
    expected_candidate.update(
        {
            "work_order_digest": work_order.digest,
            "signature_alg": "Ed25519",
            "signer_key_id": maintainer.key_id,
        }
    )
    candidate_payload = unsigned_payload(
        candidate.model_dump(mode="json")
    )
    maintainer_key = decode_and_verify_key_binding(maintainer)
    if (
        candidate_payload != expected_candidate
        or not verify_payload(
            "capability-grant",
            candidate.model_dump(mode="json"),
            maintainer_key,
        )
        or key_id(sidecar_private_key.public_key()) != sidecar.key_id
        or not verify_nested_claim(request, work_order)
        or request.actor_id != manager.subject_id
        or request.actor_key_id != manager.key_id
        or request.grant_id != candidate.grant_id
        or request.tool_name != "owp.activate_root_grant"
    ):
        raise _root_activation_error("root activation authority is invalid")

    arguments = {
        "operation": "activate_root",
        "authorizing_grant_id": candidate.grant_id,
        "candidate_grant_digest": candidate.digest,
    }
    if (
        request.arguments_digest
        != request_arguments_digest("owp.activate_root_grant", arguments)
        or request.requested_at < work_order.issued_at
        or request.requested_at > work_order.deadline
        or request.requested_at < candidate.valid_from
        or request.requested_at > candidate.expires_at
        or utc_now < request.requested_at
        or (utc_now - request.requested_at).total_seconds() > 300
        or utc_now < candidate.valid_from
        or utc_now > candidate.expires_at
    ):
        raise _root_activation_error("root activation request is invalid")
    return utc_now


def _receipt_id(request: AgentRequest, candidate: CapabilityGrant) -> str:
    return hashlib.sha256(
        rfc8785.dumps(
            {
                "domain": "openworkproof/receipt-id/v0.1",
                "request_digest": request.digest,
                "candidate_grant_digest": candidate.digest,
                "entropy": secrets.token_hex(32),
            }
        )
    ).hexdigest()


def _build_root_receipt(
    work_order: WorkOrder,
    candidate: CapabilityGrant,
    request: AgentRequest,
    sidecar_private_key: Ed25519PrivateKey,
    now: datetime,
) -> GrantIssuedReceipt:
    occurred_at = (
        now.astimezone(timezone.utc)
        .replace(microsecond=0)
        .strftime("%Y-%m-%dT%H:%M:%SZ")
    )
    raw = {
        "protocol_version": "0.1",
        "receipt_id": _receipt_id(request, candidate),
        "work_order_digest": work_order.digest,
        "actor_type": "agent",
        "actor_id": request.actor_id,
        "actor_key_id": request.actor_key_id,
        "nested_claim_type": "agent-request",
        "nested_claim_digest": request.digest,
        "nested_claim": request.model_dump(mode="json"),
        "gateway_signer_key_id": key_id(sidecar_private_key.public_key()),
        "event_type": "grant_issued",
        "policy_decision": "allow",
        "policy_error_code": None,
        "execution_status": "succeeded",
        "execution_error_code": None,
        "quota_charge": None,
        "state_before": "issued",
        "state_after": "running",
        "parent_receipt_ids": [],
        "correlation_factors": None,
        "evidence_refs": [],
        "occurred_at": occurred_at,
        "sequence": 1,
        "nonce": request.nonce,
        "previous_receipt_digest": None,
        "authorizing_grant_id": candidate.grant_id,
        "candidate_grant_digest": candidate.digest,
        "parent_grant_id": None,
        "issued_grant_id": candidate.grant_id,
    }
    receipt = GrantIssuedReceipt.model_validate(
        sign_payload("action-receipt", raw, sidecar_private_key)
    )
    receipt.validate_against_work_order(work_order)
    receipt.validate_candidate(candidate)
    return receipt


def activate_root_grant(
    ledger_path: Path,
    candidate: CapabilityGrant,
    request: AgentRequest,
    *,
    sidecar_private_key: Ed25519PrivateKey,
    clock: Callable[[], datetime],
) -> GrantIssuedReceipt:
    """Atomically convert the exact root reservation into sequence-one genesis."""

    path = Path(ledger_path)
    if not path.is_file():
        cause = FileNotFoundError(f"ledger is unavailable: {path}")
        raise _root_activation_error(
            "root activation ledger is unavailable"
        ) from cause
    connection: sqlite3.Connection | None = None
    receipt_result: GrantIssuedReceipt | None = None
    primary_error: Exception | None = None
    secondary_errors: list[Exception] = []
    try:
        try:
            connection = connect_ledger(path)
        except Exception as error:
            raise _root_activation_error(
                "root activation ledger could not be opened"
            ) from error
        connection.execute("BEGIN IMMEDIATE")
        try:
            work_order = load_authoritative_work_order(connection)
        except LedgerInitializationError as error:
            raise _root_activation_error(
                "authoritative WorkOrder is unavailable"
            ) from error

        now = clock()
        utc_now = _trusted_activation_inputs(
            work_order,
            candidate,
            request,
            sidecar_private_key,
            now,
        )
        state = connection.execute(
            """
            SELECT current_state, version
            FROM work_order_state
            WHERE singleton = 1 AND work_order_digest = ?
            """,
            (work_order.digest,),
        ).fetchone()
        sequence = connection.execute(
            """
            SELECT next_sequence
            FROM sequence_counter
            WHERE singleton = 1
            """
        ).fetchone()
        reservation = connection.execute(
            """
            SELECT work_order_digest, candidate_grant_digest, reservation_kind
            FROM grant_id_reservations
            WHERE grant_id = ?
            """,
            (candidate.grant_id,),
        ).fetchone()
        if (
            state != ("issued", 0)
            or sequence != (1,)
            or reservation
            != (work_order.digest, None, "root_template")
            or connection.execute("SELECT COUNT(*) FROM grants").fetchone()
            != (0,)
            or connection.execute(
                "SELECT COUNT(*) FROM grant_attempts"
            ).fetchone()
            != (0,)
            or connection.execute("SELECT COUNT(*) FROM receipts").fetchone()
            != (0,)
        ):
            cause = LookupError(
                "root activation state or reservation is unavailable"
            )
            raise _root_activation_error(
                "root activation is not the unique genesis action"
            ) from cause

        receipt = _build_root_receipt(
            work_order,
            candidate,
            request,
            sidecar_private_key,
            utc_now,
        )
        updated = connection.execute(
            """
            UPDATE grant_id_reservations
            SET candidate_grant_digest = ?, reservation_kind = 'effective'
            WHERE grant_id = ?
              AND work_order_digest = ?
              AND candidate_grant_digest IS NULL
              AND reservation_kind = 'root_template'
            """,
            (candidate.digest, candidate.grant_id, work_order.digest),
        )
        if updated.rowcount != 1:
            raise _root_activation_error(
                "root reservation could not be converted"
            )
        connection.execute(
            """
            INSERT INTO grants (
                grant_id,
                work_order_digest,
                parent_grant_id,
                subject_agent_id,
                usage_mode,
                grant_json
            )
            VALUES (?, ?, NULL, ?, ?, ?)
            """,
            (
                candidate.grant_id,
                work_order.digest,
                candidate.subject_agent_id,
                candidate.usage_mode,
                _canonical_json(candidate.model_dump(mode="json")),
            ),
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
            VALUES (?, ?, ?, 1, NULL, ?)
            """,
            (
                receipt.receipt_id,
                work_order.digest,
                request.nonce,
                _canonical_json(receipt.model_dump(mode="json")),
            ),
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
                    f"grant-issued:{receipt.receipt_id}".encode("ascii")
                ).hexdigest(),
                receipt.receipt_id,
                candidate.grant_id,
            ),
        )
        state_update = connection.execute(
            """
            UPDATE work_order_state
            SET current_state = 'running', version = 1
            WHERE singleton = 1
              AND work_order_digest = ?
              AND current_state = 'issued'
              AND version = 0
            """,
            (work_order.digest,),
        )
        sequence_update = connection.execute(
            """
            UPDATE sequence_counter
            SET next_sequence = 2
            WHERE singleton = 1 AND next_sequence = 1
            """
        )
        if state_update.rowcount != 1 or sequence_update.rowcount != 1:
            raise _root_activation_error(
                "root activation state could not be committed"
            )
        connection.execute("COMMIT")
        receipt_result = receipt
    except Exception as error:
        primary_error = error
        rollback_error = _best_effort_rollback(connection)
        if rollback_error is not None:
            secondary_errors.append(
                _contextualize_secondary("rollback", rollback_error)
            )

    closed, close_errors = _close_with_retries(connection)
    if primary_error is not None:
        secondary_errors.extend(close_errors)
    if primary_error is None and closed:
        if receipt_result is None:
            cause = RuntimeError("root activation produced no receipt")
            raise _root_activation_error(
                "root activation failed atomically"
            ) from cause
        return receipt_result
    if (
        primary_error is None
        and receipt_result is not None
        and not closed
    ):
        raise RootActivationCommittedError(
            receipt_result
        ) from _error_cause(
            "root activation close failures",
            list(close_errors),
        )

    errors = (
        ([primary_error] if primary_error is not None else [])
        + secondary_errors
    )
    if (
        isinstance(primary_error, RootActivationError)
        and not secondary_errors
    ):
        raise primary_error
    raise _root_activation_error(
        "root activation failed atomically"
    ) from _error_cause("root activation failures", errors)


def _child_issuance_error(message: str) -> ChildGrantIssuanceError:
    return ChildGrantIssuanceError(message)


def _grant_revocation_error(message: str) -> GrantRevocationError:
    return GrantRevocationError(message)


def _root_contains(root: str, candidate: str) -> bool:
    return candidate == root or candidate.startswith(f"{root}/")


def _roots_within(
    candidates: tuple[str, ...],
    allowed: tuple[str, ...],
) -> bool:
    return all(
        any(_root_contains(root, candidate) for root in allowed)
        for candidate in candidates
    )


def _child_signing_binding(
    work_order: WorkOrder,
    candidate: CapabilityGrant,
):
    matches = tuple(
        binding
        for binding in work_order.key_bindings
        if binding.key_id == candidate.signer_key_id
    )
    if (
        len(matches) != 1
        or candidate.issuer_key_id != candidate.signer_key_id
    ):
        raise _child_issuance_error(
            "child Grant signer is not a unique WorkOrder identity"
        )
    return matches[0]


def _request_matches_candidate_issuer(
    request: AgentRequest,
    signing_binding,
) -> bool:
    return (
        request.actor_id == signing_binding.subject_id
        and request.actor_key_id == signing_binding.key_id
        and request.signer_key_id == signing_binding.key_id
    )


def _trusted_child_inputs(
    work_order: WorkOrder,
    parent: CapabilityGrant,
    candidate: CapabilityGrant,
    request: AgentRequest,
    sidecar_private_key: Ed25519PrivateKey,
    now: datetime,
):
    try:
        utc_now = _freeze_trusted_utc_second(now)
    except ValueError as error:
        raise _child_issuance_error(
            "child Grant input is malformed"
        ) from error
    if (
        not isinstance(candidate, CapabilityGrant)
        or not isinstance(request, AgentRequest)
        or not isinstance(sidecar_private_key, Ed25519PrivateKey)
    ):
        raise _child_issuance_error("child Grant input is malformed")

    bindings = {binding.role: binding for binding in work_order.key_bindings}
    sidecar = bindings["Sidecar"]
    signing_binding = _child_signing_binding(work_order, candidate)
    candidate_key = decode_and_verify_key_binding(signing_binding)
    candidate_json = candidate.model_dump(mode="json")
    if (
        candidate.work_order_digest != work_order.digest
        or candidate.parent_grant_id is None
        or candidate.parent_grant_id != parent.grant_id
        or not verify_payload(
            "capability-grant",
            candidate_json,
            candidate_key,
        )
        or key_id(sidecar_private_key.public_key()) != sidecar.key_id
        or not verify_nested_claim(request, work_order)
        or request.work_order_digest != work_order.digest
        or request.grant_id != parent.grant_id
        or request.tool_name != "owp.delegate_grant"
        or not _request_matches_candidate_issuer(
            request,
            signing_binding,
        )
    ):
        raise _child_issuance_error(
            "child Grant structure, signature, or identity is invalid"
        )

    arguments = {
        "operation": "delegate_child",
        "authorizing_grant_id": parent.grant_id,
        "candidate_grant_digest": candidate.digest,
    }
    if (
        request.arguments_digest
        != request_arguments_digest("owp.delegate_grant", arguments)
        or request.requested_at < work_order.issued_at
        or request.requested_at > work_order.deadline
        or utc_now < request.requested_at
        or (utc_now - request.requested_at).total_seconds() > 300
    ):
        raise _child_issuance_error(
            "child Grant request binding or freshness is invalid"
        )
    return signing_binding, bindings, utc_now


def _validate_receipt_nested_claim(
    receipt,
    work_order: WorkOrder,
) -> None:
    if receipt.actor_type in {"agent", "human"}:
        expected_type = (
            "agent-request"
            if receipt.actor_type == "agent"
            else "human-decision"
        )
        if (
            receipt.nested_claim_type != expected_type
            or not verify_nested_claim(
                receipt.nested_claim,
                work_order,
            )
        ):
            raise _child_issuance_error(
                "receipt nested signed claim failed verification"
            )
        return

    sidecar = {
        binding.role: binding for binding in work_order.key_bindings
    }["Sidecar"]
    claim = receipt.nested_claim
    if (
        receipt.actor_type != "sidecar"
        or receipt.nested_claim_type != "sidecar-event"
        or not isinstance(claim, SidecarEvent)
        or receipt.actor_id != sidecar.subject_id
        or receipt.actor_key_id != sidecar.key_id
        or claim.work_order_digest != work_order.digest
        or receipt.nested_claim_digest != claim.input_digest
    ):
        raise _child_issuance_error(
            "receipt nested Sidecar claim failed verification"
        )


def _bounded_rows(
    connection: sqlite3.Connection,
    *,
    count_sql: str,
    select_sql: str,
    parameters: tuple[object, ...] = (),
    cap: int,
    label: str,
):
    count_row = connection.execute(
        count_sql,
        parameters,
    ).fetchone()
    if (
        count_row is None
        or len(count_row) != 1
        or type(count_row[0]) is not int
        or count_row[0] < 0
        or count_row[0] > cap
    ):
        raise _child_issuance_error(
            f"{label} exceeds its bounded ledger capacity"
        )
    rows = connection.execute(
        f"{select_sql}\nLIMIT ?",
        (*parameters, cap + 1),
    ).fetchall()
    if len(rows) != count_row[0] or len(rows) > cap:
        raise _child_issuance_error(
            f"{label} changed during bounded ledger read"
        )
    return rows


def _bounded_input(values, *, cap: int, label: str):
    bounded = tuple(islice(values, cap + 1))
    if len(bounded) > cap:
        raise _child_issuance_error(
            f"{label} exceeds its bounded input capacity"
        )
    return bounded


def _derive_protocol_transaction_version(
    *,
    action_receipts,
    acceptance_receipts,
    acceptance_rejections=(),
) -> int:
    actions = tuple(action_receipts)
    acceptances = tuple(acceptance_receipts)
    rejections = tuple(acceptance_rejections)
    if (
        len(actions) > MAX_RECEIPTS
        or len(acceptances) > MAX_ACCEPTANCE_RECEIPTS
        or len(rejections) > MAX_ACCEPTANCE_REJECTION_RECEIPTS
        or any(
            not isinstance(receipt, ActionReceiptEnvelope)
            for receipt in actions
        )
        or any(
            not isinstance(receipt, AcceptanceReceipt)
            for receipt in acceptances
        )
        or any(
            not isinstance(receipt, AcceptanceRejectionReceipt)
            for receipt in rejections
        )
    ):
        raise _child_issuance_error(
            "protocol version inputs are not verified receipt models"
        )
    transactions = 0
    index = 0
    while index < len(actions):
        receipt = actions[index]
        compose_receipt = (
            isinstance(receipt, ToolCallReceipt)
            and receipt.tool_name == "owp.compose_proof"
        )
        if compose_receipt and (
            not isinstance(
                receipt.request_arguments,
                ComposeProofArguments,
            )
            or receipt.request_arguments.expected_state_version
            != transactions
        ):
            raise _child_issuance_error(
                "composition transaction preversion is invalid"
            )
        compose_initiator = (
            compose_receipt
            and receipt.policy_decision == "allow"
            and receipt.execution_status == "succeeded"
        )
        derived_trigger = (
            isinstance(receipt, SystemEventReceipt)
            and receipt.system_event_name
            in {"proof_composed", "security_violation"}
        )
        if derived_trigger:
            raise _child_issuance_error(
                "composition trigger has no adjacent initiator"
            )
        if not compose_initiator:
            transactions += 1
            index += 1
            continue
        if index + 1 >= len(actions):
            raise _child_issuance_error(
                "composition initiator has no adjacent trigger"
            )
        trigger = actions[index + 1]
        cause = (
            trigger.cause
            if isinstance(trigger, SystemEventReceipt)
            else None
        )
        if (
            not isinstance(trigger, SystemEventReceipt)
            or trigger.system_event_name
            not in {"proof_composed", "security_violation"}
            or not isinstance(cause, CompositionCause)
            or receipt.request_arguments.expected_state_version
            != cause.state_version_before
            or cause.state_version_before != transactions
            or cause.initiator_receipt_digest != receipt.digest
            or trigger.sequence != receipt.sequence + 1
            or trigger.previous_receipt_digest != receipt.digest
            or trigger.parent_receipt_ids != (receipt.receipt_id,)
            or trigger.work_order_digest != receipt.work_order_digest
            or trigger.state_before != receipt.state_after
            or trigger.occurred_at < receipt.occurred_at
        ):
            raise _child_issuance_error(
                "composition transaction binding is incomplete"
            )
        transactions += 1
        index += 2
    return transactions + len(acceptances) + len(rejections)


def _validated_acceptance_receipts(
    connection: sqlite3.Connection,
    work_order: WorkOrder,
) -> tuple[AcceptanceReceipt, ...]:
    rows = _bounded_rows(
        connection,
        count_sql="SELECT COUNT(*) FROM acceptance_receipts",
        select_sql="""
        SELECT acceptance_id, work_order_digest, acceptance_json
        FROM acceptance_receipts
        ORDER BY acceptance_id
        """,
        cap=MAX_ACCEPTANCE_RECEIPTS,
        label="Acceptance receipts",
    )
    acceptor = next(
        (
            binding
            for binding in work_order.key_bindings
            if binding.role == "Acceptor"
        ),
        None,
    )
    if acceptor is None:
        raise _child_issuance_error(
            "WorkOrder has no bound Acceptor"
        )
    acceptor_key = decode_and_verify_key_binding(acceptor)
    receipts = []
    for stored_id, stored_work_order, stored_json in rows:
        try:
            receipt = AcceptanceReceipt.model_validate_json(stored_json)
            canonical = _canonical_json(
                receipt.model_dump(mode="json")
            )
            receipt.validate_against_work_order(work_order)
        except Exception as error:
            raise _child_issuance_error(
                "Acceptance receipt row is malformed"
            ) from error
        if (
            stored_id != receipt.acceptance_id
            or stored_work_order != work_order.digest
            or receipt.work_order_digest != work_order.digest
            or stored_json != canonical
            or receipt.signer_key_id != acceptor.key_id
            or not verify_payload(
                "acceptance-receipt",
                receipt.model_dump(mode="json"),
                acceptor_key,
            )
        ):
            raise _child_issuance_error(
                "Acceptance receipt row failed integrity verification"
            )
        receipts.append(receipt)
    return tuple(receipts)


def _validated_acceptance_rejections(
    connection: sqlite3.Connection,
    work_order: WorkOrder,
) -> tuple[AcceptanceRejectionReceipt, ...]:
    rows = _bounded_rows(
        connection,
        count_sql="SELECT COUNT(*) FROM acceptance_rejection_receipts",
        select_sql="""
        SELECT
            rejection_id,
            work_order_digest,
            acceptance_request_receipt_id,
            rejection_json
        FROM acceptance_rejection_receipts
        ORDER BY rejection_id
        """,
        cap=MAX_ACCEPTANCE_REJECTION_RECEIPTS,
        label="Acceptance rejection receipts",
    )
    acceptor = next(
        (
            binding
            for binding in work_order.key_bindings
            if binding.role == "Acceptor"
        ),
        None,
    )
    if acceptor is None:
        raise _child_issuance_error(
            "WorkOrder has no bound Acceptor"
        )
    acceptor_key = decode_and_verify_key_binding(acceptor)
    rejections = []
    for (
        stored_id,
        stored_work_order,
        stored_request_id,
        stored_json,
    ) in rows:
        try:
            receipt = AcceptanceRejectionReceipt.model_validate_json(
                stored_json
            )
            canonical = _canonical_json(
                receipt.model_dump(mode="json")
            )
            receipt.validate_against_work_order(work_order)
        except Exception as error:
            raise _child_issuance_error(
                "Acceptance rejection row is malformed"
            ) from error
        if (
            stored_id != receipt.rejection_id
            or stored_work_order != work_order.digest
            or stored_request_id
            != receipt.acceptance_request_receipt_id
            or receipt.work_order_digest != work_order.digest
            or stored_json != canonical
            or receipt.signer_key_id != acceptor.key_id
            or not verify_payload(
                "acceptance-rejection-receipt",
                receipt.model_dump(mode="json"),
                acceptor_key,
            )
        ):
            raise _child_issuance_error(
                "Acceptance rejection row failed integrity verification"
            )
        rejections.append(receipt)
    return tuple(rejections)


def _validated_composition_reports(
    connection: sqlite3.Connection,
    work_order: WorkOrder,
) -> tuple[CompositionReport, ...]:
    receipts = _validated_receipt_prefix(
        connection,
        work_order,
        _validate_acceptance_suffix=False,
    )
    reports = _validated_composition_reports_for_receipts(
        connection,
        work_order,
        receipts,
    )
    acceptances = _validated_acceptance_receipts(connection, work_order)
    if acceptances:
        from openworkproof.acceptance import (  # noqa: PLC0415
            AcceptanceTransactionError,
            composition_report_digest,
            validate_acceptance_bindings,
        )

        matching = tuple(
            report
            for report in reports
            if composition_report_digest(report)
            == acceptances[0].composition_report_digest
        )
        try:
            if len(matching) != 1:
                raise AcceptanceTransactionError(
                    "acceptance has no unique composition report"
                )
            validate_acceptance_bindings(
                work_order=work_order,
                report=matching[0],
                receipts=receipts,
                acceptance_receipt=acceptances[0],
            )
        except AcceptanceTransactionError as error:
            raise _child_issuance_error(
                "acceptance suffix failed report binding"
            ) from error
    return reports


def _validated_composition_reports_for_receipts(
    connection: sqlite3.Connection,
    work_order: WorkOrder,
    receipts,
) -> tuple[CompositionReport, ...]:
    rows = _bounded_rows(
        connection,
        count_sql="SELECT COUNT(*) FROM composition_reports",
        select_sql="""
        SELECT
            report_digest,
            work_order_digest,
            initiator_receipt_id,
            initiator_receipt_digest,
            source_state_version,
            report_json
        FROM composition_reports
        ORDER BY source_state_version
        """,
        cap=MAX_RECEIPTS,
        label="Composition reports",
    )
    by_id = {receipt.receipt_id: receipt for receipt in receipts}
    reports = []
    for (
        stored_digest,
        stored_work_order,
        initiator_id,
        initiator_digest,
        stored_version,
        stored_json,
    ) in rows:
        try:
            report = CompositionReport.model_validate_json(stored_json)
            canonical = _canonical_json(report.model_dump(mode="json"))
            recomputed = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        except Exception as error:
            raise _child_issuance_error(
                "Composition report row is malformed"
            ) from error
        initiator = by_id.get(initiator_id)
        if (
            stored_digest != recomputed
            or stored_work_order != work_order.digest
            or report.work_order_digest != work_order.digest
            or stored_json != canonical
            or type(stored_version) is not int
            or stored_version < 0
            or initiator is None
            or initiator.digest != initiator_digest
            or report.initiator_receipt_id != initiator_id
            or report.initiator_receipt_digest != initiator_digest
        ):
            raise _child_issuance_error(
                "Composition report row failed integrity verification"
            )
        reports.append(report)
    return tuple(reports)


def _validated_receipt_prefix(
    connection: sqlite3.Connection,
    work_order: WorkOrder,
    *,
    _validate_acceptance_suffix: bool = True,
):
    rows = _bounded_rows(
        connection,
        count_sql="SELECT COUNT(*) FROM receipts",
        select_sql="""
        SELECT
            receipt_id,
            work_order_digest,
            nonce,
            sequence,
            previous_digest,
            receipt_json
        FROM receipts
        ORDER BY sequence
        """,
        cap=MAX_RECEIPTS,
        label="receipt history",
    )
    parent_rows = _bounded_rows(
        connection,
        count_sql="SELECT COUNT(*) FROM receipt_parents",
        select_sql="""
        SELECT child_receipt_id, parent_receipt_id
        FROM receipt_parents
        ORDER BY child_receipt_id, parent_receipt_id
        """,
        cap=MAX_RECEIPT_PARENT_EDGES,
        label="receipt parent edges",
    )
    sidecar = {
        binding.role: binding for binding in work_order.key_bindings
    }["Sidecar"]
    sidecar_key = decode_and_verify_key_binding(sidecar)
    receipts = []
    seen_ids: set[str] = set()
    previous_digest: str | None = None
    previous_time: datetime | None = None
    previous_state: str | None = None
    for expected_sequence, row in enumerate(rows, start=1):
        (
            stored_id,
            stored_work_order,
            stored_nonce,
            stored_sequence,
            stored_previous,
            stored_json,
        ) = row
        try:
            receipt = ACTION_RECEIPT_ADAPTER.validate_json(stored_json)
            canonical = _canonical_json(
                receipt.model_dump(mode="json")
            )
            receipt.validate_against_work_order(work_order)
            _validate_receipt_nested_claim(receipt, work_order)
        except Exception as error:
            raise _child_issuance_error(
                "receipt prefix contains a malformed receipt"
            ) from error
        if (
            stored_json != canonical
            or stored_id != receipt.receipt_id
            or stored_work_order != work_order.digest
            or stored_nonce != receipt.nonce
            or stored_sequence != receipt.sequence
            or stored_sequence != expected_sequence
            or stored_previous != receipt.previous_receipt_digest
            or stored_previous != previous_digest
            or not verify_payload(
                "action-receipt",
                receipt.model_dump(mode="json"),
                sidecar_key,
            )
        ):
            raise _child_issuance_error(
                "receipt prefix row or signature integrity failed"
            )
        parents = tuple(
            parent_id
            for child_id, parent_id in parent_rows
            if child_id == receipt.receipt_id
        )
        signed_parents = tuple(
            sorted(receipt.parent_receipt_ids)
        )
        if (
            parents != signed_parents
            or any(parent not in seen_ids for parent in parents)
            or (
                previous_time is not None
                and receipt.occurred_at < previous_time
            )
            or (
                previous_state is not None
                and receipt.state_before != previous_state
            )
        ):
            raise _child_issuance_error(
                "receipt prefix parent, time, or state integrity failed"
            )
        if expected_sequence == 1:
            root_valid = (
                isinstance(receipt, GrantIssuedReceipt)
                and receipt.parent_grant_id is None
                and receipt.policy_decision == "allow"
                and receipt.execution_status == "succeeded"
                and receipt.state_before == "issued"
                and receipt.state_after == "running"
            )
            if not root_valid:
                raise _child_issuance_error(
                    "receipt history does not begin with root activation"
                )
        elif (
            isinstance(receipt, GrantIssuedReceipt)
            and receipt.parent_grant_id is not None
            and receipt.state_before != receipt.state_after
        ):
            raise _child_issuance_error(
                "child Grant issuance receipt must be same-state"
            )
        seen_ids.add(receipt.receipt_id)
        previous_digest = receipt.digest
        previous_time = receipt.occurred_at
        previous_state = receipt.state_after
        receipts.append(receipt)
    if any(
        child_id not in seen_ids or parent_id not in seen_ids
        for child_id, parent_id in parent_rows
    ):
        raise _child_issuance_error(
            "receipt parent table points outside verified history"
        )
    counter = connection.execute(
        """
        SELECT next_sequence
        FROM sequence_counter
        WHERE singleton = 1
        """,
    ).fetchone()
    state_row = connection.execute(
        """
        SELECT current_state, version
        FROM work_order_state
        WHERE singleton = 1 AND work_order_digest = ?
        """,
        (work_order.digest,),
    ).fetchone()
    acceptance_receipts = _validated_acceptance_receipts(
        connection,
        work_order,
    )
    rejections = _validated_acceptance_rejections(
        connection,
        work_order,
    )
    expected_version = _derive_protocol_transaction_version(
        action_receipts=tuple(receipts),
        acceptance_receipts=acceptance_receipts,
        acceptance_rejections=rejections,
    )
    if acceptance_receipts or rejections:
        if (
            len(acceptance_receipts) > 1
            or len(rejections) > 1
            or (acceptance_receipts and rejections)
            or not receipts
            or receipts[-1].state_after != "awaiting_human"
        ):
            raise _child_issuance_error(
                "acceptance ledger suffix is malformed"
            )
        if _validate_acceptance_suffix:
            from openworkproof.acceptance import (  # noqa: PLC0415
                AcceptanceTransactionError,
                composition_report_digest,
                validate_acceptance_bindings,
                validate_rejection_bindings,
            )

            reports = _validated_composition_reports_for_receipts(
                connection,
                work_order,
                tuple(receipts),
            )
            if acceptance_receipts:
                matching = tuple(
                    report
                    for report in reports
                    if composition_report_digest(report)
                    == acceptance_receipts[0].composition_report_digest
                )
                try:
                    if len(matching) != 1:
                        raise AcceptanceTransactionError(
                            "acceptance has no unique composition report"
                        )
                    validate_acceptance_bindings(
                        work_order=work_order,
                        report=matching[0],
                        receipts=tuple(receipts),
                        acceptance_receipt=acceptance_receipts[0],
                    )
                except AcceptanceTransactionError as error:
                    raise _child_issuance_error(
                        "acceptance suffix failed authoritative binding"
                    ) from error
            else:
                matching = tuple(
                    report
                    for report in reports
                    if composition_report_digest(report)
                    == rejections[0].composition_report_digest
                )
                try:
                    if len(matching) != 1:
                        raise AcceptanceTransactionError(
                            "rejection has no unique composition report"
                        )
                    validate_rejection_bindings(
                        work_order=work_order,
                        report=matching[0],
                        receipts=tuple(receipts),
                        rejection=rejections[0],
                    )
                except AcceptanceTransactionError as error:
                    raise _child_issuance_error(
                        "rejection suffix failed authoritative binding"
                    ) from error
        expected_state = (
            ("accepted", expected_version)
            if acceptance_receipts
            else ("rejected", expected_version)
        )
    else:
        expected_state = (
            ("issued", 0)
            if not receipts
            else (receipts[-1].state_after, expected_version)
        )
    if (
        counter != (len(receipts) + 1,)
        or state_row != expected_state
    ):
        raise _child_issuance_error(
            "receipt history, sequence, and state row disagree"
        )
    return tuple(receipts)


def _validated_effective_grants(
    connection: sqlite3.Connection,
    work_order: WorkOrder,
    receipts,
) -> dict[str, CapabilityGrant]:
    issuance_receipts: dict[str, GrantIssuedReceipt] = {}
    for receipt in receipts:
        if not (
            isinstance(receipt, GrantIssuedReceipt)
            and receipt.policy_decision == "allow"
            and receipt.execution_status == "succeeded"
            and receipt.issued_grant_id is not None
        ):
            continue
        if receipt.issued_grant_id in issuance_receipts:
            raise _child_issuance_error(
                "effective Grant has duplicate successful issuance receipts"
            )
        issuance_receipts[receipt.issued_grant_id] = receipt
    bindings = {
        binding.role: binding for binding in work_order.key_bindings
    }
    rows = _bounded_rows(
        connection,
        count_sql="SELECT COUNT(*) FROM grants",
        select_sql="""
        SELECT
            grant_id,
            work_order_digest,
            parent_grant_id,
            subject_agent_id,
            usage_mode,
            grant_json
        FROM grants
        ORDER BY grant_id
        """,
        cap=MAX_EFFECTIVE_GRANTS,
        label="effective Grants",
    )
    grants: dict[str, CapabilityGrant] = {}
    for row in rows:
        (
            stored_id,
            stored_work_order,
            stored_parent,
            stored_subject,
            stored_usage,
            stored_json,
        ) = row
        try:
            grant = CapabilityGrant.model_validate_json(stored_json)
            canonical = _canonical_json(
                grant.model_dump(mode="json")
            )
        except Exception as error:
            raise _child_issuance_error(
                "effective Grant row is malformed"
            ) from error
        signing_binding = (
            bindings["Maintainer"]
            if grant.parent_grant_id is None
            else bindings["Manager"]
        )
        signing_key = decode_and_verify_key_binding(signing_binding)
        reservation = connection.execute(
            """
            SELECT
                work_order_digest,
                candidate_grant_digest,
                reservation_kind
            FROM grant_id_reservations
            WHERE grant_id = ?
            """,
            (grant.grant_id,),
        ).fetchone()
        receipt = issuance_receipts.get(grant.grant_id)
        if (
            stored_json != canonical
            or stored_id != grant.grant_id
            or stored_work_order != grant.work_order_digest
            or stored_work_order != work_order.digest
            or stored_parent != grant.parent_grant_id
            or stored_subject != grant.subject_agent_id
            or stored_usage != grant.usage_mode
            or grant.issuer_key_id != signing_binding.key_id
            or grant.signer_key_id != signing_binding.key_id
            or not verify_payload(
                "capability-grant",
                grant.model_dump(mode="json"),
                signing_key,
            )
            or reservation
            != (work_order.digest, grant.digest, "effective")
            or receipt is None
        ):
            raise _child_issuance_error(
                "effective Grant row failed integrity verification"
            )
        try:
            receipt.validate_candidate(grant)
        except Exception as error:
            raise _child_issuance_error(
                "effective Grant does not match its issuance receipt"
            ) from error
        if grant.parent_grant_id is None:
            manager = bindings["Manager"]
            expected = work_order.root_grant_template.model_dump(
                mode="json"
            )
            expected.update(
                {
                    "work_order_digest": work_order.digest,
                    "signature_alg": "Ed25519",
                    "signer_key_id": signing_binding.key_id,
                }
            )
            if (
                unsigned_payload(
                    grant.model_dump(mode="json")
                )
                != expected
                or grant.subject_agent_id != manager.subject_id
                or grant.subject_key_id != manager.key_id
            ):
                raise _child_issuance_error(
                    "effective root Grant is not WorkOrder-bound"
                )
        grants[grant.grant_id] = grant
    if set(grants) != set(issuance_receipts):
        raise _child_issuance_error(
            "effective Grants and issuance receipts disagree"
        )
    return grants


def _parse_attempt_candidate(stored_json: str) -> CapabilityGrant:
    try:
        raw = json.loads(stored_json)
        if type(raw) is not dict:
            raise ValueError("candidate Grant must be a JSON object")
        try:
            return CapabilityGrant.model_validate(raw)
        except Exception:
            if (
                raw.get("parent_grant_id") is None
                or raw.get("may_delegate") is not True
            ):
                raise
            structurally_valid = dict(raw)
            structurally_valid["may_delegate"] = False
            candidate = CapabilityGrant.model_validate(
                structurally_valid
            )
            return candidate.model_copy(
                update={"may_delegate": True}
            )
    except Exception as error:
        raise _child_issuance_error(
            "Grant attempt candidate is malformed"
        ) from error


def _validated_grant_attempts(
    connection: sqlite3.Connection,
    work_order: WorkOrder,
    receipts,
) -> dict[str, CapabilityGrant]:
    denial_receipts: dict[str, GrantIssuedReceipt] = {}
    for receipt in receipts:
        if not (
            isinstance(receipt, GrantIssuedReceipt)
            and receipt.policy_decision == "deny"
            and receipt.execution_status == "denied"
        ):
            continue
        if receipt.candidate_grant_digest in denial_receipts:
            raise _child_issuance_error(
                "signed Grant denial history is ambiguous"
            )
        denial_receipts[receipt.candidate_grant_digest] = receipt

    rows = _bounded_rows(
        connection,
        count_sql="SELECT COUNT(*) FROM grant_attempts",
        select_sql="""
        SELECT
            candidate_grant_digest,
            grant_id,
            work_order_digest,
            candidate_grant_json
        FROM grant_attempts
        ORDER BY candidate_grant_digest
        """,
        cap=MAX_GRANT_ATTEMPTS,
        label="Grant attempts",
    )
    attempts: dict[str, CapabilityGrant] = {}
    for (
        stored_digest,
        stored_grant_id,
        stored_work_order,
        stored_json,
    ) in rows:
        candidate = _parse_attempt_candidate(stored_json)
        canonical = _canonical_json(
            candidate.model_dump(mode="json")
        )
        signing_binding = _child_signing_binding(
            work_order,
            candidate,
        )
        signing_key = decode_and_verify_key_binding(signing_binding)
        reservation = connection.execute(
            """
            SELECT
                work_order_digest,
                candidate_grant_digest,
                reservation_kind
            FROM grant_id_reservations
            WHERE grant_id = ?
            """,
            (candidate.grant_id,),
        ).fetchone()
        receipt = denial_receipts.get(candidate.digest)
        if (
            stored_json != canonical
            or stored_digest != candidate.digest
            or stored_grant_id != candidate.grant_id
            or stored_work_order != candidate.work_order_digest
            or stored_work_order != work_order.digest
            or candidate.parent_grant_id is None
            or not verify_payload(
                "capability-grant",
                candidate.model_dump(mode="json"),
                signing_key,
            )
            or reservation
            != (work_order.digest, candidate.digest, "attempt")
            or receipt is None
            or receipt.actor_id != signing_binding.subject_id
            or receipt.actor_key_id != signing_binding.key_id
            or not _request_matches_candidate_issuer(
                receipt.nested_claim,
                signing_binding,
            )
        ):
            raise _child_issuance_error(
                "Grant attempt row failed integrity verification"
            )
        try:
            receipt.validate_candidate(candidate)
        except Exception as error:
            raise _child_issuance_error(
                "Grant attempt does not match its denial receipt"
            ) from error
        attempts[candidate.digest] = candidate
    if set(attempts) != set(denial_receipts):
        raise _child_issuance_error(
            "Grant attempts and signed denial history disagree"
        )
    reservation_rows = _bounded_rows(
        connection,
        count_sql="""
        SELECT COUNT(*)
        FROM grant_id_reservations
        WHERE reservation_kind = 'attempt'
        """,
        select_sql="""
        SELECT
            grant_id,
            work_order_digest,
            candidate_grant_digest
        FROM grant_id_reservations
        WHERE reservation_kind = 'attempt'
        ORDER BY grant_id
        """,
        cap=MAX_GRANT_ATTEMPTS,
        label="Grant attempt reservations",
    )
    reservations = {
        tuple(row) for row in reservation_rows
    }
    expected_reservations = {
        (
            candidate.grant_id,
            work_order.digest,
            candidate.digest,
        )
        for candidate in attempts.values()
    }
    if (
        len(reservations) != len(reservation_rows)
        or reservations != expected_reservations
    ):
        raise _child_issuance_error(
            "Grant attempt reservations are not closed"
        )
    return attempts


def _validate_grant_reservation_closure(
    connection: sqlite3.Connection,
    work_order: WorkOrder,
    grants: dict[str, CapabilityGrant],
    attempts: dict[str, CapabilityGrant],
) -> None:
    rows = _bounded_rows(
        connection,
        count_sql="SELECT COUNT(*) FROM grant_id_reservations",
        select_sql="""
        SELECT
            grant_id,
            work_order_digest,
            candidate_grant_digest,
            reservation_kind
        FROM grant_id_reservations
        ORDER BY grant_id
        """,
        cap=MAX_GRANT_RESERVATIONS,
        label="Grant reservations",
    )
    stored = {tuple(row) for row in rows}
    expected = {
        (
            grant.grant_id,
            work_order.digest,
            grant.digest,
            "effective",
        )
        for grant in grants.values()
    } | {
        (
            candidate.grant_id,
            work_order.digest,
            candidate.digest,
            "attempt",
        )
        for candidate in attempts.values()
    }
    if len(stored) != len(rows) or stored != expected:
        raise _child_issuance_error(
            "Grant reservation table is not fully closed"
        )


def _validate_grant_event_index(
    connection: sqlite3.Connection,
    receipts,
    grants: dict[str, CapabilityGrant],
) -> None:
    receipt_by_id = {
        receipt.receipt_id: receipt for receipt in receipts
    }
    event_rows = _bounded_rows(
        connection,
        count_sql="SELECT COUNT(*) FROM grant_events",
        select_sql="""
        SELECT event_id, receipt_id, grant_id, event_type, metric, amount
        FROM grant_events
        ORDER BY event_id
        """,
        cap=MAX_GRANT_EVENTS,
        label="Grant events",
    )
    seen_receipts: set[str] = set()
    for (
        event_id,
        receipt_id,
        grant_id,
        event_type,
        metric,
        amount,
    ) in event_rows:
        receipt = receipt_by_id.get(receipt_id)
        if receipt is None or receipt_id in seen_receipts:
            raise _child_issuance_error(
                "Grant event points outside the verified receipt prefix"
            )
        if (
            isinstance(receipt, GrantIssuedReceipt)
            and receipt.policy_decision == "allow"
            and receipt.execution_status == "succeeded"
        ):
            expected_event_id = hashlib.sha256(
                f"grant-issued:{receipt.receipt_id}".encode("ascii")
            ).hexdigest()
            valid = (
                event_id == expected_event_id
                and grant_id == receipt.issued_grant_id
                and grant_id in grants
                and event_type == "grant_issued"
                and metric is None
                and amount is None
            )
        else:
            charge = receipt.quota_charge
            valid = (
                charge is not None
                and grant_id == charge.grant_id
                and grant_id in grants
                and event_type == receipt.event_type
                and metric == charge.metric
                and amount == charge.amount
            )
        if not valid:
            raise _child_issuance_error(
                "Grant event disagrees with its signed receipt"
            )
        seen_receipts.add(receipt_id)
    expected_receipts = {
        receipt.receipt_id
        for receipt in receipts
        if (
            (
                isinstance(receipt, GrantIssuedReceipt)
                and receipt.policy_decision == "allow"
                and receipt.execution_status == "succeeded"
            )
            or receipt.quota_charge is not None
        )
    }
    if seen_receipts != expected_receipts:
        raise _child_issuance_error(
            "Grant event index is incomplete"
        )


def _authorization_public_keys_snapshot(
    work_order: WorkOrder,
    public_keys: Mapping[str, Ed25519PublicKey],
) -> dict[str, Ed25519PublicKey]:
    expected_key_ids = tuple(
        binding.key_id for binding in work_order.key_bindings
    )
    if (
        len(expected_key_ids) != 6
        or any(
            not isinstance(key_id_value, str)
            for key_id_value in expected_key_ids
        )
        or len(set(expected_key_ids)) != 6
    ):
        raise _child_issuance_error(
            "WorkOrder must bind exactly six unique public keys"
        )
    try:
        supplied_key_ids = tuple(
            islice(public_keys, len(expected_key_ids) + 1)
        )
    except Exception as error:
        raise _child_issuance_error(
            "authorization key iteration failed"
        ) from error
    if (
        len(supplied_key_ids) != len(expected_key_ids)
        or any(
            not isinstance(key_id_value, str)
            for key_id_value in supplied_key_ids
        )
        or len(set(supplied_key_ids)) != len(supplied_key_ids)
        or set(supplied_key_ids) != set(expected_key_ids)
    ):
        raise _child_issuance_error(
            "authorization key set must exactly match WorkOrder bindings"
        )
    snapshot: dict[str, Ed25519PublicKey] = {}
    for key_id_value in expected_key_ids:
        try:
            public_key = public_keys[key_id_value]
        except Exception as error:
            raise _child_issuance_error(
                "authorization public key access failed"
            ) from error
        if (
            not isinstance(public_key, Ed25519PublicKey)
            or key_id(public_key) != key_id_value
        ):
            raise _child_issuance_error(
                "authorization chain references an unknown public key"
            )
        snapshot[key_id_value] = public_key
    return snapshot


def _authorization_memory_ledger(
    work_order: WorkOrder,
    grants: tuple[CapabilityGrant, ...],
    attempts: tuple[CapabilityGrant, ...],
    receipts: tuple[ActionReceiptEnvelope, ...],
) -> sqlite3.Connection:
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(":memory:")
        connection.execute("PRAGMA foreign_keys = ON")
        _create_schema(connection)
        connection.execute(
            "INSERT INTO work_orders VALUES (?, ?)",
            (
                work_order.digest,
                _canonical_json(work_order.model_dump(mode="json")),
            ),
        )
        for grant, kind in (
            *((item, "effective") for item in grants),
            *((item, "attempt") for item in attempts),
        ):
            connection.execute(
                "INSERT INTO grant_id_reservations VALUES (?, ?, ?, ?)",
                (grant.grant_id, work_order.digest, grant.digest, kind),
            )
        for grant in sorted(
            grants,
            key=lambda item: item.parent_grant_id is not None,
        ):
            connection.execute(
                "INSERT INTO grants VALUES (?, ?, ?, ?, ?, ?)",
                (
                    grant.grant_id,
                    work_order.digest,
                    grant.parent_grant_id,
                    grant.subject_agent_id,
                    grant.usage_mode,
                    _canonical_json(grant.model_dump(mode="json")),
                ),
            )
        for candidate in attempts:
            connection.execute(
                "INSERT INTO grant_attempts VALUES (?, ?, ?, ?)",
                (
                    candidate.digest,
                    candidate.grant_id,
                    work_order.digest,
                    _canonical_json(candidate.model_dump(mode="json")),
                ),
            )
        for receipt in receipts:
            connection.execute(
                "INSERT INTO receipts VALUES (?, ?, ?, ?, ?, ?)",
                (
                    receipt.receipt_id,
                    work_order.digest,
                    receipt.nonce,
                    receipt.sequence,
                    receipt.previous_receipt_digest,
                    _canonical_json(receipt.model_dump(mode="json")),
                ),
            )
        for receipt in receipts:
            for parent_id in receipt.parent_receipt_ids:
                connection.execute(
                    "INSERT INTO receipt_parents VALUES (?, ?)",
                    (receipt.receipt_id, parent_id),
                )
            charge = receipt.quota_charge
            issued = (
                receipt.issued_grant_id
                if isinstance(receipt, GrantIssuedReceipt)
                and receipt.policy_decision == "allow"
                else None
            )
            if issued is not None or charge is not None:
                event_id = hashlib.sha256(
                    (
                        f"grant-issued:{receipt.receipt_id}"
                        if issued is not None
                        else f"grant-charge:{receipt.receipt_id}"
                    ).encode("ascii")
                ).hexdigest()
                connection.execute(
                    "INSERT INTO grant_events VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        event_id,
                        receipt.receipt_id,
                        (
                            issued
                            if issued is not None
                            else charge.grant_id
                        ),
                        (
                            "grant_issued"
                            if issued is not None
                            else receipt.event_type
                        ),
                        None if issued is not None else charge.metric,
                        None if issued is not None else charge.amount,
                    ),
                )
        version = _derive_protocol_transaction_version(
            action_receipts=receipts,
            acceptance_receipts=(),
        )
        connection.execute(
            "INSERT INTO sequence_counter VALUES (1, ?)",
            (len(receipts) + 1,),
        )
        connection.execute(
            "INSERT INTO work_order_state VALUES (1, ?, ?, ?)",
            (
                work_order.digest,
                receipts[-1].state_after if receipts else "issued",
                version,
            ),
        )
        return connection
    except Exception as primary_error:
        _, close_errors = _close_with_retries(connection)
        raise _child_issuance_error(
            "authorization memory ledger construction failed"
        ) from _error_cause(
            "authorization memory ledger construction failures",
            [primary_error, *close_errors],
        )


def _validate_authorization_system_events(
    work_order: WorkOrder,
    receipts: tuple[ActionReceiptEnvelope, ...],
) -> None:
    for receipt in receipts:
        if not (
            isinstance(receipt, SystemEventReceipt)
            and receipt.system_event_name == "contract_expired"
        ):
            continue
        cause = receipt.cause
        if (
            getattr(cause, "deadline", None) != work_order.deadline
            or getattr(cause, "observed_at", None) != receipt.occurred_at
            or getattr(cause, "tip_receipt_digest", None)
            != receipt.previous_receipt_digest
            or receipt.occurred_at <= work_order.deadline
        ):
            raise _child_issuance_error(
                "contract expiry failed historical replay"
            )


def validate_grant_chain(
    work_order: WorkOrder,
    grants: Iterable[CapabilityGrant],
    grant_attempts: Iterable[CapabilityGrant],
    receipts: Iterable[ActionReceiptEnvelope],
    public_keys: Mapping[str, Ed25519PublicKey],
) -> AuthorizationChainResult:
    """Validate an offline Sidecar-signed authorization assertion chain.

    The five-input API has no ResolutionManifest preimage bytes. Path replay
    therefore verifies the signed request/resolution assertion, its exact
    vector closure, and child-Grant scope; it does not independently rehash
    ResolutionManifest bytes.
    """

    connection: sqlite3.Connection | None = None
    result: AuthorizationChainResult | None = None
    primary_error: Exception | None = None
    try:
        if (
            not isinstance(work_order, WorkOrder)
            or not isinstance(public_keys, Mapping)
            or not verify_work_order_identity_bindings(work_order)
        ):
            raise ValueError("WorkOrder identity bindings are invalid")
        key_snapshot = _authorization_public_keys_snapshot(
            work_order,
            public_keys,
        )
        maintainer = work_order.key_bindings[0]
        if not verify_payload(
            "work-order",
            work_order.model_dump(mode="json"),
            key_snapshot[maintainer.key_id],
        ):
            raise ValueError("WorkOrder signature is invalid")
        supplied_grants = _bounded_input(
            grants,
            cap=MAX_EFFECTIVE_GRANTS,
            label="effective Grants",
        )
        supplied_attempts = _bounded_input(
            grant_attempts,
            cap=MAX_GRANT_ATTEMPTS,
            label="Grant attempts",
        )
        supplied_receipts = _bounded_input(
            receipts,
            cap=MAX_RECEIPTS,
            label="receipt history",
        )
        connection = _authorization_memory_ledger(
            work_order,
            supplied_grants,
            supplied_attempts,
            supplied_receipts,
        )
        validated_receipts = _validated_receipt_prefix(
            connection,
            work_order,
        )
        effective = _validated_effective_grants(
            connection,
            work_order,
            validated_receipts,
        )
        attempts = _validated_grant_attempts(
            connection,
            work_order,
            validated_receipts,
        )
        _validate_grant_reservation_closure(
            connection,
            work_order,
            effective,
            attempts,
        )
        try:
            causal_state = replay_authorization_causality(
                work_order,
                validated_receipts,
            )
            replay_authorization_policy(
                work_order,
                effective,
                attempts,
                validated_receipts,
                causal_state,
            )
        except AuthorizationCausalityError as error:
            raise _child_issuance_error(
                "receipt is denied by the frozen state machine"
            ) from error
        except AuthorizationPolicyError as error:
            message = (
                "PR approval failed historical replay"
                if "allowed tool failed" in str(error)
                else "receipt is denied by the frozen state machine"
                if "frozen state machine" in str(error)
                else "authorization policy failed historical replay"
            )
            raise _child_issuance_error(
                message
            ) from error
        _validate_authorization_system_events(
            work_order,
            validated_receipts,
        )
        _validate_grant_event_index(
            connection,
            validated_receipts,
            effective,
        )
        result = AuthorizationChainResult()
    except Exception as error:
        primary_error = error
    closed, close_errors = _close_with_retries(connection)
    if primary_error is None and closed:
        assert result is not None
        return result
    if (
        isinstance(primary_error, ChildGrantIssuanceError)
        and not close_errors
    ):
        raise primary_error
    errors = (
        ([] if primary_error is None else [primary_error])
        + list(close_errors)
    )
    raise _child_issuance_error(
        "authorization chain validation failed closed"
    ) from _error_cause(
        "authorization chain validation failures",
        errors,
    )


def _build_child_receipt(
    work_order: WorkOrder,
    candidate: CapabilityGrant,
    request: AgentRequest,
    sidecar_private_key: Ed25519PrivateKey,
    now: datetime,
    *,
    allowed: bool,
    policy_error_code: str | None,
    sequence: int,
    state: str,
    parent_receipt_ids: tuple[str, ...],
    tip_receipt_digest: str,
) -> GrantIssuedReceipt:
    occurred_at = (
        now.astimezone(timezone.utc)
        .replace(microsecond=0)
        .strftime("%Y-%m-%dT%H:%M:%SZ")
    )
    raw = {
        "protocol_version": "0.1",
        "receipt_id": _receipt_id(request, candidate),
        "work_order_digest": work_order.digest,
        "actor_type": "agent",
        "actor_id": request.actor_id,
        "actor_key_id": request.actor_key_id,
        "nested_claim_type": "agent-request",
        "nested_claim_digest": request.digest,
        "nested_claim": request.model_dump(mode="json"),
        "gateway_signer_key_id": key_id(sidecar_private_key.public_key()),
        "event_type": "grant_issued",
        "policy_decision": "allow" if allowed else "deny",
        "policy_error_code": None if allowed else policy_error_code,
        "execution_status": "succeeded" if allowed else "denied",
        "execution_error_code": None,
        "quota_charge": None,
        "state_before": state,
        "state_after": state,
        "parent_receipt_ids": list(parent_receipt_ids),
        "correlation_factors": None,
        "evidence_refs": [],
        "occurred_at": occurred_at,
        "sequence": sequence,
        "nonce": request.nonce,
        "previous_receipt_digest": tip_receipt_digest,
        "authorizing_grant_id": candidate.parent_grant_id,
        "candidate_grant_digest": candidate.digest,
        "parent_grant_id": candidate.parent_grant_id,
    }
    if allowed:
        raw["issued_grant_id"] = candidate.grant_id
    receipt = GrantIssuedReceipt.model_validate(
        sign_payload("action-receipt", raw, sidecar_private_key)
    )
    receipt.validate_against_work_order(work_order)
    receipt.validate_candidate(candidate)
    return receipt


def _load_effective_parent(
    grants: dict[str, CapabilityGrant],
    candidate: CapabilityGrant,
) -> CapabilityGrant:
    parent = grants.get(candidate.parent_grant_id)
    if parent is None:
        raise _child_issuance_error(
            "child Grant parent is not effective"
        )
    if parent.parent_grant_id is not None or not parent.may_delegate:
        raise _child_issuance_error(
            "child Grant parent cannot delegate"
        )
    return parent


def _tip_receipt(
    receipts,
):
    if not receipts:
        raise _child_issuance_error(
            "child Grant issuance requires an existing root receipt"
        )
    return receipts[-1]


def _confirm_committed_child_receipt(
    ledger_path: Path,
    expected: GrantIssuedReceipt,
) -> GrantIssuedReceipt | None:
    connection: sqlite3.Connection | None = None
    result: GrantIssuedReceipt | None = None
    try:
        connection = _connect_ledger_direct(ledger_path)
        connection.execute("BEGIN")
        work_order = load_authoritative_work_order(connection)
        receipts = _validated_receipt_prefix(connection, work_order)
        grants = _validated_effective_grants(
            connection,
            work_order,
            receipts,
        )
        attempts = _validated_grant_attempts(
            connection,
            work_order,
            receipts,
        )
        _validate_grant_reservation_closure(
            connection,
            work_order,
            grants,
            attempts,
        )
        _policy_history_replay(
            work_order,
            receipts,
            grants,
            attempts,
        )
        _validate_grant_event_index(connection, receipts, grants)
        matches = tuple(
            receipt
            for receipt in receipts
            if receipt.nonce == expected.nonce
        )
        if len(matches) != 1 or matches[0] != expected:
            raise LookupError(
                "committed receipt does not match the read snapshot"
            )
        receipt = matches[0]
        if receipt.issued_grant_id is not None:
            reservation_grant_id = receipt.issued_grant_id
        else:
            attempt = attempts.get(receipt.candidate_grant_digest)
            if attempt is None:
                raise LookupError(
                    "committed denial attempt is unavailable"
                )
            reservation_grant_id = attempt.grant_id
        reservation = connection.execute(
            """
            SELECT
                work_order_digest,
                candidate_grant_digest,
                reservation_kind
            FROM grant_id_reservations
            WHERE grant_id = ?
            """,
            (reservation_grant_id,),
        ).fetchone()
        expected_kind = (
            "effective"
            if receipt.policy_decision == "allow"
            else "attempt"
        )
        if reservation != (
            work_order.digest,
            receipt.candidate_grant_digest,
            expected_kind,
        ):
            raise LookupError(
                "committed receipt reservation is unavailable"
            )
        result = receipt
    except Exception:
        result = None
    finally:
        _best_effort_rollback(connection)
        _best_effort_close(connection)
    return result


def issue_child_grant(
    ledger_path: Path,
    candidate: CapabilityGrant,
    request: AgentRequest,
    *,
    sidecar_private_key: Ed25519PrivateKey,
    clock: Callable[[], datetime],
) -> GrantIssuedReceipt:
    """Atomically deny or issue one WorkOrder-bound child Grant candidate."""

    path = Path(ledger_path)
    if not path.is_file():
        cause = FileNotFoundError(f"ledger is unavailable: {path}")
        raise _child_issuance_error(
            "child Grant ledger is unavailable"
        ) from cause
    connection: sqlite3.Connection | None = None
    receipt_result: GrantIssuedReceipt | None = None
    primary_error: Exception | None = None
    secondary_errors: list[Exception] = []
    try:
        try:
            connection = connect_ledger(path)
        except Exception as error:
            raise _child_issuance_error(
                "child Grant ledger could not be opened"
            ) from error
        connection.execute("BEGIN IMMEDIATE")
        try:
            work_order = load_authoritative_work_order(connection)
        except LedgerInitializationError as error:
            raise _child_issuance_error(
                "authoritative WorkOrder is unavailable"
            ) from error
        receipts = _validated_receipt_prefix(
            connection,
            work_order,
        )
        effective_grants = _validated_effective_grants(
            connection,
            work_order,
            receipts,
        )
        grant_attempts = _validated_grant_attempts(
            connection,
            work_order,
            receipts,
        )
        _validate_grant_reservation_closure(
            connection,
            work_order,
            effective_grants,
            grant_attempts,
        )
        grant_states = _policy_history_replay(
            work_order,
            receipts,
            effective_grants,
            grant_attempts,
        )
        _validate_grant_event_index(
            connection,
            receipts,
            effective_grants,
        )
        if len(receipts) >= MAX_ROUTINE_ACTION_RECEIPTS:
            raise _child_issuance_error(
                "routine child Grant receipt capacity is exhausted"
            )
        parent = _load_effective_parent(
            effective_grants,
            candidate,
        )
        now = clock()
        signing_binding, bindings, utc_now = _trusted_child_inputs(
            work_order,
            parent,
            candidate,
            request,
            sidecar_private_key,
            now,
        )
        tip = _tip_receipt(receipts)
        if utc_now < tip.occurred_at:
            raise _child_issuance_error(
                "child receipt time precedes the verified chain tip"
            )
        state_row = connection.execute(
            """
            SELECT current_state, version
            FROM work_order_state
            WHERE singleton = 1 AND work_order_digest = ?
            """,
            (work_order.digest,),
        ).fetchone()
        sequence_row = connection.execute(
            """
            SELECT next_sequence
            FROM sequence_counter
            WHERE singleton = 1
            """
        ).fetchone()
        if state_row is None or sequence_row is None:
            raise _child_issuance_error(
                "child Grant ledger state is unavailable"
            )
        current_state, current_version = state_row
        sequence = sequence_row[0]
        if current_state != "running":
            raise _child_issuance_error(
                "child Grant issuance is unavailable in current state"
            )
        allowed, policy_error_code = _policy_child_decision(
            work_order,
            parent,
            grant_states.get(parent.grant_id),
            candidate,
            request,
            signing_binding,
            bindings,
            utc_now,
            state_allowed=True,
        )
        kind = "effective" if allowed else "attempt"
        count = (
            len(effective_grants)
            if allowed
            else len(grant_attempts)
        )
        if count >= 8:
            raise _child_issuance_error(
                f"child Grant {kind} capacity is exhausted"
            )
        tip_receipt_digest = tip.digest
        authorizing_issuance = _successful_issuance_for(
            receipts,
            parent.grant_id,
        )
        parent_receipt_ids = (authorizing_issuance.receipt_id,)
        receipt = _build_child_receipt(
            work_order,
            candidate,
            request,
            sidecar_private_key,
            utc_now,
            allowed=allowed,
            policy_error_code=policy_error_code,
            sequence=sequence,
            state=current_state,
            parent_receipt_ids=parent_receipt_ids,
            tip_receipt_digest=tip_receipt_digest,
        )
        receipt_result = receipt
        try:
            connection.execute(
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
                    candidate.grant_id,
                    work_order.digest,
                    candidate.digest,
                    kind,
                ),
            )
        except sqlite3.IntegrityError as error:
            raise _child_issuance_error(
                "child Grant identity is permanently reserved"
            ) from error
        candidate_json = _canonical_json(
            candidate.model_dump(mode="json")
        )
        if allowed:
            connection.execute(
                """
                INSERT INTO grants (
                    grant_id,
                    work_order_digest,
                    parent_grant_id,
                    subject_agent_id,
                    usage_mode,
                    grant_json
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    candidate.grant_id,
                    work_order.digest,
                    parent.grant_id,
                    candidate.subject_agent_id,
                    candidate.usage_mode,
                    candidate_json,
                ),
            )
        else:
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
                    candidate.digest,
                    candidate.grant_id,
                    work_order.digest,
                    candidate_json,
                ),
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
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                receipt.receipt_id,
                work_order.digest,
                request.nonce,
                sequence,
                tip_receipt_digest,
                _canonical_json(receipt.model_dump(mode="json")),
            ),
        )
        for parent_receipt_id in parent_receipt_ids:
            connection.execute(
                """
                INSERT INTO receipt_parents (
                    child_receipt_id,
                    parent_receipt_id
                )
                VALUES (?, ?)
                """,
                (receipt.receipt_id, parent_receipt_id),
            )
        if allowed:
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
                            f"{receipt.receipt_id}"
                        ).encode("ascii")
                    ).hexdigest(),
                    receipt.receipt_id,
                    candidate.grant_id,
                ),
            )
        state_update = connection.execute(
            """
            UPDATE work_order_state
            SET version = version + 1
            WHERE singleton = 1
              AND work_order_digest = ?
              AND current_state = ?
              AND version = ?
            """,
            (
                work_order.digest,
                current_state,
                current_version,
            ),
        )
        sequence_update = connection.execute(
            """
            UPDATE sequence_counter
            SET next_sequence = next_sequence + 1
            WHERE singleton = 1 AND next_sequence = ?
            """,
            (sequence,),
        )
        if state_update.rowcount != 1 or sequence_update.rowcount != 1:
            raise _child_issuance_error(
                "child Grant ledger counters could not be advanced"
            )
        connection.execute("COMMIT")
    except Exception as error:
        primary_error = error
        rollback_error = _best_effort_rollback(connection)
        if rollback_error is not None:
            secondary_errors.append(
                _contextualize_secondary("rollback", rollback_error)
            )

    closed, close_errors = _close_with_retries(connection)
    if primary_error is not None:
        secondary_errors.extend(close_errors)
    if primary_error is None and closed:
        if receipt_result is None:
            cause = RuntimeError("child Grant issuance produced no receipt")
            raise _child_issuance_error(
                "child Grant issuance failed atomically"
            ) from cause
        return receipt_result
    committed_receipt = (
        _confirm_committed_child_receipt(path, receipt_result)
        if receipt_result is not None
        else None
    )
    errors = (
        ([primary_error] if primary_error is not None else [])
        + secondary_errors
        + ([] if primary_error is not None else list(close_errors))
    )
    if committed_receipt is not None:
        raise ChildGrantIssuanceCommittedError(
            committed_receipt
        ) from _error_cause(
            "child Grant committed completion failures",
            errors,
        )
    if (
        isinstance(primary_error, ChildGrantIssuanceError)
        and not secondary_errors
    ):
        raise primary_error
    raise _child_issuance_error(
        "child Grant issuance failed atomically"
    ) from _error_cause("child Grant issuance failures", errors)


def _build_revocation_receipt(
    work_order: WorkOrder,
    request: AgentRequest,
    sidecar_private_key: Ed25519PrivateKey,
    now: datetime,
    *,
    authorizing_grant_id: str,
    revoked_grant_id: str,
    revocation_reason: str,
    sequence: int,
    state: str,
    parent_receipt_ids: tuple[str, ...],
    tip_receipt_digest: str,
) -> GrantRevokedReceipt:
    occurred_at = (
        now.astimezone(timezone.utc)
        .replace(microsecond=0)
        .strftime("%Y-%m-%dT%H:%M:%SZ")
    )
    receipt_id = hashlib.sha256(
        rfc8785.dumps(
            {
                "domain": "openworkproof/receipt-id/v0.1",
                "request_digest": request.digest,
                "revoked_grant_id": revoked_grant_id,
                "entropy": secrets.token_hex(32),
            }
        )
    ).hexdigest()
    raw = {
        "protocol_version": "0.1",
        "receipt_id": receipt_id,
        "work_order_digest": work_order.digest,
        "actor_type": "agent",
        "actor_id": request.actor_id,
        "actor_key_id": request.actor_key_id,
        "nested_claim_type": "agent-request",
        "nested_claim_digest": request.digest,
        "nested_claim": request.model_dump(mode="json"),
        "gateway_signer_key_id": key_id(sidecar_private_key.public_key()),
        "event_type": "grant_revoked",
        "policy_decision": "allow",
        "policy_error_code": None,
        "execution_status": "succeeded",
        "execution_error_code": None,
        "quota_charge": None,
        "state_before": state,
        "state_after": state,
        "parent_receipt_ids": list(parent_receipt_ids),
        "correlation_factors": None,
        "evidence_refs": [],
        "occurred_at": occurred_at,
        "sequence": sequence,
        "nonce": request.nonce,
        "previous_receipt_digest": tip_receipt_digest,
        "authorizing_grant_id": authorizing_grant_id,
        "revoked_grant_id": revoked_grant_id,
        "revocation_reason": revocation_reason,
    }
    receipt = GrantRevokedReceipt.model_validate(
        sign_payload("action-receipt", raw, sidecar_private_key)
    )
    receipt.validate_against_work_order(work_order)
    return receipt


def _confirm_committed_revocation_receipt(
    ledger_path: Path,
    expected: GrantRevokedReceipt,
) -> GrantRevokedReceipt | None:
    connection: sqlite3.Connection | None = None
    result: GrantRevokedReceipt | None = None
    try:
        connection = _connect_ledger_direct(ledger_path)
        connection.execute("BEGIN")
        work_order = load_authoritative_work_order(connection)
        receipts = _validated_receipt_prefix(connection, work_order)
        grants = _validated_effective_grants(
            connection,
            work_order,
            receipts,
        )
        attempts = _validated_grant_attempts(
            connection,
            work_order,
            receipts,
        )
        _validate_grant_reservation_closure(
            connection,
            work_order,
            grants,
            attempts,
        )
        _policy_history_replay(
            work_order,
            receipts,
            grants,
            attempts,
        )
        _validate_grant_event_index(connection, receipts, grants)
        matches = tuple(
            receipt
            for receipt in receipts
            if receipt.nonce == expected.nonce
        )
        if len(matches) == 1 and matches[0] == expected:
            result = expected
    except Exception:
        result = None
    finally:
        _best_effort_rollback(connection)
        _best_effort_close(connection)
    return result


def revoke_child_grant(
    ledger_path: Path,
    *,
    authorizing_grant_id: str,
    revoked_grant_id: str,
    revocation_reason: str,
    request: AgentRequest,
    sidecar_private_key: Ed25519PrivateKey,
    clock: Callable[[], datetime],
) -> GrantRevokedReceipt:
    """Atomically revoke one effective direct child Grant."""

    path = Path(ledger_path)
    if not path.is_file():
        cause = FileNotFoundError(f"ledger is unavailable: {path}")
        raise _grant_revocation_error(
            "Grant revocation ledger is unavailable"
        ) from cause
    connection: sqlite3.Connection | None = None
    receipt_result: GrantRevokedReceipt | None = None
    primary_error: Exception | None = None
    secondary_errors: list[Exception] = []
    try:
        try:
            connection = connect_ledger(path)
        except Exception as error:
            raise _grant_revocation_error(
                "Grant revocation ledger could not be opened"
            ) from error
        connection.execute("BEGIN IMMEDIATE")
        try:
            work_order = load_authoritative_work_order(connection)
        except LedgerInitializationError as error:
            raise _grant_revocation_error(
                "authoritative WorkOrder is unavailable"
            ) from error
        try:
            receipts = _validated_receipt_prefix(
                connection,
                work_order,
            )
            effective_grants = _validated_effective_grants(
                connection,
                work_order,
                receipts,
            )
            grant_attempts = _validated_grant_attempts(
                connection,
                work_order,
                receipts,
            )
            _validate_grant_reservation_closure(
                connection,
                work_order,
                effective_grants,
                grant_attempts,
            )
            _policy_history_replay(
                work_order,
                receipts,
                effective_grants,
                grant_attempts,
            )
            _validate_grant_event_index(
                connection,
                receipts,
                effective_grants,
            )
        except ChildGrantIssuanceError as error:
            raise _grant_revocation_error(
                "Grant revocation ledger history is invalid"
            ) from error
        if len(receipts) >= MAX_ROUTINE_ACTION_RECEIPTS:
            raise _grant_revocation_error(
                "routine Grant revocation receipt capacity is exhausted"
            )
        if any(receipt.nonce == request.nonce for receipt in receipts):
            raise _grant_revocation_error(
                "Grant revocation nonce is already committed"
            )
        authorizer = effective_grants.get(authorizing_grant_id)
        target = effective_grants.get(revoked_grant_id)
        if (
            authorizer is None
            or authorizer.parent_grant_id is not None
            or target is None
            or target.parent_grant_id != authorizer.grant_id
            or any(
                isinstance(receipt, GrantRevokedReceipt)
                and receipt.revoked_grant_id == revoked_grant_id
                for receipt in receipts
            )
        ):
            raise _grant_revocation_error(
                "Grant revocation target is not an active direct child"
            )
        if (
            type(authorizing_grant_id) is not str
            or type(revoked_grant_id) is not str
            or revocation_reason
            not in {"LEAST_PRIVILEGE", "SUPERSEDED", "WORK_STOPPED"}
            or not isinstance(request, AgentRequest)
            or not isinstance(sidecar_private_key, Ed25519PrivateKey)
        ):
            raise _grant_revocation_error(
                "Grant revocation input is malformed"
            )
        try:
            utc_now = _freeze_trusted_utc_second(clock())
        except Exception as error:
            raise _grant_revocation_error(
                "Grant revocation trusted clock is invalid"
            ) from error
        bindings = {
            binding.role: binding for binding in work_order.key_bindings
        }
        manager = bindings["Manager"]
        sidecar = bindings["Sidecar"]
        arguments = {
            "authorizing_grant_id": authorizing_grant_id,
            "revoked_grant_id": revoked_grant_id,
            "revocation_reason": revocation_reason,
        }
        if (
            authorizer.subject_agent_id != manager.subject_id
            or authorizer.subject_key_id != manager.key_id
            or key_id(sidecar_private_key.public_key()) != sidecar.key_id
            or not verify_nested_claim(request, work_order)
            or request.work_order_digest != work_order.digest
            or request.grant_id != authorizing_grant_id
            or request.actor_id != manager.subject_id
            or request.actor_key_id != manager.key_id
            or request.signer_key_id != manager.key_id
            or request.tool_name != "owp.revoke_grant"
            or request.arguments_digest
            != request_arguments_digest("owp.revoke_grant", arguments)
            or request.requested_at < work_order.issued_at
            or request.requested_at > work_order.deadline
            or utc_now < request.requested_at
            or (utc_now - request.requested_at).total_seconds() > 300
            or utc_now < authorizer.valid_from
            or utc_now > authorizer.expires_at
        ):
            raise _grant_revocation_error(
                "Grant revocation request binding is invalid"
            )
        tip = _tip_receipt(receipts)
        if utc_now < tip.occurred_at:
            raise _grant_revocation_error(
                "Grant revocation time precedes the verified chain tip"
            )
        state_row = connection.execute(
            """
            SELECT current_state, version
            FROM work_order_state
            WHERE singleton = 1 AND work_order_digest = ?
            """,
            (work_order.digest,),
        ).fetchone()
        sequence_row = connection.execute(
            """
            SELECT next_sequence
            FROM sequence_counter
            WHERE singleton = 1
            """
        ).fetchone()
        if state_row is None or sequence_row is None:
            raise _grant_revocation_error(
                "Grant revocation ledger state is unavailable"
            )
        current_state, current_version = state_row
        sequence = sequence_row[0]
        if current_state != "running":
            raise _grant_revocation_error(
                "Grant revocation is unavailable in current state"
            )
        parent_receipts = sorted(
            (
                _successful_issuance_for(
                    receipts,
                    authorizing_grant_id,
                ),
                _successful_issuance_for(
                    receipts,
                    revoked_grant_id,
                ),
            ),
            key=lambda item: item.sequence,
        )
        parent_receipt_ids = tuple(
            item.receipt_id for item in parent_receipts
        )
        receipt = _build_revocation_receipt(
            work_order,
            request,
            sidecar_private_key,
            utc_now,
            authorizing_grant_id=authorizing_grant_id,
            revoked_grant_id=revoked_grant_id,
            revocation_reason=revocation_reason,
            sequence=sequence,
            state=current_state,
            parent_receipt_ids=parent_receipt_ids,
            tip_receipt_digest=tip.digest,
        )
        receipt_result = receipt
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
                work_order.digest,
                request.nonce,
                sequence,
                tip.digest,
                _canonical_json(receipt.model_dump(mode="json")),
            ),
        )
        for parent_receipt_id in parent_receipt_ids:
            connection.execute(
                """
                INSERT INTO receipt_parents (
                    child_receipt_id,
                    parent_receipt_id
                )
                VALUES (?, ?)
                """,
                (receipt.receipt_id, parent_receipt_id),
            )
        state_update = connection.execute(
            """
            UPDATE work_order_state
            SET version = version + 1
            WHERE singleton = 1
              AND work_order_digest = ?
              AND current_state = ?
              AND version = ?
            """,
            (
                work_order.digest,
                current_state,
                current_version,
            ),
        )
        sequence_update = connection.execute(
            """
            UPDATE sequence_counter
            SET next_sequence = next_sequence + 1
            WHERE singleton = 1 AND next_sequence = ?
            """,
            (sequence,),
        )
        if state_update.rowcount != 1 or sequence_update.rowcount != 1:
            raise _grant_revocation_error(
                "Grant revocation ledger counters could not be advanced"
            )
        connection.execute("COMMIT")
    except Exception as error:
        primary_error = error
        rollback_error = _best_effort_rollback(connection)
        if rollback_error is not None:
            secondary_errors.append(
                _contextualize_secondary("rollback", rollback_error)
            )

    closed, close_errors = _close_with_retries(connection)
    if primary_error is not None:
        secondary_errors.extend(close_errors)
    if primary_error is None and closed:
        if receipt_result is None:
            cause = RuntimeError("Grant revocation produced no receipt")
            raise _grant_revocation_error(
                "Grant revocation failed atomically"
            ) from cause
        return receipt_result
    committed_receipt = (
        _confirm_committed_revocation_receipt(path, receipt_result)
        if receipt_result is not None
        else None
    )
    errors = (
        ([primary_error] if primary_error is not None else [])
        + secondary_errors
        + ([] if primary_error is not None else list(close_errors))
    )
    if committed_receipt is not None:
        raise GrantRevocationCommittedError(
            committed_receipt
        ) from _error_cause(
            "Grant revocation committed completion failures",
            errors,
        )
    if (
        isinstance(primary_error, GrantRevocationError)
        and not secondary_errors
    ):
        raise primary_error
    raise _grant_revocation_error(
        "Grant revocation failed atomically"
    ) from _error_cause("Grant revocation failures", errors)


def _retry_error(message: str) -> RetryConsumptionError:
    return RetryConsumptionError(message)


@dataclass(frozen=True)
class _ReworkEpisode:
    root_issuance: GrantIssuedReceipt
    failure: ToolCallReceipt
    rollback: RollbackReceipt
    target_patch: ToolCallReceipt


@dataclass(frozen=True)
class _RetryEpisode:
    root_issuance: GrantIssuedReceipt
    failure: ToolCallReceipt
    rollback: RollbackReceipt
    target_patch: ToolCallReceipt
    patch_result: PatchResultEvidence


def _receipt_by_id(receipts) -> dict[str, ActionReceiptEnvelope]:
    return {receipt.receipt_id: receipt for receipt in receipts}


def _successful_issuance_for(
    receipts,
    grant_id: str,
) -> GrantIssuedReceipt:
    matches = tuple(
        receipt
        for receipt in receipts
        if (
            isinstance(receipt, GrantIssuedReceipt)
            and receipt.policy_decision == "allow"
            and receipt.execution_status == "succeeded"
            and receipt.issued_grant_id == grant_id
        )
    )
    if len(matches) != 1:
        raise RetryEvidenceIntegrityError(
            "retry episode Grant issuance is ambiguous"
        )
    return matches[0]


def _reconstruct_rework_episode(
    *,
    work_order: WorkOrder,
    receipts,
    grants: dict[str, CapabilityGrant],
    current_state: str,
    retry_receipt: GrantConsumedReceipt | None = None,
    rollback_candidate: RollbackReceipt | None = None,
) -> _ReworkEpisode:
    by_id = _receipt_by_id(receipts)
    root_matches = tuple(
        receipt
        for receipt in receipts
        if (
            isinstance(receipt, GrantIssuedReceipt)
            and receipt.parent_grant_id is None
            and receipt.policy_decision == "allow"
            and receipt.execution_status == "succeeded"
        )
    )
    if len(root_matches) != 1:
        raise RetryEvidenceIntegrityError(
            "retry root issuance is unavailable"
        )
    failures = tuple(
        receipt
        for receipt in receipts
        if (
            isinstance(receipt, ToolCallReceipt)
            and receipt.tool_name == "owp.run_tests"
            and receipt.policy_decision == "allow"
            and receipt.execution_status == "succeeded"
            and receipt.state_before in {"running", "retrying"}
            and receipt.state_after == "needs_rework"
        )
    )
    if not failures:
        raise RetryEvidenceIntegrityError(
            "retry episode failure is unavailable"
        )
    failure = failures[-1]
    try:
        failure.validate_predicates_against(work_order)
    except ValueError as error:
        raise RetryEvidenceIntegrityError(
            "retry failure predicates do not match the WorkOrder"
        ) from error
    postcondition_ids = {
        spec.predicate_id
        for spec in work_order.postconditions
        if failure.tool_name in spec.applies_to_tools
    }
    if not any(
        result.predicate_id in postcondition_ids
        and not result.passed
        and result.error_code == "PREDICATE_FALSE"
        for result in failure.predicate_results
    ):
        raise RetryEvidenceIntegrityError(
            "retry failure has no false Verifier postcondition"
        )
    verifier_grant = grants.get(failure.grant_id)
    verifier_issuance = _successful_issuance_for(
        receipts,
        failure.grant_id,
    )
    parent_receipts = tuple(
        by_id.get(parent_id) for parent_id in failure.parent_receipt_ids
    )
    patch_matches = tuple(
        receipt
        for receipt in parent_receipts
        if (
            isinstance(receipt, ToolCallReceipt)
            and receipt.tool_name == "owp.apply_patch"
            and receipt.policy_decision == "allow"
            and receipt.execution_status == "succeeded"
        )
    )
    if (
        verifier_grant is None
        or verifier_grant.subject_agent_id != failure.actor_id
        or verifier_grant.subject_key_id != failure.actor_key_id
        or len(patch_matches) != 1
        or failure.parent_receipt_ids
        != (
            verifier_issuance.receipt_id,
            patch_matches[0].receipt_id,
        )
    ):
        raise RetryEvidenceIntegrityError(
            "retry episode failure DAG is invalid or ambiguous"
        )
    target_patch = patch_matches[0]
    episode_end = (
        retry_receipt.sequence if retry_receipt is not None else None
    )
    rollback_source = (
        receipts if rollback_candidate is None else (rollback_candidate,)
    )
    permitted_results = (
        {"succeeded"}
        if rollback_candidate is None
        else {"succeeded", "failed"}
    )
    rollbacks = tuple(
        receipt
        for receipt in rollback_source
        if (
            isinstance(receipt, RollbackReceipt)
            and receipt.sequence > failure.sequence
            and (
                episode_end is None
                or receipt.sequence < episode_end
            )
            and receipt.policy_decision == "allow"
            and receipt.execution_status in permitted_results
            and receipt.target_patch_receipt_id
            == target_patch.receipt_id
            and receipt.target_patch_digest == target_patch.digest
        )
    )
    if len(rollbacks) != 1:
        raise RetryEvidenceIntegrityError(
            "retry episode rollback is unavailable or ambiguous"
        )
    rollback = rollbacks[0]
    developer_grant = grants.get(rollback.grant_id)
    developer_issuance = _successful_issuance_for(
        receipts,
        rollback.grant_id,
    )
    expected_rollback_parents = (
        developer_issuance.receipt_id,
        target_patch.receipt_id,
        failure.receipt_id,
    )
    if (
        developer_grant is None
        or developer_grant.subject_agent_id != rollback.actor_id
        or developer_grant.subject_key_id != rollback.actor_key_id
        or rollback.parent_receipt_ids != expected_rollback_parents
        or rollback.state_before != "needs_rework"
        or rollback.state_after != "needs_rework"
    ):
        raise RetryEvidenceIntegrityError(
            "retry episode rollback DAG is invalid"
        )
    tail = tuple(
        receipt
        for receipt in receipts
        if failure.sequence < receipt.sequence
        and (
            retry_receipt is None
            or receipt.sequence < retry_receipt.sequence
        )
    )
    if (
        retry_receipt is not None or current_state == "needs_rework"
    ) and any(receipt.state_after != "needs_rework" for receipt in tail):
        raise RetryEvidenceIntegrityError(
            "retry episode is not the current immutable episode"
    )
    if retry_receipt is not None:
        quota_charge = retry_receipt.quota_charge
        retry_issuance = _successful_issuance_for(
            receipts,
            retry_receipt.grant_id,
        )
        expected_retry_parents = tuple(
            receipt.receipt_id
            for receipt in sorted(
                (retry_issuance, failure, rollback),
                key=lambda receipt: receipt.sequence,
            )
        )
        if (
            retry_receipt.state_before != "needs_rework"
            or retry_receipt.state_after != "retrying"
            or retry_receipt.policy_decision != "allow"
            or retry_receipt.execution_status != "succeeded"
            or retry_receipt.metric != "repair_rounds"
            or retry_receipt.amount != 1
            or quota_charge is None
            or quota_charge.grant_id != retry_receipt.grant_id
            or quota_charge.metric != "repair_rounds"
            or quota_charge.amount != 1
            or retry_receipt.parent_receipt_ids
            != expected_retry_parents
        ):
            raise RetryEvidenceIntegrityError(
                "retry charge is not bound to the reconstructed episode"
            )
    return _ReworkEpisode(
        root_issuance=root_matches[0],
        failure=failure,
        rollback=rollback,
        target_patch=target_patch,
    )


def _close_evidence_descriptors(descriptors: list[int]) -> None:
    errors: list[Exception] = []
    for descriptor in reversed(descriptors):
        try:
            os.close(descriptor)
        except OSError as error:
            errors.append(error)
    if errors:
        raise _error_cause(
            "evidence descriptor close failures",
            errors,
        )


def _open_evidence_chain(
    root: Path,
    parts: tuple[str, ...],
    *,
    expected_size: int,
) -> tuple[list[int], tuple[tuple[int, int, int, int, int | None], ...]]:
    common_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    directory_flags = common_flags | getattr(os, "O_DIRECTORY", 0)
    descriptors: list[int] = []
    identities: list[tuple[int, int, int, int, int | None]] = []
    try:
        current_descriptor = os.open(root, directory_flags)
        descriptors.append(current_descriptor)
        for part in parts[:-1]:
            metadata = os.fstat(current_descriptor)
            if not stat.S_ISDIR(metadata.st_mode):
                raise OSError("evidence path parent is not a directory")
            identities.append(
                (
                    metadata.st_dev,
                    metadata.st_ino,
                    metadata.st_mode,
                    metadata.st_nlink,
                    None,
                )
            )
            current_descriptor = os.open(
                part,
                directory_flags,
                dir_fd=current_descriptor,
            )
            descriptors.append(current_descriptor)
        metadata = os.fstat(current_descriptor)
        if not stat.S_ISDIR(metadata.st_mode):
            raise OSError("evidence path parent is not a directory")
        identities.append(
            (
                metadata.st_dev,
                metadata.st_ino,
                metadata.st_mode,
                metadata.st_nlink,
                None,
            )
        )
        descriptor = os.open(
            parts[-1],
            common_flags,
            dir_fd=current_descriptor,
        )
        descriptors.append(descriptor)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size != expected_size
        ):
            raise OSError("committed evidence is not a stable regular file")
        identities.append(
            (
                metadata.st_dev,
                metadata.st_ino,
                metadata.st_mode,
                metadata.st_nlink,
                metadata.st_size,
            )
        )
    except OSError:
        _close_evidence_descriptors(descriptors)
        raise
    return descriptors, tuple(identities)


def _read_committed_patch_result(
    connection: sqlite3.Connection,
    *,
    work_order: WorkOrder,
    target_patch: ToolCallReceipt,
    evidence_root: Path,
) -> PatchResultEvidence:
    committing = connection.execute(
        """
        SELECT COUNT(*)
        FROM evidence_publications
        WHERE state = 'COMMITTING'
        """
    ).fetchone()
    if (
        committing is None
        or len(committing) != 1
        or type(committing[0]) is not int
    ):
        raise RetryEvidenceIntegrityError(
            "evidence publication state is malformed"
        )
    if committing[0] != 0:
        raise RetryEvidenceRecoveryError(
            "evidence publication recovery is required"
        )

    result_refs = tuple(
        reference
        for reference in target_patch.evidence_refs
        if reference.media_type == "application/json"
    )
    if len(result_refs) != 1:
        raise RetryEvidenceIntegrityError(
            "target patch result reference is ambiguous"
        )
    reference = result_refs[0]
    diff_refs = tuple(
        item
        for item in target_patch.evidence_refs
        if item.media_type == "text/x-diff"
    )
    policy_slots = {
        f"{work_order.evidence_policy.evidence_root}/{artifact.path}": artifact
        for artifact in work_order.evidence_policy.artifacts
    }
    result_slot = policy_slots.get(reference.path)
    diff_slot = (
        policy_slots.get(diff_refs[0].path)
        if len(diff_refs) == 1
        else None
    )
    if (
        result_slot is None
        or diff_slot is None
        or result_slot.media_type != reference.media_type
        or diff_slot.media_type != diff_refs[0].media_type
        or reference.size_bytes > result_slot.max_size_bytes
        or diff_refs[0].size_bytes > diff_slot.max_size_bytes
        or result_slot.purpose != "patch_result"
        or diff_slot.purpose != "patch_input"
        or result_slot.ordinal != diff_slot.ordinal
    ):
        raise RetryEvidenceIntegrityError(
            "target patch evidence is not bound to paired WorkOrder slots"
        )
    rows = connection.execute(
        """
        SELECT
            final_path,
            digest,
            media_type,
            size_bytes,
            state
        FROM evidence_publications
        WHERE receipt_id = ? AND final_path = ?
        ORDER BY final_path
        LIMIT 2
        """,
        (target_patch.receipt_id, reference.path),
    ).fetchall()
    if len(rows) != 1:
        raise RetryEvidenceIntegrityError(
            "target patch has no unique committed publication"
        )
    (
        final_path,
        stored_digest,
        stored_media_type,
        stored_size,
        publication_state,
    ) = rows[0]
    if (
        final_path != reference.path
        or stored_digest != reference.sha256
        or stored_media_type != reference.media_type
        or stored_size != reference.size_bytes
        or publication_state != "COMMITTED"
    ):
        raise RetryEvidenceIntegrityError(
            "target patch publication does not match its EvidenceRef"
        )

    root = Path(evidence_root)
    prefix = f"{work_order.evidence_policy.evidence_root}/"
    if (
        not reference.path.startswith(prefix)
        or reference.path.startswith("/")
    ):
        raise RetryEvidenceIntegrityError(
            "evidence path is outside the WorkOrder evidence root"
        )
    relative = reference.path[len(prefix) :]
    parts = Path(relative).parts
    if (
        not parts
        or any(part in {"", ".", ".."} for part in parts)
        or Path(relative).is_absolute()
    ):
        raise RetryEvidenceIntegrityError(
            "evidence path is not a safe relative path"
    )
    descriptors: list[int] = []
    recheck_descriptors: list[int] = []
    try:
        try:
            descriptors, identities = _open_evidence_chain(
                root,
                parts,
                expected_size=reference.size_bytes,
            )
            descriptor = descriptors[-1]
            payload = os.read(descriptor, reference.size_bytes + 1)
            after = os.fstat(descriptor)
            if (
                len(payload) != reference.size_bytes
                or (
                    after.st_dev,
                    after.st_ino,
                    after.st_mode,
                    after.st_nlink,
                    after.st_size,
                )
                != identities[-1]
            ):
                raise OSError("committed evidence changed while being read")
        except OSError as error:
            raise RetryEvidenceIntegrityError(
                "committed evidence bytes are unavailable or unstable"
            ) from error
        if hashlib.sha256(payload).hexdigest() != reference.sha256:
            raise RetryEvidenceIntegrityError(
                "committed evidence digest does not match its EvidenceRef"
            )
        try:
            parsed = json.loads(payload)
            if rfc8785.dumps(parsed) != payload:
                raise ValueError("patch result is not canonical JCS")
            result = PatchResultEvidence.model_validate(parsed)
        except Exception as error:
            raise RetryEvidenceIntegrityError(
                "committed PatchResultEvidence is malformed"
            ) from error
        arguments = target_patch.request_arguments
        if (
            target_patch.output_digest != reference.sha256
            or not isinstance(arguments, ApplyPatchArguments)
            or result.patch_digest != arguments.patch_digest
            or result.patch_size_bytes != arguments.patch_size_bytes
            or result.replay_profile_digest
            != work_order.replay_profile_digest
        ):
            raise RetryEvidenceIntegrityError(
                "committed PatchResultEvidence does not match the patch receipt"
            )
        try:
            recheck_descriptors, recheck_identities = _open_evidence_chain(
                root,
                parts,
                expected_size=reference.size_bytes,
            )
        except OSError as error:
            raise RetryEvidenceIntegrityError(
                "committed evidence namespace changed during validation"
            ) from error
        if recheck_identities != identities:
            raise RetryEvidenceIntegrityError(
                "committed evidence namespace changed during validation"
            )
        return result
    finally:
        _close_evidence_descriptors(recheck_descriptors)
        _close_evidence_descriptors(descriptors)


def _validated_retry_episode(
    connection: sqlite3.Connection,
    *,
    work_order: WorkOrder,
    receipts,
    grants: dict[str, CapabilityGrant],
    evidence_root: Path,
    current_state: str,
    rollback_candidate: RollbackReceipt | None = None,
) -> _RetryEpisode:
    episode = _reconstruct_rework_episode(
        work_order=work_order,
        receipts=receipts,
        grants=grants,
        current_state=current_state,
        rollback_candidate=rollback_candidate,
    )
    patch_result = _read_committed_patch_result(
        connection,
        work_order=work_order,
        target_patch=episode.target_patch,
        evidence_root=evidence_root,
    )
    failure_arguments = episode.failure.request_arguments
    verifier_profile = next(
        (
            profile
            for profile in work_order.test_profiles
            if profile.test_mode == "verifier"
        ),
        None,
    )
    if (
        verifier_profile is None
        or not isinstance(failure_arguments, RunTestsArguments)
        or (
            failure_arguments.test_mode,
            failure_arguments.command_digest,
            failure_arguments.source_commit,
            failure_arguments.container_image_digest,
            failure_arguments.fixed_test_source_digest,
        )
        != (
            "verifier",
            verifier_profile.command_digest,
            work_order.source_commit,
            verifier_profile.container_image_digest,
            verifier_profile.fixed_test_source_digest,
        )
        or failure_arguments.candidate_commit
        != patch_result.candidate_commit
        or failure_arguments.workspace_manifest_digest
        != patch_result.workspace_manifest_digest
    ):
        raise RetryEvidenceIntegrityError(
            "retry failure does not test the target patch result"
        )
    try:
        episode.rollback.validate_target_patch(
            episode.target_patch,
            patch_result,
        )
    except ValueError as error:
        raise RetryEvidenceIntegrityError(
            "retry rollback does not match the committed patch result"
        ) from error
    return _RetryEpisode(
        root_issuance=episode.root_issuance,
        failure=episode.failure,
        rollback=episode.rollback,
        target_patch=episode.target_patch,
        patch_result=patch_result,
    )


def _build_retry_receipt(
    work_order: WorkOrder,
    request: AgentRequest,
    sidecar_private_key: Ed25519PrivateKey,
    now: datetime,
    *,
    sequence: int,
    state: str,
    tip: ActionReceiptEnvelope,
    parents: tuple[str, ...],
    allowed: bool,
    policy_error_code: str | None,
    remaining_after: int | None,
) -> GrantConsumedReceipt:
    receipt_id = hashlib.sha256(
        rfc8785.dumps(
            {
                "domain": "openworkproof/receipt-id/v0.1",
                "request_digest": request.digest,
                "entropy": secrets.token_hex(32),
            }
        )
    ).hexdigest()
    raw = {
        "protocol_version": "0.1",
        "receipt_id": receipt_id,
        "work_order_digest": work_order.digest,
        "actor_type": "agent",
        "actor_id": request.actor_id,
        "actor_key_id": request.actor_key_id,
        "nested_claim_type": "agent-request",
        "nested_claim_digest": request.digest,
        "nested_claim": request.model_dump(mode="json"),
        "gateway_signer_key_id": key_id(sidecar_private_key.public_key()),
        "event_type": "grant_consumed",
        "policy_decision": "allow" if allowed else "deny",
        "policy_error_code": None if allowed else policy_error_code,
        "execution_status": "succeeded" if allowed else "denied",
        "execution_error_code": None,
        "quota_charge": (
            {
                "grant_id": request.grant_id,
                "metric": "repair_rounds",
                "amount": 1,
                "remaining_after": remaining_after,
            }
            if allowed
            else None
        ),
        "state_before": state,
        "state_after": "retrying" if allowed else state,
        "parent_receipt_ids": list(parents),
        "correlation_factors": None,
        "evidence_refs": [],
        "occurred_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "sequence": sequence,
        "nonce": request.nonce,
        "previous_receipt_digest": tip.digest,
        "grant_id": request.grant_id,
        "metric": "repair_rounds",
        "amount": 1,
        "remaining_after": remaining_after,
    }
    receipt = GrantConsumedReceipt.model_validate(
        sign_payload("action-receipt", raw, sidecar_private_key)
    )
    receipt.validate_against_work_order(work_order)
    return receipt


def _confirm_committed_retry_receipt(
    ledger_path: Path,
    expected: GrantConsumedReceipt,
) -> GrantConsumedReceipt | None:
    connection: sqlite3.Connection | None = None
    result: GrantConsumedReceipt | None = None
    try:
        connection = _connect_ledger_direct(ledger_path)
        connection.execute("BEGIN")
        work_order = load_authoritative_work_order(connection)
        receipts = _validated_receipt_prefix(connection, work_order)
        grants = _validated_effective_grants(
            connection,
            work_order,
            receipts,
        )
        attempts = _validated_grant_attempts(
            connection,
            work_order,
            receipts,
        )
        _validate_grant_reservation_closure(
            connection,
            work_order,
            grants,
            attempts,
        )
        _policy_history_replay(
            work_order,
            receipts,
            grants,
            attempts,
        )
        _validate_grant_event_index(connection, receipts, grants)
        matches = tuple(
            receipt
            for receipt in receipts
            if receipt.nonce == expected.nonce
        )
        if len(matches) == 1 and matches[0] == expected:
            result = expected
    except Exception:
        result = None
    finally:
        _best_effort_rollback(connection)
        _best_effort_close(connection)
    return result


def start_retry(
    ledger_path: Path,
    *,
    request: AgentRequest,
    sidecar_private_key: Ed25519PrivateKey,
    evidence_root: Path,
    clock: Callable[[], datetime],
) -> GrantConsumedReceipt:
    """Atomically consume one root repair round and enter ``retrying``."""

    path = Path(ledger_path)
    if not path.is_file():
        raise _retry_error("retry consumption ledger is unavailable")
    connection: sqlite3.Connection | None = None
    receipt_result: GrantConsumedReceipt | None = None
    primary_error: Exception | None = None
    secondary_errors: list[Exception] = []
    try:
        try:
            connection = connect_ledger(path)
        except Exception as error:
            raise _retry_error(
                "retry consumption ledger could not be opened"
            ) from error
        connection.execute("BEGIN IMMEDIATE")
        try:
            work_order = load_authoritative_work_order(connection)
            receipts = _validated_receipt_prefix(connection, work_order)
            grants = _validated_effective_grants(
                connection,
                work_order,
                receipts,
            )
            attempts = _validated_grant_attempts(
                connection,
                work_order,
                receipts,
            )
            _validate_grant_reservation_closure(
                connection,
                work_order,
                grants,
                attempts,
            )
            replay = _policy_history_replay(
                work_order,
                receipts,
                grants,
                attempts,
            )
            _validate_grant_event_index(
                connection,
                receipts,
                grants,
            )
        except RetryConsumptionError:
            raise
        except Exception as error:
            raise _retry_error(
                "retry consumption ledger history is invalid"
            ) from error
        if (
            not isinstance(request, AgentRequest)
            or not isinstance(sidecar_private_key, Ed25519PrivateKey)
            or not isinstance(evidence_root, Path)
        ):
            raise _retry_error("retry consumption input is malformed")
        if len(receipts) >= MAX_ROUTINE_ACTION_RECEIPTS:
            raise _retry_error(
                "routine retry receipt capacity is exhausted"
            )
        if any(receipt.nonce == request.nonce for receipt in receipts):
            raise _retry_error("retry consumption nonce is already committed")
        try:
            utc_now = _freeze_trusted_utc_second(clock())
        except Exception as error:
            raise _retry_error(
                "retry consumption trusted clock is invalid"
            ) from error
        bindings = {
            binding.role: binding for binding in work_order.key_bindings
        }
        manager = bindings["Manager"]
        sidecar = bindings["Sidecar"]
        request_grant = grants.get(request.grant_id)
        root = grants.get(work_order.root_grant_template.grant_id)
        arguments = {
            "grant_id": request.grant_id,
            "metric": "repair_rounds",
            "amount": 1,
        }
        if (
            request_grant is None
            or root is None
            or root.parent_grant_id is not None
            or request_grant.subject_agent_id != request.actor_id
            or request_grant.subject_key_id != request.actor_key_id
            or key_id(sidecar_private_key.public_key()) != sidecar.key_id
            or not verify_nested_claim(request, work_order)
            or request.work_order_digest != work_order.digest
            or request.signer_key_id != request_grant.subject_key_id
            or request.tool_name != "owp.start_retry"
            or request.arguments_digest
            != request_arguments_digest("owp.start_retry", arguments)
            or request.requested_at < work_order.issued_at
            or request.requested_at > work_order.deadline
            or utc_now < request.requested_at
            or (utc_now - request.requested_at).total_seconds() > 300
        ):
            raise _retry_error(
                "retry consumption request binding is invalid"
            )
        tip = _tip_receipt(receipts)
        if utc_now < tip.occurred_at:
            raise _retry_error(
                "retry consumption time precedes the verified chain tip"
            )
        state_row = connection.execute(
            """
            SELECT current_state, version
            FROM work_order_state
            WHERE singleton = 1 AND work_order_digest = ?
            """,
            (work_order.digest,),
        ).fetchone()
        sequence_row = connection.execute(
            """
            SELECT next_sequence
            FROM sequence_counter
            WHERE singleton = 1
            """
        ).fetchone()
        if state_row is None or sequence_row is None:
            raise _retry_error(
                "retry consumption ledger state is unavailable"
            )
        current_state, current_version = state_row
        sequence = sequence_row[0]
        episode = _validated_retry_episode(
            connection,
            work_order=work_order,
            receipts=receipts,
            grants=grants,
            evidence_root=evidence_root,
            current_state=current_state,
        )
        request_issuance = _successful_issuance_for(
            receipts,
            request_grant.grant_id,
        )
        if current_state == "needs_rework":
            base_parents = (
                request_issuance.receipt_id,
                episode.failure.receipt_id,
                episode.rollback.receipt_id,
            )
        else:
            base_parents = (
                request_issuance.receipt_id,
                episode.failure.receipt_id,
                episode.rollback.receipt_id,
                tip.receipt_id,
            )
        receipt_sequence = {
            receipt.receipt_id: receipt.sequence
            for receipt in receipts
        }
        parents = tuple(
            sorted(
                set(base_parents),
                key=receipt_sequence.__getitem__,
            )
        )
        root_replay = replay.get(root.grant_id)
        if root_replay is None:
            raise _retry_error(
                "retry root quota history is unavailable"
            )
        if current_state != "needs_rework":
            allowed = False
            policy_error_code = "STATE_DENIED"
            remaining_after = None
        elif (
            request_grant.grant_id != root.grant_id
            or request_grant.parent_grant_id is not None
            or request.actor_id != manager.subject_id
            or request.actor_key_id != manager.key_id
        ):
            allowed = False
            policy_error_code = "ROLE_DENIED"
            remaining_after = None
        elif (
            root_replay.revoked
            or utc_now < root.valid_from
            or utc_now > root.expires_at
        ):
            allowed = False
            policy_error_code = "CAPABILITY_DENIED"
            remaining_after = None
        elif root_replay.remaining_repair_rounds == 0:
            allowed = False
            policy_error_code = "QUOTA_EXHAUSTED"
            remaining_after = None
        else:
            allowed = True
            policy_error_code = None
            remaining_after = (
                root_replay.remaining_repair_rounds - 1
            )
        receipt = _build_retry_receipt(
            work_order,
            request,
            sidecar_private_key,
            utc_now,
            sequence=sequence,
            state=current_state,
            tip=tip,
            parents=parents,
            allowed=allowed,
            policy_error_code=policy_error_code,
            remaining_after=remaining_after,
        )
        receipt_result = receipt
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
                work_order.digest,
                request.nonce,
                sequence,
                tip.digest,
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
        if allowed:
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
                VALUES (?, ?, ?, 'grant_consumed', 'repair_rounds', 1)
                """,
                (
                    hashlib.sha256(
                        f"grant-consumed:{receipt.receipt_id}".encode(
                            "ascii"
                        )
                    ).hexdigest(),
                    receipt.receipt_id,
                    root.grant_id,
                ),
            )
        state_update = connection.execute(
            """
            UPDATE work_order_state
            SET current_state = ?, version = version + 1
            WHERE singleton = 1
              AND work_order_digest = ?
              AND current_state = ?
              AND version = ?
            """,
            (
                receipt.state_after,
                work_order.digest,
                current_state,
                current_version,
            ),
        )
        sequence_update = connection.execute(
            """
            UPDATE sequence_counter
            SET next_sequence = next_sequence + 1
            WHERE singleton = 1 AND next_sequence = ?
            """,
            (sequence,),
        )
        if state_update.rowcount != 1 or sequence_update.rowcount != 1:
            raise _retry_error(
                "retry consumption ledger counters could not be advanced"
            )
        connection.execute("COMMIT")
    except Exception as error:
        primary_error = error
        rollback_error = _best_effort_rollback(connection)
        if rollback_error is not None:
            secondary_errors.append(
                _contextualize_secondary("rollback", rollback_error)
            )

    closed, close_errors = _close_with_retries(connection)
    if primary_error is not None:
        secondary_errors.extend(close_errors)
    if primary_error is None and closed:
        if receipt_result is None:
            raise _retry_error(
                "retry consumption produced no receipt"
            )
        return receipt_result
    committed_receipt = (
        _confirm_committed_retry_receipt(path, receipt_result)
        if receipt_result is not None
        else None
    )
    errors = (
        ([primary_error] if primary_error is not None else [])
        + secondary_errors
        + ([] if primary_error is not None else list(close_errors))
    )
    if committed_receipt is not None:
        raise RetryConsumptionCommittedError(
            committed_receipt
        ) from _error_cause(
            "retry consumption committed completion failures",
            errors,
        )
    if (
        isinstance(primary_error, RetryConsumptionError)
        and not secondary_errors
    ):
        raise primary_error
    raise _retry_error(
        "retry consumption failed atomically"
    ) from _error_cause("retry consumption failures", errors)
