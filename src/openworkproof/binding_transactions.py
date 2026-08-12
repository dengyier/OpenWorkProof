"""Atomic append-only transactions for Judgment-to-Action Binding v0.4."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Literal, TypeVar

from openworkproof import evidence
from openworkproof.binding import (
    BindingInputError,
    CanonicalAdapterProfile,
    projection_from_adapter_profile,
    validate_action_binding_manifest,
)
from openworkproof.models import (
    ActionBindingManifest,
    EvaluationScopeManifest,
    JudgmentCommitment,
    KeyBinding,
    SubjectClaim,
    WorkOrder,
)
from openworkproof.scope import validate_evaluation_scope
from openworkproof.signing import decode_and_verify_key_binding, verify_payload


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


def _canonical_model_blob(value: object) -> bytes:
    if not hasattr(value, "model_dump"):
        raise BindingInputError("binding protocol object is malformed")
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


def _load_canonical_row(model_type, raw: object, label: str):
    if not isinstance(raw, (bytes, str)):
        raise BindingTransactionError(f"committed {label} row has the wrong type")
    try:
        parsed = model_type.model_validate_json(raw)
    except Exception as error:
        raise BindingTransactionError(f"committed {label} row is invalid") from error
    encoded = raw.encode("utf-8") if isinstance(raw, str) else raw
    if _canonical_model_blob(parsed) != encoded:
        raise BindingTransactionError(f"committed {label} row is not canonical")
    return parsed


def _load_committed_judgment(
    connection: sqlite3.Connection,
    manifest: ActionBindingManifest,
) -> tuple[JudgmentCommitment, datetime]:
    row = connection.execute(
        """
        SELECT commitment_digest, authority_namespace, subject_id, nonce,
               signer_key_id, commitment_json, committed_at
        FROM judgment_commitments_v04 WHERE commitment_id = ?
        """,
        (manifest.judgment_commitment_id,),
    ).fetchone()
    if row is None:
        raise BindingInputError("committed Judgment is unavailable")
    judgment = _load_canonical_row(
        JudgmentCommitment, row[5], "Judgment"
    )
    if row[:5] != (
        judgment.digest,
        judgment.authority_namespace,
        judgment.subject_id,
        judgment.nonce,
        judgment.signer_key_id,
    ):
        raise BindingTransactionError(
            "committed Judgment index does not match canonical row"
        )
    if (
        judgment.commitment_id != manifest.judgment_commitment_id
        or judgment.digest != manifest.judgment_commitment_digest
    ):
        raise BindingInputError("committed Judgment digest chain does not match")
    committed_at = _validate_committed_at(row[6])
    if not judgment.valid_from <= committed_at < judgment.expires_at:
        raise BindingTransactionError(
            "committed Judgment validity timestamp is invalid"
        )
    return judgment, committed_at


def _load_committed_scope(
    connection: sqlite3.Connection,
    manifest: ActionBindingManifest,
    work_order: WorkOrder,
) -> EvaluationScopeManifest:
    row = connection.execute(
        """
        SELECT scope_digest, work_order_digest, claim_id,
               subject_claim_digest, scope_json
        FROM evaluation_scopes_v03 WHERE scope_id = ?
        """,
        (manifest.evaluation_scope_id,),
    ).fetchone()
    if row is None:
        raise BindingInputError("committed Scope is unavailable")
    scope = _load_canonical_row(EvaluationScopeManifest, row[4], "Scope")
    if row[:2] != (scope.digest, scope.work_order_digest) or row[3] != (
        scope.subject_claim_digest
    ):
        raise BindingTransactionError(
            "committed Scope index does not match canonical row"
        )
    if (
        scope.scope_id != manifest.evaluation_scope_id
        or scope.digest != manifest.evaluation_scope_digest
    ):
        raise BindingInputError("committed Scope digest chain does not match")
    claim_row = connection.execute(
        "SELECT claim_json FROM subject_claims WHERE claim_id = ?", (row[2],)
    ).fetchone()
    if claim_row is None:
        raise BindingTransactionError("committed Scope claim row is unavailable")
    claim = _load_canonical_row(SubjectClaim, claim_row[0], "Scope claim")
    manager = next(
        (binding for binding in work_order.key_bindings if binding.role == "Manager"),
        None,
    )
    if manager is None:
        raise BindingTransactionError("committed Scope Manager is unavailable")
    try:
        manager_key = decode_and_verify_key_binding(manager)
        grant = work_order.root_grant_template
        valid_authority = (
            grant.subject_agent_id == manager.subject_id
            and grant.subject_key_id == manager.key_id
            and "owp.compose_proof" in grant.allowed_tools
            and grant.quota.tool_calls > 0
            and claim.claim_id == row[2]
            and claim.digest == scope.subject_claim_digest
            and claim.work_order_digest == work_order.digest
            and claim.customer_acceptor_key_id in work_order.acceptor_key_ids
            and claim.signer_key_id == manager.key_id
            and verify_payload(
                "subject-claim", claim.model_dump(mode="json"), manager_key
            )
            and scope.signer_key_id == manager.key_id
            and verify_payload(
                "evaluation-scope",
                scope.model_dump(mode="json"),
                manager_key,
                version="0.3",
            )
            and grant.valid_from <= claim.created_at <= scope.created_at
            and scope.created_at < scope.expires_at
            and scope.expires_at <= min(grant.expires_at, work_order.deadline)
        )
        validate_evaluation_scope(scope, claim=claim)
    except Exception as error:
        raise BindingTransactionError(
            "committed Scope Manager grant, claim authority, or linkage is invalid"
        ) from error
    if not valid_authority:
        raise BindingTransactionError(
            "committed Scope Manager grant, claim authority, or linkage is invalid"
        )
    return scope


def _validate_committed_at(value: object) -> datetime:
    if not isinstance(value, str):
        raise BindingTransactionError("manifest committed_at is not canonical")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as error:
        raise BindingTransactionError(
            "manifest committed_at is not canonical"
        ) from error
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value or parsed.year < 1970:
        raise BindingTransactionError("manifest committed_at is not canonical")
    return parsed


def _load_adapter_profile(
    digest: object,
    raw: object,
) -> CanonicalAdapterProfile:
    if not isinstance(raw, bytes) or not isinstance(digest, str):
        raise BindingTransactionError("stored adapter profile row is malformed")
    profile = CanonicalAdapterProfile(
        canonical_json=raw,
        adapter_profile_digest=digest,
    )
    try:
        projection_from_adapter_profile(profile)
    except BindingInputError as error:
        raise BindingTransactionError(
            "stored adapter profile row is invalid"
        ) from error
    return profile


def _validated_manifest_history(
    connection: sqlite3.Connection,
    work_order: WorkOrder,
) -> tuple[
    dict[str, tuple[ActionBindingManifest, CanonicalAdapterProfile, datetime]],
    ActionBindingManifest | None,
]:
    rows = tuple(
        connection.execute(
            """
            SELECT binding_manifest_id, manifest_digest, work_order_digest,
                   judgment_commitment_id, judgment_commitment_digest,
                   evaluation_scope_id, evaluation_scope_digest,
                   adapter_profile_digest, adapter_profile_json, nonce,
                   signer_key_id, manifest_json, committed_at
            FROM action_binding_manifests_v04
            WHERE work_order_digest = ?
            ORDER BY binding_manifest_id
            """,
            (work_order.digest,),
        )
    )
    validated: dict[
        str, tuple[ActionBindingManifest, CanonicalAdapterProfile, datetime]
    ] = {}
    for row in rows:
        manifest = _load_canonical_row(
            ActionBindingManifest, row[11], "ActionBindingManifest history"
        )
        profile = _load_adapter_profile(row[7], row[8])
        committed_at = _validate_committed_at(row[12])
        if row[:7] != (
            manifest.binding_manifest_id,
            manifest.digest,
            manifest.work_order_digest,
            manifest.judgment_commitment_id,
            manifest.judgment_commitment_digest,
            manifest.evaluation_scope_id,
            manifest.evaluation_scope_digest,
        ) or row[9:11] != (manifest.nonce, manifest.signer_key_id):
            raise BindingTransactionError(
                "binding manifest history index does not match canonical row"
            )
        judgment, judgment_committed_at = _load_committed_judgment(
            connection, manifest
        )
        scope = _load_committed_scope(connection, manifest, work_order)
        if judgment_committed_at > committed_at:
            raise BindingTransactionError(
                "Judgment committed after its binding Manifest"
            )
        try:
            validate_action_binding_manifest(
                work_order=work_order,
                judgment=judgment,
                scope=scope,
                adapter_profile=profile,
                manifest=manifest,
                transaction_time=committed_at,
            )
        except BindingInputError as error:
            raise BindingTransactionError(
                "binding manifest history signature or authority is invalid"
            ) from error
        validated[manifest.binding_manifest_id] = (
            manifest,
            profile,
            committed_at,
        )

    relation_rows = tuple(
        connection.execute(
            """
            SELECT child_manifest_id, parent_manifest_id,
                   parent_manifest_digest
            FROM action_binding_manifest_supersessions_v04
            ORDER BY child_manifest_id
            """
        )
    )
    if not validated:
        if relation_rows:
            raise BindingTransactionError(
                "binding manifest history has relations without objects"
            )
        return validated, None
    if len(relation_rows) != len(validated) - 1:
        raise BindingTransactionError(
            "binding manifest history relation count is invalid"
        )
    relations_by_child: dict[str, tuple[str, str]] = {}
    children_by_parent: dict[str, str] = {}
    for child_id, parent_id, parent_digest in relation_rows:
        if (
            child_id not in validated
            or parent_id not in validated
            or child_id in relations_by_child
            or parent_id in children_by_parent
        ):
            raise BindingTransactionError(
                "binding manifest history contains a fork or dangling relation"
            )
        parent = validated[parent_id][0]
        child = validated[child_id][0]
        if (
            parent.digest != parent_digest
            or child.supersedes_binding_manifest_id != parent_id
            or child.supersedes_binding_manifest_digest != parent_digest
            or child.causal_parent_manifest_ids != (parent_id,)
            or child.created_at <= parent.created_at
            or validated[parent_id][2] > validated[child_id][2]
        ):
            raise BindingTransactionError(
                "binding manifest history relation does not match signed child"
            )
        relations_by_child[child_id] = (parent_id, parent_digest)
        children_by_parent[parent_id] = child_id

    roots = tuple(
        manifest
        for manifest, _, _ in validated.values()
        if manifest.supersedes_binding_manifest_id is None
    )
    if len(roots) != 1 or roots[0].binding_manifest_id in relations_by_child:
        raise BindingTransactionError(
            "binding manifest history must contain exactly one signed root"
        )
    current = roots[0]
    visited: set[str] = set()
    while True:
        identifier = current.binding_manifest_id
        if identifier in visited:
            raise BindingTransactionError("binding manifest history contains a cycle")
        visited.add(identifier)
        child_id = children_by_parent.get(identifier)
        if child_id is None:
            break
        current = validated[child_id][0]
    if len(visited) != len(validated):
        raise BindingTransactionError(
            "binding manifest history is disconnected or cyclic"
        )
    return validated, current


def _exact_manifest_readback(
    path: Path,
    manifest: ActionBindingManifest,
    adapter_profile: CanonicalAdapterProfile,
    committed_at: str,
) -> bool:
    connection = evidence.connect_ledger(path)
    try:
        work_order = evidence.load_authoritative_work_order(connection)
        history, _ = _validated_manifest_history(connection, work_order)
        existing = history.get(manifest.binding_manifest_id)
        return (
            existing is not None
            and existing
            == (
                manifest,
                adapter_profile,
                _validate_committed_at(committed_at),
            )
        )
    finally:
        connection.close()


def load_current_action_binding_manifest(
    ledger_path: Path,
    work_order_digest: str,
) -> ActionBindingManifest:
    """Load the sole graph-derived current manifest for one WorkOrder."""

    path = Path(ledger_path)
    if not path.is_file():
        raise BindingTransactionError("binding ledger is unavailable")
    connection = evidence.connect_ledger(path)
    try:
        work_order = evidence.load_authoritative_work_order(connection)
        if work_order.digest != work_order_digest:
            raise BindingTransactionError(
                "requested WorkOrder is not the authoritative ledger WorkOrder"
            )
        try:
            _, current = _validated_manifest_history(connection, work_order)
        except sqlite3.OperationalError as error:
            if "no such table" not in str(error):
                raise
            # A pre-v0.4 ledger has no binding tables; that is equivalent
            # to "no manifest has ever been committed" for this WorkOrder.
            raise BindingTransactionError(
                "current binding manifest is unavailable"
            ) from error
        if current is None:
            raise BindingTransactionError("current binding manifest is unavailable")
        return current
    finally:
        connection.close()


def load_historical_action_binding_manifest(
    ledger_path: Path,
    *,
    work_order_digest: str,
    binding_manifest_id: str,
    binding_manifest_digest: str,
    judgment_commitment_id: str,
    judgment_commitment_digest: str,
    transaction_time: datetime,
) -> ActionBindingManifest:
    """Load the manifest that was current at one durable execution boundary."""

    path = Path(ledger_path)
    if not path.is_file():
        raise BindingTransactionError("binding ledger is unavailable")
    instant = datetime.strptime(
        _canonical_utc_second(transaction_time), "%Y-%m-%dT%H:%M:%SZ"
    ).replace(tzinfo=timezone.utc)
    connection = evidence.connect_ledger(path)
    try:
        work_order = evidence.load_authoritative_work_order(connection)
        if work_order.digest != work_order_digest:
            raise BindingTransactionError(
                "requested WorkOrder is not the authoritative ledger WorkOrder"
            )
        history, _ = _validated_manifest_history(connection, work_order)
        record = history.get(binding_manifest_id)
        if record is None:
            raise BindingTransactionError(
                "historical binding manifest is unavailable"
            )
        manifest, _, committed_at = record
        if (
            manifest.digest != binding_manifest_digest
            or manifest.judgment_commitment_id != judgment_commitment_id
            or manifest.judgment_commitment_digest
            != judgment_commitment_digest
        ):
            raise BindingTransactionError(
                "historical binding reference does not match"
            )
        if (
            committed_at > instant
            or not manifest.created_at <= instant < manifest.expires_at
        ):
            raise BindingTransactionError(
                "historical binding manifest was not effective"
            )
        superseding_commits = tuple(
            child_committed_at
            for child, _, child_committed_at in history.values()
            if child.supersedes_binding_manifest_id == binding_manifest_id
        )
        if any(committed_at <= instant for committed_at in superseding_commits):
            raise BindingTransactionError(
                "historical binding manifest was already superseded"
            )
        return manifest
    finally:
        connection.close()


def commit_action_binding_manifest(
    ledger_path: Path,
    manifest: ActionBindingManifest,
    adapter_profile: CanonicalAdapterProfile,
    *,
    transaction_time: datetime,
    fault: _Fault | None = None,
) -> ActionBindingManifest:
    """Commit one Manager manifest after loading every signed authority row."""

    path = Path(ledger_path)
    try:
        parsed = ActionBindingManifest.model_validate(
            manifest.model_dump(mode="json")
        )
    except Exception as error:
        raise BindingInputError("action binding manifest is malformed") from error
    projection_from_adapter_profile(adapter_profile)
    committed_at = _canonical_utc_second(transaction_time)
    committed_datetime = _validate_committed_at(committed_at)
    canonical = _canonical_model_blob(parsed)

    def stage(connection: sqlite3.Connection) -> ActionBindingManifest:
        work_order = evidence.load_authoritative_work_order(connection)
        history, current = _validated_manifest_history(connection, work_order)
        existing = history.get(parsed.binding_manifest_id)
        if existing is not None:
            existing_manifest, existing_profile, _ = existing
            if (
                existing_manifest != parsed
                or _canonical_model_blob(existing_manifest) != canonical
                or existing_profile != adapter_profile
            ):
                raise BindingTransactionError("binding manifest id is already used")
            raise BindingCommittedError(
                "the exact action binding manifest is already committed", parsed
            )
        if connection.execute(
            "SELECT 1 FROM action_binding_manifests_v04 "
            "WHERE binding_manifest_id = ?",
            (parsed.binding_manifest_id,),
        ).fetchone() is not None:
            raise BindingTransactionError("binding manifest id is already used")

        judgment, judgment_committed_at = _load_committed_judgment(
            connection, parsed
        )
        scope = _load_committed_scope(connection, parsed, work_order)
        if judgment_committed_at > committed_datetime:
            raise BindingTransactionError(
                "Judgment committed after its binding Manifest"
            )
        validate_action_binding_manifest(
            work_order=work_order,
            judgment=judgment,
            scope=scope,
            adapter_profile=adapter_profile,
            manifest=parsed,
            transaction_time=transaction_time,
        )
        if connection.execute(
            """
            SELECT 1 FROM action_binding_manifests_v04
            WHERE signer_key_id = ? AND nonce = ?
            """,
            (parsed.signer_key_id, parsed.nonce),
        ).fetchone() is not None:
            raise BindingTransactionError("binding manifest nonce is already used")

        if not history:
            if parsed.supersedes_binding_manifest_id is not None:
                raise BindingTransactionError(
                    "binding manifest supersession parent is unavailable"
                )
        else:
            if current is None:
                raise BindingTransactionError(
                    "binding manifest history has no unique current object"
                )
            if (
                parsed.supersedes_binding_manifest_id
                != current.binding_manifest_id
                or parsed.supersedes_binding_manifest_digest != current.digest
            ):
                raise BindingTransactionError(
                    "manifest does not supersede the exact current manifest"
                )
            if parsed.created_at <= current.created_at:
                raise BindingInputError(
                    "superseding manifest must be created after its parent"
                )
            if history[current.binding_manifest_id][2] > committed_datetime:
                raise BindingTransactionError(
                    "parent Manifest committed after its child"
                )

        connection.execute(
            """
            INSERT INTO action_binding_manifests_v04 (
                binding_manifest_id, manifest_digest, work_order_digest,
                judgment_commitment_id, judgment_commitment_digest,
                evaluation_scope_id, evaluation_scope_digest,
                adapter_profile_digest, adapter_profile_json, nonce,
                signer_key_id, manifest_json, committed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                parsed.binding_manifest_id,
                parsed.digest,
                parsed.work_order_digest,
                parsed.judgment_commitment_id,
                parsed.judgment_commitment_digest,
                parsed.evaluation_scope_id,
                parsed.evaluation_scope_digest,
                adapter_profile.adapter_profile_digest,
                adapter_profile.canonical_json,
                parsed.nonce,
                parsed.signer_key_id,
                canonical,
                committed_at,
            ),
        )
        if parsed.supersedes_binding_manifest_id is not None:
            connection.execute(
                """
                INSERT INTO action_binding_manifest_supersessions_v04 (
                    child_manifest_id, parent_manifest_id,
                    parent_manifest_digest
                ) VALUES (?, ?, ?)
                """,
                (
                    parsed.binding_manifest_id,
                    parsed.supersedes_binding_manifest_id,
                    parsed.supersedes_binding_manifest_digest,
                ),
            )
        return parsed

    return _commit_with_readback(
        path,
        stage=stage,
        readback=lambda _: _exact_manifest_readback(
            path, parsed, adapter_profile, committed_at
        ),
        fault=fault,
    )


__all__ = [
    "BindingCommitIndeterminateError",
    "BindingCommittedError",
    "BindingInputError",
    "BindingTransactionError",
    "JudgmentAuthorityContext",
    "commit_action_binding_manifest",
    "commit_judgment_commitment",
    "load_current_action_binding_manifest",
]
