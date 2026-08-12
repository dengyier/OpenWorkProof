"""Deterministic acceptance and settlement-readiness read models."""

from __future__ import annotations

from enum import Enum
from pathlib import Path
import sqlite3

import rfc8785

from pydantic import BaseModel, ConfigDict, model_validator

from openworkproof.models import (
    AcceptanceReceipt,
    BindingDecision,
    AcceptanceRejectionReceipt,
    AcceptanceTransitionReceipt,
    Digest64,
    ProtocolModel,
    VerificationDecision,
    VerificationDecisionV03,
)
import openworkproof.evidence as evidence
from openworkproof.signing import decode_and_verify_key_binding, verify_payload


class EffectiveAcceptance(str, Enum):
    NONE = "NONE"
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    WITHDRAWN = "WITHDRAWN"
    SUPERSEDED = "SUPERSEDED"


class SettlementReadiness(str, Enum):
    NOT_READY = "NOT_READY"
    READY_FOR_ACCEPTANCE = "READY_FOR_ACCEPTANCE"
    ACCEPTED_FOR_SETTLEMENT = "ACCEPTED_FOR_SETTLEMENT"
    READY_FOR_SETTLEMENT_REVIEW = "READY_FOR_SETTLEMENT_REVIEW"
    SUSPENDED = "SUSPENDED"
    WITHDRAWN = "WITHDRAWN"
    SUPERSEDED = "SUPERSEDED"


class SettlementReadError(RuntimeError):
    """The ledger cannot produce one validated settlement snapshot."""


class AcceptanceHistory(ProtocolModel):
    acceptance: AcceptanceReceipt | None
    rejection: AcceptanceRejectionReceipt | None
    withdrawal: AcceptanceTransitionReceipt | None
    supersession: AcceptanceTransitionReceipt | None
    current_decision: VerificationDecision | VerificationDecisionV03 | None

    @model_validator(mode="after")
    def _closed_history(self) -> AcceptanceHistory:
        if self.acceptance is not None and self.rejection is not None:
            raise ValueError("acceptance and rejection are mutually exclusive")
        if self.withdrawal is not None and self.supersession is not None:
            raise ValueError("withdrawal and supersession are mutually exclusive")
        for transition, expected in (
            (self.withdrawal, "withdrawn"),
            (self.supersession, "superseded"),
        ):
            if transition is None:
                continue
            if (
                self.acceptance is None
                or transition.transition != expected
                or transition.target_acceptance_id
                != self.acceptance.acceptance_id
                or transition.target_acceptance_digest != self.acceptance.digest
            ):
                raise ValueError("acceptance transition history is inconsistent")
        return self


class SettlementSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    current_decision_id: Digest64 | None
    effective_acceptance: EffectiveAcceptance
    settlement_readiness: SettlementReadiness


def effective_acceptance(
    validated_history: AcceptanceHistory,
) -> EffectiveAcceptance:
    if validated_history.withdrawal is not None:
        return EffectiveAcceptance.WITHDRAWN
    if validated_history.supersession is not None:
        return EffectiveAcceptance.SUPERSEDED
    if validated_history.acceptance is None:
        return EffectiveAcceptance.NONE
    if (
        validated_history.current_decision is None
        or validated_history.current_decision.decision != "VERIFIED"
    ):
        return EffectiveAcceptance.SUSPENDED
    return EffectiveAcceptance.ACTIVE


def settlement_readiness(
    *,
    decision: VerificationDecision | VerificationDecisionV03 | None,
    acceptance: EffectiveAcceptance,
    rejection: AcceptanceRejectionReceipt | None,
) -> SettlementReadiness:
    if acceptance is EffectiveAcceptance.WITHDRAWN:
        return SettlementReadiness.WITHDRAWN
    if acceptance is EffectiveAcceptance.SUPERSEDED:
        return SettlementReadiness.SUPERSEDED
    if acceptance is EffectiveAcceptance.SUSPENDED:
        return SettlementReadiness.SUSPENDED
    if decision is not None and decision.decision == "VERIFIED":
        if acceptance is EffectiveAcceptance.ACTIVE:
            return SettlementReadiness.ACCEPTED_FOR_SETTLEMENT
        if rejection is None:
            return SettlementReadiness.READY_FOR_ACCEPTANCE
    return SettlementReadiness.NOT_READY


def _load_transition(
    connection: sqlite3.Connection,
    *,
    work_order,
    acceptance: AcceptanceReceipt | None,
    protocol_version: str | None,
    decision: VerificationDecision | VerificationDecisionV03 | None,
) -> AcceptanceTransitionReceipt | None:
    v02_rows = tuple(
        connection.execute(
            """
            SELECT transition_id, target_acceptance_id,
                   verification_decision_id, transition_json
            FROM acceptance_transitions ORDER BY transition_id
            """
        )
    )
    v03_rows = tuple(
        connection.execute(
            """
            SELECT transition_id, target_acceptance_id,
                   verification_decision_id, transition_json
            FROM acceptance_transitions_v03 ORDER BY transition_id
            """
        )
    )
    if len(v02_rows) + len(v03_rows) > 1:
        raise SettlementReadError("multiple acceptance transitions are invalid")
    if not v02_rows and not v03_rows:
        return None
    if acceptance is None or decision is None or protocol_version is None:
        raise SettlementReadError("acceptance transition has no acceptance")
    if (v02_rows and protocol_version != "0.2") or (
        v03_rows and protocol_version != "0.3"
    ):
        raise SettlementReadError("acceptance transition protocol is mismatched")
    rows = v02_rows if protocol_version == "0.2" else v03_rows
    parent_table = (
        "acceptance_transition_parents"
        if protocol_version == "0.2"
        else "acceptance_transition_parents_v03"
    )
    transition_id, target_id, decision_id, raw = rows[0]
    try:
        transition = AcceptanceTransitionReceipt.model_validate_json(raw)
        canonical = rfc8785.dumps(transition.model_dump(mode="json"))
        transition.validate_against_work_order(work_order)
    except Exception as error:
        raise SettlementReadError("acceptance transition row is invalid") from error
    encoded = raw.encode("utf-8") if isinstance(raw, str) else raw
    acceptor = next(
        binding
        for binding in work_order.key_bindings
        if binding.role == "Acceptor"
    )
    acceptor_key = decode_and_verify_key_binding(acceptor)
    parents = tuple(
        connection.execute(
            f"""
            SELECT ordinal, parent_id
            FROM {parent_table}
            WHERE transition_id = ?
            ORDER BY ordinal
            """,
            (transition.transition_id,),
        )
    )
    expected_parents = tuple(
        (ordinal, parent_id)
        for ordinal, parent_id in enumerate(transition.causal_parent_ids)
    )
    if (
        transition_id != transition.transition_id
        or target_id != transition.target_acceptance_id
        or decision_id != transition.verification_decision_id
        or encoded != canonical
        or transition.target_acceptance_id != acceptance.acceptance_id
        or transition.target_acceptance_digest != acceptance.digest
        or transition.verification_decision_digest != decision.digest
        or parents != expected_parents
        or not verify_payload(
            "acceptance-transition",
            transition.model_dump(mode="json"),
            acceptor_key,
        )
    ):
        raise SettlementReadError("acceptance transition integrity failed")
    return transition


def read_settlement_snapshot(ledger: Path) -> SettlementSnapshot:
    """Validate one ledger snapshot and derive its settlement readiness."""
    from openworkproof import acceptance as acceptance_module  # noqa: PLC0415

    path = Path(ledger)
    if not path.is_file():
        raise SettlementReadError("settlement ledger is unavailable")
    lock_descriptor: int | None = None
    connection: sqlite3.Connection | None = None
    try:
        lock_descriptor, _ = evidence._borrow_or_acquire_target_lock(path, None)
        connection = evidence.connect_ledger(path)
        connection.execute("BEGIN")
        work_order = evidence.load_authoritative_work_order(connection)
        acceptances = evidence._validated_acceptance_receipts(
            connection,
            work_order,
        )
        rejections = evidence._validated_acceptance_rejections(
            connection,
            work_order,
        )
        if len(acceptances) > 1 or len(rejections) > 1 or (
            acceptances and rejections
        ):
            raise SettlementReadError("acceptance terminal history is invalid")
        try:
            current = acceptance_module._load_current_verification_decision(
                connection
            )
        except acceptance_module.AcceptanceTransactionError as error:
            raise SettlementReadError(
                "verification profile history is invalid"
            ) from error
        if current is None:
            protocol_version = None
            current_decision = None
        else:
            protocol_version, current_decision = current
        acceptance = acceptances[0] if acceptances else None
        rejection = rejections[0] if rejections else None
        transition = _load_transition(
            connection,
            work_order=work_order,
            acceptance=acceptance,
            protocol_version=protocol_version,
            decision=current_decision,
        )
        history = AcceptanceHistory.model_validate(
            {
                "acceptance": (
                    None
                    if acceptance is None
                    else acceptance.model_dump(mode="json")
                ),
                "rejection": (
                    None if rejection is None else rejection.model_dump(mode="json")
                ),
                "withdrawal": (
                    transition.model_dump(mode="json")
                    if transition is not None
                    and transition.transition == "withdrawn"
                    else None
                ),
                "supersession": (
                    transition.model_dump(mode="json")
                    if transition is not None
                    and transition.transition == "superseded"
                    else None
                ),
                "current_decision": (
                    None
                    if current_decision is None
                    else current_decision.model_dump(mode="json")
                ),
            }
        )
        effective = effective_acceptance(history)
        readiness = settlement_readiness(
            decision=current_decision,
            acceptance=effective,
            rejection=rejection,
        )
        snapshot = SettlementSnapshot(
            current_decision_id=(
                None if current_decision is None else current_decision.decision_id
            ),
            effective_acceptance=effective,
            settlement_readiness=readiness,
        )
        connection.execute("ROLLBACK")
        return snapshot
    except SettlementReadError:
        evidence._best_effort_rollback(connection)
        raise
    except Exception as error:
        evidence._best_effort_rollback(connection)
        raise SettlementReadError("settlement snapshot validation failed") from error
    finally:
        evidence._best_effort_close(connection)
        evidence._release_target_lock(lock_descriptor)

def settlement_readiness_v04(
    *,
    verification: VerificationDecisionV03 | None,
    binding_decision: BindingDecision | None,
    acceptance: EffectiveAcceptance,
    commercial_evidence_refs: tuple[str, ...] | None = None,
) -> SettlementReadiness:
    """v0.4 dual-gate settlement readiness.

    ``READY_FOR_SETTLEMENT_REVIEW`` is the only positive v0.4 state. It
    requires a current VERIFIED verification, a current BOUND binding
    decision, ``EffectiveAcceptance.ACTIVE`` and the presence of required
    commercial evidence references. It never proves payment or settlement:
    payment vouchers remain external commercial evidence.
    """

    if acceptance is EffectiveAcceptance.WITHDRAWN:
        return SettlementReadiness.WITHDRAWN
    if acceptance is EffectiveAcceptance.SUPERSEDED:
        return SettlementReadiness.SUPERSEDED
    if acceptance is EffectiveAcceptance.SUSPENDED:
        return SettlementReadiness.SUSPENDED
    if (
        verification is None
        or verification.decision != "VERIFIED"
        or binding_decision is None
        or binding_decision.decision != "BOUND"
    ):
        return SettlementReadiness.NOT_READY
    if acceptance is not EffectiveAcceptance.ACTIVE:
        return SettlementReadiness.NOT_READY
    if not commercial_evidence_refs:
        return SettlementReadiness.NOT_READY
    return SettlementReadiness.READY_FOR_SETTLEMENT_REVIEW
