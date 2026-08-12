"""BindingDecision ledger transactions, concurrency and recovery (Task 9)."""

from __future__ import annotations

import base64
import hashlib
import threading

import pytest
import rfc8785

import openworkproof.evidence as evidence
from openworkproof.binding import BindingDecisionDraftRequest
from openworkproof.binding_transactions import (
    BindingCommitIndeterminateError,
    BindingCommittedError,
    BindingInputError,
    BindingTransactionError,
    commit_binding_decision,
    load_current_binding_decision,
)
from openworkproof.models import BindingDecision
from openworkproof.signing import key_id
from test_binding_decision_v04 import (
    DECIDED_AT,
    _compose,
    _sign_decision,
    _verified_decision,
)

DECIDED_AT_SUPERSEDE = "2026-01-01T00:00:20Z"


def _canonical_blob(value) -> bytes:
    return rfc8785.dumps(value.model_dump(mode="json"))


def _seed_verification_row(case, verification) -> None:
    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        scope_row = connection.execute(
            "SELECT scope_id FROM evaluation_scopes_v03 "
            "ORDER BY scope_id LIMIT 1"
        ).fetchone()
        assert scope_row is not None
        connection.execute(
            """
            INSERT INTO verification_profiles_v03 (
                profile_id, profile_digest, scope_id, scope_digest,
                subject_claim_id, profile_json
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                verification.profile_id,
                verification.profile_digest,
                scope_row[0],
                "0" * 64,
                case["claim"].claim_id,
                rfc8785.dumps({"schema_version": "openworkproof-verification-profile/0.3"}),
            ),
        )
        connection.execute(
            """
            INSERT INTO verification_decisions_v03 (
                decision_id, decision_digest, profile_id, scope_id,
                predecessor_id, decision_json
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                verification.decision_id,
                verification.digest,
                verification.profile_id,
                scope_row[0],
                None,
                _canonical_blob(verification),
            ),
        )
        connection.commit()
    finally:
        connection.close()


def _build_signed_decision(
    case,
    *,
    supersedes: BindingDecision | None = None,
    nonce: str = "a" * 64,
    decided_at: str = DECIDED_AT,
) -> BindingDecision:
    request = BindingDecisionDraftRequest(
        decided_at=decided_at,
        nonce=nonce,
        causal_parent_decision_ids=(
            (supersedes.binding_decision_id,) if supersedes is not None else ()
        ),
        supersedes_binding_decision_id=(
            supersedes.binding_decision_id if supersedes is not None else None
        ),
        supersedes_binding_decision_digest=(
            supersedes.digest if supersedes is not None else None
        ),
    )
    return _sign_decision(case, _compose(case, request=request))


def _commit(case, decision, **kwargs):
    return commit_binding_decision(
        case["ledger_path"],
        decision,
        transaction_time=kwargs.pop("transaction_time", case["now"]),
        **kwargs,
    )


def _tamper_decision(case, decision, **changes) -> BindingDecision:
    from openworkproof.binding import binding_decision_signing_bytes
    from openworkproof.models import BindingDecisionDraft

    payload = decision.model_dump(mode="json")
    payload.update(changes)
    draft_payload = {
        k: v
        for k, v in payload.items()
        if k not in {"schema_version", "digest", "verifier_signatures"}
    }
    draft = BindingDecisionDraft.model_validate(draft_payload)
    encoded = binding_decision_signing_bytes(draft)
    verifier_key = case["role_keys"]["Verifier"][0]
    signature = (
        base64.urlsafe_b64encode(verifier_key.sign(encoded))
        .decode("ascii")
        .rstrip("=")
    )
    return BindingDecision.model_validate(
        {
            **draft_payload,
            "schema_version": "openworkproof-binding-decision/0.4",
            "digest": hashlib.sha256(encoded).hexdigest(),
            "verifier_signatures": [
                {
                    "verifier_subject_id": (
                        decision.verifier_signatures[0].verifier_subject_id
                        if decision.verifier_signatures
                        else "verifier.example"
                    ),
                    "verifier_key_id": key_id(verifier_key.public_key()),
                    "signature_alg": "Ed25519",
                    "signature": signature,
                }
            ],
        }
    )

def test_commit_exact_decision_and_current_head(binding_decision_case) -> None:
    case = binding_decision_case
    verification = _verified_decision(
        work_order=case["work_order"],
        claim=case["claim"],
        scope=case["scope"],
        manifest=case["manifest"],
        keys=case["role_keys"],
    )
    _seed_verification_row(case, verification)
    decision = _build_signed_decision(case)
    committed = _commit(case, decision)
    assert committed == decision
    current = load_current_binding_decision(
        case["ledger_path"], case["work_order"].digest
    )
    assert current == decision
    row = evidence.connect_ledger(case["ledger_path"]).execute(
        "SELECT decision_json FROM binding_decisions_v04 "
        "WHERE binding_decision_id = ?",
        (decision.binding_decision_id,),
    ).fetchone()
    assert row[0] == _canonical_blob(decision)


def test_exact_idempotent_recommit(binding_decision_case) -> None:
    case = binding_decision_case
    verification = _verified_decision(
        work_order=case["work_order"],
        claim=case["claim"],
        scope=case["scope"],
        manifest=case["manifest"],
        keys=case["role_keys"],
    )
    _seed_verification_row(case, verification)
    decision = _build_signed_decision(case)
    _commit(case, decision)
    with pytest.raises(BindingCommittedError):
        _commit(case, decision)


def test_same_id_conflicting_payload(binding_decision_case) -> None:
    case = binding_decision_case
    verification = _verified_decision(
        work_order=case["work_order"],
        claim=case["claim"],
        scope=case["scope"],
        manifest=case["manifest"],
        keys=case["role_keys"],
    )
    _seed_verification_row(case, verification)
    decision = _build_signed_decision(case)
    _commit(case, decision)
    conflicting = _tamper_decision(
        case, decision, adapter_replay_digest="f" * 64
    )
    with pytest.raises(BindingTransactionError):
        _commit(case, conflicting)


def test_incomplete_malformed_decision(binding_decision_case) -> None:
    case = binding_decision_case
    verification = _verified_decision(
        work_order=case["work_order"],
        claim=case["claim"],
        scope=case["scope"],
        manifest=case["manifest"],
        keys=case["role_keys"],
    )
    _seed_verification_row(case, verification)
    decision = _tamper_decision(
        case, _build_signed_decision(case), judgment_commitment_digest="0" * 64
    )
    with pytest.raises(BindingInputError):
        _commit(case, decision)


def test_unknown_manifest_reference(binding_decision_case) -> None:
    case = binding_decision_case
    verification = _verified_decision(
        work_order=case["work_order"],
        claim=case["claim"],
        scope=case["scope"],
        manifest=case["manifest"],
        keys=case["role_keys"],
    )
    _seed_verification_row(case, verification)
    decision = _build_signed_decision(case)
    forged = _tamper_decision(
        case, decision, action_binding_manifest_digest="0" * 64
    )
    with pytest.raises((BindingInputError, BindingTransactionError)):
        _commit(case, forged)


def test_unknown_verification_reference(binding_decision_case) -> None:
    case = binding_decision_case
    verification = _verified_decision(
        work_order=case["work_order"],
        claim=case["claim"],
        scope=case["scope"],
        manifest=case["manifest"],
        keys=case["role_keys"],
    )
    _seed_verification_row(case, verification)
    decision = _build_signed_decision(case)
    forged = _tamper_decision(
        case, decision, verification_decision_digest="0" * 64
    )
    with pytest.raises((BindingInputError, BindingTransactionError)):
        _commit(case, forged)


def test_stale_supersession_parent(binding_decision_case) -> None:
    case = binding_decision_case
    verification = _verified_decision(
        work_order=case["work_order"],
        claim=case["claim"],
        scope=case["scope"],
        manifest=case["manifest"],
        keys=case["role_keys"],
    )
    _seed_verification_row(case, verification)
    head = _build_signed_decision(case)
    superseding = _build_signed_decision(
        case,
        supersedes=head,
        nonce="b" * 64,
        decided_at=DECIDED_AT_SUPERSEDE,
    )
    forged = _tamper_decision(
        case,
        superseding,
        causal_parent_decision_ids=("c" * 64,),
        supersedes_binding_decision_id="c" * 64,
        supersedes_binding_decision_digest="d" * 64,
    )
    with pytest.raises(BindingTransactionError):
        _commit(case, forged)

def test_already_superseded_parent(binding_decision_case) -> None:
    case = binding_decision_case
    verification = _verified_decision(
        work_order=case["work_order"],
        claim=case["claim"],
        scope=case["scope"],
        manifest=case["manifest"],
        keys=case["role_keys"],
    )
    _seed_verification_row(case, verification)
    head = _build_signed_decision(case)
    _commit(case, head)
    first = _build_signed_decision(
        case,
        supersedes=head,
        nonce="b" * 64,
        decided_at=DECIDED_AT_SUPERSEDE,
    )
    _commit(case, first, transaction_time=case["now"] + _one_second())
    second = _build_signed_decision(
        case,
        supersedes=head,
        nonce="c" * 64,
        decided_at=DECIDED_AT_SUPERSEDE,
    )
    with pytest.raises(BindingTransactionError):
        _commit(case, second, transaction_time=case["now"] + _two_seconds())
    current = load_current_binding_decision(
        case["ledger_path"], case["work_order"].digest
    )
    assert current == first


def _one_second():
    from datetime import timedelta

    return timedelta(seconds=1)


def _two_seconds():
    from datetime import timedelta

    return timedelta(seconds=2)


# ---------------------------------------------------------------------------
# Step 1: fault injection
# ---------------------------------------------------------------------------


def test_before_commit_fault_writes_nothing(binding_decision_case) -> None:
    case = binding_decision_case
    verification = _verified_decision(
        work_order=case["work_order"],
        claim=case["claim"],
        scope=case["scope"],
        manifest=case["manifest"],
        keys=case["role_keys"],
    )
    _seed_verification_row(case, verification)
    decision = _build_signed_decision(case)
    with pytest.raises(BindingTransactionError):
        _commit(case, decision, fault="before_commit")
    connection = evidence.connect_ledger(case["ledger_path"])
    try:
        assert (
            connection.execute(
                "SELECT 1 FROM binding_decisions_v04 "
                "WHERE binding_decision_id = ?",
                (decision.binding_decision_id,),
            ).fetchone()
            is None
        )
    finally:
        connection.close()


def test_commit_ack_loss_reports_committed(binding_decision_case) -> None:
    case = binding_decision_case
    verification = _verified_decision(
        work_order=case["work_order"],
        claim=case["claim"],
        scope=case["scope"],
        manifest=case["manifest"],
        keys=case["role_keys"],
    )
    _seed_verification_row(case, verification)
    decision = _build_signed_decision(case)
    with pytest.raises(BindingCommittedError) as captured:
        _commit(case, decision, fault="commit_ack_loss")
    assert captured.value.committed == decision
    current = load_current_binding_decision(
        case["ledger_path"], case["work_order"].digest
    )
    assert current == decision


def test_readback_failure_is_indeterminate(binding_decision_case) -> None:
    case = binding_decision_case
    verification = _verified_decision(
        work_order=case["work_order"],
        claim=case["claim"],
        scope=case["scope"],
        manifest=case["manifest"],
        keys=case["role_keys"],
    )
    _seed_verification_row(case, verification)
    decision = _build_signed_decision(case)
    with pytest.raises(BindingCommitIndeterminateError):
        _commit(case, decision, fault="readback_failure")


def test_cleanup_failure_reports_committed(binding_decision_case) -> None:
    case = binding_decision_case
    verification = _verified_decision(
        work_order=case["work_order"],
        claim=case["claim"],
        scope=case["scope"],
        manifest=case["manifest"],
        keys=case["role_keys"],
    )
    _seed_verification_row(case, verification)
    decision = _build_signed_decision(case)
    with pytest.raises(BindingCommittedError):
        _commit(case, decision, fault="cleanup_failure")
    current = load_current_binding_decision(
        case["ledger_path"], case["work_order"].digest
    )
    assert current == decision


# ---------------------------------------------------------------------------
# Step 4: one concurrent current winner
# ---------------------------------------------------------------------------


def test_concurrent_supersession_single_winner(binding_decision_case) -> None:
    case = binding_decision_case
    verification = _verified_decision(
        work_order=case["work_order"],
        claim=case["claim"],
        scope=case["scope"],
        manifest=case["manifest"],
        keys=case["role_keys"],
    )
    _seed_verification_row(case, verification)
    head = _build_signed_decision(case)
    _commit(case, head)
    first = _build_signed_decision(
        case,
        supersedes=head,
        nonce="b" * 64,
        decided_at=DECIDED_AT_SUPERSEDE,
    )
    second = _build_signed_decision(
        case,
        supersedes=head,
        nonce="c" * 64,
        decided_at=DECIDED_AT_SUPERSEDE,
    )
    barrier = threading.Barrier(2)
    outcomes: dict[str, str] = {}

    def attempt(decision: BindingDecision, label: str) -> None:
        barrier.wait()
        try:
            _commit(
                case,
                decision,
                transaction_time=case["now"] + _one_second(),
            )
            outcomes[label] = "committed"
        except BindingTransactionError:
            outcomes[label] = "conflict"
        except Exception:
            outcomes[label] = "other"

    first_thread = threading.Thread(
        target=attempt, args=(first, "first")
    )
    second_thread = threading.Thread(
        target=attempt, args=(second, "second")
    )
    first_thread.start()
    second_thread.start()
    first_thread.join(timeout=30)
    second_thread.join(timeout=30)
    assert sorted(outcomes.values()) == ["committed", "conflict"]
    current = load_current_binding_decision(
        case["ledger_path"], case["work_order"].digest
    )
    winner_id = (
        first.binding_decision_id
        if outcomes["first"] == "committed"
        else second.binding_decision_id
    )
    assert current.binding_decision_id == winner_id
