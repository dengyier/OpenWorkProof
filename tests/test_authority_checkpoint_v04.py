"""AuthorityCheckpoint chain, as-of evaluation and high-risk integration (Task 10)."""

from __future__ import annotations

from datetime import timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import openworkproof.authority as authority
import openworkproof.evidence as evidence
from openworkproof.binding import (
    BindingDecisionDraftRequest,
    compose_binding_decision,
)
from openworkproof.binding_transactions import (
    BindingCommittedError,
    BindingTransactionError,
    commit_authority_checkpoint,
    load_authority_chain,
)
from openworkproof.models import AuthorityCheckpoint
from openworkproof.signing import sign_authority_checkpoint
from test_binding_decision_v04 import (
    _compose,
    _sign_decision,
    _verified_decision,
)

NAMESPACE = "customer.example"
SUBJECT = "issue-123"
DECIDED_AT_CURRENT = "2026-01-01T00:20:00Z"
DECIDED_AT_STALE = "2026-01-01T00:05:00Z"


def _checkpoint(
    authority_key: Ed25519PrivateKey,
    *,
    revision: int,
    effective_at: str,
    expires_at: str,
    predecessor_digest: str | None = None,
    checkpoint_id: str | None = None,
    digest: str | None = None,
) -> AuthorityCheckpoint:
    return AuthorityCheckpoint.model_validate(
        sign_authority_checkpoint(
            {
                "schema_version": "openworkproof-authority-checkpoint/0.4",
                "checkpoint_id": (
                    checkpoint_id
                    or f"{revision:064d}"
                ),
                "authority_namespace": NAMESPACE,
                "subject_id": SUBJECT,
                "monotonic_revision": revision,
                "current_judgment_commitment_digest": (
                    digest or f"{revision:064d}"
                ),
                "predecessor_checkpoint_digest": predecessor_digest,
                "effective_at": effective_at,
                "expires_at": expires_at,
            },
            authority_key,
        )
    )


def _chain(authority_key: Ed25519PrivateKey) -> tuple[AuthorityCheckpoint, ...]:
    genesis = _checkpoint(
        authority_key,
        revision=1,
        effective_at="2026-01-01T00:00:00Z",
        expires_at="2026-01-01T00:30:00Z",
    )
    successor = _checkpoint(
        authority_key,
        revision=2,
        effective_at="2026-01-01T00:15:00Z",
        expires_at="2026-01-01T01:00:00Z",
        predecessor_digest=genesis.digest,
    )
    return (genesis, successor)


@pytest.fixture
def authority_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


# ---------------------------------------------------------------------------
# Step 1: pure chain validation and as-of evaluation
# ---------------------------------------------------------------------------


def test_valid_chain_is_current(authority_key) -> None:
    status, digest = authority.evaluate_authority_status(
        _chain(authority_key),
        authority_namespace=NAMESPACE,
        subject_id=SUBJECT,
        authority_key=authority_key.public_key(),
        occurred_at=_as_utc(DECIDED_AT_CURRENT),
    )
    assert status == "current"
    assert digest == _chain(authority_key)[-1].digest


def test_wrong_authority_key_is_invalid(authority_key) -> None:
    other_key = Ed25519PrivateKey.generate()
    verdict = authority.validate_authority_chain(
        _chain(authority_key),
        authority_namespace=NAMESPACE,
        subject_id=SUBJECT,
        authority_key=other_key.public_key(),
    )
    assert verdict.status == "invalid"


def test_non_monotonic_revision_is_invalid(authority_key) -> None:
    genesis = _checkpoint(
        authority_key,
        revision=1,
        effective_at="2026-01-01T00:00:00Z",
        expires_at="2026-01-01T01:00:00Z",
    )
    skipped = _checkpoint(
        authority_key,
        revision=3,
        effective_at="2026-01-01T00:30:00Z",
        expires_at="2026-01-01T01:00:00Z",
        predecessor_digest=genesis.digest,
    )
    verdict = authority.validate_authority_chain(
        (genesis, skipped),
        authority_namespace=NAMESPACE,
        subject_id=SUBJECT,
        authority_key=authority_key.public_key(),
    )
    assert verdict.status == "invalid"


def test_wrong_predecessor_digest_is_invalid(authority_key) -> None:
    genesis = _checkpoint(
        authority_key,
        revision=1,
        effective_at="2026-01-01T00:00:00Z",
        expires_at="2026-01-01T01:00:00Z",
    )
    broken = _checkpoint(
        authority_key,
        revision=2,
        effective_at="2026-01-01T00:30:00Z",
        expires_at="2026-01-01T01:00:00Z",
        predecessor_digest="f" * 64,
    )
    verdict = authority.validate_authority_chain(
        (genesis, broken),
        authority_namespace=NAMESPACE,
        subject_id=SUBJECT,
        authority_key=authority_key.public_key(),
    )
    assert verdict.status == "invalid"


def test_same_revision_fork_detected(authority_key) -> None:
    genesis = _checkpoint(
        authority_key,
        revision=1,
        effective_at="2026-01-01T00:00:00Z",
        expires_at="2026-01-01T01:00:00Z",
    )
    fork_a = _checkpoint(
        authority_key,
        revision=2,
        effective_at="2026-01-01T00:15:00Z",
        expires_at="2026-01-01T01:00:00Z",
        predecessor_digest=genesis.digest,
    )
    fork_b = _checkpoint(
        authority_key,
        revision=2,
        effective_at="2026-01-01T00:15:00Z",
        expires_at="2026-01-01T01:00:00Z",
        predecessor_digest=genesis.digest,
        checkpoint_id="b" * 64,
    )
    verdict = authority.validate_authority_chain(
        (genesis, fork_a, fork_b),
        authority_namespace=NAMESPACE,
        subject_id=SUBJECT,
        authority_key=authority_key.public_key(),
    )
    assert verdict.status == "forked"


def test_revision_rollback_detected(authority_key) -> None:
    genesis = _checkpoint(
        authority_key,
        revision=1,
        effective_at="2026-01-01T00:00:00Z",
        expires_at="2026-01-01T01:00:00Z",
    )
    successor = _checkpoint(
        authority_key,
        revision=2,
        effective_at="2026-01-01T00:15:00Z",
        expires_at="2026-01-01T01:00:00Z",
        predecessor_digest=genesis.digest,
    )
    verdict = authority.validate_authority_chain(
        (successor, genesis),
        authority_namespace=NAMESPACE,
        subject_id=SUBJECT,
        authority_key=authority_key.public_key(),
    )
    assert verdict.status == "rollback"


def test_stale_when_head_not_effective_at_action_time(authority_key) -> None:
    status, digest = authority.evaluate_authority_status(
        _chain(authority_key),
        authority_namespace=NAMESPACE,
        subject_id=SUBJECT,
        authority_key=authority_key.public_key(),
        occurred_at=_as_utc(DECIDED_AT_STALE),
    )
    assert status == "stale"
    assert digest == _chain(authority_key)[-1].digest


def test_resolver_unavailable_is_input_status(authority_key) -> None:
    status, digest = authority.evaluate_authority_status(
        _chain(authority_key),
        authority_namespace=NAMESPACE,
        subject_id=SUBJECT,
        authority_key=authority_key.public_key(),
        occurred_at=_as_utc(DECIDED_AT_CURRENT),
        resolver_unavailable=True,
    )
    assert status == "unavailable"
    assert digest is None


def test_historical_action_uses_checkpoint_as_of_occurred_at(
    authority_key,
) -> None:
    # At 00:20 the successor (00:15-01:00) is current; even though a later
    # review would find it expired, the as-of verdict stays current.
    status, digest = authority.evaluate_authority_status(
        _chain(authority_key),
        authority_namespace=NAMESPACE,
        subject_id=SUBJECT,
        authority_key=authority_key.public_key(),
        occurred_at=_as_utc(DECIDED_AT_CURRENT),
    )
    assert status == "current"
    assert digest is not None


def _as_utc(value: str):
    from datetime import datetime, timezone

    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )


# ---------------------------------------------------------------------------
# Step 3: append-only checkpoint ledger
# ---------------------------------------------------------------------------


def test_commit_genesis_and_successor(binding_decision_case, authority_key) -> None:
    case = binding_decision_case
    genesis, successor = _chain(authority_key)
    commit_authority_checkpoint(
        case["ledger_path"],
        genesis,
        transaction_time=case["now"],
    )
    commit_authority_checkpoint(
        case["ledger_path"],
        successor,
        transaction_time=case["now"] + timedelta(seconds=1),
    )
    chain = load_authority_chain(
        case["ledger_path"],
        authority_namespace=NAMESPACE,
        subject_id=SUBJECT,
    )
    assert tuple(item.digest for item in chain) == (
        genesis.digest,
        successor.digest,
    )


def test_commit_rejects_fork(binding_decision_case, authority_key) -> None:
    case = binding_decision_case
    genesis, successor = _chain(authority_key)
    commit_authority_checkpoint(
        case["ledger_path"], genesis, transaction_time=case["now"]
    )
    commit_authority_checkpoint(
        case["ledger_path"], successor, transaction_time=case["now"]
    )
    fork = _checkpoint(
        authority_key,
        revision=2,
        effective_at="2026-01-01T00:15:00Z",
        expires_at="2026-01-01T01:00:00Z",
        predecessor_digest=genesis.digest,
        checkpoint_id="b" * 64,
    )
    with pytest.raises(BindingTransactionError):
        commit_authority_checkpoint(
            case["ledger_path"], fork, transaction_time=case["now"]
        )


def test_commit_missing_predecessor_rejected(
    binding_decision_case, authority_key,
) -> None:
    case = binding_decision_case
    _, successor = _chain(authority_key)
    with pytest.raises(BindingTransactionError):
        commit_authority_checkpoint(
            case["ledger_path"], successor, transaction_time=case["now"]
        )


def test_commit_exact_idempotent(binding_decision_case, authority_key) -> None:
    case = binding_decision_case
    genesis, _ = _chain(authority_key)
    commit_authority_checkpoint(
        case["ledger_path"], genesis, transaction_time=case["now"]
    )
    with pytest.raises(BindingCommittedError):
        commit_authority_checkpoint(
            case["ledger_path"], genesis, transaction_time=case["now"]
        )


# ---------------------------------------------------------------------------
# Step 4: high-risk decision integration
# ---------------------------------------------------------------------------


def _compose_high_risk(
    case,
    *,
    checkpoint_chain,
    authority_key,
    decided_at=DECIDED_AT_CURRENT,
    resolver_unavailable=False,
):
    verification = _verified_decision(
        work_order=case["work_order"],
        claim=case["claim"],
        scope=case["scope"],
        manifest=case["manifest"],
        keys=case["role_keys"],
        assurance_level="high_risk",
    )
    return compose_binding_decision(
        judgment=case["judgment"],
        manifest=case["manifest"],
        verification=verification,
        receipts=(case["receipt"],),
        replay=_bound_replay(case),
        checkpoint=None,
        request=BindingDecisionDraftRequest(
            decided_at=decided_at, nonce="a" * 64
        ),
        checkpoint_chain=checkpoint_chain,
        authority_key=authority_key.public_key(),
        resolver_unavailable=resolver_unavailable,
    )


def _bound_replay(case):
    from test_binding_decision_v04 import _bound_replay as _replay

    return _replay(case["judgment"], case["projection"])


def test_high_risk_current_checkpoint_bounds(
    binding_decision_case, authority_key,
) -> None:
    case = binding_decision_case
    draft = _compose_high_risk(
        case,
        checkpoint_chain=_chain(authority_key),
        authority_key=authority_key,
    )
    assert draft.decision == "BOUND"
    assert draft.authority_status == "current"
    assert draft.authority_checkpoint_digest == _chain(authority_key)[-1].digest


def test_high_risk_stale_checkpoint_unbounds(
    binding_decision_case, authority_key,
) -> None:
    case = binding_decision_case
    draft = _compose_high_risk(
        case,
        checkpoint_chain=_chain(authority_key),
        authority_key=authority_key,
        decided_at=DECIDED_AT_STALE,
    )
    assert draft.decision == "UNBOUND"
    assert draft.reason_codes == ("AUTHORITY_CHECKPOINT_STALE",)
    assert draft.authority_status == "stale"


def test_high_risk_fork_unbounds(binding_decision_case, authority_key) -> None:
    case = binding_decision_case
    genesis, successor = _chain(authority_key)
    fork = _checkpoint(
        authority_key,
        revision=2,
        effective_at="2026-01-01T00:15:00Z",
        expires_at="2026-01-01T01:00:00Z",
        predecessor_digest=genesis.digest,
        checkpoint_id="b" * 64,
    )
    draft = _compose_high_risk(
        case,
        checkpoint_chain=(genesis, successor, fork),
        authority_key=authority_key,
    )
    assert draft.decision == "UNBOUND"
    assert draft.reason_codes == ("AUTHORITY_FORK_DETECTED",)
    assert draft.authority_status == "forked"


def test_high_risk_rollback_unbounds(
    binding_decision_case, authority_key,
) -> None:
    case = binding_decision_case
    genesis, successor = _chain(authority_key)
    draft = _compose_high_risk(
        case,
        checkpoint_chain=(successor, genesis),
        authority_key=authority_key,
    )
    assert draft.decision == "UNBOUND"
    assert draft.reason_codes == ("AUTHORITY_ROLLBACK_DETECTED",)
    assert draft.authority_status == "stale"


def test_high_risk_missing_checkpoint_indeterminate(
    binding_decision_case, authority_key,
) -> None:
    case = binding_decision_case
    draft = _compose_high_risk(
        case,
        checkpoint_chain=(),
        authority_key=authority_key,
    )
    assert draft.decision == "INDETERMINATE"
    assert draft.reason_codes == ("AUTHORITY_CHECKPOINT_MISSING",)
    assert draft.authority_status == "missing"


def test_high_risk_resolver_unavailable_indeterminate(
    binding_decision_case, authority_key,
) -> None:
    case = binding_decision_case
    draft = _compose_high_risk(
        case,
        checkpoint_chain=_chain(authority_key),
        authority_key=authority_key,
        resolver_unavailable=True,
    )
    assert draft.decision == "INDETERMINATE"
    assert draft.reason_codes == ("REPLAY_UNAVAILABLE",)
    assert draft.authority_status == "unavailable"
