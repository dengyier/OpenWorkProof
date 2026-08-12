"""v0.4 acceptance dual gate and settlement readiness (Task 11)."""

from __future__ import annotations

import copy

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from openworkproof.acceptance import (
    validate_v04_acceptance_chain,
    v04_dual_gate_opens,
)
from openworkproof.models import (
    BindingDecision,
    VerificationDecisionV03,
)
from openworkproof.settlement import (
    EffectiveAcceptance,
    SettlementReadiness,
    settlement_readiness_v04,
)
from test_binding_decision_v04 import (
    _bound_replay,
    _compose,
    _sign_decision,
    _verified_decision,
)


def _bound_decision(case) -> BindingDecision:
    return _sign_decision(case, _compose(case))


def _unbound_decision(case) -> BindingDecision:
    replay = _bound_replay(case["judgment"], case["projection"])
    unbound = type(replay)(
        outcome="UNBOUND",
        reason_codes=("ACTION_OUTSIDE_APPROVED_SCOPE",),
        replay_digest=replay.replay_digest,
    )
    return _sign_decision(case, _compose(case, replay=unbound))


def _indeterminate_decision(case) -> BindingDecision:
    replay = _bound_replay(case["judgment"], case["projection"])
    indeterminate = type(replay)(
        outcome="INDETERMINATE",
        reason_codes=("EVALUATOR_VERSION_DRIFT",),
        replay_digest=replay.replay_digest,
    )
    return _sign_decision(case, _compose(case, replay=indeterminate))


def _verified(case, decision="VERIFIED") -> VerificationDecisionV03:
    return _verified_decision(
        work_order=case["work_order"],
        claim=case["claim"],
        scope=case["scope"],
        manifest=case["manifest"],
        keys=case["role_keys"],
        decision=decision,
    )


def _checkpoint() -> "object":
    key = Ed25519PrivateKey.generate()
    from openworkproof.models import AuthorityCheckpoint
    from openworkproof.signing import sign_authority_checkpoint

    return AuthorityCheckpoint.model_validate(
        sign_authority_checkpoint(
            {
                "schema_version": "openworkproof-authority-checkpoint/0.4",
                "checkpoint_id": "1" * 64,
                "authority_namespace": "customer.example",
                "subject_id": "issue-123",
                "monotonic_revision": 1,
                "current_judgment_commitment_digest": "2" * 64,
                "predecessor_checkpoint_digest": None,
                "effective_at": "2026-01-01T00:00:00Z",
                "expires_at": "2026-01-01T01:00:00Z",
            },
            key,
        )
    )


# ---------------------------------------------------------------------------
# Step 1: cross-product acceptance gate
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("verification", "binding", "acceptance", "checkpoint_required", "current", "opens"),
    [
        ("VERIFIED", "BOUND", "ACTIVE", False, None, True),
        ("VERIFIED", "BOUND", "ACTIVE", True, True, True),
        ("REFUTED", "BOUND", "ACTIVE", False, None, False),
        ("UNKNOWN", "BOUND", "ACTIVE", False, None, False),
        ("VERIFIED", "UNBOUND", "ACTIVE", False, None, False),
        ("VERIFIED", "INDETERMINATE", "ACTIVE", False, None, False),
        ("VERIFIED", "BOUND", "NONE", False, None, False),
        ("VERIFIED", "BOUND", "SUSPENDED", False, None, False),
        ("VERIFIED", "BOUND", "ACTIVE", True, False, False),
    ],
)
def test_dual_gate_cross_product(
    binding_decision_case,
    verification,
    binding,
    acceptance,
    checkpoint_required,
    current,
    opens,
) -> None:
    case = binding_decision_case
    verified = _verified(case) if verification is not None else None
    if verification in {"REFUTED", "UNKNOWN"}:
        verified = _verified(case, decision=verification)
    bound = {
        "BOUND": _bound_decision(case),
        "UNBOUND": _unbound_decision(case),
        "INDETERMINATE": _indeterminate_decision(case),
    }[binding] if binding in {"BOUND", "UNBOUND", "INDETERMINATE"} else None
    gate_opens, reasons = v04_dual_gate_opens(
        verification=verified,
        binding_decision=bound,
        acceptance=EffectiveAcceptance(acceptance),
        checkpoint_required=checkpoint_required,
        checkpoint_current=current,
    )
    assert gate_opens is opens
    assert bool(reasons) != opens


def test_dual_gate_never_opens_on_mixed_products(
    binding_decision_case,
) -> None:
    case = binding_decision_case
    # Every non-approved combination must be closed.
    combinations = [
        (_verified(case, decision="REFUTED"), _bound_decision(case)),
        (_verified(case, decision="UNKNOWN"), _bound_decision(case)),
        (_verified(case), _unbound_decision(case)),
        (_verified(case), _indeterminate_decision(case)),
        (_verified(case), None),
        (None, _bound_decision(case)),
    ]
    for verification, binding in combinations:
        opens, _ = v04_dual_gate_opens(
            verification=verification,
            binding_decision=binding,
            acceptance=EffectiveAcceptance.ACTIVE,
        )
        assert opens is False


# ---------------------------------------------------------------------------
# Step 3: exact same-chain identities
# ---------------------------------------------------------------------------


def test_same_chain_identities_pass(binding_decision_case) -> None:
    case = binding_decision_case
    ok, failures = validate_v04_acceptance_chain(
        work_order=case["work_order"],
        subject_claim=case["claim"],
        scope=case["scope"],
        judgment=case["judgment"],
        manifest=case["manifest"],
        verification=_verified(case),
        binding_decision=_bound_decision(case),
    )
    assert ok is True
    assert failures == ()


def test_binding_verification_mismatch_rejected(binding_decision_case) -> None:
    from test_binding_transactions_v04 import _tamper_decision

    case = binding_decision_case
    binding = _tamper_decision(
        case, _bound_decision(case), verification_decision_digest="0" * 64
    )
    ok, failures = validate_v04_acceptance_chain(
        work_order=case["work_order"],
        subject_claim=case["claim"],
        scope=case["scope"],
        judgment=case["judgment"],
        manifest=case["manifest"],
        verification=_verified(case),
        binding_decision=binding,
    )
    assert ok is False
    assert "BINDING_VERIFICATION_MISMATCH" in failures


def test_binding_manifest_mismatch_rejected(binding_decision_case) -> None:
    from test_binding_transactions_v04 import _tamper_decision

    case = binding_decision_case
    binding = _tamper_decision(
        case, _bound_decision(case), action_binding_manifest_digest="0" * 64
    )
    ok, failures = validate_v04_acceptance_chain(
        work_order=case["work_order"],
        subject_claim=case["claim"],
        scope=case["scope"],
        judgment=case["judgment"],
        manifest=case["manifest"],
        verification=_verified(case),
        binding_decision=binding,
    )
    assert ok is False
    assert "BINDING_MANIFEST_MISMATCH" in failures


def test_checkpoint_digest_mismatch_rejected(binding_decision_case) -> None:
    case = binding_decision_case
    checkpoint = _checkpoint()
    binding = _bound_decision(case)
    ok, failures = validate_v04_acceptance_chain(
        work_order=case["work_order"],
        subject_claim=case["claim"],
        scope=case["scope"],
        judgment=case["judgment"],
        manifest=case["manifest"],
        verification=_verified(case),
        binding_decision=binding,
        checkpoint=checkpoint,
    )
    # binding has no checkpoint digest (not_required) so a supplied
    # checkpoint must be rejected as mismatched.
    assert ok is False
    assert "BINDING_CHECKPOINT_MISMATCH" in failures


# ---------------------------------------------------------------------------
# Step 4: v0.4 readiness result
# ---------------------------------------------------------------------------


def test_v04_readiness_requires_complete_tuple(binding_decision_case) -> None:
    case = binding_decision_case
    verified = _verified(case)
    bound = _bound_decision(case)
    readiness = settlement_readiness_v04(
        verification=verified,
        binding_decision=bound,
        acceptance=EffectiveAcceptance.ACTIVE,
        commercial_evidence_refs=("sow://customer.example/sow-2026-01",),
    )
    assert readiness is SettlementReadiness.READY_FOR_SETTLEMENT_REVIEW


def test_v04_readiness_never_positive_on_partial_tuple(
    binding_decision_case,
) -> None:
    case = binding_decision_case
    verified = _verified(case)
    bound = _bound_decision(case)
    cases = [
        dict(
            verification=None,
            binding_decision=bound,
            acceptance=EffectiveAcceptance.ACTIVE,
        ),
        dict(
            verification=_verified(case, decision="REFUTED"),
            binding_decision=bound,
            acceptance=EffectiveAcceptance.ACTIVE,
        ),
        dict(
            verification=verified,
            binding_decision=None,
            acceptance=EffectiveAcceptance.ACTIVE,
        ),
        dict(
            verification=verified,
            binding_decision=_unbound_decision(case),
            acceptance=EffectiveAcceptance.ACTIVE,
        ),
        dict(
            verification=verified,
            binding_decision=bound,
            acceptance=EffectiveAcceptance.NONE,
        ),
        dict(
            verification=verified,
            binding_decision=bound,
            acceptance=EffectiveAcceptance.ACTIVE,
            commercial_evidence_refs=(),
        ),
    ]
    for kwargs in cases:
        assert (
            settlement_readiness_v04(**kwargs)
            is SettlementReadiness.NOT_READY
        )


def test_v04_readiness_preserves_acceptance_terminals(
    binding_decision_case,
) -> None:
    case = binding_decision_case
    for state in (
        EffectiveAcceptance.SUSPENDED,
        EffectiveAcceptance.WITHDRAWN,
        EffectiveAcceptance.SUPERSEDED,
    ):
        assert (
            settlement_readiness_v04(
                verification=_verified(case),
                binding_decision=_bound_decision(case),
                acceptance=state,
                commercial_evidence_refs=("sow://x",),
            )
            is SettlementReadiness(state.value)
        )
