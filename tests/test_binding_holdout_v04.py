"""Pre-registered holdouts for judgment-to-action binding (Task 14, Step 4).

Four independent holdouts are frozen here before any execution. The runner
classifies each result as ``adjudicated`` (matches the frozen expectation),
``divergent`` (does not) or ``pipeline-invalid`` (could not be executed). The
frozen expectations are never rewritten after execution.
"""

from __future__ import annotations

from openworkproof.binding import (
    BindingDecisionDraftRequest,
    compose_binding_decision,
)
from openworkproof.models import VerificationDecisionV03
from test_binding_adversarial_v04 import (
    _checkpoint_chain,
    _clean_observed,
    _compose_with_replay,
    _high_risk_verification,
    _replay,
    _verified_decision as _verified,
)
from test_binding_decision_v04 import _compose

DECIDED_AT = "2026-01-01T00:00:10Z"

# Frozen holdout registry: (id, responsibility layer, expected outcome,
# adversarial description). Immutable; never edited post-hoc.
HOLDOUTS = (
    ("H1", "adapter", "UNBOUND", "covered acceptance conditions incomplete"),
    ("H2", "authority", "UNBOUND", "stale external checkpoint at action time"),
    ("H3", "binding", "INDETERMINATE", "judgment referenced only in metadata"),
    ("H4", "full_chain", "BOUND", "clean positive control"),
)


def _run_holdout(case, holdout) -> tuple[str, str | None]:
    """Execute one holdout and return (classification, actual_outcome)."""
    holdout_id, layer, expected, _ = holdout
    try:
        if holdout_id == "H1":
            observed = _clean_observed(case)
            observed["covered_condition_digests"] = [
                case["judgment"].acceptance_condition_digests[0]
            ]
            outcome = _replay(case, observed=observed).outcome
        elif holdout_id == "H2":
            chain, key = _checkpoint_chain(case, expired=True)
            draft = compose_binding_decision(
                judgment=case["judgment"],
                manifest=case["manifest"],
                verification=_high_risk_verification(case),
                receipts=(case["receipt"],),
                replay=_replay(case),
                checkpoint=None,
                request=BindingDecisionDraftRequest(
                    decided_at="2026-01-01T00:10:00Z", nonce="a" * 64
                ),
                checkpoint_chain=chain,
                authority_key=key,
            )
            outcome = draft.decision
        elif holdout_id == "H3":
            legacy_receipt = next(
                receipt
                for receipt in case["context"].ledger_prefix.receipts
                if type(receipt).__name__ == "ToolCallReceipt"
            )
            outcome = _compose(case, receipts=(legacy_receipt,)).decision
        elif holdout_id == "H4":
            outcome = _compose_with_replay(case, _replay(case)).decision
        else:  # pragma: no cover - registry is frozen above
            raise AssertionError("unknown holdout id")
    except Exception:
        return "pipeline-invalid", None
    if outcome == expected:
        return "adjudicated", outcome
    return "divergent", outcome


def test_four_holdouts_pre_registered_and_adjudicated(
    binding_decision_case,
) -> None:
    assert len(HOLDOUTS) == 4
    assert tuple(holdout[0] for holdout in HOLDOUTS) == (
        "H1",
        "H2",
        "H3",
        "H4",
    )
    for holdout in HOLDOUTS:
        classification, actual = _run_holdout(binding_decision_case, holdout)
        assert classification == "adjudicated", (
            f"holdout {holdout[0]} classified {classification}, "
            f"actual={actual}, expected={holdout[2]}"
        )


def test_holdout_registry_is_immutable() -> None:
    # Expectations are data, not code: they cannot be rewritten by the
    # runner after execution.
    ids = tuple(holdout[0] for holdout in HOLDOUTS)
    layers = tuple(holdout[1] for holdout in HOLDOUTS)
    expected = tuple(holdout[2] for holdout in HOLDOUTS)
    assert ids == ("H1", "H2", "H3", "H4")
    assert layers == ("adapter", "authority", "binding", "full_chain")
    assert expected == ("UNBOUND", "UNBOUND", "INDETERMINATE", "BOUND")
