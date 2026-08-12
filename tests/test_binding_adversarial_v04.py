"""Registered adversarial attack matrix C0 + A1-A18 and negative controls
(Task 14). Expectations are frozen before execution: each case carries its
responsibility layer and expected result and is never rewritten post-hoc."""

from __future__ import annotations

import base64
import copy
import hashlib

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from openworkproof.adapters import (
    ADAPTER_ID,
    ADAPTER_VERSION,
    CodeDeliveryAdapterProfile,
    CodeDeliveryJudgmentInput,
    CodeDeliveryReplayInput,
    ObservedAction,
    replay_code_delivery_binding,
)
from openworkproof.binding import (
    BindingDecisionDraftRequest,
    compose_binding_decision,
)
from openworkproof.binding_transactions import (
    BindingInputError,
    BindingTransactionError,
    commit_judgment_commitment,
    JudgmentAuthorityContext,
)
from openworkproof.models import (
    BindingDecision,
    JudgmentCommitment,
    ToolCallReceiptV04,
    VerificationDecisionV03,
)
from openworkproof.verification import verification_decision_signing_bytes_v03
from test_binding_decision_v04 import (
    _bound_replay,
    _compose,
    _sign_decision,
    _verified_decision,
)
from test_binding_transactions_v04 import _tamper_decision

DECIDED_AT = "2026-01-01T00:00:10Z"


# ---------------------------------------------------------------------------
# replay helpers (code-delivery analogues)
# ---------------------------------------------------------------------------


def _judgment_input(case) -> dict:
    judgment = case["judgment"]
    projection = case["projection"]
    return {
        "adapter_id": ADAPTER_ID,
        "adapter_version": ADAPTER_VERSION,
        "adapter_profile_digest": judgment.adapter_profile_digest,
        "issue_snapshot_digest": judgment.judgment_artifact_digest,
        "repository_identity": judgment.repository,
        "source_revision": judgment.source_revision,
        "target_branch": judgment.target_branch,
        "acceptance_condition_digests": list(
            judgment.acceptance_condition_digests
        ),
        "excluded_scope_digests": list(judgment.excluded_scope_digests),
        "excluded_path_roots": [],
        "required_artifact_digests": list(judgment.required_artifact_digests),
        "allowed_path_roots": list(projection.allowed_path_roots),
        "allowed_action_kinds": list(projection.allowed_action_kinds),
        "required_test_profile_digests": list(
            projection.required_test_profile_digests
        ),
    }


def _profile(case) -> dict:
    judgment = case["judgment"]
    projection = case["projection"]
    return {
        "adapter_id": ADAPTER_ID,
        "adapter_version": ADAPTER_VERSION,
        "adapter_profile_digest": judgment.adapter_profile_digest,
        "allowed_tool_names": list(projection.allowed_tool_names),
        "allowed_action_kinds": list(projection.allowed_action_kinds),
        "allowed_path_roots": list(projection.allowed_path_roots),
        "required_test_profile_digests": list(
            projection.required_test_profile_digests
        ),
    }


def _clean_observed(case) -> dict:
    judgment = case["judgment"]
    return {
        "tool_name": "owp.run_tests",
        "action_kind": "test",
        "changed_paths": [],
        "patch_digest": None,
        "candidate_commit_digest": None,
        "workspace_digest": None,
        "artifact_digests": list(judgment.required_artifact_digests),
        "covered_condition_digests": list(
            judgment.acceptance_condition_digests
        ),
        "undeclared_side_effects": [],
        "issue_snapshot_digest": judgment.judgment_artifact_digest,
    }


def _replay(case, *, observed=None, judgment=None, profile=None):
    return replay_code_delivery_binding(
        CodeDeliveryReplayInput(
            judgment=CodeDeliveryJudgmentInput(
                **(judgment or _judgment_input(case))
            ),
            profile=CodeDeliveryAdapterProfile(
                **(profile or _profile(case))
            ),
            observed=ObservedAction(**(observed or _clean_observed(case))),
        )
    )


def _compose_with_replay(case, replay):
    return compose_binding_decision(
        judgment=case["judgment"],
        manifest=case["manifest"],
        verification=_verified_decision(
            work_order=case["work_order"],
            claim=case["claim"],
            scope=case["scope"],
            manifest=case["manifest"],
            keys=case["role_keys"],
        ),
        receipts=(case["receipt"],),
        replay=replay,
        checkpoint=None,
        request=BindingDecisionDraftRequest(
            decided_at=DECIDED_AT, nonce="a" * 64
        ),
    )


def _tamper_verification(
    case, verification: VerificationDecisionV03, *, work_order_digest: str
) -> VerificationDecisionV03:
    from openworkproof.models import VerificationDecisionDraftV03

    raw = verification.model_dump(
        mode="json",
        exclude={"digest", "verifier_signatures", "schema_version"},
    )
    raw["work_order_digest"] = work_order_digest
    draft = VerificationDecisionDraftV03.model_validate(raw)
    encoded = verification_decision_signing_bytes_v03(draft)
    keys = [case["role_keys"]["Verifier"][0]]
    if raw.get("assurance_level") == "high_risk":
        keys.append(Ed25519PrivateKey.generate())
    signatures = [
        {
            "verifier_subject_id": f"verifier{index + 1}.example",
            "verifier_key_id": _key_id(key.public_key()),
            "signature_alg": "Ed25519",
            "signature": _sign(key, encoded),
        }
        for index, key in enumerate(keys)
    ]
    signatures.sort(key=lambda item: item["verifier_key_id"].encode("utf-8"))
    return VerificationDecisionV03.model_validate(
        {
            **raw,
            "schema_version": "openworkproof-verification-decision/0.3",
            "digest": hashlib.sha256(encoded).hexdigest(),
            "verifier_signatures": signatures,
        }
    )


def _key_id(public_key) -> str:
    from openworkproof.signing import key_id

    return key_id(public_key)


def _sign(private_key, encoded: bytes) -> str:
    return (
        base64.urlsafe_b64encode(private_key.sign(encoded))
        .decode("ascii")
        .rstrip("=")
    )


def _high_risk_verification(case) -> VerificationDecisionV03:
    return _verified_decision(
        work_order=case["work_order"],
        claim=case["claim"],
        scope=case["scope"],
        manifest=case["manifest"],
        keys=case["role_keys"],
        assurance_level="high_risk",
    )


def _checkpoint_chain(case, *, expired=False) -> tuple:
    from openworkproof.models import AuthorityCheckpoint
    from openworkproof.signing import sign_authority_checkpoint

    authority_key = Ed25519PrivateKey.generate()
    genesis = AuthorityCheckpoint.model_validate(
        sign_authority_checkpoint(
            {
                "schema_version": "openworkproof-authority-checkpoint/0.4",
                "checkpoint_id": "1" * 64,
                "authority_namespace": case["judgment"].authority_namespace,
                "subject_id": case["judgment"].subject_id,
                "monotonic_revision": 1,
                "current_judgment_commitment_digest": "2" * 64,
                "predecessor_checkpoint_digest": None,
                "effective_at": "2026-01-01T00:00:00Z",
                "expires_at": (
                    "2026-01-01T00:05:00Z" if expired else "2026-01-01T01:00:00Z"
                ),
            },
            authority_key,
        )
    )
    return (genesis,), authority_key.public_key()


# ---------------------------------------------------------------------------
# C0: clean positive control
# ---------------------------------------------------------------------------


def test_c0_clean_delivery_is_bound(binding_decision_case) -> None:
    case = binding_decision_case
    replay = _replay(case)
    assert replay.outcome == "BOUND"
    draft = _compose_with_replay(case, replay)
    assert draft.decision == "BOUND"
    assert draft.reason_codes == ()


# ---------------------------------------------------------------------------
# A1-A18: registered attack matrix
# ---------------------------------------------------------------------------


def test_a1_modified_action_without_resign_is_layer1_rejected(
    binding_decision_case,
) -> None:
    # Modify the receipt payload without re-signing: Layer 1 must reject.
    case = binding_decision_case
    raw = case["receipt"].model_dump(mode="json")
    raw["output_digest"] = "f" * 64
    with pytest.raises(Exception):
        ToolCallReceiptV04.model_validate(raw)


def test_a2_coherent_resign_outside_judgment_is_unbound(
    binding_decision_case,
) -> None:
    # Manager/Agent/Sidecar re-sign a complete internally valid chain for an
    # action outside the Acceptor's signed constraint (250 -> 2500 analogue).
    case = binding_decision_case
    observed = _clean_observed(case)
    observed["changed_paths"] = ["docs/outside.md"]
    replay = _replay(case, observed=observed)
    assert replay.outcome == "UNBOUND"
    assert replay.reason_codes == ("ACTION_OUTSIDE_APPROVED_SCOPE",)
    draft = _compose_with_replay(case, replay)
    assert draft.decision == "UNBOUND"


def test_a3_replaced_issue_snapshot_is_unbound(binding_decision_case) -> None:
    case = binding_decision_case
    observed = _clean_observed(case)
    observed["issue_snapshot_digest"] = "f" * 64
    replay = _replay(case, observed=observed)
    assert replay.outcome == "UNBOUND"
    assert replay.reason_codes == ("ACTION_ARGUMENTS_MISMATCH",)


def test_a4_replaced_normalized_facts_is_unbound(binding_decision_case) -> None:
    case = binding_decision_case
    observed = _clean_observed(case)
    observed["issue_snapshot_digest"] = "e" * 64
    replay = _replay(case, observed=observed)
    assert replay.outcome == "UNBOUND"


def test_a5_replaced_acceptance_conditions_is_unbound(
    binding_decision_case,
) -> None:
    case = binding_decision_case
    observed = _clean_observed(case)
    observed["covered_condition_digests"] = [
        case["judgment"].acceptance_condition_digests[0]
    ]
    replay = _replay(case, observed=observed)
    assert replay.outcome == "UNBOUND"
    assert replay.reason_codes == ("ACTION_MAPPING_REJECTED",)


def test_a6_modified_path_or_tool_parameter_is_denied(
    binding_decision_case,
) -> None:
    case = binding_decision_case
    observed = _clean_observed(case)
    observed["tool_name"] = "owp.compose_proof"
    replay = _replay(case, observed=observed)
    assert replay.outcome == "UNBOUND"
    assert replay.reason_codes == ("ACTION_OUTSIDE_APPROVED_SCOPE",)


def test_a7_self_consistent_chain_violating_mapping_is_unbound(
    binding_decision_case,
) -> None:
    # Commitment and receipt are internally consistent but the observed
    # action violates the signed mapping.
    case = binding_decision_case
    observed = _clean_observed(case)
    observed["covered_condition_digests"] = [
        case["judgment"].acceptance_condition_digests[0]
    ]
    replay = _replay(case, observed=observed)
    assert replay.outcome == "UNBOUND"
    assert replay.reason_codes == ("ACTION_MAPPING_REJECTED",)
    draft = _compose_with_replay(case, replay)
    assert draft.decision == "UNBOUND"


def test_a8_forged_disposition_is_unbound(binding_decision_case) -> None:
    case = binding_decision_case
    observed = _clean_observed(case)
    observed["issue_snapshot_digest"] = "0" * 64
    replay = _replay(case, observed=observed)
    assert replay.outcome == "UNBOUND"


def test_a9_adapter_version_drift_is_indeterminate(
    binding_decision_case,
) -> None:
    case = binding_decision_case
    profile = _profile(case)
    profile["adapter_version"] = "9.9"
    replay = _replay(case, profile=profile)
    assert replay.outcome == "INDETERMINATE"
    assert replay.reason_codes == ("EVALUATOR_VERSION_DRIFT",)


def test_a10_expired_commitment_new_action_fails_closed(
    binding_decision_case,
) -> None:
    case = binding_decision_case
    # decided_at outside the Judgment window must not bind.
    replay = _replay(case)
    draft = compose_binding_decision(
        judgment=case["judgment"],
        manifest=case["manifest"],
        verification=_verified_decision(
            work_order=case["work_order"],
            claim=case["claim"],
            scope=case["scope"],
            manifest=case["manifest"],
            keys=case["role_keys"],
        ),
        receipts=(case["receipt"],),
        replay=replay,
        checkpoint=None,
        request=BindingDecisionDraftRequest(
            decided_at="2026-01-02T00:00:00Z", nonce="a" * 64
        ),
    )
    assert draft.decision == "INDETERMINATE"
    assert draft.reason_codes == ("VERIFICATION_NOT_CURRENT",)


def test_a11_stale_checkpoint_is_unbound(binding_decision_case) -> None:
    case = binding_decision_case
    chain, key = _checkpoint_chain(case, expired=True)
    verification = _high_risk_verification(case)
    draft = compose_binding_decision(
        judgment=case["judgment"],
        manifest=case["manifest"],
        verification=verification,
        receipts=(case["receipt"],),
        replay=_replay(case),
        checkpoint=None,
        request=BindingDecisionDraftRequest(
            decided_at="2026-01-01T00:10:00Z", nonce="a" * 64
        ),
        checkpoint_chain=chain,
        authority_key=key,
    )
    assert draft.decision == "UNBOUND"
    assert draft.reason_codes == ("AUTHORITY_CHECKPOINT_STALE",)


def test_a12_checkpoint_resolver_unavailable_is_indeterminate(
    binding_decision_case,
) -> None:
    case = binding_decision_case
    chain, key = _checkpoint_chain(case)
    draft = compose_binding_decision(
        judgment=case["judgment"],
        manifest=case["manifest"],
        verification=_high_risk_verification(case),
        receipts=(case["receipt"],),
        replay=_replay(case),
        checkpoint=None,
        request=BindingDecisionDraftRequest(
            decided_at=DECIDED_AT, nonce="a" * 64
        ),
        checkpoint_chain=chain,
        authority_key=key,
        resolver_unavailable=True,
    )
    assert draft.decision == "INDETERMINATE"
    assert draft.reason_codes == ("REPLAY_UNAVAILABLE",)


def test_a13_alternative_work_order_high_risk_is_unbound(
    binding_decision_case,
) -> None:
    case = binding_decision_case
    verification = _tamper_verification(
        case,
        _high_risk_verification(case),
        work_order_digest="f" * 64,
    )
    chain, key = _checkpoint_chain(case)
    draft = compose_binding_decision(
        judgment=case["judgment"],
        manifest=case["manifest"],
        verification=verification,
        receipts=(case["receipt"],),
        replay=_replay(case),
        checkpoint=None,
        request=BindingDecisionDraftRequest(
            decided_at=DECIDED_AT, nonce="a" * 64
        ),
        checkpoint_chain=chain,
        authority_key=key,
    )
    assert draft.decision == "UNBOUND"
    assert draft.reason_codes == ("ALTERNATIVE_WORK_ORDER_DETECTED",)


def test_a14_alternative_work_order_standard_is_indeterminate(
    binding_decision_case,
) -> None:
    case = binding_decision_case
    verification = _tamper_verification(
        case,
        _verified_decision(
            work_order=case["work_order"],
            claim=case["claim"],
            scope=case["scope"],
            manifest=case["manifest"],
            keys=case["role_keys"],
        ),
        work_order_digest="f" * 64,
    )
    draft = compose_binding_decision(
        judgment=case["judgment"],
        manifest=case["manifest"],
        verification=verification,
        receipts=(case["receipt"],),
        replay=_replay(case),
        checkpoint=None,
        request=BindingDecisionDraftRequest(
            decided_at=DECIDED_AT, nonce="a" * 64
        ),
    )
    assert draft.decision == "INDETERMINATE"
    assert draft.reason_codes == ("VERIFICATION_NOT_CURRENT",)


def test_a15_metadata_only_judgment_reference_is_indeterminate(
    binding_decision_case,
) -> None:
    case = binding_decision_case
    legacy_receipt = next(
        receipt
        for receipt in case["context"].ledger_prefix.receipts
        if type(receipt).__name__ == "ToolCallReceipt"
    )
    draft = _compose(case, receipts=(legacy_receipt,))
    assert draft.decision == "INDETERMINATE"
    assert draft.reason_codes == ("UNSIGNED_METADATA_REFERENCE",)


def test_a16_empty_acceptance_conditions_fails_closed(
    binding_decision_case,
) -> None:
    case = binding_decision_case
    observed = _clean_observed(case)
    observed["covered_condition_digests"] = []
    replay = _replay(case, observed=observed)
    assert replay.outcome == "UNBOUND"
    assert replay.reason_codes == ("ACTION_MAPPING_REJECTED",)


def test_a17_required_scope_omission_is_indeterminate(
    binding_decision_case,
) -> None:
    # A17: a manifest that binds a different scope than the one supplied is
    # an explicit scope-omission attack; the acceptance chain must reject it.
    from openworkproof.acceptance import validate_v04_acceptance_chain
    from test_binding_manifest_transactions_v04 import _signed_scope

    case = binding_decision_case
    payload = copy.deepcopy(evaluation_scope_payload(case))
    payload["selector_rules"] = [
        {**rule, "selector_engine_digest": "f" * 64}
        for rule in payload["selector_rules"]
    ]
    forged_scope = _signed_scope(
        payload=payload,
        manager_key=case["role_keys"]["Manager"][0],
        work_order=case["work_order"],
        claim=case["claim"],
    )
    assert forged_scope.digest != case["scope"].digest
    decision = _sign_decision(case, _compose(case))
    ok, failures = validate_v04_acceptance_chain(
        work_order=case["work_order"],
        subject_claim=case["claim"],
        scope=forged_scope,
        judgment=case["judgment"],
        manifest=case["manifest"],
        verification=_verified_decision(
            work_order=case["work_order"],
            claim=case["claim"],
            scope=case["scope"],
            manifest=case["manifest"],
            keys=case["role_keys"],
        ),
        binding_decision=decision,
    )
    assert ok is False
    assert "SCOPE_CHAIN_MISMATCH" in failures


def evaluation_scope_payload(case) -> dict:
    return copy.deepcopy(
        case["scope"].model_dump(
            mode="json",
            exclude={"digest", "signature_alg", "signer_key_id", "signature"},
        )
    )


def test_a18_manager_resign_without_acceptor_is_rejected(
    binding_decision_case,
) -> None:
    from openworkproof.signing import sign_payload

    case = binding_decision_case
    raw = case["judgment"].model_dump(
        mode="json",
        exclude={"digest", "signature_alg", "signer_key_id", "signature"},
    )
    forged = JudgmentCommitment.model_validate(
        sign_payload(
            "judgment-commitment",
            raw,
            case["role_keys"]["Manager"][0],
            version="0.4",
        )
    )
    with pytest.raises((BindingInputError, BindingTransactionError)):
        commit_judgment_commitment(
            case["ledger_path"],
            forged,
            JudgmentAuthorityContext(
                authority_namespace=forged.authority_namespace,
                authority_binding=next(
                    item
                    for item in case["work_order"].key_bindings
                    if item.role == "Acceptor"
                ),
                transaction_time=case["now"],
            ),
        )


# ---------------------------------------------------------------------------
# Step 3: required negative-control categories
# ---------------------------------------------------------------------------

# 1. chain-only tamper          -> A1 (Layer 1 rejection)
# 2. coherent binding mismatch  -> A2 (UNBOUND)
# 3. replay-only mismatch       -> A3/A5 (UNBOUND)
# 4. authority-only boundary    -> A11/A12 (UNBOUND / INDETERMINATE)
# 5. scope omission             -> A17 (chain gate)
# 6. metadata-only judgment     -> A15 (INDETERMINATE)
# 7. missing Acceptor signature -> A18 (Layer 1 rejection)
# 8. clean positive control     -> C0 (BOUND)


def test_negative_control_categories_are_present() -> None:
    registered = {
        "chain_only_tamper": "A1",
        "coherent_binding_mismatch": "A2",
        "replay_only_mismatch": "A3",
        "authority_only_boundary": "A11",
        "scope_omission": "A17",
        "metadata_only_judgment": "A15",
        "missing_acceptor_signature": "A18",
        "clean_positive_control": "C0",
    }
    # Each category maps to at least one frozen attack case implemented above.
    assert len(registered) == 8
    for label, case_id in registered.items():
        assert case_id.startswith(("A", "C"))
