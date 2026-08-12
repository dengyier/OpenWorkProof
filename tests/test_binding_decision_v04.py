"""Pure BindingDecision composition and verification coverage (Task 8)."""

from __future__ import annotations

import copy
import hashlib
from datetime import timedelta

import pytest
import rfc8785

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
    binding_decision_signing_bytes,
    compose_binding_decision,
    verify_binding_decision,
)
from openworkproof.models import (
    ActionReceiptEnvelope,
    BindingDecision,
    BindingDecisionDraft,
    JudgmentCommitment,
    ScopeAssessment,
    VerificationArmResultReference,
    VerificationDecisionDraftV03,
    VerificationDecisionV03,
    VerificationIndependenceAssessment,
)
from openworkproof.signing import key_id
from openworkproof.verification import verification_decision_signing_bytes_v03

import openworkproof.mcp_server as mcp_server
import openworkproof.repo_tools as repo_tools
from test_binding_manifest_transactions_v04 import (
    _profile_from_axes,
    _signed_judgment,
    _signed_manifest,
    _signed_scope,
)
from test_mcp_server import (
    _FakeRunTestsExecutionDriver,
    _current_run_tests_context,
    _run_tests_case,
    _run_tests_snapshot,
    _run_tests_snapshot_request,
)

DECIDED_AT = "2026-01-01T00:00:10Z"


def _verified_decision(
    *,
    work_order,
    claim,
    scope,
    manifest,
    keys,
    decision="VERIFIED",
    assurance_level="standard",
    decided_at=DECIDED_AT,
) -> VerificationDecisionV03:
    draft = VerificationDecisionDraftV03.model_validate(
        {
            "decision_id": "1" * 64,
            "work_order_digest": work_order.digest,
            "subject_claim_digest": claim.digest,
            "profile_id": "2" * 64,
            "profile_digest": manifest.adapter_profile_digest,
            "arm_results": (
                {
                    "arm_id": "3" * 64,
                    "arm_result_id": "4" * 64,
                    "arm_result_digest": "5" * 64,
                    "evidence_snapshot_digest": "6" * 64,
                },
            ),
            "assurance_level": assurance_level,
            "decision": decision,
            "independence": {
                "distinct_subjects": True,
                "distinct_keys": True,
                "distinct_controllers": True,
                "distinct_execution_contexts": True,
                "reason_codes": [],
            },
            "reason_codes": [],
            "supersedes_decision_id": None,
            "supersedes_decision_digest": None,
            "causal_parent_receipt_ids": ["7" * 64],
            "causal_parent_decision_ids": [],
            "decided_at": decided_at,
            "nonce": "8" * 64,
            "scope_manifest_digest": scope.digest,
            "scope_assessment": {
                "declared_member_count": 1,
                "observed_member_counts": [1],
                "population_digest": "9" * 64,
                "required_target_count": 1,
                "missing_required_target_ids": [],
                "scope_status": "satisfied",
            },
        }
    )
    encoded = verification_decision_signing_bytes_v03(draft)
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )

    verifier_keys = (keys["Verifier"][0],)
    if assurance_level == "high_risk":
        verifier_keys += (Ed25519PrivateKey.generate(),)
    signatures = [
        {
            "verifier_subject_id": f"verifier{index + 1}.example",
            "verifier_key_id": key_id(verifier_key.public_key()),
            "signature_alg": "Ed25519",
            "signature": _signature(verifier_key, encoded),
        }
        for index, verifier_key in enumerate(verifier_keys)
    ]
    signatures.sort(key=lambda item: item["verifier_key_id"].encode("utf-8"))
    return VerificationDecisionV03.model_validate(
        {
            **draft.model_dump(mode="json"),
            "schema_version": "openworkproof-verification-decision/0.3",
            "digest": hashlib.sha256(encoded).hexdigest(),
            "verifier_signatures": signatures,
        }
    )


def _signature(private_key, encoded: bytes) -> str:
    import base64

    return (
        base64.urlsafe_b64encode(private_key.sign(encoded))
        .decode("ascii")
        .rstrip("=")
    )


def _bound_replay(judgment: JudgmentCommitment, projection) -> "object":
    profile = CodeDeliveryAdapterProfile(
        adapter_id=ADAPTER_ID,
        adapter_version=ADAPTER_VERSION,
        adapter_profile_digest=judgment.adapter_profile_digest,
        allowed_tool_names=projection.allowed_tool_names,
        allowed_action_kinds=projection.allowed_action_kinds,
        allowed_path_roots=projection.allowed_path_roots,
        required_test_profile_digests=projection.required_test_profile_digests,
    )
    judgment_input = CodeDeliveryJudgmentInput(
        adapter_id=ADAPTER_ID,
        adapter_version=ADAPTER_VERSION,
        adapter_profile_digest=judgment.adapter_profile_digest,
        issue_snapshot_digest=judgment.judgment_artifact_digest,
        repository_identity=judgment.repository,
        source_revision=judgment.source_revision,
        target_branch=judgment.target_branch,
        acceptance_condition_digests=judgment.acceptance_condition_digests,
        excluded_scope_digests=judgment.excluded_scope_digests,
        excluded_path_roots=(),
        required_artifact_digests=judgment.required_artifact_digests,
        allowed_path_roots=projection.allowed_path_roots,
        allowed_action_kinds=projection.allowed_action_kinds,
        required_test_profile_digests=projection.required_test_profile_digests,
    )
    observed = ObservedAction(
        tool_name="owp.run_tests",
        action_kind="test",
        changed_paths=(),
        patch_digest=None,
        candidate_commit_digest=None,
        workspace_digest=None,
        artifact_digests=judgment.required_artifact_digests,
        covered_condition_digests=judgment.acceptance_condition_digests,
        undeclared_side_effects=(),
    )
    return replay_code_delivery_binding(
        CodeDeliveryReplayInput(
            judgment=judgment_input, profile=profile, observed=observed
        )
    )




def _compose(case, **changes) -> BindingDecisionDraft:
    verification = changes.get(
        "verification",
        _verified_decision(
            work_order=case["work_order"],
            claim=case["claim"],
            scope=case["scope"],
            manifest=case["manifest"],
            keys=case["role_keys"],
        ),
    )
    replay = changes.get(
        "replay", _bound_replay(case["judgment"], case["projection"])
    )
    return compose_binding_decision(
        judgment=changes.get("judgment", case["judgment"]),
        manifest=changes.get("manifest", case["manifest"]),
        verification=verification,
        receipts=changes.get("receipts", (case["receipt"],)),
        replay=replay,
        checkpoint=changes.get("checkpoint"),
        request=changes.get(
            "request",
            BindingDecisionDraftRequest(
                decided_at=DECIDED_AT,
                nonce="a" * 64,
            ),
        ),
    )


# ---------------------------------------------------------------------------
# Step 1: outcome decision table
# ---------------------------------------------------------------------------


def test_complete_chain_composes_bound(binding_decision_case) -> None:
    draft = _compose(binding_decision_case)
    verification = _verified_decision(
        work_order=binding_decision_case["work_order"],
        claim=binding_decision_case["claim"],
        scope=binding_decision_case["scope"],
        manifest=binding_decision_case["manifest"],
        keys=binding_decision_case["role_keys"],
    )
    replay = _bound_replay(
        binding_decision_case["judgment"],
        binding_decision_case["projection"],
    )
    assert draft.decision == "BOUND"
    assert draft.reason_codes == ()
    assert draft.verification_decision_id == verification.decision_id
    assert draft.verification_decision_digest == verification.digest
    assert draft.action_receipt_ids == (
        binding_decision_case["receipt"].receipt_id,
    )
    assert draft.adapter_replay_digest == replay.replay_digest
    assert draft.authority_status == "not_required"
    assert draft.authority_checkpoint_digest is None


def test_unknown_verification_never_bounds(binding_decision_case) -> None:
    case = binding_decision_case
    unknown = _verified_decision(
        work_order=case["work_order"],
        claim=case["claim"],
        scope=case["scope"],
        manifest=case["manifest"],
        keys=case["role_keys"],
        decision="UNKNOWN",
    )
    draft = _compose(case, verification=unknown)
    assert draft.decision == "INDETERMINATE"
    assert draft.reason_codes == ("VERIFICATION_NOT_CURRENT",)


def test_refuted_verification_never_bounds(binding_decision_case) -> None:
    case = binding_decision_case
    refuted = _verified_decision(
        work_order=case["work_order"],
        claim=case["claim"],
        scope=case["scope"],
        manifest=case["manifest"],
        keys=case["role_keys"],
        decision="REFUTED",
    )
    draft = _compose(case, verification=refuted)
    assert draft.decision == "INDETERMINATE"
    assert draft.reason_codes == ("VERIFICATION_NOT_CURRENT",)


def test_replay_unbound_propagates_unbound(binding_decision_case) -> None:
    case = binding_decision_case
    attacked = _bound_replay(case["judgment"], case["projection"])
    unbound_replay = type(attacked)(
        outcome="UNBOUND",
        reason_codes=("ACTION_OUTSIDE_APPROVED_SCOPE",),
        replay_digest=attacked.replay_digest,
    )
    draft = _compose(case, replay=unbound_replay)
    assert draft.decision == "UNBOUND"
    assert draft.reason_codes == ("ACTION_OUTSIDE_APPROVED_SCOPE",)


def test_replay_indeterminate_propagates(binding_decision_case) -> None:
    case = binding_decision_case
    attacked = _bound_replay(case["judgment"], case["projection"])
    indeterminate_replay = type(attacked)(
        outcome="INDETERMINATE",
        reason_codes=("EVALUATOR_VERSION_DRIFT",),
        replay_digest=attacked.replay_digest,
    )
    draft = _compose(case, replay=indeterminate_replay)
    assert draft.decision == "INDETERMINATE"
    assert draft.reason_codes == ("EVALUATOR_VERSION_DRIFT",)


def test_judgment_manifest_digest_mismatch_is_unbound(
    binding_decision_case,
) -> None:
    from openworkproof.signing import sign_payload

    case = binding_decision_case
    raw = case["judgment"].model_dump(
        mode="json",
        exclude={"digest", "signature_alg", "signer_key_id", "signature"},
    )
    raw["commitment_id"] = "0" * 64
    mismatched = JudgmentCommitment.model_validate(
        sign_payload(
            "judgment-commitment",
            raw,
            case["role_keys"]["Acceptor"][0],
            version="0.4",
        )
    )
    assert mismatched.digest != case["judgment"].digest
    draft = _compose(case, judgment=mismatched)
    assert draft.decision == "UNBOUND"
    assert draft.reason_codes == ("JUDGMENT_DIGEST_MISMATCH",)


def test_empty_receipts_fail_closed(binding_decision_case) -> None:
    # The frozen BindingDecision model requires non-empty action receipt
    # references, so an empty receipt set cannot form a decision object at
    # all. The composer fails closed rather than fabricating evidence.
    from openworkproof.binding import BindingInputError

    with pytest.raises(BindingInputError):
        _compose(binding_decision_case, receipts=())


def test_legacy_receipt_never_binds(binding_decision_case) -> None:
    case = binding_decision_case
    legacy_receipt = next(
        receipt
        for receipt in case["context"].ledger_prefix.receipts
        if type(receipt).__name__ == "ToolCallReceipt"
    )
    draft = _compose(case, receipts=(legacy_receipt,))
    assert draft.decision == "INDETERMINATE"
    assert draft.reason_codes == ("UNSIGNED_METADATA_REFERENCE",)


def test_high_risk_without_checkpoint_is_indeterminate(
    binding_decision_case,
) -> None:
    case = binding_decision_case
    high_risk = _verified_decision(
        work_order=case["work_order"],
        claim=case["claim"],
        scope=case["scope"],
        manifest=case["manifest"],
        keys=case["role_keys"],
        assurance_level="high_risk",
    )
    draft = _compose(case, verification=high_risk)
    assert draft.decision == "INDETERMINATE"
    assert draft.reason_codes == ("AUTHORITY_CHECKPOINT_MISSING",)
    assert draft.authority_status == "missing"


def test_reason_codes_match_outcome(binding_decision_case) -> None:
    # The model rejects any reason code incompatible with its outcome.
    case = binding_decision_case
    replay = _bound_replay(case["judgment"], case["projection"])
    invalid = type(replay)(
        outcome="UNBOUND",
        reason_codes=("EVIDENCE_INCOMPLETE",),
        replay_digest=replay.replay_digest,
    )
    draft = _compose(case, replay=invalid)
    assert draft.decision == "INDETERMINATE"
    assert draft.reason_codes == ("EVIDENCE_INCOMPLETE",)


# ---------------------------------------------------------------------------
# Step 2 / Step 4: signing bytes and tamper tests
# ---------------------------------------------------------------------------


def test_signing_bytes_match_decision_digest(binding_decision_case) -> None:
    case = binding_decision_case
    draft = _compose(case)
    signed = BindingDecision.model_validate(
        {
            **draft.model_dump(mode="json"),
            "schema_version": "openworkproof-binding-decision/0.4",
            "digest": hashlib.sha256(
                binding_decision_signing_bytes(draft)
            ).hexdigest(),
            "verifier_signatures": [
                {
                    "verifier_subject_id": "verifier.example",
                    "verifier_key_id": key_id(
                        case["role_keys"]["Verifier"][0].public_key()
                    ),
                    "signature_alg": "Ed25519",
                    "signature": _signature(
                        case["role_keys"]["Verifier"][0],
                        binding_decision_signing_bytes(draft),
                    ),
                }
            ],
        }
    )
    assert hashlib.sha256(
        binding_decision_signing_bytes(signed)
    ).hexdigest() == signed.digest


def test_verify_requires_external_trust_key(binding_decision_case) -> None:
    case = binding_decision_case
    draft = _compose(case)
    signed = _sign_decision(case, draft)
    trust = dict(case["role_keys"])
    missing = {
        key_id(value[0].public_key()): value[0].public_key()
        for key, value in case["role_keys"].items()
        if key in {"Verifier", "Sidecar", "Manager", "Developer", "Acceptor"}
    }
    assert verify_binding_decision(
        signed,
        work_order=case["work_order"],
        public_keys=missing,
        expected_signatures=1,
    )

    missing.pop(key_id(case["role_keys"]["Verifier"][0].public_key()))
    assert not verify_binding_decision(
        signed,
        work_order=case["work_order"],
        public_keys=missing,
        expected_signatures=1,
    )


def test_bad_signature_fails_verification(binding_decision_case) -> None:
    case = binding_decision_case
    draft = _compose(case)
    signed = _sign_decision(case, draft)
    raw = signed.model_dump(mode="json")
    raw["verifier_signatures"] = [
        {**raw["verifier_signatures"][0], "signature": "A" * 86}
    ]
    tampered = BindingDecision.model_validate(raw)
    trust = {
        key_id(value[0].public_key()): value[0].public_key()
        for key, value in case["role_keys"].items()
        if key == "Verifier"
    }
    assert not verify_binding_decision(
        tampered,
        work_order=case["work_order"],
        public_keys=trust,
        expected_signatures=1,
    )


def test_wrong_signature_count_fails(binding_decision_case) -> None:
    case = binding_decision_case
    draft = _compose(case)
    signed = _sign_decision(case, draft)
    trust = {
        key_id(value[0].public_key()): value[0].public_key()
        for key, value in case["role_keys"].items()
        if key == "Verifier"
    }
    assert not verify_binding_decision(
        signed,
        work_order=case["work_order"],
        public_keys=trust,
        expected_signatures=2,
    )


def test_changed_replay_digest_changes_decision(binding_decision_case) -> None:
    case = binding_decision_case
    first = _compose(case)
    replay = _bound_replay(case["judgment"], case["projection"])
    changed = type(replay)(
        outcome=replay.outcome,
        reason_codes=replay.reason_codes,
        replay_digest="f" * 64,
    )
    second = _compose(case, replay=changed)
    assert second.adapter_replay_digest == "f" * 64
    assert first.adapter_replay_digest != second.adapter_replay_digest


def _sign_decision(case, draft: BindingDecisionDraft) -> BindingDecision:
    encoded = binding_decision_signing_bytes(draft)
    verifier_key = case["role_keys"]["Verifier"][0]
    return BindingDecision.model_validate(
        {
            **draft.model_dump(mode="json"),
            "schema_version": "openworkproof-binding-decision/0.4",
            "digest": hashlib.sha256(encoded).hexdigest(),
            "verifier_signatures": [
                {
                    "verifier_subject_id": "verifier.example",
                    "verifier_key_id": key_id(verifier_key.public_key()),
                    "signature_alg": "Ed25519",
                    "signature": _signature(verifier_key, encoded),
                }
            ],
        }
    )
