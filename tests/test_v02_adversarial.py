from __future__ import annotations

import base64
import copy
from datetime import datetime, timezone
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from openworkproof.models import (
    SubjectClaim,
    VerificationArmResult,
    VerificationDecision,
    VerificationProfileV02,
    WorkOrder,
)
from openworkproof.settlement import (
    EffectiveAcceptance,
    SettlementReadiness,
    settlement_readiness,
)
from openworkproof.signing import key_id, sign_payload
from openworkproof.verification import (
    VerificationInputError,
    compose_verification_decision,
)
from test_verification_models_v02 import (
    _compose_decision_draft,
    _decision_results,
    _signed_decision,
)


_REGISTRATION = (
    Path(__file__).parents[1] / "docs/pilot/registered-adversarial-study.json"
)
_SIGNED_FIELDS = {"digest", "signature", "signature_alg", "signer_key_id"}


def _resign_arm(
    result: VerificationArmResult,
    private_key: Ed25519PrivateKey,
    **changes,
) -> VerificationArmResult:
    raw = result.model_dump(mode="json", exclude=_SIGNED_FIELDS)
    raw.update(changes)
    return VerificationArmResult.model_validate(
        sign_payload("verification-arm-result", raw, private_key)
    )


def test_adversarial_registration_is_canonical_and_contains_no_results() -> None:
    import rfc8785

    raw = _REGISTRATION.read_bytes()
    registration = json.loads(raw)
    assert raw == rfc8785.dumps(registration) + b"\n"
    assert registration["source_revision"] == (
        "d2620dc89774a382df15933abd182e404c2fd9fb"
    )
    assert len(registration["named_cases"]) == 12
    assert len(registration["holdout_case_ids"]) == 2
    assert not any("observed" in key for key in registration)


@pytest.mark.parametrize(
    ("case_id", "positive", "negative", "negative_change", "expected"),
    (
        ("ADV-CORRECT-CAUGHT", "satisfied", "satisfied", None, "VERIFIED"),
        ("ADV-INCORRECT-FIX", "contradicted", "satisfied", None, "REFUTED"),
        ("ADV-MUTANT-SURVIVED", "satisfied", "contradicted", None, "REFUTED"),
        (
            "ADV-MUTANT-NOT-APPLIED",
            "satisfied",
            "satisfied",
            {
                "mutation_status": "not_applied",
                "expectation_status": "indeterminate",
                "reason_codes": ["MUTATION_NOT_APPLIED"],
            },
            "UNKNOWN",
        ),
        (
            "ADV-VERIFIER-TIMEOUT",
            "satisfied",
            "satisfied",
            {
                "execution_status": "timed_out",
                "expectation_status": "indeterminate",
                "reason_codes": ["EXEC_TIMEOUT", "MUTATION_APPLIED"],
            },
            "UNKNOWN",
        ),
        (
            "ADV-VERIFIER-CRASH",
            "satisfied",
            "satisfied",
            {
                "execution_status": "crashed",
                "expectation_status": "indeterminate",
                "reason_codes": ["EXEC_CRASHED", "MUTATION_APPLIED"],
            },
            "UNKNOWN",
        ),
        (
            "ADV-EVIDENCE-MISSING",
            "satisfied",
            "satisfied",
            {
                "execution_status": "evidence_unavailable",
                "expectation_status": "indeterminate",
                "reason_codes": ["EVIDENCE_MISSING", "MUTATION_APPLIED"],
                "evidence_refs": [],
            },
            "UNKNOWN",
        ),
    ),
)
def test_registered_semantic_mutation_matrix(
    case_id,
    positive,
    negative,
    negative_change,
    expected,
    signed_verification_profile,
    signed_subject_claim,
    ephemeral_role_keys,
) -> None:
    results = _decision_results(
        signed_verification_profile,
        ephemeral_role_keys,
        positive=positive,
        negative=negative,
    )
    if negative_change is not None:
        results = (
            results[0],
            _resign_arm(
                results[1],
                ephemeral_role_keys["Verifier"][0],
                **negative_change,
            ),
        )
    draft = _compose_decision_draft(
        signed_verification_profile,
        signed_subject_claim,
        results,
    )
    assert draft.decision == expected, case_id


@pytest.mark.parametrize(
    "overlap",
    ("verifier_key", "controller", "execution_context"),
)
def test_high_risk_profile_rejects_registered_independence_overlap(
    overlap,
    verification_profile_dict,
    ephemeral_role_keys,
) -> None:
    candidate = copy.deepcopy(verification_profile_dict)
    candidate.update(
        delivery_trust_level=3,
        commitment_anchor_digest="c" * 64,
        assurance_level="high_risk",
    )
    primary = candidate["verifier_bindings"][0]
    independent_key = Ed25519PrivateKey.generate()
    public_key = independent_key.public_key()
    public_raw = public_key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    second = {
        "binding_id": "f" * 64,
        "verifier_subject_id": "registered-independent-verifier",
        "verifier_key_id": key_id(public_key),
        "verifier_public_key_b64url": base64.urlsafe_b64encode(public_raw)
        .decode("ascii")
        .rstrip("="),
        "controller_factors": ["registered-independent-controller"],
        "execution_context_factors": ["registered-independent-context"],
        "valid_from": "2026-01-01T00:00:04Z",
        "expires_at": "2026-01-01T01:00:00Z",
    }
    if overlap == "verifier_key":
        second["verifier_key_id"] = primary["verifier_key_id"]
        second["verifier_public_key_b64url"] = primary[
            "verifier_public_key_b64url"
        ]
    elif overlap == "controller":
        second["controller_factors"] = primary["controller_factors"]
    else:
        second["execution_context_factors"] = primary[
            "execution_context_factors"
        ]
    candidate["verifier_bindings"].append(second)
    candidate["verifier_bindings"].sort(key=lambda item: item["binding_id"])
    with pytest.raises(ValidationError, match="two distinct"):
        VerificationProfileV02.model_validate(
            sign_payload(
                "verification-profile",
                candidate,
                ephemeral_role_keys["Manager"][0],
            )
        )


def test_registered_stale_supersession_is_rejected(
    signed_verification_profile,
    signed_subject_claim,
    ephemeral_role_keys,
) -> None:
    results = _decision_results(signed_verification_profile, ephemeral_role_keys)
    first_draft = _compose_decision_draft(
        signed_verification_profile,
        signed_subject_claim,
        results,
    )
    first = _signed_decision(
        first_draft,
        profile=signed_verification_profile,
        private_keys=(ephemeral_role_keys["Verifier"][0],),
    )
    with pytest.raises(VerificationInputError, match="time is stale"):
        compose_verification_decision(
            profile=signed_verification_profile,
            subject_claim=signed_subject_claim,
            arm_results=results,
            previous_decision=first,
            decision_id="e" * 64,
            decided_at=datetime(2026, 1, 1, 0, 19, tzinfo=timezone.utc),
            nonce="f" * 64,
        )


def test_registered_withdrawal_overrides_verified_readiness() -> None:
    decision = VerificationDecision.model_construct(decision="VERIFIED")
    assert settlement_readiness(
        decision=decision,
        acceptance=EffectiveAcceptance.WITHDRAWN,
        rejection=None,
    ) is SettlementReadiness.WITHDRAWN


@pytest.mark.parametrize(
    "object_name",
    ("work_order", "claim", "profile", "arm_result", "decision", "receipt"),
)
def test_signed_object_tamper_fails_during_full_rebuild(
    object_name,
    signed_work_order,
    signed_subject_claim,
    signed_verification_profile,
    ephemeral_role_keys,
    sidecar_receipt_factory,
) -> None:
    results = _decision_results(signed_verification_profile, ephemeral_role_keys)
    draft = _compose_decision_draft(
        signed_verification_profile,
        signed_subject_claim,
        results,
    )
    decision = _signed_decision(
        draft,
        profile=signed_verification_profile,
        private_keys=(ephemeral_role_keys["Verifier"][0],),
    )
    receipt = sidecar_receipt_factory(
        state_before="locally_verified",
        state_after="evidence_incomplete",
        event_type="system_event",
        event_name="proof_composed",
    )
    target, field, changed = {
        "work_order": (signed_work_order, "goal", "tampered goal"),
        "claim": (signed_subject_claim, "claim_statement", "tampered claim"),
        "profile": (signed_verification_profile, "max_output_bytes", 1),
        "arm_result": (results[0], "verifier_build_digest", "f" * 64),
        "decision": (decision, "decided_at", "2026-01-01T00:20:01Z"),
        "receipt": (receipt, "occurred_at", "2026-01-01T00:00:04Z"),
    }[object_name]
    raw = target.model_dump(mode="json")
    raw[field] = changed
    with pytest.raises((ValidationError, ValueError)):
        type(target).model_validate(raw)
