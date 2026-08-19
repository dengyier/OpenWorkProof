from __future__ import annotations

from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from openworkproof.models import (
    VerificationArmResultV05,
    VerificationProfileV05,
)
from openworkproof.signing import sign_payload

from test_verification_integrity_transactions_v05 import (
    _base64,
    _compose_v05,
    _key_id,
    _v05_arm_result,
    _v05_control_observation,
    _v05_population_observation,
    _write_json_evidence,
    v05_transaction_case,
    verification_profile_v03,
)


def _high_risk_profile(case: dict[str, Any]) -> tuple[VerificationProfileV05, Ed25519PrivateKey, dict[str, str]]:
    """Build a high_risk profile with two distinct verifier bindings and
    return (profile, second_key, second_binding)."""
    second_key = Ed25519PrivateKey.generate()
    second_public_b64url = _base64.urlsafe_b64encode(
        second_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
    ).decode("ascii").rstrip("=")
    second_binding = {
        **case["profile"].verifier_bindings[0].model_dump(mode="json"),
        "binding_id": "9" * 64,
        "verifier_subject_id": "second-verifier",
        "verifier_key_id": _key_id(second_key.public_key()),
        "verifier_public_key_b64url": second_public_b64url,
        "controller_factors": ["second-controller"],
        "execution_context_factors": ["second-container"],
    }
    raw = case["profile"].model_dump(
        mode="json",
        exclude={"digest", "signature_alg", "signer_key_id", "signature"},
    )
    raw["assurance_level"] = "high_risk"
    raw["verifier_bindings"] = sorted(
        [*raw["verifier_bindings"], second_binding],
        key=lambda item: item["binding_id"],
    )
    profile = VerificationProfileV05.model_validate(
        sign_payload(
            "verification-profile",
            raw,
            case["keys"]["Manager"][0],
            version="0.5",
        )
    )
    return profile, second_key, second_binding


def _arm_result_for_verifier(
    case: dict[str, Any],
    profile: VerificationProfileV05,
    manifest: Any,
    *,
    verifier_key: Ed25519PrivateKey,
    binding: dict[str, str],
    arm_kind: str,
    suffix: str,
    evidence_ref: dict[str, object],
    scope_evidence_ref: dict[str, object],
    result_id: str,
) -> VerificationArmResultV05:
    """Build one signed arm result for a specific verifier binding."""
    arm = profile.positive_arm if arm_kind == "positive" else profile.negative_arms[0]
    observations = [
        _v05_population_observation(
            case["tmp_path"],
            contract,
            suffix=f"{suffix}-{contract.member_kind}",
        )
        for contract in profile.population_contracts
    ]
    control = (
        _v05_control_observation(
            case["tmp_path"],
            profile.control_contracts[0],
            arm_kind=arm_kind,
        )
        if arm_kind == "negative"
        else None
    )
    receipt_id = case["results"][0].action_receipt_ids[0]
    payload = {
        "schema_version": "openworkproof-verification-arm-result/0.5",
        "arm_result_id": result_id,
        "profile_digest": profile.digest,
        "arm_id": arm.arm_id,
        "arm_kind": arm_kind,
        "mutation_status": "not_applicable" if arm_kind == "positive" else "applied",
        "execution_status": "completed",
        "expectation_status": "satisfied",
        "reason_codes": (
            ["MUTATION_APPLIED", "MUTATION_CAUGHT"]
            if arm_kind == "negative"
            else []
        ),
        "action_receipt_ids": [receipt_id],
        "evidence_refs": [evidence_ref],
        "scope_manifest_digest": manifest.digest,
        "observed_member_count": manifest.member_count,
        "observed_population_digest": manifest.population_digest,
        "observed_required_target_ids": list(manifest.required_target_ids),
        "scope_expectation_status": "satisfied",
        "scope_evidence_refs": [scope_evidence_ref],
        "population_observations": observations,
        "control_observation": control,
        "verifier_subject_id": binding["verifier_subject_id"],
        "verifier_key_id": binding["verifier_key_id"],
        "verifier_build_digest": "4" * 64,
        "dependency_lock_digest": "5" * 64,
        "controller_factors": binding["controller_factors"],
        "execution_context_factors": binding["execution_context_factors"],
        "created_at": "2026-01-01T00:10:00Z",
    }
    return VerificationArmResultV05.model_validate(
        sign_payload(
            "verification-arm-result",
            payload,
            verifier_key,
            version="0.5",
        )
    )


def _dual_verifier_results(
    case: dict[str, Any],
    profile: VerificationProfileV05,
    *,
    divergent_evidence: bool = False,
    same_key: bool = False,
) -> tuple[VerificationArmResultV05, ...]:
    """Produce two verifier result sets for the high-risk profile.

    With divergent_evidence the two positive arms carry different evidence
    digests; otherwise they share the same evidence (convergent).
    With same_key both sets are signed by the first verifier key only.
    """
    manifest = case["manifest"]
    first_binding = profile.verifier_bindings[0].model_dump(mode="json")
    second_binding = profile.verifier_bindings[1].model_dump(mode="json")
    first_key = case["keys"]["Verifier"][0]
    _, second_key, _ = _high_risk_profile(case)

    def evidence_for(suffix: str, divergent: bool) -> dict[str, object]:
        value = {"arm": suffix, "passed": True}
        if divergent:
            value["dup"] = suffix
        return _write_json_evidence(
            case["tmp_path"], f"dual/{suffix}.json", value
        )

    results = []
    for arm_kind, arm_suffix, result_prefix in (
        ("positive", "positive", "8"),
        ("negative", "negative", "9"),
    ):
        pos_ev = evidence_for(f"{arm_suffix}-v0", False)
        scope_ref = _write_json_evidence(
            case["tmp_path"],
            f"dual/scope-{arm_suffix}.json",
            {"arm": arm_suffix, "population_digest": manifest.population_digest},
        )
        verifier_key = first_key if same_key else second_key
        binding = first_binding if same_key else second_binding
        results.append(
            _arm_result_for_verifier(
                case,
                profile,
                manifest,
                verifier_key=verifier_key,
                binding=binding,
                arm_kind=arm_kind,
                suffix=f"{arm_suffix}-v1",
                evidence_ref=pos_ev,
                scope_evidence_ref=scope_ref,
                result_id=result_prefix + "1" * 63,
            )
        )
    return tuple(results)


def test_high_risk_single_verifier_arm_set_is_unknown(
    v05_transaction_case,
) -> None:
    """One verifier producing the entire arm set under a high-risk profile
    must not derive VERIFIED."""
    case = v05_transaction_case
    profile, _, _ = _high_risk_profile(case)
    rebound = []
    for result in case["results"]:
        raw = result.model_dump(
            mode="json",
            exclude={"digest", "signature_alg", "signer_key_id", "signature"},
        )
        raw["profile_digest"] = profile.digest
        rebound.append(
            VerificationArmResultV05.model_validate(
                sign_payload(
                    "verification-arm-result",
                    raw,
                    case["keys"]["Verifier"][0],
                    version="0.5",
                )
            )
        )
    draft = _compose_v05(case, profile=profile, results=tuple(rebound))
    assert draft.decision == "UNKNOWN"
    assert any(
        code.startswith("INDEPENDENCE") for code in draft.reason_codes
    )


def test_high_risk_dual_verifier_divergent_evidence_is_unknown(
    v05_transaction_case,
) -> None:
    """Two independent verifiers whose positive-arm evidence does not converge
    must not derive VERIFIED: a lying verifier's forged exit code is exposed
    by the second verifier's different evidence. This drives RED."""
    case = v05_transaction_case
    profile, second_key, second_binding = _high_risk_profile(case)
    first_key = case["keys"]["Verifier"][0]
    first_binding = next(
        item.model_dump(mode="json")
        for item in profile.verifier_bindings
        if item.verifier_key_id == _key_id(first_key.public_key())
    )
    second_binding = {
        **second_binding,
        "verifier_key_id": _key_id(second_key.public_key()),
    }
    manifest = case["manifest"]

    def evidence_for(suffix: str, value: object) -> dict[str, object]:
        return _write_json_evidence(
            case["tmp_path"], f"dual/{suffix}.json", value
        )

    results = []
    for arm_kind, suffix, result_prefix in (
        ("positive", "positive", "8"),
        ("negative", "negative", "9"),
    ):
        for verifier_idx, (vkey, binding) in enumerate(
            (
                (case["keys"]["Verifier"][0], first_binding),
                (second_key, second_binding),
            )
        ):
            # Divergent: each verifier's positive evidence differs.
            ev = evidence_for(
                f"{suffix}-v{verifier_idx}",
                {"arm": suffix, "passed": True, "run": verifier_idx},
            )
            scope_ref = evidence_for(
                f"scope-{suffix}-v{verifier_idx}",
                {"arm": suffix, "population_digest": manifest.population_digest},
            )
            results.append(
                _arm_result_for_verifier(
                    case,
                    profile,
                    manifest,
                    verifier_key=vkey,
                    binding=binding,
                    arm_kind=arm_kind,
                    suffix=f"{suffix}-v{verifier_idx}",
                    evidence_ref=ev,
                    scope_evidence_ref=scope_ref,
                    result_id=result_prefix + str(verifier_idx) * 63,
                )
            )
    draft = _compose_v05(case, profile=profile, results=tuple(results))
    assert draft.decision == "UNKNOWN"
    assert "DUAL_VERIFIER_DIVERGENCE" in draft.reason_codes


def test_high_risk_dual_verifier_convergent_is_verified(
    v05_transaction_case,
) -> None:
    """Two independent verifiers with identical positive-arm evidence converge
    to VERIFIED when all other conditions hold."""
    case = v05_transaction_case
    profile, second_key, _ = _high_risk_profile(case)
    first_key = case["keys"]["Verifier"][0]
    first_binding = next(
        item.model_dump(mode="json")
        for item in profile.verifier_bindings
        if item.verifier_key_id == _key_id(first_key.public_key())
    )
    second_binding = next(
        item.model_dump(mode="json")
        for item in profile.verifier_bindings
        if item.verifier_key_id == _key_id(second_key.public_key())
    )
    manifest = case["manifest"]

    def evidence_for(suffix: str, value: object) -> dict[str, object]:
        return _write_json_evidence(
            case["tmp_path"], f"dual/{suffix}.json", value
        )

    results = []
    for arm_kind, suffix, result_prefix in (
        ("positive", "positive", "8"),
        ("negative", "negative", "9"),
    ):
        for verifier_idx, (vkey, binding) in enumerate(
            (
                (first_key, first_binding),
                (second_key, second_binding),
            )
        ):
            # Convergent: both verifiers reference the same evidence bytes.
            ev = evidence_for(
                f"{suffix}-shared",
                {"arm": suffix, "passed": True},
            )
            scope_ref = evidence_for(
                f"scope-{suffix}-shared",
                {"arm": suffix, "population_digest": manifest.population_digest},
            )
            results.append(
                _arm_result_for_verifier(
                    case,
                    profile,
                    manifest,
                    verifier_key=vkey,
                    binding=binding,
                    arm_kind=arm_kind,
                    suffix=f"{suffix}-v{verifier_idx}",
                    evidence_ref=ev,
                    scope_evidence_ref=scope_ref,
                    result_id=result_prefix + str(verifier_idx) * 63,
                )
            )
    draft = _compose_v05(case, profile=profile, results=tuple(results))
    assert draft.decision == "VERIFIED"
