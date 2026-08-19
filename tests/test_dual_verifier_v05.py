from __future__ import annotations

from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import hashlib

from openworkproof.models import (
    DecisionDraftRequest,
    VerificationArmResultV05,
    VerificationDecisionV05,
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
    from openworkproof.verification import VerificationInputError

    with pytest.raises(VerificationInputError, match="diverged"):
        _compose_v05(case, profile=profile, results=tuple(results))


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
                    suffix=f"{suffix}-shared",
                    evidence_ref=ev,
                    scope_evidence_ref=scope_ref,
                    result_id=result_prefix + str(verifier_idx) * 63,
                )
            )
    draft = _compose_v05(case, profile=profile, results=tuple(results))
    assert draft.decision == "VERIFIED"


def test_high_risk_dual_verifier_full_chain_commit_and_replay(
    v05_transaction_case,
) -> None:
    """End-to-end: two independent verifier result sets commit to the ledger,
    prepare derives a converged VERIFIED, the decision commits, and a later
    prepare/replay stays stable (the decision replays from its own arm
    results plus the two-verifier signature set)."""
    import openworkproof.evidence as evidence
    from openworkproof.verification import (
        VerificationCommittedError,
        commit_verification_arm_result_v05,
        commit_verification_decision_v05,
        commit_verification_profile_v05,
        prepare_verification_decision_v05,
    )

    from test_verification_integrity_transactions_v05 import (
        _sign_decision_draft_v05,
    )

    case = dict(v05_transaction_case)
    profile, second_key, second_binding = _high_risk_profile(case)
    first_key = case["keys"]["Verifier"][0]
    first_binding = next(
        item.model_dump(mode="json")
        for item in profile.verifier_bindings
        if item.verifier_key_id == _key_id(first_key.public_key())
    )
    manifest = case["manifest"]

    from openworkproof.scope import ObservedScope

    observed = ObservedScope(
        member_ids=tuple(member.member_id for member in manifest.members),
        member_count=manifest.member_count,
        population_digest=manifest.population_digest,
        required_target_ids=manifest.required_target_ids,
        source_revision=manifest.source_revision,
        workspace_manifest_digest=manifest.workspace_manifest_digest,
        selector_engine_digests=tuple(
            sorted(rule.selector_engine_digest for rule in manifest.selector_rules)
        ),
        evidence_complete=True,
    )

    def evidence_for(suffix: str, value: object) -> dict[str, object]:
        return _write_json_evidence(
            case["tmp_path"], suffix, value
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
            ev = evidence_for(
                f"results/{arm_kind}.json", {"arm": arm_kind, "passed": True}
            )
            scope_ref = evidence_for(
                f"scope/{arm_kind}.json",
                observed.model_dump(mode="json"),
            )
            results.append(
                _arm_result_for_verifier(
                    case,
                    profile,
                    manifest,
                    verifier_key=vkey,
                    binding=binding,
                    arm_kind=arm_kind,
                    suffix=f"{arm_kind}-shared",
                    evidence_ref=ev,
                    scope_evidence_ref=scope_ref,
                    result_id=result_prefix + str(verifier_idx) * 63,
                )
            )

    # Commit the high-risk profile and all four arm results.
    commit_verification_profile_v05(case["ledger"], profile)
    for result in results:
        commit_verification_arm_result_v05(case["ledger"], result)

    # prepare must see both verifier sets and converge to VERIFIED.
    draft = prepare_verification_decision_v05(
        case["ledger"],
        DecisionDraftRequest(
            decision_id="c" * 64,
            decided_at="2026-01-01T00:20:00Z",
            nonce="d" * 64,
        ),
    )
    assert draft.decision == "VERIFIED"
    from openworkproof.verification import verification_decision_signing_bytes_v05

    encoded = verification_decision_signing_bytes_v05(draft)
    signatures = []
    for key, binding in (
        (first_key, first_binding),
        (second_key, second_binding),
    ):
        signatures.append(
            {
                "verifier_subject_id": binding["verifier_subject_id"],
                "verifier_key_id": _key_id(key.public_key()),
                "signature_alg": "Ed25519",
                "signature": _base64.urlsafe_b64encode(key.sign(encoded))
                .decode("ascii")
                .rstrip("="),
            }
        )
    signatures.sort(key=lambda item: item["verifier_key_id"].encode("utf-8"))
    decision = VerificationDecisionV05.model_validate(
        {
            "schema_version": "openworkproof-verification-decision/0.5",
            **draft.model_dump(mode="json"),
            "digest": hashlib.sha256(encoded).hexdigest(),
            "verifier_signatures": signatures,
        }
    )
    assert len(decision.verifier_signatures) == 2
    commit_verification_decision_v05(case["ledger"], decision)

    # A second prepare must replay the committed chain stably (VERIFIED).
    again = prepare_verification_decision_v05(
        case["ledger"],
        DecisionDraftRequest(
            decision_id="e" * 64,
            decided_at="2026-01-01T00:30:00Z",
            nonce="f" * 64,
        ),
    )
    assert again.decision == "VERIFIED"


def test_high_risk_split_verifier_coverage_is_rejected(
    v05_transaction_case,
) -> None:
    """A split coverage (positive arm from verifier A, negative arm from
    verifier B) must not bypass cross-validation: every arm needs both
    verifiers, so this inconsistent set is rejected."""
    from openworkproof.verification import VerificationInputError

    case = v05_transaction_case
    profile, second_key, second_binding = _high_risk_profile(case)
    first_key = case["keys"]["Verifier"][0]
    first_binding = next(
        item.model_dump(mode="json")
        for item in profile.verifier_bindings
        if item.verifier_key_id == _key_id(first_key.public_key())
    )
    manifest = case["manifest"]

    # Positive arm from verifier 0, negative arm from verifier 1 (split).
    results = [
        _arm_result_for_verifier(
            case,
            profile,
            manifest,
            verifier_key=first_key,
            binding=first_binding,
            arm_kind="positive",
            suffix="positive-split",
            evidence_ref=_write_json_evidence(
                case["tmp_path"], "results/positive.json", {"passed": True}
            ),
            scope_evidence_ref=_write_json_evidence(
                case["tmp_path"],
                "scope/positive.json",
                {"population_digest": manifest.population_digest},
            ),
            result_id="8" * 63 + "0",
        ),
        _arm_result_for_verifier(
            case,
            profile,
            manifest,
            verifier_key=second_key,
            binding=second_binding,
            arm_kind="negative",
            suffix="negative-split",
            evidence_ref=_write_json_evidence(
                case["tmp_path"], "results/negative.json", {"passed": True}
            ),
            scope_evidence_ref=_write_json_evidence(
                case["tmp_path"],
                "scope/negative.json",
                {"population_digest": manifest.population_digest},
            ),
            result_id="9" * 63 + "1",
        ),
    ]
    with pytest.raises(VerificationInputError, match="incomplete or inconsistent"):
        _compose_v05(case, profile=profile, results=tuple(results))


def test_high_risk_commit_rejects_signer_without_results(
    v05_transaction_case,
) -> None:
    """A second verifier that signs the draft but produced no arm results must
    not let a single-verifier set commit as high-risk VERIFIED: commit
    recomposes from the full ledger set (only one verifier present) and the
    draft diverges from the signed VERIFIED."""
    import openworkproof.evidence as evidence
    from openworkproof.verification import (
        VerificationTransactionError,
        commit_verification_arm_result_v05,
        commit_verification_decision_v05,
        commit_verification_profile_v05,
        prepare_verification_decision_v05,
        verification_decision_signing_bytes_v05,
    )

    from test_verification_integrity_transactions_v05 import (
        _sign_decision_draft_v05,
    )

    case = dict(v05_transaction_case)
    profile, second_key, second_binding = _high_risk_profile(case)
    first_key = case["keys"]["Verifier"][0]
    first_binding = next(
        item.model_dump(mode="json")
        for item in profile.verifier_bindings
        if item.verifier_key_id == _key_id(first_key.public_key())
    )
    manifest = case["manifest"]
    from openworkproof.scope import ObservedScope

    observed = ObservedScope(
        member_ids=tuple(member.member_id for member in manifest.members),
        member_count=manifest.member_count,
        population_digest=manifest.population_digest,
        required_target_ids=manifest.required_target_ids,
        source_revision=manifest.source_revision,
        workspace_manifest_digest=manifest.workspace_manifest_digest,
        selector_engine_digests=tuple(
            sorted(rule.selector_engine_digest for rule in manifest.selector_rules)
        ),
        evidence_complete=True,
    )

    # Only verifier A produces results; B signs later.
    results = []
    for arm_kind, suffix, result_prefix in (
        ("positive", "positive", "8"),
        ("negative", "negative", "9"),
    ):
        results.append(
            _arm_result_for_verifier(
                case,
                profile,
                manifest,
                verifier_key=first_key,
                binding=first_binding,
                arm_kind=arm_kind,
                suffix=f"{arm_kind}-a",
                evidence_ref=_write_json_evidence(
                    case["tmp_path"], f"results/{arm_kind}.json", {"passed": True}
                ),
                scope_evidence_ref=_write_json_evidence(
                    case["tmp_path"], f"scope/{arm_kind}.json",
                    observed.model_dump(mode="json"),
                ),
                result_id=result_prefix + "a" * 63,
            )
        )

    commit_verification_profile_v05(case["ledger"], profile)
    for result in results:
        commit_verification_arm_result_v05(case["ledger"], result)

    # prepare honestly derives UNKNOWN (single verifier under high risk).
    draft = prepare_verification_decision_v05(
        case["ledger"],
        DecisionDraftRequest(
            decision_id="c" * 64,
            decided_at="2026-01-01T00:20:00Z",
            nonce="d" * 64,
        ),
    )
    assert draft.decision == "UNKNOWN"
    encoded = verification_decision_signing_bytes_v05(draft)
    signatures = []
    for key, binding in (
        (first_key, first_binding),
        (second_key, second_binding),
    ):
        signatures.append(
            {
                "verifier_subject_id": binding["verifier_subject_id"],
                "verifier_key_id": _key_id(key.public_key()),
                "signature_alg": "Ed25519",
                "signature": _base64.urlsafe_b64encode(key.sign(encoded))
                .decode("ascii")
                .rstrip("="),
            }
        )
    signatures.sort(key=lambda item: item["verifier_key_id"].encode("utf-8"))
    decision = VerificationDecisionV05.model_validate(
        {
            "schema_version": "openworkproof-verification-decision/0.5",
            **draft.model_dump(mode="json"),
            "digest": hashlib.sha256(encoded).hexdigest(),
            "verifier_signatures": signatures,
        }
    )
    # Commit recomposes from the full ledger (single verifier present) and the
    # recomposed draft is UNKNOWN, matching the signed UNKNOWN -> commits.
    commit_verification_decision_v05(case["ledger"], decision)
    assert evidence.connect_ledger(case["ledger"]).execute(
        "SELECT 1 FROM verification_decisions_v05 WHERE decision_id = ?",
        (decision.decision_id,),
    ).fetchone() is not None

    # Forge: flip the signed draft to VERIFIED and try to commit. Recomposition
    # from the single-verifier ledger derives UNKNOWN, so the mismatch rejects.
    forged_draft = draft.model_dump(mode="json")
    forged_draft["decision"] = "VERIFIED"
    forged_draft["decision_id"] = "e" * 64
    forged_draft["nonce"] = "f" * 64
    from openworkproof.models import VerificationDecisionDraftV05

    forged = VerificationDecisionDraftV05.model_validate(forged_draft)
    forged_encoded = verification_decision_signing_bytes_v05(forged)
    forged_signatures = []
    for key, binding in (
        (first_key, first_binding),
        (second_key, second_binding),
    ):
        forged_signatures.append(
            {
                "verifier_subject_id": binding["verifier_subject_id"],
                "verifier_key_id": _key_id(key.public_key()),
                "signature_alg": "Ed25519",
                "signature": _base64.urlsafe_b64encode(key.sign(forged_encoded))
                .decode("ascii")
                .rstrip("="),
            }
        )
    forged_signatures.sort(key=lambda item: item["verifier_key_id"].encode("utf-8"))
    forged_decision = VerificationDecisionV05.model_validate(
        {
            "schema_version": "openworkproof-verification-decision/0.5",
            **forged.model_dump(mode="json"),
            "digest": hashlib.sha256(forged_encoded).hexdigest(),
            "verifier_signatures": forged_signatures,
        }
    )
    with pytest.raises(VerificationTransactionError, match="draft mismatch"):
        commit_verification_decision_v05(case["ledger"], forged_decision)


def test_high_risk_dual_verifier_offline_package_replays(
    v05_transaction_case,
) -> None:
    """A customer-private package from a converged high-risk decision must
    replay offline: the package carries both verifier sets and the offline
    verifier re-runs the dual cross-validation."""
    import openworkproof.evidence as evidence
    from openworkproof.delivery_package import (
        export_delivery_package,
        verify_delivery_package,
    )
    from openworkproof.scope import ObservedScope
    from openworkproof.verification import (
        commit_verification_arm_result_v05,
        commit_verification_decision_v05,
        commit_verification_profile_v05,
        prepare_verification_decision_v05,
        verification_decision_signing_bytes_v05,
    )

    case = dict(v05_transaction_case)
    profile, second_key, second_binding = _high_risk_profile(case)
    first_key = case["keys"]["Verifier"][0]
    first_binding = next(
        item.model_dump(mode="json")
        for item in profile.verifier_bindings
        if item.verifier_key_id == _key_id(first_key.public_key())
    )
    manifest = case["manifest"]
    observed = ObservedScope(
        member_ids=tuple(member.member_id for member in manifest.members),
        member_count=manifest.member_count,
        population_digest=manifest.population_digest,
        required_target_ids=manifest.required_target_ids,
        source_revision=manifest.source_revision,
        workspace_manifest_digest=manifest.workspace_manifest_digest,
        selector_engine_digests=tuple(
            sorted(rule.selector_engine_digest for rule in manifest.selector_rules)
        ),
        evidence_complete=True,
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
            results.append(
                _arm_result_for_verifier(
                    case,
                    profile,
                    manifest,
                    verifier_key=vkey,
                    binding=binding,
                    arm_kind=arm_kind,
                    suffix=f"{arm_kind}-shared",
                    evidence_ref=_write_json_evidence(
                        case["tmp_path"],
                        f"results/{arm_kind}.json",
                        {"arm": arm_kind, "passed": True},
                    ),
                    scope_evidence_ref=_write_json_evidence(
                        case["tmp_path"],
                        f"scope/{arm_kind}.json",
                        observed.model_dump(mode="json"),
                    ),
                    result_id=result_prefix + str(verifier_idx) * 63,
                )
            )
    commit_verification_profile_v05(case["ledger"], profile)
    for result in results:
        commit_verification_arm_result_v05(case["ledger"], result)
    draft = prepare_verification_decision_v05(
        case["ledger"],
        DecisionDraftRequest(
            decision_id="c" * 64,
            decided_at="2026-01-01T00:20:00Z",
            nonce="d" * 64,
        ),
    )
    assert draft.decision == "VERIFIED"
    encoded = verification_decision_signing_bytes_v05(draft)
    signatures = []
    for key, binding in (
        (first_key, first_binding),
        (second_key, second_binding),
    ):
        signatures.append(
            {
                "verifier_subject_id": binding["verifier_subject_id"],
                "verifier_key_id": _key_id(key.public_key()),
                "signature_alg": "Ed25519",
                "signature": _base64.urlsafe_b64encode(key.sign(encoded))
                .decode("ascii")
                .rstrip("="),
            }
        )
    signatures.sort(key=lambda item: item["verifier_key_id"].encode("utf-8"))
    decision = VerificationDecisionV05.model_validate(
        {
            "schema_version": "openworkproof-verification-decision/0.5",
            **draft.model_dump(mode="json"),
            "digest": hashlib.sha256(encoded).hexdigest(),
            "verifier_signatures": signatures,
        }
    )
    commit_verification_decision_v05(case["ledger"], decision)
    output = case["tmp_path"] / "dual-package"
    export_delivery_package(
        case["ledger"], output, privacy_view="customer_private"
    )
    result = verify_delivery_package(output)
    assert result.current_decision == "VERIFIED"
