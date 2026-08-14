from __future__ import annotations

import copy
import hashlib
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from openworkproof.integrity import (
    PopulationAssessmentResult,
    assess_population_integrity,
    validate_population_contracts,
)
from openworkproof.models import (
    ControlContractV05,
    EvaluationScopeManifest,
    PopulationContractV05,
    ScopeMember,
    VerificationArmResultV03,
    VerificationArmResultV05,
    VerificationProfileV03,
    VerificationProfileV05,
    control_contract_id,
    failure_signature_digest,
    population_contract_id,
    population_member_digest,
)
from openworkproof.scope import (
    evaluation_scope_id,
    population_digest,
    scope_member_id,
)
from openworkproof.signing import sign_payload


def _contract(
    rule: dict[str, Any],
    member_ids: list[str],
    member_kind: str,
    *,
    minimum_eligible_count: int = 1,
    minimum_selected_count: int = 1,
    minimum_capture_numerator: int = 1,
    minimum_capture_denominator: int = 100,
) -> dict[str, Any]:
    payload = {
        "selector_rule_id": rule["rule_id"],
        "member_kind": member_kind,
        "selector_spec_digest": rule["selector_spec_digest"],
        "selector_engine_digest": rule["selector_engine_digest"],
        "declared_selected_member_ids": sorted(member_ids),
        "minimum_eligible_count": minimum_eligible_count,
        "minimum_selected_count": minimum_selected_count,
        "maximum_eligible_count": 4096,
        "maximum_selected_count": 4096,
        "minimum_capture_numerator": minimum_capture_numerator,
        "minimum_capture_denominator": minimum_capture_denominator,
        "empty_population_policy": "unknown",
        "required_population_evidence_purposes": [
            "eligible-population",
            "selected-population",
        ],
    }
    return {"contract_id": population_contract_id(payload), **payload}


def _control_contract(arm_id: str, fixture_digest: str) -> dict[str, Any]:
    signature = {
        "execution_status": "completed",
        "exit_codes": [1],
        "reason_codes": ["MUTATION_CAUGHT"],
        "predicate_ids": ["tests_passed"],
        "required_evidence_purposes": ["test-result"],
    }
    payload = {
        "arm_id": arm_id,
        "control_target": "semantic_regression",
        "fixture_digest": fixture_digest,
        "provocation_digest": "8" * 64,
        "expected_failure_signature": signature,
        "expected_failure_signature_digest": failure_signature_digest(signature),
        "valid_from": "2026-01-01T00:00:00Z",
        "expires_at": "2026-01-01T01:00:00Z",
    }
    return {"control_id": control_contract_id(payload), **payload}


def _signed_manifest(
    base: EvaluationScopeManifest,
    manager_key: Ed25519PrivateKey,
) -> EvaluationScopeManifest:
    payload = base.model_dump(
        mode="json",
        exclude={"digest", "signature_alg", "signer_key_id", "signature"},
    )
    original = payload["selector_rules"][0]
    payload["selector_rules"] = sorted(
        (
            {
                **original,
                "rule_id": "3" * 64,
                "selector_spec_digest": "4" * 64,
                "selector_engine_digest": "5" * 64,
            },
            {
                **original,
                "rule_id": "6" * 64,
                "selector_spec_digest": "7" * 64,
                "selector_engine_digest": "8" * 64,
            },
        ),
        key=lambda rule: (rule["selector_kind"].encode("utf-8"), rule["rule_id"]),
    )
    payload["scope_id"] = evaluation_scope_id(
        {key: value for key, value in payload.items() if key != "scope_id"}
    )
    return EvaluationScopeManifest.model_validate(
        sign_payload("evaluation-scope", payload, manager_key, version="0.3")
    )


def _signed_profile(
    base: VerificationProfileV03,
    manifest: EvaluationScopeManifest,
    manager_key: Ed25519PrivateKey,
    *,
    contract_changes: dict[str, dict[str, Any]] | None = None,
) -> VerificationProfileV05:
    payload = base.model_dump(
        mode="json",
        exclude={"digest", "signature_alg", "signer_key_id", "signature"},
    )
    payload["schema_version"] = "openworkproof-verification-profile/0.5"
    payload["evaluation_scope_id"] = manifest.scope_id
    payload["evaluation_scope_digest"] = manifest.digest
    members_by_kind = {
        kind: sorted(
            member.member_id
            for member in manifest.members
            if member.member_kind == kind
        )
        for kind in ("source_file", "test_case")
    }
    contracts = [
        _contract(
            rule.model_dump(mode="json"),
            members_by_kind[kind],
            kind,
        )
        for rule, kind in zip(
            manifest.selector_rules, ("source_file", "test_case"), strict=True
        )
    ]
    if contract_changes:
        for contract in contracts:
            changes = contract_changes.get(contract["member_kind"])
            if changes:
                contract.update(copy.deepcopy(changes))
                contract["contract_id"] = population_contract_id(contract)
    payload["population_contracts"] = sorted(
        contracts, key=lambda contract: contract["contract_id"]
    )
    negative_arm = payload["negative_arms"][0]
    payload["control_contracts"] = [
        _control_contract(
            negative_arm["arm_id"], negative_arm["mutant_patch_digest"]
        )
    ]
    return VerificationProfileV05.model_validate(
        sign_payload("verification-profile", payload, manager_key, version="0.5")
    )


def _evidence(path: str) -> dict[str, Any]:
    return {
        "path": path,
        "sha256": "e" * 64,
        "media_type": "application/json",
        "size_bytes": 128,
    }


def _observation(
    contract: PopulationContractV05,
    *,
    eligible_seen: int | None = None,
    selected_count: int | None = None,
    eligible_digest: str | None = None,
    selected_digest: str | None = None,
) -> dict[str, Any]:
    selected_ids = contract.declared_selected_member_ids
    eligible_seen = len(selected_ids) if eligible_seen is None else eligible_seen
    selected_count = len(selected_ids) if selected_count is None else selected_count
    if eligible_seen == 0:
        numerator, denominator = 0, 1
    elif selected_count == 0:
        numerator, denominator = 0, 1
    else:
        numerator, denominator = selected_count, eligible_seen
    return {
        "contract_id": contract.contract_id,
        "selector_rule_id": contract.selector_rule_id,
        "selector_spec_digest": contract.selector_spec_digest,
        "selector_engine_digest": contract.selector_engine_digest,
        "eligible_seen": eligible_seen,
        "eligible_population_digest": eligible_digest
        or (
            population_member_digest(())
            if eligible_seen == 0
            else population_member_digest(selected_ids)
        ),
        "selected_count": selected_count,
        "selected_population_digest": selected_digest
        or (
            population_member_digest(())
            if selected_count == 0
            else population_member_digest(selected_ids)
        ),
        "capture_numerator": numerator,
        "capture_denominator": denominator,
        "observed_at": "2026-01-01T00:10:00Z",
        "evidence_refs": [
            _evidence("eligible-population"),
            _evidence("selected-population"),
        ],
    }


def _control_observation(contract: ControlContractV05) -> dict[str, Any]:
    signature = contract.expected_failure_signature.model_dump(mode="json")
    return {
        "control_id": contract.control_id,
        "fixture_digest": contract.fixture_digest,
        "provocation_digest": contract.provocation_digest,
        "observed_failure_signature": signature,
        "observed_failure_signature_digest": failure_signature_digest(signature),
        "control_status": "proven",
        "evidence_refs": [_evidence("test-result")],
    }


def _signed_result(
    base: VerificationArmResultV03,
    profile: VerificationProfileV05,
    manifest: EvaluationScopeManifest,
    verifier_key: Ed25519PrivateKey,
    *,
    arm_kind: str,
    observation_changes: dict[str, dict[str, Any]] | None = None,
) -> VerificationArmResultV05:
    payload = base.model_dump(
        mode="json",
        exclude={"digest", "signature_alg", "signer_key_id", "signature"},
    )
    arm = profile.positive_arm if arm_kind == "positive" else profile.negative_arms[0]
    payload.update(
        schema_version="openworkproof-verification-arm-result/0.5",
        profile_digest=profile.digest,
        arm_result_id="8" * 64 if arm_kind == "positive" else "9" * 64,
        arm_id=arm.arm_id,
        arm_kind=arm_kind,
        mutation_status="not_applicable" if arm_kind == "positive" else "applied",
        reason_codes=[]
        if arm_kind == "positive"
        else ["MUTATION_APPLIED", "MUTATION_CAUGHT"],
        scope_manifest_digest=manifest.digest,
    )
    observations = []
    for contract in profile.population_contracts:
        observation = _observation(contract)
        changes = (observation_changes or {}).get(contract.member_kind)
        if changes:
            observation.update(copy.deepcopy(changes))
        observations.append(observation)
    payload["population_observations"] = sorted(
        observations, key=lambda observation: observation["contract_id"]
    )
    payload["control_observation"] = (
        None
        if arm_kind == "positive"
        else _control_observation(profile.control_contracts[0])
    )
    return VerificationArmResultV05.model_validate(
        sign_payload("verification-arm-result", payload, verifier_key, version="0.5")
    )


@pytest.fixture
def population_case(
    evaluation_scope_v03: EvaluationScopeManifest,
    frozen_verification_profile_v03: VerificationProfileV03,
    frozen_verification_arm_result_v03: VerificationArmResultV03,
    frozen_role_keys_v05: dict[str, tuple[Ed25519PrivateKey, dict[str, str]]],
) -> dict[str, Any]:
    manager_key = frozen_role_keys_v05["Manager"][0]
    verifier_key = frozen_role_keys_v05["Verifier"][0]
    manifest = _signed_manifest(evaluation_scope_v03, manager_key)
    profile = _signed_profile(
        frozen_verification_profile_v03, manifest, manager_key
    )
    results = tuple(
        _signed_result(
            frozen_verification_arm_result_v03,
            profile,
            manifest,
            verifier_key,
            arm_kind=arm_kind,
        )
        for arm_kind in ("positive", "negative")
    )
    return {
        "base_profile": frozen_verification_profile_v03,
        "base_result": frozen_verification_arm_result_v03,
        "manager_key": manager_key,
        "verifier_key": verifier_key,
        "manifest": manifest,
        "profile": profile,
        "results": results,
    }


def _resigned_profile(
    case: dict[str, Any],
    contracts: list[dict[str, Any]],
) -> VerificationProfileV05:
    payload = case["profile"].model_dump(
        mode="json",
        exclude={"digest", "signature_alg", "signer_key_id", "signature"},
    )
    payload["population_contracts"] = sorted(
        contracts, key=lambda contract: contract["contract_id"]
    )
    return VerificationProfileV05.model_validate(
        sign_payload(
            "verification-profile", payload, case["manager_key"], version="0.5"
        )
    )


def _results(
    case: dict[str, Any],
    *,
    positive_changes: dict[str, dict[str, Any]] | None = None,
    negative_changes: dict[str, dict[str, Any]] | None = None,
) -> tuple[VerificationArmResultV05, VerificationArmResultV05]:
    return tuple(
        _signed_result(
            case["base_result"],
            case["profile"],
            case["manifest"],
            case["verifier_key"],
            arm_kind=arm_kind,
            observation_changes=(
                positive_changes if arm_kind == "positive" else negative_changes
            ),
        )
        for arm_kind in ("positive", "negative")
    )  # type: ignore[return-value]


def test_profile_contracts_exactly_cover_scope_and_selector_rules(
    population_case: dict[str, Any],
) -> None:
    assert (
        validate_population_contracts(
            population_case["profile"], population_case["manifest"]
        )
        is None
    )


@pytest.mark.parametrize("mutation", ("missing", "duplicate"))
def test_profile_rejects_missing_or_duplicate_contract(
    population_case: dict[str, Any], mutation: str
) -> None:
    contracts = [
        contract.model_dump(mode="json")
        for contract in population_case["profile"].population_contracts
    ]
    malformed = (
        population_case["profile"].model_copy(
            update={
                "population_contracts": tuple(
                    population_case["profile"].population_contracts[:1]
                )
            }
        )
        if mutation == "missing"
        else population_case["profile"].model_copy(
            update={
                "population_contracts": tuple(
                    [
                        population_case["profile"].population_contracts[0],
                        population_case["profile"].population_contracts[0],
                    ]
                )
            }
        )
    )
    assert contracts
    with pytest.raises(ValueError):
        validate_population_contracts(malformed, population_case["manifest"])


@pytest.mark.parametrize(
    "field",
    ("selector_rule_id", "selector_spec_digest", "selector_engine_digest"),
)
def test_profile_rejects_selector_mapping_drift(
    population_case: dict[str, Any], field: str
) -> None:
    contracts = [
        contract.model_dump(mode="json")
        for contract in population_case["profile"].population_contracts
    ]
    contracts[0][field] = "f" * 64
    contracts[0]["contract_id"] = population_contract_id(contracts[0])
    profile = _resigned_profile(population_case, contracts)
    with pytest.raises(ValueError):
        validate_population_contracts(profile, population_case["manifest"])


@pytest.mark.parametrize("mutation", ("orphan", "wrong_kind", "duplicate_member"))
def test_profile_rejects_invalid_declared_member_relations(
    population_case: dict[str, Any], mutation: str
) -> None:
    contracts = [
        contract.model_dump(mode="json")
        for contract in population_case["profile"].population_contracts
    ]
    source = next(c for c in contracts if c["member_kind"] == "source_file")
    test = next(c for c in contracts if c["member_kind"] == "test_case")
    if mutation == "orphan":
        source["declared_selected_member_ids"] = ["f" * 64]
    elif mutation == "wrong_kind":
        source["declared_selected_member_ids"] = list(
            test["declared_selected_member_ids"]
        )
    else:
        source["declared_selected_member_ids"] = list(
            test["declared_selected_member_ids"]
        )
    source["contract_id"] = population_contract_id(source)
    if mutation == "duplicate_member":
        source["member_kind"] = "test_case"
        source["contract_id"] = population_contract_id(source)
    profile = _resigned_profile(population_case, contracts)
    with pytest.raises(ValueError):
        validate_population_contracts(profile, population_case["manifest"])


def test_profile_rejects_delivery_artifact_member(
    population_case: dict[str, Any]
) -> None:
    manifest_payload = population_case["manifest"].model_dump(
        mode="json",
        exclude={"digest", "signature_alg", "signer_key_id", "signature"},
    )
    locator = "delivery/report.json"
    delivery = ScopeMember.model_validate(
        {
            "member_id": scope_member_id("delivery_artifact", locator),
            "member_kind": "delivery_artifact",
            "locator": locator,
            "locator_digest": hashlib.sha256(locator.encode("utf-8")).hexdigest(),
            "content_digest": "f" * 64,
            "source_revision": population_case["manifest"].source_revision,
        }
    )
    members = sorted(
        (*population_case["manifest"].members, delivery),
        key=lambda member: (
            member.member_kind,
            member.locator_digest,
            member.member_id,
        ),
    )
    manifest_payload["members"] = [
        member.model_dump(mode="json") for member in members
    ]
    manifest_payload["member_count"] = len(members)
    manifest_payload["population_digest"] = population_digest(members)
    manifest_payload["scope_id"] = evaluation_scope_id(
        {
            key: value
            for key, value in manifest_payload.items()
            if key != "scope_id"
        }
    )
    manifest = EvaluationScopeManifest.model_validate(
        sign_payload(
            "evaluation-scope",
            manifest_payload,
            population_case["manager_key"],
            version="0.3",
        )
    )
    profile = _signed_profile(
        population_case["base_profile"],
        manifest,
        population_case["manager_key"],
    )
    contracts = [
        contract.model_dump(mode="json")
        for contract in profile.population_contracts
    ]
    source = next(c for c in contracts if c["member_kind"] == "source_file")
    source["declared_selected_member_ids"] = [delivery.member_id]
    source["contract_id"] = population_contract_id(source)
    case = {**population_case, "profile": profile}
    malformed_profile = _resigned_profile(case, contracts)
    with pytest.raises(ValueError):
        validate_population_contracts(malformed_profile, manifest)


def test_population_assessment_requires_every_contract_observation_by_id(
    population_case: dict[str, Any]
) -> None:
    result = population_case["results"][0]
    payload = result.model_dump(
        mode="json",
        exclude={"digest", "signature_alg", "signer_key_id", "signature"},
    )
    payload["population_observations"] = payload["population_observations"][:1]
    incomplete = VerificationArmResultV05.model_validate(
        sign_payload(
            "verification-arm-result",
            payload,
            population_case["verifier_key"],
            version="0.5",
        )
    )
    assessed = assess_population_integrity(
        population_case["profile"],
        population_case["manifest"],
        (incomplete, population_case["results"][1]),
    )
    assert assessed.status == "drifted"
    assert "POPULATION_CROSS_ARM_MISMATCH" in assessed.reason_codes


def test_profile_rejects_4097_declared_members(
    population_case: dict[str, Any]
) -> None:
    contract = population_case["profile"].population_contracts[0].model_copy(
        update={
            "declared_selected_member_ids": tuple(
                f"{index:064x}" for index in range(4097)
            )
        }
    )
    malformed = population_case["profile"].model_copy(
        update={"population_contracts": (contract,)}
    )
    with pytest.raises(ValueError):
        validate_population_contracts(malformed, population_case["manifest"])


def test_signed_profile_cross_object_anomaly_is_invalid_not_unknown(
    population_case: dict[str, Any]
) -> None:
    contracts = [
        contract.model_dump(mode="json")
        for contract in population_case["profile"].population_contracts
    ]
    contracts[0]["declared_selected_member_ids"] = ["f" * 64]
    contracts[0]["contract_id"] = population_contract_id(contracts[0])
    profile = _resigned_profile(population_case, contracts)
    with pytest.raises(ValueError):
        assess_population_integrity(
            profile, population_case["manifest"], population_case["results"]
        )


def test_population_assessment_matches_at_exact_minimum_capture(
    population_case: dict[str, Any]
) -> None:
    case = dict(population_case)
    case["profile"] = _signed_profile(
        case["base_profile"],
        case["manifest"],
        case["manager_key"],
        contract_changes={
            "test_case": {
                "minimum_capture_numerator": 1,
                "minimum_capture_denominator": 100,
            }
        },
    )
    test_contract = next(
        c for c in case["profile"].population_contracts if c.member_kind == "test_case"
    )
    selected_digest = population_member_digest(
        test_contract.declared_selected_member_ids
    )
    results = _results(
        case,
        positive_changes={
            "test_case": {
                "eligible_seen": 100,
                "selected_count": 1,
                "eligible_population_digest": "a" * 64,
                "selected_population_digest": selected_digest,
                "capture_numerator": 1,
                "capture_denominator": 100,
            }
        },
        negative_changes={
            "test_case": {
                "eligible_seen": 100,
                "selected_count": 1,
                "eligible_population_digest": "a" * 64,
                "selected_population_digest": selected_digest,
                "capture_numerator": 1,
                "capture_denominator": 100,
            }
        },
    )
    assert assess_population_integrity(
        case["profile"], case["manifest"], results
    ) == PopulationAssessmentResult("matched", ())


def test_population_assessment_empty_precedes_thresholds(
    population_case: dict[str, Any]
) -> None:
    empty = {
        kind: {
            "eligible_seen": 0,
            "eligible_population_digest": population_member_digest(()),
            "selected_count": 0,
            "selected_population_digest": population_member_digest(()),
            "capture_numerator": 0,
            "capture_denominator": 1,
        }
        for kind in ("source_file", "test_case")
    }
    result = assess_population_integrity(
        population_case["profile"],
        population_case["manifest"],
        _results(population_case, positive_changes=empty, negative_changes=empty),
    )
    assert result == PopulationAssessmentResult(
        "empty", ("NO_ELIGIBLE_POPULATION",)
    )


def test_population_assessment_eligible_400_selected_zero_is_capture_failed(
    population_case: dict[str, Any]
) -> None:
    changes = {
        "test_case": {
            "eligible_seen": 400,
            "eligible_population_digest": "a" * 64,
            "selected_count": 0,
            "selected_population_digest": population_member_digest(()),
            "capture_numerator": 0,
            "capture_denominator": 1,
        }
    }
    result = assess_population_integrity(
        population_case["profile"],
        population_case["manifest"],
        _results(
            population_case,
            positive_changes=changes,
            negative_changes=changes,
        ),
    )
    assert result == PopulationAssessmentResult(
        "capture_failed", ("POPULATION_CAPTURE_FAILED",)
    )


def test_population_observation_rejects_non_reduced_fraction(
    population_case: dict[str, Any]
) -> None:
    with pytest.raises(ValidationError, match="reduced"):
        _results(
            population_case,
            positive_changes={
                "test_case": {
                    "eligible_seen": 4,
                    "selected_count": 2,
                    "eligible_population_digest": "a" * 64,
                    "selected_population_digest": "b" * 64,
                    "capture_numerator": 2,
                    "capture_denominator": 4,
                }
            },
        )


@pytest.mark.parametrize(
    ("field", "reason"),
    (
        ("selector_spec_digest", "POPULATION_RULE_DRIFT"),
        ("selector_engine_digest", "POPULATION_ENGINE_DRIFT"),
        ("selected_population_digest", "POPULATION_DIGEST_MISMATCH"),
    ),
)
def test_population_assessment_detects_rule_engine_and_digest_drift(
    population_case: dict[str, Any], field: str, reason: str
) -> None:
    changes = {"test_case": {field: "f" * 64}}
    result = assess_population_integrity(
        population_case["profile"],
        population_case["manifest"],
        _results(
            population_case,
            positive_changes=changes,
            negative_changes=changes,
        ),
    )
    assert result.status == "drifted"
    assert reason in result.reason_codes


def test_population_assessment_missing_required_evidence_is_unavailable(
    population_case: dict[str, Any]
) -> None:
    changes = {
        "test_case": {"evidence_refs": [_evidence("eligible-population")]}
    }
    result = assess_population_integrity(
        population_case["profile"],
        population_case["manifest"],
        _results(population_case, positive_changes=changes),
    )
    assert result == PopulationAssessmentResult(
        "unavailable", ("POPULATION_EVIDENCE_MISSING",)
    )


def test_population_assessment_selected_count_must_equal_declaration(
    population_case: dict[str, Any]
) -> None:
    changes = {
        "test_case": {
            "eligible_seen": 2,
            "eligible_population_digest": "a" * 64,
            "selected_count": 2,
            "selected_population_digest": "b" * 64,
            "capture_numerator": 1,
            "capture_denominator": 1,
        }
    }
    result = assess_population_integrity(
        population_case["profile"],
        population_case["manifest"],
        _results(
            population_case,
            positive_changes=changes,
            negative_changes=changes,
        ),
    )
    assert result.status == "drifted"
    assert "POPULATION_DIGEST_MISMATCH" in result.reason_codes


def test_population_assessment_zero_selected_requires_empty_digest(
    population_case: dict[str, Any]
) -> None:
    changes = {
        "test_case": {
            "eligible_seen": 400,
            "eligible_population_digest": "a" * 64,
            "selected_count": 0,
            "selected_population_digest": "b" * 64,
            "capture_numerator": 0,
            "capture_denominator": 1,
        }
    }
    result = assess_population_integrity(
        population_case["profile"],
        population_case["manifest"],
        _results(
            population_case,
            positive_changes=changes,
            negative_changes=changes,
        ),
    )
    assert result.status == "drifted"
    assert "POPULATION_DIGEST_MISMATCH" in result.reason_codes


@pytest.mark.parametrize("field", ("eligible_population_digest", "selected_count"))
def test_population_assessment_detects_cross_arm_mismatch(
    population_case: dict[str, Any], field: str
) -> None:
    changes: dict[str, Any]
    if field == "eligible_population_digest":
        changes = {field: "f" * 64}
    else:
        changes = {
            "eligible_seen": 2,
            "eligible_population_digest": "a" * 64,
            "selected_count": 2,
            "selected_population_digest": "b" * 64,
            "capture_numerator": 1,
            "capture_denominator": 1,
        }
    result = assess_population_integrity(
        population_case["profile"],
        population_case["manifest"],
        _results(population_case, negative_changes={"test_case": changes}),
    )
    assert result.status == "drifted"
    assert "POPULATION_CROSS_ARM_MISMATCH" in result.reason_codes


def test_population_assessment_precedence_and_reason_codes_are_closed(
    population_case: dict[str, Any]
) -> None:
    changes = {
        "test_case": {
            "selector_spec_digest": "f" * 64,
            "selector_engine_digest": "e" * 64,
            "selected_population_digest": "d" * 64,
        }
    }
    drifted = assess_population_integrity(
        population_case["profile"],
        population_case["manifest"],
        _results(
            population_case,
            positive_changes=changes,
            negative_changes=changes,
        ),
    )
    assert drifted.status == "drifted"
    assert drifted.reason_codes == tuple(sorted(set(drifted.reason_codes)))
    assert drifted.reason_codes == (
        "POPULATION_DIGEST_MISMATCH",
        "POPULATION_ENGINE_DRIFT",
        "POPULATION_RULE_DRIFT",
    )

    unavailable = assess_population_integrity(
        population_case["profile"],
        population_case["manifest"],
        _results(
            population_case,
            positive_changes={
                "test_case": {
                    **changes["test_case"],
                    "evidence_refs": [_evidence("eligible-population")],
                }
            },
        ),
    )
    assert unavailable == PopulationAssessmentResult(
        "unavailable", ("POPULATION_EVIDENCE_MISSING",)
    )
