from __future__ import annotations

import copy
import hashlib
from collections.abc import Sequence
from typing import Any

import pytest
import rfc8785
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
    *,
    members: Sequence[ScopeMember] | None = None,
    selector_kinds: Sequence[str] | None = None,
) -> EvaluationScopeManifest:
    payload = base.model_dump(
        mode="json",
        exclude={"digest", "signature_alg", "signer_key_id", "signature"},
    )
    original = payload["selector_rules"][0]
    kinds = list(selector_kinds) if selector_kinds is not None else [
        original["selector_kind"],
        original["selector_kind"],
    ]
    payload["selector_rules"] = sorted(
        (
            {
                **original,
                "rule_id": "3" * 64,
                "selector_kind": kinds[0],
                "selector_spec_digest": "4" * 64,
                "selector_engine_digest": "5" * 64,
            },
            {
                **original,
                "rule_id": "6" * 64,
                "selector_kind": kinds[1],
                "selector_spec_digest": "7" * 64,
                "selector_engine_digest": "8" * 64,
            },
        ),
        key=lambda rule: (rule["selector_kind"].encode("utf-8"), rule["rule_id"]),
    )
    if members is not None:
        ordered_members = tuple(
            sorted(
                members,
                key=lambda member: (
                    member.member_kind,
                    member.locator_digest,
                    member.member_id,
                ),
            )
        )
        payload["members"] = [
            member.model_dump(mode="json") for member in ordered_members
        ]
        payload["member_count"] = len(ordered_members)
        payload["population_digest"] = population_digest(ordered_members)
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
    declared_by_kind: dict[str, Sequence[str]] | None = None,
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
    declared_by_kind = declared_by_kind or {}
    contracts = [
        _contract(
            rule.model_dump(mode="json"),
            sorted(declared_by_kind.get(kind, members_by_kind[kind])),
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


_EVIDENCE_CONTENT: dict[str, bytes] = {}

_OBSERVATION_PARAMS = {
    "eligible_seen",
    "selected_count",
    "eligible_population_digest",
    "selected_population_digest",
    "capture_numerator",
    "capture_denominator",
    "evidence_refs",
}


def _population_inventory() -> dict[str, bytes]:
    return dict(_EVIDENCE_CONTENT)


def _evidence(
    purpose: str,
    member_ids: Sequence[str] = (),
    *,
    path: str | None = None,
    raw_content: bytes | None = None,
) -> dict[str, Any]:
    document: dict[str, Any] = {
        "schema_version": "openworkproof-population-evidence/0.5",
        "purpose": purpose,
        "member_ids": sorted(set(member_ids)),
    }
    content = rfc8785.dumps(document) if raw_content is None else raw_content
    reference = {
        "path": path if path is not None else f"evidence/{purpose}.json",
        "sha256": hashlib.sha256(content).hexdigest(),
        "media_type": "application/json",
        "size_bytes": len(content),
    }
    _EVIDENCE_CONTENT[reference["sha256"]] = content
    return reference


def _observation(
    contract: PopulationContractV05,
    *,
    eligible_seen: int | None = None,
    selected_count: int | None = None,
    eligible_population_digest: str | None = None,
    selected_population_digest: str | None = None,
    capture_numerator: int | None = None,
    capture_denominator: int | None = None,
    evidence_refs: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    declared = list(contract.declared_selected_member_ids)
    eligible_seen = len(declared) if eligible_seen is None else eligible_seen
    selected_count = len(declared) if selected_count is None else selected_count

    def _synthetic_extras(count: int) -> list[str]:
        extras: list[str] = []
        index = 0
        while len(extras) < count:
            candidate = f"e{index:063x}"
            index += 1
            if candidate not in declared:
                extras.append(candidate)
        return extras

    if eligible_seen == 0:
        eligible_members: list[str] = []
        selected_members: list[str] = []
        numerator, denominator = 0, 1
    elif selected_count == 0:
        eligible_members = declared + _synthetic_extras(
            max(0, eligible_seen - len(declared))
        )
        selected_members = []
        numerator, denominator = 0, 1
    else:
        eligible_members = declared + _synthetic_extras(
            max(0, eligible_seen - len(declared))
        )
        selected_members = declared
        numerator, denominator = selected_count, eligible_seen
    if capture_numerator is not None and capture_denominator is not None:
        numerator, denominator = capture_numerator, capture_denominator
    return {
        "contract_id": contract.contract_id,
        "selector_rule_id": contract.selector_rule_id,
        "selector_spec_digest": contract.selector_spec_digest,
        "selector_engine_digest": contract.selector_engine_digest,
        "eligible_seen": eligible_seen,
        "eligible_population_digest": (
            eligible_population_digest
            if eligible_population_digest is not None
            else (
                population_member_digest(())
                if eligible_seen == 0
                else population_member_digest(eligible_members)
            )
        ),
        "selected_count": selected_count,
        "selected_population_digest": (
            selected_population_digest
            if selected_population_digest is not None
            else (
                population_member_digest(())
                if selected_count == 0
                else population_member_digest(selected_members)
            )
        ),
        "capture_numerator": numerator,
        "capture_denominator": denominator,
        "observed_at": "2026-01-01T00:10:00Z",
        "evidence_refs": (
            [
                _evidence("eligible-population", eligible_members),
                _evidence("selected-population", selected_members),
            ]
            if evidence_refs is None
            else evidence_refs
        ),
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
        changes = (observation_changes or {}).get(contract.member_kind)
        params = copy.deepcopy(changes) if changes else {}
        updates = {
            key: params.pop(key)
            for key in list(params)
            if key not in _OBSERVATION_PARAMS
        }
        observation = _observation(contract, **params)
        if updates:
            observation.update(updates)
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
            population_case["profile"],
            population_case["manifest"],
            rule_outputs=_rule_outputs(population_case),
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
    if mutation == "missing":
        malformed = _resigned_profile(population_case, contracts[:1])
        with pytest.raises(ValueError):
            validate_population_contracts(
                malformed,
                population_case["manifest"],
                rule_outputs=_rule_outputs(population_case),
            )
    else:
        with pytest.raises(ValueError):
            _resigned_profile(
                population_case, [contracts[0], contracts[0]]
            )


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
        validate_population_contracts(
            profile,
            population_case["manifest"],
            rule_outputs=_rule_outputs(population_case),
        )


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
        validate_population_contracts(
            profile,
            population_case["manifest"],
            rule_outputs=_rule_outputs(population_case),
        )


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
        validate_population_contracts(
            malformed_profile,
            manifest,
            rule_outputs=_rule_outputs(population_case),
        )


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
        rule_outputs=_rule_outputs(population_case),
        evidence_inventory=_population_inventory(),
    )
    assert assessed.status == "drifted"
    assert "POPULATION_CROSS_ARM_MISMATCH" in assessed.reason_codes


def test_profile_rejects_4097_declared_members(
    population_case: dict[str, Any]
) -> None:
    contracts = [
        contract.model_dump(mode="json")
        for contract in population_case["profile"].population_contracts
    ]
    with pytest.raises(ValueError):
        contracts[0]["declared_selected_member_ids"] = [
            f"{index:064x}" for index in range(4097)
        ]
        contracts[0]["contract_id"] = population_contract_id(contracts[0])
        _resigned_profile(population_case, contracts)


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
            profile,
            population_case["manifest"],
            population_case["results"],
            rule_outputs=_rule_outputs(population_case),
            evidence_inventory=_population_inventory(),
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
                "selected_population_digest": selected_digest,
                "capture_numerator": 1,
                "capture_denominator": 100,
            }
        },
        negative_changes={
            "test_case": {
                "eligible_seen": 100,
                "selected_count": 1,
                "selected_population_digest": selected_digest,
                "capture_numerator": 1,
                "capture_denominator": 100,
            }
        },
    )
    assert assess_population_integrity(
        case["profile"],
        case["manifest"],
        results,
        rule_outputs=_rule_outputs(case),
        evidence_inventory=_population_inventory(),
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
        rule_outputs=_rule_outputs(population_case),
        evidence_inventory=_population_inventory(),
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
        rule_outputs=_rule_outputs(population_case),
        evidence_inventory=_population_inventory(),
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
        rule_outputs=_rule_outputs(population_case),
        evidence_inventory=_population_inventory(),
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
        rule_outputs=_rule_outputs(population_case),
        evidence_inventory=_population_inventory(),
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
        rule_outputs=_rule_outputs(population_case),
        evidence_inventory=_population_inventory(),
    )
    assert result.status == "drifted"
    assert "POPULATION_DIGEST_MISMATCH" in result.reason_codes


def test_population_assessment_zero_selected_requires_empty_digest(
    population_case: dict[str, Any]
) -> None:
    changes = {
        "test_case": {
            "eligible_seen": 400,
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
        rule_outputs=_rule_outputs(population_case),
        evidence_inventory=_population_inventory(),
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
        rule_outputs=_rule_outputs(population_case),
        evidence_inventory=_population_inventory(),
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
        rule_outputs=_rule_outputs(population_case),
        evidence_inventory=_population_inventory(),
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
        rule_outputs=_rule_outputs(population_case),
        evidence_inventory=_population_inventory(),
    )
    assert unavailable == PopulationAssessmentResult(
        "unavailable", ("POPULATION_EVIDENCE_MISSING",)
    )


# ---------------------------------------------------------------------------
# Task 4 review-fix RED tests: the four recorded defects.
# ---------------------------------------------------------------------------

def _rule_outputs(case: dict[str, Any]) -> dict[str, list[str]]:
    """Authoritative selector-rule output witness derived from Scope members."""
    manifest: EvaluationScopeManifest = case["manifest"]
    members_by_kind = {
        kind: sorted(
            member.member_id
            for member in manifest.members
            if member.member_kind == kind
        )
        for kind in ("source_file", "test_case")
    }
    return {
        manifest.selector_rules[0].rule_id: members_by_kind["source_file"],
        manifest.selector_rules[1].rule_id: members_by_kind["test_case"],
    }


def _population_evidence_ref(
    purpose: str,
    member_ids: Sequence[str],
    *,
    path: str | None = None,
    raw_content: bytes | None = None,
) -> tuple[dict[str, Any], bytes]:
    document: dict[str, Any] = {
        "schema_version": "openworkproof-population-evidence/0.5",
        "purpose": purpose,
        "member_ids": sorted(set(member_ids)),
    }
    content = rfc8785.dumps(document) if raw_content is None else raw_content
    reference = {
        "path": path if path is not None else f"evidence/{purpose}.json",
        "sha256": hashlib.sha256(content).hexdigest(),
        "media_type": "application/json",
        "size_bytes": len(content),
    }
    return reference, content


def _population_observation_changes(
    contract: PopulationContractV05,
    eligible_member_ids: Sequence[str],
    selected_member_ids: Sequence[str],
    *,
    eligible_seen: int | None = None,
    selected_count: int | None = None,
    eligible_digest: str | None = None,
    selected_digest: str | None = None,
    eligible_ref: tuple[dict[str, Any], bytes] | None = None,
    selected_ref: tuple[dict[str, Any], bytes] | None = None,
) -> tuple[dict[str, Any], dict[str, bytes]]:
    eligible = sorted(set(eligible_member_ids))
    selected = sorted(set(selected_member_ids))
    eligible_seen = len(eligible) if eligible_seen is None else eligible_seen
    selected_count = len(selected) if selected_count is None else selected_count
    numerator, denominator = (
        (0, 1)
        if eligible_seen == 0 or selected_count == 0
        else (selected_count, eligible_seen)
    )
    eligible_reference, eligible_content = (
        eligible_ref
        if eligible_ref is not None
        else _population_evidence_ref("eligible-population", eligible)
    )
    selected_reference, selected_content = (
        selected_ref
        if selected_ref is not None
        else _population_evidence_ref("selected-population", selected)
    )
    changes: dict[str, Any] = {
        "eligible_seen": eligible_seen,
        "eligible_population_digest": (
            population_member_digest(())
            if eligible_seen == 0
            else (
                eligible_digest
                if eligible_digest is not None
                else population_member_digest(eligible)
            )
        ),
        "selected_count": selected_count,
        "selected_population_digest": (
            population_member_digest(())
            if selected_count == 0
            else (
                selected_digest
                if selected_digest is not None
                else population_member_digest(selected)
            )
        ),
        "capture_numerator": numerator,
        "capture_denominator": denominator,
        "evidence_refs": [eligible_reference, selected_reference],
    }
    inventory = {
        eligible_reference["sha256"]: eligible_content,
        selected_reference["sha256"]: selected_content,
    }
    return changes, inventory


def _default_assessment_inputs(
    case: dict[str, Any],
) -> tuple[dict[str, dict[str, Any]], dict[str, bytes]]:
    changes: dict[str, dict[str, Any]] = {}
    inventory: dict[str, bytes] = {}
    for contract in case["profile"].population_contracts:
        declared = list(contract.declared_selected_member_ids)
        kind_changes, kind_inventory = _population_observation_changes(
            contract, declared, declared
        )
        changes[contract.member_kind] = kind_changes
        inventory.update(kind_inventory)
    return changes, inventory


def _assess(
    case: dict[str, Any],
    *,
    changes: dict[str, dict[str, Any]] | None = None,
    inventory: dict[str, bytes] | None = None,
    rule_outputs: dict[str, list[str]] | None = None,
) -> PopulationAssessmentResult:
    default_changes, default_inventory = _default_assessment_inputs(case)
    changes = {**default_changes, **(changes or {})}
    if inventory is None:
        inventory = default_inventory
    results = _results(
        case,
        positive_changes=changes,
        negative_changes=changes,
    )
    return assess_population_integrity(
        case["profile"],
        case["manifest"],
        results,
        rule_outputs=_rule_outputs(case) if rule_outputs is None else rule_outputs,
        evidence_inventory=inventory,
    )


def test_population_assessment_empty_contract_is_not_masked_by_other_contracts(
    population_case: dict[str, Any],
) -> None:
    """Design 6.1.1: an empty population follows empty_population_policy=unknown
    and stays empty/NO_ELIGIBLE_POPULATION even when the rule output is
    non-empty; it is never misreported as a collection failure and can
    never reach matched."""
    changes, inventory = _default_assessment_inputs(population_case)
    source_contract = next(
        contract
        for contract in population_case["profile"].population_contracts
        if contract.member_kind == "source_file"
    )
    empty_changes, empty_inventory = _population_observation_changes(
        source_contract, [], []
    )
    changes[source_contract.member_kind] = empty_changes
    inventory.update(empty_inventory)
    result = _assess(population_case, changes=changes, inventory=inventory)
    assert result == PopulationAssessmentResult(
        "empty", ("NO_ELIGIBLE_POPULATION",)
    )


def test_population_assessment_rejects_path_strings_as_evidence_purposes(
    population_case: dict[str, Any],
) -> None:
    changes: dict[str, dict[str, Any]] = {}
    inventory: dict[str, bytes] = {}
    for contract in population_case["profile"].population_contracts:
        declared = list(contract.declared_selected_member_ids)
        eligible_ref, eligible_content = _population_evidence_ref(
            "eligible-population",
            declared,
            path="eligible-population",
            raw_content=b"opaque raw log bytes\n",
        )
        selected_ref, selected_content = _population_evidence_ref(
            "selected-population",
            declared,
            path="selected-population",
            raw_content=b"opaque raw log bytes\n",
        )
        changes[contract.member_kind] = {
            "evidence_refs": [eligible_ref, selected_ref]
        }
        inventory.update(
            {
                eligible_ref["sha256"]: eligible_content,
                selected_ref["sha256"]: selected_content,
            }
        )
    result = _assess(population_case, changes=changes, inventory=inventory)
    assert result == PopulationAssessmentResult(
        "unavailable", ("POPULATION_EVIDENCE_MISSING",)
    )


def test_population_assessment_binds_purpose_through_replayed_content(
    population_case: dict[str, Any],
) -> None:
    changes, inventory = _default_assessment_inputs(population_case)
    for contract in population_case["profile"].population_contracts:
        declared = list(contract.declared_selected_member_ids)
        eligible_ref, eligible_content = _population_evidence_ref(
            "eligible-population", declared, path="reports/a.json"
        )
        selected_ref, selected_content = _population_evidence_ref(
            "selected-population", declared, path="reports/b.json"
        )
        changes[contract.member_kind]["evidence_refs"] = [
            eligible_ref,
            selected_ref,
        ]
        inventory.update(
            {
                eligible_ref["sha256"]: eligible_content,
                selected_ref["sha256"]: selected_content,
            }
        )
    result = _assess(population_case, changes=changes, inventory=inventory)
    assert result == PopulationAssessmentResult("matched", ())


def test_population_assessment_evidence_content_must_replay_signed_ref(
    population_case: dict[str, Any],
) -> None:
    changes, inventory = _default_assessment_inputs(population_case)
    inventory[next(iter(inventory))] = b'{"tampered": true}'
    result = _assess(population_case, changes=changes, inventory=inventory)
    assert result == PopulationAssessmentResult(
        "unavailable", ("POPULATION_EVIDENCE_MISSING",)
    )


def test_population_assessment_missing_evidence_content_is_unavailable(
    population_case: dict[str, Any],
) -> None:
    changes, inventory = _default_assessment_inputs(population_case)
    inventory.pop(next(iter(inventory)))
    result = _assess(population_case, changes=changes, inventory=inventory)
    assert result == PopulationAssessmentResult(
        "unavailable", ("POPULATION_EVIDENCE_MISSING",)
    )


def test_population_assessment_recomputes_eligible_digest_from_evidence(
    population_case: dict[str, Any],
) -> None:
    contract = next(
        item
        for item in population_case["profile"].population_contracts
        if item.member_kind == "test_case"
    )
    declared = list(contract.declared_selected_member_ids)
    eligible = declared + [f"e{index:063x}" for index in range(99)]
    kind_changes, kind_inventory = _population_observation_changes(
        contract,
        eligible,
        declared,
        eligible_digest=population_member_digest(()),
    )
    changes, inventory = _default_assessment_inputs(population_case)
    changes[contract.member_kind] = kind_changes
    inventory.update(kind_inventory)
    result = _assess(population_case, changes=changes, inventory=inventory)
    assert result.status == "drifted"
    assert "POPULATION_DIGEST_MISMATCH" in result.reason_codes


def test_population_assessment_eligible_count_must_equal_evidence_members(
    population_case: dict[str, Any],
) -> None:
    contract = next(
        item
        for item in population_case["profile"].population_contracts
        if item.member_kind == "test_case"
    )
    declared = list(contract.declared_selected_member_ids)
    eligible = declared + [f"e{index:063x}" for index in range(99)]
    kind_changes, kind_inventory = _population_observation_changes(
        contract, eligible, declared, eligible_seen=101
    )
    changes, inventory = _default_assessment_inputs(population_case)
    changes[contract.member_kind] = kind_changes
    inventory.update(kind_inventory)
    result = _assess(population_case, changes=changes, inventory=inventory)
    assert result.status == "drifted"
    assert "POPULATION_DIGEST_MISMATCH" in result.reason_codes


def test_population_assessment_selected_evidence_must_equal_declared_members(
    population_case: dict[str, Any],
) -> None:
    contract = next(
        item
        for item in population_case["profile"].population_contracts
        if item.member_kind == "test_case"
    )
    declared = list(contract.declared_selected_member_ids)
    kind_changes, kind_inventory = _population_observation_changes(
        contract,
        declared,
        ["f" * 64],
        selected_digest=population_member_digest(declared),
    )
    changes, inventory = _default_assessment_inputs(population_case)
    changes[contract.member_kind] = kind_changes
    inventory.update(kind_inventory)
    result = _assess(population_case, changes=changes, inventory=inventory)
    assert result.status == "drifted"
    assert "POPULATION_DIGEST_MISMATCH" in result.reason_codes


def test_profile_rejects_declared_members_not_produced_by_bound_rule(
    population_case: dict[str, Any],
) -> None:
    contracts = [
        contract.model_dump(mode="json")
        for contract in population_case["profile"].population_contracts
    ]
    source = next(item for item in contracts if item["member_kind"] == "source_file")
    test = next(item for item in contracts if item["member_kind"] == "test_case")
    source["member_kind"], test["member_kind"] = (
        test["member_kind"],
        source["member_kind"],
    )
    (
        source["declared_selected_member_ids"],
        test["declared_selected_member_ids"],
    ) = (
        list(test["declared_selected_member_ids"]),
        list(source["declared_selected_member_ids"]),
    )
    source["contract_id"] = population_contract_id(source)
    test["contract_id"] = population_contract_id(test)
    profile = _resigned_profile(population_case, contracts)
    with pytest.raises(ValueError, match="not produced"):
        validate_population_contracts(
            profile,
            population_case["manifest"],
            rule_outputs=_rule_outputs(population_case),
        )


def test_profile_requires_rule_output_witness(
    population_case: dict[str, Any],
) -> None:
    with pytest.raises(ValueError, match="rule outputs"):
        validate_population_contracts(
            population_case["profile"], population_case["manifest"]
        )


def test_profile_rejects_rule_outputs_outside_scope_members(
    population_case: dict[str, Any],
) -> None:
    outputs = _rule_outputs(population_case)
    rule_id = next(iter(outputs))
    outputs[rule_id] = [*outputs[rule_id], "f" * 64]
    with pytest.raises(ValueError, match="non-scope"):
        validate_population_contracts(
            population_case["profile"],
            population_case["manifest"],
            rule_outputs=outputs,
        )


def test_profile_rejects_incomplete_rule_output_witness(
    population_case: dict[str, Any],
) -> None:
    outputs = _rule_outputs(population_case)
    outputs.pop(next(iter(outputs)))
    with pytest.raises(ValueError, match="exactly"):
        validate_population_contracts(
            population_case["profile"],
            population_case["manifest"],
            rule_outputs=outputs,
        )


def test_population_assessment_without_rule_outputs_is_unavailable(
    population_case: dict[str, Any],
) -> None:
    result = assess_population_integrity(
        population_case["profile"],
        population_case["manifest"],
        population_case["results"],
    )
    assert result == PopulationAssessmentResult(
        "unavailable", ("POPULATION_EVIDENCE_MISSING",)
    )


def test_population_assessment_without_evidence_inventory_is_unavailable(
    population_case: dict[str, Any],
) -> None:
    result = assess_population_integrity(
        population_case["profile"],
        population_case["manifest"],
        population_case["results"],
        rule_outputs=_rule_outputs(population_case),
    )
    assert result == PopulationAssessmentResult(
        "unavailable", ("POPULATION_EVIDENCE_MISSING",)
    )


# ---------------------------------------------------------------------------
# Second-review fix tests: C1 (eligible under-reporting), F4 (selected zero),
# I1 (unparseable evidence), I3/I4/F8 (witness semantics coverage).
# ---------------------------------------------------------------------------

def _synthetic_member(
    manifest: EvaluationScopeManifest, kind: str, locator: str
) -> ScopeMember:
    return ScopeMember.model_validate(
        {
            "member_id": scope_member_id(kind, locator),
            "member_kind": kind,
            "locator": locator,
            "locator_digest": hashlib.sha256(locator.encode("utf-8")).hexdigest(),
            "content_digest": "c" * 64,
            "source_revision": manifest.source_revision,
        }
    )


def test_profile_rejects_selector_witness_drifting_from_signed_scope_partition(
    population_case: dict[str, Any],
) -> None:
    """First-adapter selector outputs are provable from the signed manifest."""
    base = population_case["manifest"]
    extra = _synthetic_member(base, "source_file", "src/extra.py")
    manifest = _signed_manifest(
        base,
        population_case["manager_key"],
        members=(*base.members, extra),
        selector_kinds=("git_diff_closure", "pytest_collection"),
    )
    profile = _signed_profile(
        population_case["base_profile"],
        manifest,
        population_case["manager_key"],
    )
    outputs = _rule_outputs({**population_case, "manifest": manifest})
    git_rule_id = manifest.selector_rules[0].rule_id
    outputs[git_rule_id] = [
        member_id
        for member_id in outputs[git_rule_id]
        if member_id != extra.member_id
    ]
    with pytest.raises(ValueError, match="kind partition"):
        validate_population_contracts(profile, manifest, rule_outputs=outputs)


def test_population_assessment_rejects_under_reported_eligible_population(
    population_case: dict[str, Any],
) -> None:
    """A verifier may not shrink eligible below the rule output to raise capture."""
    contract = next(
        item
        for item in population_case["profile"].population_contracts
        if item.member_kind == "test_case"
    )
    declared = list(contract.declared_selected_member_ids)
    kind_changes, kind_inventory = _population_observation_changes(
        contract, ["f" * 64], declared
    )
    changes, inventory = _default_assessment_inputs(population_case)
    changes[contract.member_kind] = kind_changes
    inventory.update(kind_inventory)
    result = _assess(population_case, changes=changes, inventory=inventory)
    assert result.status == "drifted"
    assert "POPULATION_DIGEST_MISMATCH" in result.reason_codes


def test_population_assessment_selected_zero_is_capture_failed_regardless_of_minimum(
    population_case: dict[str, Any],
) -> None:
    case = dict(population_case)
    case["profile"] = _signed_profile(
        case["base_profile"],
        case["manifest"],
        case["manager_key"],
        contract_changes={
            "test_case": {
                "minimum_selected_count": 0,
                "minimum_capture_numerator": 0,
                "minimum_capture_denominator": 1,
            }
        },
    )
    contract = next(
        item
        for item in case["profile"].population_contracts
        if item.member_kind == "test_case"
    )
    declared = list(contract.declared_selected_member_ids)
    kind_changes, kind_inventory = _population_observation_changes(
        contract,
        declared + [f"e{index:063x}" for index in range(399)],
        [],
    )
    changes, inventory = _default_assessment_inputs(case)
    changes[contract.member_kind] = kind_changes
    inventory.update(kind_inventory)
    result = _assess(case, changes=changes, inventory=inventory)
    assert result == PopulationAssessmentResult(
        "capture_failed", ("POPULATION_CAPTURE_FAILED",)
    )


def test_population_assessment_deeply_nested_evidence_is_unavailable(
    population_case: dict[str, Any],
) -> None:
    contract = next(
        item
        for item in population_case["profile"].population_contracts
        if item.member_kind == "test_case"
    )
    declared = list(contract.declared_selected_member_ids)
    nested = (
        b'{"schema_version":"openworkproof-population-evidence/0.5",'
        b'"purpose":"eligible-population","member_ids":'
        + b"[" * 50_000
        + b"0"
        + b"]" * 50_000
        + b"}"
    )
    eligible_ref, eligible_content = _population_evidence_ref(
        "eligible-population", declared, raw_content=nested
    )
    kind_changes, kind_inventory = _population_observation_changes(
        contract,
        declared,
        declared,
        eligible_ref=(eligible_ref, eligible_content),
    )
    changes, inventory = _default_assessment_inputs(population_case)
    changes[contract.member_kind] = kind_changes
    inventory.update(kind_inventory)
    result = _assess(population_case, changes=changes, inventory=inventory)
    assert result == PopulationAssessmentResult(
        "unavailable", ("POPULATION_EVIDENCE_MISSING",)
    )


def test_profile_rejects_declared_members_outside_replayed_rule_output(
    population_case: dict[str, Any],
) -> None:
    """The witness is a real replay output, not the kind-partitioned manifest."""
    base = population_case["manifest"]
    extra = _synthetic_member(base, "source_file", "src/extra.py")
    manifest = _signed_manifest(
        base,
        population_case["manager_key"],
        members=(*base.members, extra),
    )
    profile = _signed_profile(
        population_case["base_profile"],
        manifest,
        population_case["manager_key"],
    )
    outputs = _rule_outputs({**population_case, "manifest": manifest})
    source_rule_id = manifest.selector_rules[0].rule_id
    outputs[source_rule_id] = [
        member_id
        for member_id in outputs[source_rule_id]
        if member_id != extra.member_id
    ]
    with pytest.raises(ValueError, match="not produced"):
        validate_population_contracts(profile, manifest, rule_outputs=outputs)


def test_profile_rejects_duplicate_declaration_across_contracts(
    population_case: dict[str, Any],
) -> None:
    manifest = population_case["manifest"]
    source_member_id = next(
        member.member_id
        for member in manifest.members
        if member.member_kind == "source_file"
    )
    rules = [rule.model_dump(mode="json") for rule in manifest.selector_rules]
    contracts = [
        _contract(rules[0], [source_member_id], "source_file"),
        _contract(rules[1], [source_member_id], "source_file"),
    ]
    profile = _resigned_profile(population_case, contracts)
    witness = {
        rules[0]["rule_id"]: [source_member_id],
        rules[1]["rule_id"]: [source_member_id],
    }
    with pytest.raises(ValueError, match="multiple contracts"):
        validate_population_contracts(profile, manifest, rule_outputs=witness)


def test_population_assessment_rejects_incomplete_rule_outputs_as_invalid_input(
    population_case: dict[str, Any],
) -> None:
    outputs = _rule_outputs(population_case)
    outputs.pop(next(iter(outputs)))
    with pytest.raises(ValueError):
        assess_population_integrity(
            population_case["profile"],
            population_case["manifest"],
            population_case["results"],
            rule_outputs=outputs,
            evidence_inventory=_population_inventory(),
        )
