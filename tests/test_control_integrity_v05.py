from __future__ import annotations

import copy
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from openworkproof.integrity import (
    ControlAssessmentResult,
    assess_control_integrity,
    validate_control_contracts,
)
from openworkproof.models import (
    ControlContractV05,
    EvaluationScopeManifest,
    FailureSignatureV05,
    VerificationArmResultV03,
    VerificationArmResultV05,
    VerificationProfileV03,
    VerificationProfileV05,
    failure_signature_digest,
)
from openworkproof.signing import sign_payload

from test_population_integrity_v05 import (
    _EVIDENCE_CONTENT,
    _contract,
    _control_contract,
    _control_observation,
    _observation,
    _signed_manifest,
    _signed_profile,
)


def _signed_control_profile(
    base: VerificationProfileV03,
    manifest: EvaluationScopeManifest,
    manager_key: Ed25519PrivateKey,
    *,
    negative_arms: list[dict[str, Any]] | None = None,
    control_contracts: list[dict[str, Any]] | None = None,
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
    payload["population_contracts"] = [
        _contract(rule.model_dump(mode="json"), members_by_kind[kind], kind)
        for rule, kind in zip(
            manifest.selector_rules, ("source_file", "test_case"), strict=True
        )
    ]
    if negative_arms is not None:
        payload["negative_arms"] = copy.deepcopy(negative_arms)
    arms = payload["negative_arms"]
    if control_contracts is None:
        control_contracts = [
            _control_contract(arm["arm_id"], arm["mutant_patch_digest"])
            for arm in arms
        ]
    payload["control_contracts"] = sorted(
        control_contracts, key=lambda item: item["control_id"]
    )
    return VerificationProfileV05.model_validate(
        sign_payload("verification-profile", payload, manager_key, version="0.5")
    )


def _control_observation_payload(
    contract: ControlContractV05,
    *,
    control_status: str = "proven",
    fixture_digest: str | None = None,
    provocation_digest: str | None = None,
    signature: dict[str, Any] | None = None,
    execution_status: str = "completed",
    exit_codes: list[int] | None = None,
    evidence_refs: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    payload = _control_observation(contract)
    payload["control_status"] = control_status
    if fixture_digest is not None:
        payload["fixture_digest"] = fixture_digest
    if provocation_digest is not None:
        payload["provocation_digest"] = provocation_digest
    observed = (
        contract.expected_failure_signature.model_dump(mode="json")
        if signature is None
        else dict(signature)
    )
    if execution_status != "completed" or exit_codes is not None:
        observed["execution_status"] = execution_status
    if exit_codes is not None:
        observed["exit_codes"] = exit_codes
    payload["observed_failure_signature"] = observed
    payload["observed_failure_signature_digest"] = failure_signature_digest(observed)
    if evidence_refs is not None:
        payload["evidence_refs"] = evidence_refs
    return payload


def _signed_control_result(
    base_result: VerificationArmResultV03,
    profile: VerificationProfileV05,
    manifest: EvaluationScopeManifest,
    verifier_key: Ed25519PrivateKey,
    *,
    arm: Any,
    mutation_status: str = "applied",
    created_at: str = "2026-01-01T00:10:00Z",
    control_observation: dict[str, Any] | None = None,
) -> VerificationArmResultV05:
    payload = base_result.model_dump(
        mode="json",
        exclude={"digest", "signature_alg", "signer_key_id", "signature"},
    )
    arm_kind = arm.arm_kind
    payload.update(
        schema_version="openworkproof-verification-arm-result/0.5",
        profile_digest=profile.digest,
        arm_result_id=(
            "8" * 64
            if arm_kind == "positive"
            else ("9" * 64 if arm.arm_id == "2" * 64 else "b" * 64)
        ),
        arm_id=arm.arm_id,
        arm_kind=arm_kind,
        mutation_status=(
            "not_applicable" if arm_kind == "positive" else mutation_status
        ),
        scope_manifest_digest=manifest.digest,
        created_at=created_at,
    )
    if arm_kind == "negative":
        if mutation_status == "not_applied":
            payload["expectation_status"] = "indeterminate"
            payload["reason_codes"] = ["MUTATION_NOT_APPLIED"]
        else:
            payload["expectation_status"] = "satisfied"
            payload["reason_codes"] = ["MUTATION_APPLIED", "MUTATION_CAUGHT"]
    else:
        payload["expectation_status"] = "satisfied"
        payload["reason_codes"] = []
    payload["population_observations"] = [
        _observation(contract) for contract in profile.population_contracts
    ]
    payload["control_observation"] = control_observation
    return VerificationArmResultV05.model_validate(
        sign_payload("verification-arm-result", payload, verifier_key, version="0.5")
    )


@pytest.fixture
def control_case(
    evaluation_scope_v03: EvaluationScopeManifest,
    frozen_verification_profile_v03: VerificationProfileV03,
    frozen_verification_arm_result_v03: VerificationArmResultV03,
    frozen_role_keys_v05: dict[str, tuple[Ed25519PrivateKey, dict[str, str]]],
) -> dict[str, Any]:
    manager_key = frozen_role_keys_v05["Manager"][0]
    verifier_key = frozen_role_keys_v05["Verifier"][0]
    manifest = _signed_manifest(evaluation_scope_v03, manager_key)
    profile = _signed_profile(frozen_verification_profile_v03, manifest, manager_key)
    return {
        "base_profile": frozen_verification_profile_v03,
        "base_result": frozen_verification_arm_result_v03,
        "manager_key": manager_key,
        "verifier_key": verifier_key,
        "manifest": manifest,
        "profile": profile,
    }


def _negative_results(
    case: dict[str, Any],
    *,
    control_observation: dict[str, Any] | None = None,
    mutation_status: str = "applied",
    created_at: str = "2026-01-01T00:10:00Z",
) -> tuple[VerificationArmResultV05, ...]:
    arm = case["profile"].negative_arms[0]
    return (
        _signed_control_result(
            case["base_result"],
            case["profile"],
            case["manifest"],
            case["verifier_key"],
            arm=arm,
            mutation_status=mutation_status,
            created_at=created_at,
            control_observation=control_observation,
        ),
    )


def _assess_control(
    case: dict[str, Any],
    results: tuple[VerificationArmResultV05, ...],
    *,
    with_evidence: bool = False,
) -> ControlAssessmentResult:
    inventory = None
    if with_evidence:
        inventory = {}
        for result in results:
            observation = result.control_observation
            if observation is None:
                continue
            for ref in observation.evidence_refs:
                content = _EVIDENCE_CONTENT.get(ref.sha256)
                if content is None:
                    raise AssertionError("control evidence content is unavailable")
                inventory[ref.sha256] = content
    return assess_control_integrity(
        case["profile"], results, evidence_inventory=inventory
    )


def test_control_contracts_exactly_cover_negative_arms(
    control_case: dict[str, Any],
) -> None:
    assert validate_control_contracts(control_case["profile"]) is None


def test_profile_rejects_control_contract_for_positive_arm(
    control_case: dict[str, Any],
) -> None:
    arm = control_case["profile"].positive_arm
    contracts = [
        _control_contract(arm.arm_id, "5" * 64),
    ]
    with pytest.raises(ValueError):
        _signed_control_profile(
            control_case["base_profile"],
            control_case["manifest"],
            control_case["manager_key"],
            control_contracts=contracts,
        )


def test_profile_rejects_duplicate_control_contracts(
    control_case: dict[str, Any],
) -> None:
    arm = control_case["profile"].negative_arms[0]
    contract = _control_contract(arm.arm_id, arm.mutant_patch_digest)
    with pytest.raises(ValueError):
        _signed_control_profile(
            control_case["base_profile"],
            control_case["manifest"],
            control_case["manager_key"],
            control_contracts=[contract, contract],
        )


def test_profile_rejects_control_fixture_drift(
    control_case: dict[str, Any],
) -> None:
    arm = control_case["profile"].negative_arms[0]
    contracts = [_control_contract(arm.arm_id, "d" * 64)]
    with pytest.raises(ValueError):
        _signed_control_profile(
            control_case["base_profile"],
            control_case["manifest"],
            control_case["manager_key"],
            control_contracts=contracts,
        )


def test_profile_rejects_unknown_control_target(
    control_case: dict[str, Any],
) -> None:
    arm = control_case["profile"].negative_arms[0]
    contract = _control_contract(arm.arm_id, arm.mutant_patch_digest)
    contract["control_target"] = "dependency_health"
    with pytest.raises(ValidationError):
        _signed_control_profile(
            control_case["base_profile"],
            control_case["manifest"],
            control_case["manager_key"],
            control_contracts=[contract],
        )


def test_profile_rejects_inverted_control_window(
    control_case: dict[str, Any],
) -> None:
    arm = control_case["profile"].negative_arms[0]
    contract = _control_contract(arm.arm_id, arm.mutant_patch_digest)
    contract["valid_from"] = "2026-01-01T01:00:00Z"
    contract["expires_at"] = "2026-01-01T00:00:00Z"
    with pytest.raises(ValidationError):
        _signed_control_profile(
            control_case["base_profile"],
            control_case["manifest"],
            control_case["manager_key"],
            control_contracts=[contract],
        )


def test_profile_rejects_bad_expected_signature_digest(
    control_case: dict[str, Any],
) -> None:
    arm = control_case["profile"].negative_arms[0]
    contract = _control_contract(arm.arm_id, arm.mutant_patch_digest)
    contract["expected_failure_signature_digest"] = "f" * 64
    with pytest.raises(ValidationError):
        _signed_control_profile(
            control_case["base_profile"],
            control_case["manifest"],
            control_case["manager_key"],
            control_contracts=[contract],
        )


def test_control_observation_proven(control_case: dict[str, Any]) -> None:
    contract = control_case["profile"].control_contracts[0]
    results = _negative_results(
        control_case,
        control_observation=_control_observation_payload(contract),
    )
    assert _assess_control(
        control_case, results, with_evidence=True
    ) == ControlAssessmentResult("proven", ())


def test_control_observation_survived(control_case: dict[str, Any]) -> None:
    contract = control_case["profile"].control_contracts[0]
    results = _negative_results(
        control_case,
        control_observation=_control_observation_payload(
            contract,
            control_status="survived",
            exit_codes=[0],
            signature={
                **contract.expected_failure_signature.model_dump(mode="json"),
                "reason_codes": ["SCOPE_SELECTOR_MISMATCH"],
            },
        ),
    )
    assert _assess_control(control_case, results) == ControlAssessmentResult(
        "survived", ("CONTROL_SURVIVED",)
    )


def test_control_observation_mismatched_failure_signature(
    control_case: dict[str, Any],
) -> None:
    contract = control_case["profile"].control_contracts[0]
    results = _negative_results(
        control_case,
        control_observation=_control_observation_payload(
            contract,
            control_status="mismatched",
            signature={
                **contract.expected_failure_signature.model_dump(mode="json"),
                "reason_codes": ["EXEC_DEPENDENCY_DRIFT"],
            },
        ),
    )
    assert _assess_control(control_case, results) == ControlAssessmentResult(
        "mismatched", ("CONTROL_FAILURE_SIGNATURE_MISMATCH",)
    )


def test_control_observation_unavailable_when_fixture_not_applied(
    control_case: dict[str, Any],
) -> None:
    contract = control_case["profile"].control_contracts[0]
    results = _negative_results(
        control_case,
        mutation_status="not_applied",
        control_observation=_control_observation_payload(
            contract, control_status="unavailable"
        ),
    )
    assert _assess_control(control_case, results) == ControlAssessmentResult(
        "unavailable", ("CONTROL_EVIDENCE_MISSING",)
    )


def test_control_observation_unavailable_when_execution_incomplete(
    control_case: dict[str, Any],
) -> None:
    contract = control_case["profile"].control_contracts[0]
    results = _negative_results(
        control_case,
        control_observation=_control_observation_payload(
            contract,
            control_status="unavailable",
            execution_status="timed_out",
        ),
    )
    assert _assess_control(control_case, results) == ControlAssessmentResult(
        "unavailable", ("CONTROL_EVIDENCE_MISSING",)
    )


def test_control_observation_unavailable_when_contract_expired(
    control_case: dict[str, Any],
) -> None:
    contract = control_case["profile"].control_contracts[0]
    results = _negative_results(
        control_case,
        created_at="2026-01-01T02:00:00Z",
        control_observation=_control_observation_payload(
            contract, control_status="unavailable"
        ),
    )
    assert _assess_control(control_case, results) == ControlAssessmentResult(
        "unavailable", ("CONTROL_CONTRACT_EXPIRED",)
    )


def test_control_observation_fixture_drift_is_mismatched(
    control_case: dict[str, Any],
) -> None:
    contract = control_case["profile"].control_contracts[0]
    results = _negative_results(
        control_case,
        control_observation=_control_observation_payload(
            contract,
            control_status="mismatched",
            fixture_digest="d" * 64,
        ),
    )
    assert _assess_control(control_case, results) == ControlAssessmentResult(
        "mismatched", ("CONTROL_FIXTURE_DRIFT",)
    )


def test_control_observation_provocation_drift_is_mismatched(
    control_case: dict[str, Any],
) -> None:
    contract = control_case["profile"].control_contracts[0]
    results = _negative_results(
        control_case,
        control_observation=_control_observation_payload(
            contract,
            control_status="mismatched",
            provocation_digest="d" * 64,
        ),
    )
    assert _assess_control(control_case, results) == ControlAssessmentResult(
        "mismatched", ("CONTROL_PROVOCATION_DRIFT",)
    )


def test_control_observation_rejects_wrong_claimed_status(
    control_case: dict[str, Any],
) -> None:
    contract = control_case["profile"].control_contracts[0]
    results = _negative_results(
        control_case,
        control_observation=_control_observation_payload(
            contract,
            control_status="proven",
            fixture_digest="d" * 64,
        ),
    )
    with pytest.raises(ValueError, match="derives"):
        _assess_control(control_case, results)


def test_dependency_failure_cannot_be_proven(control_case: dict[str, Any]) -> None:
    contract = control_case["profile"].control_contracts[0]
    results = _negative_results(
        control_case,
        control_observation=_control_observation_payload(
            contract,
            control_status="proven",
            signature={
                **contract.expected_failure_signature.model_dump(mode="json"),
                "reason_codes": ["EXEC_DEPENDENCY_DRIFT"],
            },
        ),
    )
    with pytest.raises(ValueError, match="derives"):
        _assess_control(control_case, results)


def test_control_assessment_requires_every_negative_arm(
    control_case: dict[str, Any],
) -> None:
    assert _assess_control(control_case, ()) == ControlAssessmentResult(
        "unavailable", ("CONTROL_EVIDENCE_MISSING",)
    )


def test_control_assessment_aggregates_multiple_arms(
    control_case: dict[str, Any],
) -> None:
    extra_arm = {
        **control_case["profile"].negative_arms[0].model_dump(mode="json"),
        "arm_id": "a" * 64,
        "mutant_patch_digest": "c" * 64,
    }
    profile = _signed_control_profile(
        control_case["base_profile"],
        control_case["manifest"],
        control_case["manager_key"],
        negative_arms=[
            control_case["profile"].negative_arms[0].model_dump(mode="json"),
            extra_arm,
        ],
    )
    case = {**control_case, "profile": profile}
    first = next(
        c
        for c in profile.control_contracts
        if c.arm_id == profile.negative_arms[0].arm_id
    )
    second = next(c for c in profile.control_contracts if c.arm_id == "a" * 64)
    proven = _signed_control_result(
        case["base_result"],
        profile,
        case["manifest"],
        case["verifier_key"],
        arm=profile.negative_arms[0],
        control_observation=_control_observation_payload(first),
    )
    survived = _signed_control_result(
        case["base_result"],
        profile,
        case["manifest"],
        case["verifier_key"],
        arm=profile.negative_arms[1],
        control_observation=_control_observation_payload(
            second,
            control_status="survived",
            exit_codes=[0],
            signature={
                **second.expected_failure_signature.model_dump(mode="json"),
                "reason_codes": ["SCOPE_SELECTOR_MISMATCH"],
            },
        ),
    )
    assert _assess_control(case, (proven, survived)) == ControlAssessmentResult(
        "survived", ("CONTROL_SURVIVED",)
    )
    both_proven = _signed_control_result(
        case["base_result"],
        profile,
        case["manifest"],
        case["verifier_key"],
        arm=profile.negative_arms[1],
        control_observation=_control_observation_payload(second),
    )
    assert _assess_control(
        case, (proven, both_proven), with_evidence=True
    ) == ControlAssessmentResult("proven", ())


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("execution_status", "crashed"),
        ("exit_codes", [2]),
        ("reason_codes", ["EXEC_DEPENDENCY_DRIFT"]),
        ("predicate_ids", ["other_predicate"]),
        ("required_evidence_purposes", ["other-purpose"]),
    ),
)
def test_failure_signature_digest_is_sensitive_to_structured_fields(
    field: str, value: Any
) -> None:
    base_fields = {
        "execution_status": "completed",
        "exit_codes": [1],
        "reason_codes": ["MUTATION_CAUGHT"],
        "predicate_ids": ["tests_passed"],
        "required_evidence_purposes": ["test-result"],
    }
    first = FailureSignatureV05.model_validate(base_fields)
    changed = FailureSignatureV05.model_validate({**base_fields, field: value})
    assert changed != first
    assert failure_signature_digest(changed) != failure_signature_digest(first)


def test_control_observation_exit_zero_with_caught_reason_is_mismatched(
    control_case: dict[str, Any],
) -> None:
    """A signature claiming MUTATION_CAUGHT while exiting zero is a failure
    with a mismatched signature, never a silent survived."""
    contract = control_case["profile"].control_contracts[0]
    results = _negative_results(
        control_case,
        control_observation=_control_observation_payload(
            contract,
            control_status="mismatched",
            exit_codes=[0],
            signature={
                **contract.expected_failure_signature.model_dump(mode="json"),
                "exit_codes": [0],
            },
        ),
    )
    assert _assess_control(control_case, results) == ControlAssessmentResult(
        "mismatched", ("CONTROL_FAILURE_SIGNATURE_MISMATCH",)
    )


def test_control_observation_survived_with_survived_reason(
    control_case: dict[str, Any],
) -> None:
    contract = control_case["profile"].control_contracts[0]
    results = _negative_results(
        control_case,
        control_observation=_control_observation_payload(
            contract,
            control_status="survived",
            exit_codes=[0],
            signature={
                **contract.expected_failure_signature.model_dump(mode="json"),
                "exit_codes": [0],
                "reason_codes": ["MUTATION_SURVIVED"],
            },
        ),
    )
    assert _assess_control(control_case, results) == ControlAssessmentResult(
        "survived", ("CONTROL_SURVIVED",)
    )


def test_failure_signature_ignores_platform_noise() -> None:
    # stderr, absolute paths, hostnames, durations, and temp directories have
    # no channel into the signed structure; identical structured fields must
    # produce identical signatures and digests regardless of such noise.
    structured_fields = {
        "execution_status": "completed",
        "exit_codes": [1],
        "reason_codes": ["MUTATION_CAUGHT"],
        "predicate_ids": ["tests_passed"],
        "required_evidence_purposes": ["test-result"],
    }
    first = FailureSignatureV05.model_validate(structured_fields)
    second = FailureSignatureV05.model_validate(dict(structured_fields))
    assert first == second
    assert failure_signature_digest(first) == failure_signature_digest(second)
    for noise_field, noise_value in (
        ("stderr", "raw log bytes"),
        ("absolute_path", "/tmp/whatever"),
        ("hostname", "runner-01"),
        ("duration_seconds", 12.5),
        ("temp_directory", "/tmp/owp-xyz"),
    ):
        with pytest.raises(ValidationError):
            FailureSignatureV05.model_validate(
                {**structured_fields, noise_field: noise_value}
            )
