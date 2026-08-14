"""Pure verification-integrity derivation for v0.5 population evidence."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

from openworkproof.models import (
    EvaluationScopeManifest,
    VerificationArmResultV05,
    VerificationIntegrityReasonCode,
    VerificationProfileV05,
    population_member_digest,
)


PopulationAssessmentStatus = Literal[
    "matched", "empty", "capture_failed", "drifted", "unavailable"
]


@dataclass(frozen=True, slots=True)
class PopulationAssessmentResult:
    status: PopulationAssessmentStatus
    reason_codes: tuple[VerificationIntegrityReasonCode, ...]


def _validated_profile(profile: VerificationProfileV05) -> VerificationProfileV05:
    if type(profile) is not VerificationProfileV05:
        raise ValueError("profile must be an exact VerificationProfileV05")
    return VerificationProfileV05.model_validate(profile.model_dump(mode="json"))


def _validated_manifest(manifest: EvaluationScopeManifest) -> EvaluationScopeManifest:
    if type(manifest) is not EvaluationScopeManifest:
        raise ValueError("manifest must be an exact EvaluationScopeManifest")
    return EvaluationScopeManifest.model_validate(manifest.model_dump(mode="json"))


def _rule_member_kind(selector_kind: str, declared_kind: str) -> str:
    if selector_kind == "git_diff_closure":
        return "source_file"
    if selector_kind == "pytest_collection":
        return "test_case"
    if selector_kind == "explicit":
        return declared_kind
    raise ValueError("unsupported selector kind")


def validate_population_contracts(
    profile: VerificationProfileV05,
    manifest: EvaluationScopeManifest,
) -> None:
    """Reject a signed profile whose population contracts do not match Scope."""

    profile = _validated_profile(profile)
    manifest = _validated_manifest(manifest)
    if (
        profile.evaluation_scope_id != manifest.scope_id
        or profile.evaluation_scope_digest != manifest.digest
    ):
        raise ValueError("profile does not bind the supplied evaluation scope")

    rules_by_id = {rule.rule_id: rule for rule in manifest.selector_rules}
    if len(rules_by_id) != len(manifest.selector_rules):
        raise ValueError("selector rule identifiers must be unique")
    contracts_by_rule = {
        contract.selector_rule_id: contract
        for contract in profile.population_contracts
    }
    if (
        len(contracts_by_rule) != len(profile.population_contracts)
        or set(contracts_by_rule) != set(rules_by_id)
    ):
        raise ValueError("population contracts must map one-to-one to selector rules")

    members_by_id = {member.member_id: member for member in manifest.members}
    scoped_population_ids = {
        member.member_id
        for member in manifest.members
        if member.member_kind in {"source_file", "test_case"}
    }
    declared_owner: dict[str, str] = {}
    for rule_id, rule in rules_by_id.items():
        contract = contracts_by_rule[rule_id]
        if (
            contract.selector_spec_digest != rule.selector_spec_digest
            or contract.selector_engine_digest != rule.selector_engine_digest
        ):
            raise ValueError("population contract selector digests do not match scope")
        if (
            _rule_member_kind(rule.selector_kind, contract.member_kind)
            != contract.member_kind
        ):
            raise ValueError("population contract member kind does not match selector")
        if not contract.declared_selected_member_ids:
            raise ValueError("population contract declaration cannot be empty")
        if len(contract.declared_selected_member_ids) > 4096:
            raise ValueError("population contract declaration exceeds 4096 members")

        rule_output_ids = {
            member.member_id
            for member in manifest.members
            if member.member_kind == contract.member_kind
        }
        for member_id in contract.declared_selected_member_ids:
            member = members_by_id.get(member_id)
            if member is None or member_id not in rule_output_ids:
                raise ValueError(
                    "population contract declares an orphan selector member"
                )
            if member.member_kind != contract.member_kind:
                raise ValueError(
                    "population contract member kind does not match member"
                )
            if member.member_kind == "delivery_artifact":
                raise ValueError("delivery artifacts cannot be population members")
            if member_id in declared_owner:
                raise ValueError("population member is declared by multiple contracts")
            declared_owner[member_id] = contract.contract_id

    if set(declared_owner) != scoped_population_ids:
        raise ValueError(
            "population contracts do not exactly cover scope source/test members"
        )


def _validated_results(
    results: Sequence[VerificationArmResultV05],
) -> tuple[VerificationArmResultV05, ...]:
    if type(results) not in {list, tuple}:
        raise ValueError("results must use an exact built-in list or tuple")
    if len(results) > 4096:
        raise ValueError("results exceed 4096 items")
    validated: list[VerificationArmResultV05] = []
    for result in results:
        if type(result) is not VerificationArmResultV05:
            raise ValueError("result must be an exact VerificationArmResultV05")
        validated.append(
            VerificationArmResultV05.model_validate(result.model_dump(mode="json"))
        )
    return tuple(validated)


def assess_population_integrity(
    profile: VerificationProfileV05,
    manifest: EvaluationScopeManifest,
    results: Sequence[VerificationArmResultV05],
) -> PopulationAssessmentResult:
    """Derive one deterministic population status from signed v0.5 inputs."""

    validate_population_contracts(profile, manifest)
    profile = _validated_profile(profile)
    manifest = _validated_manifest(manifest)
    validated_results = _validated_results(results)

    contracts_by_id = {
        contract.contract_id: contract for contract in profile.population_contracts
    }
    expected_arm_ids = {
        profile.positive_arm.arm_id,
        *(arm.arm_id for arm in profile.negative_arms),
    }
    result_arm_ids = [result.arm_id for result in validated_results]
    cross_arm_mismatch = (
        len(result_arm_ids) != len(set(result_arm_ids))
        or set(result_arm_ids) != expected_arm_ids
    )

    evidence_missing = False
    drift_reasons: set[VerificationIntegrityReasonCode] = set()
    capture_failed = False
    observations_by_contract: dict[str, list[tuple[int, str, int, str]]] = {
        contract_id: [] for contract_id in contracts_by_id
    }
    all_empty = bool(validated_results)

    for result in validated_results:
        if (
            result.profile_digest != profile.digest
            or result.scope_manifest_digest != manifest.digest
        ):
            cross_arm_mismatch = True
        observation_ids = [
            observation.contract_id for observation in result.population_observations
        ]
        if (
            len(observation_ids) != len(set(observation_ids))
            or set(observation_ids) != set(contracts_by_id)
        ):
            cross_arm_mismatch = True

        for observation in result.population_observations:
            contract = contracts_by_id.get(observation.contract_id)
            if contract is None:
                continue
            if (
                observation.selector_rule_id != contract.selector_rule_id
                or observation.selector_spec_digest != contract.selector_spec_digest
            ):
                drift_reasons.add("POPULATION_RULE_DRIFT")
            if observation.selector_engine_digest != contract.selector_engine_digest:
                drift_reasons.add("POPULATION_ENGINE_DRIFT")

            evidence_paths = {reference.path for reference in observation.evidence_refs}
            if not set(contract.required_population_evidence_purposes).issubset(
                evidence_paths
            ):
                evidence_missing = True

            selected_ids = contract.declared_selected_member_ids
            selected_digest_mismatch = (
                observation.selected_population_digest
                != population_member_digest(())
                if observation.selected_count == 0
                else observation.selected_count != len(selected_ids)
                or observation.selected_population_digest
                != population_member_digest(selected_ids)
            )
            if selected_digest_mismatch:
                drift_reasons.add("POPULATION_DIGEST_MISMATCH")

            observations_by_contract[contract.contract_id].append(
                (
                    observation.eligible_seen,
                    observation.eligible_population_digest,
                    observation.selected_count,
                    observation.selected_population_digest,
                )
            )
            all_empty = all_empty and (
                observation.eligible_seen == 0 and observation.selected_count == 0
            )
            below_capture = (
                observation.capture_numerator
                * contract.minimum_capture_denominator
                < contract.minimum_capture_numerator
                * observation.capture_denominator
            )
            if observation.eligible_seen > 0 and (
                observation.eligible_seen < contract.minimum_eligible_count
                or observation.eligible_seen > contract.maximum_eligible_count
                or observation.selected_count < contract.minimum_selected_count
                or observation.selected_count > contract.maximum_selected_count
                or below_capture
            ):
                capture_failed = True

    for observed in observations_by_contract.values():
        if len(observed) != len(validated_results) or len(set(observed)) > 1:
            cross_arm_mismatch = True
    if cross_arm_mismatch:
        drift_reasons.add("POPULATION_CROSS_ARM_MISMATCH")

    if evidence_missing:
        return PopulationAssessmentResult(
            "unavailable", ("POPULATION_EVIDENCE_MISSING",)
        )
    if drift_reasons:
        return PopulationAssessmentResult(
            "drifted", tuple(sorted(drift_reasons))
        )
    if all_empty:
        return PopulationAssessmentResult(
            "empty", ("NO_ELIGIBLE_POPULATION",)
        )
    if capture_failed:
        return PopulationAssessmentResult(
            "capture_failed", ("POPULATION_CAPTURE_FAILED",)
        )
    return PopulationAssessmentResult("matched", ())


__all__ = [
    "PopulationAssessmentResult",
    "assess_population_integrity",
    "validate_population_contracts",
]
