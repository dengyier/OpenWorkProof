"""Pure verification-integrity derivation for v0.5 population evidence.

This module derives one deterministic population status from signed v0.5
inputs. Two external inputs are required to make the derivation sound:

- ``rule_outputs``: the authoritative output member set of every v0.3
  selector rule, produced by replaying the signed selector spec and engine
  digests against the frozen Git revision. Declared selected members must
  be a subset of their bound rule's output, and the eligible evidence must
  contain the bound rule's output (a verifier cannot shrink the eligible
  population to inflate the capture rate). For the first-adapter selector
  kinds (``git_diff_closure`` / ``pytest_collection``) the output is
  provable from the signed manifest itself and must equal the signed scope
  kind partition, so caller metadata cannot drift it; for ``explicit``
  rules the caller supplies the replayed output and the adapter layer must
  bind it to the signed selector engine digest. Missing outputs make the
  assessment ``unavailable``.
- ``evidence_inventory``: an authoritative artifact inventory that maps
  SHA-256 digests to evidence bytes. Every ``EvidenceRefV05`` inside a
  population observation must replay exactly (content digest and byte size)
  and must carry a canonical population-evidence document whose declared
  ``purpose`` satisfies the contract's required evidence purposes. The
  evidence document's member list is the authoritative population from
  which the eligible and selected counts and digests are recomputed.
  ``EvidenceRefV05.path`` is a locator only and never satisfies a purpose.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import hashlib
import json
import re
from typing import Literal

from openworkproof.models import (
    ControlContractV05,
    EvaluationScopeManifest,
    EvidenceRefV05,
    VerificationArmResultV05,
    VerificationIntegrityReasonCode,
    VerificationProfileV05,
    population_member_digest,
)


PopulationAssessmentStatus = Literal[
    "matched", "empty", "capture_failed", "drifted", "unavailable"
]
ControlAssessmentStatus = Literal["proven", "survived", "mismatched", "unavailable"]

POPULATION_EVIDENCE_SCHEMA_VERSION = "openworkproof-population-evidence/0.5"
_MEMBER_ID_PATTERN = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True, slots=True)
class PopulationAssessmentResult:
    status: PopulationAssessmentStatus
    reason_codes: tuple[VerificationIntegrityReasonCode, ...]


@dataclass(frozen=True, slots=True)
class ControlAssessmentResult:
    status: ControlAssessmentStatus
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


def _validated_rule_outputs(
    rule_outputs: Mapping[str, Sequence[str]],
    rules_by_id: dict[str, object],
) -> dict[str, tuple[str, ...]]:
    if not isinstance(rule_outputs, Mapping):
        raise ValueError("rule outputs must be a mapping")
    if set(rule_outputs) != set(rules_by_id):
        raise ValueError("rule outputs must cover exactly the selector rules")
    validated: dict[str, tuple[str, ...]] = {}
    for rule_id, outputs in rule_outputs.items():
        if type(outputs) not in {list, tuple}:
            raise ValueError("rule outputs must use exact built-in list or tuple")
        if len(outputs) > 4096:
            raise ValueError("rule outputs exceed 4096 members")
        member_ids: list[str] = []
        for value in outputs:
            if type(value) is not str or _MEMBER_ID_PATTERN.fullmatch(value) is None:
                raise ValueError("rule outputs must be 64-hex member identifiers")
            member_ids.append(value)
        if len(member_ids) != len(set(member_ids)):
            raise ValueError("rule outputs must be unique")
        validated[rule_id] = tuple(sorted(member_ids))
    return validated


def validate_population_contracts(
    profile: VerificationProfileV05,
    manifest: EvaluationScopeManifest,
    *,
    rule_outputs: Mapping[str, Sequence[str]] | None = None,
) -> None:
    """Reject a signed profile whose population contracts do not match Scope.

    ``rule_outputs`` is the authoritative output member set per selector
    rule, replayed from the signed selector spec and engine digests. Every
    declared selected member must be a member of its bound rule's output;
    relying on the Scope manifest population alone is not sufficient. For
    the first-adapter selector kinds (``git_diff_closure`` /
    ``pytest_collection``) the output must equal the signed scope kind
    partition exactly, so caller-supplied outputs cannot drift from signed
    data.
    """

    profile = _validated_profile(profile)
    manifest = _validated_manifest(manifest)
    if rule_outputs is None:
        raise ValueError(
            "rule outputs are required to validate the declared selected members"
        )
    if (
        profile.evaluation_scope_id != manifest.scope_id
        or profile.evaluation_scope_digest != manifest.digest
    ):
        raise ValueError("profile does not bind the supplied evaluation scope")

    rules_by_id = {rule.rule_id: rule for rule in manifest.selector_rules}
    if len(rules_by_id) != len(manifest.selector_rules):
        raise ValueError("selector rule identifiers must be unique")
    validated_outputs = _validated_rule_outputs(rule_outputs, rules_by_id)
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

        output_ids = set(validated_outputs[rule_id])
        if rule.selector_kind in {"git_diff_closure", "pytest_collection"}:
            kind_partition = tuple(
                sorted(
                    member.member_id
                    for member in manifest.members
                    if member.member_kind == contract.member_kind
                )
            )
            if tuple(sorted(output_ids)) != kind_partition:
                raise ValueError(
                    "selector rule outputs must equal the signed scope kind partition"
                )
        for member_id in contract.declared_selected_member_ids:
            member = members_by_id.get(member_id)
            if member is None:
                raise ValueError(
                    "population contract declares an orphan selector member"
                )
            if member.member_kind != contract.member_kind:
                raise ValueError(
                    "population contract member kind does not match member"
                )
            if member_id not in output_ids:
                raise ValueError(
                    "population contract declares a member "
                    "not produced by the bound selector rule"
                )
            if member_id in declared_owner:
                raise ValueError("population member is declared by multiple contracts")
            declared_owner[member_id] = contract.contract_id
        for member_id in output_ids:
            member = members_by_id.get(member_id)
            if member is None:
                raise ValueError("rule outputs reference a non-scope member")
            if member.member_kind != contract.member_kind:
                raise ValueError(
                    "rule output member kind does not match the contract"
                )

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


def _parse_population_evidence(
    content: bytes,
) -> tuple[str, tuple[str, ...]]:
    """Parse one canonical population-evidence document.

    Returns ``(purpose, member_ids)``; raises ``ValueError`` when the
    document is not replayable as closed v0.5 population evidence.
    """

    try:
        document = json.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError) as error:
        raise ValueError("population evidence is not valid JSON") from error
    if not isinstance(document, dict) or set(document) != {
        "schema_version",
        "purpose",
        "member_ids",
    }:
        raise ValueError("population evidence document must have a closed schema")
    if document["schema_version"] != POPULATION_EVIDENCE_SCHEMA_VERSION:
        raise ValueError("population evidence schema version is not 0.5")
    purpose = document["purpose"]
    if type(purpose) is not str or not purpose or len(purpose) > 128:
        raise ValueError("population evidence purpose must be a bounded string")
    member_ids = document["member_ids"]
    if type(member_ids) is not list or len(member_ids) > 4096:
        raise ValueError("population evidence member ids must be a bounded array")
    validated: list[str] = []
    for value in member_ids:
        if type(value) is not str or _MEMBER_ID_PATTERN.fullmatch(value) is None:
            raise ValueError(
                "population evidence member ids must be 64-hex identifiers"
            )
        validated.append(value)
    if validated != sorted(validated) or len(validated) != len(set(validated)):
        raise ValueError("population evidence member ids must be sorted and unique")
    return purpose, tuple(validated)


def _resolve_population_evidence(
    refs: Sequence[EvidenceRefV05],
    inventory: Mapping[str, bytes],
) -> dict[str, tuple[str, ...]]:
    """Replay every evidence ref and return the declared purpose bindings.

    Each ref must resolve through the authoritative artifact inventory, its
    content must replay the signed SHA-256 and byte size, and its document
    must declare a purpose. Paths never satisfy a purpose.
    """

    purposes: dict[str, tuple[str, ...]] = {}
    for ref in refs:
        content = inventory.get(ref.sha256)
        if content is None:
            raise ValueError("population evidence content is unavailable")
        if type(content) is not bytes:
            raise ValueError("population evidence content must be bytes")
        if len(content) != ref.size_bytes:
            raise ValueError(
                "population evidence size does not replay the signed reference"
            )
        if hashlib.sha256(content).hexdigest() != ref.sha256:
            raise ValueError(
                "population evidence content does not replay the signed reference"
            )
        purpose, member_ids = _parse_population_evidence(content)
        if purpose in purposes:
            raise ValueError("population evidence repeats a purpose")
        purposes[purpose] = member_ids
    return purposes


def assess_population_integrity(
    profile: VerificationProfileV05,
    manifest: EvaluationScopeManifest,
    results: Sequence[VerificationArmResultV05],
    *,
    rule_outputs: Mapping[str, Sequence[str]] | None = None,
    evidence_inventory: Mapping[str, bytes] | None = None,
) -> PopulationAssessmentResult:
    """Derive one deterministic population status from signed v0.5 inputs.

    Closed precedence: missing or unreplayable evidence -> ``unavailable``;
    rule/engine/digest/cross-arm mismatch -> ``drifted``; any contract with
    an empty population -> ``empty``; below count/capture thresholds or a
    zero selected population with a non-empty eligible population ->
    ``capture_failed``; otherwise ``matched``. Each contract's
    ``empty_population_policy=unknown`` takes effect independently: an
    empty eligible population is ``empty`` (never ``matched`` and never a
    collection failure) even when the bound rule output is non-empty, and
    a non-empty eligible population must contain the bound rule's output
    so a verifier cannot inflate the capture rate by shrinking it.
    """

    profile = _validated_profile(profile)
    manifest = _validated_manifest(manifest)
    if rule_outputs is None:
        return PopulationAssessmentResult(
            "unavailable", ("POPULATION_EVIDENCE_MISSING",)
        )
    validate_population_contracts(profile, manifest, rule_outputs=rule_outputs)
    validated_results = _validated_results(results)
    if not isinstance(evidence_inventory, Mapping):
        return PopulationAssessmentResult(
            "unavailable", ("POPULATION_EVIDENCE_MISSING",)
        )

    rules_by_id = {rule.rule_id: rule for rule in manifest.selector_rules}
    outputs_by_rule = _validated_rule_outputs(rule_outputs, rules_by_id)
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
    any_empty = False
    observations_by_contract: dict[str, list[tuple[int, str, int, str]]] = {
        contract_id: [] for contract_id in contracts_by_id
    }

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

            try:
                evidence_purposes = _resolve_population_evidence(
                    observation.evidence_refs, evidence_inventory
                )
            except ValueError:
                evidence_missing = True
                continue
            if not set(contract.required_population_evidence_purposes).issubset(
                evidence_purposes
            ):
                evidence_missing = True
                continue

            eligible_ids = evidence_purposes.get("eligible-population", ())
            selected_ids = evidence_purposes.get("selected-population", ())
            if (
                len(eligible_ids) != observation.eligible_seen
                or population_member_digest(eligible_ids)
                != observation.eligible_population_digest
            ):
                drift_reasons.add("POPULATION_DIGEST_MISMATCH")
            expected_eligible = outputs_by_rule.get(
                observation.selector_rule_id, ()
            )
            if eligible_ids and not set(expected_eligible).issubset(
                eligible_ids
            ):
                drift_reasons.add("POPULATION_DIGEST_MISMATCH")
            if observation.selected_count == 0:
                if (
                    selected_ids
                    or observation.selected_population_digest
                    != population_member_digest(())
                ):
                    drift_reasons.add("POPULATION_DIGEST_MISMATCH")
            else:
                if (
                    selected_ids != tuple(contract.declared_selected_member_ids)
                    or len(selected_ids) != observation.selected_count
                    or population_member_digest(selected_ids)
                    != observation.selected_population_digest
                ):
                    drift_reasons.add("POPULATION_DIGEST_MISMATCH")

            observations_by_contract[contract.contract_id].append(
                (
                    observation.eligible_seen,
                    observation.eligible_population_digest,
                    observation.selected_count,
                    observation.selected_population_digest,
                )
            )
            if observation.eligible_seen == 0:
                any_empty = True
            below_capture = (
                observation.capture_numerator
                * contract.minimum_capture_denominator
                < contract.minimum_capture_numerator
                * observation.capture_denominator
            )
            if observation.eligible_seen > 0 and (
                observation.eligible_seen < contract.minimum_eligible_count
                or observation.eligible_seen > contract.maximum_eligible_count
                or observation.selected_count == 0
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
    if any_empty:
        return PopulationAssessmentResult(
            "empty", ("NO_ELIGIBLE_POPULATION",)
        )
    if capture_failed:
        return PopulationAssessmentResult(
            "capture_failed", ("POPULATION_CAPTURE_FAILED",)
        )
    return PopulationAssessmentResult("matched", ())


# ---------------------------------------------------------------------------
# v0.5 control integrity: negative controls proved by exact failure signature.
# ---------------------------------------------------------------------------

_CONTROL_MISMATCH_CODES = frozenset(
    {
        "CONTROL_FIXTURE_DRIFT",
        "CONTROL_PROVOCATION_DRIFT",
        "CONTROL_FAILURE_SIGNATURE_MISMATCH",
    }
)
_CONTROL_UNAVAILABLE_CODES = frozenset(
    {
        "CONTROL_CONTRACT_EXPIRED",
        "CONTROL_EVIDENCE_MISSING",
    }
)


def validate_control_contracts(profile: VerificationProfileV05) -> None:
    """Reject a signed profile whose control contracts do not match its arms.

    Every negative arm must have exactly one control contract, the positive
    arm must have none, and each contract's fixture digest must equal its
    arm's mutant patch digest. Windows, closed control targets, and
    recomputed digests are enforced by the closed v0.5 models.
    """

    profile = _validated_profile(profile)
    contracts_by_arm = {
        contract.arm_id: contract for contract in profile.control_contracts
    }
    if len(contracts_by_arm) != len(profile.control_contracts):
        raise ValueError("control contracts must be unique per negative arm")
    negative_by_id = {arm.arm_id: arm for arm in profile.negative_arms}
    if set(contracts_by_arm) != set(negative_by_id):
        raise ValueError("every negative arm requires exactly one control contract")
    for arm_id, contract in contracts_by_arm.items():
        if contract.fixture_digest != negative_by_id[arm_id].mutant_patch_digest:
            raise ValueError(
                "control fixture_digest must equal arm mutant_patch_digest"
            )


def _derived_control_status(
    contract: ControlContractV05,
    result: VerificationArmResultV05,
) -> tuple[ControlAssessmentStatus, VerificationIntegrityReasonCode | None]:
    """Derive one observation's closed control status from its content.

    The design's closed truth table: expired / unapplied fixture / incomplete
    execution / missing evidence -> ``unavailable``; fixture or provocation
    drift and any failing signature that differs from the expected signature
    -> ``mismatched``; an exact expected-signature match -> ``proven``; a
    completed non-failing execution -> ``survived``. A signed observation
    whose claimed status contradicts this derivation is invalid input.
    """

    observation = result.control_observation
    if observation is None:
        raise ValueError("negative arm requires a control observation")
    if not (contract.valid_from <= result.created_at <= contract.expires_at):
        return "unavailable", "CONTROL_CONTRACT_EXPIRED"
    if result.mutation_status != "applied":
        return "unavailable", "CONTROL_EVIDENCE_MISSING"
    if observation.observed_failure_signature.execution_status != "completed":
        return "unavailable", "CONTROL_EVIDENCE_MISSING"
    if not observation.evidence_refs:
        return "unavailable", "CONTROL_EVIDENCE_MISSING"
    if observation.fixture_digest != contract.fixture_digest:
        return "mismatched", "CONTROL_FIXTURE_DRIFT"
    if observation.provocation_digest != contract.provocation_digest:
        return "mismatched", "CONTROL_PROVOCATION_DRIFT"
    if (
        observation.observed_failure_signature
        == contract.expected_failure_signature
    ):
        return "proven", None
    if any(
        exit_code != 0
        for exit_code in observation.observed_failure_signature.exit_codes
    ):
        return "mismatched", "CONTROL_FAILURE_SIGNATURE_MISMATCH"
    return "survived", "CONTROL_SURVIVED"


def assess_control_integrity(
    profile: VerificationProfileV05,
    results: Sequence[VerificationArmResultV05],
) -> ControlAssessmentResult:
    """Aggregate negative-control observations into one closed control status.

    Design 7.2 precedence: all proven -> ``proven``; any survived ->
    ``survived``; no survived with any mismatched -> ``mismatched``; any
    other incomplete set -> ``unavailable``. Each observation's claimed
    status is re-derived from its signed content and must match; caller
    metadata is never trusted alone.
    """

    validate_control_contracts(profile)
    profile = _validated_profile(profile)
    validated_results = _validated_results(results)

    contracts_by_arm = {
        contract.arm_id: contract for contract in profile.control_contracts
    }
    positive_arm_id = profile.positive_arm.arm_id
    negative_ids = {arm.arm_id for arm in profile.negative_arms}

    seen: dict[str, VerificationArmResultV05] = {}
    for result in validated_results:
        if result.profile_digest != profile.digest:
            raise ValueError("arm result does not bind the supplied profile")
        if result.arm_id == positive_arm_id:
            if result.arm_kind != "positive":
                raise ValueError("positive arm result kind mismatch")
            continue
        if result.arm_id not in negative_ids:
            raise ValueError("arm result references an unknown arm")
        if result.arm_kind != "negative":
            raise ValueError("negative arm result kind mismatch")
        if result.arm_id in seen:
            raise ValueError("duplicate arm result")
        seen[result.arm_id] = result

    if set(seen) != negative_ids:
        return ControlAssessmentResult(
            "unavailable", ("CONTROL_EVIDENCE_MISSING",)
        )

    statuses: set[ControlAssessmentStatus] = set()
    reason_codes: set[VerificationIntegrityReasonCode] = set()
    for arm_id in sorted(negative_ids):
        result = seen[arm_id]
        contract = contracts_by_arm[arm_id]
        observation = result.control_observation
        if observation is None or observation.control_id != contract.control_id:
            raise ValueError(
                "negative arm control observation does not bind its contract"
            )
        derived, code = _derived_control_status(contract, result)
        if observation.control_status != derived:
            raise ValueError(
                f"control observation claims {observation.control_status} "
                f"but derives {derived}"
            )
        statuses.add(derived)
        if code is not None:
            reason_codes.add(code)

    if statuses == {"proven"}:
        return ControlAssessmentResult("proven", ())
    if "survived" in statuses:
        return ControlAssessmentResult("survived", ("CONTROL_SURVIVED",))
    if "mismatched" in statuses:
        return ControlAssessmentResult(
            "mismatched",
            tuple(sorted(reason_codes & _CONTROL_MISMATCH_CODES)),
        )
    return ControlAssessmentResult(
        "unavailable",
        tuple(sorted(reason_codes & _CONTROL_UNAVAILABLE_CODES)),
    )


__all__ = [
    "PopulationAssessmentResult",
    "assess_population_integrity",
    "validate_population_contracts",
    "ControlAssessmentResult",
    "assess_control_integrity",
    "validate_control_contracts",
]
