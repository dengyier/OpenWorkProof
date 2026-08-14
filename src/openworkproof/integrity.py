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
import math
import re
from typing import Literal

import rfc8785

from openworkproof.models import (
    ControlContractV05,
    DecisionDraftRequest,
    EvaluationScopeManifest,
    EvidenceRefV05,
    FailureSignatureV05,
    PopulationObservationV05,
    ScopeAssessment,
    VerificationArmResultReference,
    VerificationArmResultV05,
    VerificationDecisionDraftV05,
    VerificationDecisionV05,
    VerificationIntegrityAssessmentV05,
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


@dataclass(frozen=True, slots=True)
class PopulationObservationBuildResult:
    """One adapter-built population observation with its replayable evidence.

    ``observation`` is ``None`` when the adapter could not observe (collection
    error, timeout, or selector/engine drift); the reason codes and status
    then carry the failure. ``evidence_inventory`` maps SHA-256 digests to
    the canonical population-evidence bytes the observation references.
    """

    observation: PopulationObservationV05 | None
    evidence_inventory: tuple[tuple[str, bytes], ...]
    eligible_member_ids: tuple[str, ...]
    selected_member_ids: tuple[str, ...]
    status: Literal["satisfied", "indeterminate"]
    reason_codes: tuple[str, ...]


def population_observation_payload(
    *,
    contract: PopulationContractV05,
    eligible_member_ids: Sequence[str],
    selected_member_ids: Sequence[str],
    observed_at: str,
    eligible_path: str = "evidence/eligible-population.json",
    selected_path: str = "evidence/selected-population.json",
) -> tuple[dict[str, object], dict[str, bytes]]:
    """Build one canonical population observation payload and evidence docs."""

    eligible = tuple(sorted(set(eligible_member_ids)))
    selected = tuple(sorted(set(selected_member_ids)))
    eligible_seen = len(eligible)
    selected_count = len(selected)
    if eligible_seen == 0 or selected_count == 0:
        numerator, denominator = 0, 1
    else:
        divisor = math.gcd(selected_count, eligible_seen)
        numerator = selected_count // divisor
        denominator = eligible_seen // divisor
    eligible_ref, eligible_bytes = _evidence_reference(
        {
            "schema_version": POPULATION_EVIDENCE_SCHEMA_VERSION,
            "purpose": "eligible-population",
            "member_ids": list(eligible),
        },
        eligible_path,
    )
    selected_ref, selected_bytes = _evidence_reference(
        {
            "schema_version": POPULATION_EVIDENCE_SCHEMA_VERSION,
            "purpose": "selected-population",
            "member_ids": list(selected),
        },
        selected_path,
    )
    observation = {
        "contract_id": contract.contract_id,
        "selector_rule_id": contract.selector_rule_id,
        "selector_spec_digest": contract.selector_spec_digest,
        "selector_engine_digest": contract.selector_engine_digest,
        "eligible_seen": eligible_seen,
        "eligible_population_digest": population_member_digest(eligible),
        "selected_count": selected_count,
        "selected_population_digest": population_member_digest(selected),
        "capture_numerator": numerator,
        "capture_denominator": denominator,
        "observed_at": observed_at,
        "evidence_refs": [eligible_ref, selected_ref],
    }
    inventory = {
        eligible_ref["sha256"]: eligible_bytes,
        selected_ref["sha256"]: selected_bytes,
    }
    return observation, inventory


def _evidence_reference(
    document: Mapping[str, object], path: str
) -> tuple[dict[str, object], bytes]:
    content = rfc8785.dumps(dict(document))
    return (
        {
            "path": path,
            "sha256": hashlib.sha256(content).hexdigest(),
            "media_type": "application/json",
            "size_bytes": len(content),
        },
        content,
    )


def build_failure_signature(
    *,
    execution_status: str,
    exit_codes: Sequence[int],
    reason_codes: Sequence[str],
    predicate_ids: Sequence[str],
    evidence_purposes: Sequence[str],
) -> FailureSignatureV05:
    """Build one closed failure signature from structured fields only.

    Raw stderr, absolute paths, hostnames, durations, and arbitrary metadata
    have no channel into this structure; the closed model rejects unknown
    fields and non-canonical arrays.
    """

    return FailureSignatureV05(
        execution_status=execution_status,  # type: ignore[arg-type]
        exit_codes=tuple(sorted(set(exit_codes))),
        reason_codes=tuple(sorted(set(reason_codes))),
        predicate_ids=tuple(sorted(set(predicate_ids))),
        required_evidence_purposes=tuple(sorted(set(evidence_purposes))),
    )


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
    completed non-failing execution -> ``survived``. A target failure is
    derived from a non-zero exit code or a ``MUTATION_CAUGHT`` reason code,
    so contradictory signatures cannot silently derive survived. A signed
    observation whose claimed status contradicts this derivation is invalid
    input.
    """

    observation = result.control_observation
    if observation is None:
        raise ValueError("negative arm requires a control observation")
    if not (contract.valid_from <= result.created_at <= contract.expires_at):
        # The closed code set has one window code; a result before the window
        # is treated as expired rather than invented as a new reason code.
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
    observed = observation.observed_failure_signature
    target_failed = any(
        exit_code != 0 for exit_code in observed.exit_codes
    ) or "MUTATION_CAUGHT" in observed.reason_codes
    if target_failed:
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
    positive_seen = False
    for result in validated_results:
        if result.profile_digest != profile.digest:
            raise ValueError("arm result does not bind the supplied profile")
        if result.arm_id == positive_arm_id:
            if result.arm_kind != "positive":
                raise ValueError("positive arm result kind mismatch")
            if positive_seen:
                raise ValueError("duplicate positive arm result")
            positive_seen = True
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


def validate_population_observation(
    profile: VerificationProfileV05,
    manifest: EvaluationScopeManifest,
    result: VerificationArmResultV05,
    *,
    rule_outputs: Mapping[str, Sequence[str]] | None = None,
    evidence_inventory: Mapping[str, bytes] | None = None,
) -> None:
    """Validate one arm result's population observations without aggregation.

    Used by the append-only transaction layer to prove that a single signed
    arm result's observations replay exactly before commit. Raises
    ``ValueError`` when evidence is missing or unreplayable, or when any
    observation's rule, engine, digest, or eligible binding drifts from the
    signed contract. Returns ``None`` when every observation replays to a
    consistent matched / empty / capture_failed state.
    """

    profile = _validated_profile(profile)
    manifest = _validated_manifest(manifest)
    if rule_outputs is None:
        raise ValueError("rule outputs are required to replay observations")
    validate_population_contracts(profile, manifest, rule_outputs=rule_outputs)
    result = _validated_results((result,))[0]
    if not isinstance(evidence_inventory, Mapping):
        raise ValueError("evidence inventory is required to replay observations")
    if (
        result.profile_digest != profile.digest
        or result.scope_manifest_digest != manifest.digest
    ):
        raise ValueError("arm result does not bind the supplied profile and scope")
    contracts_by_id = {
        contract.contract_id: contract for contract in profile.population_contracts
    }
    observation_ids = [
        observation.contract_id for observation in result.population_observations
    ]
    if (
        len(observation_ids) != len(set(observation_ids))
        or set(observation_ids) != set(contracts_by_id)
    ):
        raise ValueError("population observations do not cover the contracts")

    outputs_by_rule = {
        rule_id: tuple(sorted(member_ids))
        for rule_id, member_ids in _validated_rule_outputs(
            rule_outputs, {rule.rule_id: rule for rule in manifest.selector_rules}
        ).items()
    }
    for observation in result.population_observations:
        contract = contracts_by_id[observation.contract_id]
        if (
            observation.selector_rule_id != contract.selector_rule_id
            or observation.selector_spec_digest != contract.selector_spec_digest
            or observation.selector_engine_digest != contract.selector_engine_digest
        ):
            raise ValueError("population observation drifts from its contract")
        evidence_purposes = _resolve_population_evidence(
            observation.evidence_refs, evidence_inventory
        )
        if not set(contract.required_population_evidence_purposes).issubset(
            evidence_purposes
        ):
            raise ValueError("population observation evidence purposes are missing")
        eligible_ids = evidence_purposes.get("eligible-population", ())
        selected_ids = evidence_purposes.get("selected-population", ())
        if (
            len(eligible_ids) != observation.eligible_seen
            or population_member_digest(eligible_ids)
            != observation.eligible_population_digest
        ):
            raise ValueError("population observation eligible digest does not replay")
        expected_eligible = outputs_by_rule.get(observation.selector_rule_id, ())
        if eligible_ids and not set(expected_eligible).issubset(eligible_ids):
            raise ValueError(
                "population observation eligible set does not contain the rule output"
            )
        if observation.selected_count == 0:
            if (
                selected_ids
                or observation.selected_population_digest
                != population_member_digest(())
            ):
                raise ValueError(
                    "population observation selected digest does not replay"
                )
        else:
            if (
                selected_ids != tuple(contract.declared_selected_member_ids)
                or len(selected_ids) != observation.selected_count
                or population_member_digest(selected_ids)
                != observation.selected_population_digest
            ):
                raise ValueError(
                    "population observation selected digest does not replay"
                )
    return None


def compose_verification_decision_v05(
    *,
    profile: VerificationProfileV05,
    manifest: EvaluationScopeManifest,
    arm_results: Sequence[VerificationArmResultV05],
    request: DecisionDraftRequest,
    previous_decision: VerificationDecisionV05 | None = None,
    rule_outputs: Mapping[str, Sequence[str]] | None = None,
    evidence_inventory: Mapping[str, bytes] | None = None,
) -> VerificationDecisionDraftV05:
    """Compose the three-state v0.5 decision draft from signed inputs.

    Runs the existing v0.3 semantic checks, then the population and control
    assessments. Closed matrix: population not matched -> UNKNOWN; matched
    with a survived control -> REFUTED; matched with a mismatched or
    unavailable control -> UNKNOWN; matched with proven controls follows
    the v0.3 satisfied/contradicted/independence rules. The integrity
    assessment carries the sorted unique population and control reason
    codes, and the top-level reason codes reproduce them exactly.
    """

    from openworkproof import verification as verification_module  # lazy import
    from openworkproof.acceptance import (  # lazy import
        AcceptanceTransactionError,
        evidence_snapshot_digest,
    )

    if type(profile) is not VerificationProfileV05:
        raise verification_module.VerificationInputError(
            "profile must be an exact VerificationProfileV05"
        )
    if type(request) is not DecisionDraftRequest:
        raise verification_module.VerificationInputError(
            "request must be a DecisionDraftRequest"
        )
    if rule_outputs is None or evidence_inventory is None:
        raise verification_module.VerificationInputError(
            "rule outputs and evidence inventory are required to compose a v0.5 decision"
        )
    profile = _validated_profile(profile)
    manifest = _validated_manifest(manifest)
    verification_module.validate_verification_profile_v03(profile, manifest)
    validate_population_contracts(profile, manifest, rule_outputs=rule_outputs)
    validate_control_contracts(profile)

    results = tuple(arm_results)
    expected_arms = {
        arm.arm_id: arm for arm in (profile.positive_arm, *profile.negative_arms)
    }
    if len(results) != len(expected_arms) or {
        result.arm_id for result in results
    } != set(expected_arms):
        raise verification_module.VerificationInputError(
            "arm result set is incomplete"
        )
    for result in results:
        if type(result) is not VerificationArmResultV05:
            raise verification_module.VerificationInputError(
                "arm results must be exact VerificationArmResultV05"
            )
        if (
            result.profile_digest != profile.digest
            or result.scope_manifest_digest != manifest.digest
        ):
            raise verification_module.VerificationInputError(
                "arm result binding mismatch"
            )
    bindings = {
        binding.verifier_key_id: binding for binding in profile.verifier_bindings
    }
    for result in results:
        arm = expected_arms[result.arm_id]
        if result.arm_kind != arm.arm_kind:
            raise verification_module.VerificationInputError(
                "arm result kind or id mismatch"
            )
        binding = bindings.get(result.verifier_key_id)
        if (
            binding is None
            or binding.verifier_subject_id != result.verifier_subject_id
            or binding.controller_factors != result.controller_factors
            or binding.execution_context_factors != result.execution_context_factors
        ):
            raise verification_module.VerificationInputError(
                "arm result verifier is not profile-bound"
            )
        if not (
            binding.valid_from <= result.created_at < binding.expires_at
            and profile.created_at <= result.created_at < profile.expires_at
        ):
            raise verification_module.VerificationInputError(
                "arm result verifier binding is not current"
            )
        if not verification_module.verify_payload(
            "verification-arm-result",
            result.model_dump(mode="json"),
            verification_module._decode_public_key(
                binding.verifier_public_key_b64url
            ),
            version="0.5",
        ):
            raise verification_module.VerificationInputError(
                "arm result signature is invalid"
            )
    if not profile.created_at <= request.decided_at < profile.expires_at:
        raise verification_module.VerificationInputError(
            "verification decision is outside profile validity"
        )
    if previous_decision is not None:
        verification_module.validate_verification_decision_v05(
            profile=profile, manifest=manifest, decision=previous_decision
        )
        if not previous_decision.decided_at < request.decided_at:
            raise verification_module.VerificationInputError(
                "superseding decision time is stale"
            )

    positive = tuple(
        result for result in results if result.arm_kind == "positive"
    )
    negative = tuple(
        result for result in results if result.arm_kind == "negative"
    )
    if len(positive) != 1 or len(negative) != len(profile.negative_arms):
        raise verification_module.VerificationInputError(
            "arm result set is incomplete"
        )

    population = assess_population_integrity(
        profile,
        manifest,
        results,
        rule_outputs=rule_outputs,
        evidence_inventory=evidence_inventory,
    )
    control = assess_control_integrity(profile, results)

    missing_required = tuple(
        sorted(
            {
                target
                for result in results
                for target in (
                    set(manifest.required_target_ids)
                    - set(result.observed_required_target_ids)
                )
            }
        )
    )
    counts = tuple(result.observed_member_count for result in results)
    population_digests = {
        result.observed_population_digest for result in results
    }
    scope_reasons = {
        code
        for result in results
        for code in result.reason_codes
        if code.startswith("SCOPE_")
    }
    cross_arm_mismatch = len(set(counts)) != 1 or len(population_digests) != 1
    if cross_arm_mismatch:
        scope_reasons.add("SCOPE_CROSS_ARM_MISMATCH")
    if missing_required:
        scope_reasons.add("SCOPE_REQUIRED_TARGET_MISSING")
    population_mismatch = any(
        result.observed_member_count != manifest.member_count
        or result.observed_population_digest != manifest.population_digest
        for result in results
    )
    if population_mismatch:
        scope_reasons.add("SCOPE_POPULATION_DRIFT")
    if any(not result.scope_evidence_refs for result in results):
        scope_reasons.add("SCOPE_EVIDENCE_MISSING")

    reported_statuses = {result.scope_expectation_status for result in results}
    if (
        cross_arm_mismatch
        or missing_required
        or "indeterminate" in reported_statuses
        or "SCOPE_EVIDENCE_MISSING" in scope_reasons
    ):
        scope_status = "indeterminate"
    elif population_mismatch or "contradicted" in reported_statuses:
        scope_status = "contradicted"
    else:
        scope_status = "satisfied"

    independence = verification_module.assess_independence(profile, results)
    if scope_status != "satisfied":
        decision = "UNKNOWN"
    elif population.status != "matched":
        decision = "UNKNOWN"
    elif control.status == "survived":
        decision = "REFUTED"
    elif control.status in {"mismatched", "unavailable"}:
        decision = "UNKNOWN"
    elif positive[0].expectation_status == "contradicted" or any(
        result.expectation_status == "contradicted" for result in negative
    ):
        decision = "REFUTED"
    elif positive[0].expectation_status != "satisfied" or any(
        result.expectation_status != "satisfied" for result in negative
    ) or not independence.is_sufficient:
        decision = "UNKNOWN"
    else:
        decision = "VERIFIED"

    references: list[VerificationArmResultReference] = []
    for result in results:
        try:
            snapshot = evidence_snapshot_digest(
                tuple(
                    sorted(
                        (*result.evidence_refs, *result.scope_evidence_refs),
                        key=lambda ref: ref.path,
                    )
                )
            )
        except AcceptanceTransactionError as error:
            raise verification_module.VerificationInputError(
                "arm result evidence is not canonical"
            ) from error
        references.append(
            VerificationArmResultReference(
                arm_id=result.arm_id,
                arm_result_id=result.arm_result_id,
                arm_result_digest=result.digest,
                evidence_snapshot_digest=snapshot,
            )
        )

    assessment = VerificationIntegrityAssessmentV05(
        population_status=population.status,
        control_status=control.status,
        reason_codes=tuple(
            sorted(set(population.reason_codes) | set(control.reason_codes))
        ),
    )
    v03_reason_codes = {
        *scope_reasons,
        *independence.reason_codes,
        *(code for result in results for code in result.reason_codes),
    }
    reason_codes = tuple(
        sorted(v03_reason_codes | set(assessment.reason_codes))
    )
    scope_assessment = ScopeAssessment(
        declared_member_count=manifest.member_count,
        observed_member_counts=counts,
        population_digest=manifest.population_digest,
        required_target_count=len(manifest.required_target_ids),
        missing_required_target_ids=missing_required,
        scope_status=scope_status,
    )
    return VerificationDecisionDraftV05(
        decision_id=request.decision_id,
        work_order_digest=profile.work_order_digest,
        subject_claim_digest=profile.subject_claim_digest,
        profile_id=profile.profile_id,
        profile_digest=profile.digest,
        arm_results=tuple(
            reference.model_dump(mode="json") for reference in references
        ),
        assurance_level=profile.assurance_level,
        decision=decision,
        independence=independence.model_dump(mode="json"),
        reason_codes=reason_codes,
        supersedes_decision_id=(
            None if previous_decision is None else previous_decision.decision_id
        ),
        supersedes_decision_digest=(
            None if previous_decision is None else previous_decision.digest
        ),
        causal_parent_receipt_ids=tuple(
            sorted(
                {
                    receipt_id
                    for result in results
                    for receipt_id in result.action_receipt_ids
                }
            )
        ),
        causal_parent_decision_ids=(
            ()
            if previous_decision is None
            else (previous_decision.decision_id,)
        ),
        decided_at=request.model_dump(mode="json")["decided_at"],
        nonce=request.nonce,
        scope_manifest_digest=manifest.digest,
        scope_assessment=scope_assessment.model_dump(mode="json"),
        integrity_assessment=assessment.model_dump(mode="json"),
    )


__all__ = [
    "PopulationAssessmentResult",
    "assess_population_integrity",
    "validate_population_contracts",
    "validate_population_observation",
    "ControlAssessmentResult",
    "assess_control_integrity",
    "validate_control_contracts",
    "compose_verification_decision_v05",
]
