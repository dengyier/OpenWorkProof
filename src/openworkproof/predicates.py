"""Finite, fail-closed predicate evaluation for protocol v0.1."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Literal

from openworkproof.models import (
    ArtifactDigestPredicateInput,
    HumanSignaturePredicateInput,
    PathAllowedPredicateInput,
    PredicateInput,
    PredicateResult,
    PredicateSpec,
    QuotaRemainingPredicateInput,
    TestsPassedPredicateInput,
    ToolAllowedPredicateInput,
    WorkOrder,
    _jcs_digest,
)


EvaluationOutcome = Literal["pass", "false", "fail_closed"]


def _immutable_snapshot(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType(
            {key: _immutable_snapshot(item) for key, item in value.items()}
        )
    if isinstance(value, (list, tuple)):
        return tuple(_immutable_snapshot(item) for item in value)
    if isinstance(value, (set, frozenset)):
        return frozenset(_immutable_snapshot(item) for item in value)
    return deepcopy(value)


@dataclass(frozen=True)
class EvaluationContext:
    """Trusted runtime facts and closed actual inputs for one evaluation step."""

    inputs: Mapping[str, Any] = field(default_factory=dict)
    authoritative_inputs: Mapping[str, Any] = field(default_factory=dict)
    authoritative_ledger_prefix_digests: Mapping[str, str] = field(
        default_factory=dict
    )
    verified_human_claim_digests: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        object.__setattr__(self, "inputs", _immutable_snapshot(self.inputs))
        object.__setattr__(
            self,
            "authoritative_inputs",
            _immutable_snapshot(self.authoritative_inputs),
        )
        object.__setattr__(
            self,
            "authoritative_ledger_prefix_digests",
            _immutable_snapshot(self.authoritative_ledger_prefix_digests),
        )
        object.__setattr__(
            self,
            "verified_human_claim_digests",
            frozenset(self.verified_human_claim_digests),
        )

    @classmethod
    def empty(cls) -> EvaluationContext:
        return cls()


def _is_within(path: str, roots: Sequence[str]) -> bool:
    return any(path == root or path.startswith(f"{root}/") for root in roots)


def evaluate_path_allowed(
    spec: PredicateSpec,
    value: PredicateInput,
    context: EvaluationContext,
) -> EvaluationOutcome:
    del context
    assert isinstance(value, PathAllowedPredicateInput)
    roots = tuple(spec.arguments["allowed_roots"])
    if value.resolution_manifest_digest is None:
        return "false"
    if any(entry.resolved_relative_path is None for entry in value.resolved_entries):
        return "fail_closed"
    if not all(_is_within(path, roots) for path in value.requested_paths):
        return "false"
    if not all(
        _is_within(entry.resolved_relative_path, roots)
        for entry in value.resolved_entries
        if entry.resolved_relative_path is not None
    ):
        return "false"
    return "pass"


def evaluate_tool_allowed(
    spec: PredicateSpec,
    value: PredicateInput,
    context: EvaluationContext,
) -> EvaluationOutcome:
    del context
    assert isinstance(value, ToolAllowedPredicateInput)
    actual = value.actual_tool_name
    return (
        "pass"
        if actual == spec.arguments["tool_name"]
        and actual in spec.arguments["allowed_tools"]
        else "false"
    )


def evaluate_quota_remaining(
    spec: PredicateSpec,
    value: PredicateInput,
    context: EvaluationContext,
) -> EvaluationOutcome:
    assert isinstance(value, QuotaRemainingPredicateInput)
    authoritative = context.authoritative_ledger_prefix_digests.get(value.grant_id)
    if authoritative is None or authoritative != value.ledger_prefix_digest:
        return "fail_closed"
    if (
        value.metric != spec.arguments["metric"]
        or value.amount != spec.arguments["amount"]
    ):
        return "false"
    return (
        "pass" if value.grant_remaining_before >= value.amount else "false"
    )


def evaluate_tests_passed(
    spec: PredicateSpec,
    value: PredicateInput,
    context: EvaluationContext,
) -> EvaluationOutcome:
    del context
    assert isinstance(value, TestsPassedPredicateInput)
    if value.actual_exit_code is None or value.test_evidence_digest is None:
        return "fail_closed"
    expected = spec.arguments
    if (
        value.test_mode != expected["test_mode"]
        or value.command_digest != expected["command_digest"]
        or value.expected_exit_code != expected["expected_exit_code"]
        or value.fixed_test_source_digest
        != expected["fixed_test_source_digest"]
    ):
        return "false"
    return (
        "pass"
        if value.actual_exit_code == value.expected_exit_code
        else "false"
    )


def evaluate_artifact_digest_matches(
    spec: PredicateSpec,
    value: PredicateInput,
    context: EvaluationContext,
) -> EvaluationOutcome:
    del context
    assert isinstance(value, ArtifactDigestPredicateInput)
    if (
        value.actual_digest is None
        or value.size_bytes is None
        or value.workspace_manifest_digest is None
    ):
        return "fail_closed"
    if (
        value.artifact_path != spec.arguments["artifact_path"]
        or value.expected_digest != spec.arguments["expected_digest"]
    ):
        return "false"
    return (
        "pass" if value.actual_digest == value.expected_digest else "false"
    )


def evaluate_human_signature_present(
    spec: PredicateSpec,
    value: PredicateInput,
    context: EvaluationContext,
) -> EvaluationOutcome:
    assert isinstance(value, HumanSignaturePredicateInput)
    if value.claim_digest not in context.verified_human_claim_digests:
        return "fail_closed"
    if value.required_role != spec.arguments["required_role"]:
        return "false"
    if value.expires_at is not None and value.validated_at > value.expires_at:
        return "false"
    return "pass"


PREDICATE_EVALUATORS = {
    "path_allowed": evaluate_path_allowed,
    "tool_allowed": evaluate_tool_allowed,
    "quota_remaining": evaluate_quota_remaining,
    "tests_passed": evaluate_tests_passed,
    "artifact_digest_matches": evaluate_artifact_digest_matches,
    "human_signature_present": evaluate_human_signature_present,
}

_INPUT_MODELS = {
    "path_allowed": PathAllowedPredicateInput,
    "tool_allowed": ToolAllowedPredicateInput,
    "quota_remaining": QuotaRemainingPredicateInput,
    "tests_passed": TestsPassedPredicateInput,
    "artifact_digest_matches": ArtifactDigestPredicateInput,
    "human_signature_present": HumanSignaturePredicateInput,
}


def predicate_input_digest(predicate_id: str, value: PredicateInput) -> str:
    return _jcs_digest(
        {
            "domain": "openworkproof/predicate-input/v0.1",
            "predicate_id": predicate_id,
            "input": value,
        }
    )


def evaluate_predicate(
    spec: PredicateSpec,
    context: EvaluationContext,
) -> PredicateResult:
    spec = PredicateSpec.model_validate(spec.model_dump(mode="json"))
    evaluator = PREDICATE_EVALUATORS.get(spec.name)
    input_model = _INPUT_MODELS.get(spec.name)
    if evaluator is None or input_model is None:
        raise ValueError("unknown predicate")
    if spec.predicate_id not in context.inputs:
        raise ValueError("closed predicate input is required")

    value = input_model.model_validate(context.inputs[spec.predicate_id])
    authoritative_raw = context.authoritative_inputs.get(spec.predicate_id)
    if authoritative_raw is None:
        outcome: EvaluationOutcome = "fail_closed"
    else:
        try:
            authoritative = input_model.model_validate(authoritative_raw)
        except Exception:
            outcome = "fail_closed"
        else:
            outcome = (
                "fail_closed"
                if value != authoritative
                else "pass"
            )
    try:
        if outcome == "pass":
            outcome = evaluator(spec, value, context)
    except Exception:
        outcome = "fail_closed"

    return PredicateResult(
        predicate_id=spec.predicate_id,
        name=spec.name,
        version=spec.version,
        arguments_digest=_jcs_digest(spec.arguments),
        input=value.model_dump(mode="json"),
        input_digest=predicate_input_digest(spec.predicate_id, value),
        passed=outcome == "pass",
        error_code=(
            None
            if outcome == "pass"
            else "PREDICATE_FALSE"
            if outcome == "false"
            else "FAIL_CLOSED"
        ),
    )


def evaluate_required_predicates(
    specs: Sequence[PredicateSpec],
    context: EvaluationContext,
) -> tuple[PredicateResult, ...]:
    ids = tuple(spec.predicate_id for spec in specs)
    if ids != tuple(sorted(set(ids))):
        raise ValueError("predicate specs must be sorted and unique")
    return tuple(evaluate_predicate(spec, context) for spec in specs)


def select_required_predicates(
    *,
    work_order: WorkOrder,
    tool_name: str,
    policy_decision: str,
    execution_status: str,
    test_mode: str,
) -> tuple[PredicateSpec, ...]:
    valid_outcomes = {
        ("deny", "denied"),
        ("allow", "succeeded"),
        ("allow", "failed"),
    }
    if (policy_decision, execution_status) not in valid_outcomes:
        raise ValueError("invalid policy/execution outcome")
    if test_mode not in {"developer", "verifier"}:
        raise ValueError("invalid test mode")

    selected = [
        spec
        for spec in work_order.preconditions + work_order.invariants
        if tool_name in spec.applies_to_tools
    ]
    if (
        policy_decision == "allow"
        and test_mode == "verifier"
        and execution_status in {"succeeded", "failed"}
    ):
        selected.extend(
            spec
            for spec in work_order.postconditions
            if tool_name in spec.applies_to_tools
        )
    return tuple(sorted(selected, key=lambda spec: spec.predicate_id))


__all__ = [
    "EvaluationContext",
    "PREDICATE_EVALUATORS",
    "evaluate_predicate",
    "evaluate_required_predicates",
    "predicate_input_digest",
    "select_required_predicates",
]
