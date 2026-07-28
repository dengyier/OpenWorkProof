"""Executable tests for the frozen v0.1 predicate registry."""

from __future__ import annotations

import copy
import importlib
from typing import Any

import pytest
from pydantic import ValidationError

from openworkproof.models import PredicateResult, PredicateSpec, WorkOrder
from openworkproof.signing import sign_payload

from conftest import (
    IMAGE_A,
    SHA256_A,
    SHA256_B,
    SHA256_C,
    SOURCE_COMMIT,
    jcs_digest,
)


OTHER_COMMIT = "2" * 40
TOO_LARGE = 9_007_199_254_740_992


def _api():
    # Keep the import inside the tests so the first TDD run is a test failure
    # caused by the missing feature, rather than a collection error.
    return importlib.import_module("openworkproof.predicates")


def _spec(
    name: str,
    arguments: dict[str, Any],
    tools: tuple[str, ...],
) -> PredicateSpec:
    return PredicateSpec.from_parts(
        name=name,
        version="0.1",
        applies_to_tools=tools,
        arguments=arguments,
    )


def _recompute_predicate_id(value: dict[str, Any]) -> None:
    value["predicate_id"] = jcs_digest(
        {
            "domain": "openworkproof/predicate-id/v0.1",
            "name": value["name"],
            "version": value["version"],
            "applies_to_tools": value["applies_to_tools"],
            "arguments": value["arguments"],
        }
    )


def _valid_cases() -> list[tuple[PredicateSpec, dict[str, Any], dict[str, Any]]]:
    path = _spec(
        "path_allowed",
        {"allowed_roots": ["src"]},
        ("owp.repo_read",),
    )
    tool = _spec(
        "tool_allowed",
        {
            "allowed_tools": ["owp.repo_read"],
            "tool_name": "owp.repo_read",
        },
        ("owp.repo_read",),
    )
    quota = _spec(
        "quota_remaining",
        {"metric": "tool_calls", "amount": 1},
        ("owp.repo_read",),
    )
    tests = _spec(
        "tests_passed",
        {
            "test_mode": "verifier",
            "command_digest": SHA256_A,
            "expected_exit_code": 0,
            "fixed_test_source_digest": SHA256_B,
        },
        ("owp.run_tests",),
    )
    artifact = _spec(
        "artifact_digest_matches",
        {
            "artifact_path": "reports/result.json",
            "expected_digest": SHA256_A,
        },
        ("owp.run_tests",),
    )
    human = _spec(
        "human_signature_present",
        {"required_role": "Maintainer"},
        (),
    )

    return [
        (
            path,
            {
                "requested_paths": ["src/module.py"],
                "resolved_entries": [
                    {
                        "requested_path": "src/module.py",
                        "resolved_relative_path": "src/module.py",
                    }
                ],
                "resolution_manifest_digest": SHA256_A,
            },
            {},
        ),
        (
            tool,
            {"actual_tool_name": "owp.repo_read"},
            {},
        ),
        (
            quota,
            {
                "grant_id": SHA256_A,
                "metric": "tool_calls",
                "amount": 1,
                "grant_remaining_before": 1,
                "ledger_prefix_digest": SHA256_B,
            },
            {"authoritative_ledger_prefix_digests": {SHA256_A: SHA256_B}},
        ),
        (
            tests,
            {
                "test_mode": "verifier",
                "command_digest": SHA256_A,
                "expected_exit_code": 0,
                "actual_exit_code": 0,
                "test_evidence_digest": SHA256_C,
                "source_commit": SOURCE_COMMIT,
                "candidate_commit": OTHER_COMMIT,
                "workspace_manifest_digest": SHA256_A,
                "container_image_digest": IMAGE_A,
                "fixed_test_source_digest": SHA256_B,
            },
            {},
        ),
        (
            artifact,
            {
                "artifact_path": "reports/result.json",
                "expected_digest": SHA256_A,
                "actual_digest": SHA256_A,
                "size_bytes": 128,
                "workspace_manifest_digest": SHA256_B,
            },
            {},
        ),
        (
            human,
            {
                "decision_type": "final_acceptance",
                "required_role": "Maintainer",
                "actor_key_id": f"ed25519:{SHA256_A}",
                "claim_digest": SHA256_B,
                "decision": "accepted",
                "expires_at": "2026-01-01T00:10:00Z",
                "validated_at": "2026-01-01T00:05:00Z",
            },
            {"verified_human_claim_digests": frozenset({SHA256_B})},
        ),
    ]


def _context(
    api: Any,
    spec: PredicateSpec,
    input_value: dict[str, Any],
    extras: dict[str, Any],
):
    return api.EvaluationContext(
        inputs={spec.predicate_id: input_value},
        authoritative_inputs={
            spec.predicate_id: copy.deepcopy(input_value),
        },
        **extras,
    )


def test_registry_is_literal_and_contains_exactly_six_evaluators() -> None:
    api = _api()

    assert tuple(api.PREDICATE_EVALUATORS) == (
        "path_allowed",
        "tool_allowed",
        "quota_remaining",
        "tests_passed",
        "artifact_digest_matches",
        "human_signature_present",
    )


def test_predicate_spec_factory_canonicalizes_tools_and_rejects_unknown_specs() -> None:
    spec = PredicateSpec.from_parts(
        name="tool_allowed",
        version="0.1",
        applies_to_tools=("owp.repo_read", "owp.repo_read"),
        arguments={
            "allowed_tools": ["owp.repo_read"],
            "tool_name": "owp.repo_read",
        },
    )

    assert spec.applies_to_tools == ("owp.repo_read",)
    with pytest.raises(ValidationError):
        PredicateSpec.from_parts(
            name="arbitrary_python",
            version="0.1",
            applies_to_tools=(),
            arguments={},
        )
    with pytest.raises(ValidationError):
        PredicateSpec.from_parts(
            name="tool_allowed",
            version="0.2",
            applies_to_tools=("owp.repo_read",),
            arguments={
                "allowed_tools": ["owp.repo_read"],
                "tool_name": "owp.repo_read",
            },
        )


def test_normal_parser_rejects_unknown_name_and_non_frozen_version() -> None:
    base = _valid_cases()[1][0].model_dump(mode="json")

    for field, value in (("name", "arbitrary_python"), ("version", "0.2")):
        candidate = copy.deepcopy(base)
        candidate[field] = value
        _recompute_predicate_id(candidate)
        with pytest.raises(ValidationError):
            PredicateSpec.model_validate(candidate)


@pytest.mark.parametrize("case_index", range(6))
@pytest.mark.parametrize("mutation", ("extra", "missing", "wrong_type"))
def test_normal_parser_rejects_non_registry_arguments(
    case_index: int,
    mutation: str,
) -> None:
    candidate = _valid_cases()[case_index][0].model_dump(mode="json")
    arguments = candidate["arguments"]
    assert isinstance(arguments, dict)

    if mutation == "extra":
        arguments["unexpected"] = True
    elif mutation == "missing":
        arguments.pop(next(iter(arguments)))
    else:
        wrong_values = {
            "path_allowed": ("allowed_roots", "src"),
            "tool_allowed": ("allowed_tools", "owp.repo_read"),
            "quota_remaining": ("amount", "1"),
            "tests_passed": ("command_digest", 1),
            "artifact_digest_matches": ("artifact_path", 1),
            "human_signature_present": ("required_role", 1),
        }
        field, value = wrong_values[candidate["name"]]
        arguments[field] = value

    _recompute_predicate_id(candidate)
    with pytest.raises(ValidationError):
        PredicateSpec.model_validate(candidate)


@pytest.mark.parametrize(
    ("case_index", "field", "value"),
    [
        (0, "allowed_roots", ["src", "src"]),
        (0, "allowed_roots", ["tests", "src"]),
        (0, "allowed_roots", [".git"]),
        (1, "allowed_tools", ["owp.repo_read", "owp.repo_read"]),
        (1, "allowed_tools", ["owp.run_tests", "owp.repo_read"]),
        (1, "allowed_tools", ["owp.delegate_grant"]),
        (1, "tool_name", "owp.delegate_grant"),
        (2, "metric", "tokens"),
        (2, "amount", True),
        (2, "amount", 0),
        (3, "test_mode", "developer"),
        (3, "command_digest", "A" * 64),
        (3, "expected_exit_code", True),
        (3, "expected_exit_code", 256),
        (4, "artifact_path", "../result.json"),
        (4, "expected_digest", "A" * 64),
        (5, "required_role", "Developer"),
    ],
)
def test_normal_parser_rejects_noncanonical_or_out_of_bounds_arguments(
    case_index: int,
    field: str,
    value: Any,
) -> None:
    candidate = _valid_cases()[case_index][0].model_dump(mode="json")
    candidate["arguments"][field] = value
    _recompute_predicate_id(candidate)

    with pytest.raises(ValidationError):
        PredicateSpec.model_validate(candidate)


def test_human_signature_spec_is_valid_standalone_but_not_in_work_order(
    work_order_dict: dict[str, Any],
) -> None:
    human = _valid_cases()[5][0]
    assert PredicateSpec.model_validate(
        human.model_dump(mode="json")
    ) == human

    candidate = copy.deepcopy(work_order_dict)
    candidate["preconditions"][0] = human.model_dump(mode="json")
    candidate["preconditions"].sort(key=lambda item: item["predicate_id"])
    with pytest.raises(ValidationError):
        WorkOrder.model_validate(candidate)


def test_resigned_work_order_rejects_non_frozen_predicate_version(
    signed_work_order: WorkOrder,
    ephemeral_role_keys: dict[str, tuple[Any, dict[str, str]]],
) -> None:
    candidate = signed_work_order.model_dump(mode="json")
    maintainer_private, _ = ephemeral_role_keys["Maintainer"]
    predicate = candidate["preconditions"][0]
    predicate["version"] = "0.2"
    _recompute_predicate_id(predicate)
    candidate["preconditions"].sort(key=lambda item: item["predicate_id"])

    resigned = sign_payload("work-order", candidate, maintainer_private)
    with pytest.raises(ValidationError):
        WorkOrder.model_validate(resigned)


@pytest.mark.parametrize("malformation", ("version", "allowed_tools"))
def test_evaluator_rejects_model_construct_registry_bypass(
    malformation: str,
) -> None:
    api = _api()
    valid_spec, input_value, _ = _valid_cases()[1]
    values = valid_spec.model_dump(mode="python")
    if malformation == "version":
        values["version"] = "0.2"
    else:
        values["arguments"] = {
            "allowed_tools": "owp.repo_read",
            "tool_name": "owp.repo_read",
        }
    bypassed = PredicateSpec.model_construct(**values)

    with pytest.raises((ValidationError, ValueError)):
        api.evaluate_predicate(
            bypassed,
            api.EvaluationContext(
                inputs={bypassed.predicate_id: input_value},
                authoritative_inputs={
                    bypassed.predicate_id: copy.deepcopy(input_value)
                },
            ),
        )


@pytest.mark.parametrize("case_index", range(6))
def test_each_registered_predicate_emits_a_closed_bound_passing_result(
    case_index: int,
) -> None:
    api = _api()
    spec, input_value, extras = _valid_cases()[case_index]

    result = api.evaluate_predicate(
        spec,
        _context(api, spec, input_value, extras),
    )

    assert isinstance(result, PredicateResult)
    assert result.passed is True
    assert result.error_code is None
    assert result.predicate_id == spec.predicate_id
    assert result.name == spec.name
    assert result.version == spec.version
    assert result.matches_spec(spec)
    assert result.input.model_dump(mode="json") == input_value


def test_normal_false_results_use_predicate_false() -> None:
    api = _api()
    cases = _valid_cases()
    false_inputs = [
        {
            **cases[0][1],
            "requested_paths": ["outside/module.py"],
            "resolved_entries": [
                {
                    "requested_path": "outside/module.py",
                    "resolved_relative_path": None,
                }
            ],
            "resolution_manifest_digest": None,
        },
        {"actual_tool_name": "owp.apply_patch"},
        {**cases[2][1], "grant_remaining_before": 0},
        {**cases[3][1], "actual_exit_code": 1},
        {**cases[4][1], "actual_digest": SHA256_B},
        {
            **cases[5][1],
            "expires_at": "2026-01-01T00:04:59Z",
        },
    ]

    for (spec, _, extras), input_value in zip(cases, false_inputs, strict=True):
        result = api.evaluate_predicate(
            spec,
            _context(api, spec, input_value, extras),
        )
        assert result.passed is False
        assert result.error_code == "PREDICATE_FALSE"
        assert result.matches_spec(spec)


def test_unavailable_authoritative_context_fails_closed_with_bound_input() -> None:
    api = _api()
    quota_spec, quota_input, _ = _valid_cases()[2]
    human_spec, human_input, _ = _valid_cases()[5]

    for spec, input_value in (
        (quota_spec, quota_input),
        (human_spec, human_input),
    ):
        result = api.evaluate_predicate(
            spec,
            api.EvaluationContext(
                inputs={spec.predicate_id: input_value},
                authoritative_inputs={
                    spec.predicate_id: copy.deepcopy(input_value),
                },
            ),
        )
        assert result.passed is False
        assert result.error_code == "FAIL_CLOSED"
        assert result.matches_spec(spec)
        assert result.input.model_dump(mode="json") == input_value


def test_evaluator_exception_fails_closed_without_losing_the_actual_input(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = _api()
    spec, input_value, extras = _valid_cases()[1]

    def explode(*_: object) -> bool:
        raise RuntimeError("evaluator failed")

    monkeypatch.setitem(api.PREDICATE_EVALUATORS, spec.name, explode)
    result = api.evaluate_predicate(
        spec,
        _context(api, spec, input_value, extras),
    )

    assert result.passed is False
    assert result.error_code == "FAIL_CLOSED"
    assert result.matches_spec(spec)
    assert result.input.model_dump(mode="json") == input_value


def test_symlink_resolution_failure_is_fail_closed_not_normal_false() -> None:
    api = _api()
    spec, input_value, _ = _valid_cases()[0]
    input_value["resolved_entries"][0]["resolved_relative_path"] = None

    result = api.evaluate_predicate(
        spec,
        api.EvaluationContext(
            inputs={spec.predicate_id: input_value},
            authoritative_inputs={
                spec.predicate_id: copy.deepcopy(input_value),
            },
        ),
    )

    assert result.passed is False
    assert result.error_code == "FAIL_CLOSED"


@pytest.mark.parametrize("case_index", range(6))
def test_input_digest_is_bound_to_the_predicate_id(case_index: int) -> None:
    api = _api()
    spec, input_value, extras = _valid_cases()[case_index]
    result = api.evaluate_predicate(
        spec,
        _context(api, spec, input_value, extras),
    )
    alternate = spec.model_copy(
        update={"predicate_id": "f" * 64},
    )

    assert result.input_digest != api.predicate_input_digest(
        alternate.predicate_id,
        result.input,
    )


@pytest.mark.parametrize("case_index", range(6))
def test_closed_inputs_reject_unknown_or_missing_fields(case_index: int) -> None:
    api = _api()
    spec, input_value, extras = _valid_cases()[case_index]
    unknown = {**input_value, "unexpected": True}
    missing = copy.deepcopy(input_value)
    missing.pop(next(iter(missing)))

    for malformed in (unknown, missing):
        with pytest.raises(ValidationError):
            api.evaluate_predicate(
                spec,
                _context(api, spec, malformed, extras),
            )


def test_safe_integer_bounds_are_enforced_before_evaluation() -> None:
    api = _api()
    spec, input_value, extras = _valid_cases()[2]
    input_value["grant_remaining_before"] = TOO_LARGE

    with pytest.raises(ValidationError):
        api.evaluate_predicate(
            spec,
            _context(api, spec, input_value, extras),
        )


def test_missing_closed_input_is_rejected_at_the_parse_boundary() -> None:
    api = _api()
    spec, _, _ = _valid_cases()[1]

    with pytest.raises(ValueError, match="closed predicate input"):
        api.evaluate_predicate(spec, api.EvaluationContext.empty())


def test_required_evaluation_rejects_unsorted_or_duplicate_specs() -> None:
    api = _api()
    first, first_input, _ = _valid_cases()[0]
    second, second_input, _ = _valid_cases()[1]
    ordered = tuple(sorted((first, second), key=lambda item: item.predicate_id))
    context = api.EvaluationContext(
        inputs={
            first.predicate_id: first_input,
            second.predicate_id: second_input,
        },
        authoritative_inputs={
            first.predicate_id: copy.deepcopy(first_input),
            second.predicate_id: copy.deepcopy(second_input),
        },
    )

    results = api.evaluate_required_predicates(ordered, context)
    assert tuple(result.predicate_id for result in results) == tuple(
        item.predicate_id for item in ordered
    )
    with pytest.raises(ValueError, match="sorted and unique"):
        api.evaluate_required_predicates(tuple(reversed(ordered)), context)
    with pytest.raises(ValueError, match="sorted and unique"):
        api.evaluate_required_predicates((ordered[0], ordered[0]), context)


@pytest.mark.parametrize(
    ("policy_decision", "execution_status", "test_mode", "include_post"),
    [
        ("deny", "denied", "verifier", False),
        ("allow", "succeeded", "verifier", True),
        ("allow", "failed", "verifier", True),
        ("allow", "succeeded", "developer", False),
    ],
)
def test_action_stage_selector_derives_the_frozen_four_outcome_matrix(
    work_order_dict: dict[str, Any],
    policy_decision: str,
    execution_status: str,
    test_mode: str,
    include_post: bool,
) -> None:
    api = _api()
    work_order = WorkOrder.model_validate(work_order_dict)

    selected = api.select_required_predicates(
        work_order=work_order,
        tool_name="owp.run_tests",
        policy_decision=policy_decision,
        execution_status=execution_status,
        test_mode=test_mode,
    )

    pre_and_invariant = tuple(
        spec
        for spec in work_order.preconditions + work_order.invariants
        if "owp.run_tests" in spec.applies_to_tools
    )
    post = tuple(
        spec
        for spec in work_order.postconditions
        if "owp.run_tests" in spec.applies_to_tools
    )
    expected = pre_and_invariant + (post if include_post else ())
    assert tuple(item.predicate_id for item in selected) == tuple(
        sorted(item.predicate_id for item in expected)
    )


def test_missing_authoritative_input_fails_closed_with_claimed_input() -> None:
    api = _api()
    spec, input_value, _ = _valid_cases()[1]

    result = api.evaluate_predicate(
        spec,
        api.EvaluationContext(inputs={spec.predicate_id: input_value}),
    )

    assert result.passed is False
    assert result.error_code == "FAIL_CLOSED"
    assert result.input.model_dump(mode="json") == input_value


@pytest.mark.parametrize(
    ("case_index", "field_name", "forged_value"),
    [
        (0, "requested_paths", ["src/forged.py"]),
        (
            0,
            "resolved_entries",
            [
                {
                    "requested_path": "src/module.py",
                    "resolved_relative_path": "src/forged.py",
                }
            ],
        ),
        (0, "resolution_manifest_digest", SHA256_B),
        (1, "actual_tool_name", "owp.apply_patch"),
        (3, "command_digest", SHA256_B),
        (3, "expected_exit_code", 1),
        (3, "actual_exit_code", 1),
        (3, "test_evidence_digest", SHA256_B),
        (3, "source_commit", "3" * 40),
        (3, "candidate_commit", "4" * 40),
        (3, "workspace_manifest_digest", SHA256_B),
        (3, "container_image_digest", f"sha256:{SHA256_B}"),
        (3, "fixed_test_source_digest", SHA256_C),
        (4, "artifact_path", "reports/forged.json"),
        (4, "expected_digest", SHA256_B),
        (4, "actual_digest", SHA256_B),
        (4, "size_bytes", 129),
        (4, "workspace_manifest_digest", SHA256_C),
    ],
)
def test_claimed_runtime_input_cannot_replace_sidecar_recomputed_fact(
    case_index: int,
    field_name: str,
    forged_value: Any,
) -> None:
    api = _api()
    spec, authoritative, extras = _valid_cases()[case_index]
    claimed = copy.deepcopy(authoritative)
    claimed[field_name] = forged_value
    if field_name == "requested_paths":
        claimed["resolved_entries"] = [
            {
                "requested_path": "src/forged.py",
                "resolved_relative_path": "src/forged.py",
            }
        ]

    result = api.evaluate_predicate(
        spec,
        api.EvaluationContext(
            inputs={spec.predicate_id: claimed},
            authoritative_inputs={
                spec.predicate_id: copy.deepcopy(authoritative),
            },
            **extras,
        ),
    )

    assert result.passed is False
    assert result.error_code == "FAIL_CLOSED"
    assert result.input.model_dump(mode="json") == claimed


def test_evaluation_context_takes_independent_immutable_snapshots() -> None:
    api = _api()
    spec, input_value, _ = _valid_cases()[1]
    source = {spec.predicate_id: input_value}
    ledger = {SHA256_A: SHA256_B}

    context = api.EvaluationContext(
        inputs=source,
        authoritative_inputs=source,
        authoritative_ledger_prefix_digests=ledger,
    )
    source[spec.predicate_id]["actual_tool_name"] = "owp.apply_patch"
    ledger[SHA256_A] = SHA256_C

    assert context.inputs is not context.authoritative_inputs
    assert context.inputs[spec.predicate_id] is not context.authoritative_inputs[
        spec.predicate_id
    ]
    assert context.inputs[spec.predicate_id]["actual_tool_name"] == "owp.repo_read"
    assert (
        context.authoritative_inputs[spec.predicate_id]["actual_tool_name"]
        == "owp.repo_read"
    )
    assert context.authoritative_ledger_prefix_digests[SHA256_A] == SHA256_B
    with pytest.raises(TypeError):
        context.inputs[spec.predicate_id]["actual_tool_name"] = "owp.apply_patch"

    result = api.evaluate_predicate(spec, context)
    assert result.passed is True
