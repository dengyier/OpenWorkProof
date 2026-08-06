from __future__ import annotations

import base64
import copy
import hashlib
import json

import pytest
import rfc8785
from pydantic import BaseModel, TypeAdapter, ValidationError

import openworkproof.models as contract_models
from conftest import (
    ALL_TOOLS,
    FIXED_ENV,
    IMAGE_A,
    SHA256_A,
    SHA256_B,
    SHA256_C,
    SHA256_D,
    SHA256_E,
    VERIFIER_ARGV,
    deterministic_key_binding,
    evidence_artifact,
    jcs_digest,
    make_test_command,
    make_test_profile,
    predicate,
)
from openworkproof.models import (
    BUNDLE_FINALIZATION_GRACE_SECONDS,
    ApprovalGate,
    Artifact,
    CapabilityGrant,
    Command,
    EvidencePolicy,
    FixedTestSource,
    FrozenDict,
    KeyBinding,
    PolicyDecision,
    PredicateResult,
    PredicateSpec,
    ProtocolModel,
    ReplayProfile,
    RootGrantTemplate,
    SourceArtifact,
    TestProfile as ContractTestProfile,
    TransitionDecision,
    WorkOrder,
    validate_fixed_test_source_bytes,
)

MANAGER_DIRECT_TOOLS = (
    "owp.activate_root_grant",
    "owp.compose_proof",
    "owp.create_pr_proposal",
    "owp.delegate_grant",
    "owp.request_acceptance",
    "owp.request_pr_proposal",
    "owp.revoke_grant",
    "owp.start_retry",
)


def mutate(source: dict, path: tuple[str | int, ...], value: object) -> dict:
    candidate = copy.deepcopy(source)
    target = candidate
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = value
    return candidate


def recompute_predicate_id(item: dict) -> None:
    item["predicate_id"] = jcs_digest(
        {
            "domain": "openworkproof/predicate-id/v0.1",
            "name": item["name"],
            "version": item["version"],
            "applies_to_tools": item["applies_to_tools"],
            "arguments": item["arguments"],
        }
    )


def recompute_command_digest(profile: dict) -> None:
    profile["command_digest"] = jcs_digest(
        {
            "domain": "openworkproof/test-command/v0.1",
            "command": profile["command"],
        }
    )


def recompute_gate_id(gate: dict) -> None:
    gate["gate_id"] = jcs_digest(
        {
            "domain": "openworkproof/approval-gate-id/v0.1",
            "tool_name": gate["tool_name"],
            "required_role": gate["required_role"],
            "max_validity_seconds": gate["max_validity_seconds"],
            "scope_schema": gate["scope_schema"],
        }
    )


def recompute_replay_digest(work_order: dict) -> None:
    work_order["replay_profile_digest"] = jcs_digest(
        {
            "domain": "openworkproof/replay-profile/v0.1",
            "profile": work_order["replay_profile"],
        }
    )


def assert_rejected(model: type[ProtocolModel], value: dict) -> None:
    with pytest.raises(ValidationError):
        model.model_validate(value)


def test_complete_work_order_and_grants_validate_and_freeze_arrays(
    work_order_dict: dict,
    root_grant_dict: dict,
    child_grant_dict: dict,
) -> None:
    work_order = WorkOrder.model_validate(work_order_dict)
    root = CapabilityGrant.model_validate(root_grant_dict)
    child = CapabilityGrant.model_validate(child_grant_dict)

    assert work_order.protocol_version == "0.1"
    assert len(work_order.evidence_policy.artifacts) == 9
    assert isinstance(work_order.allowed_tools, tuple)
    assert isinstance(work_order.preconditions, tuple)
    assert root.parent_grant_id is None
    assert child.usage_mode == "metered"
    with pytest.raises(ValidationError):
        child.quota.tool_calls = 11


def test_protocol_json_objects_are_deeply_immutable_and_dump_as_objects(
    work_order_dict: dict,
) -> None:
    work_order = WorkOrder.model_validate(work_order_dict)

    with pytest.raises(TypeError):
        work_order.test_profiles[0].command.env["PATH"] = "/tmp/attacker"
    with pytest.raises(TypeError):
        work_order.preconditions[0].arguments["runtime_override"] = "x"
    with pytest.raises(TypeError):
        work_order.test_profiles[0].command.env._data["HOME"] = "/tmp"
    with pytest.raises(TypeError):
        work_order.test_profiles[0].command.env._data = {"HOME": "/tmp"}

    dumped = work_order.model_dump(mode="json")
    assert dumped["test_profiles"][0]["command"]["env"] == FIXED_ENV
    assert isinstance(dumped["preconditions"][0]["arguments"], dict)
    assert jcs_digest(dumped["preconditions"][0]["arguments"]) == jcs_digest(
        work_order_dict["preconditions"][0]["arguments"]
    )


def test_nested_base_models_are_not_strict_json_values(
    work_order_dict: dict,
) -> None:
    class MutablePayload(BaseModel):
        value: dict[str, int]

    payload = MutablePayload(value={"a": 1})
    spec = copy.deepcopy(work_order_dict["preconditions"][0])
    spec["arguments"] = {"payload": payload}
    spec["predicate_id"] = jcs_digest(
        {
            "domain": "openworkproof/predicate-id/v0.1",
            "name": spec["name"],
            "version": spec["version"],
            "applies_to_tools": spec["applies_to_tools"],
            "arguments": {"payload": payload.model_dump()},
        }
    )
    assert_rejected(PredicateSpec, spec)


def test_frozen_dict_direct_validation_recursively_freezes_values() -> None:
    mutable_list: list[str] = []
    parsed = TypeAdapter(FrozenDict).validate_python(
        FrozenDict({"value": mutable_list})
    )

    mutable_list.append("attacker")
    assert parsed["value"] == ()
    with pytest.raises(TypeError):
        parsed["value"][0:0] = ("attacker",)


def test_frozen_dict_nested_maps_are_frozen_in_one_linear_pass(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    value: object = 0
    depth = 14
    for _ in range(depth):
        value = {"x": value}

    calls = 0
    original = contract_models._freeze_json

    def counted_freeze(
        item: object, current_depth: int = 1, *, freeze_mapping: bool = True
    ) -> object:
        nonlocal calls
        calls += 1
        return original(
            item, current_depth, freeze_mapping=freeze_mapping
        )

    monkeypatch.setattr(contract_models, "_freeze_json", counted_freeze)
    parsed = FrozenDict({"root": value})

    assert parsed["root"]["x"] is not None
    assert calls <= (depth + 2) * 2


def test_closed_top_level_key_sets_match_v01_exactly() -> None:
    assert set(WorkOrder.model_fields) == {
        "work_order_id",
        "protocol_version",
        "issuer_id",
        "signer_key_id",
        "acceptor_key_ids",
        "objective",
        "preconditions",
        "invariants",
        "repository",
        "branch",
        "allowed_read_roots",
        "allowed_write_roots",
        "source_commit",
        "source_artifact",
        "patch_profile_id",
        "replay_profile",
        "replay_profile_digest",
        "test_profiles",
        "allowed_tools",
        "quota_ceiling",
        "deadline",
        "retention_until",
        "acceptance_criteria",
        "postconditions",
        "approval_gates",
        "required_evidence_dimensions",
        "independence_policy",
        "evidence_policy",
        "root_grant_template",
        "key_bindings",
        "issued_at",
        "digest",
        "signature_alg",
        "signature",
    }
    assert set(CapabilityGrant.model_fields) == {
        "grant_id",
        "work_order_digest",
        "parent_grant_id",
        "issuer_key_id",
        "subject_agent_id",
        "subject_key_id",
        "allowed_tools",
        "allowed_read_roots",
        "allowed_write_roots",
        "usage_mode",
        "quota",
        "valid_from",
        "expires_at",
        "may_delegate",
        "issued_at",
        "digest",
        "signature_alg",
        "signer_key_id",
        "signature",
    }


def test_unknown_protocol_version_is_rejected(work_order_dict: dict) -> None:
    assert_rejected(WorkOrder, mutate(work_order_dict, ("protocol_version",), "0.2"))


def test_negative_child_quota_is_rejected(child_grant_dict: dict) -> None:
    assert_rejected(
        CapabilityGrant,
        mutate(child_grant_dict, ("quota", "tool_calls"), -1),
    )


@pytest.mark.parametrize("model_name", ["work_order", "grant"])
def test_signed_top_level_models_forbid_extra_fields(
    model_name: str,
    work_order_dict: dict,
    child_grant_dict: dict,
) -> None:
    model, value = (
        (WorkOrder, work_order_dict)
        if model_name == "work_order"
        else (CapabilityGrant, child_grant_dict)
    )
    assert_rejected(model, {**value, "unexpected": "field"})


@pytest.mark.parametrize("model_name", ["work_order", "grant"])
def test_signed_top_level_models_require_every_field(
    model_name: str,
    work_order_dict: dict,
    child_grant_dict: dict,
) -> None:
    model, value, missing = (
        (WorkOrder, work_order_dict, "objective")
        if model_name == "work_order"
        else (CapabilityGrant, child_grant_dict, "quota")
    )
    candidate = copy.deepcopy(value)
    del candidate[missing]
    assert_rejected(model, candidate)


@pytest.mark.parametrize("bad_value", [True, 1.0, "1", -1, 9007199254740992])
def test_quota_uses_strict_safe_non_negative_json_integers(
    child_grant_dict: dict, bad_value: object
) -> None:
    assert_rejected(
        CapabilityGrant,
        mutate(child_grant_dict, ("quota", "tool_calls"), bad_value),
    )


@pytest.mark.parametrize("bad_value", [True, 1.0, "1", 0, 9007199254740992])
def test_positive_integer_fields_are_strict_and_safe(
    work_order_dict: dict, bad_value: object
) -> None:
    assert_rejected(
        WorkOrder,
        mutate(work_order_dict, ("source_artifact", "size_bytes"), bad_value),
    )


@pytest.mark.parametrize(
    "bad_time",
    [
        "2026-01-01T00:00:00+00:00",
        "2026-01-01T08:00:00+08:00",
        "2026-01-01T00:00:00.000Z",
        "2026-01-01t00:00:00Z",
        "2026-01-01T00:00:00z",
        "2026-01-01T00:00:60Z",
        "1969-12-31T23:59:59Z",
        1767225600,
        True,
    ],
)
def test_time_parser_accepts_only_canonical_utc_seconds(
    child_grant_dict: dict, bad_time: object
) -> None:
    assert_rejected(
        CapabilityGrant,
        mutate(child_grant_dict, ("issued_at",), bad_time),
    )


def test_grant_own_time_window_is_strict(child_grant_dict: dict) -> None:
    CapabilityGrant.model_validate(
        mutate(
            child_grant_dict,
            ("valid_from",),
            child_grant_dict["issued_at"],
        )
    )
    assert_rejected(
        CapabilityGrant,
        mutate(
            child_grant_dict,
            ("valid_from",),
            "2026-01-01T00:00:00Z",
        ),
    )
    assert_rejected(
        CapabilityGrant,
        mutate(
            child_grant_dict,
            ("expires_at",),
            child_grant_dict["valid_from"],
        ),
    )


def test_work_order_time_boundaries_are_exact(work_order_dict: dict) -> None:
    assert BUNDLE_FINALIZATION_GRACE_SECONDS == 3600
    assert_rejected(
        WorkOrder,
        mutate(work_order_dict, ("deadline",), work_order_dict["issued_at"]),
    )
    assert_rejected(
        WorkOrder,
        mutate(work_order_dict, ("retention_until",), "2026-01-02T00:59:59Z"),
    )
    WorkOrder.model_validate(
        mutate(work_order_dict, ("retention_until",), "2026-01-02T01:00:00Z")
    )


@pytest.mark.parametrize(
    ("field", "limit"),
    [
        ("objective", 4096),
        ("acceptance_criteria", 4096),
        ("repository", 1024),
        ("branch", 255),
    ],
)
def test_display_strings_are_non_empty_and_byte_bounded(
    work_order_dict: dict, field: str, limit: int
) -> None:
    assert_rejected(WorkOrder, mutate(work_order_dict, (field,), ""))
    WorkOrder.model_validate(mutate(work_order_dict, (field,), "é" * (limit // 2)))
    assert_rejected(
        WorkOrder,
        mutate(work_order_dict, (field,), "é" * (limit // 2 + 1)),
    )


def test_generic_array_and_map_limit_is_64() -> None:
    adapter = TypeAdapter(FrozenDict)
    adapter.validate_python({f"k{i:02d}": i for i in range(64)})
    with pytest.raises(ValidationError):
        adapter.validate_python({f"k{i:02d}": i for i in range(65)})

    parsed = adapter.validate_python({"values": list(range(64))})
    assert isinstance(parsed["values"], tuple)
    with pytest.raises(ValidationError):
        adapter.validate_python({"values": list(range(65))})


@pytest.mark.parametrize(
    ("accepted", "rejected"),
    [
        ("x" * 4096, "x" * 4097),
        ("é" * 2048, "é" * 2048 + "x"),
    ],
)
def test_generic_json_strings_are_bounded_by_utf8_bytes(
    accepted: str, rejected: str
) -> None:
    adapter = TypeAdapter(FrozenDict)
    adapter.validate_python({"value": accepted})
    with pytest.raises(ValidationError):
        adapter.validate_python({"value": rejected})


def test_quota_shape_is_closed(work_order_dict: dict, child_grant_dict: dict) -> None:
    assert_rejected(
        WorkOrder,
        mutate(work_order_dict, ("quota_ceiling", "tokens"), 1),
    )
    assert_rejected(
        CapabilityGrant,
        mutate(child_grant_dict, ("quota", "tokens"), 1),
    )


def test_root_and_child_grant_structures_are_distinct(
    root_grant_dict: dict, child_grant_dict: dict
) -> None:
    for path, value in [
        (("usage_mode",), "single_use"),
        (("may_delegate",), False),
        (("quota", "tool_calls"), 0),
        (("quota", "repair_rounds"), 2),
    ]:
        assert_rejected(CapabilityGrant, mutate(root_grant_dict, path, value))

    for path, value in [
        (("may_delegate",), True),
        (("quota", "tool_calls"), 0),
        (("quota", "repair_rounds"), 1),
    ]:
        assert_rejected(CapabilityGrant, mutate(child_grant_dict, path, value))


def test_grant_usage_mode_and_signer_are_closed(child_grant_dict: dict) -> None:
    assert_rejected(
        CapabilityGrant, mutate(child_grant_dict, ("usage_mode",), "unlimited")
    )
    assert_rejected(
        CapabilityGrant,
        mutate(child_grant_dict, ("signer_key_id",), f"ed25519:{SHA256_A}"),
    )


def test_allowed_tools_are_closed_sorted_and_unique(child_grant_dict: dict) -> None:
    assert_rejected(
        CapabilityGrant,
        mutate(child_grant_dict, ("allowed_tools",), ["owp.unknown"]),
    )
    assert_rejected(
        CapabilityGrant,
        mutate(
            child_grant_dict,
            ("allowed_tools",),
            list(reversed(child_grant_dict["allowed_tools"])),
        ),
    )
    assert_rejected(
        CapabilityGrant,
        mutate(
            child_grant_dict,
            ("allowed_tools",),
            child_grant_dict["allowed_tools"] + ["owp.run_tests"],
        ),
    )


def test_approval_gate_is_exactly_one_and_derived(work_order_dict: dict) -> None:
    assert_rejected(WorkOrder, mutate(work_order_dict, ("approval_gates",), []))
    assert_rejected(
        WorkOrder,
        mutate(
            work_order_dict,
            ("approval_gates",),
            work_order_dict["approval_gates"] * 2,
        ),
    )
    gate = copy.deepcopy(work_order_dict["approval_gates"][0])
    gate["max_validity_seconds"] = 3601
    recompute_gate_id(gate)
    assert_rejected(ApprovalGate, gate)
    gate = copy.deepcopy(work_order_dict["approval_gates"][0])
    gate["gate_id"] = SHA256_A
    assert_rejected(ApprovalGate, gate)
    gate = copy.deepcopy(work_order_dict["approval_gates"][0])
    gate["scope_schema"] = "openworkproof/other/0.1"
    recompute_gate_id(gate)
    assert_rejected(ApprovalGate, gate)


def test_predicate_id_sorting_uniqueness_and_closed_tools(
    work_order_dict: dict,
) -> None:
    spec = copy.deepcopy(work_order_dict["preconditions"][0])
    spec["predicate_id"] = SHA256_A
    assert_rejected(PredicateSpec, spec)
    spec = copy.deepcopy(work_order_dict["preconditions"][0])
    spec["applies_to_tools"] = list(reversed(spec["applies_to_tools"]))
    recompute_predicate_id(spec)
    assert_rejected(PredicateSpec, spec)
    spec = copy.deepcopy(work_order_dict["preconditions"][0])
    spec["applies_to_tools"] = ["owp.delegate_grant"]
    recompute_predicate_id(spec)
    assert_rejected(PredicateSpec, spec)

    candidate = copy.deepcopy(work_order_dict)
    candidate["preconditions"] = list(reversed(candidate["preconditions"]))
    assert_rejected(WorkOrder, candidate)
    candidate = copy.deepcopy(work_order_dict)
    candidate["invariants"] = [copy.deepcopy(candidate["preconditions"][0])]
    candidate["invariants"].sort(key=lambda item: item["predicate_id"])
    assert_rejected(WorkOrder, candidate)


def test_applicable_predicate_union_cannot_exceed_64(
    work_order_dict: dict,
) -> None:
    candidate = copy.deepcopy(work_order_dict)
    candidate["preconditions"] = [
        predicate(
            "tool_allowed",
            ["owp.run_tests"],
            {"partition": "pre", "ordinal": ordinal},
        )
        for ordinal in range(32)
    ]
    candidate["invariants"] = [
        predicate(
            "tool_allowed",
            ["owp.run_tests"],
            {"partition": "invariant", "ordinal": ordinal},
        )
        for ordinal in range(32)
    ]
    candidate["preconditions"].sort(key=lambda item: item["predicate_id"])
    candidate["invariants"].sort(key=lambda item: item["predicate_id"])
    assert_rejected(WorkOrder, candidate)


@pytest.mark.parametrize(
    ("partition", "bad_name"),
    [
        ("preconditions", "tests_passed"),
        ("invariants", "quota_remaining"),
        ("postconditions", "tool_allowed"),
        ("preconditions", "human_signature_present"),
    ],
)
def test_predicate_placement_is_closed(
    work_order_dict: dict, partition: str, bad_name: str
) -> None:
    candidate = copy.deepcopy(work_order_dict)
    item = candidate[partition][0]
    item["name"] = bad_name
    recompute_predicate_id(item)
    candidate[partition].sort(key=lambda value: value["predicate_id"])
    assert_rejected(WorkOrder, candidate)


def test_postconditions_are_verifier_only_and_require_one_tests_passed(
    work_order_dict: dict,
) -> None:
    assert_rejected(WorkOrder, mutate(work_order_dict, ("postconditions",), []))
    candidate = copy.deepcopy(work_order_dict)
    item = candidate["postconditions"][0]
    item["applies_to_tools"] = ["owp.apply_patch"]
    recompute_predicate_id(item)
    assert_rejected(WorkOrder, candidate)
    candidate = copy.deepcopy(work_order_dict)
    item = candidate["postconditions"][0]
    item["arguments"]["expected_exit_code"] = 1
    recompute_predicate_id(item)
    assert_rejected(WorkOrder, candidate)


def test_predicate_result_recomputes_input_digest_and_error_pairing(
    work_order_dict: dict,
) -> None:
    spec = next(
        item
        for item in work_order_dict["preconditions"]
        if item["name"] == "path_allowed"
    )
    input_value = {
        "requested_paths": ["src/a.py"],
        "resolved_entries": [
            {
                "requested_path": "src/a.py",
                "resolved_relative_path": "src/a.py",
            }
        ],
        "resolution_manifest_digest": SHA256_B,
    }
    result = {
        "predicate_id": spec["predicate_id"],
        "name": spec["name"],
        "version": spec["version"],
        "arguments_digest": jcs_digest(spec["arguments"]),
        "input": input_value,
        "input_digest": jcs_digest(
            {
                "domain": "openworkproof/predicate-input/v0.1",
                "predicate_id": spec["predicate_id"],
                "input": input_value,
            }
        ),
        "passed": True,
        "error_code": None,
    }
    parsed = PredicateResult.model_validate(result)
    parsed_spec = PredicateSpec.model_validate(spec)
    assert parsed.matches_spec(parsed_spec)
    assert parsed.validate_against(parsed_spec) is parsed
    with pytest.raises(TypeError):
        parsed.input["requested_paths"] = ["other.py"]
    assert_rejected(PredicateResult, {**result, "name": "other_predicate"})
    for field, value in [
        ("version", "0.2"),
        ("arguments_digest", SHA256_A),
    ]:
        mismatched = PredicateResult.model_validate({**result, field: value})
        with pytest.raises(ValueError, match="does not match"):
            mismatched.validate_against(parsed_spec)
    assert_rejected(PredicateResult, {**result, "input_digest": SHA256_A})
    assert_rejected(
        PredicateResult, {**result, "passed": False, "error_code": None}
    )
    assert_rejected(
        PredicateResult,
        {**result, "passed": True, "error_code": "PREDICATE_FALSE"},
    )
    failed = {**result, "passed": False, "error_code": "FAIL_CLOSED"}
    PredicateResult.model_validate(failed)


@pytest.mark.parametrize(
    "bad_root",
    [
        "",
        "/src",
        "src/",
        "src//x",
        "src/./x",
        "src/../x",
        r"src\x",
        "src/*",
        ".git",
        ".git/config",
        "src/é",
    ],
)
def test_roots_use_canonical_relative_posix_grammar(
    child_grant_dict: dict, bad_root: str
) -> None:
    assert_rejected(
        CapabilityGrant,
        mutate(child_grant_dict, ("allowed_read_roots",), [bad_root]),
    )


def test_roots_are_sorted_unique_and_write_is_within_read(
    child_grant_dict: dict,
) -> None:
    assert_rejected(
        CapabilityGrant,
        mutate(child_grant_dict, ("allowed_read_roots",), ["tests", "src"]),
    )
    assert_rejected(
        CapabilityGrant,
        mutate(child_grant_dict, ("allowed_read_roots",), ["src", "src"]),
    )
    assert_rejected(
        CapabilityGrant,
        mutate(child_grant_dict, ("allowed_write_roots",), ["src2"]),
    )
    CapabilityGrant.model_validate(
        mutate(child_grant_dict, ("allowed_write_roots",), ["src/pkg"])
    )
    verifier = copy.deepcopy(child_grant_dict)
    verifier["allowed_read_roots"] = ["tests"]
    verifier["allowed_write_roots"] = []
    verifier["allowed_tools"] = ["owp.run_tests"]
    CapabilityGrant.model_validate(verifier)


def test_evidence_dimensions_and_policy_are_bijective(work_order_dict: dict) -> None:
    candidate = copy.deepcopy(work_order_dict)
    candidate["required_evidence_dimensions"] = [
        "authority",
        "scope",
        "result",
        "execution",
        "independent_result",
    ]
    assert_rejected(WorkOrder, candidate)
    candidate = copy.deepcopy(work_order_dict)
    candidate["required_evidence_dimensions"] = [
        "authority",
        "scope",
        "execution",
        "result",
    ]
    candidate["independence_policy"] = "independent_test_source_required"
    assert_rejected(WorkOrder, candidate)
    candidate = copy.deepcopy(work_order_dict)
    candidate["required_evidence_dimensions"] = [
        "authority",
        "scope",
        "execution",
        "result",
    ]
    candidate["independence_policy"] = "disclose_only"
    candidate["evidence_policy"]["artifacts"] = [
        item
        for item in candidate["evidence_policy"]["artifacts"]
        if item["purpose"] != "verifier_independent_result"
    ]
    WorkOrder.model_validate(candidate)


def test_command_shape_env_argv_and_digest_are_closed() -> None:
    command = make_test_command(["/usr/bin/python", "-m", "pytest"])
    parsed = Command.model_validate(command)
    assert isinstance(parsed.argv, tuple)
    assert_rejected(Command, {**command, "shell": False})
    assert_rejected(Command, {**command, "working_directory": "."})
    assert_rejected(Command, {**command, "env": {**FIXED_ENV, "PATH": "/bin"}})
    assert_rejected(Command, {**command, "argv": ["python", "-V"]})
    assert_rejected(Command, {**command, "argv": ["/bin/x"] * 17})
    assert_rejected(Command, {**command, "argv": ["/bin/sh", "-c", "pytest"]})
    assert_rejected(Command, {**command, "argv": ["/usr/bin/env", "python", "-V"]})

    profile = make_test_profile(
        "developer", fixed=False, argv=["/usr/bin/python", "-V"]
    )
    profile["command_digest"] = SHA256_A
    assert_rejected(ContractTestProfile, profile)


def test_developer_and_verifier_profiles_are_closed() -> None:
    developer = make_test_profile(
        "developer", fixed=False, argv=["/usr/bin/python", "-m", "pytest"]
    )
    verifier = make_test_profile("verifier", fixed=True)
    ContractTestProfile.model_validate(developer)
    ContractTestProfile.model_validate(verifier)

    assert_rejected(
        ContractTestProfile,
        {**developer, "fixed_test_source_digest": SHA256_B},
    )
    assert_rejected(
        ContractTestProfile,
        mutate(verifier, ("command", "argv"), ["/bin/true"]),
    )
    assert_rejected(
        ContractTestProfile,
        {**verifier, "fixed_test_source_digest": SHA256_A},
    )
    assert_rejected(
        FixedTestSource,
        {
            **verifier["fixed_test_source"],
            "path": "fixed-tests/other.py",
        },
    )
    assert_rejected(
        FixedTestSource,
        {
            **verifier["fixed_test_source"],
            "size_bytes": 65537,
        },
    )


def test_fixed_test_source_exact_bytes_are_verified() -> None:
    valid_bytes = b"x" * 65_535 + b"\n"
    valid_source = FixedTestSource(
        path="fixed-tests/verifier_test.py",
        media_type="text/x-python",
        sha256=hashlib.sha256(valid_bytes).hexdigest(),
        size_bytes=len(valid_bytes),
    )
    assert (
        validate_fixed_test_source_bytes(valid_source, valid_bytes) is valid_source
    )

    for invalid_bytes in [
        b"\xef\xbb\xbftest\n",
        b"test\x00value\n",
        b"test\r\n",
        b"test",
    ]:
        source = FixedTestSource(
            path="fixed-tests/verifier_test.py",
            media_type="text/x-python",
            sha256=hashlib.sha256(invalid_bytes).hexdigest(),
            size_bytes=len(invalid_bytes),
        )
        with pytest.raises(ValueError):
            validate_fixed_test_source_bytes(source, invalid_bytes)

    with pytest.raises(ValidationError):
        FixedTestSource(
            path="fixed-tests/verifier_test.py",
            media_type="text/x-python",
            sha256=hashlib.sha256(b"x" * 65_536 + b"\n").hexdigest(),
            size_bytes=65_537,
        )
    with pytest.raises(ValueError, match="size"):
        validate_fixed_test_source_bytes(
            valid_source.model_copy(update={"size_bytes": len(valid_bytes) - 1}),
            valid_bytes,
        )
    with pytest.raises(ValueError, match="SHA-256"):
        validate_fixed_test_source_bytes(
            valid_source.model_copy(update={"sha256": SHA256_A}),
            valid_bytes,
        )
    with pytest.raises(ValueError, match="bytes"):
        validate_fixed_test_source_bytes(valid_source, "not bytes")


def test_work_order_test_profiles_are_unique_and_ordered(
    work_order_dict: dict,
) -> None:
    verifier = work_order_dict["test_profiles"][0]
    developer = make_test_profile(
        "developer", fixed=False, argv=["/usr/bin/python", "-m", "pytest"]
    )
    candidate_without_slot = mutate(
        work_order_dict, ("test_profiles",), [developer, verifier]
    )
    assert_rejected(WorkOrder, candidate_without_slot)
    candidate = copy.deepcopy(candidate_without_slot)
    developer_slot = evidence_artifact(
        "developer_test_result",
        1,
        media_type="application/json",
        dimension="execution",
        suffix="json",
    )
    candidate["evidence_policy"]["artifacts"].insert(6, developer_slot)
    WorkOrder.model_validate(candidate)
    assert_rejected(
        WorkOrder, mutate(work_order_dict, ("test_profiles",), [developer])
    )
    assert_rejected(
        WorkOrder, mutate(work_order_dict, ("test_profiles",), [verifier, developer])
    )
    assert_rejected(
        WorkOrder, mutate(work_order_dict, ("test_profiles",), [verifier, verifier])
    )


def test_source_artifact_and_replay_profile_are_closed_and_bound(
    work_order_dict: dict,
) -> None:
    SourceArtifact.model_validate(work_order_dict["source_artifact"])
    ReplayProfile.model_validate(work_order_dict["replay_profile"])
    assert_rejected(
        SourceArtifact,
        {**work_order_dict["source_artifact"], "path": "source/other.zip"},
    )
    assert_rejected(
        SourceArtifact,
        {**work_order_dict["source_artifact"], "size_bytes": 8 * 1024 * 1024 + 1},
    )
    candidate = copy.deepcopy(work_order_dict)
    candidate["replay_profile"]["source_artifact_sha256"] = SHA256_B
    recompute_replay_digest(candidate)
    assert_rejected(WorkOrder, candidate)
    candidate = copy.deepcopy(work_order_dict)
    candidate["replay_profile"]["author_name"] = "Someone else"
    recompute_replay_digest(candidate)
    assert_rejected(WorkOrder, candidate)
    assert_rejected(
        WorkOrder,
        mutate(work_order_dict, ("replay_profile_digest",), SHA256_A),
    )


def test_artifact_binding_paths_and_sizes_are_closed(
    demo_evidence_artifacts: list[dict],
) -> None:
    Artifact.model_validate(demo_evidence_artifacts[0])
    bad = copy.deepcopy(demo_evidence_artifacts[0])
    bad["media_type"] = "application/json"
    assert_rejected(Artifact, bad)
    bad = copy.deepcopy(demo_evidence_artifacts[0])
    bad["max_size_bytes"] = 65537
    assert_rejected(Artifact, bad)
    for path in [
        "/patch/1.diff",
        "patch//1.diff",
        "patch/../1.diff",
        "evidence/patch.diff",
        ".pending/patch.diff",
        "manifest.json",
        "patch/*.diff",
        "é.diff",
    ]:
        bad = copy.deepcopy(demo_evidence_artifacts[0])
        bad["path"] = path
        assert_rejected(Artifact, bad)


def test_evidence_inventory_counts_pairs_order_and_uniqueness(
    work_order_dict: dict,
) -> None:
    artifacts = work_order_dict["evidence_policy"]["artifacts"]
    EvidencePolicy.model_validate(work_order_dict["evidence_policy"])

    for index in [0, 1, 2, 4, 6]:
        candidate = copy.deepcopy(work_order_dict["evidence_policy"])
        candidate["artifacts"].pop(index)
        assert_rejected(EvidencePolicy, candidate)
    candidate = copy.deepcopy(work_order_dict)
    candidate["evidence_policy"]["artifacts"].pop(8)
    assert_rejected(WorkOrder, candidate)

    candidate = copy.deepcopy(work_order_dict["evidence_policy"])
    candidate["artifacts"] = list(reversed(candidate["artifacts"]))
    assert_rejected(EvidencePolicy, candidate)
    for field in ["name", "path"]:
        candidate = copy.deepcopy(work_order_dict["evidence_policy"])
        candidate["artifacts"][1][field] = candidate["artifacts"][0][field]
        assert_rejected(EvidencePolicy, candidate)
    candidate = copy.deepcopy(work_order_dict["evidence_policy"])
    candidate["artifacts"][2]["ordinal"] = 3
    assert_rejected(EvidencePolicy, candidate)

    candidate = copy.deepcopy(work_order_dict["evidence_policy"])
    candidate["artifacts"][0]["max_size_bytes"] = 8 * 1024 * 1024
    assert_rejected(EvidencePolicy, candidate)
    assert len(artifacts) == 9


def test_evidence_policy_inventory_global_size_limit(
    work_order_dict: dict,
) -> None:
    candidate = copy.deepcopy(work_order_dict["evidence_policy"])
    for item in candidate["artifacts"]:
        if item["purpose"] not in {"patch_input", "patch_denial_audit"}:
            item["max_size_bytes"] = 8 * 1024 * 1024
    assert_rejected(EvidencePolicy, candidate)


def test_key_bindings_are_exact_order_unique_and_cryptographically_bound(
    work_order_dict: dict,
) -> None:
    KeyBinding.model_validate(work_order_dict["key_bindings"][0])
    candidate = copy.deepcopy(work_order_dict)
    candidate["key_bindings"] = list(reversed(candidate["key_bindings"]))
    assert_rejected(WorkOrder, candidate)
    candidate = copy.deepcopy(work_order_dict)
    candidate["key_bindings"][1]["key_id"] = candidate["key_bindings"][0]["key_id"]
    assert_rejected(WorkOrder, candidate)

    binding = copy.deepcopy(work_order_dict["key_bindings"][0])
    binding["key_id"] = f"ed25519:{SHA256_A}"
    assert_rejected(KeyBinding, binding)
    binding = copy.deepcopy(work_order_dict["key_bindings"][0])
    binding["public_key_b64url"] += "="
    assert_rejected(KeyBinding, binding)
    binding = copy.deepcopy(work_order_dict["key_bindings"][0])
    raw = b"\x01" * 31
    binding["public_key_b64url"] = (
        base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    )
    assert_rejected(KeyBinding, binding)


def test_work_order_maintainer_is_sole_issuer_signer_and_acceptor(
    work_order_dict: dict,
) -> None:
    manager = work_order_dict["key_bindings"][1]
    assert_rejected(
        WorkOrder, mutate(work_order_dict, ("issuer_id",), manager["subject_id"])
    )
    assert_rejected(
        WorkOrder, mutate(work_order_dict, ("signer_key_id",), manager["key_id"])
    )
    assert_rejected(
        WorkOrder, mutate(work_order_dict, ("acceptor_key_ids",), [manager["key_id"]])
    )


def test_work_order_binds_distinct_acceptor(
    work_order_dict: dict,
    key_bindings: list[dict],
) -> None:
    acceptor = deterministic_key_binding("Acceptor", "acceptor-local", 6)
    candidate = copy.deepcopy(work_order_dict)
    candidate["key_bindings"] = [*key_bindings[:5], acceptor]
    candidate["acceptor_key_ids"] = [acceptor["key_id"]]

    parsed = contract_models.WorkOrder.model_validate(candidate)

    assert parsed.key_bindings[-1].role == "Acceptor"
    assert parsed.acceptor_key_ids == (acceptor["key_id"],)


def test_work_order_rejects_acceptor_alias_of_another_role(
    work_order_dict: dict,
    key_bindings: list[dict],
) -> None:
    # Acceptor must not reuse the Maintainer subject or key.
    for acceptor in (
        key_bindings[0],
        deterministic_key_binding("Acceptor", "maintainer", 1),
    ):
        candidate = copy.deepcopy(work_order_dict)
        candidate["key_bindings"] = [*key_bindings[:5], acceptor]
        candidate["acceptor_key_ids"] = [acceptor["key_id"]]
        assert_rejected(WorkOrder, candidate)


def test_root_grant_template_is_closed_and_bound_to_work_order(
    work_order_dict: dict,
) -> None:
    RootGrantTemplate.model_validate(work_order_dict["root_grant_template"])
    for extra in ["digest", "signature", "work_order_digest", "signer_key_id"]:
        assert_rejected(
            RootGrantTemplate,
            {**work_order_dict["root_grant_template"], extra: SHA256_A},
        )
    assert_rejected(
        WorkOrder,
        mutate(
            work_order_dict,
            ("root_grant_template", "issued_at"),
            "2026-01-01T00:00:01Z",
        ),
    )
    for tool_name in MANAGER_DIRECT_TOOLS:
        candidate = copy.deepcopy(work_order_dict)
        candidate["root_grant_template"]["allowed_tools"].remove(tool_name)
        assert_rejected(WorkOrder, candidate)
    assert_rejected(
        WorkOrder,
        mutate(
            work_order_dict,
            ("root_grant_template", "expires_at"),
            "2026-01-01T23:59:59Z",
        ),
    )
    assert_rejected(
        WorkOrder,
        mutate(
            work_order_dict,
            ("root_grant_template", "quota", "tool_calls"),
            101,
        ),
    )
    assert_rejected(
        WorkOrder,
        mutate(
            work_order_dict,
            ("root_grant_template", "allowed_write_roots"),
            ["other"],
        ),
    )


def test_signed_identifiers_digests_and_key_ids_are_closed(
    child_grant_dict: dict,
) -> None:
    for path, value in [
        (("grant_id",), "A" * 64),
        (("digest",), "a" * 63),
        (("work_order_digest",), "g" * 64),
        (("signature_alg",), "ed25519"),
        (("issuer_key_id",), SHA256_A),
    ]:
        assert_rejected(CapabilityGrant, mutate(child_grant_dict, path, value))


def test_policy_and_transition_decisions_are_immutable_and_closed() -> None:
    allow = PolicyDecision(
        allowed=True, decision="allow", error_code=None, reason="policy satisfied"
    )
    deny = PolicyDecision(
        allowed=False,
        decision="deny",
        error_code="ROLE_DENIED",
        reason="role is not authorized",
    )
    assert allow.decision == "allow"
    assert deny.decision == "deny"
    with pytest.raises(ValidationError):
        PolicyDecision(
            allowed=True,
            decision="deny",
            error_code="ROLE_DENIED",
            reason="mismatch",
        )
    with pytest.raises(ValidationError):
        allow.reason = "changed"
    assert "signature" not in PolicyDecision.model_fields

    transition = TransitionDecision(
        allowed=False, error_code="INVALID_TRANSITION", reason="not reachable"
    )
    assert transition.allowed is False
    assert "digest" not in TransitionDecision.model_fields
    with pytest.raises(ValidationError):
        transition.reason = "changed"


RECEIPT_SIGNATURE = base64.urlsafe_b64encode(b"\x00" * 64).decode().rstrip("=")


def agent_arguments_digest(tool_name: str, arguments: dict) -> str:
    return jcs_digest(
        {
            "domain": "openworkproof/agent-arguments/v0.1",
            "tool_name": tool_name,
            "arguments": arguments,
        }
    )


def system_input_digest(event_name: str, work_order_digest: str, cause: dict) -> str:
    return jcs_digest(
        {
            "domain": "openworkproof/system-event-input/v0.1",
            "event_name": event_name,
            "work_order_digest": work_order_digest,
            "cause": cause,
        }
    )


def predicate_result_data(
    spec: dict,
    *,
    passed: bool = True,
    error_code: str | None = None,
    input_value: dict | None = None,
) -> dict:
    if input_value is not None:
        value = input_value
    elif spec["name"] == "path_allowed":
        value = {
            "requested_paths": ["src/example.py"],
            "resolved_entries": [
                {
                    "requested_path": "src/example.py",
                    "resolved_relative_path": "src/example.py",
                }
            ],
            "resolution_manifest_digest": SHA256_A,
        }
    elif spec["name"] == "tool_allowed":
        value = {"actual_tool_name": spec["applies_to_tools"][0]}
    elif spec["name"] == "quota_remaining":
        value = {
            "grant_id": SHA256_A,
            "metric": "tool_calls",
            "amount": 1,
            "grant_remaining_before": 1,
            "ledger_prefix_digest": SHA256_B,
        }
    elif spec["name"] == "tests_passed":
        value = {
            "test_mode": "verifier",
            "command_digest": SHA256_A,
            "expected_exit_code": 0,
            "actual_exit_code": 0,
            "test_evidence_digest": SHA256_B,
            "source_commit": "1" * 40,
            "candidate_commit": "2" * 40,
            "workspace_manifest_digest": SHA256_C,
            "container_image_digest": IMAGE_A,
            "fixed_test_source_digest": SHA256_D,
        }
    else:
        value = {
            "artifact_path": "result.json",
            "expected_digest": SHA256_A,
            "actual_digest": SHA256_A,
            "size_bytes": 1,
            "workspace_manifest_digest": SHA256_B,
        }
    return {
        "predicate_id": spec["predicate_id"],
        "name": spec["name"],
        "version": spec["version"],
        "arguments_digest": jcs_digest(spec["arguments"]),
        "input": value,
        "input_digest": jcs_digest(
            {
                "domain": "openworkproof/predicate-input/v0.1",
                "predicate_id": spec["predicate_id"],
                "input": value,
            }
        ),
        "passed": passed,
        "error_code": error_code,
    }


def correlation_data(key_bindings: list[dict], *, started: bool = True) -> dict:
    return {
        "model_id": "model",
        "model_version": "1",
        "prompt_template_digest": SHA256_A,
        "context_source_digest": SHA256_B,
        "toolchain_id": SHA256_C if started else None,
        "execution_context_id": SHA256_D if started else None,
        "container_instance_id_digest": SHA256_E if started else None,
        "controller_id": key_bindings[4]["key_id"],
        "fixed_test_source_digest": None,
    }


def _signed_fields(key_id: str, *, digest: str = SHA256_B) -> dict:
    return {
        "digest": digest,
        "signature_alg": "Ed25519",
        "signer_key_id": key_id,
        "signature": RECEIPT_SIGNATURE,
    }


def agent_claim(
    key_bindings: list[dict],
    *,
    grant_id: str,
    tool_name: str,
    arguments: dict,
) -> dict:
    manager = key_bindings[1]
    return {
        "claim_type": "agent-request",
        "work_order_digest": SHA256_A,
        "grant_id": grant_id,
        "actor_id": manager["subject_id"],
        "actor_key_id": manager["key_id"],
        "tool_name": tool_name,
        "arguments_digest": agent_arguments_digest(tool_name, arguments),
        "nonce": SHA256_C,
        "requested_at": "2026-01-01T00:00:01Z",
        "authentication_method": "agent_signature",
        "model_id": "model",
        "model_version": "1",
        "prompt_template_digest": SHA256_A,
        "context_source_digest": SHA256_B,
        **_signed_fields(manager["key_id"]),
    }


def human_claim(key_bindings: list[dict], *, termination: bool) -> dict:
    maintainer = key_bindings[0]
    common = {
        "claim_type": "human-decision",
        "decision_type": (
            "termination_decision" if termination else "approval_decision"
        ),
        "work_order_digest": SHA256_A,
        "decision": "rejected" if termination else "approved",
        "reason": "MAINTAINER_REJECTED" if termination else "APPROVAL_GRANTED",
        "decided_at": "2026-01-01T00:00:02Z",
        "actor_id": maintainer["subject_id"],
        "actor_key_id": maintainer["key_id"],
        **_signed_fields(maintainer["key_id"]),
    }
    if termination:
        common["target_work_order_digest"] = SHA256_A
    else:
        common.update(
            {
                "request_receipt_id": SHA256_C,
                "request_receipt_digest": SHA256_D,
                "approved_scope": {
                    "work_order_digest": SHA256_A,
                    "operation": "create_local_pr_proposal",
                    "target_patch_digest": SHA256_E,
                },
                "expires_at": "2026-01-01T01:00:00Z",
            }
        )
    return common


def receipt_data(
    event_type: str,
    key_bindings: list[dict],
    *,
    policy_decision: str = "allow",
    execution_status: str = "succeeded",
) -> dict:
    manager = key_bindings[1]
    sidecar = key_bindings[4]
    is_denied = (policy_decision, execution_status) == ("deny", "denied")
    is_failed = execution_status == "failed"
    common = {
        "protocol_version": "0.1",
        "receipt_id": SHA256_A,
        "work_order_digest": SHA256_A,
        "gateway_signer_key_id": sidecar["key_id"],
        "event_type": event_type,
        "policy_decision": policy_decision,
        "policy_error_code": "STATE_DENIED" if is_denied else None,
        "execution_status": execution_status,
        "execution_error_code": "HANDLER_ERROR" if is_failed else None,
        "state_before": "running",
        "state_after": "running",
        "parent_receipt_ids": [],
        "correlation_factors": None,
        "evidence_refs": [],
        "occurred_at": "2026-01-01T00:00:03Z",
        "sequence": 1,
        "nonce": SHA256_C,
        "previous_receipt_digest": None,
        **_signed_fields(sidecar["key_id"], digest=SHA256_D),
    }

    if event_type == "system_event":
        cause = {
            "initiator_receipt_digest": SHA256_B,
            "composition_report_digest": SHA256_C,
            "state_version_before": 0,
        }
        input_digest = system_input_digest("proof_composed", SHA256_A, cause)
        common.update(
            {
                "actor_type": "sidecar",
                "actor_id": sidecar["subject_id"],
                "actor_key_id": sidecar["key_id"],
                "nested_claim_type": "sidecar-event",
                "nested_claim_digest": input_digest,
                "nested_claim": {
                    "claim_type": "sidecar-event",
                    "work_order_digest": SHA256_A,
                    "event_name": "proof_composed",
                    "cause": cause,
                    "input_digest": input_digest,
                    "occurred_at": "2026-01-01T00:00:03Z",
                },
                "system_event_name": "proof_composed",
                "cause": cause,
                "input_digest": input_digest,
                "error_code": None,
                "policy_decision": "not_applicable",
                "policy_error_code": None,
                "execution_status": "succeeded",
                "execution_error_code": None,
                "state_before": "locally_verified",
                "state_after": "proof_ready",
                "quota_charge": None,
            }
        )
        return common

    if event_type in {"approval_decision", "termination_decision"}:
        termination = event_type == "termination_decision"
        claim = human_claim(key_bindings, termination=termination)
        common.update(
            {
                "actor_type": "human",
                "actor_id": claim["actor_id"],
                "actor_key_id": claim["actor_key_id"],
                "nested_claim_type": "human-decision",
                "nested_claim_digest": claim["digest"],
                "nested_claim": claim,
                "quota_charge": None,
            }
        )
        if termination:
            common.update(
                {
                    "target_work_order_digest": SHA256_A,
                    "decision": "rejected",
                    "termination_reason": "MAINTAINER_REJECTED",
                    "decided_at": "2026-01-01T00:00:02Z",
                }
            )
        else:
            common.update(
                {
                    "request_receipt_id": SHA256_C,
                    "request_receipt_digest": SHA256_D,
                    "decision": "approved",
                    "approved_scope": copy.deepcopy(claim["approved_scope"]),
                    "expires_at": "2026-01-01T01:00:00Z",
                    "decision_reason": "APPROVAL_GRANTED",
                    "decided_at": "2026-01-01T00:00:02Z",
                }
            )
        return common

    arguments: dict
    tool_name: str
    grant_id = SHA256_E
    if event_type == "grant_issued":
        arguments = {
            "operation": "delegate_child",
            "authorizing_grant_id": grant_id,
            "candidate_grant_digest": SHA256_B,
        }
        tool_name = "owp.delegate_grant"
        common.update(
            {
                "authorizing_grant_id": grant_id,
                "candidate_grant_digest": SHA256_B,
                "parent_grant_id": grant_id,
            }
        )
        if not is_denied:
            common["issued_grant_id"] = SHA256_C
        common["quota_charge"] = None
    elif event_type == "grant_consumed":
        arguments = {"grant_id": grant_id, "metric": "repair_rounds", "amount": 1}
        tool_name = "owp.start_retry"
        common.update(
            {
                "grant_id": grant_id,
                "metric": "repair_rounds",
                "amount": 1,
                "remaining_after": None if is_denied else 0,
            }
        )
        common["quota_charge"] = (
            None
            if is_denied
            else {
                "grant_id": grant_id,
                "metric": "repair_rounds",
                "amount": 1,
                "remaining_after": 0,
            }
        )
    elif event_type == "grant_revoked":
        arguments = {
            "authorizing_grant_id": grant_id,
            "revoked_grant_id": SHA256_B,
            "revocation_reason": "LEAST_PRIVILEGE",
        }
        tool_name = "owp.revoke_grant"
        common.update(arguments)
        common["quota_charge"] = None
    elif event_type == "tool_call":
        request_arguments = {"path": "src/example.py"}
        arguments = request_arguments
        tool_name = "owp.repo_read"
        output_digest = (
            None
            if is_denied
            else (
                jcs_digest(
                    {"status": "failed", "error_code": "HANDLER_ERROR"}
                )
                if is_failed
                else SHA256_E
            )
        )
        common.update(
            {
                "grant_id": grant_id,
                "tool_name": tool_name,
                "tool_version": "0.1",
                "request_arguments": request_arguments,
                "arguments_digest": agent_arguments_digest(
                    tool_name, request_arguments
                ),
                "output_digest": output_digest,
                "predicate_results": [],
                "correlation_factors": correlation_data(
                    key_bindings, started=not is_denied
                ),
            }
        )
        common["quota_charge"] = (
            None
            if is_denied
            else {
                "grant_id": grant_id,
                "metric": "tool_calls",
                "amount": 1,
                "remaining_after": 9,
            }
        )
    elif event_type == "approval_requested":
        scope = {
            "work_order_digest": SHA256_A,
            "operation": "create_local_pr_proposal",
            "target_patch_digest": SHA256_B,
        }
        arguments = {
            "request_kind": "high_risk_action",
            "target_action_digest": jcs_digest(
                {
                    "domain": "openworkproof/high-risk-action/v0.1",
                    "tool_name": "owp.create_pr_proposal",
                    "requested_scope": scope,
                }
            ),
            "required_role": "Maintainer",
            "requested_scope": scope,
            "expires_at": "2026-01-01T01:00:00Z",
        }
        tool_name = "owp.request_pr_proposal"
        common.update({"grant_id": grant_id, **copy.deepcopy(arguments)})
        common["quota_charge"] = (
            None
            if is_denied
            else {
                "grant_id": grant_id,
                "metric": "tool_calls",
                "amount": 1,
                "remaining_after": 9,
            }
        )
    elif event_type == "rollback":
        arguments = {
            "target_patch_receipt_id": SHA256_B,
            "target_patch_digest": SHA256_C,
            "before_commit": "1" * 40,
        }
        tool_name = "owp.rollback_patch"
        common.update(
            {
                "grant_id": grant_id,
                **arguments,
                "after_commit": "0" * 40 if not (is_denied or is_failed) else "1" * 40,
                "after_manifest_digest": (
                    None if is_denied else SHA256_D
                ),
                "rollback_result": (
                    "denied"
                    if is_denied
                    else ("failed" if is_failed else "succeeded")
                ),
            }
        )
        common["quota_charge"] = (
            None
            if is_denied
            else {
                "grant_id": grant_id,
                "metric": "tool_calls",
                "amount": 1,
                "remaining_after": 9,
            }
        )
    else:
        raise AssertionError(event_type)

    claim = agent_claim(
        key_bindings,
        grant_id=grant_id,
        tool_name=tool_name,
        arguments=arguments,
    )
    common.update(
        {
            "actor_type": "agent",
            "actor_id": claim["actor_id"],
            "actor_key_id": claim["actor_key_id"],
            "nested_claim_type": "agent-request",
            "nested_claim_digest": claim["digest"],
            "nested_claim": claim,
        }
    )
    return common


def acceptance_data(
    key_bindings: list[dict],
    work_order_dict: dict,
) -> dict:
    maintainer = key_bindings[0]
    factors = correlation_data(key_bindings)
    factors["execution_context_id"] = "6" * 64
    factors["container_instance_id_digest"] = "7" * 64
    factors["fixed_test_source_digest"] = SHA256_B
    postcondition = predicate_result_data(work_order_dict["postconditions"][0])
    shared_values = {
        "model": {"model_id": "model", "model_version": "1"},
        "prompt_template": SHA256_A,
        "context_source": SHA256_B,
        "toolchain": SHA256_C,
        "controller": key_bindings[4]["key_id"],
    }
    warning_codes = {
        "model": "SHARED_MODEL",
        "prompt_template": "SHARED_PROMPT_TEMPLATE",
        "context_source": "SHARED_CONTEXT_SOURCE",
        "toolchain": "SHARED_TOOLCHAIN",
        "controller": "SHARED_CONTROLLER",
    }
    warnings = [
        {
            "code": warning_codes[factor],
            "subject_ref": jcs_digest(
                {
                    "domain": "openworkproof/shared-factor-ref/v0.1",
                    "factor": factor,
                    "value": value,
                }
            ),
        }
        for factor, value in shared_values.items()
    ]
    warnings.sort(key=lambda item: (item["code"], item["subject_ref"]))
    return {
        "protocol_version": "0.1",
        "acceptance_id": SHA256_A,
        "work_order_digest": SHA256_A,
        "signer_key_id": maintainer["key_id"],
        "acceptance_request_receipt_id": SHA256_B,
        "acceptance_request_receipt_digest": SHA256_C,
        "composition_report_digest": SHA256_D,
        "final_artifact": {
            "active_patch_receipt_digest": SHA256_A,
            "candidate_commit": "1" * 40,
            "workspace_manifest_digest": SHA256_B,
        },
        "artifact_digests": [
            {
                "path": "patch-result/01.json",
                "sha256": SHA256_C,
                "media_type": "application/json",
                "size_bytes": 100,
            }
        ],
        "evidence_snapshot_digest": SHA256_D,
        "receipt_digests": [SHA256_A],
        "causal_graph_root": SHA256_E,
        "causal_complete": True,
        "evidence_coverage": {
            "authority": True,
            "scope": True,
            "execution": True,
            "result": True,
            "independent_result": True,
        },
        "independence_assessment": {
            "policy": "independent_test_source_required",
            "developer_reference": {
                "receipt_digest": SHA256_A,
                "factors": correlation_data(key_bindings),
            },
            "verifier_reference": {
                "receipt_digest": SHA256_B,
                "factors": factors,
            },
            "shared_factors": [
                "model",
                "prompt_template",
                "context_source",
                "toolchain",
                "controller",
            ],
            "satisfied": True,
        },
        "test_evidence_refs": [
            {
                "path": "verifier-result/01.json",
                "sha256": SHA256_D,
                "media_type": "application/json",
                "size_bytes": 100,
            }
        ],
        "decision": "accepted",
        "unresolved_failures": [],
        "warnings": warnings,
        "global_postconditions": [postcondition],
        "global_postconditions_satisfied": True,
        "verifier_conclusion": "proof_ready",
        "accepted_at": "2026-01-01T00:00:04Z",
        "digest": SHA256_E,
        "signature_alg": "Ed25519",
        "signature": RECEIPT_SIGNATURE,
    }


@pytest.mark.parametrize(
    "event_type",
    [
        "grant_issued",
        "grant_consumed",
        "grant_revoked",
        "tool_call",
        "system_event",
        "approval_requested",
        "approval_decision",
        "termination_decision",
        "rollback",
    ],
)
def test_action_receipt_is_a_closed_nine_branch_union(
    key_bindings: list[dict], event_type: str
) -> None:
    parsed = contract_models.ACTION_RECEIPT_ADAPTER.validate_python(
        receipt_data(event_type, key_bindings)
    )
    assert parsed.event_type == event_type
    with pytest.raises(ValidationError):
        contract_models.ACTION_RECEIPT_ADAPTER.validate_python(
            {**receipt_data(event_type, key_bindings), "unknown_branch_field": True}
        )


def test_unknown_receipt_branch_is_rejected(key_bindings: list[dict]) -> None:
    candidate = receipt_data("grant_revoked", key_bindings)
    candidate["event_type"] = "authorization_revoked"
    with pytest.raises(ValidationError):
        contract_models.ACTION_RECEIPT_ADAPTER.validate_python(candidate)


def test_human_decisions_and_approval_request_actor_types_are_closed(
    key_bindings: list[dict],
) -> None:
    for event_type in ("approval_decision", "termination_decision"):
        valid = receipt_data(event_type, key_bindings)
        assert (
            contract_models.ACTION_RECEIPT_ADAPTER.validate_python(valid).actor_type
            == "human"
        )
        with pytest.raises(ValidationError):
            contract_models.ACTION_RECEIPT_ADAPTER.validate_python(
                {**valid, "actor_type": "agent"}
            )
    approval = receipt_data("approval_requested", key_bindings)
    assert (
        contract_models.ACTION_RECEIPT_ADAPTER.validate_python(
            approval
        ).actor_type
        == "agent"
    )
    with pytest.raises(ValidationError):
        contract_models.ACTION_RECEIPT_ADAPTER.validate_python(
            {**approval, "actor_type": "human"}
        )


def test_human_decision_forbids_grant_and_tool_fields(
    key_bindings: list[dict],
) -> None:
    approval = receipt_data("approval_decision", key_bindings)
    with pytest.raises(ValidationError):
        contract_models.ACTION_RECEIPT_ADAPTER.validate_python(
            {**approval, "grant_id": SHA256_A}
        )
    with pytest.raises(ValidationError):
        contract_models.ACTION_RECEIPT_ADAPTER.validate_python(
            {**approval, "tool_name": "owp.repo_read"}
        )


def test_termination_does_not_require_approval_request(
    key_bindings: list[dict],
) -> None:
    receipt = contract_models.ACTION_RECEIPT_ADAPTER.validate_python(
        receipt_data("termination_decision", key_bindings)
    )
    assert receipt.event_type == "termination_decision"
    for forbidden in (
        "request_receipt_id",
        "request_receipt_digest",
        "approved_scope",
        "expires_at",
    ):
        candidate = receipt_data("termination_decision", key_bindings)
        candidate["nested_claim"][forbidden] = SHA256_A
        with pytest.raises(ValidationError):
            contract_models.ACTION_RECEIPT_ADAPTER.validate_python(candidate)


@pytest.mark.parametrize(
    ("event_type", "path", "bad_value"),
    [
        ("grant_consumed", ("nested_claim", "actor_id"), "other"),
        ("grant_revoked", ("nested_claim", "work_order_digest"), SHA256_B),
        ("grant_revoked", ("nested_claim", "grant_id"), SHA256_B),
        ("tool_call", ("nested_claim", "tool_name"), "owp.apply_patch"),
        ("tool_call", ("nested_claim", "arguments_digest"), SHA256_A),
        ("approval_requested", ("nested_claim", "nonce"), SHA256_B),
        ("approval_decision", ("nested_claim", "decision"), "denied"),
        ("approval_decision", ("nested_claim", "request_receipt_id"), SHA256_A),
        ("approval_decision", ("nested_claim", "approved_scope", "operation"), "x"),
        ("approval_decision", ("nested_claim", "expires_at"), "2026-01-01T00:30:00Z"),
        ("termination_decision", ("nested_claim", "reason"), "OTHER"),
        ("system_event", ("nested_claim", "event_name"), "security_violation"),
        ("system_event", ("nested_claim", "input_digest"), SHA256_A),
    ],
)
def test_outer_and_nested_claim_fields_must_match(
    key_bindings: list[dict],
    event_type: str,
    path: tuple[str, ...],
    bad_value: object,
) -> None:
    with pytest.raises(ValidationError):
        contract_models.ACTION_RECEIPT_ADAPTER.validate_python(
            mutate(receipt_data(event_type, key_bindings), path, bad_value)
        )


def test_agent_and_human_claim_signatures_are_structurally_bound(
    key_bindings: list[dict],
) -> None:
    for event_type in ("grant_revoked", "approval_decision"):
        valid = receipt_data(event_type, key_bindings)
        for path, bad in (
            (("nested_claim_type",), "sidecar-event"),
            (("nested_claim_digest",), SHA256_A),
            (("nested_claim", "signer_key_id"), key_bindings[4]["key_id"]),
            (("nested_claim", "signature"), "bad"),
        ):
            with pytest.raises(ValidationError):
                contract_models.ACTION_RECEIPT_ADAPTER.validate_python(
                    mutate(valid, path, bad)
                )
    agent = receipt_data("grant_revoked", key_bindings)
    with pytest.raises(ValidationError):
        contract_models.ACTION_RECEIPT_ADAPTER.validate_python(
            mutate(
                agent,
                ("nested_claim", "authentication_method"),
                "gateway_attestation",
            )
        )


def test_agent_semantic_argument_mutation_is_request_integrity_invalid(
    key_bindings: list[dict],
    work_order_dict: dict,
) -> None:
    valid = receipt_data("grant_revoked", key_bindings)
    invalid = mutate(valid, ("revocation_reason",), "SUPERSEDED")
    result = contract_models.validate_receipt_or_error(
        invalid,
        work_order=WorkOrder.model_validate(work_order_dict),
    )
    assert isinstance(result, contract_models.McpErrorEnvelope)
    assert result.code == "REQUEST_INTEGRITY_INVALID"
    assert result.work_order_digest == SHA256_A
    assert result.nonce == SHA256_C
    assert "signature" not in type(result).model_fields


def test_receipt_outcome_matrix_is_exhaustive(key_bindings: list[dict]) -> None:
    allowed = {
        "grant_issued": {("allow", "succeeded"), ("deny", "denied")},
        "grant_consumed": {("allow", "succeeded"), ("deny", "denied")},
        "grant_revoked": {("allow", "succeeded"), ("deny", "denied")},
        "tool_call": {
            ("allow", "succeeded"),
            ("allow", "failed"),
            ("deny", "denied"),
        },
        "system_event": {("not_applicable", "succeeded")},
        "approval_requested": {("allow", "succeeded"), ("deny", "denied")},
        "approval_decision": {("allow", "succeeded"), ("deny", "denied")},
        "termination_decision": {("allow", "succeeded"), ("deny", "denied")},
        "rollback": {
            ("allow", "succeeded"),
            ("allow", "failed"),
            ("deny", "denied"),
        },
    }
    for event_type, valid_pairs in allowed.items():
        for policy in ("allow", "deny", "not_applicable"):
            for status in ("succeeded", "failed", "denied"):
                if (policy, status) in valid_pairs:
                    candidate = receipt_data(
                        event_type,
                        key_bindings,
                        policy_decision=policy,
                        execution_status=status,
                    )
                    contract_models.ACTION_RECEIPT_ADAPTER.validate_python(candidate)
                else:
                    candidate = receipt_data(event_type, key_bindings)
                    candidate["policy_decision"] = policy
                    candidate["execution_status"] = status
                    with pytest.raises(ValidationError):
                        contract_models.ACTION_RECEIPT_ADAPTER.validate_python(candidate)


def test_quota_charge_is_branch_closed(key_bindings: list[dict]) -> None:
    approval = receipt_data("approval_requested", key_bindings)
    for path, bad in (
        (("quota_charge", "grant_id"), SHA256_A),
        (("quota_charge", "metric"), "repair_rounds"),
        (("quota_charge", "amount"), 2),
        (("quota_charge", "remaining_after"), -1),
        (("quota_charge", "remaining_after"), 9_007_199_254_740_992),
    ):
        with pytest.raises(ValidationError):
            contract_models.ACTION_RECEIPT_ADAPTER.validate_python(
                mutate(approval, path, bad)
            )
    denied = receipt_data(
        "approval_requested",
        key_bindings,
        policy_decision="deny",
        execution_status="denied",
    )
    denied["quota_charge"] = {
        "grant_id": SHA256_E,
        "metric": "tool_calls",
        "amount": 1,
        "remaining_after": 9,
    }
    with pytest.raises(ValidationError):
        contract_models.ACTION_RECEIPT_ADAPTER.validate_python(denied)


def test_tool_request_registry_and_correlation_are_closed(
    key_bindings: list[dict],
) -> None:
    receipt = receipt_data("tool_call", key_bindings)
    for mutation in (
        ("request_arguments", {"path": "src/example.py", "extra": True}),
        ("tool_version", "0.2"),
        ("approval_receipt_id", SHA256_A),
    ):
        with pytest.raises(ValidationError):
            contract_models.ACTION_RECEIPT_ADAPTER.validate_python(
                {**receipt, mutation[0]: mutation[1]}
            )
    for field in (
        "model_id",
        "model_version",
        "prompt_template_digest",
        "context_source_digest",
    ):
        bad = mutate(receipt, ("correlation_factors", field), "other")
        with pytest.raises(ValidationError):
            contract_models.ACTION_RECEIPT_ADAPTER.validate_python(bad)


def test_predicate_results_are_sorted_unique_and_context_bound(
    key_bindings: list[dict],
    work_order_dict: dict,
) -> None:
    receipt = receipt_data("tool_call", key_bindings)
    applicable = [
        item
        for partition in ("preconditions", "invariants")
        for item in work_order_dict[partition]
        if "owp.repo_read" in item["applies_to_tools"]
    ]
    applicable.sort(key=lambda item: item["predicate_id"])
    receipt["predicate_results"] = [
        predicate_result_data(item) for item in applicable
    ]
    parsed = contract_models.ACTION_RECEIPT_ADAPTER.validate_python(receipt)
    assert parsed.validate_predicates_against(WorkOrder.model_validate(work_order_dict))
    for results in (
        list(reversed(receipt["predicate_results"])),
        receipt["predicate_results"] + [receipt["predicate_results"][0]],
    ):
        with pytest.raises(ValidationError):
            contract_models.ACTION_RECEIPT_ADAPTER.validate_python(
                {**receipt, "predicate_results": results}
            )
    bad = copy.deepcopy(receipt)
    bad["predicate_results"][0]["arguments_digest"] = SHA256_A
    parsed_bad = contract_models.ACTION_RECEIPT_ADAPTER.validate_python(bad)
    with pytest.raises(ValueError):
        parsed_bad.validate_predicates_against(WorkOrder.model_validate(work_order_dict))


def test_system_event_registry_cause_and_target_are_closed(
    key_bindings: list[dict],
) -> None:
    valid = receipt_data("system_event", key_bindings)
    contract_models.ACTION_RECEIPT_ADAPTER.validate_python(valid)
    for field, value in (
        ("system_event_name", "authorization_revoked"),
        ("error_code", "SECURITY_VIOLATION"),
        ("state_after", "frozen"),
    ):
        with pytest.raises(ValidationError):
            contract_models.ACTION_RECEIPT_ADAPTER.validate_python(
                {**valid, field: value}
            )
    expired = copy.deepcopy(valid)
    cause = {
        "deadline": "2026-01-01T00:00:02Z",
        "observed_at": "2026-01-01T00:00:03Z",
        "tip_receipt_digest": None,
    }
    input_digest = system_input_digest("contract_expired", SHA256_A, cause)
    expired.update(
        {
            "system_event_name": "contract_expired",
            "cause": cause,
            "input_digest": input_digest,
            "error_code": "CONTRACT_EXPIRED",
            "state_before": "running",
            "state_after": "frozen",
            "nested_claim_digest": input_digest,
            "nested_claim": {
                "claim_type": "sidecar-event",
                "work_order_digest": SHA256_A,
                "event_name": "contract_expired",
                "cause": cause,
                "input_digest": input_digest,
                "occurred_at": "2026-01-01T00:00:03Z",
            },
        }
    )
    contract_models.ACTION_RECEIPT_ADAPTER.validate_python(expired)

    security = copy.deepcopy(valid)
    security_digest = system_input_digest(
        "security_violation", SHA256_A, security["cause"]
    )
    security.update(
        {
            "system_event_name": "security_violation",
            "input_digest": security_digest,
            "error_code": "SECURITY_VIOLATION",
            "state_after": "frozen",
            "nested_claim_digest": security_digest,
        }
    )
    security["nested_claim"].update(
        {
            "event_name": "security_violation",
            "input_digest": security_digest,
        }
    )
    contract_models.ACTION_RECEIPT_ADAPTER.validate_python(security)


def test_final_acceptance_request_cannot_masquerade_as_pr_request(
    key_bindings: list[dict],
) -> None:
    final_request = receipt_data("approval_requested", key_bindings)
    scope = {
        "work_order_digest": SHA256_A,
        "operation": "submit_final_acceptance",
        "composition_report_digest": SHA256_B,
    }
    final_request.update(
        {
            "request_kind": "final_acceptance",
            "required_role": "Acceptor",
            "requested_scope": scope,
            "target_action_digest": jcs_digest(
                {
                    "domain": "openworkproof/final-acceptance-action/v0.1",
                    "requested_scope": scope,
                }
            ),
        }
    )
    claim = agent_claim(
        key_bindings,
        grant_id=SHA256_E,
        tool_name="owp.request_acceptance",
        arguments={
            "request_kind": final_request["request_kind"],
            "target_action_digest": final_request["target_action_digest"],
            "required_role": final_request["required_role"],
            "requested_scope": scope,
            "expires_at": final_request["expires_at"],
        },
    )
    final_request["nested_claim"] = claim
    final_request["nested_claim_digest"] = claim["digest"]
    contract_models.ACTION_RECEIPT_ADAPTER.validate_python(final_request)
    with pytest.raises(ValidationError):
        contract_models.ACTION_RECEIPT_ADAPTER.validate_python(
            {
                **final_request,
                "request_kind": "high_risk_action",
                "required_role": "Maintainer",
            }
        )


@pytest.mark.parametrize("evidence_path_kind", ("rooted", "child_only", "wrong_root"))
def test_apply_patch_and_test_result_evidence_are_closed_and_rehashable(
    key_bindings: list[dict],
    work_order_dict: dict,
    evidence_path_kind: str,
) -> None:
    work_order = WorkOrder.model_validate(work_order_dict)
    evidence_root = work_order.evidence_policy.evidence_root
    runtime_root = (
        evidence_root
        if evidence_path_kind == "rooted"
        else "wrong-root"
        if evidence_path_kind == "wrong_root"
        else None
    )
    patch_input_path = (
        f"{runtime_root}/patch-input/01.diff"
        if runtime_root is not None
        else "patch-input/01.diff"
    )
    patch_result_path = (
        f"{runtime_root}/patch-result/01.json"
        if runtime_root is not None
        else "patch-result/01.json"
    )
    patch_bytes = b"diff --git a/x b/x\n"
    patch_digest = hashlib.sha256(patch_bytes).hexdigest()
    patch_result = {
        "schema_version": "openworkproof-patch-result/0.1",
        "parent_commit": "0" * 40,
        "parent_manifest_digest": SHA256_A,
        "candidate_commit": "1" * 40,
        "workspace_manifest_digest": SHA256_B,
        "patch_digest": patch_digest,
        "patch_size_bytes": len(patch_bytes),
        "replay_profile_digest": work_order_dict["replay_profile_digest"],
    }
    patch_result_bytes = rfc8785.dumps(patch_result)
    patch_result_digest = hashlib.sha256(patch_result_bytes).hexdigest()
    contract_models.PatchResultEvidence.model_validate(patch_result)

    receipt = receipt_data("tool_call", key_bindings)
    request = {
        "target_paths": ["src/x"],
        "patch_digest": patch_digest,
        "patch_size_bytes": len(patch_bytes),
    }
    receipt.update(
        {
            "tool_name": "owp.apply_patch",
            "request_arguments": request,
            "arguments_digest": agent_arguments_digest("owp.apply_patch", request),
            "output_digest": patch_result_digest,
            "evidence_refs": [
                {
                    "path": patch_input_path,
                    "sha256": patch_digest,
                    "media_type": "text/x-diff",
                    "size_bytes": len(patch_bytes),
                },
                {
                    "path": patch_result_path,
                    "sha256": patch_result_digest,
                    "media_type": "application/json",
                    "size_bytes": len(patch_result_bytes),
                },
            ],
        }
    )
    claim = agent_claim(
        key_bindings,
        grant_id=SHA256_E,
        tool_name="owp.apply_patch",
        arguments=request,
    )
    receipt["nested_claim"] = claim
    receipt["nested_claim_digest"] = claim["digest"]
    parsed = contract_models.ACTION_RECEIPT_ADAPTER.validate_python(receipt)
    payloads = {
        patch_input_path: patch_bytes,
        patch_result_path: patch_result_bytes,
    }
    if evidence_path_kind != "rooted":
        with pytest.raises(ValueError):
            parsed.validate_evidence_payloads(payloads, work_order)
        return
    assert parsed.validate_evidence_payloads(
        payloads,
        work_order,
    )

    wrong_purpose = copy.deepcopy(receipt)
    wrong_purpose["evidence_refs"][0]["path"] = (
        f"{evidence_root}/patch-denial-audit/01.diff"
    )
    parsed_wrong_purpose = contract_models.ACTION_RECEIPT_ADAPTER.validate_python(
        wrong_purpose
    )
    with pytest.raises(ValueError):
        parsed_wrong_purpose.validate_evidence_payloads(
            {
                f"{evidence_root}/patch-denial-audit/01.diff": patch_bytes,
                patch_result_path: patch_result_bytes,
            },
            work_order,
        )

    wrong_ordinal = copy.deepcopy(receipt)
    wrong_ordinal["evidence_refs"][1]["path"] = (
        f"{evidence_root}/patch-result/02.json"
    )
    parsed_wrong_ordinal = contract_models.ACTION_RECEIPT_ADAPTER.validate_python(
        wrong_ordinal
    )
    with pytest.raises(ValueError):
        parsed_wrong_ordinal.validate_evidence_payloads(
            {
                patch_input_path: patch_bytes,
                f"{evidence_root}/patch-result/02.json": patch_result_bytes,
            },
            work_order,
        )

    denied = receipt_data(
        "tool_call",
        key_bindings,
        policy_decision="deny",
        execution_status="denied",
    )
    denied.update(
        {
            "tool_name": "owp.apply_patch",
            "request_arguments": request,
            "arguments_digest": agent_arguments_digest("owp.apply_patch", request),
            "evidence_refs": [
                {
                    "path": patch_input_path,
                    "sha256": patch_digest,
                    "media_type": "text/x-diff",
                    "size_bytes": len(patch_bytes),
                }
            ],
        }
    )
    denied_claim = agent_claim(
        key_bindings,
        grant_id=SHA256_E,
        tool_name="owp.apply_patch",
        arguments=request,
    )
    denied["nested_claim"] = denied_claim
    denied["nested_claim_digest"] = denied_claim["digest"]
    parsed_denied = contract_models.ACTION_RECEIPT_ADAPTER.validate_python(denied)
    with pytest.raises(ValueError):
        parsed_denied.validate_evidence_payloads(
            {patch_input_path: patch_bytes},
            work_order,
        )

    with pytest.raises(ValueError):
        parsed.validate_evidence_payloads(
            {
                patch_input_path: patch_bytes + b"x",
                patch_result_path: patch_result_bytes,
            },
            work_order,
        )


def test_rollback_result_mirrors_status(key_bindings: list[dict]) -> None:
    for policy, status in (
        ("allow", "succeeded"),
        ("allow", "failed"),
        ("deny", "denied"),
    ):
        contract_models.ACTION_RECEIPT_ADAPTER.validate_python(
            receipt_data(
                "rollback",
                key_bindings,
                policy_decision=policy,
                execution_status=status,
            )
        )
    bad = receipt_data(
        "rollback",
        key_bindings,
        policy_decision="allow",
        execution_status="failed",
    )
    bad["rollback_result"] = "succeeded"
    with pytest.raises(ValidationError):
        contract_models.ACTION_RECEIPT_ADAPTER.validate_python(bad)


def test_acceptance_receipt_only_represents_strong_acceptance(
    key_bindings: list[dict],
    work_order_dict: dict,
) -> None:
    valid = acceptance_data(key_bindings, work_order_dict)
    receipt = contract_models.AcceptanceReceipt.model_validate(valid)
    assert receipt.decision == "accepted"
    for path, value in (
        (("decision",), "rejected"),
        (("unresolved_failures",), [{"code": "CAUSAL_INCOMPLETE", "subject_ref": "x"}]),
        (("causal_complete",), False),
        (("evidence_coverage", "result"), False),
        (("independence_assessment", "satisfied"), False),
        (("global_postconditions", 0, "passed"), False),
        (("global_postconditions_satisfied",), False),
        (("verifier_conclusion",), "evidence_incomplete"),
    ):
        with pytest.raises(ValidationError):
            contract_models.AcceptanceReceipt.model_validate(mutate(valid, path, value))


def test_acceptance_diagnostics_and_shared_factors_are_closed_sorted_unique(
    key_bindings: list[dict],
    work_order_dict: dict,
) -> None:
    valid = acceptance_data(key_bindings, work_order_dict)
    warning = {"code": "SHARED_MODEL", "subject_ref": SHA256_A}
    for warnings in (
        [{"code": "FREE_TEXT", "subject_ref": "x"}],
        [warning, warning],
        [
            {"code": "SHARED_TOOLCHAIN", "subject_ref": SHA256_B},
            warning,
        ],
        ["free text"],
    ):
        with pytest.raises(ValidationError):
            contract_models.AcceptanceReceipt.model_validate(
                {**valid, "warnings": warnings}
            )
    bad = copy.deepcopy(valid)
    bad["independence_assessment"]["shared_factors"] = ["toolchain", "model"]
    with pytest.raises(ValidationError):
        contract_models.AcceptanceReceipt.model_validate(bad)
    bad = copy.deepcopy(valid)
    bad["warnings"] = bad["warnings"][1:]
    with pytest.raises(ValidationError):
        contract_models.AcceptanceReceipt.model_validate(bad)


@pytest.mark.parametrize(
    "code",
    [
        "REQUEST_INTEGRITY_INVALID",
        "ROOT_ACTIVATION_INVALID",
        "RECOVERY_REQUIRED",
        "HANDLER_UNAVAILABLE",
        "EVIDENCE_SLOT_UNAVAILABLE",
        "INDEPENDENT_RESULT_NOT_READY",
        "EVIDENCE_FAILURE_SEALED",
        "COMPLETION_RESERVE_UNAVAILABLE",
        "DENIAL_AUDIT_LIMIT_EXCEEDED",
        "BUNDLE_CAPACITY_EXCEEDED",
        "CONTRACT_EXPIRED",
    ],
)
def test_mcp_error_envelope_is_closed_unsigned_and_lexically_projected(
    code: str,
) -> None:
    envelope = contract_models.McpErrorEnvelope.from_untrusted(
        code=code,
        work_order_digest=SHA256_A,
        nonce=SHA256_B,
    )
    assert envelope.model_dump() == {
        "schema_version": "openworkproof-mcp-error/0.1",
        "code": code,
        "work_order_digest": SHA256_A,
        "nonce": SHA256_B,
    }
    assert "signature" not in type(envelope).model_fields
    assert (
        contract_models.McpErrorEnvelope.from_untrusted(
            code=code,
            work_order_digest="INVALID",
            nonce="INVALID",
        ).model_dump()
        == {
            "schema_version": "openworkproof-mcp-error/0.1",
            "code": code,
            "work_order_digest": None,
            "nonce": None,
        }
    )
    with pytest.raises(ValidationError):
        contract_models.McpErrorEnvelope.model_validate(
            {**envelope.model_dump(), "message": "raw exception"}
        )


def test_mcp_expiry_projection_helpers_are_exact() -> None:
    startup = contract_models.McpErrorEnvelope.startup_expiry(SHA256_A)
    assert startup.code == "CONTRACT_EXPIRED"
    assert startup.work_order_digest == SHA256_A
    assert startup.nonce is None
    request = contract_models.McpErrorEnvelope.request_expiry(SHA256_A, SHA256_B)
    assert request.work_order_digest == SHA256_A
    assert request.nonce == SHA256_B
    with pytest.raises(ValidationError):
        contract_models.McpErrorEnvelope.startup_expiry("INVALID")
    with pytest.raises(ValidationError):
        contract_models.McpErrorEnvelope.request_expiry(SHA256_A, "INVALID")


def test_work_order_context_binds_sidecar_and_maintainer_identities(
    key_bindings: list[dict],
    work_order_dict: dict,
) -> None:
    work_order = WorkOrder.model_validate(work_order_dict)
    system = receipt_data("system_event", key_bindings)
    system["work_order_digest"] = work_order.digest
    system["nested_claim"]["work_order_digest"] = work_order.digest
    input_digest = system_input_digest(
        system["system_event_name"], work_order.digest, system["cause"]
    )
    system["input_digest"] = input_digest
    system["nested_claim_digest"] = input_digest
    system["nested_claim"]["input_digest"] = input_digest
    parsed_system = contract_models.ACTION_RECEIPT_ADAPTER.validate_python(system)
    assert parsed_system.validate_against_work_order(work_order) is parsed_system

    forged = copy.deepcopy(system)
    forged["actor_id"] = "manager"
    parsed_forged = contract_models.ACTION_RECEIPT_ADAPTER.validate_python(forged)
    with pytest.raises(ValueError):
        parsed_forged.validate_against_work_order(work_order)

    termination = receipt_data("termination_decision", key_bindings)
    termination["work_order_digest"] = work_order.digest
    termination["target_work_order_digest"] = work_order.digest
    termination["nested_claim"]["work_order_digest"] = work_order.digest
    termination["nested_claim"]["target_work_order_digest"] = work_order.digest
    parsed_termination = contract_models.ACTION_RECEIPT_ADAPTER.validate_python(
        termination
    )
    assert (
        parsed_termination.validate_against_work_order(work_order)
        is parsed_termination
    )


def test_tool_call_context_binds_controller_to_work_order_sidecar(
    key_bindings: list[dict],
    work_order_dict: dict,
) -> None:
    work_order = WorkOrder.model_validate(work_order_dict)
    receipt = receipt_data("tool_call", key_bindings)
    receipt["work_order_digest"] = work_order.digest
    receipt["nested_claim"]["work_order_digest"] = work_order.digest
    applicable = [
        item
        for partition in ("preconditions", "invariants")
        for item in work_order_dict[partition]
        if receipt["tool_name"] in item["applies_to_tools"]
    ]
    applicable.sort(key=lambda item: item["predicate_id"])
    receipt["predicate_results"] = [
        predicate_result_data(item) for item in applicable
    ]

    parsed = contract_models.ACTION_RECEIPT_ADAPTER.validate_python(receipt)
    assert parsed.validate_against_work_order(work_order) is parsed

    forged = copy.deepcopy(receipt)
    forged["correlation_factors"]["controller_id"] = key_bindings[0]["key_id"]
    parsed_forged = contract_models.ACTION_RECEIPT_ADAPTER.validate_python(forged)
    with pytest.raises(ValueError):
        parsed_forged.validate_against_work_order(work_order)
    assert isinstance(
        contract_models.validate_receipt_or_error(
            forged,
            work_order=work_order,
        ),
        contract_models.McpErrorEnvelope,
    )


def test_protocol_receipt_entrypoint_requires_work_order_and_tool_predicates(
    key_bindings: list[dict],
    work_order_dict: dict,
) -> None:
    work_order = WorkOrder.model_validate(work_order_dict)
    receipt = receipt_data("tool_call", key_bindings)
    receipt["work_order_digest"] = work_order.digest
    receipt["nested_claim"]["work_order_digest"] = work_order.digest
    applicable = [
        item
        for partition in ("preconditions", "invariants")
        for item in work_order_dict[partition]
        if receipt["tool_name"] in item["applies_to_tools"]
    ]
    applicable.sort(key=lambda item: item["predicate_id"])
    receipt["predicate_results"] = [
        predicate_result_data(item) for item in applicable
    ]

    valid = contract_models.validate_receipt_or_error(
        receipt,
        work_order=work_order,
    )
    assert isinstance(valid, contract_models.ToolCallReceipt)
    assert isinstance(
        contract_models.validate_receipt_or_error(receipt),
        contract_models.McpErrorEnvelope,
    )

    non_tool = receipt_data("grant_revoked", key_bindings)
    non_tool["work_order_digest"] = work_order.digest
    non_tool["nested_claim"]["work_order_digest"] = work_order.digest
    assert isinstance(
        contract_models.validate_receipt_or_error(
            non_tool,
            work_order=work_order,
        ),
        contract_models.GrantRevokedReceipt,
    )

    missing_predicates = copy.deepcopy(receipt)
    missing_predicates["predicate_results"] = []
    assert isinstance(
        contract_models.validate_receipt_or_error(
            missing_predicates,
            work_order=work_order,
        ),
        contract_models.McpErrorEnvelope,
    )


def test_acceptance_warning_set_is_recomputed_from_shared_factors(
    key_bindings: list[dict],
    work_order_dict: dict,
) -> None:
    valid = acceptance_data(key_bindings, work_order_dict)
    contract_models.AcceptanceReceipt.model_validate(valid)
    missing = copy.deepcopy(valid)
    missing["independence_assessment"]["shared_factors"].pop()
    with pytest.raises(ValidationError):
        contract_models.AcceptanceReceipt.model_validate(missing)
    forged = copy.deepcopy(valid)
    forged["warnings"][0]["subject_ref"] = SHA256_A
    with pytest.raises(ValidationError):
        contract_models.AcceptanceReceipt.model_validate(forged)


def test_repo_read_success_output_is_closed_and_rehashable(
    key_bindings: list[dict],
) -> None:
    output = {
        "path": "src/example.py",
        "content_sha256": SHA256_B,
        "size_bytes": 10,
        "workspace_manifest_digest": SHA256_C,
    }
    receipt = receipt_data("tool_call", key_bindings)
    receipt["output_digest"] = jcs_digest(
        {
            "domain": "openworkproof/repo-read-output/v0.1",
            "output": output,
        }
    )
    parsed = contract_models.ACTION_RECEIPT_ADAPTER.validate_python(receipt)
    assert parsed.validate_handler_output(output) is parsed
    with pytest.raises(ValueError):
        parsed.validate_handler_output({**output, "size_bytes": 11})


def test_high_risk_tool_repeats_exact_approval_references(
    key_bindings: list[dict],
) -> None:
    request = {
        "target_patch_digest": SHA256_B,
        "approval_receipt_id": SHA256_C,
        "approval_receipt_digest": SHA256_D,
    }
    receipt = receipt_data("tool_call", key_bindings)
    receipt.update(
        {
            "tool_name": "owp.create_pr_proposal",
            "request_arguments": request,
            "arguments_digest": agent_arguments_digest(
                "owp.create_pr_proposal", request
            ),
            "approval_receipt_id": SHA256_C,
            "approval_receipt_digest": SHA256_D,
            "output_digest": jcs_digest(
                {
                    "status": "local_pr_proposal_created",
                    "target_patch_digest": SHA256_B,
                }
            ),
            "correlation_factors": correlation_data(
                key_bindings, started=False
            ),
            "evidence_refs": [],
        }
    )
    claim = agent_claim(
        key_bindings,
        grant_id=SHA256_E,
        tool_name="owp.create_pr_proposal",
        arguments=request,
    )
    receipt["nested_claim"] = claim
    receipt["nested_claim_digest"] = claim["digest"]
    contract_models.ACTION_RECEIPT_ADAPTER.validate_python(receipt)
    with pytest.raises(ValidationError):
        contract_models.ACTION_RECEIPT_ADAPTER.validate_python(
            {**receipt, "approval_receipt_digest": SHA256_A}
        )


def run_tests_receipt_data(
    key_bindings: list[dict],
    work_order: WorkOrder,
    *,
    test_mode: str,
    evidence_path: str,
) -> tuple[dict, bytes]:
    runtime_evidence_path = (
        f"{work_order.evidence_policy.evidence_root}/{evidence_path}"
    )
    profile = next(
        item for item in work_order.test_profiles if item.test_mode == test_mode
    )
    request = {
        "test_mode": test_mode,
        "command_digest": profile.command_digest,
        "source_commit": work_order.source_commit,
        "candidate_commit": "2" * 40,
        "workspace_manifest_digest": SHA256_C,
        "container_image_digest": profile.container_image_digest,
        "fixed_test_source_digest": profile.fixed_test_source_digest,
    }
    result_bytes = rfc8785.dumps(
        {
            "schema_version": "openworkproof-test-result/0.1",
            **request,
            "actual_exit_code": 1,
        }
    )
    result_digest = hashlib.sha256(result_bytes).hexdigest()
    receipt = receipt_data("tool_call", key_bindings)
    factors = correlation_data(key_bindings)
    factors["fixed_test_source_digest"] = profile.fixed_test_source_digest
    receipt.update(
        {
            "tool_name": "owp.run_tests",
            "request_arguments": request,
            "arguments_digest": agent_arguments_digest("owp.run_tests", request),
            "output_digest": result_digest,
            "correlation_factors": factors,
            "evidence_refs": [
                {
                    "path": runtime_evidence_path,
                    "sha256": result_digest,
                    "media_type": "application/json",
                    "size_bytes": len(result_bytes),
                }
            ],
        }
    )
    claim = agent_claim(
        key_bindings,
        grant_id=SHA256_E,
        tool_name="owp.run_tests",
        arguments=request,
    )
    receipt["nested_claim"] = claim
    receipt["nested_claim_digest"] = claim["digest"]
    return receipt, result_bytes


def test_verifier_run_tests_rejects_non_verifier_evidence_slot(
    key_bindings: list[dict],
    work_order_dict: dict,
) -> None:
    work_order = WorkOrder.model_validate(work_order_dict)
    receipt, result_bytes = run_tests_receipt_data(
        key_bindings,
        work_order,
        test_mode="verifier",
        evidence_path="patch-result/01.json",
    )
    parsed = contract_models.ACTION_RECEIPT_ADAPTER.validate_python(receipt)
    with pytest.raises(ValueError):
        parsed.validate_evidence_payloads(
            {receipt["evidence_refs"][0]["path"]: result_bytes},
            work_order,
        )


def test_developer_run_tests_rejects_non_developer_evidence_slot(
    key_bindings: list[dict],
    work_order_dict: dict,
) -> None:
    candidate = copy.deepcopy(work_order_dict)
    candidate["test_profiles"].insert(
        0,
        make_test_profile("developer", fixed=False),
    )
    candidate["evidence_policy"]["artifacts"].insert(
        6,
        evidence_artifact(
            "developer_test_result",
            1,
            media_type="application/json",
            dimension="execution",
            suffix="json",
        ),
    )
    work_order = WorkOrder.model_validate(candidate)
    receipt, result_bytes = run_tests_receipt_data(
        key_bindings,
        work_order,
        test_mode="developer",
        evidence_path="verifier-result/01.json",
    )
    parsed = contract_models.ACTION_RECEIPT_ADAPTER.validate_python(receipt)
    with pytest.raises(ValueError):
        parsed.validate_evidence_payloads(
            {receipt["evidence_refs"][0]["path"]: result_bytes},
            work_order,
        )
    valid_receipt, valid_result_bytes = run_tests_receipt_data(
        key_bindings,
        work_order,
        test_mode="developer",
        evidence_path="developer-test-result/01.json",
    )
    parsed_valid = contract_models.ACTION_RECEIPT_ADAPTER.validate_python(
        valid_receipt
    )
    assert (
        parsed_valid.validate_evidence_payloads(
            {valid_receipt["evidence_refs"][0]["path"]: valid_result_bytes},
            work_order,
        )
        is parsed_valid
    )


def test_run_tests_result_bytes_bind_request_profile_and_real_exit(
    key_bindings: list[dict],
    work_order_dict: dict,
) -> None:
    work_order = WorkOrder.model_validate(work_order_dict)
    verifier_result_path = (
        f"{work_order.evidence_policy.evidence_root}/verifier-result/01.json"
    )
    profile = work_order.test_profiles[0]
    request = {
        "test_mode": "verifier",
        "command_digest": profile.command_digest,
        "source_commit": work_order.source_commit,
        "candidate_commit": "2" * 40,
        "workspace_manifest_digest": SHA256_C,
        "container_image_digest": profile.container_image_digest,
        "fixed_test_source_digest": profile.fixed_test_source_digest,
    }
    result = {
        "schema_version": "openworkproof-test-result/0.1",
        **request,
        "actual_exit_code": 1,
    }
    result_bytes = rfc8785.dumps(result)
    result_digest = hashlib.sha256(result_bytes).hexdigest()
    receipt = receipt_data("tool_call", key_bindings)
    factors = correlation_data(key_bindings)
    factors["fixed_test_source_digest"] = profile.fixed_test_source_digest
    receipt.update(
        {
            "tool_name": "owp.run_tests",
            "request_arguments": request,
            "arguments_digest": agent_arguments_digest("owp.run_tests", request),
            "output_digest": result_digest,
            "correlation_factors": factors,
            "evidence_refs": [
                {
                    "path": verifier_result_path,
                    "sha256": result_digest,
                    "media_type": "application/json",
                    "size_bytes": len(result_bytes),
                }
            ],
        }
    )
    claim = agent_claim(
        key_bindings,
        grant_id=SHA256_E,
        tool_name="owp.run_tests",
        arguments=request,
    )
    receipt["nested_claim"] = claim
    receipt["nested_claim_digest"] = claim["digest"]
    parsed = contract_models.ACTION_RECEIPT_ADAPTER.validate_python(receipt)
    assert (
        parsed.validate_evidence_payloads(
            {verifier_result_path: result_bytes}, work_order
        )
        is parsed
    )
    mutated_result = {**result, "command_digest": SHA256_A}
    mutated_bytes = rfc8785.dumps(mutated_result)
    mutated_ref = copy.deepcopy(receipt)
    mutated_ref["output_digest"] = hashlib.sha256(mutated_bytes).hexdigest()
    mutated_ref["evidence_refs"][0]["sha256"] = mutated_ref["output_digest"]
    mutated_ref["evidence_refs"][0]["size_bytes"] = len(mutated_bytes)
    parsed_mutated = contract_models.ACTION_RECEIPT_ADAPTER.validate_python(
        mutated_ref
    )
    with pytest.raises(ValueError):
        parsed_mutated.validate_evidence_payloads(
            {verifier_result_path: mutated_bytes}, work_order
        )


def test_rollback_context_binds_target_patch_result(
    key_bindings: list[dict],
) -> None:
    patch = receipt_data("tool_call", key_bindings)
    patch_request = {
        "target_paths": ["src/x"],
        "patch_digest": SHA256_A,
        "patch_size_bytes": 10,
    }
    patch_result = contract_models.PatchResultEvidence(
        schema_version="openworkproof-patch-result/0.1",
        parent_commit="0" * 40,
        parent_manifest_digest=SHA256_A,
        candidate_commit="1" * 40,
        workspace_manifest_digest=SHA256_B,
        patch_digest=SHA256_A,
        patch_size_bytes=10,
        replay_profile_digest=SHA256_C,
    )
    patch.update(
        {
            "tool_name": "owp.apply_patch",
            "request_arguments": patch_request,
            "arguments_digest": agent_arguments_digest(
                "owp.apply_patch", patch_request
            ),
            "output_digest": SHA256_D,
            "evidence_refs": [
                {
                    "path": "patch-input/01.diff",
                    "sha256": SHA256_A,
                    "media_type": "text/x-diff",
                    "size_bytes": 10,
                },
                {
                    "path": "patch-result/01.json",
                    "sha256": SHA256_D,
                    "media_type": "application/json",
                    "size_bytes": 100,
                },
            ],
        }
    )
    claim = agent_claim(
        key_bindings,
        grant_id=SHA256_E,
        tool_name="owp.apply_patch",
        arguments=patch_request,
    )
    patch["nested_claim"] = claim
    patch["nested_claim_digest"] = claim["digest"]
    parsed_patch = contract_models.ACTION_RECEIPT_ADAPTER.validate_python(patch)

    rollback = receipt_data("rollback", key_bindings)
    rollback.update(
        {
            "target_patch_receipt_id": parsed_patch.receipt_id,
            "target_patch_digest": parsed_patch.digest,
            "before_commit": patch_result.candidate_commit,
            "after_commit": patch_result.parent_commit,
            "after_manifest_digest": patch_result.parent_manifest_digest,
        }
    )
    arguments = {
        "target_patch_receipt_id": rollback["target_patch_receipt_id"],
        "target_patch_digest": rollback["target_patch_digest"],
        "before_commit": rollback["before_commit"],
    }
    claim = agent_claim(
        key_bindings,
        grant_id=SHA256_E,
        tool_name="owp.rollback_patch",
        arguments=arguments,
    )
    rollback["nested_claim"] = claim
    rollback["nested_claim_digest"] = claim["digest"]
    parsed_rollback = contract_models.ACTION_RECEIPT_ADAPTER.validate_python(
        rollback
    )
    assert (
        parsed_rollback.validate_target_patch(parsed_patch, patch_result)
        is parsed_rollback
    )


def test_predicate_result_inputs_use_the_closed_name_specific_registry(
    work_order_dict: dict,
) -> None:
    path_spec = next(
        item
        for item in work_order_dict["preconditions"]
        if item["name"] == "path_allowed"
    )
    valid = predicate_result_data(path_spec)
    PredicateResult.model_validate(valid)
    with pytest.raises(ValidationError):
        PredicateResult.model_validate(
            mutate(valid, ("input", "unregistered"), True)
        )
    with pytest.raises(ValidationError):
        PredicateResult.model_validate(
            {
                **valid,
                "input": {"actual_tool_name": "owp.repo_read"},
                "input_digest": jcs_digest(
                    {
                        "domain": "openworkproof/predicate-input/v0.1",
                        "predicate_id": valid["predicate_id"],
                        "input": {"actual_tool_name": "owp.repo_read"},
                    }
                ),
            }
        )


def test_conditional_branch_fields_serialize_as_absent_not_null(
    key_bindings: list[dict],
) -> None:
    denied_grant = contract_models.ACTION_RECEIPT_ADAPTER.validate_python(
        receipt_data(
            "grant_issued",
            key_bindings,
            policy_decision="deny",
            execution_status="denied",
        )
    )
    assert "issued_grant_id" not in denied_grant.model_dump(mode="json")

    low_risk = contract_models.ACTION_RECEIPT_ADAPTER.validate_python(
        receipt_data("tool_call", key_bindings)
    )
    dumped = low_risk.model_dump(mode="json")
    assert "approval_receipt_id" not in dumped
    assert "approval_receipt_digest" not in dumped


def test_root_and_child_issuance_bind_the_referenced_candidate(
    key_bindings: list[dict],
    root_grant_dict: dict,
    child_grant_dict: dict,
) -> None:
    child = receipt_data("grant_issued", key_bindings)
    child_candidate = CapabilityGrant.model_validate(child_grant_dict)
    child["candidate_grant_digest"] = child_candidate.digest
    child["parent_grant_id"] = child_candidate.parent_grant_id
    child["authorizing_grant_id"] = child_candidate.parent_grant_id
    child["issued_grant_id"] = child_candidate.grant_id
    child_arguments = {
        "operation": "delegate_child",
        "authorizing_grant_id": child["authorizing_grant_id"],
        "candidate_grant_digest": child["candidate_grant_digest"],
    }
    child_claim = agent_claim(
        key_bindings,
        grant_id=child["authorizing_grant_id"],
        tool_name="owp.delegate_grant",
        arguments=child_arguments,
    )
    child["nested_claim"] = child_claim
    child["nested_claim_digest"] = child_claim["digest"]
    parsed_child = contract_models.ACTION_RECEIPT_ADAPTER.validate_python(child)
    assert parsed_child.validate_candidate(child_candidate) is parsed_child

    root = receipt_data("grant_issued", key_bindings)
    root_candidate = CapabilityGrant.model_validate(root_grant_dict)
    root.update(
        {
            "candidate_grant_digest": root_candidate.digest,
            "parent_grant_id": None,
            "authorizing_grant_id": root_candidate.grant_id,
            "issued_grant_id": root_candidate.grant_id,
        }
    )
    root_arguments = {
        "operation": "activate_root",
        "authorizing_grant_id": root["authorizing_grant_id"],
        "candidate_grant_digest": root["candidate_grant_digest"],
    }
    root_claim = agent_claim(
        key_bindings,
        grant_id=root["authorizing_grant_id"],
        tool_name="owp.activate_root_grant",
        arguments=root_arguments,
    )
    root["nested_claim"] = root_claim
    root["nested_claim_digest"] = root_claim["digest"]
    parsed_root = contract_models.ACTION_RECEIPT_ADAPTER.validate_python(root)
    assert parsed_root.validate_candidate(root_candidate) is parsed_root


@pytest.mark.parametrize(
    ("event_type", "path", "value"),
    [
        ("grant_issued", ("candidate_grant_digest",), SHA256_A),
        ("grant_consumed", ("amount",), 2),
        (
            "approval_requested",
            ("requested_scope", "target_patch_digest"),
            SHA256_A,
        ),
        ("tool_call", ("request_arguments", "path"), "src/other.py"),
        ("rollback", ("target_patch_digest",), SHA256_A),
    ],
)
def test_agent_semantic_splicing_always_returns_closed_integrity_error(
    key_bindings: list[dict],
    work_order_dict: dict,
    event_type: str,
    path: tuple[str, ...],
    value: object,
) -> None:
    original = receipt_data(event_type, key_bindings)
    result = contract_models.validate_receipt_or_error(
        mutate(original, path, value),
        work_order=WorkOrder.model_validate(work_order_dict),
    )
    assert isinstance(result, contract_models.McpErrorEnvelope)
    assert result.code == "REQUEST_INTEGRITY_INVALID"
    assert result.work_order_digest == original["work_order_digest"]
    assert result.nonce == original["nonce"]
