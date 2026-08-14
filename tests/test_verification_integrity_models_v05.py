from __future__ import annotations

import base64
import copy
import hashlib
from collections.abc import Iterator, Mapping, Sequence
from typing import Any

import pytest
import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

import openworkproof.models as models_module
from openworkproof.models import (
    ActionBindingManifest,
    ControlContractV05,
    ControlObservationV05,
    EvaluationScopeManifest,
    FailureSignatureV05,
    PopulationContractV05,
    PopulationObservationV05,
    VerificationArmResultV03,
    VerificationArmResultV05,
    VerificationDecisionV03,
    VerificationDecisionDraftV05,
    VerificationDecisionV05,
    VerificationIntegrityAssessmentV05,
    VerificationProfileV02,
    VerificationProfileV03,
    VerificationProfileV05,
    control_contract_id,
    failure_signature_digest,
    population_contract_id,
    population_member_digest,
)
from openworkproof.signing import (
    canonical_bytes,
    key_id,
    sign_payload,
    verify_payload,
)
from openworkproof.verification import verification_decision_signing_bytes_v03


def test_v05_model_names_import_and_instantiate_without_validation() -> None:
    model_types = (
        PopulationContractV05,
        PopulationObservationV05,
        FailureSignatureV05,
        ControlContractV05,
        ControlObservationV05,
        VerificationIntegrityAssessmentV05,
        VerificationProfileV05,
        VerificationArmResultV05,
        VerificationDecisionDraftV05,
        VerificationDecisionV05,
    )

    assert all(model_type.model_construct().__class__ is model_type for model_type in model_types)


def test_v05_minor_api_surface_is_closed_and_type_correct() -> None:
    assert "VerificationArmExecutionStatus" in models_module.__all__
    assert VerificationDecisionV05.__private_attributes__ == {}
    assert (
        models_module._validate_verification_decision_content.__annotations__[
            "reason_codes"
        ]
        == "tuple[str, ...]"
    )


def _evidence(path: str) -> dict[str, Any]:
    return {
        "path": path,
        "sha256": "e" * 64,
        "media_type": "application/json",
        "size_bytes": 128,
    }


def _population_contract_payload() -> dict[str, Any]:
    payload = {
        "selector_rule_id": "1" * 64,
        "member_kind": "test_case",
        "selector_spec_digest": "2" * 64,
        "selector_engine_digest": "3" * 64,
        "declared_selected_member_ids": ["4" * 64],
        "minimum_eligible_count": 1,
        "minimum_selected_count": 1,
        "maximum_eligible_count": 4096,
        "maximum_selected_count": 4096,
        "minimum_capture_numerator": 1,
        "minimum_capture_denominator": 2,
        "empty_population_policy": "unknown",
        "required_population_evidence_purposes": [
            "eligible-population",
            "selected-population",
        ],
    }
    return {"contract_id": population_contract_id(payload), **payload}


def _population_observation_payload(
    contract: dict[str, Any] | None = None,
) -> dict[str, Any]:
    source = _population_contract_payload() if contract is None else contract
    eligible_ids = ("4" * 64, "5" * 64)
    selected_ids = ("4" * 64,)
    return {
        "contract_id": source["contract_id"],
        "selector_rule_id": source["selector_rule_id"],
        "selector_spec_digest": source["selector_spec_digest"],
        "selector_engine_digest": source["selector_engine_digest"],
        "eligible_seen": 2,
        "eligible_population_digest": population_member_digest(eligible_ids),
        "selected_count": 1,
        "selected_population_digest": population_member_digest(selected_ids),
        "capture_numerator": 1,
        "capture_denominator": 2,
        "observed_at": "2026-01-01T00:10:00Z",
        "evidence_refs": [
            _evidence("population/eligible.json"),
            _evidence("population/selected.json"),
        ],
    }


def _failure_signature_payload(
    *, execution_status: str = "completed"
) -> dict[str, Any]:
    return {
        "execution_status": execution_status,
        "exit_codes": [1],
        "reason_codes": ["MUTATION_CAUGHT"],
        "predicate_ids": ["tests_passed"],
        "required_evidence_purposes": ["test-result"],
    }


def _control_contract_payload(
    *, arm_id: str = "6" * 64, fixture_digest: str = "7" * 64
) -> dict[str, Any]:
    signature = _failure_signature_payload()
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


def _control_observation_payload(
    *, status: str = "proven", execution_status: str = "completed"
) -> dict[str, Any]:
    contract = _control_contract_payload()
    signature = _failure_signature_payload(execution_status=execution_status)
    return {
        "control_id": contract["control_id"],
        "fixture_digest": contract["fixture_digest"],
        "provocation_digest": contract["provocation_digest"],
        "observed_failure_signature": signature,
        "observed_failure_signature_digest": failure_signature_digest(signature),
        "control_status": status,
        "evidence_refs": [_evidence("control/result.json")],
    }


def _revalidate(model: Any, **changes: Any) -> Any:
    payload = model.model_dump(mode="json")
    payload.update(copy.deepcopy(changes))
    return type(model).model_validate(payload)


class _LyingMapping(Mapping[str, Any]):
    def __init__(self) -> None:
        self.length_attempts = 0
        self.iteration_attempts = 0

    def __len__(self) -> int:
        self.length_attempts += 1
        return 1

    def __iter__(self) -> Iterator[str]:
        self.iteration_attempts += 1
        return iter(str(index) for index in range(1000))

    def __getitem__(self, key: str) -> Any:
        return key


class _ThrowingMapping(Mapping[str, Any]):
    def __init__(self) -> None:
        self.length_attempts = 0
        self.iteration_attempts = 0

    def __len__(self) -> int:
        self.length_attempts += 1
        raise RuntimeError("mapping length must not be read")

    def __iter__(self) -> Iterator[str]:
        self.iteration_attempts += 1
        raise RuntimeError("mapping iterator must not run")

    def __getitem__(self, key: str) -> Any:
        del key
        raise RuntimeError("mapping item must not be read")


class _LyingSequence(Sequence[str]):
    def __init__(self) -> None:
        self.length_attempts = 0
        self.item_attempts = 0

    def __len__(self) -> int:
        self.length_attempts += 1
        return 1

    def __getitem__(self, index: int) -> str:
        self.item_attempts += 1
        if index < 1000:
            return f"{index:064x}"
        raise IndexError


class _ThrowingSequence(Sequence[str]):
    def __init__(self) -> None:
        self.length_attempts = 0
        self.item_attempts = 0

    def __len__(self) -> int:
        self.length_attempts += 1
        raise RuntimeError("sequence length must not be read")

    def __getitem__(self, index: int) -> str:
        del index
        self.item_attempts += 1
        raise RuntimeError("sequence item must not be read")


class _DictSubclass(dict[str, Any]):
    pass


class _ListSubclass(list[str]):
    pass


def _deep_mapping(depth: int) -> dict[str, Any]:
    root: dict[str, Any] = {}
    cursor = root
    for _ in range(depth):
        child: dict[str, Any] = {}
        cursor["child"] = child
        cursor = child
    return root


def test_population_contract_exact_fields_and_domain_formula() -> None:
    raw = _population_contract_payload()
    contract = PopulationContractV05.model_validate(raw)
    payload = {key: value for key, value in raw.items() if key != "contract_id"}

    assert set(type(contract).model_fields) == set(raw)
    assert contract.contract_id == hashlib.sha256(
        rfc8785.dumps(
            {
                "domain": "openworkproof/population-contract/v0.5",
                "payload": payload,
            }
        )
    ).hexdigest()
    assert population_contract_id(contract) == contract.contract_id


def test_population_contract_id_excludes_own_id_and_binds_every_other_field() -> None:
    contract = PopulationContractV05.model_validate(_population_contract_payload())
    dumped = contract.model_dump(mode="json")
    dumped["contract_id"] = "f" * 64
    assert population_contract_id(dumped) == contract.contract_id

    dumped["minimum_selected_count"] = 2
    assert population_contract_id(dumped) != contract.contract_id


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        ("declared_selected_member_ids", [], "declared_selected_member_ids"),
        ("declared_selected_member_ids", ["4" * 64, "4" * 64], "sorted and unique"),
        ("required_population_evidence_purposes", ["selected", "eligible"], "sorted and unique"),
        ("maximum_eligible_count", 4097, "4096"),
        ("maximum_selected_count", 4097, "4096"),
        ("minimum_eligible_count", 2, "minimum_eligible_count"),
        ("minimum_selected_count", 2, "minimum_selected_count"),
        ("maximum_selected_count", 4096, "selected maximum"),
        ("minimum_capture_numerator", 3, "capture"),
        ("minimum_capture_denominator", 0, "1.."),
    ),
)
def test_population_contract_rejects_invalid_bounds_and_arrays(
    field: str, value: Any, message: str
) -> None:
    contract = PopulationContractV05.model_validate(_population_contract_payload())
    changes: dict[str, Any] = {field: value}
    if field == "minimum_eligible_count":
        changes["maximum_eligible_count"] = 1
        changes["maximum_selected_count"] = 1
    if field == "minimum_selected_count":
        changes["maximum_selected_count"] = 1
    if field == "maximum_selected_count" and value == 4096:
        changes["maximum_eligible_count"] = 4095
    with pytest.raises(ValidationError, match=message):
        _revalidate(contract, **changes)


@pytest.mark.parametrize(
    ("numerator", "denominator"),
    ((0, 2), (0, 3), (1, 0)),
)
def test_population_contract_rejects_noncanonical_zero_capture_bound(
    numerator: int, denominator: int
) -> None:
    contract = PopulationContractV05.model_validate(_population_contract_payload())
    with pytest.raises(ValidationError, match="0/1|capture"):
        _revalidate(
            contract,
            minimum_capture_numerator=numerator,
            minimum_capture_denominator=denominator,
        )


def test_population_contract_rejects_wrong_id_and_unknown_field() -> None:
    contract = PopulationContractV05.model_validate(_population_contract_payload())
    with pytest.raises(ValidationError, match="contract_id"):
        _revalidate(contract, contract_id="f" * 64)
    raw = contract.model_dump(mode="json")
    raw["unexpected"] = True
    with pytest.raises(ValidationError, match="Extra inputs"):
        PopulationContractV05.model_validate(raw)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        (
            "declared_selected_member_ids",
            [f"{index:064x}" for index in range(4097)],
            "4096",
        ),
        (
            "required_population_evidence_purposes",
            [f"purpose-{index:03d}" for index in range(257)],
            "256",
        ),
    ),
)
def test_population_contract_rejects_oversized_declared_arrays(
    field: str, value: list[str], message: str
) -> None:
    raw = _population_contract_payload()
    raw[field] = value
    with pytest.raises(ValidationError, match=message):
        PopulationContractV05.model_validate(raw)


def test_population_member_digest_is_stable_nonzero_and_mutation_sensitive() -> None:
    expected_empty = hashlib.sha256(
        rfc8785.dumps(
            {
                "domain": "openworkproof/population-members/v0.5",
                "payload": [],
            }
        )
    ).hexdigest()
    assert expected_empty == "7e2e22b988d0b2f74f0e851a871e91ef429aafa072653bf8a8f85f982dbdf693"
    assert population_member_digest(()) == expected_empty != "0" * 64
    assert population_member_digest(("1" * 64,)) != population_member_digest(
        ("2" * 64,)
    )
    for invalid in (("2" * 64, "1" * 64), ("1" * 64, "1" * 64), ("x",)):
        with pytest.raises(ValueError, match="sorted|unique|digest"):
            population_member_digest(invalid)


def test_population_member_digest_accepts_4096_and_rejects_4097_members() -> None:
    member_ids = tuple(f"{index:064x}" for index in range(4097))
    assert population_member_digest(member_ids[:4096]) != "0" * 64
    with pytest.raises(ValueError, match="4096"):
        population_member_digest(member_ids)


@pytest.mark.parametrize(
    "consumer",
    (
        population_contract_id,
        control_contract_id,
        failure_signature_digest,
    ),
)
def test_closed_input_shape_rejects_lying_mapping_without_traversal(
    consumer: Any,
) -> None:
    payload = _LyingMapping()
    with pytest.raises(ValueError, match="exact built-in dict"):
        consumer(payload)
    assert payload.length_attempts == 0
    assert payload.iteration_attempts == 0


@pytest.mark.parametrize(
    "model_type",
    (
        PopulationContractV05,
        PopulationObservationV05,
        FailureSignatureV05,
        ControlContractV05,
        ControlObservationV05,
        VerificationIntegrityAssessmentV05,
        VerificationProfileV05,
        VerificationArmResultV05,
        VerificationDecisionDraftV05,
        VerificationDecisionV05,
    ),
)
def test_closed_input_shape_rejects_throwing_mapping_without_traversal(
    model_type: type[Any],
) -> None:
    payload = _ThrowingMapping()
    with pytest.raises(ValueError, match="exact built-in dict"):
        model_type.model_validate(payload)
    assert payload.length_attempts == 0
    assert payload.iteration_attempts == 0


@pytest.mark.parametrize(
    "consumer",
    (
        population_contract_id,
        control_contract_id,
        failure_signature_digest,
        PopulationContractV05.model_validate,
    ),
)
def test_closed_input_shape_rejects_dict_subclasses(consumer: Any) -> None:
    with pytest.raises(ValueError, match="exact built-in dict"):
        consumer(_DictSubclass())


@pytest.mark.parametrize("sequence_type", (_LyingSequence, _ThrowingSequence))
def test_closed_input_shape_rejects_custom_sequence_without_traversal(
    sequence_type: type[Sequence[str]],
) -> None:
    members = sequence_type()
    with pytest.raises(ValueError, match="exact built-in list or tuple"):
        population_member_digest(members)
    assert members.length_attempts == 0
    assert members.item_attempts == 0


def test_closed_input_shape_accepts_exact_list_tuple_and_rejects_subclass() -> None:
    expected = population_member_digest(("1" * 64,))
    assert population_member_digest(["1" * 64]) == expected
    with pytest.raises(ValueError, match="exact built-in list or tuple"):
        population_member_digest(_ListSubclass(["1" * 64]))


@pytest.mark.parametrize(
    "consumer",
    (population_contract_id, control_contract_id, failure_signature_digest),
)
def test_closed_input_shape_still_rejects_extreme_builtin_depth(
    consumer: Any,
) -> None:
    with pytest.raises(ValueError, match="depth"):
        consumer(_deep_mapping(1500))


def test_population_observation_accepts_exact_reduced_fraction() -> None:
    observation = PopulationObservationV05.model_validate(
        _population_observation_payload()
    )
    assert observation.capture_numerator == 1
    assert observation.capture_denominator == 2
    assert tuple(ref.path for ref in observation.evidence_refs) == tuple(
        sorted(ref.path for ref in observation.evidence_refs)
    )


@pytest.mark.parametrize(
    ("changes", "message"),
    (
        ({"selected_count": 3}, "selected_count"),
        ({"capture_numerator": 2, "capture_denominator": 4}, "reduced"),
        ({"capture_numerator": 1, "capture_denominator": 3}, "exact"),
        ({"evidence_refs": [_evidence("z.json"), _evidence("a.json")]}, "path sorted"),
        ({"evidence_refs": [_evidence("a.json"), _evidence("a.json")]}, "path sorted"),
    ),
)
def test_population_observation_rejects_invalid_nonempty_semantics(
    changes: dict[str, Any], message: str
) -> None:
    observation = PopulationObservationV05.model_validate(
        _population_observation_payload()
    )
    with pytest.raises(ValidationError, match=message):
        _revalidate(observation, **changes)


def test_population_observation_closes_empty_population_semantics() -> None:
    empty_digest = population_member_digest(())
    raw = _population_observation_payload()
    raw.update(
        eligible_seen=0,
        eligible_population_digest=empty_digest,
        selected_count=0,
        selected_population_digest=empty_digest,
        capture_numerator=0,
        capture_denominator=1,
    )
    observation = PopulationObservationV05.model_validate(raw)

    for changes in (
        {"selected_count": 1},
        {"capture_denominator": 2},
        {"eligible_population_digest": "f" * 64},
        {"selected_population_digest": "f" * 64},
    ):
        with pytest.raises(ValidationError, match="empty|0/1|selected_count"):
            _revalidate(observation, **changes)


def test_population_observation_is_intrinsic_not_contract_comparison() -> None:
    raw = _population_observation_payload()
    raw["selector_engine_digest"] = "f" * 64
    assert PopulationObservationV05.model_validate(raw).selector_engine_digest == "f" * 64


def test_failure_signature_exact_fields_formula_and_mutation_sensitivity() -> None:
    raw = _failure_signature_payload()
    signature = FailureSignatureV05.model_validate(raw)
    expected = hashlib.sha256(
        rfc8785.dumps(
            {
                "domain": "openworkproof/failure-signature/v0.5",
                "payload": raw,
            }
        )
    ).hexdigest()
    assert set(type(signature).model_fields) == set(raw)
    assert failure_signature_digest(signature) == expected
    mutated = signature.model_copy(
        update={"exit_codes": (2,)},
    )
    assert failure_signature_digest(mutated) != expected


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("exit_codes", []),
        ("exit_codes", [1, 1]),
        ("reason_codes", ["SCOPE_UNPROVEN", "MUTATION_CAUGHT"]),
        ("predicate_ids", ["tests_passed", "tests_passed"]),
        ("required_evidence_purposes", []),
        ("exit_codes", list(range(65))),
        ("reason_codes", [f"CODE-{index:03d}" for index in range(257)]),
    ),
)
def test_failure_signature_rejects_invalid_arrays(field: str, value: Any) -> None:
    signature = FailureSignatureV05.model_validate(_failure_signature_payload())
    with pytest.raises(ValidationError, match="non-empty|sorted|unique|64|256"):
        _revalidate(signature, **{field: value})


def test_failure_signature_rejects_unknown_reason_code() -> None:
    raw = _failure_signature_payload()
    raw["reason_codes"] = ["NOT_A_VERIFICATION_REASON"]
    with pytest.raises(ValidationError, match="reason_codes"):
        FailureSignatureV05.model_validate(raw)


def test_control_contract_exact_fields_and_nested_domain_formulas() -> None:
    raw = _control_contract_payload()
    contract = ControlContractV05.model_validate(raw)
    payload = {key: value for key, value in raw.items() if key != "control_id"}
    assert set(type(contract).model_fields) == set(raw)
    assert contract.control_id == hashlib.sha256(
        rfc8785.dumps(
            {
                "domain": "openworkproof/control-contract/v0.5",
                "payload": payload,
            }
        )
    ).hexdigest()
    assert control_contract_id(contract) == contract.control_id


@pytest.mark.parametrize(
    ("changes", "message"),
    (
        ({"control_id": "f" * 64}, "control_id"),
        ({"expected_failure_signature_digest": "f" * 64}, "signature digest"),
        ({"valid_from": "2026-01-01T01:00:00Z"}, "times"),
        ({"expires_at": "2026-01-01T00:00:00Z"}, "times"),
    ),
)
def test_control_contract_rejects_wrong_digests_and_times(
    changes: dict[str, Any], message: str
) -> None:
    contract = ControlContractV05.model_validate(_control_contract_payload())
    with pytest.raises(ValidationError, match=message):
        _revalidate(contract, **changes)


def test_control_contract_requires_completed_expected_signature() -> None:
    raw = _control_contract_payload()
    signature = _failure_signature_payload(execution_status="crashed")
    raw["expected_failure_signature"] = signature
    raw["expected_failure_signature_digest"] = failure_signature_digest(signature)
    raw["control_id"] = control_contract_id(raw)
    with pytest.raises(ValidationError, match="completed"):
        ControlContractV05.model_validate(raw)


def test_control_contract_id_excludes_own_id_and_binds_nested_signature() -> None:
    contract = ControlContractV05.model_validate(_control_contract_payload())
    raw = contract.model_dump(mode="json")
    raw["control_id"] = "f" * 64
    assert control_contract_id(raw) == contract.control_id
    raw["provocation_digest"] = "f" * 64
    assert control_contract_id(raw) != contract.control_id


@pytest.mark.parametrize(
    ("status", "execution_status", "evidence", "valid"),
    (
        ("proven", "completed", True, True),
        ("proven", "crashed", True, False),
        ("proven", "completed", False, False),
        ("survived", "completed", True, True),
        ("survived", "timed_out", True, False),
        ("survived", "completed", False, False),
        ("mismatched", "crashed", True, False),
        ("mismatched", "completed", False, False),
        ("unavailable", "crashed", True, True),
        ("unavailable", "evidence_unavailable", False, True),
    ),
)
def test_control_observation_status_constraints(
    status: str, execution_status: str, evidence: bool, valid: bool
) -> None:
    raw = _control_observation_payload(
        status=status, execution_status=execution_status
    )
    if not evidence:
        raw["evidence_refs"] = []
    if valid:
        assert ControlObservationV05.model_validate(raw).control_status == status
    else:
        with pytest.raises(ValidationError, match="evidence|completed"):
            ControlObservationV05.model_validate(raw)


def test_control_observation_rejects_wrong_nested_digest_and_unsorted_refs() -> None:
    observation = ControlObservationV05.model_validate(
        _control_observation_payload()
    )
    with pytest.raises(ValidationError, match="signature digest"):
        _revalidate(observation, observed_failure_signature_digest="f" * 64)
    with pytest.raises(ValidationError, match="path sorted"):
        _revalidate(
            observation,
            evidence_refs=[_evidence("z.json"), _evidence("a.json")],
        )


@pytest.mark.parametrize(
    ("model_type", "payload"),
    (
        (PopulationObservationV05, _population_observation_payload()),
        (FailureSignatureV05, _failure_signature_payload()),
        (ControlContractV05, _control_contract_payload()),
        (ControlObservationV05, _control_observation_payload()),
        (
            VerificationIntegrityAssessmentV05,
            {
                "population_status": "matched",
                "control_status": "proven",
                "reason_codes": [],
            },
        ),
    ),
)
def test_nested_v05_models_reject_unknown_fields(
    model_type: type[Any], payload: dict[str, Any]
) -> None:
    raw = copy.deepcopy(payload)
    raw["unexpected"] = True
    with pytest.raises(ValidationError, match="Extra inputs"):
        model_type.model_validate(raw)


@pytest.mark.parametrize(
    ("population_status", "control_status", "reason_codes"),
    (
        ("matched", "proven", []),
        ("empty", "proven", ["NO_ELIGIBLE_POPULATION"]),
        ("capture_failed", "proven", ["POPULATION_CAPTURE_FAILED"]),
        ("drifted", "proven", ["POPULATION_ENGINE_DRIFT"]),
        ("unavailable", "proven", ["POPULATION_EVIDENCE_MISSING"]),
        ("matched", "survived", ["CONTROL_SURVIVED"]),
        ("matched", "mismatched", ["CONTROL_FIXTURE_DRIFT"]),
        ("matched", "unavailable", ["CONTROL_EVIDENCE_MISSING"]),
        (
            "drifted",
            "mismatched",
            ["CONTROL_PROVOCATION_DRIFT", "POPULATION_RULE_DRIFT"],
        ),
    ),
)
def test_integrity_assessment_accepts_compatible_status_codes(
    population_status: str, control_status: str, reason_codes: list[str]
) -> None:
    assessment = VerificationIntegrityAssessmentV05.model_validate(
        {
            "population_status": population_status,
            "control_status": control_status,
            "reason_codes": reason_codes,
        }
    )
    assert list(assessment.reason_codes) == reason_codes


@pytest.mark.parametrize(
    ("population_status", "control_status", "reason_codes"),
    (
        ("matched", "proven", ["POPULATION_RULE_DRIFT"]),
        ("empty", "proven", []),
        ("capture_failed", "proven", ["NO_ELIGIBLE_POPULATION"]),
        ("drifted", "proven", ["POPULATION_CAPTURE_FAILED"]),
        ("unavailable", "proven", ["POPULATION_ENGINE_DRIFT"]),
        ("matched", "proven", ["CONTROL_SURVIVED"]),
        ("matched", "survived", []),
        ("matched", "mismatched", ["CONTROL_EVIDENCE_MISSING"]),
        ("matched", "unavailable", ["CONTROL_FAILURE_SIGNATURE_MISMATCH"]),
        ("matched", "proven", ["UNKNOWN_CODE"]),
        ("matched", "survived", ["CONTROL_SURVIVED", "CONTROL_SURVIVED"]),
    ),
)
def test_integrity_assessment_rejects_incompatible_status_codes(
    population_status: str, control_status: str, reason_codes: list[str]
) -> None:
    with pytest.raises(ValidationError):
        VerificationIntegrityAssessmentV05.model_validate(
            {
                "population_status": population_status,
                "control_status": control_status,
                "reason_codes": reason_codes,
            }
        )


def _signed_profile_v05(
    base: VerificationProfileV03,
    private_key: Ed25519PrivateKey,
    *,
    population_contracts: list[dict[str, Any]] | None = None,
    control_contracts: list[dict[str, Any]] | None = None,
) -> VerificationProfileV05:
    payload = base.model_dump(
        mode="json",
        exclude={"digest", "signature_alg", "signer_key_id", "signature"},
    )
    payload["schema_version"] = "openworkproof-verification-profile/0.5"
    payload["population_contracts"] = (
        [_population_contract_payload()]
        if population_contracts is None
        else population_contracts
    )
    negative_arm = payload["negative_arms"][0]
    payload["control_contracts"] = (
        [
            _control_contract_payload(
                arm_id=negative_arm["arm_id"],
                fixture_digest=negative_arm["mutant_patch_digest"],
            )
        ]
        if control_contracts is None
        else control_contracts
    )
    return VerificationProfileV05.model_validate(
        sign_payload(
            "verification-profile", payload, private_key, version="0.5"
        )
    )


def _signed_arm_result_v05(
    base: VerificationArmResultV03,
    private_key: Ed25519PrivateKey,
    *,
    arm_kind: str = "positive",
    population_observations: list[dict[str, Any]] | None = None,
    control_observation: dict[str, Any] | None = None,
) -> VerificationArmResultV05:
    payload = base.model_dump(
        mode="json",
        exclude={"digest", "signature_alg", "signer_key_id", "signature"},
    )
    payload["schema_version"] = "openworkproof-verification-arm-result/0.5"
    payload["population_observations"] = (
        [_population_observation_payload()]
        if population_observations is None
        else population_observations
    )
    if arm_kind == "negative":
        payload.update(
            arm_result_id="9" * 64,
            arm_id="2" * 64,
            arm_kind="negative",
            mutation_status="applied",
            reason_codes=["MUTATION_APPLIED", "MUTATION_CAUGHT"],
        )
        payload["control_observation"] = (
            _control_observation_payload()
            if control_observation is None
            else control_observation
        )
    else:
        payload["control_observation"] = control_observation
    return VerificationArmResultV05.model_validate(
        sign_payload(
            "verification-arm-result", payload, private_key, version="0.5"
        )
    )


def _integrity(
    population_status: str = "matched",
    control_status: str = "proven",
) -> dict[str, Any]:
    population_reason = {
        "matched": [],
        "empty": ["NO_ELIGIBLE_POPULATION"],
        "capture_failed": ["POPULATION_CAPTURE_FAILED"],
        "drifted": ["POPULATION_RULE_DRIFT"],
        "unavailable": ["POPULATION_EVIDENCE_MISSING"],
    }[population_status]
    control_reason = {
        "proven": [],
        "survived": ["CONTROL_SURVIVED"],
        "mismatched": ["CONTROL_FAILURE_SIGNATURE_MISMATCH"],
        "unavailable": ["CONTROL_EVIDENCE_MISSING"],
    }[control_status]
    return {
        "population_status": population_status,
        "control_status": control_status,
        "reason_codes": sorted(population_reason + control_reason),
    }


def _draft_v05(
    base: VerificationDecisionV03,
    *,
    decision: str = "VERIFIED",
    population_status: str = "matched",
    control_status: str = "proven",
) -> VerificationDecisionDraftV05:
    payload = base.model_dump(
        mode="json",
        exclude={"schema_version", "digest", "verifier_signatures"},
    )
    integrity = _integrity(population_status, control_status)
    payload["decision"] = decision
    payload["integrity_assessment"] = integrity
    payload["reason_codes"] = sorted(
        list(base.reason_codes) + integrity["reason_codes"]
    )
    return VerificationDecisionDraftV05.model_validate(payload)


def _decision_payload_v05(
    draft: VerificationDecisionDraftV05,
    base: VerificationDecisionV03,
    verifier_key: Ed25519PrivateKey,
) -> dict[str, Any]:
    return _raw_decision_payload_v05(
        draft.model_dump(mode="json"), base, verifier_key
    )


def _raw_decision_payload_v05(
    draft_payload: dict[str, Any],
    base: VerificationDecisionV03,
    verifier_key: Ed25519PrivateKey,
) -> dict[str, Any]:
    unsigned = {
        "schema_version": "openworkproof-verification-decision/0.5",
        **copy.deepcopy(draft_payload),
    }
    encoded = canonical_bytes(
        "verification-decision", unsigned, version="0.5"
    )
    return {
        **unsigned,
        "digest": hashlib.sha256(encoded).hexdigest(),
        "verifier_signatures": [
            {
                "verifier_subject_id": (
                    base.verifier_signatures[0].verifier_subject_id
                ),
                "verifier_key_id": key_id(verifier_key.public_key()),
                "signature_alg": "Ed25519",
                "signature": base64.urlsafe_b64encode(
                    verifier_key.sign(encoded)
                ).decode("ascii").rstrip("="),
            }
        ],
    }


def _decision_reason_payload(
    base: VerificationDecisionV03,
    *,
    decision: str,
    assessment: dict[str, Any],
    top_integrity_reasons: list[str],
    v03_reasons: list[str] | None = None,
) -> dict[str, Any]:
    payload = base.model_dump(
        mode="json",
        exclude={"schema_version", "digest", "verifier_signatures"},
    )
    payload["decision"] = decision
    payload["integrity_assessment"] = assessment
    payload["reason_codes"] = sorted(
        (list(base.reason_codes) if v03_reasons is None else v03_reasons)
        + top_integrity_reasons
    )
    return payload


def _valid_v05_model_instances(
    frozen_verification_profile_v03: VerificationProfileV03,
    frozen_verification_arm_result_v03: VerificationArmResultV03,
    frozen_verification_decision_v03: VerificationDecisionV03,
    frozen_role_keys_v05: dict[str, tuple[Ed25519PrivateKey, dict[str, str]]],
) -> tuple[Any, ...]:
    verifier_key = frozen_role_keys_v05["Verifier"][0]
    population_contract = PopulationContractV05.model_validate(
        _population_contract_payload()
    )
    population_observation = PopulationObservationV05.model_validate(
        _population_observation_payload()
    )
    failure_signature = FailureSignatureV05.model_validate(
        _failure_signature_payload()
    )
    control_contract = ControlContractV05.model_validate(
        _control_contract_payload()
    )
    control_observation = ControlObservationV05.model_validate(
        _control_observation_payload()
    )
    integrity_assessment = VerificationIntegrityAssessmentV05.model_validate(
        _integrity()
    )
    profile = _signed_profile_v05(
        frozen_verification_profile_v03,
        frozen_role_keys_v05["Manager"][0],
    )
    arm_result = _signed_arm_result_v05(
        frozen_verification_arm_result_v03, verifier_key
    )
    draft = _draft_v05(frozen_verification_decision_v03)
    decision = VerificationDecisionV05.model_validate(
        _decision_payload_v05(
            draft,
            frozen_verification_decision_v03,
            verifier_key,
        )
    )
    return (
        population_contract,
        population_observation,
        failure_signature,
        control_contract,
        control_observation,
        integrity_assessment,
        profile,
        arm_result,
        draft,
        decision,
    )


@pytest.mark.parametrize(
    ("model_index", "field", "invalid_value"),
    (
        (0, "member_kind", "invalid-member-kind"),
        (1, "selector_rule_id", "not-a-digest"),
        (2, "execution_status", "invalid-execution"),
        (3, "control_target", "invalid-target"),
        (4, "control_status", "invalid-status"),
        (5, "population_status", "invalid-status"),
        (6, "schema_version", "openworkproof-verification-profile/invalid"),
        (7, "schema_version", "openworkproof-verification-arm-result/invalid"),
        (8, "decision", "INVALID"),
        (9, "digest", "f" * 64),
    ),
)
def test_v05_models_revalidate_malicious_subclass_instances(
    frozen_verification_profile_v03: VerificationProfileV03,
    frozen_verification_arm_result_v03: VerificationArmResultV03,
    frozen_verification_decision_v03: VerificationDecisionV03,
    frozen_role_keys_v05: dict[str, tuple[Ed25519PrivateKey, dict[str, str]]],
    model_index: int,
    field: str,
    invalid_value: Any,
) -> None:
    valid = _valid_v05_model_instances(
        frozen_verification_profile_v03,
        frozen_verification_arm_result_v03,
        frozen_verification_decision_v03,
        frozen_role_keys_v05,
    )[model_index]
    model_type = type(valid)
    assert model_type.model_validate(valid) is valid
    assert model_type.model_validate(valid.model_dump(mode="json")) == valid

    malicious_type = type(
        f"_Malicious{model_type.__name__}",
        (model_type,),
        {},
    )
    malicious_payload = valid.model_dump(mode="python")
    malicious_payload[field] = invalid_value
    malicious = malicious_type.model_construct(**malicious_payload)
    with pytest.raises(ValidationError):
        model_type.model_validate(malicious)


def test_v05_profile_is_signed_only_in_v05_domain(
    frozen_verification_profile_v03: VerificationProfileV03,
    frozen_role_keys_v05: dict[str, tuple[Ed25519PrivateKey, dict[str, str]]],
) -> None:
    manager_key = frozen_role_keys_v05["Manager"][0]
    profile = _signed_profile_v05(frozen_verification_profile_v03, manager_key)
    dumped = profile.model_dump(mode="json")

    assert profile.schema_version == "openworkproof-verification-profile/0.5"
    assert verify_payload(
        "verification-profile", dumped, manager_key.public_key(), version="0.5"
    )
    assert not verify_payload(
        "verification-profile", dumped, manager_key.public_key(), version="0.3"
    )
    with pytest.raises(ValidationError, match="frozen_instance"):
        profile.profile_id = "f" * 64


def test_v05_profile_rejects_population_and_control_cardinality(
    frozen_verification_profile_v03: VerificationProfileV03,
    frozen_role_keys_v05: dict[str, tuple[Ed25519PrivateKey, dict[str, str]]],
) -> None:
    manager_key = frozen_role_keys_v05["Manager"][0]
    for population_contracts, control_contracts, message in (
        ([], None, "population contracts"),
        ([_population_contract_payload()] * 2, None, "population contracts"),
        (None, [], "control contracts"),
    ):
        with pytest.raises(ValidationError, match=message):
            _signed_profile_v05(
                frozen_verification_profile_v03,
                manager_key,
                population_contracts=population_contracts,
                control_contracts=control_contracts,
            )


def test_v05_profile_rejects_positive_control_duplicate_arm_and_fixture_drift(
    frozen_verification_profile_v03: VerificationProfileV03,
    frozen_role_keys_v05: dict[str, tuple[Ed25519PrivateKey, dict[str, str]]],
) -> None:
    manager_key = frozen_role_keys_v05["Manager"][0]
    negative = frozen_verification_profile_v03.negative_arms[0]
    cases = (
        (
            [_control_contract_payload(arm_id=frozen_verification_profile_v03.positive_arm.arm_id)],
            "positive",
        ),
        (
            [
                _control_contract_payload(
                    arm_id=negative.arm_id,
                    fixture_digest=negative.mutant_patch_digest,
                )
            ]
            * 2,
            "control contracts",
        ),
        (
            [_control_contract_payload(arm_id=negative.arm_id, fixture_digest="f" * 64)],
            "fixture_digest",
        ),
    )
    for contracts, message in cases:
        with pytest.raises(ValidationError, match=message):
            _signed_profile_v05(
                frozen_verification_profile_v03,
                manager_key,
                control_contracts=contracts,
            )


def test_v05_profile_rejects_unsorted_population_contracts(
    frozen_verification_profile_v03: VerificationProfileV03,
    frozen_role_keys_v05: dict[str, tuple[Ed25519PrivateKey, dict[str, str]]],
) -> None:
    first = _population_contract_payload()
    second_payload = {
        **first,
        "selector_rule_id": "9" * 64,
        "declared_selected_member_ids": ["a" * 64],
    }
    second_payload["contract_id"] = population_contract_id(second_payload)
    contracts = sorted([first, second_payload], key=lambda item: item["contract_id"])
    with pytest.raises(ValidationError, match="population contracts"):
        _signed_profile_v05(
            frozen_verification_profile_v03,
            frozen_role_keys_v05["Manager"][0],
            population_contracts=list(reversed(contracts)),
        )


def test_v05_arm_result_closes_population_and_control_shape(
    frozen_verification_arm_result_v03: VerificationArmResultV03,
    frozen_role_keys_v05: dict[str, tuple[Ed25519PrivateKey, dict[str, str]]],
) -> None:
    verifier_key = frozen_role_keys_v05["Verifier"][0]
    positive = _signed_arm_result_v05(
        frozen_verification_arm_result_v03, verifier_key
    )
    negative = _signed_arm_result_v05(
        frozen_verification_arm_result_v03,
        verifier_key,
        arm_kind="negative",
    )
    assert positive.control_observation is None
    assert negative.control_observation is not None
    assert verify_payload(
        "verification-arm-result",
        positive.model_dump(mode="json"),
        verifier_key.public_key(),
        version="0.5",
    )
    assert not verify_payload(
        "verification-arm-result",
        positive.model_dump(mode="json"),
        verifier_key.public_key(),
        version="0.3",
    )


def test_v05_arm_result_rejects_empty_duplicate_and_control_wrong_arm_kind(
    frozen_verification_arm_result_v03: VerificationArmResultV03,
    frozen_role_keys_v05: dict[str, tuple[Ed25519PrivateKey, dict[str, str]]],
) -> None:
    verifier_key = frozen_role_keys_v05["Verifier"][0]
    observation = _population_observation_payload()
    with pytest.raises(ValidationError, match="population observations"):
        _signed_arm_result_v05(
            frozen_verification_arm_result_v03,
            verifier_key,
            population_observations=[],
        )
    with pytest.raises(ValidationError, match="population observations"):
        _signed_arm_result_v05(
            frozen_verification_arm_result_v03,
            verifier_key,
            population_observations=[observation, observation],
        )
    with pytest.raises(ValidationError, match="positive"):
        _signed_arm_result_v05(
            frozen_verification_arm_result_v03,
            verifier_key,
            control_observation=_control_observation_payload(),
        )

    payload = frozen_verification_arm_result_v03.model_dump(
        mode="json",
        exclude={"digest", "signature_alg", "signer_key_id", "signature"},
    )
    payload.update(
        schema_version="openworkproof-verification-arm-result/0.5",
        arm_result_id="9" * 64,
        arm_id="2" * 64,
        arm_kind="negative",
        mutation_status="applied",
        reason_codes=["MUTATION_APPLIED", "MUTATION_CAUGHT"],
        population_observations=[observation],
        control_observation=None,
    )
    with pytest.raises(ValidationError, match="negative"):
        VerificationArmResultV05.model_validate(
            sign_payload(
                "verification-arm-result", payload, verifier_key, version="0.5"
            )
        )


@pytest.mark.parametrize(
    ("decision", "assessment", "top_integrity_reasons"),
    (
        ("REFUTED", _integrity("matched", "survived"), []),
        ("VERIFIED", _integrity("matched", "proven"), ["CONTROL_SURVIVED"]),
        (
            "UNKNOWN",
            _integrity("drifted", "proven"),
            ["POPULATION_ENGINE_DRIFT"],
        ),
    ),
)
def test_decision_reason_codes_match_integrity_assessment_exactly(
    frozen_verification_decision_v03: VerificationDecisionV03,
    frozen_role_keys_v05: dict[str, tuple[Ed25519PrivateKey, dict[str, str]]],
    decision: str,
    assessment: dict[str, Any],
    top_integrity_reasons: list[str],
) -> None:
    draft_payload = _decision_reason_payload(
        frozen_verification_decision_v03,
        decision=decision,
        assessment=assessment,
        top_integrity_reasons=top_integrity_reasons,
    )
    with pytest.raises(ValidationError, match="integrity reason codes"):
        VerificationDecisionDraftV05.model_validate(draft_payload)
    with pytest.raises(ValidationError, match="integrity reason codes"):
        VerificationDecisionV05.model_validate(
            _raw_decision_payload_v05(
                draft_payload,
                frozen_verification_decision_v03,
                frozen_role_keys_v05["Verifier"][0],
            )
        )


def test_decision_reason_codes_preserve_v03_reasons_outside_integrity_equality(
    frozen_verification_decision_v03: VerificationDecisionV03,
    frozen_role_keys_v05: dict[str, tuple[Ed25519PrivateKey, dict[str, str]]],
) -> None:
    draft_payload = _decision_reason_payload(
        frozen_verification_decision_v03,
        decision="UNKNOWN",
        assessment=_integrity(),
        top_integrity_reasons=[],
        v03_reasons=["SCOPE_UNPROVEN"],
    )
    draft_payload["scope_assessment"]["scope_status"] = "indeterminate"
    draft = VerificationDecisionDraftV05.model_validate(draft_payload)
    decision = VerificationDecisionV05.model_validate(
        _raw_decision_payload_v05(
            draft.model_dump(mode="json"),
            frozen_verification_decision_v03,
            frozen_role_keys_v05["Verifier"][0],
        )
    )
    assert draft.reason_codes == decision.reason_codes == ("SCOPE_UNPROVEN",)


def test_v05_decision_signature_uses_exact_v05_bytes_and_keeps_cardinality(
    frozen_verification_decision_v03: VerificationDecisionV03,
    frozen_role_keys_v05: dict[str, tuple[Ed25519PrivateKey, dict[str, str]]],
) -> None:
    draft = _draft_v05(frozen_verification_decision_v03)
    payload = _decision_payload_v05(
        draft,
        frozen_verification_decision_v03,
        frozen_role_keys_v05["Verifier"][0],
    )
    decision = VerificationDecisionV05.model_validate(payload)
    assert decision.schema_version == "openworkproof-verification-decision/0.5"
    unsigned = decision.model_dump(
        mode="json", exclude={"digest", "verifier_signatures"}
    )
    encoded = canonical_bytes(
        "verification-decision", unsigned, version="0.5"
    )
    frozen_role_keys_v05["Verifier"][0].public_key().verify(
        base64.urlsafe_b64decode(
            decision.verifier_signatures[0].signature
            + "=" * (-len(decision.verifier_signatures[0].signature) % 4)
        ),
        encoded,
    )

    wrong = copy.deepcopy(payload)
    unsigned = {
        key: value
        for key, value in wrong.items()
        if key not in {"digest", "verifier_signatures"}
    }
    wrong["digest"] = hashlib.sha256(
        rfc8785.dumps(
            {
                "domain": "openworkproof/verification-decision/v0.3",
                "payload": unsigned,
            }
        )
    ).hexdigest()
    with pytest.raises(ValidationError, match="digest"):
        VerificationDecisionV05.model_validate(wrong)

    no_signatures = copy.deepcopy(payload)
    no_signatures["verifier_signatures"] = []
    with pytest.raises(ValidationError, match="signature set"):
        VerificationDecisionV05.model_validate(no_signatures)


@pytest.mark.parametrize(
    ("population_status", "control_status", "decision"),
    (
        ("empty", "proven", "VERIFIED"),
        ("capture_failed", "survived", "REFUTED"),
        ("drifted", "mismatched", "REFUTED"),
        ("unavailable", "unavailable", "VERIFIED"),
        ("matched", "survived", "VERIFIED"),
        ("matched", "mismatched", "REFUTED"),
        ("matched", "unavailable", "VERIFIED"),
    ),
)
def test_v05_draft_and_decision_reject_contradictory_integrity_status(
    frozen_verification_decision_v03: VerificationDecisionV03,
    frozen_role_keys_v05: dict[str, tuple[Ed25519PrivateKey, dict[str, str]]],
    population_status: str,
    control_status: str,
    decision: str,
) -> None:
    with pytest.raises(ValidationError, match="UNKNOWN|REFUTED"):
        _draft_v05(
            frozen_verification_decision_v03,
            decision=decision,
            population_status=population_status,
            control_status=control_status,
        )

    valid_decision = (
        "UNKNOWN"
        if population_status != "matched"
        or control_status in {"mismatched", "unavailable"}
        else "REFUTED"
    )
    draft = _draft_v05(
        frozen_verification_decision_v03,
        decision=valid_decision,
        population_status=population_status,
        control_status=control_status,
    )
    draft_payload = draft.model_dump(mode="json")
    draft_payload["decision"] = decision
    payload = _raw_decision_payload_v05(
        draft_payload,
        frozen_verification_decision_v03,
        frozen_role_keys_v05["Verifier"][0],
    )
    with pytest.raises(ValidationError, match="UNKNOWN|REFUTED"):
        VerificationDecisionV05.model_validate(payload)


def test_v05_decision_keeps_v03_scope_status_constraint(
    frozen_verification_decision_v03: VerificationDecisionV03,
) -> None:
    raw = frozen_verification_decision_v03.model_dump(
        mode="json", exclude={"schema_version", "digest", "verifier_signatures"}
    )
    raw["scope_assessment"]["scope_status"] = "indeterminate"
    raw["decision"] = "VERIFIED"
    raw["integrity_assessment"] = _integrity()
    with pytest.raises(ValidationError, match="scope requires UNKNOWN"):
        VerificationDecisionDraftV05.model_validate(raw)


def test_v05_signing_domains_reject_nested_objects_and_unsigned_decision() -> None:
    key = Ed25519PrivateKey.generate()
    for domain, payload in (
        ("population-contract", _population_contract_payload()),
        ("population-observation", _population_observation_payload()),
        ("failure-signature", _failure_signature_payload()),
        ("control-contract", _control_contract_payload()),
        ("control-observation", _control_observation_payload()),
        ("verification-decision", {"value": 1}),
    ):
        with pytest.raises(ValueError, match="cannot be signed"):
            sign_payload(domain, payload, key, version="0.5")

    assert canonical_bytes(
        "verification-decision", {"value": 1}, version="0.5"
    ) != canonical_bytes(
        "verification-decision", {"value": 1}, version="0.3"
    )


def test_v05_siblings_reject_unknown_fields_and_wrong_schema(
    frozen_verification_profile_v03: VerificationProfileV03,
    frozen_verification_arm_result_v03: VerificationArmResultV03,
    frozen_verification_decision_v03: VerificationDecisionV03,
    frozen_role_keys_v05: dict[str, tuple[Ed25519PrivateKey, dict[str, str]]],
) -> None:
    profile = _signed_profile_v05(
        frozen_verification_profile_v03,
        frozen_role_keys_v05["Manager"][0],
    )
    arm_result = _signed_arm_result_v05(
        frozen_verification_arm_result_v03,
        frozen_role_keys_v05["Verifier"][0],
    )
    draft = _draft_v05(frozen_verification_decision_v03)
    decision = VerificationDecisionV05.model_validate(
        _decision_payload_v05(
            draft,
            frozen_verification_decision_v03,
            frozen_role_keys_v05["Verifier"][0],
        )
    )

    for model in (profile, arm_result, draft, decision):
        raw = model.model_dump(mode="json")
        raw["unexpected"] = True
        with pytest.raises(ValidationError, match="Extra inputs"):
            type(model).model_validate(raw)

    for model in (profile, arm_result, decision):
        raw = model.model_dump(mode="json")
        raw["schema_version"] = raw["schema_version"].replace("0.5", "0.3")
        with pytest.raises(ValidationError, match="schema_version"):
            type(model).model_validate(raw)


def test_frozen_pre_v05_canonical_bytes_and_signatures(
    frozen_verification_profile_v02: VerificationProfileV02,
    evaluation_scope_v03: EvaluationScopeManifest,
    frozen_verification_profile_v03: VerificationProfileV03,
    frozen_verification_arm_result_v03: VerificationArmResultV03,
    frozen_verification_decision_v03: VerificationDecisionV03,
    action_binding_manifest_v04: ActionBindingManifest,
) -> None:
    actual = {
        "v02_profile_digest": hashlib.sha256(
            canonical_bytes(
                "verification-profile",
                frozen_verification_profile_v02.model_dump(mode="json"),
            )
        ).hexdigest(),
        "v02_profile_signature": frozen_verification_profile_v02.signature,
        "v03_scope_digest": hashlib.sha256(
            canonical_bytes(
                "evaluation-scope",
                evaluation_scope_v03.model_dump(mode="json"),
                version="0.3",
            )
        ).hexdigest(),
        "v03_scope_signature": evaluation_scope_v03.signature,
        "v03_profile_digest": hashlib.sha256(
            canonical_bytes(
                "verification-profile",
                frozen_verification_profile_v03.model_dump(mode="json"),
                version="0.3",
            )
        ).hexdigest(),
        "v03_profile_signature": frozen_verification_profile_v03.signature,
        "v03_arm_result_digest": hashlib.sha256(
            canonical_bytes(
                "verification-arm-result",
                frozen_verification_arm_result_v03.model_dump(mode="json"),
                version="0.3",
            )
        ).hexdigest(),
        "v03_arm_result_signature": frozen_verification_arm_result_v03.signature,
        "v03_decision_digest": hashlib.sha256(
            verification_decision_signing_bytes_v03(frozen_verification_decision_v03)
        ).hexdigest(),
        "v03_decision_signature": (
            frozen_verification_decision_v03.verifier_signatures[0].signature
        ),
        "v04_binding_digest": hashlib.sha256(
            canonical_bytes(
                "action-binding-manifest",
                action_binding_manifest_v04.model_dump(mode="json"),
                version="0.4",
            )
        ).hexdigest(),
        "v04_binding_signature": action_binding_manifest_v04.signature,
    }

    assert actual == {
        "v02_profile_digest": "38a8cb8c9a415980d8f3c9df4b7b5d08f8245b2ea124271cafed178d73315245",
        "v02_profile_signature": "fqv9pL7SPmGgYclR4NzEjTnP5SPqAxwjbfOslM6_kbfrBm3bllDy_U-bP9Pr6eoQlRKdZsDRqlL-T8wj8NAaAw",
        "v03_scope_digest": "13365cbb1a2af3a4951fc838ab07e58f63387e0cd79ca61c8635981626fa1f83",
        "v03_scope_signature": "ktEnletSX2ROHAiOeYUlX2XCg6U1b7xKEkf07TV2_zBhlhRHTg27OprAqhFrCFVyarCJ5S6oCQtxcIQpG_htAA",
        "v03_profile_digest": "4f254e559a556a3fc86cc98f5ab03bd25dbb6867f0584cc0e8dfc7c64a224ca2",
        "v03_profile_signature": "5G_YOMtMU45QiyI6nq5FCx4MyNHaARMTBNmAWngu1YZjvVZXiuhZ1TX_LKmMF-W5xqlWehPzxyLd5k6JIdLhBA",
        "v03_arm_result_digest": "62b43fa1134d7f68f51e0e7153ab43fabb9966534d338c61f6f2e112784805ef",
        "v03_arm_result_signature": "MVMhXvzqhgaiysA4Qqcv9jfY0AQqR2sDjqfHdri7dDhg4HeoICIb08FOu4whi183VmBw1AhVPnkNrvX26QXIAA",
        "v03_decision_digest": "db0c57be0f83c38b585c39f3c631b1efee83d7f87308d5c97bd5869360ccf73b",
        "v03_decision_signature": "7TS6R1-oBNStohQhx_Ce6LGdV0ucyGMhzGfeUF2IhLHoQfNYWvc2WwtGWMccicvp1c66SAZqDbYQlTIp7LSXCQ",
        "v04_binding_digest": "34b81680b9e1e5af65de11420a19154981d9f7b45ff9c8429139086e2fa253c2",
        "v04_binding_signature": "EBGSKn-kzOLdLB06vIRxr9Qrydj6jCA-xeUhRcyLx5rrTdnNWKp_uC3Co2w7Dg1xSe0Vg5gxIFtFT3b5tNUYAQ",
    }
