from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest

from openworkproof.cli import app as cli_app
from openworkproof.mcp_transport import (
    owp_control_observation_validate,
    owp_integrity_observation_validate,
)
from openworkproof.models import VerificationDecisionDraftV05
from openworkproof.services import OpenWorkProofServices
from openworkproof.signing import key_id
from openworkproof.verification import verification_decision_signing_bytes_v05

from test_verification_integrity_transactions_v05 import (
    commit_verification_arm_result_v05,
    commit_verification_decision_v05,
    commit_verification_profile_v05,
    v05_transaction_case,
    verification_profile_v03,
)


@pytest.fixture
def service_case(v05_transaction_case):
    case = v05_transaction_case
    services = OpenWorkProofServices()
    profile_payload = case["profile"].model_dump(mode="json")
    assert services.validate_profile(profile_payload)["schema_version"] == (
        "openworkproof-verification-profile/0.5"
    )
    return {**case, "services": services, "profile_payload": profile_payload}


def test_service_routes_v05_profile_and_arm_result(service_case) -> None:
    case = service_case
    commit_verification_profile_v05(case["ledger"], case["profile"])
    result = case["results"][0].model_dump(mode="json")
    committed = case["services"].commit_arm_result(case["ledger"], result)
    assert committed["schema_version"] == (
        "openworkproof-verification-arm-result/0.5"
    )


def test_service_routes_v05_decision_prepare_and_commit(service_case) -> None:
    case = service_case
    commit_verification_profile_v05(case["ledger"], case["profile"])
    for result in case["results"]:
        case["services"].commit_arm_result(
            case["ledger"], result.model_dump(mode="json")
        )
    request = {
        "decision_id": "c" * 64,
        "decided_at": "2026-01-01T00:20:00Z",
        "nonce": "d" * 64,
    }
    draft = case["services"].prepare_decision(case["ledger"], request)
    assert draft["integrity_assessment"]["population_status"] == "matched"
    encoded = verification_decision_signing_bytes_v05(
        VerificationDecisionDraftV05.model_validate(draft)
    )
    binding = case["profile"].verifier_bindings[0]
    private_key = case["keys"]["Verifier"][0]
    decision = {
        "schema_version": "openworkproof-verification-decision/0.5",
        **draft,
        "digest": hashlib.sha256(encoded).hexdigest(),
        "verifier_signatures": [
            {
                "verifier_subject_id": binding.verifier_subject_id,
                "verifier_key_id": key_id(private_key.public_key()),
                "signature_alg": "Ed25519",
                "signature": base64.urlsafe_b64encode(
                    private_key.sign(encoded)
                )
                .decode("ascii")
                .rstrip("="),
            }
        ],
    }
    committed = case["services"].commit_decision(case["ledger"], decision)
    assert committed["schema_version"] == "openworkproof-verification-decision/0.5"
    assert committed["decision"] == "VERIFIED"


def test_service_builds_and_audits_v05_delivery(service_case) -> None:
    case = service_case
    commit_verification_profile_v05(case["ledger"], case["profile"])
    for result in case["results"]:
        case["services"].commit_arm_result(
            case["ledger"], result.model_dump(mode="json")
        )
    request = {
        "decision_id": "c" * 64,
        "decided_at": "2026-01-01T00:20:00Z",
        "nonce": "d" * 64,
    }
    draft = case["services"].prepare_decision(case["ledger"], request)
    encoded = verification_decision_signing_bytes_v05(
        VerificationDecisionDraftV05.model_validate(draft)
    )
    binding = case["profile"].verifier_bindings[0]
    private_key = case["keys"]["Verifier"][0]
    decision = {
        "schema_version": "openworkproof-verification-decision/0.5",
        **draft,
        "digest": __import__("hashlib").sha256(encoded).hexdigest(),
        "verifier_signatures": [
            {
                "verifier_subject_id": binding.verifier_subject_id,
                "verifier_key_id": key_id(private_key.public_key()),
                "signature_alg": "Ed25519",
                "signature": base64.urlsafe_b64encode(
                    private_key.sign(encoded)
                )
                .decode("ascii")
                .rstrip("="),
            }
        ],
    }
    case["services"].commit_decision(case["ledger"], decision)
    output = case["tmp_path"] / "delivery"
    manifest = case["services"].build_delivery(
        case["ledger"], output, "customer_private"
    )
    assert manifest["verification_protocol_version"] == "0.5"
    audit = case["services"].audit_delivery(output)
    assert audit["current_decision"] == "VERIFIED"
    explanation = case["services"].explain_integrity_package(output)
    assert explanation["decision"] == "VERIFIED"
    assert "boundary" in explanation


def test_service_validates_population_and_control_observations(
    service_case,
) -> None:
    case = service_case
    profile = case["profile"].model_dump(mode="json")
    manifest = case["manifest"].model_dump(mode="json")
    result = case["results"][0].model_dump(mode="json")
    rule_outputs = {}
    for rule in case["manifest"].selector_rules:
        contract = next(
            item
            for item in case["profile"].population_contracts
            if item.selector_rule_id == rule.rule_id
        )
        rule_outputs[rule.rule_id] = list(contract.declared_selected_member_ids)
    inventory = {}
    for observation_payload in result["population_observations"]:
        for ref in observation_payload["evidence_refs"]:
            content = (
                case["tmp_path"] / ref["path"]
            ).read_bytes()
            inventory[ref["sha256"]] = base64.urlsafe_b64encode(content).decode(
                "ascii"
            ).rstrip("=")
    validated = case["services"].validate_population_observation(
        {
            "profile": profile,
            "manifest": manifest,
            "result": result,
            "rule_outputs": rule_outputs,
            "evidence_inventory": inventory,
        }
    )
    assert validated == {
        "valid": True,
        "schema_version": "openworkproof-verification-arm-result/0.5",
    }
    controls = case["services"].validate_control_observation(
        {"profile": profile, "results": [case["results"][1].model_dump(mode="json")]}
    )
    assert controls["control_status"] == "proven"


def test_cli_and_mcp_observation_commands(service_case) -> None:
    case = service_case
    profile = case["profile"].model_dump(mode="json")
    manifest = case["manifest"].model_dump(mode="json")
    result = case["results"][0].model_dump(mode="json")
    rule_outputs = {}
    for rule in case["manifest"].selector_rules:
        contract = next(
            item
            for item in case["profile"].population_contracts
            if item.selector_rule_id == rule.rule_id
        )
        rule_outputs[rule.rule_id] = list(contract.declared_selected_member_ids)
    inventory = {}
    for observation_payload in result["population_observations"]:
        for ref in observation_payload["evidence_refs"]:
            content = (case["tmp_path"] / ref["path"]).read_bytes()
            inventory[ref["sha256"]] = base64.urlsafe_b64encode(content).decode(
                "ascii"
            ).rstrip("=")
    payload = {
        "profile": profile,
        "manifest": manifest,
        "result": result,
        "rule_outputs": rule_outputs,
        "evidence_inventory": inventory,
    }
    payload_path = case["tmp_path"] / "observation.json"
    payload_path.write_text(json.dumps(payload), encoding="utf-8")
    exit_code = cli_app(["integrity-observation", "validate", str(payload_path)])
    assert exit_code == 0
    mcp_result = owp_integrity_observation_validate(json.dumps(payload))
    assert mcp_result["valid"] is True
    control_payload = {
        "profile": profile,
        "results": [case["results"][1].model_dump(mode="json")],
    }
    control_path = case["tmp_path"] / "control.json"
    control_path.write_text(json.dumps(control_payload), encoding="utf-8")
    assert cli_app(["control-observation", "validate", str(control_path)]) == 0
    assert owp_control_observation_validate(json.dumps(control_payload))[
        "control_status"
    ] == "proven"
