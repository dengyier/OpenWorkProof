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

from openworkproof.models import DecisionDraftRequest
from test_verification_integrity_transactions_v05 import (
    _resign_arm_result_v05,
    _sign_decision_draft_v05,
    _v05_control_observation,
    _v05_population_observation,
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


def _population_payload(case) -> dict:
    profile = case["profile"].model_dump(mode="json")
    manifest = case["manifest"].model_dump(mode="json")
    results = [result.model_dump(mode="json") for result in case["results"]]
    rule_outputs = {}
    for rule in case["manifest"].selector_rules:
        contract = next(
            item
            for item in case["profile"].population_contracts
            if item.selector_rule_id == rule.rule_id
        )
        rule_outputs[rule.rule_id] = list(contract.declared_selected_member_ids)
    inventory = {}
    for result_payload in results:
        for observation_payload in result_payload["population_observations"]:
            for ref in observation_payload["evidence_refs"]:
                content = (case["tmp_path"] / ref["path"]).read_bytes()
                inventory[ref["sha256"]] = base64.urlsafe_b64encode(
                    content
                ).decode("ascii").rstrip("=")
    return {
        "profile": profile,
        "manifest": manifest,
        "results": results,
        "rule_outputs": rule_outputs,
        "evidence_inventory": inventory,
    }


def test_service_validates_population_and_control_observations(
    service_case,
) -> None:
    case = service_case
    validated = case["services"].validate_population_observation(
        _population_payload(case)
    )
    assert validated == {
        "valid": True,
        "authority": "not_checked",
        "population_status": "matched",
        "reason_codes": [],
    }
    controls = case["services"].validate_control_observation(
        _control_payload(case)
    )
    assert controls == {
        "valid": True,
        "authority": "not_checked",
        "control_status": "proven",
        "reason_codes": [],
        "evidence": "checked",
    }


def test_cli_and_mcp_observation_commands(service_case) -> None:
    case = service_case
    payload = _population_payload(case)
    payload_path = case["tmp_path"] / "observation.json"
    payload_path.write_text(json.dumps(payload), encoding="utf-8")
    assert cli_app(["integrity-observation", "validate", str(payload_path)]) == 0
    mcp_result = owp_integrity_observation_validate(json.dumps(payload))
    assert mcp_result["ok"] is True
    assert mcp_result["population_status"] == "matched"
    assert mcp_result["authority"] == "not_checked"
    control_payload = _control_payload(case)
    control_path = case["tmp_path"] / "control.json"
    control_path.write_text(json.dumps(control_payload), encoding="utf-8")
    assert cli_app(["control-observation", "validate", str(control_path)]) == 0
    control_result = owp_control_observation_validate(json.dumps(control_payload))
    assert control_result["control_status"] == "proven"
    assert control_result["authority"] == "not_checked"
    assert control_result["evidence"] == "checked"


@pytest.mark.parametrize(
    ("kind", "expected_exit"),
    (("survived", 4), ("mismatched", 3), ("unavailable", 3)),
)
def test_cli_control_exit_codes_cover_every_verdict(
    service_case, kind: str, expected_exit: int
) -> None:
    case = service_case
    contract = case["profile"].control_contracts[0]
    expected = contract.expected_failure_signature.model_dump(mode="json")
    if kind == "survived":
        overrides = {
            "control_status": "survived",
            "signature": {
                **expected,
                "exit_codes": [0],
                "reason_codes": ["MUTATION_SURVIVED"],
            },
        }
        changes: dict = {}
    elif kind == "mismatched":
        overrides = {
            "control_status": "mismatched",
            "fixture_digest": "d" * 64,
        }
        changes = {}
    else:
        overrides = {
            "control_status": "unavailable",
            "execution_status": "evidence_unavailable",
        }
        changes = {
            "mutation_status": "not_applied",
            "expectation_status": "indeterminate",
            "reason_codes": ["MUTATION_NOT_APPLIED"],
        }
    control = _v05_control_observation(
        case["tmp_path"], contract, arm_kind="negative", **overrides
    )
    negative = _resign_arm_result_v05(
        case, case["results"][1], control_observation=control, **changes
    )
    payload = {
        "profile": case["profile"].model_dump(mode="json"),
        "results": [negative.model_dump(mode="json")],
    }
    path = case["tmp_path"] / f"control-{kind}.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert cli_app(["control-observation", "validate", str(path)]) == expected_exit


def test_cli_population_non_matched_verdict_exits_unknown(service_case) -> None:
    case = service_case
    payload = _population_payload(case)
    payload["evidence_inventory"] = {}
    path = case["tmp_path"] / "observation-unavailable.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert cli_app(["integrity-observation", "validate", str(path)]) == 3


def test_malformed_observation_payloads_fail_closed(service_case) -> None:
    case = service_case
    missing_profile = {"manifest": {}, "results": []}
    path = case["tmp_path"] / "malformed.json"
    path.write_text(json.dumps(missing_profile), encoding="utf-8")
    assert cli_app(["integrity-observation", "validate", str(path)]) == 1
    assert cli_app(["control-observation", "validate", str(path)]) == 1
    mcp_result = owp_integrity_observation_validate(json.dumps(missing_profile))
    assert mcp_result["ok"] is False
    assert "profile" in mcp_result["error"]
    control_result = owp_control_observation_validate(json.dumps(missing_profile))
    assert control_result["ok"] is False
    assert "profile" in control_result["error"]


def test_operator_docs_cover_v05_observation_commands() -> None:
    root = Path(__file__).parent.parent
    mcp = (root / "MCP_SERVER.md").read_text(encoding="utf-8")
    assert "owp_integrity_observation_validate" in mcp
    assert "owp_control_observation_validate" in mcp
    assert "not_checked" in mcp
    offline = (root / "docs/offline-verification.md").read_text(encoding="utf-8")
    for command in (
        "owp integrity-observation validate",
        "owp control-observation validate",
    ):
        assert command in offline
    for code in (
        "POPULATION_CAPTURE_FAILED",
        "CONTROL_FAILURE_SIGNATURE_MISMATCH",
        "POPULATION_CROSS_ARM_MISMATCH",
    ):
        assert code in offline
    assert "是安全结论" in offline
    assert "不是系统崩溃" in offline


def _export_decision_package(case, results) -> Path:
    from openworkproof.delivery_package import export_delivery_package
    from openworkproof.verification import (
        prepare_verification_decision_v05,
        commit_verification_decision_v05,
    )

    commit_verification_profile_v05(case["ledger"], case["profile"])
    for result in results:
        commit_verification_arm_result_v05(case["ledger"], result)
    draft = prepare_verification_decision_v05(
        case["ledger"],
        DecisionDraftRequest(
            decision_id="c" * 64,
            decided_at="2026-01-01T00:20:00Z",
            nonce="d" * 64,
        ),
    )
    decision = _sign_decision_draft_v05(case, draft)
    commit_verification_decision_v05(case["ledger"], decision)
    output = case["tmp_path"] / "decision-package"
    export_delivery_package(
        case["ledger"], output, privacy_view="customer_private"
    )
    return output, draft.decision


@pytest.mark.parametrize(
    ("blind_selection", "control_overrides", "expected_exit"),
    (
        (False, None, 0),
        (True, None, 3),
        (False, {"control_status": "survived", "exit_codes": [0]}, 4),
    ),
)
def test_cli_decision_exit_codes_cover_every_verdict(
    service_case, blind_selection, control_overrides, expected_exit
) -> None:
    """Audit I4: verify-compose commit and audit-replay must exit 0 only for
    VERIFIED; UNKNOWN -> 3 and REFUTED -> 4."""
    case = service_case
    if blind_selection:
        results = []
        for kind, result in zip(
            ("positive", "negative"), case["results"], strict=True
        ):
            observations = [
                _v05_population_observation(
                    case["tmp_path"],
                    contract,
                    suffix=f"exit-{kind}-{contract.member_kind}",
                    eligible_seen=2,
                    selected_count=0,
                )
                for contract in case["profile"].population_contracts
            ]
            results.append(
                _resign_arm_result_v05(
                    case, result, population_observations=observations
                )
            )
        results = tuple(results)
    else:
        results = list(case["results"])
        if control_overrides is not None:
            contract = case["profile"].control_contracts[0]
            expected = contract.expected_failure_signature.model_dump(
                mode="json"
            )
            overrides = dict(control_overrides)
            if overrides.get("control_status") == "survived":
                overrides["signature"] = {
                    **expected,
                    "exit_codes": [0],
                    "reason_codes": ["MUTATION_SURVIVED"],
                }
            control = _v05_control_observation(
                case["tmp_path"],
                contract,
                arm_kind="negative",
                **overrides,
            )
            results[1] = _resign_arm_result_v05(
                case, case["results"][1], control_observation=control
            )
        results = tuple(results)
    package, decision = _export_decision_package(case, results)
    assert decision == {0: "VERIFIED", 3: "UNKNOWN", 4: "REFUTED"}[expected_exit]
    assert cli_app(["audit-replay", str(package)]) == expected_exit


def test_cli_audit_explain_and_compare_use_v05_derived_views(
    service_case,
) -> None:
    """Audit I4: explain/compare must reuse the v0.5 derived functions."""
    case = service_case
    package, decision = _export_decision_package(case, case["results"])
    assert decision == "VERIFIED"
    exit_code = cli_app(["audit-explain", str(package)])
    assert exit_code == 0
    from openworkproof.delivery_package import explain_integrity_package

    expected = explain_integrity_package(package)
    assert "population_status" in expected
    second = case["tmp_path"] / "second-package"
    from openworkproof.delivery_package import export_delivery_package

    export_delivery_package(
        case["ledger"], second, privacy_view="customer_private"
    )
    assert cli_app(["audit-compare", str(package), str(second)]) == 0
    from openworkproof.delivery_package import compare_integrity_packages

    comparison = compare_integrity_packages(package, second)
    assert comparison["selector_rule_changes"] == []
    assert comparison["control_changes"] == []


def _control_payload(case) -> dict:
    """Payload with the honest control evidence inventory for the negative
    arm result."""
    observation = case["results"][1].control_observation
    inventory = {}
    for ref in observation.evidence_refs:
        content = (case["tmp_path"] / ref.path).read_bytes()
        inventory[ref.sha256] = (
            base64.urlsafe_b64encode(content).decode("ascii").rstrip("=")
        )
    return {
        "profile": case["profile"].model_dump(mode="json"),
        "results": [case["results"][1].model_dump(mode="json")],
        "evidence_inventory": inventory,
    }


def _build_v05_package(case) -> Path:
    from openworkproof.models import VerificationDecisionDraftV05
    from openworkproof.verification import (
        verification_decision_signing_bytes_v05,
    )

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
    case["services"].commit_decision(case["ledger"], decision)
    output = case["tmp_path"] / "delivery-b"
    case["services"].build_delivery(case["ledger"], output, "customer_private")
    return output


def test_audit_d_control_without_evidence_is_not_checked(service_case) -> None:
    """Audit D: the control observation surface must not claim proven from
    refs-existence alone — without an evidence inventory it reports
    evidence:not_checked and a non-proven status."""
    case = service_case
    payload = {
        "profile": case["profile"].model_dump(mode="json"),
        "results": [case["results"][1].model_dump(mode="json")],
    }
    result = case["services"].validate_control_observation(payload)
    assert result["control_status"] == "unavailable"
    assert "CONTROL_EVIDENCE_MISSING" in result["reason_codes"]
    assert result["evidence"] == "not_checked"


def test_audit_d_control_with_unreplayable_evidence_fails_closed(
    service_case,
) -> None:
    """Audit D: a supplied evidence inventory whose content does not replay
    the signed references must fail closed instead of proving."""
    case = service_case
    observation = case["results"][1].control_observation
    junk = {
        ref.sha256: base64.urlsafe_b64encode(b"junk").decode("ascii").rstrip("=")
        for ref in observation.evidence_refs
    }
    payload = {
        "profile": case["profile"].model_dump(mode="json"),
        "results": [case["results"][1].model_dump(mode="json")],
        "evidence_inventory": junk,
    }
    with pytest.raises(ValueError):
        case["services"].validate_control_observation(payload)


def test_audit_e_explain_derived_failure_is_operational(
    service_case, monkeypatch
) -> None:
    """Audit E: a v0.5 derived-view failure must exit operationally (1),
    never silently fall back and exit with the replay's decision code."""
    case = service_case
    output = _build_v05_package(case)
    import openworkproof.delivery_package as delivery_package

    monkeypatch.setattr(
        delivery_package,
        "explain_integrity_package",
        lambda package: (_ for _ in ()).throw(
            RuntimeError("derived view exploded")
        ),
    )
    assert cli_app(["audit-explain", str(output)]) == 1


def test_audit_e_compare_derived_failure_is_operational(
    service_case, monkeypatch
) -> None:
    """Audit E: a v0.5 compare-view failure must exit operationally (1)."""
    case = service_case
    left = _build_v05_package(case)
    right = case["tmp_path"] / "delivery-b2"
    case["services"].build_delivery(case["ledger"], right, "customer_private")
    import openworkproof.delivery_package as delivery_package

    monkeypatch.setattr(
        delivery_package,
        "compare_integrity_packages",
        lambda a, b: (_ for _ in ()).throw(
            RuntimeError("compare view exploded")
        ),
    )
    assert cli_app(["audit-compare", str(left), str(right)]) == 1


def test_audit_e_legacy_explain_uses_controlled_fallback(
    service_case, monkeypatch
) -> None:
    """Audit E: a legacy (non-v0.5) package keeps the controlled fallback
    and exits with the replay decision code."""
    case = service_case
    output = _build_v05_package(case)
    import openworkproof.delivery_package as delivery_package

    monkeypatch.setattr(
        delivery_package,
        "explain_integrity_package",
        lambda package: (_ for _ in ()).throw(
            delivery_package.LegacyPackageError("legacy package")
        ),
    )
    assert cli_app(["audit-explain", str(output)]) == 0
