from __future__ import annotations

import json
from pathlib import Path

import pytest

import openworkproof.evidence as evidence
from openworkproof.delivery_package import (
    DeliveryPackageError,
    DeliveryVerificationResult,
    compare_integrity_packages,
    explain_integrity_package,
    export_delivery_package,
    verify_delivery_package,
)
from openworkproof.models import DecisionDraftRequest

from test_acceptance_v05 import _commit_v05_decision
from test_verification_integrity_transactions_v05 import (
    commit_verification_arm_result_v05,
    commit_verification_profile_v05,
    v05_transaction_case,
    verification_profile_v03,
)


def _full_case(case):
    case = dict(case)
    _commit_v05_decision(case)
    return case


def _package_bytes(root: Path) -> bytes:
    return b"\n".join(
        path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    )


def test_customer_private_v05_package_replays_offline(v05_transaction_case) -> None:
    case = _full_case(v05_transaction_case)
    output = case["tmp_path"] / "customer-package"
    manifest = export_delivery_package(
        case["ledger"], output, privacy_view="customer_private"
    )
    assert manifest.verification_protocol_version == "0.5"
    assert manifest.full_offline_replay is True
    assert manifest.scope_manifest_digest == case["manifest"].digest
    paths = {entry.path for entry in manifest.entries}
    assert {
        "evaluation-scope.json",
        "scope/selector-rules.json",
        "scope/members.json",
        "scope-coverage-report.json",
        "verification-profile.json",
        "verification-decision.json",
        "verify.sh",
        "settlement-readiness.json",
    } <= paths
    population_paths = [
        entry.path for entry in manifest.entries if "evidence/populations/" in entry.path
    ]
    assert len(population_paths) >= 4
    control_paths = [
        entry.path for entry in manifest.entries if "evidence/controls/" in entry.path
    ]
    assert len(control_paths) >= 1
    from openworkproof.delivery_package import digest_manifest

    result = verify_delivery_package(output)
    assert result.current_decision == "VERIFIED"
    assert result.full_offline_replay is True
    assert result.manifest_digest == digest_manifest(manifest)


def test_v05_public_and_diagnostic_views_are_aggregate_only(
    v05_transaction_case,
) -> None:
    case = _full_case(v05_transaction_case)
    public_root = case["tmp_path"] / "public-package"
    manifest = export_delivery_package(
        case["ledger"], public_root, privacy_view="public"
    )
    assert {entry.path for entry in manifest.entries} == {
        "scope-coverage-report.json"
    }
    assert verify_delivery_package(public_root).current_decision == "VERIFIED"
    diagnostic_root = case["tmp_path"] / "diagnostic-package"
    diagnostic = export_delivery_package(
        case["ledger"], diagnostic_root, privacy_view="diagnostic"
    )
    assert {entry.path for entry in diagnostic.entries} == {
        "scope-coverage-report.json",
        "scope-diagnostics.json",
    }
    assert verify_delivery_package(diagnostic_root).current_decision == "VERIFIED"


def test_v05_package_bytes_do_not_leak_private_material(
    v05_transaction_case,
) -> None:
    case = _full_case(v05_transaction_case)
    output = case["tmp_path"] / "customer-package"
    export_delivery_package(case["ledger"], output, privacy_view="customer_private")
    payload = _package_bytes(output).decode("utf-8", errors="replace")
    forbidden = (
        str(case["tmp_path"]),
        "/private/var/",
        "/Users/molin",
        "openworkproof-day0",
    )
    for token in forbidden:
        assert token not in payload, token
    public_root = case["tmp_path"] / "public-package"
    export_delivery_package(case["ledger"], public_root, privacy_view="public")
    public_payload = _package_bytes(public_root).decode("utf-8", errors="replace")
    for token in forbidden:
        assert token not in public_payload, token
    for token in ("verification-profile.json", "work-order.json", "evidence/"):
        assert token not in public_payload, token


def test_v05_package_tamper_fails_closed(v05_transaction_case) -> None:
    case = _full_case(v05_transaction_case)
    output = case["tmp_path"] / "customer-package"
    manifest = export_delivery_package(
        case["ledger"], output, privacy_view="customer_private"
    )
    population_entry = next(
        entry for entry in manifest.entries if "evidence/populations/" in entry.path
    )
    target = output / population_entry.path
    original = target.read_bytes()
    target.write_bytes(original[:-1] + b"x")
    with pytest.raises(DeliveryPackageError):
        verify_delivery_package(output)
    target.write_bytes(original)
    report = output / "scope-coverage-report.json"
    report.write_text(json.dumps({"tampered": True}), encoding="utf-8")
    with pytest.raises(DeliveryPackageError):
        verify_delivery_package(output)


def test_v05_explain_and_compare_derived_views(v05_transaction_case) -> None:
    case = _full_case(v05_transaction_case)
    output = case["tmp_path"] / "customer-package"
    export_delivery_package(case["ledger"], output, privacy_view="customer_private")
    explanation = explain_integrity_package(output)
    assert explanation["decision"] == "VERIFIED"
    assert explanation["population_status"] == "matched"
    assert explanation["control_status"] == "proven"
    assert "boundary" in explanation
    for contract_entry in explanation["contracts"]:
        assert contract_entry["eligible_seen"] is not None
        assert contract_entry["selected_count"] is not None
    comparison = compare_integrity_packages(output, output)
    assert comparison["selector_rule_changes"] == []
    assert comparison["control_changes"] == []
    assert comparison["population_status_left"] == "matched"
    assert comparison["population_status_right"] == "matched"


def _retamper(case, root, relative, new_bytes):
    """Replace one packaged file and repair the manifest digest chain."""
    target = root / relative
    target.write_bytes(new_bytes)
    manifest_path = root / "manifest.json"
    import rfc8785

    manifest_payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    for entry in manifest_payload["entries"]:
        if entry["path"] == relative:
            entry["sha256"] = __import__("hashlib").sha256(new_bytes).hexdigest()
            entry["size_bytes"] = len(new_bytes)
    manifest_path.write_bytes(rfc8785.dumps(manifest_payload))


def test_v05_package_tampered_claim_fails_closed(v05_transaction_case) -> None:
    case = _full_case(v05_transaction_case)
    output = case["tmp_path"] / "customer-package"
    export_delivery_package(case["ledger"], output, privacy_view="customer_private")
    claim_path = output / "subject-claim.json"
    tampered = json.loads(claim_path.read_text(encoding="utf-8"))
    tampered["claim_statement"] = "replaced claim"
    _retamper(
        case, output, "subject-claim.json",
        __import__("rfc8785").dumps(tampered),
    )
    with pytest.raises(DeliveryPackageError):
        verify_delivery_package(output)


def test_v05_package_tampered_scope_evidence_fails_closed(
    v05_transaction_case,
) -> None:
    case = _full_case(v05_transaction_case)
    output = case["tmp_path"] / "customer-package"
    manifest = export_delivery_package(
        case["ledger"], output, privacy_view="customer_private"
    )
    scope_entry = next(
        entry for entry in manifest.entries if "evidence/scope/" in entry.path
    )
    _retamper(case, output, scope_entry.path, b"tampered scope evidence")
    with pytest.raises(DeliveryPackageError):
        verify_delivery_package(output)


def test_v05_package_tampered_manifest_digest_fails_closed(
    v05_transaction_case,
) -> None:
    case = _full_case(v05_transaction_case)
    output = case["tmp_path"] / "customer-package"
    export_delivery_package(case["ledger"], output, privacy_view="customer_private")
    manifest_path = output / "manifest.json"
    import rfc8785

    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    payload["verification_decision_digest"] = "0" * 64
    manifest_path.write_bytes(rfc8785.dumps(payload))
    with pytest.raises(DeliveryPackageError):
        verify_delivery_package(output)


def test_v05_package_tampered_schema_fails_closed(v05_transaction_case) -> None:
    case = _full_case(v05_transaction_case)
    output = case["tmp_path"] / "customer-package"
    export_delivery_package(case["ledger"], output, privacy_view="customer_private")
    _retamper(
        case,
        output,
        "schemas/verification-profile.schema.json",
        b'{"tampered": true}',
    )
    with pytest.raises(DeliveryPackageError):
        verify_delivery_package(output)


def test_v05_package_invalid_object_raises_closed_exception(
    v05_transaction_case,
) -> None:
    case = _full_case(v05_transaction_case)
    output = case["tmp_path"] / "customer-package"
    export_delivery_package(case["ledger"], output, privacy_view="customer_private")
    _retamper(case, output, "verification-profile.json", b"{}")
    with pytest.raises(DeliveryPackageError):
        verify_delivery_package(output)


def test_ledger_delivery_protocol_detects_exactly_one_family(
    v05_transaction_case,
) -> None:
    from openworkproof.delivery_package import _ledger_delivery_protocol

    case = _full_case(v05_transaction_case)
    assert _ledger_delivery_protocol(case["ledger"]) == "0.5"
    connection = evidence.connect_ledger(case["ledger"])
    try:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            """
            INSERT INTO verification_profiles_v03 (
                profile_id, profile_digest, scope_id, scope_digest,
                subject_claim_id, profile_json
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                "ab" * 32,
                "c" * 64,
                case["manifest"].scope_id,
                case["manifest"].digest,
                "d" * 64,
                __import__("rfc8785").dumps({"nonce": "x"}),
            ),
        )
        connection.execute("COMMIT")
    finally:
        connection.close()
    with pytest.raises(DeliveryPackageError, match="ambiguous"):
        _ledger_delivery_protocol(case["ledger"])
