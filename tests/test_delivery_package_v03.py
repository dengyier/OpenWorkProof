from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from openworkproof.delivery_package import (
    DeliveryPackageError,
    digest_manifest,
    export_delivery_package,
    verify_delivery_package,
)
from test_acceptance_v03 import _commit_v03_decision
from test_verification_transactions_v03 import (
    v03_transaction_case,
    verification_profile_v03,
)


def _package_bytes(root: Path) -> bytes:
    return b"\n".join(
        path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    )


def test_customer_private_v03_package_replays_exact_scope(
    v03_transaction_case,
) -> None:
    case = v03_transaction_case
    decision = _commit_v03_decision(case)
    output = case["tmp_path"] / "customer-package"
    manifest = export_delivery_package(
        case["ledger"], output, privacy_view="customer_private"
    )
    assert manifest.verification_protocol_version == "0.3"
    assert manifest.full_offline_replay is True
    assert manifest.scope_manifest_digest == case["manifest"].digest
    assert {entry.privacy_class for entry in manifest.entries} == {
        "public",
        "diagnostic",
        "customer_private",
    }
    paths = {entry.path for entry in manifest.entries}
    assert {
        "evaluation-scope.json",
        "scope/selector-rules.json",
        "scope/selector-evidence/scope/selectors/explicit.json",
        "scope/members.json",
        "scope-coverage-report.json",
        "scope-coverage-report.html",
        "verification-profile.json",
        "verification-decision.json",
        "verify.sh",
    } <= paths
    report = json.loads(
        (output / "scope-coverage-report.json").read_text(encoding="utf-8")
    )
    assert report["claim"]["statement"]
    assert report["declared_member_count"] == case["manifest"].member_count
    assert report["observed_member_counts"] == [
        case["manifest"].member_count,
        case["manifest"].member_count,
    ]
    assert report["required_coverage"]["missing_count"] == 0
    assert report["cross_arm_consistent"] is True
    assert report["decision"] == "VERIFIED"
    assert report["bounded_conclusion"].startswith("VERIFIED within")
    assert "payment" not in report["bounded_conclusion"].lower()
    result = verify_delivery_package(output)
    assert result.current_decision == decision.decision
    assert result.full_offline_replay is True
    assert result.manifest_digest == digest_manifest(manifest)


def test_public_v03_package_is_aggregate_only_and_does_not_leak_locators(
    v03_transaction_case,
    signed_work_order,
    signed_subject_claim,
) -> None:
    case = v03_transaction_case
    _commit_v03_decision(case)
    output = case["tmp_path"] / "public-package"
    manifest = export_delivery_package(
        case["ledger"], output, privacy_view="public"
    )
    assert manifest.full_offline_replay is False
    assert {entry.privacy_class for entry in manifest.entries} == {"public"}
    assert {entry.path for entry in manifest.entries} == {
        "scope-coverage-report.json",
        "scope-coverage-report.html",
    }
    payload = _package_bytes(output)
    forbidden = (
        b"src/widget.py",
        b"tests/test_widget.py::test_widget",
        b"scope/selectors/explicit.json",
        signed_work_order.issuer_id.encode("utf-8"),
        signed_subject_claim.delivery_target.encode("utf-8"),
        b'"selector_kind"',
    )
    assert all(value not in payload for value in forbidden)
    report = json.loads(
        (output / "scope-coverage-report.json").read_text(encoding="utf-8")
    )
    assert report["full_offline_replay"] is False
    assert "statement" not in report["claim"]
    result = verify_delivery_package(output)
    assert result.current_decision == "VERIFIED"
    assert result.full_offline_replay is False


def test_diagnostic_v03_package_is_monotonic_but_not_full_replay(
    v03_transaction_case,
) -> None:
    case = v03_transaction_case
    _commit_v03_decision(case)
    public_output = case["tmp_path"] / "public"
    diagnostic_output = case["tmp_path"] / "diagnostic"
    public = export_delivery_package(
        case["ledger"], public_output, privacy_view="public"
    )
    diagnostic = export_delivery_package(
        case["ledger"], diagnostic_output, privacy_view="diagnostic"
    )
    public_paths = {entry.path for entry in public.entries}
    diagnostic_paths = {entry.path for entry in diagnostic.entries}
    assert public_paths < diagnostic_paths
    assert {entry.privacy_class for entry in diagnostic.entries} <= {
        "public",
        "diagnostic",
    }
    assert diagnostic.full_offline_replay is False
    assert "scope-diagnostics.json" in diagnostic_paths
    assert verify_delivery_package(diagnostic_output).full_offline_replay is False


@pytest.mark.parametrize(
    "prefix",
    ("evidence/scope/", "scope/selector-evidence/"),
)
def test_customer_private_v03_scope_evidence_tamper_fails_closed(
    v03_transaction_case,
    prefix,
) -> None:
    case = v03_transaction_case
    _commit_v03_decision(case)
    output = case["tmp_path"] / "customer-package"
    manifest = export_delivery_package(
        case["ledger"], output, privacy_view="customer_private"
    )
    target = next(
        entry.path
        for entry in manifest.entries
        if entry.path.startswith(prefix)
    )
    path = output / target
    path.write_bytes(path.read_bytes() + b" ")
    with pytest.raises(DeliveryPackageError, match="integrity"):
        verify_delivery_package(output)


def test_public_manifest_preserves_original_scope_digest(
    v03_transaction_case,
) -> None:
    case = v03_transaction_case
    _commit_v03_decision(case)
    output = case["tmp_path"] / "public-package"
    manifest = export_delivery_package(
        case["ledger"], output, privacy_view="public"
    )
    report_raw = (output / "scope-coverage-report.json").read_bytes()
    assert case["manifest"].digest.encode("ascii") in report_raw
    assert manifest.scope_manifest_digest == case["manifest"].digest
    assert hashlib.sha256(report_raw).hexdigest() in {
        entry.sha256 for entry in manifest.entries
    }
