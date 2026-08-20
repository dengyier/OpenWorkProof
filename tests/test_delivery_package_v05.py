from __future__ import annotations

import hashlib
import json
import base64
from pathlib import Path

import pytest
import rfc8785

import openworkproof.evidence as evidence
from openworkproof.delivery_package import (
    DeliverySurfaceFacts,
    DeliveryManifest,
    DeliveryManifestEntry,
    DeliveryPackageError,
    DeliveryVerificationResult,
    compare_integrity_packages,
    explain_integrity_package,
    export_delivery_package,
    load_surface_facts,
    verify_delivery_package,
)
from openworkproof.models import AcceptanceReceipt, DecisionDraftRequest
from openworkproof.signing import sign_payload
from openworkproof.verification import verification_decision_signing_bytes_v05

from test_acceptance_v05 import _commit_acceptance_fixture, _commit_v05_decision
from test_verification_integrity_transactions_v05 import (
    _resign_arm_result_v05,
    commit_verification_arm_result_v05,
    commit_verification_profile_v05,
    v05_transaction_case,
    verification_profile_v03,
)
from test_acceptance_v03 import _commit_v03_decision
from test_verification_transactions_v03 import v03_transaction_case


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
    result = verify_delivery_package(public_root)
    assert result.current_decision == "UNAUTHENTICATED"
    assert result.settlement_readiness == "NOT_READY"
    diagnostic_root = case["tmp_path"] / "diagnostic-package"
    diagnostic = export_delivery_package(
        case["ledger"], diagnostic_root, privacy_view="diagnostic"
    )
    assert {entry.path for entry in diagnostic.entries} == {
        "scope-coverage-report.json",
        "scope-diagnostics.json",
    }
    result = verify_delivery_package(diagnostic_root)
    assert result.current_decision == "UNAUTHENTICATED"
    assert result.settlement_readiness == "NOT_READY"


def _rewrite_report_and_sync_manifest(root: Path, decision: str) -> None:
    manifest_path = root / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    report_path = root / "scope-coverage-report.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["decision"] = decision
    report_path.write_bytes(rfc8785.dumps(report))
    payload = report_path.read_bytes()
    for entry in manifest["entries"]:
        if entry["path"] == "scope-coverage-report.json":
            entry["sha256"] = hashlib.sha256(payload).hexdigest()
            entry["size_bytes"] = len(payload)
    manifest_path.write_bytes(rfc8785.dumps(manifest))


def test_v05_customer_private_rejects_forged_report_decision(
    v05_transaction_case,
) -> None:
    """Audit C1: the replayed signed Decision is the only decision truth."""
    case = _full_case(v05_transaction_case)
    output = case["tmp_path"] / "customer-package"
    export_delivery_package(
        case["ledger"], output, privacy_view="customer_private"
    )
    _rewrite_report_and_sync_manifest(output, "REFUTED")
    with pytest.raises(DeliveryPackageError, match="diverges"):
        verify_delivery_package(output)


def test_v05_public_forged_package_is_unauthenticated_not_ready(
    v05_transaction_case,
) -> None:
    """Audit C1: a public package carries no signed attestation, so a
    from-zero forged VERIFIED report must never read back as verified."""
    root = v05_transaction_case["tmp_path"] / "forged-public"
    root.mkdir()
    report = {
        "schema_version": "openworkproof-scope-coverage-report/0.5",
        "privacy_view": "public",
        "scope_manifest_digest": "1" * 64,
        "full_offline_replay": False,
        "decision": "VERIFIED",
        "population_status": "matched",
        "control_status": "proven",
        "integrity_reason_codes": [],
    }
    report_path = root / "scope-coverage-report.json"
    report_path.write_bytes(rfc8785.dumps(report))
    payload = report_path.read_bytes()
    manifest = DeliveryManifest(
        schema_version="openworkproof-delivery-manifest/0.1",
        privacy_view="public",
        work_order_digest="2" * 64,
        subject_claim_digest="3" * 64,
        verification_decision_digest="4" * 64,
        verification_protocol_version="0.5",
        scope_manifest_digest="1" * 64,
        full_offline_replay=False,
        entries=[
            {
                "path": "scope-coverage-report.json",
                "sha256": hashlib.sha256(payload).hexdigest(),
                "size_bytes": len(payload),
                "media_type": "application/json",
                "privacy_class": "public",
                "required": True,
            }
        ],
    )
    (root / "manifest.json").write_bytes(
        rfc8785.dumps(manifest.model_dump(mode="json"))
    )
    result = verify_delivery_package(root)
    assert result.current_decision == "UNAUTHENTICATED"
    assert result.settlement_readiness == "NOT_READY"


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


def _retract_causal_receipts(case) -> None:
    """Retract every causal receipt of the committed chain with
    evidence_refuted. The committed decision stays as history; the
    retraction affects future decisions (covered by the decision-layer
    tests). Here we only need the retraction rows to be exportable."""
    from openworkproof.models import (
        RetractionReceiptV05,
        parse_action_receipt_json,
        retraction_receipt_id,
    )
    from openworkproof.retraction import commit_retraction_receipt
    from openworkproof.signing import sign_payload

    results = case["results"]
    retracted_ids = {
        receipt_id
        for result in results
        for receipt_id in result.action_receipt_ids
    }
    for receipt_id in retracted_ids:
        row = evidence.connect_ledger(case["ledger"]).execute(
            "SELECT receipt_json FROM receipts WHERE receipt_id = ?",
            (receipt_id,),
        ).fetchone()
        parsed = parse_action_receipt_json(row[0])
        payload = {
            "schema_version": "openworkproof-retraction-receipt/0.5",
            "protocol_version": "0.5",
            "work_order_digest": case["profile"].work_order_digest,
            "target_receipt_id": receipt_id,
            "target_receipt_digest": parsed.digest,
            "target_receipt_kind": "tool_call",
            "retraction_effect": "refuted",
            "retraction_reason": "evidence_refuted",
            "refutes_decision_id": None,
            "refutes_decision_digest": None,
            "causal_parent_ids": [receipt_id],
            "nonce": "0" * 64,
            "retracted_at": "2026-01-01T00:40:00Z",
        }
        payload["retraction_id"] = retraction_receipt_id(payload)
        retraction = RetractionReceiptV05.model_validate(
            sign_payload(
                "retraction-receipt",
                payload,
                case["keys"]["Manager"][0],
                version="0.5",
            )
        )
        commit_retraction_receipt(case["ledger"], retraction)



def test_customer_private_v05_package_includes_retraction_chain(
    v05_transaction_case,
) -> None:
    """A customer-private package from a chain with committed retractions must
    carry the retraction ledger rows so an offline verifier can see the
    lifecycle, and must replay to the retracted decision."""
    case = _full_case(v05_transaction_case)
    _retract_causal_receipts(case)
    output = case["tmp_path"] / "customer-package-retracted"
    manifest = export_delivery_package(
        case["ledger"], output, privacy_view="customer_private"
    )
    paths = {entry.path for entry in manifest.entries}
    assert "execution-ledger/retraction-receipts.json" in paths
    raw = (output / "execution-ledger/retraction-receipts.json").read_bytes()
    receipts = json.loads(raw)
    assert len(receipts) >= 1
    assert receipts[0]["retraction_effect"] == "refuted"
    assert receipts[0]["retraction_reason"] == "evidence_refuted"


def test_customer_private_v05_package_replays_refuted_decision(
    v05_transaction_case,
) -> None:
    """A single-decision package whose decision is UNKNOWN with
    RECEIPT_RETRACTED (retractions committed before the first decision) must
    export and verify offline: the integrity-assessment replay must reproduce
    the decision-level code, not just the population/control subset."""
    from openworkproof.models import (
        RetractionReceiptV05,
        parse_action_receipt_json,
        retraction_receipt_id,
    )
    from openworkproof.retraction import commit_retraction_receipt
    from openworkproof.signing import sign_payload

    case = dict(v05_transaction_case)
    # No decision is committed yet: commit profile + arm results only.
    commit_verification_profile_v05(case["ledger"], case["profile"])
    for result in case["results"]:
        committed = _resign_arm_result_v05(case, result)
        commit_verification_arm_result_v05(case["ledger"], committed)

    retracted_ids = {
        receipt_id
        for result in case["results"]
        for receipt_id in result.action_receipt_ids
    }
    for receipt_id in retracted_ids:
        row = evidence.connect_ledger(case["ledger"]).execute(
            "SELECT receipt_json FROM receipts WHERE receipt_id = ?",
            (receipt_id,),
        ).fetchone()
        parsed = parse_action_receipt_json(row[0])
        payload = {
            "schema_version": "openworkproof-retraction-receipt/0.5",
            "protocol_version": "0.5",
            "work_order_digest": case["profile"].work_order_digest,
            "target_receipt_id": receipt_id,
            "target_receipt_digest": parsed.digest,
            "target_receipt_kind": "tool_call",
            "retraction_effect": "refuted",
            "retraction_reason": "evidence_refuted",
            "refutes_decision_id": None,
            "refutes_decision_digest": None,
            "causal_parent_ids": [receipt_id],
            "nonce": "0" * 64,
            "retracted_at": "2026-01-01T00:25:00Z",
        }
        payload["retraction_id"] = retraction_receipt_id(payload)
        retraction = RetractionReceiptV05.model_validate(
            sign_payload(
                "retraction-receipt",
                payload,
                case["keys"]["Manager"][0],
                version="0.5",
            )
        )
        commit_retraction_receipt(case["ledger"], retraction)

    from openworkproof.verification import (
        commit_verification_decision_v05,
        prepare_verification_decision_v05,
    )

    from test_verification_integrity_transactions_v05 import (
        _sign_decision_draft_v05,
    )

    draft = prepare_verification_decision_v05(
        case["ledger"],
        DecisionDraftRequest(
            decision_id="c" * 64,
            decided_at="2026-01-01T00:30:00Z",
            nonce="d" * 64,
        ),
    )
    assert draft.decision == "UNKNOWN"
    assert "RECEIPT_RETRACTED" in draft.reason_codes
    decision = _sign_decision_draft_v05(case, draft)
    commit_verification_decision_v05(case["ledger"], decision)

    output = case["tmp_path"] / "customer-package-refuted-decision"
    export_delivery_package(
        case["ledger"], output, privacy_view="customer_private"
    )
    result = verify_delivery_package(output)
    assert result.current_decision == "UNKNOWN"


def test_customer_private_v05_package_tampered_retraction_fails_offline(
    v05_transaction_case,
) -> None:
    """Audit C7 analog: tampering the retraction row in a package must make the
    offline verification fail closed."""
    case = _full_case(v05_transaction_case)
    _retract_causal_receipts(case)
    output = case["tmp_path"] / "customer-package-tampered"
    export_delivery_package(
        case["ledger"], output, privacy_view="customer_private"
    )
    target = output / "execution-ledger/retraction-receipts.json"
    tampered = json.loads(target.read_bytes())
    tampered[0]["retraction_reason"] = "interpretation_error"
    target.write_text(rfc8785.dumps(tampered).decode("utf-8"))
    with pytest.raises(DeliveryPackageError):
        verify_delivery_package(output)


# --------------------------------------------------------------------------- #
# Verified read-only surface facts
# --------------------------------------------------------------------------- #


def _rewrite_private_object(
    root: Path,
    relative: str,
    mutate,
) -> None:
    target = root / relative
    document = json.loads(target.read_text(encoding="utf-8"))
    mutate(document)
    payload = rfc8785.dumps(document)
    target.write_bytes(payload)

    manifest_path = root / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for entry in manifest["entries"]:
        if entry["path"] == relative:
            entry["sha256"] = hashlib.sha256(payload).hexdigest()
            entry["size_bytes"] = len(payload)
            break
    else:  # pragma: no cover - fixture invariant
        raise AssertionError(f"missing manifest entry: {relative}")
    manifest_path.write_bytes(rfc8785.dumps(manifest))


def _change_verifier_role(value) -> None:
    next(
        item
        for item in value["key_bindings"]
        if item["role"] == "Verifier"
    )["role"] = "Developer"


def _change_verifier_public_key(value) -> None:
    next(
        item
        for item in value["key_bindings"]
        if item["role"] == "Verifier"
    )["public_key_b64url"] = "A" * 43


def _change_source_commit(value) -> None:
    current = value["source_commit"]
    value["source_commit"] = ("0" if current[0] != "0" else "1") + current[1:]


def _change_decision_nonce(value) -> None:
    current = value["nonce"]
    value["nonce"] = ("0" if current[0] != "0" else "1") + current[1:]


def _change_decision_digest(value) -> None:
    current = value["digest"]
    value["digest"] = ("0" if current[0] != "0" else "1") + current[1:]


def test_surface_facts_come_only_from_verified_private_v05_package(
    v05_transaction_case,
) -> None:
    case = _full_case(v05_transaction_case)
    output = case["tmp_path"] / "surface-facts-private"
    manifest = export_delivery_package(
        case["ledger"], output, privacy_view="customer_private"
    )

    facts = load_surface_facts(output)
    assert isinstance(facts, DeliverySurfaceFacts)

    work_order = json.loads((output / "work-order.json").read_bytes())
    profile = json.loads((output / "verification-profile.json").read_bytes())
    decision = json.loads((output / "verification-decision.json").read_bytes())
    assert facts.decision == decision["decision"]
    assert facts.reason_codes == tuple(decision["reason_codes"])
    assert facts.work_order_digest == manifest.work_order_digest
    assert facts.source_revision == work_order["source_commit"]
    assert facts.risk_class == profile["assurance_level"]
    assert facts.decision_digests == (decision["digest"],)
    assert facts.acceptance_receipt_digest is None
    assert facts.evidence_closed_at == decision["decided_at"]

    verifier_ids = {
        item["key_id"]
        for item in work_order["key_bindings"]
        if item["role"] == "Verifier"
    }
    assert set(facts.trusted_verifier_keys) == verifier_ids
    with pytest.raises(TypeError):
        facts.trusted_verifier_keys["ed25519:" + "0" * 64] = next(
            iter(facts.trusted_verifier_keys.values())
        )

    encoded = verification_decision_signing_bytes_v05(
        __import__("openworkproof.models", fromlist=["VerificationDecisionV05"])
        .VerificationDecisionV05.model_validate(decision)
    )
    for signature in decision["verifier_signatures"]:
        public_key = facts.trusted_verifier_keys[signature["verifier_key_id"]]
        raw = base64.urlsafe_b64decode(
            signature["signature"]
            + "=" * (-len(signature["signature"]) % 4)
        )
        public_key.verify(raw, encoded)


def test_surface_facts_reject_public_and_diagnostic_v05_views(
    v05_transaction_case,
) -> None:
    case = _full_case(v05_transaction_case)
    for privacy_view in ("public", "diagnostic"):
        output = case["tmp_path"] / f"surface-facts-{privacy_view}"
        export_delivery_package(
            case["ledger"], output, privacy_view=privacy_view
        )
        with pytest.raises(DeliveryPackageError):
            load_surface_facts(output)


def test_surface_facts_include_verified_acceptance_terminal(
    v05_transaction_case,
    signed_acceptance_receipt,
) -> None:
    case = _full_case(v05_transaction_case)
    connection = evidence.connect_ledger(case["ledger"])
    try:
        receipts = tuple(
            evidence.parse_action_receipt_json(row[0])
            for row in connection.execute(
                "SELECT receipt_json FROM receipts ORDER BY sequence"
            )
        )
    finally:
        connection.close()
    request = receipts[-1]
    payload = signed_acceptance_receipt.model_dump(
        mode="json",
        exclude={"digest", "signature_alg", "signer_key_id", "signature"},
    )
    payload.update(
        {
            "acceptance_request_receipt_id": request.receipt_id,
            "acceptance_request_receipt_digest": request.digest,
            "receipt_digests": sorted({item.digest for item in receipts}),
            "accepted_at": "2026-01-01T00:30:00Z",
        }
    )
    accepted = AcceptanceReceipt.model_validate(
        sign_payload(
            "acceptance-receipt",
            payload,
            case["keys"]["Acceptor"][0],
        )
    )
    _commit_acceptance_fixture(case["ledger"], accepted)
    output = case["tmp_path"] / "surface-facts-accepted"
    export_delivery_package(
        case["ledger"], output, privacy_view="customer_private"
    )

    facts = load_surface_facts(output)
    assert facts.acceptance_receipt_digest == accepted.digest
    assert facts.evidence_closed_at == accepted.model_dump(
        mode="json"
    )["accepted_at"]


def test_surface_facts_reject_legacy_private_package(
    v03_transaction_case,
) -> None:
    case = v03_transaction_case
    _commit_v03_decision(case)
    output = case["tmp_path"] / "surface-facts-v03"
    export_delivery_package(
        case["ledger"], output, privacy_view="customer_private"
    )
    with pytest.raises(DeliveryPackageError):
        load_surface_facts(output)


@pytest.mark.parametrize(
    ("case_id", "relative", "mutate"),
    (
        ("work-order-role", "work-order.json", _change_verifier_role),
        ("work-order-key", "work-order.json", _change_verifier_public_key),
        ("work-order-source", "work-order.json", _change_source_commit),
        ("decision-content", "verification-decision.json", _change_decision_nonce),
        ("decision-digest", "verification-decision.json", _change_decision_digest),
    ),
)
def test_surface_facts_reject_rebuilt_inner_object_tamper(
    v05_transaction_case,
    case_id,
    relative,
    mutate,
) -> None:
    case = _full_case(v05_transaction_case)
    output = case["tmp_path"] / f"surface-facts-tamper-{case_id}"
    export_delivery_package(
        case["ledger"], output, privacy_view="customer_private"
    )
    _rewrite_private_object(output, relative, mutate)
    with pytest.raises(DeliveryPackageError):
        load_surface_facts(output)


def test_surface_facts_reject_manifest_entry_hash_or_path_tamper(
    v05_transaction_case,
) -> None:
    case = _full_case(v05_transaction_case)
    for field, replacement in (
        ("sha256", "1" * 64),
        ("path", "renamed-work-order.json"),
    ):
        output = case["tmp_path"] / f"surface-facts-manifest-{field}"
        export_delivery_package(
            case["ledger"], output, privacy_view="customer_private"
        )
        manifest_path = output / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["entries"][0][field] = replacement
        manifest_path.write_bytes(rfc8785.dumps(manifest))
        with pytest.raises(DeliveryPackageError):
            load_surface_facts(output)
