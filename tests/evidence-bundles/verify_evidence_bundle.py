#!/usr/bin/env python3
"""Standalone offline verifier for OpenWorkProof evidence bundles.

This script verifies an evidence bundle JSON file without any live ledger,
network access, or trusting the runtime. It only needs the ``openworkproof``
package installed (``pip install openworkproof``) and the bundle JSON file.

Usage::

    python verify_evidence_bundle.py <bundle.json>

Exit codes:
    0 — verification passed
    1 — verification failed
    2 — usage error
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
import tempfile
from pathlib import Path


def bundle_schema(bundle_path: str | Path) -> str:
    """Return the exact supported-schema discriminator candidate."""
    try:
        bundle = json.loads(Path(bundle_path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise ValueError("bundle is not valid JSON") from error
    if type(bundle) is not dict or type(bundle.get("schema_version")) is not str:
        raise ValueError("bundle schema_version is missing")
    return bundle["schema_version"]


def _verify_v01_bundle(bundle_path: str) -> bool:
    """Verify an evidence bundle and print the results."""
    import rfc8785

    from openworkproof.models import (
        ACTION_RECEIPT_ADAPTER,
        AcceptanceReceipt,
        CapabilityGrant,
        CompositionReport,
        WorkOrder,
        EvidenceRef,
    )
    from openworkproof.policy import CommittedEvidence
    from openworkproof.signing import decode_and_verify_key_binding, verify_payload
    import openworkproof.acceptance as acceptance

    # --- Load bundle ---
    bundle = json.loads(Path(bundle_path).read_text(encoding="utf-8"))
    meta = bundle["metadata"]
    print(f"\n{'=' * 60}")
    print(f"Evidence Bundle: {meta['bug_id']}")
    print(f"Bug URL: {meta['bug_url']}")
    print(f"Pinned commit: {meta['pinned_commit']}")
    if meta.get("fix_commit"):
        print(f"Fix commit: {meta['fix_commit']}")
    print(f"Protocol: {meta['protocol_version']}")
    print(f"Signature: {meta['signature_algorithm']}")
    print(f"Canonicalization: {meta['canonicalization']}")
    print(f"{'=' * 60}\n")

    # --- Reconstruct typed objects ---
    work_order = WorkOrder.model_validate(bundle["work_order"])

    # Public keys from WorkOrder key bindings
    public_keys = {}
    for binding in work_order.key_bindings:
        public_keys[binding.key_id] = decode_and_verify_key_binding(binding)

    # Grants
    grants = tuple(
        CapabilityGrant.model_validate(g)
        for g in sorted(
            bundle["effective_grants"], key=lambda g: g["grant_id"]
        )
    )

    # Grant attempts (they are CapabilityGrant objects)
    grant_attempts = tuple(
        CapabilityGrant.model_validate(a)
        for a in sorted(
            bundle["grant_attempts"], key=lambda a: a["digest"]
        )
    )

    # Receipts — use the adapter because ActionReceipt is a Union type
    receipts = tuple(
        ACTION_RECEIPT_ADAPTER.validate_python(r)
        for r in bundle["receipts"]
    )

    # Composition reports
    reports = tuple(
        CompositionReport.model_validate(r)
        for r in bundle["composition_reports"]
    )

    # Acceptance receipt
    acceptance_receipt = AcceptanceReceipt.model_validate(
        bundle["acceptance_receipt"]
    )

    # Committed evidence
    committed_evidence = tuple(
        CommittedEvidence(
            reference=EvidenceRef.model_validate(ce["reference"]),
            payload=base64.b64decode(ce["payload_b64"]),
        )
        for ce in bundle["committed_evidence"]
    )

    # --- Verify evidence payload hashes ---
    print("Step 1: Verify committed evidence hashes...")
    for i, ce in enumerate(bundle["committed_evidence"]):
        payload = base64.b64decode(ce["payload_b64"])
        actual = hashlib.sha256(payload).hexdigest()
        expected = ce["reference"]["sha256"]
        assert actual == expected, (
            f"Evidence file {i} ({ce['reference']['path']}): "
            f"hash mismatch! expected={expected}, actual={actual}"
        )
        print(f"  ✓ {ce['reference']['path']} — SHA-256 verified")

    # --- Verify WorkOrder signature ---
    print("\nStep 2: Verify WorkOrder signature...")
    verify_payload(
        "work-order",
        work_order.model_dump(mode="json"),
        public_keys[work_order.signer_key_id],
    )
    print(f"  ✓ WorkOrder signed by {work_order.signer_key_id}")
    print(f"  ✓ WorkOrder digest: {work_order.digest}")

    # --- Verify all grant signatures ---
    print(f"\nStep 3: Verify {len(grants)} CapabilityGrant signatures...")
    for grant in grants:
        verify_payload(
            "capability-grant",
            grant.model_dump(mode="json"),
            public_keys[grant.issuer_key_id],
        )
        print(f"  ✓ Grant {grant.grant_id[:16]}... signed by {grant.issuer_key_id}")

    # --- Verify all receipt signatures ---
    print(f"\nStep 4: Verify {len(receipts)} ActionReceipt signatures...")
    for receipt in receipts:
        verify_payload(
            "action-receipt",
            receipt.model_dump(mode="json"),
            public_keys[receipt.signer_key_id],
        )
        # Different receipt types have different descriptive fields
        desc = getattr(receipt, "tool_name", None) or \
              getattr(receipt, "event_type", None) or \
              type(receipt).__name__
        print(
            f"  ✓ Receipt #{receipt.sequence} ({desc}) "
            f"signed by {receipt.signer_key_id}"
        )

    # --- Verify composition report chain ---
    print(f"\nStep 5: Verify {len(reports)} composition reports...")
    for i, report in enumerate(reports):
        conclusion = report.verifier_conclusion
        print(f"  ✓ Report {i + 1}: verifier_conclusion = {conclusion}")

    # --- Full offline verification ---
    print("\nStep 6: Full offline verification (verify_acceptance_bundle)...")
    final_report = reports[-1]

    verified = acceptance.verify_acceptance_bundle(
        work_order=work_order,
        report=final_report,
        effective_grants=grants,
        grant_attempts=grant_attempts,
        receipts=receipts,
        committed_evidence=committed_evidence,
        acceptance_receipt=acceptance_receipt,
        public_keys=public_keys,
        reports=reports,
    )

    print(f"\n{'=' * 60}")
    print(f"✅ VERIFICATION PASSED")
    print(f"   Acceptance ID: {verified.acceptance_id}")
    print(f"   Final conclusion: {final_report.verifier_conclusion}")
    print(f"   Receipts verified: {len(receipts)}")
    print(f"   Grants verified: {len(grants)}")
    print(f"   Evidence files verified: {len(committed_evidence)}")
    print(f"   Composition reports: {len(reports)}")
    print(f"{'=' * 60}\n")
    return True


def _verify_v02_envelope(bundle_path: str) -> bool:
    """Materialize and verify one closed v0.2 Delivery Package envelope."""
    from openworkproof.delivery_package import (
        DeliveryPackageError,
        verify_delivery_package,
    )

    envelope = json.loads(Path(bundle_path).read_text(encoding="utf-8"))
    if set(envelope) != {"schema_version", "metadata", "files"}:
        raise DeliveryPackageError("delivery envelope fields are not closed")
    if type(envelope["metadata"]) is not dict or type(envelope["files"]) is not list:
        raise DeliveryPackageError("delivery envelope shape is invalid")
    expected_metadata = {
        "bug_id",
        "bug_url",
        "pinned_source_commit",
        "positive_candidate_commit",
        "candidate_revision_type",
        "fixed_test_source_digest",
        "negative_mutant_patch_digest",
        "container_image_digest",
        "dependency_lock_digest",
        "fix_description",
        "current_decision",
        "current_readiness",
    }
    if set(envelope["metadata"]) != expected_metadata:
        raise DeliveryPackageError("delivery envelope metadata is not closed")
    paths = tuple(item.get("path") for item in envelope["files"] if type(item) is dict)
    if (
        len(paths) != len(envelope["files"])
        or any(type(path) is not str for path in paths)
        or paths != tuple(sorted(set(paths), key=lambda value: value.encode("utf-8")))
        or "manifest.json" not in paths
    ):
        raise DeliveryPackageError("delivery envelope paths are not closed")
    with tempfile.TemporaryDirectory(prefix="openworkproof-v02-") as temporary:
        root = Path(temporary)
        for item in envelope["files"]:
            if set(item) != {"path", "sha256", "payload_b64"}:
                raise DeliveryPackageError("delivery envelope file fields are invalid")
            relative = item["path"]
            if (
                type(relative) is not str
                or relative.startswith("/")
                or any(part in {"", ".", ".."} for part in relative.split("/"))
            ):
                raise DeliveryPackageError("delivery envelope path is unsafe")
            try:
                payload = base64.b64decode(item["payload_b64"], validate=True)
            except (TypeError, ValueError) as error:
                raise DeliveryPackageError("delivery envelope payload is invalid") from error
            if hashlib.sha256(payload).hexdigest() != item["sha256"]:
                raise DeliveryPackageError("delivery envelope file hash mismatch")
            target = root.joinpath(*relative.split("/"))
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload)
        result = verify_delivery_package(root)
    metadata = envelope["metadata"]
    print(f"\n{'=' * 60}")
    print(f"✅ VERIFICATION PASSED")
    print(f"   Case: {metadata.get('bug_id', 'unknown')}")
    print(f"   Current decision: {result.current_decision}")
    print(f"   Current readiness: {result.settlement_readiness}")
    print(f"   Manifest digest: {result.manifest_digest}")
    print(f"{'=' * 60}\n")
    return True


def _verify_v03_envelope(bundle_path: str) -> bool:
    """Materialize and verify one closed scope-bound v0.3 package."""
    from openworkproof.delivery_package import (
        DeliveryPackageError,
        verify_delivery_package,
    )

    envelope = json.loads(Path(bundle_path).read_text(encoding="utf-8"))
    if set(envelope) != {"schema_version", "metadata", "files"}:
        raise DeliveryPackageError("delivery envelope fields are not closed")
    metadata = envelope["metadata"]
    expected_metadata = {
        "issue_source",
        "demo_owner",
        "upstream_adoption",
        "customer_case",
        "old_green_scope_status",
        "repaired_scope_status",
        "bounded_conclusion",
        "current_decision",
        "current_readiness",
        "full_offline_replay",
    }
    if type(metadata) is not dict or set(metadata) != expected_metadata:
        raise DeliveryPackageError("v0.3 envelope metadata is not closed")
    if (
        metadata["demo_owner"] != "OpenWorkProof"
        or metadata["upstream_adoption"] != "not_evidenced"
        or metadata["customer_case"] != "not_evidenced"
        or metadata["old_green_scope_status"] != "indeterminate"
        or metadata["repaired_scope_status"] != "satisfied"
        or metadata["full_offline_replay"] is not True
    ):
        raise DeliveryPackageError("v0.3 envelope boundary metadata is invalid")
    if type(envelope["files"]) is not list:
        raise DeliveryPackageError("v0.3 envelope files are invalid")
    paths = tuple(
        item.get("path") for item in envelope["files"] if type(item) is dict
    )
    if (
        len(paths) != len(envelope["files"])
        or any(type(path) is not str for path in paths)
        or paths != tuple(sorted(set(paths), key=lambda value: value.encode("utf-8")))
        or "manifest.json" not in paths
    ):
        raise DeliveryPackageError("v0.3 envelope paths are not closed")
    with tempfile.TemporaryDirectory(prefix="openworkproof-v03-") as temporary:
        root = Path(temporary)
        for item in envelope["files"]:
            if set(item) != {"path", "sha256", "payload_b64"}:
                raise DeliveryPackageError(
                    "v0.3 envelope file fields are invalid"
                )
            relative = item["path"]
            if (
                type(relative) is not str
                or relative.startswith("/")
                or any(part in {"", ".", ".."} for part in relative.split("/"))
            ):
                raise DeliveryPackageError("v0.3 envelope path is unsafe")
            try:
                payload = base64.b64decode(item["payload_b64"], validate=True)
            except (TypeError, ValueError) as error:
                raise DeliveryPackageError(
                    "v0.3 envelope payload is invalid"
                ) from error
            if hashlib.sha256(payload).hexdigest() != item["sha256"]:
                raise DeliveryPackageError("v0.3 envelope file hash mismatch")
            target = root.joinpath(*relative.split("/"))
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload)
        result = verify_delivery_package(root)
    if (
        result.current_decision != "VERIFIED"
        or result.full_offline_replay is not True
    ):
        raise DeliveryPackageError("v0.3 replay conclusion is invalid")
    print(f"\n{'=' * 60}")
    print("✅ VERIFICATION PASSED")
    print(f"   Case: {metadata['issue_source']}")
    print("   v0.3 scope: satisfied")
    print(f"   Current decision: {result.current_decision}")
    print(f"   Current readiness: {result.settlement_readiness}")
    print(f"   Manifest digest: {result.manifest_digest}")
    print(f"{'=' * 60}\n")
    return True


def verify_bundle(bundle_path: str) -> bool:
    """Dispatch to the exact offline verifier selected by schema_version."""
    schema = bundle_schema(bundle_path)
    if schema == "openworkproof/evidence-bundle/v0.1":
        return _verify_v01_bundle(bundle_path)
    if schema == "openworkproof/delivery-package-envelope/0.2":
        return _verify_v02_envelope(bundle_path)
    if schema == "openworkproof/delivery-package-envelope/0.3":
        return _verify_v03_envelope(bundle_path)
    raise ValueError(f"unsupported bundle schema: {schema}")


def main() -> int:
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <bundle.json>")
        return 2

    bundle_path = sys.argv[1]
    if not Path(bundle_path).exists():
        print(f"Error: file not found: {bundle_path}")
        return 2

    try:
        verify_bundle(bundle_path)
        return 0
    except Exception as e:
        print(f"\n❌ VERIFICATION FAILED: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
